//! Rodata tracing over `HighIr`: resolve a `(pointer, length)` pair to the
//! constant bytes a Soroban guest baked into the WASM data section.
//!
//! Soroban's linear-memory constructors — `symbol_new_from_linear_memory`,
//! `bytes_new_from_linear_memory`, `string_new_from_linear_memory` — take a
//! `(position, length)` pair into linear memory and build a host object
//! from the bytes there. When those bytes are compile-time constants (a
//! symbol name, a byte literal), they live in an active data segment,
//! captured module-side as [`MemoryImage`]. [`trace_bytes()`] bridges the
//! two: resolve each operand to a constant, then slice the image.
//!
//! ## The `U32Val` wrapper
//!
//! The position and length arrive as `U32Val`s — a `u32` packed into a Val
//! as `(raw << 32) | U32_TAG`. Because the linear-memory recognizer runs
//! *after* the C1 Val-encoding pass, that packing is usually already
//! recognized as [`KnownOp::ValEncodeSmall`]; [`trace_u32val`] peels either
//! that recognized form or a raw constant `U32Val` (or a bare `u32`/`i32`).
//!
//! ## Reachability
//!
//! Like [`trace_int`], these tracers are intra-procedural and stop at the
//! first non-constant definition (a phi/block-param or a computed value).
//! On the current corpus every linear-memory site threads its position
//! through phi chains or helper parameters, so [`trace_bytes()`] returns
//! `None` there — the literal stays honestly unresolved until a
//! constant-propagation engine can reach across those boundaries. The
//! machinery here is correct and exercised for the local-constant case.

use sordec_common::{IrId, ValueId};
use sordec_ir::{
    Expr, HighFunction, KnownOp, KnownType, Literal, MemoryImage, SemanticOp, WasmOpcodeKind,
};

use super::high::{resolve_use, trace_int};
use crate::val_abi::{TAG_MASK, TAG_U32_VAL};

/// Depth cap for peeling chained width conversions ahead of a constant.
/// Conversion chains in real code are one deep (the `i32 -> i64` extend
/// before Val-encoding); this only guards against a pathological IR.
const CONVERSION_PEEL_DEPTH: u32 = 8;

/// Resolve `value` to the `u32` it carries as a Soroban `U32Val`.
///
/// Accepts the three shapes a linear-memory position/length operand takes:
/// the C1-recognized [`KnownOp::ValEncodeSmall`] `{ ty: U32 }` wrapper
/// (tracing its inner payload), a fully-constant `U32Val` literal
/// (`(raw << 32) | U32_TAG`), or a bare `u32`/`i32` constant. Returns
/// `None` when the operand is not a locally-provable constant of one of
/// those shapes.
#[must_use]
pub fn trace_u32val(func: &HighFunction, value: ValueId) -> Option<u32> {
    let terminal = resolve_use(func, value);
    // Bounds-check before Arena::get (which debug_asserts on out-of-range
    // ids); resolve_use returns its input unchanged for a dangling id.
    if (terminal.index() as usize) >= func.bindings.len() {
        return None;
    }
    match &func.bindings.get(terminal)?.expr {
        // C1 recognized `(raw << 32) | 4` as a U32 small-encode; the raw
        // u32 is the wrapped payload. It commonly arrives as an
        // `i32 -> i64` extend of a constant offset (the SDK widens the
        // u32 before packing), so peel any width conversion first.
        Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall {
            ty: KnownType::U32,
            value: inner,
        })) => u32::try_from(trace_int_through_conversions(func, *inner, CONVERSION_PEEL_DEPTH)?)
            .ok(),
        // A fully-constant U32Val literal.
        Expr::Literal(Literal::I64(bits)) => decode_u32val(*bits as u64),
        Expr::Literal(Literal::U64(bits)) => decode_u32val(*bits),
        // A bare (unwrapped) integer offset.
        Expr::Literal(Literal::U32(n)) => Some(*n),
        Expr::Literal(Literal::I32(n)) => u32::try_from(*n).ok(),
        _ => None,
    }
}

/// Trace `value` to an integer constant, seeing through single-operand
/// width conversions.
///
/// The lowering erases the specific conversion operator — an
/// `i64.extend_i32_u`, an `i32.wrap_i64`, etc. all become
/// `Expr::Unknown { op_kind: Conversion }` — so this peels *any*
/// single-operand conversion over an integer constant. That is sound for
/// the one caller ([`trace_u32val`]'s `U32Val` payload): only the low 32
/// bits are packed into the Val, and every integer width conversion of a
/// constant agrees on those bits (a float operand traces to `None` via
/// [`trace_int`], so it stays safe). Mirrors the same peel in
/// `recognizers::wrappers::operand_param_walk`.
fn trace_int_through_conversions(func: &HighFunction, value: ValueId, depth: u32) -> Option<i128> {
    let terminal = resolve_use(func, value);
    match conversion_operand(func, terminal) {
        Some(inner) if depth > 0 => trace_int_through_conversions(func, inner, depth - 1),
        _ => trace_int(func, terminal),
    }
}

/// The sole operand of `id` when it is a single-operand width conversion,
/// else `None`. See [`trace_int_through_conversions`] for why the specific
/// conversion opcode does not matter.
fn conversion_operand(func: &HighFunction, id: ValueId) -> Option<ValueId> {
    // Bounds-check before `Arena::get`, which debug_asserts on an
    // out-of-range id (`resolve_use` returns dangling ids unchanged).
    if (id.index() as usize) >= func.bindings.len() {
        return None;
    }
    match &func.bindings.get(id)?.expr {
        Expr::Unknown {
            op_kind: WasmOpcodeKind::Conversion,
            args,
            ..
        } if args.len() == 1 => Some(args[0]),
        _ => None,
    }
}

/// Decode a raw 64-bit `Val` as a `U32Val`: verify the tag byte and
/// extract the `u32` from the major word. `None` if the tag is not
/// `U32Val`.
fn decode_u32val(bits: u64) -> Option<u32> {
    if (bits & TAG_MASK) == u64::from(TAG_U32_VAL) {
        // The u32 lives in the major (bits 32-63); the shift result is
        // ≤ u32::MAX, so the cast is exact.
        Some((bits >> 32) as u32)
    } else {
        None
    }
}

/// Resolve a `(pointer, length)` pair to the constant bytes it names, if
/// both operands are locally-provable `U32Val` constants and a single
/// active data segment covers `[pointer, pointer + length)`.
///
/// Returns `None` when either operand is not constant (the common corpus
/// case — see the module docs) or when the range is not covered by the
/// module's rodata.
#[must_use]
pub fn trace_bytes(
    func: &HighFunction,
    memory: &MemoryImage,
    ptr: ValueId,
    len: ValueId,
) -> Option<Vec<u8>> {
    let pos = trace_u32val(func, ptr)?;
    let length = trace_u32val(func, len)?;
    memory.read(pos, length).map(|slice| slice.to_vec())
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{Arena, BlockId, FuncId, Provenance, ProvenanceSource, UnknownReason};
    use sordec_ir::{Binding, DataSegment, HighBlock, IrType, Region};

    /// One-block `HighFunction` whose bindings are the supplied `Expr`s at
    /// ids `0..N`.
    fn func_with_exprs(exprs: Vec<Expr>) -> HighFunction {
        let mut bindings: Arena<ValueId, Binding> = Arena::new();
        for expr in exprs {
            let id = ValueId::from_index(bindings.len() as u32);
            bindings.push(Binding::new(
                id,
                IrType::Unknown(UnknownReason::InsufficientEvidence),
                expr,
                Provenance::new("test", ProvenanceSource::DataFlow, "seed"),
            ));
        }
        let mut blocks: Arena<BlockId, HighBlock> = Arena::new();
        blocks.push(HighBlock {
            id: BlockId::from_index(0),
            bindings: vec![],
        });
        HighFunction {
            id: FuncId::from_index(0),
            name: None,
            signature: None,
            blocks,
            bindings,
            region: Region::Unreachable,
            params: vec![],
            returns: vec![],
        }
    }

    fn v(i: u32) -> ValueId {
        ValueId::from_index(i)
    }

    /// The raw bits of a `U32Val` carrying `n`.
    fn u32val_bits(n: u32) -> i64 {
        (((n as u64) << 32) | u64::from(TAG_U32_VAL)) as i64
    }

    /// A segment `[100, 105)` holding "hello".
    fn image() -> MemoryImage {
        MemoryImage::from_segments(vec![DataSegment {
            offset: 100,
            bytes: b"hello".to_vec(),
        }])
    }

    #[test]
    fn u32val_literal_decodes() {
        // v0 = U32Val(100) literal.
        let func = func_with_exprs(vec![Expr::Literal(Literal::I64(u32val_bits(100)))]);
        assert_eq!(trace_u32val(&func, v(0)), Some(100));
    }

    #[test]
    fn wrong_tag_is_not_a_u32val() {
        // Tag byte 6 (U64Small), not U32Val — must not decode.
        let bits = (((100u64) << 32) | 6) as i64;
        let func = func_with_exprs(vec![Expr::Literal(Literal::I64(bits))]);
        assert_eq!(trace_u32val(&func, v(0)), None);
    }

    #[test]
    fn val_encode_small_wrapper_is_peeled() {
        // v0 = raw offset 100 (i32); v1 = ValEncodeSmall<U32>(v0).
        let func = func_with_exprs(vec![
            Expr::Literal(Literal::I32(100)),
            Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall {
                ty: KnownType::U32,
                value: v(0),
            })),
        ]);
        assert_eq!(trace_u32val(&func, v(1)), Some(100));
    }

    #[test]
    fn bare_u32_offset_resolves() {
        let func = func_with_exprs(vec![Expr::Literal(Literal::U32(42))]);
        assert_eq!(trace_u32val(&func, v(0)), Some(42));
    }

    #[test]
    fn val_encode_small_peels_width_conversion() {
        // The timelock shape: v0 = i32 const offset; v1 = i64.extend_i32_u
        // (an opaque `Conversion` after lowering); v2 = ValEncodeSmall<U32>.
        // trace_u32val must see through the extend to the constant.
        let func = func_with_exprs(vec![
            Expr::Literal(Literal::I32(1_048_600)),
            Expr::Unknown {
                op_kind: WasmOpcodeKind::Conversion,
                args: vec![v(0)],
                reason: UnknownReason::UnsupportedPattern,
            },
            Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall {
                ty: KnownType::U32,
                value: v(1),
            })),
        ]);
        assert_eq!(trace_u32val(&func, v(2)), Some(1_048_600));
    }

    #[test]
    fn non_constant_position_returns_none() {
        // A phi (block param) is not a constant.
        let func = func_with_exprs(vec![Expr::Phi { incoming: vec![] }]);
        assert_eq!(trace_u32val(&func, v(0)), None);
    }

    #[test]
    fn trace_bytes_recovers_literal_slice() {
        // v0 = U32Val(100) pos; v1 = U32Val(5) len.
        let func = func_with_exprs(vec![
            Expr::Literal(Literal::I64(u32val_bits(100))),
            Expr::Literal(Literal::I64(u32val_bits(5))),
        ]);
        assert_eq!(
            trace_bytes(&func, &image(), v(0), v(1)),
            Some(b"hello".to_vec())
        );
    }

    #[test]
    fn trace_bytes_recovers_through_val_encode_wrappers() {
        // Mirrors the post-C1 corpus shape: pos/len are ValEncodeSmall<U32>
        // over raw i32 offsets. (Here the offsets are local constants; the
        // real corpus threads them through phis — see module docs.)
        let func = func_with_exprs(vec![
            Expr::Literal(Literal::I32(101)),
            Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall {
                ty: KnownType::U32,
                value: v(0),
            })),
            Expr::Literal(Literal::I32(3)),
            Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall {
                ty: KnownType::U32,
                value: v(2),
            })),
        ]);
        // "ell" — offset 101, len 3.
        assert_eq!(
            trace_bytes(&func, &image(), v(1), v(3)),
            Some(b"ell".to_vec())
        );
    }

    #[test]
    fn trace_bytes_out_of_range_returns_none() {
        // pos 100, len 99 overruns the 5-byte segment.
        let func = func_with_exprs(vec![
            Expr::Literal(Literal::I64(u32val_bits(100))),
            Expr::Literal(Literal::I64(u32val_bits(99))),
        ]);
        assert_eq!(trace_bytes(&func, &image(), v(0), v(1)), None);
    }

    #[test]
    fn trace_bytes_non_constant_returns_none() {
        let func = func_with_exprs(vec![
            Expr::Phi { incoming: vec![] },
            Expr::Literal(Literal::I64(u32val_bits(5))),
        ]);
        assert_eq!(trace_bytes(&func, &image(), v(0), v(1)), None);
    }
}
