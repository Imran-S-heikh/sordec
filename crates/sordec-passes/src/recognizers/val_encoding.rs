//! C1 — the Soroban `Val` encoding recognizer.
//!
//! Soroban represents every value crossing the host boundary as a tagged
//! 64-bit `Val`. The SDK compiles encode/decode scaffolding into every
//! contract; this pass recognizes it and rewrites the matching HighIr
//! bindings into [`KnownOp`] `Val` operations, so downstream recognizers
//! (storage, auth, events) see clean values instead of shift/or soup.
//!
//! ## What it recognizes
//!
//! | Pattern | Shape (post-lowering) | Rewrite |
//! |---|---|---|
//! | small encode | `(value << 8) \| tag`, tag ∈ 6..=13 | `ValEncodeSmall` |
//! | u32/i32 encode | `(value << 32) \| tag`, tag ∈ {4,5} | `ValEncodeSmall` |
//! | tag check | `(value & 0xFF) == tag` | `ValTagCheck` |
//! | small decode | `value >> {8,32}` (gated) | `ValDecodeSmall` |
//! | object conv. | `i`-module host call | `ValObject` |
//!
//! ## Certainty (the "no guessing" contract)
//!
//! Object conversions are recognized by host-function *identity* — the
//! ABI is proof — so their bindings become `Known`. Bit-pattern matches
//! are structural inference, so they become `Inferred`; every rewrite
//! records an `SdkPattern` (or `HostFunctionAbi`) provenance entry
//! naming the pattern, so nothing claims more than its evidence
//! supports and every rewrite is auditable.
//!
//! ## What it does NOT do (see the C1 plan for full reasons)
//!
//! - No round-trip *elimination* (encode/decode pairs live in separate
//!   functions connected through linear memory — inter-procedural,
//!   later work). Recognition only.
//! - No dead-binding removal — the inner `shl` / tag-constant feeder
//!   bindings stay. Cleanup is a future DCE pass.
//! - `ValDecodeSmall` carries no payload type — the lowering erased
//!   shift signedness, so u64-vs-i64 isn't determinable here.
//! - No symbol (tag 14) recognition — that's C8, needing the 6-bit
//!   char decoder.

use std::collections::HashSet;

use sordec_common::{IrId, ProvenanceSource, ValueId};
use sordec_ir::{
    BinaryOp, Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, SemanticOp,
    WasmOpcodeKind,
};

use crate::pass::{Pass, PassMetrics, PassResult};
use crate::val_abi;

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "val-encoding";

// Metric counter keys (per-pattern match counts).
const M_OBJECT: &str = "val_object";
const M_TAG_CHECK: &str = "val_tag_check";
const M_ENCODE_SMALL: &str = "val_encode_small";
const M_ENCODE_U32: &str = "val_encode_u32";
const M_DECODE: &str = "val_decode_small";

/// The C1 Val-encoding recognizer. Stateless.
#[derive(Debug, Default, Clone, Copy)]
pub struct ValEncodingPass;

impl Pass<HighIr> for ValEncodingPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        for func in &mut ir.functions {
            let (changed, metrics) = recognize_function(func);
            result.changed |= changed;
            for (key, value) in metrics.iter() {
                result.metrics.increment(key, value);
            }
        }
        result
    }
}

use super::{apply_rewrites, is_recognized, Rewrite};

/// Recognize all Val patterns in one function. Returns whether anything
/// changed plus per-pattern metrics.
fn recognize_function(func: &mut HighFunction) -> (bool, PassMetrics) {
    let mut metrics = PassMetrics::new();
    let mut rewrites: Vec<Rewrite> = Vec::new();
    let mut saw_tag_check = false;

    // Scan 1: object conversions, tag checks, and encodes. Each binding
    // matches at most one pattern; bindings already recognized (a prior
    // run) are skipped, which is what makes the pass idempotent.
    for (id, binding) in func.bindings.iter() {
        if is_recognized(&binding.expr) {
            continue;
        }
        let matched = try_object(func, id, &binding.expr)
            .or_else(|| try_tag_check(func, id, &binding.expr))
            .or_else(|| try_encode(func, id, &binding.expr));
        if let Some(rw) = matched {
            if rw.metric == M_TAG_CHECK {
                saw_tag_check = true;
            }
            rewrites.push(rw);
        }
    }

    // Scan 2: small decodes, gated on the function containing at least
    // one recognized tag check (a coarse function-level anchor — the
    // corpus shows decode and tag-check are always connected, but the
    // precise connection needs phi-aware analysis we don't have yet).
    if saw_tag_check {
        let taken: HashSet<ValueId> = rewrites.iter().map(|r| r.id).collect();
        for (id, binding) in func.bindings.iter() {
            if taken.contains(&id) || is_recognized(&binding.expr) {
                continue;
            }
            if let Some(rw) = try_decode(id, &binding.expr, func) {
                rewrites.push(rw);
            }
        }
    }

    let changed = !rewrites.is_empty();

    // Apply.
    for rw in &rewrites {
        metrics.increment(rw.metric, 1);
    }
    apply_rewrites(func, PASS_NAME, rewrites);

    (changed, metrics)
}

// ---------------------------------------------------------------------
// Pattern matchers
// ---------------------------------------------------------------------

/// P5 — object-form conversion: an `i`-module host call.
fn try_object(_func: &HighFunction, id: ValueId, expr: &Expr) -> Option<Rewrite> {
    let Expr::Semantic(SemanticOp::Unknown {
        host_module,
        host_fn,
        args,
        ..
    }) = expr
    else {
        return None;
    };
    let kind = val_abi::obj_fn_kind(host_module, host_fn)?;
    Some(Rewrite {
        id,
        expr: Expr::Semantic(SemanticOp::Known(KnownOp::ValObject {
            kind,
            args: args.clone(),
        })),
        ty: Some(IrType::Known(val_abi::obj_kind_result_type(kind))),
        source: ProvenanceSource::HostFunctionAbi,
        note: format!("val-object {}", val_abi::obj_kind_name(kind)),
        metric: M_OBJECT,
    })
}

/// P3 — tag check: `(value & 0xFF) == tag`.
fn try_tag_check(func: &HighFunction, id: ValueId, expr: &Expr) -> Option<Rewrite> {
    let Expr::Binary {
        op: BinaryOp::Eq,
        lhs,
        rhs,
    } = expr
    else {
        return None;
    };
    // Either operand may be the tag literal (commutative `==`).
    for (masked_side, tag_side) in [(*lhs, *rhs), (*rhs, *lhs)] {
        let Some(tag) = lit_tag(func, tag_side) else {
            continue;
        };
        if !val_abi::is_valid_tag(tag) {
            continue;
        }
        // The other side must resolve to `_ & 0xFF`.
        let Some(Expr::Binary {
            op: BinaryOp::BitAnd,
            lhs: and_l,
            rhs: and_r,
        }) = resolved_expr(func, masked_side)
        else {
            continue;
        };
        let (and_l, and_r) = (*and_l, *and_r);
        // One side is the 0xFF mask; the other is the value being tagged.
        let value_side = if lit_int(func, and_l) == Some(255) {
            and_r
        } else if lit_int(func, and_r) == Some(255) {
            and_l
        } else {
            continue;
        };
        // The corpus wraps the 64-bit Val to i32 before masking
        // (`I32WrapI64`), lowered as `Unknown { Conversion }`. Report the
        // pre-conversion value so the check points at the real Val.
        let value = match resolved_expr(func, value_side) {
            Some(Expr::Unknown {
                op_kind: WasmOpcodeKind::Conversion,
                args,
                ..
            }) => args.first().copied().unwrap_or(value_side),
            _ => value_side,
        };
        return Some(Rewrite {
            id,
            expr: Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck { value, tag })),
            ty: Some(IrType::Inferred(KnownType::Bool)),
            source: ProvenanceSource::SdkPattern,
            note: format!("val-tag-check {}", val_abi::tag_name(tag).unwrap_or("?")),
            metric: M_TAG_CHECK,
        });
    }
    None
}

/// P1/P2 — small / u32 encode: `(value << shift) | tag`.
fn try_encode(func: &HighFunction, id: ValueId, expr: &Expr) -> Option<Rewrite> {
    let Expr::Binary {
        op: BinaryOp::BitOr,
        lhs,
        rhs,
    } = expr
    else {
        return None;
    };
    // Either operand may be the tag literal (commutative `|`).
    for (shl_side, tag_side) in [(*lhs, *rhs), (*rhs, *lhs)] {
        let Some(tag) = lit_tag(func, tag_side) else {
            continue;
        };
        // The other side must resolve to `value << shift`.
        let Some(Expr::Binary {
            op: BinaryOp::Shl,
            lhs: value,
            rhs: shift_operand,
        }) = resolved_expr(func, shl_side)
        else {
            continue;
        };
        let (value, shift_operand) = (*value, *shift_operand);
        let Some(shift) = lit_int(func, shift_operand) else {
            continue;
        };
        // Only two (shift, tag) shapes are valid Val encodings; anything
        // else is unrelated arithmetic that happens to shift-and-or.
        let metric = match (shift, tag) {
            (8, 6..=13) => M_ENCODE_SMALL,
            (32, 4 | 5) => M_ENCODE_U32,
            _ => continue,
        };
        let payload = val_abi::small_tag_payload_type(tag)?;
        return Some(Rewrite {
            id,
            expr: Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall {
                ty: payload,
                value,
            })),
            ty: Some(IrType::Inferred(KnownType::Val)),
            source: ProvenanceSource::SdkPattern,
            note: format!("val-encode {}", val_abi::tag_name(tag).unwrap_or("?")),
            metric,
        });
    }
    None
}

/// P4 — small decode: `value >> {8,32}`. Caller gates on the function
/// having a recognized tag check.
fn try_decode(id: ValueId, expr: &Expr, func: &HighFunction) -> Option<Rewrite> {
    let Expr::Binary {
        op: BinaryOp::Shr,
        lhs,
        rhs,
    } = expr
    else {
        return None;
    };
    let shift = lit_int(func, *rhs)?;
    if !matches!(shift, 8 | 32) {
        return None;
    }
    Some(Rewrite {
        id,
        expr: Expr::Semantic(SemanticOp::Known(KnownOp::ValDecodeSmall { value: *lhs })),
        // No type claim — signedness of the payload is not determinable.
        ty: None,
        source: ProvenanceSource::SdkPattern,
        note: "val-decode-small".to_string(),
        metric: M_DECODE,
    })
}

// ---------------------------------------------------------------------
// Operand resolution helpers
// ---------------------------------------------------------------------

/// The resolved (through `Use` chains) `Expr` behind `value`, or `None`
/// for a dangling id.
fn resolved_expr(func: &HighFunction, value: ValueId) -> Option<&Expr> {
    let id = crate::dataflow::resolve_use(func, value);
    if (id.index() as usize) >= func.bindings.len() {
        return None;
    }
    Some(&func.bindings.get(id)?.expr)
}

/// Resolve `value` to an integer literal. Thin local alias for the
/// shared [`crate::dataflow::trace_int`] helper.
fn lit_int(func: &HighFunction, value: ValueId) -> Option<i128> {
    crate::dataflow::trace_int(func, value)
}

/// Resolve `value` to a tag byte (an integer literal in `0..=255`).
fn lit_tag(func: &HighFunction, value: ValueId) -> Option<u8> {
    let n = lit_int(func, value)?;
    u8::try_from(n).ok()
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{Arena, BlockId, FuncId, Provenance, UnknownReason};
    use sordec_ir::{Binding, HighBlock, Literal, Region};

    /// Build a one-block `HighFunction` from a list of `Expr`s (ids
    /// 0..N, each `Unknown`-typed with a seed provenance entry).
    fn func_with(exprs: Vec<Expr>) -> HighFunction {
        let mut bindings: Arena<ValueId, Binding> = Arena::new();
        for expr in exprs {
            let id = ValueId::from_index(bindings.len() as u32);
            bindings.push(Binding::new(
                id,
                IrType::Unknown(UnknownReason::InsufficientEvidence),
                expr,
                Provenance::new("seed", ProvenanceSource::DataFlow, "seed"),
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

    fn i64c(n: i64) -> Expr {
        Expr::Literal(Literal::I64(n))
    }

    fn i32c(n: i32) -> Expr {
        Expr::Literal(Literal::I32(n))
    }

    fn bin(op: BinaryOp, lhs: ValueId, rhs: ValueId) -> Expr {
        Expr::Binary { op, lhs, rhs }
    }

    fn run(func: &mut HighFunction) -> (bool, PassMetrics) {
        recognize_function(func)
    }

    fn expr_at(func: &HighFunction, id: ValueId) -> &Expr {
        &func.bindings.get(id).unwrap().expr
    }

    // --- P1/P2 encode ---

    #[test]
    fn small_encode_u64_recognized() {
        // v0 = value; v1 = 8; v2 = v0 << v1; v3 = 6 (U64Small); v4 = v2 | v3
        let mut func = func_with(vec![
            i64c(0),                        // v0 the raw value
            i64c(8),                        // v1 shift
            bin(BinaryOp::Shl, v(0), v(1)), // v2
            i64c(6),                        // v3 tag U64Small
            bin(BinaryOp::BitOr, v(2), v(3)), // v4 root
        ]);
        let (changed, metrics) = run(&mut func);
        assert!(changed);
        assert_eq!(metrics.get(M_ENCODE_SMALL), Some(1));
        match expr_at(&func, v(4)) {
            Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty, value })) => {
                assert_eq!(*ty, KnownType::U64);
                assert_eq!(*value, v(0));
            }
            other => panic!("expected ValEncodeSmall, got {other:?}"),
        }
        // Inferred(Val) type on the rewritten binding.
        assert_eq!(func.bindings.get(v(4)).unwrap().ty, IrType::Inferred(KnownType::Val));
    }

    #[test]
    fn u32_encode_recognized_with_shift_32() {
        // v0 = value; v1 = 32; v2 = v0 << v1; v3 = 4 (U32Val); v4 = v2 | v3
        let mut func = func_with(vec![
            i64c(0),
            i64c(32),
            bin(BinaryOp::Shl, v(0), v(1)),
            i64c(4),
            bin(BinaryOp::BitOr, v(2), v(3)),
        ]);
        let (changed, metrics) = run(&mut func);
        assert!(changed);
        assert_eq!(metrics.get(M_ENCODE_U32), Some(1));
        match expr_at(&func, v(4)) {
            Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty, .. })) => {
                assert_eq!(*ty, KnownType::U32);
            }
            other => panic!("expected ValEncodeSmall U32, got {other:?}"),
        }
    }

    #[test]
    fn encode_operands_commuted() {
        // v4 = v3 | v2 (tag first) — must still match.
        let mut func = func_with(vec![
            i64c(0),
            i64c(8),
            bin(BinaryOp::Shl, v(0), v(1)),
            i64c(11), // I128Small
            bin(BinaryOp::BitOr, v(3), v(2)),
        ]);
        let (changed, _) = run(&mut func);
        assert!(changed);
        match expr_at(&func, v(4)) {
            Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty, .. })) => {
                assert_eq!(*ty, KnownType::I128);
            }
            other => panic!("expected ValEncodeSmall I128, got {other:?}"),
        }
    }

    #[test]
    fn encode_wrong_shift_not_matched() {
        // shift 16 is not a valid Val shift → no match.
        let mut func = func_with(vec![
            i64c(0),
            i64c(16),
            bin(BinaryOp::Shl, v(0), v(1)),
            i64c(6),
            bin(BinaryOp::BitOr, v(2), v(3)),
        ]);
        let (changed, _) = run(&mut func);
        assert!(!changed, "shift 16 must not be recognized as Val encode");
    }

    #[test]
    fn encode_invalid_tag_not_matched() {
        // shift 8 but tag 200 is not a valid tag → no match.
        let mut func = func_with(vec![
            i64c(0),
            i64c(8),
            bin(BinaryOp::Shl, v(0), v(1)),
            i64c(200),
            bin(BinaryOp::BitOr, v(2), v(3)),
        ]);
        let (changed, _) = run(&mut func);
        assert!(!changed);
    }

    #[test]
    fn encode_shift8_with_u32_tag_not_matched() {
        // shift 8 with tag 4 (U32Val wants shift 32) is inconsistent.
        let mut func = func_with(vec![
            i64c(0),
            i64c(8),
            bin(BinaryOp::Shl, v(0), v(1)),
            i64c(4),
            bin(BinaryOp::BitOr, v(2), v(3)),
        ]);
        let (changed, _) = run(&mut func);
        assert!(!changed, "shift/tag mismatch must not match");
    }

    // --- P3 tag check ---

    #[test]
    fn tag_check_recognized() {
        // v0 = the Val; v1 = 0xFF; v2 = v0 & v1; v3 = 64 (U64Object); v4 = v2 == v3
        let mut func = func_with(vec![
            i64c(0),
            i32c(255),
            bin(BinaryOp::BitAnd, v(0), v(1)),
            i32c(64),
            bin(BinaryOp::Eq, v(2), v(3)),
        ]);
        let (changed, metrics) = run(&mut func);
        assert!(changed);
        assert_eq!(metrics.get(M_TAG_CHECK), Some(1));
        match expr_at(&func, v(4)) {
            Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck { value, tag })) => {
                assert_eq!(*value, v(0));
                assert_eq!(*tag, 64);
            }
            other => panic!("expected ValTagCheck, got {other:?}"),
        }
        assert_eq!(func.bindings.get(v(4)).unwrap().ty, IrType::Inferred(KnownType::Bool));
    }

    #[test]
    fn tag_check_sees_through_wrap_conversion() {
        // v0 = Val; v1 = I32WrapI64(v0) [Unknown Conversion]; v2 = 0xFF;
        // v3 = v1 & v2; v4 = 77 (AddressObject); v5 = v3 == v4.
        // Expect the check to point at v0, not v1.
        let mut func = func_with(vec![
            i64c(0),
            Expr::Unknown {
                op_kind: WasmOpcodeKind::Conversion,
                args: vec![v(0)],
                reason: UnknownReason::UnsupportedPattern,
            },
            i32c(255),
            bin(BinaryOp::BitAnd, v(1), v(2)),
            i32c(77),
            bin(BinaryOp::Eq, v(3), v(4)),
        ]);
        let (changed, _) = run(&mut func);
        assert!(changed);
        match expr_at(&func, v(5)) {
            Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck { value, tag })) => {
                assert_eq!(*value, v(0), "should see through the wrap conversion");
                assert_eq!(*tag, 77);
            }
            other => panic!("expected ValTagCheck, got {other:?}"),
        }
    }

    #[test]
    fn eq_without_mask_not_matched() {
        // v2 = v0 == v1 with no `& 0xFF` → not a tag check.
        let mut func = func_with(vec![i64c(0), i64c(64), bin(BinaryOp::Eq, v(0), v(1))]);
        let (changed, _) = run(&mut func);
        assert!(!changed);
    }

    // --- P5 object conversions ---

    fn host_i(name: &str, args: Vec<ValueId>) -> Expr {
        Expr::Semantic(SemanticOp::Unknown {
            host_module: "i".to_string(),
            host_fn: name.to_string(),
            args,
            reason: UnknownReason::UnsupportedPattern,
        })
    }

    #[test]
    fn obj_from_u64_recognized_as_known_val() {
        let mut func = func_with(vec![i64c(0), host_i("_", vec![v(0)])]);
        let (changed, metrics) = run(&mut func);
        assert!(changed);
        assert_eq!(metrics.get(M_OBJECT), Some(1));
        match expr_at(&func, v(1)) {
            Expr::Semantic(SemanticOp::Known(KnownOp::ValObject { kind, args })) => {
                assert_eq!(*kind, sordec_ir::ValObjectKind::ObjFromU64);
                assert_eq!(args.as_slice(), &[v(0)]);
            }
            other => panic!("expected ValObject, got {other:?}"),
        }
        assert_eq!(func.bindings.get(v(1)).unwrap().ty, IrType::Known(KnownType::Val));
    }

    #[test]
    fn obj_to_i128_hi64_typed_i64() {
        // obj_to_i128_hi64 (export "8") returns i64 per the ABI.
        let mut func = func_with(vec![i64c(0), host_i("8", vec![v(0)])]);
        let (changed, _) = run(&mut func);
        assert!(changed);
        assert_eq!(func.bindings.get(v(1)).unwrap().ty, IrType::Known(KnownType::I64));
    }

    #[test]
    fn i_module_arithmetic_not_recognized() {
        // i.n = u256_add is arithmetic, not a Val conversion — left alone.
        let mut func = func_with(vec![i64c(0), host_i("n", vec![v(0)])]);
        let (changed, _) = run(&mut func);
        assert!(!changed, "u256_add must stay Unknown (wide-arithmetic scope)");
    }

    // --- P4 decode + gate ---

    #[test]
    fn decode_recognized_only_with_tag_check_present() {
        // A function containing BOTH a tag check and a `>> 8`. The decode
        // is recognized because the gate (a tag check exists) is met.
        let mut func = func_with(vec![
            // tag check chain: v0 & 0xFF == 64
            i64c(0),                          // v0 val
            i32c(255),                        // v1
            bin(BinaryOp::BitAnd, v(0), v(1)), // v2
            i32c(64),                         // v3
            bin(BinaryOp::Eq, v(2), v(3)),    // v4 tag check
            // decode: v5 = v0 >> v6(8)
            i64c(8),                          // v5 shift
            bin(BinaryOp::Shr, v(0), v(5)),   // v6 decode root
        ]);
        let (changed, metrics) = run(&mut func);
        assert!(changed);
        assert_eq!(metrics.get(M_TAG_CHECK), Some(1));
        assert_eq!(metrics.get(M_DECODE), Some(1));
        match expr_at(&func, v(6)) {
            Expr::Semantic(SemanticOp::Known(KnownOp::ValDecodeSmall { value })) => {
                assert_eq!(*value, v(0));
            }
            other => panic!("expected ValDecodeSmall, got {other:?}"),
        }
        // No type claim on decode — stays Unknown.
        assert!(matches!(
            func.bindings.get(v(6)).unwrap().ty,
            IrType::Unknown(_)
        ));
    }

    #[test]
    fn decode_not_recognized_without_gate() {
        // A `>> 8` in a function with NO tag check must be left alone.
        let mut func = func_with(vec![i64c(0), i64c(8), bin(BinaryOp::Shr, v(0), v(1))]);
        let (changed, _) = run(&mut func);
        assert!(!changed, "bare shr without a tag check must not be recognized");
    }

    // --- monotonicity / idempotency ---

    #[test]
    fn second_run_reports_no_change() {
        let mut func = func_with(vec![
            i64c(0),
            i64c(8),
            bin(BinaryOp::Shl, v(0), v(1)),
            i64c(6),
            bin(BinaryOp::BitOr, v(2), v(3)),
        ]);
        let (first, _) = run(&mut func);
        assert!(first);
        let (second, _) = run(&mut func);
        assert!(!second, "idempotent: nothing new to recognize on rerun");
    }

    #[test]
    fn feeder_bindings_left_untouched() {
        // The inner shl (v2) and tag const (v3) stay as they were —
        // recognition annotates the root, it does not remove feeders.
        let mut func = func_with(vec![
            i64c(0),
            i64c(8),
            bin(BinaryOp::Shl, v(0), v(1)),
            i64c(6),
            bin(BinaryOp::BitOr, v(2), v(3)),
        ]);
        run(&mut func);
        assert!(matches!(expr_at(&func, v(2)), Expr::Binary { op: BinaryOp::Shl, .. }));
        assert!(matches!(expr_at(&func, v(3)), Expr::Literal(Literal::I64(6))));
    }
}
