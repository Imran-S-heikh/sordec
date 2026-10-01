//! Fold a load from a constant address into the byte it reads.
//!
//! A load whose address is a literal is reading the module's own
//! initialized data — `62` of the held-out corpus's loads are this, and
//! every one renders as `todo!("load 1048576+0 width W4")`, a hole over a
//! value that is sitting in the data section.
//!
//! ```text
//! v6 = load 1048576 width 4        ← the discriminant of a `#[contracttype]`
//!                                    value rustc put in rodata
//! match v6 { … }                   ← cannot fold, so every arm survives
//! ```
//!
//! ## The assumption, stated
//!
//! [`MemoryImage`](sordec_ir::MemoryImage) is the module's *initial*
//! image; wasm data segments carry no read-only flag, so "this byte still
//! holds what the segment put there" is an assumption rather than a proof.
//!
//! It is the same assumption this pipeline already rests on elsewhere:
//! [`resolve_bytes`](crate::dataflow::const_prop::Resolver::resolve_bytes)
//! reads symbol text straight out of the image, so every recovered
//! `Symbol` name already depends on rodata being rodata. Making it here
//! explicit rather than implicit is the only change in kind.
//!
//! What the pass does prove, module-wide, is the part that can be:
//!
//! - **No store to a constant address may touch the bytes read.** A
//!   `static mut` lives in a data segment too, and rustc writes it through
//!   a literal address exactly as it reads it. The held-out corpus has 19
//!   such stores, so this gate is load-bearing, not theoretical.
//! - **The whole width must come from one segment.** A read straddling two
//!   segments, or running off the end of one, is not a constant;
//!   [`MemoryImage::read`](sordec_ir::MemoryImage::read) returns `None`
//!   and the load stays.
//!
//! What it cannot prove is that no store through a *computed* pointer
//! aliases the range. Safe Rust cannot write through a `&'static`, and no
//! Soroban contract is compiled from anything else — but it is an
//! assumption, so a folded load is marked
//! [`ProvenanceSource::DataFlow`] with a note that names it, rather than
//! passed off as a fact read from the instruction stream.

use std::collections::BTreeSet;

use sordec_common::{Provenance, ProvenanceSource};
use sordec_ir::{Expr, HighIr, IrType, KnownType, Literal, MemWidth};

use crate::dataflow::canon_addr;
use crate::pass::{Pass, PassResult};

/// Pass name — also the provenance `pass` field for every fold.
pub const PASS_NAME: &str = "refine-const-load";

/// Loads folded to the constant they read.
const M_FOLDED: &str = crate::metrics_catalog::REFINE_CONST_LOADS_FOLDED;
/// Constant-address loads left alone because a constant-address store may
/// write the same bytes — the `static mut` case.
const M_MUTABLE: &str = crate::metrics_catalog::REFINE_CONST_LOADS_MUTABLE;
/// Constant-address loads left alone because no single data segment covers
/// the width: uninitialized memory, or a read across a segment boundary.
const M_UNCOVERED: &str = crate::metrics_catalog::REFINE_CONST_LOADS_UNCOVERED;

/// Replaces `load <literal>` with the bytes the data section puts there.
#[derive(Debug, Default, Clone, Copy)]
pub struct ConstLoadPass;

impl Pass<HighIr> for ConstLoadPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        // Decided over the whole module before anything is rewritten: a
        // store in one function makes a byte mutable for every reader of
        // it, so this cannot be a per-function judgement.
        let written = written_constants(ir);

        for index in 0..ir.functions.len() {
            let mut folds: Vec<(sordec_common::ValueId, Literal, IrType, u32)> = Vec::new();
            {
                let func = &ir.functions[index];
                for (id, binding) in func.bindings.iter() {
                    let Expr::Load { addr, offset, width, signed, .. } = &binding.expr else {
                        continue;
                    };
                    let Some(at) = const_address(func, *addr, *offset) else {
                        continue;
                    };
                    let bytes = u32::from(width_bytes(*width));
                    if overlaps(&written, at, bytes) {
                        result.metrics.increment(M_MUTABLE, 1);
                        continue;
                    }
                    let Some(raw) = ir.memory.read(at, bytes) else {
                        result.metrics.increment(M_UNCOVERED, 1);
                        continue;
                    };
                    let (lit, ty) = decode(raw, *width, *signed);
                    folds.push((id, lit, ty, at));
                }
            }
            let func = &mut ir.functions[index];
            for (id, lit, ty, at) in folds {
                let Some(binding) = func.bindings.get_mut(id) else {
                    continue;
                };
                binding.expr = Expr::Literal(lit);
                binding.ty = ty;
                binding.add_provenance(Provenance::new(
                    PASS_NAME,
                    ProvenanceSource::DataFlow,
                    format!(
                        "constant at {at:#x}, read from the module's data section \
                         (no constant-address store writes it; segments assumed \
                         read-only, as symbol-text recovery already assumes)"
                    ),
                ));
                result.metrics.increment(M_FOLDED, 1);
                result.changed = true;
            }
        }
        result
    }
}

/// Byte ranges any store writes through a literal address.
///
/// Half-open `(start, end)` pairs. A `static mut` is written this way and
/// read the same way, so these are exactly the bytes a fold must not
/// claim are constant.
fn written_constants(ir: &HighIr) -> Vec<(u32, u32)> {
    let mut ranges: BTreeSet<(u32, u32)> = BTreeSet::new();
    for func in &ir.functions {
        for (_, binding) in func.bindings.iter() {
            let Expr::Store { addr, offset, width, .. } = &binding.expr else {
                continue;
            };
            let Some(at) = const_address(func, *addr, *offset) else {
                continue;
            };
            ranges.insert((at, at.saturating_add(u32::from(width_bytes(*width)))));
        }
    }
    ranges.into_iter().collect()
}

/// The literal address a memory operand names, or `None` when its base is
/// anything but a constant.
fn const_address(
    func: &sordec_ir::HighFunction,
    addr: sordec_common::ValueId,
    offset: u32,
) -> Option<u32> {
    let (base, delta) = canon_addr(func, addr);
    let Expr::Literal(lit) = &func.bindings.get(base)?.expr else {
        return None;
    };
    let literal = match lit {
        Literal::I32(n) => u32::try_from(*n).ok()?,
        Literal::U32(n) => *n,
        Literal::I64(n) => u32::try_from(*n).ok()?,
        Literal::U64(n) => u32::try_from(*n).ok()?,
        _ => return None,
    };
    literal.checked_add(delta).and_then(|a| a.checked_add(offset))
}

/// Whether `[at, at + len)` meets any written range.
fn overlaps(written: &[(u32, u32)], at: u32, len: u32) -> bool {
    let end = at.saturating_add(len);
    written.iter().any(|&(lo, hi)| at < hi && lo < end)
}

const fn width_bytes(width: MemWidth) -> u8 {
    match width {
        MemWidth::W1 => 1,
        MemWidth::W2 => 2,
        MemWidth::W4 => 4,
        MemWidth::W8 => 8,
    }
}

/// The literal `bytes` holds at `width`, with the load's own sign
/// extension applied.
///
/// A sub-word load is `i32`-shaped in wasm, so an unsigned one widens and a
/// signed one sign-extends — getting this backwards is how a `-1` discriminant
/// becomes `255`.
fn decode(bytes: &[u8], width: MemWidth, signed: Option<bool>) -> (Literal, IrType) {
    let mut buf = [0u8; 8];
    buf[..bytes.len()].copy_from_slice(bytes);
    let raw = u64::from_le_bytes(buf);
    match width {
        MemWidth::W8 => (Literal::I64(raw as i64), IrType::Inferred(KnownType::I64)),
        MemWidth::W4 if signed == Some(false) => {
            (Literal::U32(raw as u32), IrType::Inferred(KnownType::U32))
        }
        MemWidth::W4 => (Literal::I32(raw as u32 as i32), IrType::Inferred(KnownType::I32)),
        MemWidth::W2 => {
            let v = raw as u16;
            let n = if signed == Some(true) { i32::from(v as i16) } else { i32::from(v) };
            (Literal::I32(n), IrType::Inferred(KnownType::I32))
        }
        MemWidth::W1 => {
            let v = raw as u8;
            let n = if signed == Some(true) { i32::from(v as i8) } else { i32::from(v) };
            (Literal::I32(n), IrType::Inferred(KnownType::I32))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, module, store, v};
    use sordec_ir::{DataSegment, MemoryImage};

    fn with_segment(mut ir: HighIr, offset: u32, bytes: Vec<u8>) -> HighIr {
        ir.memory = MemoryImage::from_segments(vec![DataSegment { offset, bytes }]);
        ir
    }

    /// The whole point: a load off a literal address is the byte the data
    /// section put there.
    #[test]
    fn a_load_from_rodata_is_the_byte_it_reads() {
        let ir = module(vec![func_with(
            vec![
                Expr::Literal(Literal::I32(1024)),
                Expr::Load {
                    addr: v(0),
                    offset: 0,
                    width: MemWidth::W4,
                    signed: Some(false),
                    ty: IrType::Unknown(sordec_common::UnknownReason::InsufficientEvidence),
                },
            ],
            vec![],
            (0..2).collect(),
        )]);
        let mut ir = with_segment(ir, 1024, vec![7, 0, 0, 0]);

        assert!(ConstLoadPass.run(&mut ir).changed, "the gate passes");
        let func = ir.functions.first().expect("one function");
        assert!(
            matches!(
                func.bindings.get(v(1)).expect("the load").expr,
                Expr::Literal(Literal::U32(7))
            ),
            "folded to the little-endian word at 1024"
        );
    }

    /// The half that matters. A `static mut` is written through a literal
    /// address and read through one, so its initial bytes are not its
    /// value and folding them would invent a fact.
    #[test]
    fn a_byte_some_store_writes_is_not_constant() {
        let ir = module(vec![func_with(
            vec![
                Expr::Literal(Literal::I32(1024)),
                Expr::Literal(Literal::I64(99)),
                store(v(0), v(1), 0),
                Expr::Load {
                    addr: v(0),
                    offset: 0,
                    width: MemWidth::W4,
                    signed: Some(false),
                    ty: IrType::Unknown(sordec_common::UnknownReason::InsufficientEvidence),
                },
            ],
            vec![],
            (0..4).collect(),
        )]);
        let mut ir = with_segment(ir, 1024, vec![7, 0, 0, 0]);

        let result = ConstLoadPass.run(&mut ir);
        assert!(!result.changed, "a written byte is not a constant");
        assert_eq!(result.metrics.get(M_MUTABLE), Some(1), "and it says why");
    }

    /// A read the image does not cover is not a constant either — and it
    /// is counted apart, because "nothing is there" and "something writes
    /// it" want different work.
    #[test]
    fn a_read_past_the_segment_declines_separately() {
        let ir = module(vec![func_with(
            vec![
                Expr::Literal(Literal::I32(1024)),
                Expr::Load {
                    addr: v(0),
                    offset: 2,
                    width: MemWidth::W4,
                    signed: Some(false),
                    ty: IrType::Unknown(sordec_common::UnknownReason::InsufficientEvidence),
                },
            ],
            vec![],
            (0..2).collect(),
        )]);
        let mut ir = with_segment(ir, 1024, vec![7, 0, 0, 0]);

        let result = ConstLoadPass.run(&mut ir);
        assert!(!result.changed, "the last two bytes are uninitialized");
        assert_eq!(result.metrics.get(M_UNCOVERED), Some(1));
    }

    /// Sign extension follows the load's own opcode: a `load8_s` of `0xFF`
    /// is `-1`, not `255`.
    #[test]
    fn a_signed_sub_word_load_sign_extends() {
        let ir = module(vec![func_with(
            vec![
                Expr::Literal(Literal::I32(1024)),
                Expr::Load {
                    addr: v(0),
                    offset: 0,
                    width: MemWidth::W1,
                    signed: Some(true),
                    ty: IrType::Unknown(sordec_common::UnknownReason::InsufficientEvidence),
                },
            ],
            vec![],
            (0..2).collect(),
        )]);
        let mut ir = with_segment(ir, 1024, vec![0xFF]);

        assert!(ConstLoadPass.run(&mut ir).changed);
        let func = ir.functions.first().expect("one function");
        assert!(
            matches!(
                func.bindings.get(v(1)).expect("the load").expr,
                Expr::Literal(Literal::I32(-1))
            ),
            "0xFF read as a signed byte is -1"
        );
    }
}
