//! Forward a frame store to the load that reads it back, within a block.
//!
//! The lifted layer's `StoreForwardPass` and `SlotPromotionPass` do this
//! job before any recognizer runs, and they cannot do it again afterward.
//! The marshalling elisions then create exactly the shape they would have
//! removed: a decode collapse turns `store fp+0 <- t.0` into
//! `store fp+0 <- 0`, an encode collapse turns the value a wrapper stores
//! into a wide join, and the load that reads the slot back is still a
//! load. Left there, the constant never reaches the guard that compares
//! it, so the guard survives as a real branch and the wrapper it sits in
//! is never trivial enough to inline.
//!
//! This pass is the missing second application, on the high IR:
//!
//! ```text
//! store fp <- 0i64 offset=0        store fp <- 0i64 offset=0   (dead once unread)
//! …                          →     …
//! load fp offset=0                 0
//! ```
//!
//! ## Soundness
//!
//! Every fact comes from [`crate::dataflow::frame_facts`], whose kill
//! discipline is the whole argument: a store to a different base may
//! alias and kills everything, any call may write through an escaped
//! pointer and kills everything, and facts are position-sensitive. A load
//! is forwarded only when a store of the **same base, same offset and same
//! width** reaches it along the blocks that dominate it, with nothing on
//! the way that may write memory. [`facts_at`] walks the region tree to
//! find those blocks: a branch arm, a loop or a scope with an early exit
//! that the path does not pass through contributes no facts, and kills
//! them all if it may write.
//!
//! Width is exact with one exception: a narrower load of a slot holding a
//! *literal* becomes the truncated literal, because rustc reads a
//! `Result` discriminant it wrote as `i64` back as `i32` and the value is
//! known bit-for-bit. A narrower load of a runtime value is declined —
//! spelling the truncation would need a cast the IR does not carry.
//!
//! The store is left in place. It becomes dead once nothing reads the
//! slot, and [`super::frame`] is what collects dead frame slots.

use sordec_ir::{Expr, HighFunction, HighIr, IrType, KnownType, Literal, MemWidth};

use super::{apply_elisions, metrics, Elision};
use crate::dataflow::frame_facts::facts_at;
use crate::dataflow::{canon_addr, resolve_use};
use crate::pass::{Pass, PassResult};

/// Pass name — also the provenance `pass` field for every elision.
pub const PASS_NAME: &str = "marshalling-frame-forward";

/// Forwards block-local frame stores to their loads on the high IR.
#[derive(Debug, Default, Clone, Copy)]
pub struct FrameForwardPass;

impl Pass<HighIr> for FrameForwardPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        for func in &mut ir.functions {
            let elisions = plan(func);
            if elisions.is_empty() {
                continue;
            }
            result.changed = true;
            result.metrics.increment(metrics::FRAME_LOADS_FORWARDED, elisions.len() as i64);
            apply_elisions(func, PASS_NAME, elisions);
        }
        result
    }
}

fn plan(func: &HighFunction) -> Vec<Elision> {
    let mut elisions = Vec::new();
    for (_, block) in func.blocks.iter() {
        for &id in &block.bindings {
            let Some(binding) = func.bindings.get(id) else {
                continue;
            };
            let Expr::Load { addr, offset, width, .. } = &binding.expr else {
                continue;
            };
            let (base, off) = canon_addr(func, *addr);
            let Some(total) = off.checked_add(*offset) else {
                continue;
            };
            let facts = facts_at(func, id, base);
            if let Some(value) = facts.value_at(total, *width) {
                let value = resolve_use(func, value);
                elisions.push(Elision {
                    id,
                    expr: Expr::Use(value),
                    ty: None,
                    note: "frame load forwarded from the store that reaches it".to_string(),
                    metric: metrics::FRAME_LOADS_FORWARDED,
                });
            } else if let Some(value) = facts.value_at_trunc(total, *width)
                && let Some(lit) = truncated_literal(func, value, *width, &binding.ty)
            {
                elisions.push(Elision {
                    id,
                    expr: Expr::Literal(lit),
                    ty: None,
                    note: "narrow frame load of a stored constant, truncated".to_string(),
                    metric: metrics::FRAME_LOADS_FORWARDED,
                });
            }
        }
    }
    elisions
}

/// The literal a narrower load of `value` reads, when `value` is a
/// constant. `None` for anything else — a runtime value would need a cast.
fn truncated_literal(func: &HighFunction, value: sordec_common::ValueId, width: MemWidth, ty: &IrType) -> Option<Literal> {
    let n = crate::dataflow::trace_int(func, value)?;
    Some(match width {
        MemWidth::W4 => match ty {
            IrType::Known(KnownType::U32) | IrType::Inferred(KnownType::U32) => Literal::U32(n as u32),
            _ => Literal::I32(n as i32),
        },
        MemWidth::W8 => Literal::I64(n as i64),
        // Sub-word reads of a constant: the value is known, but their
        // sign/zero extension is a fact of the load this does not carry.
        MemWidth::W1 | MemWidth::W2 => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, load, module, store, v};
    use sordec_common::{IrId, UnknownReason, ValueId};
    use sordec_ir::BinaryOp;

    fn narrow_load(addr: ValueId, offset: u32) -> Expr {
        Expr::Load {
            addr,
            offset,
            width: MemWidth::W4,
            signed: None,
            ty: IrType::Unknown(UnknownReason::InsufficientEvidence),
        }
    }

    fn expr_at(ir: &HighIr, value: u32) -> &Expr {
        &ir.functions[0].bindings.get(v(value)).unwrap().expr
    }

    /// `store fp+8 <- x; load fp offset=8` — same base, same slot, same width.
    #[test]
    fn a_reaching_store_is_forwarded_to_its_load() {
        let f = func_with(
            vec![
                Expr::Phi { incoming: vec![] },                              // v0 fp
                Expr::Phi { incoming: vec![] },                              // v1 x
                Expr::Literal(Literal::I32(8)),                              // v2
                Expr::Binary { op: BinaryOp::Add, lhs: v(0), rhs: v(2) },    // v3 fp+8
                store(v(3), v(1), 0),                                        // v4
                load(v(0), 8),                                               // v5
            ],
            vec![v(0), v(1)],
            vec![2, 3, 4, 5],
        );
        let mut m = module(vec![f]);
        let r = FrameForwardPass.run(&mut m);
        assert!(r.changed);
        assert!(matches!(expr_at(&m, 5), Expr::Use(x) if *x == v(1)));
    }

    /// A call between the store and the load may write through an escaped
    /// pointer, so the fact dies there.
    #[test]
    fn an_intervening_call_kills_the_fact() {
        let f = func_with(
            vec![
                Expr::Phi { incoming: vec![] },
                Expr::Phi { incoming: vec![] },
                store(v(0), v(1), 8),
                Expr::Call { target: sordec_common::FuncId::from_index(7), args: vec![v(0)] },
                load(v(0), 8),
            ],
            vec![v(0), v(1)],
            vec![2, 3, 4],
        );
        let mut m = module(vec![f]);
        assert!(!FrameForwardPass.run(&mut m).changed);
    }

    /// The discriminant shape: an `i64` store of a constant read back as
    /// `i32` becomes the truncated constant.
    #[test]
    fn a_narrow_load_of_a_stored_constant_becomes_the_constant() {
        let f = func_with(
            vec![
                Expr::Phi { incoming: vec![] },
                Expr::Literal(Literal::I64(0)),
                store(v(0), v(1), 0),
                narrow_load(v(0), 0),
            ],
            vec![v(0)],
            vec![1, 2, 3],
        );
        let mut m = module(vec![f]);
        assert!(FrameForwardPass.run(&mut m).changed);
        assert!(matches!(expr_at(&m, 3), Expr::Literal(Literal::I32(0))));
    }

    /// A narrow load of a runtime value would need a cast; declined.
    #[test]
    fn a_narrow_load_of_a_runtime_value_is_declined() {
        let f = func_with(
            vec![
                Expr::Phi { incoming: vec![] },
                Expr::Phi { incoming: vec![] },
                store(v(0), v(1), 0),
                narrow_load(v(0), 0),
            ],
            vec![v(0), v(1)],
            vec![2, 3],
        );
        let mut m = module(vec![f]);
        assert!(!FrameForwardPass.run(&mut m).changed);
    }

    #[test]
    fn the_pass_is_idempotent() {
        let f = func_with(
            vec![
                Expr::Phi { incoming: vec![] },
                Expr::Phi { incoming: vec![] },
                store(v(0), v(1), 8),
                load(v(0), 8),
            ],
            vec![v(0), v(1)],
            vec![2, 3],
        );
        let mut m = module(vec![f]);
        assert!(FrameForwardPass.run(&mut m).changed);
        assert!(!FrameForwardPass.run(&mut m).changed);
    }
}
