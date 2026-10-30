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
//! Equal width is not enough for a one- or two-byte load either: the
//! store keeps the value's low bytes and the load extends them to its own
//! word, so the read is the value only when the value fits and is in that
//! word. Such a load is forwarded only from a value that provably reads
//! back as itself — a fitting constant, the same read, a test, or a
//! helper's component that is a fitting constant on every return
//! ([`reads_back_unchanged`] says why each is exact). Anything else stays
//! a load.
//!
//! A four-byte read into a 64-bit word (`i64.load32_u` after a 32-bit
//! store) has the same word gap and is still forwarded as the stored
//! value: what reads it back today takes the 32-bit value, and turning
//! those reads into loads was measured to cost holes and an error with
//! nothing gained. Spelling its zero extension is the exact form, left
//! for when a site needs it.
//!
//! The store is left in place. It becomes dead once nothing reads the
//! slot, and [`super::frame`] is what collects dead frame slots.

use std::collections::HashMap;

use sordec_common::FuncId;
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
        let constants = constant_components(ir);
        for func in &mut ir.functions {
            let elisions = plan(func, &constants);
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

/// For each helper's return component that is an integer constant on every
/// return: the smallest and largest constant, and whether they are 64-bit
/// words. A sub-word read of such a component, stored by the caller, reads
/// one of those constants back ([`reads_back_unchanged`]).
type ConstantComponents = HashMap<(FuncId, usize), (i128, i128, bool)>;

fn constant_components(ir: &HighIr) -> ConstantComponents {
    let mut table = ConstantComponents::new();
    for func in &ir.functions {
        let Some(arity) = func.returns.first().map(Vec::len) else {
            continue;
        };
        if func.returns.iter().any(|site| site.len() != arity) {
            continue;
        }
        for index in 0..arity {
            let mut range: Option<(i128, i128, bool)> = None;
            let constant_everywhere = func.returns.iter().all(|site| {
                let Some((n, wide)) = func
                    .bindings
                    .get(resolve_use(func, site[index]))
                    .and_then(|b| int_literal(&b.expr))
                else {
                    return false;
                };
                range = match range {
                    None => Some((n, n, wide)),
                    Some((lo, hi, w)) if w == wide => Some((lo.min(n), hi.max(n), w)),
                    Some(_) => return false,
                };
                true
            });
            if constant_everywhere && let Some(r) = range {
                table.insert((func.id, index), r);
            }
        }
    }
    table
}

/// An integer literal's value, and whether it is a 64-bit word.
fn int_literal(expr: &Expr) -> Option<(i128, bool)> {
    match expr {
        Expr::Literal(Literal::I32(n)) => Some((i128::from(*n), false)),
        Expr::Literal(Literal::U32(n)) => Some((i128::from(*n), false)),
        Expr::Literal(Literal::I64(n)) => Some((i128::from(*n), true)),
        Expr::Literal(Literal::U64(n)) => Some((i128::from(*n), true)),
        _ => None,
    }
}

fn plan(func: &HighFunction, constants: &ConstantComponents) -> Vec<Elision> {
    let mut elisions = Vec::new();
    for (_, block) in func.blocks.iter() {
        for &id in &block.bindings {
            let Some(binding) = func.bindings.get(id) else {
                continue;
            };
            let Expr::Load { addr, offset, width, signed, ty: word } = &binding.expr else {
                continue;
            };
            let (base, off) = canon_addr(func, *addr);
            let Some(total) = off.checked_add(*offset) else {
                continue;
            };
            let facts = facts_at(func, id, base);
            if let Some(value) = facts.value_at(total, *width) {
                let value = resolve_use(func, value);
                if width.bytes() < 4 && !reads_back_unchanged(func, constants, value, *width, *signed, word) {
                    continue;
                }
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

/// Whether a sub-word load of the slot `value` was stored into reads
/// `value` back, unchanged and in the same machine word.
///
/// A sub-word store keeps only the low bytes, and the load extends them to
/// its own word: `store8 fp <- x` then `i64.load8_u fp` is
/// `(x & 0xff) as u64`, which is `x` only when `x` fits in a byte and is
/// already a 64-bit word. Forwarded as `x` regardless, a byte rustc carries
/// in an `i32` came out an `i32` where the read is an `i64`, and the
/// truncation was silently assumed away. So the forward is kept for the
/// values that provably read back as themselves:
///
/// - a constant that fits the read (zero- or sign-extended as the load
///   is), which is the same number whatever word the constant was written
///   in;
/// - a load of the same width, extension and word — the same read again;
/// - a test (a comparison, `eqz`, a tag check), which is the `i32` `0` or
///   `1`, read back by a load whose word is `i32`;
/// - a component of a helper's result that is a constant on every return
///   — the tag byte a converted out-parameter helper hands back — when
///   every such constant fits the read and is in the load's word.
///
/// Anything else stays a load. Why it is exact: each kept case reads back
/// the stored number in the load's own word, so the read and the value are
/// one number of one type.
fn reads_back_unchanged(
    func: &HighFunction,
    constants: &ConstantComponents,
    value: sordec_common::ValueId,
    width: MemWidth,
    signed: Option<bool>,
    word: &IrType,
) -> bool {
    let Some(binding) = func.bindings.get(value) else {
        return false;
    };
    let bits = 8 * width.bytes();
    let fits = |n: i128| {
        if signed == Some(true) {
            let half = 1i128 << (bits - 1);
            (-half..half).contains(&n)
        } else {
            (0..1i128 << bits).contains(&n)
        }
    };
    match &binding.expr {
        Expr::Literal(Literal::Bool(b)) => fits(i128::from(*b)),
        Expr::Literal(_) => int_literal(&binding.expr).is_some_and(|(n, _)| fits(n)),
        Expr::Load { width: w, signed: s, ty, .. } => *w == width && *s == signed && ty == word,
        Expr::Project { value: call, index } => {
            let Some(Expr::Call { target, .. }) = func.bindings.get(resolve_use(func, *call)).map(|b| &b.expr) else {
                return false;
            };
            constants.get(&(*target, *index as usize)).is_some_and(|&(lo, hi, wide)| {
                fits(lo) && fits(hi) && wide == matches!(word, IrType::Known(KnownType::I64))
            })
        }
        Expr::Binary { op, .. } if op.is_comparison() => is_i32_word(word),
        Expr::Unary { op: sordec_ir::UnaryOp::Eqz, .. }
        | Expr::Semantic(sordec_ir::SemanticOp::Known(sordec_ir::KnownOp::ValTagCheck { .. })) => is_i32_word(word),
        _ => false,
    }
}

fn is_i32_word(word: &IrType) -> bool {
    matches!(word, IrType::Known(KnownType::I32))
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

    fn byte_load(addr: ValueId, word: KnownType) -> Expr {
        Expr::Load { addr, offset: 0, width: MemWidth::W1, signed: Some(false), ty: IrType::Known(word) }
    }

    fn byte_store(addr: ValueId, value: ValueId) -> Expr {
        Expr::Store { addr, value, offset: 0, width: MemWidth::W1 }
    }

    /// `store8 fp <- x; i64.load8_u fp` is `(x & 0xff) as u64`, not `x`.
    #[test]
    fn a_byte_read_of_a_runtime_value_stays_a_load() {
        let f = func_with(
            vec![
                Expr::Phi { incoming: vec![] },
                Expr::Phi { incoming: vec![] },
                byte_store(v(0), v(1)),
                byte_load(v(0), KnownType::I64),
            ],
            vec![v(0), v(1)],
            vec![2, 3],
        );
        let mut m = module(vec![f]);
        assert!(!FrameForwardPass.run(&mut m).changed);
    }

    /// A helper `f` returning `(255, x)` or `(1, y)`: its first component is
    /// a byte on every path, so `store8 fp <- t.0; i32.load8_u fp` is `t.0`.
    /// Its second is not a constant, and stays a load.
    fn tag_helper_and_caller(word: KnownType) -> HighIr {
        let mut helper = func_with(
            vec![
                Expr::Phi { incoming: vec![] },  // v0 x
                Expr::Literal(Literal::I32(255)), // v1
                Expr::Literal(Literal::I32(1)),   // v2
            ],
            vec![v(0)],
            vec![1, 2],
        );
        helper.id = sordec_common::FuncId::from_index(1);
        helper.returns = vec![vec![v(1), v(0)], vec![v(2), v(0)]];
        let caller = func_with(
            vec![
                Expr::Phi { incoming: vec![] },                                                // v0 fp
                Expr::Call { target: sordec_common::FuncId::from_index(1), args: vec![v(0)] }, // v1
                Expr::Project { value: v(1), index: 0 },                                       // v2
                Expr::Project { value: v(1), index: 1 },                                       // v3
                byte_store(v(0), v(2)),                                                        // v4
                byte_load(v(0), word.clone()),                                                 // v5
                Expr::Literal(Literal::I32(1)),                                                // v6
                Expr::Binary { op: BinaryOp::Add, lhs: v(0), rhs: v(6) },                      // v7 fp+1
                byte_store(v(7), v(3)),                                                        // v8
                byte_load(v(7), word),                                                         // v9
            ],
            vec![v(0)],
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
        );
        module(vec![caller, helper])
    }

    #[test]
    fn a_byte_read_of_a_constant_component_is_the_component() {
        let mut m = tag_helper_and_caller(KnownType::I32);
        assert!(FrameForwardPass.run(&mut m).changed);
        assert!(matches!(expr_at(&m, 5), Expr::Use(x) if *x == v(2)));
        assert!(matches!(expr_at(&m, 9), Expr::Load { .. }));
    }

    /// The same component read into a 64-bit word is an `i64`, not the
    /// helper's `i32`: declined.
    #[test]
    fn a_constant_component_read_into_another_word_stays_a_load() {
        let mut m = tag_helper_and_caller(KnownType::I64);
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
