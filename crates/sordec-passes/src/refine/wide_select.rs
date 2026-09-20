//! Read a choice between two 128-bit values back off its limbs.
//!
//! Wasm has no 128-bit type and `select` picks one register, so a source
//! line choosing between two `i128`s compiles to *two* selects sharing a
//! condition — one per limb:
//!
//! ```text
//! lo = select(lo(a), lo(b), c)          r  = if c { a } else { b }
//! hi = select(hi(a), hi(b), c)     →    lo = wide_lo(r)
//!                                       hi = wide_hi(r)
//! ```
//!
//! Unrecovered, that is two holes where dex's `swap` writes
//!
//! ```ignore
//! let (reserve_sell, reserve_buy) = if buy_a { (b, a) } else { (a, b) };
//! ```
//!
//! — and, worse, *no* control flow at all against a source that has an
//! `if`. It is the one place the structure measure marks us down for
//! recovering too little rather than too much.
//!
//! # Why the choice is an expression, not a branch
//!
//! There is no branch in the binary: both arms are computed and one is
//! picked. Recovering a [`Region::If`](sordec_ir::Region) would claim a
//! control-flow edge the wasm does not have, and would need a merge
//! parameter to carry the result. [`Expr::Select`] says exactly what
//! happened — and renders as the `if`/`else` *expression* the source
//! wrote, which is also how rustc came to emit a `select`.
//!
//! # Why it is exact
//!
//! Per limb. The two selects share one condition, so they resolve the
//! same way on any execution; on the true side the pair is the two
//! halves of one value and on the false side the two halves of another.
//! Choosing between the values and then splitting is choosing between
//! the splits.
//!
//! # Gates
//!
//! - **One condition**, tested by identity after renames.
//! - **Each side is an operand**: both limbs are halves of one value, or
//!   both are loose registers to be joined ([`super::wide`]).
//! - **Low with low, high with high.** Wasm's `select` puts the
//!   if-true arm first, so the pairing is read off the argument order
//!   rather than assumed.
//! - **The operands are in hand** where the first limb is, since that is
//!   where the recovered choice has to be named.

use sordec_common::{IrId, Provenance, ProvenanceSource, ValueId};
use sordec_ir::{
    Binding, Expr, HighFunction, HighIr, IrType, KnownType, UnaryOp, WasmOpcodeKind,
};

use super::wide::{available_before, materialize, paired, Side};
use crate::dataflow::resolve_use;
use crate::metrics_catalog::REFINE_WIDE_SELECTS as M_SELECTS;
use crate::pass::{Pass, PassResult};

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "refine-wide-select";

/// Names the 128-bit value a pair of limb selects chooses.
#[derive(Debug, Default, Clone, Copy)]
pub struct WideSelectPass;

/// One recovered choice: the two limb selects and what they choose.
struct Found {
    lo: ValueId,
    hi: ValueId,
    cond: ValueId,
    if_true: Side,
    if_false: Side,
}

impl Pass<HighIr> for WideSelectPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        for func in &mut ir.functions {
            for f in pairs(func) {
                let order = crate::marshalling::sret::emission_order(func);
                let at = |v: ValueId| order.iter().position(|o| *o == v);
                let Some((first_pos, first)) =
                    [f.lo, f.hi].into_iter().filter_map(|v| at(v).map(|p| (p, v))).min()
                else {
                    continue;
                };
                if !available_before(&order, &[f.if_true, f.if_false], first_pos) {
                    continue;
                }
                let base = ValueId::from_index(func.bindings.len() as u32);
                let if_true = materialize(func, f.if_true, PASS_NAME);
                let if_false = materialize(func, f.if_false, PASS_NAME);
                let note = Provenance::new(
                    PASS_NAME,
                    ProvenanceSource::DataFlow,
                    "the value these two limb selects choose between",
                );
                let whole = ValueId::from_index(func.bindings.len() as u32);
                func.bindings.push(Binding::new(
                    whole,
                    IrType::Inferred(KnownType::I128),
                    Expr::Select { cond: f.cond, if_true, if_false },
                    note.clone(),
                ));
                // Reverse order, because each insertion pushes the last
                // one right: the operands end up ahead of the choice.
                let fresh: Vec<ValueId> = std::iter::once(whole)
                    .chain([if_false, if_true].into_iter().filter(|v| *v >= base))
                    .collect();
                for (_, block) in func.blocks.iter_mut() {
                    if let Some(pos) = block.bindings.iter().position(|v| *v == first) {
                        for v in &fresh {
                            block.bindings.insert(pos, *v);
                        }
                        break;
                    }
                }
                for (id, op) in [(f.lo, UnaryOp::WideLo), (f.hi, UnaryOp::WideHi)] {
                    if let Some(b) = func.bindings.get_mut(id) {
                        b.expr = Expr::Unary { op, value: whole };
                        b.add_provenance(note.clone());
                    }
                }
                result.metrics.increment(M_SELECTS, 1);
                result.changed = true;
            }
        }
        result
    }
}

/// Every pair of limb selects sharing one condition.
fn pairs(func: &HighFunction) -> Vec<Found> {
    let selects: Vec<(ValueId, [ValueId; 3])> =
        func.bindings.iter().filter_map(|(id, b)| arms(func, &b.expr).map(|a| (id, a))).collect();
    let mut taken: Vec<ValueId> = Vec::new();
    let mut found = Vec::new();
    for (i, (lo, lo_arms)) in selects.iter().enumerate() {
        if taken.contains(lo) {
            continue;
        }
        for (hi, hi_arms) in &selects[i + 1..] {
            // One condition, and the arms in the order `select` gives
            // them: if-true first.
            if taken.contains(hi) || lo_arms[2] != hi_arms[2] {
                continue;
            }
            let (Some(if_true), Some(if_false)) = (
                paired(func, lo_arms[0], hi_arms[0]),
                paired(func, lo_arms[1], hi_arms[1]),
            ) else {
                continue;
            };
            // A pair that is the same value on both sides is not a
            // choice; something else built it.
            if matches!((if_true, if_false), (Side::Whole(a), Side::Whole(b)) if a == b) {
                continue;
            }
            taken.push(*lo);
            taken.push(*hi);
            found.push(Found {
                lo: *lo,
                hi: *hi,
                cond: lo_arms[2],
                if_true,
                if_false,
            });
            break;
        }
    }
    found
}

/// The `[if_true, if_false, cond]` of a `select`, resolved.
fn arms(func: &HighFunction, expr: &Expr) -> Option<[ValueId; 3]> {
    let Expr::Unknown { op_kind: WasmOpcodeKind::Select, args, .. } = expr else {
        return None;
    };
    let [t, f, c] = args.as_slice() else {
        return None;
    };
    Some([resolve_use(func, *t), resolve_use(func, *f), resolve_use(func, *c)])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, module, v};
    use sordec_common::UnknownReason;

    /// Two selects on one condition, each choosing a limb.
    fn shape(same_cond: bool) -> HighIr {
        let select = |t: ValueId, f: ValueId, c: ValueId| Expr::Unknown {
            op_kind: WasmOpcodeKind::Select,
            args: vec![t, f, c],
            reason: UnknownReason::UnsupportedPattern,
        };
        module(vec![func_with(
            vec![
                Expr::Phi { incoming: vec![] },                     // v0 lo of a
                Expr::Phi { incoming: vec![] },                     // v1 hi of a
                Expr::Phi { incoming: vec![] },                     // v2 lo of b
                Expr::Phi { incoming: vec![] },                     // v3 hi of b
                Expr::Phi { incoming: vec![] },                     // v4 the condition
                Expr::Phi { incoming: vec![] },                     // v5 another condition
                select(v(0), v(2), v(4)),                           // v6 low
                select(v(1), v(3), if same_cond { v(4) } else { v(5) }), // v7 high
            ],
            vec![v(0), v(1), v(2), v(3), v(4), v(5)],
            vec![6, 7],
        )])
    }

    #[test]
    fn two_limb_selects_are_one_choice() {
        let mut m = shape(true);
        assert!(WideSelectPass.run(&mut m).changed);
        let f = &m.functions[0];
        let Expr::Unary { op: UnaryOp::WideLo, value: whole } = f.bindings.get(v(6)).unwrap().expr
        else {
            panic!("the low limb names its half");
        };
        assert!(matches!(
            f.bindings.get(v(7)).unwrap().expr,
            Expr::Unary { op: UnaryOp::WideHi, value } if value == whole
        ));
        let Expr::Select { cond, if_true, if_false } = f.bindings.get(whole).unwrap().expr else {
            panic!("the whole is the choice");
        };
        assert_eq!(cond, v(4));
        assert!(matches!(
            f.bindings.get(if_true).unwrap().expr,
            Expr::WideJoin { lo, hi } if lo == v(0) && hi == v(1)
        ));
        assert!(matches!(
            f.bindings.get(if_false).unwrap().expr,
            Expr::WideJoin { lo, hi } if lo == v(2) && hi == v(3)
        ));
    }

    /// Two conditions are two choices, not one over a wide value.
    #[test]
    fn selects_on_different_conditions_are_left_alone() {
        let mut m = shape(false);
        assert!(!WideSelectPass.run(&mut m).changed);
    }

    #[test]
    fn the_pass_is_idempotent() {
        let mut m = shape(true);
        assert!(WideSelectPass.run(&mut m).changed);
        assert!(!WideSelectPass.run(&mut m).changed);
    }
}
