//! Read a 128-bit addition or subtraction back off its limbs.
//!
//! The multiply and divide arrive as calls to compiler-rt helpers and are
//! already recovered from those. Addition and subtraction are cheap
//! enough that rustc writes them out, one limb at a time, threading a
//! carry between:
//!
//! ```text
//! lo = lo(a) - lo(b)                             r  = a - b
//! hi = (hi(a) - hi(b)) - (lo(a) <u lo(b))   →    lo = wide_lo(r)
//!                                                hi = wide_hi(r)
//! ```
//!
//! Left in limbs it is the last thing holding several recognizers apart.
//! A helper handed `lo` and `hi` cannot be given the whole value, because
//! there is no whole value to give; the comparison the callee makes on it
//! stays a `select` over two unrelated registers; and the guard that
//! comparison feeds keeps the polarity wasm gave it.
//!
//! # Why it is exact
//!
//! This is the definition of the operation at twice the width: the low
//! limb wraps and the carry it produces is exactly the `<u` test rustc
//! writes, so the pair `(hi, lo)` is the two halves of `a ± b`. The
//! rewrite names that value and leaves each limb naming its own half of
//! it, so every reader sees what it saw.
//!
//! # Operands the function never named
//!
//! Often neither operand is a whole either: a balance is loaded out of
//! storage as two registers, an amount arrives in two parameters, and
//! nothing in the function ever puts them together. For a **difference**
//! the borrow settles it — `lo(a) <u lo(b)` names the two low limbs in
//! operand order, so which low limb goes with which high one is read off
//! the pattern rather than assumed, and each pair is joined into the
//! operand it is the halves of.
//!
//! A **sum** gets no such help: its carry compares the result against
//! one of the lows, and addition is symmetric in its low limbs, so a
//! loose pair could be split either way. Both splits give the same sum
//! and different operands, and naming the wrong two is naming values the
//! source never had — so a sum still requires operands the function
//! already names.
//!
//! # Which 128-bit type
//!
//! Wrapping addition and subtraction are the same bits signed or not, so
//! the limbs say nothing of sign. An operand the function already typed
//! does: `min_y - delta`, where `delta` is a `u128` an unsigned division
//! returned, is a `u128` subtraction, and its loose other operand is the
//! `u128` it is subtracted from. So the recovered value, and any operand
//! joined from loose limbs, take the 128-bit type the named operands agree
//! on; with none, or with two that disagree, `i128` as before.
//!
//! Why it is exact: the type changes no bit of any value. It only stops a
//! `u128` and the value computed from it being named as two types.
//!
//! # Gates
//!
//! - **Both limbs of both operands**, and the same two values throughout.
//! - **The carry is the one this addition produces**: `lo <u lo(b)` for a
//!   sum, `lo(a) <u lo(b)` for a difference. A carry from somewhere else
//!   makes this some other arithmetic.
//! - **The carry is zero-extended.** That is how a 1-bit flag becomes a
//!   limb, and anything else in that position is a value, not a carry.
//! - **A limb pairs with a limb of its own kind.** Half of one value
//!   beside half of another, or beside a loose register, is not a pair.
//! - **The operands are in hand before the first limb**, which is where
//!   the recovered value has to be named.

use sordec_common::{IrId, Provenance, ProvenanceSource, ValueId};
use sordec_ir::{BinaryOp, Binding, Expr, HighFunction, HighIr, IrType, KnownType, UnaryOp};

use super::wide::{Side, available_before, half_of, materialize, paired};
use crate::dataflow::resolve_use;
use crate::metrics_catalog::REFINE_WIDE_ARITH as M_ARITH;
use crate::pass::{Pass, PassResult};

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "refine-wide-arith";

/// Names the 128-bit sum or difference a limb pair computes.
#[derive(Debug, Default, Clone, Copy)]
pub struct WideArithPass;

/// One recovered operation.
struct Found {
    lo: ValueId,
    hi: ValueId,
    op: BinaryOp,
    a: Side,
    b: Side,
}

impl Pass<HighIr> for WideArithPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        for func in &mut ir.functions {
            let found: Vec<Found> =
                func.bindings.iter().filter_map(|(id, b)| limbs(func, id, &b.expr)).collect();
            for f in found {
                let note = Provenance::new(
                    PASS_NAME,
                    ProvenanceSource::DataFlow,
                    "the 128-bit value these two limbs compute",
                );
                // Before whichever limb the schedule reaches first: the
                // other one reads this value too, and rustc is free to
                // compute the high limb before the low.
                let order = crate::marshalling::sret::emission_order(func);
                let at = |v: ValueId| order.iter().position(|o| *o == v);
                let Some((first_pos, first)) = [f.lo, f.hi]
                    .into_iter()
                    .filter_map(|v| at(v).map(|p| (p, v)))
                    .min()
                else {
                    continue;
                };
                // Everything the operands are built from has to be in
                // hand by then. An operand computed between the two
                // limbs cannot be named before the first of them, and
                // naming it there anyway is a use before its definition.
                // (Nothing in the schedule is a parameter, and a
                // parameter is always in hand.)
                if !available_before(&order, &[f.a, f.b], first_pos) {
                    continue;
                }
                let ty = IrType::Inferred(wide_type(func, [f.a, f.b]));
                let base = ValueId::from_index(func.bindings.len() as u32);
                let lhs = materialize(func, f.a, PASS_NAME);
                let rhs = materialize(func, f.b, PASS_NAME);
                for joined in [lhs, rhs].into_iter().filter(|v| *v >= base) {
                    if let Some(b) = func.bindings.get_mut(joined) {
                        b.ty = ty.clone();
                    }
                }
                let whole = ValueId::from_index(func.bindings.len() as u32);
                func.bindings.push(Binding::new(whole, ty, Expr::Binary { op: f.op, lhs, rhs }, note.clone()));
                // Reverse order, because each insertion pushes the last
                // one right: the joins end up ahead of the value that
                // reads them.
                let fresh: Vec<ValueId> = std::iter::once(whole)
                    .chain([rhs, lhs].into_iter().filter(|v| *v >= base))
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
                result.metrics.increment(M_ARITH, 1);
                result.changed = true;
            }
        }
        result
    }
}

/// The 128-bit type the named operands agree on ("Which 128-bit type"):
/// `u128` or `i128` when every operand the function already names with
/// one of the two names the same, `i128` otherwise.
fn wide_type(func: &HighFunction, sides: [Side; 2]) -> KnownType {
    let mut agreed: Option<KnownType> = None;
    for side in sides {
        let Side::Whole(v) = side else { continue };
        let named = match func.bindings.get(resolve_use(func, v)).map(|b| &b.ty) {
            Some(IrType::Known(k) | IrType::Inferred(k)) if matches!(k, KnownType::U128 | KnownType::I128) => k.clone(),
            _ => continue,
        };
        if agreed.get_or_insert_with(|| named.clone()) != &named {
            return KnownType::I128;
        }
    }
    agreed.unwrap_or(KnownType::I128)
}

/// The operation a high limb completes, given the whole function.
///
/// Keyed on the *high* limb because that is where the carry appears, and
/// the carry is what says which low limb belongs to it.
fn limbs(func: &HighFunction, hi: ValueId, expr: &Expr) -> Option<Found> {
    // `(hi_a ± hi_b) ± carry`
    let Expr::Binary { op, lhs, rhs } = expr else {
        return None;
    };
    if !matches!(op, BinaryOp::Add | BinaryOp::Sub) {
        return None;
    }
    let carry = zero_extended(func, *rhs)?;
    let Expr::Binary { op: inner, lhs: hi_a, rhs: hi_b } =
        &func.bindings.get(resolve_use(func, *lhs))?.expr
    else {
        return None;
    };
    if inner != op {
        return None;
    }
    let (hi_a, hi_b) = (resolve_use(func, *hi_a), resolve_use(func, *hi_b));
    // The carry: the low limbs' unsigned comparison.
    let Expr::Binary { op: BinaryOp::LtU, lhs: c_l, rhs: c_r } =
        &func.bindings.get(resolve_use(func, carry))?.expr
    else {
        return None;
    };
    let (c_l, c_r) = (resolve_use(func, *c_l), resolve_use(func, *c_r));
    // For a difference the borrow compares the operands' low limbs, in
    // operand order — so it says which low limb goes with which high
    // one, and the pair is an operand whether or not the function
    // already names it. For a sum the carry compares the *result*
    // against one of the lows, which leaves the pairing open: addition
    // is symmetric in its low limbs, so a loose pair could be split
    // either way and name two values the source never had. There, only
    // an operand the function already names is admitted.
    let (a, b) = match op {
        BinaryOp::Sub => (paired(func, c_l, hi_a)?, paired(func, c_r, hi_b)?),
        _ => (
            Side::Whole(half_of(func, hi_a, UnaryOp::WideHi)?),
            Side::Whole(half_of(func, hi_b, UnaryOp::WideHi)?),
        ),
    };
    // And the low limb itself, computed from the same two operands.
    let lo = func.bindings.iter().find_map(|(id, bind)| {
        let Expr::Binary { op: low_op, lhs, rhs } = &bind.expr else {
            return None;
        };
        (low_op == op && a.has_lo(func, *lhs) && b.has_lo(func, *rhs)).then_some(id)
    })?;
    let carry_ok = match op {
        BinaryOp::Sub => true,
        _ => {
            c_l == lo
                && [a, b]
                    .iter()
                    .any(|side| side.has_lo(func, c_r) || matches!(side, Side::Whole(w) if *w == c_r))
        }
    };
    carry_ok.then_some(Found { lo, hi, op: *op, a, b })
}

/// The flag behind a zero-extension, which is how a carry becomes a limb.
fn zero_extended(func: &HighFunction, value: ValueId) -> Option<ValueId> {
    match &func.bindings.get(resolve_use(func, value))?.expr {
        Expr::Unary { op: UnaryOp::ExtendU32, value } => Some(resolve_use(func, *value)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, module, v};

    /// A difference whose operands the function never named: four loose
    /// registers, the borrow pairing them up.
    ///
    /// ```text
    /// v4 = v0 - v2                    v9  = join(v0, v1)
    /// v5 = v0 <u v2                   v10 = join(v2, v3)
    /// v6 = v1 - v3              →     v11 = v9 - v10
    /// v8 = v6 - extend(v5)            v4  = wide_lo(v11), v8 = wide_hi(v11)
    /// ```
    fn loose(op: BinaryOp, carry_lhs: u32) -> HighIr {
        module(vec![func_with(
            vec![
                Expr::Phi { incoming: vec![] },                              // v0 lo a
                Expr::Phi { incoming: vec![] },                              // v1 hi a
                Expr::Phi { incoming: vec![] },                              // v2 lo b
                Expr::Phi { incoming: vec![] },                              // v3 hi b
                Expr::Binary { op, lhs: v(0), rhs: v(2) },                   // v4 low
                Expr::Binary { op: BinaryOp::LtU, lhs: v(carry_lhs), rhs: v(2) }, // v5 carry
                Expr::Binary { op, lhs: v(1), rhs: v(3) },                   // v6
                Expr::Unary { op: UnaryOp::ExtendU32, value: v(5) },         // v7
                Expr::Binary { op, lhs: v(6), rhs: v(7) },                   // v8 high
            ],
            vec![v(0), v(1), v(2), v(3)],
            vec![4, 5, 6, 7, 8],
        )])
    }

    #[test]
    fn a_difference_over_loose_limbs_joins_its_operands() {
        let mut m = loose(BinaryOp::Sub, 0);
        assert!(WideArithPass.run(&mut m).changed);
        let f = &m.functions[0];
        let Expr::Unary { op: UnaryOp::WideLo, value: whole } = f.bindings.get(v(4)).unwrap().expr
        else {
            panic!("the low limb names its half");
        };
        assert!(matches!(
            f.bindings.get(v(8)).unwrap().expr,
            Expr::Unary { op: UnaryOp::WideHi, value } if value == whole
        ));
        let Expr::Binary { op: BinaryOp::Sub, lhs, rhs } = f.bindings.get(whole).unwrap().expr
        else {
            panic!("the whole is the difference");
        };
        assert!(matches!(
            f.bindings.get(lhs).unwrap().expr,
            Expr::WideJoin { lo, hi } if lo == v(0) && hi == v(1)
        ));
        assert!(matches!(
            f.bindings.get(rhs).unwrap().expr,
            Expr::WideJoin { lo, hi } if lo == v(2) && hi == v(3)
        ));
        // The joins are named before the value that reads them.
        let sched = &f.blocks.get(sordec_common::BlockId::from_index(0)).unwrap().bindings;
        let at = |x: ValueId| sched.iter().position(|s| *s == x).unwrap();
        assert!(at(lhs) < at(whole) && at(rhs) < at(whole));
        assert!(at(whole) < at(v(4)));
    }

    /// A sum's carry compares the result, not the operands, so it says
    /// nothing about which low limb belongs to which high one.
    #[test]
    fn a_sum_over_loose_limbs_is_left_alone() {
        let mut m = loose(BinaryOp::Add, 4);
        assert!(!WideArithPass.run(&mut m).changed);
    }

    /// `a - d`, `a` two loose registers and `d` a value the function
    /// typed `named` (v9), whose halves are v2 and v3.
    fn minus_named(named: Option<KnownType>) -> HighIr {
        let mut m = loose(BinaryOp::Sub, 0);
        let f = &mut m.functions[0];
        let d = v(f.bindings.len() as u32);
        f.bindings.push(Binding::new(
            d,
            named.map_or(IrType::Unknown(sordec_common::UnknownReason::InsufficientEvidence), IrType::Inferred),
            Expr::Phi { incoming: vec![] },
            Provenance::new("seed", ProvenanceSource::DataFlow, "seed"),
        ));
        f.bindings.get_mut(v(2)).unwrap().expr = Expr::Unary { op: UnaryOp::WideLo, value: d };
        f.bindings.get_mut(v(3)).unwrap().expr = Expr::Unary { op: UnaryOp::WideHi, value: d };
        m
    }

    fn whole_and_join(m: &HighIr) -> (IrType, IrType) {
        let f = &m.functions[0];
        let Expr::Unary { op: UnaryOp::WideLo, value: whole } = f.bindings.get(v(4)).unwrap().expr else {
            panic!("the low limb names its half");
        };
        let Expr::Binary { op: BinaryOp::Sub, lhs, .. } = f.bindings.get(whole).unwrap().expr else {
            panic!("the whole is the difference");
        };
        (f.bindings.get(whole).unwrap().ty.clone(), f.bindings.get(lhs).unwrap().ty.clone())
    }

    /// A difference from a `u128` the function named is a `u128`, and so
    /// is the loose operand it is taken from.
    #[test]
    fn a_difference_with_a_u128_operand_is_a_u128() {
        let mut m = minus_named(Some(KnownType::U128));
        assert!(WideArithPass.run(&mut m).changed);
        let u128 = IrType::Inferred(KnownType::U128);
        assert_eq!(whole_and_join(&m), (u128.clone(), u128));
    }

    /// With no operand named as a 128-bit type the value is an `i128`.
    #[test]
    fn a_difference_with_no_typed_operand_is_an_i128() {
        let mut m = minus_named(None);
        assert!(WideArithPass.run(&mut m).changed);
        let i128 = IrType::Inferred(KnownType::I128);
        assert_eq!(whole_and_join(&m), (i128.clone(), i128));
    }

    #[test]
    fn the_pass_is_idempotent() {
        let mut m = loose(BinaryOp::Sub, 0);
        assert!(WideArithPass.run(&mut m).changed);
        assert!(!WideArithPass.run(&mut m).changed);
    }
}
