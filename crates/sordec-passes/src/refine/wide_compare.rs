//! Read a 128-bit comparison back off its halves.
//!
//! WASM compares 64 bits at a time, so `a < b` on an `i128` becomes:
//! compare the high halves; if they are equal the answer is the low
//! halves' comparison, otherwise it is the high halves'. rustc spells the
//! choice with `select`, which reaches us unrecognized:
//!
//! ```text
//! select(lt(lo(a), lo(b)), lt(hi(a), hi(b)), eq(hi(a), hi(b)))  →  a < b
//! ```
//!
//! Left alone it is a hole in the output and, worse, it hides what the
//! branch beneath it is testing — including the borrow check rustc puts
//! on `a - b`, which [`super::overflow_guard`] can only elide once it can
//! see that the comparison is between a difference and its own operand.
//!
//! # Why it is exact
//!
//! Lexicographic order on (high, low) is the order on the whole value:
//! the high half dominates, and the low half decides only when the high
//! halves are equal. That is the identity the compiler used to emit this
//! and the identity used to read it back.
//!
//! Both halves of both operands must appear, in the same relation, with
//! the tie-break testing the same two high halves that the fallback
//! compares. Anything less is some other use of `select`.

use sordec_common::{IrId, Provenance, ProvenanceSource, ValueId};
use sordec_ir::{BinaryOp, Expr, HighFunction, HighIr, IrType, KnownType, UnaryOp, WasmOpcodeKind};

use super::wide::{Side, available_before, half_of, materialize, paired};
use crate::dataflow::{resolve_use, trace_int};
use crate::metrics_catalog::REFINE_WIDE_COMPARES as M_COMPARES;
use crate::pass::{Pass, PassResult};

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "refine-wide-compare";

/// Rewrites the lexicographic half-comparison as a comparison.
#[derive(Debug, Default, Clone, Copy)]
pub struct WideComparePass;

impl Pass<HighIr> for WideComparePass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        for func in &mut ir.functions {
            let found: Vec<_> = func
                .bindings
                .iter()
                .filter_map(|(id, b)| {
                    comparison(func, &b.expr)
                        .or_else(|| against_zero(func, &b.expr))
                        .map(|c| (id, c))
                })
                .collect();
            for (id, (op, a, b)) in found {
                // The operands have to be nameable where the comparison
                // is; a limb computed after it is not one of its halves.
                let order = crate::marshalling::sret::emission_order(func);
                let Some(pos) = order.iter().position(|o| *o == id) else {
                    continue;
                };
                let sides: Vec<Side> = std::iter::once(a).chain(b).collect();
                if !available_before(&order, &sides, pos) {
                    continue;
                }
                let base = ValueId::from_index(func.bindings.len() as u32);
                let lhs = materialize(func, a, PASS_NAME);
                // The zero side is not a value the function had; make
                // one at the width the comparison is really at.
                let rhs = match b {
                    Some(side) => materialize(func, side, PASS_NAME),
                    None => {
                        let zero = ValueId::from_index(func.bindings.len() as u32);
                        func.bindings.push(sordec_ir::Binding::new(
                            zero,
                            IrType::Inferred(KnownType::I128),
                            Expr::Literal(sordec_ir::Literal::I64(0)),
                            Provenance::new(
                                PASS_NAME,
                                ProvenanceSource::DataFlow,
                                "the zero it is compared against",
                            ),
                        ));
                        zero
                    }
                };
                // Reverse order, because each insertion pushes the last
                // one right: the operands end up ahead of the test.
                let fresh: Vec<ValueId> = [rhs, lhs].into_iter().filter(|v| *v >= base).collect();
                for (_, block) in func.blocks.iter_mut() {
                    if let Some(at) = block.bindings.iter().position(|v| *v == id) {
                        for v in &fresh {
                            block.bindings.insert(at, *v);
                        }
                        break;
                    }
                }
                if let Some(bind) = func.bindings.get_mut(id) {
                    bind.expr = Expr::Binary { op, lhs, rhs };
                    bind.ty = IrType::Inferred(KnownType::Bool);
                    bind.add_provenance(Provenance::new(
                        PASS_NAME,
                        ProvenanceSource::DataFlow,
                        "the halves compared lexicographically: the comparison",
                    ));
                    result.metrics.increment(M_COMPARES, 1);
                    result.changed = true;
                }
            }
        }
        result
    }
}

/// The comparison a `select` over two values' halves performs.
fn comparison(func: &HighFunction, expr: &Expr) -> Option<(BinaryOp, Side, Option<Side>)> {
    let Expr::Unknown { op_kind: WasmOpcodeKind::Select, args, .. } = expr else {
        return None;
    };
    let [on_equal, otherwise, tie] = args.as_slice() else {
        return None;
    };
    // The tie-break: the high halves are equal.
    let (BinaryOp::Eq, hi_l, hi_r) = compare_of(func, *tie)? else {
        return None;
    };
    // The fallback compares those same high halves...
    let (high_op, fb_l, fb_r) = compare_of(func, *otherwise)?;
    if (fb_l, fb_r) != (hi_l, hi_r) || !ordering(high_op) {
        return None;
    }
    // ...and the tie-break case compares the low halves the same way,
    // in the same operand order. That order is what pairs each low limb
    // with its own high one, so both operands are named even when the
    // function itself never put either pair together.
    let (low_op, lo_l, lo_r) = compare_of(func, *on_equal)?;
    if low_op != high_op {
        return None;
    }
    Some((
        high_op,
        paired(func, lo_l, hi_l)?,
        Some(paired(func, lo_r, hi_r)?),
    ))
}

/// The comparison against zero a `select` over one value's halves makes.
///
/// A bound of zero lets rustc drop one operand entirely: the high half
/// decides unless it is zero, and then the low half — read unsigned, so
/// `<= 0` on it is `== 0` and `> 0` is `!= 0`.
///
/// ```text
/// select(lo(a) == 0, hi(a) <  0, hi(a) == 0)   →  a <= 0
/// select(lo(a) != 0, hi(a) >  0, hi(a) == 0)   →  a >  0
/// ```
fn against_zero(func: &HighFunction, expr: &Expr) -> Option<(BinaryOp, Side, Option<Side>)> {
    let Expr::Unknown { op_kind: WasmOpcodeKind::Select, args, .. } = expr else {
        return None;
    };
    let [on_equal, otherwise, tie] = args.as_slice() else {
        return None;
    };
    let (on_equal, otherwise, tie) = (*on_equal, *otherwise, *tie);
    // The tie-break: the high half is zero.
    let hi = is_zero(func, tie)?;
    // The fallback orders that same high half against zero.
    let (op, again, bound) = compare_of(func, otherwise)?;
    if !same_limb(func, again, hi, UnaryOp::WideHi) || trace_int(func, bound) != Some(0) {
        return None;
    }
    // And the tie case asks the unsigned question of the low half. What
    // it asks decides the whole predicate, not the fallback's operator:
    // `hi < 0` with `lo == 0` beneath it is `<= 0`, because the tie case
    // is where equality lives.
    let (low, whole) = match op {
        BinaryOp::Lt => match (is_zero(func, on_equal), is_nonzero(func, on_equal)) {
            (Some(v), _) => (v, BinaryOp::Le),
            (_, Some(v)) => (v, BinaryOp::Lt),
            _ => return None,
        },
        BinaryOp::Gt => match (is_nonzero(func, on_equal), is_zero(func, on_equal)) {
            (Some(v), _) => (v, BinaryOp::Gt),
            (_, Some(v)) => (v, BinaryOp::Ge),
            _ => return None,
        },
        _ => return None,
    };
    Some((whole, paired(func, low, hi)?, None))
}

/// Whether two values are the same limb: the same register, or two
/// registers naming the same half of one value.
fn same_limb(func: &HighFunction, x: ValueId, y: ValueId, want: UnaryOp) -> bool {
    resolve_use(func, x) == resolve_use(func, y)
        || matches!(
            (half_of(func, x, want), half_of(func, y, want)),
            (Some(a), Some(b)) if a == b
        )
}

/// The value a `x == 0` test names, however it is spelled.
fn is_zero(func: &HighFunction, value: ValueId) -> Option<ValueId> {
    match &func.bindings.get(resolve_use(func, value))?.expr {
        Expr::Unary { op: UnaryOp::Eqz, value } => Some(resolve_use(func, *value)),
        Expr::Binary { op: BinaryOp::Eq, lhs, rhs } => sided(func, *lhs, *rhs),
        _ => None,
    }
}

/// The value a `x != 0` test names.
fn is_nonzero(func: &HighFunction, value: ValueId) -> Option<ValueId> {
    match &func.bindings.get(resolve_use(func, value))?.expr {
        Expr::Binary { op: BinaryOp::Ne, lhs, rhs } => sided(func, *lhs, *rhs),
        _ => None,
    }
}

/// Of a comparison against the constant zero, the other operand.
fn sided(func: &HighFunction, lhs: ValueId, rhs: ValueId) -> Option<ValueId> {
    [(lhs, rhs), (rhs, lhs)]
        .into_iter()
        .find_map(|(v, k)| (trace_int(func, k) == Some(0)).then(|| resolve_use(func, v)))
}

/// Whether this operator orders — equality decides nothing lexicographic.
fn ordering(op: BinaryOp) -> bool {
    matches!(op, BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge)
}

/// The comparison a value is.
fn compare_of(func: &HighFunction, value: ValueId) -> Option<(BinaryOp, ValueId, ValueId)> {
    match &func.bindings.get(resolve_use(func, value))?.expr {
        Expr::Binary { op, lhs, rhs }
            if ordering(*op) || matches!(op, BinaryOp::Eq | BinaryOp::Ne) =>
        {
            Some((*op, resolve_use(func, *lhs), resolve_use(func, *rhs)))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, module, v};
    use sordec_common::UnknownReason;

    /// `select(gt(lo a, lo b), gt(hi a, hi b), eq(hi a, hi b))`.
    /// `matching` false makes the tie-break case use the wrong operator.
    fn shape(matching: bool) -> HighIr {
        let low = if matching { BinaryOp::Gt } else { BinaryOp::Lt };
        module(vec![func_with(
            vec![
                Expr::Phi { incoming: vec![] },                             // v0 a
                Expr::Phi { incoming: vec![] },                             // v1 b
                Expr::Unary { op: UnaryOp::WideLo, value: v(0) },            // v2
                Expr::Unary { op: UnaryOp::WideLo, value: v(1) },            // v3
                Expr::Unary { op: UnaryOp::WideHi, value: v(0) },            // v4
                Expr::Unary { op: UnaryOp::WideHi, value: v(1) },            // v5
                Expr::Binary { op: low, lhs: v(2), rhs: v(3) },              // v6 lows
                Expr::Binary { op: BinaryOp::Gt, lhs: v(4), rhs: v(5) },     // v7 highs
                Expr::Binary { op: BinaryOp::Eq, lhs: v(4), rhs: v(5) },     // v8 tie
                Expr::Unknown {
                    op_kind: WasmOpcodeKind::Select,
                    args: vec![v(6), v(7), v(8)],
                    reason: UnknownReason::UnsupportedPattern,
                }, // v9
            ],
            vec![v(0), v(1)],
            vec![2, 3, 4, 5, 6, 7, 8, 9],
        )])
    }

    #[test]
    fn halves_compared_lexicographically_are_the_comparison() {
        let mut m = shape(true);
        assert!(WideComparePass.run(&mut m).changed);
        assert!(matches!(
            m.functions[0].bindings.get(v(9)).unwrap().expr,
            Expr::Binary { op: BinaryOp::Gt, lhs, rhs } if lhs == v(0) && rhs == v(1)
        ));
    }

    /// Halves compared in different directions order nothing.
    #[test]
    fn a_select_whose_halves_disagree_is_left_alone() {
        let mut m = shape(false);
        assert!(!WideComparePass.run(&mut m).changed);
    }

    #[test]
    fn the_pass_is_idempotent() {
        let mut m = shape(true);
        assert!(WideComparePass.run(&mut m).changed);
        assert!(!WideComparePass.run(&mut m).changed);
    }
}
