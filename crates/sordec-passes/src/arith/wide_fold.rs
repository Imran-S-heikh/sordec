//! Cancel a wide join against its own limbs.
//!
//! Two rewrites, both identities:
//!
//! ```text
//! wide(wide_lo(x), wide_hi(x))   →   x
//! wide_lo(wide(lo, hi))          →   lo        (and hi likewise)
//! ```
//!
//! They matter because every producer of a 128-bit value in this
//! pipeline speaks limbs at its boundary. A decoded `amount` parameter
//! becomes `wide_lo(amount)` / `wide_hi(amount)` in the caller's frame;
//! a `__muloti4` call becomes a product whose consumers read
//! `wide_lo(p)` / `wide_hi(p)`; the next helper joins those back. Without
//! the fold, `amount * rate` would emit as a join of two limb extractions
//! of each operand — correct Rust, and unreadable. With it, the chain
//! `decode → join → multiply → split → join → encode` collapses to the
//! expression the author wrote.
//!
//! Idempotent and monotone: each rewrite replaces an expression with a
//! `Use` of an existing binding, so the count of `WideJoin`/`WideLo`/
//! `WideHi` nodes strictly decreases. It sits inside the marshalling
//! fixpoint group because the decode collapse is what plants the limb
//! extractors it cancels.

use sordec_common::{Provenance, ProvenanceSource, ValueId};
use sordec_ir::{Expr, HighFunction, HighIr, UnaryOp};

use crate::dataflow::resolve_use;
use crate::metrics_catalog::WIDE_FOLDED as M_FOLDED;
use crate::pass::{Pass, PassResult};

/// Pass name, also its provenance `pass` field.
pub const PASS_NAME: &str = "wide-fold";

/// Cancels wide joins against their own limbs.
#[derive(Debug, Default, Clone, Copy)]
pub struct WideFoldPass;

impl Pass<HighIr> for WideFoldPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        for func in &mut ir.functions {
            let folds = plan(func);
            if folds.is_empty() {
                continue;
            }
            result.metrics.increment(M_FOLDED, folds.len() as i64);
            result.changed = true;
            for (id, target, note) in folds {
                let Some(binding) = func.bindings.get_mut(id) else {
                    continue;
                };
                binding.expr = Expr::Use(target);
                binding.add_provenance(Provenance::new(
                    PASS_NAME,
                    ProvenanceSource::DataFlow,
                    note,
                ));
            }
        }
        result
    }
}

/// Every binding that is an identity over a wide value, with what it
/// reduces to.
fn plan(func: &HighFunction) -> Vec<(ValueId, ValueId, &'static str)> {
    let mut folds = Vec::new();
    for (id, binding) in func.bindings.iter() {
        match &binding.expr {
            Expr::WideJoin { lo, hi } => {
                let (Some(x), Some(y)) = (limb_source(func, *lo, UnaryOp::WideLo), limb_source(func, *hi, UnaryOp::WideHi))
                else {
                    continue;
                };
                if x == y {
                    folds.push((id, x, "join of a value's own limbs is the value"));
                }
            }
            Expr::Unary {
                op: op @ (UnaryOp::WideLo | UnaryOp::WideHi),
                value,
            } => {
                let joined = resolve_use(func, *value);
                let Some(Expr::WideJoin { lo, hi }) = func.bindings.get(joined).map(|b| &b.expr)
                else {
                    continue;
                };
                let (limb, note) = match op {
                    UnaryOp::WideLo => (*lo, "low limb of a join is its low operand"),
                    _ => (*hi, "high limb of a join is its high operand"),
                };
                folds.push((id, limb, note));
            }
            _ => {}
        }
    }
    folds
}

/// The wide value `limb` extracts `op` from, if it is such an extraction.
fn limb_source(func: &HighFunction, limb: ValueId, op: UnaryOp) -> Option<ValueId> {
    let limb = resolve_use(func, limb);
    match &func.bindings.get(limb)?.expr {
        Expr::Unary { op: got, value } if *got == op => Some(resolve_use(func, *value)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::IrId;

    fn v(i: u32) -> ValueId {
        ValueId::from_index(i)
    }

    fn ir(exprs: Vec<Expr>) -> HighIr {
        super::super::i128_builtins::tests::ir(vec![super::super::i128_builtins::tests::function(0, 0, exprs)])
    }

    fn expr_at(ir: &HighIr, value: u32) -> &Expr {
        &ir.functions[0].bindings.get(v(value)).unwrap().expr
    }

    /// `v0` is some wide value; `v1`/`v2` split it; `v3` joins the halves.
    #[test]
    fn a_join_of_a_values_own_limbs_folds_to_the_value() {
        let mut m = ir(vec![
            Expr::Phi { incoming: vec![] },
            Expr::Unary { op: UnaryOp::WideLo, value: v(0) },
            Expr::Unary { op: UnaryOp::WideHi, value: v(0) },
            Expr::WideJoin { lo: v(1), hi: v(2) },
        ]);
        let r = WideFoldPass.run(&mut m);
        assert!(r.changed);
        assert!(matches!(expr_at(&m, 3), Expr::Use(x) if *x == v(0)));
    }

    /// Limbs of two *different* values are not a value.
    #[test]
    fn limbs_of_different_values_do_not_fold() {
        let mut m = ir(vec![
            Expr::Phi { incoming: vec![] },
            Expr::Phi { incoming: vec![] },
            Expr::Unary { op: UnaryOp::WideLo, value: v(0) },
            Expr::Unary { op: UnaryOp::WideHi, value: v(1) },
            Expr::WideJoin { lo: v(2), hi: v(3) },
        ]);
        let r = WideFoldPass.run(&mut m);
        assert!(!r.changed);
        assert!(matches!(expr_at(&m, 4), Expr::WideJoin { .. }));
    }

    /// `v2 = wide(v0, v1)`; `v3 = wide_lo(v2)` is `v0`, `v4 = wide_hi(v2)` is `v1`.
    #[test]
    fn a_limb_of_a_join_folds_to_the_operand() {
        let mut m = ir(vec![
            Expr::Phi { incoming: vec![] },
            Expr::Phi { incoming: vec![] },
            Expr::WideJoin { lo: v(0), hi: v(1) },
            Expr::Unary { op: UnaryOp::WideLo, value: v(2) },
            Expr::Unary { op: UnaryOp::WideHi, value: v(2) },
        ]);
        let r = WideFoldPass.run(&mut m);
        assert_eq!(r.metrics.get(M_FOLDED), Some(2));
        assert!(matches!(expr_at(&m, 3), Expr::Use(x) if *x == v(0)));
        assert!(matches!(expr_at(&m, 4), Expr::Use(x) if *x == v(1)));
    }

    /// The fold sees through `Use` chains on both sides.
    #[test]
    fn the_fold_resolves_use_chains() {
        let mut m = ir(vec![
            Expr::Phi { incoming: vec![] },
            Expr::Unary { op: UnaryOp::WideLo, value: v(0) },
            Expr::Use(v(1)),
            Expr::Unary { op: UnaryOp::WideHi, value: v(0) },
            Expr::WideJoin { lo: v(2), hi: v(3) },
        ]);
        assert!(WideFoldPass.run(&mut m).changed);
        assert!(matches!(expr_at(&m, 4), Expr::Use(x) if *x == v(0)));
    }

    #[test]
    fn the_pass_is_idempotent() {
        let mut m = ir(vec![
            Expr::Phi { incoming: vec![] },
            Expr::Unary { op: UnaryOp::WideLo, value: v(0) },
            Expr::Unary { op: UnaryOp::WideHi, value: v(0) },
            Expr::WideJoin { lo: v(1), hi: v(2) },
        ]);
        assert!(WideFoldPass.run(&mut m).changed);
        assert!(!WideFoldPass.run(&mut m).changed);
    }
}
