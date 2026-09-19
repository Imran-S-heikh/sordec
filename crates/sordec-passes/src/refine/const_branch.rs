//! Fold a branch whose condition is a constant.
//!
//! The marshalling elisions produce these on purpose. A decode collapse
//! turns the `Result` discriminant the helper wrote into the literal `0`,
//! the frame forward carries that literal to the load that read it back,
//! and the guard that compared the load is left testing `0 != 1`:
//!
//! ```text
//! if 0 != 1 { return v }     →     return v
//! panic!()
//! ```
//!
//! Nothing downstream can use a branch that always goes one way, and the
//! `if` still counts as control flow the source never wrote. So the taken
//! arm replaces the branch, in place, and the other arm's bindings become
//! unscheduled residue exactly as a dead `let` does.
//!
//! ## What it evaluates
//!
//! Only what is bit-for-bit certain without a signedness: a literal
//! integer or boolean condition, `==`/`!=` between two literals, and
//! `eqz`/`!` of one. Ordered comparisons are left alone — `BinaryOp`
//! erases whether the operands were signed, and `-1 < 0` has two
//! answers.
//!
//! ## Why folding is exact
//!
//! The condition's value is the same on every execution, so the dropped
//! arm never ran. No binding moves across a branch; the kept arm executes
//! exactly when and where it did. A phi that had an incoming edge from the
//! dropped arm keeps that entry in its list — the transfer that fed it is
//! gone with the arm, which is the same state a dead predecessor leaves in
//! any other pass.

use sordec_common::{Diagnostic, LiftDiagnosticCode, Location};
use sordec_ir::{BinaryOp, Expr, HighFunction, HighIr, Literal, Region, UnaryOp};

use crate::dataflow::{resolve_use, trace_int};
use crate::metrics_catalog::REFINE_CONST_BRANCHES_FOLDED as M_FOLDED;
use crate::pass::{Pass, PassResult};

/// Pass name.
pub const PASS_NAME: &str = "refine-const-branch";

/// Replaces branches on constant conditions with the arm they take.
#[derive(Debug, Default, Clone, Copy)]
pub struct ConstBranchFoldPass;

impl Pass<HighIr> for ConstBranchFoldPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        for func in &mut ir.functions {
            let mut counts = Counts::default();
            let region = std::mem::replace(&mut func.region, Region::Unreachable);
            func.region = fold(func, region, &mut counts);
            let folded = counts.folded;
            if folded > 0 || counts.truncated > 0 {
                result.changed = true;
                result.metrics.increment(M_FOLDED, folded + counts.truncated);
                // Every constant condition here came out of a marshalling
                // collapse — a decode discriminant the caller no longer
                // tests — so the branch it folds is an elided guard, and
                // the coverage lint counts it as one.
                for _ in 0..folded {
                    result.diagnostics.push(
                        Diagnostic::info(
                            LiftDiagnosticCode::MarshallingGuardElided,
                            "branch on a constant condition folded to the arm it takes",
                        )
                        .at(Location::Function(func.id)),
                    );
                }
            }
        }
        result
    }
}

/// Branches folded, and unreachable tails dropped after a terminal.
#[derive(Default)]
struct Counts {
    folded: i64,
    truncated: i64,
}

fn fold(func: &HighFunction, region: Region, c: &mut Counts) -> Region {
    match region {
        Region::If {
            cond,
            then_region,
            else_region,
        } => match constant(func, cond) {
            Some(true) => {
                c.folded += 1;
                fold(func, *then_region, c)
            }
            Some(false) => {
                c.folded += 1;
                match else_region {
                    Some(e) => fold(func, *e, c),
                    None => Region::Sequence(vec![]),
                }
            }
            None => Region::If {
                cond,
                then_region: Box::new(fold(func, *then_region, c)),
                else_region: else_region.map(|e| Box::new(fold(func, *e, c))),
            },
        },
        Region::Sequence(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                match fold(func, item, c) {
                    // Splice a folded arm's own sequence in place, so the
                    // tree stays flat where it was flat.
                    Region::Sequence(inner) => out.extend(inner),
                    other => out.push(other),
                }
            }
            // Nothing after a terminal runs. A folded `if ok { return v }`
            // leaves the `panic!()` that followed it as an unreachable
            // tail, and that tail is what stops the body reading as
            // straight-line.
            if let Some(end) = out.iter().position(is_terminal)
                && end + 1 < out.len()
            {
                out.truncate(end + 1);
                c.truncated += 1;
            }
            Region::Sequence(out)
        }
        Region::Scope { out, body } => Region::Scope {
            out,
            body: Box::new(fold(func, *body, c)),
        },
        Region::Loop { header, body, kind } => Region::Loop {
            header,
            body: Box::new(fold(func, *body, c)),
            kind,
        },
        Region::Switch {
            index,
            arms,
            default,
            dispatch,
        } => Region::Switch {
            index,
            arms: arms
                .into_iter()
                .map(|mut arm| {
                    let body = std::mem::replace(&mut arm.body, Region::Unreachable);
                    arm.body = fold(func, body, c);
                    arm
                })
                .collect(),
            default: Box::new(fold(func, *default, c)),
            dispatch,
        },
        leaf => leaf,
    }
}

/// A node control never falls out of.
fn is_terminal(region: &Region) -> bool {
    matches!(
        region,
        Region::Return { .. }
            | Region::Panic { .. }
            | Region::Unreachable
            | Region::Break { .. }
            | Region::Continue { .. }
    )
}

/// The condition's value, when it is certain.
fn constant(func: &HighFunction, cond: sordec_common::ValueId) -> Option<bool> {
    let id = resolve_use(func, cond);
    match &func.bindings.get(id)?.expr {
        Expr::Literal(Literal::Bool(b)) => Some(*b),
        Expr::Unary {
            op: UnaryOp::Eqz | UnaryOp::Not,
            value,
        } => constant(func, *value).map(|b| !b),
        _ => int_value(func, id, INT_FOLD_DEPTH).map(|n| n != 0),
    }
}

/// How deep [`int_value`] follows operands. A forwarded discriminant is
/// tested through one or two operators (`d & 1`, `(d & 1) != 0`).
const INT_FOLD_DEPTH: u32 = 4;

/// The integer a binding evaluates to, when every operand it reads is a
/// constant: a literal, or the comparisons and bit operations a guard
/// wraps around one. Width is not modelled, so only operators whose
/// result does not depend on it are folded — no arithmetic that could
/// wrap, no shifts.
fn int_value(func: &HighFunction, value: sordec_common::ValueId, depth: u32) -> Option<i128> {
    let id = resolve_use(func, value);
    match &func.bindings.get(id)?.expr {
        Expr::Literal(Literal::Bool(b)) => Some(i128::from(*b)),
        Expr::Literal(lit) => int_of(lit),
        Expr::Unary { op: UnaryOp::Eqz | UnaryOp::Not, value } if depth > 0 => {
            int_value(func, *value, depth - 1).map(|n| i128::from(n == 0))
        }
        Expr::Binary { op, lhs, rhs } if depth > 0 => {
            let a = int_value(func, *lhs, depth - 1).or_else(|| trace_int(func, *lhs))?;
            let b = int_value(func, *rhs, depth - 1).or_else(|| trace_int(func, *rhs))?;
            match op {
                BinaryOp::Eq => Some(i128::from(a == b)),
                BinaryOp::Ne => Some(i128::from(a != b)),
                // Bitwise operators on two non-negative operands agree at
                // every width; a negative one would need the width.
                BinaryOp::BitAnd if a >= 0 && b >= 0 => Some(a & b),
                BinaryOp::BitOr if a >= 0 && b >= 0 => Some(a | b),
                BinaryOp::BitXor if a >= 0 && b >= 0 => Some(a ^ b),
                _ => None,
            }
        }
        // Anything else is constant only if the tracer says so — which
        // includes a named width move of one, the form a discriminant
        // written as `i64` and read back as `i32` arrives in.
        _ => trace_int(func, id),
    }
}

fn int_of(lit: &Literal) -> Option<i128> {
    match lit {
        Literal::I32(n) => Some(i128::from(*n)),
        Literal::I64(n) => Some(i128::from(*n)),
        Literal::U32(n) => Some(i128::from(*n)),
        Literal::U64(n) => Some(i128::from(*n)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, module, v};
    use sordec_common::{BlockId, IrId};
    use sordec_ir::PanicKind;

    fn bb(i: u32) -> BlockId {
        BlockId::from_index(i)
    }

    /// `v0 = 0; v1 = 1; v2 = v0 != v1; if v2 { return } panic!()`
    fn guarded(op: BinaryOp) -> HighFunction {
        let mut f = func_with(
            vec![
                Expr::Literal(Literal::I32(0)),
                Expr::Literal(Literal::I32(1)),
                Expr::Binary { op, lhs: v(0), rhs: v(1) },
            ],
            vec![],
            vec![0, 1, 2],
        );
        f.region = Region::Sequence(vec![
            Region::Basic(bb(0)),
            Region::If {
                cond: v(2),
                then_region: Box::new(Region::Return { values: vec![] }),
                else_region: None,
            },
            Region::Panic { kind: PanicKind::Bare },
        ]);
        f
    }

    /// The taken arm replaces the branch, and the `panic!()` that followed
    /// the guard is now an unreachable tail, dropped with it.
    #[test]
    fn a_true_constant_keeps_the_then_arm_in_place() {
        let mut m = module(vec![guarded(BinaryOp::Ne)]);
        let r = ConstBranchFoldPass.run(&mut m);
        assert!(r.changed);
        let Region::Sequence(items) = &m.functions[0].region else { panic!("sequence") };
        assert!(matches!(items[..], [Region::Basic(_), Region::Return { .. }]));
    }

    #[test]
    fn a_false_constant_drops_an_else_less_branch() {
        let mut m = module(vec![guarded(BinaryOp::Eq)]);
        assert!(ConstBranchFoldPass.run(&mut m).changed);
        let Region::Sequence(items) = &m.functions[0].region else { panic!("sequence") };
        assert!(matches!(items[..], [Region::Basic(_), Region::Panic { .. }]));
    }

    /// Signedness is erased on `BinaryOp`, so an ordered comparison of
    /// literals has no certain answer here.
    #[test]
    fn an_ordered_comparison_is_not_folded() {
        let mut m = module(vec![guarded(BinaryOp::Lt)]);
        assert!(!ConstBranchFoldPass.run(&mut m).changed);
    }

    #[test]
    fn the_pass_is_idempotent() {
        let mut m = module(vec![guarded(BinaryOp::Ne)]);
        assert!(ConstBranchFoldPass.run(&mut m).changed);
        assert!(!ConstBranchFoldPass.run(&mut m).changed);
    }
}
