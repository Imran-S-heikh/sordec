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
//!
//! ## What the fold leaves unreachable
//!
//! Code after a terminal (`return`, a trap, a `break`) in the same
//! sequence, and code after a labeled scope that nothing can leave forward
//! any more — the dropped arm held its only `break`, and its body ends in
//! a jump elsewhere on every path ([`dead_scope_tail`]). Both are dropped,
//! the scope unwrapped, and each merge keeps only the inputs a surviving
//! edge assigns. Why it is exact: control never reaches what is dropped.
//! Gates: any `break` to the label keeps the tail, and a body holding a
//! loop or an unstructured region is taken to fall through.

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
                prune_merges(func);
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

/// Drop each merge's inputs that no surviving edge assigns.
///
/// A folded arm's transfer goes with it, but the merge's own input list
/// still names what it carried — and type inference reads that list. Left
/// in, `unwrap_or(0)`'s dead `0i64` disagrees with the `u32` read and the
/// merge comes out untyped. The region tree is the record of which edges
/// remain, so an input is kept exactly when some transfer still assigns it.
fn prune_merges(func: &mut HighFunction) {
    let mut assigned: std::collections::HashMap<sordec_common::ValueId, Vec<sordec_common::ValueId>> =
        std::collections::HashMap::new();
    let mut unstructured = false;
    func.region.for_each_node(|node| match node {
        Region::Transfer { transfer, .. } | Region::Break { transfer, .. } | Region::Continue { transfer, .. } => {
            for (phi, src) in transfer {
                assigned.entry(*phi).or_default().push(*src);
            }
        }
        Region::Unstructured { .. } => unstructured = true,
        _ => {}
    });
    if unstructured {
        return;
    }
    for (id, binding) in func.bindings.iter_mut() {
        let Some(sources) = assigned.get(&id) else { continue };
        if let sordec_ir::Expr::Phi { incoming } = &mut binding.expr {
            incoming.retain(|(_, v)| sources.contains(v));
        }
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
            // Nor after a scope nothing leaves: see [`dead_scope_tail`].
            if let Some(end) = dead_scope_tail(&out) {
                out.truncate(end + 1);
                let Some(Region::Scope { body, .. }) = out.pop() else {
                    unreachable!("dead_scope_tail returns the index of a scope");
                };
                match *body {
                    Region::Sequence(inner) => out.extend(inner),
                    other => out.push(other),
                }
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

/// The first scope in a sequence that control can never leave forward,
/// when code follows it.
///
/// A folded `if` can take with it the only `break` to a scope's label:
/// rustc's `?` on a conversion that cannot fail leaves
///
/// ```text
/// 'b3: { ..; if err { break 'b3 }; r = Ok(v); break 'b2 }
/// r = Err(conversion error)          ← reached only by `break 'b3`
/// ```
///
/// and once the test is a constant `false` the `Err` arm after the scope
/// is dead, while the merge it feeds still counts it and comes out
/// untyped. The code after a scope runs only when a `break` to its label
/// leaves it, or when its body falls off the end. When the body does
/// neither — no `break` names the label, and every path through it ends
/// in a `break` elsewhere, a `return` or a trap — nothing after the scope
/// runs. The scope is then a label nothing targets, and its body stands in
/// its place.
///
/// Why it is exact: the dropped code is unreachable, and unwrapping a
/// scope no `break` names changes no path. Gates: a `break` to the label
/// anywhere inside the body keeps the tail, however nested; a loop or an
/// unstructured region in the body is taken to fall through (a loop leaves
/// by breaking to some scope, which is not worth modelling here).
fn dead_scope_tail(items: &[Region]) -> Option<usize> {
    let end = items.iter().position(|item| match item {
        Region::Scope { out, body } => !may_fall_through(body) && !breaks_to(body, *out),
        _ => false,
    })?;
    (end + 1 < items.len()).then_some(end)
}

/// Whether control can run off the end of `region` into what follows it.
/// Errs towards `true`.
fn may_fall_through(region: &Region) -> bool {
    match region {
        Region::Sequence(items) => items.iter().all(may_fall_through),
        Region::Scope { out, body } => may_fall_through(body) || breaks_to(body, *out),
        Region::If { then_region, else_region, .. } => {
            may_fall_through(then_region) || else_region.as_ref().is_none_or(|e| may_fall_through(e))
        }
        Region::Switch { arms, default, .. } => {
            may_fall_through(default) || arms.iter().any(|arm| may_fall_through(&arm.body))
        }
        Region::Break { .. }
        | Region::Continue { .. }
        | Region::Return { .. }
        | Region::Unreachable
        | Region::Panic { .. } => false,
        Region::Basic(_) | Region::Transfer { .. } | Region::Loop { .. } | Region::Unstructured { .. } => true,
    }
}

/// Whether a `break` to `label` occurs anywhere inside `region`.
fn breaks_to(region: &Region, label: sordec_common::BlockId) -> bool {
    let mut found = false;
    region.for_each_node(|node| {
        if let Region::Break { target, .. } = node
            && *target == label
        {
            found = true;
        }
    });
    found
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

    /// An ordered comparison of literals is not folded: the fold reads
    /// equality only.
    #[test]
    fn an_ordered_comparison_is_not_folded() {
        let mut m = module(vec![guarded(BinaryOp::Lt)]);
        assert!(!ConstBranchFoldPass.run(&mut m).changed);
    }

    /// `'b3: { bb0; break 'b2 (v2 <- v0) }; bb3; transfer 'b2 (v2 <- v1)`
    /// inside `'b2`, then `return v2`: the `Err` arm after `'b3` is reached
    /// only by a `break 'b3` that no longer exists.
    fn dead_tail(live_break: bool) -> HighFunction {
        let mut f = func_with(
            vec![
                Expr::Literal(Literal::I64(0)),
                Expr::Literal(Literal::I64(1)),
                Expr::Phi { incoming: vec![(bb(5), v(0)), (bb(3), v(1))] },
                Expr::Literal(Literal::Bool(true)),
            ],
            vec![],
            vec![0, 1, 3],
        );
        let mut inner = vec![Region::Basic(bb(0))];
        if live_break {
            // `if v3 { break 'b3 }`.
            inner.push(Region::If {
                cond: v(3),
                then_region: Box::new(Region::Break { target: bb(3), transfer: vec![] }),
                else_region: None,
            });
        }
        inner.push(Region::Break { target: bb(2), transfer: vec![(v(2), v(0))] });
        f.region = Region::Sequence(vec![
            Region::Scope {
                out: bb(2),
                body: Box::new(Region::Sequence(vec![
                    Region::Scope { out: bb(3), body: Box::new(Region::Sequence(inner)) },
                    Region::Basic(bb(3)),
                    Region::Transfer { target: bb(2), transfer: vec![(v(2), v(1))] },
                ])),
            },
            Region::Basic(bb(2)),
            Region::Return { values: vec![v(2)] },
        ]);
        f
    }

    /// Nothing breaks to `'b3` and its body never falls out, so the code
    /// after it is dropped, the scope unwrapped, and the merge keeps only
    /// the input a surviving edge assigns.
    #[test]
    fn the_tail_of_a_scope_nothing_leaves_is_dropped() {
        let mut m = module(vec![dead_tail(false)]);
        assert!(ConstBranchFoldPass.run(&mut m).changed);
        let f = &m.functions[0];
        let Region::Sequence(items) = &f.region else { panic!("sequence") };
        let Region::Scope { body, .. } = &items[0] else { panic!("outer scope kept") };
        let Region::Sequence(inner) = body.as_ref() else { panic!("sequence") };
        assert!(matches!(inner[..], [Region::Basic(_), Region::Break { .. }]), "{inner:?}");
        let Expr::Phi { incoming } = &f.bindings.get(v(2)).unwrap().expr else { panic!("phi") };
        assert_eq!(incoming, &vec![(bb(5), v(0))]);
    }

    /// A `break` to the label, even under an `if`, keeps the tail.
    #[test]
    fn a_scope_something_breaks_to_keeps_its_tail() {
        let mut f = dead_tail(true);
        // The test must stay a variable for the `if` to survive the fold.
        f.bindings.get_mut(v(3)).unwrap().expr = Expr::Load {
            addr: v(0),
            offset: 0,
            width: sordec_ir::MemWidth::W4,
            signed: None,
            ty: sordec_ir::IrType::Unknown(sordec_common::UnknownReason::InsufficientEvidence),
        };
        let mut m = module(vec![f]);
        assert!(!ConstBranchFoldPass.run(&mut m).changed);
    }

    #[test]
    fn the_pass_is_idempotent() {
        let mut m = module(vec![guarded(BinaryOp::Ne)]);
        assert!(ConstBranchFoldPass.run(&mut m).changed);
        assert!(!ConstBranchFoldPass.run(&mut m).changed);
    }
}
