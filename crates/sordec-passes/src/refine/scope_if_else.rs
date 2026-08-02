//! Forward-jump recovery — the `Scope` + guarded `Break` that is an
//! `if`/`else` written the way wasm has to write it.
//!
//! [`super::scope_fallthrough`] removes the `Break`s that jump where
//! control was going anyway. What it leaves is the other kind: a break
//! that genuinely *skips* the code after it. On the corpus that residue is
//! 17 scopes on token-v23, 34 on dex, 13 on timelock — all of one shape:
//!
//! ```text
//! 'bb7: {                                if v46 {
//!     if v46 { v49 = to_muxed;               v49 = to_muxed
//!              break 'bb7 }        →     } else {
//!     v48 = get_address(…)                   v48 = get_address(…)
//!     v49 = v48                              v49 = v48
//! }                                      }
//! ```
//!
//! The break skips the tail, which is exactly what an `else` does. So the
//! tail *is* the else-arm, and once it moves inside, nothing names the
//! label and the scope goes with it.
//!
//! This is the transform that pays for itself twice: one `break` token
//! leaves the skeleton, and the `branch:1` we were emitting becomes the
//! `branch:2` the source actually wrote.
//!
//! ## Gates
//!
//! - The `If` must be **directly in the scope's body sequence** and its
//!   `then` must end in a `Break` to *this* scope's label. A break to an
//!   outer label is a real early exit and not ours to restructure.
//! - The `If` must have **no `else` already** — one that does is not this
//!   shape.
//! - The break must be the **only** one left naming the label, so the
//!   rewrite deletes the scope. A transform that left the label standing
//!   would trade a `break` for an `else` and gain nothing.
//! - There must be **something after the `If`** to become the else-arm.
//!   With nothing to skip, the break is vacuous, and that is
//!   `scope_fallthrough`'s to remove, not ours to wrap in an empty `else`.
//! - The scope must not be **re-declared** by a nested scope, and the
//!   splice must leave every other exit enclosed — the same two invariants
//!   `scope_fallthrough` checks, reused from it.
//!
//! ## Why this does not fight [`GuardClausePass`](super::GuardClausePass)
//!
//! That pass performs the exact inverse: it hoists
//! `if c { break } else { REST }` into `if c { break }; REST`. Run in one
//! fixpoint group the two would oscillate forever, so the question is not
//! academic.
//!
//! Two independent reasons it holds. The first is structural: `can_hoist`
//! requires [`is_terminating`](super::is_terminating) of the `then` arm,
//! and this rewrite *removes the trailing `Break`* that made it terminate.
//! The output is not a shape `GuardClausePass` can match, so it cannot
//! hoist it back. The second is placement: this pass runs late, beside
//! `scope_fallthrough` and well after the wave-1 refinement group that
//! contains `GuardClausePass`. A regression test pins the first, because
//! the second could be undone by a manifest edit.

use std::collections::HashSet;

use sordec_common::BlockId;
use sordec_ir::{HighIr, Region};

use super::scope_fallthrough::{breaks_stay_enclosed, count_breaks_to, redeclares};
use super::debug_validate;
use crate::pass::{Pass, PassResult};
use crate::structuring::seq;

/// Unique pipeline name of this pass.
pub const PASS_NAME: &str = "refine-scope-if-else";

use crate::metrics_catalog::REFINE_SCOPE_TO_IF_ELSE as M_RECOVERED;

/// Recovers `if`/`else` from a scope exited by a guarded forward branch.
#[derive(Debug, Default, Clone, Copy)]
pub struct ScopeIfElsePass;

impl Pass<HighIr> for ScopeIfElsePass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let mut recovered: i64 = 0;
        for func in &mut ir.functions {
            let region = std::mem::replace(&mut func.region, Region::Unreachable);
            func.region = rewrite(region, &mut recovered);
        }
        if recovered > 0 {
            result.metrics.increment(M_RECOVERED, recovered);
            result.changed = true;
        }
        debug_validate(ir, PASS_NAME);
        result
    }
}

/// Bottom-up structural walk, children first so an inner scope is already
/// in its final shape when its parent is judged.
fn rewrite(region: Region, n: &mut i64) -> Region {
    match region {
        Region::Sequence(items) => {
            seq(items.into_iter().map(|i| rewrite(i, n)).collect())
        }
        Region::Scope { out, body } => {
            let body = rewrite(*body, n);
            match recover(out, body) {
                Ok(spliced) => {
                    *n += 1;
                    spliced
                }
                Err(body) => Region::Scope {
                    out,
                    body: Box::new(body),
                },
            }
        }
        Region::Loop { header, body, kind } => Region::Loop {
            header,
            body: Box::new(rewrite(*body, n)),
            kind,
        },
        Region::If {
            cond,
            then_region,
            else_region,
        } => Region::If {
            cond,
            then_region: Box::new(rewrite(*then_region, n)),
            else_region: else_region.map(|e| Box::new(rewrite(*e, n))),
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
                    arm.body = rewrite(arm.body, n);
                    arm
                })
                .collect(),
            default: Box::new(rewrite(*default, n)),
            dispatch,
        },
        leaf => leaf,
    }
}

/// Turn `Scope{out}{ P.., If(c){ T… Break out }, R.. }` into
/// `P.., If(c){ T… } else { R.. }`, or hand the body back in `Err`.
fn recover(out: BlockId, body: Region) -> Result<Region, Region> {
    // Exactly one exit names the label; the rewrite must consume it and
    // leave the scope deletable.
    if count_breaks_to(out, &body) != 1 || redeclares(out, &body) {
        return Err(body);
    }
    let Region::Sequence(items) = body else {
        return Err(body);
    };
    // Find the guard: an else-less `If` whose `then` ends in the break.
    let Some(at) = items.iter().position(is_guard_for(out)) else {
        return Err(Region::Sequence(items));
    };
    // Something has to become the else-arm.
    if at + 1 >= items.len() {
        return Err(Region::Sequence(items));
    }

    let mut items = items;
    let rest: Vec<Region> = items.split_off(at + 1);
    let guard = items.pop().expect("position() found it");
    let Region::If {
        cond, then_region, ..
    } = guard
    else {
        unreachable!("is_guard_for matched an If");
    };

    let then_region = drop_tail_break(*then_region, out);
    let rebuilt = seq(vec![
        Region::If {
            cond,
            then_region: Box::new(then_region),
            else_region: Some(Box::new(seq(rest))),
        },
    ]);
    items.push(rebuilt);
    let spliced = seq(items);

    // The label is gone, so every remaining exit must find its own
    // construct one level up.
    if !breaks_stay_enclosed(&spliced, &mut HashSet::new()) {
        return Err(spliced);
    }
    Ok(spliced)
}

/// An else-less `If` whose `then` arm ends in a `Break` to `out`.
fn is_guard_for(out: BlockId) -> impl Fn(&Region) -> bool {
    move |region| {
        matches!(
            region,
            Region::If { then_region, else_region: None, .. }
                if tail_break_to(then_region, out)
        )
    }
}

/// Whether the last thing `region` does is break to `out`.
fn tail_break_to(region: &Region, out: BlockId) -> bool {
    match region {
        Region::Break { target, .. } => *target == out,
        Region::Sequence(items) => items.last().is_some_and(|l| tail_break_to(l, out)),
        _ => false,
    }
}

/// Remove the trailing `Break` to `out`, keeping its phi assignments as a
/// `Transfer` — the arm now reaches the merge by falling out of the `if`.
fn drop_tail_break(region: Region, out: BlockId) -> Region {
    match region {
        Region::Break { target, transfer } if target == out => {
            Region::Transfer { target, transfer }
        }
        Region::Sequence(mut items) => {
            if let Some(last) = items.pop() {
                items.push(drop_tail_break(last, out));
            }
            seq(items)
        }
        other => other,
    }
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{IrId, ValueId};
    use sordec_ir::{LoopKind, PhiTransfer};

    fn bb(i: u32) -> BlockId {
        BlockId::from_index(i)
    }
    fn v(i: u32) -> ValueId {
        ValueId::from_index(i)
    }
    fn brk(target: u32, transfer: PhiTransfer) -> Region {
        Region::Break {
            target: bb(target),
            transfer,
        }
    }
    fn run(region: Region) -> (Region, i64) {
        let mut n = 0;
        let out = rewrite(region, &mut n);
        (out, n)
    }

    /// token-v23's `bb7`: guard breaks past a tail that is really the else.
    fn guarded(out: u32) -> Region {
        Region::Scope {
            out: bb(out),
            body: Box::new(Region::Sequence(vec![
                Region::If {
                    cond: v(1),
                    then_region: Box::new(Region::Sequence(vec![
                        Region::Basic(bb(20)),
                        brk(out, vec![(v(49), v(30))]),
                    ])),
                    else_region: None,
                },
                Region::Basic(bb(21)),
                Region::Basic(bb(22)),
            ])),
        }
    }

    #[test]
    fn a_guarded_break_becomes_an_else_arm() {
        let (out, n) = run(guarded(7));
        assert_eq!(n, 1);
        let Region::If {
            then_region,
            else_region,
            ..
        } = out
        else {
            panic!("expected a bare if/else, got {out:?}");
        };
        // The break became a Transfer, keeping its phi assignment.
        let Region::Sequence(t) = *then_region else {
            panic!("expected the then arm to survive as a sequence");
        };
        assert!(matches!(
            &t[1],
            Region::Transfer { target, transfer }
                if *target == bb(7) && transfer == &vec![(v(49), v(30))]
        ));
        // Everything that followed the `if` is now the else arm.
        let Region::Sequence(e) = *else_region.expect("else arm") else {
            panic!("expected two blocks in the else arm");
        };
        assert_eq!(e.len(), 2);
    }

    #[test]
    fn nothing_after_the_guard_is_left_alone() {
        // No tail to skip means the break is vacuous, which is
        // `scope_fallthrough`'s shape — not an empty `else`.
        let region = Region::Scope {
            out: bb(7),
            body: Box::new(Region::Sequence(vec![
                Region::Basic(bb(20)),
                Region::If {
                    cond: v(1),
                    then_region: Box::new(brk(7, vec![])),
                    else_region: None,
                },
            ])),
        };
        assert_eq!(run(region).1, 0);
    }

    #[test]
    fn a_second_break_to_the_label_blocks_the_rewrite() {
        // The scope would survive the rewrite, so it buys nothing.
        let region = Region::Scope {
            out: bb(7),
            body: Box::new(Region::Sequence(vec![
                Region::If {
                    cond: v(1),
                    then_region: Box::new(brk(7, vec![])),
                    else_region: None,
                },
                brk(7, vec![]),
                Region::Basic(bb(21)),
            ])),
        };
        assert_eq!(run(region).1, 0);
    }

    #[test]
    fn a_break_to_an_outer_label_is_a_real_early_exit() {
        // Breaking past an *enclosing* scope is control flow we must not
        // restructure into an else of the inner one.
        let region = Region::Scope {
            out: bb(9),
            body: Box::new(Region::Scope {
                out: bb(7),
                body: Box::new(Region::Sequence(vec![
                    Region::If {
                        cond: v(1),
                        then_region: Box::new(brk(9, vec![])),
                        else_region: None,
                    },
                    Region::Basic(bb(21)),
                ])),
            }),
        };
        assert_eq!(run(region).1, 0);
    }

    #[test]
    fn a_guard_that_already_has_an_else_is_not_this_shape() {
        let region = Region::Scope {
            out: bb(7),
            body: Box::new(Region::Sequence(vec![
                Region::If {
                    cond: v(1),
                    then_region: Box::new(brk(7, vec![])),
                    else_region: Some(Box::new(Region::Basic(bb(20)))),
                },
                Region::Basic(bb(21)),
            ])),
        };
        assert_eq!(run(region).1, 0);
    }

    #[test]
    fn a_loop_carrying_the_break_is_not_a_guard() {
        // The break is inside a loop body, not an else-less `If` in the
        // scope's own sequence.
        let region = Region::Scope {
            out: bb(7),
            body: Box::new(Region::Sequence(vec![
                Region::Loop {
                    header: bb(1),
                    kind: LoopKind::Unclassified,
                    body: Box::new(brk(7, vec![])),
                },
                Region::Basic(bb(21)),
            ])),
        };
        assert_eq!(run(region).1, 0);
    }

    #[test]
    fn the_output_is_not_a_shape_guard_clause_can_hoist_back() {
        // The termination argument, pinned: `GuardClausePass` keys on
        // `is_terminating(then)`, and this rewrite is what stops the arm
        // terminating. Without this the two passes would oscillate.
        let (out, n) = run(guarded(7));
        assert_eq!(n, 1);
        let Region::If { then_region, .. } = &out else {
            panic!("expected an if/else");
        };
        assert!(
            !super::super::is_terminating(then_region),
            "the then arm must no longer terminate, or guard-clause hoists it straight back"
        );
    }

    #[test]
    fn a_second_run_changes_nothing() {
        let (once, first) = run(guarded(7));
        assert_eq!(first, 1);
        assert_eq!(run(once).1, 0, "the rewrite must not re-fire on its output");
    }
}
