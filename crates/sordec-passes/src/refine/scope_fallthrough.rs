//! Vacuous-break elision — a `Break` that jumps where control was going
//! anyway, and the labeled scope left with nothing to scope.
//!
//! Wasm has no `if`/`else`. rustc lowers `if c { X } else { Y }` into
//! `block { br_if $out; X; br $out } Y`, and the structurer reproduces that
//! faithfully because it is what the binary says. Nothing else in the
//! pipeline converts the forward-branch idiom back into Rust's structured
//! one, so the emitted corpus carries **246 `break`s against sources that
//! contain none at all**. Every one is structuring residue.
//!
//! This pass removes the half of them that are *vacuous*: a `Break` sitting
//! where falling off the end would reach the same continuation.
//!
//! ## Tail-exit positions
//!
//! A position is a **tail exit** of a scope when control reaching it and
//! running off the end leaves the scope. Defined recursively over the body:
//!
//! | region at a tail-exit position | children that inherit it |
//! |---|---|
//! | [`Region::Sequence`] | the last element only |
//! | [`Region::If`] | both arms (and the missing `else` — falling past the `if` exits too) |
//! | [`Region::Switch`] | every arm, and the default |
//! | [`Region::Scope`] (a *different* label) | its body — falling out of the inner scope lands at the outer's continuation |
//! | [`Region::Loop`] | **none** — falling off a loop body iterates, it does not exit |
//!
//! ```text
//! 'bb4: {                            match v18 {
//!     match v18 {                        0 => { v45 = 0 }
//!         0 => { v45 = 0;                 1 => { v45 = v12 }
//!                break 'bb4 }   →         _ => unreachable!()
//!         1 => { v45 = v12;            }
//!                break 'bb4 }         ;; bb4 …
//!         _ => unreachable!()
//!     }
//! }
//! ;; bb4 …
//! ```
//!
//! The predicate this replaces refused to descend into a trailing `If` or
//! `Switch`, on the grounds that "the other arm falls through". That is
//! true and is exactly why the break is vacuous: **the arm that falls
//! through and the arm that breaks land in the same place.** Correcting
//! that one reading is what takes the pass from 2 scopes on the corpus to
//! the bulk of them.
//!
//! Each converted `Break` becomes a [`Region::Transfer`], not nothing: the
//! edge still carries the phi assignments the merge block's parameters
//! need, and `Transfer` is exactly the "fall through into `target`'s
//! region without exiting a scope, assigning phi inputs first" form.
//!
//! ## Why this is worth a pass
//!
//! `sordec-score`'s structure skeleton counts a `break` as a control-flow
//! token while the labeled block itself costs nothing (it has no
//! `visit_expr_block` override). So each vacuous break is one surplus
//! token measured against an original that never wrote it, and this pass
//! strictly reduces the `{Scope, Break}` node count — the measure `super`'s
//! charter names.
//!
//! ## What it will not touch
//!
//! - A `Break` that is **not** at a tail exit — it skips code, so it is
//!   real control flow. Those are the forward jumps that encode an
//!   `if`/`else`, and converting *them* is a different transform with a
//!   different justification. The [`M_LIVE_LABEL`] counter sizes them.
//! - A nested `Scope` inside the body re-declaring the same `out` — then
//!   the breaks belong to the inner scope, not this one, and rewriting
//!   would silently retarget them.
//! - A splice that would leave a `Break`/`Continue` unenclosed — see
//!   [`breaks_stay_enclosed`]. That is the invariant `sordec_ir::validate`
//!   calls label enclosure, and getting it wrong is the one way this pass
//!   can produce an IR that does not validate. `debug_validate` runs after
//!   every rewrite.
//!
//! Conversions are kept even when the scope survives: each is sound on its
//! own (a tail exit is a tail exit regardless of what the other exits do),
//! and a scope whose label is still live simply keeps it.

use std::collections::HashSet;

use sordec_common::BlockId;
use sordec_ir::{HighIr, Region};

use super::debug_validate;
use crate::pass::{Pass, PassResult};
use crate::structuring::seq;

/// Unique pipeline name of this pass.
pub const PASS_NAME: &str = "refine-scope-fallthrough";

use crate::metrics_catalog::{
    REFINE_SCOPES_FALLTHROUGH as M_ELIDED, REFINE_SCOPES_LIVE_LABEL as M_LIVE_LABEL,
    REFINE_TAIL_EXIT_BREAKS as M_BREAKS,
};

/// What one walk of a function's region tree changed, and what it left.
#[derive(Debug, Default, Clone, Copy)]
struct Stats {
    /// Scopes spliced away, having no exit left to name them.
    scopes: i64,
    /// `Break`s at a tail exit rewritten to [`Region::Transfer`].
    breaks: i64,
    /// Scopes that kept their label because a real forward jump names it.
    /// The widening signal for the `if`/`else` transform.
    live_labels: i64,
}

/// Elides `Break`s that jump where control was going anyway, and the scopes
/// that are left with nothing to scope. Stateless.
#[derive(Debug, Default, Clone, Copy)]
pub struct ScopeFallthroughPass;

impl Pass<HighIr> for ScopeFallthroughPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let mut stats = Stats::default();
        for func in &mut ir.functions {
            let region = std::mem::replace(&mut func.region, Region::Unreachable);
            func.region = elide(region, &mut stats);
        }
        if stats.scopes > 0 {
            result.metrics.increment(M_ELIDED, stats.scopes);
        }
        if stats.breaks > 0 {
            result.metrics.increment(M_BREAKS, stats.breaks);
        }
        if stats.live_labels > 0 {
            result.metrics.increment(M_LIVE_LABEL, stats.live_labels);
        }
        // Only a rewrite counts as change; a surviving label is a census
        // observation, and reporting it would spin a fixpoint group forever.
        result.changed = stats.scopes > 0 || stats.breaks > 0;
        debug_validate(ir, PASS_NAME);
        result
    }
}

/// Bottom-up structural rewrite. Children first, so an inner scope that
/// becomes vacuous is elided before its parent is judged — which is what
/// makes one pass enough for a nest of them.
fn elide(region: Region, stats: &mut Stats) -> Region {
    match region {
        Region::Sequence(items) => {
            seq(items.into_iter().map(|item| elide(item, stats)).collect())
        }
        Region::Scope { out, body } => {
            let body = elide(*body, stats);
            refine_scope(out, body, stats)
        }
        Region::Loop { header, body, kind } => Region::Loop {
            header,
            body: Box::new(elide(*body, stats)),
            kind,
        },
        Region::If {
            cond,
            then_region,
            else_region,
        } => Region::If {
            cond,
            then_region: Box::new(elide(*then_region, stats)),
            else_region: else_region.map(|e| Box::new(elide(*e, stats))),
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
                    arm.body = elide(arm.body, stats);
                    arm
                })
                .collect(),
            default: Box::new(elide(*default, stats)),
            dispatch,
        },
        leaf @ (Region::Basic(_)
        | Region::Break { .. }
        | Region::Continue { .. }
        | Region::Transfer { .. }
        | Region::Return { .. }
        | Region::Unreachable
        | Region::Panic { .. }
        | Region::Unstructured { .. }) => leaf,
    }
}

/// Convert `body`'s tail-exit `Break`s to `out`, then splice the scope away
/// if nothing names its label any more.
fn refine_scope(out: BlockId, body: Region, stats: &mut Stats) -> Region {
    // A nested scope re-declaring `out` owns the breaks that name it;
    // rewriting from out here would retarget them.
    if redeclares(out, &body) {
        stats.live_labels += 1;
        return Region::Scope {
            out,
            body: Box::new(body),
        };
    }

    let mut converted = 0;
    let body = elide_tail_exits(out, body, &mut converted);
    stats.breaks += converted;

    // The scope goes only as a *consequence* of this pass having removed its
    // last break — never merely because it arrived with none. A label no
    // exit ever named is residue from somewhere else, it costs nothing in
    // the structure skeleton, and claiming it here would widen the pass
    // beyond what its rewrite justifies.
    if converted > 0
        && count_breaks_to(out, &body) == 0
        && breaks_stay_enclosed(&body, &mut HashSet::new())
    {
        stats.scopes += 1;
        return body;
    }
    stats.live_labels += 1;
    Region::Scope {
        out,
        body: Box::new(body),
    }
}

/// Rewrite every `Break` to `out` that sits at a **tail exit** of `region`
/// into a [`Region::Transfer`], counting the conversions.
///
/// `region` is always a region already known to be at a tail exit, so the
/// recursion is simply the table in the module docs. The phi assignments
/// ride along on the `Transfer`.
fn elide_tail_exits(out: BlockId, region: Region, n: &mut i64) -> Region {
    match region {
        Region::Break { target, transfer } if target == out => {
            *n += 1;
            Region::Transfer { target, transfer }
        }
        // Only the last element is a tail exit; earlier ones are followed
        // by code that a break would skip.
        Region::Sequence(mut items) => {
            if let Some(last) = items.pop() {
                items.push(elide_tail_exits(out, last, n));
            }
            seq(items)
        }
        // Both arms are tail exits, including the absent `else` — falling
        // past the `if` altogether exits the scope just the same.
        Region::If {
            cond,
            then_region,
            else_region,
        } => Region::If {
            cond,
            then_region: Box::new(elide_tail_exits(out, *then_region, n)),
            else_region: else_region.map(|e| Box::new(elide_tail_exits(out, *e, n))),
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
                    arm.body = elide_tail_exits(out, arm.body, n);
                    arm
                })
                .collect(),
            default: Box::new(elide_tail_exits(out, *default, n)),
            dispatch,
        },
        // Falling out of an inner scope lands at this scope's continuation,
        // so its body inherits the tail exit. A scope re-declaring `out` is
        // refused by the caller and cannot reach here.
        Region::Scope { out: inner, body } if inner != out => Region::Scope {
            out: inner,
            body: Box::new(elide_tail_exits(out, *body, n)),
        },
        // Everything else terminates or, in a `Loop`'s case, falls to its
        // own back edge rather than out of the scope.
        other => other,
    }
}

/// How many `Break`s in `body` target `out`, not descending into a nested
/// scope that re-declares it (those belong to the inner scope).
pub(super) fn count_breaks_to(out: BlockId, body: &Region) -> usize {
    match body {
        Region::Break { target, .. } if *target == out => 1,
        Region::Scope { out: inner, .. } if *inner == out => 0,
        Region::Sequence(items) => items.iter().map(|i| count_breaks_to(out, i)).sum(),
        Region::Scope { body, .. } | Region::Loop { body, .. } => count_breaks_to(out, body),
        Region::If {
            then_region,
            else_region,
            ..
        } => {
            count_breaks_to(out, then_region)
                + else_region
                    .as_ref()
                    .map_or(0, |e| count_breaks_to(out, e))
        }
        Region::Switch { arms, default, .. } => {
            arms.iter().map(|a| count_breaks_to(out, &a.body)).sum::<usize>()
                + count_breaks_to(out, default)
        }
        _ => 0,
    }
}

/// Whether any nested `Scope` inside `body` declares `out` as its own
/// label.
pub(super) fn redeclares(out: BlockId, body: &Region) -> bool {
    match body {
        Region::Scope { out: inner, body } => *inner == out || redeclares(out, body),
        Region::Sequence(items) => items.iter().any(|i| redeclares(out, i)),
        Region::Loop { body, .. } => redeclares(out, body),
        Region::If {
            then_region,
            else_region,
            ..
        } => {
            redeclares(out, then_region)
                || else_region.as_ref().is_some_and(|e| redeclares(out, e))
        }
        Region::Switch { arms, default, .. } => {
            arms.iter().any(|a| redeclares(out, &a.body)) || redeclares(out, default)
        }
        _ => false,
    }
}

/// Whether every `Break`/`Continue` in `body` targets a label declared
/// *inside* `body`.
///
/// A target declared outside is still enclosed after the splice — the
/// enclosing `Scope`/`Loop` is unchanged and the subtree only moves up one
/// level, which cannot escape it. A target declared inside is likewise
/// fine. So the check is really "we are not the one enclosing it", and the
/// only way that fails is a break to *our own* `out`, which the caller has
/// already counted to exactly one and placed in the tail.
///
/// Kept as an explicit walk rather than a comment because it is the
/// invariant `validate`'s `UnenclosedLabel` catches, and a future shape
/// (a `Break` targeting a merge block we do not model as a `Scope`) would
/// silently break it.
pub(super) fn breaks_stay_enclosed(body: &Region, declared: &mut HashSet<BlockId>) -> bool {
    match body {
        Region::Scope { out, body } => {
            let fresh = declared.insert(*out);
            let ok = breaks_stay_enclosed(body, declared);
            if fresh {
                declared.remove(out);
            }
            ok
        }
        Region::Loop { header, body, .. } => {
            let fresh = declared.insert(*header);
            let ok = breaks_stay_enclosed(body, declared);
            if fresh {
                declared.remove(header);
            }
            ok
        }
        Region::Sequence(items) => items.iter().all(|i| breaks_stay_enclosed(i, declared)),
        Region::If {
            then_region,
            else_region,
            ..
        } => {
            breaks_stay_enclosed(then_region, declared)
                && else_region
                    .as_ref()
                    .is_none_or(|e| breaks_stay_enclosed(e, declared))
        }
        Region::Switch { arms, default, .. } => {
            arms.iter().all(|a| breaks_stay_enclosed(&a.body, declared))
                && breaks_stay_enclosed(default, declared)
        }
        // A break to a label this subtree declares is self-contained; one to
        // an outer label survives the splice because the splice only moves
        // this subtree up, never out of that label's scope.
        Region::Break { .. } | Region::Continue { .. } => true,
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{IrId, ValueId};
    use sordec_ir::{LoopKind, PhiTransfer, SwitchArm};

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

    /// The hello-add shape: `'bb7: { Basic(bb6); v40 = v30; break 'bb7 }`.
    fn vacuous() -> Region {
        Region::Scope {
            out: bb(7),
            body: Box::new(Region::Sequence(vec![
                Region::Basic(bb(6)),
                brk(7, vec![(v(40), v(30))]),
            ])),
        }
    }

    /// Returns the rewritten region and the number of scopes elided — the
    /// figure every test below asserts on. `run_stats` exposes the rest.
    fn run(region: Region) -> (Region, i64) {
        let (out, stats) = run_stats(region);
        (out, stats.scopes)
    }

    fn run_stats(region: Region) -> (Region, Stats) {
        let mut stats = Stats::default();
        let out = elide(region, &mut stats);
        (out, stats)
    }

    #[test]
    fn a_tail_break_to_its_own_label_elides_the_scope() {
        let (out, n) = run(vacuous());
        assert_eq!(n, 1);
        // The scope is gone and the break became a Transfer carrying the
        // same assignments.
        let Region::Sequence(items) = out else {
            panic!("expected the body spliced in, got {out:?}");
        };
        assert!(matches!(items[0], Region::Basic(b) if b == bb(6)));
        assert!(matches!(
            &items[1],
            Region::Transfer { target, transfer }
                if *target == bb(7) && transfer == &vec![(v(40), v(30))]
        ));
    }

    #[test]
    fn a_second_break_to_the_label_keeps_the_scope() {
        // The label is a real merge point for two paths.
        let region = Region::Scope {
            out: bb(7),
            body: Box::new(Region::Sequence(vec![
                Region::If {
                    cond: v(1),
                    then_region: Box::new(brk(7, vec![])),
                    else_region: None,
                },
                brk(7, vec![]),
            ])),
        };
        let (out, n) = run(region);
        assert_eq!(n, 0);
        assert!(matches!(out, Region::Scope { .. }));
    }

    #[test]
    fn a_break_that_is_not_in_tail_position_keeps_the_scope() {
        // Breaking early skips the rest of the body — that is real control
        // flow, not a fallthrough.
        let region = Region::Scope {
            out: bb(7),
            body: Box::new(Region::Sequence(vec![
                brk(7, vec![]),
                Region::Basic(bb(6)),
            ])),
        };
        assert_eq!(run(region).1, 0);
    }

    #[test]
    fn a_break_inside_a_trailing_if_arm_is_a_tail_exit() {
        // The arm that breaks and the arm that falls through land in the
        // *same place* — past the end of the scope. So the break carries no
        // information and the label merges nothing.
        //
        // This is the reading the pass used to get backwards ("the other arm
        // falls through, so the label still merges two paths"), and
        // correcting it is what takes the pass from 2 scopes on the corpus
        // to the bulk of them.
        let region = Region::Scope {
            out: bb(7),
            body: Box::new(Region::Sequence(vec![
                Region::Basic(bb(6)),
                Region::If {
                    cond: v(1),
                    then_region: Box::new(brk(7, vec![])),
                    else_region: None,
                },
            ])),
        };
        let (out, n) = run(region);
        assert_eq!(n, 1);
        let Region::Sequence(items) = out else {
            panic!("expected the body spliced in, got {out:?}");
        };
        let Region::If { then_region, .. } = &items[1] else {
            panic!("expected the if to survive, got {:?}", items[1]);
        };
        assert!(matches!(**then_region, Region::Transfer { .. }));
    }

    #[test]
    fn a_shadowed_label_is_resolved_innermost_first() {
        // 'bb7: { 'bb7: { break 'bb7 } } — the break belongs to the INNER
        // scope, and bottom-up order is what gets that right: the inner is
        // vacuous and goes, after which the outer has no break to its label
        // and stays. The outer must never claim a break it does not own.
        let region = Region::Scope {
            out: bb(7),
            body: Box::new(Region::Scope {
                out: bb(7),
                body: Box::new(brk(7, vec![])),
            }),
        };
        let (out, n) = run(region);
        assert_eq!(n, 1, "only the inner scope is vacuous");
        let Region::Scope { out: label, body } = out else {
            panic!("the outer scope owns no break and must survive");
        };
        assert_eq!(label, bb(7));
        assert!(matches!(*body, Region::Transfer { .. }));
    }

    #[test]
    fn a_live_shadowing_scope_stops_the_outer_from_claiming_its_break() {
        // Same shadowing, but the inner scope is NOT vacuous (two breaks to
        // its label), so it survives — and the outer must not then read the
        // inner's tail break as its own.
        let region = Region::Scope {
            out: bb(7),
            body: Box::new(Region::Scope {
                out: bb(7),
                body: Box::new(Region::Sequence(vec![
                    Region::If {
                        cond: v(1),
                        then_region: Box::new(brk(7, vec![])),
                        else_region: None,
                    },
                    Region::Basic(bb(6)),
                    brk(7, vec![]),
                ])),
            }),
        };
        let (out, n) = run(region);
        assert_eq!(n, 0, "neither scope may be elided");
        let Region::Scope { body, .. } = out else {
            panic!("outer scope must survive");
        };
        assert!(
            matches!(*body, Region::Scope { .. }),
            "inner scope must survive too"
        );
    }

    #[test]
    fn a_scope_with_no_break_to_its_label_keeps_it() {
        // Zero breaks is not this pass's shape: the label may be unused
        // residue, but eliding it is `Sequence` flattening's job and the
        // count-of-one rule is what makes the tail rewrite meaningful.
        let region = Region::Scope {
            out: bb(7),
            body: Box::new(Region::Basic(bb(6))),
        };
        assert_eq!(run(region).1, 0);
    }

    #[test]
    fn an_inner_break_to_an_outer_label_survives_the_splice() {
        // 'bb9: { 'bb7: { break 'bb9 ; break 'bb7 } } — eliding bb7 leaves
        // the bb9 break still inside bb9.
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
                    brk(7, vec![]),
                ])),
            }),
        };
        let (out, n) = run(region);
        assert_eq!(n, 1, "the inner scope is vacuous and the outer is not");
        // Outer scope intact, inner gone.
        let Region::Scope { out: label, body } = out else {
            panic!("outer scope must survive");
        };
        assert_eq!(label, bb(9));
        assert!(
            !matches!(*body, Region::Scope { .. }),
            "inner scope should be spliced away"
        );
    }

    #[test]
    fn nested_vacuous_scopes_both_go_in_one_pass() {
        // Bottom-up order is what makes this work.
        let region = Region::Scope {
            out: bb(9),
            body: Box::new(Region::Sequence(vec![
                Region::Scope {
                    out: bb(7),
                    body: Box::new(brk(7, vec![])),
                },
                brk(9, vec![]),
            ])),
        };
        assert_eq!(run(region).1, 2);
    }

    #[test]
    fn a_loop_body_is_walked_but_a_continue_is_left_alone() {
        let region = Region::Loop {
            header: bb(1),
            kind: LoopKind::Unclassified,
            body: Box::new(Region::Sequence(vec![
                vacuous(),
                Region::Continue {
                    target: bb(1),
                    transfer: vec![],
                },
            ])),
        };
        let (out, n) = run(region);
        assert_eq!(n, 1);
        assert!(matches!(out, Region::Loop { .. }));
    }

    #[test]
    fn switch_arms_are_walked() {
        let region = Region::Switch {
            index: v(1),
            arms: vec![SwitchArm {
                cases: vec![0],
                body: vacuous(),
            }],
            default: Box::new(vacuous()),
            dispatch: None,
        };
        assert_eq!(run(region).1, 2);
    }

    // --- the tail-exit table, one test per row ---

    #[test]
    fn every_switch_arm_ending_in_a_break_is_a_tail_exit() {
        // token-v23's `bb4`: a match whose arms each assign the merge phi
        // and break. The switch is the last thing in the scope, so every
        // arm lands past its end — `match` arms fall through natively.
        let arm = |c: u32, val: u32| SwitchArm {
            cases: vec![c],
            body: Region::Sequence(vec![Region::Basic(bb(val)), brk(7, vec![])]),
        };
        let region = Region::Scope {
            out: bb(7),
            body: Box::new(Region::Switch {
                index: v(1),
                arms: vec![arm(0, 20), arm(1, 21)],
                default: Box::new(Region::Unreachable),
                dispatch: None,
            }),
        };
        let (out, stats) = run_stats(region);
        assert_eq!(stats.scopes, 1, "no exit is left to name the label");
        assert_eq!(stats.breaks, 2);
        assert!(matches!(out, Region::Switch { .. }), "got {out:?}");
    }

    #[test]
    fn a_break_at_the_tail_of_a_loop_body_is_not_a_tail_exit() {
        // THE negative that matters. Falling off a loop body reaches the
        // back edge — another iteration — not the enclosing scope's end. So
        // this break carries real information and must survive, even though
        // the loop is the last thing in the scope.
        let region = Region::Scope {
            out: bb(7),
            body: Box::new(Region::Loop {
                header: bb(1),
                kind: LoopKind::Unclassified,
                body: Box::new(Region::Sequence(vec![
                    Region::Basic(bb(6)),
                    brk(7, vec![]),
                ])),
            }),
        };
        let (out, stats) = run_stats(region);
        assert_eq!(stats.breaks, 0, "a loop body is not a tail exit");
        assert_eq!(stats.scopes, 0);
        assert_eq!(stats.live_labels, 1);
        assert!(matches!(out, Region::Scope { .. }));
    }

    #[test]
    fn both_arms_of_a_trailing_if_else_are_tail_exits() {
        let region = Region::Scope {
            out: bb(7),
            body: Box::new(Region::If {
                cond: v(1),
                then_region: Box::new(brk(7, vec![(v(40), v(30))])),
                else_region: Some(Box::new(brk(7, vec![(v(40), v(31))]))),
            }),
        };
        let (out, stats) = run_stats(region);
        assert_eq!(stats.breaks, 2);
        assert_eq!(stats.scopes, 1);
        let Region::If {
            then_region,
            else_region,
            ..
        } = out
        else {
            panic!("expected the if to survive");
        };
        // Both edges keep their own phi assignment.
        assert!(matches!(*then_region, Region::Transfer { .. }));
        assert!(matches!(*else_region.unwrap(), Region::Transfer { .. }));
    }

    #[test]
    fn an_inner_scope_passes_the_tail_exit_through() {
        // Falling out of 'bb8 lands at 'bb7's continuation, so a break to
        // 'bb7 from 'bb8's tail is still going where control was headed.
        let region = Region::Scope {
            out: bb(7),
            body: Box::new(Region::Scope {
                out: bb(8),
                body: Box::new(Region::Sequence(vec![
                    Region::Basic(bb(6)),
                    brk(7, vec![]),
                ])),
            }),
        };
        let (_, stats) = run_stats(region);
        assert_eq!(stats.breaks, 1);
        assert_eq!(stats.scopes, 1, "the outer label is the one that goes");
    }

    #[test]
    fn a_guarded_break_survives_while_the_tail_one_goes() {
        // token-v23's `bb7`: an if/else in disguise. The guarded break skips
        // the code after the `if`, so it is real control flow; the trailing
        // one is not. The scope keeps its label for the survivor, and the
        // live-label counter is what sizes the follow-up transform.
        let region = Region::Scope {
            out: bb(7),
            body: Box::new(Region::Sequence(vec![
                Region::If {
                    cond: v(1),
                    then_region: Box::new(brk(7, vec![])),
                    else_region: None,
                },
                Region::Basic(bb(6)),
                brk(7, vec![]),
            ])),
        };
        let (out, stats) = run_stats(region);
        assert_eq!(stats.breaks, 1, "only the trailing break is vacuous");
        assert_eq!(stats.scopes, 0);
        assert_eq!(stats.live_labels, 1);
        let Region::Scope { body, .. } = out else {
            panic!("the scope must survive for the guarded break");
        };
        let Region::Sequence(items) = *body else {
            panic!("expected a sequence");
        };
        let Region::If { then_region, .. } = &items[0] else {
            panic!("expected the guard to survive");
        };
        assert!(matches!(**then_region, Region::Break { .. }), "guard kept");
        assert!(matches!(items[2], Region::Transfer { .. }), "tail converted");
    }

    #[test]
    fn a_second_run_changes_nothing() {
        let (once, first) = run(vacuous());
        assert_eq!(first, 1);
        let (_, second) = run(once);
        assert_eq!(second, 0, "the rewrite must not re-fire on its own output");
    }
}
