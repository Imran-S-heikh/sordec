//! Vacuous-scope elision — a labeled scope whose only exit is falling off
//! its own end.
//!
//! The structurer emits a `Scope` for every CFG forward-merge point,
//! because that is what the CFG says. Once the passes above have folded a
//! width dispatch or collapsed an encode, a scope can be left with exactly
//! one `Break` to its label, sitting in tail position — which is to say the
//! scope no longer scopes anything:
//!
//! ```text
//! 'bb7: {                        REST
//!     REST            →          <transfer>
//!     v40 = v30                  ;; bb7 …
//!     break 'bb7
//! }
//! ;; bb7 …
//! ```
//!
//! Breaking out of a block from its last statement is the same control flow
//! as running off the end of it. The label and the `break` are pure
//! structuring residue.
//!
//! The `Break` becomes a [`Region::Transfer`], not nothing: the edge still
//! carries the phi assignments that the merge block's parameters need, and
//! `Transfer` is exactly the "fall through into `target`'s region without
//! exiting a scope, assigning phi inputs first" form. Only the `break`
//! goes.
//!
//! ## Why this is worth a pass
//!
//! `sordec-score`'s structure skeleton counts a `break` as a control-flow
//! token while the labeled block itself costs nothing (it has no
//! `visit_expr_block` override). So a vacuous scope contributes exactly one
//! surplus token, measured against an original that never wrote it. It is
//! also the measure `super`'s charter names: this pass strictly reduces the
//! `{Scope, Break}` node count.
//!
//! ## What it will not touch
//!
//! Narrow on purpose — the corpus census found only **2** scopes in this
//! shape (hello-add and attestation) against **101** with a live label, so
//! the value is in being certainly right rather than broadly applicable:
//!
//! - more than one `Break` to the label, or one that is not in tail
//!   position — the label is doing real work;
//! - a nested `Scope` inside the body re-declaring the same `out` — then
//!   the tail break belongs to the inner scope, not this one, and hoisting
//!   would silently retarget it;
//! - a body carrying a `Break`/`Continue` to a label declared *by* this
//!   scope's subtree is fine, but one that would be left unenclosed is not
//!   — see [`breaks_stay_enclosed`].
//!
//! That last rule is the invariant `sordec_ir::validate` calls label
//! enclosure, and getting it wrong is the one way this pass can produce an
//! IR that does not validate. `debug_validate` runs after every rewrite.

use std::collections::HashSet;

use sordec_common::BlockId;
use sordec_ir::{HighIr, Region};

use super::debug_validate;
use crate::pass::{Pass, PassResult};
use crate::structuring::seq;

/// Unique pipeline name of this pass.
pub const PASS_NAME: &str = "refine-scope-fallthrough";

use crate::metrics_catalog::REFINE_SCOPES_FALLTHROUGH as M_ELIDED;

/// Elides labeled scopes whose sole `Break` is a fallthrough. Stateless.
#[derive(Debug, Default, Clone, Copy)]
pub struct ScopeFallthroughPass;

impl Pass<HighIr> for ScopeFallthroughPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let mut elided: i64 = 0;
        for func in &mut ir.functions {
            let region = std::mem::replace(&mut func.region, Region::Unreachable);
            func.region = elide(region, &mut elided);
        }
        if elided > 0 {
            result.metrics.increment(M_ELIDED, elided);
            result.changed = true;
        }
        debug_validate(ir, PASS_NAME);
        result
    }
}

/// Bottom-up structural rewrite. Children first, so an inner scope that
/// becomes vacuous is elided before its parent is judged — which is what
/// makes one pass enough for a nest of them.
fn elide(region: Region, elided: &mut i64) -> Region {
    match region {
        Region::Sequence(items) => {
            seq(items.into_iter().map(|item| elide(item, elided)).collect())
        }
        Region::Scope { out, body } => {
            let body = elide(*body, elided);
            match fallthrough_body(out, body) {
                Ok(spliced) => {
                    *elided += 1;
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
            body: Box::new(elide(*body, elided)),
            kind,
        },
        Region::If {
            cond,
            then_region,
            else_region,
        } => Region::If {
            cond,
            then_region: Box::new(elide(*then_region, elided)),
            else_region: else_region.map(|e| Box::new(elide(*e, elided))),
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
                    arm.body = elide(arm.body, elided);
                    arm
                })
                .collect(),
            default: Box::new(elide(*default, elided)),
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

/// `body` with its tail `Break` to `out` rewritten as a `Transfer`, or the
/// body unchanged in `Err` when the scope must stay.
fn fallthrough_body(out: BlockId, body: Region) -> Result<Region, Region> {
    // Exactly one break to this label, and it is the last thing the body
    // does. Anything else and the label is load-bearing.
    if count_breaks_to(out, &body) != 1 || !tail_breaks_to(out, &body) {
        return Err(body);
    }
    // A nested scope re-declaring `out` owns the tail break, not us.
    if redeclares(out, &body) {
        return Err(body);
    }
    // Every other labeled exit in the body must still find its scope after
    // the splice.
    if !breaks_stay_enclosed(&body, &mut HashSet::new()) {
        return Err(body);
    }
    Ok(rewrite_tail(body))
}

/// How many `Break`s in `body` target `out`, not descending into a nested
/// scope that re-declares it (those belong to the inner scope).
fn count_breaks_to(out: BlockId, body: &Region) -> usize {
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

/// Whether the *last* thing `body` does is break to `out`.
///
/// Only a direct tail: a break at the end of one arm of a trailing `If` is
/// not the body's tail, because the other arm falls through.
fn tail_breaks_to(out: BlockId, body: &Region) -> bool {
    match body {
        Region::Break { target, .. } => *target == out,
        Region::Sequence(items) => items.last().is_some_and(|l| tail_breaks_to(out, l)),
        _ => false,
    }
}

/// Whether any nested `Scope` inside `body` declares `out` as its own
/// label.
fn redeclares(out: BlockId, body: &Region) -> bool {
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
fn breaks_stay_enclosed(body: &Region, declared: &mut HashSet<BlockId>) -> bool {
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

/// Replace the tail `Break` with a `Transfer`, preserving its phi
/// assignments.
fn rewrite_tail(body: Region) -> Region {
    match body {
        Region::Break { target, transfer } => Region::Transfer { target, transfer },
        Region::Sequence(mut items) => {
            if let Some(last) = items.pop() {
                items.push(rewrite_tail(last));
            }
            seq(items)
        }
        other => other,
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

    fn run(region: Region) -> (Region, i64) {
        let mut n = 0;
        let out = elide(region, &mut n);
        (out, n)
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
    fn a_break_inside_a_trailing_if_arm_is_not_a_tail_break() {
        // The other arm falls through, so the label still merges two paths.
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
        assert_eq!(run(region).1, 0);
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

    #[test]
    fn a_second_run_changes_nothing() {
        let (once, first) = run(vacuous());
        assert_eq!(first, 1);
        let (_, second) = run(once);
        assert_eq!(second, 0, "the rewrite must not re-fire on its own output");
    }
}
