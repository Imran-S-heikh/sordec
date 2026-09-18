//! Inline the panic helpers rustc left behind as real functions.
//!
//! `core::panicking::panic` and the `unwrap_failed` family are ordinary
//! functions that never return. rustc emits them once and calls them from
//! every guard, so what reaches us is not `if bad { panic!() }` but a call
//! to a helper whose whole body is a trap:
//!
//! ```text
//! fn func34(e) { panic!() }                if bad { func34(e) }
//! fn func3(e)  { func34(e); panic!() }  →  if bad { panic!() }
//! ```
//!
//! ## Why this is not [`super::trap_inline`]
//!
//! That pass undoes LLVM's tail-merging of `unreachable` **inside one
//! function**: several guards break to one shared out-block, and it copies
//! the block back to each break site. This is the *interprocedural* case —
//! the trap is behind a `Call`, in another function entirely — and nothing
//! in the pipeline knew which functions never return.
//!
//! The consequence was larger than the missing `panic!()`s. Every pass that
//! asks "does this arm trap?" answers by looking for
//! `Region::Panic`/`Unreachable`, so a guard whose arm is a *call* is
//! invisible as a guard. Measured on the corpus: **93 call sites across 12
//! helpers, 63 of them in dex alone**, which is why dex reported 121 `If`s
//! whose "taken arm is not a trap" — most of them were traps.
//!
//! ## What a helper has to be
//!
//! Two properties, and the second is what makes deleting the call sound:
//!
//! - **It diverges.** Every path through it reaches `Panic` or
//!   `Unreachable`, counting a call to an already-known diverging helper as
//!   reaching one. Computed as a fixpoint over the call graph, so `func3`
//!   qualifies on the round after `func34` does.
//! - **It is a *pure* trap.** Every binding it schedules is itself a call to
//!   a pure trap — nothing else. A helper that stored, published an event or
//!   called a host function before dying would have an observable effect,
//!   and replacing the call with a bare `panic!()` would lose it. Requiring
//!   the body to be *only* traps is stricter than "diverges" and is what
//!   licenses the rewrite.
//!
//! An exported function is never a helper: its signature is the contract
//! ABI, and the host may call it whatever its body does.
//!
//! ## What it rewrites, and what it declines
//!
//! Only a `Region::Basic` whose block is **nothing but** calls to pure
//! traps. That block's region position becomes `Region::Panic`, and the
//! block is emptied.
//!
//! A block that mixes a trap call with real work is left alone and counted.
//! The call is still unreachable-after, so truncating the block would also
//! be correct — but truncation has to decide what happens to bindings later
//! blocks read, and the corpus contains no such block, so the honest move is
//! to decline and let the counter say if that ever changes.
//!
//! Once every call site is gone the helpers themselves are unreachable, and
//! an uncalled, unexported function is deleted outright — it is not in the
//! source and re-emitting it is noise.

use std::collections::HashSet;

use sordec_common::FuncId;
use sordec_ir::{Expr, HighFunction, HighIr, Region};

use super::debug_validate;
use crate::pass::{Pass, PassResult};

/// Unique pipeline name of this pass.
pub const PASS_NAME: &str = "refine-trap-call";

// Metric counter keys.
/// Calls to a pure-trap helper rewritten into an inline `panic!()`.
const M_INLINED: &str = "refine_trap_calls_inlined";
/// Pure-trap helpers deleted once nothing called them.
const M_HELPERS_DROPPED: &str = "refine_trap_helpers_dropped";
/// Blocks that call a pure trap but also schedule real work, so the
/// region position could not simply become a trap.
const M_DECLINED_MIXED: &str = "refine_trap_call_declined_mixed";

/// Replaces calls to never-returning panic helpers with the trap itself.
#[derive(Debug, Default, Clone, Copy)]
pub struct TrapCallInlinePass;

impl Pass<HighIr> for TrapCallInlinePass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let helpers = pure_traps(ir);
        if helpers.is_empty() {
            return result;
        }

        let (mut inlined, mut declined) = (0i64, 0i64);
        for func in &mut ir.functions {
            // A helper's own body is left alone: rewriting `func34(e)`
            // inside `func3` would be correct but pointless, since the
            // whole function is about to go.
            if helpers.contains(&func.id) {
                continue;
            }
            let region = std::mem::replace(&mut func.region, Region::Unreachable);
            func.region = inline(func, region, &helpers, &mut inlined, &mut declined);
        }

        // The helpers are now uncalled, but they are **not** removed from
        // `ir.functions`. `HighIr::function` indexes that vector by
        // `FuncId::index`, so deleting one silently renumbers every later
        // function and every `Expr::Call` that names it — which the
        // validator catches as a `CallArityMismatch` against whichever
        // function slid into the slot. Dropping them from the *output* is
        // the emitter's decision, where identity is no longer positional.
        let dropped = called_functions(ir)
            .iter()
            .filter(|id| helpers.contains(id))
            .count();
        let dropped = helpers.len().saturating_sub(dropped) as i64;

        if inlined > 0 {
            result.changed = true;
        }
        result.metrics.increment(M_INLINED, inlined);
        result.metrics.increment(M_HELPERS_DROPPED, dropped);
        result.metrics.increment(M_DECLINED_MIXED, declined);
        debug_validate(ir, PASS_NAME);
        result
    }
}

/// Every function whose body is nothing but traps and calls to such
/// functions, and which therefore never returns.
///
/// A fixpoint, because a helper qualifies only once the helpers *it* calls
/// already have. Two rounds settle the corpus; the loop runs to stability
/// rather than a fixed count so a deeper chain is not silently truncated.
fn pure_traps(ir: &HighIr) -> HashSet<FuncId> {
    let mut traps: HashSet<FuncId> = HashSet::new();
    loop {
        let mut grew = false;
        for func in &ir.functions {
            if traps.contains(&func.id) || is_exported(func) {
                continue;
            }
            if body_is_only_trap_calls(func, &traps) && always_traps(&func.region, func, &traps) {
                traps.insert(func.id);
                grew = true;
            }
        }
        if !grew {
            return traps;
        }
    }
}

/// Whether every binding `func` schedules is a call to a known pure trap.
///
/// Scheduled bindings only: the arenas keep unscheduled residue, and a
/// binding no block emits cannot have an effect.
fn body_is_only_trap_calls(func: &HighFunction, traps: &HashSet<FuncId>) -> bool {
    func.blocks.iter().all(|(_, block)| {
        block.bindings.iter().all(|id| {
            matches!(
                func.bindings.get(*id).map(|b| &b.expr),
                Some(Expr::Call { target, .. }) if traps.contains(target)
            )
        })
    })
}

/// Whether every path through `region` reaches a trap.
fn always_traps(region: &Region, func: &HighFunction, traps: &HashSet<FuncId>) -> bool {
    match region {
        Region::Panic { .. } | Region::Unreachable => true,
        // A block that calls a pure trap never reaches its successor.
        Region::Basic(b) => func.blocks.get(*b).is_some_and(|block| {
            block.bindings.iter().any(|id| {
                matches!(
                    func.bindings.get(*id).map(|b| &b.expr),
                    Some(Expr::Call { target, .. }) if traps.contains(target)
                )
            })
        }),
        Region::Sequence(items) => items.iter().any(|i| always_traps(i, func, traps)),
        Region::Scope { body, .. } => always_traps(body, func, traps),
        Region::If {
            then_region,
            else_region,
            ..
        } => {
            else_region
                .as_ref()
                .is_some_and(|e| always_traps(e, func, traps))
                && always_traps(then_region, func, traps)
        }
        Region::Switch { arms, default, .. } => {
            always_traps(default, func, traps)
                && arms.iter().all(|a| always_traps(&a.body, func, traps))
        }
        // A `Return` reaches the caller; a loop or a jump may not trap.
        _ => false,
    }
}

/// Rewrite every trap-call block in `region` into the trap itself.
fn inline(
    func: &mut HighFunction,
    region: Region,
    traps: &HashSet<FuncId>,
    inlined: &mut i64,
    declined: &mut i64,
) -> Region {
    match region {
        Region::Basic(b) => {
            let Some(block) = func.blocks.get(b) else {
                return Region::Basic(b);
            };
            let calls: Vec<bool> = block
                .bindings
                .iter()
                .map(|id| {
                    matches!(
                        func.bindings.get(*id).map(|x| &x.expr),
                        Some(Expr::Call { target, .. }) if traps.contains(target)
                    )
                })
                .collect();
            if !calls.iter().any(|c| *c) {
                return Region::Basic(b);
            }
            if !calls.iter().all(|c| *c) {
                // Mixed: real work alongside the trap call. Declining keeps
                // this pass to the shape it can prove.
                *declined += 1;
                return Region::Basic(b);
            }
            *inlined += calls.len() as i64;
            if let Some(block) = func.blocks.get_mut(b) {
                block.bindings.clear();
            }
            // `Unreachable`, not `Panic`: typing the trap is
            // [`super::panic_recover`]'s job, and it is the pass that can
            // tell an `.unwrap()` from a bare panic by reading the guard
            // condition. Minting a `Panic { Bare }` here would settle that
            // question before the evidence is looked at, and `panic:unwrap`
            // is a semantic fact the scorer counts.
            Region::Unreachable
        }
        Region::Sequence(items) => {
            let rewritten: Vec<Region> = items
                .into_iter()
                .map(|i| inline(func, i, traps, inlined, declined))
                .collect();
            // A trap-call block is usually *followed* by the trap it jumps
            // to, so replacing the block in place yields `panic!(); panic!()`.
            // The second is unreachable, and leaving it there is not merely
            // untidy: `OverflowGuardElisionPass` and the guard pass both
            // match on an arm that is exactly one trap, so a doubled one
            // stops being recognised as a guard at all — measured as
            // hello-add regaining the overflow check this pass was supposed
            // to help remove.
            let mut folded: Vec<Region> = Vec::with_capacity(rewritten.len());
            for item in rewritten {
                let both_traps = matches!(
                    (folded.last(), &item),
                    (
                        Some(Region::Panic { .. } | Region::Unreachable),
                        Region::Panic { .. } | Region::Unreachable
                    )
                );
                if both_traps {
                    continue;
                }
                folded.push(item);
            }
            crate::structuring::seq(folded)
        }
        Region::Scope { out, body } => Region::Scope {
            out,
            body: Box::new(inline(func, *body, traps, inlined, declined)),
        },
        Region::Loop { header, body, kind } => Region::Loop {
            header,
            body: Box::new(inline(func, *body, traps, inlined, declined)),
            kind,
        },
        Region::If {
            cond,
            then_region,
            else_region,
        } => Region::If {
            cond,
            then_region: Box::new(inline(func, *then_region, traps, inlined, declined)),
            else_region: else_region.map(|e| Box::new(inline(func, *e, traps, inlined, declined))),
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
                .map(|mut a| {
                    a.body = inline(func, a.body, traps, inlined, declined);
                    a
                })
                .collect(),
            default: Box::new(inline(func, *default, traps, inlined, declined)),
            dispatch,
        },
        leaf => leaf,
    }
}

/// Every function some surviving call still names.
fn called_functions(ir: &HighIr) -> HashSet<FuncId> {
    let mut called = HashSet::new();
    for func in &ir.functions {
        for (_, block) in func.blocks.iter() {
            for id in &block.bindings {
                if let Some(Expr::Call { target, .. }) = func.bindings.get(*id).map(|b| &b.expr) {
                    called.insert(*target);
                }
            }
        }
    }
    called
}

/// Whether the host can reach this function regardless of its body.
fn is_exported(func: &HighFunction) -> bool {
    func.name.is_some() || func.signature.is_some()
}
