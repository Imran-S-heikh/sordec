//! Pre-structuring de-cluttering passes over [`sordec_ir::LiftedIr`].
//!
//! Our lift runs waffle's `convert_to_max_ssa(None)` (`lift.rs`), which
//! parks every live value in a block parameter at every block it
//! crosses and funnels function exits through a synthetic return block.
//! Correct SSA — but measured on the seven-fixture corpus it means 73%
//! of all block parameters are trivial phis, plus ~2,500 alias defs and
//! hundreds of empty forwarding/merge blocks. Structuring the raw soup
//! would make every downstream refinement pattern unmatchable (Phase-3
//! kickoff, R5).
//!
//! The passes in this module normalize the lifted CFG and SSA name
//! graph **without moving or deleting anything observable** (kickoff
//! K4). Two of them delete code and are therefore gated:
//! dead-*block* clearing requires unreachability from the entry (never
//! executes), and dead-*value* sweeping requires a pure-total effect
//! row from [`crate::effects`] (may not trap, read, or write). All the
//! others — alias resolution, trivial-phi pruning, jump threading,
//! chain merging — are pure rewiring: no computation changes its
//! execution order.
//!
//! ## Fixpoint contract for transforms
//!
//! The [`crate::Pass`] docs describe monotonicity in recognizer terms
//! ("adds information or replaces an `Unknown`"). De-cluttering passes
//! are *transforms*; what the pipeline's fixpoint loop actually needs
//! from them is an honest `changed` flag and a termination measure.
//! Every pass here strictly decreases the tuple
//! `(reachable blocks, CFG edges, scheduled instructions, block
//! params)` or reports `changed: false`.
//!
//! Two passes in [`crate::default_lifted_pipeline`]'s fixpoint group are
//! not from this module and do **not** decrease that tuple, so the group
//! terminates on a lexicographic extension of it:
//!
//! - [`crate::SlotPromotionPass`] *increases* block params and scheduled
//!   instructions — that is its whole method (a parameter in every
//!   reachable block, plus an initial constant). It strictly decreases
//!   **the number of promotable frame slots**: promoting one retires
//!   every load and store that made it promotable, so `discover` cannot
//!   see it again. Its `second_run_reports_no_work` test is that
//!   property stated as a test.
//! - [`ResolveAliasesPass`] moves nothing at all, so it decreases no
//!   component of the tuple. It strictly decreases **the number of
//!   alias uses**, which is bounded and which nothing in the group
//!   increases except promotion — and promotion creates finitely many
//!   per slot it retires.
//!
//! Ordering the extended measure as `(promotable slots, alias uses, the
//! four original components)` gives a well-founded descent for the whole
//! group: promotion is the only pass that raises the later components,
//! and it strictly lowers the first.
//!
//! ## Tombstones, not compaction
//!
//! [`sordec_common::Arena`] is push-only, so nothing is ever removed
//! from the `values`/`blocks` arenas. "Deleted" params/values become
//! unscheduled residue (pruned params are rewritten to
//! [`sordec_ir::LiftedValueDef::Alias`] pointing at their replacement);
//! emptied blocks keep their id with an `Unreachable` terminator.
//! Renderers hide residue behind honest count lines; ids stay stable
//! across the whole pipeline for diffable dumps.

mod merge_chains;
mod prune_dead_params;
mod prune_phis;
mod resolve_aliases;
mod sweep_dead;
mod thread_jumps;

pub use merge_chains::MergeBlockChainsPass;
pub use prune_dead_params::PruneDeadParamsPass;
pub use prune_phis::PruneTrivialPhisPass;
pub use resolve_aliases::ResolveAliasesPass;
pub use sweep_dead::SweepDeadPass;
pub use thread_jumps::ThreadTrivialJumpsPass;

use std::collections::HashMap;

use sordec_common::{BlockId, ValueId};
use sordec_ir::{BlockTarget, LiftedFunction, LiftedTerminator, LiftedValueDef};

/// Drop the block parameters a per-block keep-mask marks `false`, and the
/// matching positional argument from every edge into those blocks.
///
/// Shared by [`PruneTrivialPhisPass`] and [`PruneDeadParamsPass`], which
/// disagree about *which* parameters to remove but must perform the
/// removal identically — parameters and edge arguments are matched
/// positionally, so a discrepancy between the two would corrupt every
/// parameter after the dropped one.
///
/// Three things happen, in this order:
///
/// 1. **Every terminator** is swept, including those of *unreachable*
///    predecessors. They never execute, but their argument lists still
///    have to match the arity of the block they name.
/// 2. Each masked block's parameter list is filtered.
/// 3. Survivors' [`LiftedValueDef::BlockParam`] `index` fields are
///    renumbered to their new positions.
///
/// The removed parameters' own defs are left to the caller: the two
/// passes leave different residue, because one has a replacement value to
/// point at and the other does not.
pub(crate) fn drop_params(func: &mut LiftedFunction, masks: &HashMap<BlockId, Vec<bool>>) {
    for (_id, block) in func.blocks.iter_mut() {
        for_each_target_mut(&mut block.terminator, |target| {
            if let Some(mask) = masks.get(&target.block) {
                let mut position = 0;
                target.args.retain(|_| {
                    let keep = mask.get(position).copied().unwrap_or(true);
                    position += 1;
                    keep
                });
            }
        });
    }

    for (&block_id, mask) in masks {
        let Some(block) = func.blocks.get_mut(block_id) else {
            continue;
        };
        let mut position = 0;
        block.params.retain(|_| {
            let keep = mask.get(position).copied().unwrap_or(true);
            position += 1;
            keep
        });
        // Renumber survivors' BlockParam defs to their new positions.
        for (index, &param) in block.params.clone().iter().enumerate() {
            if let Some(value) = func.values.get_mut(param) {
                value.def = LiftedValueDef::BlockParam {
                    block: block_id,
                    index: index as u32,
                };
            }
        }
    }
}

/// Visit every [`BlockTarget`] of a terminator mutably.
///
/// Mutable counterpart of [`crate::dataflow::for_each_target`], local to
/// this module until a second consumer family needs it.
pub(crate) fn for_each_target_mut<F: FnMut(&mut BlockTarget)>(
    term: &mut LiftedTerminator,
    mut f: F,
) {
    match term {
        LiftedTerminator::Branch(target) => f(target),
        LiftedTerminator::BranchIf {
            if_true, if_false, ..
        } => {
            f(if_true);
            f(if_false);
        }
        LiftedTerminator::Switch {
            targets, default, ..
        } => {
            for target in targets {
                f(target);
            }
            f(default);
        }
        LiftedTerminator::Return { .. } | LiftedTerminator::Unreachable => {}
    }
}

/// Rewrite every value **use** in `func` through `resolve`, returning
/// how many ids actually changed.
///
/// Uses are: `Operator` args, `Alias` targets, `PickOutput` sources,
/// terminator conditions / switch indices / return values, and every
/// `BlockTarget` argument. `BlockParam` defs define — nothing to
/// rewrite. The `resolve` closure must be a projection (applying it to
/// its own output returns the same id), which every caller in this
/// module guarantees by resolving through a chased map.
pub(crate) fn rewrite_uses<F: Fn(ValueId) -> ValueId>(func: &mut LiftedFunction, resolve: F) -> u64 {
    let mut changed: u64 = 0;
    let mut apply = |slot: &mut ValueId| {
        let new = resolve(*slot);
        if new != *slot {
            *slot = new;
            changed += 1;
        }
    };

    for (_id, value) in func.values.iter_mut() {
        match &mut value.def {
            LiftedValueDef::Operator { args, .. } => {
                for arg in args {
                    apply(arg);
                }
            }
            LiftedValueDef::Alias(target) => apply(target),
            LiftedValueDef::PickOutput { from, .. } => apply(from),
            LiftedValueDef::BlockParam { .. } => {}
        }
    }

    for (_id, block) in func.blocks.iter_mut() {
        match &mut block.terminator {
            LiftedTerminator::BranchIf { cond, .. } => apply(cond),
            LiftedTerminator::Switch { index, .. } => apply(index),
            LiftedTerminator::Return { values } => {
                for value in values {
                    apply(value);
                }
            }
            LiftedTerminator::Branch(_) | LiftedTerminator::Unreachable => {}
        }
        for_each_target_mut(&mut block.terminator, |target| {
            for arg in &mut target.args {
                apply(arg);
            }
        });
    }

    changed
}
