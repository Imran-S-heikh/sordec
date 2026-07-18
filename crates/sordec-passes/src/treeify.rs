//! Treeification statistics pass (Phase-3 B6 metrics surface).
//!
//! Terminal, diagnostics-only `Pass<HighIr>` — the same contract as
//! [`crate::UnrecognizedScanPass`]: it never rewrites anything. It
//! builds an [`InlinePlan`] per function and emits the `treeify_*`
//! counters so `PipelineReport::metric_totals` (and, in W8, the
//! coverage surface) can report how much of the IR is foldable, how
//! much the K4 effect discipline pins despite being single-use, and
//! how much de-clutter residue is hidden.
//!
//! Consumers that need the plan itself (the renderer, refinement
//! passes, the emitter) rebuild it on demand — it is a cheap
//! deterministic analysis, and a stored copy would go stale the moment
//! any pass rewrites a binding.

use sordec_ir::HighIr;

use crate::dataflow::InlinePlan;
use crate::pass::{Pass, PassResult};

/// Unique pipeline name of this pass.
pub const PASS_NAME: &str = "treeify-stats";

/// Bindings classified `Inline` (pure-total, single live use).
const M_INLINE: &str = "treeify_inline";
/// Single-live-use bindings pinned only by their effects.
const M_PINNED_SINGLE_USE: &str = "treeify_pinned_single_use";
/// De-clutter residue bindings classified `Dead`.
const M_DEAD_RESIDUE: &str = "treeify_dead_residue";

/// The treeification-statistics pass. Stateless; see the module docs.
#[derive(Debug, Default, Clone, Copy)]
pub struct TreeifyStatsPass;

impl Pass<HighIr> for TreeifyStatsPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let mut inline: i64 = 0;
        let mut pinned_single_use: i64 = 0;
        let mut dead_residue: i64 = 0;
        for func in &ir.functions {
            let stats = InlinePlan::build(func).stats();
            inline += stats.inline as i64;
            pinned_single_use += stats.pinned_single_use as i64;
            dead_residue += stats.dead_residue as i64;
        }
        if inline > 0 {
            result.metrics.increment(M_INLINE, inline);
        }
        if pinned_single_use > 0 {
            result.metrics.increment(M_PINNED_SINGLE_USE, pinned_single_use);
        }
        if dead_residue > 0 {
            result.metrics.increment(M_DEAD_RESIDUE, dead_residue);
        }
        // Metrics-only: `changed` stays false by definition (the
        // fixpoint contract's "provenance/notes/metrics don't count").
        result
    }
}
