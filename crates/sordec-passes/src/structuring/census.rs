//! Structuring census pass (Phase-3 A6 metrics surface, W8).
//!
//! Terminal, metrics-only `Pass<HighIr>` — the same never-rewrites
//! contract as [`crate::TreeifyStatsPass`]. It walks every function's
//! settled [`Region`] tree once and emits the structuring coverage
//! counters the `sordec coverage` `structuring:` section renders:
//! per-function structured ratio, the per-[`LoopKind`] breakdown,
//! recovered-`Switch` (`match`) count, and the labeled-exit
//! readability-tax meter.
//!
//! ## Why terminal, not the head [`StructuringStatsPass`]
//!
//! The census must observe the *final* tree the renderer and emitter
//! consume, which only exists at the end of the high pipeline:
//!
//! - Loop kinds are written by `LoopClassifyPass`; before it every
//!   [`Region::Loop`] still reads [`LoopKind::Unclassified`].
//! - The break/continue shape is rewritten by the trap-inline and
//!   trap-duplication refinements inside the fixpoint group.
//!
//! Running once as the last pipeline entry also keeps these as **census
//! values** — a pass inside the fixpoint group would have its counters
//! summed once per iteration by [`PipelineReport::metric_totals`]
//! (crate::PipelineReport::metric_totals).
//!
//! ## Relationship to `structuring_fallback`
//!
//! [`StructuringStatsPass`](super::StructuringStatsPass) emits the
//! *node-level* [`STRUCTURING_FALLBACK`](crate::metrics_catalog::STRUCTURING_FALLBACK)
//! counter (one per [`Region::Unstructured`]) with a diagnostic, at the
//! head of the pipeline. This pass emits the *function-level* view:
//! `functions_total` and `functions_structured` (functions with zero
//! `Unstructured` nodes). On the committed corpus both agree at 100%
//! (K3); they differ only when a single function has multiple
//! unstructured fragments.
//!
//! ## Labeled-continue caveat
//!
//! `structuring_labeled_continues` counts every [`Region::Continue`]
//! node, but `render_while` elides a `WhileTop` loop's back-edge
//! continue from the rendered source. The census is therefore an upper
//! bound on rendered labeled continues; it is deliberately
//! renderer-independent so the meter tracks structural complexity, not
//! a rendering artifact.

use sordec_ir::{HighIr, LoopKind, Region};

use crate::pass::{Pass, PassResult};

/// Unique pipeline name of this pass.
pub const PASS_NAME: &str = "structuring-census";

/// Local functions in the high IR.
const M_FUNCTIONS_TOTAL: &str = "structuring_functions_total";
/// Functions with zero `Region::Unstructured` nodes.
const M_FUNCTIONS_STRUCTURED: &str = "structuring_functions_structured";
/// `Region::Loop` nodes tagged `LoopKind::WhileTop`.
const M_LOOPS_WHILE_TOP: &str = "structuring_loops_while_top";
/// `Region::Loop` nodes tagged `LoopKind::DoWhileBottom`.
const M_LOOPS_DO_WHILE_BOTTOM: &str = "structuring_loops_do_while_bottom";
/// `Region::Loop` nodes tagged `LoopKind::GuardedDoWhile`.
const M_LOOPS_GUARDED_DO_WHILE: &str = "structuring_loops_guarded_do_while";
/// `Region::Loop` nodes tagged `LoopKind::Infinite`.
const M_LOOPS_INFINITE: &str = "structuring_loops_infinite";
/// `Region::Loop` nodes left `LoopKind::Unclassified`.
const M_LOOPS_UNCLASSIFIED: &str = "structuring_loops_unclassified";
/// `Region::Switch` nodes (recovered `match` constructs).
const M_SWITCHES: &str = "structuring_switches";
/// `Region::Break` nodes (rendered labeled breaks).
const M_LABELED_BREAKS: &str = "structuring_labeled_breaks";
/// `Region::Continue` nodes (upper bound on rendered labeled continues).
const M_LABELED_CONTINUES: &str = "structuring_labeled_continues";

/// Per-walk tally of the census counters. Kept as a plain struct so the
/// `LoopKind` match is exhaustive in one place (a new kind fails to
/// compile until it is counted).
#[derive(Debug, Default, Clone, Copy)]
struct Census {
    while_top: i64,
    do_while_bottom: i64,
    guarded_do_while: i64,
    infinite: i64,
    unclassified: i64,
    switches: i64,
    breaks: i64,
    continues: i64,
}

impl Census {
    /// Fold one region node into the running tally.
    fn record(&mut self, region: &Region) {
        match region {
            Region::Loop { kind, .. } => match kind {
                LoopKind::WhileTop => self.while_top += 1,
                LoopKind::DoWhileBottom => self.do_while_bottom += 1,
                LoopKind::GuardedDoWhile => self.guarded_do_while += 1,
                LoopKind::Infinite => self.infinite += 1,
                LoopKind::Unclassified => self.unclassified += 1,
            },
            Region::Switch { .. } => self.switches += 1,
            Region::Break { .. } => self.breaks += 1,
            Region::Continue { .. } => self.continues += 1,
            _ => {}
        }
    }
}

/// The structuring-census pass. Stateless; see the module docs.
#[derive(Debug, Default, Clone, Copy)]
pub struct StructuringCensusPass;

impl Pass<HighIr> for StructuringCensusPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();

        let functions_total = ir.functions.len() as i64;
        let mut functions_structured = 0i64;
        let mut census = Census::default();

        for func in &ir.functions {
            let mut saw_unstructured = false;
            func.region.for_each_node(|region| {
                if matches!(region, Region::Unstructured { .. }) {
                    saw_unstructured = true;
                }
                census.record(region);
            });
            if !saw_unstructured {
                functions_structured += 1;
            }
        }

        // The function census always emits (it is the ratio denominator);
        // the per-shape counters follow the `> 0` guard convention so
        // shape-free functions leave the coverage map sparse.
        result.metrics.increment(M_FUNCTIONS_TOTAL, functions_total);
        result
            .metrics
            .increment(M_FUNCTIONS_STRUCTURED, functions_structured);
        for (key, value) in [
            (M_LOOPS_WHILE_TOP, census.while_top),
            (M_LOOPS_DO_WHILE_BOTTOM, census.do_while_bottom),
            (M_LOOPS_GUARDED_DO_WHILE, census.guarded_do_while),
            (M_LOOPS_INFINITE, census.infinite),
            (M_LOOPS_UNCLASSIFIED, census.unclassified),
            (M_SWITCHES, census.switches),
            (M_LABELED_BREAKS, census.breaks),
            (M_LABELED_CONTINUES, census.continues),
        ] {
            if value > 0 {
                result.metrics.increment(key, value);
            }
        }

        // Metrics-only: `changed` stays false by definition.
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{Arena, BlockId, FuncId, IrId, ValueId};
    use sordec_ir::{HighBlock, HighFunction, MemoryImage, Region, WasmFacts};

    fn bb(i: u32) -> BlockId {
        BlockId::from_index(i)
    }

    /// A loop region of the given kind with an empty basic body.
    fn loop_of(kind: LoopKind) -> Region {
        Region::Loop {
            header: bb(0),
            body: Box::new(Region::Basic(bb(0))),
            kind,
        }
    }

    fn func_with_region(region: Region) -> HighFunction {
        let mut blocks: Arena<BlockId, HighBlock> = Arena::new();
        blocks.push(HighBlock {
            id: bb(0),
            bindings: vec![],
        });
        HighFunction {
            id: FuncId::from_index(0),
            name: None,
            signature: None,
            blocks,
            bindings: Arena::new(),
            region,
            params: vec![],
            returns: vec![],
        }
    }

    fn run(functions: Vec<HighFunction>) -> std::collections::HashMap<&'static str, i64> {
        let mut ir = HighIr {
            facts: WasmFacts {
                imports: vec![],
                exports: vec![],
                function_type_indices: vec![],
                function_bodies: vec![],
                custom_sections: vec![],
            },
            soroban_facts: None,
            functions,
            memory: MemoryImage::empty(),
        };
        StructuringCensusPass.run(&mut ir).metrics.iter().collect()
    }

    #[test]
    fn census_counts_every_loop_kind() {
        // One loop of each kind — the only place the three witness-less
        // corpus kinds (Infinite / DoWhileBottom / GuardedDoWhile) get a
        // non-zero exercise, closing the matrix `== 0` drift-guard gap.
        let m = run(vec![func_with_region(Region::Sequence(vec![
            loop_of(LoopKind::WhileTop),
            loop_of(LoopKind::DoWhileBottom),
            loop_of(LoopKind::GuardedDoWhile),
            loop_of(LoopKind::Infinite),
            loop_of(LoopKind::Unclassified),
        ]))]);
        assert_eq!(m.get(M_LOOPS_WHILE_TOP), Some(&1));
        assert_eq!(m.get(M_LOOPS_DO_WHILE_BOTTOM), Some(&1));
        assert_eq!(m.get(M_LOOPS_GUARDED_DO_WHILE), Some(&1));
        assert_eq!(m.get(M_LOOPS_INFINITE), Some(&1));
        assert_eq!(m.get(M_LOOPS_UNCLASSIFIED), Some(&1));
    }

    #[test]
    fn census_counts_switches_and_labeled_exits() {
        let m = run(vec![func_with_region(Region::Sequence(vec![
            Region::Switch {
                index: ValueId::from_index(0),
                arms: vec![],
                default: Box::new(Region::Unreachable),
                dispatch: None,
            },
            Region::Break {
                target: bb(0),
                transfer: vec![],
            },
            Region::Continue {
                target: bb(0),
                transfer: vec![],
            },
        ]))]);
        assert_eq!(m.get(M_SWITCHES), Some(&1));
        assert_eq!(m.get(M_LABELED_BREAKS), Some(&1));
        assert_eq!(m.get(M_LABELED_CONTINUES), Some(&1));
    }

    #[test]
    fn functions_structured_excludes_unstructured() {
        let clean = func_with_region(Region::Basic(bb(0)));
        let fell_back = func_with_region(Region::Unstructured {
            entry: bb(0),
            reason: sordec_common::UnknownReason::UpstreamUnknown,
        });
        let m = run(vec![clean, fell_back]);
        assert_eq!(m.get(M_FUNCTIONS_TOTAL), Some(&2));
        assert_eq!(m.get(M_FUNCTIONS_STRUCTURED), Some(&1));
    }

    #[test]
    fn shape_free_functions_leave_the_map_sparse() {
        // No loops/switches/exits: only the always-on function counters
        // appear, so `metric()` in the coverage builder defaults the rest
        // to zero rather than the pass emitting explicit zeros.
        let m = run(vec![func_with_region(Region::Return { values: vec![] })]);
        assert_eq!(m.get(M_FUNCTIONS_TOTAL), Some(&1));
        assert_eq!(m.get(M_FUNCTIONS_STRUCTURED), Some(&1));
        assert_eq!(m.get(M_LOOPS_WHILE_TOP), None);
        assert_eq!(m.get(M_SWITCHES), None);
        assert_eq!(m.get(M_LABELED_BREAKS), None);
    }
}
