//! Corpus locks for the control-flow structurer (Phase 3, C3/K3).
//!
//! Every committed fixture must structure completely: WASM can only
//! express reducible control flow, and on reducible input a correct
//! Beyond Relooper implementation never fails — so any
//! `Region::Unstructured` on the corpus is a structurer bug, not an
//! input problem (kickoff K3). The locks:
//!
//! 1. zero `Region::Unstructured` in any function's region tree;
//! 2. every CFG-reachable block appears **exactly once** as a
//!    `Region::Basic` leaf — the two structurer bug classes are dropped
//!    subtrees and duplicated subtrees, and this catches both;
//! 3. zero `StructuringFallback` diagnostics from the high pipeline —
//!    the diagnostic-side statement of the same invariant.

mod common;

use std::collections::HashMap;

use common::FIXTURES;
use sordec_common::{BlockId, DiagnosticCode, LiftDiagnosticCode};
use sordec_ir::{HighIr, LiftedIr, Region};
use sordec_passes::{
    default_high_pipeline, default_lifted_pipeline, lift_with_waffle, CfgFacts, LiftToHigh,
    LoweringStep, PipelineReport,
};

/// The front half of the real pipeline: parse, lift, declutter, lower
/// (which structures at the boundary), recognize. Returns the
/// decluttered lifted IR (CFG ground truth) alongside the high IR and
/// the pipeline report.
fn structure_fixture(wasm: &[u8]) -> (LiftedIr, HighIr, PipelineReport) {
    let parsed = sordec_frontend::parse(wasm).expect("frontend parses fixture");
    let mut lifted = lift_with_waffle(wasm, &parsed.wasm_facts, parsed.soroban_facts.as_ref())
        .expect("lifter accepts fixture")
        .lifted;
    default_lifted_pipeline().run(&mut lifted);
    common::assert_invariants_hold(&lifted);
    let mut high = LiftToHigh
        .lower(lifted.clone())
        .expect("boundary lowering succeeds");
    let report = default_high_pipeline().run(&mut high);
    (lifted, high, report)
}

#[test]
fn corpus_structures_with_zero_unstructured_regions() {
    for (name, wasm) in FIXTURES {
        let (lifted, high, report) = structure_fixture(wasm);

        for (lifted_func, high_func) in lifted.functions.iter().zip(&high.functions) {
            // Lock 1 (K3): zero Unstructured.
            high_func.region.for_each_node(|region| {
                assert!(
                    !matches!(region, Region::Unstructured { .. }),
                    "[{name}] {} contains an Unstructured region",
                    high_func.id,
                );
            });

            // Lock 2: every reachable block exactly once as a Basic
            // leaf; unreachable blocks (declutter tombstones) never
            // appear.
            let cfg = CfgFacts::build(lifted_func);
            let mut basic_counts: HashMap<BlockId, u32> = HashMap::new();
            high_func.region.for_each_node(|region| {
                if let Region::Basic(b) = region {
                    *basic_counts.entry(*b).or_insert(0) += 1;
                }
            });
            for (block_id, _) in lifted_func.blocks.iter() {
                let count = basic_counts.get(&block_id).copied().unwrap_or(0);
                if cfg.is_reachable(block_id) {
                    assert_eq!(
                        count, 1,
                        "[{name}] {} reachable block {} appears {count} times in the region tree",
                        high_func.id, block_id,
                    );
                } else {
                    assert_eq!(
                        count, 0,
                        "[{name}] {} unreachable block {} leaked into the region tree",
                        high_func.id, block_id,
                    );
                }
            }
        }

        // Lock 3: no StructuringFallback diagnostics.
        let fallbacks: Vec<_> = report
            .diagnostics()
            .filter(|d| {
                matches!(
                    d.code,
                    DiagnosticCode::Lift(LiftDiagnosticCode::StructuringFallback)
                )
            })
            .collect();
        assert!(
            fallbacks.is_empty(),
            "[{name}] StructuringFallback on corpus input: {fallbacks:?}",
        );
    }
}
