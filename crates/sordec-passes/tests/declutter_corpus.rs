//! Corpus normal-form assertions for the declutter pipeline (W3/B5).
//!
//! Runs [`sordec_passes::default_lifted_pipeline`] on every committed
//! fixture and asserts the decluttered normal form: the properties each
//! landed pass guarantees on real input, not just on synthetic units.
//! The list grows with the pipeline (threading/merge/sweep assertions
//! land with their passes).
//!
//! Semantic preservation is NOT asserted here — that net is the
//! recognizer coverage matrix (`sordec-driver/tests/coverage_matrix.rs`),
//! whose counters may only hold or improve once the driver wiring runs
//! this pipeline before lowering.

mod common;

use std::collections::HashMap;

use sordec_common::{BlockId, IrId, ValueId};
use sordec_ir::{LiftedFunction, LiftedIr, LiftedValueDef};
use sordec_passes::{
    default_lifted_pipeline, for_each_target, lift_with_waffle, metrics_catalog as mc, CfgFacts,
    DefUseIndex,
};

const FIXTURES: &[(&str, &[u8])] = &[
    (
        "hello-add",
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../samples/contracts/hello-add/hello-add.wasm"
        )),
    ),
    (
        "token-v22",
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../samples/contracts/token-v22/token-v22.wasm"
        )),
    ),
    (
        "token-v23",
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../samples/contracts/token-v23/token-v23.wasm"
        )),
    ),
    (
        "token-v23-stripped",
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../samples/contracts/token-v23-stripped/token-v23-stripped.wasm"
        )),
    ),
    (
        "timelock",
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../samples/contracts/timelock/timelock.wasm"
        )),
    ),
    (
        "dex-liquidity-pool",
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../samples/contracts/dex-liquidity-pool/dex-liquidity-pool.wasm"
        )),
    ),
    (
        "attestation",
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../samples/contracts/attestation/attestation.wasm"
        )),
    ),
];

/// Lift a fixture and run the declutter pipeline over it.
fn declutter(wasm: &[u8]) -> LiftedIr {
    let parsed = sordec_frontend::parse(wasm).expect("frontend parses fixture");
    let mut lifted = lift_with_waffle(wasm, &parsed.wasm_facts, parsed.soroban_facts.as_ref())
        .expect("lifter accepts fixture")
        .lifted;
    default_lifted_pipeline().run(&mut lifted);
    lifted
}

/// Alias defs must have zero uses anywhere (operands, terminators,
/// edge args) after the pipeline.
fn assert_no_used_aliases(name: &str, func: &LiftedFunction) {
    let uses = DefUseIndex::build(func);
    for (id, value) in func.values.iter() {
        if matches!(value.def, LiftedValueDef::Alias(_)) {
            assert!(
                uses.is_unused(id),
                "[{name}] fn{}: alias {id} still has uses {:?}",
                func.id.index(),
                uses.uses_of(id),
            );
        }
    }
}

/// No reachable non-entry block may retain a first-order trivial phi:
/// a param whose incoming args over reachable in-edges, minus itself,
/// are a single value. This is the §2 evidence counter, re-computed
/// in-process, locked at zero.
fn assert_no_trivial_phis(name: &str, func: &LiftedFunction) {
    let cfg = CfgFacts::build(func);
    let mut incoming: HashMap<BlockId, Vec<Vec<ValueId>>> = HashMap::new();
    for (block_id, block) in func.blocks.iter() {
        if !cfg.is_reachable(block_id) {
            continue;
        }
        for_each_target(&block.terminator, |target| {
            incoming
                .entry(target.block)
                .or_default()
                .push(target.args.clone());
        });
    }
    for (block_id, block) in func.blocks.iter() {
        if block_id == func.entry || !cfg.is_reachable(block_id) {
            continue;
        }
        let Some(edges) = incoming.get(&block_id) else {
            continue;
        };
        for (position, &param) in block.params.iter().enumerate() {
            let mut sources: Vec<ValueId> = edges
                .iter()
                .filter_map(|args| args.get(position).copied())
                .filter(|&arg| arg != param)
                .collect();
            sources.sort_unstable_by_key(|v| v.index());
            sources.dedup();
            assert_ne!(
                sources.len(),
                1,
                "[{name}] fn{} {block_id}: param {param} is still trivially fed by {:?}",
                func.id.index(),
                sources[0],
            );
        }
    }
}

#[test]
fn corpus_reaches_declutter_normal_form() {
    for (name, wasm) in FIXTURES {
        let lifted = declutter(wasm);
        common::assert_invariants_hold(&lifted);
        for func in &lifted.functions {
            assert_no_used_aliases(name, func);
            assert_no_trivial_phis(name, func);
        }
    }
}

#[test]
fn declutter_pipeline_is_idempotent_on_corpus() {
    // A second full pipeline run over already-decluttered IR must
    // report no change in any pass invocation.
    for (name, wasm) in FIXTURES {
        let mut lifted = declutter(wasm);
        let report = default_lifted_pipeline().run(&mut lifted);
        for (pass, result) in &report.per_pass {
            assert!(
                !result.changed,
                "[{name}] pass `{pass}` reported change on decluttered input"
            );
        }
    }
}

#[test]
fn declutter_prunes_the_measured_clutter() {
    // Coarse magnitude lock against silent no-op regressions: the
    // corpus-wide counters must show the pipeline actually working.
    // Measured 2026-07-18 on the pinned corpus: 3,403 of 3,648 block
    // params pruned (fixpoint beats the 2,652 first-order census) and
    // 42 alias uses rewritten — waffle's ~2,500 alias defs are almost
    // all use-free arena residue already; the alias pass exists for the
    // invariant (zero USED aliases), not for volume. Thresholds sit
    // below the measured values to tolerate waffle/fixture drift while
    // still catching a silently disabled pass.
    let mut aliases_resolved = 0;
    let mut phis_pruned = 0;
    for (_, wasm) in FIXTURES {
        let parsed = sordec_frontend::parse(wasm).expect("frontend parses fixture");
        let mut lifted =
            lift_with_waffle(wasm, &parsed.wasm_facts, parsed.soroban_facts.as_ref())
                .expect("lifter accepts fixture")
                .lifted;
        let report = default_lifted_pipeline().run(&mut lifted);
        let totals = report.metric_totals();
        aliases_resolved += totals.get(mc::DECLUTTER_ALIASES_RESOLVED).copied().unwrap_or(0);
        phis_pruned += totals.get(mc::DECLUTTER_PHIS_PRUNED).copied().unwrap_or(0);
    }
    assert!(
        aliases_resolved > 0,
        "expected some alias uses rewritten corpus-wide (42 measured), got {aliases_resolved}"
    );
    assert!(
        phis_pruned > 3_000,
        "expected >3000 params pruned corpus-wide (3403 measured), got {phis_pruned}"
    );
}
