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

/// No reachable edge may still point at an empty forwarding block, no
/// unconditional branch at an empty return/unreachable block, and no
/// single-in-edge parameterless `Branch` chain may survive.
fn assert_no_threadable_or_mergeable_shapes(name: &str, func: &LiftedFunction) {
    let cfg = CfgFacts::build(func);
    let mut in_count: HashMap<BlockId, u32> = HashMap::new();
    for (block_id, block) in func.blocks.iter() {
        if !cfg.is_reachable(block_id) {
            continue;
        }
        for_each_target(&block.terminator, |target| {
            *in_count.entry(target.block).or_insert(0) += 1;
        });
    }
    let is_empty_forwarder = |b: BlockId| {
        func.blocks.get(b).is_some_and(|blk| {
            blk.instructions.is_empty()
                && matches!(blk.terminator, sordec_ir::LiftedTerminator::Branch(_))
        })
    };
    for (block_id, block) in func.blocks.iter() {
        if !cfg.is_reachable(block_id) {
            continue;
        }
        for_each_target(&block.terminator, |target| {
            assert!(
                !is_empty_forwarder(target.block),
                "[{name}] fn{} {block_id}: edge to un-threaded empty forwarder {}",
                func.id.index(),
                target.block,
            );
        });
        if let sordec_ir::LiftedTerminator::Branch(target) = &block.terminator {
            let b = func.blocks.get(target.block).expect("target resolves");
            assert!(
                !(b.instructions.is_empty()
                    && matches!(
                        b.terminator,
                        sordec_ir::LiftedTerminator::Return { .. }
                            | sordec_ir::LiftedTerminator::Unreachable
                    )),
                "[{name}] fn{} {block_id}: un-inlined branch to empty terminal {}",
                func.id.index(),
                target.block,
            );
            assert!(
                !(target.block != block_id
                    && target.block != func.entry
                    && b.params.is_empty()
                    && in_count.get(&target.block).copied().unwrap_or(0) == 1),
                "[{name}] fn{} {block_id}: un-merged single-pred chain into {}",
                func.id.index(),
                target.block,
            );
        }
    }
}

/// Every reachable scheduled pure-total instruction must have at least
/// one use (first-order form of the mark-and-sweep guarantee, asserted
/// through the independent `DefUseIndex` implementation), and every
/// unreachable block must be an empty tombstone.
fn assert_dead_swept(name: &str, func: &LiftedFunction) {
    let cfg = CfgFacts::build(func);
    let uses = DefUseIndex::build(func);
    for (block_id, block) in func.blocks.iter() {
        if !cfg.is_reachable(block_id) {
            assert!(
                block.params.is_empty()
                    && block.instructions.is_empty()
                    && matches!(block.terminator, sordec_ir::LiftedTerminator::Unreachable),
                "[{name}] fn{} {block_id}: unreachable block not tombstoned",
                func.id.index(),
            );
            continue;
        }
        for &value in &block.instructions {
            let pure = match func.values.get(value).map(|v| &v.def) {
                Some(LiftedValueDef::Operator { op, .. }) => {
                    sordec_passes::effects::wasm_operator_effects(&op.0).is_pure_total()
                }
                _ => false,
            };
            assert!(
                !(pure && uses.is_unused(value)),
                "[{name}] fn{} {block_id}: dead pure {value} still scheduled",
                func.id.index(),
            );
        }
    }
}

/// The reducibility bar (kickoff B3/K3 groundwork) must survive the
/// CFG surgery: zero irreducible edges, before and after.
fn assert_still_reducible(name: &str, func: &LiftedFunction) {
    let cfg = CfgFacts::build(func);
    assert!(
        cfg.is_reducible(),
        "[{name}] fn{}: declutter introduced irreducible edges {:?}",
        func.id.index(),
        cfg.irreducible_edges(),
    );
}

#[test]
fn corpus_reaches_declutter_normal_form() {
    for (name, wasm) in FIXTURES {
        let lifted = declutter(wasm);
        common::assert_invariants_hold(&lifted);
        for func in &lifted.functions {
            assert_no_used_aliases(name, func);
            assert_no_trivial_phis(name, func);
            assert_no_threadable_or_mergeable_shapes(name, func);
            assert_dead_swept(name, func);
            assert_still_reducible(name, func);
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
    // Measured 2026-07-18 on the pinned corpus:
    //   phis_pruned 3,404 · returns_inlined 140 · dead_blocks 210 ·
    //   jumps_threaded 29 · aliases_resolved 42 · traps_inlined 6 ·
    //   chains_merged 0 · dead_values 0.
    // The zeros are structural, not bugs: every raw single-pred chain
    // ran through an empty forwarder (threading consumes it from the
    // predecessor side before merge sees it), and rustc emits no dead
    // pure code — both passes are safety nets for shapes the fixpoint
    // group can produce, each unit-tested and guarded by the
    // normal-form asserts above. Floors sit below measured values to
    // tolerate waffle/fixture drift while catching a silently disabled
    // pass.
    let mut totals: std::collections::BTreeMap<&str, i64> = std::collections::BTreeMap::new();
    for (_, wasm) in FIXTURES {
        let parsed = sordec_frontend::parse(wasm).expect("frontend parses fixture");
        let mut lifted =
            lift_with_waffle(wasm, &parsed.wasm_facts, parsed.soroban_facts.as_ref())
                .expect("lifter accepts fixture")
                .lifted;
        let report = default_lifted_pipeline().run(&mut lifted);
        for (key, value) in report.metric_totals() {
            *totals.entry(key).or_insert(0) += value;
        }
    }
    let floors: &[(&str, i64)] = &[
        (mc::DECLUTTER_ALIASES_RESOLVED, 0),
        (mc::DECLUTTER_PHIS_PRUNED, 3_000),
        (mc::DECLUTTER_JUMPS_THREADED, 10),
        (mc::DECLUTTER_RETURNS_INLINED, 100),
        (mc::DECLUTTER_DEAD_BLOCKS_CLEARED, 100),
    ];
    for (key, floor) in floors {
        let got = totals.get(key).copied().unwrap_or(0);
        assert!(
            got > *floor,
            "corpus-wide `{key}` = {got}, expected > {floor}; all totals: {totals:?}"
        );
    }
}
