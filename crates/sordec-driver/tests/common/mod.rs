//! Test helpers shared across `tests/corpus.rs` and any future integration
//! test binaries in this crate. Cargo treats `tests/common/mod.rs`
//! specially — it is NOT compiled as its own test binary; it's only
//! visible to siblings that declare `mod common;`.
//!
//! Note: an identical helper lives in `crates/sordec-passes/tests/common/mod.rs`.
//! The duplication is intentional. Two callers don't justify a
//! `sordec-test-support` crate; revisit at three.

use sordec_common::{BlockId, IrId, ValueId};
use sordec_ir::{LiftedIr, LiftedTerminator};
use sordec_passes::{Pipeline, lift_with_waffle};

/// Re-derives the post-lift invariants on the public IR surface.
///
/// Panics if any invariant is violated. The panic message identifies
/// which function and which dangling reference triggered the failure.
pub fn assert_invariants_hold(lifted: &LiftedIr) {
    for func in &lifted.functions {
        assert!(
            func.blocks.get(func.entry).is_some(),
            "function {} entry {} does not resolve",
            func.id,
            func.entry
        );

        let block_count = func.blocks.len() as u32;
        let value_count = func.values.len() as u32;

        let resolves_block = |b: BlockId| b.index() < block_count;
        let resolves_value = |v: ValueId| v.index() < value_count;

        for (_block_id, block) in func.blocks.iter() {
            for &v in &block.params {
                assert!(
                    resolves_value(v),
                    "block param {} dangles in {}",
                    v,
                    func.id
                );
            }
            for &v in &block.instructions {
                assert!(
                    resolves_value(v),
                    "instruction {} dangles in {}",
                    v,
                    func.id
                );
            }
            match &block.terminator {
                LiftedTerminator::Branch(t) => {
                    assert!(resolves_block(t.block));
                    for &v in &t.args {
                        assert!(resolves_value(v));
                    }
                }
                LiftedTerminator::BranchIf {
                    cond,
                    if_true,
                    if_false,
                } => {
                    assert!(resolves_value(*cond));
                    assert!(resolves_block(if_true.block));
                    assert!(resolves_block(if_false.block));
                }
                LiftedTerminator::Switch {
                    index,
                    targets,
                    default,
                } => {
                    assert!(resolves_value(*index));
                    for t in targets {
                        assert!(resolves_block(t.block));
                    }
                    assert!(resolves_block(default.block));
                }
                LiftedTerminator::Return { values } => {
                    for &v in values {
                        assert!(resolves_value(v));
                    }
                }
                LiftedTerminator::Unreachable => {}
            }
        }
    }
}

/// Run the standard six smoke + invariant assertions against a fixture.
///
/// This is the corpus's contract for every contract: it must lift
/// without error, satisfy the IR invariants, agree with the frontend on
/// function count, expose at least one function, and survive a no-op
/// lifted-pipeline run (the same call `Driver::run` performs).
///
/// Feature-specific assertions ("token has a storage call", "timelock
/// has a require_auth") belong in per-pass test files in Phase 2+.
/// This helper deliberately makes no such claims.
///
/// `fixture_name` appears in panic messages so the failing fixture is
/// immediately identifiable.
pub fn assert_corpus_fixture(wasm: &[u8], fixture_name: &str) {
    // 1. Frontend parses.
    let parse_output = sordec_frontend::parse(wasm)
        .unwrap_or_else(|e| panic!("[{fixture_name}] frontend parse failed: {e}"));

    // 2. Diagnostic-severity gate (D12): no Error-severity diagnostics
    //    are tolerated by default. Warning and Info are allowed; if a
    //    fixture surfaces a real Warning that's a per-pass concern, not
    //    a corpus-test failure.
    if let Some(err_diag) = parse_output
        .diagnostics
        .iter()
        .find(|d| d.severity == sordec_common::Severity::Error)
    {
        panic!("[{fixture_name}] frontend emitted an Error-severity diagnostic: {err_diag}");
    }

    // 3. Lifter accepts the WASM.
    let lift_output = lift_with_waffle(
        wasm,
        &parse_output.wasm_facts,
        parse_output.soroban_facts.as_ref(),
    )
    .unwrap_or_else(|e| panic!("[{fixture_name}] lifter failed: {e}"));

    // 4. Lifter must not emit Error-severity diagnostics either.
    if let Some(err_diag) = lift_output
        .diagnostics
        .iter()
        .find(|d| d.severity == sordec_common::Severity::Error)
    {
        panic!("[{fixture_name}] lifter emitted an Error-severity diagnostic: {err_diag}");
    }

    let mut lifted = lift_output.lifted;
    let facts = &parse_output.wasm_facts;

    // 3. Lifted-vs-frontend agreement on local function count.
    assert_eq!(
        lifted.functions.len(),
        facts.function_type_indices.len(),
        "[{fixture_name}] lifted function count {} disagrees with frontend's count {}",
        lifted.functions.len(),
        facts.function_type_indices.len()
    );

    // 4. IR invariants hold across the public surface.
    assert_invariants_hold(&lifted);

    // 5. Non-empty function set — every Soroban contract has at least
    //    one entry point.
    assert!(
        !lifted.functions.is_empty(),
        "[{fixture_name}] lifted IR has zero functions"
    );

    // 6. Empty-pipeline run completes — exercises the same wiring
    //    `Driver::run` uses, without needing a `LoweringStep` stub.
    let pipeline = Pipeline::<LiftedIr>::new(Vec::new(), Vec::new());
    let report = pipeline.run(&mut lifted);
    assert_eq!(
        report.passes_run, 0,
        "[{fixture_name}] empty pipeline reported {} passes run",
        report.passes_run
    );
}
