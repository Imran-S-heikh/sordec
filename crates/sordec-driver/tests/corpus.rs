//! Corpus tests — every contract in `samples/contracts/` plus the
//! existing learning fixtures must satisfy the basic six assertions
//! defined in `common::assert_corpus_fixture`.
//!
//! These are the **broad smoke tests**. Deep structural assertions
//! (which functions exist, what terminators they have) live in
//! per-pass test files. The corpus's job here is only to prove the
//! lifter doesn't choke on real-world contracts.

mod common;

use common::assert_corpus_fixture;

// ---------------------------------------------------------------------
// Existing learning fixtures (3) — kept in `learning/experiments/`
// because they predate the corpus infrastructure.
// ---------------------------------------------------------------------

const HELLO_ADD_WASM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../learning/experiments/01-hello-add/target/wasm32-unknown-unknown/release/hello_add.wasm"
));

const COUNTER_V21_WASM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../learning/experiments/02-counter/target/wasm32-unknown-unknown/release/counter.wasm"
));

const COUNTER_V26_WASM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../learning/experiments/02-counter-v26/target/wasm32v1-none/release/counter_v26.wasm"
));

#[test]
fn corpus_hello_add() {
    assert_corpus_fixture(HELLO_ADD_WASM, "hello-add");
}

#[test]
fn corpus_counter_v21() {
    assert_corpus_fixture(COUNTER_V21_WASM, "counter-v21");
}

#[test]
fn corpus_counter_v26() {
    assert_corpus_fixture(COUNTER_V26_WASM, "counter-v26");
}

// ---------------------------------------------------------------------
// New corpus fixtures (5) — under `samples/contracts/` with full
// toolchain pinning + sha256 verification.
// ---------------------------------------------------------------------

const TOKEN_V22_WASM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../samples/contracts/token-v22/token-v22.wasm"
));

const TOKEN_V23_WASM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../samples/contracts/token-v23/token-v23.wasm"
));

const TOKEN_V23_STRIPPED_WASM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../samples/contracts/token-v23-stripped/token-v23-stripped.wasm"
));

const TIMELOCK_WASM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../samples/contracts/timelock/timelock.wasm"
));

const DEX_LIQUIDITY_POOL_WASM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../samples/contracts/dex-liquidity-pool/dex-liquidity-pool.wasm"
));

#[test]
fn corpus_token_v22() {
    assert_corpus_fixture(TOKEN_V22_WASM, "token-v22");
}

#[test]
fn corpus_token_v23() {
    assert_corpus_fixture(TOKEN_V23_WASM, "token-v23");
}

#[test]
fn corpus_token_v23_stripped() {
    assert_corpus_fixture(TOKEN_V23_STRIPPED_WASM, "token-v23-stripped");
}

#[test]
fn corpus_timelock() {
    assert_corpus_fixture(TIMELOCK_WASM, "timelock");
}

#[test]
fn corpus_dex_liquidity_pool() {
    assert_corpus_fixture(DEX_LIQUIDITY_POOL_WASM, "dex-liquidity-pool");
}

// ---------------------------------------------------------------------
// Diagnostics-clean assertions for canonical fixtures
//
// The corpus's primary assert_corpus_fixture helper rejects only
// Error-severity diagnostics. These tests strengthen that for the
// canonical clean fixture: token-v23 (a fresh build of the upstream
// SEP-41 token) should produce ZERO diagnostics of any severity. If
// this regresses, either we introduced a real diagnostic in code or
// the upstream contract source changed in a way we should investigate.
// ---------------------------------------------------------------------

#[test]
fn corpus_token_v23_emits_no_diagnostics() {
    let parse_output =
        sordec_frontend::parse(TOKEN_V23_WASM).expect("token-v23 parses");
    assert!(
        parse_output.diagnostics.is_empty(),
        "token-v23 (canonical clean fixture) emitted {} diagnostic(s): {:?}",
        parse_output.diagnostics.len(),
        parse_output.diagnostics,
    );
}

#[test]
fn corpus_token_v23_stripped_has_no_soroban_facts_and_no_diagnostics() {
    // A stripped contract has no contractspecv0, so soroban_facts is
    // None — and the metadata-decoder code path that emits diagnostics
    // is never entered. Therefore: zero diagnostics expected.
    let parse_output = sordec_frontend::parse(TOKEN_V23_STRIPPED_WASM)
        .expect("token-v23-stripped parses");
    assert!(
        parse_output.soroban_facts.is_none(),
        "stripped fixture should report no SorobanFacts"
    );
    assert!(
        parse_output.diagnostics.is_empty(),
        "stripped fixture should not emit diagnostics; got {:?}",
        parse_output.diagnostics,
    );
}
