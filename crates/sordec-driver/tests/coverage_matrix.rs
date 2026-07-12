//! H1 — recognizer × fixture coverage matrix.
//!
//! Runs the full `default_high_pipeline` over every committed corpus
//! fixture and tallies each pass's `PassMetrics` into a
//! fixture × metric-key matrix. Two jobs:
//!
//! - **Artifact**: with `--nocapture` it prints the matrix, a
//!   human-readable "which recognizer fires on which fixture" table
//!   (the data H1 asks for; surfacing these counters in the `sordec
//!   coverage` CLI is W7's separate scope).
//! - **Assertions**: pin the load-bearing coverage facts — most
//!   importantly that the attestation fixture (W8) is the *only* corpus
//!   contract exercising the crypto/prng recognizer, giving W3's
//!   vocabulary real corpus evidence.

// This test's entire purpose is to emit the matrix artifact to stderr.
#![allow(clippy::print_stderr)]

use std::collections::BTreeMap;

use sordec_passes::{default_high_pipeline, lift_with_waffle, LiftToHigh, LoweringStep};

/// Every committed fixture, in corpus order.
fn fixtures() -> Vec<(&'static str, &'static [u8])> {
    macro_rules! fixture {
        ($name:literal, $path:literal) => {
            (
                $name,
                include_bytes!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../samples/contracts/",
                    $path
                )) as &[u8],
            )
        };
    }
    vec![
        fixture!("hello-add", "hello-add/hello-add.wasm"),
        fixture!("token-v22", "token-v22/token-v22.wasm"),
        fixture!("token-v23", "token-v23/token-v23.wasm"),
        fixture!("token-v23-stripped", "token-v23-stripped/token-v23-stripped.wasm"),
        fixture!("timelock", "timelock/timelock.wasm"),
        fixture!("dex-liquidity-pool", "dex-liquidity-pool/dex-liquidity-pool.wasm"),
        fixture!("attestation", "attestation/attestation.wasm"),
    ]
}

/// Run the full high-IR pipeline over one fixture and aggregate every
/// pass's metric counters into one `metric-key → total` map.
fn pipeline_metrics(name: &str, wasm: &[u8]) -> BTreeMap<String, i64> {
    let parsed =
        sordec_frontend::parse(wasm).unwrap_or_else(|e| panic!("[{name}] parse: {e}"));
    let lifted = lift_with_waffle(wasm, &parsed.wasm_facts, parsed.soroban_facts.as_ref())
        .unwrap_or_else(|e| panic!("[{name}] lift: {e}"))
        .lifted;
    let mut ir = LiftToHigh
        .lower(lifted)
        .unwrap_or_else(|e| panic!("[{name}] lower: {e:?}"));

    let report = default_high_pipeline().run(&mut ir);
    let mut totals: BTreeMap<String, i64> = BTreeMap::new();
    for (_pass, result) in &report.per_pass {
        for (key, value) in result.metrics.iter() {
            *totals.entry(key.to_string()).or_insert(0) += value;
        }
    }
    totals
}

/// Build the full matrix once.
fn build_matrix() -> BTreeMap<&'static str, BTreeMap<String, i64>> {
    fixtures()
        .into_iter()
        .map(|(name, wasm)| (name, pipeline_metrics(name, wasm)))
        .collect()
}

#[test]
fn coverage_matrix_prints_and_holds_invariants() {
    let matrix = build_matrix();

    // --- artifact: print the matrix (visible under --nocapture) ---
    let all_keys: BTreeMap<&str, ()> = matrix
        .values()
        .flat_map(|m| m.keys().map(|k| (k.as_str(), ())))
        .collect();
    eprintln!("\n=== recognizer × fixture coverage matrix ===");
    for (fixture, metrics) in &matrix {
        eprintln!("  {fixture}:");
        for key in all_keys.keys() {
            if let Some(count) = metrics.get(*key) {
                eprintln!("      {key:36} {count}");
            }
        }
    }

    // --- assertions: the load-bearing coverage facts ---
    let count = |fixture: &str, key: &str| -> i64 {
        matrix.get(fixture).and_then(|m| m.get(key)).copied().unwrap_or(0)
    };

    // W8's headline: attestation is the ONLY fixture exercising the
    // crypto/prng recognizer — W3's vocabulary now has real evidence.
    assert!(count("attestation", "crypto_op") >= 3, "attestation crypto");
    assert!(count("attestation", "prng_op") >= 1, "attestation prng");
    for other in [
        "hello-add",
        "token-v22",
        "token-v23",
        "token-v23-stripped",
        "timelock",
        "dex-liquidity-pool",
    ] {
        assert_eq!(count(other, "crypto_op"), 0, "{other} must not crypto");
        assert_eq!(count(other, "prng_op"), 0, "{other} must not prng");
    }

    // W1 evidence: the spec-bearing tokens name enum storage keys.
    assert!(count("token-v22", "enum_key_named") >= 1, "v22 enum-key");
    assert!(count("token-v23", "enum_key_named") >= 1, "v23 enum-key");
    // The stripped token has no spec section → no enum-key naming.
    assert_eq!(
        count("token-v23-stripped", "enum_key_named"),
        0,
        "stripped must not name keys"
    );

    // W2 evidence: dex + timelock type cross-contract calls against SEP-41.
    assert!(count("dex-liquidity-pool", "client_iface_matched") >= 1, "dex sep41");
    assert!(count("timelock", "client_iface_matched") >= 1, "timelock sep41");

    // W4 evidence: timelock is the ONLY fixture importing `b.m`
    // symbol_index_in_linear_memory — its TimeBoundKind decode is
    // recognized and named against the spec.
    assert!(count("timelock", "dispatcher_cases_resolved") >= 1, "timelock dispatch");
    assert!(count("timelock", "dispatcher_enum_named") >= 1, "timelock dispatch enum");
    for other in [
        "hello-add",
        "token-v22",
        "token-v23",
        "token-v23-stripped",
        "dex-liquidity-pool",
        "attestation",
    ] {
        assert_eq!(
            count(other, "dispatcher_cases_resolved"),
            0,
            "{other} must not dispatch"
        );
    }
}
