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

use sordec_passes::{
    default_high_pipeline, lift_with_waffle, metrics_catalog as mc, LiftToHigh, LoweringStep,
};

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

/// Run the full pipeline — de-cluttering, lowering, recognizers — over
/// one fixture and aggregate every pass's metric counters into one
/// `metric-key → total` map — the same
/// [`PipelineReport::metric_totals`] the `sordec coverage` CLI consumes
/// (W7), exercised here across the whole corpus.
///
/// The declutter stage runs deliberately (W3): every recognizer-count
/// assertion in this matrix doubles as the semantic-preservation net
/// for the CFG surgery — a declutter bug that breaks a use chain shows
/// up here as a dropped count.
fn pipeline_metrics(name: &str, wasm: &[u8]) -> BTreeMap<&'static str, i64> {
    let parsed =
        sordec_frontend::parse(wasm).unwrap_or_else(|e| panic!("[{name}] parse: {e}"));
    let mut lifted = lift_with_waffle(wasm, &parsed.wasm_facts, parsed.soroban_facts.as_ref())
        .unwrap_or_else(|e| panic!("[{name}] lift: {e}"))
        .lifted;
    sordec_passes::default_lifted_pipeline().run(&mut lifted);
    let mut ir = LiftToHigh
        .lower(lifted)
        .unwrap_or_else(|e| panic!("[{name}] lower: {e:?}"));

    default_high_pipeline().run(&mut ir).metric_totals()
}

/// Build the full matrix once.
fn build_matrix() -> BTreeMap<&'static str, BTreeMap<&'static str, i64>> {
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
        .flat_map(|m| m.keys().map(|&k| (k, ())))
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
    //
    // Every per-key lookup routes through a `metrics_catalog` const, not
    // a raw string. That makes this test the W7 drift guard: if a pass
    // renames an emitted counter without updating its catalog const, the
    // stale const reads zero here and the fixture's `>= 1` assertion
    // fails — instead of the coverage report silently showing zero.
    let count = |fixture: &str, key: &str| -> i64 {
        matrix.get(fixture).and_then(|m| m.get(key)).copied().unwrap_or(0)
    };

    // W8's headline: attestation is the ONLY fixture exercising the
    // crypto/prng recognizer — W3's vocabulary now has real evidence.
    // (crypto_op/prng_op are not W7-surfaced keys, so referenced as
    // literals — they carry no coverage ratio.)
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
    assert!(count("token-v22", mc::ENUM_KEY_NAMED) >= 1, "v22 enum-key");
    assert!(count("token-v23", mc::ENUM_KEY_NAMED) >= 1, "v23 enum-key");
    // The stripped token has no spec section → no enum-key naming, but
    // it still attempts (and soundly declines) some — the F-ratio miss.
    assert_eq!(
        count("token-v23-stripped", mc::ENUM_KEY_NAMED),
        0,
        "stripped must not name keys"
    );

    // W2 evidence: dex + timelock type cross-contract calls against SEP-41,
    // and recover call arity (the F5 "typed" numerator).
    assert!(count("dex-liquidity-pool", mc::CLIENT_IFACE_MATCHED) >= 1, "dex sep41");
    assert!(count("timelock", mc::CLIENT_IFACE_MATCHED) >= 1, "timelock sep41");
    assert!(count("dex-liquidity-pool", mc::CLIENT_ARITY_RESOLVED) >= 1, "dex arity");
    assert!(count("dex-liquidity-pool", mc::INVOKE_CONTRACT) >= 1, "dex invoke");

    // W4 evidence: timelock is the ONLY fixture importing `b.m`
    // symbol_index_in_linear_memory — its TimeBoundKind decode is
    // recognized and named against the spec.
    assert!(count("timelock", mc::DISPATCHER_CASES_RESOLVED) >= 1, "timelock dispatch");
    assert!(count("timelock", mc::DISPATCHER_ENUM_NAMED) >= 1, "timelock dispatch enum");
    for other in [
        "hello-add",
        "token-v22",
        "token-v23",
        "token-v23-stripped",
        "dex-liquidity-pool",
        "attestation",
    ] {
        assert_eq!(
            count(other, mc::DISPATCHER_CASES_RESOLVED),
            0,
            "{other} must not dispatch"
        );
    }

    // W5 D3: the token contracts resolve their SEP-41 instance-bump TTL
    // ledger amounts (and leave the balance-bump unresolved — the F-ratio
    // miss); no other fixture extends TTL.
    for token in ["token-v22", "token-v23", "token-v23-stripped"] {
        assert!(count(token, mc::TTL_RESOLVED) >= 1, "{token} ttl");
        assert!(count(token, mc::TTL_UNRESOLVED) >= 1, "{token} ttl miss");
    }
    for other in ["hello-add", "timelock", "dex-liquidity-pool", "attestation"] {
        assert_eq!(count(other, mc::TTL_RESOLVED), 0, "{other} must not ttl");
    }

    // W5 D4: only timelock stores a unit-value marker (`set(&Init, &())`).
    // (const_prop_unit_value is not a W7-surfaced key — literal.)
    assert!(count("timelock", "const_prop_unit_value") >= 1, "timelock unit value");
    for other in [
        "hello-add",
        "token-v22",
        "token-v23",
        "token-v23-stripped",
        "dex-liquidity-pool",
        "attestation",
    ] {
        assert_eq!(count(other, "const_prop_unit_value"), 0, "{other} must not unit");
    }

    // W6: the terminal unrecognised-scan finds no surviving `Unknown` host
    // call on any corpus fixture — every host call is recognised (the
    // zero-`host:` sweep, now enforced through the diagnostic pass metric).
    // This is also the W7 headline "host interactions = 100%" evidence.
    for fixture in [
        "hello-add",
        "token-v22",
        "token-v23",
        "token-v23-stripped",
        "timelock",
        "dex-liquidity-pool",
        "attestation",
    ] {
        assert_eq!(
            count(fixture, mc::UNRECOGNISED_HOST_CALL),
            0,
            "{fixture} has an unrecognised host call"
        );
    }
    // W6: the token contracts surface real recogniser-miss diagnostics
    // (unresolved storage tiers) — the counter that backs the E3 coverage
    // section and the F1 storage-tier miss ratio.
    for token in ["token-v22", "token-v23", "token-v23-stripped"] {
        assert!(
            count(token, mc::STORAGE_TIER_UNKNOWN) >= 1,
            "{token} storage-tier miss"
        );
        assert!(
            count(token, mc::STORAGE_TIER_RESOLVED) >= 1,
            "{token} storage-tier resolved"
        );
    }

    // W7 deep-facts pin: token-v23 resolves 15 of 20 attempted deep facts
    // (storage-tier 8/10, enum-key 6/8, ttl 1/2) = 75%. This is the exact
    // number the `sordec coverage` headline publishes; pinned here (the
    // driver test is the home for exact numbers, per the CLI test header).
    let (resolved, attempted) = deep_facts("token-v23", &matrix);
    assert_eq!(attempted, 20, "token-v23 deep facts attempted");
    assert_eq!(resolved, 15, "token-v23 deep facts resolved");

    // --- A6/H3: structuring coverage columns (measured 2026-07-20) ---
    //
    // Per-fixture structuring census (`StructuringCensusPass`). This
    // driver test is the home for the exact numbers; the CLI e2e test
    // only anchors the section structure. Each lookup routes through an
    // `mc::` const, so a renamed census counter reads zero and fails
    // here — the same drift guard the recognizer keys rely on.
    //
    // Columns: functions (total, structured); loops (while_top,
    // unclassified); switches; dispatch_linked. The other three loop
    // kinds (do_while_bottom / guarded_do_while / infinite) are zero
    // corpus-wide — the classifier declines a shape it cannot prove
    // rather than guessing — and are asserted zero in the loop below.
    let structuring: &[(&str, i64, i64, i64, i64, i64, i64)] = &[
        // fixture,           f_total, f_struct, while_top, unclass, switches, dispatch_linked
        ("hello-add", 5, 5, 0, 0, 0, 0),
        ("token-v22", 48, 48, 6, 1, 1, 0),
        ("token-v23", 46, 46, 6, 1, 2, 0),
        ("token-v23-stripped", 46, 46, 6, 1, 2, 0),
        ("timelock", 18, 18, 4, 1, 1, 1),
        ("dex-liquidity-pool", 50, 50, 4, 2, 1, 0),
        ("attestation", 8, 8, 0, 0, 0, 0),
    ];
    for &(fx, f_total, f_struct, while_top, unclass, switches, dispatch_linked) in structuring {
        // Every function structured — the metric-side twin of the K3
        // zero-Unstructured lock, pinned per fixture.
        assert!(count(fx, mc::STRUCTURING_FUNCTIONS_TOTAL) >= 1, "{fx} has functions");
        assert_eq!(count(fx, mc::STRUCTURING_FUNCTIONS_TOTAL), f_total, "{fx} functions_total");
        assert_eq!(
            count(fx, mc::STRUCTURING_FUNCTIONS_STRUCTURED),
            f_struct,
            "{fx} functions_structured"
        );
        assert_eq!(
            count(fx, mc::STRUCTURING_FUNCTIONS_STRUCTURED),
            count(fx, mc::STRUCTURING_FUNCTIONS_TOTAL),
            "{fx} must be 100% structured (K3)"
        );

        // Loop-kind breakdown. Only WhileTop and Unclassified occur on
        // the corpus; the other three are pinned to zero (no witness).
        assert_eq!(count(fx, mc::STRUCTURING_LOOPS_WHILE_TOP), while_top, "{fx} while_top");
        assert_eq!(count(fx, mc::STRUCTURING_LOOPS_UNCLASSIFIED), unclass, "{fx} unclassified");
        assert_eq!(count(fx, mc::STRUCTURING_LOOPS_DO_WHILE_BOTTOM), 0, "{fx} no do_while");
        assert_eq!(count(fx, mc::STRUCTURING_LOOPS_GUARDED_DO_WHILE), 0, "{fx} no guarded do_while");
        assert_eq!(count(fx, mc::STRUCTURING_LOOPS_INFINITE), 0, "{fx} no infinite loop");

        // Census/classifier drift guard: the census's non-Unclassified
        // loop count equals the `LoopClassifyPass` event counter. Both
        // run once, so neither is inflated by the fixpoint group.
        let classified = count(fx, mc::STRUCTURING_LOOPS_WHILE_TOP)
            + count(fx, mc::STRUCTURING_LOOPS_DO_WHILE_BOTTOM)
            + count(fx, mc::STRUCTURING_LOOPS_GUARDED_DO_WHILE)
            + count(fx, mc::STRUCTURING_LOOPS_INFINITE);
        assert_eq!(
            classified,
            count(fx, mc::REFINE_LOOPS_CLASSIFIED),
            "{fx} census vs classifier loop-count drift"
        );

        // Recovered `match` count. The skeleton cross-check proves
        // Switch nodes == the original `br_table` opcode count, so these
        // are stable pins.
        assert_eq!(count(fx, mc::STRUCTURING_SWITCHES), switches, "{fx} switches recovered");

        // Cascade→match: only timelock links a switch to a recovered
        // `SymbolDispatch` enum (D6).
        assert_eq!(count(fx, mc::REFINE_DISPATCH_LINKED), dispatch_linked, "{fx} dispatch_linked");
    }

    // Corpus loop totals: 32 loops = 26 WhileTop + 6 Unclassified.
    let corpus = |key| structuring.iter().map(|s| count(s.0, key)).sum::<i64>();
    assert_eq!(corpus(mc::STRUCTURING_LOOPS_WHILE_TOP), 26, "corpus while loops");
    assert_eq!(corpus(mc::STRUCTURING_LOOPS_UNCLASSIFIED), 6, "corpus unclassified loops");
    assert_eq!(corpus(mc::STRUCTURING_SWITCHES), 7, "corpus recovered switches");

    // --- Type recovery: the Tranche 2 "typed program" evidence ---
    // After the type-infer pass a majority of every fixture's bindings
    // carry a type (baseline was ~7% corpus-wide), and the `known`
    // (proven) count is far beyond the handful of ABI parameters — i.e.
    // the IR is typed *beyond* the public signatures. Floors are
    // conservative against the 2026-07 measurement (dex 54% low,
    // attestation 78% high; even the stripped fixture, with no
    // contractspec, reaches 65% by propagation).
    let all_fixtures = [
        "hello-add",
        "token-v23",
        "token-v22",
        "token-v23-stripped",
        "timelock",
        "dex-liquidity-pool",
        "attestation",
    ];
    for fx in all_fixtures {
        let known = count(fx, mc::TYPES_KNOWN);
        let inferred = count(fx, mc::TYPES_INFERRED);
        let total = known + inferred + count(fx, mc::TYPES_UNKNOWN);
        assert!(total > 0, "{fx} has bindings");
        let typed_pct = 100 * (known + inferred) / total;
        assert!(typed_pct >= 50, "{fx} typedness {typed_pct}% below the 50% floor");
        assert!(known >= 15, "{fx} proven types {known} below floor (beyond-ABI evidence)");
    }
    let ty_corpus = |key| all_fixtures.iter().map(|f| count(f, key)).sum::<i64>();
    let (k, i) = (ty_corpus(mc::TYPES_KNOWN), ty_corpus(mc::TYPES_INFERRED));
    let ty_total = k + i + ty_corpus(mc::TYPES_UNKNOWN);
    assert!(100 * (k + i) / ty_total >= 55, "corpus typedness below the 55% floor");

    // D5 evidence: the token contracts and dex fold at least one switch
    // arm into the wildcard default (timelock's dispatch switch does not).
    for fx in ["token-v22", "token-v23", "token-v23-stripped", "dex-liquidity-pool"] {
        assert!(count(fx, mc::REFINE_SWITCH_ARMS_DEDUPED) >= 1, "{fx} switch-arm dedup");
    }
}

/// Sum the W7 deep-facts `(resolved, attempted)` over the five
/// `metrics_catalog::DEEP_FACT_PAIRS` for one fixture — the same
/// computation the coverage headline performs.
fn deep_facts(fixture: &str, matrix: &BTreeMap<&'static str, BTreeMap<&'static str, i64>>) -> (i64, i64) {
    let m = matrix.get(fixture).expect("fixture in matrix");
    let mut resolved = 0i64;
    let mut attempted = 0i64;
    for (ok, miss) in mc::DEEP_FACT_PAIRS {
        let r = m.get(*ok).copied().unwrap_or(0);
        let u = m.get(*miss).copied().unwrap_or(0);
        resolved += r;
        attempted += r + u;
    }
    (resolved, attempted)
}
