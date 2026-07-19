//! End-to-end tests for `sordec coverage`.
//!
//! Asserts behaviour, not exact numbers: host-call recognition % is
//! sensitive to vendor drift in the catalog, and operator counts shift
//! across SDK versions. We pin only the structural anchors and the
//! denominator-zero edge case.

use assert_cmd::Command;
use predicates::prelude::*;

const HELLO_ADD: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../samples/contracts/hello-add/hello-add.wasm"
);

const TOKEN_V23: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../samples/contracts/token-v23/token-v23.wasm"
);

const DEX_LP: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../samples/contracts/dex-liquidity-pool/dex-liquidity-pool.wasm"
);

#[test]
fn coverage_on_hello_add_succeeds_with_clean_lift() {
    // hello-add is the smallest realistic contract we ship — one
    // exported function, two host calls (Val encoding for the
    // `i64`-typed `add` args). Anchor on the structural shape, not
    // the exact numbers.
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["coverage", HELLO_ADD])
        .assert()
        .success()
        .stdout(predicate::str::contains("coverage report"))
        .stdout(predicate::str::contains("catalog:"))
        .stdout(predicate::str::contains("lift:"))
        .stdout(predicate::str::contains("100.0%"))
        // Hard NaN/inf negative — must never render either even on
        // tiny contracts. Denominator-zero is covered by unit tests.
        .stdout(predicate::str::contains("NaN").not())
        .stdout(predicate::str::contains("inf").not())
        .stderr(predicate::str::is_empty());
}

#[test]
fn coverage_on_token_v23_shows_high_recognition() {
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["coverage", TOKEN_V23])
        .assert()
        .success()
        // Structural anchors. Don't pin the percentage — vendor bumps
        // shift the numerator.
        .stdout(predicate::str::contains("host calls:"))
        .stdout(predicate::str::contains("recognized"))
        .stdout(predicate::str::contains("operators:"))
        .stdout(predicate::str::contains("call (import):"))
        // token-v23 must have at least one host call (every SEP-41
        // token writes via `put_contract_data`), so the n/a branch
        // must NOT fire.
        .stdout(predicate::str::contains("no host calls").not())
        .stderr(predicate::str::is_empty());
}

#[test]
fn coverage_with_json_emits_parseable_json() {
    let out = Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["coverage", "--json", TOKEN_V23])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let v: serde_json::Value =
        serde_json::from_slice(&out).expect("--json must emit valid JSON on stdout");

    // Schema anchors per plan D7. Future Phase 4 fields may be added,
    // but none of these may be removed or renamed.
    for key in [
        "wasm",
        "catalog",
        "parse",
        "metadata",
        "lift",
        "host_calls",
        "operators",
        "diagnostics",
    ] {
        assert!(v.get(key).is_some(), "missing top-level key {key:?}");
    }
    // Sanity-check a few nested anchors.
    assert!(v["host_calls"]["total"].is_number());
    assert!(v["host_calls"]["recognized"].is_number());
    assert!(v["host_calls"]["unrecognized"].is_array());
    assert!(v["operators"]["total"].is_number());
    assert!(v["diagnostics"]["total"].is_number());
    assert!(v["diagnostics"]["by_code"].is_array());
}

#[test]
fn coverage_json_reports_recognizer_miss_diagnostics_on_token_v23() {
    // W6 E3/F9: the token contract has real recogniser misses (unresolved
    // storage tiers, unnamed enum keys, the cross-function balance-bump
    // TTL). They surface as per-code counts in the coverage diagnostics
    // section.
    let out = Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["coverage", "--json", TOKEN_V23])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).expect("valid JSON");

    let total = v["diagnostics"]["total"].as_u64().expect("total is a number");
    assert!(total >= 1, "token-v23 has recogniser misses, got {total}");
    let by_code = v["diagnostics"]["by_code"].as_array().expect("by_code array");
    let codes: Vec<&str> = by_code
        .iter()
        .filter_map(|e| e["code"].as_str())
        .collect();
    assert!(
        codes.contains(&"lift::non_constant_durability_arg"),
        "expected the storage-tier miss code, got {codes:?}"
    );
    // Every listed code is `lift::`-namespaced with a positive count.
    for e in by_code {
        assert!(e["code"].as_str().unwrap().starts_with("lift::"));
        assert!(e["count"].as_u64().unwrap() >= 1);
    }
}

#[test]
fn coverage_on_hello_add_reports_only_the_panic_lint() {
    // A fully-recovered contract: no recogniser misses, no surviving
    // unknown host calls. The only code present is the informational
    // bare-panic lint the D8 pass wires (hello-add's decode guards,
    // overflow check, and panic-glue wrappers = 5 sites) — any other
    // code appearing here is a recovery regression.
    let out = Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["coverage", "--json", HELLO_ADD])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).expect("valid JSON");
    let by_code = v["diagnostics"]["by_code"].as_array().unwrap();
    assert_eq!(by_code.len(), 1, "only the panic lint fires: {by_code:?}");
    assert_eq!(
        by_code[0]["code"].as_str(),
        Some("lift::panic_without_error_code")
    );
    assert_eq!(v["diagnostics"]["total"].as_u64(), Some(5));
}

#[test]
fn coverage_with_json_emits_finite_ratios() {
    // Smoke test that the JSON output contains finite numeric ratios
    // (or `null`), never `NaN` / `inf` / `-inf` — none of which are
    // valid JSON. Token-v23 has both host calls and local functions
    // so both ratios should be present and finite.
    let out = Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["coverage", "--json", TOKEN_V23])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let v: serde_json::Value = serde_json::from_slice(&out).expect("valid JSON");
    let ratio = &v["host_calls"]["ratio"];
    assert!(
        ratio.is_null() || ratio.as_f64().is_some_and(f64::is_finite),
        "host_calls.ratio must be null or finite, got {ratio:?}"
    );
    let completeness = &v["lift"]["completeness"];
    assert!(
        completeness.is_null() || completeness.as_f64().is_some_and(f64::is_finite),
        "lift.completeness must be null or finite, got {completeness:?}"
    );
}

#[test]
fn coverage_on_token_v23_renders_recognition_and_headline_sections() {
    // W7: the recognition + semantic-recovery sections render on a real
    // contract. Anchor on section labels and stable structural claims,
    // not vendor-sensitive counts (exact numbers live in the driver
    // coverage-matrix test).
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["coverage", TOKEN_V23])
        .assert()
        .success()
        .stdout(predicate::str::contains("recognition:"))
        .stdout(predicate::str::contains("storage:"))
        .stdout(predicate::str::contains("enum keys:"))
        .stdout(predicate::str::contains("val boilerplate:"))
        .stdout(predicate::str::contains("semantic recovery:"))
        .stdout(predicate::str::contains("host interactions:"))
        .stdout(predicate::str::contains("deep facts:"))
        // The Phase-3/4 accuracy caveat must be present so the headline
        // is never mistaken for the RFP accuracy score.
        .stdout(predicate::str::contains("Phase-4"))
        .stdout(predicate::str::contains("NaN").not())
        .stdout(predicate::str::contains("inf").not())
        .stderr(predicate::str::is_empty());
}

#[test]
fn coverage_json_exposes_recognition_and_headline_on_token_v23() {
    let out = Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["coverage", "--json", TOKEN_V23])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).expect("valid JSON");

    // Recognition sub-structs present with the honest-denominator shape.
    let rec = &v["recognition"];
    assert!(rec["storage"]["tier_ratio"].is_number() || rec["storage"]["tier_ratio"].is_null());
    assert_eq!(rec["events"]["flavor_split"], "phase-3-emit");
    assert_eq!(rec["wide_arithmetic"]["deferred"], "C19");
    // token-v23 makes no cross-contract calls, so the typed ratio must be
    // null (never 0.0, never NaN) — the zero-denominator contract.
    assert!(
        rec["client_calls"]["typed_ratio"].is_null(),
        "token has no invoke sites → typed_ratio null, got {:?}",
        rec["client_calls"]["typed_ratio"]
    );

    // Headline: host interactions are the stable 100% recognition claim;
    // deep facts are a finite fraction (exact value pinned in the driver
    // matrix). The note carries the Phase-4 caveat.
    let host = &v["headline"]["host_interactions"];
    assert_eq!(host["ratio"].as_f64(), Some(1.0), "host interactions 100%");
    let deep = v["headline"]["deep_facts"]["ratio"]
        .as_f64()
        .expect("deep-facts ratio is a number on token-v23");
    assert!((0.0..=1.0).contains(&deep), "deep facts in [0,1], got {deep}");
    assert!(
        v["headline"]["note"].as_str().unwrap().contains("Phase-4"),
        "headline note must state the Phase-4 accuracy caveat"
    );
}

#[test]
fn coverage_on_dex_types_its_cross_contract_calls() {
    // The dex fixture is the corpus's cross-contract witness: it calls
    // SEP-41 token clients, so the client-calls ratio must be non-null
    // and its interface-matched count positive.
    let out = Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["coverage", "--json", DEX_LP])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).expect("valid JSON");
    let cc = &v["recognition"]["client_calls"];
    assert!(cc["sites"].as_i64().unwrap() >= 1, "dex has invoke sites");
    assert!(cc["iface_matched"].as_i64().unwrap() >= 1, "dex matches SEP-41");
    let typed = cc["typed_ratio"].as_f64().expect("dex typed_ratio is a number");
    assert!((0.0..=1.0).contains(&typed), "typed ratio in [0,1], got {typed}");
}

#[test]
fn coverage_on_hello_add_renders_degenerate_recognition_without_nan() {
    // hello-add exercises no recognisers with a miss channel, so every
    // ratio row is `n/a` — but host interactions are still 100% (its two
    // Val-encode host calls are recognised) and nothing renders NaN/inf.
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["coverage", HELLO_ADD])
        .assert()
        .success()
        .stdout(predicate::str::contains("recognition:"))
        .stdout(predicate::str::contains("semantic recovery:"))
        .stdout(predicate::str::contains("n/a"))
        .stdout(predicate::str::contains("NaN").not())
        .stdout(predicate::str::contains("inf").not())
        .stderr(predicate::str::is_empty());
}

#[test]
fn coverage_with_missing_file_exits_three() {
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["coverage", "/tmp/sordec-coverage-definitely-does-not-exist.wasm"])
        .assert()
        .failure()
        .code(3)
        .stderr(predicate::str::contains("could not read"));
}

#[test]
fn coverage_with_garbage_input_exits_one() {
    let tmp = std::env::temp_dir().join("sordec-test-coverage-garbage.wasm");
    std::fs::write(&tmp, b"definitely not WASM").expect("write tmp");

    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["coverage"])
        .arg(&tmp)
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("parse failed"));

    let _ = std::fs::remove_file(&tmp);
}
