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
    ] {
        assert!(v.get(key).is_some(), "missing top-level key {key:?}");
    }
    // Sanity-check a few nested anchors.
    assert!(v["host_calls"]["total"].is_number());
    assert!(v["host_calls"]["recognized"].is_number());
    assert!(v["host_calls"]["unrecognized"].is_array());
    assert!(v["operators"]["total"].is_number());
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
fn coverage_with_missing_file_exits_three() {
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args([
            "coverage",
            "/tmp/sordec-coverage-definitely-does-not-exist.wasm",
        ])
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
