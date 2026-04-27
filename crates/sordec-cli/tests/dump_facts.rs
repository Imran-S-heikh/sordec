//! End-to-end tests for `sordec dump-facts`.
//!
//! Spawns the binary as a subprocess via [`assert_cmd`] and asserts on
//! stdout / stderr / exit code. Uses corpus fixtures to keep the tests
//! representative of real usage.

use assert_cmd::Command;
use predicates::prelude::*;

const TOKEN_V23: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../samples/contracts/token-v23/token-v23.wasm"
);

const TOKEN_V23_STRIPPED: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../samples/contracts/token-v23-stripped/token-v23-stripped.wasm"
);

#[test]
fn dump_facts_on_canonical_fixture_emits_clean_json() {
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-facts", TOKEN_V23])
        .assert()
        .success()
        .stdout(predicate::str::starts_with("{"))
        .stdout(predicate::str::contains("\"wasm_facts\""))
        .stdout(predicate::str::contains("\"soroban_facts\""))
        .stdout(predicate::str::contains("\"diagnostics\""))
        // token-v23 is the canonical clean fixture: no diagnostics
        // means stderr is empty.
        .stderr(predicate::str::is_empty());
}

#[test]
fn dump_facts_on_stripped_fixture_reports_no_soroban_facts() {
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-facts", TOKEN_V23_STRIPPED])
        .assert()
        .success()
        // Stripped contracts have no contractspecv0 → soroban_facts is None,
        // which serde renders as `null`.
        .stdout(predicate::str::contains("\"soroban_facts\": null"))
        // No metadata to decode, so no diagnostics emitted.
        .stderr(predicate::str::is_empty());
}

#[test]
fn dump_facts_with_missing_file_exits_three() {
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-facts", "/tmp/sordec-definitely-does-not-exist.wasm"])
        .assert()
        .failure()
        .code(3)
        .stderr(predicate::str::contains("could not read"));
}

#[test]
fn dump_facts_with_garbage_input_surfaces_invalid_wasm() {
    // Write a few bytes of garbage into a temp file and feed it to dump-facts.
    let tmp = std::env::temp_dir().join("sordec-test-garbage.wasm");
    std::fs::write(&tmp, b"this is not WASM").expect("write tmp");

    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-facts"])
        .arg(&tmp)
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("parse failed"));

    let _ = std::fs::remove_file(&tmp);
}
