//! End-to-end tests for `sordec score`.
//!
//! G1 wires the command with placeholder category scoring, so these
//! assert the plumbing — the report shape, the identity pass, JSON keys,
//! and error handling — not the (not-yet-real) category numbers. The
//! calibration battery that pins real behaviour lives in `sordec-score`.

use assert_cmd::Command;
use predicates::prelude::*;

const HELLO_ADD_SRC: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../samples/contracts/hello-add/source/src/lib.rs"
);

const TOKEN_V23_SRC_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../samples/contracts/token-v23/source/src"
);

#[test]
fn score_identity_passes_and_reports_all_categories() {
    // Scoring a file against itself must pass, and the text report must
    // name every category and the scorer version.
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["score", HELLO_ADD_SRC, HELLO_ADD_SRC])
        .assert()
        .success()
        .stdout(predicate::str::contains("scorer version: score-"))
        .stdout(predicate::str::contains("PASS"))
        .stdout(predicate::str::contains("interface"))
        .stdout(predicate::str::contains("structure"))
        .stdout(predicate::str::contains("semantic"))
        .stdout(predicate::str::contains("compilation"))
        .stderr(predicate::str::is_empty());
}

#[test]
fn score_json_emits_the_report_schema() {
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["score", HELLO_ADD_SRC, HELLO_ADD_SRC, "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"scorer_version\""))
        .stdout(predicate::str::contains("\"overall\""))
        .stdout(predicate::str::contains("\"passed\": true"))
        .stdout(predicate::str::contains("\"categories\""))
        .stdout(predicate::str::contains("\"interface\""))
        .stdout(predicate::str::contains("\"compilation\""));
}

#[test]
fn score_reports_compilation_unchecked_by_default() {
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["score", HELLO_ADD_SRC, HELLO_ADD_SRC, "--json"])
        .assert()
        .success()
        // The compilation category is opt-in; by default it is excluded
        // from the mean, not silently scored zero.
        .stdout(predicate::str::contains("\"checked\": false"));
}

#[test]
fn score_flattens_and_passes_a_multi_file_source_directory() {
    // token-v23 is a real multi-file contract (lib.rs + contract.rs +
    // admin.rs + …). The loader must flatten the directory and identity
    // must still pass.
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["score", TOKEN_V23_SRC_DIR, TOKEN_V23_SRC_DIR])
        .assert()
        .success()
        .stdout(predicate::str::contains("PASS"))
        .stderr(predicate::str::is_empty());
}

#[test]
fn score_missing_input_is_an_io_error() {
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["score", "/no/such/file.rs", HELLO_ADD_SRC])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("could not read"));
}

#[test]
fn score_unparseable_input_is_a_pipeline_error() {
    // Write a bad-Rust temp file and point the reconstructed side at it.
    let dir = std::env::temp_dir().join(format!("sordec_score_e2e_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let bad = dir.join("bad.rs");
    std::fs::write(&bad, "fn (").expect("write bad source");

    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args([
            "score",
            bad.to_str().expect("utf8 path"),
            HELLO_ADD_SRC,
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("scoring failed"));

    let _ = std::fs::remove_dir_all(&dir);
}
