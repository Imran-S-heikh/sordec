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
#[ignore = "shells out to cargo check against soroban-sdk (slow)"]
fn score_check_compile_marks_compilation_checked() {
    // A minimal soroban-sdk-only contract compiled against the cached SDK.
    // Run with: cargo test -p sordec-cli --test score -- --ignored
    let dir = std::env::temp_dir().join(format!("sordec_score_compile_e2e_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let src = dir.join("lib.rs");
    std::fs::write(
        &src,
        r#"#![no_std]
use soroban_sdk::{contract, contractimpl, Env};
#[contract]
pub struct C;
#[contractimpl]
impl C {
    pub fn add(_e: Env, a: u32, b: u32) -> u32 { a + b }
}
"#,
    )
    .expect("write contract");

    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args([
            "score",
            src.to_str().unwrap(),
            src.to_str().unwrap(),
            "--check-compile",
            "--json",
        ])
        .assert()
        .success()
        // With the check requested and the SDK available, compilation is
        // a checked category, not excluded.
        .stdout(predicate::str::contains("\"compilation\""))
        .stdout(predicate::str::contains("\"checked\": true"));

    let _ = std::fs::remove_dir_all(&dir);
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
