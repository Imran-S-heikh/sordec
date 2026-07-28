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
        .stdout(predicate::str::contains("behavior"))
        // The gate renders on its own line, above `overall`, because it is a
        // precondition on the verdict rather than a contributor to the score.
        .stdout(predicate::str::contains("compile gate:"))
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
        .stdout(predicate::str::contains("\"weights_profile\""))
        .stdout(predicate::str::contains("\"overall\""))
        .stdout(predicate::str::contains("\"passed\": true"))
        .stdout(predicate::str::contains("\"categories\""))
        .stdout(predicate::str::contains("\"interface\""))
        .stdout(predicate::str::contains("\"behavior\""))
        .stdout(predicate::str::contains("\"compilation_gate\""));
}

#[test]
fn score_leaves_the_gate_unchecked_by_default() {
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["score", HELLO_ADD_SRC, HELLO_ADD_SRC, "--json"])
        .assert()
        .success()
        // The gate is opt-in. Unchecked must not veto, or every default run
        // would fail — hence `passed: true` alongside it on an identity score.
        .stdout(predicate::str::contains("\"outcome\": \"unchecked\""))
        .stdout(predicate::str::contains("\"passed\": true"))
        // Behavior is unchecked too, until the differential harness is wired
        // in: excluded from the mean rather than silently scored zero.
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
fn score_check_compile_passes_the_gate_on_a_valid_contract() {
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
        // With the check requested and the SDK available the gate is evaluated
        // and passes. It contributes no score — an identity comparison already
        // scores 1.0 — but it no longer withholds the verdict.
        .stdout(predicate::str::contains("\"outcome\": \"passed\""))
        .stdout(predicate::str::contains("\"passed\": true"));

    let _ = std::fs::remove_dir_all(&dir);
}

/// The gate's whole reason for existing: a reconstruction that does not build
/// fails, however well it scores.
///
/// Scored against itself, so every AST category is a perfect 1.0 and `overall`
/// is 1.0 — comfortably over the 0.90 threshold. The verdict must still be FAIL,
/// on the gate alone. Before T19 this same input reported PASS with compilation
/// dragging the mean down slightly, which is exactly the behaviour the gate
/// replaces.
///
/// Run with: cargo test -p sordec-cli --test score -- --ignored
#[test]
#[ignore = "shells out to cargo check against soroban-sdk (slow)"]
fn a_failed_gate_vetoes_a_perfect_score() {
    let dir = std::env::temp_dir().join(format!("sordec_score_gate_veto_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let src = dir.join("lib.rs");
    // Valid Rust that parses (so the categories score) but does not type-check
    // (so the gate fails) — the exact shape our emitter currently produces.
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
fn leaked() -> u32 { "not a u32" }
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
        // Exit code still 0: scoring ran. The verdict lives in the report, not
        // the exit status — the existing convention (main.rs `run_score`).
        .success()
        .stdout(predicate::str::contains("\"outcome\": \"failed\""))
        .stdout(predicate::str::contains("\"passed\": false"))
        // ...while the score itself is untouched and perfect.
        .stdout(predicate::str::contains("\"overall\": 1.0"))
        // Diagnostics survive: the error count is our emitter-progress signal.
        .stdout(predicate::str::contains("\"diagnostics\""));

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

#[test]
fn score_accepts_a_weights_profile() {
    // The shipped default profile reproduces the built-in weights, so an
    // identity pair still passes when weights are supplied via --weights.
    const PROFILE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../sordec-score/profiles/rfp-default.toml"
    );
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["score", HELLO_ADD_SRC, HELLO_ADD_SRC, "--weights", PROFILE])
        .assert()
        .success()
        .stdout(predicate::str::contains("PASS"))
        .stderr(predicate::str::is_empty());
}

#[test]
fn score_rejects_a_bad_weights_file() {
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args([
            "score",
            HELLO_ADD_SRC,
            HELLO_ADD_SRC,
            "--weights",
            "/no/such/weights.toml",
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("could not read"));
}
