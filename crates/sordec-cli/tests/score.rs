//! End-to-end tests for `sordec score`.
//!
//! G1 wires the command with placeholder category scoring, so these
//! assert the plumbing — the report shape, the identity pass, JSON keys,
//! and error handling — not the (not-yet-real) category numbers. The
//! calibration battery that pins real behaviour lives in `sordec-score`.

use std::path::Path;

use assert_cmd::Command;
use predicates::prelude::*;

const HELLO_ADD_SRC: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../samples/contracts/hello-add/source/src/lib.rs"
);

const HELLO_ADD_WASM: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../samples/contracts/hello-add/hello-add.wasm"
);

const ATTESTATION_WASM: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../samples/contracts/attestation/attestation.wasm"
);

/// A contract with one entrypoint, for renderer assertions that need a report but not
/// a particular score.
const MINIMAL_CONTRACT: &str = r"
#![no_std]
use soroban_sdk::{contract, contractimpl, Env};
#[contract]
pub struct C;
#[contractimpl]
impl C {
    pub fn go(e: Env, n: u32) -> u32 { if n > 0 { n } else { 0 } }
}
";

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

/// `--behavior` reports *why* it could not measure, and the reason names the stage.
///
/// Behaviour needs a crate to recompile, so pointing it at a lone `.rs` file has to
/// fail — and fail informatively. A bare "unavailable" would leave the user guessing
/// between a missing toolchain, a broken reconstruction and a wrong argument.
///
/// Fast: it never reaches a build, because the crate check comes first.
#[test]
fn behavior_reports_the_stage_it_could_not_get_past() {
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args([
            "score",
            HELLO_ADD_SRC,
            HELLO_ADD_SRC,
            "--behavior",
            HELLO_ADD_WASM,
            "--basis",
            "source-only",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("not a crate directory"))
        // Unavailable must not veto the verdict, exactly as for the compile gate.
        .stdout(predicate::str::contains("PASS"));
}

/// An unreadable oracle is reported as unavailable, not as a behavioural failure.
///
/// The distinction is the whole of T21: a score of 0.0 says the reconstruction does
/// the wrong thing, and a missing file says nothing of the kind.
#[test]
fn a_missing_oracle_wasm_is_unavailable_not_a_zero() {
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args([
            "score",
            HELLO_ADD_SRC,
            HELLO_ADD_SRC,
            "--behavior",
            "/no/such/contract.wasm",
            "--json",
            "--basis",
            "source-only",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("cannot read"))
        // Unchecked, so it renormalises out of the mean rather than scoring zero.
        .stdout(predicate::str::contains("\"checked\": false"))
        .stdout(predicate::str::contains("\"passed\": true"));
}

/// A behaviour rate never renders without its coverage fraction.
///
/// The rule T22 absorbed from the retired B24, and the one thing separating an honest
/// number from the "99.2%" we criticised in a competitor's harness. Asserted on a
/// synthetic report rather than a real run, because the point is the *renderer*: it
/// must be impossible to print a rate alone, whatever produced it.
///
/// Note the scorer makes this hard to get wrong by construction — `Behavior::new`
/// takes the denominator as a required argument — so this guards the last mile, where
/// a renderer could still choose to drop it.
#[test]
fn a_behavior_rate_never_renders_without_its_coverage() {
    let report = sordec_score::score_str(
        MINIMAL_CONTRACT,
        MINIMAL_CONTRACT,
        &sordec_score::ScoreOptions {
            behavior: sordec_score::BehaviorInput::Measured(
                sordec_score::Behavior::new(0.9925, sordec_score::BSide::Reconstruction, 3, 30)
                    .with_tuples(vec![
                        sordec_score::TupleScore {
                            name: "return".to_owned(),
                            matched: 3,
                            exercised: 3,
                        },
                        sordec_score::TupleScore {
                            name: "storage".to_owned(),
                            matched: 0,
                            exercised: 0,
                        },
                    ])
                    .with_trivial_agreements(4),
            ),
            ..Default::default()
        },
    )
    .expect("scores");

    let json = serde_json::to_string(&report).expect("serialises");
    // The denominator is in the machine-readable form...
    assert!(json.contains("\"entrypoints_total\":30"), "{json}");
    assert!(json.contains("\"entrypoints_driven\":3"), "{json}");
    // ...and the per-tuple breakdown, so "events 94%, storage 87%" is expressible
    // rather than blended into one number.
    assert!(json.contains("\"tuples\""), "{json}");
    assert!(json.contains("\"trivial_agreements\":4"), "{json}");

    // And the text form pairs them on the category line.
    let coverage = report
        .behavior
        .as_ref()
        .expect("measured")
        .coverage();
    assert_eq!(coverage, "3 of 30 entrypoints");
    assert!(
        report
            .categories
            .behavior
            .notes
            .iter()
            .any(|n| n.contains("3 of 30 entrypoints")),
        "a 0.9925 rate over 3 of 30 entrypoints must never appear alone: {:?}",
        report.categories.behavior.notes
    );
}

/// The behavioural net: hello-add's *reconstruction*, recompiled to wasm
/// and run against the original in a real host, must agree on every
/// exercised check.
///
/// This is the gate the marshalling elision needed. Structure rewards
/// deleting control flow and cannot tell "deleted the junk we invented"
/// from "deleted the contract's logic" — both raise the number. Only
/// behaviour on a contract we actually decompiled can, and this is it.
///
/// The generated arguments include 2^56 - 1 and 2^56, which straddle the
/// point where Soroban switches a `u64` from a small `Val` body to an
/// object handle. That is precisely the branch the return-encode collapse
/// removes, so an over-eager collapse fails here rather than silently.
///
/// `#[ignore]`d: it decompiles, recompiles to wasm, and executes both
/// modules. Run with:
///
///   cargo test -p sordec-cli --test score -- --ignored --nocapture behavior_on_the_reconstruction
#[test]
#[ignore = "decompiles, recompiles to wasm and runs both modules (slow, toolchain-dependent)"]
fn behavior_on_the_reconstruction_of_hello_add_matches_the_original() {
    let behavior = measured_behavior("hello-add", HELLO_ADD_WASM);

    // Only our own reconstruction counts toward the category.
    assert_eq!(behavior["b_side"]["kind"], "reconstruction", "{behavior}");
    assert_eq!(behavior["score"], 1.0, "{behavior}");
    assert_eq!(behavior["entrypoints_driven"], 1, "{behavior}");
    assert_eq!(behavior["entrypoints_total"], 1, "{behavior}");
    // Something was actually compared — a rate over zero checks is not a
    // pass, and the trivial agreements (both sides trapping on overflow)
    // are excluded from it rather than counted as matches.
    assert_return_tuple_is_perfect(&behavior, 5);
}

/// The same net over the second fixture that compiles, and a wider one.
///
/// attestation exercises what hello-add cannot: it has six declared
/// entrypoints rather than one, so the coverage fraction is a real fraction
/// and the `2 of 6` has to keep travelling with the `1.0000`. It is also the
/// fixture the crypto/prng lowerings landed on, and the only one whose
/// `semantic` reached 1.0000 — precisely the situation where a structure-only
/// view would be blind to a regression that changed what the contract does.
///
/// Its number was published in `PHASE_4.md` from a hand-run CLI invocation and
/// asserted nowhere, which is the gap this closes. The other four entrypoints
/// need `Bytes` argument construction, not emitter work, so `2 of 6` is the
/// harness's reach and not a reconstruction failure — assert it exactly, so
/// that widening the driver is a deliberate change to this test.
#[test]
#[ignore = "decompiles, recompiles to wasm and runs both modules (slow, toolchain-dependent)"]
fn behavior_on_the_reconstruction_of_attestation_matches_the_original() {
    let behavior = measured_behavior("attestation", ATTESTATION_WASM);

    assert_eq!(behavior["b_side"]["kind"], "reconstruction", "{behavior}");
    assert_eq!(behavior["score"], 1.0, "{behavior}");
    assert_eq!(behavior["entrypoints_driven"], 2, "{behavior}");
    assert_eq!(behavior["entrypoints_total"], 6, "{behavior}");
    assert_return_tuple_is_perfect(&behavior, 20);
}

/// Decompile `fixture` to a crate, score it against its vendored source with
/// `--behavior`, and return the `behavior` object from the JSON report.
///
/// Goes through the installed binary rather than the library so this exercises
/// the path a user actually runs — `decompile --out-dir` producing a buildable
/// crate, then `score --behavior` recompiling it. Panics if the category came
/// back unavailable, because a test asserting a *rate* must not quietly pass
/// on a machine that measured nothing.
fn measured_behavior(fixture: &str, wasm: &str) -> serde_json::Value {
    let out = std::env::temp_dir().join(format!("sordec-behavior-{fixture}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&out);

    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["decompile", wasm, "--out-dir"])
        .arg(&out)
        .assert()
        .success();

    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../samples/contracts")
        .join(fixture)
        .join("source/src");
    let stdout = Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["score", "--json", "--behavior", wasm])
        .arg(out.join(fixture))
        .arg(&source)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let _ = std::fs::remove_dir_all(&out);

    let v: serde_json::Value = serde_json::from_slice(&stdout).expect("valid JSON");
    assert!(
        !v["behavior"].is_null(),
        "{fixture}: behaviour must be measured, not unavailable: {v}"
    );
    v["behavior"].clone()
}

/// Every return-tuple check agreed, over at least `min_checks` of them.
///
/// The floor is the point: a 1.0000 over two calls is not evidence, and a
/// match rate detached from its denominator is the failure this project
/// called out in a competitor's harness.
fn assert_return_tuple_is_perfect(behavior: &serde_json::Value, min_checks: u64) {
    let returns = behavior["tuples"]
        .as_array()
        .expect("tuples")
        .iter()
        .find(|t| t["name"] == "return")
        .expect("return tuple");
    assert!(
        returns["exercised"].as_u64().unwrap_or(0) >= min_checks,
        "too few checks to mean anything (want >= {min_checks}): {returns}"
    );
    assert_eq!(returns["matched"], returns["exercised"], "{returns}");
}
