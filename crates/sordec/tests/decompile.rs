//! End-to-end tests for `sordec decompile`.
//!
//! Verifies the file-writing contract (nested per-contract layout, the
//! annotated WAT content) and the standard exit codes. The WAT's own
//! correctness is covered by `sordec-backend`'s K5 gates.

use assert_cmd::Command;
use predicates::prelude::*;

const TOKEN_V23: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../samples/contracts/token-v23/token-v23.wasm"
);

/// A unique, cleaned scratch dir for one test.
fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("sordec-test-decompile-{tag}"));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

#[test]
fn decompile_writes_a_buildable_crate() {
    let out = scratch("token");
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["decompile", TOKEN_V23, "--out-dir"])
        .arg(&out)
        .assert()
        .success()
        // stdout reports all three written paths.
        .stdout(predicate::str::contains("token-v23.wat"))
        .stdout(predicate::str::contains("Cargo.toml"))
        .stdout(predicate::str::contains("lib.rs"));

    let dir = out.join("token-v23");

    // Nested per-contract layout: <out>/<name>/{<name>.wat, Cargo.toml, src/lib.rs}.
    let wat = dir.join("token-v23.wat");
    let content = std::fs::read_to_string(&wat).expect("read wat");
    assert!(content.contains("Soroban annotated WAT"), "the annotated WAT");
    assert!(content.contains(";; ── fn "), "carries per-function headers");

    let manifest = std::fs::read_to_string(dir.join("Cargo.toml")).expect("read Cargo.toml");
    assert!(manifest.contains("crate-type = [\"cdylib\"]"), "cdylib manifest");
    assert!(manifest.contains("soroban-sdk = "), "depends on soroban-sdk");

    let lib = std::fs::read_to_string(dir.join("src").join("lib.rs")).expect("read src/lib.rs");
    assert!(lib.starts_with("#![no_std]"), "the reconstructed module");
    // A recovered idiom is present (proves the Rust half is real). Parse
    // validity itself is covered by sordec-backend's rust_emit corpus gate.
    assert!(lib.contains(".require_auth()"), "recovered a Soroban idiom");

    let _ = std::fs::remove_dir_all(&out);
}

#[test]
fn decompile_with_missing_file_exits_three() {
    let out = scratch("missing");
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args([
            "decompile",
            "/tmp/sordec-decompile-does-not-exist.wasm",
            "--out-dir",
        ])
        .arg(&out)
        .assert()
        .failure()
        .code(3)
        .stderr(predicate::str::contains("could not read"));
}

#[test]
fn decompile_with_garbage_input_exits_one() {
    let out = scratch("garbage");
    let tmp = std::env::temp_dir().join("sordec-test-decompile-garbage.wasm");
    std::fs::write(&tmp, b"definitely not WASM").expect("write tmp");

    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["decompile"])
        .arg(&tmp)
        .arg("--out-dir")
        .arg(&out)
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("decompile failed"));

    let _ = std::fs::remove_file(&tmp);
}
