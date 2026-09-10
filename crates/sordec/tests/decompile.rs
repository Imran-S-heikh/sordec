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

/// A second `decompile` into the same directory must refuse, not clobber.
///
/// The emitted crate is meant to be edited — filling in a `todo!()` hole,
/// adding a test — and this used to overwrite that work silently. The test
/// asserts the edit survives, which is the property that matters; the exit
/// code and the message only explain it.
#[test]
fn decompile_refuses_to_overwrite_without_force() {
    let out = scratch("no-clobber");

    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["decompile", TOKEN_V23, "--out-dir"])
        .arg(&out)
        .assert()
        .success();

    let lib = out.join("token-v23/src/lib.rs");
    let edited = format!("{}\n// hand-edited\n", std::fs::read_to_string(&lib).expect("read"));
    std::fs::write(&lib, &edited).expect("write");

    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["decompile", TOKEN_V23, "--out-dir"])
        .arg(&out)
        .assert()
        .code(3)
        .stderr(predicate::str::contains("already exists"))
        .stderr(predicate::str::contains("--force"));

    assert_eq!(
        std::fs::read_to_string(&lib).expect("read"),
        edited,
        "the refusal must leave the edited file untouched"
    );

    let _ = std::fs::remove_dir_all(&out);
}

/// `--force` is the way through, and it really does overwrite.
#[test]
fn decompile_with_force_overwrites() {
    let out = scratch("force");

    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["decompile", TOKEN_V23, "--out-dir"])
        .arg(&out)
        .assert()
        .success();

    let lib = out.join("token-v23/src/lib.rs");
    let pristine = std::fs::read_to_string(&lib).expect("read");
    std::fs::write(&lib, "// replaced\n").expect("write");

    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["decompile", TOKEN_V23, "--out-dir"])
        .arg(&out)
        .arg("--force")
        .assert()
        .success();

    assert_eq!(
        std::fs::read_to_string(&lib).expect("read"),
        pristine,
        "--force must restore the emitted output"
    );

    let _ = std::fs::remove_dir_all(&out);
}

/// A module arriving on stdin has no filename, so the output is named
/// `contract/`. Stated in `--help`; asserted here so it stays true.
#[test]
fn decompile_from_stdin_writes_to_contract_dir() {
    let out = scratch("stdin");
    let wasm = std::fs::read(TOKEN_V23).expect("fixture present");

    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["decompile", "-", "--out-dir"])
        .arg(&out)
        .write_stdin(wasm)
        .assert()
        .success();

    assert!(out.join("contract/src/lib.rs").is_file());
    assert!(out.join("contract/contract.wat").is_file());

    let _ = std::fs::remove_dir_all(&out);
}
