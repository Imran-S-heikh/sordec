//! End-to-end tests for `sordec dump-ir`.
//!
//! Asserts only structural anchors that don't depend on the
//! `WasmOp::Display` output — that's currently a Debug-fallback and
//! brittle to snapshot. Function/block/terminator scaffolding is what
//! we're testing here.

use assert_cmd::Command;
use predicates::prelude::*;

const HELLO_ADD: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../learning/experiments/01-hello-add/target/wasm32-unknown-unknown/release/hello_add.wasm"
);

const TOKEN_V23: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../samples/contracts/token-v23/token-v23.wasm"
);

#[test]
fn dump_ir_on_hello_add_emits_expected_scaffolding() {
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-ir", HELLO_ADD])
        .assert()
        .success()
        // Every non-trivial Soroban contract has at least one function
        // and an entry block bb0.
        .stdout(predicate::str::contains("function func_"))
        .stdout(predicate::str::contains("bb0"))
        // hello-add's `add` export must show up as an annotation.
        .stdout(predicate::str::contains("[exported as \"add\"]"))
        // hello-add is clean — no diagnostics.
        .stderr(predicate::str::is_empty());
}

#[test]
fn dump_ir_with_header_prepends_module_info() {
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-ir", "--with-header", HELLO_ADD])
        .assert()
        .success()
        // Header lines are comment-prefixed (`;;`).
        .stdout(predicate::str::contains(";; module"))
        .stdout(predicate::str::contains(";;   imports:"))
        .stdout(predicate::str::contains(";;   exports:"))
        .stdout(predicate::str::contains(";;   local functions:"))
        .stdout(predicate::str::contains(";;   metadata: present"));
}

#[test]
fn dump_ir_on_canonical_token_emits_no_diagnostics() {
    // token-v23 is the canonical clean fixture: zero diagnostics
    // expected on either parse or lift.
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-ir", TOKEN_V23])
        .assert()
        .success()
        .stdout(predicate::str::contains("function func_"))
        .stderr(predicate::str::is_empty());
}

#[test]
fn dump_ir_with_missing_file_exits_three() {
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-ir", "/tmp/sordec-definitely-does-not-exist.wasm"])
        .assert()
        .failure()
        .code(3)
        .stderr(predicate::str::contains("could not read"));
}

#[test]
fn dump_ir_with_garbage_input_surfaces_invalid_wasm() {
    let tmp = std::env::temp_dir().join("sordec-test-dump-ir-garbage.wasm");
    std::fs::write(&tmp, b"definitely not WASM").expect("write tmp");

    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-ir"])
        .arg(&tmp)
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("parse failed"));

    let _ = std::fs::remove_file(&tmp);
}
