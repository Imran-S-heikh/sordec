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
    "/../../samples/contracts/hello-add/hello-add.wasm"
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
fn dump_ir_recognises_host_calls_in_token_v23() {
    // Every SEP-41 token contract calls `put_contract_data` (the
    // ledger storage write primitive — module "l", name "_") to
    // record balance and metadata. After semantic recovery v0 the
    // output must show that call's friendly name, not the raw
    // `Call { function_index: ... }` Debug form.
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-ir", TOKEN_V23])
        .assert()
        .success()
        .stdout(predicate::str::contains("host:l:put_contract_data"));
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

// ---------------------------------------------------------------------
// W3 de-cluttering: default view vs --raw
// ---------------------------------------------------------------------

#[test]
fn dump_ir_default_view_is_decluttered() {
    // The default view is the lifted IR the pipeline actually consumes:
    // dead blocks (waffle orphans + blocks emptied by threading) are
    // hidden behind an honest count line, and waffle's synthetic
    // return funnel is gone from at least one function (returns
    // inlined into predecessors).
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-ir", TOKEN_V23])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "unreachable block(s) hidden (--raw shows them)",
        ));
}

#[test]
fn dump_ir_raw_flag_shows_the_pristine_lift() {
    // --raw skips the de-cluttering pipeline entirely: no hidden-block
    // notes, and the max-SSA clutter is visible again.
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-ir", "--raw", TOKEN_V23])
        .assert()
        .success()
        .stdout(predicate::str::contains("unreachable block(s) hidden").not())
        .stderr(predicate::str::is_empty());
}

#[test]
fn dump_ir_default_output_is_deterministic() {
    // Two runs must be byte-identical — no hash-order leaks from the
    // de-cluttering passes.
    let run = || {
        Command::cargo_bin("sordec")
            .expect("sordec binary builds")
            .args(["dump-ir", TOKEN_V23])
            .output()
            .expect("sordec runs")
            .stdout
    };
    assert_eq!(run(), run(), "dump-ir output must be deterministic");
}
