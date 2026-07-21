//! End-to-end tests for `sordec dump-wat`.
//!
//! Structural anchors of the annotated-WAT output — the banner, the
//! per-function header blocks, and the inline host-call labels — plus the
//! standard exit-code contract. The rigorous WAT-validity and
//! losslessness checks live in `sordec-backend`'s K5 acceptance gates.

use assert_cmd::Command;
use predicates::prelude::*;

const TOKEN_V23: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../samples/contracts/token-v23/token-v23.wasm"
);

const TIMELOCK: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../samples/contracts/timelock/timelock.wasm"
);

#[test]
fn dump_wat_emits_banner_interface_and_headers() {
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-wat", TOKEN_V23])
        .assert()
        .success()
        // Module-header banner with the recovered interface.
        .stdout(predicate::str::contains("Soroban annotated WAT"))
        .stdout(predicate::str::contains("interface (from contractspecv0):"))
        .stdout(predicate::str::contains(
            "fn transfer(from: Address, to_muxed: MuxedAddress, amount: i128) -> ()",
        ))
        // At least one per-function L1 header block.
        .stdout(predicate::str::contains(";; ── fn "))
        // The flat disassembly is still present.
        .stdout(predicate::str::contains("(module"))
        .stdout(predicate::str::contains("(func"))
        .stderr(predicate::str::contains("[error]").not());
}

#[test]
fn dump_wat_labels_host_calls_inline_with_friendly_names() {
    // Inline notes name the callee from the host-call catalog. These are
    // the raw host imports (`put_contract_data`), distinct from the
    // recognized op names in the header block (`storage_set`), so a
    // catalog name proves the inline tier fired.
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-wat", TOKEN_V23])
        .assert()
        .success()
        .stdout(predicate::str::contains(";; put_contract_data"))
        .stdout(predicate::str::contains(";; require_auth"));
}

#[test]
fn dump_wat_header_lists_recovered_operations() {
    // The header block carries the recovered semantics: storage ops with
    // their tier, the SEP-41 client call, typed panics.
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-wat", TIMELOCK])
        .assert()
        .success()
        .stdout(predicate::str::contains("invoke_contract transfer/3 [SEP-41]"))
        .stdout(predicate::str::contains("panic!() [no error code]"))
        .stderr(predicate::str::contains("[error]").not());
}

#[test]
fn dump_wat_with_missing_file_exits_three() {
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-wat", "/tmp/sordec-dump-wat-does-not-exist.wasm"])
        .assert()
        .failure()
        .code(3)
        .stderr(predicate::str::contains("could not read"));
}

#[test]
fn dump_wat_with_garbage_input_exits_one() {
    let tmp = std::env::temp_dir().join("sordec-test-dump-wat-garbage.wasm");
    std::fs::write(&tmp, b"definitely not WASM").expect("write tmp");

    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-wat"])
        .arg(&tmp)
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("parse failed"));

    let _ = std::fs::remove_file(&tmp);
}
