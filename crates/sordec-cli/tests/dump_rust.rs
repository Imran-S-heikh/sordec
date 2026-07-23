//! End-to-end tests for `sordec dump-rust`.
//!
//! Structural anchors of the reconstructed-Rust output — the `#![no_std]`
//! module, the `#[contract]` scaffold, a spec method, and reconstructed
//! `#[contracttype]`s — plus the standard exit-code contract. The rigorous
//! parse-validity gate lives in `sordec-backend`'s `rust_emit` corpus test.

use assert_cmd::Command;
use predicates::prelude::*;

const TOKEN_V23: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../samples/contracts/token-v23/token-v23.wasm"
);

const HELLO_ADD: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../samples/contracts/hello-add/hello-add.wasm"
);

#[test]
fn dump_rust_emits_hello_add_skeleton() {
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-rust", HELLO_ADD])
        .assert()
        .success()
        .stdout(predicate::str::starts_with("#![no_std]"))
        .stdout(predicate::str::contains("#[contract]\npub struct Contract;"))
        .stdout(predicate::str::contains("pub fn add(a: u64, b: u64) -> u64"))
        .stderr(predicate::str::contains("[error]").not());
}

#[test]
fn dump_rust_reconstructs_token_contract_types() {
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-rust", TOKEN_V23])
        .assert()
        .success()
        .stdout(predicate::str::contains("#[contracttype]"))
        .stdout(predicate::str::contains("pub enum DataKey"))
        .stdout(predicate::str::contains("Balance(soroban_sdk::Address)"))
        .stderr(predicate::str::contains("[error]").not());
}

#[test]
fn dump_rust_with_missing_file_exits_three() {
    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-rust", "/tmp/sordec-dump-rust-does-not-exist.wasm"])
        .assert()
        .failure()
        .code(3)
        .stderr(predicate::str::contains("could not read"));
}

#[test]
fn dump_rust_with_garbage_input_exits_one() {
    let tmp = std::env::temp_dir().join("sordec-test-dump-rust-garbage.wasm");
    std::fs::write(&tmp, b"definitely not WASM").expect("write tmp");

    Command::cargo_bin("sordec")
        .expect("sordec binary builds")
        .args(["dump-rust"])
        .arg(&tmp)
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("parse failed"));

    let _ = std::fs::remove_file(&tmp);
}
