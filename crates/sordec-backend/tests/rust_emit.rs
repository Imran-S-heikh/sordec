//! Corpus gates for the compilable-Rust emitter (Phase 4 · W1 skeleton).
//!
//! The Rust counterpart of `wat_gates.rs`. W1 emits the module *skeleton*
//! (reconstructed types + scaffold + signatures with `todo!()` bodies), so
//! the load-bearing invariant is **structural validity**: every fixture
//! emits, and every emission re-parses as a Rust file. Bodies arrive in a
//! later wave; the acceptance shape locked here is the frame they drop into.

mod common;

use sordec_backend::{emit_cargo_toml, emit_rust};

/// Structural-validity gate: every fixture emits, and the emitted source is
/// syntactically valid Rust (parses via `syn`). This is W1's headline
/// acceptance — the emitter cannot produce unparseable output.
#[test]
fn every_fixture_emits_parseable_rust() {
    for (name, wasm) in common::fixtures() {
        let high = common::build_high(wasm);
        let src = emit_rust(&high).unwrap_or_else(|e| panic!("{name}: emit failed: {e}"));
        assert!(!src.is_empty(), "{name}: produced output");
        syn::parse_file(&src)
            .unwrap_or_else(|e| panic!("{name}: emitted Rust did not parse: {e}\n---\n{src}"));
    }
}

/// Emission is byte-for-byte deterministic (a scorer/regression prerequisite).
#[test]
fn emission_is_deterministic() {
    let high = common::build_high(common::TOKEN_V23);
    assert_eq!(
        emit_rust(&high).expect("emits"),
        emit_rust(&high).expect("emits"),
        "emission must be deterministic",
    );
}

/// The canonical acceptance shape: hello-add reconstructs its `#[contract]`
/// scaffold and its one spec method exactly. Asserted by containment of the
/// stable contract-facing fragment rather than a full-file snapshot, so
/// incidental internal-helper numbering does not make the lock brittle.
#[test]
fn hello_add_skeleton_shape() {
    let (_, wasm) = common::fixtures()[0];
    let high = common::build_high(wasm);
    let src = emit_rust(&high).expect("emits");

    assert!(src.starts_with("#![no_std]"), "no_std module attribute:\n{src}");
    assert!(src.contains("#[contract]\npub struct Contract;"), "contract struct:\n{src}");

    let expected_method = "\
#[contractimpl]
impl Contract {
    pub fn add(a: u64, b: u64) -> u64 {
        todo!()
    }
}";
    assert!(src.contains(expected_method), "spec method not emitted verbatim:\n{src}");
}

/// The generated `Cargo.toml` is a buildable cdylib crate manifest pinning
/// the SDK version recovered from the contract's own metadata.
#[test]
fn hello_add_cargo_toml_is_a_cdylib_crate() {
    let (_, wasm) = common::fixtures()[0];
    let manifest = emit_cargo_toml(&common::build_high(wasm));
    assert!(manifest.contains("crate-type = [\"cdylib\"]"), "{manifest}");
    assert!(manifest.contains("soroban-sdk = "), "{manifest}");
    // parseable as TOML-ish: has the three required tables.
    for table in ["[package]", "[lib]", "[dependencies]"] {
        assert!(manifest.contains(table), "missing {table}:\n{manifest}");
    }
}

/// Type reconstruction lands on the canonical benchmark: token-v23's
/// `#[contracttype]` definitions come back with the right shape.
#[test]
fn token_v23_reconstructs_contract_types() {
    let high = common::build_high(common::TOKEN_V23);
    let src = emit_rust(&high).expect("emits");

    assert!(src.contains("#[contracttype]"), "has contracttype defs:\n{src}");
    // The DataKey enum: mixed unit + payload variants, exactly as in source.
    assert!(src.contains("pub enum DataKey"), "DataKey enum present:\n{src}");
    assert!(src.contains("Balance(soroban_sdk::Address)"), "payload variant:\n{src}");
    assert!(src.contains("Admin,"), "unit variant:\n{src}");
}
