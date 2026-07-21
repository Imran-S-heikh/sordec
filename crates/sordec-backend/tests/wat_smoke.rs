//! End-to-end smoke checks for the annotated-WAT emitter.
//!
//! Structural, not exhaustive — the K5 acceptance gates
//! (`wat_gates.rs`) do the rigorous verification. Here we just confirm
//! the emitter runs on the corpus, produces the banner + header + inline
//! tiers, and is deterministic.

mod common;

use sordec_backend::emit_annotated_wat;

#[test]
fn token_v23_emits_banner_headers_and_inline_notes() {
    let high = common::build_high(common::TOKEN_V23);
    let wat = emit_annotated_wat(&high, common::TOKEN_V23).expect("emits");

    assert!(wat.contains("Soroban annotated WAT"), "banner rule present");
    assert!(
        wat.contains("interface (from contractspecv0):"),
        "interface section present"
    );
    assert!(wat.contains(";; ── fn "), "at least one L1 header block");
    assert!(
        wat.contains("require_auth"),
        "a recovered host operation surfaces (auth is present in SEP-41)"
    );
    // The disassembly itself is still there.
    assert!(wat.contains("(module"), "wraps the printed module");
    assert!(wat.contains("(func"), "prints function bodies");
}

#[test]
fn emission_is_deterministic() {
    let high = common::build_high(common::TOKEN_V23);
    let first = emit_annotated_wat(&high, common::TOKEN_V23).expect("emits");
    let second = emit_annotated_wat(&high, common::TOKEN_V23).expect("emits");
    assert_eq!(first, second, "emission must be byte-for-byte deterministic");
}

#[test]
fn every_fixture_emits_without_error() {
    for (name, wasm) in common::fixtures() {
        let high = common::build_high(wasm);
        let wat = emit_annotated_wat(&high, wasm).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(!wat.is_empty(), "{name}: produced output");
    }
}
