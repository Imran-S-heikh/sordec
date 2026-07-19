//! Test helpers shared across `tests/lift.rs` and any future integration
//! test binaries in this crate. Cargo treats `tests/common/mod.rs`
//! specially — it is NOT compiled as its own test binary; it's only
//! visible to siblings that declare `mod common;`.
//!
//! Note: an identical helper lives in `crates/sordec-driver/tests/common/mod.rs`.
//! The duplication is intentional. Two callers don't justify a
//! `sordec-test-support` crate; revisit at three.

use sordec_ir::{validate_lifted, LiftedIr};

/// The committed WASM corpus, `(name, bytes)`, sha256-pinned via
/// `tools/verify-fixtures.sh`. Shared by the corpus-lock test binaries.
///
/// `allow(dead_code)`: every sibling binary that declares `mod common;`
/// compiles its own copy of this module, and not all of them reference
/// the corpus.
#[allow(dead_code)]
pub const FIXTURES: &[(&str, &[u8])] = &[
    (
        "hello-add",
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../samples/contracts/hello-add/hello-add.wasm"
        )),
    ),
    (
        "token-v22",
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../samples/contracts/token-v22/token-v22.wasm"
        )),
    ),
    (
        "token-v23",
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../samples/contracts/token-v23/token-v23.wasm"
        )),
    ),
    (
        "token-v23-stripped",
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../samples/contracts/token-v23-stripped/token-v23-stripped.wasm"
        )),
    ),
    (
        "timelock",
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../samples/contracts/timelock/timelock.wasm"
        )),
    ),
    (
        "dex-liquidity-pool",
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../samples/contracts/dex-liquidity-pool/dex-liquidity-pool.wasm"
        )),
    ),
    (
        "attestation",
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../samples/contracts/attestation/attestation.wasm"
        )),
    ),
];

/// Re-derives the post-lift reference-integrity invariants on the public
/// IR surface, from outside the crate. Delegates to the canonical
/// [`sordec_ir::validate_lifted`] (the same checks the lifter runs via
/// `debug_assert!` internally), so there is one source of truth.
///
/// Panics if any invariant is violated, naming the offending function
/// and reference.
///
/// `allow(dead_code)`: not every sibling binary that compiles this
/// module calls it.
#[allow(dead_code)]
pub fn assert_invariants_hold(lifted: &LiftedIr) {
    validate_lifted(lifted).expect("lifted IR satisfies reference-integrity invariants");
}
