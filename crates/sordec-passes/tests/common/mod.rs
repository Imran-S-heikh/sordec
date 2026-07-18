//! Test helpers shared across `tests/lift.rs` and any future integration
//! test binaries in this crate. Cargo treats `tests/common/mod.rs`
//! specially — it is NOT compiled as its own test binary; it's only
//! visible to siblings that declare `mod common;`.
//!
//! Note: an identical helper lives in `crates/sordec-driver/tests/common/mod.rs`.
//! The duplication is intentional. Two callers don't justify a
//! `sordec-test-support` crate; revisit at three.

use sordec_common::{BlockId, IrId, ValueId};
use sordec_ir::{LiftedIr, LiftedTerminator};

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

/// Re-derives the post-lift invariants on the public IR surface. The
/// crate-internal `validate_lifted_function` is also invoked via
/// `debug_assert!` from inside `lift_with_waffle`; this helper repeats
/// the checks from outside the crate to guarantee they hold for callers
/// (not just for the lifter itself).
///
/// Panics if any invariant is violated. The panic message identifies
/// which function and which dangling reference triggered the failure.
pub fn assert_invariants_hold(lifted: &LiftedIr) {
    for func in &lifted.functions {
        // Entry block resolves.
        assert!(
            func.blocks.get(func.entry).is_some(),
            "function {} entry {} does not resolve",
            func.id,
            func.entry
        );

        let block_count = func.blocks.len() as u32;
        let value_count = func.values.len() as u32;

        let resolves_block = |b: BlockId| b.index() < block_count;
        let resolves_value = |v: ValueId| v.index() < value_count;

        for (_block_id, block) in func.blocks.iter() {
            for &v in &block.params {
                assert!(resolves_value(v), "block param {} dangles in {}", v, func.id);
            }
            for &v in &block.instructions {
                assert!(
                    resolves_value(v),
                    "instruction {} dangles in {}",
                    v,
                    func.id
                );
            }
            match &block.terminator {
                LiftedTerminator::Branch(t) => {
                    assert!(resolves_block(t.block));
                    for &v in &t.args {
                        assert!(resolves_value(v));
                    }
                }
                LiftedTerminator::BranchIf {
                    cond,
                    if_true,
                    if_false,
                } => {
                    assert!(resolves_value(*cond));
                    assert!(resolves_block(if_true.block));
                    assert!(resolves_block(if_false.block));
                }
                LiftedTerminator::Switch {
                    index,
                    targets,
                    default,
                } => {
                    assert!(resolves_value(*index));
                    for t in targets {
                        assert!(resolves_block(t.block));
                    }
                    assert!(resolves_block(default.block));
                }
                LiftedTerminator::Return { values } => {
                    for &v in values {
                        assert!(resolves_value(v));
                    }
                }
                LiftedTerminator::Unreachable => {}
            }
        }
    }
}
