//! Integration tests for [`sordec_passes::lift_with_waffle`].
//!
//! Exercises the lifter end-to-end against the two real WASM fixtures
//! we built in `learning/experiments`:
//!
//! - `01-hello-add` — single-function `add(u64, u64) → u64`.
//! - `02-counter` — multi-function with custom enum, storage, auth,
//!   events.
//!
//! Tests are split into smoke checks (does it lift at all?), structural
//! assertions (does the `add` function look the way we expect?), and
//! invariant checks (every cross-reference resolves).

use sordec_common::IrId;
use sordec_ir::{LiftedTerminator, LiftedValueDef, WasmOpcodeKind};
use sordec_passes::lift_with_waffle;

/// Canonical `add(u64, u64) -> u64` contract.
const HELLO_ADD_WASM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../learning/experiments/01-hello-add/target/wasm32-unknown-unknown/release/hello_add.wasm"
));

/// Counter contract — exercises a custom enum, multiple functions,
/// storage tiers, auth, and events.
const COUNTER_WASM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../learning/experiments/02-counter/target/wasm32-unknown-unknown/release/counter.wasm"
));

// ---------------------------------------------------------------------
// Smoke tests (2)
// ---------------------------------------------------------------------

#[test]
fn lifts_hello_add_smoke() {
    let facts = sordec_frontend::parse(HELLO_ADD_WASM).expect("frontend parses hello_add");
    let lifted = lift_with_waffle(HELLO_ADD_WASM, &facts).expect("lifter accepts hello_add");

    // Local-function count should match the number of bodies the
    // frontend tagged with type indices.
    assert_eq!(
        lifted.functions.len(),
        facts.function_type_indices.len(),
        "lifted function count must equal frontend's function_type_indices count"
    );

    // Every function should have at least one block (an entry block)
    // and its `entry` should resolve.
    for func in &lifted.functions {
        assert!(!func.blocks.is_empty(), "function {} has no blocks", func.id);
        assert!(
            func.blocks.get(func.entry).is_some(),
            "function {} entry {} does not resolve",
            func.id,
            func.entry
        );
    }
}

#[test]
fn lifts_counter_smoke() {
    let facts = sordec_frontend::parse(COUNTER_WASM).expect("frontend parses counter");
    let lifted = lift_with_waffle(COUNTER_WASM, &facts).expect("lifter accepts counter");

    assert_eq!(
        lifted.functions.len(),
        facts.function_type_indices.len(),
        "lifted function count must equal frontend's function_type_indices count"
    );
    assert!(
        lifted.functions.len() > 1,
        "counter has multiple functions; expected >1 got {}",
        lifted.functions.len()
    );
    for func in &lifted.functions {
        assert!(!func.blocks.is_empty(), "function {} has no blocks", func.id);
    }
}

// ---------------------------------------------------------------------
// Structural assertion (1)
// ---------------------------------------------------------------------

#[test]
fn hello_add_add_function_has_arithmetic_return() {
    let facts = sordec_frontend::parse(HELLO_ADD_WASM).expect("frontend parses hello_add");
    let lifted = lift_with_waffle(HELLO_ADD_WASM, &facts).expect("lifter accepts hello_add");

    // The frontend records the `add` export's WASM function index. We
    // map it to a local FuncId by subtracting the imported-function
    // count (imports come first in the WASM index space).
    let imported_funcs: u32 = facts
        .imports
        .iter()
        .filter(|imp| matches!(imp.kind, sordec_ir::ImportKind::Func(_)))
        .count() as u32;
    let add_export = facts
        .exports
        .iter()
        .find(|e| e.name == "add")
        .expect("hello_add exports `add`");
    let add_local_idx = add_export.index - imported_funcs;
    let add_func = lifted
        .functions
        .iter()
        .find(|f| f.id.index() == add_local_idx)
        .expect("lifted IR contains the add function");

    // Walk to the entry block and inspect what produced the return value.
    let entry_block = add_func
        .blocks
        .get(add_func.entry)
        .expect("entry block resolves");

    // Most builds produce a multi-block function (the SDK wraps `add`
    // with overflow-check + Val-encoding glue). Find any block whose
    // terminator is `Return` with at least one value, then assert that
    // somewhere in the function's value arena there is at least one
    // arithmetic operator. This is the structural shape we care about
    // — the exact CFG can wobble across SDK / rustc versions.
    let _ = entry_block; // entry block is at least populated
    let mut saw_return = false;
    for (_block_id, block) in add_func.blocks.iter() {
        if let LiftedTerminator::Return { values } = &block.terminator {
            assert!(!values.is_empty(), "add must return a value");
            saw_return = true;
        }
    }
    assert!(saw_return, "add function must have at least one Return terminator");

    let mut saw_arithmetic = false;
    for (_value_id, value) in add_func.values.iter() {
        if let LiftedValueDef::Operator { op, .. } = &value.def {
            if matches!(op.kind(), WasmOpcodeKind::Arithmetic) {
                saw_arithmetic = true;
                break;
            }
        }
    }
    assert!(
        saw_arithmetic,
        "add function must contain at least one arithmetic operator"
    );
}

// ---------------------------------------------------------------------
// Invariant checks (2)
// ---------------------------------------------------------------------

/// Manually re-derives the post-lift invariants on the public IR
/// surface. The crate-internal `validate_lifted_function` is also
/// invoked via `debug_assert!` from inside `lift_with_waffle`; this
/// integration test repeats the checks from outside the crate to
/// guarantee they hold for callers (not just for the lifter itself).
fn assert_invariants_hold(lifted: &sordec_ir::LiftedIr) {
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

        let resolves_block = |b: sordec_common::BlockId| b.index() < block_count;
        let resolves_value = |v: sordec_common::ValueId| v.index() < value_count;

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

#[test]
fn invariants_hold_for_hello_add() {
    let facts = sordec_frontend::parse(HELLO_ADD_WASM).expect("frontend parses hello_add");
    let lifted = lift_with_waffle(HELLO_ADD_WASM, &facts).expect("lifter accepts hello_add");
    assert_invariants_hold(&lifted);
}

#[test]
fn invariants_hold_for_counter() {
    let facts = sordec_frontend::parse(COUNTER_WASM).expect("frontend parses counter");
    let lifted = lift_with_waffle(COUNTER_WASM, &facts).expect("lifter accepts counter");
    assert_invariants_hold(&lifted);
}
