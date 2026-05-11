//! Integration tests for [`sordec_passes::lift_with_waffle`].
//!
//! Exercises the lifter end-to-end against committed real WASM fixtures:
//!
//! - `hello-add` — small exported `add(u64, u64) -> u64` contract.
//! - `timelock` — multi-function contract with storage, auth, and events.
//!
//! Tests are split into smoke checks (does it lift at all?), structural
//! assertions (does the `add` function look the way we expect?), and
//! invariant checks (every cross-reference resolves).

use sordec_common::IrId;
use sordec_ir::{LiftedTerminator, LiftedValueDef, WasmOpcodeKind};
use sordec_passes::lift_with_waffle;

mod common;
use common::assert_invariants_hold;

/// Canonical `add(u64, u64) -> u64` contract.
const HELLO_ADD_WASM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../samples/contracts/hello-add/hello-add.wasm"
));

/// Timelock contract — exercises multiple functions, storage tiers, auth,
/// and events.
const TIMELOCK_WASM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../samples/contracts/timelock/timelock.wasm"
));

// ---------------------------------------------------------------------
// Smoke tests (2)
// ---------------------------------------------------------------------

#[test]
fn lifts_hello_add_smoke() {
    let sordec_frontend::ParseOutput {
        wasm_facts: facts,
        soroban_facts,
        ..
    } = sordec_frontend::parse(HELLO_ADD_WASM).expect("frontend parses hello_add");
    let lifted = lift_with_waffle(HELLO_ADD_WASM, &facts, soroban_facts.as_ref())
        .expect("lifter accepts hello_add")
        .lifted;

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
fn lifts_timelock_smoke() {
    let sordec_frontend::ParseOutput {
        wasm_facts: facts,
        soroban_facts,
        ..
    } = sordec_frontend::parse(TIMELOCK_WASM).expect("frontend parses timelock");
    let lifted = lift_with_waffle(TIMELOCK_WASM, &facts, soroban_facts.as_ref())
        .expect("lifter accepts timelock")
        .lifted;

    assert_eq!(
        lifted.functions.len(),
        facts.function_type_indices.len(),
        "lifted function count must equal frontend's function_type_indices count"
    );
    assert!(
        lifted.functions.len() > 1,
        "timelock has multiple functions; expected >1 got {}",
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
    let sordec_frontend::ParseOutput {
        wasm_facts: facts,
        soroban_facts,
        ..
    } = sordec_frontend::parse(HELLO_ADD_WASM).expect("frontend parses hello_add");
    let lifted = lift_with_waffle(HELLO_ADD_WASM, &facts, soroban_facts.as_ref())
        .expect("lifter accepts hello_add")
        .lifted;

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
        if let LiftedValueDef::Operator { op, .. } = &value.def
            && matches!(op.kind(), WasmOpcodeKind::Arithmetic)
        {
            saw_arithmetic = true;
            break;
        }
    }
    assert!(
        saw_arithmetic,
        "add function must contain at least one arithmetic operator"
    );
}

// ---------------------------------------------------------------------
// Invariant checks (2) — `assert_invariants_hold` lives in `common/mod.rs`
// ---------------------------------------------------------------------

#[test]
fn invariants_hold_for_hello_add() {
    let sordec_frontend::ParseOutput {
        wasm_facts: facts,
        soroban_facts,
        ..
    } = sordec_frontend::parse(HELLO_ADD_WASM).expect("frontend parses hello_add");
    let lifted = lift_with_waffle(HELLO_ADD_WASM, &facts, soroban_facts.as_ref())
        .expect("lifter accepts hello_add")
        .lifted;
    assert_invariants_hold(&lifted);
}

#[test]
fn invariants_hold_for_timelock() {
    let sordec_frontend::ParseOutput {
        wasm_facts: facts,
        soroban_facts,
        ..
    } = sordec_frontend::parse(TIMELOCK_WASM).expect("frontend parses timelock");
    let lifted = lift_with_waffle(TIMELOCK_WASM, &facts, soroban_facts.as_ref())
        .expect("lifter accepts timelock")
        .lifted;
    assert_invariants_hold(&lifted);
}
