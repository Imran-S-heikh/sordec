//! Integration tests for [`sordec_frontend::parse`].
//!
//! These exercise the public API end-to-end against the two real WASM
//! fixtures we built in `learning/experiments`:
//!
//! - `01-hello-add` — simplest possible contract (one `add(u64, u64) → u64`).
//! - `02-counter` — exercises a custom enum (`DataKey`), constructor,
//!   storage, auth, events.
//!
//! Plus a short suite of error-path tests to lock the failure modes.

use sordec_frontend::{
    parse, ExportKind, FrontendError, ImportKind, PrimitiveType, TypeRef,
};

/// Canonical `add(u64, u64) -> u64` contract from `learning/experiments/01-hello-add`.
const HELLO_ADD_WASM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../learning/experiments/01-hello-add/target/wasm32-unknown-unknown/release/hello_add.wasm"
));

/// Counter contract from `learning/experiments/02-counter` — exercises
/// custom enum + constructor + storage + auth + events.
const COUNTER_WASM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../learning/experiments/02-counter/target/wasm32-unknown-unknown/release/counter.wasm"
));

// ---------------------------------------------------------------------
// hello-add fixture (5 tests)
// ---------------------------------------------------------------------

#[test]
fn hello_add_imports_are_typed_func_imports_from_int_module() {
    let facts = parse(HELLO_ADD_WASM)
        .expect("hello_add.wasm should parse")
        .wasm_facts;

    // hello-add imports two host functions from module `"i"` (the Soroban
    // int module): `obj_to_u64` and `obj_from_u64`. Both are functions.
    assert!(!facts.imports.is_empty(), "expected at least one import");
    for import in &facts.imports {
        assert_eq!(import.module, "i", "hello-add only imports from module `i`");
        assert!(
            matches!(import.kind, ImportKind::Func(_)),
            "every hello-add import is a function; got {:?}",
            import.kind
        );
    }
}

#[test]
fn hello_add_exports_include_named_function_memory_and_dispatcher() {
    let facts = parse(HELLO_ADD_WASM)
        .expect("hello_add.wasm should parse")
        .wasm_facts;

    // Required exports for any Soroban contract built by the SDK.
    let add = facts
        .exports
        .iter()
        .find(|e| e.name == "add")
        .expect("`add` export missing");
    assert_eq!(add.kind, ExportKind::Func);

    let memory = facts
        .exports
        .iter()
        .find(|e| e.name == "memory")
        .expect("`memory` export missing");
    assert_eq!(memory.kind, ExportKind::Memory);

    // The SDK-generated dispatcher export is named `_`.
    let dispatcher = facts
        .exports
        .iter()
        .find(|e| e.name == "_")
        .expect("`_` dispatcher export missing");
    assert_eq!(dispatcher.kind, ExportKind::Func);
}

#[test]
fn hello_add_has_local_function_type_indices() {
    let facts = parse(HELLO_ADD_WASM)
        .expect("hello_add.wasm should parse")
        .wasm_facts;

    // hello-add has at least one local (non-imported) function.
    assert!(
        !facts.function_type_indices.is_empty(),
        "expected at least one local function"
    );
}

#[test]
fn hello_add_metadata_includes_add_with_typed_u64_signature() {
    let soroban_facts = parse(HELLO_ADD_WASM)
        .expect("hello_add.wasm should parse")
        .soroban_facts;

    let metadata = soroban_facts.expect("hello_add is a Soroban contract");

    let add = metadata
        .functions
        .get("add")
        .expect("`add` function missing from metadata");

    assert_eq!(add.name, "add");
    assert_eq!(add.inputs.len(), 2);
    for param in &add.inputs {
        assert!(
            matches!(param.ty, TypeRef::Primitive(PrimitiveType::U64)),
            "expected `add` parameter to be u64; got {:?}",
            param.ty
        );
    }
    assert_eq!(add.outputs.len(), 1);
    assert!(matches!(
        add.outputs[0],
        TypeRef::Primitive(PrimitiveType::U64)
    ));

    // hello-add defines no user types.
    assert!(metadata.types.structs.is_empty());
    assert!(metadata.types.unions.is_empty());
    assert!(metadata.types.enums.is_empty());
    assert!(metadata.types.errors.is_empty());
    assert!(metadata.types.events.is_empty());
}

#[test]
fn hello_add_contract_meta_records_sdk_and_compiler_versions() {
    let soroban_facts = parse(HELLO_ADD_WASM)
        .expect("hello_add.wasm should parse")
        .soroban_facts;
    let metadata = soroban_facts.expect("hello_add is a Soroban contract");

    assert!(
        metadata.contract_meta.contains_key("rsver"),
        "contract_meta missing `rsver` (rustc version) entry: {:?}",
        metadata.contract_meta.keys().collect::<Vec<_>>()
    );
    assert!(
        metadata.contract_meta.contains_key("rssdkver"),
        "contract_meta missing `rssdkver` (Soroban SDK version) entry"
    );

    // env_meta.protocol must be populated for SDK-built contracts.
    assert!(metadata.env_meta.protocol.is_some());
}

// ---------------------------------------------------------------------
// counter fixture (4 tests)
// ---------------------------------------------------------------------

#[test]
fn counter_has_multiple_imports_and_exports() {
    let facts = parse(COUNTER_WASM)
        .expect("counter.wasm should parse")
        .wasm_facts;

    assert!(
        facts.imports.len() >= 4,
        "counter should import several host functions; got {}",
        facts.imports.len()
    );
    assert!(
        facts.exports.len() >= 4,
        "counter should export at least add, increment, get_count, get_admin, ...; got {}",
        facts.exports.len()
    );
}

#[test]
fn counter_metadata_lists_all_four_contract_functions() {
    let soroban_facts = parse(COUNTER_WASM)
        .expect("counter.wasm should parse")
        .soroban_facts;
    let metadata = soroban_facts.expect("counter is a Soroban contract");

    for fname in [
        "__constructor",
        "increment",
        "get_count",
        "get_admin",
    ] {
        assert!(
            metadata.functions.contains_key(fname),
            "counter metadata missing function `{fname}`; have: {:?}",
            metadata.functions.keys().collect::<Vec<_>>()
        );
    }
}

#[test]
fn counter_data_key_union_is_typed_with_address_payload() {
    let soroban_facts = parse(COUNTER_WASM)
        .expect("counter.wasm should parse")
        .soroban_facts;
    let metadata = soroban_facts.expect("counter is a Soroban contract");

    let data_key = metadata
        .types
        .unions
        .iter()
        .find(|u| u.name == "DataKey")
        .expect("counter defines a `DataKey` union");
    assert_eq!(data_key.cases.len(), 2, "DataKey has Counter + Admin variants");

    let counter_case = data_key
        .cases
        .iter()
        .find(|c| c.name == "Counter")
        .expect("DataKey::Counter variant missing");
    assert_eq!(counter_case.fields.len(), 1, "Counter wraps one Address");
    assert!(
        matches!(
            counter_case.fields[0],
            TypeRef::Primitive(PrimitiveType::Address)
        ),
        "Counter payload should be Address; got {:?}",
        counter_case.fields[0]
    );

    let admin_case = data_key
        .cases
        .iter()
        .find(|c| c.name == "Admin")
        .expect("DataKey::Admin variant missing");
    assert!(admin_case.fields.is_empty(), "Admin is a void variant");
}

#[test]
fn counter_env_meta_records_protocol() {
    let soroban_facts = parse(COUNTER_WASM)
        .expect("counter.wasm should parse")
        .soroban_facts;
    let metadata = soroban_facts.expect("counter is a Soroban contract");
    assert!(
        metadata.env_meta.protocol.is_some(),
        "counter env_meta protocol must be populated"
    );
}

// ---------------------------------------------------------------------
// Error-path tests (3 tests)
// ---------------------------------------------------------------------

#[test]
fn empty_input_is_typed_error_not_silent_success() {
    assert!(matches!(parse(&[]), Err(FrontendError::Empty)));
}

#[test]
fn garbage_bytes_surface_invalid_wasm() {
    let garbage: &[u8] = b"this is definitely not WASM";
    let err = parse(garbage).unwrap_err();
    assert!(
        matches!(err, FrontendError::InvalidWasm(_)),
        "expected InvalidWasm; got {err:?}"
    );
}

#[test]
fn malformed_contractspec_surfaces_typed_error() {
    // Build a minimal valid WASM module: magic + version, plus a single
    // custom section named "contractspecv0" containing intentionally
    // unparseable bytes. We assemble the bytes by hand so we can be sure
    // the WASM itself is valid (so wasmparser doesn't reject it before
    // our spec decoder gets a chance).
    //
    // WASM module layout:
    //   magic      : "\0asm"   = 0x00 0x61 0x73 0x6d
    //   version    : 1         = 0x01 0x00 0x00 0x00
    //   custom sec : id=0, name="contractspecv0", body=8 bytes of garbage
    //
    // Custom section format: [id=0u8] [section_size:LEB128]
    //                        [name_len:LEB128] [name_bytes] [payload_bytes]
    let mut wasm = Vec::<u8>::new();
    wasm.extend_from_slice(&[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);

    // Build the custom section payload: name length + name + 8 garbage bytes.
    let name = b"contractspecv0";
    let mut payload = Vec::<u8>::new();
    payload.push(name.len() as u8); // LEB128 for short lengths is just the byte
    payload.extend_from_slice(name);
    payload.extend_from_slice(&[0xFF; 8]); // intentional garbage

    // Section header: id=0 (custom), section_size = payload.len()
    wasm.push(0x00);
    wasm.push(payload.len() as u8); // again LEB128 short form
    wasm.extend_from_slice(&payload);

    let err = parse(&wasm).unwrap_err();
    assert!(
        matches!(err, FrontendError::MalformedSpec(_)),
        "expected MalformedSpec; got {err:?}"
    );
}
