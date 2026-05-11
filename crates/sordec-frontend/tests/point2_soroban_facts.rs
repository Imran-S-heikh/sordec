//! Point 2 deliverable tests: decode Soroban metadata into `SorobanFacts`
//! plus `MetadataDiagnostics`.

use std::str::FromStr;

use sordec_frontend::{
    CompositeType, DiagnosticCode, EventParamLocation, FrontendError, MetadataDiagnosticCode,
    PrimitiveType, Severity, TypeRef, parse,
};
use stellar_xdr::curr::{
    Limits, ScEnvMetaEntry, ScEnvMetaEntryInterfaceVersion, ScMetaEntry, ScMetaV0, ScSpecEntry,
    ScSpecEventDataFormat, ScSpecEventParamLocationV0, ScSpecEventParamV0, ScSpecEventV0,
    ScSpecFunctionInputV0, ScSpecFunctionV0, ScSpecTypeBytesN, ScSpecTypeDef, ScSpecTypeMap,
    ScSpecTypeOption, ScSpecTypeResult, ScSpecTypeTuple, ScSpecTypeUdt, ScSpecTypeVec,
    ScSpecUdtEnumCaseV0, ScSpecUdtEnumV0, ScSpecUdtErrorEnumCaseV0, ScSpecUdtErrorEnumV0,
    ScSpecUdtStructFieldV0, ScSpecUdtStructV0, ScSpecUdtUnionCaseTupleV0, ScSpecUdtUnionCaseV0,
    ScSpecUdtUnionCaseVoidV0, ScSpecUdtUnionV0, ScSymbol, StringM, VecM, WriteXdr,
};

const EMPTY_WASM_MODULE: &[u8] = b"\0asm\x01\0\0\0";

const HELLO_ADD_WASM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../samples/contracts/hello-add/hello-add.wasm"
));
const TOKEN_V22_WASM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../samples/contracts/token-v22/token-v22.wasm"
));
const TOKEN_V23_WASM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../samples/contracts/token-v23/token-v23.wasm"
));
const TOKEN_V23_STRIPPED_WASM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../samples/contracts/token-v23-stripped/token-v23-stripped.wasm"
));
const TIMELOCK_WASM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../samples/contracts/timelock/timelock.wasm"
));
const DEX_LIQUIDITY_POOL_WASM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../samples/contracts/dex-liquidity-pool/dex-liquidity-pool.wasm"
));

fn leb_u32(mut value: u32) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
    out
}

fn wasm_name(name: &str) -> Vec<u8> {
    let mut out = leb_u32(name.len() as u32);
    out.extend_from_slice(name.as_bytes());
    out
}

fn custom_section(name: &str, bytes: &[u8]) -> Vec<u8> {
    let mut payload = wasm_name(name);
    payload.extend_from_slice(bytes);

    let mut out = vec![0x00];
    out.extend(leb_u32(payload.len() as u32));
    out.extend(payload);
    out
}

fn wasm_with_custom_sections(sections: Vec<(&str, Vec<u8>)>) -> Vec<u8> {
    let mut wasm = EMPTY_WASM_MODULE.to_vec();
    for (name, bytes) in sections {
        wasm.extend(custom_section(name, &bytes));
    }
    wasm
}

fn string_m<const N: u32>(s: &str) -> StringM<N> {
    StringM::<N>::from_str(s).expect("synthetic string fits bounded XDR string")
}

fn symbol(s: &str) -> ScSymbol {
    ScSymbol(string_m(s))
}

fn vecm<T, const MAX: u32>(items: Vec<T>) -> VecM<T, MAX> {
    VecM::<T, MAX>::try_from(items).expect("synthetic vector fits VecM bound")
}

fn spec_bytes(entries: Vec<ScSpecEntry>) -> Vec<u8> {
    let mut out = Vec::new();
    for entry in entries {
        out.extend(entry.to_xdr(Limits::none()).expect("spec entry serializes"));
    }
    out
}

fn meta_bytes(entries: Vec<ScMetaEntry>) -> Vec<u8> {
    let mut out = Vec::new();
    for entry in entries {
        out.extend(entry.to_xdr(Limits::none()).expect("meta entry serializes"));
    }
    out
}

fn env_meta_bytes(entries: Vec<ScEnvMetaEntry>) -> Vec<u8> {
    let mut out = Vec::new();
    for entry in entries {
        out.extend(
            entry
                .to_xdr(Limits::none())
                .expect("env meta entry serializes"),
        );
    }
    out
}

fn input(name: &str, type_: ScSpecTypeDef) -> ScSpecFunctionInputV0 {
    ScSpecFunctionInputV0 {
        doc: string_m(""),
        name: string_m(name),
        type_,
    }
}

fn function(
    name: &str,
    inputs: Vec<ScSpecFunctionInputV0>,
    outputs: Vec<ScSpecTypeDef>,
) -> ScSpecEntry {
    ScSpecEntry::FunctionV0(ScSpecFunctionV0 {
        doc: string_m(""),
        name: symbol(name),
        inputs: vecm(inputs),
        outputs: vecm(outputs),
    })
}

fn struct_entry(name: &str, fields: Vec<ScSpecUdtStructFieldV0>) -> ScSpecEntry {
    ScSpecEntry::UdtStructV0(ScSpecUdtStructV0 {
        doc: string_m(""),
        lib: string_m("test"),
        name: string_m(name),
        fields: vecm(fields),
    })
}

fn struct_field(name: &str, type_: ScSpecTypeDef) -> ScSpecUdtStructFieldV0 {
    ScSpecUdtStructFieldV0 {
        doc: string_m(""),
        name: string_m(name),
        type_,
    }
}

fn union_entry(name: &str, cases: Vec<ScSpecUdtUnionCaseV0>) -> ScSpecEntry {
    ScSpecEntry::UdtUnionV0(ScSpecUdtUnionV0 {
        doc: string_m(""),
        lib: string_m("test"),
        name: string_m(name),
        cases: vecm(cases),
    })
}

fn union_void(name: &str) -> ScSpecUdtUnionCaseV0 {
    ScSpecUdtUnionCaseV0::VoidV0(ScSpecUdtUnionCaseVoidV0 {
        doc: string_m(""),
        name: string_m(name),
    })
}

fn union_tuple(name: &str, fields: Vec<ScSpecTypeDef>) -> ScSpecUdtUnionCaseV0 {
    ScSpecUdtUnionCaseV0::TupleV0(ScSpecUdtUnionCaseTupleV0 {
        doc: string_m(""),
        name: string_m(name),
        type_: vecm(fields),
    })
}

fn enum_entry(name: &str, cases: Vec<(&str, u32)>) -> ScSpecEntry {
    ScSpecEntry::UdtEnumV0(ScSpecUdtEnumV0 {
        doc: string_m(""),
        lib: string_m("test"),
        name: string_m(name),
        cases: vecm(
            cases
                .into_iter()
                .map(|(name, value)| ScSpecUdtEnumCaseV0 {
                    doc: string_m(""),
                    name: string_m(name),
                    value,
                })
                .collect(),
        ),
    })
}

fn error_enum_entry(name: &str, cases: Vec<(&str, u32)>) -> ScSpecEntry {
    ScSpecEntry::UdtErrorEnumV0(ScSpecUdtErrorEnumV0 {
        doc: string_m(""),
        lib: string_m("test"),
        name: string_m(name),
        cases: vecm(
            cases
                .into_iter()
                .map(|(name, value)| ScSpecUdtErrorEnumCaseV0 {
                    doc: string_m(""),
                    name: string_m(name),
                    value,
                })
                .collect(),
        ),
    })
}

fn event_entry(name: &str) -> ScSpecEntry {
    ScSpecEntry::EventV0(ScSpecEventV0 {
        doc: string_m(""),
        lib: string_m("test"),
        name: symbol(name),
        prefix_topics: vecm(vec![symbol("topic")]),
        params: vecm(vec![
            ScSpecEventParamV0 {
                doc: string_m(""),
                name: string_m("who"),
                type_: ScSpecTypeDef::Address,
                location: ScSpecEventParamLocationV0::TopicList,
            },
            ScSpecEventParamV0 {
                doc: string_m(""),
                name: string_m("amount"),
                type_: ScSpecTypeDef::I128,
                location: ScSpecEventParamLocationV0::Data,
            },
        ]),
        data_format: ScSpecEventDataFormat::Map,
    })
}

fn udt(name: &str) -> ScSpecTypeDef {
    ScSpecTypeDef::Udt(ScSpecTypeUdt {
        name: string_m(name),
    })
}

fn option(inner: ScSpecTypeDef) -> ScSpecTypeDef {
    ScSpecTypeDef::Option(Box::new(ScSpecTypeOption {
        value_type: Box::new(inner),
    }))
}

fn result(ok: ScSpecTypeDef, err: ScSpecTypeDef) -> ScSpecTypeDef {
    ScSpecTypeDef::Result(Box::new(ScSpecTypeResult {
        ok_type: Box::new(ok),
        error_type: Box::new(err),
    }))
}

fn vec_type(inner: ScSpecTypeDef) -> ScSpecTypeDef {
    ScSpecTypeDef::Vec(Box::new(ScSpecTypeVec {
        element_type: Box::new(inner),
    }))
}

fn map_type(key: ScSpecTypeDef, value: ScSpecTypeDef) -> ScSpecTypeDef {
    ScSpecTypeDef::Map(Box::new(ScSpecTypeMap {
        key_type: Box::new(key),
        value_type: Box::new(value),
    }))
}

fn tuple_type(values: Vec<ScSpecTypeDef>) -> ScSpecTypeDef {
    ScSpecTypeDef::Tuple(Box::new(ScSpecTypeTuple {
        value_types: vecm(values),
    }))
}

fn bytes_n(n: u32) -> ScSpecTypeDef {
    ScSpecTypeDef::BytesN(ScSpecTypeBytesN { n })
}

fn meta_entry(key: &str, val: &str) -> ScMetaEntry {
    ScMetaEntry::ScMetaV0(ScMetaV0 {
        key: string_m(key),
        val: string_m(val),
    })
}

fn synthetic_contract_wasm(entries: Vec<ScSpecEntry>) -> Vec<u8> {
    wasm_with_custom_sections(vec![("contractspecv0", spec_bytes(entries))])
}

#[test]
fn no_contractspec_means_no_soroban_facts_and_no_metadata_diagnostics() {
    let output = parse(EMPTY_WASM_MODULE).expect("minimal generic wasm parses");

    assert!(output.soroban_facts.is_none());
    assert!(output.diagnostics.is_empty());
}

#[test]
fn decodes_all_spec_entry_families_into_soroban_facts() {
    let wasm = synthetic_contract_wasm(vec![
        struct_entry(
            "Config",
            vec![
                struct_field("admin", ScSpecTypeDef::Address),
                struct_field("limit", ScSpecTypeDef::U64),
            ],
        ),
        union_entry(
            "Key",
            vec![
                union_void("Admin"),
                union_tuple("Balance", vec![ScSpecTypeDef::Address, ScSpecTypeDef::I128]),
            ],
        ),
        enum_entry("Mode", vec![("Fast", 1), ("Safe", 2)]),
        error_enum_entry("ContractError", vec![("Denied", 7), ("Missing", 8)]),
        event_entry("transfer"),
        function(
            "configure",
            vec![
                input("cfg", udt("Config")),
                input("key", udt("Key")),
                input("mode", udt("Mode")),
            ],
            vec![udt("ContractError")],
        ),
    ]);

    let output = parse(&wasm).expect("synthetic contract metadata parses");
    let facts = output.soroban_facts.expect("contractspecv0 yields facts");

    assert!(output.diagnostics.is_empty());
    assert!(facts.functions.contains_key("configure"));
    assert_eq!(facts.types.structs.len(), 1);
    assert_eq!(facts.types.unions.len(), 1);
    assert_eq!(facts.types.enums.len(), 1);
    assert_eq!(facts.types.errors.len(), 1);
    assert_eq!(facts.types.events.len(), 1);

    let config = &facts.types.structs[0];
    assert_eq!(config.name, "Config");
    assert_eq!(config.fields.len(), 2);
    assert!(matches!(
        &config.fields[0].ty,
        TypeRef::Primitive(PrimitiveType::Address)
    ));
    assert!(matches!(
        &config.fields[1].ty,
        TypeRef::Primitive(PrimitiveType::U64)
    ));

    let key = &facts.types.unions[0];
    assert_eq!(key.cases.len(), 2);
    assert!(
        key.cases
            .iter()
            .any(|case| case.name == "Admin" && case.fields.is_empty())
    );
    assert!(
        key.cases
            .iter()
            .any(|case| case.name == "Balance" && case.fields.len() == 2)
    );

    let event = &facts.types.events[0];
    assert_eq!(event.name, "transfer");
    assert_eq!(event.prefix_topics, vec!["topic"]);
    assert_eq!(event.params.len(), 2);
    assert_eq!(event.params[0].location, EventParamLocation::Topic);
    assert_eq!(event.params[1].location, EventParamLocation::Data);
}

#[test]
fn decodes_all_primitive_type_variants_in_function_signatures() {
    let primitive_cases = vec![
        ("val", ScSpecTypeDef::Val, PrimitiveType::Val),
        ("bool", ScSpecTypeDef::Bool, PrimitiveType::Bool),
        ("void", ScSpecTypeDef::Void, PrimitiveType::Void),
        ("error", ScSpecTypeDef::Error, PrimitiveType::Error),
        ("u32", ScSpecTypeDef::U32, PrimitiveType::U32),
        ("i32", ScSpecTypeDef::I32, PrimitiveType::I32),
        ("u64", ScSpecTypeDef::U64, PrimitiveType::U64),
        ("i64", ScSpecTypeDef::I64, PrimitiveType::I64),
        (
            "timepoint",
            ScSpecTypeDef::Timepoint,
            PrimitiveType::Timepoint,
        ),
        ("duration", ScSpecTypeDef::Duration, PrimitiveType::Duration),
        ("u128", ScSpecTypeDef::U128, PrimitiveType::U128),
        ("i128", ScSpecTypeDef::I128, PrimitiveType::I128),
        ("u256", ScSpecTypeDef::U256, PrimitiveType::U256),
        ("i256", ScSpecTypeDef::I256, PrimitiveType::I256),
        ("bytes", ScSpecTypeDef::Bytes, PrimitiveType::Bytes),
        ("string", ScSpecTypeDef::String, PrimitiveType::String),
        ("symbol", ScSpecTypeDef::Symbol, PrimitiveType::Symbol),
        ("address", ScSpecTypeDef::Address, PrimitiveType::Address),
        (
            "muxed",
            ScSpecTypeDef::MuxedAddress,
            PrimitiveType::MuxedAddress,
        ),
    ];

    let wasm = synthetic_contract_wasm(
        primitive_cases
            .iter()
            .enumerate()
            .map(|(idx, (_, ty, _))| {
                function(
                    &format!("f{idx}"),
                    vec![input("value", ty.clone())],
                    vec![ty.clone()],
                )
            })
            .collect(),
    );

    let facts = parse(&wasm)
        .expect("primitive matrix metadata parses")
        .soroban_facts
        .expect("contractspecv0 yields facts");

    for (idx, (_, _, expected)) in primitive_cases.iter().enumerate() {
        let signature = facts
            .functions
            .get(&format!("f{idx}"))
            .expect("function exists");
        assert!(
            matches!(&signature.inputs[0].ty, TypeRef::Primitive(actual) if actual == expected)
        );
        assert!(matches!(&signature.outputs[0], TypeRef::Primitive(actual) if actual == expected));
    }
}

#[test]
fn decodes_composite_types_and_udt_references() {
    let wasm = synthetic_contract_wasm(vec![
        struct_entry("Config", vec![struct_field("enabled", ScSpecTypeDef::Bool)]),
        function(
            "complex",
            vec![
                input("maybe", option(ScSpecTypeDef::U32)),
                input("result", result(ScSpecTypeDef::U64, ScSpecTypeDef::Error)),
                input("vec", vec_type(ScSpecTypeDef::Address)),
                input("map", map_type(ScSpecTypeDef::Symbol, ScSpecTypeDef::I128)),
                input(
                    "tuple",
                    tuple_type(vec![ScSpecTypeDef::Bool, ScSpecTypeDef::U32]),
                ),
                input("bytesn", bytes_n(32)),
                input("config", udt("Config")),
            ],
            vec![udt("Config")],
        ),
    ]);

    let facts = parse(&wasm)
        .expect("composite metadata parses")
        .soroban_facts
        .expect("contractspecv0 yields facts");
    let signature = facts
        .functions
        .get("complex")
        .expect("complex function exists");

    assert!(matches!(
        &signature.inputs[0].ty,
        TypeRef::Composite(CompositeType::Option(_))
    ));
    assert!(matches!(
        &signature.inputs[1].ty,
        TypeRef::Composite(CompositeType::Result(_, _))
    ));
    assert!(matches!(
        &signature.inputs[2].ty,
        TypeRef::Composite(CompositeType::Vec(_))
    ));
    assert!(matches!(
        &signature.inputs[3].ty,
        TypeRef::Composite(CompositeType::Map(_, _))
    ));
    assert!(matches!(
        &signature.inputs[4].ty,
        TypeRef::Composite(CompositeType::Tuple(_))
    ));
    assert!(matches!(
        &signature.inputs[5].ty,
        TypeRef::Composite(CompositeType::BytesN(32))
    ));
    assert!(matches!(&signature.inputs[6].ty, TypeRef::UserDefined(_)));
    assert!(matches!(&signature.outputs[0], TypeRef::UserDefined(_)));
}

#[test]
fn duplicate_names_emit_metadata_diagnostics_and_keep_first_declaration() {
    let wasm = synthetic_contract_wasm(vec![
        struct_entry("Config", vec![struct_field("first", ScSpecTypeDef::U32)]),
        struct_entry("Config", vec![struct_field("second", ScSpecTypeDef::I32)]),
        function(
            "same",
            vec![input("a", ScSpecTypeDef::U32)],
            vec![ScSpecTypeDef::U32],
        ),
        function(
            "same",
            vec![input("b", ScSpecTypeDef::I32)],
            vec![ScSpecTypeDef::I32],
        ),
    ]);

    let output = parse(&wasm).expect("duplicate metadata parses with warnings");
    let facts = output.soroban_facts.expect("contractspecv0 yields facts");

    assert_eq!(facts.types.structs.len(), 1);
    assert_eq!(facts.types.structs[0].fields[0].name, "first");
    assert_eq!(facts.functions.len(), 1);
    assert_eq!(facts.functions["same"].inputs[0].name, "a");

    assert_eq!(output.diagnostics.len(), 2);
    assert!(
        output
            .diagnostics
            .iter()
            .all(|diag| diag.severity == Severity::Warning)
    );
    assert!(output.diagnostics.iter().any(|diag| matches!(
        &diag.code,
        DiagnosticCode::Metadata(MetadataDiagnosticCode::DuplicateTypeName { name }) if name == "Config"
    )));
    assert!(output.diagnostics.iter().any(|diag| matches!(
        &diag.code,
        DiagnosticCode::Metadata(MetadataDiagnosticCode::DuplicateFunctionName { name }) if name == "same"
    )));
}

#[test]
fn unresolved_udt_reference_emits_warning_and_uses_unknown_placeholder() {
    let wasm = synthetic_contract_wasm(vec![function(
        "broken",
        vec![input("missing", udt("MissingType"))],
        vec![ScSpecTypeDef::Void],
    )]);

    let output = parse(&wasm).expect("unresolved UDT recovers with diagnostic");
    let facts = output.soroban_facts.expect("contractspecv0 yields facts");
    let signature = facts.functions.get("broken").expect("function exists");

    assert!(matches!(&signature.inputs[0].ty, TypeRef::Unknown(_)));
    assert_eq!(output.diagnostics.len(), 1);
    assert!(matches!(
        &output.diagnostics[0].code,
        DiagnosticCode::Metadata(MetadataDiagnosticCode::UnresolvedTypeReference { name })
            if name == "MissingType"
    ));
}

#[test]
fn contract_meta_sections_are_concatenated_and_decoded() {
    let wasm = wasm_with_custom_sections(vec![
        (
            "contractspecv0",
            spec_bytes(vec![function("noop", vec![], vec![ScSpecTypeDef::Void])]),
        ),
        (
            "contractmetav0",
            meta_bytes(vec![meta_entry("rssdkver", "25.0.0")]),
        ),
        (
            "contractmetav0",
            meta_bytes(vec![meta_entry("rsver", "1.90.0")]),
        ),
    ]);

    let facts = parse(&wasm)
        .expect("contractmetav0 metadata parses")
        .soroban_facts
        .expect("contractspecv0 yields facts");

    assert_eq!(facts.contract_meta["rssdkver"], "25.0.0");
    assert_eq!(facts.contract_meta["rsver"], "1.90.0");
}

#[test]
fn env_meta_decodes_protocol_and_pre_release() {
    let wasm = wasm_with_custom_sections(vec![
        (
            "contractspecv0",
            spec_bytes(vec![function("noop", vec![], vec![ScSpecTypeDef::Void])]),
        ),
        (
            "contractenvmetav0",
            env_meta_bytes(vec![ScEnvMetaEntry::ScEnvMetaKindInterfaceVersion(
                ScEnvMetaEntryInterfaceVersion {
                    protocol: 26,
                    pre_release: 3,
                },
            )]),
        ),
    ]);

    let facts = parse(&wasm)
        .expect("contractenvmetav0 metadata parses")
        .soroban_facts
        .expect("contractspecv0 yields facts");

    assert_eq!(facts.env_meta.protocol.as_deref(), Some("26"));
    assert_eq!(facts.env_meta.pre_release.as_deref(), Some("3"));
}

#[test]
fn malformed_metadata_sections_surface_expected_error_or_warning() {
    let malformed_spec = wasm_with_custom_sections(vec![("contractspecv0", vec![0xff; 8])]);
    assert!(matches!(
        parse(&malformed_spec),
        Err(FrontendError::MalformedSpec(_))
    ));

    let malformed_env = wasm_with_custom_sections(vec![
        (
            "contractspecv0",
            spec_bytes(vec![function("noop", vec![], vec![ScSpecTypeDef::Void])]),
        ),
        ("contractenvmetav0", vec![0xff; 8]),
    ]);
    assert!(matches!(
        parse(&malformed_env),
        Err(FrontendError::MalformedEnvMeta(_))
    ));

    let malformed_meta = wasm_with_custom_sections(vec![
        (
            "contractspecv0",
            spec_bytes(vec![function("noop", vec![], vec![ScSpecTypeDef::Void])]),
        ),
        ("contractmetav0", vec![0xff; 8]),
    ]);
    let output = parse(&malformed_meta).expect("malformed contract meta degrades with warning");
    assert_eq!(output.diagnostics.len(), 1);
    assert!(matches!(
        &output.diagnostics[0].code,
        DiagnosticCode::Metadata(MetadataDiagnosticCode::MalformedContractMeta { .. })
    ));
    assert!(
        output
            .soroban_facts
            .expect("facts still produced")
            .contract_meta
            .is_empty()
    );
}

#[test]
fn deterministic_synthetic_metadata_matrix_decodes_thousands_of_function_specs() {
    let primitive_types = [
        ScSpecTypeDef::Bool,
        ScSpecTypeDef::U32,
        ScSpecTypeDef::I32,
        ScSpecTypeDef::U64,
        ScSpecTypeDef::I64,
        ScSpecTypeDef::U128,
        ScSpecTypeDef::I128,
        ScSpecTypeDef::Bytes,
        ScSpecTypeDef::String,
        ScSpecTypeDef::Symbol,
        ScSpecTypeDef::Address,
    ];

    for case in 0..4096_usize {
        let input_count = 1 + case % 8;
        let entries = vec![function(
            "matrix",
            (0..input_count)
                .map(|idx| {
                    input(
                        &format!("p{idx}"),
                        primitive_types[(case + idx) % primitive_types.len()].clone(),
                    )
                })
                .collect(),
            vec![primitive_types[(case * 3) % primitive_types.len()].clone()],
        )];
        let output = parse(&synthetic_contract_wasm(entries))
            .unwrap_or_else(|err| panic!("metadata matrix case {case} failed: {err:?}"));
        let facts = output.soroban_facts.expect("contractspecv0 yields facts");
        let signature = facts
            .functions
            .get("matrix")
            .expect("matrix function exists");

        assert_eq!(signature.inputs.len(), input_count, "case {case}");
        assert_eq!(signature.outputs.len(), 1, "case {case}");
        assert!(output.diagnostics.is_empty(), "case {case}");
    }
}

#[test]
fn committed_corpus_metadata_decodes_or_is_absent_when_stripped() {
    let fixtures = [
        ("hello-add", HELLO_ADD_WASM, true),
        ("token-v22", TOKEN_V22_WASM, true),
        ("token-v23", TOKEN_V23_WASM, true),
        ("token-v23-stripped", TOKEN_V23_STRIPPED_WASM, false),
        ("timelock", TIMELOCK_WASM, true),
        ("dex-liquidity-pool", DEX_LIQUIDITY_POOL_WASM, true),
    ];

    for (name, wasm, expects_metadata) in fixtures {
        let output = parse(wasm).unwrap_or_else(|err| panic!("{name} failed to parse: {err:?}"));
        assert!(
            output.diagnostics.is_empty(),
            "{name} emitted metadata diagnostics: {:?}",
            output.diagnostics
        );
        assert_eq!(
            output.soroban_facts.is_some(),
            expects_metadata,
            "{name} metadata presence mismatch"
        );
    }
}
