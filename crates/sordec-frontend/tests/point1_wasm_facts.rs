//! Point 1 deliverable tests: parse WASM into `WasmFacts` plus diagnostics.
//!
//! These tests synthesize core WASM modules directly in binary form. Keeping
//! the generator local avoids depending on fixture compiler output when the
//! behavior under test is the generic frontend parser.

use sordec_frontend::{ExportKind, FrontendError, ImportKind, parse};

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

#[derive(Debug, Clone)]
struct ExpectedModule {
    imports: usize,
    function_type_indices: Vec<u32>,
    exports: usize,
    custom_sections: Vec<(String, Vec<u8>)>,
}

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

fn section(id: u8, payload: Vec<u8>) -> Vec<u8> {
    let mut out = vec![id];
    out.extend(leb_u32(payload.len() as u32));
    out.extend(payload);
    out
}

fn vec_payload(items: Vec<Vec<u8>>) -> Vec<u8> {
    let mut out = leb_u32(items.len() as u32);
    for item in items {
        out.extend(item);
    }
    out
}

fn module(sections: Vec<Vec<u8>>) -> Vec<u8> {
    let mut out = EMPTY_WASM_MODULE.to_vec();
    for section in sections {
        out.extend(section);
    }
    out
}

fn empty_func_type() -> Vec<u8> {
    vec![0x60, 0x00, 0x00]
}

fn type_section(type_count: usize) -> Vec<u8> {
    section(
        1,
        vec_payload((0..type_count).map(|_| empty_func_type()).collect()),
    )
}

fn import_entry(module: &str, name: &str, desc: Vec<u8>) -> Vec<u8> {
    let mut out = wasm_name(module);
    out.extend(wasm_name(name));
    out.extend(desc);
    out
}

fn import_func(module: &str, name: &str, type_index: u32) -> Vec<u8> {
    let mut desc = vec![0x00];
    desc.extend(leb_u32(type_index));
    import_entry(module, name, desc)
}

fn import_table(module: &str, name: &str) -> Vec<u8> {
    // importdesc table + tabletype(funcref, limits min=1)
    import_entry(module, name, vec![0x01, 0x70, 0x00, 0x01])
}

fn import_memory(module: &str, name: &str) -> Vec<u8> {
    // importdesc memory + memtype(limits min=1)
    import_entry(module, name, vec![0x02, 0x00, 0x01])
}

fn import_global(module: &str, name: &str) -> Vec<u8> {
    // importdesc global + globaltype(i32, immutable)
    import_entry(module, name, vec![0x03, 0x7f, 0x00])
}

fn import_tag(module: &str, name: &str, type_index: u32) -> Vec<u8> {
    // importdesc tag + tagtype(exception attribute=0, function type index)
    let mut desc = vec![0x04, 0x00];
    desc.extend(leb_u32(type_index));
    import_entry(module, name, desc)
}

fn import_section(entries: Vec<Vec<u8>>) -> Vec<u8> {
    section(2, vec_payload(entries))
}

fn function_section(type_indices: &[u32]) -> Vec<u8> {
    let mut out = leb_u32(type_indices.len() as u32);
    for type_index in type_indices {
        out.extend(leb_u32(*type_index));
    }
    section(3, out)
}

fn table_section(count: usize) -> Vec<u8> {
    section(
        4,
        vec_payload((0..count).map(|_| vec![0x70, 0x00, 0x01]).collect()),
    )
}

fn memory_section(count: usize) -> Vec<u8> {
    section(
        5,
        vec_payload((0..count).map(|_| vec![0x00, 0x01]).collect()),
    )
}

fn global_section(count: usize) -> Vec<u8> {
    section(
        6,
        vec_payload(
            (0..count)
                .map(|idx| vec![0x7f, 0x00, 0x41, idx as u8, 0x0b])
                .collect(),
        ),
    )
}

fn export_entry(name: &str, kind: u8, index: u32) -> Vec<u8> {
    let mut out = wasm_name(name);
    out.push(kind);
    out.extend(leb_u32(index));
    out
}

fn export_section(entries: Vec<Vec<u8>>) -> Vec<u8> {
    section(7, vec_payload(entries))
}

fn code_section(function_count: usize) -> Vec<u8> {
    section(
        10,
        vec_payload(
            (0..function_count)
                .map(|_| vec![0x02, 0x00, 0x0b])
                .collect(),
        ),
    )
}

fn custom_section(name: &str, bytes: &[u8]) -> Vec<u8> {
    let mut payload = wasm_name(name);
    payload.extend_from_slice(bytes);
    section(0, payload)
}

#[test]
fn minimal_wasm_module_produces_empty_wasm_facts_and_no_diagnostics() {
    let output = parse(EMPTY_WASM_MODULE).expect("minimal module parses");

    assert!(output.wasm_facts.imports.is_empty());
    assert!(output.wasm_facts.exports.is_empty());
    assert!(output.wasm_facts.function_type_indices.is_empty());
    assert!(output.wasm_facts.custom_sections.is_empty());
    assert!(output.soroban_facts.is_none());
    assert!(output.diagnostics.is_empty());
}

#[test]
fn import_matrix_maps_core_import_kinds_and_indices() {
    let wasm = module(vec![
        type_section(1),
        import_section(vec![
            import_func("env", "call", 0),
            import_table("env", "table"),
            import_memory("env", "memory"),
            import_global("env", "global"),
            import_tag("env", "tag", 0),
        ]),
    ]);

    let facts = parse(&wasm).expect("import matrix parses").wasm_facts;

    assert_eq!(facts.imports.len(), 5);
    assert_eq!(facts.imports[0].index, 0);
    assert_eq!(facts.imports[0].module, "env");
    assert_eq!(facts.imports[0].name, "call");
    assert!(matches!(facts.imports[0].kind, ImportKind::Func(0)));
    assert_eq!(facts.imports[1].index, 1);
    assert!(matches!(facts.imports[1].kind, ImportKind::Table));
    assert_eq!(facts.imports[2].index, 2);
    assert!(matches!(facts.imports[2].kind, ImportKind::Memory));
    assert_eq!(facts.imports[3].index, 3);
    assert!(matches!(facts.imports[3].kind, ImportKind::Global));
    assert_eq!(facts.imports[4].index, 4);
    assert!(matches!(facts.imports[4].kind, ImportKind::Tag));
}

#[test]
fn export_matrix_maps_core_export_kinds_and_indices() {
    let wasm = module(vec![
        type_section(1),
        function_section(&[0]),
        table_section(1),
        memory_section(1),
        global_section(1),
        export_section(vec![
            export_entry("run", 0x00, 0),
            export_entry("table", 0x01, 0),
            export_entry("memory", 0x02, 0),
            export_entry("global", 0x03, 0),
        ]),
        code_section(1),
    ]);

    let facts = parse(&wasm).expect("export matrix parses").wasm_facts;

    assert_eq!(facts.exports.len(), 4);
    assert_eq!(facts.exports[0].name, "run");
    assert_eq!(facts.exports[0].kind, ExportKind::Func);
    assert_eq!(facts.exports[0].index, 0);
    assert_eq!(facts.exports[1].kind, ExportKind::Table);
    assert_eq!(facts.exports[2].kind, ExportKind::Memory);
    assert_eq!(facts.exports[3].kind, ExportKind::Global);
}

#[test]
fn tag_imports_and_exports_are_mapped_when_present() {
    let wasm = module(vec![
        type_section(1),
        import_section(vec![import_tag("env", "tag", 0)]),
        export_section(vec![export_entry("tag", 0x04, 0)]),
    ]);

    let facts = parse(&wasm)
        .expect("imported tag export module parses")
        .wasm_facts;

    assert_eq!(facts.imports.len(), 1);
    assert!(matches!(facts.imports[0].kind, ImportKind::Tag));
    assert_eq!(facts.exports.len(), 1);
    assert_eq!(facts.exports[0].name, "tag");
    assert_eq!(facts.exports[0].kind, ExportKind::Tag);
    assert_eq!(facts.exports[0].index, 0);
}

#[test]
fn local_function_type_indices_preserve_order_and_duplicates() {
    let expected = vec![2, 0, 2, 1, 3, 1, 0];
    let wasm = module(vec![
        type_section(4),
        function_section(&expected),
        code_section(expected.len()),
    ]);

    let facts = parse(&wasm)
        .expect("function index matrix parses")
        .wasm_facts;

    assert_eq!(facts.function_type_indices, expected);
}

#[test]
fn custom_sections_preserve_order_names_bytes_and_monotonic_ranges() {
    let large_payload = vec![0xaa; 193];
    let wasm = module(vec![
        custom_section("prelude", b"alpha"),
        type_section(1),
        custom_section("middle", &large_payload),
        function_section(&[0]),
        code_section(1),
        custom_section("empty-tail", b""),
    ]);

    let facts = parse(&wasm)
        .expect("custom-section module parses")
        .wasm_facts;

    assert_eq!(facts.custom_sections.len(), 3);
    assert_eq!(facts.custom_sections[0].name, "prelude");
    assert_eq!(facts.custom_sections[0].bytes, b"alpha");
    assert_eq!(facts.custom_sections[1].name, "middle");
    assert_eq!(facts.custom_sections[1].bytes, large_payload);
    assert_eq!(facts.custom_sections[2].name, "empty-tail");
    assert!(facts.custom_sections[2].bytes.is_empty());

    let mut previous_end = 0;
    for section in facts.custom_sections {
        assert!(section.byte_range.start < section.byte_range.end);
        assert!(section.byte_range.end <= wasm.len() as u64);
        assert!(section.byte_range.start >= previous_end);
        previous_end = section.byte_range.end;
    }
}

#[test]
fn ignored_core_sections_do_not_pollute_wasm_facts_without_exports() {
    let wasm = module(vec![
        type_section(1),
        table_section(1),
        memory_section(1),
        global_section(2),
    ]);

    let facts = parse(&wasm)
        .expect("module with non-exported core sections parses")
        .wasm_facts;

    assert!(facts.imports.is_empty());
    assert!(facts.exports.is_empty());
    assert!(facts.function_type_indices.is_empty());
    assert!(facts.custom_sections.is_empty());
}

#[test]
fn fatal_parse_error_matrix_surfaces_typed_frontend_errors() {
    let invalid_cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![]),
        ("bad magic", b"not wasm".to_vec()),
        ("truncated custom section", {
            let mut wasm = EMPTY_WASM_MODULE.to_vec();
            wasm.extend([0x00, 0x0a, 0x01, b'x']);
            wasm
        }),
        (
            "duplicate type section",
            module(vec![type_section(1), type_section(1)]),
        ),
        ("invalid utf8 import name", {
            let mut bad_import_payload = Vec::new();
            bad_import_payload.push(1); // one import
            bad_import_payload.extend([1, 0xff]); // malformed module name
            bad_import_payload.extend(wasm_name("thing"));
            bad_import_payload.extend([0x00, 0x00]);
            module(vec![type_section(1), section(2, bad_import_payload)])
        }),
    ];

    for (name, wasm) in invalid_cases {
        let err = match parse(&wasm) {
            Ok(_) => panic!("{name} unexpectedly parsed"),
            Err(err) => err,
        };
        match name {
            "empty" => assert!(matches!(err, FrontendError::Empty)),
            _ => assert!(
                matches!(err, FrontendError::InvalidWasm(_)),
                "{name}: {err:?}"
            ),
        }
    }
}

#[test]
fn deterministic_synthetic_matrix_covers_thousands_of_valid_wasm_shapes() {
    for case in 0..4096_u32 {
        let (wasm, expected) = generated_valid_module(case);
        let output = parse(&wasm).unwrap_or_else(|err| panic!("case {case} failed: {err:?}"));
        let facts = output.wasm_facts;

        assert_eq!(facts.imports.len(), expected.imports, "case {case}");
        for (idx, import) in facts.imports.iter().enumerate() {
            assert_eq!(import.index, idx as u32, "case {case}");
            match import.kind {
                ImportKind::Func(type_index) => {
                    assert!(type_index < 4, "case {case}: bad type index {type_index}");
                }
                ref other => {
                    panic!("case {case}: generated imports should be funcs, got {other:?}")
                }
            }
        }

        assert_eq!(
            facts.function_type_indices, expected.function_type_indices,
            "case {case}"
        );
        assert_eq!(facts.exports.len(), expected.exports, "case {case}");
        assert_eq!(
            facts.custom_sections.len(),
            expected.custom_sections.len(),
            "case {case}"
        );
        for (actual, (expected_name, expected_bytes)) in facts
            .custom_sections
            .iter()
            .zip(expected.custom_sections.iter())
        {
            assert_eq!(&actual.name, expected_name, "case {case}");
            assert_eq!(&actual.bytes, expected_bytes, "case {case}");
            assert!(
                actual.byte_range.start < actual.byte_range.end,
                "case {case}"
            );
            assert!(actual.byte_range.end <= wasm.len() as u64, "case {case}");
        }

        assert!(output.soroban_facts.is_none(), "case {case}");
        assert!(output.diagnostics.is_empty(), "case {case}");
    }
}

#[test]
fn committed_corpus_fixtures_parse_to_wasm_facts_without_parse_diagnostics() {
    let fixtures = [
        ("hello-add", HELLO_ADD_WASM),
        ("token-v22", TOKEN_V22_WASM),
        ("token-v23", TOKEN_V23_WASM),
        ("token-v23-stripped", TOKEN_V23_STRIPPED_WASM),
        ("timelock", TIMELOCK_WASM),
        ("dex-liquidity-pool", DEX_LIQUIDITY_POOL_WASM),
    ];

    for (name, wasm) in fixtures {
        let output = parse(wasm).unwrap_or_else(|err| panic!("{name} failed to parse: {err:?}"));

        assert!(
            !output.wasm_facts.exports.is_empty(),
            "{name} should expose at least one export"
        );
        assert!(
            !output.wasm_facts.function_type_indices.is_empty(),
            "{name} should contain local function type indices"
        );
        assert!(
            output.diagnostics.is_empty(),
            "{name} emitted diagnostics: {:?}",
            output.diagnostics
        );
    }
}

fn generated_valid_module(case: u32) -> (Vec<u8>, ExpectedModule) {
    let type_count = 1 + (case as usize % 4);
    let import_count = ((case / 4) as usize) % 7;
    let local_count = ((case / 28) as usize) % 9;
    let custom_count = ((case / 252) as usize) % 5;
    let include_memory = case & 0b1 != 0;
    let export_memory = include_memory && case & 0b10 != 0;
    let total_funcs = import_count + local_count;
    let func_export_count = if total_funcs == 0 {
        0
    } else {
        ((case / 3) as usize) % (total_funcs + 1)
    };

    let function_type_indices = (0..local_count)
        .map(|idx| ((case as usize + idx * 3) % type_count) as u32)
        .collect::<Vec<_>>();

    let mut sections = Vec::new();
    let mut custom_sections = Vec::new();

    for idx in 0..custom_count.min(2) {
        let payload = generated_payload(case, idx);
        custom_sections.push((format!("point1.pre.{case}.{idx}"), payload.clone()));
        sections.push(custom_section(
            &format!("point1.pre.{case}.{idx}"),
            &payload,
        ));
    }

    sections.push(type_section(type_count));

    if import_count > 0 {
        sections.push(import_section(
            (0..import_count)
                .map(|idx| import_func("host", &format!("f{idx}"), (idx % type_count) as u32))
                .collect(),
        ));
    }

    if local_count > 0 {
        sections.push(function_section(&function_type_indices));
    }
    if include_memory {
        sections.push(memory_section(1));
    }

    let mut exports = Vec::new();
    for idx in 0..func_export_count {
        exports.push(export_entry(&format!("run{idx}"), 0x00, idx as u32));
    }
    if export_memory {
        exports.push(export_entry("memory", 0x02, 0));
    }
    if !exports.is_empty() {
        sections.push(export_section(exports));
    }

    if local_count > 0 {
        sections.push(code_section(local_count));
    }

    for idx in 2..custom_count {
        let payload = generated_payload(case, idx);
        custom_sections.push((format!("point1.post.{case}.{idx}"), payload.clone()));
        sections.push(custom_section(
            &format!("point1.post.{case}.{idx}"),
            &payload,
        ));
    }

    (
        module(sections),
        ExpectedModule {
            imports: import_count,
            function_type_indices,
            exports: func_export_count + usize::from(export_memory),
            custom_sections,
        },
    )
}

fn generated_payload(case: u32, slot: usize) -> Vec<u8> {
    let len = ((case as usize * 17 + slot * 31) % 211) + slot;
    (0..len)
        .map(|idx| ((case as usize + slot * 13 + idx * 7) & 0xff) as u8)
        .collect()
}
