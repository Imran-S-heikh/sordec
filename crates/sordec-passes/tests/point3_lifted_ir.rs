//! Point 3 deliverable tests: lift WASM to waffle-backed CFG/SSA `LiftedIr`
//! plus `LiftDiagnostics`.
//!
//! The synthetic inputs are raw WASM binaries built in-memory. This keeps
//! Point 3 focused on the frontend-to-lifter boundary instead of depending
//! on a Rust/Soroban compiler to generate fixtures.

use sordec_common::IrId;
use sordec_ir::{LiftedIr, LiftedTerminator, LiftedType, LiftedValueDef, WasmFacts, WasmOpcodeKind};
use sordec_passes::{lift_with_waffle, LiftError, LiftOutput};
use waffle::entity::EntityRef as _;

mod common;
use common::assert_invariants_hold;

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

const I32: u8 = 0x7f;
const I64: u8 = 0x7e;
const F32: u8 = 0x7d;
const F64: u8 = 0x7c;

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

fn func_type(params: &[u8], results: &[u8]) -> Vec<u8> {
    let mut out = vec![0x60];
    out.extend(leb_u32(params.len() as u32));
    out.extend_from_slice(params);
    out.extend(leb_u32(results.len() as u32));
    out.extend_from_slice(results);
    out
}

fn type_section(types: Vec<Vec<u8>>) -> Vec<u8> {
    section(1, vec_payload(types))
}

fn import_func(module_name: &str, name: &str, type_index: u32) -> Vec<u8> {
    let mut out = wasm_name(module_name);
    out.extend(wasm_name(name));
    out.push(0x00);
    out.extend(leb_u32(type_index));
    out
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

fn table_section() -> Vec<u8> {
    section(4, vec_payload(vec![vec![0x70, 0x00, 0x01]]))
}

fn memory_section() -> Vec<u8> {
    section(5, vec_payload(vec![vec![0x00, 0x01]]))
}

fn global_section() -> Vec<u8> {
    // One mutable i32 global initialised to zero.
    section(6, vec_payload(vec![vec![I32, 0x01, 0x41, 0x00, 0x0b]]))
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

fn func_body(local_groups: Vec<Vec<u8>>, expr_without_end: Vec<u8>) -> Vec<u8> {
    let mut body = leb_u32(local_groups.len() as u32);
    for group in local_groups {
        body.extend(group);
    }
    body.extend(expr_without_end);
    body.push(0x0b);

    let mut out = leb_u32(body.len() as u32);
    out.extend(body);
    out
}

fn code_section(bodies: Vec<Vec<u8>>) -> Vec<u8> {
    section(10, vec_payload(bodies))
}

fn i32_const(value: u8) -> Vec<u8> {
    assert!(value < 0x40, "test helper only emits small positive SLEB values");
    vec![0x41, value]
}

fn i64_const(value: u8) -> Vec<u8> {
    assert!(value < 0x40, "test helper only emits small positive SLEB values");
    vec![0x42, value]
}

fn f32_const(value: f32) -> Vec<u8> {
    let mut out = vec![0x43];
    out.extend(value.to_le_bytes());
    out
}

fn f64_const(value: f64) -> Vec<u8> {
    let mut out = vec![0x44];
    out.extend(value.to_le_bytes());
    out
}

fn local_get(index: u32) -> Vec<u8> {
    let mut out = vec![0x20];
    out.extend(leb_u32(index));
    out
}

fn parse_and_lift(wasm: &[u8]) -> LiftOutput {
    let parsed = sordec_frontend::parse(wasm).expect("synthetic module parses");
    let output = lift_with_waffle(wasm, &parsed.wasm_facts, parsed.soroban_facts.as_ref())
        .expect("waffle lifts synthetic module");
    assert!(
        output.diagnostics.is_empty(),
        "LiftDiagnostics is expected to be empty in v0"
    );
    assert_eq!(
        output.lifted.functions.len(),
        parsed.wasm_facts.function_type_indices.len(),
        "one lifted function is produced per local WASM body"
    );
    assert_invariants_hold(&output.lifted);
    output
}

fn empty_facts() -> WasmFacts {
    WasmFacts {
        imports: Vec::new(),
        exports: Vec::new(),
        function_type_indices: Vec::new(),
        custom_sections: Vec::new(),
    }
}

fn has_opcode_kind(lifted: &LiftedIr, kind: WasmOpcodeKind) -> bool {
    lifted.functions.iter().any(|func| {
        func.values.iter().any(|(_value_id, value)| {
            matches!(&value.def, LiftedValueDef::Operator { op, .. } if op.kind() == kind)
        })
    })
}

fn has_value_def(lifted: &LiftedIr, predicate: impl Fn(&LiftedValueDef) -> bool) -> bool {
    lifted.functions.iter().any(|func| {
        func.values
            .iter()
            .any(|(_value_id, value)| predicate(&value.def))
    })
}

fn has_terminator(lifted: &LiftedIr, predicate: impl Fn(&LiftedTerminator) -> bool) -> bool {
    lifted.functions.iter().any(|func| {
        func.blocks
            .iter()
            .any(|(_block_id, block)| predicate(&block.terminator))
    })
}

fn linear_operator_matrix_wasm() -> Vec<u8> {
    module(vec![
        type_section(vec![
            func_type(&[], &[I32]),
            func_type(&[], &[I64]),
            func_type(&[], &[F32]),
            func_type(&[], &[F64]),
            func_type(&[], &[]),
            func_type(&[I32, I32], &[I32]),
        ]),
        function_section(&[0, 1, 2, 3, 4, 0, 5, 0, 4, 0, 0, 0, 0, 0, 0, 4]),
        memory_section(),
        global_section(),
        code_section(vec![
            func_body(Vec::new(), i32_const(7)),
            func_body(Vec::new(), i64_const(7)),
            func_body(Vec::new(), f32_const(1.5)),
            func_body(Vec::new(), f64_const(2.5)),
            func_body(Vec::new(), [i32_const(0), i32_const(1), vec![0x36, 0x02, 0x00]].concat()),
            func_body(Vec::new(), [i32_const(0), vec![0x28, 0x02, 0x00]].concat()),
            func_body(
                Vec::new(),
                [local_get(0), local_get(1), vec![0x6a]].concat(),
            ),
            func_body(Vec::new(), vec![0x23, 0x00]),
            func_body(Vec::new(), [i32_const(1), vec![0x24, 0x00]].concat()),
            func_body(Vec::new(), vec![0x3f, 0x00]),
            func_body(
                Vec::new(),
                [i32_const(1), i32_const(2), i32_const(0), vec![0x1b]].concat(),
            ),
            func_body(Vec::new(), [i32_const(1), i32_const(2), vec![0x46]].concat()),
            func_body(Vec::new(), [i32_const(1), vec![0x67]].concat()),
            func_body(Vec::new(), [i32_const(1), i32_const(2), vec![0x71]].concat()),
            func_body(Vec::new(), [i64_const(1), vec![0xa7]].concat()),
            func_body(Vec::new(), vec![0x01]),
        ]),
    ])
}

fn if_i32_body() -> Vec<u8> {
    func_body(
        Vec::new(),
        [
            i32_const(1),
            vec![0x04, I32],
            i32_const(10),
            vec![0x05],
            i32_const(20),
            vec![0x0b],
        ]
        .concat(),
    )
}

fn branch_i32_body() -> Vec<u8> {
    func_body(
        Vec::new(),
        [vec![0x02, I32], i32_const(7), vec![0x0c, 0x00, 0x0b]].concat(),
    )
}

fn br_table_i32_body() -> Vec<u8> {
    func_body(
        Vec::new(),
        [
            vec![0x02, I32, 0x02, I32, 0x02, I32],
            i32_const(7),
            local_get(0),
            vec![0x0e, 0x02, 0x00, 0x01, 0x02, 0x0b, 0x0b, 0x0b],
        ]
        .concat(),
    )
}

fn control_flow_matrix_wasm() -> Vec<u8> {
    module(vec![
        type_section(vec![
            func_type(&[], &[I32]),
            func_type(&[I32], &[I32]),
            func_type(&[], &[]),
        ]),
        function_section(&[0, 0, 1, 2]),
        code_section(vec![
            if_i32_body(),
            branch_i32_body(),
            br_table_i32_body(),
            func_body(Vec::new(), vec![0x00]),
        ]),
    ])
}

fn direct_and_indirect_call_wasm() -> Vec<u8> {
    module(vec![
        type_section(vec![func_type(&[], &[I32])]),
        import_section(vec![import_func("env", "imported", 0)]),
        function_section(&[0, 0]),
        table_section(),
        code_section(vec![
            func_body(Vec::new(), vec![0x10, 0x00]),
            func_body(Vec::new(), [i32_const(0), vec![0x11, 0x00, 0x00]].concat()),
        ]),
    ])
}

fn multi_result_wasm() -> Vec<u8> {
    module(vec![
        type_section(vec![
            func_type(&[], &[I32, I64]),
            func_type(&[], &[I32]),
        ]),
        function_section(&[0, 1]),
        code_section(vec![
            func_body(Vec::new(), [i32_const(7), i64_const(8)].concat()),
            func_body(Vec::new(), vec![0x10, 0x00, 0x1a]),
        ]),
    ])
}

fn dense_local_id_wasm() -> Vec<u8> {
    module(vec![
        type_section(vec![func_type(&[], &[])]),
        import_section(vec![
            import_func("env", "first", 0),
            import_func("env", "second", 0),
        ]),
        function_section(&[0, 0, 0]),
        export_section(vec![
            export_entry("local_a", 0x00, 2),
            export_entry("local_b", 0x00, 3),
            export_entry("local_c", 0x00, 4),
        ]),
        code_section(vec![
            func_body(Vec::new(), Vec::new()),
            func_body(Vec::new(), Vec::new()),
            func_body(Vec::new(), Vec::new()),
        ]),
    ])
}

fn synthetic_lift_wasm(seed: u32) -> Vec<u8> {
    match seed % 8 {
        0 => module(vec![
            type_section(vec![func_type(&[], &[])]),
            function_section(&[0]),
            code_section(vec![func_body(Vec::new(), Vec::new())]),
        ]),
        1 => module(vec![
            type_section(vec![func_type(&[], &[I32])]),
            function_section(&[0]),
            export_section(vec![export_entry("f", 0x00, 0)]),
            code_section(vec![func_body(Vec::new(), i32_const((seed % 31) as u8))]),
        ]),
        2 => module(vec![
            type_section(vec![func_type(&[I32, I32], &[I32])]),
            function_section(&[0]),
            code_section(vec![func_body(
                Vec::new(),
                [local_get(0), local_get(1), vec![0x6a]].concat(),
            )]),
        ]),
        3 => module(vec![
            type_section(vec![func_type(&[], &[I32])]),
            function_section(&[0]),
            code_section(vec![if_i32_body()]),
        ]),
        4 => module(vec![
            type_section(vec![func_type(&[], &[I32])]),
            function_section(&[0]),
            code_section(vec![branch_i32_body()]),
        ]),
        5 => module(vec![
            type_section(vec![func_type(&[I32], &[I32])]),
            function_section(&[0]),
            code_section(vec![br_table_i32_body()]),
        ]),
        6 => module(vec![
            type_section(vec![func_type(&[], &[]), func_type(&[], &[I32])]),
            function_section(&[0, 1]),
            memory_section(),
            code_section(vec![
                func_body(Vec::new(), [i32_const(0), i32_const(1), vec![0x36, 0x02, 0x00]].concat()),
                func_body(Vec::new(), [i32_const(0), vec![0x28, 0x02, 0x00]].concat()),
            ]),
        ]),
        _ => module(vec![
            type_section(vec![func_type(&[], &[I32])]),
            import_section(vec![import_func("env", "imported", 0)]),
            function_section(&[0]),
            code_section(vec![func_body(Vec::new(), vec![0x10, 0x00])]),
        ]),
    }
}

#[test]
fn minimal_module_lifts_to_empty_ir_without_diagnostics() {
    let output = parse_and_lift(EMPTY_WASM_MODULE);

    assert!(output.lifted.functions.is_empty());
    assert!(output.lifted.facts.imports.is_empty());
    assert!(output.lifted.facts.exports.is_empty());
    assert!(output.lifted.soroban_facts.is_none());
}

#[test]
fn linear_numeric_memory_and_global_ops_lift_to_typed_ssa() {
    let output = parse_and_lift(&linear_operator_matrix_wasm());
    let lifted = &output.lifted;

    assert_eq!(lifted.functions.len(), 16);

    let lifted_types: Vec<LiftedType> = lifted
        .functions
        .iter()
        .flat_map(|func| func.values.iter())
        .flat_map(|(_value_id, value)| value.types.iter().copied())
        .collect();
    for expected in [
        LiftedType::I32,
        LiftedType::I64,
        LiftedType::F32,
        LiftedType::F64,
    ] {
        assert!(
            lifted_types.contains(&expected),
            "lifted value types should include {expected:?}"
        );
    }

    for expected in [
        WasmOpcodeKind::Const,
        WasmOpcodeKind::Arithmetic,
        WasmOpcodeKind::Bitwise,
        WasmOpcodeKind::Comparison,
        WasmOpcodeKind::Unary,
        WasmOpcodeKind::Conversion,
        WasmOpcodeKind::Load,
        WasmOpcodeKind::Store,
        WasmOpcodeKind::MemoryOp,
        WasmOpcodeKind::GlobalGet,
        WasmOpcodeKind::GlobalSet,
        WasmOpcodeKind::Select,
    ] {
        assert!(
            has_opcode_kind(lifted, expected),
            "lifted IR should contain opcode kind {expected:?}"
        );
    }

    assert!(has_value_def(lifted, |def| matches!(
        def,
        LiftedValueDef::BlockParam { .. }
    )));
    assert!(has_value_def(lifted, |def| matches!(
        def,
        LiftedValueDef::Operator { .. }
    )));
}

#[test]
fn control_flow_terminator_matrix_lifts_branching_shapes() {
    let output = parse_and_lift(&control_flow_matrix_wasm());
    let lifted = &output.lifted;

    assert_eq!(lifted.functions.len(), 4);
    assert!(has_terminator(lifted, |term| matches!(
        term,
        LiftedTerminator::BranchIf { .. }
    )));
    assert!(has_terminator(lifted, |term| matches!(
        term,
        LiftedTerminator::Branch(_)
    )));
    assert!(has_terminator(lifted, |term| matches!(
        term,
        LiftedTerminator::Switch { .. }
    )));
    assert!(has_terminator(lifted, |term| matches!(
        term,
        LiftedTerminator::Return { .. }
    )));
    assert!(has_terminator(lifted, |term| matches!(
        term,
        LiftedTerminator::Unreachable
    )));
}

#[test]
fn direct_and_indirect_calls_preserve_call_operators() {
    let output = parse_and_lift(&direct_and_indirect_call_wasm());
    let lifted = &output.lifted;

    assert_eq!(lifted.facts.imports.len(), 1);
    assert_eq!(lifted.functions.len(), 2);
    assert!(has_opcode_kind(lifted, WasmOpcodeKind::Call));
    assert!(has_opcode_kind(lifted, WasmOpcodeKind::CallIndirect));

    let saw_import_call = lifted.functions.iter().any(|func| {
        func.values.iter().any(|(_value_id, value)| {
            matches!(
                &value.def,
                LiftedValueDef::Operator {
                    op: sordec_ir::WasmOp(waffle::Operator::Call { function_index }),
                    ..
                } if function_index.index() == 0
            )
        })
    });
    assert!(saw_import_call, "direct call should retain raw imported function index 0");
}

#[test]
fn multi_result_call_creates_pick_output_values() {
    let output = parse_and_lift(&multi_result_wasm());

    assert!(has_value_def(&output.lifted, |def| matches!(
        def,
        LiftedValueDef::PickOutput { .. }
    )));
}

#[test]
fn function_ids_are_dense_local_indices_after_imports() {
    let output = parse_and_lift(&dense_local_id_wasm());
    let lifted = &output.lifted;

    assert_eq!(lifted.facts.imports.len(), 2);
    assert_eq!(lifted.functions.len(), 3);
    for (idx, func) in lifted.functions.iter().enumerate() {
        assert_eq!(
            func.id.index(),
            idx as u32,
            "FuncId should be dense over local functions, not raw WASM indices"
        );
    }
}

#[test]
fn waffle_parse_failure_surfaces_lift_error() {
    let err = lift_with_waffle(b"definitely not wasm", &empty_facts(), None)
        .expect_err("garbage bytes should fail at the waffle boundary");

    assert!(matches!(err, LiftError::WaffleParseFailed(_)));
}

#[test]
fn deterministic_generated_lift_matrix_decodes_thousands_of_modules() {
    for seed in 0..4096 {
        let wasm = synthetic_lift_wasm(seed);
        let output = parse_and_lift(&wasm);
        assert!(
            !output
                .lifted
                .functions
                .iter()
                .any(|func| func.blocks.is_empty()),
            "seed {seed} produced a function without blocks"
        );
    }
}

#[test]
fn committed_corpus_lifts_to_non_empty_ir_without_lift_diagnostics() {
    let fixtures: &[(&str, &[u8])] = &[
        ("hello-add", HELLO_ADD_WASM),
        ("token-v22", TOKEN_V22_WASM),
        ("token-v23", TOKEN_V23_WASM),
        ("token-v23-stripped", TOKEN_V23_STRIPPED_WASM),
        ("timelock", TIMELOCK_WASM),
        ("dex-liquidity-pool", DEX_LIQUIDITY_POOL_WASM),
    ];

    for (name, wasm) in fixtures {
        let parsed = sordec_frontend::parse(wasm)
            .unwrap_or_else(|err| panic!("[{name}] frontend parse failed: {err}"));
        let output = lift_with_waffle(wasm, &parsed.wasm_facts, parsed.soroban_facts.as_ref())
            .unwrap_or_else(|err| panic!("[{name}] lift failed: {err}"));

        assert!(
            output.diagnostics.is_empty(),
            "[{name}] lifter emitted unexpected diagnostics: {:?}",
            output.diagnostics
        );
        assert_eq!(
            output.lifted.functions.len(),
            parsed.wasm_facts.function_type_indices.len(),
            "[{name}] lifted function count disagrees with frontend local function count"
        );
        assert!(
            !output.lifted.functions.is_empty(),
            "[{name}] committed Soroban contract should have local functions"
        );
        assert_invariants_hold(&output.lifted);
    }
}

#[test]
fn lifted_ir_threads_soroban_metadata_from_frontend() {
    let hello = parse_and_lift(HELLO_ADD_WASM);
    assert!(
        hello.lifted.soroban_facts.is_some(),
        "unstripped Soroban fixture should carry decoded SorobanFacts into LiftedIr"
    );

    let stripped = parse_and_lift(TOKEN_V23_STRIPPED_WASM);
    assert!(
        stripped.lifted.soroban_facts.is_none(),
        "stripped fixture should keep LiftedIr.soroban_facts as None"
    );
}
