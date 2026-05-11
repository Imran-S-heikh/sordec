# Point 3 Scenario Matrix

| Area | Scenario | Test |
| --- | --- | --- |
| Empty module | Minimal valid WASM lifts to empty `LiftedIr` | `minimal_module_lifts_to_empty_ir_without_diagnostics` |
| Function accounting | Local function count matches `WasmFacts.function_type_indices` | `parse_and_lift` helper, all valid tests |
| ID model | Imported functions are skipped and local `FuncId` values are dense | `function_ids_are_dense_local_indices_after_imports` |
| SSA values | Operators and block parameters are present | `linear_numeric_memory_and_global_ops_lift_to_typed_ssa` |
| Multi-result SSA | Multi-value call projections create `PickOutput` values | `multi_result_call_creates_pick_output_values` |
| Numeric types | `i32`, `i64`, `f32`, and `f64` lifted value types appear | `linear_numeric_memory_and_global_ops_lift_to_typed_ssa` |
| Operator families | Const, arithmetic, bitwise, comparison, unary, conversion, load/store, memory, globals, select | `linear_numeric_memory_and_global_ops_lift_to_typed_ssa` |
| Direct calls | `waffle::Operator::Call` survives with raw imported function index | `direct_and_indirect_calls_preserve_call_operators` |
| Indirect calls | `waffle::Operator::CallIndirect` survives classification | `direct_and_indirect_calls_preserve_call_operators` |
| CFG return | Return terminators resolve referenced values | `control_flow_terminator_matrix_lifts_branching_shapes` |
| CFG branch | Unconditional branch terminators resolve target blocks | `control_flow_terminator_matrix_lifts_branching_shapes` |
| CFG conditional | Conditional branch terminators resolve condition and both targets | `control_flow_terminator_matrix_lifts_branching_shapes` |
| CFG switch | `br_table` lifts as switch/select terminator | `control_flow_terminator_matrix_lifts_branching_shapes` |
| CFG trap | `unreachable` lifts as `LiftedTerminator::Unreachable` | `control_flow_terminator_matrix_lifts_branching_shapes` |
| Diagnostics | Current lifter emits no non-fatal `LiftDiagnostics` | `parse_and_lift` helper, corpus test |
| Hard error | Invalid bytes surface typed `LiftError::WaffleParseFailed` | `waffle_parse_failure_surfaces_lift_error` |
| Synthetic scale | 4096 generated valid modules lift and satisfy invariants | `deterministic_generated_lift_matrix_decodes_thousands_of_modules` |
| Real corpus | All committed Soroban fixtures lift with no lift diagnostics | `committed_corpus_lifts_to_non_empty_ir_without_lift_diagnostics` |
| Metadata threading | Frontend Soroban metadata is cloned into `LiftedIr` | `lifted_ir_threads_soroban_metadata_from_frontend` |
