# Point 3 Completion Report

## Deliverable

Point 3 requires the tool to lift WASM to CFG/SSA IR via waffle and produce `LiftedIR` plus `LiftDiagnostics`.

## Test Assets Added

- `crates/sordec-passes/tests/point3_lifted_ir.rs`
- `testing/point-3-lifted-ir/README.md`
- `testing/point-3-lifted-ir/SCENARIO_MATRIX.md`
- `testing/point-3-lifted-ir/RUNBOOK.md`
- `testing/point-3-lifted-ir/REPORT.md`

The pre-existing `crates/sordec-passes/tests/lift.rs` and `crates/sordec-driver/tests/corpus.rs` were also corrected to use committed fixtures under `samples/contracts` instead of missing `learning/experiments` build outputs.

## Coverage Statistics

Unique input definitions:

| Input class | Count | Purpose |
| --- | ---: | --- |
| Focused valid synthetic WASM modules | 6 | Target specific lifter contracts |
| Deterministic generated valid WASM modules | 4096 | High-volume CFG/SSA regression coverage |
| Malformed lift-boundary inputs | 1 | Typed `LiftError` behavior |
| Committed Soroban corpus fixtures | 6 | Real-world contract coverage |
| Total unique inputs | 4109 | Point 3 verification surface |

Test execution lift attempts:

| Lift attempt class | Count |
| --- | ---: |
| Valid synthetic lift attempts | 4102 |
| Corpus lift attempts | 8 |
| Expected failing lift attempts | 1 |
| Total lift attempts | 4111 |

## Coverage Chart

```text
Focused synthetic modules      | ###### 6
Generated synthetic modules    | ################################################## 4096
Malformed boundary inputs      | # 1
Committed corpus fixtures      | ###### 6
```

## Component Coverage

| Component | Status | Evidence |
| --- | --- | --- |
| `lift_with_waffle` boundary | Covered | Synthetic, generated, malformed, and corpus tests call the public API |
| `LiftedIr.functions` | Covered | Count checked against frontend local function facts |
| `LiftedFunction` IDs | Covered | Dense local IDs verified after imports |
| `LiftedBlock` CFG | Covered | Entry and terminator targets validated by invariant helper |
| `LiftedValue` SSA | Covered | Value references and defs validated, including `BlockParam` and `PickOutput` |
| `WasmOp` classification | Covered | Core opcode families asserted through `WasmOpcodeKind` |
| `LiftDiagnostics` | Partial by design | Current implementation intentionally returns an empty vector |
| `LiftError` | Covered | Invalid bytes assert `WaffleParseFailed` |
| Real Soroban contracts | Covered | All committed fixture WASMs are lifted |

## Findings

The lifter has a real `LiftedIr` implementation backed by waffle and already exposes the expected public boundary. The added suite covers the CFG/SSA contract, ID model, operator categories, multi-result values, direct/indirect calls, error handling, high-volume generated WASM, and the committed Soroban corpus.

`LiftDiagnostics` is not meaningfully implemented yet. The current code documents this as intentional v0 behavior: recoverable lift diagnostics are empty, while hard failures surface as `LiftError`. This means Point 3 is complete for `LiftedIR`, but only structurally complete for `LiftDiagnostics`.

## Completion Assessment

Point 3 is verified for the implemented `LiftedIr` surface.

Executed result:

```text
running 10 tests
test result: ok. 10 passed; 0 failed; 0 ignored
```

Completion criteria:

| Criterion | Assessment |
| --- | --- |
| Lift valid WASM to CFG/SSA `LiftedIr` | Structurally complete |
| Preserve stable function/block/value IDs | Structurally complete |
| Preserve calls, memory/global ops, and control-flow edges | Structurally complete |
| Produce `LiftDiagnostics` | Present as API field, empty by current design |
| Pass automated Point 3 test suite | Complete |

Recommended verification command:

```bash
cargo test -p sordec-passes --test point3_lifted_ir
```
