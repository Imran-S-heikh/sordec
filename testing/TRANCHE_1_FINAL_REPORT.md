# Tranche 1 Final Testing And Completion Report

## Project Context

RFP: Soroban (WASM) Specialized Reverse Engineering Tool
Program: Soroban Reverse Engineering Tool, SCF #41
Requested budget: $120.0K
Tranche: 1, MVP

Tranche 1 brief:

```text
Parse a WASM Soroban contract, insert Soroban related facts, then emit CFG/SSA IR via waffle.
```

The tranche deliverables are:

1. Parse WASM and produce `WasmFacts` and `ParseDiagnostics`.
2. Decode `contractspecv0`, `contractmetav0`, and `contractenvmetav0` into `SorobanFacts` and `MetadataDiagnostics`.
3. Lift WASM to CFG/SSA IR via waffle and produce `LiftedIR` plus `LiftDiagnostics`.
4. Add baseline semantic recovery for core host calls and publish initial test vectors and scoring rules.

The RFP completion checks are:

1. The tool should be able to print human-readable waffle CFG/SSA IR.
2. The tool should emit `WasmFacts` and `ParseDiagnostics`.

## Executive Verdict

Tranche 1 is **not defensibly 100% complete yet**.

The implementation and test assets are strong enough to call most of the tranche **structurally complete and ready for verification**, but there are two real completion gaps:

1. `ParseDiagnostics` is not a dedicated implemented taxonomy. WASM parse failures currently surface as typed fatal `FrontendError`s, not recoverable `ParseDiagnosticCode` diagnostics.
2. `LiftDiagnostics` exists as an API field but is intentionally empty in v0. That is acceptable if the tranche only requires a field placeholder, but not if it requires actual recoverable lifter diagnostics.

There is also a hard verification blocker in this local environment: `cargo`, `rustc`, `rustup`, and `rustfmt` are not installed. Because of that, no Rust test suite was able to execute here. The reports below are based on the code and test assets added, plus local shell/static checks, not on successful `cargo test` execution.

Recommended status:

```text
Overall Tranche 1 status: 80-85% complete pending Rust test execution.
If ParseDiagnostics and LiftDiagnostics are accepted as v0 placeholders/fatal errors, status rises to ~90-95%.
Do not claim 100% until the focused and workspace test commands pass on a Rust-enabled machine.
```

## Local Test Execution Results

Local toolchain check:

```text
cargo not found
rustc not found
rustup not found
rustfmt not found
```

Focused test commands attempted during this review failed before test execution:

```text
$ cargo test -p sordec-passes --test point3_lifted_ir
zsh:1: command not found: cargo

$ cargo test -p sordec-passes --test point4_host_call_catalog
zsh:1: command not found: cargo

$ cargo test -p sordec-cli --test point4_semantic_recovery
zsh:1: command not found: cargo
```

Commands that still need to run to close the tranche:

```bash
cargo test -p sordec-frontend --test point1_wasm_facts
cargo test -p sordec-frontend --test point2_soroban_facts
cargo test -p sordec-passes --test point3_lifted_ir
cargo test -p sordec-passes --test point4_host_call_catalog
cargo test -p sordec-cli --test point4_semantic_recovery
cargo test --workspace
```

## Test Assets Created

Point-specific testing folders:

| Folder | Purpose |
| --- | --- |
| `testing/point-1-wasm-facts` | WASM parsing, `WasmFacts`, parser behavior matrix |
| `testing/point-2-soroban-facts` | Soroban metadata decoding, `SorobanFacts`, metadata diagnostics |
| `testing/point-3-lifted-ir` | Waffle CFG/SSA lifting, `LiftedIR`, lifter invariants |
| `testing/point-4-semantic-recovery` | Host-call recovery, `dump-ir` rendering, coverage scoring |

Focused Rust test files added:

| Test file | Lines | Focus |
| --- | ---: | --- |
| `crates/sordec-frontend/tests/point1_wasm_facts.rs` | 546 | `WasmFacts` parser scenarios |
| `crates/sordec-frontend/tests/point2_soroban_facts.rs` | 639 | Soroban metadata scenarios |
| `crates/sordec-passes/tests/point3_lifted_ir.rs` | 654 | Waffle lift and CFG/SSA scenarios |
| `crates/sordec-passes/tests/point4_host_call_catalog.rs` | 147 | Host-call catalog resolver scenarios |
| `crates/sordec-cli/tests/point4_semantic_recovery.rs` | 319 | CLI-visible host-call recovery and scoring |
| Total focused test code | 2305 | Tranche 1 focused automated coverage |

Additional fixes made for testability:

- `crates/sordec-frontend/tests/parse.rs` was updated away from missing `learning/experiments` fixtures.
- `crates/sordec-passes/tests/lift.rs` was updated to committed `samples/contracts` fixtures.
- `crates/sordec-driver/tests/corpus.rs` was updated to committed `samples/contracts` fixtures.

## Scenario Coverage Summary

| Point | Synthetic / generated inputs | Malformed / negative inputs | Corpus fixtures | Status |
| --- | ---: | ---: | ---: | --- |
| Point 1: `WasmFacts` | 4103 | 5 | 6 | Partial: parser facts covered, dedicated parse diagnostics missing |
| Point 2: `SorobanFacts` | 4102 | 5 | 6 | Structurally complete, needs test execution |
| Point 3: `LiftedIR` | 4102 | 1 | 6 | Structurally complete for IR, `LiftDiagnostics` placeholder only |
| Point 4: host-call recovery | 8395 resolver checks plus 3 CLI WASM modules | 4096 unknown lookup checks | Existing corpus remains covered elsewhere | Structurally complete for Phase 1 baseline |

Combined focused scenario volume:

```text
Point 1 parser inputs:             4114
Point 2 metadata inputs:           4113
Point 3 unique lift inputs:        4109
Point 4 resolver/CLI scenarios:    8398+
```

## Completion By Deliverable

### 1. WASM Parsing: `WasmFacts` And `ParseDiagnostics`

Implemented:

- Valid WASM parsing through `sordec_frontend::parse`.
- `WasmFacts` with imports, exports, local function type indices, custom sections, section payload bytes, and byte ranges.
- Typed fatal parser errors through `FrontendError`.
- Synthetic coverage for import/export kinds, function indices, custom-section order, ignored sections, invalid inputs, and committed Soroban fixtures.

Missing:

- Dedicated `ParseDiagnosticCode` or equivalent parse-diagnostic taxonomy.
- Recoverable parser diagnostics. Current generic parse failures are fatal, not diagnostics.

Assessment:

```text
WasmFacts: complete for Phase 1 surface.
ParseDiagnostics: incomplete as a distinct deliverable.
Point 1 status: partial.
```

### 2. Soroban Metadata Decoding: `SorobanFacts` And `MetadataDiagnostics`

Implemented:

- `contractspecv0` decoding into functions, structs, unions, enums, errors, events, primitive types, composite types, UDT references, and event fields.
- `contractmetav0` decoding into key/value metadata.
- `contractenvmetav0` decoding into protocol and pre-release compatibility facts.
- `MetadataDiagnosticCode` coverage for duplicate names, unresolved type references, and malformed recoverable contract metadata.
- Fatal metadata errors for malformed spec and env metadata.

Missing:

- No known structural gap from the written tests.
- Verification still requires executing the focused test command.

Assessment:

```text
SorobanFacts: structurally complete.
MetadataDiagnostics: structurally complete for current decoder behavior.
Point 2 status: ready for verification.
```

### 3. Waffle Lifting: `LiftedIR` And `LiftDiagnostics`

Implemented:

- `sordec_passes::lift_with_waffle`.
- Waffle-backed CFG/SSA `LiftedIr`.
- Per-local-function `LiftedFunction` list.
- Stable `FuncId`, `BlockId`, and `ValueId` invariants.
- Typed lifted blocks, SSA values, value definitions, operators, and terminators.
- Coverage for direct calls, indirect calls, memory/global ops, branches, `br_table`, returns, traps, multi-result projections, generated modules, and committed Soroban contracts.
- CLI path exists for human-readable CFG/SSA via `sordec dump-ir`.

Missing:

- `LiftDiagnostics` is currently empty by design. Hard lift failures are `LiftError`s.
- No executed test pass in this local environment.

Assessment:

```text
LiftedIR: structurally complete.
LiftDiagnostics: API present, semantic content missing.
Point 3 status: ready for verification, with diagnostics caveat.
```

### 4. Baseline Semantic Recovery For Core Host Calls

Implemented:

- Vendored `soroban-env-common 26.1.2` host-call catalog.
- 192 host-call entries across 11 Soroban host modules.
- Resolver from `(module, name)` to friendly host-call name.
- `dump-ir` renders recognized calls as `host:<module>:<friendly_name>`.
- Unknown host calls render as raw `host:<module>:<name>` instead of failing.
- `coverage` computes host-call recognition ratio and unknown-call groups.
- Initial scoring rule is published:

```text
recognized_host_calls / total_direct_calls_to_imported_functions
```

Missing:

- Full semantic operation collapse is not implemented. The tool does not yet turn low-level host-call sequences into high-level Rust SDK operations such as storage set/get, auth chains, event publishing, or cross-contract client calls.
- That deeper recovery appears outside the stated Tranche 1 MVP if Point 4 is interpreted as baseline core host-call recovery only.

Assessment:

```text
Baseline host-call recovery: structurally complete.
Full Soroban semantic recovery: not Phase 1 complete.
Point 4 status: complete for baseline Phase 1 scope, not full decompiler scope.
```

## RFP Measurement Check

| RFP measure | Evidence | Status |
| --- | --- | --- |
| Print human-readable waffle CFG/SSA IR | `sordec dump-ir`, `crates/sordec-cli/src/pretty.rs`, Point 3/4 CLI tests | Implemented, needs local test execution |
| Emit `WasmFacts` | `sordec_frontend::parse`, Point 1 tests, `sordec dump-facts` path exists | Implemented, needs local test execution |
| Emit `ParseDiagnostics` | Shared diagnostics vector exists, but no dedicated parse diagnostics | Not complete |

## Overall Coverage Chart

```text
Point 1 WasmFacts              | ################################################## 100%
Point 1 ParseDiagnostics       | ############                                      25%
Point 2 SorobanFacts           | ################################################## 100% structural
Point 2 MetadataDiagnostics    | ################################################## 100% structural
Point 3 LiftedIR               | ################################################## 100% structural
Point 3 LiftDiagnostics        | #########################                         50% API only
Point 4 Host-call baseline     | ################################################## 100% structural
Local test execution           |                                                   0% blocked
```

## What Is Missing Before Claiming 100%

1. Install or provide a Rust toolchain and run the focused and workspace test commands.
2. Decide whether Tranche 1 requires real `ParseDiagnostics`. If yes, add `ParseDiagnosticCode` and at least one recoverable parser diagnostic.
3. Decide whether Tranche 1 requires non-empty `LiftDiagnostics`. If yes, add at least one recoverable lift diagnostic path or adjust the deliverable wording to say diagnostics are reserved for future recoverable lifter conditions.
4. If Point 4 is judged beyond baseline host-call naming, implement first-pass semantic operation collapse for at least storage get/set, auth, invoke-contract, and publish-event patterns.

## Final Recommendation

Do not present this tranche as 100% complete yet.

Best defensible statement:

```text
Tranche 1 implementation is largely complete and has comprehensive automated test assets prepared.
It is blocked on Rust test execution in the current environment.
The only clear deliverable gap is dedicated ParseDiagnostics; LiftDiagnostics is present but empty by v0 design.
Baseline host-call semantic recovery is complete for Phase 1, while deeper semantic pattern collapse remains Phase 2+.
```

Once `cargo test --workspace` passes and the diagnostic-scope decision is resolved, this tranche can be closed with a much stronger completion claim.
