# Point 1: WASM Parsing -> WasmFacts + ParseDiagnostics

This folder tracks the Point 1 deliverable from Tranche 1:

> Parse WASM and produce `WasmFacts` and `ParseDiagnostics`.

The automated test entry point is:

```bash
cargo test -p sordec-frontend --test point1_wasm_facts
```

The test suite is implemented in:

```text
crates/sordec-frontend/tests/point1_wasm_facts.rs
```

## What Is Covered

- minimal valid WASM
- all `WasmFacts` fields
- import mapping for function, table, memory, global, and tag imports
- export mapping for function, table, memory, global, and tag exports
- local function type-index ordering and duplicate preservation
- custom-section name, payload, declaration order, and byte-range sanity
- ignored core sections that should not pollute `WasmFacts`
- fatal parse errors surfaced as typed `FrontendError`
- deterministic synthetic matrix of 4096 valid WASM shapes
- all committed Soroban corpus fixtures under `samples/contracts`

## Current Diagnostic Reality

The current frontend exposes `ParseOutput.diagnostics`, but the repository does
not yet define a dedicated `ParseDiagnosticCode`. Generic WASM parse failures
are fatal `FrontendError`s, while recoverable diagnostics currently come from
Soroban metadata decoding.

Therefore, Point 1 is complete for `WasmFacts` extraction, but not fully
complete against the exact RFP wording if `ParseDiagnostics` means a dedicated
recoverable parse-diagnostic taxonomy.
