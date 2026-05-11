# Point 2: Soroban Metadata -> SorobanFacts + MetadataDiagnostics

This folder tracks the Point 2 deliverable from Tranche 1:

> Decode `contractspecv0`, `contractmetav0`, and `contractenvmetav0` into
> `SorobanFacts` and `MetadataDiagnostics`.

The automated test entry point is:

```bash
cargo test -p sordec-frontend --test point2_soroban_facts
```

The test suite is implemented in:

```text
crates/sordec-frontend/tests/point2_soroban_facts.rs
```

## What Is Covered

- generic WASM without `contractspecv0`
- `contractspecv0` decoding into function signatures
- all six `ScSpecEntry` families:
  function, struct, union, enum, error enum, event
- all Soroban primitive type mappings
- composite type mappings:
  option, result, vec, map, tuple, bytesN, user-defined type
- duplicate type and function metadata diagnostics
- unresolved user-defined type metadata diagnostic
- malformed `contractmetav0` warning behavior
- malformed `contractspecv0` fatal behavior
- malformed `contractenvmetav0` fatal behavior
- multiple `contractmetav0` section concatenation
- `contractenvmetav0` protocol and pre-release decoding
- deterministic synthetic metadata matrix of 4096 generated specs
- committed real Soroban corpus metadata presence and clean diagnostics

## Current Status

The codebase has a dedicated `MetadataDiagnosticCode` taxonomy and a typed
`SorobanFacts` model. Point 2 is structurally implemented.

Local execution is blocked in this workspace because the machine does not have
`cargo`, `rustc`, or `rustup` installed. The report therefore records the test
design and expected completion status, but final closure requires running the
test command above on a Rust-enabled machine.
