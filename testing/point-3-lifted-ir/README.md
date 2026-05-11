# Point 3: Lifted IR Test Suite

This folder documents the test evidence for Tranche 1 deliverable point 3:

> Lift WASM to CFG/SSA IR via waffle and produce `LiftedIR` plus `LiftDiagnostics`.

The executable coverage lives in:

```text
crates/sordec-passes/tests/point3_lifted_ir.rs
```

## What Is Tested

The suite verifies the public `sordec_passes::lift_with_waffle` boundary:

- Raw WASM bytes are accepted after frontend parsing.
- One `LiftedFunction` is emitted per local WASM function body.
- Imported functions are excluded from `LiftedIr.functions` but raw call indices are preserved.
- `FuncId`, `BlockId`, and `ValueId` references remain dense and internally resolvable.
- SSA value definitions cover operators, block parameters, and multi-result projections.
- CFG terminators cover return, branch, conditional branch, switch, and unreachable.
- `LiftDiagnostics` is empty by design in current v0 lifter behavior.
- Waffle parse failures surface as typed `LiftError` values.

## Synthetic Data

The tests construct WASM modules directly in binary form. This avoids depending on `rustc`,
`soroban-sdk`, or fixture compiler output for the lifter’s generic correctness.

Synthetic coverage includes:

- Numeric operators and lifted value types: `i32`, `i64`, `f32`, `f64`.
- Operator families: const, arithmetic, bitwise, comparison, unary, conversion, load, store,
  memory op, global get/set, select, call, and indirect call.
- Control-flow shapes: straight-line return, block branch, `if`, `br_table`, and trap.
- Multi-value functions to exercise `LiftedValueDef::PickOutput`.
- Imported-function offset handling to ensure local `FuncId` values stay dense.
- 4096 deterministic generated valid WASM modules.

## Corpus Data

The suite also lifts all committed Soroban fixture contracts:

- `hello-add`
- `token-v22`
- `token-v23`
- `token-v23-stripped`
- `timelock`
- `dex-liquidity-pool`

## How To Run

```bash
cargo test -p sordec-passes --test point3_lifted_ir
```

For the full Point 3 surface including the pre-existing smoke tests:

```bash
cargo test -p sordec-passes
```
