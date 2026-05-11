# Point 3 Runbook

## Prerequisites

Install a Rust toolchain with `cargo`, `rustc`, and `rustfmt`.

## Primary Verification

```bash
cargo test -p sordec-passes --test point3_lifted_ir
```

Expected result:

```text
10 passed; 0 failed
```

## Broader Lifter Verification

```bash
cargo test -p sordec-passes
```

This runs the new Point 3 suite plus the existing lifter smoke/invariant tests.

## Workspace Regression Pass

```bash
cargo test --workspace
```

Use this after Points 1 through 4 are all added, because the point-specific suites touch multiple crates.

## Failure Triage

If a focused synthetic test fails, inspect the failing WASM scenario first. Those inputs are intentionally small and should isolate one lifter contract.

If the 4096-module matrix fails, rerun the reported seed by temporarily reducing the range in `deterministic_generated_lift_matrix_decodes_thousands_of_modules`.

If a corpus fixture fails, compare:

- Whether `sordec_frontend::parse` failed before lifting.
- Whether `waffle::Module::from_wasm_bytes` or `expand_all_funcs` failed.
- Whether the invariant helper found a dangling `BlockId` or `ValueId`.
