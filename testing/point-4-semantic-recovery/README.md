# Point 4: Baseline Semantic Recovery Test Suite

This folder documents the test evidence for Tranche 1 deliverable point 4:

> Add baseline semantic recovery for core host calls and publish initial test vectors and scoring rules.

Phase 1 semantic recovery is intentionally narrow. It does not yet collapse instruction sequences into Rust SDK calls such as `env.storage().persistent().set(...)`. The implemented baseline is:

- Resolve Soroban WASM host imports from `(module, name)` to friendly names using the vendored `soroban-env-common` catalog.
- Render recognized host calls in `dump-ir` as `host:<module>:<friendly_name>`.
- Preserve unknown host calls as raw `host:<module>:<name>` instead of failing.
- Score host-call recognition in `sordec coverage` text and JSON output.

## Executable Tests

Catalog and resolver tests:

```text
crates/sordec-passes/tests/point4_host_call_catalog.rs
```

CLI-visible semantic recovery tests:

```text
crates/sordec-cli/tests/point4_semantic_recovery.rs
```

## Synthetic Data

The CLI suite builds raw WASM binaries in memory with controlled import tables and call bodies. This lets the tests force known, unknown, mixed, all-known, and no-host-call cases without relying on a Soroban compiler.

The catalog suite uses the vendored `env.json` as the source of truth and verifies every catalog entry.

## Scoring Rules

The initial recognition score is:

```text
recognized_host_calls / total_direct_calls_to_imported_functions
```

Rules:

- Direct `call` to an imported function contributes to `host_calls.total`.
- A direct imported call contributes to `host_calls.recognized` only when `(import.module, import.name)` resolves in the vendored catalog.
- Unknown pairs are grouped by `(module, name)` and counted.
- Direct `call` to a local function is counted under `operators.call_to_local`, not host-call recognition.
- Indirect calls are counted under `operators.call_indirect`, not host-call recognition.
- When there are zero host calls, `host_calls.ratio` is `null`, never `NaN` or infinity.

## How To Run

```bash
cargo test -p sordec-passes --test point4_host_call_catalog
cargo test -p sordec-cli --test point4_semantic_recovery
```
