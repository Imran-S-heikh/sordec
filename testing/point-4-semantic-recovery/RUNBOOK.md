# Point 4 Runbook

## Prerequisites

Install a Rust toolchain with `cargo`, `rustc`, and `rustfmt`.

## Primary Verification

```bash
cargo test -p sordec-passes --test point4_host_call_catalog
cargo test -p sordec-cli --test point4_semantic_recovery
```

Expected focused result:

```text
13 passed; 0 failed
```

## Broader Verification

```bash
cargo test -p sordec-passes
cargo test -p sordec-cli
```

## Workspace Regression Pass

```bash
cargo test --workspace
```

Use this after all four point folders are present.

## Failure Triage

If catalog tests fail, inspect `crates/sordec-passes/src/host_calls/env.json` and `CATALOG_VERSION`. A catalog-size or resolver mismatch usually means the vendored JSON changed without updating the resolver assumptions.

If CLI tests fail, inspect the synthetic WASM helpers in `crates/sordec-cli/tests/point4_semantic_recovery.rs`. The generated modules are intentionally small: one function type, controlled imports, one exported local function, and direct `call` instructions.

If coverage ratio tests fail, verify whether imported-call classification changed in `crates/sordec-cli/src/coverage.rs`.
