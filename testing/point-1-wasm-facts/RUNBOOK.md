# Point 1 Runbook

## Prerequisite

Install a Rust toolchain with `cargo` and `rustc` available on `PATH`.

This workspace currently does not include a bundled Rust runtime, so the tests
cannot be executed on a machine that lacks Rust.

## Run Only Point 1

```bash
cargo test -p sordec-frontend --test point1_wasm_facts
```

## Run Frontend Tests

```bash
cargo test -p sordec-frontend
```

## Inspect the CLI Surface Manually

After building the CLI:

```bash
cargo build --release
./target/release/sordec dump-facts samples/contracts/token-v23/token-v23.wasm
```

The `dump-facts` output should include:

- `wasm_facts.imports`
- `wasm_facts.exports`
- `wasm_facts.function_type_indices`
- `wasm_facts.custom_sections`
- `diagnostics`
