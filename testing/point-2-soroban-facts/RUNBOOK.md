# Point 2 Runbook

## Prerequisite

Install a Rust toolchain with `cargo` and `rustc` available on `PATH`.

This workspace currently does not include a bundled Rust runtime, so the tests
cannot be executed on a machine that lacks Rust.

## Run Only Point 2

```bash
cargo test -p sordec-frontend --test point2_soroban_facts
```

## Run All Frontend Tests

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

- `soroban_facts.functions`
- `soroban_facts.types`
- `soroban_facts.contract_meta`
- `soroban_facts.env_meta`
- `diagnostics`
