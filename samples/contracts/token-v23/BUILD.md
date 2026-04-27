# token-v23 — build recipe

The committed `token-v23.wasm` was produced from the vendored source in
`source/` using the toolchain pinned via `source/rust-toolchain.toml`.

## Toolchain

| Component | Version | Pinned via |
|-----------|---------|------------|
| rustc | 1.89 (stable channel) | `source/rust-toolchain.toml` |
| cargo target | `wasm32v1-none` | `source/rust-toolchain.toml` |
| soroban-sdk | =23.0.1 | `source/Cargo.toml` |
| soroban-token-sdk | =23.0.1 | `source/Cargo.toml` |
| transitive deps | exact versions | `source/Cargo.lock` (committed) |

`wasm32v1-none` is the Soroban-specific WASM target (matches what
`stellar contract build` produces). It's the same WASM shape that gets
deployed to mainnet. Earlier learning fixtures used `wasm32-unknown-unknown`;
this fixture deliberately mirrors production.

## Reproduce

```bash
bash samples/contracts/token-v23/build.sh
```

`build.sh` runs `cargo build --release --target wasm32v1-none` from the
`source/` directory (rustup will install rustc 1.89 + the wasm32v1-none
target on demand if not already present), then copies the output WASM up
and recomputes its sha256.

## Expected sha256

```
03541799cc4291302d011fd49ed6f3a8d8113fa040a2cbe4a784826dbf515b44
```

The locally-rebuilt WASM may differ byte-for-byte due to embedded build
paths, parallelism, or dependency build-script ordering. That's expected.
What matters is that the committed `token-v23.wasm` continues to match
`token-v23.wasm.sha256`, verified by `tools/verify-fixtures.sh`.

## Provenance

See `source/VENDORED_FROM` for the upstream URL, commit SHA, and license.
The source is verbatim from `stellar/soroban-examples` tag `v23.0.0`,
path `token/`. The only modification is an empty `[workspace]` table
appended to `source/Cargo.toml` so this crate opts out of any parent
workspace discovery.

## Build context

| Property | Value |
|----------|-------|
| Output size | 8,494 bytes |
| Function count (lifted) | 46 |
| Imports | 19 host functions |
| Exports | 17 (16 contract entry points + dispatcher) |
| Metadata sections present | yes (`contractmetav0`, `contractspecv0`) |
| Built on | 2026-04-26 |
