# dex-liquidity-pool — build recipe

## Toolchain

| Component | Version | Pinned via |
|-----------|---------|------------|
| rustc | 1.89 (stable channel) | `source/rust-toolchain.toml` |
| cargo target | `wasm32v1-none` | `source/rust-toolchain.toml` |
| soroban-sdk | =23.0.1 | `source/Cargo.toml` |
| num-integer | =0.1.45 | `source/Cargo.toml` |
| transitive deps | exact versions | `source/Cargo.lock` (committed) |

## Reproduce

```bash
bash samples/contracts/dex-liquidity-pool/build.sh
```

## Expected sha256

```
6e63a3511081492eafd7bb8cb6e9a4f5e774fee0c1651c4fc03ea28972a0e229
```

## Provenance

See `source/VENDORED_FROM`. Vendored verbatim from soroban-examples
v23.0.0, path `liquidity_pool/`. Apache-2.0.

The originally-planned `dex-soroswap` fixture was deferred to Phase 2:
the Soroswap repo is genuinely multi-contract (factory + library + pair
+ router + token), and bringing up just the AMM `pair` contract was not
tractable inside Task 1.6's time-box. The soroban-examples `liquidity_pool`
contract exercises the same AMM patterns (constant-product swap,
LP-share mint/burn, fee accumulation) as a single self-contained
contract, with the upside of a clean vendor.

## Build context

| Property | Value |
|----------|-------|
| Output size | 10,516 bytes (largest fixture) |
| Function count (lifted) | 50 |
| Imports | 12 host functions |
| Exports | 10 |
| Metadata sections present | yes |
| Built on | 2026-04-26 |
