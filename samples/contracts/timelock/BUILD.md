# timelock — build recipe

## Toolchain

| Component | Version | Pinned via |
|-----------|---------|------------|
| rustc | 1.89 (stable channel) | `source/rust-toolchain.toml` |
| cargo target | `wasm32v1-none` | `source/rust-toolchain.toml` |
| soroban-sdk | =23.0.1 | `source/Cargo.toml` |
| transitive deps | exact versions | `source/Cargo.lock` (committed) |

## Reproduce

```bash
bash samples/contracts/timelock/build.sh
```

## Expected sha256

```
9e2b092330638218dbb7d0f0be5035c45cf1e6dfcf929d1eb8a613b870786b12
```

## Provenance

See `source/VENDORED_FROM`. Vendored verbatim from soroban-examples
v23.0.0, path `timelock/`. Apache-2.0.

## Build context

| Property | Value |
|----------|-------|
| Output size | 3,693 bytes |
| Function count (lifted) | 18 |
| Imports | 21 host functions |
| Exports | 6 (`deposit`, `claim`, plus dispatcher) |
| Metadata sections present | yes |
| Built on | 2026-04-26 |

## Note: more imports than token-v23

Timelock has 21 imports vs token-v23's 19. The extra imports are time
(`ledger().timestamp()`) and cross-contract token calls (the contract
holds a token balance and transfers from itself on claim). Despite
being a *much* simpler contract by line count, timelock exercises a
broader host-function surface — exactly the cross-contract pattern that
makes it a useful corpus addition.
