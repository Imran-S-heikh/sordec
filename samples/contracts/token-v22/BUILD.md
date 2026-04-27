# token-v22 — build recipe

The committed `token-v22.wasm` was produced from the vendored source
in `source/` using the toolchain pinned via `source/rust-toolchain.toml`.

## Toolchain

| Component | Version | Pinned via |
|-----------|---------|------------|
| rustc | 1.91 (stable channel) | `source/rust-toolchain.toml` |
| cargo target | `wasm32-unknown-unknown` | `source/rust-toolchain.toml` |
| soroban-sdk | ^22.0.1 → resolved to 22.0.11 | `source/Cargo.toml` + `source/Cargo.lock` |
| soroban-token-sdk | ^22.0.1 → resolved to 22.0.11 | `source/Cargo.toml` + `source/Cargo.lock` |
| transitive deps | exact versions | `source/Cargo.lock` (committed) |

`wasm32-unknown-unknown` matches v22-era production reality; v22 contracts
were deployed with this target before stellar CLI's switch to `wasm32v1-none`.
The cross-version testing motivation is preserved: token-v22 ships against
a genuinely older WASM target, not just an older SDK version.

## Reproduce

```bash
bash samples/contracts/token-v22/build.sh
```

## Expected sha256

```
893328ed99499ee9bfcf1e3fc969d49643919cde5ecb7e68a16036c8440cb03f
```

## Provenance

See `source/VENDORED_FROM` for upstream URL, commit, and license.
**Note**: upstream v22.0.1's `Cargo.lock` was inconsistent with its own
`Cargo.toml` (pinned soroban-sdk 22.0.0 while manifest required ^22.0.1).
Cargo resolved this on first build to 22.0.11 (latest matching patch).
Our committed lockfile reflects the resolved state — reproducible going
forward, but divergent from upstream's broken release lockfile.

## Build context

| Property | Value |
|----------|-------|
| Output size | 7,308 bytes |
| Function count (lifted) | 48 |
| Imports | 15 host functions |
| Exports | 17 (same SEP-41 surface as v23) |
| Metadata sections present | yes (`contractmetav0`, `contractspecv0`) |
| Built on | 2026-04-26 |

## Cross-version contrast with token-v23

The same SEP-41 source compiled against v22 vs v23 SDK produces:

|  | token-v22 | token-v23 |
|---|---|---|
| WASM target | wasm32-unknown-unknown | wasm32v1-none |
| Function count | 48 | 46 |
| Host imports | 15 | 19 |
| WASM size | 7,308 | 8,494 |

The import-count difference is the most decompiler-relevant: v22 and v23
made different host-function ABI choices. A correct decompiler must handle
both vintages.
