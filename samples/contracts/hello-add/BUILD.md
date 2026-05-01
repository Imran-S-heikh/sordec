# hello-add — build recipe

## Toolchain

| Component | Version | Pinned via |
|-----------|---------|------------|
| rustc | 1.91 (stable channel) | `source/rust-toolchain.toml` |
| cargo target | `wasm32-unknown-unknown` | `source/rust-toolchain.toml` |
| soroban-sdk | =21.0.0 | `source/Cargo.toml` |
| transitive deps | exact versions | `source/Cargo.lock` (committed) |

## Reproduce

```bash
bash samples/contracts/hello-add/build.sh
```

## Expected sha256

```
44980ff3292cb561f514a094e93907919d0f1b9e95dbca78a38b798f4a6c06f4
```

## Provenance

First-party. Authored as part of the sordec project under the root
`LICENSE` (Apache-2.0). No `VENDORED_FROM` file because there is no
upstream — this is original code, not vendored from
`stellar/soroban-examples` or any other repo.

## Build context

| Property | Value |
|----------|-------|
| Output size | 629 bytes |
| Function count (lifted) | 5 |
| Imports | 2 host functions (Val encoding for `u64` args) |
| Exports | 2 (`add`, `_` (dispatcher)) |
| Metadata sections present | yes (`contractspecv0`, `contractenvmetav0`, `contractmetav0`) |
| Built on | 2026-05-01 |

## Note: minimal but not empty

hello-add looks like it should be the trivial case — no storage, no
auth, no host interaction. But every Soroban contract that takes a
primitive argument hits the Val encoding/decoding path at the
dispatcher boundary. That's what produces the 2 host calls (`obj_to_*`
or `*_from_*` for converting `u64` ↔ tagged `Val`) on a contract
whose source body is `a + b`. hello-add isolates this scaffolding so
the Phase 2 Val-encoding pattern pass can validate against it without
the noise of real storage/auth/etc.
