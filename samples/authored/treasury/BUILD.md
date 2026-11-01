# treasury — build recipe

The committed `treasury.wasm` was produced from `source/` with the
toolchain pinned by `source/rust-toolchain.toml`.

## Toolchain

| Component | Version | Pinned via |
|-----------|---------|------------|
| rustc | 1.89 | `source/rust-toolchain.toml` |
| cargo target | `wasm32v1-none` | `source/rust-toolchain.toml` |
| soroban-sdk | =23.0.1 | `source/Cargo.toml` + `source/Cargo.lock` |
| transitive deps | exact versions | `source/Cargo.lock` (committed) |

The release profile in `source/Cargo.toml` is the one the
soroban-examples contracts use (`opt-level = "z"`, `lto = true`,
`codegen-units = 1`, `panic = "abort"`, symbols stripped).

## Rebuild

```sh
bash build.sh
```

Reproduces `treasury.wasm` and writes `treasury.wasm.sha256`. Expected
sha256:

```
c15d47ba3a9236ed1bf1712d15754e1325e4840beab690bddc34b8a351e47a7b
```

The bytes do not depend on where the crate is built: a rebuild from
this directory matches the original build made elsewhere.
