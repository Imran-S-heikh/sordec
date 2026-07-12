# attestation — build recipe

The committed `attestation.wasm` was produced from the **original**
source in `source/` (purpose-built for the sordec corpus — see
`source/VENDORED_FROM`, it is not vendored upstream) using the toolchain
pinned via `source/rust-toolchain.toml`.

## Toolchain

| Component | Version | Pinned via |
|-----------|---------|------------|
| rustc | 1.97 (stable channel) | `source/rust-toolchain.toml` |
| cargo target | `wasm32-unknown-unknown` | `source/rust-toolchain.toml` |
| soroban-sdk | ^23.0.1 → resolved to 23.5.3 | `source/Cargo.toml` + `source/Cargo.lock` |
| transitive deps | exact versions | `source/Cargo.lock` (committed) |

## Why this fixture exists

The SEP-41 token, timelock, and AMM fixtures import only the
`a b d i l m v x` host modules. This contract deliberately exercises the
surfaces they miss, so the decompiler's crypto/prng/error recognition is
proven against a real compiled contract rather than drift-guards alone:

- **`c` (crypto)** — `sha256` (`c._`), `keccak256` (`c.1`),
  `ed25519_verify` (`c.0`).
- **`p` (prng)** — `u64_in_range` (`p.1`).
- **`#[contracterror]`** — an `Error` enum surfaced through `Result`
  returns.
- **long `Symbol`** — `"attestation_domain"` (`> 9` chars) forces
  `Symbol::new_from_linear_memory` (`b.j`) rather than the inline
  small-symbol path.

## Rebuild

```sh
bash build.sh
```

Reproduces `attestation.wasm` and writes `attestation.wasm.sha256`.
