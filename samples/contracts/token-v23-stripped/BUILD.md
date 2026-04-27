# token-v23-stripped — build recipe

The committed `token-v23-stripped.wasm` is `token-v23.wasm` with every
custom section removed via `wasm-tools strip --all`. The compiled code
sections are identical; only the WASM-level metadata differs.

## Toolchain

| Component | Version | Pinned via |
|-----------|---------|------------|
| rustc | 1.89 (stable channel) | `source/rust-toolchain.toml` |
| cargo target | `wasm32v1-none` | `source/rust-toolchain.toml` |
| soroban-sdk | =23.0.1 | `source/Cargo.toml` |
| soroban-token-sdk | =23.0.1 | `source/Cargo.toml` |
| transitive deps | exact versions | `source/Cargo.lock` (committed) |
| wasm-tools | (any recent) | system PATH |

`wasm-tools strip --all` removes ALL custom sections, including
`contractmetav0`, `contractspecv0`, `name`, and `producers`. By default
`wasm-tools strip` preserves `name`/`component-type`/`dylink.0`; the
`--all` flag overrides that.

## Reproduce

```bash
bash samples/contracts/token-v23-stripped/build.sh
```

Same Cargo invocation as `token-v23/build.sh`, plus a final
`wasm-tools strip --all` pass.

## Expected sha256

```
f56a7e2e110f4a055e0df9788ce79ecd6fecc083b7aa42a33b0156617e4f0564
```

## Provenance

Source identical to `samples/contracts/token-v23/source/`. See that
fixture's `VENDORED_FROM` for upstream URL and commit. The duplication
is intentional — each fixture is self-contained, so removing one
doesn't break the other.

## Build context

| Property | Value |
|----------|-------|
| Output size | 6,107 bytes (28% smaller than unstripped) |
| Function count (lifted) | 46 (identical to token-v23) |
| Imports | 19 host functions (identical to token-v23) |
| Exports | 17 (identical to token-v23) |
| Metadata sections present | NO (`contractmetav0` and `contractspecv0` removed) |
| Built on | 2026-04-26 |

## Why this fixture exists

Mainnet-deployed Soroban contracts are routinely stripped of metadata —
either via `stellar contract optimize` during deployment, or by manual
post-processing to reduce on-chain storage cost. A decompiler that only
works on developer-built unstripped WASM ships incomplete.

This fixture validates that:

1. `sordec_frontend::parse()` returns `Ok` with `metadata: None` when
   custom sections are absent (rather than erroring).
2. `sordec_passes::lift_with_waffle()` produces a valid `LiftedIr` from
   stripped WASM (the SSA + CFG translation does not depend on metadata).
3. Downstream passes that consume metadata (Phase 3+) handle the
   `metadata: None` case explicitly — typically by emitting decompiler
   output with synthesised type names instead of source-provided ones.

The `learning/experiments/` fixtures all ship unstripped, so this is the
first real-world failure mode entering the corpus.
