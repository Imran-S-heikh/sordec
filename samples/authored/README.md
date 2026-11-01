# Authored test contracts

Contracts we wrote ourselves to check that the decompiler handles the
basics a Soroban developer uses every day. They sit apart from
`samples/contracts/` on purpose: that directory is the reference corpus
the acceptance criterion is measured on, and nothing here changes it.

`tools/measure.sh` decompiles and compile-checks every contract here as
the `authored` set. The results are logged in
`docs/benchmarks/wrapup-log.md`.

Each contract uses the same layout as `samples/contracts/<name>/`:
`source/` (a self-contained crate with its `Cargo.lock` and
`rust-toolchain.toml`), the committed `<name>.wasm` with its `.sha256`,
and a `build.sh` that rebuilds it.

## Contracts

| Contract | Written | soroban-sdk | rustc | Target |
|---|---|---|---|---|
| [treasury](treasury/) | 2026-10-31 | 23.0.1 | 1.89 | `wasm32v1-none` |

## What a measurement on these means

A contract is a fair test of how general the decompiler is only until
work starts on it. The treasury was measured once before any work on it
(main at 80bcb1d: 34 compile errors, 686 gaps). After that, fixes were
made with it in view, so its later numbers show progress on this
contract, not how a new contract would fare. A fresh contract kept
unseen until it is measured is what answers that.
