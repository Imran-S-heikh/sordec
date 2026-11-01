# Comparison with soroban-ret

[soroban-ret](https://github.com/Inferara/soroban-ret) is the other public tool we know
of that turns a compiled Soroban contract back into Rust. This page measures both tools
on the same contracts with **both tools' scorers**, so neither result rests on a ruler
only one side built. Measured 2026-11-01.

- **sordec:** `main` at `3b78442`, scorer `score-2.2.0`.
- **soroban-ret:** commit `1b6a5ae`, one commit after v0.0.4 (it adds a report option
  and documentation; the output is the same). Its scorer is its own interface and body
  comparison code, called unmodified from a small driver. On its own fixtures it
  reproduces the 98.3% in its README exactly.

## Their scorer

| Contracts | sordec | soroban-ret | sordec ahead / level / soroban-ret ahead |
|---|---:|---:|---|
| soroban-ret's own 37 test contracts (soroban-sdk 26.0.1) | 94.4 | **98.3** | 1 / 27 / 9 |
| Our 7 reference contracts ([`acceptance.md`](../acceptance.md)) | **95.0** | 83.5 | 5 / 2 / 0 |
| Stellar `soroban-examples`, the 24 both tools run | **95.4** | 88.2 | 14 / 8 / 2 |
| Our authored treasury contract ([`samples/authored`](../../samples/authored/)) | **91.8** | 83.5 | ahead |

soroban-ret stops with an error on the 25th example, `import_ark_bn254`.

## Our scorer, and whether the output builds

Behaviour is left out on both sides here, because it needs the output to build and
most of soroban-ret's does not. Builds were checked with `cargo check`, each file inside
the same crate manifest for both tools.

| Contracts | sordec | soroban-ret | Builds: sordec | Builds: soroban-ret | sordec ahead / level / soroban-ret ahead |
|---|---:|---:|---|---|---|
| Our 7 reference contracts | **0.881** | 0.665 | **7 of 7** | 2 of 7 | 6 / 1 / 0 |
| Stellar examples, the 24 both tools run | **0.810** | 0.677 | **24 of 24** | 10 of 24 | 16 / 4 / 4 |
| Authored treasury | **0.668** | 0.645 | **yes** | no (33 errors) | ahead |

The reference-contract figure here (0.881) is lower than the acceptance figure (0.9359)
because this run scores the stripped token contract without its WASM, which costs it
interface credit. [`report.md`](report.md) is the acceptance measurement.

## What each scorer looks at

- **soroban-ret's scorer** compares type definitions, function signatures, attributes,
  and the names of the operations found in each public function's body. It does not
  build the output. Its check for `todo!()` gaps looks for a spelling the token printer
  never produces, so it counts no gaps in either tool's output.
- **Our scorer** compares interface, control-flow structure and Soroban operations
  (storage with tier and key, auth, events, cross-contract calls, errors), and can
  replay both contracts side by side ([`scoring_metric.md`](../scoring_metric.md)).
  Builds are a separate pass/fail check.

Each tool was developed against its own scorer, so each looks best on its own. The
contracts neither tool was shaped around (the Stellar examples) are the fairer ground.

## Where soroban-ret is ahead

On its own 37 test contracts, by 3.9 points. The causes, in the order they cost us:

- **Operations kept in helper functions.** sordec keeps a helper function where the
  binary has one. soroban-ret's scorer reads only the public function's body, so
  storage writes inside a helper do not count (`constructor`, `contract_data`, `fuzz`,
  `contracttrait_impl_partial`).
- **Two operations sordec does not recover yet:** an event published from a struct of
  references (`events_ref`), and one cross-contract call (`invoke_contract`).
- **The SDK's cryptography wrapper type names** (`bn254`, `bls`). The contract metadata
  records only the underlying type, so sordec prints that.
- **Layout of an empty contract** (`empty2`).

Under our scorer soroban-ret is ahead on 4 of the 24 Stellar examples:
`deep_contract_auth`, `modular_account`, `fuzzing` (by 0.01), and `eth_abi`. On
`eth_abi` its output is the function signature with a `todo!()` body. Our scorer gives
that full marks because the original function has no branches or Soroban operations
to compare against. That is a limitation of our scorer, not a strength of either
output.

## What neither table shows

- **Running the output.** Neither scorer here runs the code. On our reference
  contracts sordec's replay check runs on 6 of the 7, and 5 of those behave exactly
  like the original ([`report.md`](report.md)). The treasury builds but does not run yet: its rebuilt
  constructor starts at a stack-pointer setup sordec does not recover.
- **How much each tool writes out.** sordec writes out nearly every function in the
  binary, including library code, and marks what it cannot prove with `todo!()`.
  soroban-ret writes out far fewer functions. Line and gap counts are therefore not
  comparable between the two.
