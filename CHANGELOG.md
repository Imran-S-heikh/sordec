# Changelog

Notable changes to sordec. Format follows [Keep a Changelog][kac]; versions
follow [Semantic Versioning][semver].

[kac]: https://keepachangelog.com/en/1.1.0/
[semver]: https://semver.org/spec/v2.0.0.html

## [Unreleased]

## [0.1.0-alpha.1] — 2026-09-01

First public release. **Alpha**: the pipeline is complete and runs end to end on
every contract in the reference corpus; the quality of the Rust it emits is not
yet where it needs to be, and the numbers below say exactly where.

### Added

- **WASM frontend** — parses a Soroban `.wasm`, decodes `contractspecv0`,
  `contractmetav0` and `contractenvmetav0`, and recovers the full ABI:
  entrypoints, `#[contracttype]` structs and enums, error enums and events.
- **CFG/SSA lifter** built on `waffle`, giving real dataflow rather than
  structure inferred from WASM's own block nesting.
- **Pass pipeline** (`sordec-passes`) — type inference across call boundaries,
  Soroban idiom recognition (storage tiers, TTL, auth chains, events,
  cross-contract calls, panics), ABI-marshalling elision, shadow-stack slot
  promotion and control-flow structuring.
- **Signature catalogue** (`sordec-sigs`) — masked fingerprinting that
  identifies inlined SDK library functions. Fail-closed by construction:
  ambiguity drops a candidate rather than guessing between readings.
  Zero false positives across 14 measured runs.
- **Annotated WAT emitter** — per-function headers carrying recovered
  signatures and facts, with every host call labelled inline.
- **Rust emitter** — reconstructs `#[contract]` / `#[contractimpl]` modules,
  type definitions, signatures and function bodies via `syn` + `prettyplease`.
- **Accuracy scorer** (`sordec score`, `score-2.0.0`) — a source-to-source
  comparator reporting four independent categories (interface / structure /
  semantic / behavior) against a documented, versioned metric. It never
  inspects the WASM or the decompiler's internals, so it cannot flatter the
  pipeline it grades. Definition: [`docs/scoring_metric.md`](docs/scoring_metric.md).
- **Differential-execution harness** (`sordec-diffexec`) — registers the
  original wasm and a recompiled reconstruction in an in-process Soroban host,
  drives both identically, and compares return values, event streams, auth
  trees and storage. Mutual failure is bucketed separately, never counted as
  agreement.
- **CLI** — `dump-facts`, `dump-ir`, `dump-hir`, `dump-wat`, `dump-rust`,
  `decompile`, `coverage`, `score`.

### Known limitations

Stated plainly because the alternative is a tool that looks better than it is.

- **2 of 7 reference contracts currently recompile.** The rest emit Rust that
  does not yet type-check.
- **Reconstruction score 0.6108** against a 0.90 target, aggregated over the
  reference corpus. Interface averages 0.92 and is close to done; **structure
  averages 0.14 and is the whole gap.**
- **Output is 12–25× longer than the source it came from.** Control-flow
  *recall* is 1.0000 on four of five real contracts — every branch, loop and
  guard in the original is present — but `rustc` inlines the SDK into every
  function and we currently reproduce all of it. The remaining work is
  deletion, not discovery.
- **Values that cannot be proven become `todo!()` holes, never guesses.** Output
  that admits a gap is the design, not an oversight; a plausible wrong value
  that compiles is treated as a bug class.
- **Behaviour coverage is narrow.** Only entrypoints whose parameters are all
  scalars can be driven today, so `Address`-taking entrypoints — most real ones
  — are skipped, and the event, auth and storage channels have not yet been
  exercised. Where it *can* be measured it scores 1.0000.
- **Local variable names are not recovered**, because `rustc` deletes them.
  Bindings are emitted with synthesised names.

### Notes

- Not published to crates.io. Install from git; see the README.
- Minimum supported Rust version: **1.87**.

[Unreleased]: https://github.com/Imran-S-heikh/sordec/compare/v0.1.0-alpha.1...HEAD
[0.1.0-alpha.1]: https://github.com/Imran-S-heikh/sordec/releases/tag/v0.1.0-alpha.1
