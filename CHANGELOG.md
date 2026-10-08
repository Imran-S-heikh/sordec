# Changelog

Notable changes to sordec. Format follows [Keep a Changelog][kac]; versions
follow [Semantic Versioning][semver].

[kac]: https://keepachangelog.com/en/1.1.0/
[semver]: https://semver.org/spec/v2.0.0.html

## [Unreleased]

### Reconstruction quality

Measured 2026-10-08 with `score-2.1.0`; the alpha's own numbers are kept in
its section below.

| | alpha.1 | now |
|---|---|---|
| Reference corpus: recompiles | 2 of 7 | **7 of 7** |
| Reference corpus: overall score | 0.6108 | **0.9389** |
| Reference corpus: structure | 0.14 | **0.94** |
| Reference corpus: behaviour measured on | 2 of 7 | **6 of 7** (0.93) |
| Held-out 25 (`soroban-examples`): recompiles | — | **17 of 25** |
| Held-out 25: overall score | — | **0.7570** |
| Third-party unseen (2): overall score | — | **0.53** (0 of 2 recompile) |

About 0.08 of the corpus rise is the scorer change below; the rest is the
decompiler. The bulk of the work since the alpha:

- **Marshalling elision.** The SDK glue rustc inlines into every function —
  `Val` encode/decode, tag checks, frame bookkeeping, struct and enum codecs,
  `Option`/`Result` plumbing — is recognised and removed, which is what took
  corpus structure from 0.14 to 0.94.
- **Compiling output.** Type inference, sign and width casts, `bool`/integer
  boundaries, wide (`i128`) values, `Option` helpers returned as `Option<T>`
  (through an out-pointer or a register pair), struct decoders and encoders
  collapsed at their call sites, keys promoted to constant data named.
- **Behaviour harness** drives `Address`, `String`, `Bytes`, struct and enum
  parameters and constructors, and found three real output bugs on its first
  full run (event topics, symbol literals, a constructor hole).
- **Host catalog** re-vendored to `soroban-env-common` 27.0.1 (protocol 27).

### Scorer: `score-2.1.0`

Six rule changes, one principle: a fact whose only evidence the compiler
destroys is dropped from both sides rather than scored as a miss — authored
panic messages, derived-impl bodies, a stripped contract's parameter, enum and
type names, and how many times a helper was written out. Each is listed with its
evidence in [`docs/scoring_metric.md` §7.1](docs/scoring_metric.md).

### Added

- **[`docs/compatibility.md`](docs/compatibility.md)** — which Soroban protocol
  and SDK versions sordec handles, and where the edges are. The host-call
  catalog names protocols through 27 (read out of its own per-function gating
  data, not estimated); the corpus exercises 21 through 23 and the held-out
  set 27, and the document
  says which is which rather than implying support from a version number. Also
  covers the three-rung SDK recovery ladder, the two Rust toolchains and why
  they are different numbers, what a stripped `contractspecv0` costs, and what
  is not supported at all.

- **`decompile --force`.** Without it, `decompile` now refuses to write over
  any of the three files it produces. The emitted crate is meant to be edited,
  and a second run used to replace an edited `src/lib.rs` silently. **Breaking
  CLI change**: a script that decompiles repeatedly into a fixed directory
  needs `--force` added.
- **`-` reads stdin** on every subcommand that takes a module, so sordec
  composes in a pipeline. `decompile -` writes to `<out-dir>/contract/`, since
  a pipe carries no filename to name the output after.
- **`sordec completions <shell>`** prints a completion script, and a hidden
  `sordec man` prints a roff man page. Both are generated from the argument
  definitions, so neither can drift from `--help`.
- **`--quiet` / `-q`** silences the pipeline's non-fatal diagnostics. Errors
  still print and the exit code is unchanged.
- **`--json` on `dump-ir` and `dump-hir`.** The rule is now stated in the CLI
  docs: structured output can be JSON, source-text output (`dump-wat`,
  `dump-rust`) cannot.
- **`sordec` is usable as a library**, not only as a binary:
  `sordec::Driver::standard().run(&wasm)` returns the reconstructed Rust and the
  manifest that builds it, and `sordec::score_paths` grades a reconstruction.
  Both are re-exports of `sordec-driver` and `sordec-score`, which remain
  available directly; the facade exists so the entry point is findable without
  reading the workspace. Re-exporting the scorer adds no dependency edge and
  does not compromise its independence from the pipeline it grades.
- **`docs/` is now published**, and holds the documents the code has been
  citing all along: [`architecture.md`](docs/architecture.md) (the IR type
  system, pass infrastructure and pipeline design) and
  [`scoring_metric.md`](docs/scoring_metric.md) (the metric definition, in
  full), alongside the generated corpus report. Eleven rustdoc comments cited
  these files while the directory was gitignored, so every one of those
  pointers was dead. They now resolve — as absolute links, so they work from
  `docs.rs` too, where a package contains only its own crate directory.
- **All ten crates ship the Apache-2.0 licence text.** Each declared
  `license = "Apache-2.0"` and packaged no `LICENSE` file.

### Changed

- **The CLI package is now `sordec`, not `sordec-cli`.** The binary was always
  `sordec`; only the package carried the suffix, so `cargo install sordec-cli`
  was a name nobody would guess. Install with
  `cargo install --git https://github.com/Imran-S-heikh/sordec sordec`. The
  `v0.1.0-alpha.1` tag is unchanged and still publishes `sordec-cli` — install
  that revision with `--tag v0.1.0-alpha.1 sordec-cli`. Done now because
  nothing is on crates.io yet, where a name is permanent.

### Fixed

- **A non-WASM input printed ten lines of bytes.** `wasmparser` reports a
  magic-number mismatch by pretty-printing both byte arrays, and the frontend
  passed it straight through. It now checks the magic number itself and says
  what it found. A shell script now reports as
  `not a WASM file: expected the magic number \0asm, found "#!/b"`.

## [0.1.0-alpha.1] — 2026-09-04

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
  pipeline it grades. The metric is versioned and every report stamps the
  triple that reproduces it; the full definition — categories, weights, source
  basis, and stated limits — is [`docs/scoring_metric.md`](docs/scoring_metric.md).
- **Differential-execution harness** (`sordec-diffexec`) — registers the
  original wasm and a recompiled reconstruction in an in-process Soroban host,
  drives both identically, and compares return values, event streams, auth
  trees and storage. Mutual failure is bucketed separately, never counted as
  agreement.
- **CLI** — `dump-facts`, `dump-ir`, `dump-hir`, `dump-wat`, `dump-rust`,
  `decompile`, `coverage`, `score`.
- **Corpus accuracy report** (`docs/benchmarks/report.{md,json}`) covering all
  four categories. Behaviour is reported per fixture with its coverage, and
  where it cannot be measured the report gives the reason instead of a zero —
  "does not build" and "does the wrong thing" are different findings. Two
  aggregates are published: **0.6108** over the three AST categories, the
  figure comparable with the committed regression bands, and **0.6156**
  including behaviour where it was measurable.
- **`tools/setup-toolchains.sh`** provisions both harnesses that shell out to
  cargo — `cargo-expand` for the macro-expanded scoring basis, and rustc 1.89 +
  `wasm32v1-none` for differential execution — plus the corpus prefetch that
  lets both build offline. `--scoring-only` provisions just what the gate
  needs. Without `cargo-expand`, scoring silently falls back to a different
  basis and three of seven fixtures breach their bands, so this is a
  precondition for reproducing any published number.

### Fixed

- A failed reconstruction build reported the *first diagnostic line* as its
  reason. `rustc` prints every warning before the first error, so this
  routinely read "crate does not build: warning: unreachable statement" —
  naming a warning as the cause of a compile failure. Errors now come first.
  The accompanying count is gone; it counted kept lines against a cap, so it
  read the same for twelve errors and three hundred.
- The generated accuracy report embedded absolute paths from the machine that
  produced it. Paths are now repo-relative, so two people regenerating it get
  the same bytes.

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
  exercised. It is measurable on 2 of the 7 reference contracts, gated by the
  same compile rate above, and scores 1.0000 on both: hello-add over 1 of 1
  entrypoints, attestation over 2 of 6. Read those denominators — a match rate
  without its coverage is not a result.
- **Local variable names are not recovered**, because `rustc` deletes them.
  Bindings are emitted with synthesised names.

### Notes

- Not published to crates.io. Install from git; see the README.
- Minimum supported Rust version: **1.91**, set by `soroban-spec` /
  `soroban-meta` 25.3.x rather than by our own code, whose floor is 1.87.

[Unreleased]: https://github.com/Imran-S-heikh/sordec/compare/v0.1.0-alpha.1...HEAD
[0.1.0-alpha.1]: https://github.com/Imran-S-heikh/sordec/releases/tag/v0.1.0-alpha.1
