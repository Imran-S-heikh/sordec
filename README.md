# sordec

A WebAssembly decompiler specialized for [Soroban](https://stellar.org/soroban) smart contracts.

> **Status: `v0.1.0-alpha.1`, with substantial unreleased work on `main`.** The
> pipeline runs end to end on every contract we have tried. On the seven
> reference contracts it was built against, the Rust it emits compiles and
> scores 0.94; on contracts it was not built against it is still well short of
> that. [Where it actually stands](#where-it-actually-stands) gives the
> numbers rather than an adjective.
>
> sordec parses a Soroban `.wasm`, lifts it to a typed CFG/SSA IR, recovers the
> multi-instruction SDK idioms, reconstructs control flow (`if`/`while`/`match`),
> and emits both Soroban-annotated WAT and reconstructed Rust. An accuracy
> scorer (`sordec score`) grades the result against a published, versioned
> metric — and never inspects the WASM or the decompiler's internals, so it
> cannot flatter the pipeline it measures.
>
> Per-phase deliverable summaries, verification recipes and acceptance evidence:
> [PHASE_1.md](PHASE_1.md), [PHASE_2.md](PHASE_2.md), [PHASE_3.md](PHASE_3.md),
> [PHASE_4.md](PHASE_4.md).

## Install

Not on crates.io yet — the crate boundaries are still moving, and claiming ten
public names at alpha quality is not a decision worth making early.

```bash
cargo install --git https://github.com/Imran-S-heikh/sordec sordec
```

Requires Rust **1.91** or newer. To build from a checkout instead, see
[Quick start](#quick-start).

> The package was called `sordec-cli` up to and including the
> `v0.1.0-alpha.1` tag; install that revision with
> `--tag v0.1.0-alpha.1 sordec-cli`.

### As a library

The same pipeline the binary runs, in one call:

```rust
let wasm = std::fs::read("contract.wasm")?;
let output = sordec::Driver::standard().run(&wasm)?;
println!("{}", output.rust);       // reconstructed Rust
println!("{}", output.cargo_toml); // the manifest that builds it
```

`sordec::score_paths` grades a reconstruction against the original source.
Individual stages are available as their own crates if you need one in
isolation — see [Workspace layout](#workspace-layout).

## Where it actually stands

A decompiler that overstates itself is worse than useless: you cannot audit a
contract against a reconstruction you can't calibrate. So here are three
measurements, scored by [our own published metric](docs/scoring_metric.md)
(`score-2.1.0` — four independent categories, fixed weights, stamped into every
report). Measured 2026-10-08.

| Set | Contracts | Recompile | Overall score |
|---|---|---|---|
| Reference corpus ([`samples/contracts/`](samples/contracts/)) | 7 | **7 of 7** | **0.94** |
| Held-out: the Stellar `soroban-examples` contracts | 25 | **17 of 25** | **0.76** |
| Unseen: third-party contracts built on other libraries | 2 | **0 of 2** | **0.53** |

**Read them in reverse order.** The reference corpus is what the decompiler was
developed against, so it is the most flattering number. The held-out set was
kept out of development at first and has since been used to find bugs, so it is
no longer strictly unseen. The two third-party contracts (OpenZeppelin's
`merkle-voting`, Phoenix's `vesting`) are the closest thing to "a contract you
hand it today", and **0.53 is the honest figure for that**.

By category:

| Category | Reference corpus | Held-out 25 |
|---|---|---|
| Interface — entrypoints, types | 0.90 | 0.99 |
| Structure — control-flow shape | 0.94 | 0.29 |
| Semantic — storage, auth, events, panics | 0.96 | 0.77 |
| Behaviour — differential execution | 0.93, measured on 6 of 7 | not yet run |

And the things a bare score won't tell you:

- **Part of the rise is the ruler, not the decompiler.** The corpus score was
  0.61 at the alpha release. About 0.08 of the rise to 0.94 came from the six
  rule changes in `score-2.1.0`. Each one stops scoring something the compiler
  leaves no trace of (authored panic messages, a stripped contract's type and
  parameter names, how many times a helper was inlined). They are listed with
  their measured effect in [`docs/scoring_metric.md`](docs/scoring_metric.md).
  The rest of the rise is decompiler work.
- **Held-out structure is low for a reason that is mostly not control flow.**
  Many of those contracts compile library code into the wasm (`alloc`,
  `ark-bn254`, `eth-abi`, OpenZeppelin helpers). We have to emit that code,
  because it is in the binary, but the scorer compares against the contract's
  own source, which never contained it.
- **Unprovable values become `todo!()` holes, never guesses.** There are 3,897
  of them across the 25 held-out contracts. A gap you can see is the design. A
  plausible wrong value that compiles is treated as a bug class, because that
  is the failure mode that gets someone hurt.
- **Behaviour is measured on the reference corpus only.** The harness drives
  `Address`, `String`, `Bytes`, struct and enum parameters and constructors,
  and compares return values, events, auth and storage. It has not yet been run
  on the held-out or third-party sets.
- **Local variable names are gone.** `rustc` deletes them; no decompiler
  recovers them. Bindings get synthesised names.

Which contracts this actually handles — protocol and SDK coverage, what a
stripped contract costs you, and what is untested — is
[`docs/compatibility.md`](docs/compatibility.md).

## What it does today

Eight CLI subcommands. The inspection commands are read-only (stdout only);
`decompile` writes a crate under `--out-dir`, and `score` compares two Rust
sources.

Any subcommand taking a module accepts `-` for stdin, so sordec composes in a
pipeline. `--quiet` silences the pipeline's warnings without hiding errors, and
`sordec completions <shell>` prints a completion script.

| Subcommand | Output | Use case |
|---|---|---|
| `sordec dump-facts <wasm>`  | JSON | What we extracted: imports, exports, decoded Soroban metadata, contract spec, custom sections |
| `sordec dump-ir <wasm>`     | Text or `--json` | Waffle-style CFG/SSA IR with **named host calls** (e.g. `host:l:put_contract_data`) |
| `sordec dump-hir <wasm>`    | Text or `--json` | Structured HighIR: recovered control flow (`if`/`while`/`match`, named match arms, typed panics) plus the Phase-2 semantic operations |
| `sordec dump-wat <wasm>`    | Text | Soroban-**annotated WAT**: flat disassembly with a per-function header block listing the recovered operations (storage tier/key, auth, client calls, typed panics) and each host `call` labeled inline with its friendly name |
| `sordec dump-rust <wasm>`   | Text | Reconstructed Rust (`src/lib.rs`) on stdout — the debug view of the emitter. `decompile` is what writes it to disk |
| `sordec decompile <wasm> --out-dir <dir>` | Files | Run the full pipeline and write a buildable crate: `<dir>/<name>/{Cargo.toml, src/lib.rs}` alongside `<name>.wat`. Refuses to overwrite existing artifacts without `--force`, because the emitted crate is meant to be edited. The path is echoed on stdout; pipeline diagnostics go to stderr |
| `sordec coverage <wasm>`    | Text or `--json` | How much of the contract our pipeline understands: control-flow **structuring** coverage (functions structured, loop shapes, labeled-exit tax), per-pattern recognition (storage tiers, enum keys, TTL, client calls, …), a two-number semantic-recovery headline, host-call recognition %, and recogniser-miss diagnostics |
| `sordec score <reconstructed> <original>` | Text or `--json` | Accuracy of a reconstructed Rust source (file or directory) against the original: four independently-reported categories (interface / structure / semantic / behavior), an overall weighted score, and a pass/fail verdict. `--check-compile` evaluates the compilation *gate* — a real `cargo check`, reported separately: it earns no share of the score but a reconstruction that does not build fails regardless. `--behavior <ORIGINAL_WASM>` measures the behavior category by differential execution against the deployed contract's own wasm; it reports a match rate that always travels with its coverage fraction. Entrypoints it cannot construct arguments for are reported as skipped, with the reason, rather than silently dropped from the denominator. The measuring instrument for the Rust emitter |

What's coming next:

- **Contracts it has never seen.** Neither third-party contract compiles yet
  (15 and 59 errors), and that is the number that matters most.
- **The remaining eight held-out contracts.** Their errors are concentrated:
  `other_custom_types` 33, `import_ark_bn254` 18, `fuzzing` 13, `single_offer`
  9, `account` 8, `alloc` 7, `deep_contract_auth` 1, `mint-lock` 1.
- **Values passed between helpers by pointer.** Unoptimised builds pass storage
  keys and decoded structs through memory, and the decompiler cannot always
  follow them across a call yet. This is most of what still separates
  `mint-lock`, `fuzzing` and `account` from their sources.
- **Behaviour on the held-out and third-party sets**, not just the corpus.

## Quick start

```bash
cargo build --release

# JSON: what's in the contract
./target/release/sordec dump-facts samples/contracts/token-v23/token-v23.wasm | jq .

# Text: the lifted IR with host calls named
./target/release/sordec dump-ir samples/contracts/token-v23/token-v23.wasm | head -40

# Text: Soroban-annotated WAT
./target/release/sordec dump-wat samples/contracts/token-v23/token-v23.wasm | head -40

# Files: decompile to a directory (writes out/token-v23/{token-v23.wat, Cargo.toml, src/lib.rs})
./target/release/sordec decompile samples/contracts/token-v23/token-v23.wasm --out-dir out/

# Coverage report — the headline metric
./target/release/sordec coverage samples/contracts/token-v23/token-v23.wasm

# Score a reconstruction against the original (identity is 1.0)
./target/release/sordec score \
  samples/contracts/token-v23/source/src \
  samples/contracts/token-v23/source/src
```

Sample `coverage` output on the canonical SEP-41 token fixture:

```
coverage report — token-v23.wasm
  catalog:         soroban-env-common 27.0.1
  parse:           ok (0 diagnostics)
  metadata:        present (0 diagnostics)
  lift:            46 functions, 0 with diagnostics  (100.0%)
  host calls:      35 / 35 recognized               (100.0%)
  operators:       1235 total
                     call (import):     35
                     call (local):     116
                     call indirect:      0
                     other:           1084
  structuring:
    functions:      53 / 53 structured        (100.0%)   fallback regions ×0
    loops:          0 / 1 classified          (0.0%)
                    while ×0, do_while ×0, guarded ×0, infinite ×0, unclassified ×1
    switches:       1 match recovered   (dispatch-linked ×0, arms deduped ×1)
    traps:          inlined ×37, duplicated ×0, shared+bindings ×4, panic! ×37, unwrap ×24
    labeled exits:  break ×6, continue ×1   (readability tax; while back edges not counted)
    refinements:    guards ×77, polarity ×0, &&-merge ×0 (blocked ×0), loop tags ×0, copy-loop args ×0
    scope exits:    tail-exit breaks elided ×17, scopes spliced ×2, live labels ×50   (live = a real forward jump remains)
    declutter:      aliases ×75, phis ×529, jumps ×3, returns ×28, traps ×1, chains ×12, dead blocks ×48, dead vals ×68
    treeify:        inline ×565, effect-pinned ×34, residue ×1107
  types:
    typed:          2690 / 2950 bindings          (91.2%)
      known:        1800 (proven: ABI / literal / host identity)
      inferred:     890 (propagated)
    unknown:        260 (honestly undetermined)
  recognition:
    storage:        tiers 11 / 13 resolved     (84.6%)
                    get ×4, set ×4, has ×4, remove ×0, extend_ttl ×2
    enum keys:      12 / 14 named             (85.7%)   ctor ×1
    ttl amounts:    3 / 4 resolved          (75.0%)
    client calls:   no invoke sites
    dispatcher:     no dispatch sites
    auth:           require_auth ×7, for_args ×0, as_curr ×0, addr_conv ×2, admin_gate ×2
    events:         5 published   (flavor split: Phase-3 emit)
    collections:    vec ×1, vec_op ×0, map ×3, map_op ×3, buf_op ×0
    panics:         0 typed   (bare panic!/unwrap: Phase-3)
    wide arithmetic: 0 fused   (deferred: C19)
    val boilerplate: 56 sites collapsed   (object ×5, tag ×30, enc_small ×2, enc_u32 ×14, dec_small ×5, cmp ×0)
  semantic recovery:
    host interactions:  35 / 35 recognized       (100.0%)
    deep facts:         26 / 31 resolved         (83.9%)
    note: these are recognition ratios, not reconstruction accuracy — for the scored AST comparison against source, use `sordec score`
  diagnostics:     162 total (recogniser misses)
                     lift::marshalling_guard_elided (×61)
                     lift::sdk_function_identified (×59)
                     lift::panic_without_error_code (×37)
                     lift::non_constant_durability_arg (×2)
                     lift::unrecognised_storage_pattern (×2)
                     lift::non_constant_ttl_amount (×1)
```

**Reading the headline.** *Host interactions* (100% across all seven
[corpus fixtures](samples/contracts/)) is Phase 2's recognition claim:
every host-boundary call is turned into a named semantic operation.
*Deep facts* (84% on token-v23) is the fraction of finer sub-facts —
storage tiers, enum-key names, TTL amounts, client-call arity, dispatch
cases — the recognisers resolved; each miss is a **sound decline**
carrying a located diagnostic (a polymorphic helper site, an
indirect-call-blocked amount), never a guess. A ratio is shown only
where a pass emits a real miss counter; the other rows are counts with a
note on where their misses would surface. Neither number is the RFP's
contractual accuracy score — that is the structural AST-diff against source,
which `sordec score` computes over the Rust emitter's output.

**Reading the structuring section.** *Functions structured* is 100%
across all seven fixtures (the Phase-3 K3 lock: reducible rustc output
always structures), so the interesting rows are the shape breakdowns.
*Loops* reports how many were proven to a source shape — `while ×N`
means recovered `while` loops; the honest `unclassified ×N` remainder
is loops with per-iteration effectful headers the classifier declines
to reshape rather than guess. *Labeled exits* is a readability-tax
meter, not a recovery claim: fewer `break`/`continue` labels means
source closer to idiomatic Rust. The `declutter` / `treeify` rows are
the structuring precursors (CFG cleanup and inlinability analysis).

## Architecture

Ten-crate Cargo workspace built around three IR layers:

```
WASM bytes
    │
    ▼
┌───────────────────┐
│  WasmFacts        │  parsed WASM + decoded Soroban metadata (sordec-frontend)
└───────────────────┘
    │
    ▼
┌───────────────────┐
│  LiftedIr         │  SSA + CFG, close to WASM operators (sordec-passes / waffle)
└───────────────────┘
    │
    ▼
┌───────────────────┐
│  HighIr           │  structured control flow + recovered Soroban semantics (Phase 2/3)
└───────────────────┘
    │
    ▼
Annotated WAT + reconstructed Rust
```

Each transformation between layers is a `Pass` in a `Pipeline`, with
fixpoint-group support for iterative refinement. The pass infrastructure
follows established disassembler/decompiler patterns
(Ghidra/Hex-Rays/angr).

## Workspace layout

```
crates/
├── sordec-common/    — Shared types: newtype IDs, diagnostics, provenance
├── sordec-ir/        — Three typed IR layers (WasmFacts, LiftedIr, HighIr)
├── sordec-frontend/  — WASM parsing + Soroban metadata (contractspecv0 etc.)
├── sordec-passes/    — Lifter + analysis passes + Soroban host-call catalog
├── sordec-backend/   — Annotated-WAT emitter + Rust source emitter
├── sordec-sigs/      — Masked-fingerprint catalogue for inlined SDK functions
├── sordec-driver/    — Pipeline orchestration + corpus integration tests
├── sordec-score/     — Source-to-source accuracy scorer (`sordec score`)
├── sordec-diffexec/  — Differential execution of both wasms in a Soroban host
└── sordec/           — `sordec` binary + the `sordec::Driver` facade the other nine sit behind
```

Per-crate rustdoc:

```bash
cargo doc --workspace --no-deps --open
```

## Test corpus

[`samples/contracts/`](samples/contracts/) holds seven real-world Soroban
contracts used by the integration test suite, each with pinned source +
toolchain + sha256-verified WASM bytes:

| Fixture | Origin | Size | What it exercises |
|---|---|---|---|
| `hello-add/`           | first-party | 629 B | Minimal `add(u64, u64) -> u64`; Val encoding baseline |
| `token-v22/`           | soroban-examples 22.0.11 | 7.2 KB | SEP-41 token, older SDK, `wasm32-unknown-unknown` |
| `token-v23/`           | soroban-examples 23.0.1  | 8.3 KB | SEP-41 token, canonical fixture |
| `token-v23-stripped/`  | soroban-examples 23.0.1  | 6.0 KB | token-v23 with custom sections removed |
| `timelock/`            | soroban-examples 23.0.1  | 3.7 KB | Time-bounded claimable balance, cross-contract token calls |
| `dex-liquidity-pool/`  | soroban-examples 23.0.1  | 11 KB  | Constant-product AMM, largest fixture |
| `attestation/`         | first-party (SDK 23.5.3) | 2.4 KB | Storage-free; crypto (sha256/keccak256/ed25519) + PRNG + `#[contracterror]` + long `Symbol` |

Verify all seven against their committed sha256s:

```bash
bash tools/verify-fixtures.sh
```

Rebuild any single fixture from its pinned source:

```bash
bash samples/contracts/<name>/build.sh
```

See [samples/contracts/README.md](samples/contracts/README.md) for the
full layout convention and feature-coverage matrix.

## Running the test suite

```bash
bash tools/gate.sh   # the full gate, in order (see below)

# …or step by step:
cargo build --workspace
RUSTFLAGS="-D warnings" cargo check --release --workspace --all-targets  # release-only warnings
cargo test --workspace                                        # ~1,650 tests
cargo clippy --workspace --all-features --all-targets -- -D warnings
cargo doc --workspace --no-deps                               # warning-free
bash tools/verify-fixtures.sh                                 # 7/7 sha256 OK
```

All gates green at every commit on `main`. No CI workflow yet; `tools/gate.sh`
is the contract — it includes a warnings-as-errors *release* build, which
catches warnings the dev-profile clippy run cannot see.

## Phase status

See [PHASE_1.md](PHASE_1.md), [PHASE_2.md](PHASE_2.md), [PHASE_3.md](PHASE_3.md)
and [PHASE_4.md](PHASE_4.md) for the per-phase scope, the verification recipe
(≤ 5 min from a clean clone), and the acceptance evidence.

All four phases are complete on `main` and ship as `v0.1.0-alpha.1`. What
remains is not a missing phase but output quality — see
[Where it actually stands](#where-it-actually-stands) and
[CHANGELOG.md](CHANGELOG.md).

## License

[Apache-2.0](LICENSE).

## Contact

Imran Shaikh — see `Cargo.toml` workspace metadata.
