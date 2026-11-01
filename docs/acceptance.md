# Acceptance: the accuracy criterion and where sordec stands

This page answers one question: does sordec meet the accuracy criterion it was funded
against, and what else was measured. Scorer version `score-2.2.0`. The reference-set
numbers are those of [`benchmarks/report.md`](benchmarks/report.md) (regenerated
2026-10-31; the reconstructions have not changed since); every other set was measured
2026-11-01 on commit `3b78442`, the `v0.1.0` code.

**Short answer.** On the agreed test contracts, yes: the aggregate score is **0.9359**
(0.9366 with behaviour included) against a bar of 0.90, and all seven reconstructions
build. Five of the seven clear 0.90 on their own; two do not. On contracts sordec was
not developed against the scores are lower: **0.79** on 25 of Stellar's own example
contracts, and **0.53** on two third-party contracts. The last is the honest figure
for "a contract you hand it today". Of the 87 contracts measured, 85 build.

| What the submission asks for | Evidence | Status |
|---|---|---|
| Generated Rust passes `cargo check` on the benchmark contracts | 7 of 7 build (§3) | met |
| The comparison tool outputs per-contract and aggregate scores | `sordec score`; [`benchmarks/report.md`](benchmarks/report.md) | met |
| Published report shows ≥90% on agreed vectors, with the category breakdown | 0.9359 aggregate; four categories per contract (§3) | met |

## 1. The criterion

It comes from our accepted Stellar Community Fund submission
([communityfund.stellar.org/submissions/recZfT9q0kYI6zjkE](https://communityfund.stellar.org/submissions/recZfT9q0kYI6zjkE),
login required):

> **Primary acceptance metric:** ≥90% reconstruction score on agreed vectors, with
> category breakdowns (interface / structure / semantic / behavior).

Tranche 3 lists an "AST-comparison pipeline (macro-expanded + canonicalized) for source
vs reconstructed Rust" as a deliverable, with these completion measures:

> - Generated Rust passes `cargo check` on benchmark vectors
> - AST-comparison tool outputs per-contract and aggregate scores
> - Final published report shows ≥90% on agreed vectors with the category breakdown
>   (interface / structure / semantic / behavior)

<!-- CHECK: quoted from our transcription of the submission (fetched 2026-07-18). A
second internal copy reads "and category breakdown" where this one reads "with the
category breakdown". Compare with the live page. -->

The submission answers Stellar's original request for proposals, which asks the project
to "Define a group of test vectors where the tool should reconstruct the code as close
to the source as possible (at least 90% accuracy … through an algorithmic assessment of
the AST of the decompiled source vs original source)".

What the submission leaves open, and how we read it:

- **What the 90% attaches to:** the aggregate on the agreed vectors. No threshold is set
  for any single category or contract; the breakdown must be *shown*, not cleared.
- **The weights:** none are specified, so they are ours to choose and to disclose.
  Every report records them.
- **What "behavior" means:** the word appears once, as a category name. We measure it
  by running both programs (§2).
- **Which contracts:** not named; the RFP asks us to define them. Ours are the seven in
  [`samples/contracts/`](../samples/contracts/), published with the scoring rules
  ([`scoring_metric.md`](scoring_metric.md) §10, item 3).

## 2. How it is measured

The scorer parses the reconstructed Rust and the original Rust source into syntax
trees and compares them. It never looks at the WASM or at the decompiler's internals,
so it cannot be tuned to flatter the pipeline it grades. Full definition:
[`scoring_metric.md`](scoring_metric.md).

| Category | Weight | The question it answers |
|---|---:|---|
| Interface | 0.30 | Are the public functions and declared types the same? |
| Structure | 0.25 | Does each public function have the same control-flow shape (branches, loops, early exits)? |
| Semantic | 0.30 | Does it do the same Soroban operations: storage (with tier and key), authorisation, events, cross-contract calls, errors raised? |
| Behaviour | 0.15 | Run the original WASM and the recompiled reconstruction on the same inputs. Do they return, emit, authorise and store the same things? |

- **One score per contract** is the weighted mean of the categories that could be
  measured on it. A category with nothing to compare (no branches on either side, say)
  is left out, not counted as zero or as a pass. The aggregate is the plain mean of the
  seven contract scores.
- **The weights are fixed** in the `rfp-default` profile and frozen with the scorer
  version: a test pins exact scores for a fixed input, so any rule change fails it
  until the new numbers are recorded in the same commit. Every report stamps the scorer
  version, weights profile and comparison form (here `score-2.2.0`, `rfp-default`,
  `rfp-default`).
- **Macros are expanded first**, as the submission specifies. Soroban's `#[contract]`
  macros generate code at build time; `cargo expand` writes it out, so the comparison
  sees the program the compiler saw. Interface and structure are compared this way;
  semantic uses the source as written, because expansion erases `panic!` and its facts.
- **Meaning-preserving differences cost nothing**: import paths, formatting, local
  variable names, parameter names (only parameter types are compared).
- **`cargo check` is a gate, not a score.** A reconstruction that does not build fails
  whatever it scores. It earns no share of the mean because a `todo!()` placeholder
  compiles, so a scored build check would pay out for recovering nothing.

## 3. Result on the agreed vectors

| Contract | SDK | Interface | Structure | Semantic | Overall (AST) | Behaviour | With behaviour | Builds |
|---|---|---:|---:|---:|---:|---:|---:|---|
| hello-add | 21.7.7 | 1.0000 | n/a | n/a | 1.0000 | 1.0000 | 1.0000 | yes |
| token-v22 | 22.0.11 | 0.9286 | 0.9724 | 0.9286 | 0.9415 | 1.0000 | 0.9503 | yes |
| token-v23 | 23.0.1 | 0.7500 | 0.9724 | 0.9286 | **0.8784** | 1.0000 | 0.8967 | yes |
| token-v23-stripped | 23.0.1 | 0.6429 | 0.9119 | 0.9286 | **0.8228** | 0.6055 | 0.7902 | yes |
| timelock | 23.0.1 | 1.0000 | 0.9286 | 1.0000 | 0.9790 | n/a | 0.9790 | yes |
| dex-liquidity-pool | 23.0.1 | 1.0000 | 0.7599 | 1.0000 | 0.9294 | 1.0000 | 0.9400 | yes |
| attestation | 23.5.3 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | yes |
| **Aggregate** | | 0.90 | 0.92 | 0.96 | **0.9359** | 0.93 (6 of 7) | **0.9366** | **7 of 7** |

"Overall (AST)" combines the first three categories, reweighted to sum to one; it is
the headline because it is comparable with every earlier measurement. Both aggregates
clear 0.90. Source: [`benchmarks/report.md`](benchmarks/report.md) and
[`report.json`](benchmarks/report.json).

**Two contracts are under 0.90 on their own.** The criterion attaches to the aggregate,
but both are worth reading:

- **token-v23 (0.8784).** The loss is in interface (0.75). The reconstruction declares
  eight types the contract's own files do not: seven event types and `TokenMetadata`.
  They are real types in the binary's interface description, but they are defined in
  the `soroban-token-sdk` library the contract imports, so its source never contains
  them. Structure, semantic and behaviour are 0.97, 0.93 and 1.00.
- **token-v23-stripped (0.8228).** The same contract with every metadata section
  removed, so no type or parameter names are left to recover. It exists to prove that
  recovery does not depend on names. Its behaviour (0.61, measured against
  `token-v23`'s identical code) is a real difference: return values match on 168 of
  176 calls but storage on only 28, because the reconstruction lays out the allowance
  storage key differently and every storage snapshot after that differs.

Two more cells need a word. **hello-add's 1.0000 rests on interface and behaviour
alone**: one function, no branches, no Soroban operations, so structure and semantic
have nothing to compare (the report prints 0.0000 there, noted "nothing to measure").
**timelock's behaviour is not measured**: every call the harness made failed the same
way on both sides, so nothing was compared. It is reported as missing, not as a pass.
**timelock was 1.0000 until 2026-10-31**, when a value chosen between two others began
printing as the `if`/`else` it is (`if kind == After { ts >= t } else { ts <= t }`)
instead of a gap. That is the source's own logic, but in the source it sits in a helper
rustc inlined, so the scorer now sees a branch the source's `claim` does not have.

**What behaviour measures.** Both WASMs are loaded into a Soroban host and called with
the same inputs; return values, events in order, the authorisation tree and storage are
compared. Calls where both sides fail identically are set aside, since they show
nothing either way. So where a reconstruction still contains `todo!()`, a placeholder
that crashes beside an original that also fails goes uncounted: behaviour on such code
is an upper bound.

**Builds.** All seven pass `cargo check`, run on each decompiled crate exactly as
`sordec decompile` writes it, manifest included. The committed report records this in
its `builds` column, and [`tools/measure.sh`](../tools/measure.sh) (§6) does the same
for every other set. Independently, the behaviour harness compiles every reconstruction
to WASM and runs it, which it could not do for a crate that does not build.

## 4. What else we measured, and why

The reference set is what sordec was developed against, so it is the most flattering
number. Two more sets test it on code it was not shaped around. From least to most
flattering:

| Set | Contracts | Build | Score |
|---|---:|---|---:|
| Authored treasury, written for sordec (§4 below) | 1 | 1 of 1 | 0.5677 |
| Third-party contracts, never seen during development | 2 | 1 of 2 | 0.5277 |
| Stellar's `soroban-examples`, multi-contract folders | 13 | 12 of 13 | 0.6643 |
| Stellar's `soroban-examples`, single-contract folders | 25 | 25 of 25 | 0.7915 |
| soroban-sdk 26.0.1's own test contracts | 39 | 39 of 39 | not scored |
| Reference set (the agreed vectors, §3) | 7 | 7 of 7 | 0.9359 |

**The authored treasury** ([`samples/authored/`](../samples/authored/)) is a 556-line
contract we wrote from Stellar's documentation to cover the everyday features: all
three storage tiers, auth, events, errors, custom types, a token call, an upgrade. It
was measured once before any work on it (34 compile errors). It now builds, but every
rebuilt function starts at a stack-pointer setup sordec does not recover, so its
constructor panics and behaviour is 0 of 16 entrypoints. Its score (interface 1.00,
structure 0.17, semantic 0.75, behaviour 0.00) is the honest one for a reconstruction
that compiles but does not run. Since work was done with it in view, it no longer
measures how a new contract would fare.

**Third-party contracts.** OpenZeppelin's `merkle-voting` scores 0.4034 and Phoenix's
`vesting` 0.6519. `merkle-voting` builds; `vesting` has 6 compiler errors left. `merkle-voting` is 90
lines of source over OpenZeppelin's library, so nearly all of its binary is library
code its source never shows (§5). `vesting` is mostly self-contained, so its gap is the
decompiler's own. Behaviour has not been run on this set.

**Stellar's example contracts** (SDK 27, `soroban-examples` commit `1f5aeb5`). The three
already in the reference set (token, timelock, liquidity pool) are left out. These were
kept out of development at first and have since been used to find bugs, so they are no
longer strictly unseen. By category: interface 1.00, structure 0.33, semantic 0.85;
structure is low mostly because of library code (§5). All 25 build. Behaviour cannot be
measured here yet: these are built for Soroban protocol 27 and the execution harness
hosts protocol 23. Of the 13 multi-contract examples (contracts that import or deploy
one another) score 0.6643; only `privacy_pools` does not build (1 error).

**The SDK's own test contracts** are small, one feature each, so a mean score says
little; they are measured for builds and gaps (343 across the 39).

**Part of the rise is the ruler, not the decompiler.** At the first alpha release the
reference set scored 0.61. About 0.08 of the rise to 0.94 came from the six rule
changes in `score-2.1.0`, each of which stops scoring something the compiler leaves no
trace of (an authored panic message, a stripped contract's type names, how many times a
helper was written out). `score-2.2.0` did not move the reference set. On the 25 Stellar
examples the mean rose from 0.757 (2026-10-08) to 0.7915: about 0.011 is `score-2.2.0`'s
two rule changes, 0.009 more is decompiler work on one contract's storage keys that only
counts under the first of them, and the rest is decompiler work. Every rule change is
listed with its measured effect in
[`scoring_metric.md` §7](scoring_metric.md#7-versioning-and-freeze-policy).

## 5. What the number does not say

- **Unresolved values are shown, never guessed.** Where sordec cannot prove what a value
  is, it writes `todo!()` in its place. There are 5,816 across the 87 contracts and
  3,165 across the 25 Stellar examples; 2,073 of those are in `import_ark_bn254`, which
  compiles an elliptic-curve cryptography library into the contract. The reference set
  has 80, in three contracts; timelock scores 0.9790 with 6, because they sit in memory
  bookkeeping none of the four categories measures. A gap you can see is the design: a plausible wrong value that
  compiles is the failure that hurts an auditor.
- **Library code is in the binary but not in the source.** Rust compiles the libraries a
  contract uses into its WASM, so a faithful reconstruction has to emit that code. The
  yardstick is the contract's own source, which never contained it, so it counts
  against the score. This is most of the gap on `merkle-voting`, on `import_ark_bn254`
  and on structure across the Stellar examples, and it is token-v23's eight extra types.
- **Local variable names cannot be recovered** by any tool: the compiler deletes them.
  sordec invents names and the scorer does not compare them. Comments and formatting
  are likewise gone and not measured.
- **A score is not a proof of equivalence.** Behaviour, the one category that runs code,
  is measured only on the reference set and the treasury, and only on the inputs the
  harness generates.
- **Compiling is not running.** A `todo!()` compiles and panics when reached, which is
  why the build check is a gate and not a share of the score.

## 6. How to reproduce every number

```bash
cargo build --release
bash tools/setup-toolchains.sh   # cargo expand, and the toolchain behaviour recompiles with

# Reference set (§3): check each score against its recorded band, then rewrite
# docs/benchmarks/report.{md,json} with behaviour included
cargo test --release -p sordec --test benchmark
SORDEC_BENCH_WRITE=1 cargo test --release -p sordec --test benchmark -- --ignored generate_report --nocapture
```

**Stellar examples (§4).** [`tools/build_heldout.sh`](../tools/build_heldout.sh) builds
the 25. Both the examples' commit and rustc 1.98.1 are pinned; either one moves scores.

```bash
git clone https://github.com/stellar/soroban-examples ~/.cache/soroban-examples
git -C ~/.cache/soroban-examples checkout 1f5aeb5
RUSTUP_TOOLCHAIN=1.98.1 tools/build_heldout.sh ~/.cache/soroban-examples ~/.cache/sordec-heldout
SORDEC_HELDOUT_DIR=~/.cache/sordec-heldout \
  cargo test --release -p sordec --test heldout_bench -- --ignored --nocapture
```

The 13 multi-contract examples are built by
[`tools/build_examples_extra.sh`](../tools/build_examples_extra.sh) from the same
checkout, into the same layout:

```bash
tools/build_examples_extra.sh
SORDEC_HELDOUT_DIR=~/.cache/sordec-examples-extra \
  cargo test --release -p sordec --test heldout_bench -- --ignored --nocapture
```

**Third-party contracts (§4).** [`tools/build_unseen.sh`](../tools/build_unseen.sh)
clones both projects at pinned commits and builds them. The run prints the scores and
then reports a failure, because its guard on the mean is set for the Stellar examples
(0.75 to 0.80); the printed table is the measurement.

```bash
tools/build_unseen.sh ~/.cache/sordec-unseen
SORDEC_HELDOUT_DIR=~/.cache/sordec-unseen \
  cargo test --release -p sordec --test heldout_bench -- --ignored --nocapture
```

**One contract by hand**, with the build check and behaviour:

```bash
./target/release/sordec decompile contract.wasm --out-dir out/
./target/release/sordec score out/contract/src original/src --json
./target/release/sordec score out/contract/src original/src --check-compile
./target/release/sordec score out/contract original/src --behavior contract.wasm
```

The build and gap counts in §3 and §4 come from
[`tools/measure.sh`](../tools/measure.sh), which decompiles every set (the SDK 26 set is
built by [`tools/build_sdk_tests.sh`](../tools/build_sdk_tests.sh); the treasury is in
the repository) and runs `cargo check` inside each crate `sordec decompile` writes:

```bash
tools/measure.sh --table
./target/release/sordec decompile samples/authored/treasury/treasury.wasm --out-dir out/
./target/release/sordec score out/treasury samples/authored/treasury/source/src \
  --behavior samples/authored/treasury/treasury.wasm
```

A comparison with soroban-ret, under its scorer and ours, is in
[`benchmarks/comparison.md`](benchmarks/comparison.md). Which SDK and protocol versions are covered, and what a
stripped contract costs, is in [`compatibility.md`](compatibility.md).
