# Phase 3 — Control-Flow Structuring + Annotated WAT

**Status:** ✅ Complete
**Delivers:** SCF **Tranche 2** (Testnet) — the second of three tranches.
**Date:** July 2026
**Cut:** `main` at the Phase 3 closeout commit.

This document records what Phase 3 was scoped to deliver, what landed, and
how to verify it end-to-end from a clean clone. It mirrors
[PHASE_1.md](PHASE_1.md) and [PHASE_2.md](PHASE_2.md); the same "no external
services, no secrets" verification contract holds.

---

## Phase 3 scope

Per the official tranche roadmap, **Tranche 2** restructures the typed IR
into a program with **explicit control flow**, and emits **human-readable,
Soroban-annotated WAT**. Phase 2 already delivered the typed, ANF-style IR
with recovered semantics (the first half of Tranche 2); Phase 3 completes it.

In development-proposal terms, Phase 3 delivers:

- **D3.3 — control-flow structuring.** Recover `if` / `while` / `match` /
  `return` from the CFG + SSA, so the IR is a structured program rather than
  a basic-block soup.
- **D3.4 — annotated WAT emitter.** Emit flat WebAssembly text with the
  recovered Soroban semantics attached as annotations.
- **D3.6 (WAT half) — the `decompile` CLI.** One command that runs the whole
  pipeline and writes the annotated WAT to disk. (Its Rust-source half is
  Phase 4.)

D3.1 (boundary lowering) and D3.2 (the HighIR type system) landed in Phase 2.
**The Rust source emitter (D3.5) and the ≥90% reconstruction score are
Tranche 3 / Phase 4**, not Phase 3.

### Built ahead of schedule

The **accuracy-scoring instrument (D4.1)** — a Tranche 3 deliverable — was
built early, in Phase 3, so the Phase-4 Rust emitter is measurable against a
fixed, versioned ruler from its first line of output. It is a bonus here, not
a Tranche-2 requirement.

---

## What landed

### D3.3 — Control-flow structuring

| Piece | What landed | Anchor |
|---|---|---|
| Region v2 IR | `Basic`/`Scope`/`Break`/`Continue`/`Loop`/`Switch`/`Return`/`Panic` regions with phi transfers | `3aac128` |
| CFG substrate | dominators / RPO / loop forest / reducibility for `LiftedFunction`, cross-checked against `waffle` on all 7 fixtures | `103fae1` |
| De-cluttering | param prune, copy-prop, jump-threading, return-funnel inlining, pure-only DCE (3,404/3,648 params pruned corpus-wide) | `42c54c2`, `04366b3`, `a8b2feb` |
| Structurer | a Beyond-Relooper port to Region v2; **`Unstructured` = 0 on every fixture** | `1fcd274`, `50805af` |
| Skeleton cross-check | `loop`/`br_table` nesting matches a `wasmparser` rescan of the original binary, 7/7 | `e14dd19` |
| Structured renderer | `dump-hir` renders Rust-native labeled scopes, `while`, `match` with named arms, typed panics | `5673795`, `6834010` |
| Refinement | guard-clause recovery (467 hoists), bounded trap duplication, loop classification (26/32 `while`), dispatcher→`match`, typed `panic!`/`unwrap` (242 bare + 85 unwrap), condition-polarity normalization, switch dedup | `05b6911`, `f194f39`, `fcf7005`, `894cb74`, `f238102`, `a6e0cb5`, `029ea59`, `96ab5f6`, `65c5245` |

The refinement stage is where the output starts to resemble source: a
seven-level nested guard cascade in timelock's `claim` flattens to top-level
guard clauses; the SDK's symbol-dispatch chains render as `match` on the
recovered enum (`TimeBoundKind::Before`).

### D3.4 — Annotated WAT emitter

| Piece | What landed | Anchor |
|---|---|---|
| Function spans | per-function code-section byte ranges recorded in `WasmFacts` | `c4f877f` |
| Emitter | `emit_annotated_wat` — flat WAT (numeric) + three tiers of annotation: a per-function header block listing every recovered fact, an inline friendly-name on each host `call`, and a module-header banner | `79dee91` |
| Anchoring | functions located by byte-range offset, host-call sites by printed callee index — **sound, no ordinal guessing** | `79dee91` |
| Acceptance gates | the annotation extractor + the redefined acceptance suite, as tests on all 7 fixtures | `dd74fa5` |
| `dump-wat` | a debug subcommand that prints the annotated WAT to stdout | `c84749c` |

**Acceptance was redefined, and the redefinition is encoded as passing
tests.** A byte-for-byte round-trip is *provably impossible* — re-encoding
LEB128 integers is not bit-stable — so "correct output" is defined as five
checks that hold 7/7: the emitted WAT **parses**; **print∘parse** reaches a
fixpoint; it is **structurally equal** to the original (opcode/section counts,
with the three Soroban custom sections byte-identical); the annotation
extractor **losslessly** recovers the fact set the emitter put in; and
emission is **deterministic**. This redefinition is submitted to ABS for
sign-off (see *Known limitations*).

### D3.6 (WAT half) — the `decompile` CLI

| Piece | What landed | Anchor |
|---|---|---|
| `Driver` | the whole pipeline wired end-to-end (parse → lift → structure → refine → emit) behind one call | `95c1861` |
| `decompile --out-dir` | writes `<dir>/<name>/<name>.wat`; the Rust `<name>.rs` joins it in Phase 4 | `1321271` |

### D4.1 (ahead of schedule) — the accuracy scorer

| Piece | What landed | Anchor |
|---|---|---|
| `sordec-score` + `sordec score` | a pure source-to-source (`.rs` × `.rs`) comparator; parses both sides with `syn`, no coupling to the pipeline | `84cb1f7`, `29177ee` |
| Four categories | interface (ABI F1), structure (control-flow-skeleton similarity), semantic (recovered-fact precision/recall), compilation (opt-in `cargo check`) | `b175a7f`, `655eba8`, `7ea1198`, `ecb6c32` |
| Calibration + freeze | identity / invariance / mutation battery; a versioned, golden-snapshot-frozen metric | `956c388`, `45efe9b`, `ce72834` |

### D3.2 (completion) — general type recovery

Tranche 2 asks for a **typed**, AST-like program. The type *system*
landed in Phase 2 (`IrType` with explicit `Known` / `Inferred` /
`Unknown` certainty and provenance); this completes it with the general
**type-propagation pass** that populates it — so the IR is typed in fact,
not only in capability, and beyond the public ABI signatures.

| Piece | What landed | Anchor |
|---|---|---|
| `type-infer` pass | seeds from the `contractspecv0` ABI, integer/bool literals, and the host-call ABI tables (`val_abi`); propagates through `Use`, arithmetic, comparisons, phis, conversions, and returned values to a monotonic fixpoint | `cf4b96a` |
| Host-call args + conversions | `require_auth` → `Address`, cross-contract → callee `Address` + `Symbol`, `val`/`obj` conversions → their scalar operand type | `533ce01` |
| Certainty discipline | `Known` only from a proven source; propagation yields `Inferred`; genuine ambiguity stays `Unknown` — no guessing, every update `TypePropagation`-provenance-tracked | `cf4b96a` |
| Typedness metric | `sordec coverage` gains a `types:` section (text + JSON): the `Known` / `Inferred` / `Unknown` census + typed ratio per contract; per-fixture floors locked in the coverage matrix | `533ce01` |

**Binding typedness rose from ~7% to 54–78% per fixture** (token-v23 67%,
timelock 70%, attestation 78%; ~62% corpus-wide). The proven-`Known` count
runs into the hundreds per contract — far past the dozen-odd ABI
parameters — which is the "typed beyond the public signatures" bar.
Reproduce: `sordec coverage samples/contracts/token-v23/token-v23.wasm`
(the `types:` section).

---

## Verification recipe (≤ 5 min on a laptop)

```bash
# 1. Clone (clean) and build
git clone git@github.com:Imran-S-heikh/sordec.git && cd sordec
cargo build --release          # ~1–2 min, no warnings

# 2. Full local gate (build · release-warnings · test · clippy · doc · fixtures)
bash tools/gate.sh             # every step must pass

# 3. Deliverable 1 — structured control flow (dump-hir)
./target/release/sordec dump-hir samples/contracts/token-v23/token-v23.wasm | less
# Expect: `if` / `while` / `match { … => … }` / labeled scopes, not basic blocks

# 4. Deliverable 2 — annotated WAT to disk
./target/release/sordec decompile samples/contracts/token-v23/token-v23.wasm --out-dir out/
# Writes out/token-v23/token-v23.wat: per-function header blocks with recovered
# signatures + facts, each host `call` labeled inline

# 5. The scoring instrument (built ahead) — identity is 1.0
./target/release/sordec score \
  samples/contracts/token-v23/source/src \
  samples/contracts/token-v23/source/src
# Expect: overall 1.0000, all categories 1.0
```

`tools/gate.sh` runs the whole acceptance gate, including a
warnings-as-errors **release** build — a step added in this phase after the
closeout audit found a warning that only appears in release (clippy runs in
the dev profile and cannot see it).

---

## Acceptance evidence

### Spec verdict — Tranche 2 deliverables

| Deliverable | Status | Evidence |
|---|---|---|
| Typed IR (D3.2) | ✅ | general type propagation; binding typedness ~7% → 54–78% per fixture (beyond ABI signatures); `sordec coverage` `types:` census, floors locked |
| Explicit control flow (D3.3) | ✅ | `dump-hir` renders `if`/`while`/`match`/`return`; `Unstructured = 0` locked on all 7 fixtures; skeleton parity vs the original binary |
| Annotated WAT (D3.4) | ✅ | `decompile` writes annotated WAT; the five-check acceptance suite passes 7/7 |
| `decompile` CLI, WAT half (D3.6) | ✅ | one-command pipeline → `<name>.wat` on every fixture |
| Accuracy scorer (D4.1, ahead) | ✅ | four categories; identity 1.0 on all 7 source fixtures; frozen + versioned |

### Test suite — 869 tests passing (0 failures)

All pass under `cargo test --workspace` from a clean clone; clippy clean under
`--all-features --all-targets -- -D warnings`; `cargo doc` builds warning-free;
the release build is warning-free under `-D warnings`. The scorer's
`cargo check` harness tests are `#[ignore]`d (they shell out to the toolchain);
run them with `cargo test -p sordec-score -- --ignored`.

### Corpus — structuring coverage (7 fixtures)

| Fixture | Fns | Structured | Loops classified | Switches |
|---|---:|---:|---:|---:|
| token-v23 | 46 | 100% | 6 / 7 | 2 |
| token-v22 | 48 | 100% | 6 / 7 | 2 |
| timelock | 18 | 100% | — | 1 (dispatch→`match`) |
| dex-liquidity-pool | 50 | 100% | (loop) | — |
| attestation, hello-add, token-v23-stripped | — | 100% | — | — |

`Unstructured = 0` and `functions_structured == functions_total` are locked
per fixture. Corpus totals: 26 `while` loops recovered, 6 honestly
`Unclassified`, 7 switches.

### The scorer, calibrated

Identity is **1.0** across all seven source fixtures. Mutations degrade the
*right* category (a dropped `require_auth`, a swapped storage tier, or a
dropped event lowers *semantic*; a removed entrypoint lowers *interface* and
*structure*) and do so monotonically. A representative cross-version run — the
SDK v22 token contract scored as if it reconstructed v23 — is **0.9385**
(interface 0.9143, structure 1.0, semantic 0.9114); the gap is real ABI and
semantic drift between the versions.

---

## Demo — structured output

`dump-hir` on token-v23 renders explicit control flow (lightly excerpted):

```
match v6 {
  1 => { … if v29 { … } }
  2 => { … if v40 { … } }
  _ => { … }
}
'bb6: while (ne v14, 24i32) { … }
```

And `decompile` produces annotated WAT whose per-function header carries the
recovered signature and facts:

```
;;   fn balance(id: Address) -> i128
;;   fn transfer(from: Address, to: Address, amount: i128) -> ()
```

---

## Known limitations (honest scope acknowledgement)

What Phase 3 does **not** do, and what is honestly imperfect. None is a silent
gap; each carries an in-code note or a surfaced diagnostic.

**Structuring — honest edges (not defects):**

| Item | Status |
|---|---|
| 6 loops stay `Unclassified` | the classifier requires a pure-total header; per-iteration-call headers (mid-test loops) are left honest rather than guessed |
| `DoWhile` / `Infinite` / `GuardedDoWhile` loop kinds | defined but never emitted — no corpus witness, so the classifier does not invent them |
| Trivial `&&`-merge | the pass is real but measured **zero** on the corpus (guard-clause hoisting dissolves the target shape first); kept for real-world growth |
| 2 switch-default traps | stay `unreachable` (exhaustiveness traps with no recoverable panic) |
| Some comparisons render `<unrecovered Comparison>` | the `if` is structured; the comparison *operator* is not always recovered (a Phase-2/4 semantic concern, surfaced, not hidden) |
| Deep-fact resolution ~75% on token-v23 | polymorphic-helper storage-tier / enum-key sites stay a typed `Unknown` with a diagnostic — a sound decline, never a guess |

**→ Phase 4 (Rust emit + accuracy report):**

| Item | Why it waits |
|---|---|
| Rust source generation (D3.5) + the Rust half of `decompile` | the emitter is Phase 4 |
| `for` / iterator-loop recovery | needs induction-variable recovery; a loop-heavy corpus fixture is deferred to land with it |
| The ≥90% reconstruction report | needs the Phase-4 emitter to score against |
| Scorer: `--spec <wasm>` interface anchor; differential-execution category; prior-generation baseline | the spec anchor and true-behavior comparison are Phase-4; the legacy baseline needs that older toolchain restored (its dependency tree no longer builds under current Rust) |

---

## Two acceptance re-definitions flagged for ABS

Both are prepared; sending is Imran's call.

1. **WAT acceptance** — a byte round-trip is provably impossible (LEB128
   re-encoding), so acceptance is the five-check suite above. The text is
   ready for ABS sign-off before the Tranche-2 review.
2. **The scorer's behavior → compilation re-scope** — an AST diff cannot
   measure runtime behavior, so the "behavior" category is recompilation
   against `soroban-sdk`, with differential execution as a Phase-4 extension.
   A standalone metric-definition write-up is prepared for the ABS packet.

---

## Reproducibility

Every number in this document is reproducible from a clean clone of `main` at
the Phase 3 cut. If a later commit changes a number, this document is updated
in the same commit; PHASE_3.md is pinned to the cut, not to a moving `main`.
