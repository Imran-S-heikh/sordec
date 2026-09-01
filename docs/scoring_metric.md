# Scoring Metric Definition

**Instrument:** `sordec-score` crate + `sordec score` CLI
**Version:** `score-2.0.0` (M1–M7 built, 2026-07-28; see §6 for limits and §7 for freeze policy)
**Status:** the definition of record. Not awaiting anyone's approval — the accepted SCF
submission specifies no weighting and no per-category threshold, so these are our
choices, disclosed here and stamped into every report (see
`plan/ACCEPTANCE_AUTHORITY.md`).
`score-2.0.0` realigns the metric with the RFP — macro-expanded basis, ABI read
from the contract spec-XDR, per-entrypoint structure. Where it differs from the
`score-1.0.0` definition first circulated, the change and its evidence are
called out in the relevant section.

---

## 1. Purpose

The reconstruction-accuracy acceptance criterion is **≥ 90% AST-diff
similarity** between the decompiled Rust and the original contract source.
This document defines exactly how that number is computed, so that a
self-defined, self-graded threshold is not a matter of interpretation at
review time.

The scorer is deliberately built **before** the Rust emitter. Emitting
compilable Rust is the heaviest remaining deliverable, and building the
measuring instrument first means every increment of the emitter is
measurable against a fixed, agreed ruler from the first line of output.

## 2. What is compared

The scorer is a **source-to-source** comparator: it takes reconstructed
Rust and original Rust, parses both with the `syn` crate, and compares the
two syntax trees. It never inspects the WASM or the decompiler's internal
representation — the instrument is independent of the pipeline it grades.

- Either input may be a single `.rs` file or a source **directory**; a
  multi-file contract is flattened into one logical unit (test modules,
  `use` bookkeeping, and build metadata removed).
- The **basis is per-category**, not global. Under the default
  `rfp-default` profile, **interface and structure are compared on
  macro-expanded sources** (`cargo expand`) — the form the RFP specifies,
  and the only one in which the spec-XDR byte strings are inline — while
  **semantic is compared on the sources as written**. Semantic is the
  deliberate exception: `panic!` and `panic_with_error!` are macros that
  *vanish* under expansion, taking their facts with them, so expanding
  would silently inflate that category's precision.

  The `source-only` profile scores everything as written and needs no
  toolchain; it is also what a machine without `cargo expand` silently falls
  back to. See §9 and the comparability note in §10.

  > **This replaces the `score-1.0.0` rule**, which compared everything
  > pre-expansion on the grounds that expanding "would swamp the diff with
  > generated SDK glue." That concern was real and is now handled directly
  > rather than by avoidance: structure walks *downward* from each ABI
  > entrypoint, and generated glue sits upstream of it — the `__mint` invoke
  > shim calls the user's `mint`, never the reverse. Verified across all six
  > distinct-source fixtures: **no glue is reachable from an entrypoint**,
  > and no denylist was needed.

## 3. The four categories

A single blended tree-edit distance can hide a serious defect (e.g. correct
shape, wrong storage semantics) behind a high aggregate. The score is
therefore split into **four independently reported categories**, each in
`[0, 1]`, combined by a fixed weighted mean:

| Category | Weight | Measures |
|---|---:|---|
| **interface** | 0.30 | The public ABI: entrypoint signatures and `#[contracttype]` / `#[contracterror]` / `#[contractevent]` type shapes. |
| **structure** | 0.25 | Per-entrypoint control-flow skeleton over the reachable call closure (branches, loops, early exits). |
| **semantic** | 0.30 | Recovered Soroban operations (storage with tier + key, authorization, events, cross-contract calls, panics, ledger context). |
| **behavior** | 0.15 | Whether the reconstruction *does* what the original does, by differential execution of both WASMs. |

The weights sum to 1.0 and are frozen with the scorer version. Every report
lists all four sub-scores, so a collapse in any one category is visible and
cannot be masked by the others.

**Compilation is not a category.** It is a pass/fail **gate**, reported
separately: it earns no share of the mean, but a reconstruction that does not
build reports FAIL whatever it scores. Three reasons it is not graded. A binary
flag has no spectrum to grade — one type error and three hundred both fail.
Grading it double-counts, since behavior cannot be observed without it. And
decisively, `todo!()` compiles, so a *scored* compilation category paid 0.15 for
recovering nothing at all. Its diagnostics are still reported, because the error
count is the sharpest available signal of emitter progress; they are simply not
scored.

`behavior` inherited compilation's 0.15 unchanged, so the swap moved no scores.
That weight arguably undersells the dimension the RFP actually asks about, but
re-weighting shifts the other three categories' ratios and is therefore held as
its own explicit change, pending the sign-off in §9.

### Interface
Exact-match **F1** over the union of entrypoint signatures and type shapes.
An item is correct when both sides carry it under the same name with an
equal normalized value. Precision = correct / reconstructed, recall =
correct / original. A missing entrypoint lowers recall; an invented one
lowers precision; a wrong signature lowers both.

### Structure
One skeleton is built per **ABI entrypoint**, covering the closure of code
that entrypoint reaches: each reachable function contributes a preorder token
stream of its control-flow constructs (straight-line code dropped), and the
streams are concatenated in call-graph order. The two sides are compared by
blending a longest-common-subsequence (ordered) similarity with a multiset
similarity. The category score is the mean over the **original's** entrypoints;
an entrypoint the reconstruction does not declare — or declares ambiguously —
scores zero.

The unit is the entrypoint, not the function, because that is what survives
compilation. Internal helper names and boundaries are not in the WASM: rustc
inlines small helpers out of existence, and a decompiler can only invent names
for whatever bodies remain. Scoring per named function measured the binary's
debug info rather than the reconstruction — `token-v23` scored 0.0522 while the
same contract with its name section stripped scored 0.0045, an 11.6× swing on
identical control flow. Per-entrypoint closure scoring reports both as 0.0480.

Consequently the metric is deliberately blind to *decomposition*: merging five
helpers into one entrypoint body, or splitting one into five, compares equal.
Emitting control flow the source does not have still costs full score.

An entrypoint that is straight-line on **both** sides drops out of the mean
entirely — neither penalized nor credited, since there was no control flow to
reproduce. If that is true of *every* entrypoint, the category compared
nothing and is reported **unchecked** rather than a perfect 1.0. Failing to
emit an entrypoint is never "nothing to measure": it scores zero regardless of
whether the original carried control flow, because the absence is itself the
finding.

Two equivalences are applied inside the vocabulary, on the same
survives-compilation rule. `if`, `if let`, and `match` unify as an *n-way
branch*, so an emitter's choice between an `if let … else` and a two-arm
`match` costs nothing; branch *arity* is kept exact, because a `match` compiles
to a jump table whose size is visible. `while`, `for`, and `loop` unify as a
single `loop` token, because all three lower to near-identical counted loops
and the kind cannot be recovered — but loop presence, ordering, and nesting
count in full.

Every structure score is reported alongside a **control-flow token census** —
precision, recall, and the ratio between the two sides' token counts. This
separates two very different situations that one score conflates: control flow
we failed to recover (low recall) and control flow we invented (low precision).
On the current corpus recall runs 0.85–1.00 while precision runs 0.03–0.05:
the reconstruction recovers nearly all the real structure and buries it in
13×–40× more un-elided marshalling. The census also reports the best
Sørensen–Dice attainable at that token ratio, as an indication of how much of
the remaining gap is reachable by improving the reconstruction rather than the
metric.

*Known limitation:* the token stream is flat preorder with no enter/exit
markers, so it records the sequence of constructs but not their containment —
a nested loop and two sequential loops compare equal. Containment does survive
compilation and is a candidate for a future vocabulary revision.

### Semantic
Both sides are reduced to a multiset of recovered Soroban-operation facts,
matched by their canonical identity. The score is the F1 of the overlap:
precision = overlap / reconstructed facts, recall = overlap / original
facts. A storage fact carries its **tier and key**, so a swapped durability
tier or an unrecovered storage key is a genuine miss — this is the category
that moves when authorization is dropped, a tier is swapped, or an event
goes unpublished.

The vocabulary covers *Soroban operations* — storage, authorization, events,
cross-contract calls, ledger context, cryptography, PRNG, and authored panics —
and deliberately excludes **value marshalling**: `Val` encode/decode, tag
checks, and container plumbing (`Vec`/`Map`/`Bytes` construction and access).
An argument-less `panic!()` falls on the same side of that line: it is the
arg-decode trap the compiler inlines out of the SDK, not something the contract
does, and it is excluded symmetrically from both sides. The line follows the
decompiler's own operation taxonomy, and it is what keeps the category
answering "does it do the same things" rather than "does it shuffle bytes the
same way". Marshalling is not thereby unmeasured — it is control flow, so the
structure category counts it and its token census reports it.

### Behavior, and the compilation gate

The tranche text names a *behavioral* comparison, and an AST diff cannot measure
runtime behavior. Behavior is therefore its own category, measured the only way
it honestly can be: **differential execution**. The original WASM and the
recompiled reconstruction are both registered in an in-process Soroban host,
invoked with identical inputs, and their outcomes compared — returned value,
ordered events, authorization tree, storage snapshot.

Note what the source of truth is: the **original WASM**, not the original source.
That choice is what lets the metric work on contracts pulled straight off-chain,
where no source exists — which is most of them, and the ones an auditor most
wants decompiled.

Behavior is the one dimension where 100% is reachable in principle. The other
three fight genuine information loss: rustc deleted the names, the comments and
the source's type structure, and no amount of work brings them back. Behavior
lost nothing — the compiled semantics are all still in the bytes.

The harness lives in `sordec-diffexec` and is wired in (`--behavior <ORIGINAL_WASM>`).
Two rules govern what it may claim.

**Only our own reconstruction scores.** The harness can compare a contract against
itself, against its own recompiled source, or against a deliberately mutated copy.
All three are valuable — they are how the instrument is validated — and none is a
measurement of this decompiler. Every result therefore carries the origin of the
compared side, and only `reconstruction` contributes to the mean. Anything else is
reported in full and excluded, with the reason stated. Letting a calibration figure
through would be self-scoring, the same line T17 held in refusing to count `todo!()`
holes as recovered facts.

**A rate never travels without its denominator.** "99.2% behavioural match" is not a
99.2% result if it was measured over three of thirty entrypoints. The coverage
fraction is a required argument of the constructor, so a score that does not know
what it covered cannot be built, let alone printed.

On the corpus today behavior reports *unchecked* and is excluded from the mean — an
honest hole, not a zero. Two things are missing, and they are different: the emitter
does not yet produce a crate that compiles, so there is nothing to recompile as the
compared side; and driving an entrypoint requires constructing arguments for its
signature, which is not built. The report says which of the two it hit.

Note this is a limit of *coverage*, not of the harness. It is validated without the
emitter, against nine known-answer divergence vectors — one per class it must
detect, including the `x * 4` versus `x << 2` overflow class a competitor shipped —
and against each fixture's own recompiled source.

**Compilation** is the gate in front of it: assemble the reconstructed source
into a scratch crate depending on `soroban-sdk` and run `cargo check`. It is
**opt-in** (`--check-compile`), and has three outcomes. *Passed* and *failed*
speak for themselves; *unchecked* (no toolchain, or a contract-specific
dependency missing offline) never vetoes, because a check that could not run must
not read as one that failed. Overall = weighted mean over the **checked**
categories only.

## 4. Canonicalization

Both sides are normalized identically before comparison, so that
meaning-preserving differences cost nothing:

- **Import qualifiers** — `soroban_sdk::Address` and `Address` compare
  equal; lifetimes are dropped.
- **Formatting** — comparison is structural, so whitespace and layout are
  irrelevant by construction.
- **Local variable names** — the compiler discards local names, so the
  emitter must invent them; the scorer never compares a local identifier.
  A storage key bound to a local (`let key = DataKey::Balance(addr); …`) is
  resolved back to its variant path, so the name chosen for `key` does not
  matter.
- **Parameter names** — not compared; only parameter *types* are. The
  implicit `Env` parameter's name (`e` vs `env`) is not part of the
  contract spec, so penalizing it would be noise.
- **Function / entrypoint names**, by contrast, **are** compared — they are
  the key by which functions and ABI items are matched across the two
  sides, since a contract's entrypoint names are recoverable from its
  export table and spec.
- **Branch form** — `if` / `if let` / `match` are unified (see Structure).

## 5. Calibration evidence

The metric is validated by a calibration battery run on every commit:

- **Identity** — every contract scored against itself is **1.0** across all
  categories. Verified on all seven vendored fixtures that ship source
  (attestation, dex-liquidity-pool, hello-add, timelock, and the token
  contract at SDK v22, v23, and v23-stripped).
- **Invariance** — import-qualifier changes, local-variable renames, and
  reformatting leave the score at ~1.0.
- **Mutation** — a dropped `require_auth`, a swapped storage tier, and a
  dropped event each lower the *semantic* category while leaving interface
  and structure at 1.0; a removed entrypoint lowers *interface and
  structure*; stacked mutations degrade the score monotonically.

A representative cross-version comparison — the SDK v22 token contract
scored as if it were a reconstruction of the v23 contract — yields:

| Category | Score |
|---|---:|
| interface | 0.8901 (entrypoints 0.9231, types 0.8571) |
| structure | 1.0000 (33 original tokens, 33 reconstructed — bloat 1.0×) |
| semantic | 0.9114 (precision 1.00, recall 0.84) |
| **overall** | **0.9299** |

The gap is real ABI and semantic drift between the two SDK versions, not
scorer noise: `transfer` appears as both a missing and an extra entrypoint
(its signature changed), `SetAdmin` is absent from v22, and one event goes
unpublished.

Structure scoring 1.0000 here is worth reading closely, because it is the
control on the whole design. The two versions genuinely have the same
control flow, and the token census now says so directly — 33 tokens on each
side with complete overlap. Under the previous name-keyed algorithm this
number was also 1.0000, but partly by coincidence of matching names; it now
holds for the stated reason and carries the evidence with it.

## 6. Limits, and how to read a score

Written at T24. Every number this metric produces has a shape, and reading it wrong
is easier than measuring it wrong.

### What a low score does and does not mean

The four categories are reported separately precisely so that one cannot mask
another, and they fail for unrelated reasons:

| category | a low score means | it does **not** mean |
|---|---|---|
| interface | the recovered ABI differs from the declared one | the logic is wrong |
| structure | the control-flow skeleton differs in shape or volume | the contract behaves differently |
| semantic | recovered Soroban operations are missing or fabricated | the operations that *are* recovered are wrong |
| behavior | the reconstruction genuinely does something different | anything at all, if it is `unchecked` |

The distinction on the last row is the one that matters most. `unchecked` is not a
bad score; it is the absence of a score, and it renormalizes out of the mean rather
than dragging it down. A category that could not be measured never poses as a
category that measured badly.

### The structure number is small for a reason that is not the metric

Structure sits near 0.05 corpus-wide. That was investigated at M4 and the metric is
not the cause: the emitter produces roughly **24× the control flow** of the original
at 0.85 recall, and token-v23's achievable ceiling under the current dice measure is
about 0.080. Rewriting the metric does not move it — cutting the bloat to ≤1.9×
would take structure to ~0.60. Read a low structure score as "the emitter emits too
much", not as "the comparison is unfair".

### Comparability

A score is reproduced by the triple `(scorer_version, weights_profile,
basis_profile)`, and all three are stamped into every report. Comparing two numbers
that do not share the triple is meaningless. In particular:

- **basis matters a lot.** `rfp-default` scores interface and structure on
  macro-expanded sources and semantic on the sources as written; `source-only`
  scores everything as written. The same reconstruction scores materially
  differently under each. A machine without a toolchain silently falls back to
  `source-only`, which is why the corpus bands double as a fallback alarm: the
  fallback moves hello-add off 0.5455 and breaches its band loudly.
- **weights are ours to set**, are recorded per report, and are *not* frozen. Only
  the built-in default is.

### What is deliberately not measured

- **Local variable names.** rustc deleted them; scoring them would score noise.
- **Comments and formatting.** Same reason.
- **Budget and metering.** `env.budget()` will never match between an original and a
  reconstruction and should not be expected to.
- **Wasm bytes.** Two builds of the *same source* under different rustc versions
  legitimately differ, so byte comparison reports codegen as a finding. Measured at
  T23: even the order of entries within `contractspecv0` varies by rustc, which is
  why ABI comparison is done per entrypoint rather than over the whole section.

### How the instrument is itself validated

Not by inspection. Three suites, each answering a different question:

- **Invariance** — meaning-preserving edits (import qualifiers, local renames,
  reformatting) must cost nothing. `sordec-score/tests/calibration.rs`.
- **Mutation** — a real change must degrade *the right category and no other*, and
  scores must degrade monotonically as mutations accumulate. Same file. Dropping
  `require_auth` hits semantic alone; removing a function hits interface and
  structure.
- **Divergence detection** — for behavior, nine contract pairs differing in exactly
  one observable way, each asserting that its own tuple diverges **and that no other
  tuple does**. `sordec-diffexec/vectors/`. Only the second half of that assertion
  rules out a comparator that flags everything.

A self-comparison suite alone would be insufficient: it can only show the instrument
reports no false differences, which a comparator returning "match" unconditionally
would also pass.

## 7. Versioning and freeze policy

Every report carries the scorer version and its weights profile. The
algorithm and default weights are **frozen** at `score-2.0.0`: a golden
calibration vector pins the exact per-category scores for a fixed input
pair, so any change that could move a score fails the freeze test until the
snapshot is updated in the same change. Once the Rust emitter is first
scored against this metric, that discipline guarantees the acceptance number
is computed the same way at review time as it was when agreed.

`score-2.0.0` is the version under active construction — it realigns the
metric with the RFP (macro-expanded basis, ABI read from the spec-XDR,
per-entrypoint structure). While a version is being built, the convention is
to **re-freeze the golden vector as each definition change lands**, recording
the new numbers and the reasoning in the same commit, rather than bumping the
version per task. The freeze test still fails loudly on every such change;
what it guarantees during construction is that no score moves *silently*.
The version bumps when the definition is settled and signed off.

## 8. Baseline

The prior-generation decompiler's Rust output is the intended
baseline-to-beat. Regenerating it currently requires restoring that older
codebase's toolchain (a transitive dependency no longer compiles under the
current Rust release); the baseline number will be recorded here once that
reference is rebuilt. It does not affect the definition or the calibration
guarantees above.

## 9. Running it

```
# Score a reconstruction against the original (file or source directory):
sordec score <reconstructed> <original>

# Machine-readable report:
sordec score <reconstructed> <original> --json

# Evaluate the compilation gate (requires a toolchain + cached SDK):
sordec score <reconstructed> <original> --check-compile
```

The report gives the overall score, the pass/fail verdict (score against the
threshold, default 0.90, **and** the compilation gate), the gate's own outcome,
and the four category sub-scores with precision/recall and the specific items
missed.

## 10. Choices we made, and why they are ours to make

Nothing here awaits external approval. The accepted SCF submission attaches ≥90% to the
aggregate reconstruction score on agreed vectors and requires a four-category breakdown
to be *shown*; it specifies **no weighting**, **no per-category threshold**, and **no
definition of "behavior"**. The upstream SDF RFP goes further and hands us the vector set
explicitly — "Define a group of test vectors". So the following are decisions, recorded
for the reader, not requests.

1. **Compilation is a gate, not a scored category** (§3). It can veto the verdict but
   earns no share of the mean; `behavior` — differential execution of both WASMs — holds
   the scored slot. Independently corroborated: the submission's completion measures list
   "Generated Rust passes cargo check" under *how to measure completion*, and name only
   interface/structure/semantic/behavior as the breakdown.

2. **The four-category weighting** (§3): interface 0.30, structure 0.25, semantic 0.30,
   behavior 0.15, with the overall figure the weighted mean over the categories actually
   checked. Behavior inherited compilation's weight unmodified so the restructuring moved
   no scores.

   Two consequences worth stating plainly, because they cut against us:

   - At structure's current 0.06, this weighting caps the achievable aggregate at
     **0.72** even with the other three perfect. Reaching 0.90 needs structure at
     **~0.60**.
   - Lowering structure's weight would raise that ceiling. We have not done so, and the
     reason is the standing rule: make the instrument fair and adjustable, never tuned to
     hit a number. Structure at 0.06 reflects a real defect — the emitter produces 24×
     the control flow of the original — and the honest fix is the emitter.

   The record supports that this is not a slogan. M4's structure rebuild *lowered* the
   aggregate (0.3896 → 0.3850) because the metric it replaced was measuring the binary's
   name section, and T18's semantic fix reported *worse* recovery than the bug it removed.

3. **The vector set.** Currently the seven contracts under `samples/contracts/`, spanning
   soroban-sdk 21/22/23 — a multi-version corpus, which has already earned its keep: T16
   found an event-recognition bug visible only on the v22 API. `token-v23-stripped` is a
   name-stripped build of `token-v23` and exists to test name-independence, not recovery;
   it is also permanently excluded from behaviour, having no metadata sections for the
   host to load.

Anyone reviewing a number from this instrument should read §6 first.
