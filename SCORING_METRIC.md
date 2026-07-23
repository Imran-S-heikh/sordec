# Scoring Metric Definition

**Instrument:** `sordec-score` crate + `sordec score` CLI
**Version:** `score-1.0.0` (frozen 2026-07-23)
**Status:** definition submitted for ABS sign-off ahead of the tranche review.

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
- Comparison is **pre-expansion**: contract macros (`#[contract]`,
  `#[contractimpl]`, `#[contracttype]`) are compared as written, not after
  macro expansion — expanding them would swamp the diff with generated SDK
  glue.

## 3. The four categories

A single blended tree-edit distance can hide a serious defect (e.g. correct
shape, wrong storage semantics) behind a high aggregate. The score is
therefore split into **four independently reported categories**, each in
`[0, 1]`, combined by a fixed weighted mean:

| Category | Weight | Measures |
|---|---:|---|
| **interface** | 0.30 | The public ABI: entrypoint signatures and `#[contracttype]` / `#[contracterror]` / `#[contractevent]` type shapes. |
| **structure** | 0.25 | Per-function control-flow skeleton (branches, loops, early exits). |
| **semantic** | 0.30 | Recovered Soroban operations (storage with tier + key, authorization, events, cross-contract calls, panics, ledger context). |
| **compilation** | 0.15 | Whether the reconstruction compiles against `soroban-sdk`. |

The weights sum to 1.0 and are frozen with the scorer version. Every report
lists all four sub-scores, so a collapse in any one category is visible and
cannot be masked by the others.

### Interface
Exact-match **F1** over the union of entrypoint signatures and type shapes.
An item is correct when both sides carry it under the same name with an
equal normalized value. Precision = correct / reconstructed, recall =
correct / original. A missing entrypoint lowers recall; an invented one
lowers precision; a wrong signature lowers both.

### Structure
Each function is reduced to a preorder token stream of its control-flow
constructs, straight-line code dropped. Two functions are compared by
blending a longest-common-subsequence (ordered) similarity with a multiset
similarity; the category score averages over the union of function names,
so a missing or invented function contributes zero. `if`, `if let`, and
`match` are unified as an *n-way branch*, so an emitter's choice between an
`if let … else` and a two-arm `match` on the same value costs nothing.

### Semantic
Both sides are reduced to a multiset of recovered Soroban-operation facts,
matched by their canonical identity. The score is the F1 of the overlap:
precision = overlap / reconstructed facts, recall = overlap / original
facts. A storage fact carries its **tier and key**, so a swapped durability
tier or an unrecovered storage key is a genuine miss — this is the category
that moves when authorization is dropped, a tier is swapped, or an event
goes unpublished.

### Compilation — the "behavior" re-scope
**This item requires ABS sign-off.** The tranche text names a *behavioral*
comparison. An AST diff cannot measure runtime behavior. The credible,
deterministic stand-in at this stage is **recompilation**: the
reconstructed source is assembled into a scratch crate that depends on
`soroban-sdk` and run through `cargo check`. A reconstruction that type-
checks against the real SDK is demonstrably well-formed Soroban code;
differential *execution* against the original (true behavioral equivalence)
is a natural future extension once the Rust emitter is complete.

The compilation category is **opt-in** (`--check-compile`). When it is not
run — or when the toolchain or a contract-specific dependency is
unavailable offline — it is reported as *unchecked* and excluded from the
weighted mean, so an unrun check never silently credits or penalizes the
score. Overall = weighted mean over the **checked** categories only.

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
  matter. Parameter names, which the contract spec preserves, *are*
  compared.
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
| interface | 0.9143 (precision 0.94, recall 0.89) |
| structure | 1.0000 |
| semantic | 0.9114 (precision 1.00, recall 0.84) |
| **overall** | **0.9385** |

The gap is real ABI and semantic drift between the two SDK versions, not
scorer noise.

## 6. Versioning and freeze policy

Every report carries the scorer version. The algorithm and weights are
**frozen** at `score-1.0.0`: a golden calibration vector pins the exact
per-category scores for a fixed input pair, so any change that could move a
score fails the freeze test until the version string is bumped and the
snapshot updated in the same change. Once the Rust emitter is first scored
against this metric, that discipline guarantees the acceptance number is
computed the same way at review time as it was when agreed.

## 7. Baseline

The prior-generation decompiler's Rust output is the intended
baseline-to-beat. Regenerating it currently requires restoring that older
codebase's toolchain (a transitive dependency no longer compiles under the
current Rust release); the baseline number will be recorded here once that
reference is rebuilt. It does not affect the definition or the calibration
guarantees above.

## 8. Running it

```
# Score a reconstruction against the original (file or source directory):
sordec score <reconstructed> <original>

# Machine-readable report:
sordec score <reconstructed> <original> --json

# Include the compilation category (requires a toolchain + cached SDK):
sordec score <reconstructed> <original> --check-compile
```

The report gives the overall score, the pass/fail against the threshold
(default 0.90), and the four category sub-scores with precision/recall and
the specific items missed.

## 9. Requested sign-off

Two points are put to ABS explicitly:

1. **The behavior → compilation re-scope** (§3, Compilation): recompilation
   against `soroban-sdk` as the deterministic stand-in for the tranche's
   behavioral comparison, with differential execution as a later extension.
2. **The four-category weighting** (§3): interface 0.30, structure 0.25,
   semantic 0.30, compilation 0.15, and the rule that the overall figure is
   the weighted mean over the categories actually checked.
