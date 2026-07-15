# Phase 2 — Semantic Depth Complete

**Status:** ✅ Complete
**Tag/cut:** `main` at the Phase 2 completion commit (git tag `phase-2-complete`); the last feature/docs commit is [`a03c54a`](https://github.com/Imran-S-heikh/sordec/commit/a03c54a)
**Date:** July 2026

This document records what Phase 2 was scoped to deliver, what landed,
and how to verify it end-to-end from a clean clone. It mirrors
[PHASE_1.md](PHASE_1.md); the same "no external services, no secrets"
verification contract holds.

---

## Phase 2 scope

Phase 1 built the foundation — typed IR, frontend, lifter, corpus, and
an inspection CLI that names host calls (`host:l:put_contract_data`
instead of `Call { func5 }`). **Phase 2 is semantic depth**: recognize
the multi-instruction Soroban SDK idioms that those host calls are part
of, and collapse them into typed semantic operations with provenance —
so a reader sees `storage_get<persistent>(DataKey::Balance(addr))`, not
a raw host call plus a pile of bit-twiddling.

Per the development proposal, the Phase 2 deliverables were **D2.1–D2.6**:

1. **D2.1 Val encoding/decoding recognizer** — collapse the tag/shift/or
   bit-packing chains into typed literals.
2. **D2.2 Storage tier resolver** — trace the durability argument back to
   `temporary`/`persistent`/`instance`; a non-constant tier stays a
   typed `Unknown`, never a guess.
3. **D2.3 Auth chain recognizer** — `require_auth` / `require_auth_for_args`,
   the admin-from-instance-storage gate, and the `transfer_from`
   allowance flow.
4. **D2.4 Cross-contract call recognizer** — type generic
   `invoke_contract` against a recovered interface (SEP-41).
5. **D2.5 Pattern integration** — register the recognizers as an ordered
   pipeline with per-pattern counters and a bounded fixpoint.
6. **D2.6 Per-pattern integration tests** — every pattern exercised on
   every applicable fixture.

**No Rust source generation and no control-flow structuring in Phase 2** —
those are Phase 3. Phase 2 produces the *semantic layer* (`dump-hir`),
not finished Rust.

---

## What landed

The six Phase 2 deliverables (D2.1–D2.6), each backed by real, gated
commits on `main`:

| Deliverable | What landed | Anchor |
|---|---|---|
| D2.1 Val encoding/decoding | Recognizer that collapses the tag/shift/or bit-packing chains and `Symbol` packing into typed literals | [`b8c45fc`](https://github.com/Imran-S-heikh/sordec/commit/b8c45fc) |
| D2.2 Storage tier resolver | Traces the durability argument back to `temporary` / `persistent` / `instance`; a non-constant tier stays a typed `Unknown` with a reason, never a guess | [`df6c191`](https://github.com/Imran-S-heikh/sordec/commit/df6c191) |
| D2.3 Auth chain | `require_auth` / `require_auth_for_args`, the admin-from-instance-storage gate, and the `transfer_from` allowance flow — with storage keys named against the contract's declared types | [`0145e79`](https://github.com/Imran-S-heikh/sordec/commit/0145e79) |
| D2.4 Cross-contract call | Types generic `invoke_contract` against a recovered SEP-41 interface, matched by callee + arity | [`6afd964`](https://github.com/Imran-S-heikh/sordec/commit/6afd964) |
| D2.5 Pattern integration | Recognizers run as an ordered pipeline with per-pattern counters and a bounded fixpoint | [`c102407`](https://github.com/Imran-S-heikh/sordec/commit/c102407) |
| D2.6 Per-pattern integration tests | 561 workspace tests; every recognizer exercised on every applicable fixture; a recognizer × fixture coverage matrix | [`5ad1cd3`](https://github.com/Imran-S-heikh/sordec/commit/5ad1cd3) |

### Depth added beyond the six deliverables

Phase 2 also went past the required surface:

- **The complete host-function vocabulary** — all ~192 Soroban runtime functions (crypto, randomness, deployment, …) are recognized, so no call is left unnamed. [`3ccc332`](https://github.com/Imran-S-heikh/sordec/commit/3ccc332)
- **Symbol-dispatch reconstruction** — recovers the enum a contract switches on when routing a call (e.g. timelock's `TimeBoundKind {Before, After}`). [`d895c26`](https://github.com/Imran-S-heikh/sordec/commit/d895c26)
- **TTL, unit-value, and constructor recovery** — named ledger durations, `()` value markers, and the `__constructor` entrypoint label. [`455f69a`](https://github.com/Imran-S-heikh/sordec/commit/455f69a)
- **Diagnostics + self-grading** — a located diagnostic at every recognizer-miss, and the two-number `coverage` report (host interactions + deep facts). [`14e11dc`](https://github.com/Imran-S-heikh/sordec/commit/14e11dc), [`818d9e0`](https://github.com/Imran-S-heikh/sordec/commit/818d9e0)
- **A purpose-built test contract** — the `attestation` fixture (crypto / randomness / `#[contracterror]` / long `Symbol`) extends the corpus to seven. [`d4ce4d9`](https://github.com/Imran-S-heikh/sordec/commit/d4ce4d9)

The recognizers run as a **15-pass ordered pipeline** over the typed
working IR, each attaching provenance to its conclusions, each monotonic
and idempotent. Per-pass metrics feed the coverage report; a terminal
scan emits a diagnostic for any host call no pass claimed.

---

## Verification recipe (≤ 5 min on a laptop)

```bash
# 1. Clone (clean)
git clone git@github.com:Imran-S-heikh/sordec.git
cd sordec

# 2. Build
cargo build --release
# Expect: completes in ~1–2 min, no warnings

# 3. Test suite
cargo test --workspace
# Expect: 561 tests pass (0 failures)

# 4. Lint gate
cargo clippy --workspace --all-features --all-targets -- -D warnings
# Expect: clean

# 5. Corpus integrity
bash tools/verify-fixtures.sh
# Expect: verified: 7, failed: 0, missing: 0

# 6. End-to-end demo: coverage on the canonical SEP-41 token
./target/release/sordec coverage samples/contracts/token-v23/token-v23.wasm
# Expect: recognition section + semantic-recovery headline (below)

# 7. The Phase 2 payoff: the recovered semantic layer
./target/release/sordec dump-hir samples/contracts/token-v23/token-v23.wasm | less
# Expect: named storage tiers + keys, require_auth with admin gate, symbol!(...)
```

---

## Acceptance evidence

### Spec verdict — D2.1–D2.6: 6/6

| Deliverable | Status | Evidence |
|---|---|---|
| D2.1 Val encoding/decoding | ✅ | `val-encoding` pass; bit-packing unit tests; small-symbol decoder |
| D2.2 Storage tier resolver | ✅ | `storage` pass on token + timelock, all three tiers; non-constant → typed `Unknown` (honest `<?>`), inter-procedural upgrade |
| D2.3 Auth chain | ✅ | `require_auth` carries `admin gate: address = storage_get<instance>(DataKey::Admin)`; allowance chain named `DataKey::Allowance(from, spender)`; zero false positives |
| D2.4 Cross-contract call | ✅ | every corpus invoke typed against SEP-41 by callee + arity; dex + timelock |
| D2.5 Pattern integration | ✅ | 15-pass ordered pipeline; per-pattern counters; bounded fixpoint |
| D2.6 Per-pattern integration tests | ✅ | 561 workspace tests; 7 corpus fixtures; recognizer × fixture coverage matrix; zero-`host:` sweep |

### Test suite — 561 tests passing

| Crate | Tests |
|---|---|
| `sordec-common`   | 23 unit |
| `sordec-frontend` | 3 unit + 12 integration (parse) |
| `sordec-ir`       | 9 unit |
| `sordec-passes`   | 339 unit + 6 integration (lift) |
| `sordec-backend`  | 0 (Phase 3 stub) |
| `sordec-cli`      | 83 unit + 73 integration (coverage 12, dump_hir 50, dump_ir 6, dump_facts 5) |
| `sordec-driver`   | 10 integration (corpus 9, coverage_matrix 1) |
| Doc tests         | 3 (1 ignored) |

All pass under `cargo test --workspace` from a clean clone; clippy clean
under `--all-features --all-targets -- -D warnings`.

### Corpus — 7 fixtures, 100% host-call recognition

| Fixture | Source | Fns | Host calls | Recognition | Deep facts |
|---|---|---:|---:|---:|---:|
| `hello-add/`          | first-party 21.0.0        | 5  | 2  | **100%** | n/a¹ |
| `token-v22/`          | soroban-examples 22.0.11  | 48 | 31 | **100%** | 15/20 (75%) |
| `token-v23/`          | soroban-examples 23.0.1   | 46 | 35 | **100%** | 15/20 (75%) |
| `token-v23-stripped/` | soroban-examples 23.0.1   | 46 | 35 | **100%** | 9/12 (75%)² |
| `timelock/`           | soroban-examples 23.0.1   | 18 | 25 | **100%** | 8/10 (80%) |
| `dex-liquidity-pool/` | soroban-examples 23.0.1   | 50 | 22 | **100%** | 7/14 (50%) |
| `attestation/`        | first-party 23.0.1        | 8  | 12 | **100%** | n/a¹ |

¹ No deep-fact sites — hello-add and attestation exercise no
storage-tier/enum-key/ttl/client/dispatcher patterns (attestation is
crypto/PRNG/error-focused and storage-free by design).
² Fewer sub-facts *attempted* than `token-v23` (12 vs 20): enum-key
naming is spec-dependent, and this fixture has its `contractspecv0`
section stripped, so those facts are soundly not attempted rather than
missed. The resolution *rate* is unchanged.

### The headline: two numbers, honestly separated

```
  semantic recovery:
    host interactions:  35 / 35 recognized       (100.0%)
    deep facts:         15 / 20 resolved         (75.0%)
    note: structural accuracy vs source (>=90% AST node-count, D4.1) is a
          Phase-4 metric built on the Phase-3 Rust emitter — not yet computable
```

- **Host interactions (100% across all seven fixtures)** — every
  host-boundary call was recognised into a named semantic operation.
  This is Phase 2's recognition claim.
- **Deep facts (75% on token-v23)** — of the finer sub-facts the
  recognisers *attempt* (storage tiers, enum-key names, TTL amounts,
  client-call arity, dispatch cases), the fraction resolved. Every miss
  is a **sound decline** — a polymorphic-helper site or an
  indirect-call-blocked amount — carrying a located diagnostic, never a
  guess.

> **Note on the accuracy number.** The proposal's contractual acceptance
> figure is **≥90% structural (AST node-count) accuracy on `token-v23`** —
> a Phase-4 deliverable (D4.1) built on the Phase-3 Rust emitter, neither
> of which exists yet. It is therefore not measurable at the end of
> Phase 2. What Phase 2 reports is the two numbers above — host-interaction
> recognition and deep-fact resolution — which measure how much of each
> contract the pipeline understands, not the AST-diff score. That score
> arrives in Phase 4 once there is emitted Rust to compare against source.

### D2-Demo — the recovered semantic layer (`dump-hir`)

The proposal's end-of-Phase-2 demo asked for the token's `dump-ir` to
show `require_auth(from)` and `storage::persistent::get(BalanceKey(...))`-class
lines instead of raw host calls. That semantic layer is real today
(`dump-hir` on `token-v23`, lightly excerpted):

```
v15: Val = storage_get<instance>(v30: DataKey::Admin)      ;; enum-key, spec union matched
v22: Val = storage_get<persistent>(v45: DataKey::Balance(v1))
v19: Val = storage_get<temporary>(v116: DataKey::Allowance(v1, v2))
v22: () = require_auth(v21)                                 ;; admin gate: address = storage_get<instance>(DataKey::Admin)
v1:  Symbol = symbol!("METADATA")
v2:  () = extend_instance_and_code_ttl(103680, 120960)     ;; ttl threshold 103680 (6 days), extend_to 120960 (7 days)
```

**What is honestly *not* here yet:** the typed function signature, the
`if`/`match` control-flow shape, and the `token::Client::new(env,&t).transfer(…)`
method-chain sugar. Those are structuring + emit — **Phase 3** — not a
Phase 2 gap. Phase 2 delivers the recognised operations and their
provenance; Phase 3 arranges them into readable Rust.

---

## Known limitations (honest scope acknowledgement)

What Phase 2 does **not** do, grouped by the phase that addresses it.
Every item below carries an in-code deferral note at its site and, where
applicable, a defined-but-unemitted `LiftDiagnosticCode` slot — no silent
gaps.

**→ Phase 3 (control-flow structuring + Rust emit):**

| Limitation | Why it waits |
|---|---|
| No Rust source generation — `sordec-backend/` is a stub | the emitter (D3.5) |
| No control-flow structuring (`if`/`while`/`match`) | the industry-hard step; recover shape from CFG+SSA |
| Vec-iteration → `for`; branch-cascade → `match` arms | need loop / cascade structuring |
| Bare `panic!` / `unwrap` recovery | control-flow shaped |
| Vec/Map/Bytes literal *element* expansion; multi-arg client-call elements | elements live in a runtime stack buffer, not rodata; recovered at emit |
| Event flavor split + topic-vec expansion | emit-side distinction |

**→ Phase 3/4 (type-registry / `#[contracttype]` reconstruction):**

| Limitation | Why it waits |
|---|---|
| Full struct/enum/tuple type recovery (`MakeStruct`/`MakeEnumVariant`) | needs type-registry inference |
| Composite storage-key structs; `Result` Ok/Err wrapping | ride type recovery |

**→ Phase 4 (accuracy + protocol + long-tail):**

| Limitation | Why it waits |
|---|---|
| Round-trip / structural **accuracy scoring** (`sordec score`, D4.1) | needs the Phase-3 emitter first |
| Multi-version protocol catalog | append-only ABI; 26.1.2 covers deployed contracts today |
| Wide-int (`i128`/`u256`) arithmetic fusion; formatted panic; `sqrt` inline; `log_from_linear_memory`; multi-`#[contractimpl]` merge | multi-block carry chains / format machinery / no SDK marker / no corpus fixture exercises them yet |

These are scope, not bugs. Ten `LiftDiagnosticCode` taxonomy slots are
defined and documented ahead of the features that will emit them
(`#[non_exhaustive]` keeps them additive).

---

## What's measured vs. what's user-visible

A reasonable reader asks: "100% host-call recognition and a recovered
semantic layer are great, but I still can't read generated Rust — what
does Phase 2 prove?"

What Phase 2 proves:

- **The SDK-idiom recognisers work on real production contracts.** Seven
  fixtures across three SDK versions collapse their storage/auth/
  cross-contract/Val/crypto patterns into typed semantic ops with zero
  per-fixture hand-tuning and zero false positives.
- **The pipeline refuses to guess.** Every unresolved fact is a typed
  `Unknown` with a located diagnostic and a reason — the
  `token-v23-stripped` fixture proves the recognisers go dark exactly
  where the evidence (the `contractspecv0` section) is removed.
- **The measurement spine for Phase 3/4 is in place.** The `recognition`
  and `semantic recovery` coverage sections extend the same `coverage`
  scaffolding; the Phase-4 accuracy score will plug into the same report.

What Phase 2 does **not** yet prove:

- That the Rust generated in Phase 3 will be readable by an auditor.
- That control-flow structuring will recover the original
  `if`/`while`/`match` shape on real contracts (the industry's hardest
  unknown, still ahead).
- The contractual ≥90% structural-accuracy number — unmeasurable until
  the Phase-3 emitter and Phase-4 scorer exist.

---

## Phase 3 plan

Phase 3 is **HighIR → structured Rust**: control-flow structuring
(recover `if`/`while`/`match`/`Return` from the CFG), an annotated-WAT
emitter, and a compilable-Rust emitter that turns the semantic layer
above into source an auditor can read. The accuracy framework that
scores that output against the vendored source (`sordec score`, the
≥90% structural bar) is Phase 4 — but the source-side half of that
scorer (parse the original into a comparable AST, validated
against itself) can be built early so the emitter is tuned toward a
measurable target rather than blind.

---

## Reproducibility

Every number in this document is reproducible from a clean clone of
`main` at the Phase 2 cut (tag `phase-2-complete`). If a future commit
changes the numbers, this document is updated in the same commit;
PHASE_2.md is pinned to the cut, not to a moving `main`.
