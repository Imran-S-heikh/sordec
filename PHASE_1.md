# Phase 1 Deliverable — Foundation Complete

**Status:** ✅ Complete  
**Tag/cut:** `main` at commit [`a260681`](https://github.com/Imran-S-heikh/sordec/commit/a260681)  
**Date:** May 2026

This document is the SCF grant deliverable for Phase 1 of the sordec
Build Award (#41). It describes what was promised, what landed, and how
to verify it from a clean clone in under 5 minutes.

---

## What was promised

Phase 1 was scoped as **foundation work** — the typed IR, frontend,
lifter, real-world test corpus, and an inspection CLI surface that lets
us see what the pipeline does. **No Rust source generation in Phase 1**
— that's Phase 3.

Concretely, the Phase 1 commitments were:

1. **Typed IR scaffolding** — three IR layers (`WasmFacts`,
   `LiftedIr`, `HighIr`) with newtype IDs, validation hooks, and a
   diagnostic-collection design that can grow into Phase 2 pattern
   recovery without retrofit pain.
2. **WASM frontend** — parse a Soroban `.wasm` and decode its three
   custom sections (`contractspecv0`, `contractenvmetav0`,
   `contractmetav0`) into typed Soroban facts.
3. **Lifter** — wrap `waffle` to convert WASM bytes into our typed
   SSA + CFG `LiftedIr`, with hard errors (no silent fallbacks) on
   SSA-invariant violations.
4. **Real-world test corpus** — a vendored, sha256-verified set of
   actual Soroban contracts, not synthetic blobs. Multi-SDK to prove
   we're not pinned to one upstream version.
5. **CLI inspection surface** — three subcommands so anyone (auditor,
   reviewer, future contributor) can see what the pipeline knows about
   any contract: `dump-facts`, `dump-ir`, `coverage`.

---

## What landed

Each of the items below is a real commit on `main`, in chronological
order. The SHAs are stable references — Sala's verification recipe
below works against any of these or against today's `main` HEAD.

| Sub-task | Commit | Description |
|---|---|---|
| Task 1.2 | [`77a6746`](https://github.com/Imran-S-heikh/sordec/commit/77a6746) | Typed IR scaffolding — three layers, newtype IDs (`FuncId`/`BlockId`/`ValueId`/`TypeId`), validate stubs |
| Task 1.4 | [`36c1824`](https://github.com/Imran-S-heikh/sordec/commit/36c1824) | WASM parsing + Soroban metadata decoding (contractspecv0, contractenvmetav0, contractmetav0) |
| Task 1.5 | [`94c2715`](https://github.com/Imran-S-heikh/sordec/commit/94c2715) | waffle integration — WASM → typed SSA + CFG `LiftedIr` |
| Task 1.6 | [`e7196aa`](https://github.com/Imran-S-heikh/sordec/commit/e7196aa) | Real-world test corpus (5 fixtures: token-v22/v23/v23-stripped, timelock, dex-liquidity-pool) |
| Closeout #1 | [`cdec888`](https://github.com/Imran-S-heikh/sordec/commit/cdec888) | Diagnostics infrastructure + `SorobanFacts` as peer to `WasmFacts` |
| Closeout #2 | [`e4d2995`](https://github.com/Imran-S-heikh/sordec/commit/e4d2995) | `sordec dump-facts` and `sordec dump-ir` subcommands |
| Closeout #3 | [`d08ed56`](https://github.com/Imran-S-heikh/sordec/commit/d08ed56) | Soroban host-call catalog (vendored from `soroban-env-common 26.1.2`) + recognition in `dump-ir` |
| Closeout #4 | [`ff9326d`](https://github.com/Imran-S-heikh/sordec/commit/ff9326d) | `sordec coverage` subcommand — host-call recognition %, lift completeness, JSON schema |
| Public-prep | [`9cab0fb`](https://github.com/Imran-S-heikh/sordec/commit/9cab0fb), [`a260681`](https://github.com/Imran-S-heikh/sordec/commit/a260681) | Hello-add promoted to corpus fixture; personal sandbox untracked |

---

## Verification recipe (≤ 5 min on a laptop)

```bash
# 1. Clone (clean)
git clone git@github.com:Imran-S-heikh/sordec.git
cd sordec

# 2. Build
cargo build --release
# Expect: completes in ~1 min on a modern laptop, no warnings

# 3. Test suite
cargo test --workspace
# Expect: 110 tests pass (0 failures, 1 ignored doc-test)

# 4. Lint gate
cargo clippy --workspace --all-features --all-targets -- -D warnings
# Expect: clean (no warnings under -D warnings)

# 5. Corpus integrity
bash tools/verify-fixtures.sh
# Expect: verified: 6, failed: 0, missing: 0

# 6. End-to-end demo: coverage on the canonical SEP-41 token fixture
./target/release/sordec coverage samples/contracts/token-v23/token-v23.wasm
# Expect: 100% host-call recognition, 100% lift completeness
```

If all six commands succeed with the expected outputs, Phase 1 is
verified end-to-end. No external services, no secrets, no manual
warmup steps.

---

## Acceptance evidence

### Test suite — 110 tests passing

| Crate | Tests |
|---|---|
| `sordec-common`    | 29 unit |
| `sordec-frontend`  | 6 unit + 4 integration |
| `sordec-ir`        | 15 unit |
| `sordec-passes`    | 17 unit + 5 integration + 12 host-call catalog |
| `sordec-cli`       | 10 unit (pretty-printer) + 9 unit (coverage) + 6 + 6 + 4 integration (dump_ir, coverage, dump_facts) |
| `sordec-driver`    | 3 corpus integration |
| Doc tests          | 2 (1 ignored) |

All 110 tests pass under `cargo test --workspace` from a clean clone.
Clippy clean under `--all-features --all-targets -- -D warnings`.

### Corpus — 6 fixtures, 100% host-call recognition

Run `bash tools/verify-fixtures.sh` to confirm all sha256s match.

| Fixture | Source | Functions | Host calls | Recognition | Lift |
|---|---|---:|---:|---:|---:|
| `hello-add/`           | first-party | 5 | 2 | **100%** | **100%** |
| `token-v22/`           | soroban-examples 22.0.11 | 48 | 31 | **100%** | **100%** |
| `token-v23/`           | soroban-examples 23.0.1  | 46 | 35 | **100%** | **100%** |
| `token-v23-stripped/`  | soroban-examples 23.0.1  | 46 | 35 | **100%** | **100%** |
| `timelock/`            | soroban-examples 23.0.1  | 18 | 25 | **100%** | **100%** |
| `dex-liquidity-pool/`  | soroban-examples 23.0.1  | 50 | 22 | **100%** | **100%** |

Reproduce per fixture:

```bash
./target/release/sordec coverage samples/contracts/<name>/<name>.wasm
```

### Three CLI subcommands, all working end-to-end

```bash
# 1. dump-facts: structured JSON of WasmFacts + SorobanFacts
./target/release/sordec dump-facts samples/contracts/token-v23/token-v23.wasm | jq .

# 2. dump-ir: waffle-style text rendering with named host calls
./target/release/sordec dump-ir samples/contracts/token-v23/token-v23.wasm | head -40

# 3. coverage: text or --json
./target/release/sordec coverage --json samples/contracts/token-v23/token-v23.wasm | jq .
```

### Coverage demo on token-v23 (canonical SEP-41 token)

```
coverage report — token-v23.wasm
  catalog:         soroban-env-common 26.1.2
  parse:           ok (0 diagnostics)            ← WASM parsed cleanly, no recoverable issues
  metadata:        present (0 diagnostics)       ← Soroban contractspecv0/etc all decoded
  lift:            46 functions, 0 with diagnostics  (100.0%)   ← every local function lifted to SSA+CFG cleanly
  host calls:      35 / 35 recognized               (100.0%)    ← every host import resolved to its friendly name
  operators:       1085 total
                     call (import):     35
                     call (local):     116
                     call indirect:      0
                     other:            934
```

The `host calls: 35/35 recognized` line is the headline metric. It
means every call out to the Soroban host runtime in this contract
(storage writes, auth checks, cross-contract dispatch, Val encoding,
etc.) was recognized by name from our vendored 26.1.2 catalog. A
human reading the lifted IR sees `host:l:put_contract_data(...)`
instead of `Call { function_index: func5 }(...)`.

---

## Known limitations (honest scope acknowledgement)

What Phase 1 does **not** do, and where each piece lands in the
roadmap:

| Limitation | Phase that addresses it |
|---|---|
| No Rust source generation. The `sordec-backend/` crate exists as a stub. | Phase 3 |
| No multi-instruction pattern recovery (storage tier resolution, auth chains, cross-contract clients, Val encoding/decoding). Today we name `host:l:put_contract_data` but don't yet collapse it into `env.storage().persistent().set(...)`. | Phase 2 |
| No control-flow structuring. The lifted IR is gotos and basic blocks; recovering `if`/`while`/`match` from CFG+SSA is the hardest unknown ahead of us. | Phase 2/3 |
| `LiftDiagnosticCode` enum is uninhabited in v0. Lift completeness is structurally always 100% — the metric is wired so Phase 2's first diagnostic-emitting pass surfaces immediately as a coverage drop. | Phase 2 |
| Single-protocol catalog (vendored from `soroban-env-common 26.1.2`). The append-only invariant of the host-function ABI means older contracts are covered cleanly; future-protocol calls would render as raw `host:<module>:<name>` instead of friendly names. | Phase 4 (multi-version awareness) |
| No CI workflow yet. The verification recipe above is the contract; running it locally is the gate. GitHub Actions will be added before Phase 2 ships. | Phase 2 prep |
| No accuracy framework yet (round-trip `decompile(compile(X)) == X` measurement). | Phase 4 |

These are scope, not bugs. The Phase 2 plan picks up exactly where
Phase 1 stops.

---

## What's measured vs. what's user-visible

A reasonable reader could ask: "100% host-call recognition is great,
but I can't yet read recovered Rust — so what does this prove?"

What Phase 1 proves:

- **The pipeline works end-to-end on real production Soroban
  contracts.** Six contracts spanning multiple SDK versions, parse,
  decode, and lift cleanly with zero hand-tuning per fixture.
- **The infrastructure for accuracy measurement is in place.** Every
  Phase 2/3/4 metric (storage-tier recognition %, control-flow
  structuring success rate, round-trip accuracy) extends the same
  `coverage` scaffolding shipped in closeout #4.
- **The IR design holds up.** No type retrofit needed across the four
  closeout sub-tasks — the `WasmFacts` / `LiftedIr` / `HighIr`
  scaffolding designed in Task 1.2 absorbed every later piece without
  schema churn.
- **Test discipline is real.** 110 tests, 6 corpus fixtures verified
  by sha256, three feature-config build matrices clean, clippy
  `-D warnings` clean. Every commit on `main` passes every gate.

What Phase 1 does **not** yet prove:

- That the Rust we'll generate in Phase 3 will be readable by an
  auditor.
- That the control-flow structuring algorithm will recover the
  original `if`/`while`/`match` shape on real contracts (industry's
  hardest unknown).
- That multi-instruction pattern recovery is feasible at the depth
  proposed (Phase 2).

Those land in the next phases.

---

## Phase 2 plan

The Phase 2 development plan covers multi-instruction pattern
recovery: storage-tier resolution (`put_contract_data` + durability
constant → `env.storage().persistent().set(...)`), auth chain
recognition (`require_auth(addr)` patterns), cross-contract clients
(`call_contract(...)` + signature recovery), and Val
encoding/decoding (the round-trip pattern at every dispatcher
boundary). The full plan is in private development notes; a public
summary will accompany the Phase 2 cut.

---

## Reproducibility

Every number in this document is reproducible from a clean clone of
`main` at commit [`a260681`](https://github.com/Imran-S-heikh/sordec/commit/a260681).
If a future commit changes the numbers, this document will be updated
in the same commit; PHASE_1.md is pinned to the cut, not to `main`.
