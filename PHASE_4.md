# Phase 4 — Rust Emitter + Accuracy Measurement + Release

**Status:** ✅ Complete — shipped as `v0.1.0-alpha.1`
**Delivers:** SCF **Tranche 3** (Mainnet) — the third of three tranches.
**Date:** September 2026
**Cut:** `main` at the Phase 4 closeout commit.

This document records what Phase 4 was scoped to deliver, what landed, what
did **not** reach its target, and how to verify all of it end-to-end from a
clean clone. It mirrors [PHASE_1.md](PHASE_1.md), [PHASE_2.md](PHASE_2.md) and
[PHASE_3.md](PHASE_3.md); the same "no external services, no secrets"
verification contract holds.

---

## Phase 4 scope

Per the official tranche roadmap, **Tranche 3** emits **compilable Rust** from
the structured IR and **proves reconstruction quality** against the original
source, reported by category.

In development-proposal terms, Phase 4 delivers:

- **D3.5 — Rust source emitter.** Function bodies, type reconstruction
  (`#[contracttype]` structs and enums), SDK imports, `#[contract]` /
  `#[contractimpl]` macros.
- **D3.6 (Rust half) — the `decompile` CLI.** Write a buildable crate
  alongside the Phase-3 annotated WAT.
- **D4.1 — accuracy framework completion.** The scorer core landed early in
  Phase 3; Phase 4 completes it — ABI read from the spec-XDR, per-entrypoint
  structure, per-category source basis, and the behavioural extension.
- **D4.2 — per-fixture accuracy report** and gap analysis.
- **D4.3 — output-quality polish.**
- **D4.4 — pattern extensions** (`#[contractevent]`, `#[contracterror]`,
  `Result<T, Error>`).
- **D4.5–D4.7 — documentation, CI, and a tagged release.**

---

## What landed

### D3.5 — Rust source emitter

`sordec-backend`'s `rust` module walks the HighIR region tree and builds a
typed `syn` AST, printed by `prettyplease`. It reconstructs the contract
module, `#[contracttype]` structs (including tuple structs), unions, enums,
`#[contracterror]` enums with their discriminants, `#[contractevent]`
definitions, entrypoint signatures taken from `contractspecv0`, and function
bodies with recovered Soroban idioms — storage tier and key, TTL extension,
auth chains, event publication, cross-contract calls and typed panics.

**Certainty is structural, and it is preserved.** `IrType::{Known, Inferred,
Unknown}` routes through a single `HolePolicy` choke point: a proven type is
written, an unprovable value becomes `todo!("<what was unrecoverable>")`. The
label survives formatting, so every gap is visible in the output rather than
papered over. Fabricating a plausible stand-in is treated as a bug class.

### D3.6 (Rust half) — the `decompile` CLI

`sordec decompile <wasm> --out-dir <dir>` writes a buildable crate —
`<name>/Cargo.toml` and `<name>/src/lib.rs` — beside the Phase-3
`<name>.wat`. `sordec dump-rust` prints the same source to stdout for
inspection.

### D4.1 — accuracy framework completion (`score-2.0.0`)

The scorer was realigned with the RFP and re-versioned. It remains a
**source-to-source** comparator that never inspects the WASM or the
decompiler's internals, so it cannot flatter the pipeline it grades.

- **Interface** is read from the **spec-XDR ABI** rather than from
  documentation shape, and reports entrypoints and types separately.
- **Structure** is scored **per ABI entrypoint** over its call closure, which
  removed a name-matching artefact worth 11.6× on one fixture pair.
- **Basis is per-category**: interface and structure on macro-expanded
  sources, semantic on the sources as written — because `panic!` is a macro
  that vanishes under expansion, taking its facts with it.
- **Behaviour** is a real injected category guarded by a typed `BSide`, so
  only a measurement of *our own reconstruction* can score.

The full definition — categories, weights, per-category source basis, limits,
and how to read a score — is maintained as the metric's specification document
and versioned alongside it (`score-2.0.0`).

**Differential execution** (`sordec-diffexec`) registers the original wasm and
the recompiled reconstruction in an in-process Soroban host, drives both
identically, and compares four observations: return value, ordered event
stream, authorization tree and storage snapshot. Two rules are enforced rather
than assumed: every rate travels with its coverage fraction, and mutual
failure is bucketed separately instead of counted as agreement.

### D4.2 — per-fixture accuracy report

The benchmark harness regenerates a per-fixture report (`report.{md,json}`)
from the corpus on demand, and each fixture carries a committed accuracy band
in the harness itself, so that a silent regression *or* an unearned jump fails
CI.

### D4.4 — pattern extensions

`#[contracterror]` enums with `Result<T, Error>` returns, `Ok`/`Err`
reconstruction with the error type resolved to the contract's sole error enum,
and `#[contractevent]` definitions.

---

## What did not reach target

Stated here rather than in a footnote, because the number is the deliverable.

**Reconstruction score: 0.6108 against a 0.90 target.** By category, averaged
over the five real contracts: interface **0.92**, semantic **0.71**, structure
**0.14**. Behaviour scores **1.0000** wherever it can be measured, on narrow
coverage.

**The gap is structure, and its cause is specific.** Control-flow *recall* is
1.0000 on four of five real contracts — every branch, loop and guard in the
original source is present in the output. Precision is 0.041–0.143. `rustc`
inlines the SDK into every function, leaving no boundary in the finished WASM
between what the author wrote and what came from the library, and the emitter
currently reproduces all of it. Output runs **12–25× longer** than its source,
and the metric penalises excess exactly as it penalises omission.

The consequence is unusual and worth stating plainly: **the remaining work is
deletion, not discovery.** No further analysis is needed to find missing
logic; SDK plumbing needs recognising and removing.

**Compilation: 2 of 7 fixtures.** `hello-add` and `attestation` recompile for
`wasm32v1-none`; the rest emit Rust that does not yet type-check, dominated by
type mismatches on values whose marshalling has not been elided.

**Behaviour coverage.** Only entrypoints whose parameters are all scalars can
be driven, so `Address`- and `Bytes`-taking entrypoints are skipped and the
event, auth and storage channels have not yet been exercised.

---

## Verification recipe (≤ 5 min on a laptop)

```bash
# 1. Clone (clean) and build
git clone https://github.com/Imran-S-heikh/sordec && cd sordec
cargo build --release

# 2. Full local gate (build · release-warnings · test · clippy · doc · fixtures)
bash tools/gate.sh

# 3. Deliverable 1 — reconstructed Rust on stdout
./target/release/sordec dump-rust samples/contracts/attestation/attestation.wasm
# Expect: #[contract]/#[contractimpl], #[contracterror] enum with discriminants,
# recovered bodies, and todo!("…") where a value could not be proven

# 4. Deliverable 2 — a buildable crate on disk
./target/release/sordec decompile samples/contracts/hello-add/hello-add.wasm --out-dir out/
# Writes out/hello-add/{Cargo.toml, src/lib.rs, hello-add.wat}

# 5. Deliverable 3 — the score, by category
./target/release/sordec score out/hello-add samples/contracts/hello-add/source/src \
  --behavior samples/contracts/hello-add/hello-add.wasm
# Expect: overall 1.0000 PASS, behavior 1.0000 over 1 of 1 entrypoints

# 6. The scorer is honest about identity: source against itself is 1.0
./target/release/sordec score \
  samples/contracts/token-v23/source/src samples/contracts/token-v23/source/src

# 7. The corpus report (needs `cargo install cargo-expand` + per-fixture `cargo fetch`)
cargo test -p sordec --test benchmark -- --ignored --nocapture generate_report
```

---

## Acceptance evidence

### Spec verdict — Tranche 3 deliverables

| Deliverable | Status |
|---|---|
| D3.5 — Rust source emitter | ✅ |
| D3.6 — `decompile` writes a crate | ✅ |
| D4.1 — accuracy framework (`score-2.0.0`) + differential execution | ✅ |
| D4.2 — per-fixture report + gap analysis | ✅ |
| D4.4 — `#[contracterror]` / `Result` / `#[contractevent]` | ✅ |
| D4.5–D4.7 — docs, CI, tagged release | ✅ |
| **≥90% reconstruction score** | ❌ **0.6108** — see *What did not reach target* |

### Test suite — 1,413 tests passing (0 failures)

Full `tools/gate.sh` green: build · release `-D warnings` · test · clippy
`-D warnings` · doc `-D warnings` · fixtures 7/7.

### Corpus — per-fixture accuracy

| Fixture | Overall | Interface | Structure | Semantic |
|---|---|---|---|---|
| hello-add | 1.0000 | 1.0000 | n/a | n/a |
| attestation | 0.7794 | 1.0000 | 0.2500 | 1.0000 |
| timelock | 0.6561 | 1.0000 | 0.0879 | 0.7857 |
| token-v22 | 0.5829 | 0.9286 | 0.1292 | 0.6154 |
| dex-liquidity-pool | 0.5689 | 1.0000 | 0.0723 | 0.5517 |
| token-v23 | 0.5035 | 0.6875 | 0.1485 | 0.6154 |
| token-v23-stripped | 0.1851 | 0.0000 | 0.1123 | 0.4308 |
| **aggregate** | **0.6108** | | | |

`token-v23-stripped` has its `contractspecv0` destroyed deliberately, to test
name-independence; its interface is 0.0000 by construction and it cannot
exceed ~0.70 however good the decompiler becomes. It earns its place as a
regression fixture rather than as an acceptance vector.

### Behaviour, where measurable

| Fixture | Behaviour | Coverage | Checks |
|---|---|---|---|
| hello-add | 1.0000 | 1 of 1 entrypoints | 9 / 9 return |
| attestation | 1.0000 | 2 of 6 entrypoints | 20 / 20 return |

Both on the `reconstruction` B-side — the only one that scores. The other five
fixtures report *unavailable* with the reason, never a zero: they do not
compile yet, which is a statement about the emitter and not about what the
reconstruction does.

Including behaviour where it was measured moves the corpus mean to **0.6156**.
Both figures are in `docs/benchmarks/report.md`, and the AST-only **0.6108**
stays the headline: it is the one comparable with the committed accuracy bands
and with every earlier measurement. The gap is small because only attestation
moves — hello-add is already 1.0000 — and it will grow as the compile rate
does.

---

## Demo — reconstructed output

`attestation`, showing both halves of the design: recovered structure where it
is proven, and an admitted hole where it is not.

```rust
#[contracterror]
#[derive(Copy, Clone)]
#[repr(u32)]
pub enum Error {
    EmptyMessage = 1,
    DigestMismatch = 2,
}

pub fn digest_keccak(e: Env, message: Bytes) -> Result<BytesN<32>, Error> {
    let v6 = Error::EmptyMessage;
    let v8 = message.len();
    let v9 = 0u32;
    let v10 = v8 == v9;
    if v10 {
        return Err(v6);
    }
    let v12 = e.crypto().keccak256(&message).to_bytes();
    Ok(v12)
}
```

The guard, the comparison, the early return and the keccak call are all
recovered; only the local names are gone, because `rustc` deleted them. Where
a value genuinely cannot be proven — `check`'s shadow-stack digest comparison —
the body carries `todo!("memory load")` instead of a plausible substitute.
