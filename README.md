# sordec

A WebAssembly decompiler specialized for [Soroban](https://stellar.org/soroban) smart contracts.

> **Status: Phase 2 of 4 complete — Phase 3 (control-flow structuring) in progress**
>
> Phases 1–2 ship an inspection toolkit: parse a Soroban `.wasm`, lift it
> to a typed CFG/SSA IR, recover the multi-instruction Soroban SDK idioms,
> and report what we understand about it. Phase 3 adds control-flow
> structuring (`if`/`while`/`match` reconstruction) — surfaced today in
> `sordec dump-hir` and the `coverage` structuring section — with Rust
> source generation to follow. See [PHASE_1.md](PHASE_1.md) and
> [PHASE_2.md](PHASE_2.md) for the per-phase deliverable summaries,
> verification recipes, and acceptance evidence.

## What it does today

Four CLI subcommands, all read-only inspection. None of these mutate
your `.wasm` or write outside of stdout.

| Subcommand | Output | Use case |
|---|---|---|
| `sordec dump-facts <wasm>`  | JSON | What we extracted: imports, exports, decoded Soroban metadata, contract spec, custom sections |
| `sordec dump-ir <wasm>`     | Text | Waffle-style CFG/SSA IR with **named host calls** (e.g. `host:l:put_contract_data`) |
| `sordec dump-hir <wasm>`    | Text | Structured HighIR: recovered control flow (`if`/`while`/`match`, named match arms, typed panics) plus the Phase-2 semantic operations |
| `sordec coverage <wasm>`    | Text or `--json` | How much of the contract our pipeline understands: control-flow **structuring** coverage (functions structured, loop shapes, labeled-exit tax), per-pattern recognition (storage tiers, enum keys, TTL, client calls, …), a two-number semantic-recovery headline, host-call recognition %, and recogniser-miss diagnostics |

What's coming next:

- **Phase 3 (in progress)** — control-flow structuring (`if`/`while`/`match` reconstruction, shipping now in `dump-hir` + `coverage`), annotated WAT emit, then Rust source emit
- **Phase 4** — accuracy framework, multi-version protocol catalog, polish

Each phase ships when it's ready and verified end-to-end (see `PHASE_N.md` per phase). Phase 3 is the current deliverable.

## Quick start

```bash
cargo build --release

# JSON: what's in the contract
./target/release/sordec dump-facts samples/contracts/token-v23/token-v23.wasm | jq .

# Text: the lifted IR with host calls named
./target/release/sordec dump-ir samples/contracts/token-v23/token-v23.wasm | head -40

# Coverage report — the headline metric
./target/release/sordec coverage samples/contracts/token-v23/token-v23.wasm
```

Sample `coverage` output on the canonical SEP-41 token fixture:

```
coverage report — token-v23.wasm
  catalog:         soroban-env-common 26.1.2
  parse:           ok (0 diagnostics)
  metadata:        present (0 diagnostics)
  lift:            46 functions, 0 with diagnostics  (100.0%)
  host calls:      35 / 35 recognized               (100.0%)
  operators:       1085 total
                     call (import):     35
                     call (local):     116
                     call indirect:      0
                     other:            934
  structuring:
    functions:      46 / 46 structured        (100.0%)   fallback regions ×0
    loops:          6 / 7 classified          (85.7%)
                    while ×6, do_while ×0, guarded ×0, infinite ×0, unclassified ×1
    switches:       2 match recovered   (dispatch-linked ×0, arms deduped ×1)
    traps:          inlined ×37, duplicated ×0, shared+bindings ×6, panic! ×37, unwrap ×23
    labeled exits:  break ×43, continue ×7   (readability tax; while back edges not counted)
    refinements:    guards ×83, polarity ×0, &&-merge ×0 (blocked ×0), loop tags ×6, copy-loop args ×0
    declutter:      aliases ×12, phis ×467, jumps ×2, returns ×28, traps ×1, chains ×0, dead blocks ×41, dead vals ×0
    treeify:        inline ×532, effect-pinned ×120, residue ×869
  recognition:
    storage:        tiers 8 / 10 resolved     (80.0%)
                    get ×4, set ×4, has ×1, remove ×0, extend_ttl ×2
    enum keys:      6 / 8 named             (75.0%)   ctor ×1
    ttl amounts:    1 / 2 resolved          (50.0%)
    client calls:   no invoke sites
    dispatcher:     no dispatch sites
    auth:           require_auth ×7, for_args ×0, as_curr ×0, addr_conv ×2, admin_gate ×2
    events:         5 published   (flavor split: Phase-3 emit)
    collections:    vec ×1, vec_op ×0, map ×1, map_op ×1, buf_op ×0
    panics:         0 typed   (bare panic!/unwrap: Phase-3)
    wide arithmetic: 0 fused   (deferred: C19)
    val boilerplate: 28 sites collapsed   (object ×5, tag ×5, enc_small ×2, enc_u32 ×14, dec_small ×2, cmp ×0)
  semantic recovery:
    host interactions:  35 / 35 recognized       (100.0%)
    deep facts:         15 / 20 resolved         (75.0%)
    note: structural accuracy vs source (>=90% AST node-count, D4.1) is a Phase-4 metric built on the Phase-3 Rust emitter — not yet computable
  diagnostics:     42 total (recogniser misses)
                     lift::panic_without_error_code (×37)
                     lift::non_constant_durability_arg (×2)
                     lift::unrecognised_storage_pattern (×2)
                     lift::non_constant_ttl_amount (×1)
```

**Reading the headline.** *Host interactions* (100% across all seven
[corpus fixtures](samples/contracts/)) is Phase 2's recognition claim:
every host-boundary call is turned into a named semantic operation.
*Deep facts* (75% on token-v23) is the fraction of finer sub-facts —
storage tiers, enum-key names, TTL amounts, client-call arity, dispatch
cases — the recognisers resolved; each miss is a **sound decline**
carrying a located diagnostic (a polymorphic helper site, an
indirect-call-blocked amount), never a guess. A ratio is shown only
where a pass emits a real miss counter; the other rows are counts with a
note on where their misses would surface. Neither number is the RFP's
contractual accuracy score — that is structural AST-diff against source,
a Phase-4 artifact over the Phase-3 Rust emitter.

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

Seven-crate Cargo workspace built around three IR layers:

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
Annotated WAT + recovered Rust (Phase 3)
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
├── sordec-backend/   — Rust + WAT emitters (Phase 3)
├── sordec-driver/    — Pipeline orchestration + corpus integration tests
└── sordec-cli/       — `sordec` binary (dump-facts, dump-ir, dump-hir, coverage)
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
cargo test --workspace                                       # 769 tests
cargo clippy --workspace --all-features --all-targets -- -D warnings
cargo doc --workspace --no-deps                              # no broken intra-doc links
bash tools/verify-fixtures.sh                                # 7/7 sha256 OK
```

All gates green at every commit on `main`. No CI workflow yet; the
verification recipe is the contract.

## Phase status

See [PHASE_1.md](PHASE_1.md) and [PHASE_2.md](PHASE_2.md) for the
per-phase scope, the verification recipe (≤ 5 min from a clean clone),
and the acceptance evidence (100% host-call recognition across all seven
fixtures). Phase 3 (control-flow structuring) is in progress on `main`.

## License

[Apache-2.0](LICENSE).

## Contact

Imran Shaikh — see `Cargo.toml` workspace metadata.
