# Reconstruction accuracy report

Scorer `score-2.1.0`, threshold 0.90. Reconstruction (`sordec decompile`) scored directory-vs-directory against each fixture's vendored source. Compilation is a gate and is not evaluated here. Regenerate with `SORDEC_BENCH_WRITE=1 cargo test -p sordec --test benchmark -- --ignored`.

**Two aggregates, and they answer different questions.** The AST-only mean covers interface, structure and semantic; it is the figure comparable with the committed accuracy bands and with every earlier measurement, so it stays the headline. The second adds `behavior` — differential execution of the recompiled reconstruction against the original wasm — which is measurable on 2 of 7 fixtures today, because the other 5 do not yet compile. An unmeasurable category is reported `n/a` and renormalises out of that fixture's mean; it is never a zero, since "does not build" and "does the wrong thing" are different findings.

| fixture | overall (AST) | interface | structure | semantic | behavior |
|---|---|---|---|---|---|
| hello-add | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 |
| token-v22 | 0.9220 | 0.9286 | 0.9063 | 0.9286 | n/a |
| token-v23 | 0.8453 | 0.7500 | 0.8598 | 0.9286 | n/a |
| token-v23-stripped | 0.7939 | 0.6044 | 0.8598 | 0.9286 | n/a |
| timelock | 1.0000 | 1.0000 | 1.0000 | 1.0000 | n/a |
| dex-liquidity-pool | 0.9429 | 1.0000 | 0.8059 | 1.0000 | n/a |
| attestation | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| **aggregate (mean, AST)** | **0.9292** | | | | |
| **aggregate (mean, incl. behaviour)** | **0.9292** | | | | |

## Per-fixture detail

### hello-add

- **interface** 1.0000 — entrypoints 1.0000  precision=1.0000 recall=1.0000 (1 original, 1 reconstructed)
- **structure** 0.0000 — no entrypoint carries control flow on either side — nothing to measure
- **semantic** 0.0000 — no semantic facts on either side — nothing to measure
- **behavior** 1.0000 — 1 of 1 entrypoints driven; return 9/9; 3 trivial agreement(s) excluded

### token-v22

- **interface** 0.9286 — entrypoints 1.0000  precision=1.0000 recall=1.0000 (13 original, 13 reconstructed) — types 0.8571  precision=0.7500 recall=1.0000 (3 original, 4 reconstructed) — types extra: type TokenMetadata
- **structure** 0.9063 — 13 entrypoints (0 unreconstructed, 4 without control flow) — ambiguous names (1 original, 1 reconstructed) — their call edges are dropped, so this is a lower bound — control flow: precision=0.7500 recall=1.0000 (33 original tokens, 44 reconstructed) — bloat 1.3x, dice ceiling ~0.8571
- **semantic** 0.9286 — precision=0.8667 recall=1.0000 (13 original facts, 15 reconstructed) — over-recovered: storage:get:instance:?, storage:set:instance:?
- **behavior** n/a — behavior unavailable: crate does not build: error[E0308]: mismatched types

### token-v23

- **interface** 0.7500 — entrypoints 1.0000  precision=1.0000 recall=1.0000 (13 original, 13 reconstructed) — types 0.5000  precision=0.3333 recall=1.0000 (4 original, 12 reconstructed) — types extra: type Approve, type Burn, type Clawback, type Mint, type MintWithAmountOnly, type TokenMetadata, type Transfer, type TransferWithAmountOnly
- **structure** 0.8598 — 13 entrypoints (0 unreconstructed, 4 without control flow) — ambiguous names (1 original, 2 reconstructed) — their call edges are dropped, so this is a lower bound — control flow: precision=0.6346 recall=1.0000 (33 original tokens, 52 reconstructed) — bloat 1.6x, dice ceiling ~0.7765 — low-similarity: transfer(0.44)
- **semantic** 0.9286 — precision=0.8667 recall=1.0000 (13 original facts, 15 reconstructed) — over-recovered: storage:get:instance:?, storage:set:instance:?
- **behavior** n/a — behavior unavailable: crate does not build: error[E0308]: mismatched types

### token-v23-stripped

- **interface** 0.6044 — entrypoints 0.9231  precision=0.9231 recall=0.9231 (13 original, 13 reconstructed) — entrypoints missing: fn transfer — entrypoints extra: fn transfer — types 0.2857  precision=0.3333 recall=0.2500 (4 original, 3 reconstructed) — types missing: type SetAdmin, type struct{from:Address,spender:Address}, type union{Allowance(AllowanceDataKey),Balance(Address),State(Address),Admin} — types extra: type struct{decimal:u32,name:String,symbol:String}, type union{Allowance(Val,Val),Balance(Val),State(Val),Admin}
- **structure** 0.8598 — 13 entrypoints (0 unreconstructed, 4 without control flow) — ambiguous names (1 original, 1 reconstructed) — their call edges are dropped, so this is a lower bound — control flow: precision=0.6346 recall=1.0000 (33 original tokens, 52 reconstructed) — bloat 1.6x, dice ceiling ~0.7765 — low-similarity: transfer(0.44)
- **semantic** 0.9286 — precision=0.8667 recall=1.0000 (13 original facts, 15 reconstructed) — over-recovered: storage:get:instance:?, storage:set:instance:?
- **behavior** n/a — behavior unavailable: samples/contracts/token-v23-stripped/token-v23-stripped.wasm has no `contractenvmetav0` section, so the host cannot load it and it cannot serve as a behaviour oracle

### timelock

- **interface** 1.0000 — entrypoints 1.0000  precision=1.0000 recall=1.0000 (2 original, 2 reconstructed) — types 1.0000  precision=1.0000 recall=1.0000 (4 original, 4 reconstructed)
- **structure** 1.0000 — 2 entrypoints (0 unreconstructed, 0 without control flow) — ambiguous names (1 original, 1 reconstructed) — their call edges are dropped, so this is a lower bound — control flow: precision=1.0000 recall=1.0000 (5 original tokens, 5 reconstructed) — bloat 1.0x, dice ceiling ~1.0000
- **semantic** 1.0000 — precision=1.0000 recall=1.0000 (10 original facts, 10 reconstructed)
- **behavior** n/a — behavior unavailable: both modules build and load, but no entrypoint could be driven — 0 of 2 entrypoints drivable (skipped — claim: parameter `claimant` is an Address, which needs a value constructed against a live host; deposit: parameter `from` is an Address, which needs a value constructed against a live host)

### dex-liquidity-pool

- **interface** 1.0000 — entrypoints 1.0000  precision=1.0000 recall=1.0000 (6 original, 6 reconstructed) — types 1.0000  precision=1.0000 recall=1.0000 (1 original, 1 reconstructed)
- **structure** 0.8059 — 6 entrypoints (0 unreconstructed, 2 without control flow) — ambiguous names (1 original, 1 reconstructed) — their call edges are dropped, so this is a lower bound — control flow: precision=0.4872 recall=0.9500 (20 original tokens, 39 reconstructed) — bloat 1.9x, dice ceiling ~0.6780 — low-similarity: deposit(0.40)
- **semantic** 1.0000 — precision=1.0000 recall=1.0000 (17 original facts, 17 reconstructed)
- **behavior** n/a — behavior unavailable: crate does not build: error[E0308]: mismatched types

### attestation

- **interface** 1.0000 — entrypoints 1.0000  precision=1.0000 recall=1.0000 (6 original, 6 reconstructed) — types 1.0000  precision=1.0000 recall=1.0000 (1 original, 1 reconstructed)
- **structure** 1.0000 — 6 entrypoints (0 unreconstructed, 4 without control flow) — ambiguous names (2 original, 2 reconstructed) — their call edges are dropped, so this is a lower bound — control flow: precision=1.0000 recall=1.0000 (3 original tokens, 3 reconstructed) — bloat 1.0x, dice ceiling ~1.0000
- **semantic** 1.0000 — precision=1.0000 recall=1.0000 (4 original facts, 4 reconstructed)
- **behavior** 1.0000 — 2 of 6 entrypoints driven; return 20/20; 4 trivial agreement(s) excluded

