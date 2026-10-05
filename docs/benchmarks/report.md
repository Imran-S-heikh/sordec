# Reconstruction accuracy report

Scorer `score-2.1.0`, threshold 0.90. Reconstruction (`sordec decompile`) scored directory-vs-directory against each fixture's vendored source. Compilation is a gate and is not evaluated here. Regenerate with `SORDEC_BENCH_WRITE=1 cargo test -p sordec --test benchmark -- --ignored`.

**Two aggregates, and they answer different questions.** The AST-only mean covers interface, structure and semantic; it is the figure comparable with the committed accuracy bands and with every earlier measurement, so it stays the headline. The second adds `behavior` — differential execution of the recompiled reconstruction against the original wasm — which is measured on 6 of 7 fixtures; each fixture's detail below says what was driven, and for any `n/a`, why not. An unmeasurable category is reported `n/a` and renormalises out of that fixture's mean; it is never a zero, since "could not be run" and "does the wrong thing" are different findings.

| fixture | overall (AST) | interface | structure | semantic | behavior |
|---|---|---|---|---|---|
| hello-add | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 |
| token-v22 | 0.9415 | 0.9286 | 0.9724 | 0.9286 | 1.0000 |
| token-v23 | 0.8784 | 0.7500 | 0.9724 | 0.9286 | 1.0000 |
| token-v23-stripped | 0.8228 | 0.6429 | 0.9119 | 0.9286 | 0.6055 |
| timelock | 1.0000 | 1.0000 | 1.0000 | 1.0000 | n/a |
| dex-liquidity-pool | 0.9294 | 1.0000 | 0.7599 | 1.0000 | 1.0000 |
| attestation | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| **aggregate (mean, AST)** | **0.9389** | | | | |
| **aggregate (mean, incl. behaviour)** | **0.9396** | | | | |

## Per-fixture detail

### hello-add

- **interface** 1.0000 — entrypoints 1.0000  precision=1.0000 recall=1.0000 (1 original, 1 reconstructed)
- **structure** 0.0000 — no entrypoint carries control flow on either side — nothing to measure
- **semantic** 0.0000 — no semantic facts on either side — nothing to measure
- **behavior** 1.0000 — 1 of 1 entrypoints driven; return 18/18; 6 trivial agreement(s) excluded

### token-v22

- **interface** 0.9286 — entrypoints 1.0000  precision=1.0000 recall=1.0000 (13 original, 13 reconstructed) — types 0.8571  precision=0.7500 recall=1.0000 (3 original, 4 reconstructed) — types extra: type TokenMetadata
- **structure** 0.9724 — 13 entrypoints (0 unreconstructed, 4 without control flow) — ambiguous names (1 original, 1 reconstructed) — their call edges are dropped, so this is a lower bound — control flow: precision=0.9167 recall=1.0000 (33 original tokens, 36 reconstructed) — bloat 1.1x, dice ceiling ~0.9565
- **semantic** 0.9286 — precision=0.8667 recall=1.0000 (13 original facts, 15 reconstructed) — over-recovered: storage:get:instance:?, storage:set:instance:?
- **behavior** 1.0000 — 12 of 12 entrypoints driven; return 174/174, events 27/27, auth 54/54, storage 174/174; 114 trivial agreement(s) excluded

### token-v23

- **interface** 0.7500 — entrypoints 1.0000  precision=1.0000 recall=1.0000 (13 original, 13 reconstructed) — types 0.5000  precision=0.3333 recall=1.0000 (4 original, 12 reconstructed) — types extra: type Approve, type Burn, type Clawback, type Mint, type MintWithAmountOnly, type TokenMetadata, type Transfer, type TransferWithAmountOnly
- **structure** 0.9724 — 13 entrypoints (0 unreconstructed, 4 without control flow) — ambiguous names (1 original, 2 reconstructed) — their call edges are dropped, so this is a lower bound — control flow: precision=0.9167 recall=1.0000 (33 original tokens, 36 reconstructed) — bloat 1.1x, dice ceiling ~0.9565
- **semantic** 0.9286 — precision=0.8667 recall=1.0000 (13 original facts, 15 reconstructed) — over-recovered: storage:get:instance:?, storage:set:instance:?
- **behavior** 1.0000 — 12 of 12 entrypoints driven; return 176/176, events 28/28, auth 56/56, storage 176/176; 112 trivial agreement(s) excluded

### token-v23-stripped

- **interface** 0.6429 — entrypoints 1.0000  precision=1.0000 recall=1.0000 (13 original, 13 reconstructed) — types 0.2857  precision=0.3333 recall=0.2500 (4 original, 3 reconstructed) — types missing: type SetAdmin, type struct{from:Address,spender:Address}, type union{Allowance(AllowanceDataKey),Balance(Address),State(Address),Admin} — types extra: type struct{decimal:u32,name:String,symbol:String}, type union{Allowance(Address,Address),Balance(Address),State(Val),Admin}
- **structure** 0.9119 — 13 entrypoints (0 unreconstructed, 4 without control flow) — ambiguous names (1 original, 1 reconstructed) — their call edges are dropped, so this is a lower bound — control flow: precision=0.7674 recall=1.0000 (33 original tokens, 43 reconstructed) — bloat 1.3x, dice ceiling ~0.8684 — low-similarity: transfer(0.55)
- **semantic** 0.9286 — precision=0.8667 recall=1.0000 (13 original facts, 15 reconstructed) — over-recovered: storage:get:instance:?, storage:set:instance:?
- **behavior** 0.6055 — 12 of 12 entrypoints driven; return 168/176, events 20/28, auth 48/56, storage 28/176; 112 trivial agreement(s) excluded

### timelock

- **interface** 1.0000 — entrypoints 1.0000  precision=1.0000 recall=1.0000 (2 original, 2 reconstructed) — types 1.0000  precision=1.0000 recall=1.0000 (4 original, 4 reconstructed)
- **structure** 1.0000 — 2 entrypoints (0 unreconstructed, 0 without control flow) — ambiguous names (1 original, 1 reconstructed) — their call edges are dropped, so this is a lower bound — control flow: precision=1.0000 recall=1.0000 (5 original tokens, 5 reconstructed) — bloat 1.0x, dice ceiling ~1.0000
- **semantic** 1.0000 — precision=1.0000 recall=1.0000 (10 original facts, 10 reconstructed)
- **behavior** n/a — behavior unavailable: both modules ran, but every call was a trivial agreement (both sides failed identically), so nothing was actually compared — 2 of 2 entrypoints drivable

### dex-liquidity-pool

- **interface** 1.0000 — entrypoints 1.0000  precision=1.0000 recall=1.0000 (6 original, 6 reconstructed) — types 1.0000  precision=1.0000 recall=1.0000 (1 original, 1 reconstructed)
- **structure** 0.7599 — 6 entrypoints (0 unreconstructed, 2 without control flow) — ambiguous names (1 original, 1 reconstructed) — their call edges are dropped, so this is a lower bound — control flow: precision=0.4634 recall=0.9500 (20 original tokens, 41 reconstructed) — bloat 2.0x, dice ceiling ~0.6557 — low-similarity: deposit(0.40)
- **semantic** 1.0000 — precision=1.0000 recall=1.0000 (17 original facts, 17 reconstructed)
- **behavior** 1.0000 — 5 of 5 entrypoints driven; return 48/48, storage 48/48; 72 trivial agreement(s) excluded

### attestation

- **interface** 1.0000 — entrypoints 1.0000  precision=1.0000 recall=1.0000 (6 original, 6 reconstructed) — types 1.0000  precision=1.0000 recall=1.0000 (1 original, 1 reconstructed)
- **structure** 1.0000 — 6 entrypoints (0 unreconstructed, 4 without control flow) — ambiguous names (2 original, 2 reconstructed) — their call edges are dropped, so this is a lower bound — control flow: precision=1.0000 recall=1.0000 (3 original tokens, 3 reconstructed) — bloat 1.0x, dice ceiling ~1.0000
- **semantic** 1.0000 — precision=1.0000 recall=1.0000 (4 original facts, 4 reconstructed)
- **behavior** 1.0000 — 6 of 6 entrypoints driven; return 80/80; 64 trivial agreement(s) excluded

