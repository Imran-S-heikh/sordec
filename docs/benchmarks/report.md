# Reconstruction accuracy report

Scorer `score-2.0.0`, threshold 0.90. Reconstruction (`sordec decompile`) scored directory-vs-directory against each fixture's vendored source. Compilation is a gate and is not evaluated here. Regenerate with `SORDEC_BENCH_WRITE=1 cargo test -p sordec --test benchmark -- --ignored`.

**Two aggregates, and they answer different questions.** The AST-only mean covers interface, structure and semantic; it is the figure comparable with the committed accuracy bands and with every earlier measurement, so it stays the headline. The second adds `behavior` — differential execution of the recompiled reconstruction against the original wasm — which is measurable on 0 of 7 fixtures today, because the other 7 do not yet compile. An unmeasurable category is reported `n/a` and renormalises out of that fixture's mean; it is never a zero, since "does not build" and "does the wrong thing" are different findings.

| fixture | overall (AST) | interface | structure | semantic | behavior |
|---|---|---|---|---|---|
| hello-add | 1.0000 | 1.0000 | 0.0000 | 0.0000 | n/a |
| token-v22 | 0.8168 | 0.9286 | 0.6302 | 0.8605 | n/a |
| token-v23 | 0.7289 | 0.7500 | 0.5783 | 0.8333 | n/a |
| token-v23-stripped | 0.2853 | 0.0000 | 0.2104 | 0.6329 | n/a |
| timelock | 0.8166 | 1.0000 | 0.5833 | 0.8276 | n/a |
| dex-liquidity-pool | 0.7319 | 1.0000 | 0.4784 | 0.6750 | n/a |
| attestation | 1.0000 | 1.0000 | 1.0000 | 1.0000 | n/a |
| **aggregate (mean, AST)** | **0.7685** | | | | |
| **aggregate (mean, incl. behaviour)** | **0.7685** | | | | |

## Per-fixture detail

### hello-add

- **interface** 1.0000 — entrypoints 1.0000  precision=1.0000 recall=1.0000 (1 original, 1 reconstructed)
- **structure** 0.0000 — no entrypoint carries control flow on either side — nothing to measure
- **semantic** 0.0000 — no semantic facts on either side — nothing to measure
- **behavior** n/a — behavior unavailable: crate does not build: error: failed to download `jiff-tzdb v0.1.8`

### token-v22

- **interface** 0.9286 — entrypoints 1.0000  precision=1.0000 recall=1.0000 (13 original, 13 reconstructed) — types 0.8571  precision=0.7500 recall=1.0000 (3 original, 4 reconstructed) — types extra: type TokenMetadata
- **structure** 0.6302 — 13 entrypoints (0 unreconstructed, 3 without control flow) — ambiguous names (2 original, 2 reconstructed) — their call edges are dropped, so this is a lower bound — control flow: precision=0.5167 recall=0.9394 (33 original tokens, 60 reconstructed) — bloat 1.8x, dice ceiling ~0.7097 — low-similarity: allowance(0.00), approve(0.72), burn_from(0.66), mint(0.70), set_admin(0.00), transfer_from(0.66)
- **semantic** 0.8605 — precision=0.8605 recall=0.8605 (43 original facts, 43 reconstructed) — under-recovered: panic:bare, storage:get:temporary:DataKey::Allowance — over-recovered: panic:unwrap, storage:get:instance:?, storage:set:instance:?
- **behavior** n/a — behavior unavailable: crate does not build: error: failed to download `jiff-tzdb v0.1.8`

### token-v23

- **interface** 0.7500 — entrypoints 1.0000  precision=1.0000 recall=1.0000 (13 original, 13 reconstructed) — types 0.5000  precision=0.3333 recall=1.0000 (4 original, 12 reconstructed) — types extra: type Approve, type Burn, type Clawback, type Mint, type MintWithAmountOnly, type TokenMetadata, type Transfer, type TransferWithAmountOnly
- **structure** 0.5783 — 13 entrypoints (0 unreconstructed, 3 without control flow) — ambiguous names (2 original, 3 reconstructed) — their call edges are dropped, so this is a lower bound — control flow: precision=0.4133 recall=0.9394 (33 original tokens, 75 reconstructed) — bloat 2.3x, dice ceiling ~0.6111 — low-similarity: allowance(0.00), approve(0.72), burn_from(0.66), mint(0.70), set_admin(0.00), transfer(0.34), transfer_from(0.58)
- **semantic** 0.8333 — precision=0.8537 recall=0.8140 (43 original facts, 41 reconstructed) — under-recovered: event, panic:bare, storage:get:temporary:DataKey::Allowance — over-recovered: panic:unwrap, storage:get:instance:?, storage:set:instance:?
- **behavior** n/a — behavior unavailable: crate does not build: error: failed to download `jiff-tzdb v0.1.8`

### token-v23-stripped

- **interface** 0.0000 — entrypoints 0.0000  precision=n/a recall=0.0000 (13 original, 0 reconstructed) — entrypoints missing: fn __constructor, fn allowance, fn approve, fn balance, fn burn, fn burn_from, fn decimals, fn mint, … (+5) — types 0.0000  precision=n/a recall=0.0000 (4 original, 0 reconstructed) — types missing: type AllowanceDataKey, type AllowanceValue, type DataKey, type SetAdmin
- **structure** 0.2104 — 13 entrypoints (0 unreconstructed, 0 without control flow) — ambiguous names (2 original, 0 reconstructed) — their call edges are dropped, so this is a lower bound — control flow: precision=0.1626 recall=1.0000 (33 original tokens, 203 reconstructed) — bloat 6.2x, dice ceiling ~0.2797 — low-similarity: __constructor(0.20), allowance(0.20), approve(0.31), balance(0.26), burn(0.37), burn_from(0.46), decimals(0.00), mint(0.28), … (+5)
- **semantic** 0.6329 — precision=0.6944 recall=0.5814 (43 original facts, 36 reconstructed) — under-recovered: event, panic:bare, panic:unwrap, storage:extend_ttl:persistent:DataKey::Balance, storage:extend_ttl:temporary:DataKey::Allowance, storage:get:instance:DataKey::Admin, storage:get:persistent:DataKey::Balance, storage:get:temporary:DataKey::Allowance, … (+3) — over-recovered: storage:extend_ttl:persistent:?, storage:extend_ttl:temporary:?, storage:get:instance:?, storage:get:persistent:?, storage:get:temporary:?, storage:set:instance:?, storage:set:persistent:?, storage:set:temporary:?
- **behavior** n/a — behavior unavailable: samples/contracts/token-v23-stripped/token-v23-stripped.wasm has no `contractenvmetav0` section, so the host cannot load it and it cannot serve as a behaviour oracle

### timelock

- **interface** 1.0000 — entrypoints 1.0000  precision=1.0000 recall=1.0000 (2 original, 2 reconstructed) — types 1.0000  precision=1.0000 recall=1.0000 (4 original, 4 reconstructed)
- **structure** 0.5833 — 2 entrypoints (0 unreconstructed, 0 without control flow) — ambiguous names (2 original, 2 reconstructed) — their call edges are dropped, so this is a lower bound — control flow: precision=0.4167 recall=1.0000 (5 original tokens, 12 reconstructed) — bloat 2.4x, dice ceiling ~0.5882 — low-similarity: claim(0.67), deposit(0.50)
- **semantic** 0.8276 — precision=1.0000 recall=0.7059 (17 original facts, 12 reconstructed) — under-recovered: panic:bare, xcall:transfer
- **behavior** n/a — behavior unavailable: crate does not build: error: failed to download `jiff-tzdb v0.1.8`

### dex-liquidity-pool

- **interface** 1.0000 — entrypoints 1.0000  precision=1.0000 recall=1.0000 (6 original, 6 reconstructed) — types 1.0000  precision=1.0000 recall=1.0000 (1 original, 1 reconstructed)
- **structure** 0.4784 — 6 entrypoints (0 unreconstructed, 1 without control flow) — ambiguous names (1 original, 1 reconstructed) — their call edges are dropped, so this is a lower bound — control flow: precision=0.3158 recall=0.7826 (23 original tokens, 57 reconstructed) — bloat 2.5x, dice ceiling ~0.5750 — low-similarity: balance_shares(0.00), deposit(0.32), swap(0.64), withdraw(0.43)
- **semantic** 0.6750 — precision=0.6923 recall=0.6585 (41 original facts, 39 reconstructed) — under-recovered: panic:bare, xcall:transfer — over-recovered: ledger:current_contract_address, storage:set:instance:DataKey::ReserveA, storage:set:instance:DataKey::ReserveB, storage:set:instance:DataKey::TotalShares, storage:set:persistent:DataKey::Shares
- **behavior** n/a — behavior unavailable: crate does not build: error: failed to download `jiff-tzdb v0.1.8`

### attestation

- **interface** 1.0000 — entrypoints 1.0000  precision=1.0000 recall=1.0000 (6 original, 6 reconstructed) — types 1.0000  precision=1.0000 recall=1.0000 (1 original, 1 reconstructed)
- **structure** 1.0000 — 6 entrypoints (0 unreconstructed, 4 without control flow) — ambiguous names (2 original, 2 reconstructed) — their call edges are dropped, so this is a lower bound — control flow: precision=1.0000 recall=1.0000 (3 original tokens, 3 reconstructed) — bloat 1.0x, dice ceiling ~1.0000
- **semantic** 1.0000 — precision=1.0000 recall=1.0000 (5 original facts, 5 reconstructed)
- **behavior** n/a — behavior unavailable: crate does not build: error: failed to download `jiff-tzdb v0.1.8`

