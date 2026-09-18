# Reconstruction accuracy report

Scorer `score-2.0.0`, threshold 0.90. Reconstruction (`sordec decompile`) scored directory-vs-directory against each fixture's vendored source. Compilation is a gate and is not evaluated here. Regenerate with `SORDEC_BENCH_WRITE=1 cargo test -p sordec --test benchmark -- --ignored`.

**Two aggregates, and they answer different questions.** The AST-only mean covers interface, structure and semantic; it is the figure comparable with the committed accuracy bands and with every earlier measurement, so it stays the headline. The second adds `behavior` — differential execution of the recompiled reconstruction against the original wasm — which is measurable on 0 of 7 fixtures today, because the other 7 do not yet compile. An unmeasurable category is reported `n/a` and renormalises out of that fixture's mean; it is never a zero, since "does not build" and "does the wrong thing" are different findings.

| fixture | overall (AST) | interface | structure | semantic | behavior |
|---|---|---|---|---|---|
| hello-add | 1.0000 | 1.0000 | 0.0000 | 0.0000 | n/a |
| token-v22 | 0.7042 | 0.9286 | 0.2826 | 0.8312 | n/a |
| token-v23 | 0.6141 | 0.6875 | 0.3029 | 0.8000 | n/a |
| token-v23-stripped | 0.2870 | 0.0000 | 0.2078 | 0.6400 | n/a |
| timelock | 0.7711 | 1.0000 | 0.4787 | 0.7857 | n/a |
| dex-liquidity-pool | 0.6109 | 1.0000 | 0.2084 | 0.5574 | n/a |
| attestation | 0.7794 | 1.0000 | 0.2500 | 1.0000 | n/a |
| **aggregate (mean, AST)** | **0.6810** | | | | |
| **aggregate (mean, incl. behaviour)** | **0.6810** | | | | |

## Per-fixture detail

### hello-add

- **interface** 1.0000 — entrypoints 1.0000  precision=1.0000 recall=1.0000 (1 original, 1 reconstructed)
- **structure** 0.0000 — no entrypoint carries control flow on either side — nothing to measure
- **semantic** 0.0000 — no semantic facts on either side — nothing to measure
- **behavior** n/a — behavior unavailable: crate does not build: error: failed to download `jiff-tzdb v0.1.8`

### token-v22

- **interface** 0.9286 — entrypoints 1.0000  precision=1.0000 recall=1.0000 (13 original, 13 reconstructed) — types 0.8571  precision=0.7500 recall=1.0000 (3 original, 4 reconstructed) — types extra: type TokenMetadata
- **structure** 0.2826 — 13 entrypoints (0 unreconstructed, 0 without control flow) — ambiguous names (2 original, 2 reconstructed) — their call edges are dropped, so this is a lower bound — control flow: precision=0.2246 recall=0.9394 (33 original tokens, 138 reconstructed) — bloat 4.2x, dice ceiling ~0.3860 — low-similarity: allowance(0.00), approve(0.37), balance(0.17), burn(0.38), burn_from(0.55), decimals(0.00), mint(0.27), name(0.00), … (+4)
- **semantic** 0.8312 — precision=0.9412 recall=0.7442 (43 original facts, 34 reconstructed) — under-recovered: panic:bare, panic:unwrap, storage:extend_ttl:persistent:DataKey::Balance, storage:extend_ttl:temporary:DataKey::Allowance, storage:get:temporary:DataKey::Allowance — over-recovered: storage:get:instance:?, storage:set:instance:?
- **behavior** n/a — behavior unavailable: crate does not build: error: failed to download `jiff-tzdb v0.1.8`

### token-v23

- **interface** 0.6875 — entrypoints 1.0000  precision=1.0000 recall=1.0000 (13 original, 13 reconstructed) — types 0.3750  precision=0.2500 recall=0.7500 (4 original, 12 reconstructed) — types missing: type SetAdmin — types extra: type Approve, type Burn, type Clawback, type Mint, type MintWithAmountOnly, type SetAdmin, type TokenMetadata, type Transfer, … (+1)
- **structure** 0.3029 — 13 entrypoints (0 unreconstructed, 0 without control flow) — ambiguous names (2 original, 3 reconstructed) — their call edges are dropped, so this is a lower bound — control flow: precision=0.2460 recall=0.9394 (33 original tokens, 126 reconstructed) — bloat 3.8x, dice ceiling ~0.4151 — low-similarity: allowance(0.00), approve(0.45), balance(0.26), burn(0.51), burn_from(0.56), decimals(0.00), mint(0.37), name(0.00), … (+4)
- **semantic** 0.8000 — precision=0.9375 recall=0.6977 (43 original facts, 32 reconstructed) — under-recovered: event, panic:bare, panic:unwrap, storage:extend_ttl:persistent:DataKey::Balance, storage:extend_ttl:temporary:DataKey::Allowance, storage:get:temporary:DataKey::Allowance — over-recovered: storage:get:instance:?, storage:set:instance:?
- **behavior** n/a — behavior unavailable: crate does not build: error: failed to download `jiff-tzdb v0.1.8`

### token-v23-stripped

- **interface** 0.0000 — entrypoints 0.0000  precision=n/a recall=0.0000 (13 original, 0 reconstructed) — entrypoints missing: fn __constructor, fn allowance, fn approve, fn balance, fn burn, fn burn_from, fn decimals, fn mint, … (+5) — types 0.0000  precision=n/a recall=0.0000 (4 original, 0 reconstructed) — types missing: type AllowanceDataKey, type AllowanceValue, type DataKey, type SetAdmin
- **structure** 0.2078 — 13 entrypoints (0 unreconstructed, 0 without control flow) — ambiguous names (2 original, 0 reconstructed) — their call edges are dropped, so this is a lower bound — control flow: precision=0.1602 recall=1.0000 (33 original tokens, 206 reconstructed) — bloat 6.2x, dice ceiling ~0.2762 — low-similarity: __constructor(0.20), allowance(0.20), approve(0.30), balance(0.26), burn(0.37), burn_from(0.46), decimals(0.00), mint(0.26), … (+5)
- **semantic** 0.6400 — precision=0.7500 recall=0.5581 (43 original facts, 32 reconstructed) — under-recovered: event, panic:bare, panic:unwrap, storage:extend_ttl:persistent:DataKey::Balance, storage:extend_ttl:temporary:DataKey::Allowance, storage:get:instance:DataKey::Admin, storage:get:persistent:DataKey::Balance, storage:get:temporary:DataKey::Allowance, … (+3) — over-recovered: storage:get:instance:?, storage:get:persistent:?, storage:get:temporary:?, storage:set:instance:?, storage:set:persistent:?, storage:set:temporary:?
- **behavior** n/a — behavior unavailable: samples/contracts/token-v23-stripped/token-v23-stripped.wasm has no `contractenvmetav0` section, so the host cannot load it and it cannot serve as a behaviour oracle

### timelock

- **interface** 1.0000 — entrypoints 1.0000  precision=1.0000 recall=1.0000 (2 original, 2 reconstructed) — types 1.0000  precision=1.0000 recall=1.0000 (4 original, 4 reconstructed)
- **structure** 0.4787 — 2 entrypoints (0 unreconstructed, 0 without control flow) — ambiguous names (2 original, 2 reconstructed) — their call edges are dropped, so this is a lower bound — control flow: precision=0.3125 recall=1.0000 (5 original tokens, 16 reconstructed) — bloat 3.2x, dice ceiling ~0.4762 — low-similarity: claim(0.51), deposit(0.44)
- **semantic** 0.7857 — precision=1.0000 recall=0.6471 (17 original facts, 11 reconstructed) — under-recovered: panic:bare, panic:unwrap, xcall:transfer
- **behavior** n/a — behavior unavailable: crate does not build: error: failed to download `jiff-tzdb v0.1.8`

### dex-liquidity-pool

- **interface** 1.0000 — entrypoints 1.0000  precision=1.0000 recall=1.0000 (6 original, 6 reconstructed) — types 1.0000  precision=1.0000 recall=1.0000 (1 original, 1 reconstructed)
- **structure** 0.2084 — 6 entrypoints (0 unreconstructed, 0 without control flow) — ambiguous names (1 original, 1 reconstructed) — their call edges are dropped, so this is a lower bound — control flow: precision=0.1667 recall=0.9565 (23 original tokens, 132 reconstructed) — bloat 5.7x, dice ceiling ~0.2968 — low-similarity: __constructor(0.27), balance_shares(0.00), deposit(0.27), get_rsrvs(0.00), swap(0.43), withdraw(0.28)
- **semantic** 0.5574 — precision=0.8500 recall=0.4146 (41 original facts, 20 reconstructed) — under-recovered: panic:bare, panic:unwrap, storage:get:instance:DataKey::TokenB, storage:set:instance:DataKey::ReserveA, storage:set:instance:DataKey::ReserveB, storage:set:instance:DataKey::TotalShares, storage:set:persistent:DataKey::Shares, xcall:transfer — over-recovered: ledger:current_contract_address
- **behavior** n/a — behavior unavailable: crate does not build: error: failed to download `jiff-tzdb v0.1.8`

### attestation

- **interface** 1.0000 — entrypoints 1.0000  precision=1.0000 recall=1.0000 (6 original, 6 reconstructed) — types 1.0000  precision=1.0000 recall=1.0000 (1 original, 1 reconstructed)
- **structure** 0.2500 — 6 entrypoints (0 unreconstructed, 2 without control flow) — ambiguous names (2 original, 2 reconstructed) — their call edges are dropped, so this is a lower bound — control flow: precision=0.1429 recall=0.6667 (3 original tokens, 14 reconstructed) — bloat 4.7x, dice ceiling ~0.3529 — low-similarity: attest(0.00), check(0.00), digest(0.00)
- **semantic** 1.0000 — precision=1.0000 recall=1.0000 (5 original facts, 5 reconstructed)
- **behavior** n/a — behavior unavailable: crate does not build: error: failed to download `jiff-tzdb v0.1.8`

