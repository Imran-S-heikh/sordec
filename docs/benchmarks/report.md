# Reconstruction accuracy report

Scorer `score-2.0.0`, threshold 0.90. Reconstruction (`sordec decompile`) scored directory-vs-directory against each fixture's vendored source. Compilation is a gate and is not evaluated here. Regenerate with `SORDEC_BENCH_WRITE=1 cargo test -p sordec --test benchmark -- --ignored`.

**Two aggregates, and they answer different questions.** The AST-only mean covers interface, structure and semantic; it is the figure comparable with the committed accuracy bands and with every earlier measurement, so it stays the headline. The second adds `behavior` — differential execution of the recompiled reconstruction against the original wasm — which is measurable on 0 of 7 fixtures today, because the other 7 do not yet compile. An unmeasurable category is reported `n/a` and renormalises out of that fixture's mean; it is never a zero, since "does not build" and "does the wrong thing" are different findings.

| fixture | overall (AST) | interface | structure | semantic | behavior |
|---|---|---|---|---|---|
| hello-add | 1.0000 | 1.0000 | 0.0000 | 0.0000 | n/a |
| token-v22 | 0.5831 | 0.9286 | 0.1299 | 0.6154 | n/a |
| token-v23 | 0.5038 | 0.6875 | 0.1493 | 0.6154 | n/a |
| token-v23-stripped | 0.1853 | 0.0000 | 0.1131 | 0.4308 | n/a |
| timelock | 0.6561 | 1.0000 | 0.0879 | 0.7857 | n/a |
| dex-liquidity-pool | 0.5783 | 1.0000 | 0.1041 | 0.5517 | n/a |
| attestation | 0.7794 | 1.0000 | 0.2500 | 1.0000 | n/a |
| **aggregate (mean, AST)** | **0.6123** | | | | |
| **aggregate (mean, incl. behaviour)** | **0.6123** | | | | |

## Per-fixture detail

### hello-add

- **interface** 1.0000 — entrypoints 1.0000  precision=1.0000 recall=1.0000 (1 original, 1 reconstructed)
- **structure** 0.0000 — no entrypoint carries control flow on either side — nothing to measure
- **semantic** 0.0000 — no semantic facts on either side — nothing to measure
- **behavior** n/a — behavior unavailable: crate does not build: error: failed to download `jiff-tzdb v0.1.8`

### token-v22

- **interface** 0.9286 — entrypoints 1.0000  precision=1.0000 recall=1.0000 (13 original, 13 reconstructed) — types 0.8571  precision=0.7500 recall=1.0000 (3 original, 4 reconstructed) — types extra: type TokenMetadata
- **structure** 0.1299 — 13 entrypoints (0 unreconstructed, 0 without control flow) — ambiguous names (2 original, 2 reconstructed) — their call edges are dropped, so this is a lower bound — control flow: precision=0.0652 recall=1.0000 (33 original tokens, 506 reconstructed) — bloat 15.3x, dice ceiling ~0.1224 — low-similarity: __constructor(0.54), allowance(0.09), approve(0.13), balance(0.06), burn(0.13), burn_from(0.26), decimals(0.00), mint(0.09), … (+5)
- **semantic** 0.6154 — precision=0.9091 recall=0.4651 (43 original facts, 22 reconstructed) — under-recovered: event, ledger:sequence, panic:bare, panic:unwrap, storage:extend_ttl:instance:?, storage:extend_ttl:persistent:DataKey::Balance, storage:extend_ttl:temporary:DataKey::Allowance, storage:get:temporary:DataKey::Allowance
- **behavior** n/a — behavior unavailable: crate does not build: error: failed to download `jiff-tzdb v0.1.8`

### token-v23

- **interface** 0.6875 — entrypoints 1.0000  precision=1.0000 recall=1.0000 (13 original, 13 reconstructed) — types 0.3750  precision=0.2500 recall=0.7500 (4 original, 12 reconstructed) — types missing: type SetAdmin — types extra: type Approve, type Burn, type Clawback, type Mint, type MintWithAmountOnly, type SetAdmin, type TokenMetadata, type Transfer, … (+1)
- **structure** 0.1493 — 13 entrypoints (0 unreconstructed, 0 without control flow) — ambiguous names (2 original, 3 reconstructed) — their call edges are dropped, so this is a lower bound — control flow: precision=0.0833 recall=1.0000 (33 original tokens, 396 reconstructed) — bloat 12.0x, dice ceiling ~0.1538 — low-similarity: __constructor(0.54), allowance(0.11), approve(0.17), balance(0.09), burn(0.18), burn_from(0.31), decimals(0.00), mint(0.12), … (+5)
- **semantic** 0.6154 — precision=0.9091 recall=0.4651 (43 original facts, 22 reconstructed) — under-recovered: event, ledger:sequence, panic:bare, panic:unwrap, storage:extend_ttl:instance:?, storage:extend_ttl:persistent:DataKey::Balance, storage:extend_ttl:temporary:DataKey::Allowance, storage:get:temporary:DataKey::Allowance
- **behavior** n/a — behavior unavailable: crate does not build: error: failed to download `jiff-tzdb v0.1.8`

### token-v23-stripped

- **interface** 0.0000 — entrypoints 0.0000  precision=n/a recall=0.0000 (13 original, 0 reconstructed) — entrypoints missing: fn __constructor, fn allowance, fn approve, fn balance, fn burn, fn burn_from, fn decimals, fn mint, … (+5) — types 0.0000  precision=n/a recall=0.0000 (4 original, 0 reconstructed) — types missing: type AllowanceDataKey, type AllowanceValue, type DataKey, type SetAdmin
- **structure** 0.1131 — 13 entrypoints (0 unreconstructed, 0 without control flow) — ambiguous names (2 original, 0 reconstructed) — their call edges are dropped, so this is a lower bound — control flow: precision=0.0782 recall=1.0000 (33 original tokens, 422 reconstructed) — bloat 12.8x, dice ceiling ~0.1451 — low-similarity: __constructor(0.13), allowance(0.10), approve(0.16), balance(0.09), burn(0.17), burn_from(0.30), decimals(0.00), mint(0.12), … (+5)
- **semantic** 0.4308 — precision=0.6364 recall=0.3256 (43 original facts, 22 reconstructed) — under-recovered: event, ledger:sequence, panic:bare, panic:unwrap, storage:extend_ttl:instance:?, storage:extend_ttl:persistent:DataKey::Balance, storage:extend_ttl:temporary:DataKey::Allowance, storage:get:instance:DataKey::Admin, … (+5)
- **behavior** n/a — behavior unavailable: samples/contracts/token-v23-stripped/token-v23-stripped.wasm has no `contractenvmetav0` section, so the host cannot load it and it cannot serve as a behaviour oracle

### timelock

- **interface** 1.0000 — entrypoints 1.0000  precision=1.0000 recall=1.0000 (2 original, 2 reconstructed) — types 1.0000  precision=1.0000 recall=1.0000 (4 original, 4 reconstructed)
- **structure** 0.0879 — 2 entrypoints (0 unreconstructed, 0 without control flow) — ambiguous names (2 original, 2 reconstructed) — their call edges are dropped, so this is a lower bound — control flow: precision=0.0407 recall=1.0000 (5 original tokens, 123 reconstructed) — bloat 24.6x, dice ceiling ~0.0781 — low-similarity: claim(0.10), deposit(0.07)
- **semantic** 0.7857 — precision=1.0000 recall=0.6471 (17 original facts, 11 reconstructed) — under-recovered: panic:bare, panic:unwrap, xcall:transfer
- **behavior** n/a — behavior unavailable: crate does not build: error: failed to download `jiff-tzdb v0.1.8`

### dex-liquidity-pool

- **interface** 1.0000 — entrypoints 1.0000  precision=1.0000 recall=1.0000 (6 original, 6 reconstructed) — types 1.0000  precision=1.0000 recall=1.0000 (1 original, 1 reconstructed)
- **structure** 0.1041 — 6 entrypoints (0 unreconstructed, 0 without control flow) — ambiguous names (1 original, 1 reconstructed) — their call edges are dropped, so this is a lower bound — control flow: precision=0.0618 recall=1.0000 (23 original tokens, 372 reconstructed) — bloat 16.2x, dice ceiling ~0.1165 — low-similarity: __constructor(0.07), balance_shares(0.06), deposit(0.15), get_rsrvs(0.00), swap(0.23), withdraw(0.12)
- **semantic** 0.5517 — precision=0.9412 recall=0.3902 (41 original facts, 17 reconstructed) — under-recovered: panic:bare, panic:unwrap, storage:get:instance:DataKey::TokenB, storage:get:persistent:DataKey::Shares, storage:set:instance:DataKey::ReserveA, storage:set:instance:DataKey::ReserveB, storage:set:instance:DataKey::TotalShares, storage:set:persistent:DataKey::Shares, … (+1)
- **behavior** n/a — behavior unavailable: crate does not build: error: failed to download `jiff-tzdb v0.1.8`

### attestation

- **interface** 1.0000 — entrypoints 1.0000  precision=1.0000 recall=1.0000 (6 original, 6 reconstructed) — types 1.0000  precision=1.0000 recall=1.0000 (1 original, 1 reconstructed)
- **structure** 0.2500 — 6 entrypoints (0 unreconstructed, 2 without control flow) — ambiguous names (2 original, 2 reconstructed) — their call edges are dropped, so this is a lower bound — control flow: precision=0.1429 recall=0.6667 (3 original tokens, 14 reconstructed) — bloat 4.7x, dice ceiling ~0.3529 — low-similarity: attest(0.00), check(0.00), digest(0.00)
- **semantic** 1.0000 — precision=1.0000 recall=1.0000 (5 original facts, 5 reconstructed)
- **behavior** n/a — behavior unavailable: crate does not build: error: failed to download `jiff-tzdb v0.1.8`

