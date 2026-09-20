# Reconstruction accuracy report

Scorer `score-2.0.0`, threshold 0.90. Reconstruction (`sordec decompile`) scored directory-vs-directory against each fixture's vendored source. Compilation is a gate and is not evaluated here. Regenerate with `SORDEC_BENCH_WRITE=1 cargo test -p sordec --test benchmark -- --ignored`.

**Two aggregates, and they answer different questions.** The AST-only mean covers interface, structure and semantic; it is the figure comparable with the committed accuracy bands and with every earlier measurement, so it stays the headline. The second adds `behavior` — differential execution of the recompiled reconstruction against the original wasm — which is measurable on 2 of 7 fixtures today, because the other 5 do not yet compile. An unmeasurable category is reported `n/a` and renormalises out of that fixture's mean; it is never a zero, since "does not build" and "does the wrong thing" are different findings.

| fixture | overall (AST) | interface | structure | semantic | behavior |
|---|---|---|---|---|---|
| hello-add | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 |
| token-v22 | 0.8980 | 0.9286 | 0.9063 | 0.8605 | n/a |
| token-v23 | 0.8117 | 0.7500 | 0.8598 | 0.8333 | n/a |
| token-v23-stripped | 0.3802 | 0.0385 | 0.4870 | 0.6329 | n/a |
| timelock | 0.9391 | 1.0000 | 1.0000 | 0.8276 | n/a |
| dex-liquidity-pool | 0.7783 | 1.0000 | 0.6362 | 0.6750 | n/a |
| attestation | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| **aggregate (mean, AST)** | **0.8296** | | | | |
| **aggregate (mean, incl. behaviour)** | **0.8296** | | | | |

## Per-fixture detail

### hello-add

- **interface** 1.0000 — entrypoints 1.0000  precision=1.0000 recall=1.0000 (1 original, 1 reconstructed)
- **structure** 0.0000 — no entrypoint carries control flow on either side — nothing to measure
- **semantic** 0.0000 — no semantic facts on either side — nothing to measure
- **behavior** 1.0000 — 1 of 1 entrypoints driven; return 9/9; 3 trivial agreement(s) excluded

### token-v22

- **interface** 0.9286 — entrypoints 1.0000  precision=1.0000 recall=1.0000 (13 original, 13 reconstructed) — types 0.8571  precision=0.7500 recall=1.0000 (3 original, 4 reconstructed) — types extra: type TokenMetadata
- **structure** 0.9063 — 13 entrypoints (0 unreconstructed, 4 without control flow) — ambiguous names (2 original, 2 reconstructed) — their call edges are dropped, so this is a lower bound — control flow: precision=0.7500 recall=1.0000 (33 original tokens, 44 reconstructed) — bloat 1.3x, dice ceiling ~0.8571
- **semantic** 0.8605 — precision=0.8605 recall=0.8605 (43 original facts, 43 reconstructed) — under-recovered: panic:bare, storage:get:temporary:DataKey::Allowance — over-recovered: panic:unwrap, storage:get:instance:?, storage:set:instance:?
- **behavior** n/a — behavior unavailable: crate does not build: error[E0308]: mismatched types

### token-v23

- **interface** 0.7500 — entrypoints 1.0000  precision=1.0000 recall=1.0000 (13 original, 13 reconstructed) — types 0.5000  precision=0.3333 recall=1.0000 (4 original, 12 reconstructed) — types extra: type Approve, type Burn, type Clawback, type Mint, type MintWithAmountOnly, type TokenMetadata, type Transfer, type TransferWithAmountOnly
- **structure** 0.8598 — 13 entrypoints (0 unreconstructed, 4 without control flow) — ambiguous names (2 original, 3 reconstructed) — their call edges are dropped, so this is a lower bound — control flow: precision=0.6346 recall=1.0000 (33 original tokens, 52 reconstructed) — bloat 1.6x, dice ceiling ~0.7765 — low-similarity: transfer(0.44)
- **semantic** 0.8333 — precision=0.8537 recall=0.8140 (43 original facts, 41 reconstructed) — under-recovered: event, panic:bare, storage:get:temporary:DataKey::Allowance — over-recovered: panic:unwrap, storage:get:instance:?, storage:set:instance:?
- **behavior** n/a — behavior unavailable: crate does not build: error[E0308]: mismatched types

### token-v23-stripped

- **interface** 0.0385 — entrypoints 0.0769  precision=0.0769 recall=0.0769 (13 original, 13 reconstructed) — entrypoints missing: fn __constructor, fn allowance, fn approve, fn balance, fn burn, fn burn_from, fn mint, fn name, … (+4) — entrypoints extra: fn __constructor, fn allowance, fn approve, fn balance, fn burn, fn burn_from, fn mint, fn name, … (+4) — types 0.0000  precision=0.0000 recall=0.0000 (4 original, 1 reconstructed) — types missing: type AllowanceDataKey, type AllowanceValue, type DataKey, type SetAdmin — types extra: type StorageKey
- **structure** 0.4870 — 13 entrypoints (0 unreconstructed, 0 without control flow) — ambiguous names (2 original, 1 reconstructed) — their call edges are dropped, so this is a lower bound — control flow: precision=0.3367 recall=1.0000 (33 original tokens, 98 reconstructed) — bloat 3.0x, dice ceiling ~0.5038 — low-similarity: allowance(0.41), burn(0.69), burn_from(0.66), decimals(0.00), name(0.00), set_admin(0.00), symbol(0.00), transfer(0.41), … (+1)
- **semantic** 0.6329 — precision=0.6944 recall=0.5814 (43 original facts, 36 reconstructed) — under-recovered: event, panic:bare, panic:unwrap, storage:extend_ttl:persistent:DataKey::Balance, storage:extend_ttl:temporary:DataKey::Allowance, storage:get:instance:DataKey::Admin, storage:get:persistent:DataKey::Balance, storage:get:temporary:DataKey::Allowance, … (+3) — over-recovered: storage:extend_ttl:persistent:StorageKey::Balance, storage:extend_ttl:temporary:StorageKey::Allowance, storage:get:instance:?, storage:get:instance:StorageKey::Admin, storage:get:persistent:StorageKey::Balance, storage:get:temporary:StorageKey::Allowance, storage:set:instance:?, storage:set:instance:StorageKey::Admin, … (+2)
- **behavior** n/a — behavior unavailable: samples/contracts/token-v23-stripped/token-v23-stripped.wasm has no `contractenvmetav0` section, so the host cannot load it and it cannot serve as a behaviour oracle

### timelock

- **interface** 1.0000 — entrypoints 1.0000  precision=1.0000 recall=1.0000 (2 original, 2 reconstructed) — types 1.0000  precision=1.0000 recall=1.0000 (4 original, 4 reconstructed)
- **structure** 1.0000 — 2 entrypoints (0 unreconstructed, 0 without control flow) — ambiguous names (2 original, 3 reconstructed) — their call edges are dropped, so this is a lower bound — control flow: precision=1.0000 recall=1.0000 (5 original tokens, 5 reconstructed) — bloat 1.0x, dice ceiling ~1.0000
- **semantic** 0.8276 — precision=1.0000 recall=0.7059 (17 original facts, 12 reconstructed) — under-recovered: panic:bare, xcall:transfer
- **behavior** n/a — behavior unavailable: both modules build and load, but no entrypoint could be driven — 0 of 2 entrypoints drivable (skipped — claim: parameter `claimant` is an Address, which needs a value constructed against a live host; deposit: parameter `from` is an Address, which needs a value constructed against a live host)

### dex-liquidity-pool

- **interface** 1.0000 — entrypoints 1.0000  precision=1.0000 recall=1.0000 (6 original, 6 reconstructed) — types 1.0000  precision=1.0000 recall=1.0000 (1 original, 1 reconstructed)
- **structure** 0.6362 — 6 entrypoints (0 unreconstructed, 1 without control flow) — ambiguous names (1 original, 1 reconstructed) — their call edges are dropped, so this is a lower bound — control flow: precision=0.5000 recall=0.9130 (23 original tokens, 42 reconstructed) — bloat 1.8x, dice ceiling ~0.7077 — low-similarity: balance_shares(0.00), deposit(0.40)
- **semantic** 0.6750 — precision=0.6923 recall=0.6585 (41 original facts, 39 reconstructed) — under-recovered: panic:bare, xcall:transfer — over-recovered: ledger:current_contract_address, storage:set:instance:DataKey::ReserveA, storage:set:instance:DataKey::ReserveB, storage:set:instance:DataKey::TotalShares, storage:set:persistent:DataKey::Shares
- **behavior** n/a — behavior unavailable: crate does not build: error[E0308]: mismatched types

### attestation

- **interface** 1.0000 — entrypoints 1.0000  precision=1.0000 recall=1.0000 (6 original, 6 reconstructed) — types 1.0000  precision=1.0000 recall=1.0000 (1 original, 1 reconstructed)
- **structure** 1.0000 — 6 entrypoints (0 unreconstructed, 4 without control flow) — ambiguous names (2 original, 2 reconstructed) — their call edges are dropped, so this is a lower bound — control flow: precision=1.0000 recall=1.0000 (3 original tokens, 3 reconstructed) — bloat 1.0x, dice ceiling ~1.0000
- **semantic** 1.0000 — precision=1.0000 recall=1.0000 (5 original facts, 5 reconstructed)
- **behavior** 1.0000 — 2 of 6 entrypoints driven; return 20/20; 4 trivial agreement(s) excluded

