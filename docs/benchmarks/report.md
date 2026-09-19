# Reconstruction accuracy report

Scorer `score-2.0.0`, threshold 0.90. Reconstruction (`sordec decompile`) scored directory-vs-directory against each fixture's vendored source. Compilation is a gate and is not evaluated here. Regenerate with `SORDEC_BENCH_WRITE=1 cargo test -p sordec --test benchmark -- --ignored`.

**Two aggregates, and they answer different questions.** The AST-only mean covers interface, structure and semantic; it is the figure comparable with the committed accuracy bands and with every earlier measurement, so it stays the headline. The second adds `behavior` — differential execution of the recompiled reconstruction against the original wasm — which is measurable on 2 of 7 fixtures today, because the other 5 do not yet compile. An unmeasurable category is reported `n/a` and renormalises out of that fixture's mean; it is never a zero, since "does not build" and "does the wrong thing" are different findings.

| fixture | overall (AST) | interface | structure | semantic | behavior |
|---|---|---|---|---|---|
| hello-add | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 |
| token-v22 | 0.8592 | 0.9286 | 0.7744 | 0.8605 | n/a |
| token-v23 | 0.7715 | 0.7500 | 0.7232 | 0.8333 | n/a |
| token-v23-stripped | 0.2890 | 0.0000 | 0.2230 | 0.6329 | n/a |
| timelock | 0.8166 | 1.0000 | 0.5833 | 0.8276 | n/a |
| dex-liquidity-pool | 0.7525 | 1.0000 | 0.5486 | 0.6750 | n/a |
| attestation | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| **aggregate (mean, AST)** | **0.7841** | | | | |
| **aggregate (mean, incl. behaviour)** | **0.7841** | | | | |

## Per-fixture detail

### hello-add

- **interface** 1.0000 — entrypoints 1.0000  precision=1.0000 recall=1.0000 (1 original, 1 reconstructed)
- **structure** 0.0000 — no entrypoint carries control flow on either side — nothing to measure
- **semantic** 0.0000 — no semantic facts on either side — nothing to measure
- **behavior** 1.0000 — 1 of 1 entrypoints driven; return 9/9; 3 trivial agreement(s) excluded

### token-v22

- **interface** 0.9286 — entrypoints 1.0000  precision=1.0000 recall=1.0000 (13 original, 13 reconstructed) — types 0.8571  precision=0.7500 recall=1.0000 (3 original, 4 reconstructed) — types extra: type TokenMetadata
- **structure** 0.7744 — 13 entrypoints (0 unreconstructed, 4 without control flow) — ambiguous names (2 original, 2 reconstructed) — their call edges are dropped, so this is a lower bound — control flow: precision=0.6200 recall=0.9394 (33 original tokens, 50 reconstructed) — bloat 1.5x, dice ceiling ~0.7952 — low-similarity: allowance(0.43), approve(0.52), burn_from(0.73), transfer_from(0.73)
- **semantic** 0.8605 — precision=0.8605 recall=0.8605 (43 original facts, 43 reconstructed) — under-recovered: panic:bare, storage:get:temporary:DataKey::Allowance — over-recovered: panic:unwrap, storage:get:instance:?, storage:set:instance:?
- **behavior** n/a — behavior unavailable: crate does not build: error[E0308]: mismatched types

### token-v23

- **interface** 0.7500 — entrypoints 1.0000  precision=1.0000 recall=1.0000 (13 original, 13 reconstructed) — types 0.5000  precision=0.3333 recall=1.0000 (4 original, 12 reconstructed) — types extra: type Approve, type Burn, type Clawback, type Mint, type MintWithAmountOnly, type TokenMetadata, type Transfer, type TransferWithAmountOnly
- **structure** 0.7232 — 13 entrypoints (0 unreconstructed, 4 without control flow) — ambiguous names (2 original, 3 reconstructed) — their call edges are dropped, so this is a lower bound — control flow: precision=0.5000 recall=0.9394 (33 original tokens, 62 reconstructed) — bloat 1.9x, dice ceiling ~0.6947 — low-similarity: allowance(0.43), approve(0.52), burn_from(0.73), transfer(0.37), transfer_from(0.68)
- **semantic** 0.8333 — precision=0.8537 recall=0.8140 (43 original facts, 41 reconstructed) — under-recovered: event, panic:bare, storage:get:temporary:DataKey::Allowance — over-recovered: panic:unwrap, storage:get:instance:?, storage:set:instance:?
- **behavior** n/a — behavior unavailable: crate does not build: error[E0308]: mismatched types

### token-v23-stripped

- **interface** 0.0000 — entrypoints 0.0000  precision=n/a recall=0.0000 (13 original, 0 reconstructed) — entrypoints missing: fn __constructor, fn allowance, fn approve, fn balance, fn burn, fn burn_from, fn decimals, fn mint, … (+5) — types 0.0000  precision=n/a recall=0.0000 (4 original, 0 reconstructed) — types missing: type AllowanceDataKey, type AllowanceValue, type DataKey, type SetAdmin
- **structure** 0.2230 — 13 entrypoints (0 unreconstructed, 0 without control flow) — ambiguous names (2 original, 0 reconstructed) — their call edges are dropped, so this is a lower bound — control flow: precision=0.1737 recall=1.0000 (33 original tokens, 190 reconstructed) — bloat 5.8x, dice ceiling ~0.2960 — low-similarity: __constructor(0.20), allowance(0.24), approve(0.33), balance(0.26), burn(0.37), burn_from(0.48), decimals(0.00), mint(0.31), … (+5)
- **semantic** 0.6329 — precision=0.6944 recall=0.5814 (43 original facts, 36 reconstructed) — under-recovered: event, panic:bare, panic:unwrap, storage:extend_ttl:persistent:DataKey::Balance, storage:extend_ttl:temporary:DataKey::Allowance, storage:get:instance:DataKey::Admin, storage:get:persistent:DataKey::Balance, storage:get:temporary:DataKey::Allowance, … (+3) — over-recovered: storage:extend_ttl:persistent:?, storage:extend_ttl:temporary:?, storage:get:instance:?, storage:get:persistent:?, storage:get:temporary:?, storage:set:instance:?, storage:set:persistent:?, storage:set:temporary:?
- **behavior** n/a — behavior unavailable: samples/contracts/token-v23-stripped/token-v23-stripped.wasm has no `contractenvmetav0` section, so the host cannot load it and it cannot serve as a behaviour oracle

### timelock

- **interface** 1.0000 — entrypoints 1.0000  precision=1.0000 recall=1.0000 (2 original, 2 reconstructed) — types 1.0000  precision=1.0000 recall=1.0000 (4 original, 4 reconstructed)
- **structure** 0.5833 — 2 entrypoints (0 unreconstructed, 0 without control flow) — ambiguous names (2 original, 3 reconstructed) — their call edges are dropped, so this is a lower bound — control flow: precision=0.4167 recall=1.0000 (5 original tokens, 12 reconstructed) — bloat 2.4x, dice ceiling ~0.5882 — low-similarity: claim(0.67), deposit(0.50)
- **semantic** 0.8276 — precision=1.0000 recall=0.7059 (17 original facts, 12 reconstructed) — under-recovered: panic:bare, xcall:transfer
- **behavior** n/a — behavior unavailable: both modules build and load, but no entrypoint could be driven — 0 of 2 entrypoints drivable (skipped — claim: parameter `claimant` is an Address, which needs a value constructed against a live host; deposit: parameter `from` is an Address, which needs a value constructed against a live host)

### dex-liquidity-pool

- **interface** 1.0000 — entrypoints 1.0000  precision=1.0000 recall=1.0000 (6 original, 6 reconstructed) — types 1.0000  precision=1.0000 recall=1.0000 (1 original, 1 reconstructed)
- **structure** 0.5486 — 6 entrypoints (0 unreconstructed, 1 without control flow) — ambiguous names (1 original, 1 reconstructed) — their call edges are dropped, so this is a lower bound — control flow: precision=0.4250 recall=0.7391 (23 original tokens, 40 reconstructed) — bloat 1.7x, dice ceiling ~0.7302 — low-similarity: balance_shares(0.00), deposit(0.40), swap(0.67), withdraw(0.67)
- **semantic** 0.6750 — precision=0.6923 recall=0.6585 (41 original facts, 39 reconstructed) — under-recovered: panic:bare, xcall:transfer — over-recovered: ledger:current_contract_address, storage:set:instance:DataKey::ReserveA, storage:set:instance:DataKey::ReserveB, storage:set:instance:DataKey::TotalShares, storage:set:persistent:DataKey::Shares
- **behavior** n/a — behavior unavailable: crate does not build: error[E0308]: mismatched types

### attestation

- **interface** 1.0000 — entrypoints 1.0000  precision=1.0000 recall=1.0000 (6 original, 6 reconstructed) — types 1.0000  precision=1.0000 recall=1.0000 (1 original, 1 reconstructed)
- **structure** 1.0000 — 6 entrypoints (0 unreconstructed, 4 without control flow) — ambiguous names (2 original, 2 reconstructed) — their call edges are dropped, so this is a lower bound — control flow: precision=1.0000 recall=1.0000 (3 original tokens, 3 reconstructed) — bloat 1.0x, dice ceiling ~1.0000
- **semantic** 1.0000 — precision=1.0000 recall=1.0000 (5 original facts, 5 reconstructed)
- **behavior** 1.0000 — 2 of 6 entrypoints driven; return 20/20; 4 trivial agreement(s) excluded

