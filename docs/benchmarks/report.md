# Reconstruction accuracy report

Scorer `score-2.0.0`, threshold 0.90. Reconstruction (`sordec decompile`) scored directory-vs-directory against each fixture's vendored source. Compilation is a gate and is not evaluated here. Regenerate with `SORDEC_BENCH_WRITE=1 cargo test -p sordec --test benchmark -- --ignored`.

**Two aggregates, and they answer different questions.** The AST-only mean covers interface, structure and semantic; it is the figure comparable with the committed accuracy bands and with every earlier measurement, so it stays the headline. The second adds `behavior` — differential execution of the recompiled reconstruction against the original wasm — which is measurable on 0 of 7 fixtures today, because the other 7 do not yet compile. An unmeasurable category is reported `n/a` and renormalises out of that fixture's mean; it is never a zero, since "does not build" and "does the wrong thing" are different findings.

| fixture | overall (AST) | interface | structure | semantic | behavior |
|---|---|---|---|---|---|
| hello-add | 1.0000 | 1.0000 | 0.0000 | 0.0000 | n/a |
| token-v22 | 0.7737 | 0.9286 | 0.4496 | 0.8889 | n/a |
| token-v23 | 0.6652 | 0.6875 | 0.4038 | 0.8608 | n/a |
| token-v23-stripped | 0.2849 | 0.0000 | 0.2092 | 0.6329 | n/a |
| timelock | 0.7929 | 1.0000 | 0.5027 | 0.8276 | n/a |
| dex-liquidity-pool | 0.6164 | 1.0000 | 0.2146 | 0.5676 | n/a |
| attestation | 0.7794 | 1.0000 | 0.2500 | 1.0000 | n/a |
| **aggregate (mean, AST)** | **0.7018** | | | | |
| **aggregate (mean, incl. behaviour)** | **0.7018** | | | | |

## Per-fixture detail

### hello-add

- **interface** 1.0000 — entrypoints 1.0000  precision=1.0000 recall=1.0000 (1 original, 1 reconstructed)
- **structure** 0.0000 — no entrypoint carries control flow on either side — nothing to measure
- **semantic** 0.0000 — no semantic facts on either side — nothing to measure
- **behavior** n/a — behavior unavailable: crate does not build: error: failed to download `jiff-tzdb v0.1.8`

### token-v22

- **interface** 0.9286 — entrypoints 1.0000  precision=1.0000 recall=1.0000 (13 original, 13 reconstructed) — types 0.8571  precision=0.7500 recall=1.0000 (3 original, 4 reconstructed) — types extra: type TokenMetadata
- **structure** 0.4496 — 13 entrypoints (0 unreconstructed, 0 without control flow) — ambiguous names (2 original, 2 reconstructed) — their call edges are dropped, so this is a lower bound — control flow: precision=0.4247 recall=0.9394 (33 original tokens, 73 reconstructed) — bloat 2.2x, dice ceiling ~0.6226 — low-similarity: allowance(0.00), approve(0.72), balance(0.54), burn_from(0.66), decimals(0.00), mint(0.70), name(0.00), set_admin(0.00), … (+2)
- **semantic** 0.8889 — precision=0.9474 recall=0.8372 (43 original facts, 38 reconstructed) — under-recovered: panic:bare, panic:unwrap, storage:get:temporary:DataKey::Allowance — over-recovered: storage:get:instance:?, storage:set:instance:?
- **behavior** n/a — behavior unavailable: crate does not build: error: failed to download `jiff-tzdb v0.1.8`

### token-v23

- **interface** 0.6875 — entrypoints 1.0000  precision=1.0000 recall=1.0000 (13 original, 13 reconstructed) — types 0.3750  precision=0.2500 recall=0.7500 (4 original, 12 reconstructed) — types missing: type SetAdmin — types extra: type Approve, type Burn, type Clawback, type Mint, type MintWithAmountOnly, type SetAdmin, type TokenMetadata, type Transfer, … (+1)
- **structure** 0.4038 — 13 entrypoints (0 unreconstructed, 0 without control flow) — ambiguous names (2 original, 3 reconstructed) — their call edges are dropped, so this is a lower bound — control flow: precision=0.3483 recall=0.9394 (33 original tokens, 89 reconstructed) — bloat 2.7x, dice ceiling ~0.5410 — low-similarity: allowance(0.00), approve(0.64), balance(0.54), burn_from(0.66), decimals(0.00), mint(0.70), name(0.00), set_admin(0.00), … (+3)
- **semantic** 0.8608 — precision=0.9444 recall=0.7907 (43 original facts, 36 reconstructed) — under-recovered: event, panic:bare, panic:unwrap, storage:get:temporary:DataKey::Allowance — over-recovered: storage:get:instance:?, storage:set:instance:?
- **behavior** n/a — behavior unavailable: crate does not build: error: failed to download `jiff-tzdb v0.1.8`

### token-v23-stripped

- **interface** 0.0000 — entrypoints 0.0000  precision=n/a recall=0.0000 (13 original, 0 reconstructed) — entrypoints missing: fn __constructor, fn allowance, fn approve, fn balance, fn burn, fn burn_from, fn decimals, fn mint, … (+5) — types 0.0000  precision=n/a recall=0.0000 (4 original, 0 reconstructed) — types missing: type AllowanceDataKey, type AllowanceValue, type DataKey, type SetAdmin
- **structure** 0.2092 — 13 entrypoints (0 unreconstructed, 0 without control flow) — ambiguous names (2 original, 0 reconstructed) — their call edges are dropped, so this is a lower bound — control flow: precision=0.1618 recall=1.0000 (33 original tokens, 204 reconstructed) — bloat 6.2x, dice ceiling ~0.2785 — low-similarity: __constructor(0.20), allowance(0.20), approve(0.30), balance(0.26), burn(0.37), burn_from(0.46), decimals(0.00), mint(0.28), … (+5)
- **semantic** 0.6329 — precision=0.6944 recall=0.5814 (43 original facts, 36 reconstructed) — under-recovered: event, panic:bare, panic:unwrap, storage:extend_ttl:persistent:DataKey::Balance, storage:extend_ttl:temporary:DataKey::Allowance, storage:get:instance:DataKey::Admin, storage:get:persistent:DataKey::Balance, storage:get:temporary:DataKey::Allowance, … (+3) — over-recovered: storage:extend_ttl:persistent:?, storage:extend_ttl:temporary:?, storage:get:instance:?, storage:get:persistent:?, storage:get:temporary:?, storage:set:instance:?, storage:set:persistent:?, storage:set:temporary:?
- **behavior** n/a — behavior unavailable: samples/contracts/token-v23-stripped/token-v23-stripped.wasm has no `contractenvmetav0` section, so the host cannot load it and it cannot serve as a behaviour oracle

### timelock

- **interface** 1.0000 — entrypoints 1.0000  precision=1.0000 recall=1.0000 (2 original, 2 reconstructed) — types 1.0000  precision=1.0000 recall=1.0000 (4 original, 4 reconstructed)
- **structure** 0.5027 — 2 entrypoints (0 unreconstructed, 0 without control flow) — ambiguous names (2 original, 2 reconstructed) — their call edges are dropped, so this is a lower bound — control flow: precision=0.3333 recall=1.0000 (5 original tokens, 15 reconstructed) — bloat 3.0x, dice ceiling ~0.5000 — low-similarity: claim(0.56), deposit(0.44)
- **semantic** 0.8276 — precision=1.0000 recall=0.7059 (17 original facts, 12 reconstructed) — under-recovered: panic:bare, xcall:transfer
- **behavior** n/a — behavior unavailable: crate does not build: error: failed to download `jiff-tzdb v0.1.8`

### dex-liquidity-pool

- **interface** 1.0000 — entrypoints 1.0000  precision=1.0000 recall=1.0000 (6 original, 6 reconstructed) — types 1.0000  precision=1.0000 recall=1.0000 (1 original, 1 reconstructed)
- **structure** 0.2146 — 6 entrypoints (0 unreconstructed, 0 without control flow) — ambiguous names (1 original, 1 reconstructed) — their call edges are dropped, so this is a lower bound — control flow: precision=0.1802 recall=0.8696 (23 original tokens, 111 reconstructed) — bloat 4.8x, dice ceiling ~0.3433 — low-similarity: __constructor(0.27), balance_shares(0.00), deposit(0.26), get_rsrvs(0.00), swap(0.50), withdraw(0.26)
- **semantic** 0.5676 — precision=0.6364 recall=0.5122 (41 original facts, 33 reconstructed) — under-recovered: panic:bare, panic:unwrap, storage:get:instance:DataKey::TokenB, xcall:transfer — over-recovered: ledger:current_contract_address, storage:set:instance:?, storage:set:instance:DataKey::ReserveA, storage:set:instance:DataKey::ReserveB, storage:set:instance:DataKey::TotalShares, storage:set:persistent:DataKey::Shares
- **behavior** n/a — behavior unavailable: crate does not build: error: failed to download `jiff-tzdb v0.1.8`

### attestation

- **interface** 1.0000 — entrypoints 1.0000  precision=1.0000 recall=1.0000 (6 original, 6 reconstructed) — types 1.0000  precision=1.0000 recall=1.0000 (1 original, 1 reconstructed)
- **structure** 0.2500 — 6 entrypoints (0 unreconstructed, 2 without control flow) — ambiguous names (2 original, 2 reconstructed) — their call edges are dropped, so this is a lower bound — control flow: precision=0.1429 recall=0.6667 (3 original tokens, 14 reconstructed) — bloat 4.7x, dice ceiling ~0.3529 — low-similarity: attest(0.00), check(0.00), digest(0.00)
- **semantic** 1.0000 — precision=1.0000 recall=1.0000 (5 original facts, 5 reconstructed)
- **behavior** n/a — behavior unavailable: crate does not build: error: failed to download `jiff-tzdb v0.1.8`

