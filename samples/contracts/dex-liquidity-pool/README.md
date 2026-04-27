# dex-liquidity-pool

A constant-product AMM (automated market maker) contract from
`stellar/soroban-examples` v23.0.0. Pairs two tokens, mints LP-share
tokens to liquidity providers, charges a fee on swaps, and uses the
classic `x * y = k` invariant.

This is the corpus's representation of **DeFi-style smart contracts**:
multi-token math, share accounting, fee mechanics. While simpler than
Soroswap's actual production AMM, it exercises the same core patterns.

## What this fixture exercises

### AMM math

The contract implements the classic constant-product invariant
`reserve_a * reserve_b = k`. Every swap solves for the output amount
that preserves `k` (minus fees). This involves:

- `i128` multiplication and division (with overflow protection)
- `num-integer::Roots::sqrt` for LP-share initial mint (`sqrt(a*b)`)
- Per-step fee deduction (3/1000 fee on swaps)

These compile to non-trivial WASM arithmetic sequences that semantic
recovery passes will need to collapse back to `a * b / c`-style
expressions.

### Multi-token storage

The pool tracks balances of two tokens (`token_a`, `token_b`) plus an
LP-share token. Storage entries:

- `instance` — pair tokens (`token_a`, `token_b`), share token contract address
- `instance` — total LP shares minted
- (LP share balances are stored in the share-token contract via
  cross-contract calls, not in the pool's own storage)

### Cross-contract calls

The pool calls *out* to:

- Both pair token contracts (`transfer`, `transfer_from`) for liquidity in/out
- The LP-share token contract (`mint`, `burn`, `total_supply`) on every
  liquidity event

This is the **multi-target cross-contract call** pattern: a single
contract calls into 3+ external contracts. `try_call` is not used —
failures unwind the entire call.

### LP-share mint/burn

`deposit` (add liquidity):

1. Pull token_a + token_b from caller via `transfer_from`.
2. Compute LP shares to mint: `min(a / total_a, b / total_b) * total_supply`,
   or `sqrt(a * b)` for the first deposit.
3. Mint LP shares to caller.

`withdraw` (remove liquidity):

1. Burn LP shares from caller.
2. Compute proportional `a` and `b` to return: `share / total_supply *
   reserves`.
3. `transfer` both tokens back to caller.

These compile to specific arithmetic patterns that benchmark the
decompiler's ability to recover proportional-share math.

### Auth chain

Every state-mutating entry takes `to: Address` and calls
`to.require_auth()`. No admin role — fully permissionless.

## What this fixture does NOT exercise

- No events (the pool is silent — does not emit on swap/deposit/withdraw)
- No oracle integration (price is purely on-chain reserves)
- No flash-loan pattern (no `try_call` / mid-call invariant relaxation)
- No multi-pool factory (single self-contained pool)
- No dynamic fee curves (fixed 3/1000)

## Why this fixture is in the corpus

A decompiler that ships without a DEX fixture has a credibility
problem — DeFi is the most common Soroban contract type after tokens.
Liquidity-pool exercises the patterns that token + timelock can't
reach: constant-product math, multi-token coordination, LP-share
accounting.

It is also (at 10,516 bytes) the **largest fixture** in the corpus —
50 functions of real arithmetic-heavy logic. If the decompiler chokes,
this is where it'll choke first.

## Soroswap as Phase 2 expansion

Production Soroswap on Stellar mainnet uses a multi-contract
architecture: a factory deploys per-pair contracts, a library
provides shared math, a router orchestrates swaps across multiple
pools. Vendoring a production-shape Soroswap pair contract is a Phase 2
task — it expands the corpus to include real production complexity
(multi-contract deployment, version-skewed dependencies, audited code).

`dex-liquidity-pool/` is the Phase 1 stand-in: not real production,
but real AMM patterns.
