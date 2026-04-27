# timelock

A simplified Claimable Balance contract from `stellar/soroban-examples`
v23.0.0. Deposits tokens against a list of claimants and a
before/after time bound; claimants can withdraw the balance once the
ledger timestamp falls on the right side of the bound.

## What this fixture exercises

### Time-based authorization

The contract reads `env.ledger().timestamp()` and compares against a
stored `TimeBound` enum (`Before` or `After`). This is **the canonical
ledger-time pattern** in Soroban, exercised by escrow / vesting /
claim contracts industry-wide. Phase 2's pattern recognition for
ledger-time gates validates against this fixture.

### Cross-contract token calls

`deposit` calls `token::Client::new(env, &token).transfer(&from, &env.current_contract_address(), &amount)`
to escrow tokens into itself. `claim` does the inverse — transfers from
the contract address back to the claimant. This is the **cross-contract
client call pattern** that token-v22 / token-v23 don't exercise (they
*are* the called contract, never the caller).

### Algebraic data types

The contract defines several `#[contracttype]` types:

- `DataKey` — enum tagging storage entries (`Init`, `Balance`)
- `TimeBoundKind` — enum (`Before`, `After`)
- `TimeBound` — struct `{ kind, timestamp }`
- `ClaimableBalance` — struct holding `token`, `amount`, `claimants: Vec<Address>`, `time_bound`

These compile to non-trivial XDR encoding. Recovering the type
definitions correctly is a Phase 3 challenge (especially the nested
struct `ClaimableBalance.time_bound: TimeBound`).

### Vec<Address> iteration

`claim` iterates `claimants: Vec<Address>` to check whether the
caller is in the allow-list. Vec iteration patterns are common in
real-world Soroban contracts and require correct host-function
recovery (`vec_get`, `vec_len`, etc.).

### Invoker-based auth

The contract uses `claimant.require_auth()` and `from.require_auth()`
on Address arguments — the simplest auth pattern. No allowance, no
delegated auth, no admin role. Good baseline for Phase 2's auth
recovery.

## What this fixture does NOT exercise

- No events (timelock predates `#[contractevent]` adoption in soroban-examples)
- No custom errors (uses `panic!` / `core::panic!` for failures)
- No persistent storage tier (all state is `instance`)
- No multi-contract deployment (single self-contained contract)

## Why this fixture is in the corpus

Timelock is the **smallest fixture that exercises cross-contract
token calls**. Without it, `dex-liquidity-pool/` (much larger, much riskier
to bring up) would be the only fixture exercising that pattern — a
single point of failure for an entire pattern category. Timelock is
the safety net.

It also exercises ledger-time gates, which no other fixture in the
corpus touches. Useful even after `dex-liquidity-pool` is in.
