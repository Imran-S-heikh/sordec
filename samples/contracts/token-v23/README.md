# token-v23

The canonical SEP-41 token contract from `stellar/soroban-examples`,
vendored at tag `v23.0.0` and built against `soroban-sdk 23.0.1`.

This is the **canonical real-world Soroban contract** — every deployed
token on Stellar mainnet uses an implementation of this interface. The
decompiler's accuracy on this fixture is a load-bearing benchmark for
the grant deliverable.

## What this fixture exercises

### Storage tiers

The token uses all three Soroban storage tiers (instance, persistent,
temporary):

- `instance` — admin address, token metadata (decimals, name, symbol)
- `persistent` — balance entries (per-account)
- `temporary` — allowance entries (with explicit expiration ledger)

A correct decompiler must distinguish these tiers — emitting
`env.storage().persistent()` where the source uses persistent, etc.
This fixture is the canonical test case for storage-tier recovery.

### Authorization

Every state-mutating entry point calls `require_auth()` on a specific
`Address`:

- `transfer` — auth on `from`
- `transfer_from` — auth on `spender`, with allowance check
- `approve` — auth on `from`
- `burn` — auth on `from`
- `burn_from` — auth on `spender`
- `mint` — auth on `admin` (instance storage lookup)
- `set_admin` — auth on current `admin`

The auth chain pattern (lookup admin from instance storage → require_auth
on the result) is one of the harder patterns to recover.

### Events

Token operations emit events with multi-symbol topics, e.g.:

- `transfer`: topics `("transfer", from, to)`, data `amount`
- `approve`: topics `("approve", from, spender)`, data `(amount, expiration)`
- `mint`: topics `("mint", admin, to)`, data `amount`
- `set_admin`: topics `("set_admin", admin)`, data `new_admin`
- `burn`: topics `("burn", from)`, data `amount`
- `clawback`: topics `("clawback", admin, from)`, data `amount`
- `set_authorized`: topics `("set_authorized", admin, id)`, data `authorize`

Event reconstruction (Phase 3) will validate against this fixture's
`#[contractevent]` definitions.

### Custom errors

The token defines a `TokenError` enum with `#[contracterror]`. A correct
decompiler reconstructs the enum and wires it to the `Result<T, TokenError>`
return types.

### Integer arithmetic

Token amounts are `i128`. The contract performs:

- `checked_add` and `checked_sub` on balances (overflow protection)
- `checked_mul` in some calls
- Negative-amount checks (reject `amount < 0`)

The compiler lowers `i128` arithmetic into multi-instruction WASM
sequences. A correct decompiler collapses these back to single
expressions (`a + b`, not the WASM-level i64 pair manipulation).

### Cross-contract reads

`token-v23` does not call into other contracts directly, but it is
*called* by every cross-contract pattern in the ecosystem (DEXes, lending
pools, etc.). It defines the **client-side interface** that other
fixtures consume (`dex-liquidity-pool` would call `token-v23`-like clients,
though it does not in this fixture's vendored form).

## What this fixture does NOT exercise

- No multi-contract deployment (single-contract fixture)
- No `try_call` / error recovery patterns
- No re-entrancy patterns (the token is reentrancy-safe by design but
  doesn't demonstrate the pattern)
- No `Bytes`/`String`/`Symbol` packing beyond simple cases (advanced
  Val-encoding patterns are exercised by other fixtures)

## Source layout

The source under `source/src/` is split into modules, mirroring upstream:

| File | Responsibility |
|------|----------------|
| `lib.rs` | Module wiring and the public `TokenContract` struct |
| `contract.rs` | Entry-point implementations (`transfer`, `approve`, ...) |
| `admin.rs` | Admin storage helpers (instance tier) |
| `balance.rs` | Balance storage + checked arithmetic (persistent tier) |
| `allowance.rs` | Allowance storage + expiration logic (temporary tier) |
| `metadata.rs` | Token metadata helpers (decimals/name/symbol) |
| `storage_types.rs` | `DataKey` enum tagging storage entries |
| `test.rs` | Upstream's testutils-based test suite (NOT compiled by `build.sh`) |

`build.sh` compiles `--release` only, which skips `test.rs`. The dev
dependency on `soroban-sdk[testutils]` is preserved for fidelity but
unused by the WASM build.
