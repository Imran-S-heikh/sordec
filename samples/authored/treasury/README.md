# treasury

A community treasury. Members deposit a token, propose payments or
setting changes, and vote with a weight that depends on their role.
Once the voting period is over anyone can close a proposal, and the
admin executes the ones that passed. Written for sordec on 2026-10-31
from the Stellar developer docs' list of contract features; not
vendored from anywhere.

## What it exercises

- **Storage:** all three tiers (instance, persistent, temporary), with
  get, set, has, remove, update and `extend_ttl` on each.
- **Auth:** `require_auth` and `require_auth_for_args`.
- **Events:** `#[contractevent]` with static and dynamic topics in
  single-value, map and vec data formats, plus the older
  `events().publish`.
- **Errors:** a `#[contracterror]` enum returned through `Result`, with
  `?` and `panic_with_error!`.
- **Custom types:** a struct, a tuple struct, a unit enum, an enum with
  payloads, a `#[repr(u32)]` enum and a nested struct.
- **Calls and runtime:** a `token::Client` cross-contract call, the
  ledger timestamp, `sha256` over `to_xdr`, `log!`, and an upgrade
  through `update_current_contract_wasm`.
- **SDK types:** `Vec`, `Map`, `Bytes`, `BytesN`, `String`, `Symbol`,
  `Address`, `Option`, `i128`, `u64`, `u32`.
- **Rust features:** `match` with guards, `if let`, `let`-`else`
  destructuring of a tuple struct, `while` and `for` loops, iterator
  `filter`/`count`, closures, a trait impl, a generic helper, and
  checked arithmetic.

The source is 556 lines.

## Rebuild

See [BUILD.md](BUILD.md).
