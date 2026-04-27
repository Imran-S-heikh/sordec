# token-v22

The same SEP-41 token source as `token-v23/`, compiled against
`soroban-sdk 22.0.x` and the older `wasm32-unknown-unknown` target.

This fixture's value is **cross-version testing**: it exercises the
decompiler's ability to handle WASM produced by an older SDK + target
generation, alongside the canonical `token-v23/` produced by the
current generation.

## What this fixture exercises

Same SEP-41 surface as `token-v23/`:

- Three-tier storage (instance / persistent / temporary)
- Auth chain (`require_auth` per entry point, `transfer_from` with allowance)
- Multi-topic events (transfer, approve, mint, burn, set_admin, …)
- Custom `TokenError` enum with `#[contracterror]`
- `i128` checked arithmetic on balances

## Cross-version coverage (versus token-v23)

The motivation for shipping both is **decompiler resilience across SDK
generations**. The two fixtures differ in:

| | token-v22 | token-v23 |
|---|---|---|
| WASM target | `wasm32-unknown-unknown` | `wasm32v1-none` |
| Imports | 15 host functions | 19 host functions |
| Function count | 48 | 46 |
| Host-function ABI | v22 generation | v23 generation |
| Code section size | similar | similar |

The most consequential difference is the **15 vs 19 host imports**.
Different SDK generations chose different host-function decompositions
for the same operation. For example, v22's allowance lookup may pack
into one `get_contract_data` call where v23 splits it across two.

A decompiler that recovers `env.storage().temporary().get(...)` from
the v23 imports must also recover the same pattern from v22's different
underlying calls. Phase 2 storage-tier recovery validates against both
fixtures to prove the recognition is SDK-version-agnostic.

## What this fixture does NOT exercise

The source is identical to `token-v23/` — same features, same code
paths. Functional differences from v23 come from the SDK / target
choice, not the contract logic. For features specific to a contract
*type*, see other fixtures (DEX patterns in `dex-liquidity-pool/`, time
patterns in `timelock/`).
