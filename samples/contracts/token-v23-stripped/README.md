# token-v23-stripped

The same SEP-41 token contract as `token-v23/`, post-processed with
`wasm-tools strip --all` to remove every custom section. Code sections
are byte-for-byte identical to the unstripped version; only metadata
differs.

## Why this fixture exists

Production Soroban contracts deployed to mainnet are **routinely
stripped** of custom sections. The Stellar CLI's `stellar contract
optimize` removes them by default to reduce on-chain storage cost.
Hand-deployed contracts may also have metadata removed by the deployer
to save fees or to obscure source structure.

A decompiler that only works on developer-built unstripped WASM ships
incomplete. This fixture is the corpus's representation of that real
failure mode.

## What this fixture exercises

Beyond what `token-v23/` already exercises, this fixture specifically
validates **graceful degradation when metadata is absent**:

- Frontend `parse()` returns `Ok(facts)` with `facts.metadata == None`
  rather than failing.
- Lifter `lift_with_waffle()` produces a valid `LiftedIr` from a WASM
  module that has no Soroban metadata sections — the SSA + CFG
  construction depends only on the WASM core, not on custom sections.
- Downstream passes (Phase 3+) that recover types from `contractspecv0`
  must handle `None` explicitly. They will need to synthesise type
  names from usage patterns rather than reading them from metadata.
- Function exports are still discoverable (the WASM `export` section is
  not a custom section and is preserved by `wasm-tools strip`).

## What this fixture exposes

The same code as `token-v23/`, but everything that gets recovered must
be derived from the WASM core:

- Type recovery cannot read `contractspecv0` for SEP-41's struct/enum
  definitions — must be inferred from host-function call patterns.
- Function names cannot be read from `name` section — entry points are
  identified by export name only (still preserved).
- Compiler/SDK version cannot be read from `producers` section — must
  be inferred from instruction patterns (or left as Unknown).

## Comparison with `token-v23/`

| Property | token-v23 | token-v23-stripped |
|----------|-----------|--------------------|
| Source | identical | identical |
| WASM size | 8,494 bytes | 6,107 bytes |
| Function count | 46 | 46 |
| Imports | 19 | 19 |
| Exports | 17 | 17 |
| `metadata.is_some()` | `true` | `false` |

The corpus tests assert that **every contract in the corpus lifts
successfully**, including this one. Asserting *what we recover* from a
stripped contract is the job of the per-pass tests in Phase 3.
