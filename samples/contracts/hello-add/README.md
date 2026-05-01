# hello-add

The smallest realistic Soroban contract: one exported function that
adds two `u64`s. First-party — written for sordec's test corpus, not
vendored from upstream.

## What this fixture exercises

### Minimal Soroban surface

A single `#[contract]` struct with a single `#[contractimpl]` method
taking two `u64` arguments and returning a `u64`. No storage, no auth,
no events, no cross-contract calls. Useful as the **smallest
end-to-end SDK contract** to validate that the pipeline works on the
simplest possible Soroban contract.

### Val encoding for primitives

Even with no host calls in the source-code body, the compiled WASM
contains two host calls — one each for encoding the two `u64`
arguments into Soroban's tagged `Val` representation at the dispatcher
boundary. This makes hello-add the **minimum reproducer for Val
encoding/decoding patterns**: any contract that takes a primitive
argument hits the same encoding path.

### Dispatcher generation

`#[contractimpl]` generates a thin dispatcher that decodes incoming
`Val`s, calls the user method, encodes the result. hello-add isolates
this scaffolding (5 functions in the lifted IR: 1 user method,
4 dispatcher / Val-encoding helpers).

## What this fixture does NOT exercise

- No storage tier (no `env.storage()` calls)
- No auth (no `require_auth`)
- No cross-contract calls
- No events
- No custom errors (no `panic!`, no `#[contracterror]`)
- No persistent state — pure function

## Why this fixture is in the corpus

Two reasons:

1. **Smoke-test for the entire pipeline.** Every other fixture is at
   least 18 functions; if a regression breaks lifting on the simplest
   possible Soroban contract, hello-add catches it first. Tests
   reference it as the "tiny contract" baseline.
2. **Val-encoding minimum reproducer.** The Phase 2 Val-encoding
   pattern recognition pass needs a fixture with the encoding
   present-but-isolated, free of confounding host calls.

## Provenance

First-party. Authored by Imran Shaikh as part of the sordec project
under the root [LICENSE](../../../LICENSE) (Apache-2.0). No upstream
vendoring; no separate `VENDORED_FROM` file.
