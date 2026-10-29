# Wrap-up measurement log

One row per set per measured commit, from `tools/measure.sh` (compile = reconstructions
that pass `cargo check`; errors = compiler errors summed over the set; holes =
`todo!()` placeholders summed) and the scoring benches (`benchmark`, `heldout_bench`).
Scores use `score-2.2.0`. Sets: the reference corpus `samples/contracts`; the 25
single-crate Stellar examples; the 13 multi-contract Stellar examples; two third-party
contracts; the Stellar SDK's own test contracts built at soroban-sdk 26.0.1
(`tools/build_sdk_tests.sh`).

## 2026-10-29 — baseline, commit d6e0f94

| Set | Contracts | Compile | Errors | Holes | Lines | Score |
|---|---:|---:|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 85 | 2,026 | 0.9389 |
| Stellar examples, single-crate | 25 | 22/25 | 29 | 3,898 | 17,682 | 0.7850 |
| Stellar examples, multi-contract | 13 | 9/13 | 48 | 4,243 | 14,785 | 0.6226 |
| third-party | 2 | 0/2 | 54 | 788 | 3,462 | 0.53 |
| SDK 26 test contracts | 39 | 17/39 | 126 | 1,607 | — | n/a |

Not compiling: other_custom_types 18, fuzzing 8, account 3 · privacy_pools 30,
groth16_bn254 8, groth16_bls12_381 8, atomic_multiswap 2 · phoenix-vesting 45,
merkle-voting 9 · and 22 of the 39 SDK 26 contracts.

## 2026-10-29 — commit 1a6a29e (empty-contract scaffold merged)

Output byte-identical to d6e0f94 on all five sets (no measured contract lacks
entrypoints); same table as the baseline. Baseline moved to this commit.

## 2026-10-29 — commit 488ae8d (hole typing merged)

| Set | Contracts | Compile | Errors | Holes | Lines |
|---|---:|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 85 | 2,026 |
| Stellar examples, single-crate | 25 | 22/25 | 28 | 3,898 | 17,682 |
| Stellar examples, multi-contract | 13 | 9/13 | 42 | 4,243 | 14,785 |
| third-party | 2 | 0/2 | 52 | 788 | 3,462 |
| SDK 26 test contracts | 39 | 17/39 | 122 | 1,607 | 8,206 |

Errors 257 → 244. Moved: account 3→2, atomic_multiswap 2→1, privacy_pools 30→25,
phoenix-vesting 45→43, udt 12→10, spec_shaking_v1/v2 18→17 each. Holes unchanged;
every changed line is a placeholder gaining a type. Scores not re-run (no body changed).

## 2026-10-29 — commit 69f7e39 (sign and width casts merged)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 85 |
| Stellar examples, single-crate | 25 | 22/25 | 27 | 3,898 |
| Stellar examples, multi-contract | 13 | 9/13 | 40 | 4,243 |
| third-party | 2 | 0/2 | 51 | 788 |
| SDK 26 test contracts | 39 | 19/39 | 110 | 1,607 |

Errors 244 → 228; two more SDK 26 contracts compile (mutability, workspace_contract).
Scores unchanged: corpus bands pass, held-out mean 0.7850. 42 reconstructions
changed by casts, decoded constants and dropped literal suffixes, none by value.

## 2026-10-29 — commit 94f3c3b (four type-inference facts merged)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 85 |
| Stellar examples, single-crate | 25 | 24/25 | 18 | 3,898 |
| Stellar examples, multi-contract | 13 | 10/13 | 35 | 4,243 |
| third-party | 2 | 0/2 | 39 | 788 |
| SDK 26 test contracts | 39 | 23/39 | 103 | 1,607 |

Errors 228 → 195. Now compiling: account, fuzzing (held-out), atomic_multiswap
(extra), and alloc, errors, events, import_contract (SDK 26). Also merkle-voting
9 → 3, phoenix-vesting 42 → 36, privacy_pools 23 → 19. The branch alone measured
228 → 215; the rest is the combination with the cast work merged just before.
Scores unchanged (corpus bands pass, held-out mean 0.7850).
