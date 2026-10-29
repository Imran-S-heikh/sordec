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

## 2026-10-29 — commit 94f3c3b (four type-inference facts merged), corrected

Measured again at 5a598a6 (the same decompiler; `tools/measure.sh` now checks
each crate under a package name unique to the run). The first measurement of
this commit ran while another measurement shared the cargo-check cache, and
five of its "compiles" verdicts were that run's cached result rather than this
commit's: account, fuzzing, and the SDK 26 errors, events and import_contract
contracts do not compile. The message of commit 94f3c3b carries the wrong list.
The rows above this one were re-measured the same way and reproduce exactly.

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 85 |
| Stellar examples, single-crate | 25 | 22/25 | 26 | 3,898 |
| Stellar examples, multi-contract | 13 | 10/13 | 35 | 4,243 |
| third-party | 2 | 0/2 | 39 | 788 |
| SDK 26 test contracts | 39 | 20/39 | 109 | 1,607 |

Errors 228 → 209. Now compiling: atomic_multiswap (extra) and alloc (SDK 26).
Also merkle-voting 9 → 3, phoenix-vesting 42 → 36, privacy_pools 23 → 19,
fuzzing 7 → 6. Scores unchanged (corpus bands pass, held-out mean 0.7850).

Not compiling: account 2, fuzzing 6, other_custom_types 18 · privacy_pools 19,
groth16_bn254 8, groth16_bls12_381 8 · phoenix-vesting 36, merkle-voting 3 ·
and 19 of the 39 SDK 26 contracts.

## 2026-10-29 — commit 41d2250 (pointer parameters promoted one by one)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 85 |
| Stellar examples, single-crate | 25 | 22/25 | 26 | 3,898 |
| Stellar examples, multi-contract | 13 | 10/13 | 35 | 4,243 |
| third-party | 2 | 0/2 | 39 | 788 |
| SDK 26 test contracts | 39 | 20/39 | 109 | 1,604 |

One reconstruction changed: SDK 26 `events_ref`, holes 51 → 48 (a helper now
takes its three arguments by value). Every other reconstruction is
byte-identical to 5a598a6, so scores are unchanged (held-out mean 0.7850 on the
branch). The larger shape this work was aimed at, a decoder helper reached only
through a function table, is blocked by a module-wide rule and is recorded as
the next task.
