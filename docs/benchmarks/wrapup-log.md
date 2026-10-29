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

## 2026-10-29 — commit 3c91cba (operators keep the opcode's signedness)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 85 |
| Stellar examples, single-crate | 25 | 22/25 | 26 | 3,898 |
| Stellar examples, multi-contract | 13 | 10/13 | 35 | 4,243 |
| third-party | 2 | 0/2 | 37 | 788 |
| SDK 26 test contracts | 39 | 20/39 | 108 | 1,604 |

A correctness fix rather than a number: an unsigned shift, division, remainder
or ordering printed on a value typed signed (or the reverse) was silently the
other operation, and compiled. The IR now keeps the opcode's reading and the
emitter reinterprets an operand whose printed type disagrees, at its own width.
40 reconstructions changed, 1,008 lines, every one a reinterpretation cast (21
also rewrite a constant as its bits); 1,319 operator sites reread, 23 printed
bare because no operand's type is known (17) or the operands disagree on
width (6), both listed by `SORDEC_SIGN_TRACE=1`. Errors 209 → 207: three
vanished (phoenix-vesting ×2, SDK 26 add_u128) because both sides of a
comparison are now cast to one reading where rustc had been reporting a type
disagreement the recovered types do not show; that disagreement is unchanged
one line earlier (see the working notes). One error in fuzzing changed its
message, not its site. Holes and compile counts unchanged; corpus bands pass;
held-out mean 0.7850 unchanged.

## 2026-10-29 — commit 732df9e (enum ordering, Val width move, nested import, key payload)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 85 |
| Stellar examples, single-crate | 25 | 22/25 | 26 | 3,898 |
| Stellar examples, multi-contract | 13 | 10/13 | 35 | 4,243 |
| third-party | 2 | 0/2 | 36 | 788 |
| SDK 26 test contracts | 39 | 20/39 | 104 | 1,604 |

Errors 207 → 202: merkle-voting 3 → 2, SDK 26 constructor 7 → 5, errors 3 → 2,
udt 10 → 9. Holes unchanged. Twelve reconstructions changed: six only in the
spelling of `auth::Context`, two SDK 26 and one third-party at the fixed
sites, and token-v22 and token-v23 (four lines each) where a storage key is
now named from the caller's own frame and its arguments are cloned; both
still compile with no errors. Scores unchanged: corpus bands pass, held-out
mean 0.7850.

## 2026-10-29 — commit fd1fc6c (symbol constants, wrappers, Option-shaped decoders)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 85 |
| Stellar examples, single-crate | 25 | 22/25 | 26 | 3,898 |
| Stellar examples, multi-contract | 13 | 10/13 | 35 | 4,241 |
| third-party | 2 | 0/2 | 34 | 788 |
| SDK 26 test contracts | 39 | 20/39 | 104 | 1,599 |

Errors 202 → 200 (phoenix-vesting 34 → 32: two packed symbol constants read
back as `symbol_short!`). Holes 10,617 → 10,610 (workspace_contract_a 21 → 19,
SDK 26 fuzz 18 → 13: an SDK decode inside an outlined wrapper now collapses to
the wrapper's parameter). Five reconstructions changed, none by value. Scores
unchanged: corpus bands pass, held-out mean 0.7850.

The larger change these three facts were written for, promoting the pointer
parameters of decoder helpers in a module that calls through its function
table, is measured but held back: it removes 128 holes and adds four errors,
all of them two decoder shapes not yet recognised (a 128-bit decoder with two
payload slots, and a `Bytes` decoder whose tag also carries `BytesN<N>`). It
lands when those two are.
