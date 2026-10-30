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

## 2026-10-29 — commit 549ab1b (words that are really bool, Option, Val or nothing)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 85 |
| Stellar examples, single-crate | 25 | 22/25 | 22 | 3,898 |
| Stellar examples, multi-contract | 13 | 10/13 | 34 | 4,241 |
| third-party | 2 | **1/2** | 28 | 788 |
| SDK 26 test contracts | 39 | **23/39** | 84 | 1,595 |

Errors 200 → 168. merkle-voting compiles, the first third-party contract to do
so; so do the SDK 26 constructor, contract_data and events contracts. A value
the IR kept as a machine word where the program means a `bool`, an `Option`, a
`Val` or nothing now carries that meaning, each rule with its exactness note in
its pass. One soundness fix on the way: a storage read whose tag check was
removed now takes the type the check named, so the check's trap moves into the
typed read instead of being dropped. Eighteen reconstructions changed, the
corpus none. Scores unchanged: corpus bands pass, held-out mean 0.7850.

## 2026-10-29 — commit acad723 (a panic's contract error as the SDK Error)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 85 |
| Stellar examples, single-crate | 25 | 22/25 | 22 | 3,898 |
| Stellar examples, multi-contract | 13 | 10/13 | 34 | 4,241 |
| third-party | 2 | 1/2 | 28 | 788 |
| SDK 26 test contracts | 39 | 23/39 | 77 | 1,595 |

Errors 168 → 161. A constant raised by `panic_with_error!` whose contract code
two error enums share, or none declares, is now `Error::from_contract_error(code)`,
the same value; three SDK 26 reconstructions changed, at those sites only.
Holes unchanged; held-out mean 0.7850.

## 2026-10-29 — commit 79b12fb (a dispatch on a proven bool is the if on it)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 85 |
| Stellar examples, single-crate | 25 | 22/25 | 22 | 3,898 |
| Stellar examples, multi-contract | 13 | 10/13 | 34 | 4,241 |
| third-party | 2 | 1/2 | 28 | 788 |
| SDK 26 test contracts | 39 | 23/39 | 63 | 1,595 |

Errors 161 → 147. A `match` on a `bool` parameter's word, with integer arms and
the SDK's not-a-bool marker arm, is the `if` on the `bool` when the selector is
a parameter the spec declares `bool` or a comparison. Only spec_shaking_v1 and
v2 changed (12 → 5 errors each). Scores unchanged: corpus bands pass, held-out
mean 0.7850.

## 2026-10-29 — commit 7773125 (a returned error the declared Result names)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 85 |
| Stellar examples, single-crate | 25 | 22/25 | 22 | 3,898 |
| Stellar examples, multi-contract | 13 | 10/13 | 34 | 4,241 |
| third-party | 2 | 1/2 | 28 | 788 |
| SDK 26 test contracts | 39 | 24/39 | 61 | 1,595 |

Errors 147 → 145; SDK 26 add_u64 compiles. An error constant returned from a
function declared `-> Result<T, E>` takes its variant from `E` when two enums
declare the same code, or becomes `Error::from_contract_error(code)` when `E` is
the SDK's own `Error`. Only add_u64 changed; the held-out set is untouched, so
scores are unchanged.

## 2026-10-29 — commit d44be01 (a curve point's result has its protocol length)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 85 |
| Stellar examples, single-crate | 25 | 22/25 | 22 | 3,898 |
| Stellar examples, multi-contract | 13 | 10/13 | 34 | 4,241 |
| third-party | 2 | 1/2 | 28 | 788 |
| SDK 26 test contracts | 39 | 24/39 | 57 | 1,595 |

Errors 145 → 141. A BLS12-381 or BN254 point operation's result is the
`BytesN<N>` the protocol fixes (G1 96 bytes, G2 192, BN254 G1 64), as the SDK
wraps it. SDK 26 bls 5 → 3, bn254 4 → 2; bls_signature (held-out) now builds its
two-point vector with `vec![]` and scores the same (0.6873). Scores unchanged:
corpus bands pass, held-out mean 0.7850.

## 2026-10-29 — commit c3105ba (a 128-bit value decoded inline is the value)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 85 |
| Stellar examples, single-crate | 25 | 22/25 | 21 | 3,894 |
| Stellar examples, multi-contract | 13 | 10/13 | 34 | 4,241 |
| third-party | 2 | 1/2 | 26 | 776 |
| SDK 26 test contracts | 39 | 25/39 | 47 | 1,540 |

Errors 141 → 128, holes 10,607 → 10,536. The SDK's `i128`/`u128` conversion
inlined into a caller computes the two halves on each path and merges them;
each half is now named as the value's, so the merges go and the re-encode
folds back to the value. A returned 128-bit small encode is no longer
collapsed to its low half, which had made functions declared `-> i128` return
a `u64`. SDK 26 add_u128 compiles; phoenix-vesting 28 → 26; other_custom_types
15 → 14; the three contracttrait builds lose three errors each. Scores
unchanged: corpus bands pass, held-out mean 0.7850.

## 2026-10-29 — commit ec10975 (contracttype values returned or nested as their raw encoding)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 85 |
| Stellar examples, single-crate | 25 | 22/25 | 19 | 3,894 |
| Stellar examples, multi-contract | 13 | 10/13 | 34 | 4,241 |
| third-party | 2 | 1/2 | 23 | 776 |
| SDK 26 test contracts | 39 | 27/39 | 35 | 1,487 |

Errors 128 → 111. A `#[contracttype]` value handed back as its `Map`, `Vec` or
encoded word is now the declared type: a struct whose field names several
structs share is named where it goes, a tuple component in its encoded form is
what it encodes, an integer enum returned as its discriminant is the variant,
and a returned vec naming a variant is that variant. SDK 26 spec_shaking_v1/v2
compile; other_custom_types 14 → 12, phoenix-vesting 26 → 23. The corpus
changed only by dropping redundant renames.

**Day total (2026-10-29):** errors 257 → 111; compiling contracts 55 → 67 of 86;
holes 10,618 → 10,483; scores unchanged (corpus 0.9389, held-out 0.7850).

## 2026-10-30 — commit 0524957 (a returned 64-bit constant is its decoded value)

Numbers unchanged from ec10975 (errors 111, holes 10,483), output byte-identical
on all five sets. The fix guards a case no measured contract hits: a small
`i64`/`u64` constant on an entrypoint's return path could be printed as its raw
encoded word. Scores confirmed for both commits: corpus bands pass, held-out
mean 0.7850.

## 2026-10-30 — commit 812fc61 (a length-checked bytes decoder is the BytesN conversion)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 85 |
| Stellar examples, single-crate | 25 | **23/25** | 18 | 3,894 |
| Stellar examples, multi-contract | 13 | 10/13 | 34 | 4,240 |
| third-party | 2 | 1/2 | 23 | 776 |
| SDK 26 test contracts | 39 | 27/39 | 35 | 1,487 |

Errors 111 → 110; account compiles. A library helper that checks a value is a
32-byte bytes object and returns `Some` of it is now read as the SDK's
`BytesN<32>` conversion, with its input kept a `Val`; a call on a value already
proven to be 32 bytes is `Some` of it, which also removes an unused helper from
multisig_1_of_n_account (holes 3 → 2). Scores unchanged: corpus bands pass,
held-out mean 0.7850 (account 0.7941, as before).

## 2026-10-30 — commit aa34a17 (constant words read through their decode)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 85 |
| Stellar examples, single-crate | 25 | 23/25 | 18 | 3,894 |
| Stellar examples, multi-contract | 13 | 10/13 | 34 | 4,240 |
| third-party | 2 | 1/2 | 23 | 776 |
| SDK 26 test contracts | 39 | **30/39** | 29 | 1,487 |

Errors 110 → 104; SDK 26 errors, auth and bls compile. A constant `Val` word
could be printed as the 64-bit number it is packed into: a short symbol returned
inside a `Result`, and the elements of a vec built from constants. Each is now
read through its tag as the `u32`, `i32`, `bool` or short symbol it encodes. This
also corrects the topic of an event in five contracts (sdk26 events, events_ref,
spec_import; other_custom_types), which had been converting the packed number
rather than publishing the symbol. Also: a host object handed to a helper that
tests its word passes that word, and a small decode of an integer enum is its
`u32` discriminant. Scores unchanged: corpus bands pass, held-out mean 0.7850.

## 2026-10-30 — commit e54ba23 (an encoded number is not the number)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 85 |
| Stellar examples, single-crate | 25 | 23/25 | 18 | 3,894 |
| Stellar examples, multi-contract | 13 | 10/13 | 34 | 4,240 |
| third-party | 2 | 1/2 | 17 | 776 |
| SDK 26 test contracts | 39 | 30/39 | 29 | 1,481 |

Errors 104 → 98; holes 10,482 → 10,476. The SDK's `u64`-to-`Val` conversion,
outlined into a helper, had its result typed as the `u64` it was given, because a
struct field declared `u64` held the helper's encoded output. A field filled
through such a helper now takes the helper's argument, and an encoder's result
stays a `Val`. phoenix-vesting 23 → 17; the three contracttrait builds lose two
gaps each. Scores unchanged: corpus bands pass, held-out mean 0.7850.

## 2026-10-30 — commit 2db10d1 (a tuple argument unpacked into memory is its elements)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 85 |
| Stellar examples, single-crate | 25 | 23/25 | 16 | 3,879 |
| Stellar examples, multi-contract | 13 | 10/13 | 34 | 4,240 |
| third-party | 2 | 1/2 | 17 | 776 |
| SDK 26 test contracts | 39 | **31/39** | 26 | 1,444 |

Errors 98 → 93, holes 10,476 → 10,424. The SDK converts a tuple argument by
unpacking its vec into the stack frame and checking each element; that unpack
was a gap. A declared tuple parameter's unpack is now the stores it performs, so
each element reaches its reader, and the checks the typed signature already
makes go. SDK 26 tuples compiles and reads `(arg.0, arg.1)`, as its source does;
other_custom_types' `tuple` is fixed (12 → 10 errors); spec_shaking v1/v2 lose
three gaps each. Held-out mean 0.7850 → 0.7851 (other_custom_types); corpus
bands pass.

## 2026-10-30 — commit ecb5938 (a rotation count is the u32 Rust's rotate takes)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 85 |
| Stellar examples, single-crate | 25 | 23/25 | 16 | 3,879 |
| Stellar examples, multi-contract | 13 | 10/13 | 30 | 4,240 |
| third-party | 2 | 1/2 | 17 | 776 |
| SDK 26 test contracts | 39 | 31/39 | 26 | 1,444 |

Errors 93 → 89. A rotation's count was printed with its `i32`/`i64` suffix, while
Rust's `rotate_left`/`rotate_right` take a `u32`; it is now that `u32` (a literal)
or cast (anything else), the same count modulo 32 or 64. Only privacy_pools
changed (18 → 14 errors), in its four rotations; it is in no scored set, so
scores are as for 2db10d1.

## 2026-10-30 — commit d21b23d (the value a bytes call reads is a Bytes)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 85 |
| Stellar examples, single-crate | 25 | 23/25 | 16 | 3,879 |
| Stellar examples, multi-contract | 13 | 10/13 | 21 | 4,240 |
| third-party | 2 | 1/2 | 17 | 776 |
| SDK 26 test contracts | 39 | 31/39 | 26 | 1,444 |

Errors 89 → 80. A gap read only by a bytes length, slice or get call had no type,
so rustc could not infer it; the host catalog's argument kinds now type it
`Bytes`, as they already typed crypto arguments, except where something has
already typed it `Val`. Both groth16 verifiers 8 → 4, privacy_pools 14 → 13,
merkle-voting one gap typed (still compiles). The single-crate Stellar set is
unchanged, so the held-out mean stays 0.7851.

## 2026-10-30 — commit 537e767 (a u32 argument's packed word)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 85 |
| Stellar examples, single-crate | 25 | 23/25 | 14 | 3,879 |
| Stellar examples, multi-contract | 13 | 10/13 | 21 | 4,240 |
| third-party | 2 | 1/2 | 17 | 776 |
| SDK 26 test contracts | 39 | 31/39 | 23 | 1,444 |

Errors 80 → 75. rustc does some arithmetic on a `u32` argument's packed word
(`value << 32 | tag`) instead of the value; three more of those shapes are read at
the value: `v + 1`'s overflow check, `word + (1 << 32)` (`v + 1`), and a mask tested
against zero (`v % 2`). One correctness fix: a `>= 1 << 32` comparison on such a
word was rewritten to `== 0`, an inverted condition; it is `!= 0`. No measured
contract hit it. contracttrait_impl_partial 4 → 1, other_custom_types 10 → 8.
Held-out mean 0.7851, unchanged.

## 2026-10-30 — commit 2cc2b7b (phoenix-vesting round two)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 85 |
| Stellar examples, single-crate | 25 | 23/25 | 11 | 3,882 |
| Stellar examples, multi-contract | 13 | 10/13 | 21 | 4,240 |
| third-party | 2 | 1/2 | 11 | 765 |
| SDK 26 test contracts | 39 | 31/39 | 23 | 1,419 |

Errors 75 → 66, holes 10,424 → 10,391. A decoded result written into the frame
and read back through another spelling of the same slot address is the result
(three SDK 26 contracts lose 25 gaps); a 128-bit difference takes the sign of an
operand already known to be 128-bit; a helper takes a struct argument only when
every caller can build it — otherwise callers were handing it a frame address as
the struct — so other_custom_types trades three errors for three honest gaps;
and a struct field declared `Option<T>` filled from `Void` or an encode is
`None`/`Some(x)`. phoenix-vesting 17 → 11. Scores unchanged: corpus bands pass,
held-out mean 0.7851.

## 2026-10-30 — commit 5aff83a (a Result returned through caller memory is the Result)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 85 |
| Stellar examples, single-crate | 25 | 23/25 | 11 | 3,882 |
| Stellar examples, multi-contract | 13 | **12/13** | 13 | 4,228 |
| third-party | 2 | 1/2 | 11 | 765 |
| SDK 26 test contracts | 39 | 31/39 | 23 | 1,419 |

Errors 66 → 58, holes 10,391 → 10,379. A helper returning `Result<bool, E>` by
writing a tag byte and a payload into memory its caller passes, followed by the
SDK's conversion of that memory to a `Val`, is now the `Result` itself, built as
`Ok(..)` / `Err(E::Variant)` on each path. Both groth16 verifiers compile; only
they changed. Corpus bands pass; the held-out set is untouched (0.7851).

## 2026-10-30 — commit 6fd1253 (a symbol helper whose length the compiler fixed)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 85 |
| Stellar examples, single-crate | 25 | 23/25 | 11 | 3,882 |
| Stellar examples, multi-contract | 13 | 12/13 | 13 | 4,228 |
| third-party | 2 | 1/2 | 11 | 765 |
| SDK 26 test contracts | 39 | **34/39** | 20 | 1,410 |

Errors 58 → 55. When every name a helper builds has the same length, rustc folds
the length into the helper; such pointer-only calls were left unfolded, so enum
variant names went unknown. The length is now read from the helper itself and the
call folds to the symbol. The three contracttrait builds compile: their
enum-variant function returns its declared type, with honest gaps on two of its
three paths (rebuilding it as the argument itself is parked). Only SDK 26
changed; scores as for 5aff83a.

## 2026-10-30 — commit a386e20 (Option and Result of user types, and numbers, at the return)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 85 |
| Stellar examples, single-crate | 25 | 23/25 | 11 | 3,882 |
| Stellar examples, multi-contract | 13 | 12/13 | 13 | 4,228 |
| third-party | 2 | 1/2 | 11 | 765 |
| SDK 26 test contracts | 39 | **35/39** | 7 | 1,404 |

Errors 55 → 42. Six return-side facts: an error constant returned under the SDK's own
`Error` with no enum declared; a returned tuple whose parts a shared helper only
encodes; a returned merge typed by the declared number before a `0` arm's suffix can;
a struct named by an `Option<S>` return; `Result<Option<T>, E>` returns as
`Ok(Some(..))`/`Ok(None)`; an `Option` parameter returned where it was tested present.
associated_type_chained compiles; udt 7 → 2. Only those two changed; scores as before.
