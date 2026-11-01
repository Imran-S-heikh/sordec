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

## 2026-10-30 — commit f3b6fc5 (a byte read back as a word is not the stored value)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 85 |
| Stellar examples, single-crate | 25 | 23/25 | 9 | 3,883 |
| Stellar examples, multi-contract | 13 | 12/13 | 6 | 4,229 |
| third-party | 2 | 1/2 | 11 | 765 |
| SDK 26 test contracts | 39 | 35/39 | 7 | 1,404 |

Errors 42 → 33. One correctness fix: a one- or two-byte frame load was bound to
the value stored there even when it reads that value back into a wider word,
losing the truncation — a wrong value. It is now forwarded only when the value
provably reads back unchanged, and is otherwise a typed load (one more honest gap
in each of privacy_pools and fuzzing). Also: a flag merged from `false` and a
comparison is a `bool`, and the code after a scope nothing can leave is dropped.
privacy_pools 13 → 6, fuzzing 6 → 4. Scores unchanged: corpus bands pass, held-out
mean 0.7851.

## 2026-10-30 — commit e41127f (object words from memory, tuple structs, parameters typed later)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 85 |
| Stellar examples, single-crate | 25 | **24/25** | 4 | 3,883 |
| Stellar examples, multi-contract | 13 | 12/13 | 6 | 4,229 |
| third-party | 2 | 1/2 | 11 | 765 |
| SDK 26 test contracts | 39 | 35/39 | 6 | 1,402 |

Errors 33 → 28; other_custom_types compiles. An untyped 8-byte word read into a
vec of objects, or merged into a value of an object type, is that object (an
object's value is its handle); a returned vec is the tuple struct the spec
declares (fields named `0..n`), printed `Name(a, b)`; and a helper parameter waits
for callers still holding an untyped call result before it settles. spec_import
2 → 1. Four other contracts gain only a type annotation on a gap. Scores
unchanged: corpus bands pass, held-out mean 0.7851 (other_custom_types 0.7255,
as before — the scorer gives no credit for compiling).

## 2026-10-30 — commit 8631f8a (an inlined symbol loop is its symbol; a Result built in the entrypoint's frame)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 85 |
| Stellar examples, single-crate | 25 | 24/25 | 4 | 3,882 |
| Stellar examples, multi-contract | 13 | 12/13 | 6 | 4,227 |
| third-party | 2 | 1/2 | 11 | 765 |
| SDK 26 test contracts | 39 | **37/39** | 3 | 1,371 |

Errors 28 → 25. `Symbol::new` inlined into a function is a loop over the name's
bytes; with constant inputs, no effects and a fallback naming the same text, it now
folds to the symbol. A `Result` an entrypoint builds in its own frame on several
paths and converts through the SDK's helper is now `Ok(x)` or
`Err(Error::from_contract_error(code))` on each path. spec_import and
import_contract compile; three key-building helpers elsewhere print
`symbol_short!(..)` for the name (same bits). Held-out mean 0.7851 → **0.7860**
(modular_account's structure: the loop became the symbol); corpus bands pass.

## 2026-10-30 — commit 17dee6f (optional-out: bulk memory operations and raw indirect calls count)

Numbers unchanged from 8631f8a (errors 25, holes 10,330); output byte-identical on
all five sets. A soundness fix: the pass that turns an `Option` written into caller
memory into a returned `Option` ignored bulk copies and fills when checking who
reads the result, and looked for indirect calls only in a form the pipeline never
produces. Neither gap fired on these sets.

## 2026-10-30 — commit a14452d (four passes refuse a helper a raw indirect call may reach)

Numbers unchanged (errors 25, holes 10,330); output byte-identical on all five sets.
A soundness fix shared by four signature-changing passes: they checked for indirect
calls only in a form the pipeline never produces. They now keep the signature of
any helper the function table declares (table entries read with imports
subtracted). No helper they rewrote on these sets is in a table.

## 2026-10-30 — commit 8af9004 (a Result returned as a register pair is the Result)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 85 |
| Stellar examples, single-crate | 25 | 24/25 | 4 | 3,882 |
| Stellar examples, multi-contract | 13 | 12/13 | 3 | 4,220 |
| third-party | 2 | 1/2 | 11 | 765 |
| SDK 26 test contracts | 39 | 37/39 | 3 | 1,371 |

Errors 25 → 22. A helper returning `Result<u32, E>` as two registers (tag and
payload), stored by a wrapper for the SDK's converter, now returns the `Result`
itself per path; the converter's error for the code read back is exactly that
code's contract error (its two constants cancel). It follows the shared rule that a
helper a function table may reach keeps its signature. Only privacy_pools changed
(6 → 3); scores as for 8631f8a.

## 2026-10-30 — commit 7f7e7c3 (vec searches, numbers encoded through a reference, a tag-checked unpack)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 85 |
| Stellar examples, single-crate | 25 | **25/25** | **0** | 3,879 |
| Stellar examples, multi-contract | 13 | 12/13 | 1 | 4,214 |
| third-party | 2 | 1/2 | 11 | 765 |
| SDK 26 test contracts | 39 | 37/39 | 3 | 1,371 |

Errors 22 → 18; **every single-crate Stellar example now compiles** (fuzzing was the
last). The receiver of a vec search is a `Vec` by the host catalog (the SDK calls
those only from `Vec`'s methods); a helper that loads a number through a pointer
and returns only its encode is, at each call site, the value read through the
pointer; the unpack of a word a one-tag `Option` decoder hands back is its decode.
privacy_pools 3 → 1. Held-out mean 0.7860 → 0.7861 (fuzzing 0.5389 → 0.5407);
corpus bands pass.

## 2026-10-30 — commit b946d64 (a struct field read only when the read is the whole slot)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 85 |
| Stellar examples, single-crate | 25 | 25/25 | 0 | 3,879 |
| Stellar examples, multi-contract | 13 | 12/13 | 1 | 4,214 |
| third-party | 2 | 1/2 | 11 | 791 |
| SDK 26 test contracts | 39 | 37/39 | 3 | 1,385 |

Errors unchanged (18); holes +40. **Correctness fix:** the struct-decode recogniser
turned reads of a decode helper's output into field accesses without checking the
read's width. In spec_shaking v1/v2 a one-byte read of a field's tag became a test on
the value — `if s.a != 4 { panic!() }`, which panics for every value but 4; in
phoenix-vesting a field written in 4 bytes was read as 8, and another was read after
the caller partly overwrote it. Those reads are now honest gaps
(phoenix-vesting +26, spec_shaking +7 each). Scored sets unchanged.

## 2026-10-30 — commit 7b5c975 (a packed length shifted down by 32 is the length)

Numbers unchanged (errors 18, holes 10,364). **Correctness fix:** the SDK stores a
length it holds as a `U32Val` back as a number with `word >> 32`; once the length is
typed as its value, that shift read the decoded value — `len >> 32`, which is `0` or
an overflow panic where the program had the length. An unsigned shift right by
exactly 32 of a packed `U32Val` is now its payload. udt stores its lengths again;
phoenix-vesting's length arithmetic now reads as the lengths (and an underflow
check folds into the `len - 1` that already makes it). Scored sets unchanged.

## Correction (2026-10-30): running error totals

The per-set tables in the rows above are right; the running totals in five of the
rows' text (and in the matching merge commit messages) were added up wrongly from
e41127f on. The correct totals, summed from each measurement's per-contract file:

| Commit | Total errors as written | Correct total |
|---|---:|---:|
| e41127f | 28 | **27** |
| 8631f8a | 25 | **24** |
| 8af9004 | 22 | **21** |
| 7f7e7c3 | 18 | **15** |
| b946d64, 7b5c975 | 18 | **15** |

## 2026-10-30 — commit 5eafc51 (a counter typed by what it counts to; unwrap_or through caller memory)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 85 |
| Stellar examples, single-crate | 25 | 25/25 | 0 | 3,879 |
| Stellar examples, multi-contract | 13 | 12/13 | 1 | 4,214 |
| third-party | 2 | 1/2 | 8 | 784 |
| SDK 26 test contracts | 39 | **38/39** | 2 | 1,393 |

Errors 15 → 11 (summed from the per-contract file). A number literal no longer
types a value whose type is still coming from a guest call, and a loop counter
compared with a `u64` is that `u64`; on top of it, an `Option` a helper writes into
caller memory read as `select(value, 0, tag)` is `unwrap_or(0)`, and a value read
above its test is `unwrap()` under it. phoenix-vesting 11 → 8. **Correctness fix:**
bn254's U256 helper had been rewritten to return an `Option<i64>`, a wrong type; a
payload merged with an untyped arm is now refused, so bn254 compiles with 13 honest
gaps. Scores unchanged: corpus bands pass, held-out mean 0.7861.

**Day total (2026-10-30):** errors 111 → 11; compiling 67 of 86 → 83 of 86
contracts (corpus 7/7, Stellar 25/25, multi-contract 12/13, third-party 1/2,
SDK 26 38/39); held-out mean 0.7850 → 0.7861.

## 2026-10-30 — commit d4b7ee7 (unread helper parameters, and panic-message work before a trap, go)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 85 |
| Stellar examples, single-crate | 25 | 25/25 | 0 | 3,843 |
| Stellar examples, multi-contract | 13 | 12/13 | 1 | 4,084 |
| third-party | 2 | 1/2 | 8 | 661 |
| SDK 26 test contracts | 39 | 38/39 | 2 | 1,385 |

Holes 10,355 → 10,058 (summed); errors unchanged at 11. First of the gap-closing work:
a helper parameter nothing reads is removed with its argument at every visible call
site, and memory writes and host-free calls just before a trap are dropped (a trap
throws away memory and rolls back host state). Stack frames kept only to build a panic
message or pass an unused pointer go, with their loads, stores and bookkeeping
(phoenix-vesting 688 → 565). Corpus: dex's panic helper loses an argument it never
read. Corpus bands pass; held-out mean 0.7861 → 0.7862.

## 2026-10-30 — commit b82e7b3 (a parameter's two unpacks, and a branch whose two ways end the same, go)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 85 |
| Stellar examples, single-crate | 25 | 25/25 | 0 | 3,835 |
| Stellar examples, multi-contract | 13 | 12/13 | 1 | 4,084 |
| third-party | 2 | 1/2 | 8 | 661 |
| SDK 26 test contracts | 39 | 38/39 | 2 | 1,355 |

Holes 10,058 → 10,020 (summed); errors unchanged at 11. A parameter the spec declares
`u64`, `i64`, timepoint or duration is the value in each branch of its two-form unpack;
a branch whose two ways both fall through or return the same values, with only pure
code between, is dropped. Entrypoints that only hand their argument back now read as
returning it (other_custom_types, the three contracttrait builds). Corpus byte-identical;
corpus bands pass; held-out mean 0.7862 → 0.7865.

## 2026-10-30 — commit 2cb5f6b (struct conversions through memory, and events published as their literal)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 85 |
| Stellar examples, single-crate | 25 | 25/25 | 0 | 3,823 |
| Stellar examples, multi-contract | 13 | 12/13 | 1 | 4,084 |
| third-party | 2 | 1/2 | 8 | 661 |
| SDK 26 test contracts | 39 | 38/39 | 2 | 1,006 |

Holes 10,020 → 9,659 (summed); errors unchanged at 11; corpus byte-identical. A struct
decoded through the frame is named by the value's declared type when several structs
share its key table; a field's own tag check, an `Option` parameter's payload and a tuple
element's tag-byte check go with their conversions; an inlined `#[contractevent]`
publish is the event literal, fields typed by the declaration (spec_shaking v1/v2
197 → 50 and 200 → 41 gaps, their events printed as in the source). Corpus bands pass;
held-out mean 0.7865.

**Gap work so far:** 10,355 → 9,659 gaps (−696) since the start of the gap phase, with no
new errors and the corpus output unchanged apart from one unused argument.

## 2026-10-30 — commit 5f6b2a0 (an out-parameter rewrite only in the caller's own frame; the split BytesN conversion)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 85 |
| Stellar examples, single-crate | 25 | 25/25 | 0 | 3,823 |
| Stellar examples, multi-contract | 13 | 12/13 | 1 | 4,087 |
| third-party | 2 | 1/2 | 8 | 661 |
| SDK 26 test contracts | 39 | 38/39 | 2 | 1,006 |

A correctness fix. A helper that writes its result through a pointer it was handed (not
into its caller's own frame) is no longer turned into one returning an `Option`: the
caller's caller reads that memory after the call, and the rewrite had stopped writing it
(privacy_pools' and groth16_bn254's `BytesN` length checks lost their result on one path).
Those helpers print in their out-pointer form again, +9 gaps; the `BytesN` conversion split
into a tag half and a length half now folds into a typed storage read, −6. Holes 9,659 →
9,662 (summed); errors unchanged at 11. Only those two reconstructions differ; corpus and
held-out byte-identical, so their scores are unchanged (held-out mean 0.7865).

## 2026-10-31 — commit 80e4116 (an enum decoded into memory is taken apart by a match)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 85 |
| Stellar examples, single-crate | 25 | 25/25 | 0 | 3,823 |
| Stellar examples, multi-contract | 13 | 12/13 | 1 | 4,087 |
| third-party | 2 | 1/2 | 8 | 661 |
| SDK 26 test contracts | 39 | **39/39** | **0** | 935 |

A `#[contracttype]` enum with payloads that the SDK decodes into the caller's frame, and
the caller's switch on its tag, now print as one `match` binding each variant's payload
(`UdtEnum::UdtB(p) => p.a + p.b`). udt compiles (2/175 → 0/104); every other
reconstruction byte-identical. Errors 11 → 9; holes 9,662 → 9,591 (summed). Corpus bands
pass; held-out mean 0.7865.

**Totals:** 84 of 86 contracts pass `cargo check` (from 55 of 86 at the start of the
week, 257 errors → 9). Gap work: 10,355 → 9,591 gaps (−764).

## 2026-10-31 — commit 9d199bb (a resolved string literal prints as `String::from_str`)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 85 |
| Stellar examples, single-crate | 25 | 25/25 | 0 | 3,821 |
| Stellar examples, multi-contract | 13 | 12/13 | 1 | 4,066 |
| third-party | 2 | 1/2 | 8 | 646 |
| SDK 26 test contracts | 39 | 39/39 | 0 | 927 |

A string the contract builds from constant UTF-8 bytes in its binary printed as a gap,
and its pointer and length kept two more alive; it now reads as the source wrote it,
`String::from_str(&e, "Hello")`. hello_world, associated_type and
associated_type_contracttrait have no gaps left. Holes 9,591 → 9,545 (summed); errors
unchanged at 9; corpus byte-identical; held-out mean 0.7865.

## 2026-10-31 — commit 80bcb1d (resolved constant bytes print as `Bytes::from_slice`)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 85 |
| Stellar examples, single-crate | 25 | 25/25 | 0 | 3,815 |
| Stellar examples, multi-contract | 13 | 12/13 | 1 | 3,430 |
| third-party | 2 | 1/2 | 8 | 646 |
| SDK 26 test contracts | 39 | 39/39 | 0 | 923 |

`Bytes` built from constant bytes in the binary printed as a gap, with two more for its
pointer and length; it now prints as `Bytes::from_slice(&e, &[0x6f, …])`, the call that
hands the host the same bytes. Most are privacy_pools' Poseidon constants (3,151 → 2,521);
also the BLS and BN254 examples. Holes 9,545 → 8,899 (summed); errors unchanged at 9;
corpus byte-identical; held-out mean 0.7865.

## 2026-10-31 — commit ace627f (`authorize_as_current_contract` built from the SDK's auth types)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 85 |
| Stellar examples, single-crate | 25 | 25/25 | 0 | 3,780 |
| Stellar examples, multi-contract | 13 | 12/13 | 1 | 3,418 |
| third-party | 2 | 1/2 | 8 | 642 |
| SDK 26 test contracts | 39 | 39/39 | 0 | 922 |

The argument of `authorize_as_current_contract` is, by protocol, a vector of
`InvokerContractAuthEntry`; its parts now print as the SDK's `ContractContext`,
`SubContractInvocation` and `InvokerContractAuthEntry` literals when every key table matches
the declared fields and every leaf already has its declared type (deep_contract_auth `call_b`
36 → 1 gaps). An empty vec prints as `Vec::new(&e)`. Holes 8,899 → 8,847 (summed); errors
unchanged at 9; corpus byte-identical; held-out mean 0.7865.

## 2026-10-31 — commit 10a2813 (contract upgrade and deploy-with-constructor print as the deployer calls)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 85 |
| Stellar examples, single-crate | 25 | 25/25 | 0 | 3,780 |
| Stellar examples, multi-contract | 13 | 12/13 | 1 | 3,415 |
| third-party | 2 | 1/2 | 8 | 641 |
| SDK 26 test contracts | 39 | 39/39 | 0 | 922 |

`update_current_contract_wasm` and `create_contract_with_constructor` printed as gaps; they
now print as `e.deployer().update_current_contract_wasm(hash)` and
`e.deployer().with_current_contract(salt).deploy_v2(hash, args)` (or `with_address`) once
every operand already has the type the method takes. Holes 8,847 → 8,843 (summed); errors
unchanged at 9; corpus and held-out byte-identical.

## 2026-10-31 — commit 27a05a5 (an enum decoded inline through the vector iterator is a match)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 85 |
| Stellar examples, single-crate | 25 | 25/25 | 0 | 3,763 |
| Stellar examples, multi-contract | 13 | 12/13 | 1 | 3,415 |
| third-party | 2 | 1/2 | 8 | 641 |
| SDK 26 test contracts | 39 | 39/39 | 0 | 706 |

A `#[contracttype]` enum decoded inside the entrypoint, walking its vector with the SDK's
iterator, now prints as a `match` binding each variant's one-component payload
(constructor `get_data`: `match key { DataKey::Persistent(p) => … }`, 55 → 15 gaps;
contracttrait ×3 92 → 50; spec_shaking v1/v2 50 → 25, 41 → 16). Holes 8,843 → 8,610;
errors unchanged at 9; corpus byte-identical; held-out mean 0.7865.

## 2026-10-31 — commit fa19876 (compiler-builtins memcpy/memset/memcmp printed as the core primitive)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 85 |
| Stellar examples, single-crate | 25 | 25/25 | 0 | 3,493 |
| Stellar examples, multi-contract | 13 | 12/13 | 1 | 3,198 |
| third-party | 2 | 1/2 | 8 | 641 |
| SDK 26 test contracts | 39 | 39/39 | 0 | 571 |

The toolchain's own `memcpy`, `memset` and `memcmp`, proven by an exact masked fingerprint
against each installed toolchain's compiler-builtins library, print as one line
(`core::ptr::copy`, `write_bytes`, an iterator compare) instead of a 355-line body with 57
gaps; a copy's returned value reads as its destination. `memcpy` prints as `copy`, not
`copy_nonoverlapping`, because LLVM's memcpy admits identical regions. Holes 8,610 → 7,988
(summed); errors unchanged at 9; corpus byte-identical; held-out mean 0.7865 → 0.7882.

## 2026-10-31 — commit b61e010 (run-time error codes, tuple-struct encodes, integer-enum selects, vec parameter types)

The five sets are byte-identical to fa19876 (7,988 holes, 9 errors). Seven general rules
found on a fresh contract we wrote to test ordinary use (a community treasury, soroban-sdk
23.0.1; `~/.cache/sordec-ultimate/`): an `Err` whose code is known only at run time is the
declared error; an outlined tuple-struct encode is the struct of its arguments; a select
between two integer-enum encodings is the choice of variants; a parameter's own `Vec<?>`
yields to the type its callers agree on; a shifted comparison prints as the integer it
shifts; a gap read only by a storage set or publish is a `Val`, and an i128 gap keeps its
type. The treasury: `cargo check` errors 34 → 19, gaps 686 → 627, lines 2,949 → 2,588
(with fa19876's builtins); it does not build yet.

## 2026-10-31 — commit f94ed92 (an unsigned operator on a gap annotated as a machine word rereads it)

The five sets' totals are unchanged (84/86 compile, 9 errors, 7,988 holes; held-out mean
0.7882). A correctness guard: a memory-read gap printed as `let v: i64 = todo!(..)` is an
`i64` to Rust, and an unsigned comparison on it was printed bare, which reads it signed —
wrong for values with the top bit set once the gap is filled. It is now reread unsigned,
`(v12 as u64) >= (v16 as u64)`: six comparisons in import_ark_bn254's big-integer code.

## 2026-10-31 — commit f46c790 (privacy_pools' constant tables: Vec::from_array loops, by-pointer helpers, U256 from bytes)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 85 |
| Stellar examples, single-crate | 25 | 25/25 | 0 | 3,489 |
| Stellar examples, multi-contract | 13 | 12/13 | 1 | 1,686 |
| third-party | 2 | 1/2 | 8 | 641 |
| SDK 26 test contracts | 39 | 39/39 | 0 | 561 |

`Vec::from_array`'s element loops, run on values every execution shares, are replaced by
their loads and stores; a straight-line helper that reads the word behind its pointer into a
typed host operation is inlined where the caller stored a value of that type there;
`u256_val_from_be_bytes` prints as `U256::from_be_bytes`. privacy_pools 2,433 → 945 gaps (its
Poseidon round constants print as plain `vec![…]` of constants); groth16 ×2, fuzzing, bls,
bn254 and events_ref also drop. Holes 7,988 → 6,462 (summed); errors unchanged at 9; corpus
byte-identical; held-out mean 0.7883.

## 2026-10-31 — commits 5afe24d + band and report (a `select` read only by arithmetic prints as an `if`)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 84 |
| Stellar examples, single-crate | 25 | 25/25 | 0 | 3,459 |
| Stellar examples, multi-contract | 13 | 12/13 | 1 | 1,684 |
| third-party | 2 | 1/2 | 8 | 641 |
| SDK 26 test contracts | 39 | 39/39 | 0 | 559 |

wasm `select(a, b, c)` prints as `if c != 0 { a } else { b }` when both arms carry one
recovered integer type and nothing reads the result but arithmetic or a branch; a select
returned, stored or passed on keeps its gap. Holes 6,462 → 6,427; errors unchanged at 9.
**The reference aggregate moves 0.9389 → 0.9359, on purpose:** timelock's time-bound check,
a gap until now, prints the source's own logic (`if kind == After { ts >= t } else { ts <= t }`,
the `match` in `check_time_bound`), but rustc inlined that helper into `claim`, so the
structure category counts it as a branch the source's `claim` lacks (timelock 1.0000 →
0.9790). Faithful output was kept over the number; the band note in
`crates/sordec/tests/benchmark.rs` records why. Held-out mean 0.7882.

## 2026-10-31 — commit b8d86b9 (curve points as SDK calls; frame stores nothing can read)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 84 |
| Stellar examples, single-crate | 25 | 25/25 | 0 | 3,376 |
| Stellar examples, multi-contract | 13 | 12/13 | 1 | 1,525 |
| third-party | 2 | 1/2 | 8 | 607 |
| SDK 26 test contracts | 39 | 39/39 | 0 | 518 |

BLS12-381 and BN254 point operations print as `e.crypto().bls12_381()` / `bn254()` methods
when each point operand is already a `BytesN` of the point's size (`from_bytes` is a plain
wrap in every SDK version used; type names follow the recovered SDK major). A store into the
frame is dropped when every path from it overwrites those bytes, returns or traps before
anything may read them — the scratch of `vec!` builds, mostly. Holes 6,427 → 6,110 (summed);
errors unchanged at 9; corpus byte-identical; held-out mean 0.7889.

## 2026-10-31 — commit 8c9a287 (`map_unpack_to_linear_memory` reads its key array)

A correctness fix to the effects table: the host reads the keys to select from the array at
`keys_pos`, and the table recorded only the write, so an analysis trusting it could drop a
store of a key the call reads. Output byte-identical on all 86 contracts.

## 2026-10-31 — commits e47b4fe + 34c303b (custom types round 3; privacy_pools' remaining shapes)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 84 |
| Stellar examples, single-crate | 25 | 25/25 | 0 | 3,317 |
| Stellar examples, multi-contract | 13 | 12/13 | 1 | 1,365 |
| third-party | 2 | 1/2 | 8 | 533 |
| SDK 26 test contracts | 39 | 39/39 | 0 | 438 |

- **e47b4fe:**
  - a merge of two u128 values stays u128 (it became i128);
  - a struct decoder may hand a field to the i64/u64 decoder rustc splits out, whose number
    half is the field on a proven struct;
  - a 32-bit load of a stored i64 is its low half.
- **34c303b:**
  - stores in a frame handed to calls of known reach are dropped when no later read can see
    them;
  - a helper handing its own pointer to itself has a known reach;
  - an argument decode handed the `Val` by reference is the parameter the caller stored;
  - `vec_get` at a u32's encode is `get_unchecked(i)`, a push of the element type is
    `push_back`, a bare `map_new` is `Map::new`;
  - `wrap32(len >> 32)` of a length folds to `len()`, fixing a wrong spelling at 47 sites.

Holes 6,110 → 6,007 → 5,737 (summed); errors unchanged at 9; corpus byte-identical; held-out
mean 0.7890. The treasury (our authored test contract): 19 errors, 537 gaps, 2,461 lines.

**Day totals (2026-10-31):** holes 9,591 → 5,737 (−3,854); errors 11 → 9; SDK 26 39/39;
reference aggregate 0.9389 → 0.9359 (the deliberate `select` change); held-out mean 0.7865 → 0.7890.

## 2026-10-31 — commit a0922d0 (treasury round 2: map and Option typing, Result converters, vec search results)

The measured sets are unchanged apart from atomic_multiswap (16 → 14 gaps: its `remove(j)` now
prints as `remove_unchecked`); holes 5,737 → 5,735; errors 9. General rules found on the
authored treasury contract:
- a map a put or del hands back is that map, and an untyped `Map<?, ?>` yields to the declared
  `Map<K, V>`;
- an `unwrap()` names the `Option` it came from;
- the run-time error-code rewrite covers a helper every caller returns, and a `Result`
  converter handed its pair in registers becomes each path's `Ok`/`Err`;
- a vec search's result is the `Option<u32>` the SDK makes of it.

The treasury goes from 19 to 10 `cargo check` errors (535 gaps, 2,464 lines).

## 2026-10-31 — commit df5f821 (a host-filled buffer is the `[u8; N]` it fills)

The IR gains a fixed byte-array value (`[u8; N]`): the host copy that fills one
(`b.to_array()`, or `copy_into_slice` behind the `len == N` check the binary makes), reads of it
(`from_le_bytes` over a slice, or indexing), and `Bytes::from_array`; a helper handing its array
back through an out-parameter returns it. privacy_pools 727 → 660 gaps (its `take::<N>` reads);
no other output changes. Holes 5,735 → 5,668 (summed); errors unchanged at 9.

## 2026-10-31 — commit c7d75eb (account auth contexts, vector iteration and events)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 84 |
| Stellar examples, single-crate | 25 | 25/25 | 0 | 3,230 |
| Stellar examples, multi-contract | 13 | 12/13 | 1 | 1,296 |
| third-party | 2 | 1/2 | 8 | 513 |
| SDK 26 test contracts | 39 | 39/39 | 0 | 405 |

- **Account contexts:** an enum decoded inline is now taken inside a loop too, including
  `__check_auth`'s `Vec<Context>`, which prints as `match context { Context::Contract(c) => … }`
  (account 116 → 66 gaps).
- **Vector iteration:** typed iteration through outlined iterator helpers is a counter loop over
  `get_unchecked` (modular_account 38 → 2).
- **Events:** an `Option<u64>` event field and a muxed `address()` fold into the event literal
  (sdk26/events 35 → 2, score 0.7059 → 1.0000).
- **Event data maps:** maps used only as event data carry their entries.
- **Serialisation:** `serialize_to_bytes` prints as `to_xdr`.

Holes 5,668 → 5,528 (summed); errors unchanged at 9; corpus byte-identical; held-out mean
0.7890 → 0.7911.

## 2026-10-31 — commits b28e536 + 682339b (per-pass IR check; treasury round 3)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 80 |
| Stellar examples, single-crate | 25 | 25/25 | 0 | 3,195 |
| Stellar examples, multi-contract | 13 | 12/13 | 1 | 1,294 |
| third-party | 2 | 1/2 | 8 | 505 |
| SDK 26 test contracts | 39 | 39/39 | 0 | 405 |

- **b28e536:** debug builds can validate the IR after every pass (`SORDEC_VALIDATE_EACH`); it located a
  pre-existing invariant break on atomic_swap (a non-live caller left stale by the 128-bit
  parameter join, since 2026-10-04; release output unaffected), recorded as a known issue.
- **682339b:**
  - a `Result` a helper returns as a (tag, payload) pair is taken as a `Result` when its
    callers only test it (`is_err()`) or read the error code under that test;
  - stale merge inputs no longer block an out-parameter's `Option`;
  - a frame store before a call that reads only known frame bytes is dead when nothing else
    reads it.

Holes 5,528 → 5,479; errors 9; corpus bands pass (timelock and token-v23-stripped each −2 gaps);
held-out mean 0.7911. The treasury: 6 errors, 482 gaps, 2,401 lines.

## 2026-11-01 — commit 68f0049 (custom types round 4: shared iterator slot, per-call struct decoders, enum map values)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 80 |
| Stellar examples, single-crate | 25 | 25/25 | 0 | 3,190 |
| Stellar examples, multi-contract | 13 | 12/13 | 1 | 1,294 |
| third-party | 2 | 1/2 | 8 | 505 |
| SDK 26 test contracts | 39 | 39/39 | 0 | 347 |

- Two enum decodes that reuse one frame slot for their iterator are both taken apart, each step
  credited to the decode that set the slot up on every path to it.
- A struct-decoder helper that some callers hand a proven struct and others a raw value is read
  call by call.
- A value read from a map whose declared values are an enum is that enum.

sdk26/udt 84 → 26 gaps (`recursive_enum` reads as two `match`es and `router.a`/`router.b`);
other_custom_types 293 → 288. Holes 5,479 → 5,416; errors 9; corpus byte-identical; held-out
mean 0.7912.

## 2026-11-01 — commit 358f34d (account and events round 2: decoders that always succeed, protocol 27 delegation, counter indexes, frames on trap paths)

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 80 |
| Stellar examples, single-crate | 25 | 25/25 | 0 | 3,165 |
| Stellar examples, multi-contract | 13 | 12/13 | 1 | 1,290 |
| third-party | 2 | 1/2 | 8 | 497 |
| SDK 26 test contracts | 39 | 39/39 | 0 | 343 |

- An outlined decoder helper that can never fail is read as the value it decodes.
- Protocol 27's `custom_account().get_delegated_signers()` and `delegate_auth(&a)` are named.
- A vector index kept as a word beside its counter reads as the counter.
- A frame set up on a path that never returns is retired like any other.

account 66 → 45 gaps; modular_account 2 → 0; sdk26/events 2 → 0. Holes 5,416 → 5,375; errors 9;
corpus byte-identical; held-out mean 0.7915. The treasury: 6 errors, 481 gaps.

## 2026-11-01 — commit 3b78442 (enum parameters re-matched on their value; dead merge inputs left out)

From f4f6e0c the authored treasury (`samples/authored/`) is measured as its own set.

| Set | Contracts | Compile | Errors | Holes |
|---|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 80 |
| Stellar examples, single-crate | 25 | 25/25 | 0 | 3,165 |
| Stellar examples, multi-contract | 13 | 12/13 | 1 | 1,290 |
| third-party | 2 | 1/2 | 6 | 497 |
| SDK 26 test contracts | 39 | 39/39 | 0 | 343 |
| authored | 1 | 1/1 | 0 | 441 |

- An enum parameter decoded once and tested again later on the same variant is matched on the
  value; the later arms read that variant's own payload.
- A merge whose only readers are unrecovered stores is dead in the code that runs; assignments its
  type cannot hold are left out. This hides a wrong merge type where nothing runs it; it does not
  fix the type.
- A helper's access through a pointer stepped backwards is not located, so the old cautious summary
  applies.

treasury 6 → 0 errors, 481 → 441 gaps: it compiles. Its behaviour check scores 0 of 16
entrypoints: the rebuilt constructor starts at an unrecovered stack-pointer setup and traps, so
nothing can be compared yet. Its overall score is 0.5677; 0.6659 before, when behaviour could not
be measured and was left out. phoenix-vesting 8 → 6 errors. Errors outside the treasury 9 → 7;
corpus byte-identical; held-out mean 0.7915.

## 2026-11-01 — v0.1.0 (final measurement)

Code as at 3b78442. Scores with `score-2.2.0` (`heldout_bench`, macro-expanded basis):

| Set | Contracts | Compile | Errors | Holes | Score |
|---|---:|---:|---:|---:|---:|
| reference corpus | 7 | 7/7 | 0 | 80 | 0.9359 (report.md) |
| Stellar examples, single-crate | 25 | 25/25 | 0 | 3,165 | 0.7915 |
| Stellar examples, multi-contract | 13 | 12/13 | 1 | 1,290 | 0.6643 |
| third-party | 2 | 1/2 | 6 | 497 | 0.5277 |
| SDK 26 test contracts | 39 | 39/39 | 0 | 343 | not scored |
| authored | 1 | 1/1 | 0 | 441 | 0.5677 (behaviour 0 of 16) |

Since the wrap-up started (d6e0f94, 86 contracts): compile 55 → 84 of 86, errors 257 → 7, holes
~10,600 → 5,375. Comparison with soroban-ret: [`comparison.md`](comparison.md).
