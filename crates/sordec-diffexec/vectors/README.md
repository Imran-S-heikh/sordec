# Divergence vectors

Pairs of contracts differing in exactly one observable way, used to prove the
behaviour comparator **detects** things.

## Why these exist

Every other test in `sordec-diffexec` compares a contract against itself. That can
only ever show the harness reports no *false* differences — half the job. A
comparator that returned `Match` unconditionally would pass all of them.

These vectors are the other half. Because we author both sides, the correct verdict
is known before the harness runs, which makes each one a **test** rather than a
measurement.

## Why not just use the decompiler's output

It cannot do this job, in either direction:

- When a diff against our emitter's output **fails**, you cannot tell a harness bug
  from an emitter bug.
- When it **passes**, you have not established that the comparator is capable of
  failing.

Our emitter is the B-side we care about; it is not the B-side that can validate the
instrument.

## These are not scaffolding

They do not become obsolete when the emitter starts compiling. At that point they
remain the only thing that catches the comparator silently losing a tuple — a
regression that emitter-based measurement cannot detect, because with real
reconstruction output nobody knows the right answer.

Treat them the way `sordec-score`'s `tests/calibration.rs` is treated: a permanent
guard on the instrument, kept honest independently of what it is currently
measuring.

## Hard rule: a vector's score is not our score

A number produced from these contracts is a **calibration** result. It may never be
reported as sordec's behaviour score — these are contracts we wrote, not contracts
our decompiler recovered. The same line T17 held when it refused to count
`todo!()` holes as recovered facts.

The typed guard lives in the scorer bridge, as a `BSide` discriminant that travels
with every behaviour result.

## Layout

```
vectors/<class>/base.rs      the unmutated contract
vectors/<class>/mutant.rs    exactly one observable change
```

Only the contract sources are committed. Manifests are generated at test time from
one template (`tests/common/mod.rs`) so the `[profile.release]` flags — several of
which change behaviour or loadability — have a single owner and cannot drift per
vector. Built wasm is never committed: it is reproducible from the source plus the
pinned toolchain, and it lands in a persistent target directory outside the repo.

The driver for each vector — which functions to call with which arguments, and the
verdict expected — lives in `tests/vectors.rs`. Drivers are hand-written rather
than generated, which is what lets this corpus skip input generation entirely: we
wrote the contract, so there is nothing to infer.

## The classes

| Class | What differs | Tuple it must land in |
|---|---|---|
| `return_value` | `x + 1` vs `x + 2` | return |
| `overflow` | `x * 4` vs `x << 2` under `overflow-checks` | return |
| `error_code` | two `#[contracterror]` discriminants | return |
| `storage_tier` | `persistent()` vs `instance()` | storage |
| `ttl` | different `extend_ttl` target | storage |
| `event_layout` | same values, topic vs data | events |
| `auth_shape` | `require_auth` vs `require_auth_for_args` | auth |
| `argument_swap` | sender and recipient exchanged | events |
| `trivial_agreement` | both panic, differently | *none* — must score nothing |

Two of these are not hypothetical:

- **`overflow`** is the class Inferara's decompiler shipped — their output emitted
  `count << 2` where the original had `count * 4`, so it stopped trapping on inputs
  the original trapped on. Recovering the shift is correct at the instruction level
  and wrong at the semantic level, and only execution tells them apart.
- **`argument_swap`** is why `canon` labels addresses by *role* rather than by order
  of first appearance. Under first-appearance labelling both sides render as
  `(addr_0, addr_1)`, this vector passes, and money goes to the wrong party in
  silence.

`trivial_agreement` is the control. Two contracts that both panic agree perfectly
and demonstrate nothing; folded into a match rate that reads as recovery. It must
land in its own bucket and produce no rate at all.

## Adding one

1. Write `vectors/<class>/base.rs` and `mutant.rs`. Keep them minimal — one
   function, one difference. Anything extra is another way for the vector to fail
   for a reason that is not its own.
2. Add a `Vector` entry in `tests/vectors.rs` with its driver calls, any role→address
   bindings, and the tuple you expect to diverge.
3. Run `cargo test -p sordec-diffexec --test vectors -- --ignored --nocapture`.

The assertion is two-sided: the named tuple **must** diverge, and every other
exercised tuple **must not**. The second half is what stops a comparator that
flags everything from passing.
