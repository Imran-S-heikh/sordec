# Compatibility

What sordec handles, what it handles partially, and where the edges are.

Every figure here is reproducible from this repository, and each table names the
command that produces it. Where something is untested, this document says so
rather than inferring support from a version number.

Two claims are kept apart throughout, because conflating them would overstate
the tool:

- **Named** — sordec knows what a host call *is*, from the vendored catalog.
- **Recovered** — sordec reconstructs the surrounding Rust well. That is the
  accuracy question, measured separately in
  [`scoring_metric.md`](scoring_metric.md) and reported in
  [`benchmarks/report.md`](benchmarks/report.md).

A protocol can be fully named and still reconstruct poorly. This document is
about the first.

---

## 1. Soroban protocol versions

The host-function catalog is vendored from `soroban-env-common 27.0.1` —
194 functions across 11 modules. It carries each function's
`min_supported_protocol`, so per-protocol coverage is a fact read out of the
data rather than an estimate:

| Protocol | Host functions available | Catalog | Corpus |
|---|---|---|---|
| ≤ 19 | 139 | named | untested |
| 20 | 138 | named | untested |
| 21 | 141 | named | **hello-add** |
| 22 | 160 | named | **token-v22** |
| 23 | 165 | named | **token-v23, timelock, dex-liquidity-pool, attestation** |
| 24 | 165 | named | untested |
| 25 | 170 | named | untested |
| 26 | 191 | named | untested |
| 27 | 193 | named | held-out set (soroban-examples, SDK 27) |
| ≥ 28 | — | **not named** | untested |

**Why an older contract is safe.** The Soroban host ABI is append-only —
functions are added, never removed or renamed — so a catalog vendored at 27.0.1
covers everything below it. The single exception is visible in the table: one
function carries `max_supported_protocol: 19` and is gone from protocol 20
onward, which is why the count *drops* by one between 19 and 20.

**What happens above 27.** A host call the catalog does not know is not guessed.
It resolves to `SemanticOp::Unknown` carrying the `(module, name)` pair and an
`UnknownReason`, surfaces as a diagnostic, and shows up in `sordec coverage` as
an unrecognised call. The reconstruction admits the gap rather than inventing a
name for it. Re-vendoring is a documented, mechanical procedure — see
`crates/sordec-passes/src/host_calls/VENDORED_FROM`.

**Measured recognition** on the corpus is 100% — 2/2 on hello-add, 31/31 on
token-v22, 35/35 on token-v23, 12/12 on attestation. That is the catalog doing
its job on protocols 21–23; it is not a claim about 24–27.

```bash
# per-protocol availability, from the vendored catalog
python3 -c "
import json
d = json.load(open('crates/sordec-passes/src/host_calls/env.json'))
for p in range(19, 28):
    n = sum(1 for m in d['modules'] for f in m.get('functions', [])
            if f.get('min_supported_protocol', 0) <= p
            and f.get('max_supported_protocol', 99) >= p)
    print(f'protocol {p}: {n}')"

# recognition on a contract
sordec coverage samples/contracts/token-v23/token-v23.wasm | grep 'host calls'
```

### Catalog modules

The eleven single-letter module names a Soroban WASM imports from:

| `x` | `i` | `m` | `v` | `l` | `d` | `b` | `c` | `a` | `t` | `p` |
|---|---|---|---|---|---|---|---|---|---|---|
| context | int | map | vec | ledger | call | buf | crypto | address | test | prng |
| 10 | 52 | 12 | 19 | 18 | 2 | 26 | 37 | 10 | 2 | 4 |

---

## 2. soroban-sdk versions

The SDK version is the axis that changes *semantics*, so sordec recovers it per
contract rather than assuming one. There are three rungs, and the emitted
`Cargo.toml` says which one it landed on:

| Recovered from | Emitted requirement | Comment in the manifest |
|---|---|---|
| `rssdkver` in `contractmetav0` | `soroban-sdk = "=X.Y.Z"` | none needed — this is a fact |
| the protocol number in `contractenvmetav0` | `soroban-sdk = "^N"` | says the patch version was not recorded |
| neither | `soroban-sdk = "^23"` | **warns that this is a guess** |

The middle rung works because the SDK major tracks the protocol number. The
bottom rung is the only place sordec writes a version it did not recover, and it
labels itself as such in the file the user reads.

Exercised in the corpus:

| SDK | Fixture |
|---|---|
| 21.7.7 | hello-add |
| 22.0.11 | token-v22 |
| 23.0.1 | token-v23, timelock, dex-liquidity-pool |
| 23.5.3 | attestation |

One or two minor versions per major. Nothing here establishes behaviour across
the whole of a major line.

```bash
sordec dump-facts samples/contracts/token-v23/token-v23.wasm \
  | python3 -c "import json,sys; d=json.load(sys.stdin)['soroban_facts']; \
      print(d['env_meta'], d['contract_meta'])"
```

---

## 3. Rust toolchains

Two numbers, for two unrelated jobs. Confusing them is easy and the reason they
are tabled together:

| | Version | Why |
|---|---|---|
| **Building sordec** | 1.91+ | Set by `soroban-spec` / `soroban-meta` 25.3.x, which declare it. Our own code needs only 1.87. |
| **Recompiling a reconstruction** | 1.89 + `wasm32v1-none` | Behaviour harness only. Pinned, not derived from the contract. |

The second applies solely to `sordec score --behavior` and the differential-execution
tests; decompiling, scoring and every `dump-*` need none of it. Install it with
`tools/setup-toolchains.sh`.

**Why `wasm32v1-none`** rather than mirroring each contract's original target: it
restricts codegen to WebAssembly 1.0, which cannot encode `reference-types` or
`multi-value` — precisely the two proposals the Soroban host disables. A module
that cannot encode them cannot be rejected at load for containing them.

**Why 1.89** rather than each contract's own rustc: the toolchain affects codegen,
not observable behaviour, and both sides of a differential comparison are read
after the module loads. 1.89 also clears every SDK MSRV in the corpus — 21.7.7
wants 1.74, 22.x and 23.x want 1.84.

---

## 4. Metadata, and what its absence costs

For a decompiler this is the compatibility axis that matters most, because it
varies per *contract* rather than per version.

| Present | Effect |
|---|---|
| `contractspecv0` | Full ABI: entrypoint signatures, `#[contracttype]` shapes, error enums, events |
| `contractenvmetav0` | Protocol number → SDK major when `rssdkver` is absent |
| `contractmetav0` (`rssdkver`) | Exact SDK pin in the emitted manifest |
| name section | Original function names. **Absent from released contracts** — `rustc` strips it |

`token-v23-stripped` is the corpus fixture for the degraded case: the same
contract as `token-v23` with every custom section removed. It scores interface
**0.0000 by construction** — there is no ABI left to compare against — while
structure is unaffected, because structure is scored per entrypoint over call
closures and never reads names. That pair is the regression test proving
recovery is not name-keyed.

The practical reading: sordec degrades by *category* rather than failing. A
contract with no metadata still lifts, still structures, and still emits Rust;
what it loses is the signatures.

---

## 5. Not supported

Stated rather than implied.

- **Local variable names are unrecoverable.** `rustc` deletes them and no
  decompiler recovers them. Bindings get synthesised names.
- **Irreducible control flow** is refused rather than mis-structured. WASM cannot
  express it, so this never fires on real compiler output; the guard
  (`UnknownReason::IrreducibleControlFlow`) exists for exotic producers and
  hand-written modules.
- **Protocols above 27** — see §1. Named calls stop at the vendored catalog.
- **Non-Soroban WASM.** sordec is specialised for Soroban's conventions. A plain
  WASM module parses, but the metadata, host-call and idiom recovery that make
  the output readable have nothing to work with.

---

## Reproducing this document

```bash
bash tools/gate.sh                        # everything below assumes a green gate
cargo build --release
```

Then run the commands in §1 and §2. Every number in this file comes from one of
them, from `Cargo.toml` (the MSRV), or from
`crates/sordec-diffexec/src/preflight.rs` (the recompile toolchain). If a figure
here cannot be traced to one of those, it is a bug in this document.
