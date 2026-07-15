# Soroban Contract Test Corpus

This directory holds the **real-world test corpus** that every decompiler pass
in `sordec-passes` validates against. Each fixture is a real Soroban contract,
toolchain-pinned, with reproducible build instructions and SHA-256-verified
WASM bytes.

The corpus is an **infrastructural artifact** of the project, not a member
crate. The workspace `Cargo.toml` declares `exclude = ["samples"]` so that
`cargo build --workspace` never touches the vendored sources.

## Why this exists

A decompiler's value is measured by what it does on **real contracts users
deployed**, not on toy fixtures we wrote. Every fixture in this corpus
reduces the decompiler's unknown surface area: today the question "what would
happen if we ran sordec against a SEP-41 token in production?" has an answer.

The corpus is also the audit-grade story for the grant deliverable. Every
fixture ships with:

- Pinned `rustc`, `soroban-sdk`, and transitive dependencies (`Cargo.lock`)
- Vendored source with upstream URL + commit SHA + license attribution
- A reproducible `build.sh` that recompiles from source
- `<name>.wasm.sha256` so anyone can verify the committed bytes match

## Per-fixture layout

```
<fixture>/
├── source/                      # Rust source — self-contained crate
│   ├── Cargo.toml               # [workspace] empty → opts out of any parent
│   ├── Cargo.lock               # committed: pins crate graph
│   ├── rust-toolchain.toml      # pins rustc channel
│   ├── VENDORED_FROM            # machine-readable upstream provenance (vendored only)
│   ├── LICENSE                  # upstream LICENSE (vendored only — § 4(b) compliance)
│   └── src/                     # contract source
├── BUILD.md                     # human-readable recipe + expected sha256
├── README.md                    # what features this fixture exercises
├── build.sh                     # reproducible build: cargo + wasm-tools + sha256
├── <fixture>.wasm               # the committed bytes
└── <fixture>.wasm.sha256        # checksum
```

`VENDORED_FROM` and `LICENSE` inside `source/` apply to **vendored**
fixtures (sourced from `stellar/soroban-examples` etc.). First-party
fixtures (`hello-add/`) omit both — they're covered by the repo root
[LICENSE](../../LICENSE).

## Verifying the corpus

```bash
# Verify every committed WASM matches its sha256 (no rebuild)
bash tools/verify-fixtures.sh

# Rebuild a single fixture from source
bash samples/contracts/<fixture>/build.sh
```

`build.sh` rebuilds from pinned source. `verify-fixtures.sh` only checks
sha256s against committed bytes. Two scripts, two purposes — don't conflate.

Bit-stable rebuilds across machines are **not** guaranteed (cargo + rustc
have non-determinism around build paths and parallelism). The committed
WASM is the source of truth; sha256 verifies it hasn't been tampered with.
A locally-rebuilt WASM that differs is expected; what matters is that the
committed bytes are reproducible from the recipe in `BUILD.md`.

## Feature-coverage matrix

This matrix is the high-level cross-reference: which contract-level
*features* each fixture exercises. For the finer per-pass view — which
recogniser actually fires on which fixture — see
[Recognizer coverage](#recognizer-coverage) below.

| Fixture | SDK | Stripped | Storage | Auth | Events | Errors | Cross-call | Crypto | PRNG | AMM math | Notes |
|---------|-----|:--------:|:-------:|:----:|:------:|:------:|:----------:|:------:|:----:|:-------:|-------|
| `hello-add/`           | =21.0.0  | – | – | – | – | – | – | – | – | – | First-party, smallest realistic Soroban contract (`add(u64, u64) -> u64`) |
| `token-v22/`           | =22.0.11 | – | ✓ | ✓ | ✓ | ✓ | ✓ | – | – | – | SEP-41 token, older SDK + wasm32-unknown-unknown target |
| `token-v23/`           | =23.0.1  | – | ✓ | ✓ | ✓ | ✓ | ✓ | – | – | – | SEP-41 token, canonical (latest soroban-examples release) |
| `token-v23-stripped/`  | =23.0.1  | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | – | – | – | Same as token-v23, custom sections removed |
| `timelock/`            | =23.0.1  | – | ✓ | ✓ | – | – | ✓ | – | – | – | Time-bounded claimable balance (cross-contract token calls) |
| `dex-liquidity-pool/`  | =23.0.1  | – | ✓ | ✓ | – | – | ✓ | – | – | ✓ | Constant-product AMM (largest fixture, AMM math + LP shares) |
| `attestation/`         | =23.0.1  | – | – | – | – | ✓ | – | ✓ | ✓ | – | First-party, storage-free by design; crypto (sha256/keccak256/ed25519) + PRNG + `#[contracterror]` + a `>9`-char `Symbol` — the host surfaces the SEP-41 / timelock / AMM fixtures don't reach |

## Recognizer coverage

The per-pass view: which `sordec-passes` recogniser fires on which
fixture. This is the human-readable projection of the machine-checked
recogniser × fixture matrix in
`crates/sordec-driver/tests/coverage_matrix.rs` (run it with
`--nocapture` to see the raw per-metric counts), and it matches the
`recognition:` section of `sordec coverage <fixture>.wasm`. ✓ = the
recogniser rewrote at least one binding on that fixture.

| Recognizer (pass) | hello | v22 | v23 | v23-str | timelock | dex | attest |
|-------------------|:-----:|:---:|:---:|:-------:|:--------:|:---:|:------:|
| val-encoding                         | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| linear-memory (Symbol/String/Bytes/Vec/Map `new`) | – | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| storage tier                         | – | ✓ | ✓ | ✓ | ✓ | ✓ | – |
| auth primitives                      | – | ✓ | ✓ | ✓ | ✓ | ✓ | – |
| auth-flow / admin gate               | – | ✓ | ✓ | – | – | – | – |
| context (ledger / event / compare / panic) | – | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| collections (map / vec / buf ops)    | – | ✓ | ✓ | ✓ | ✓ | – | ✓ |
| const-prop (inter-proc upgrade)      | – | ✓ | ✓ | ✓ | ✓ | ✓ | – |
| enum-key                             | – | ✓ | ✓ | – | ✓ | ✓ | – |
| ttl amounts                          | – | ✓ | ✓ | ✓ | – | – | – |
| cross-contract                       | – | – | – | – | ✓ | ✓ | – |
| client-call typing                   | – | – | – | – | ✓ | ✓ | – |
| dispatcher                           | – | – | – | – | ✓ | – | – |
| abi-sweep crypto/PRNG                 | – | – | – | – | – | – | ✓ |

Reading the table:

- **The stripped token is the honesty control.** `token-v23-stripped` is
  byte-identical to `token-v23` minus the `contractspecv0` custom section.
  Two recognisers go dark on it — **auth-flow/admin-gate** and
  **enum-key** — because both name things against the spec; with the spec
  gone they soundly decline rather than guess. Everything spec-independent
  (storage, auth primitives, ttl, const-prop) still fires identically.
- **Singletons** (one fixture is the sole witness): **dispatcher** →
  timelock (the only `b.m` symbol-index enum decode in the corpus);
  **abi-sweep crypto/PRNG** → attestation (this fixture was added
  precisely to exercise the crypto and PRNG host modules); **ttl
  amounts** → the three tokens.
- **The terminal unrecognised-scan runs on all seven and finds zero
  surviving unknown host calls** — that is the 100% "host interactions"
  figure in `sordec coverage`.

## Adding a new fixture

Future tasks (Phase 2+ semantic recovery, Phase 3 event/error reconstruction)
add fixtures alongside the passes that consume them. The general recipe:

1. Identify the upstream contract (preferably real-world / mainnet-deployed).
2. Vendor the source into `samples/contracts/<name>/source/` at a pinned
   commit. Copy upstream `LICENSE`. Write `VENDORED_FROM`.
3. Pin `rust-toolchain.toml` and commit `Cargo.lock`.
4. Add an empty `[workspace]` to `source/Cargo.toml` so the fixture opts out
   of any parent workspace.
5. Write `build.sh` that produces `<name>.wasm` + `<name>.wasm.sha256`.
6. Document features in `README.md` and update the matrix above.
7. Add an integration test in `crates/sordec-driver/tests/corpus.rs` that
   runs the standard six smoke + invariant assertions.

The corpus is load-bearing infrastructure. Bumping a fixture's pinned SDK or
rustc version is a deliberate action — recipe update + sha256 update + test
review — not a casual edit.
