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
├── source/                      # vendored Rust source — self-contained crate
│   ├── Cargo.toml               # [workspace] empty → opts out of any parent
│   ├── Cargo.lock               # committed: pins crate graph
│   ├── rust-toolchain.toml      # pins rustc channel
│   ├── VENDORED_FROM            # machine-readable upstream provenance
│   ├── LICENSE                  # upstream LICENSE (Apache-2.0 § 4(b) compliance)
│   └── src/                     # contract source
├── BUILD.md                     # human-readable recipe + expected sha256
├── README.md                    # what features this fixture exercises
├── build.sh                     # reproducible build: cargo + wasm-tools + sha256
├── <fixture>.wasm               # the committed bytes
└── <fixture>.wasm.sha256        # checksum
```

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

This matrix is the cross-reference for future passes: when a Phase 2/3 task
introduces (say) storage-tier detection, scan this column to find the
fixtures that exercise it.

| Fixture | SDK | Stripped | Storage | Auth | Events | Errors | Cross-call | AMM math | Notes |
|---------|-----|:--------:|:-------:|:----:|:------:|:------:|:----------:|:-------:|-------|
| `token-v22/`           | =22.0.11 | – | ✓ | ✓ | ✓ | ✓ | ✓ | – | SEP-41 token, older SDK + wasm32-unknown-unknown target |
| `token-v23/`           | =23.0.1  | – | ✓ | ✓ | ✓ | ✓ | ✓ | – | SEP-41 token, canonical (latest soroban-examples release) |
| `token-v23-stripped/`  | =23.0.1  | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | – | Same as token-v23, custom sections removed |
| `timelock/`            | =23.0.1  | – | ✓ | ✓ | – | – | ✓ | – | Time-bounded claimable balance (cross-contract token calls) |
| `dex-liquidity-pool/`  | =23.0.1  | – | ✓ | ✓ | – | – | ✓ | ✓ | Constant-product AMM (largest fixture, AMM math + LP shares) |

**Existing fixtures** in `learning/experiments/` (referenced by tests, not
re-vendored here):

| Fixture | SDK | Notes |
|---------|-----|-------|
| `01-hello-add`     | – | Minimal `add(u64, u64) -> u64` |
| `02-counter`       | =21.0.0 | Auth + storage, older SDK |
| `02-counter-v26`   | =26.0.0-rc.1 | Same logic, newer SDK |

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
