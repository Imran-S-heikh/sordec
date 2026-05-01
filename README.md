# sordec

A WebAssembly decompiler specialized for [Soroban](https://stellar.org/soroban) smart contracts.

> **Status: Phase 1 of 4 — Foundation Complete**
>
> Phase 1 ships an inspection toolkit: parse a Soroban `.wasm`, lift it
> to a typed CFG/SSA IR, and report what we understand about it. Rust
> source generation lands in Phase 3. See [PHASE_1.md](PHASE_1.md) for
> the deliverable summary, verification recipe, and acceptance evidence.

## What it does today

Three CLI subcommands, all read-only inspection. None of these mutate
your `.wasm` or write outside of stdout.

| Subcommand | Output | Use case |
|---|---|---|
| `sordec dump-facts <wasm>`  | JSON | What we extracted: imports, exports, decoded Soroban metadata, contract spec, custom sections |
| `sordec dump-ir <wasm>`     | Text | Waffle-style CFG/SSA IR with **named host calls** (e.g. `host:l:put_contract_data`) |
| `sordec coverage <wasm>`    | Text or `--json` | How much of the contract our pipeline understands: host-call recognition %, lift completeness, operator breakdown |

What's coming next:

- **Phase 2** — multi-instruction pattern recovery (storage tier resolution, auth chain recognition, cross-contract clients, Val encoding/decoding)
- **Phase 3** — control-flow structuring (`if`/`while`/`match` reconstruction) + Rust source emit
- **Phase 4** — accuracy framework, multi-version protocol catalog, polish

No promises on dates; the public roadmap follows the SCF Build Award milestones.

## Quick start

```bash
cargo build --release

# JSON: what's in the contract
./target/release/sordec dump-facts samples/contracts/token-v23/token-v23.wasm | jq .

# Text: the lifted IR with host calls named
./target/release/sordec dump-ir samples/contracts/token-v23/token-v23.wasm | head -40

# Coverage report — the headline metric
./target/release/sordec coverage samples/contracts/token-v23/token-v23.wasm
```

Sample `coverage` output on the canonical SEP-41 token fixture:

```
coverage report — token-v23.wasm
  catalog:         soroban-env-common 26.1.2
  parse:           ok (0 diagnostics)
  metadata:        present (0 diagnostics)
  lift:            46 functions, 0 with diagnostics  (100.0%)
  host calls:      35 / 35 recognized               (100.0%)
  operators:       1085 total
                     call (import):     35
                     call (local):     116
                     call indirect:      0
                     other:            934
```

100% host-call recognition across all six [corpus fixtures](samples/contracts/) at the time of this Phase 1 cut.

## Architecture

Seven-crate Cargo workspace built around three IR layers:

```
WASM bytes
    │
    ▼
┌───────────────────┐
│  WasmFacts        │  parsed WASM + decoded Soroban metadata (sordec-frontend)
└───────────────────┘
    │
    ▼
┌───────────────────┐
│  LiftedIr         │  SSA + CFG, close to WASM operators (sordec-passes / waffle)
└───────────────────┘
    │
    ▼
┌───────────────────┐
│  HighIr           │  structured control flow + recovered Soroban semantics (Phase 2/3)
└───────────────────┘
    │
    ▼
Annotated WAT + recovered Rust (Phase 3)
```

Each transformation between layers is a `Pass` in a `Pipeline`, with
fixpoint-group support for iterative refinement. The pass infrastructure
follows established disassembler/decompiler patterns
(Ghidra/Hex-Rays/angr).

## Workspace layout

```
crates/
├── sordec-common/    — Shared types: newtype IDs, diagnostics, provenance
├── sordec-ir/        — Three typed IR layers (WasmFacts, LiftedIr, HighIr)
├── sordec-frontend/  — WASM parsing + Soroban metadata (contractspecv0 etc.)
├── sordec-passes/    — Lifter + analysis passes + Soroban host-call catalog
├── sordec-backend/   — Rust + WAT emitters (Phase 3)
├── sordec-driver/    — Pipeline orchestration + corpus integration tests
└── sordec-cli/       — `sordec` binary (dump-facts, dump-ir, coverage)
```

Per-crate rustdoc:

```bash
cargo doc --workspace --no-deps --open
```

## Test corpus

[`samples/contracts/`](samples/contracts/) holds six real-world Soroban
contracts used by the integration test suite, each with pinned source +
toolchain + sha256-verified WASM bytes:

| Fixture | Origin | Size | What it exercises |
|---|---|---|---|
| `hello-add/`           | first-party | 629 B | Minimal `add(u64, u64) -> u64`; Val encoding baseline |
| `token-v22/`           | soroban-examples 22.0.11 | 7.2 KB | SEP-41 token, older SDK, `wasm32-unknown-unknown` |
| `token-v23/`           | soroban-examples 23.0.1  | 8.3 KB | SEP-41 token, canonical fixture |
| `token-v23-stripped/`  | soroban-examples 23.0.1  | 6.0 KB | token-v23 with custom sections removed |
| `timelock/`            | soroban-examples 23.0.1  | 3.7 KB | Time-bounded claimable balance, cross-contract token calls |
| `dex-liquidity-pool/`  | soroban-examples 23.0.1  | 11 KB  | Constant-product AMM, largest fixture |

Verify all six against their committed sha256s:

```bash
bash tools/verify-fixtures.sh
```

Rebuild any single fixture from its pinned source:

```bash
bash samples/contracts/<name>/build.sh
```

See [samples/contracts/README.md](samples/contracts/README.md) for the
full layout convention and feature-coverage matrix.

## Running the test suite

```bash
cargo test --workspace                                       # 121 tests
cargo clippy --workspace --all-features --all-targets -- -D warnings
cargo doc --workspace --no-deps                              # no broken intra-doc links
bash tools/verify-fixtures.sh                                # 6/6 sha256 OK
```

All gates green at every commit on `main`. No CI workflow yet; the
verification recipe is the contract.

## Phase 1 deliverable

For SCF grant verification, see [PHASE_1.md](PHASE_1.md). It pins the
exact commits, lists what was promised vs. what landed, and gives a
five-minute reproduction recipe Sala (or anyone) can run from a clean
clone.

## Funding

Built with support from the Stellar Community Fund (SCF Build Award #41).

## License

[Apache-2.0](LICENSE).

## Contact

Imran Shaikh — see `Cargo.toml` workspace metadata.
