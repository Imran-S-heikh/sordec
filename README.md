# sordec

A specialized WebAssembly decompiler for Soroban smart contracts.

`sordec` takes a compiled Soroban contract (`.wasm`) and produces:

- **Compilable Rust source** — for security auditors and contract review
- **Annotated WAT** — for low-level analysis with Soroban-aware annotations

## Status

Under active development as part of the Stellar Community Fund RFP track
(SCF #41 Build Award). See [docs/](docs/) for the development proposal and
timeline.

## Workspace layout

```
crates/
├── sordec-common/    — Shared types: errors, IDs, confidence, provenance
├── sordec-ir/        — Typed intermediate representations
├── sordec-frontend/  — WASM parsing and Soroban metadata decoding
├── sordec-passes/    — Analysis and transformation passes
├── sordec-backend/   — Rust and WAT emitters
├── sordec-driver/    — Pipeline orchestration and pass manager
└── sordec-cli/       — Command-line interface (`sordec` binary)
```

## Build

```
cargo build --release
```

## Usage

```
sordec <path-to-contract.wasm> [--output <dir>]
```

## License

Apache-2.0
