# Soroban Decompiler — Development Proposal

Hi Team,

I want to be upfront: I don't have previous experience working with compilers or decompilers. This project will be a learning-and-building journey for me — I'll be picking up compiler design concepts (IR design, SSA, control flow structuring, pattern matching) as I work through each module. Because of that, timelines can extend unexpectedly as I work through unfamiliar territory. But you can expect a good product at the end, Inshallah.

I've done a thorough review of the current codebase and architecture document. Below is my honest assessment and proposed work plan.

---

## Current State Assessment

The existing codebase (~11,800 lines of Rust) has a working end-to-end pipeline but has significant architectural issues that will block progress on real-world contracts:

- **String-typed IR**: Opcodes, types, and terminators are all plain strings instead of proper enums — no compile-time safety, easy to introduce silent bugs
- **Monolithic emitter**: The code generation module is 5,100 lines in a single file — difficult to maintain or extend
- **Shallow semantic recovery**: Host function calls are name-mapped but multi-instruction SDK patterns (Val encoding, storage scoping, auth chains) are not recognized
- **Weak accuracy validation**: Only tested against 3 trivial contracts (add two numbers, basic storage, simple constructor). No real-world contract testing
- **Storage bug**: All storage operations are hardcoded as `.persistent()` — real contracts use 3 tiers (persistent/temporary/instance)

These need to be fixed before adding new features.

---

## Proposed Work Plan

### Phase 1 — Foundation Hardening (~13 days)

Fix the architecture so it can scale to real contracts.

| Module | Work | Days |
|--------|------|------|
| `ir_types.rs` (new) | Define proper typed enums for opcodes, types, terminators — replace all string-typed IR | 2 |
| `lifted_ir.rs` | Update waffle adapter to emit typed enums instead of debug-formatted strings | 2 |
| `emit/` (restructure) | Decompose the 5,100-line monolith into 7 focused modules (WAT emitter, Rust codegen, body recovery, pattern recovery, helpers, test harness) | 3 |
| `high_ir.rs` + `semantic.rs` | Update to use typed IR throughout — eliminate all string matching on opcodes/terminators | 2 |
| `samples/contracts/` | Build test corpus with 5+ real Soroban contracts (Token, DEX, Timelock, Errors, Events) — compiled WASM paired with original source | 4 |

**Deliverable**: Type-safe pipeline, modular emitter, real-world test corpus

---

### Phase 2 — Deep Semantic Recovery (~14 days)

Teach the decompiler to recognize SDK patterns, not just individual host calls.

| Module | Work | Days |
|--------|------|------|
| `patterns/val_encoding.rs` (new) | Recognize Val bit-packing sequences — collapse multi-instruction chains into literals, symbols, booleans | 4 |
| `patterns/storage.rs` (new) | Fix the storage scoping bug — trace durability arguments through SSA to emit correct `.persistent()` / `.temporary()` / `.instance()` | 3 |
| `patterns/auth.rs` (new) | Recognize authorization patterns — `require_auth`, scoped auth, approval chains | 2 |
| `patterns/cross_contract.rs` (new) | Recover typed cross-contract calls instead of generic `invoke_contract()` | 2 |
| `patterns/mod.rs` (new) | Integrate all pattern passes into the pipeline between semantic recovery and high-level IR | 1 |
| Benchmarking | Run full pipeline against SEP-41 token contract, measure accuracy, document gaps | 2 |

**Deliverable**: Pattern recognition engine, correct storage scoping, token contract benchmark

---

### Phase 3 — Accuracy & Complex Patterns (~16 days)

Make the accuracy metric rigorous and handle real-world complexity.

| Module | Work | Days |
|--------|------|------|
| `accuracy/` (new, replaces `evaluate.rs`) | Redesign accuracy metric — structural similarity (40%), semantic correctness (40%), syntactic quality (20%) — includes compilation and behavioral testing | 4 |
| `soroban_metadata.rs` + `emit/rust_codegen.rs` | Complex type reconstruction — nested enums, generics, recursive types, error enum + Result integration | 3 |
| `patterns/events.rs` (new) | Recover `#[contractevent]` struct definitions from WASM-level event emission sequences | 2 |
| `high_ir.rs` | Control flow improvements — short-circuit detection (&&/\|\|), early returns from loops, while-loop patterns, nested breaks | 5 |
| `benchmark/` (new) | Automated benchmark suite — decompile all test corpus contracts, run accuracy metric, compile outputs, generate reports | 2 |

**Deliverable**: Rigorous accuracy framework, complex type support, improved control flow, benchmark suite

---

### Phase 4 — Production Hardening & Release (~16 days)

Hit the 90% accuracy target, polish everything, ship it.

| Module | Work | Days |
|--------|------|------|
| Various | Gap analysis based on Tranche 3 benchmarks — fix top accuracy issues (constant propagation, dispatcher patterns, inline helpers) | 5 |
| `emit/` | Output quality polish — remove unnecessary bindings, method chaining, meaningful variable names, clean imports | 3 |
| `error.rs` + pipeline | Error handling — clear messages on failure, graceful degradation for stripped WASM, memory protection | 2 |
| CLI | Add accuracy/benchmark flags, JSON output, verbose mode, multi-file support | 1 |
| Documentation | Architecture docs, pattern catalog, API docs, contributing guide, CI setup (GitHub Actions) | 3 |
| Buffer | Final accuracy push — reserve for unexpected gaps | 2 |

**Deliverable**: 90%+ accuracy on token contract, polished CLI, complete documentation, CI pipeline, open source release

---

## Timeline Summary

| Phase | Days | Calendar Weeks |
|-------|------|----------------|
| 1 — Foundation | ~13 | 2–3 weeks |
| 2 — Semantic Recovery | ~14 | ~3 weeks |
| 3 — Accuracy & Patterns | ~16 | ~3 weeks |
| 4 — Production & Release | ~16 | ~3 weeks |
| **Total** | **~59 days** | **~12 weeks** |

Realistically, with the learning curve factored in, I'd estimate **3–4 months** for the full project.

Again — since I'm learning compiler concepts alongside building, some tasks may take longer than estimated, especially the control flow structuring (Phase 3) and the final accuracy push (Phase 4). I'll keep you updated on progress and flag any blockers early.

Looking forward to working on this.

Best,
Imran
