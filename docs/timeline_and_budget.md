# Soroban Reverse Engineering Tool — Timeline & Budget

**Project**: Soroban Specialized WASM-to-Rust Decompiler
**Award**: SCF #41 Build Award (DevTooling RFP)
**Total Budget**: $120,000 (paid in XLM)
**Duration**: 24 weeks (~6 months)
**Team Size**: 1 developer (full-time)

---

## Budget Allocation by Tranche

| Tranche | Title | Weeks | Dev-Days | Budget | Cumulative |
|---------|-------|-------|----------|--------|------------|
| 1 | Foundation Hardening | 1–6 | 30 | $30,000 | $30,000 |
| 2 | Deep Semantic Recovery | 7–12 | 30 | $30,000 | $60,000 |
| 3 | Accuracy Framework & Complex Patterns | 13–18 | 30 | $30,000 | $90,000 |
| 4 | Production Hardening & Release | 19–24 | 30 | $30,000 | $120,000 |

---

## Tranche 1: Foundation Hardening — $30,000

**Timeline**: Weeks 1–6 (30 dev-days)

| Task | Description | Days | Deliverable |
|------|-------------|------|-------------|
| 1.1 | Define typed IR enums (replace string-typed IR) | 5 | `ir_types.rs` with `WasmOp`, `IrType`, `LiftedTerminatorKind` enums |
| 1.2 | Update IR lifter for typed output | 5 | `lifted_ir.rs` emitting typed enums instead of strings |
| 1.3 | Decompose code emitter into modules | 8 | `emit/` directory with 7 focused modules (each <1000 LOC) |
| 1.4 | Update high-level IR and semantic layers | 5 | `high_ir.rs` and `semantic.rs` using typed IR |
| 1.5 | Build real-world test corpus | 7 | 5+ real Soroban contracts (Token, DEX, Timelock, Errors, Events) with WASM+source pairs |

**Milestone Criteria**:
- All existing tests pass
- String-typed IR fully replaced with compiler-checked enums
- Monolithic emitter (5,100 LOC) decomposed into modular architecture
- 5+ real-world contract test fixtures established

---

## Tranche 2: Deep Semantic Recovery — $30,000

**Timeline**: Weeks 7–12 (30 dev-days)

| Task | Description | Days | Deliverable |
|------|-------------|------|-------------|
| 2.1 | Val encoding/decoding pattern recognition | 6 | `patterns/val_encoding.rs` — collapses tagged-value instruction sequences |
| 2.2 | Storage tier pattern recognition | 6 | `patterns/storage.rs` — distinguishes persistent/temporary/instance storage |
| 2.3 | Authorization chain patterns | 5 | `patterns/auth.rs` — recognizes require_auth, scoped auth, approval patterns |
| 2.4 | Cross-contract call patterns | 5 | `patterns/cross_contract.rs` — typed client calls, try_call recovery |
| 2.5 | Pattern integration into pipeline | 4 | `patterns/mod.rs` — orchestrates all pattern passes in pipeline |
| 2.6 | Benchmark against token contract | 4 | Benchmark report with accuracy measurements and gap analysis |

**Milestone Criteria**:
- Multi-instruction SDK pattern recognition operational
- Storage tier correctly distinguished in decompiled output
- Token contract decompilation produces meaningful output
- Pattern catalog documented with examples

---

## Tranche 3: Accuracy Framework & Complex Patterns — $30,000

**Timeline**: Weeks 13–18 (30 dev-days)

| Task | Description | Days | Deliverable |
|------|-------------|------|-------------|
| 3.1 | Redesign accuracy metric | 8 | `accuracy/` module — multi-dimensional scoring (structural 40%, semantic 40%, syntactic 20%) |
| 3.2 | Complex enum/union reconstruction | 6 | Nested enums, generics, recursive types, Result<T, Error> integration |
| 3.3 | Event pattern recovery | 4 | `patterns/events.rs` — reconstructs `#[contractevent]` from WASM-level calls |
| 3.4 | Control flow improvements | 7 | Short-circuit detection, early returns, while-loop patterns, nested breaks |
| 3.5 | Automated benchmark suite | 5 | Reproducible benchmarking infrastructure with per-contract reports |

**Milestone Criteria**:
- Accuracy metric redesigned — non-gameable, includes behavioral correctness testing
- Complex type hierarchies reconstructed correctly
- Event patterns recovered from WASM
- Control flow structuring handles real-world patterns
- Automated benchmark suite producing reproducible results

---

## Tranche 4: Production Hardening & Release — $30,000

**Timeline**: Weeks 19–24 (30 dev-days)

| Task | Description | Days | Deliverable |
|------|-------------|------|-------------|
| 4.1 | Gap analysis and targeted fixes | 8 | Fix top accuracy gaps identified by Tranche 3 benchmarks |
| 4.2 | Output quality polish | 6 | Idiomatic Rust output — method chaining, meaningful names, clean imports |
| 4.3 | Error handling & edge cases | 5 | Graceful degradation, clear errors, memory protection, progress reporting |
| 4.4 | CLI improvements | 3 | Accuracy/benchmark flags, JSON output, verbose mode, multi-file support |
| 4.5 | Documentation & release prep | 5 | Architecture docs, pattern catalog, API docs, CI pipeline, contributing guide |
| 4.6 | Final accuracy push | 3 | Buffer for final benchmark gaps |

**Milestone Criteria**:
- 90%+ accuracy on token contract benchmark (multi-dimensional metric)
- Compilable Rust output for all test corpus contracts
- Polished CLI with accuracy and benchmark modes
- Complete documentation
- CI pipeline (GitHub Actions)
- Open source release

---

## Weekly Timeline (Gantt View)

```
Week  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15 16 17 18 19 20 21 22 23 24
      ├──────────────────┤├──────────────────┤├──────────────────┤├──────────────────┤
      │   TRANCHE 1      ││   TRANCHE 2      ││   TRANCHE 3      ││   TRANCHE 4      │
      │                  ││                  ││                  ││                  │
T1.1  ████████           ││                  ││                  ││                  │
T1.2       ████████      ││                  ││                  ││                  │
T1.3            █████████████                ││                  ││                  │
T1.4                 ████████                ││                  ││                  │
T1.5  ████████████████████                   ││                  ││                  │
      │                  ││                  ││                  ││                  │
T2.1  │                  ││████████████      ││                  ││                  │
T2.2  │                  ││      ████████████││                  ││                  │
T2.3  │                  ││      ████████    ││                  ││                  │
T2.4  │                  ││      ████████    ││                  ││                  │
T2.5  │                  ││            ██████││                  ││                  │
T2.6  │                  ││              ████████                ││                  │
      │                  ││                  ││                  ││                  │
T3.1  │                  ││                  ││████████████████  ││                  │
T3.2  │                  ││                  ││      ████████████││                  │
T3.3  │                  ││                  ││      ██████      ││                  │
T3.4  │                  ││                  ││  ██████████████  ││                  │
T3.5  │                  ││                  ││            ██████████                │
      │                  ││                  ││                  ││                  │
T4.1  │                  ││                  ││                  ││████████████████  │
T4.2  │                  ││                  ││                  ││      ████████████│
T4.3  │                  ││                  ││                  ││      ████████    │
T4.4  │                  ││                  ││                  ││          ████    │
T4.5  │                  ││                  ││                  ││        ██████████│
T4.6  │                  ││                  ││                  ││              ████│
      ├──────────────────┤├──────────────────┤├──────────────────┤├──────────────────┤
      $30k milestone     $60k cumulative     $90k cumulative     $120k final
```

---

## Cost Breakdown by Category

| Category | Estimated % | Amount | Details |
|----------|-------------|--------|---------|
| Architecture & IR Design | 20% | $24,000 | Typed IR enums, pipeline restructuring, module decomposition |
| Semantic Recovery | 20% | $24,000 | Pattern recognition (Val encoding, storage, auth, cross-contract) |
| Code Generation | 15% | $18,000 | Rust/WAT emitters, body recovery, output quality |
| Accuracy & Evaluation | 15% | $18,000 | Metric redesign, benchmark suite, behavioral testing |
| Testing & Test Corpus | 15% | $18,000 | Real-world contracts, integration tests, CI pipeline |
| Control Flow & Types | 10% | $12,000 | CFG structuring, complex types, event recovery |
| Documentation & Release | 5% | $6,000 | Docs, CLI, contributing guide, release prep |

---

## Risk Assessment

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| 90% accuracy target unreachable on complex contracts | Medium | High | Redesigned metric includes behavioral correctness (40% weight) — correct compilable code scores well even with imperfect syntax |
| waffle IR lifter limitations on edge-case WASM | Low | Medium | Fallback path exists; real decompilation intelligence is in pattern layer, not lifter |
| Soroban SDK version changes mid-project | Low | Low | Pin to SDK 25.3.0; host function ABI already fully mapped; version bumps handled post-release |
| Scope creep from additional contract patterns | Medium | Medium | Each tranche has explicit deliverables; test corpus provides objective measurement |
| Timeline slippage | Medium | Medium | 3-day buffer in Tranche 4 (Task 4.6); tasks within tranches can be parallelized |

---

## Deliverables Summary

| # | Deliverable | Tranche | Format |
|---|-------------|---------|--------|
| 1 | Type-safe decompiler pipeline | T1 | Rust crate (compilable, tested) |
| 2 | Modular code emitter architecture | T1 | 7-module emit/ directory |
| 3 | Real-world contract test corpus | T1 | 5+ WASM+source pairs |
| 4 | SDK pattern recognition engine | T2 | patterns/ module with 5 pattern matchers |
| 5 | Token contract benchmark report | T2 | Markdown report with accuracy data |
| 6 | Multi-dimensional accuracy framework | T3 | accuracy/ module with structural/semantic/syntactic scoring |
| 7 | Automated benchmark suite | T3 | Reproducible benchmark infrastructure |
| 8 | Production-ready CLI tool | T4 | Binary with accuracy/benchmark modes |
| 9 | Complete documentation | T4 | Architecture docs, pattern catalog, API docs |
| 10 | CI/CD pipeline | T4 | GitHub Actions configuration |
| 11 | Open source release | T4 | Published crate with license |
