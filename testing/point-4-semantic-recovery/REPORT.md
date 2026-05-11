# Point 4 Completion Report

## Deliverable

Point 4 requires baseline semantic recovery for core Soroban host calls and initial test vectors plus scoring rules.

## Test Assets Added

- `crates/sordec-passes/tests/point4_host_call_catalog.rs`
- `crates/sordec-cli/tests/point4_semantic_recovery.rs`
- `testing/point-4-semantic-recovery/README.md`
- `testing/point-4-semantic-recovery/SCENARIO_MATRIX.md`
- `testing/point-4-semantic-recovery/RUNBOOK.md`
- `testing/point-4-semantic-recovery/REPORT.md`

## Coverage Statistics

Catalog coverage:

| Input class | Count | Purpose |
| --- | ---: | --- |
| Vendored host-call catalog entries | 192 | Full resolver coverage against `env.json` |
| Host modules represented | 11 | Core module smoke coverage |
| Deterministic known lookup matrix | 4096 | Resolver repeatability |
| Deterministic unknown lookup matrix | 4096 | False-positive resistance |

Synthetic CLI coverage:

| Synthetic WASM class | Count | Purpose |
| --- | ---: | --- |
| Mixed known/unknown host-call module | 1 | Friendly rendering, fallback rendering, `3 / 5` score |
| All-core-module host-call module | 1 | 11 module examples, `11 / 11` score |
| No-host-call module | 1 | Zero-denominator scoring |

Focused automated tests:

| Test target | Count |
| --- | ---: |
| Catalog/resolver tests | 7 |
| CLI semantic-recovery tests | 6 |
| Total Point 4 focused tests | 13 |

## Coverage Chart

```text
Catalog entries resolved       | ################################################## 192
Known lookup matrix            | ################################################## 4096
Unknown lookup matrix          | ################################################## 4096
Core host modules              | ########### 11
Synthetic CLI WASM modules     | ### 3
```

## Scoring Rule

The Phase 1 host-call recognition score is:

```text
recognized_host_calls / total_direct_calls_to_imported_functions
```

The test suite verifies:

- `3 / 5 = 0.6` for mixed known/unknown calls.
- `11 / 11 = 1.0` for one known call from every core host module example.
- `null` ratio when there are zero host calls.
- Unknown calls are grouped by `(module, name)` with stable counts.
- Local calls do not affect the host-call denominator.

## Findings

Baseline host-call recovery is implemented and testable. The resolver uses the vendored `soroban-env-common 26.1.2` catalog with 192 entries across 11 host modules. `dump-ir` displays friendly host-call names for recognized imports and raw host names for unknown imports. `coverage` publishes the recognition ratio, unknown-call groups, and operator buckets.

This is not full Soroban semantic reconstruction yet. Storage tier recovery, auth-chain recovery, cross-contract client reconstruction, event collapsing, and Val encode/decode pattern collapse remain Phase 2+ work.

## Completion Assessment

Point 4 is structurally complete for Tranche 1 baseline host-call semantic recovery.

Completion criteria:

| Criterion | Assessment |
| --- | --- |
| Core host-call catalog exists | Complete |
| Known host calls render as friendly names | Complete |
| Unknown host calls degrade safely | Complete |
| Initial scoring rules published | Complete |
| Automated synthetic and catalog test vectors added | Complete |
| Full semantic operation collapse | Not in Phase 1 scope |
| Focused tests executed locally | Complete |

Executed results:

```text
point4_host_call_catalog: 7 passed; 0 failed; 0 ignored
point4_semantic_recovery: 6 passed; 0 failed; 0 ignored
```

Recommended verification commands:

```bash
cargo test -p sordec-passes --test point4_host_call_catalog
cargo test -p sordec-cli --test point4_semantic_recovery
```
