# Point 1 Scenario Matrix

## Synthetic Valid Modules

| Family | Generated shapes | Fields exercised |
|---|---:|---|
| Minimal module | 1 | empty `WasmFacts`, no diagnostics |
| Import kind matrix | 1 | function, table, memory, global, tag imports |
| Export kind matrix | 1 | function, table, memory, global exports |
| Tag export matrix | 1 | tag import plus tag export |
| Function type-index order | 1 | ordered and duplicate local type indices |
| Custom sections | 1 | name, bytes, order, range |
| Ignored core sections | 1 | table, memory, global sections without exports |
| Deterministic generator | 4096 | combinatorial imports, locals, exports, custom sections, payload sizes |

## Synthetic Invalid Modules

| Case | Expected outcome |
|---|---|
| Empty byte slice | `FrontendError::Empty` |
| Bad magic bytes | `FrontendError::InvalidWasm` |
| Truncated custom section | `FrontendError::InvalidWasm` |
| Duplicate type section | `FrontendError::InvalidWasm` |
| Invalid UTF-8 in import name | `FrontendError::InvalidWasm` |

## Real Corpus Fixtures

| Fixture | Role |
|---|---|
| `hello-add` | minimal real Soroban contract |
| `token-v22` | older SDK SEP-41 token |
| `token-v23` | canonical SDK v23 SEP-41 token |
| `token-v23-stripped` | stripped custom sections |
| `timelock` | cross-contract token calls and custom types |
| `dex-liquidity-pool` | largest committed fixture |
