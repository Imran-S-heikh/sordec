# Point 2 Scenario Matrix

## Synthetic Valid Metadata

| Family | Generated shapes | Fields exercised |
|---|---:|---|
| Generic WASM without spec | 1 | `soroban_facts == None` |
| Full spec entry family module | 1 | function, struct, union, enum, error enum, event |
| Primitive type matrix | 1 | all 19 primitive `ScSpecTypeDef` variants |
| Composite type matrix | 1 | option, result, vec, map, tuple, bytesN, UDT |
| Contract meta concat | 1 | multiple `contractmetav0` sections |
| Env meta | 1 | protocol and pre-release |
| Deterministic metadata generator | 4096 | function signatures with varying parameter counts and primitive types |

## Recoverable Diagnostics

| Case | Expected diagnostic |
|---|---|
| Duplicate UDT name | `MetadataDiagnosticCode::DuplicateTypeName` |
| Duplicate function name | `MetadataDiagnosticCode::DuplicateFunctionName` |
| Unresolved UDT reference | `MetadataDiagnosticCode::UnresolvedTypeReference` |
| Malformed `contractmetav0` | `MetadataDiagnosticCode::MalformedContractMeta` |

## Fatal Metadata Errors

| Case | Expected outcome |
|---|---|
| Malformed `contractspecv0` | `FrontendError::MalformedSpec` |
| Malformed `contractenvmetav0` | `FrontendError::MalformedEnvMeta` |

## Real Corpus Fixtures

| Fixture | Expected metadata |
|---|---|
| `hello-add` | present |
| `token-v22` | present |
| `token-v23` | present |
| `token-v23-stripped` | absent |
| `timelock` | present |
| `dex-liquidity-pool` | present |
