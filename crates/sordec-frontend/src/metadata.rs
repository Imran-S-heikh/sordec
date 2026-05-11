//! Soroban metadata decoding.
//!
//! Reads the three custom sections — `contractspecv0`, `contractenvmetav0`,
//! `contractmetav0` — from a [`crate::WasmFacts`] and produces a typed
//! [`SorobanFacts`].
//!
//! The most interesting work happens in the spec decoder ([`decode_spec`],
//! added in step 4): two-pass [`TypeId`] resolution. Helpers and the
//! simpler env/contract-meta decoders live in this step (3); spec
//! decoding lands in step 4.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;

use sordec_common::{Diagnostic, IrId, Location, MetadataDiagnosticCode, TypeId, UnknownReason};
use sordec_ir::{
    CompositeType, CustomSection, EnumCase, EnumDef, EnvCompatibility, EventDef, EventParam,
    EventParamLocation, FunctionParam, FunctionSignature, PrimitiveType, SorobanFacts, StructDef,
    StructField, TypeRef, TypeRegistry, UnionCase, UnionDef,
};
use stellar_xdr::curr::{
    Limited, Limits, ReadXdr, ScEnvMetaEntry, ScMetaEntry, ScSpecEntry, ScSpecEventParamLocationV0,
    ScSpecTypeDef, ScSpecUdtUnionCaseV0, ScSymbol, StringM,
};

use crate::error::{FrontendError, FrontendResult};

// ---------------------------------------------------------------------
// String helpers
// ---------------------------------------------------------------------

/// Convert an XDR `ScSymbol` into a `String`, surfacing any UTF-8 failure
/// as an error.
///
/// Soroban-sdk requires identifiers to be valid Rust idents at compile
/// time, so any non-UTF-8 here means the contract was hand-crafted or
/// corrupted. The legacy decompiler used `from_utf8_lossy`, which would
/// produce U+FFFD replacement chars and break downstream codegen with a
/// confusing error far from the actual cause.
pub(super) fn symbol_to_string(symbol: &ScSymbol) -> FrontendResult<String> {
    symbol
        .to_utf8_string()
        .map_err(|_| FrontendError::InvalidUtf8Name)
}

/// Convert an XDR `StringM<N>` into a `String`, surfacing any UTF-8 failure
/// as an error. See [`symbol_to_string`] for the rationale.
pub(super) fn stringm_to_string<const N: u32>(value: &StringM<N>) -> FrontendResult<String> {
    value
        .to_utf8_string()
        .map_err(|_| FrontendError::InvalidUtf8Name)
}

// ---------------------------------------------------------------------
// Type-ref converter
// ---------------------------------------------------------------------

/// Translate a `stellar-xdr` `ScSpecTypeDef` into our typed [`TypeRef`].
///
/// `name_to_id` is the lookup built by [`decode_spec`] (step 4) before
/// any body is decoded; it maps each user-defined-type name to its
/// allocated [`TypeId`]. Recursive on composite types.
///
/// **Mapping fidelity vs. legacy:** the legacy decompiler collapsed
/// `Timepoint`, `Duration`, `U256`, `I256`, and `MuxedAddress` into
/// other primitives — losing information. We preserve the original
/// Soroban primitive in every case.
///
/// The match is exhaustive over `ScSpecTypeDef` (no `_` arm). If a
/// future `stellar-xdr` bump adds a variant, we want to fail to compile,
/// not silently mis-classify.
pub(super) fn spec_type_to_typeref(
    ty: &ScSpecTypeDef,
    name_to_id: &BTreeMap<String, TypeId>,
    diagnostics: &mut Vec<Diagnostic>,
) -> FrontendResult<TypeRef> {
    let typeref = match ty {
        // ---- Primitives ----
        ScSpecTypeDef::Val => TypeRef::Primitive(PrimitiveType::Val),
        ScSpecTypeDef::Bool => TypeRef::Primitive(PrimitiveType::Bool),
        ScSpecTypeDef::Void => TypeRef::Primitive(PrimitiveType::Void),
        ScSpecTypeDef::Error => TypeRef::Primitive(PrimitiveType::Error),
        ScSpecTypeDef::U32 => TypeRef::Primitive(PrimitiveType::U32),
        ScSpecTypeDef::I32 => TypeRef::Primitive(PrimitiveType::I32),
        ScSpecTypeDef::U64 => TypeRef::Primitive(PrimitiveType::U64),
        ScSpecTypeDef::I64 => TypeRef::Primitive(PrimitiveType::I64),
        ScSpecTypeDef::Timepoint => TypeRef::Primitive(PrimitiveType::Timepoint),
        ScSpecTypeDef::Duration => TypeRef::Primitive(PrimitiveType::Duration),
        ScSpecTypeDef::U128 => TypeRef::Primitive(PrimitiveType::U128),
        ScSpecTypeDef::I128 => TypeRef::Primitive(PrimitiveType::I128),
        ScSpecTypeDef::U256 => TypeRef::Primitive(PrimitiveType::U256),
        ScSpecTypeDef::I256 => TypeRef::Primitive(PrimitiveType::I256),
        ScSpecTypeDef::Bytes => TypeRef::Primitive(PrimitiveType::Bytes),
        ScSpecTypeDef::String => TypeRef::Primitive(PrimitiveType::String),
        ScSpecTypeDef::Symbol => TypeRef::Primitive(PrimitiveType::Symbol),
        ScSpecTypeDef::Address => TypeRef::Primitive(PrimitiveType::Address),
        ScSpecTypeDef::MuxedAddress => TypeRef::Primitive(PrimitiveType::MuxedAddress),

        // ---- Composites ----
        ScSpecTypeDef::Option(inner) => TypeRef::Composite(CompositeType::Option(Box::new(
            spec_type_to_typeref(&inner.value_type, name_to_id, diagnostics)?,
        ))),
        ScSpecTypeDef::Result(inner) => TypeRef::Composite(CompositeType::Result(
            Box::new(spec_type_to_typeref(
                &inner.ok_type,
                name_to_id,
                diagnostics,
            )?),
            Box::new(spec_type_to_typeref(
                &inner.error_type,
                name_to_id,
                diagnostics,
            )?),
        )),
        ScSpecTypeDef::Vec(inner) => TypeRef::Composite(CompositeType::Vec(Box::new(
            spec_type_to_typeref(&inner.element_type, name_to_id, diagnostics)?,
        ))),
        ScSpecTypeDef::Map(inner) => TypeRef::Composite(CompositeType::Map(
            Box::new(spec_type_to_typeref(
                &inner.key_type,
                name_to_id,
                diagnostics,
            )?),
            Box::new(spec_type_to_typeref(
                &inner.value_type,
                name_to_id,
                diagnostics,
            )?),
        )),
        ScSpecTypeDef::Tuple(inner) => {
            let inner_types = inner
                .value_types
                .iter()
                .map(|t| spec_type_to_typeref(t, name_to_id, diagnostics))
                .collect::<FrontendResult<Vec<_>>>()?;
            TypeRef::Composite(CompositeType::Tuple(inner_types))
        }
        ScSpecTypeDef::BytesN(bytes_n) => TypeRef::Composite(CompositeType::BytesN(bytes_n.n)),

        // ---- User-defined ----
        //
        // If the spec references a UDT name we never saw declared, emit a
        // Warning diagnostic and fall back to `TypeRef::Unknown` rather
        // than failing the whole parse. The contract author wrote a
        // broken spec; we recover what we can.
        ScSpecTypeDef::Udt(udt) => {
            let name = stringm_to_string(&udt.name)?;
            match name_to_id.get(&name).copied() {
                Some(id) => TypeRef::UserDefined(id),
                None => {
                    diagnostics.push(
                        Diagnostic::warning(
                            MetadataDiagnosticCode::UnresolvedTypeReference { name: name.clone() },
                            String::new(),
                        )
                        .at(Location::CustomSection {
                            name: "contractspecv0".to_string(),
                        }),
                    );
                    TypeRef::Unknown(UnknownReason::NoMetadata)
                }
            }
        }
    };
    Ok(typeref)
}

// ---------------------------------------------------------------------
// Env meta + contract meta decoders
// ---------------------------------------------------------------------

/// Decode the `contractenvmetav0` custom-section bytes into [`EnvCompatibility`].
///
/// Returns `Ok(EnvCompatibility::default())` when `bytes` is empty.
/// Returns [`FrontendError::MalformedEnvMeta`] when the bytes are present
/// but cannot be decoded — the legacy decompiler swallowed this with
/// `unwrap_or_default()`, which silently produced a contract with no
/// protocol info.
pub(super) fn decode_env_meta(bytes: &[u8]) -> FrontendResult<EnvCompatibility> {
    if bytes.is_empty() {
        return Ok(EnvCompatibility::default());
    }

    let mut reader = Limited::new(Cursor::new(bytes), Limits::len(2048));
    let entries: Vec<ScEnvMetaEntry> = ScEnvMetaEntry::read_xdr_iter(&mut reader)
        .collect::<Result<_, _>>()
        .map_err(|err| FrontendError::MalformedEnvMeta(err.to_string()))?;

    let mut compat = EnvCompatibility::default();
    for entry in entries {
        let ScEnvMetaEntry::ScEnvMetaKindInterfaceVersion(interface) = entry;
        compat.protocol = Some(interface.protocol.to_string());
        compat.pre_release = Some(interface.pre_release.to_string());
    }
    Ok(compat)
}

/// Decode `contractmetav0` custom-section bytes into a key/value map.
///
/// Multiple `contractmetav0` sections legitimately exist in a contract
/// (the SDK and user code may each contribute entries). Callers
/// concatenate the bytes in declaration order before passing them here;
/// this function decodes the concatenated stream.
///
/// Returns an empty map when `bytes` is empty. If the payload cannot be
/// decoded, emits a Warning diagnostic and returns an empty map — the
/// contract metadata is just SDK version strings, so loss is recoverable.
pub(super) fn decode_contract_meta(
    bytes: &[u8],
    diagnostics: &mut Vec<Diagnostic>,
) -> FrontendResult<BTreeMap<String, String>> {
    if bytes.is_empty() {
        return Ok(BTreeMap::new());
    }

    let entries = match soroban_meta::read::parse_raw(bytes) {
        Ok(entries) => entries,
        Err(err) => {
            diagnostics.push(
                Diagnostic::warning(
                    MetadataDiagnosticCode::MalformedContractMeta {
                        reason: err.to_string(),
                    },
                    String::new(),
                )
                .at(Location::CustomSection {
                    name: "contractmetav0".to_string(),
                }),
            );
            return Ok(BTreeMap::new());
        }
    };
    let mut out = BTreeMap::<String, String>::new();
    for entry in entries {
        let ScMetaEntry::ScMetaV0(v0) = entry;
        let key = stringm_to_string(&v0.key)?;
        let val = stringm_to_string(&v0.val)?;
        out.insert(key, val);
    }
    Ok(out)
}

// ---------------------------------------------------------------------
// Custom-section helpers
// ---------------------------------------------------------------------

/// Find a single custom section by name, returning its bytes (or `None`
/// if not present). The first match wins; for sections that may legitimately
/// appear multiple times (`contractmetav0`), use [`concat_sections_named`].
pub(super) fn find_section_named<'a>(
    sections: &'a [CustomSection],
    name: &str,
) -> Option<&'a [u8]> {
    sections
        .iter()
        .find(|s| s.name == name)
        .map(|s| s.bytes.as_slice())
}

/// Concatenate the bytes of every custom section with the given name.
///
/// Used for `contractmetav0`, which may appear multiple times in a
/// well-formed contract; the legacy decompiler did the same concatenation,
/// and skipping it would silently drop entries past the first section.
pub(super) fn concat_sections_named(sections: &[CustomSection], name: &str) -> Vec<u8> {
    sections
        .iter()
        .filter(|s| s.name == name)
        .flat_map(|s| s.bytes.iter().copied())
        .collect()
}

// ---------------------------------------------------------------------
// Spec decoder — the two-pass logic
// ---------------------------------------------------------------------

/// Decode the `contractspecv0` bytes into typed function signatures and a
/// type registry.
///
/// Walks the spec entries twice:
///
/// 1. **Pass 1** assigns each user-defined-type entry a sequential
///    [`TypeId`] from a single global counter, and builds the
///    `name → TypeId` lookup. Duplicate names are a hard error.
/// 2. **Pass 2** decodes each entry's body, resolving every
///    `ScSpecTypeDef::Udt(name)` reference through the lookup. Unresolved
///    references are a hard error.
///
/// Returns the populated function map and type registry.
fn decode_spec(
    bytes: &[u8],
    diagnostics: &mut Vec<Diagnostic>,
) -> FrontendResult<(BTreeMap<String, FunctionSignature>, TypeRegistry)> {
    let entries = soroban_spec::read::parse_raw(bytes)
        .map_err(|err| FrontendError::MalformedSpec(err.to_string()))?;

    // Pass 1: allocate TypeIds for every UDT entry, build name → TypeId map.
    //
    // Duplicate names emit a Warning diagnostic and the second declaration
    // is dropped; the first declaration retains the TypeId (first-wins).
    let mut name_to_id = BTreeMap::<String, TypeId>::new();
    let mut next_id: u32 = 0;
    for entry in &entries {
        let name = match entry {
            ScSpecEntry::FunctionV0(_) => continue,
            ScSpecEntry::UdtStructV0(s) => stringm_to_string(&s.name)?,
            ScSpecEntry::UdtUnionV0(u) => stringm_to_string(&u.name)?,
            ScSpecEntry::UdtEnumV0(e) => stringm_to_string(&e.name)?,
            ScSpecEntry::UdtErrorEnumV0(e) => stringm_to_string(&e.name)?,
            ScSpecEntry::EventV0(e) => symbol_to_string(&e.name)?,
        };
        if name_to_id.contains_key(&name) {
            diagnostics.push(
                Diagnostic::warning(
                    MetadataDiagnosticCode::DuplicateTypeName { name: name.clone() },
                    String::new(),
                )
                .at(Location::CustomSection {
                    name: "contractspecv0".to_string(),
                }),
            );
            continue;
        }
        // No real contract has more than a handful of types; this assertion
        // exists purely to surface a u32 overflow as a panic in dev rather
        // than silently re-using a TypeId.
        debug_assert!(
            next_id < u32::MAX,
            "TypeId counter overflow at u32::MAX user-defined types"
        );
        name_to_id.insert(name, TypeId::from_index(next_id));
        next_id = next_id.saturating_add(1);
    }

    // Pass 2: decode each entry's body, resolving Udt references through
    // the map. Duplicates were diagnosed in pass 1 (or are diagnosed
    // below for functions) — pass 2 must skip second-and-later
    // occurrences so the registry does not collect ghost entries with
    // colliding TypeIds. We track UDT names we've already processed in
    // `processed_udts`.
    let mut functions = BTreeMap::<String, FunctionSignature>::new();
    let mut types = TypeRegistry::default();
    let mut processed_udts: BTreeSet<String> = BTreeSet::new();

    for entry in entries {
        match entry {
            ScSpecEntry::FunctionV0(f) => {
                let name = symbol_to_string(&f.name)?;
                let inputs = f
                    .inputs
                    .iter()
                    .map(|input| {
                        Ok(FunctionParam {
                            name: stringm_to_string(&input.name)?,
                            ty: spec_type_to_typeref(&input.type_, &name_to_id, diagnostics)?,
                        })
                    })
                    .collect::<FrontendResult<Vec<_>>>()?;
                let outputs = f
                    .outputs
                    .iter()
                    .map(|t| spec_type_to_typeref(t, &name_to_id, diagnostics))
                    .collect::<FrontendResult<Vec<_>>>()?;
                let signature = FunctionSignature {
                    name: name.clone(),
                    inputs,
                    outputs,
                };
                // First-wins on duplicate function names. The first
                // declaration is already in `functions`; emit a Warning
                // for the duplicate and skip the rebind.
                use std::collections::btree_map::Entry;
                match functions.entry(name.clone()) {
                    Entry::Vacant(slot) => {
                        slot.insert(signature);
                    }
                    Entry::Occupied(_) => {
                        diagnostics.push(
                            Diagnostic::warning(
                                MetadataDiagnosticCode::DuplicateFunctionName { name },
                                String::new(),
                            )
                            .at(Location::CustomSection {
                                name: "contractspecv0".to_string(),
                            }),
                        );
                    }
                }
            }

            ScSpecEntry::UdtStructV0(s) => {
                let name = stringm_to_string(&s.name)?;
                if !processed_udts.insert(name.clone()) {
                    continue;
                }
                let id = name_to_id.get(&name).copied().expect(
                    "pass 1 invariant: every non-duplicate name has a TypeId in name_to_id",
                );
                let fields = s
                    .fields
                    .iter()
                    .map(|f| {
                        Ok(StructField {
                            name: stringm_to_string(&f.name)?,
                            ty: spec_type_to_typeref(&f.type_, &name_to_id, diagnostics)?,
                        })
                    })
                    .collect::<FrontendResult<Vec<_>>>()?;
                types.structs.push(StructDef { id, name, fields });
            }

            ScSpecEntry::UdtUnionV0(u) => {
                let name = stringm_to_string(&u.name)?;
                if !processed_udts.insert(name.clone()) {
                    continue;
                }
                let id = name_to_id.get(&name).copied().expect(
                    "pass 1 invariant: every non-duplicate name has a TypeId in name_to_id",
                );
                let cases = u
                    .cases
                    .iter()
                    .map(|case| match case {
                        ScSpecUdtUnionCaseV0::VoidV0(v) => Ok(UnionCase {
                            name: stringm_to_string(&v.name)?,
                            fields: Vec::new(),
                        }),
                        ScSpecUdtUnionCaseV0::TupleV0(t) => {
                            let fields = t
                                .type_
                                .iter()
                                .map(|ty| spec_type_to_typeref(ty, &name_to_id, diagnostics))
                                .collect::<FrontendResult<Vec<_>>>()?;
                            Ok(UnionCase {
                                name: stringm_to_string(&t.name)?,
                                fields,
                            })
                        }
                    })
                    .collect::<FrontendResult<Vec<_>>>()?;
                types.unions.push(UnionDef { id, name, cases });
            }

            ScSpecEntry::UdtEnumV0(e) => {
                let name = stringm_to_string(&e.name)?;
                if !processed_udts.insert(name.clone()) {
                    continue;
                }
                let id = name_to_id.get(&name).copied().expect(
                    "pass 1 invariant: every non-duplicate name has a TypeId in name_to_id",
                );
                let cases = e
                    .cases
                    .iter()
                    .map(|case| {
                        Ok(EnumCase {
                            name: stringm_to_string(&case.name)?,
                            value: case.value,
                        })
                    })
                    .collect::<FrontendResult<Vec<_>>>()?;
                types.enums.push(EnumDef { id, name, cases });
            }

            ScSpecEntry::UdtErrorEnumV0(e) => {
                let name = stringm_to_string(&e.name)?;
                if !processed_udts.insert(name.clone()) {
                    continue;
                }
                let id = name_to_id.get(&name).copied().expect(
                    "pass 1 invariant: every non-duplicate name has a TypeId in name_to_id",
                );
                let cases = e
                    .cases
                    .iter()
                    .map(|case| {
                        Ok(EnumCase {
                            name: stringm_to_string(&case.name)?,
                            value: case.value,
                        })
                    })
                    .collect::<FrontendResult<Vec<_>>>()?;
                types.errors.push(EnumDef { id, name, cases });
            }

            ScSpecEntry::EventV0(e) => {
                let name = symbol_to_string(&e.name)?;
                if !processed_udts.insert(name.clone()) {
                    continue;
                }
                let id = name_to_id.get(&name).copied().expect(
                    "pass 1 invariant: every non-duplicate name has a TypeId in name_to_id",
                );
                let prefix_topics = e
                    .prefix_topics
                    .iter()
                    .map(symbol_to_string)
                    .collect::<FrontendResult<Vec<_>>>()?;
                let params = e
                    .params
                    .iter()
                    .map(|param| {
                        Ok(EventParam {
                            name: stringm_to_string(&param.name)?,
                            ty: spec_type_to_typeref(&param.type_, &name_to_id, diagnostics)?,
                            location: match param.location {
                                ScSpecEventParamLocationV0::Data => EventParamLocation::Data,
                                ScSpecEventParamLocationV0::TopicList => EventParamLocation::Topic,
                            },
                        })
                    })
                    .collect::<FrontendResult<Vec<_>>>()?;
                types.events.push(EventDef {
                    id,
                    name,
                    prefix_topics,
                    params,
                    data_format: e.data_format.to_string(),
                });
            }
        }
    }

    Ok((functions, types))
}

// ---------------------------------------------------------------------
// Top-level: decode_metadata
// ---------------------------------------------------------------------

/// Decode the three Soroban custom sections from a parsed module's
/// custom-section list, accumulating non-fatal warnings into
/// `diagnostics`.
///
/// Returns `Ok(None)` for generic WASM (no `contractspecv0` section).
/// Returns `Ok(Some(SorobanFacts { ... }))` when the spec is present
/// and decoded — possibly with degraded fidelity, in which case the
/// degradations are recorded in `diagnostics`. Errors only when the
/// spec section itself is malformed beyond recovery.
pub(crate) fn decode_metadata(
    sections: &[CustomSection],
    diagnostics: &mut Vec<Diagnostic>,
) -> FrontendResult<Option<SorobanFacts>> {
    let Some(spec_bytes) = find_section_named(sections, "contractspecv0") else {
        // Not a Soroban contract — produce no metadata, do not error.
        return Ok(None);
    };

    let (functions, types) = decode_spec(spec_bytes, diagnostics)?;

    // contractenvmetav0: at most one section.
    let env_meta = match find_section_named(sections, "contractenvmetav0") {
        Some(bytes) => decode_env_meta(bytes)?,
        None => EnvCompatibility::default(),
    };

    // contractmetav0: multiple sections legitimately exist; concatenate
    // their bytes in declaration order before decoding.
    let contract_meta_bytes = concat_sections_named(sections, "contractmetav0");
    let contract_meta = decode_contract_meta(&contract_meta_bytes, diagnostics)?;

    Ok(Some(SorobanFacts {
        functions,
        types,
        contract_meta,
        env_meta,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::Severity;
    use std::str::FromStr;
    use stellar_xdr::curr::{ScSpecTypeUdt, StringM};

    #[test]
    fn unresolved_udt_emits_warning_and_returns_unknown_placeholder() {
        let mut diags: Vec<Diagnostic> = Vec::new();
        let name_to_id: BTreeMap<String, TypeId> = BTreeMap::new();
        let udt = ScSpecTypeDef::Udt(ScSpecTypeUdt {
            name: StringM::<60>::from_str("MissingType").expect("valid identifier"),
        });

        let typeref = spec_type_to_typeref(&udt, &name_to_id, &mut diags)
            .expect("returns Ok with placeholder, not Err");

        assert!(
            matches!(typeref, TypeRef::Unknown(UnknownReason::NoMetadata)),
            "expected TypeRef::Unknown(NoMetadata); got {typeref:?}"
        );
        assert_eq!(diags.len(), 1, "exactly one diagnostic emitted");
        assert_eq!(diags[0].severity, Severity::Warning);
        assert!(matches!(
            &diags[0].code,
            sordec_common::DiagnosticCode::Metadata(
                MetadataDiagnosticCode::UnresolvedTypeReference { name }
            ) if name == "MissingType"
        ));
        assert!(matches!(
            &diags[0].location,
            Some(Location::CustomSection { name }) if name == "contractspecv0"
        ));
    }

    #[test]
    fn malformed_contract_meta_bytes_emit_warning_and_return_empty_map() {
        let mut diags: Vec<Diagnostic> = Vec::new();
        // Garbage bytes that the soroban_meta XDR decoder will reject.
        let garbage = vec![0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8];

        let result = decode_contract_meta(&garbage, &mut diags).expect("returns Ok with empty map");

        assert!(result.is_empty(), "fell back to empty map; got {result:?}");
        assert_eq!(diags.len(), 1, "exactly one diagnostic emitted");
        assert_eq!(diags[0].severity, Severity::Warning);
        assert!(matches!(
            &diags[0].code,
            sordec_common::DiagnosticCode::Metadata(
                MetadataDiagnosticCode::MalformedContractMeta { .. }
            )
        ));
        assert!(matches!(
            &diags[0].location,
            Some(Location::CustomSection { name }) if name == "contractmetav0"
        ));
    }

    #[test]
    fn empty_contract_meta_bytes_emit_no_diagnostic() {
        let mut diags: Vec<Diagnostic> = Vec::new();
        let result = decode_contract_meta(&[], &mut diags).expect("returns Ok");
        assert!(result.is_empty());
        assert!(
            diags.is_empty(),
            "empty contractmetav0 is legal — no diagnostic; got {diags:?}"
        );
    }
}
