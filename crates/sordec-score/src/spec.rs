//! Decoding the contract's declared ABI from its spec-XDR entries.
//!
//! [`crate::glue`] harvests the SDK-generated `spec_xdr_*` byte strings out of
//! expanded source; this module turns them into the same keyed map the
//! interface category already scores — `"fn transfer"` → a normalized
//! signature, `"type DataKey"` → a normalized shape. Everything downstream
//! (`simil::prf`, the diff notes) is unchanged; only where the map comes from
//! differs.
//!
//! Reading the ABI here rather than from `#[contractimpl]` / `#[contracttype]`
//! is what lets the interface category survive macro expansion at all —
//! expansion consumes those attributes, and the spec section is the ground
//! truth they were only ever a proxy for.
//!
//! ## Doc strings are excluded — deliberately
//!
//! Spec entries carry the author's doc comments, and they nest: on the entry
//! itself, on each function input, and on each struct field and union/enum
//! case. A reconstruction with a byte-correct ABI and no doc comments is
//! *interface-correct*, so none of them are compared. Measured: attestation
//! scores 0 of 7 on raw bytes purely for missing docs, and 7 of 7 once they
//! are excluded.
//!
//! This is the same class of decision as excluding source-level parameter
//! names (`crate::interface`), and made for the same reason: compare the
//! interface, not its presentation. Parameter names in the *spec* are a
//! different matter and are kept — unlike source names they are real,
//! recoverable ABI, carried in the binary itself.
//!
//! Doc comments are recoverable from the spec section, so emitting them is a
//! genuine fidelity win for the backend. It is simply not this category's
//! measurement.

use std::collections::BTreeMap;
use std::io::Cursor;

use stellar_xdr::curr::{
    Limited, Limits, ReadXdr, ScSpecEntry, ScSpecEventParamLocationV0, ScSpecTypeDef,
    ScSpecUdtUnionCaseV0,
};

/// Entry name → its raw spec-XDR bytes, as harvested by [`crate::glue`].
pub(crate) type SpecMap = BTreeMap<String, Vec<u8>>;

/// Upper bound for decoding one spec entry. Entries are small (the largest in
/// the corpus is a few hundred bytes); the cap just keeps a malformed length
/// prefix from driving an unbounded allocation.
const DECODE_LIMIT: usize = 64 * 1024;

/// Decode a harvested spec map into the interface category's keyed ABI map.
///
/// Entries that fail to decode are skipped rather than fatal: a spec we cannot
/// read is a measurement gap, not a scoring failure, and dropping it is
/// visible as a recall miss rather than a panic.
pub(crate) fn abi(spec: &SpecMap, names: bool) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for bytes in spec.values() {
        let Some(entry) = decode(bytes) else {
            continue;
        };
        let (key, value) = render(&entry, names);
        map.insert(key, value);
    }
    map
}

/// The key a user-defined type is compared under.
///
/// Normally its declared name: two contracts that declare `DataKey`
/// differently should not be credited with agreeing. But a type's name
/// lives only in `contractspecv0`, and a module stripped of that
/// section records only its *shape* — a struct's field names and types
/// in the key table its derived conversion unpacks by, a union's
/// variant names in its converter's switch arms. A reconstruction can
/// recover all of that and still have to invent the type's name.
///
/// So where the module declared no ABI, the shape is the key. Two types
/// with the same shape then compare equal whatever they are called,
/// which is the most the module can be asked to support.
fn type_key(name: &str, shape: &str, names: bool) -> String {
    if names {
        format!("type {name}")
    } else {
        format!("type {shape}")
    }
}

/// Decode one spec entry, or `None` if the bytes are not a readable entry.
fn decode(bytes: &[u8]) -> Option<ScSpecEntry> {
    let mut reader = Limited::new(Cursor::new(bytes), Limits::len(DECODE_LIMIT));
    ScSpecEntry::read_xdr(&mut reader).ok()
}

/// The keyed name and normalized value for one spec entry.
///
/// Keys mirror the attribute-based extractor's namespacing (`"fn name"` /
/// `"type Name"`) so both bases produce comparable maps.
///
/// Deliberately exhaustive with no catch-all: a spec entry kind added by a
/// future `stellar-xdr` should be a compile error demanding a decision, not a
/// silently dropped item that reads as a recall miss.
fn render(entry: &ScSpecEntry, names: bool) -> (String, String) {
    match entry {
        ScSpecEntry::FunctionV0(f) => {
            let params: Vec<String> = f
                .inputs
                .iter()
                .map(|input| {
                    // A parameter's name lives only in `contractspecv0`.
                    // Where the module under test carried none, it is
                    // not a thing a reconstruction could have recovered.
                    if names {
                        format!("{}:{}", input.name.to_utf8_string_lossy(), ty(&input.type_))
                    } else {
                        ty(&input.type_)
                    }
                })
                .collect();
            let outputs: Vec<String> = f.outputs.iter().map(ty).collect();
            let ret = match outputs.len() {
                0 => "()".to_owned(),
                1 => outputs[0].clone(),
                _ => format!("({})", outputs.join(",")),
            };
            (
                format!("fn {}", f.name.to_utf8_string_lossy()),
                format!("({}) -> {ret}", params.join(",")),
            )
        }
        ScSpecEntry::UdtStructV0(s) => {
            let fields: Vec<String> = s
                .fields
                .iter()
                .map(|field| format!("{}:{}", field.name.to_utf8_string_lossy(), ty(&field.type_)))
                .collect();
            let shape = format!("struct{{{}}}", fields.join(","));
            (
                type_key(&s.name.to_utf8_string_lossy(), &shape, names),
                shape,
            )
        }
        ScSpecEntry::UdtUnionV0(u) => {
            let cases: Vec<String> = u.cases.iter().map(union_case).collect();
            let shape = format!("union{{{}}}", cases.join(","));
            (type_key(&u.name.to_utf8_string_lossy(), &shape, names), shape)
        }
        ScSpecEntry::UdtEnumV0(e) => {
            let cases: Vec<String> = e
                .cases
                .iter()
                .map(|case| format!("{}={}", case.name.to_utf8_string_lossy(), case.value))
                .collect();
            let shape = format!("enum{{{}}}", cases.join(","));
            (type_key(&e.name.to_utf8_string_lossy(), &shape, names), shape)
        }
        ScSpecEntry::UdtErrorEnumV0(e) => {
            let cases: Vec<String> = e
                .cases
                .iter()
                .map(|case| format!("{}={}", case.name.to_utf8_string_lossy(), case.value))
                .collect();
            (
                format!("type {}", e.name.to_utf8_string_lossy()),
                format!("error{{{}}}", cases.join(",")),
            )
        }
        ScSpecEntry::EventV0(e) => {
            // Events are part of the declared surface, and the attribute-based
            // extractor counts `#[contractevent]` too — dropping them here
            // would make the two bases disagree *and* would hide the emitter's
            // event over-declaration (token-v23 declares 8 against the
            // original's 1), which is precisely what precision should catch.
            // The semantic category owns event *publications*; this is the
            // event's declared shape.
            let topics: Vec<String> = e
                .prefix_topics
                .iter()
                .map(|topic| topic.0.to_utf8_string_lossy())
                .collect();
            let params: Vec<String> = e
                .params
                .iter()
                .map(|param| {
                    let location = match param.location {
                        ScSpecEventParamLocationV0::Data => "data",
                        ScSpecEventParamLocationV0::TopicList => "topic",
                    };
                    format!(
                        "{}:{}@{location}",
                        param.name.to_utf8_string_lossy(),
                        ty(&param.type_)
                    )
                })
                .collect();
            (
                format!("type {}", e.name.to_utf8_string_lossy()),
                format!("event{{topics[{}],{}}}", topics.join(","), params.join(",")),
            )
        }
    }
}

/// One union case: a unit case, or a tuple case with its payload types.
fn union_case(case: &ScSpecUdtUnionCaseV0) -> String {
    match case {
        ScSpecUdtUnionCaseV0::VoidV0(v) => v.name.to_utf8_string_lossy(),
        ScSpecUdtUnionCaseV0::TupleV0(t) => {
            let payload: Vec<String> = t.type_.iter().map(ty).collect();
            format!("{}({})", t.name.to_utf8_string_lossy(), payload.join(","))
        }
    }
}

/// A canonical, comparable rendering of a spec type.
///
/// Mirrors `canon::normalize_type`'s shape so spec-derived and source-derived
/// values read alike in a report.
fn ty(def: &ScSpecTypeDef) -> String {
    match def {
        ScSpecTypeDef::Val => "Val".into(),
        ScSpecTypeDef::Bool => "bool".into(),
        ScSpecTypeDef::Void => "()".into(),
        ScSpecTypeDef::Error => "Error".into(),
        ScSpecTypeDef::U32 => "u32".into(),
        ScSpecTypeDef::I32 => "i32".into(),
        ScSpecTypeDef::U64 => "u64".into(),
        ScSpecTypeDef::I64 => "i64".into(),
        ScSpecTypeDef::Timepoint => "Timepoint".into(),
        ScSpecTypeDef::Duration => "Duration".into(),
        ScSpecTypeDef::U128 => "u128".into(),
        ScSpecTypeDef::I128 => "i128".into(),
        ScSpecTypeDef::U256 => "U256".into(),
        ScSpecTypeDef::I256 => "I256".into(),
        ScSpecTypeDef::Bytes => "Bytes".into(),
        ScSpecTypeDef::String => "String".into(),
        ScSpecTypeDef::Symbol => "Symbol".into(),
        ScSpecTypeDef::Address => "Address".into(),
        ScSpecTypeDef::MuxedAddress => "MuxedAddress".into(),
        ScSpecTypeDef::Option(inner) => format!("Option<{}>", ty(&inner.value_type)),
        ScSpecTypeDef::Result(inner) => {
            format!("Result<{},{}>", ty(&inner.ok_type), ty(&inner.error_type))
        }
        ScSpecTypeDef::Vec(inner) => format!("Vec<{}>", ty(&inner.element_type)),
        ScSpecTypeDef::Map(inner) => {
            format!("Map<{},{}>", ty(&inner.key_type), ty(&inner.value_type))
        }
        ScSpecTypeDef::Tuple(inner) => {
            let parts: Vec<String> = inner.value_types.iter().map(ty).collect();
            format!("({})", parts.join(","))
        }
        ScSpecTypeDef::BytesN(inner) => format!("BytesN<{}>", inner.n),
        ScSpecTypeDef::Udt(inner) => inner.name.to_utf8_string_lossy(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::{
        ScSpecFunctionInputV0, ScSpecFunctionV0, ScSpecUdtEnumCaseV0, ScSpecUdtEnumV0,
        ScSpecUdtStructFieldV0, ScSpecUdtStructV0, StringM, WriteXdr,
    };

    fn s<const N: u32>(text: &str) -> StringM<N> {
        text.try_into().expect("fits")
    }

    fn encode(entry: &ScSpecEntry) -> Vec<u8> {
        entry
            .to_xdr(Limits::len(DECODE_LIMIT))
            .expect("entry encodes")
    }

    /// A one-parameter function entry, with a doc string that must not be
    /// compared and a parameter type that must be.
    fn function(doc: &str, param_doc: &str, param_ty: ScSpecTypeDef) -> ScSpecEntry {
        ScSpecEntry::FunctionV0(ScSpecFunctionV0 {
            doc: s(doc),
            name: "transfer".try_into().expect("symbol"),
            inputs: vec![ScSpecFunctionInputV0 {
                doc: s(param_doc),
                name: s("to"),
                type_: param_ty,
            }]
            .try_into()
            .expect("inputs"),
            outputs: vec![].try_into().expect("outputs"),
        })
    }

    fn abi_of(entries: &[(&str, ScSpecEntry)]) -> BTreeMap<String, String> {
        let map: SpecMap = entries
            .iter()
            .map(|(key, entry)| ((*key).to_owned(), encode(entry)))
            .collect();
        abi(&map, true)
    }

    #[test]
    fn a_function_renders_its_signature() {
        let out = abi_of(&[("transfer", function("", "", ScSpecTypeDef::Address))]);
        assert_eq!(
            out.get("fn transfer").map(String::as_str),
            Some("(to:Address) -> ()")
        );
    }

    #[test]
    fn doc_strings_do_not_affect_the_comparison() {
        // THE load-bearing case (score-2.0.0 T10): attestation scores 0 of 7
        // on raw bytes purely because its entrypoints carry doc comments our
        // reconstruction does not emit. Docs are excluded at *every* level —
        // here the entry doc and the per-input doc.
        let documented = abi_of(&[(
            "transfer",
            function(
                "Move tokens between accounts. Traps on insufficient balance.",
                "The recipient address.",
                ScSpecTypeDef::Address,
            ),
        )]);
        let bare = abi_of(&[("transfer", function("", "", ScSpecTypeDef::Address))]);
        assert_eq!(documented, bare, "docs are presentation, not interface");
    }

    #[test]
    fn nested_case_docs_do_not_affect_the_comparison() {
        // The case raw byte-stripping missed: attestation's `type Error` still
        // differed after removing the entry-level doc, because each *variant*
        // carries its own.
        let enum_with = |case_doc: &str| {
            ScSpecEntry::UdtEnumV0(ScSpecUdtEnumV0 {
                doc: s(""),
                lib: s(""),
                name: s("Error"),
                cases: vec![ScSpecUdtEnumCaseV0 {
                    doc: s(case_doc),
                    name: s("EmptyMessage"),
                    value: 1,
                }]
                .try_into()
                .expect("cases"),
            })
        };
        let documented = abi_of(&[("Error", enum_with("The message to attest was empty."))]);
        let bare = abi_of(&[("Error", enum_with(""))]);
        assert_eq!(documented, bare);
        assert_eq!(
            bare.get("type Error").map(String::as_str),
            Some("enum{EmptyMessage=1}")
        );
    }

    #[test]
    fn a_changed_parameter_type_is_a_real_difference() {
        // The other half of the guard: doc-insensitivity must not blunt the
        // metric to genuine ABI changes.
        let address = abi_of(&[("transfer", function("", "", ScSpecTypeDef::Address))]);
        let u32_param = abi_of(&[("transfer", function("", "", ScSpecTypeDef::U32))]);
        assert_ne!(address, u32_param);
    }

    #[test]
    fn struct_fields_render_in_declaration_order() {
        let entry = ScSpecEntry::UdtStructV0(ScSpecUdtStructV0 {
            doc: s(""),
            lib: s(""),
            name: s("AllowanceValue"),
            fields: vec![
                ScSpecUdtStructFieldV0 {
                    doc: s("ignored"),
                    name: s("amount"),
                    type_: ScSpecTypeDef::I128,
                },
                ScSpecUdtStructFieldV0 {
                    doc: s(""),
                    name: s("live_until_ledger"),
                    type_: ScSpecTypeDef::U32,
                },
            ]
            .try_into()
            .expect("fields"),
        });
        let out = abi_of(&[("AllowanceValue", entry)]);
        assert_eq!(
            out.get("type AllowanceValue").map(String::as_str),
            Some("struct{amount:i128,live_until_ledger:u32}")
        );
    }

    #[test]
    fn nested_types_render_recursively() {
        let vec_of_addr = ScSpecTypeDef::Vec(Box::new(stellar_xdr::curr::ScSpecTypeVec {
            element_type: Box::new(ScSpecTypeDef::Address),
        }));
        let out = abi_of(&[("transfer", function("", "", vec_of_addr))]);
        assert_eq!(
            out.get("fn transfer").map(String::as_str),
            Some("(to:Vec<Address>) -> ()")
        );
    }

    #[test]
    fn undecodable_bytes_are_skipped_not_fatal() {
        let mut map = SpecMap::new();
        map.insert("junk".to_owned(), vec![0xff, 0xff, 0xff, 0xff]);
        map.insert(
            "transfer".to_owned(),
            encode(&function("", "", ScSpecTypeDef::Address)),
        );
        let out = abi(&map, true);
        assert_eq!(out.len(), 1, "the readable entry still scores: {out:?}");
        assert!(out.contains_key("fn transfer"));
    }
}
