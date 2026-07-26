//! Interface category: the contract's public ABI surface.
//!
//! Two kinds of ABI item, extracted from `syn` and pooled into one keyed
//! set, then scored by exact-match F1:
//!
//! - **entrypoints** — every method in a `#[contractimpl]` impl (both the
//!   inherent `impl Token` and any `impl TokenInterface for Token`), keyed
//!   by name, valued by its normalized signature (parameter types → return
//!   type). Trait-impl methods carry no `pub`, so visibility is *not* a
//!   filter — presence in a `#[contractimpl]` block is what makes a method
//!   an entrypoint.
//! - **type shapes** — every `#[contracttype]` / `#[contracterror]` /
//!   `#[contractevent]` struct or enum, keyed by name, valued by its
//!   normalized field/variant shape.
//!
//! An item is *correct* when it appears on both sides under the same key
//! with an equal normalized value. Precision = correct / reconstructed,
//! recall = correct / original, and the sub-score is their F1 — so a
//! missing entrypoint hurts recall, an invented one hurts precision, and a
//! wrong signature hurts both. Parameter names are intentionally excluded
//! from the signature value: types are the reliable interface identity, and
//! a `e`-vs-`env` receiver name should not cost score.
//!
//! ## Deferred to Phase 4
//!
//! This category compares two Rust sources symmetrically. When a `.wasm` is
//! also available, the binary's declared `contractspecv0` is the *ground
//! truth* interface, and the reconstruction could be scored against it
//! directly (via the frontend's `soroban_spec` parse → `FunctionSignature` /
//! `TypeRegistry` path). That `--spec <wasm>` anchor is left as a seam so the
//! Phase-3 scorer stays a pure, pipeline-decoupled source-to-source tool; it
//! wires in with the Phase-4 Rust emitter, whose output it will grade.

use std::collections::BTreeMap;

use syn::{FnArg, Fields, ImplItem, Item, ReturnType};

use crate::canon;
use crate::report::CategoryScore;
use crate::simil;
use crate::spec;

/// Score the interface category.
///
/// `spec` carries the two sides' harvested spec-XDR entries when scoring on
/// the macro-expanded basis. It is the ABI ground truth and takes precedence:
/// expansion consumes the `#[contractimpl]` / `#[contracttype]` attributes
/// this module's own extractor keys on, so without it the expanded basis
/// yields nothing to compare. `None` — the pre-expansion basis — falls back to
/// the attribute extractor.
pub(crate) fn evaluate(
    reconstructed: &syn::File,
    original: &syn::File,
    spec: Option<(&spec::SpecMap, &spec::SpecMap)>,
) -> CategoryScore {
    let (recon, orig) = match spec {
        Some((recon_spec, orig_spec)) => (spec::abi(recon_spec), spec::abi(orig_spec)),
        None => (extract(reconstructed), extract(original)),
    };

    let Some(outcome) = f1(&recon, &orig) else {
        return CategoryScore::unchecked("no ABI items on either side — nothing to measure");
    };

    let mut score = CategoryScore::checked(outcome.f1).with_note(format!(
        "precision={} recall={} ({} original ABI items, {} reconstructed)",
        simil::render_ratio(outcome.precision),
        simil::render_ratio(outcome.recall),
        orig.len(),
        recon.len()
    ));
    if let Some(note) = diff_note("missing", &orig, &recon) {
        score = score.with_note(note);
    }
    if let Some(note) = diff_note("extra", &recon, &orig) {
        score = score.with_note(note);
    }
    score
}

/// The ABI surface of one source: a keyed map from a namespaced item key
/// (`"fn transfer"`, `"type DataKey"`) to its normalized value.
fn extract(file: &syn::File) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for item in &file.items {
        collect_item(item, &mut map);
    }
    map
}

fn collect_item(item: &Item, map: &mut BTreeMap<String, String>) {
    match item {
        Item::Impl(item_impl) if canon::attr_named(&item_impl.attrs, "contractimpl") => {
            for impl_item in &item_impl.items {
                if let ImplItem::Fn(method) = impl_item {
                    map.insert(
                        format!("fn {}", method.sig.ident),
                        signature(&method.sig),
                    );
                }
            }
        }
        Item::Struct(item_struct) if is_abi_type(&item_struct.attrs) => {
            map.insert(
                format!("type {}", item_struct.ident),
                struct_shape(&item_struct.fields),
            );
        }
        Item::Enum(item_enum) if is_abi_type(&item_enum.attrs) => {
            map.insert(format!("type {}", item_enum.ident), enum_shape(item_enum));
        }
        // Recurse into inline modules the loader kept.
        Item::Mod(item_mod) => {
            if let Some((_, items)) = &item_mod.content {
                for nested in items {
                    collect_item(nested, map);
                }
            }
        }
        _ => {}
    }
}

/// Whether an item's attributes mark it as an ABI-visible type.
fn is_abi_type(attrs: &[syn::Attribute]) -> bool {
    canon::attr_named(attrs, "contracttype")
        || canon::attr_named(attrs, "contracterror")
        || canon::attr_named(attrs, "contractevent")
}

/// Normalized signature: `(param_type, …) -> return_type`. Parameter names
/// are excluded; a `&self`/`self` receiver renders as `self`.
fn signature(sig: &syn::Signature) -> String {
    let params: Vec<String> = sig
        .inputs
        .iter()
        .map(|arg| match arg {
            FnArg::Receiver(_) => "self".to_string(),
            FnArg::Typed(pat_type) => canon::normalize_type(&pat_type.ty),
        })
        .collect();
    let ret = match &sig.output {
        ReturnType::Default => "()".to_string(),
        ReturnType::Type(_, ty) => canon::normalize_type(ty),
    };
    format!("({}) -> {ret}", params.join(","))
}

/// Normalized struct shape in declaration order (field order is ABI-significant).
fn struct_shape(fields: &Fields) -> String {
    format!("struct{{{}}}", field_list(fields))
}

/// Normalized enum shape in declaration order.
fn enum_shape(item_enum: &syn::ItemEnum) -> String {
    let variants: Vec<String> = item_enum
        .variants
        .iter()
        .map(|variant| format!("{}{}", variant.ident, variant_payload(&variant.fields)))
        .collect();
    format!("enum{{{}}}", variants.join(","))
}

/// The payload of an enum variant: `(types)`, `{name:type,…}`, or empty.
fn variant_payload(fields: &Fields) -> String {
    match fields {
        Fields::Unit => String::new(),
        Fields::Unnamed(_) | Fields::Named(_) => {
            let list = field_list(fields);
            match fields {
                Fields::Named(_) => format!("{{{list}}}"),
                _ => format!("({list})"),
            }
        }
    }
}

/// A comma-joined `name:type` (named) or `type` (unnamed) field list.
fn field_list(fields: &Fields) -> String {
    let parts: Vec<String> = fields
        .iter()
        .map(|field| match &field.ident {
            Some(ident) => format!("{ident}:{}", canon::normalize_type(&field.ty)),
            None => canon::normalize_type(&field.ty),
        })
        .collect();
    parts.join(",")
}

/// Exact-match F1: an item is correct when both sides carry the same key
/// with an equal value.
///
/// `None` when neither side declared any ABI item — an extraction that
/// found nothing is unmeasurable, not perfect (see [`simil::prf`]).
fn f1(recon: &BTreeMap<String, String>, orig: &BTreeMap<String, String>) -> Option<simil::Prf> {
    let correct = orig
        .iter()
        .filter(|(key, value)| recon.get(*key) == Some(*value))
        .count();
    simil::prf(correct, recon.len(), orig.len())
}

/// A note listing keys in `from` whose value is not exactly reproduced in
/// `other`, capped so the report stays readable.
fn diff_note(
    label: &str,
    from: &BTreeMap<String, String>,
    other: &BTreeMap<String, String>,
) -> Option<String> {
    let mut names: Vec<&str> = from
        .iter()
        .filter(|(key, value)| other.get(*key) != Some(*value))
        .map(|(key, _)| key.as_str())
        .collect();
    if names.is_empty() {
        return None;
    }
    names.sort_unstable();
    const CAP: usize = 8;
    let shown = names.len().min(CAP);
    let mut list = names[..shown].join(", ");
    if names.len() > CAP {
        list.push_str(&format!(", … (+{})", names.len() - CAP));
    }
    Some(format!("{label}: {list}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(src: &str) -> syn::File {
        syn::parse_str(src).expect("source parses")
    }

    const CONTRACT: &str = r#"
        #[contract]
        pub struct Token;
        #[contractimpl]
        impl Token {
            pub fn mint(e: Env, to: Address, amount: i128) {}
            pub fn balance(e: Env, id: Address) -> i128 { 0 }
        }
        #[contracttype]
        pub enum DataKey { Balance(Address), Admin }
    "#;

    #[test]
    fn identical_interface_scores_one() {
        let f = file(CONTRACT);
        let score = evaluate(&f, &f, None);
        assert!((score.score - 1.0).abs() < 1e-9);
    }

    #[test]
    fn qualifier_differences_do_not_cost_score() {
        // Same ABI, different import paths — must still be perfect.
        let recon = file(
            r#"
            #[contractimpl]
            impl Token {
                pub fn mint(e: soroban_sdk::Env, to: soroban_sdk::Address, amount: i128) {}
            }
            "#,
        );
        let orig = file(
            r#"
            #[contractimpl]
            impl Token {
                pub fn mint(e: Env, to: Address, amount: i128) {}
            }
            "#,
        );
        assert!((evaluate(&recon, &orig, None).score - 1.0).abs() < 1e-9);
    }

    #[test]
    fn a_missing_entrypoint_lowers_recall() {
        let orig = file(CONTRACT);
        let recon = file(
            r#"
            #[contractimpl]
            impl Token {
                pub fn mint(e: Env, to: Address, amount: i128) {}
            }
            #[contracttype]
            pub enum DataKey { Balance(Address), Admin }
            "#,
        );
        // Dropped `balance` (1 of 3 ABI items) → score below 1.
        let score = evaluate(&recon, &orig, None);
        assert!(score.score < 1.0, "score was {}", score.score);
    }

    #[test]
    fn a_changed_signature_is_penalized() {
        let orig = file(CONTRACT);
        let recon = file(
            r#"
            #[contractimpl]
            impl Token {
                pub fn mint(e: Env, to: Address, amount: u64) {}
                pub fn balance(e: Env, id: Address) -> i128 { 0 }
            }
            #[contracttype]
            pub enum DataKey { Balance(Address), Admin }
            "#,
        );
        // `mint`'s amount type changed i128 → u64: wrong sig hurts both
        // precision and recall.
        assert!(evaluate(&recon, &orig, None).score < 1.0);
    }

    #[test]
    fn empty_interfaces_are_unchecked_not_perfect() {
        // No `#[contractimpl]`/`#[contracttype]` on either side: the
        // extractor found nothing, so there is nothing to score. Reporting
        // 1.0 here is the false perfect T8 removes — it is exactly what a
        // macro-expanded input (which consumes those attributes) would hit.
        let f = file("pub fn helper() {}");
        let score = evaluate(&f, &f, None);
        assert!(!score.checked, "a 0-item extraction must not be checked");
        assert_ne!(score.score, 1.0);
    }

    #[test]
    fn nothing_reconstructed_does_not_report_perfect_precision() {
        // The live bug from docs/benchmarks/report.md: 18 original items,
        // 0 reconstructed, reported as precision=1.0000.
        let orig = file(CONTRACT);
        let recon = file("pub fn unrelated() {}");
        let score = evaluate(&recon, &orig, None);
        assert!(score.checked, "the original has items — this is measurable");
        assert_eq!(score.score, 0.0);
        let note = score.notes.first().expect("a summary note");
        assert!(
            note.contains("precision=n/a"),
            "precision must read as undefined, got: {note}"
        );
    }
}
