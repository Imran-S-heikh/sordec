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

use std::collections::BTreeMap;

use syn::{FnArg, Fields, ImplItem, Item, ReturnType};

use crate::canon;
use crate::metrics;
use crate::report::CategoryScore;

/// Score the interface category.
pub(crate) fn evaluate(reconstructed: &syn::File, original: &syn::File) -> CategoryScore {
    let recon = extract(reconstructed);
    let orig = extract(original);
    let outcome = f1(&recon, &orig);

    let mut score = CategoryScore::checked(outcome.f1, metrics::INTERFACE_WEIGHT).with_note(
        format!(
            "precision={:.4} recall={:.4} ({} original ABI items, {} reconstructed)",
            outcome.precision,
            outcome.recall,
            orig.len(),
            recon.len()
        ),
    );
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

/// The outcome of an exact-match F1 over two keyed sets.
struct F1Outcome {
    precision: f64,
    recall: f64,
    f1: f64,
}

/// Exact-match F1: an item is correct when both sides carry the same key
/// with an equal value.
fn f1(recon: &BTreeMap<String, String>, orig: &BTreeMap<String, String>) -> F1Outcome {
    if recon.is_empty() && orig.is_empty() {
        return F1Outcome {
            precision: 1.0,
            recall: 1.0,
            f1: 1.0,
        };
    }
    let correct = orig
        .iter()
        .filter(|(key, value)| recon.get(*key) == Some(*value))
        .count();
    let precision = ratio(correct, recon.len());
    let recall = ratio(correct, orig.len());
    let f1 = if precision + recall == 0.0 {
        0.0
    } else {
        2.0 * precision * recall / (precision + recall)
    };
    F1Outcome {
        precision,
        recall,
        f1,
    }
}

/// `numerator / denominator`, or `1.0` when the denominator is zero (an
/// empty side has nothing to get wrong).
fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        1.0
    } else {
        numerator as f64 / denominator as f64
    }
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
        let score = evaluate(&f, &f);
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
        assert!((evaluate(&recon, &orig).score - 1.0).abs() < 1e-9);
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
        let score = evaluate(&recon, &orig);
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
        assert!(evaluate(&recon, &orig).score < 1.0);
    }

    #[test]
    fn empty_interfaces_score_one() {
        let f = file("pub fn helper() {}");
        assert!((evaluate(&f, &f).score - 1.0).abs() < 1e-9);
    }
}
