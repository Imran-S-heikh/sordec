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
//! ## The two halves are scored separately
//!
//! Entrypoints and type/event declarations get their own F1, and the category
//! is their mean (T11). Pooling them made the score depend on how many types a
//! contract happens to declare rather than on reconstruction quality:
//! token-v23's 13 byte-perfect entrypoints were diluting 12 over-declared type
//! entries into a single `0.762`, which reported neither fact. A kind neither
//! side declares drops out of the mean rather than scoring `0`.
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
    names: bool,
) -> CategoryScore {
    let (recon, orig) = match spec {
        Some((recon_spec, orig_spec)) => {
            (spec::abi(recon_spec, names), spec::abi(orig_spec, names))
        }
        None => (extract(reconstructed), extract(original)),
    };

    let kinds: Vec<Kind> = KINDS
        .iter()
        .filter_map(|kind| kind.measure(&recon, &orig))
        .collect();
    if kinds.is_empty() {
        return CategoryScore::unchecked("no ABI items on either side — nothing to measure");
    }

    // Mean over the kinds that were measurable. An absent kind drops out
    // rather than scoring 0 — the same discipline `simil::prf` applies one
    // level up, so a contract that declares no types is not penalized for it.
    let mean = kinds.iter().map(|kind| kind.outcome.f1).sum::<f64>() / kinds.len() as f64;

    let mut score = CategoryScore::checked(mean);
    for kind in &kinds {
        score = score.with_note(kind.summary());
        if let Some(note) = kind.diff_note("missing", &orig, &recon) {
            score = score.with_note(note);
        }
        if let Some(note) = kind.diff_note("extra", &recon, &orig) {
            score = score.with_note(note);
        }
    }
    score
}

/// The two halves of a contract's declared surface, scored separately.
///
/// Pooling them into one F1 makes the score depend on how many types a contract
/// happens to declare rather than on reconstruction quality: token-v23's 13
/// byte-perfect entrypoints were diluting 12 over-declared type entries into a
/// single 0.762, hiding both facts. A contract with fifty types would drown its
/// entrypoints entirely.
///
/// The two are weighted equally. Weighting the callable surface higher is
/// arguable — it is what consumers bind against — but it would raise the score,
/// so it is not a thumb to put on the scale unilaterally.
const KINDS: [KindSpec; 2] = [
    KindSpec {
        label: "entrypoints",
        prefix: "fn ",
    },
    KindSpec {
        label: "types",
        prefix: "type ",
    },
];

/// One half's identity: how its keys are namespaced, and what to call it.
struct KindSpec {
    label: &'static str,
    prefix: &'static str,
}

/// One half's measured outcome.
struct Kind {
    spec: &'static KindSpec,
    outcome: simil::Prf,
    orig_len: usize,
    recon_len: usize,
}

impl KindSpec {
    /// Score this half, or `None` when neither side declared anything of this
    /// kind — unmeasurable, not perfect.
    fn measure(
        &'static self,
        recon: &BTreeMap<String, String>,
        orig: &BTreeMap<String, String>,
    ) -> Option<Kind> {
        let mine = |map: &BTreeMap<String, String>| -> usize {
            map.keys()
                .filter(|key| key.starts_with(self.prefix))
                .count()
        };
        let correct = orig
            .iter()
            .filter(|(key, value)| key.starts_with(self.prefix) && recon.get(*key) == Some(*value))
            .count();
        let (orig_len, recon_len) = (mine(orig), mine(recon));
        simil::prf(correct, recon_len, orig_len).map(|outcome| Kind {
            spec: self,
            outcome,
            orig_len,
            recon_len,
        })
    }
}

impl Kind {
    fn summary(&self) -> String {
        format!(
            "{} {:.4}  precision={} recall={} ({} original, {} reconstructed)",
            self.spec.label,
            self.outcome.f1,
            simil::render_ratio(self.outcome.precision),
            simil::render_ratio(self.outcome.recall),
            self.orig_len,
            self.recon_len
        )
    }

    /// This kind's share of a `missing`/`extra` diff, so the two halves' notes
    /// stay separable.
    fn diff_note(
        &self,
        label: &str,
        from: &BTreeMap<String, String>,
        other: &BTreeMap<String, String>,
    ) -> Option<String> {
        let mine: BTreeMap<String, String> = from
            .iter()
            .filter(|(key, _)| key.starts_with(self.spec.prefix))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        diff_note(&format!("{} {label}", self.spec.label), &mine, other)
    }
}

/// The ABI surface of one source: a keyed map from a namespaced item key
/// (`"fn transfer"`, `"type DataKey"`) to its normalized value.
///
/// Shared with [`crate::structure`], which reads the `"fn "` keys for its
/// entrypoint set on the pre-expansion basis (T13c). Both categories are
/// anchored on the same notion of "what this contract declares", so one
/// extractor is correct — a second one could drift and make the two
/// categories disagree about which functions are entrypoints.
pub(crate) fn extract(file: &syn::File) -> BTreeMap<String, String> {
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

/// Normalized struct shape, in declaration order.
///
/// **Declaration order is not actually ABI-significant** for a
/// `#[contracttype]` struct: the SDK sorts fields when it writes the spec, so
/// timelock's source order `token, amount, claimants, time_bound` and our
/// alphabetical emission produce the identical spec entry. Comparing
/// declaration order therefore charges a reconstruction for a difference that
/// does not exist on the wire — measured, it cost timelock 0.125 of its
/// interface score.
///
/// Left as-is deliberately: this is the *source-basis* extractor, a fallback
/// used only when expansion is unavailable, and sorting here would diverge it
/// further from what it is approximating. The spec-basis path
/// ([`crate::spec`]) is authoritative and unaffected.
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
        let score = evaluate(&f, &f, None, true);
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
        assert!((evaluate(&recon, &orig, None, true).score - 1.0).abs() < 1e-9);
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
        let score = evaluate(&recon, &orig, None, true);
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
        assert!(evaluate(&recon, &orig, None, true).score < 1.0);
    }

    #[test]
    fn empty_interfaces_are_unchecked_not_perfect() {
        // No `#[contractimpl]`/`#[contracttype]` on either side: the
        // extractor found nothing, so there is nothing to score. Reporting
        // 1.0 here is the false perfect T8 removes — it is exactly what a
        // macro-expanded input (which consumes those attributes) would hit.
        let f = file("pub fn helper() {}");
        let score = evaluate(&f, &f, None, true);
        assert!(!score.checked, "a 0-item extraction must not be checked");
        assert_ne!(score.score, 1.0);
    }

    #[test]
    fn over_declared_types_cannot_hide_behind_perfect_entrypoints() {
        // THE T11 case, in miniature: this is token-v23's shape — every
        // entrypoint byte-perfect, the type set badly over-declared. Pooling
        // the two into one F1 lets the good half dilute the bad one and
        // reports neither. Scoring them separately reports both, and lands
        // *below* the pooled number.
        let orig = file(
            r#"
            #[contractimpl]
            impl Token {
                pub fn a(e: Env) {}
                pub fn b(e: Env) {}
                pub fn c(e: Env) {}
                pub fn d(e: Env) {}
            }
            #[contracttype]
            pub struct Kept { x: u32 }
            "#,
        );
        let recon = file(
            r#"
            #[contractimpl]
            impl Token {
                pub fn a(e: Env) {}
                pub fn b(e: Env) {}
                pub fn c(e: Env) {}
                pub fn d(e: Env) {}
            }
            #[contracttype]
            pub struct Kept { x: u32 }
            #[contracttype]
            pub struct Invented1 { x: u32 }
            #[contracttype]
            pub struct Invented2 { x: u32 }
            #[contracttype]
            pub struct Invented3 { x: u32 }
            "#,
        );
        let score = evaluate(&recon, &orig, None, true);

        // entrypoints 4/4/4 -> 1.0; types 1 correct of 4 emitted, 1 original
        // -> precision 0.25, recall 1.0, F1 0.4. Mean = 0.7.
        assert!(
            (score.score - 0.7).abs() < 1e-9,
            "expected the mean of the two halves, got {}",
            score.score
        );
        // Pooling would have been 5 correct / 8 emitted / 5 original -> 0.769.
        assert!(
            score.score < 0.769,
            "the split must not be more forgiving than pooling"
        );

        let notes = score.notes.join("\n");
        assert!(notes.contains("entrypoints 1.0000"), "{notes}");
        assert!(notes.contains("types 0.4000"), "{notes}");
        assert!(
            notes.contains("types extra: type Invented1"),
            "extras must be attributed to their half: {notes}"
        );
    }

    #[test]
    fn a_kind_neither_side_declares_drops_out_of_the_mean() {
        // hello-add's shape: entrypoints only, no `#[contracttype]` at all.
        // The absent half is unmeasurable, not zero, so the category is the
        // entrypoint score alone rather than half of it.
        let f = file(
            r#"
            #[contractimpl]
            impl Token { pub fn add(a: u32) -> u32 { a } }
            "#,
        );
        let score = evaluate(&f, &f, None, true);
        assert!(
            (score.score - 1.0).abs() < 1e-9,
            "score was {}",
            score.score
        );
        let notes = score.notes.join("\n");
        assert!(notes.contains("entrypoints 1.0000"), "{notes}");
        assert!(
            !notes.contains("types"),
            "absent kind must not be reported: {notes}"
        );
    }

    #[test]
    fn a_wrong_entrypoint_is_not_masked_by_correct_types() {
        // The mirror of the headline case, and the reason equal weighting is
        // the neutral choice: a broken callable surface must show even when
        // every declared type is right.
        let orig = file(
            r#"
            #[contractimpl]
            impl Token { pub fn transfer(e: Env, amount: i128) {} }
            #[contracttype]
            pub struct A { x: u32 }
            #[contracttype]
            pub struct B { x: u32 }
            #[contracttype]
            pub struct C { x: u32 }
            "#,
        );
        let recon = file(
            r#"
            #[contractimpl]
            impl Token { pub fn transfer(e: Env, amount: u64) {} }
            #[contracttype]
            pub struct A { x: u32 }
            #[contracttype]
            pub struct B { x: u32 }
            #[contracttype]
            pub struct C { x: u32 }
            "#,
        );
        // entrypoints 0.0, types 1.0 -> 0.5, regardless of there being three
        // times as many types as entrypoints.
        let score = evaluate(&recon, &orig, None, true);
        assert!(
            (score.score - 0.5).abs() < 1e-9,
            "score was {}",
            score.score
        );
    }

    #[test]
    fn nothing_reconstructed_does_not_report_perfect_precision() {
        // The live bug from docs/benchmarks/report.md: 18 original items,
        // 0 reconstructed, reported as precision=1.0000.
        let orig = file(CONTRACT);
        let recon = file("pub fn unrelated() {}");
        let score = evaluate(&recon, &orig, None, true);
        assert!(score.checked, "the original has items — this is measurable");
        assert_eq!(score.score, 0.0);
        let note = score.notes.first().expect("a summary note");
        assert!(
            note.contains("precision=n/a"),
            "precision must read as undefined, got: {note}"
        );
    }
}
