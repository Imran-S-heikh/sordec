//! Import collapse: fully-qualified `soroban_sdk::…` paths → short names,
//! plus the single `use soroban_sdk::{…}` that makes the short names resolve.
//!
//! The emitter writes every soroban-sdk path fully-qualified
//! (`soroban_sdk::Address`, `soroban_sdk::token::Client`,
//! `soroban_sdk::panic_with_error!`) so each site is self-contained and the
//! rest of the emitter needs no import bookkeeping. This post-pass, run once
//! over the assembled module, rewrites those paths to the short forms a
//! human writes and returns the set of names to import.
//!
//! It is score-neutral (the scorer's `canon::normalize_type` already drops
//! module qualifiers) and, because it emits the matching `use`, keeps the
//! opt-in `--check-compile` grading valid.
//!
//! Rewriting is bounded by allowlists — an unrecognised `soroban_sdk::X`
//! stays fully-qualified rather than being guessed into an import. In a
//! `#![no_std]` module none of these leaf names (`String`, `Vec`, …) are in
//! the prelude, so importing them shadows nothing.

use std::collections::BTreeSet;

use syn::parse_quote;
use syn::visit_mut::{self, VisitMut};

use crate::rust::ty::ident;

/// soroban-sdk leaf types the emitter writes as `soroban_sdk::<Type>`.
/// Kept in sync with [`super::ty`], the only producer of these paths.
const TYPE_NAMES: &[&str] = &[
    "Env",
    "Address",
    "MuxedAddress",
    "String",
    "Symbol",
    "Bytes",
    "BytesN",
    "Vec",
    "Map",
    "Val",
    "Error",
    "U256",
    "I256",
    "Timepoint",
    "Duration",
];

/// soroban-sdk macros the emitter writes as `soroban_sdk::<macro>!(…)`.
const MACRO_NAMES: &[&str] = &["panic_with_error", "symbol_short", "vec"];

/// soroban-sdk submodules kept as a short prefix (`token::Client::new`).
const MODULE_NAMES: &[&str] = &["token"];

/// Rewrite every recognised `soroban_sdk::…` path in `items` to its short
/// form, returning the names to import. The set is sorted (a `BTreeSet`) so
/// the emitted `use` list is deterministic.
pub(crate) fn collapse(items: &mut [syn::Item]) -> BTreeSet<String> {
    let shadowed = locally_defined(items);
    let mut collapser = Collapser { imports: BTreeSet::new(), shadowed };
    for item in items {
        collapser.visit_item_mut(item);
    }
    collapser.imports
}

/// Type names this module defines itself.
///
/// A recovered `#[contracterror] enum Error` or `#[contracttype] struct Vec`
/// occupies a name the SDK also exports, and collapsing
/// `soroban_sdk::Error` to `Error` there would both import a colliding name
/// and silently re-point every use at the wrong type. Such a path stays
/// fully qualified instead — the one case where the long form is the
/// *correct* rendering rather than a failure to shorten.
///
/// Attestation is the live witness: it declares `enum Error`, and the SDK's
/// `Error` became reachable as a binding type only once holes started
/// carrying their recovered type.
fn locally_defined(items: &[syn::Item]) -> BTreeSet<String> {
    items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Enum(e) => Some(e.ident.to_string()),
            syn::Item::Struct(s) => Some(s.ident.to_string()),
            syn::Item::Type(t) => Some(t.ident.to_string()),
            syn::Item::Union(u) => Some(u.ident.to_string()),
            _ => None,
        })
        .collect()
}

/// The `use soroban_sdk::{…};` for the merged import set, or `None` when the
/// module references nothing from the SDK (e.g. a stripped free-fn module).
pub(crate) fn use_item(names: &BTreeSet<String>) -> Option<syn::Item> {
    if names.is_empty() {
        return None;
    }
    let idents: Vec<syn::Ident> = names.iter().map(|n| ident(n)).collect();
    Some(parse_quote!(use soroban_sdk::{#(#idents),*};))
}

struct Collapser {
    imports: BTreeSet<String>,
    /// Names the module defines itself; see [`locally_defined`].
    shadowed: BTreeSet<String>,
}

impl VisitMut for Collapser {
    fn visit_path_mut(&mut self, path: &mut syn::Path) {
        // Recurse first: nested paths (generic arguments such as
        // `soroban_sdk::Vec<soroban_sdk::Address>`) are collapsed before the
        // outer path, so both the container and its argument are rewritten.
        visit_mut::visit_path_mut(self, path);

        // Decide whether this path is a `soroban_sdk::…` we collapse, and
        // what to import. Scoped so the immutable borrow ends before the
        // rewrite below.
        let import = {
            let mut segs = path.segments.iter();
            match (segs.next(), segs.next()) {
                (Some(first), Some(second)) if first.ident == "soroban_sdk" => {
                    let name = second.ident.to_string();
                    let leaf = path.segments.len() == 2;
                    if self.shadowed.contains(&name) {
                        None // the module defines this name; stay qualified
                    } else if MODULE_NAMES.contains(&name.as_str())
                        // A type collapses whether it is used as a type
                        // (`soroban_sdk::Address`) or as the receiver of an
                        // associated function (`soroban_sdk::Symbol::new`).
                        // Both shorten to the same import, and the
                        // `shadowed` check above is what makes it safe —
                        // that, not the qualified spelling, is the defence
                        // against a module defining its own `Symbol`.
                        || TYPE_NAMES.contains(&name.as_str())
                        // A macro path has no trailing segments, so it must
                        // be the leaf.
                        || (leaf && MACRO_NAMES.contains(&name.as_str()))
                    {
                        Some(name)
                    } else {
                        None // unknown `soroban_sdk::X` — leave qualified
                    }
                }
                _ => None,
            }
        };

        let Some(import) = import else {
            return;
        };

        // Drop the leading `soroban_sdk` segment, keeping the remaining
        // segments and their generic arguments intact.
        let segments = std::mem::take(&mut path.segments);
        path.segments = segments.into_iter().skip(1).collect();
        path.leading_colon = None;
        self.imports.insert(import);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quote::ToTokens;

    fn render(item: &syn::Item) -> String {
        item.to_token_stream().to_string()
    }

    #[test]
    fn leaf_types_collapse_and_are_recorded() {
        let mut items: Vec<syn::Item> =
            vec![parse_quote!(fn f(e: soroban_sdk::Env, a: soroban_sdk::Address) {})];
        let imports = collapse(&mut items);
        assert!(imports.contains("Env") && imports.contains("Address"));
        let out = render(&items[0]);
        assert!(out.contains("e : Env"), "{out}");
        assert!(out.contains("a : Address"), "{out}");
        assert!(!out.contains("soroban_sdk"), "{out}");
    }

    #[test]
    fn nested_generics_collapse_inside_out() {
        let mut items: Vec<syn::Item> =
            vec![parse_quote!(fn f() -> soroban_sdk::Vec<soroban_sdk::Address> { todo!() })];
        let imports = collapse(&mut items);
        assert!(imports.contains("Vec") && imports.contains("Address"));
        let out = render(&items[0]);
        assert!(out.contains("Vec < Address >"), "{out}");
    }

    #[test]
    fn module_prefix_is_kept_and_module_imported() {
        let mut items: Vec<syn::Item> =
            vec![parse_quote!(fn f() { soroban_sdk::token::Client::new(&e, &c); })];
        let imports = collapse(&mut items);
        assert!(imports.contains("token"), "imports token module: {imports:?}");
        let out = render(&items[0]);
        assert!(out.contains("token :: Client :: new"), "{out}");
        assert!(!out.contains("soroban_sdk"), "{out}");
    }

    #[test]
    fn a_name_the_module_defines_is_never_imported_over() {
        // Attestation's shape: a recovered `#[contracterror] enum Error`
        // alongside a reference to the SDK's own `Error`. Collapsing would
        // emit `use soroban_sdk::{Error}` beside `pub enum Error` — E0255,
        // and every use of the short name would resolve to the wrong type.
        let mut items: Vec<syn::Item> = vec![
            parse_quote!(pub enum Error { A = 1 }),
            parse_quote!(fn f(x: soroban_sdk::Error, a: soroban_sdk::Address) {}),
        ];
        let imports = collapse(&mut items);
        assert!(!imports.contains("Error"), "must not import a shadowed name: {imports:?}");
        assert!(imports.contains("Address"), "unshadowed names still collapse");
        let out = render(&items[1]);
        assert!(out.contains("soroban_sdk :: Error"), "stays qualified: {out}");
        assert!(out.contains("a : Address"), "{out}");
    }

    #[test]
    fn unknown_soroban_paths_are_left_qualified() {
        let mut items: Vec<syn::Item> = vec![parse_quote!(fn f(x: soroban_sdk::Unmapped) {})];
        let imports = collapse(&mut items);
        assert!(imports.is_empty(), "no import for an unknown type: {imports:?}");
        assert!(render(&items[0]).contains("soroban_sdk :: Unmapped"));
    }

    #[test]
    fn use_item_is_sorted_and_optional() {
        assert!(use_item(&BTreeSet::new()).is_none());
        let names: BTreeSet<String> =
            ["Env", "Address", "contract"].iter().map(|s| s.to_string()).collect();
        let out = render(&use_item(&names).unwrap());
        // BTreeSet order: Address, Env, contract.
        assert_eq!(out, "use soroban_sdk :: { Address , Env , contract } ;");
    }
}
