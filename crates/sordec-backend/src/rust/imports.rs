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

/// soroban-sdk traits the emitter names in a qualified call.
///
/// `IntoVal` is written with its parameters spelled out —
/// `IntoVal::<Env, Val>::into_val(&x, e)` — because the bare method needs
/// its target type pinned from context, and the positions that need the
/// conversion are exactly the ones with no context to pin it (see
/// `idiom::vec_items`). Collapsing it is the same decision as for a type:
/// the name shortens and the `use` carries it, and `shadowed` is what
/// keeps a contract defining its own `IntoVal` safe.
///
/// `FromVal` is written as a bare `FromVal::from_val(&e, &v)` where the
/// parameter it fills pins the target type (`idiom`'s auth entries).
const TRAIT_NAMES: &[&str] = &["FromVal", "IntoVal"];

/// soroban-sdk macros the emitter writes as `soroban_sdk::<macro>!(…)`.
const MACRO_NAMES: &[&str] = &["panic_with_error", "symbol_short", "vec"];

/// soroban-sdk submodules kept as a short prefix (`token::Client::new`).
const MODULE_NAMES: &[&str] = &["token"];

/// soroban-sdk items one module down, imported as `module::Name` and
/// written as the bare `Name`. Each is a type the contract's own item may
/// also define; `shadowed` keeps that safe, as for the leaf types.
const NESTED_NAMES: &[(&str, &str)] = &[
    ("auth", "Context"),
    ("auth", "ContractContext"),
    ("auth", "ContractExecutable"),
    ("auth", "CreateContractHostFnContext"),
    ("auth", "CreateContractWithConstructorHostFnContext"),
    ("auth", "InvokerContractAuthEntry"),
    ("auth", "SubContractInvocation"),
];

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
/// set is empty (the emitted module always imports at least `contract`, so
/// `build_file` never sees `None`).
pub(crate) fn use_item(names: &BTreeSet<String>) -> Option<syn::Item> {
    if names.is_empty() {
        return None;
    }
    // A nested name (`auth::Context`) is a path in the list, not an ident.
    let paths: Vec<syn::Path> = names
        .iter()
        .map(|n| match n.split_once("::") {
            Some((m, leaf)) => {
                let (m, leaf) = (ident(m), ident(leaf));
                parse_quote!(#m::#leaf)
            }
            None => {
                let i = ident(n);
                parse_quote!(#i)
            }
        })
        .collect();
    Some(parse_quote!(use soroban_sdk::{#(#paths),*};))
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

        // `soroban_sdk::auth::Context[::Variant]` -> `Context[::Variant]`,
        // importing `auth::Context`. Two segments dropped, not one.
        if let [first, second, third, ..] = path.segments.iter().collect::<Vec<_>>().as_slice()
            && first.ident == "soroban_sdk"
            && !self.shadowed.contains(&third.ident.to_string())
            && NESTED_NAMES.iter().any(|(m, n)| second.ident == m && third.ident == n)
        {
            let import = format!("{}::{}", second.ident, third.ident);
            let segments = std::mem::take(&mut path.segments);
            path.segments = segments.into_iter().skip(2).collect();
            path.leading_colon = None;
            self.imports.insert(import);
            return;
        }

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
                        || TRAIT_NAMES.contains(&name.as_str())
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
    fn auth_context_collapses_and_imports_by_its_module() {
        let mut items: Vec<syn::Item> = vec![parse_quote!(
            fn f(c: Vec<soroban_sdk::auth::Context>) { let _ = soroban_sdk::auth::Context::Contract; }
        )];
        let imports = collapse(&mut items);
        assert!(imports.contains("auth::Context"), "{imports:?}");
        let out = render(&items[0]);
        assert!(out.contains("Vec < Context >") && out.contains("Context :: Contract"), "{out}");
        assert!(!out.contains("auth"), "{out}");
        assert!(render(&use_item(&imports).unwrap()).contains("auth :: Context"));
    }

    #[test]
    fn auth_context_stays_qualified_when_the_module_defines_context() {
        let mut items: Vec<syn::Item> = vec![
            parse_quote!(pub struct Context;),
            parse_quote!(fn f(c: soroban_sdk::auth::Context) {}),
        ];
        let imports = collapse(&mut items);
        assert!(imports.is_empty(), "{imports:?}");
        assert!(render(&items[1]).contains("soroban_sdk :: auth :: Context"));
    }

    /// The auth entry types a contract builds, spelled from the SDK, as
    /// `Context` is.
    #[test]
    fn auth_entry_types_collapse_and_import_by_their_module() {
        let mut items: Vec<syn::Item> = vec![parse_quote!(
            fn f(e: soroban_sdk::Env, c: soroban_sdk::auth::ContractContext) {
                let s = soroban_sdk::auth::SubContractInvocation { context: c, sub_invocations: soroban_sdk::Vec::new(&e) };
                let _ = soroban_sdk::auth::InvokerContractAuthEntry::Contract(s);
            }
        )];
        let imports = collapse(&mut items);
        for name in ["auth::ContractContext", "auth::SubContractInvocation", "auth::InvokerContractAuthEntry"] {
            assert!(imports.contains(name), "{name}: {imports:?}");
        }
        let out = render(&items[0]);
        assert!(out.contains("InvokerContractAuthEntry :: Contract (s)") && !out.contains("auth"), "{out}");
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
