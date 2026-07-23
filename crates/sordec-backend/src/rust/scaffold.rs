//! Module scaffold: the pieces that frame the emitted functions —
//! `use` imports, the `#[contract]` struct, the `#[contractimpl]` wrapper,
//! and the generated `Cargo.toml`.
//!
//! The `#[contract]` type name is not recorded in `contractspecv0` (the
//! spec carries function and type names, not the impl type), so it is
//! synthesized as `Contract`. Soroban type *paths* are emitted
//! fully-qualified (`soroban_sdk::Address`), so only the attribute macros
//! need importing; collapsing paths into the `use` list is a later
//! output-quality pass.

use syn::parse_quote;

use sordec_ir::{HighIr, TypeRegistry};

use crate::rust::ty::ident;

/// The synthesized `#[contract]` type name.
const CONTRACT_TYPE: &str = "Contract";

/// The `use soroban_sdk::{…};` importing exactly the attribute macros the
/// emitted module uses, or `None` when it uses none (e.g. a stripped module
/// with only free functions and fully-qualified type paths).
pub(crate) fn use_item(types: Option<&TypeRegistry>, has_impl: bool) -> Option<syn::Item> {
    let mut names: Vec<syn::Ident> = Vec::new();
    if has_impl {
        names.push(ident("contract"));
        names.push(ident("contractimpl"));
    }
    if let Some(t) = types {
        if !t.structs.is_empty() || !t.unions.is_empty() || !t.enums.is_empty() {
            names.push(ident("contracttype"));
        }
        if !t.errors.is_empty() {
            names.push(ident("contracterror"));
        }
        if !t.events.is_empty() {
            names.push(ident("contractevent"));
        }
    }
    if names.is_empty() {
        return None;
    }
    Some(parse_quote!(use soroban_sdk::{#(#names),*};))
}

/// `#[contract] pub struct Contract;`.
pub(crate) fn contract_struct() -> syn::Item {
    let name = ident(CONTRACT_TYPE);
    parse_quote! {
        #[contract]
        pub struct #name;
    }
}

/// `#[contractimpl] impl Contract { … }` over the emitted methods.
pub(crate) fn contract_impl(methods: Vec<syn::ImplItemFn>) -> syn::Item {
    let name = ident(CONTRACT_TYPE);
    parse_quote! {
        #[contractimpl]
        impl #name {
            #(#methods)*
        }
    }
}

/// A `Cargo.toml` for the reconstructed contract crate.
///
/// The soroban-sdk version is taken from the `rssdkver` build annotation in
/// `contractmetav0` (of the form `"23.0.1#<hash>"` — the leading semver is
/// used); absent that, the major line the corpus targets.
#[must_use]
pub(crate) fn emit_cargo_toml(high: &HighIr) -> String {
    let sdk_version = high
        .soroban_facts
        .as_ref()
        .and_then(|f| f.contract_meta.get("rssdkver"))
        .map(|raw| sdk_semver(raw))
        .unwrap_or_else(|| "23".to_string());
    format!(
        "[package]\n\
         name = \"reconstructed-contract\"\n\
         version = \"0.1.0\"\n\
         edition = \"2021\"\n\
         \n\
         [lib]\n\
         crate-type = [\"cdylib\"]\n\
         \n\
         [dependencies]\n\
         soroban-sdk = \"{sdk_version}\"\n"
    )
}

/// Extract the leading semantic version from an `rssdkver` annotation,
/// dropping any `#<git-hash>` suffix.
fn sdk_semver(raw: &str) -> String {
    raw.split('#').next().unwrap_or(raw).trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use quote::ToTokens;

    #[test]
    fn imports_are_minimal_and_sorted_by_need() {
        // Impl present, no user types → only the two impl macros.
        let item = use_item(Some(&TypeRegistry::default()), true).expect("some imports");
        let out = item.to_token_stream().to_string();
        assert!(out.contains("contract"), "{out}");
        assert!(out.contains("contractimpl"), "{out}");
        assert!(!out.contains("contracttype"), "{out}");
    }

    #[test]
    fn no_imports_when_nothing_is_used() {
        assert!(use_item(None, false).is_none());
    }

    #[test]
    fn sdk_version_parses_from_rssdkver() {
        assert_eq!(sdk_semver("23.0.1#510d3feb724c2b01"), "23.0.1");
        assert_eq!(sdk_semver("22.0.0"), "22.0.0");
    }
}
