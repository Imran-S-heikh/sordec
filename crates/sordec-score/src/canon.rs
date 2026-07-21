//! Shared canonicalization utilities consumed by the category scorers.
//!
//! These normalize away cosmetic differences that must not cost score —
//! module qualifiers, lifetimes, reference/`.clone()` noise — so two
//! sources that mean the same thing compare equal. They are introduced
//! incrementally alongside their first consumer: [`normalize_type`] and
//! [`attr_named`] here for the interface category; the let-binding resolver
//! and enum-variant path helper arrive with the semantic category.

use quote::ToTokens;
use syn::{Attribute, GenericArgument, PathArguments, Type};

/// Whether `attrs` contains an attribute whose final path segment is
/// `name` (e.g. `contractimpl`, `contracttype`). Argument lists and module
/// qualifiers are ignored, so `#[soroban_sdk::contracttype]` still matches
/// `"contracttype"`.
pub(crate) fn attr_named(attrs: &[Attribute], name: &str) -> bool {
    attrs
        .iter()
        .any(|attr| attr.path().segments.last().is_some_and(|seg| seg.ident == name))
}

/// A canonical, comparable string for a type.
///
/// The leaf name plus recursively-normalized generic arguments, with
/// module qualifiers and lifetimes dropped (`soroban_sdk::Address` →
/// `Address`, `Vec<'a, T>` → `Vec<T>`). References are *kept* (`&T` is a
/// different interface type than `T`) but their lifetimes are dropped.
pub(crate) fn normalize_type(ty: &Type) -> String {
    match ty {
        Type::Path(type_path) => normalize_path_type(&type_path.path),
        Type::Reference(reference) => format!("&{}", normalize_type(&reference.elem)),
        Type::Tuple(tuple) => {
            let inner: Vec<String> = tuple.elems.iter().map(normalize_type).collect();
            format!("({})", inner.join(","))
        }
        Type::Slice(slice) => format!("[{}]", normalize_type(&slice.elem)),
        Type::Array(array) => format!("[{};{}]", normalize_type(&array.elem), compact(&array.len)),
        Type::Paren(paren) => normalize_type(&paren.elem),
        Type::Group(group) => normalize_type(&group.elem),
        // Fn pointers, impl Trait, etc. are rare in a Soroban ABI; fall back
        // to a whitespace-stripped token rendering so they still compare.
        other => compact(other),
    }
}

/// Normalize a path used as a type: leaf segment + generic args, qualifiers
/// and lifetimes dropped.
fn normalize_path_type(path: &syn::Path) -> String {
    let Some(segment) = path.segments.last() else {
        return String::new();
    };
    let mut rendered = segment.ident.to_string();
    if let PathArguments::AngleBracketed(args) = &segment.arguments {
        let inner: Vec<String> = args
            .args
            .iter()
            .filter_map(|arg| match arg {
                GenericArgument::Type(ty) => Some(normalize_type(ty)),
                GenericArgument::Const(expr) => Some(compact(expr)),
                // Drop lifetimes and binding/constraint args — cosmetic.
                _ => None,
            })
            .collect();
        if !inner.is_empty() {
            rendered = format!("{rendered}<{}>", inner.join(","));
        }
    }
    rendered
}

/// A token rendering with all whitespace removed — a stable fallback for
/// nodes without a bespoke normalization.
fn compact(tokens: &impl ToTokens) -> String {
    tokens
        .to_token_stream()
        .to_string()
        .split_whitespace()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ty(src: &str) -> Type {
        syn::parse_str(src).expect("type parses")
    }

    #[test]
    fn module_qualifiers_are_dropped() {
        assert_eq!(normalize_type(&ty("soroban_sdk::Address")), "Address");
        assert_eq!(normalize_type(&ty("Address")), "Address");
    }

    #[test]
    fn generics_normalize_recursively() {
        assert_eq!(
            normalize_type(&ty("Vec<soroban_sdk::Address>")),
            "Vec<Address>"
        );
        assert_eq!(
            normalize_type(&ty("Map<Address, i128>")),
            "Map<Address,i128>"
        );
    }

    #[test]
    fn references_kept_lifetimes_dropped() {
        assert_eq!(normalize_type(&ty("&'a Env")), "&Env");
        assert_ne!(normalize_type(&ty("&Env")), normalize_type(&ty("Env")));
    }

    #[test]
    fn tuples_and_arrays() {
        assert_eq!(normalize_type(&ty("(Address, i128)")), "(Address,i128)");
        assert_eq!(normalize_type(&ty("[u8; 32]")), "[u8;32]");
    }

    #[test]
    fn attr_named_matches_last_segment() {
        let item: syn::ItemStruct =
            syn::parse_str("#[soroban_sdk::contracttype] struct S { x: u32 }").unwrap();
        assert!(attr_named(&item.attrs, "contracttype"));
        assert!(!attr_named(&item.attrs, "contractimpl"));
    }
}
