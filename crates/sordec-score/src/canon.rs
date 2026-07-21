//! Shared canonicalization utilities consumed by the category scorers.
//!
//! These normalize away cosmetic differences that must not cost score —
//! module qualifiers, lifetimes, reference/`.clone()` noise — so two
//! sources that mean the same thing compare equal. They are introduced
//! incrementally alongside their first consumer: [`normalize_type`] and
//! [`attr_named`] here for the interface category; the let-binding resolver
//! and enum-variant path helper arrive with the semantic category.

use quote::ToTokens;
use syn::{Attribute, Expr, GenericArgument, PathArguments, Type, UnOp};

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

/// Peel cosmetic wrappers that must not affect a value's identity:
/// references (`&e`, `&mut e`), dereferences (`*e`), parentheses/groups,
/// and trailing no-arg conversion calls (`.clone()`, `.into()`,
/// `.as_ref()`, `.to_owned()`, `.borrow()`). Returns the innermost expr.
pub(crate) fn cosmetic_strip(mut expr: &Expr) -> &Expr {
    loop {
        expr = match expr {
            Expr::Reference(reference) => &reference.expr,
            Expr::Unary(unary) if matches!(unary.op, UnOp::Deref(_)) => &unary.expr,
            Expr::Paren(paren) => &paren.expr,
            Expr::Group(group) => &group.expr,
            Expr::MethodCall(call)
                if call.args.is_empty() && is_cosmetic_method(&call.method) =>
            {
                &call.receiver
            }
            _ => return expr,
        };
    }
}

fn is_cosmetic_method(method: &syn::Ident) -> bool {
    matches!(
        method.to_string().as_str(),
        "clone" | "into" | "as_ref" | "to_owned" | "borrow"
    )
}

/// The `Enum::Variant` path of an enum-variant constructor expression —
/// `DataKey::Balance` from `DataKey::Balance(addr)`, `DataKey::Admin` from
/// the unit `DataKey::Admin`, or a struct-variant literal. Returns the last
/// two path segments joined by `::`.
///
/// Requires at least two segments so a bare local (`key`) or single-segment
/// constant never masquerades as a variant path — the caller resolves
/// locals to their bindings first.
pub(crate) fn enum_variant_path(expr: &Expr) -> Option<String> {
    let path = match expr {
        Expr::Path(expr_path) => &expr_path.path,
        Expr::Call(call) => match call.func.as_ref() {
            Expr::Path(expr_path) => &expr_path.path,
            _ => return None,
        },
        Expr::Struct(expr_struct) => &expr_struct.path,
        _ => return None,
    };
    let count = path.segments.len();
    if count < 2 {
        return None;
    }
    let enum_name = &path.segments[count - 2].ident;
    let variant = &path.segments[count - 1].ident;
    Some(format!("{enum_name}::{variant}"))
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

    fn expr(src: &str) -> Expr {
        syn::parse_str(src).expect("expr parses")
    }

    #[test]
    fn cosmetic_strip_peels_ref_clone_paren() {
        assert_eq!(
            enum_variant_path(cosmetic_strip(&expr("&DataKey::Balance(addr)"))),
            Some("DataKey::Balance".to_string())
        );
        assert_eq!(
            enum_variant_path(cosmetic_strip(&expr("(DataKey::Admin).clone()"))),
            Some("DataKey::Admin".to_string())
        );
    }

    #[test]
    fn enum_variant_path_needs_two_segments() {
        // A bare local must not be mistaken for a variant path.
        assert_eq!(enum_variant_path(&expr("key")), None);
        assert_eq!(
            enum_variant_path(&expr("crate::storage::DataKey::State(a)")),
            Some("DataKey::State".to_string())
        );
    }
}
