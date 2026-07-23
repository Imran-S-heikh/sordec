//! Compilable-type transcription: IR types → [`syn::Type`].
//!
//! This is the emitter's counterpart to the WAT annotator's
//! `type_ref_label` (`super::super::wat`): the same mapping *structure*,
//! but it yields real, compilable soroban-sdk source rather than a `;;`
//! label. The two deliberately diverge where a label is not valid Rust —
//! an unresolved reference is the label `?` but a [`HolePolicy`]-provided
//! type here.
//!
//! Two entry points, because signatures reach the emitter as two type
//! vocabularies: [`type_ref`] for `contractspecv0` types
//! ([`TypeRef`]) and [`ir_type`] for recovered binding types
//! ([`IrType`]). They agree on every shared shape.

use proc_macro2::{Ident, Literal, Span};
use syn::parse_quote;

use sordec_ir::{CompositeType, IrType, KnownType, PrimitiveType, TypeRef, TypeRegistry};

use crate::rust::hole::HolePolicy;

/// Map a `contractspecv0` [`TypeRef`] to a `syn::Type`, resolving
/// user-defined references through `reg` and unresolved ones through
/// `policy`.
pub(crate) fn type_ref(ty: &TypeRef, reg: &TypeRegistry, policy: &dyn HolePolicy) -> syn::Type {
    match ty {
        TypeRef::Primitive(p) => primitive(*p),
        TypeRef::Composite(c) => composite(c, reg, policy),
        TypeRef::UserDefined(id) => match reg.name_of(*id) {
            Some(name) => named(name),
            // A `UserDefined` id absent from the registry is a degenerate,
            // internally-inconsistent case; degrade honestly rather than panic.
            None => policy.unknown_type(None),
        },
        TypeRef::Unknown(reason) => policy.unknown_type(Some(reason)),
    }
}

/// Map a recovered [`IrType`] to a `syn::Type`.
///
/// `Known` and `Inferred` map identically: the certainty distinction is
/// carried in provenance, not in the type token (there is no `u32?` in
/// Rust). `Unknown` routes through the [`HolePolicy`].
pub(crate) fn ir_type(ty: &IrType, reg: &TypeRegistry, policy: &dyn HolePolicy) -> syn::Type {
    match ty {
        IrType::Known(k) | IrType::Inferred(k) => known(k, reg, policy),
        IrType::Unknown(reason) => policy.unknown_type(Some(reason)),
    }
}

/// A named user-defined type as a path type (`DataKey`).
pub(crate) fn named(name: &str) -> syn::Type {
    let id = ident(name);
    parse_quote!(#id)
}

/// Build an identifier from a recovered name, falling back to a raw
/// identifier (`r#name`) if it collides with a Rust keyword. Names come
/// from `contractspecv0`, i.e. originally-valid Rust source, so the
/// fallback is defensive rather than expected.
pub(crate) fn ident(name: &str) -> Ident {
    syn::parse_str::<Ident>(name).unwrap_or_else(|_| Ident::new_raw(name, Span::call_site()))
}

fn primitive(p: PrimitiveType) -> syn::Type {
    match p {
        PrimitiveType::Val => parse_quote!(soroban_sdk::Val),
        PrimitiveType::Bool => parse_quote!(bool),
        PrimitiveType::Void => parse_quote!(()),
        PrimitiveType::Error => parse_quote!(soroban_sdk::Error),
        PrimitiveType::U32 => parse_quote!(u32),
        PrimitiveType::I32 => parse_quote!(i32),
        PrimitiveType::U64 => parse_quote!(u64),
        PrimitiveType::I64 => parse_quote!(i64),
        PrimitiveType::Timepoint => parse_quote!(soroban_sdk::Timepoint),
        PrimitiveType::Duration => parse_quote!(soroban_sdk::Duration),
        PrimitiveType::U128 => parse_quote!(u128),
        PrimitiveType::I128 => parse_quote!(i128),
        PrimitiveType::U256 => parse_quote!(soroban_sdk::U256),
        PrimitiveType::I256 => parse_quote!(soroban_sdk::I256),
        PrimitiveType::Bytes => parse_quote!(soroban_sdk::Bytes),
        PrimitiveType::String => parse_quote!(soroban_sdk::String),
        PrimitiveType::Symbol => parse_quote!(soroban_sdk::Symbol),
        PrimitiveType::Address => parse_quote!(soroban_sdk::Address),
        PrimitiveType::MuxedAddress => parse_quote!(soroban_sdk::MuxedAddress),
    }
}

fn composite(c: &CompositeType, reg: &TypeRegistry, policy: &dyn HolePolicy) -> syn::Type {
    match c {
        CompositeType::Option(t) => {
            let inner = type_ref(t, reg, policy);
            parse_quote!(Option<#inner>)
        }
        CompositeType::Result(t, e) => {
            let ok = type_ref(t, reg, policy);
            let err = type_ref(e, reg, policy);
            parse_quote!(Result<#ok, #err>)
        }
        CompositeType::Vec(t) => {
            let inner = type_ref(t, reg, policy);
            parse_quote!(soroban_sdk::Vec<#inner>)
        }
        CompositeType::Map(k, v) => {
            let key = type_ref(k, reg, policy);
            let val = type_ref(v, reg, policy);
            parse_quote!(soroban_sdk::Map<#key, #val>)
        }
        CompositeType::Tuple(items) => {
            let elems: Vec<syn::Type> = items.iter().map(|t| type_ref(t, reg, policy)).collect();
            tuple(&elems)
        }
        CompositeType::BytesN(n) => {
            let n = Literal::u32_unsuffixed(*n);
            parse_quote!(soroban_sdk::BytesN<#n>)
        }
    }
}

fn known(k: &KnownType, reg: &TypeRegistry, policy: &dyn HolePolicy) -> syn::Type {
    match k {
        KnownType::Bool => parse_quote!(bool),
        KnownType::Unit => parse_quote!(()),
        KnownType::U32 => parse_quote!(u32),
        KnownType::I32 => parse_quote!(i32),
        KnownType::U64 => parse_quote!(u64),
        KnownType::I64 => parse_quote!(i64),
        KnownType::U128 => parse_quote!(u128),
        KnownType::I128 => parse_quote!(i128),
        KnownType::U256 => parse_quote!(soroban_sdk::U256),
        KnownType::I256 => parse_quote!(soroban_sdk::I256),
        KnownType::Symbol => parse_quote!(soroban_sdk::Symbol),
        KnownType::String => parse_quote!(soroban_sdk::String),
        KnownType::Bytes => parse_quote!(soroban_sdk::Bytes),
        KnownType::BytesN(n) => {
            let n = Literal::u32_unsuffixed(*n);
            parse_quote!(soroban_sdk::BytesN<#n>)
        }
        KnownType::Address => parse_quote!(soroban_sdk::Address),
        KnownType::MuxedAddress => parse_quote!(soroban_sdk::MuxedAddress),
        KnownType::Timepoint => parse_quote!(soroban_sdk::Timepoint),
        KnownType::Duration => parse_quote!(soroban_sdk::Duration),
        KnownType::Error => parse_quote!(soroban_sdk::Error),
        KnownType::Val => parse_quote!(soroban_sdk::Val),
        KnownType::Option(t) => {
            let inner = ir_type(t, reg, policy);
            parse_quote!(Option<#inner>)
        }
        KnownType::Result(t, e) => {
            let ok = ir_type(t, reg, policy);
            let err = ir_type(e, reg, policy);
            parse_quote!(Result<#ok, #err>)
        }
        KnownType::Vec(t) => {
            let inner = ir_type(t, reg, policy);
            parse_quote!(soroban_sdk::Vec<#inner>)
        }
        KnownType::Map(k, v) => {
            let key = ir_type(k, reg, policy);
            let val = ir_type(v, reg, policy);
            parse_quote!(soroban_sdk::Map<#key, #val>)
        }
        KnownType::Tuple(items) => {
            let elems: Vec<syn::Type> = items.iter().map(|t| ir_type(t, reg, policy)).collect();
            tuple(&elems)
        }
        KnownType::UserDefined(id) => match reg.name_of(*id) {
            Some(name) => named(name),
            None => policy.unknown_type(None),
        },
    }
}

/// A tuple type from its element types. The trailing comma keeps the
/// one-element case (`(T,)`) a tuple rather than a parenthesised type, and
/// is valid for every other arity; the empty case is unit `()`.
fn tuple(elems: &[syn::Type]) -> syn::Type {
    if elems.is_empty() {
        parse_quote!(())
    } else {
        parse_quote!((#(#elems,)*))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quote::ToTokens;
    use sordec_common::TypeId;
    use sordec_ir::{EnumCase, EnumDef};

    use crate::rust::hole::StrictNoGuess;

    fn render(ty: &syn::Type) -> String {
        ty.to_token_stream().to_string()
    }

    fn empty() -> TypeRegistry {
        TypeRegistry::default()
    }

    #[test]
    fn primitives_map_to_real_soroban_types() {
        let p = &StrictNoGuess;
        let reg = empty();
        assert_eq!(render(&type_ref(&TypeRef::Primitive(PrimitiveType::U64), &reg, p)), "u64");
        assert_eq!(render(&type_ref(&TypeRef::Primitive(PrimitiveType::Void), &reg, p)), "()");
        assert_eq!(
            render(&type_ref(&TypeRef::Primitive(PrimitiveType::Address), &reg, p)),
            "soroban_sdk :: Address"
        );
        assert_eq!(
            render(&type_ref(&TypeRef::Primitive(PrimitiveType::String), &reg, p)),
            "soroban_sdk :: String"
        );
    }

    #[test]
    fn composites_nest() {
        let p = &StrictNoGuess;
        let reg = empty();
        let vec_addr = TypeRef::Composite(CompositeType::Vec(Box::new(TypeRef::Primitive(
            PrimitiveType::Address,
        ))));
        assert_eq!(render(&type_ref(&vec_addr, &reg, p)), "soroban_sdk :: Vec < soroban_sdk :: Address >");

        let bytes32 = TypeRef::Composite(CompositeType::BytesN(32));
        assert_eq!(render(&type_ref(&bytes32, &reg, p)), "soroban_sdk :: BytesN < 32 >");

        let tup = TypeRef::Composite(CompositeType::Tuple(vec![
            TypeRef::Primitive(PrimitiveType::U32),
            TypeRef::Primitive(PrimitiveType::Bool),
        ]));
        assert_eq!(render(&type_ref(&tup, &reg, p)), "(u32 , bool ,)");
    }

    #[test]
    fn user_defined_resolves_by_id() {
        let p = &StrictNoGuess;
        let mut reg = TypeRegistry::default();
        reg.enums.push(EnumDef {
            id: TypeId::new(3),
            name: "Kind".to_string(),
            cases: vec![EnumCase { name: "A".to_string(), value: 0 }],
        });
        assert_eq!(render(&type_ref(&TypeRef::UserDefined(TypeId::new(3)), &reg, p)), "Kind");
    }

    #[test]
    fn unresolved_reference_degrades_to_val_not_a_guess() {
        let p = &StrictNoGuess;
        let reg = empty();
        // An unknown reference and a dangling user-defined id both degrade
        // to the ABI-universal Val — never a guessed concrete type.
        let unknown = TypeRef::Unknown(sordec_common::UnknownReason::NoMetadata);
        assert_eq!(render(&type_ref(&unknown, &reg, p)), "soroban_sdk :: Val");
        let dangling = TypeRef::UserDefined(TypeId::new(99));
        assert_eq!(render(&type_ref(&dangling, &reg, p)), "soroban_sdk :: Val");
    }

    #[test]
    fn keyword_names_become_raw_identifiers() {
        // Defensive: a type named after a keyword must still parse.
        assert_eq!(render(&named("type")), "r#type");
    }
}
