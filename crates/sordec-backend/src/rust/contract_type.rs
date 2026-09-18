//! Type reconstruction: [`TypeRegistry`] → `#[contracttype]` /
//! `#[contracterror]` / `#[contractevent]` item definitions.
//!
//! This is transcription, not inference — every user-defined type is
//! recorded verbatim in `contractspecv0` (name, fields, discriminants), so
//! the work is a faithful mapping into a `syn` AST. Field and variant
//! *types* are resolved through [`ty`](super::ty), so an unresolved inner
//! reference degrades through the same [`HolePolicy`] as everywhere else.

use quote::quote;
use proc_macro2::Literal;
use syn::parse_quote;

use sordec_ir::{EnumDef, EventDef, EventParamLocation, StructDef, TypeRegistry, UnionDef};

use crate::rust::hole::HolePolicy;
use crate::rust::ty::{ident, is_tuple_struct, type_ref};

/// All user-defined types as top-level items, in registry order: structs,
/// payload enums, C-style enums, error enums, then events.
pub(crate) fn contract_types(reg: &TypeRegistry, policy: &dyn HolePolicy) -> Vec<syn::Item> {
    let mut items = Vec::new();
    items.extend(reg.structs.iter().map(|d| struct_item(d, reg, policy)));
    items.extend(reg.unions.iter().map(|d| union_item(d, reg, policy)));
    items.extend(reg.enums.iter().map(enum_item));
    items.extend(reg.errors.iter().map(error_item));
    items.extend(reg.events.iter().map(|d| event_item(d, reg, policy)));
    items
}

fn struct_item(def: &StructDef, reg: &TypeRegistry, policy: &dyn HolePolicy) -> syn::Item {
    let name = ident(&def.name);

    // A tuple struct reaches us as fields named "0", "1", … — the only trace
    // `contractspecv0` keeps of the distinction. Emitting those as named fields
    // is not merely wrong shape: `0` is not an identifier, and the attempt used
    // to abort the emitter.
    if is_tuple_struct(&def.fields) {
        let tys = def.fields.iter().map(|f| type_ref(&f.ty, reg, policy));
        return parse_quote! {
            #[contracttype]
            #[derive(Clone)]
            pub struct #name(#(pub #tys,)*);
        };
    }

    let fields = def.fields.iter().map(|f| {
        let fname = ident(&f.name);
        let fty = type_ref(&f.ty, reg, policy);
        quote!(pub #fname: #fty)
    });
    parse_quote! {
        #[contracttype]
        #[derive(Clone)]
        pub struct #name {
            #(#fields,)*
        }
    }
}

fn union_item(def: &UnionDef, reg: &TypeRegistry, policy: &dyn HolePolicy) -> syn::Item {
    let name = ident(&def.name);
    let variants = def.cases.iter().map(|c| {
        let vname = ident(&c.name);
        if c.fields.is_empty() {
            quote!(#vname)
        } else {
            let tys = c.fields.iter().map(|t| type_ref(t, reg, policy));
            quote!(#vname(#(#tys),*))
        }
    });
    parse_quote! {
        #[contracttype]
        #[derive(Clone)]
        pub enum #name {
            #(#variants,)*
        }
    }
}

fn enum_item(def: &EnumDef) -> syn::Item {
    let name = ident(&def.name);
    let variants = def.cases.iter().map(|c| {
        let vname = ident(&c.name);
        let value = Literal::u32_unsuffixed(c.value);
        quote!(#vname = #value)
    });
    parse_quote! {
        #[contracttype]
        #[derive(Clone)]
        pub enum #name {
            #(#variants,)*
        }
    }
}

fn error_item(def: &EnumDef) -> syn::Item {
    let name = ident(&def.name);
    let variants = def.cases.iter().map(|c| {
        let vname = ident(&c.name);
        let value = Literal::u32_unsuffixed(c.value);
        quote!(#vname = #value)
    });
    parse_quote! {
        #[contracterror]
        #[derive(Copy, Clone)]
        #[repr(u32)]
        pub enum #name {
            #(#variants,)*
        }
    }
}

/// Events are reconstructed as a `#[contractevent]` struct over their
/// parameters, with everything `contractspecv0` records about them: which
/// parameters are topics, the data format, and the topic prefix.
///
/// Only what differs from the macro's own defaults is spelled, because the
/// declaration has to *regenerate* this spec, not describe it: the default
/// prefix is the struct's name in snake case and the default data format is
/// `map`, so spelling those would be noise, and spelling anything else
/// wrongly would change the event the contract emits.
fn event_item(def: &EventDef, reg: &TypeRegistry, policy: &dyn HolePolicy) -> syn::Item {
    let name = ident(&def.name);
    let fields = def.params.iter().map(|p| {
        let pname = ident(&p.name);
        let pty = type_ref(&p.ty, reg, policy);
        match p.location {
            EventParamLocation::Topic => quote!(#[topic] pub #pname: #pty),
            EventParamLocation::Data => quote!(pub #pname: #pty),
        }
    });
    let mut args: Vec<proc_macro2::TokenStream> = Vec::new();
    if def.prefix_topics != vec![crate::rust::naming::snake(&def.name)] {
        let topics = def.prefix_topics.iter().map(|t| syn::LitStr::new(t, proc_macro2::Span::call_site()));
        args.push(quote!(topics = [#(#topics),*]));
    }
    if let Some(format) = data_format(&def.data_format) {
        let format = syn::LitStr::new(format, proc_macro2::Span::call_site());
        args.push(quote!(data_format = #format));
    }
    let attr = if args.is_empty() {
        quote!(#[contractevent])
    } else {
        quote!(#[contractevent(#(#args),*)])
    };
    parse_quote! {
        #attr
        pub struct #name {
            #(#fields,)*
        }
    }
}

/// The `data_format` the macro spells for a recorded format, or `None` for
/// `map` — its default, which is spelled by saying nothing.
fn data_format(recorded: &str) -> Option<&'static str> {
    match recorded {
        "SingleValue" => Some("single-value"),
        "Vec" => Some("vec"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quote::ToTokens;
    use sordec_common::TypeId;
    use sordec_ir::{
        CompositeType, EnumCase, PrimitiveType, StructField, TypeRef, UnionCase,
    };

    use crate::rust::hole::StrictNoGuess;

    fn render(item: &syn::Item) -> String {
        item.to_token_stream().to_string()
    }

    #[test]
    fn struct_reconstructs_with_fields() {
        let reg = TypeRegistry {
            structs: vec![StructDef {
                id: TypeId::new(0),
                name: "AllowanceDataKey".to_string(),
                fields: vec![
                    StructField { name: "from".to_string(), ty: TypeRef::Primitive(PrimitiveType::Address) },
                    StructField { name: "spender".to_string(), ty: TypeRef::Primitive(PrimitiveType::Address) },
                ],
            }],
            ..Default::default()
        };
        let items = contract_types(&reg, &StrictNoGuess);
        let out = render(&items[0]);
        assert!(out.contains("# [contracttype]"), "{out}");
        assert!(out.contains("pub struct AllowanceDataKey"), "{out}");
        assert!(out.contains("pub from : soroban_sdk :: Address"), "{out}");
    }

    #[test]
    fn positional_fields_reconstruct_as_a_tuple_struct() {
        // `contractspecv0` keeps no tuple-struct flag: it records the fields as
        // "0", "1", … in declaration order. Emitting those as *named* fields
        // used to abort the emitter, because `0` is not an identifier — the SDK
        // `test_udt` fixture (`UdtTuple -> ['0', '1']`) crashed `dump-rust`.
        let reg = TypeRegistry {
            structs: vec![StructDef {
                id: TypeId::new(0),
                name: "UdtTuple".to_string(),
                fields: vec![
                    StructField { name: "0".to_string(), ty: TypeRef::Primitive(PrimitiveType::I64) },
                    StructField { name: "1".to_string(), ty: TypeRef::Primitive(PrimitiveType::U32) },
                ],
            }],
            ..Default::default()
        };
        let out = render(&contract_types(&reg, &StrictNoGuess)[0]);
        assert!(out.contains("pub struct UdtTuple (pub i64 , pub u32 ,)"), "{out}");
        assert!(!out.contains('{'), "must not emit a braced struct body: {out}");
    }

    #[test]
    fn numeric_names_out_of_sequence_stay_a_named_struct() {
        // Only a full 0..n run means "tuple struct". A lone numeric-looking name
        // is some other contract's business and must not be silently reshaped —
        // it falls back to the `_`-prefixed identifier rather than panicking.
        let reg = TypeRegistry {
            structs: vec![StructDef {
                id: TypeId::new(0),
                name: "Odd".to_string(),
                fields: vec![
                    StructField { name: "7".to_string(), ty: TypeRef::Primitive(PrimitiveType::I64) },
                ],
            }],
            ..Default::default()
        };
        let out = render(&contract_types(&reg, &StrictNoGuess)[0]);
        assert!(out.contains("pub struct Odd {"), "{out}");
        assert!(out.contains("pub _7 : i64"), "{out}");
    }

    #[test]
    fn payload_enum_mixes_unit_and_tuple_variants() {
        // The canonical DataKey shape: unit variants and payload variants.
        let reg = TypeRegistry {
            unions: vec![UnionDef {
                id: TypeId::new(1),
                name: "DataKey".to_string(),
                cases: vec![
                    UnionCase {
                        name: "Balance".to_string(),
                        fields: vec![TypeRef::Primitive(PrimitiveType::Address)],
                    },
                    UnionCase { name: "Admin".to_string(), fields: vec![] },
                ],
            }],
            ..Default::default()
        };
        let items = contract_types(&reg, &StrictNoGuess);
        let out = render(&items[0]);
        assert!(out.contains("pub enum DataKey"), "{out}");
        assert!(out.contains("Balance (soroban_sdk :: Address)"), "{out}");
        assert!(out.contains("Admin ,") || out.ends_with("Admin }"), "{out}");
    }

    #[test]
    fn error_enum_carries_repr_and_discriminants() {
        let reg = TypeRegistry {
            errors: vec![EnumDef {
                id: TypeId::new(2),
                name: "TokenError".to_string(),
                cases: vec![
                    EnumCase { name: "InsufficientBalance".to_string(), value: 1 },
                    EnumCase { name: "InsufficientAllowance".to_string(), value: 2 },
                ],
            }],
            ..Default::default()
        };
        let items = contract_types(&reg, &StrictNoGuess);
        let out = render(&items[0]);
        assert!(out.contains("# [contracterror]"), "{out}");
        assert!(out.contains("# [repr (u32)]"), "{out}");
        assert!(out.contains("InsufficientBalance = 1"), "{out}");
    }

    #[test]
    fn every_emitted_item_reparses() {
        // Belt-and-braces: whatever we build must round-trip through syn.
        let reg = TypeRegistry {
            structs: vec![StructDef {
                id: TypeId::new(0),
                name: "Pair".to_string(),
                fields: vec![StructField {
                    name: "items".to_string(),
                    ty: TypeRef::Composite(CompositeType::Vec(Box::new(TypeRef::Primitive(
                        PrimitiveType::I128,
                    )))),
                }],
            }],
            ..Default::default()
        };
        for item in contract_types(&reg, &StrictNoGuess) {
            let text = item.to_token_stream().to_string();
            assert!(syn::parse_str::<syn::Item>(&text).is_ok(), "did not reparse: {text}");
        }
    }
}
