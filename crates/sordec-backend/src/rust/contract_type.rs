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

use sordec_ir::{EnumDef, EventDef, StructDef, TypeRegistry, UnionDef};

use crate::rust::hole::HolePolicy;
use crate::rust::ty::{ident, type_ref};

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
/// parameters. Topic/data placement ([`EventParamLocation`]) and the
/// declared `data_format` are recorded in the IR but not yet re-expressed
/// here — full event fidelity is a later refinement (category S). The
/// skeleton is a faithful, parseable field list.
///
/// [`EventParamLocation`]: sordec_ir::EventParamLocation
fn event_item(def: &EventDef, reg: &TypeRegistry, policy: &dyn HolePolicy) -> syn::Item {
    let name = ident(&def.name);
    let fields = def.params.iter().map(|p| {
        let pname = ident(&p.name);
        let pty = type_ref(&p.ty, reg, policy);
        quote!(pub #pname: #pty)
    });
    parse_quote! {
        #[contractevent]
        pub struct #name {
            #(#fields,)*
        }
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
