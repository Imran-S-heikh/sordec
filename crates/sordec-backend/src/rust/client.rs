//! The client a cross-contract call is spelled through, declared from the
//! calls themselves.
//!
//! The source called another contract through a generated client —
//! `contract_a::Client::new(&env, &addr).add(&x, &y)` — whose definition
//! came from that contract (`contractimport!`) or from a trait the author
//! wrote (`#[contractclient]`). Neither is in this wasm. What is in it, at
//! every call, is the method's name, the arguments it was handed and the
//! type its result was converted to. That is a method signature, so the
//! reconstruction declares one:
//!
//! ```text
//! #[soroban_sdk::contractclient(name = "ExternalClient")]
//! pub trait External {
//!     fn add(env: Env, x: u32, y: u32) -> u32;
//! }
//! ```
//!
//! and spells each call `ExternalClient::new(&e, &addr).add(&x, &y)`. The
//! generated method rebuilds the argument vector and the result's
//! conversion, which is the marshalling the pipeline elided.
//!
//! ## What qualifies
//!
//! A call whose callee name and every argument are recovered, matched to no
//! known interface (a SEP-41 call keeps `token::Client`), with every argument
//! typed. The return type is the result's type when a recognizer proved it,
//! else `Val`: the method then converts nothing, exactly as an unconverted
//! result was used. A name called with two different signatures is not
//! declared — one trait cannot hold both — and its calls stay holes.

use std::collections::BTreeMap;

use quote::ToTokens;
use sordec_common::ValueId;
use sordec_ir::{Expr, HighFunction, HighIr, IrType, KnownOp, SemanticOp, TypeRegistry};

use crate::rust::hole::HolePolicy;
use crate::rust::ty::{ident, ir_type};

/// The client type the declared trait generates.
pub(crate) const CLIENT: &str = "ExternalClient";
/// The declared trait.
const TRAIT: &str = "External";

/// One method of the declared client.
struct Method {
    params: Vec<(String, syn::Type)>,
    ret: syn::Type,
}

impl Method {
    /// What two call sites must agree on: the types, not the names.
    fn shape(&self) -> String {
        let params: Vec<String> = self.params.iter().map(|(_, t)| t.to_token_stream().to_string()).collect();
        format!("({}) -> {}", params.join(", "), self.ret.to_token_stream())
    }
}

/// Every method the module calls through the declared client, by name.
fn methods(high: &HighIr, reg: &TypeRegistry, policy: &dyn HolePolicy) -> BTreeMap<String, Method> {
    let mut declared: BTreeMap<String, Method> = BTreeMap::new();
    let mut conflicting: Vec<String> = Vec::new();
    for func in &high.functions {
        for (id, binding) in func.bindings.iter() {
            let Expr::Semantic(SemanticOp::Known(KnownOp::InvokeContract {
                resolved_callee: Some(name),
                resolved_args: Some(args),
                interface: None,
                ..
            })) = &binding.expr
            else {
                continue;
            };
            let Some(method) = site(func, id, args, reg, policy) else {
                conflicting.push(name.clone());
                continue;
            };
            match declared.get(name) {
                Some(have) if have.shape() != method.shape() => conflicting.push(name.clone()),
                Some(_) => {}
                None => {
                    declared.insert(name.clone(), method);
                }
            }
        }
    }
    for name in conflicting {
        declared.remove(&name);
    }
    declared
}

/// The signature one call site proves, or `None` when an argument is untyped.
fn site(
    func: &HighFunction,
    call: ValueId,
    args: &[ValueId],
    reg: &TypeRegistry,
    policy: &dyn HolePolicy,
) -> Option<Method> {
    let mut params = Vec::with_capacity(args.len());
    for (i, &arg) in args.iter().enumerate() {
        let ty = &func.bindings.get(arg)?.ty;
        if matches!(ty, IrType::Unknown(_)) {
            return None;
        }
        let fallback = format!("arg{i}");
        let name = param_name(func, arg)
            .filter(|n| n != "env" && params.iter().all(|(have, _): &(String, syn::Type)| have != n))
            .unwrap_or(fallback);
        params.push((name, ir_type(ty, reg, policy)));
    }
    let ret = match &func.bindings.get(call)?.ty {
        IrType::Known(_) => ir_type(&func.bindings.get(call)?.ty, reg, policy),
        _ => syn::parse_quote!(soroban_sdk::Val),
    };
    Some(Method { params, ret })
}

/// The declared name of the caller's parameter an argument is, if it is one.
fn param_name(func: &HighFunction, value: ValueId) -> Option<String> {
    let mut current = value;
    for _ in 0..8 {
        match func.bindings.get(current).map(|b| &b.expr) {
            Some(Expr::Use(inner)) => current = *inner,
            _ => break,
        }
    }
    let index = func.params.iter().position(|p| *p == current)?;
    Some(func.signature.as_ref()?.inputs.get(index)?.name.clone())
}

/// Whether calls to `name` are spelled through the declared client.
pub(crate) fn declares(high: &HighIr, reg: &TypeRegistry, policy: &dyn HolePolicy, name: &str) -> bool {
    methods(high, reg, policy).contains_key(name)
}

/// The declared client trait, or `None` when nothing calls through it.
pub(crate) fn trait_item(high: &HighIr, reg: &TypeRegistry, policy: &dyn HolePolicy) -> Option<syn::Item> {
    let methods = methods(high, reg, policy);
    if methods.is_empty() {
        return None;
    }
    let fns: Vec<syn::TraitItem> = methods
        .iter()
        .map(|(name, m)| {
            let name = ident(name);
            let params = m.params.iter().map(|(n, t)| {
                let n = ident(n);
                quote::quote!(#n: #t)
            });
            let ret = &m.ret;
            // A unit return is written as the source writes it: not at all.
            if matches!(ret, syn::Type::Tuple(t) if t.elems.is_empty()) {
                syn::parse_quote!(fn #name(env: soroban_sdk::Env, #(#params),*);)
            } else {
                syn::parse_quote!(fn #name(env: soroban_sdk::Env, #(#params),*) -> #ret;)
            }
        })
        .collect();
    let trait_name = ident(TRAIT);
    let client = CLIENT;
    Some(syn::parse_quote! {
        #[soroban_sdk::contractclient(name = #client)]
        pub trait #trait_name {
            #(#fns)*
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{Arena, BlockId, FuncId, IrId, Provenance, ProvenanceSource};
    use sordec_ir::{
        Binding, FunctionParam, FunctionSignature, HighBlock, HighFunction, KnownType, MemoryImage, PrimitiveType,
        Region, TypeRef, WasmFacts,
    };

    use crate::rust::hole::StrictNoGuess;

    fn v(i: u32) -> ValueId {
        ValueId::from_index(i)
    }

    /// `fn caller(x: u32)` calling `add(x)` on another contract; the result
    /// typed `ret`.
    fn caller(id: u32, ret: IrType) -> HighFunction {
        let mut bindings: Arena<ValueId, Binding> = Arena::new();
        let exprs = [
            (Expr::Phi { incoming: vec![] }, IrType::Known(KnownType::Address)), // v0 contract
            (Expr::Phi { incoming: vec![] }, IrType::Known(KnownType::U32)),     // v1 x
            (
                Expr::Semantic(SemanticOp::Known(KnownOp::InvokeContract {
                    contract: v(0),
                    function: v(0),
                    resolved_callee: Some("add".to_string()),
                    arg_count: Some(1),
                    resolved_args: Some(vec![v(1)]),
                    interface: None,
                    args: vec![],
                })),
                ret,
            ),
        ];
        for (expr, ty) in exprs {
            let id = ValueId::from_index(bindings.len() as u32);
            bindings.push(Binding::new(id, ty, expr, Provenance::new("seed", ProvenanceSource::DataFlow, "seed")));
        }
        let mut blocks: Arena<BlockId, HighBlock> = Arena::new();
        blocks.push(HighBlock { id: BlockId::from_index(0), bindings: vec![v(2)] });
        HighFunction {
            id: FuncId::from_index(id),
            name: None,
            signature: Some(FunctionSignature {
                name: "caller".to_string(),
                inputs: ["contract", "x"]
                    .map(|n| FunctionParam { name: n.to_string(), ty: TypeRef::Primitive(PrimitiveType::U32) })
                    .to_vec(),
                outputs: vec![],
            }),
            aliases: Vec::new(),
            blocks,
            bindings,
            region: Region::Basic(BlockId::from_index(0)),
            params: vec![v(0), v(1)],
            returns: vec![],
        }
    }

    fn module(functions: Vec<HighFunction>) -> HighIr {
        HighIr {
            facts: WasmFacts {
                imports: vec![],
                exports: vec![],
                function_type_indices: vec![],
                function_bodies: vec![],
                function_fingerprints: vec![],
                table_functions: None,
                custom_sections: vec![],
            },
            soroban_facts: None,
            functions,
            memory: MemoryImage::empty(),
        }
    }

    #[test]
    fn a_call_declares_its_method_with_the_caller_s_names() {
        let high = module(vec![caller(0, IrType::Known(KnownType::U32))]);
        let item = trait_item(&high, &TypeRegistry::default(), &StrictNoGuess).expect("a client");
        let text = item.to_token_stream().to_string();
        assert!(text.contains("fn add (env : soroban_sdk :: Env , x : u32) -> u32"), "{text}");
        assert!(declares(&high, &TypeRegistry::default(), &StrictNoGuess, "add"));
    }

    #[test]
    fn an_unproven_result_is_a_val() {
        let high = module(vec![caller(0, IrType::Inferred(KnownType::U32))]);
        let text = trait_item(&high, &TypeRegistry::default(), &StrictNoGuess).expect("a client").to_token_stream().to_string();
        assert!(text.contains("-> soroban_sdk :: Val"), "{text}");
    }

    #[test]
    fn two_signatures_for_one_name_declare_nothing() {
        let high = module(vec![
            caller(0, IrType::Known(KnownType::U32)),
            caller(1, IrType::Known(KnownType::Address)),
        ]);
        assert!(trait_item(&high, &TypeRegistry::default(), &StrictNoGuess).is_none());
        assert!(!declares(&high, &TypeRegistry::default(), &StrictNoGuess, "add"));
    }
}
