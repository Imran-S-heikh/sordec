//! Function signatures: `contractspecv0` methods and synthesized helpers.
//!
//! A `contractspecv0` function ([`spec_signature`]) is faithful — its name,
//! parameter names, and types are all recorded in the spec. An internal
//! helper ([`helper_signature`]) is synthesized: parameter names are erased
//! by the compiler, so they are positional (`arg0…`), and types come from
//! the recovered binding types (unresolved ones degrade through the
//! [`HolePolicy`]).
//!
//! Neither adds visibility or a body — [`func`](super::func) wraps the
//! signature into a method or free function.

use quote::quote;
use syn::parse_quote;

use sordec_common::{IrId, ValueId};
use sordec_ir::{FunctionSignature, HighFunction, TypeRef, TypeRegistry};

use crate::rust::hole::HolePolicy;
use crate::rust::ty::{ident, ir_type, type_ref};

/// `fn name(p: T, …) -> R` for a `contractspecv0` function.
pub(crate) fn spec_signature(
    sig: &FunctionSignature,
    reg: &TypeRegistry,
    policy: &dyn HolePolicy,
) -> syn::Signature {
    let name = ident(&sig.name);
    let params: Vec<_> = sig
        .inputs
        .iter()
        .map(|p| {
            let pn = ident(&p.name);
            let pt = type_ref(&p.ty, reg, policy);
            quote!(#pn: #pt)
        })
        .collect();
    match spec_return(&sig.outputs, reg, policy) {
        Some(ret) => parse_quote!(fn #name(#(#params),*) -> #ret),
        None => parse_quote!(fn #name(#(#params),*)),
    }
}

/// A synthesized `fn func{id}(arg0: T, …) -> R` for a non-spec function.
pub(crate) fn helper_signature(
    func: &HighFunction,
    reg: &TypeRegistry,
    policy: &dyn HolePolicy,
) -> syn::Signature {
    let name = helper_name(func);
    let params: Vec<_> = func
        .params
        .iter()
        .enumerate()
        .map(|(i, vid)| {
            let pn = ident(&format!("arg{i}"));
            let pt = value_type(func, *vid, reg, policy);
            quote!(#pn: #pt)
        })
        .collect();
    match helper_return(func, reg, policy) {
        Some(ret) => parse_quote!(fn #name(#(#params),*) -> #ret),
        None => parse_quote!(fn #name(#(#params),*)),
    }
}

/// Name for a non-spec function: the recovered export name when it is a
/// valid Rust identifier, else a synthesized `func{id}`. Export names may
/// be non-identifiers — e.g. the SDK's `_` contract-spec accessor — so the
/// synthesized fallback is load-bearing, not cosmetic.
pub(crate) fn helper_name(func: &HighFunction) -> syn::Ident {
    if let Some(name) = &func.name
        && let Ok(id) = syn::parse_str::<syn::Ident>(name)
    {
        return id;
    }
    ident(&format!("func{}", func.id.index()))
}

/// Type of a binding by id, degrading to the [`HolePolicy`] fallback when
/// the id does not resolve (a should-not-happen guard, handled honestly).
fn value_type(
    func: &HighFunction,
    vid: ValueId,
    reg: &TypeRegistry,
    policy: &dyn HolePolicy,
) -> syn::Type {
    match func.bindings.get(vid) {
        Some(b) => ir_type(&b.ty, reg, policy),
        None => policy.unknown_type(None),
    }
}

fn spec_return(
    outputs: &[TypeRef],
    reg: &TypeRegistry,
    policy: &dyn HolePolicy,
) -> Option<syn::Type> {
    match outputs {
        [] => None,
        [one] => Some(type_ref(one, reg, policy)),
        many => {
            let elems: Vec<syn::Type> = many.iter().map(|t| type_ref(t, reg, policy)).collect();
            Some(parse_quote!((#(#elems,)*)))
        }
    }
}

/// Return type from the first return site that carries values. Distinct
/// return sites almost always agree; when they do not, the first is a
/// faithful choice for a `todo!()` skeleton (W2's body walk supersedes it).
fn helper_return(
    func: &HighFunction,
    reg: &TypeRegistry,
    policy: &dyn HolePolicy,
) -> Option<syn::Type> {
    let site = func.returns.iter().find(|vals| !vals.is_empty())?;
    match site.as_slice() {
        [] => None,
        [one] => Some(value_type(func, *one, reg, policy)),
        many => {
            let elems: Vec<syn::Type> =
                many.iter().map(|v| value_type(func, *v, reg, policy)).collect();
            Some(parse_quote!((#(#elems,)*)))
        }
    }
}
