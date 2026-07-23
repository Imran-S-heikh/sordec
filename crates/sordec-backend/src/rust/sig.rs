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
use sordec_ir::{HighFunction, TypeRef, TypeRegistry};

use crate::rust::hole::HolePolicy;
use crate::rust::ty::{ident, ir_type, type_ref};

/// The parameter identifiers of a function, in order: the recovered names
/// for a `contractspecv0` function, positional `arg{i}` for an internal
/// helper. The single source of parameter names — signature emission and
/// the body's value naming both consume it, so a parameter's name in the
/// signature and its name in the body cannot drift.
pub(crate) fn param_idents(func: &HighFunction) -> Vec<syn::Ident> {
    match &func.signature {
        Some(sig) => sig.inputs.iter().map(|p| ident(&p.name)).collect(),
        None => (0..func.params.len())
            .map(|i| ident(&format!("arg{i}")))
            .collect(),
    }
}

/// `fn name(p: T, …) -> R` for a `contractspecv0` function.
pub(crate) fn spec_signature(
    func: &HighFunction,
    reg: &TypeRegistry,
    policy: &dyn HolePolicy,
) -> syn::Signature {
    let sig = func
        .signature
        .as_ref()
        .expect("spec_signature requires a contractspec signature");
    let name = ident(&sig.name);
    let params: Vec<_> = param_idents(func)
        .iter()
        .zip(&sig.inputs)
        .map(|(pn, p)| {
            let pt = type_ref(&p.ty, reg, policy);
            quote!(#pn: #pt)
        })
        .collect();
    let env = env_param();
    match spec_return(&sig.outputs, reg, policy) {
        Some(ret) => parse_quote!(fn #name(#env, #(#params),*) -> #ret),
        None => parse_quote!(fn #name(#env, #(#params),*)),
    }
}

/// The synthesized leading `e: Env` parameter every emitted function
/// carries. Host operations reach the `Env` through the VM, so it is not a
/// WASM argument and never appears in the IR — the emitter supplies it, and
/// the body walk roots every host idiom on it. Fully qualified so no import
/// is required.
fn env_param() -> proc_macro2::TokenStream {
    quote!(e: soroban_sdk::Env)
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
        .zip(param_idents(func))
        .map(|(vid, pn)| {
            let pt = value_type(func, *vid, reg, policy);
            quote!(#pn: #pt)
        })
        .collect();
    let env = env_param();
    match helper_return(func, reg, policy) {
        Some(ret) => parse_quote!(fn #name(#env, #(#params),*) -> #ret),
        None => parse_quote!(fn #name(#env, #(#params),*)),
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
