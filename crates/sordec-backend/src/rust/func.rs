//! Per-function emission: `contractspecv0` methods vs synthesized free fns.

use syn::parse_quote;

use sordec_ir::{HighFunction, HighIr, TypeRegistry};

use crate::rust::hole::HolePolicy;
use crate::rust::{body, sig};

/// One function rendered either as a contract method or a free function.
pub(crate) enum Emitted {
    /// A public method for the `#[contractimpl] impl` block.
    Method(Box<syn::ImplItemFn>),
    /// A top-level free function (an internal helper).
    Free(Box<syn::Item>),
}

/// Emit one function. A function present in `contractspecv0`
/// (`signature.is_some()`) becomes a public contract method; every other
/// function becomes a free helper. The body is the region → `syn` walk
/// ([`body::emit_body`]); `high` is needed to resolve call targets to
/// their emitted names.
pub(crate) fn emit_function(
    high: &HighIr,
    func: &HighFunction,
    reg: &TypeRegistry,
    policy: &dyn HolePolicy,
) -> Vec<Emitted> {
    let block = body::emit_body(high, func, reg, policy);
    if func.signature.is_none() {
        let signature = sig::helper_signature(func, reg, policy);
        return vec![Emitted::Free(Box::new(parse_quote!(#signature #block)))];
    }
    let signature = sig::spec_signature(func, reg, policy);
    let mut out = vec![Emitted::Method(Box::new(parse_quote!(pub #signature #block)))];
    // One method per name the linker merged onto this body. The source
    // wrote each of them separately, so emitting one and dropping the rest
    // loses entrypoints the contract really has; the body is shared
    // because it is genuinely identical.
    for alias in &func.aliases {
        let signature = sig::spec_signature_of(alias, func, reg, policy);
        let block = block.clone();
        out.push(Emitted::Method(Box::new(parse_quote!(pub #signature #block))));
    }
    out
}
