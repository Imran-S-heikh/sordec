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
) -> Emitted {
    let block = body::emit_body(high, func, reg, policy);
    if func.signature.is_some() {
        let signature = sig::spec_signature(func, reg, policy);
        Emitted::Method(Box::new(parse_quote!(pub #signature #block)))
    } else {
        let signature = sig::helper_signature(func, reg, policy);
        Emitted::Free(Box::new(parse_quote!(#signature #block)))
    }
}
