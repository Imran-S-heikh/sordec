//! Per-function emission: `contractspecv0` methods vs synthesized free fns.

use syn::parse_quote;

use sordec_ir::{HighFunction, TypeRegistry};

use crate::rust::hole::HolePolicy;
use crate::rust::sig;

/// One function rendered either as a contract method or a free function.
pub(crate) enum Emitted {
    /// A public method for the `#[contractimpl] impl` block.
    Method(Box<syn::ImplItemFn>),
    /// A top-level free function (an internal helper).
    Free(Box<syn::Item>),
}

/// Emit one function. A function present in `contractspecv0`
/// (`signature.is_some()`) becomes a public contract method; every other
/// function becomes a free helper.
///
/// W1 bodies are uniformly `todo!()` — this is the single site the W2
/// region → expression walk replaces. `todo!()` types as `!` and coerces
/// to any return type, so the skeleton is already shape-correct.
pub(crate) fn emit_function(
    func: &HighFunction,
    reg: &TypeRegistry,
    policy: &dyn HolePolicy,
) -> Emitted {
    match &func.signature {
        Some(spec) => {
            let signature = sig::spec_signature(spec, reg, policy);
            Emitted::Method(Box::new(parse_quote! {
                pub #signature {
                    todo!()
                }
            }))
        }
        None => {
            let signature = sig::helper_signature(func, reg, policy);
            Emitted::Free(Box::new(parse_quote! {
                #signature {
                    todo!()
                }
            }))
        }
    }
}
