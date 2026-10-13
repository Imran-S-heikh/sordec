//! The argument vector of a cross-contract call, elided once its
//! elements are known.
//!
//! # The shape
//!
//! The source writes one line:
//!
//! ```ignore
//! token::Client::new(&e, &token).transfer(&from, &to, &amount);
//! ```
//!
//! The host takes its arguments as a single `VecObject`, so
//! `#[contractclient]` builds one: it writes each argument into a slab
//! of the shadow stack and hands the host a pointer and a length.
//! Reconstructed literally that is a dozen stores and a vector
//! constructor wrapped around a call whose arguments we have already
//! named:
//!
//! ```ignore
//! store fp+24 <- from;  store fp+32 <- to;  store fp+40 <- amount;
//! let v53 = vec_new(val_encode(fp + 24), val_encode(3));
//! invoke_contract(token, "transfer", [from, to, amount])
//! ```
//!
//! The last line is already right — [`crate::recognizers::client_call`]
//! proved each element from the slot the caller stored, and the emitter
//! spells the call from those rather than from `v53`. So everything
//! above it produces a value the output no longer reads.
//!
//! On timelock that is eighteen of the transfer wrapper's holes, and
//! what is left of the wrapper is the one line the source wrote.
//!
//! # Why this is sound
//!
//! Same relocation argument as [`super::key_construction`], one host
//! call along. The reconstruction emits `Client::transfer(&from, &to,
//! &amount)` inside a module that declares the client, and the
//! generated method rebuilds this exact vector from those exact
//! arguments. The construction is regenerated, not dropped.
//!
//! What licenses it is that the elements are *resolved*. `resolved_args`
//! is all-or-nothing by design — the recognizer records `Some` only when
//! every element was proven — so a `Some` means the emitted argument
//! list is those same values rather than a guess. A call whose arguments
//! were not all recovered keeps its vector, because that vector is then
//! the only place the arguments exist.
//!
//! # What it does not touch
//!
//! Only the vector constructor itself. The stores that filled the slab
//! become unread once it goes, and retiring an unread frame store is
//! [`super::dead_store`]'s job — they share a fixpoint group, so the
//! slab goes with it without this pass having to reason about aliasing.
//! The argument values are deliberately untouched: they are what the
//! emitted call renders.

use sordec_common::{Provenance, ProvenanceSource, ValueId};
use sordec_ir::{Expr, HighFunction, HighIr, KnownOp, Literal, SemanticOp, VecOpKind};

use crate::dataflow::resolve_use;
use crate::metrics_catalog::MARSHALLING_CLIENT_ARG_VECS as M_VECS;
use crate::pass::{Pass, PassResult};

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-client-args";

/// Elides the argument vector of a fully-resolved cross-contract call.
#[derive(Debug, Default, Clone, Copy)]
pub struct ClientArgVecPass;

impl Pass<HighIr> for ClientArgVecPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        for func in &mut ir.functions {
            for vec in resolved_arg_vectors(func) {
                let Some(binding) = func.bindings.get_mut(vec) else {
                    continue;
                };
                binding.expr = Expr::Literal(Literal::Unit);
                binding.add_provenance(Provenance::new(
                    PASS_NAME,
                    ProvenanceSource::SdkPattern,
                    "argument vector of a cross-contract call whose arguments are \
                     recovered: the generated client method rebuilds it",
                ));
                result.metrics.increment(M_VECS, 1);
                result.changed = true;
            }
        }
        result
    }
}

/// Every still-live argument vector belonging to a call whose arguments
/// are all recovered.
fn resolved_arg_vectors(func: &HighFunction) -> Vec<ValueId> {
    let mut found: Vec<ValueId> = func
        .bindings
        .iter()
        .filter_map(|(_, binding)| {
            let (args, resolved) = match &binding.expr {
                Expr::Semantic(SemanticOp::Known(KnownOp::InvokeContract {
                    args,
                    resolved_args,
                    ..
                }))
                | Expr::Semantic(SemanticOp::Known(KnownOp::TryInvokeContract {
                    args,
                    resolved_args,
                    ..
                })) => (args, resolved_args),
                _ => None?,
            };
            resolved.as_ref()?;
            let vec = resolve_use(func, *args.first()?);
            // Only a constructor. A vector that arrived some other way
            // — a parameter, a host result — is not this pass's to
            // retire, and would take a real value with it. The host's
            // empty `vec_new()` is the constructor of a call with no
            // arguments: nothing to store, so no slab and no pointer.
            matches!(
                func.bindings.get(vec).map(|b| &b.expr),
                Some(Expr::Semantic(SemanticOp::Known(
                    KnownOp::VecNew { .. } | KnownOp::VecOp { kind: VecOpKind::New, .. }
                )))
            )
            .then_some(vec)
        })
        .collect();
    found.sort_unstable();
    found.dedup();
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, module, v};

    /// `vec_new` feeding an `invoke_contract`, with the elements either
    /// recovered or not.
    fn call(resolved: bool) -> HighIr {
        module(vec![func_with(
            vec![
                Expr::Phi { incoming: vec![] }, // v0 contract
                Expr::Phi { incoming: vec![] }, // v1 function symbol
                Expr::Phi { incoming: vec![] }, // v2 an argument
                Expr::Semantic(SemanticOp::Known(KnownOp::VecNew {
                    vals_pos: v(2),
                    len: v(2),
                    elements: None,
                })), // v3
                Expr::Semantic(SemanticOp::Known(KnownOp::InvokeContract {
                    contract: v(0),
                    function: v(1),
                    resolved_callee: Some("transfer".to_owned()),
                    arg_count: Some(1),
                    resolved_args: resolved.then(|| vec![v(2)]),
                    interface: None,
                    args: vec![v(3)],
                })), // v4
            ],
            vec![v(0), v(1), v(2)],
            vec![3, 4],
        )])
    }

    #[test]
    fn a_recovered_argument_list_retires_its_vector() {
        let mut m = call(true);
        assert!(ClientArgVecPass.run(&mut m).changed);
        assert!(matches!(
            m.functions[0].bindings.get(v(3)).expect("the vector").expr,
            Expr::Literal(Literal::Unit)
        ));
    }

    /// Unrecovered arguments live only in the vector, so it stays.
    #[test]
    fn an_unrecovered_argument_list_keeps_its_vector() {
        let mut m = call(false);
        assert!(!ClientArgVecPass.run(&mut m).changed);
    }

    #[test]
    fn the_pass_is_idempotent() {
        let mut m = call(true);
        assert!(ClientArgVecPass.run(&mut m).changed);
        assert!(!ClientArgVecPass.run(&mut m).changed);
    }
}
