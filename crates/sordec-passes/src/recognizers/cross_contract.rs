//! The Soroban cross-contract call recognizer (`d` module).
//!
//! The `d` (call) module has exactly two functions, both with the ABI
//! signature `(contract: AddressObject, func: Symbol, args: VecObject)
//! -> Val`:
//!
//! - `(d, _)` `call` — `env.invoke_contract(...)`; traps on failure.
//! - `(d, 0)` `try_call` — `env.try_invoke_contract(...)`; returns the
//!   callee's error as a `Val` instead of trapping.
//!
//! Both rewrite into the pre-existing [`KnownOp::InvokeContract`] /
//! [`KnownOp::TryInvokeContract`] vocabulary. ABI-proven recognition:
//! `Known` certainty, `HostFunctionAbi` provenance.
//!
//! ## What it does NOT do
//!
//! - **No callee naming.** `function` is a runtime `Symbol` `ValueId`;
//!   on real contracts the symbol constant threads through phi chains
//!   and helpers, so naming the callee textually (`token.transfer(...)`)
//!   is the constant-propagation engine's scope.
//! - **No argument expansion.** The `args` field holds the single
//!   `VecObject` handle (same posture as `RequireAuthForArgs` /
//!   `PublishEvent.topics`); expanding it into the underlying argument
//!   list needs vec-construction tracing.

use sordec_common::{ProvenanceSource, ValueId};
use sordec_ir::{Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, SemanticOp};

use super::{apply_rewrites, is_recognized, Rewrite};
use crate::pass::{Pass, PassMetrics, PassResult};

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "cross-contract";

// Per-op metric counter keys.
const M_INVOKE: &str = "invoke_contract";
const M_TRY_INVOKE: &str = "try_invoke_contract";

/// The cross-contract call recognizer. Stateless.
#[derive(Debug, Default, Clone, Copy)]
pub struct CrossContractPass;

impl Pass<HighIr> for CrossContractPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        for func in &mut ir.functions {
            let (changed, metrics) = recognize_function(func);
            result.changed |= changed;
            for (key, value) in metrics.iter() {
                result.metrics.increment(key, value);
            }
        }
        result
    }
}

fn recognize_function(func: &mut HighFunction) -> (bool, PassMetrics) {
    let mut metrics = PassMetrics::new();
    let mut rewrites: Vec<Rewrite> = Vec::new();

    for (id, binding) in func.bindings.iter() {
        if is_recognized(&binding.expr) {
            continue;
        }
        let Some(rewrite) = try_cross_contract(id, &binding.expr) else {
            continue;
        };
        metrics.increment(rewrite.metric, 1);
        rewrites.push(rewrite);
    }

    let changed = !rewrites.is_empty();
    apply_rewrites(func, PASS_NAME, rewrites);
    (changed, metrics)
}

/// Match a `d`-module host call and build its rewrite. Both functions
/// take exactly `(contract, func_symbol, args_vec)`; wrong arity is
/// malformed IR and stays unrecognized.
fn try_cross_contract(id: ValueId, expr: &Expr) -> Option<Rewrite> {
    let Expr::Semantic(SemanticOp::Unknown {
        host_module,
        host_fn,
        args,
        ..
    }) = expr
    else {
        return None;
    };
    if host_module != "d" {
        return None;
    }

    let (op, name, metric) = match (host_fn.as_str(), args.len()) {
        ("_", 3) => (
            KnownOp::InvokeContract {
                contract: args[0],
                function: args[1],
                // The single VecObject handle, pending expansion.
                args: vec![args[2]],
                // Filled by the const-prop engine when the symbol
                // constant is reachable.
                resolved_callee: None,
                // Filled by the client-call pass when the args-vec
                // construction is provable.
                arg_count: None,
                resolved_args: None,
                interface: None,
            },
            "call",
            M_INVOKE,
        ),
        ("0", 3) => (
            KnownOp::TryInvokeContract {
                contract: args[0],
                function: args[1],
                args: vec![args[2]],
                resolved_callee: None,
                arg_count: None,
                resolved_args: None,
                interface: None,
            },
            "try_call",
            M_TRY_INVOKE,
        ),
        _ => return None,
    };

    Some(Rewrite {
        id,
        expr: Expr::Semantic(SemanticOp::Known(op)),
        // Both are declared `-> Val` upstream (the callee's return).
        ty: Some(IrType::Known(KnownType::Val)),
        source: ProvenanceSource::HostFunctionAbi,
        note: format!("cross-contract {name}"),
        metric,
    })
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{Arena, BlockId, FuncId, IrId, Provenance, UnknownReason};
    use sordec_ir::{Binding, HighBlock, Literal, Region};

    fn func_with(exprs: Vec<Expr>) -> HighFunction {
        let mut bindings: Arena<ValueId, Binding> = Arena::new();
        for expr in exprs {
            let id = ValueId::from_index(bindings.len() as u32);
            bindings.push(Binding::new(
                id,
                IrType::Unknown(UnknownReason::InsufficientEvidence),
                expr,
                Provenance::new("seed", ProvenanceSource::DataFlow, "seed"),
            ));
        }
        let mut blocks: Arena<BlockId, HighBlock> = Arena::new();
        blocks.push(HighBlock {
            id: BlockId::from_index(0),
            bindings: vec![],
        });
        HighFunction {
            id: FuncId::from_index(0),
            name: None,
            signature: None,
            blocks,
            bindings,
            region: Region::Unreachable,
            params: vec![],
            returns: vec![],
        }
    }

    fn v(i: u32) -> ValueId {
        ValueId::from_index(i)
    }

    fn val(n: i64) -> Expr {
        Expr::Literal(Literal::I64(n))
    }

    fn host(module: &str, name: &str, args: Vec<ValueId>) -> Expr {
        Expr::Semantic(SemanticOp::Unknown {
            host_module: module.to_string(),
            host_fn: name.to_string(),
            args,
            reason: UnknownReason::UnsupportedPattern,
        })
    }

    fn run(func: &mut HighFunction) -> (bool, PassMetrics) {
        recognize_function(func)
    }

    fn expr_at(func: &HighFunction, id: ValueId) -> &Expr {
        &func.bindings.get(id).unwrap().expr
    }

    #[test]
    fn call_recognized_as_invoke_contract() {
        // (contract, func_symbol, args_vec) → InvokeContract.
        let mut func = func_with(vec![
            val(0),
            val(1),
            val(2),
            host("d", "_", vec![v(0), v(1), v(2)]),
        ]);
        let (changed, metrics) = run(&mut func);
        assert!(changed);
        assert_eq!(metrics.get(M_INVOKE), Some(1));
        match expr_at(&func, v(3)) {
            Expr::Semantic(SemanticOp::Known(KnownOp::InvokeContract {
                contract,
                function,
                args,
                resolved_callee,
                arg_count: None,
                resolved_args: None,
                interface: None,
            })) => {
                assert_eq!(*resolved_callee, None, "recognition never names");
                assert_eq!(*contract, v(0));
                assert_eq!(*function, v(1));
                // The single VecObject handle, pending expansion.
                assert_eq!(args, &[v(2)]);
            }
            other => panic!("expected InvokeContract, got {other:?}"),
        }
        assert_eq!(
            func.bindings.get(v(3)).unwrap().ty,
            IrType::Known(KnownType::Val)
        );
    }

    #[test]
    fn try_call_recognized_as_try_invoke_contract() {
        let mut func = func_with(vec![
            val(0),
            val(1),
            val(2),
            host("d", "0", vec![v(0), v(1), v(2)]),
        ]);
        let (changed, metrics) = run(&mut func);
        assert!(changed);
        assert_eq!(metrics.get(M_TRY_INVOKE), Some(1));
        assert!(matches!(
            expr_at(&func, v(3)),
            Expr::Semantic(SemanticOp::Known(KnownOp::TryInvokeContract { .. }))
        ));
    }

    #[test]
    fn wrong_arity_not_recognized() {
        let mut func = func_with(vec![val(0), val(1), host("d", "_", vec![v(0), v(1)])]);
        let (changed, _) = run(&mut func);
        assert!(!changed);
    }

    #[test]
    fn unknown_d_export_not_recognized() {
        let mut func = func_with(vec![val(0), val(1), val(2), host("d", "9", vec![v(0), v(1), v(2)])]);
        let (changed, _) = run(&mut func);
        assert!(!changed);
    }

    #[test]
    fn non_d_module_untouched() {
        let mut func = func_with(vec![val(0), val(1), val(2), host("l", "_", vec![v(0), v(1), v(2)])]);
        let (changed, _) = run(&mut func);
        assert!(!changed);
    }

    #[test]
    fn second_run_reports_no_change() {
        let mut func = func_with(vec![
            val(0),
            val(1),
            val(2),
            host("d", "_", vec![v(0), v(1), v(2)]),
        ]);
        assert!(run(&mut func).0);
        assert!(!run(&mut func).0, "idempotent on rerun");
    }

    #[test]
    fn provenance_records_source_and_name() {
        let mut func = func_with(vec![
            val(0),
            val(1),
            val(2),
            host("d", "0", vec![v(0), v(1), v(2)]),
        ]);
        run(&mut func);
        let prov = func.bindings.get(v(3)).unwrap().latest_provenance();
        assert_eq!(prov.source, ProvenanceSource::HostFunctionAbi);
        assert!(
            prov.note.contains("cross-contract try_call"),
            "note: {}",
            prov.note
        );
    }
}
