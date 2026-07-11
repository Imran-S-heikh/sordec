//! C15 (+C14, +C16-partial) — the Soroban context recognizer.
//!
//! Recognizes the `x`-module (context) host-call surface: ledger
//! accessors, the current-contract-address query, event emission
//! (`contract_event`), the host `Val` comparison, and the
//! `fail_with_error` panic primitive. Every recognition is ABI-proven
//! — the host-function identity *is* the semantic — so bindings carry
//! `Known` certainty and `HostFunctionAbi` provenance.
//!
//! This one pass covers three kickoff items that all live in the `x`
//! module: **C15 (context)** in full, **C14 (event emission)** at the
//! recognition layer (all three SDK event flavors — raw `publish`, v22
//! `TokenUtils`, v23 `#[contractevent]` — compile to the same
//! `contract_event` host call; the flavor distinction is a Phase-3 emit
//! concern), and **C16's `fail_with_error` 1:1 recognition**.
//!
//! ## What it does NOT do
//!
//! - No `log_from_linear_memory` (x._) — needs a rodata tracer + a
//!   heterogeneous `Val`-array reconstruction; deferred, and absent
//!   from the corpus.
//! - No event-topic vec expansion — `PublishEvent.topics` holds the
//!   single `VecObject` handle; the collections recognizer expands it.
//! - No full panic recovery — only the `fail_with_error(code)` host
//!   call; bare `panic!()` (control-flow `unreachable`) and formatted
//!   panics are the separate panic recognizer's scope.
//! - No `Ord`/`<` reconstruction from `obj_cmp` — `ValCompare` names
//!   the primitive; branch-context reconstruction is a later
//!   refinement.

use sordec_common::{ProvenanceSource, ValueId};
use sordec_ir::{Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, SemanticOp};

use super::{apply_rewrites, is_recognized, Rewrite};
use crate::pass::{Pass, PassMetrics, PassResult};

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "context";

// Per-op metric counter keys.
const M_GET_CURRENT_CONTRACT_ADDRESS: &str = "get_current_contract_address";
const M_LEDGER_CONTEXT: &str = "ledger_context";
const M_PUBLISH_EVENT: &str = "publish_event";
const M_VAL_COMPARE: &str = "val_compare";
const M_PANIC_WITH_ERROR: &str = "panic_with_error";

/// The C15 context recognizer. Stateless.
#[derive(Debug, Default, Clone, Copy)]
pub struct ContextPass;

impl Pass<HighIr> for ContextPass {
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
        if let Some(rw) = try_context(id, &binding.expr) {
            rewrites.push(rw);
        }
    }

    let changed = !rewrites.is_empty();
    for rw in &rewrites {
        metrics.increment(rw.metric, 1);
    }
    apply_rewrites(func, PASS_NAME, rewrites);
    (changed, metrics)
}

/// Match an `x`-module host call and build its rewrite. Arity-guarded;
/// wrong arity, the deferred `log` call, or a non-`x` / unknown export
/// yields `None`, leaving the binding as `SemanticOp::Unknown`.
fn try_context(id: ValueId, expr: &Expr) -> Option<Rewrite> {
    let Expr::Semantic(SemanticOp::Unknown {
        host_module,
        host_fn,
        args,
        ..
    }) = expr
    else {
        return None;
    };
    if host_module != "x" {
        return None;
    }

    let (op, ty, metric, note): (KnownOp, KnownType, &'static str, &'static str) =
        match (host_fn.as_str(), args.len()) {
            ("0", 2) => (
                KnownOp::ValCompare {
                    a: args[0],
                    b: args[1],
                },
                KnownType::I64,
                M_VAL_COMPARE,
                "context obj_cmp",
            ),
            ("1", 2) => (
                KnownOp::PublishEvent {
                    // Single VecObject handle; collections recognizer
                    // expands it into the topic list later.
                    topics: vec![args[0]],
                    data: args[1],
                },
                KnownType::Unit,
                M_PUBLISH_EVENT,
                "context contract_event",
            ),
            // `get_ledger_version` is Soroban's protocol version.
            ("2", 0) => (
                KnownOp::GetLedgerProtocolVersion,
                KnownType::U32,
                M_LEDGER_CONTEXT,
                "context get_ledger_version",
            ),
            ("3", 0) => (
                KnownOp::GetLedgerSequence,
                KnownType::U32,
                M_LEDGER_CONTEXT,
                "context get_ledger_sequence",
            ),
            ("4", 0) => (
                KnownOp::GetLedgerTimestamp,
                KnownType::U64,
                M_LEDGER_CONTEXT,
                "context get_ledger_timestamp",
            ),
            ("5", 1) => (
                KnownOp::PanicWithError { error: args[0] },
                KnownType::Unit,
                M_PANIC_WITH_ERROR,
                "context fail_with_error",
            ),
            ("6", 0) => (
                KnownOp::GetLedgerNetworkId,
                KnownType::Bytes,
                M_LEDGER_CONTEXT,
                "context get_ledger_network_id",
            ),
            ("7", 0) => (
                KnownOp::GetCurrentContractAddress,
                KnownType::Address,
                M_GET_CURRENT_CONTRACT_ADDRESS,
                "context get_current_contract_address",
            ),
            ("8", 0) => (
                KnownOp::GetMaxLiveUntilLedger,
                KnownType::U32,
                M_LEDGER_CONTEXT,
                "context get_max_live_until_ledger",
            ),
            // `_` (log_from_linear_memory) is deferred; wrong arity or
            // unknown export is malformed / out-of-scope.
            _ => return None,
        };

    Some(Rewrite {
        id,
        expr: Expr::Semantic(SemanticOp::Known(op)),
        ty: Some(IrType::Known(ty)),
        source: ProvenanceSource::HostFunctionAbi,
        note: note.to_string(),
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

    fn i64c(n: i64) -> Expr {
        Expr::Literal(Literal::I64(n))
    }

    fn host_x(name: &str, args: Vec<ValueId>) -> Expr {
        Expr::Semantic(SemanticOp::Unknown {
            host_module: "x".to_string(),
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

    fn ty_at(func: &HighFunction, id: ValueId) -> IrType {
        func.bindings.get(id).unwrap().ty.clone()
    }

    // --- ledger accessors (nullary) ---

    #[test]
    fn get_current_contract_address_recognized() {
        let mut func = func_with(vec![host_x("7", vec![])]);
        let (changed, metrics) = run(&mut func);
        assert!(changed);
        assert_eq!(metrics.get(M_GET_CURRENT_CONTRACT_ADDRESS), Some(1));
        assert!(matches!(
            expr_at(&func, v(0)),
            Expr::Semantic(SemanticOp::Known(KnownOp::GetCurrentContractAddress))
        ));
        assert_eq!(ty_at(&func, v(0)), IrType::Known(KnownType::Address));
    }

    #[test]
    fn ledger_accessors_map_and_type() {
        // (export, expected KnownOp discriminant via ty, expected ty)
        let cases: &[(&str, KnownType)] = &[
            ("2", KnownType::U32),   // get_ledger_version -> protocol version
            ("3", KnownType::U32),   // get_ledger_sequence
            ("4", KnownType::U64),   // get_ledger_timestamp
            ("6", KnownType::Bytes), // get_ledger_network_id
            ("8", KnownType::U32),   // get_max_live_until_ledger
        ];
        for (export, ty) in cases {
            let mut func = func_with(vec![host_x(export, vec![])]);
            let (changed, metrics) = run(&mut func);
            assert!(changed, "export {export} should be recognized");
            assert_eq!(metrics.get(M_LEDGER_CONTEXT), Some(1), "export {export}");
            assert_eq!(ty_at(&func, v(0)), IrType::Known(ty.clone()), "export {export}");
        }
    }

    #[test]
    fn get_ledger_version_maps_to_protocol_version() {
        let mut func = func_with(vec![host_x("2", vec![])]);
        run(&mut func);
        assert!(matches!(
            expr_at(&func, v(0)),
            Expr::Semantic(SemanticOp::Known(KnownOp::GetLedgerProtocolVersion))
        ));
    }

    // --- events ---

    #[test]
    fn contract_event_maps_to_publish_event() {
        // v0 topics-vec handle; v1 data; v2 = contract_event(v0, v1)
        let mut func = func_with(vec![i64c(0), i64c(0), host_x("1", vec![v(0), v(1)])]);
        let (changed, metrics) = run(&mut func);
        assert!(changed);
        assert_eq!(metrics.get(M_PUBLISH_EVENT), Some(1));
        match expr_at(&func, v(2)) {
            Expr::Semantic(SemanticOp::Known(KnownOp::PublishEvent { topics, data })) => {
                assert_eq!(topics.as_slice(), &[v(0)], "single VecObject handle");
                assert_eq!(*data, v(1));
            }
            other => panic!("expected PublishEvent, got {other:?}"),
        }
        assert_eq!(ty_at(&func, v(2)), IrType::Known(KnownType::Unit));
    }

    // --- comparison + panic ---

    #[test]
    fn obj_cmp_maps_to_val_compare_i64() {
        let mut func = func_with(vec![i64c(0), i64c(0), host_x("0", vec![v(0), v(1)])]);
        let (changed, metrics) = run(&mut func);
        assert!(changed);
        assert_eq!(metrics.get(M_VAL_COMPARE), Some(1));
        match expr_at(&func, v(2)) {
            Expr::Semantic(SemanticOp::Known(KnownOp::ValCompare { a, b })) => {
                assert_eq!(*a, v(0));
                assert_eq!(*b, v(1));
            }
            other => panic!("expected ValCompare, got {other:?}"),
        }
        assert_eq!(ty_at(&func, v(2)), IrType::Known(KnownType::I64));
    }

    #[test]
    fn fail_with_error_maps_to_panic_with_error() {
        let mut func = func_with(vec![i64c(0), host_x("5", vec![v(0)])]);
        let (changed, metrics) = run(&mut func);
        assert!(changed);
        assert_eq!(metrics.get(M_PANIC_WITH_ERROR), Some(1));
        match expr_at(&func, v(1)) {
            Expr::Semantic(SemanticOp::Known(KnownOp::PanicWithError { error })) => {
                assert_eq!(*error, v(0));
            }
            other => panic!("expected PanicWithError, got {other:?}"),
        }
        assert_eq!(ty_at(&func, v(1)), IrType::Known(KnownType::Unit));
    }

    // --- non-matches ---

    #[test]
    fn log_from_linear_memory_deferred() {
        // x._ (log) is deferred — left unrecognized.
        let mut func = func_with(vec![
            i64c(0),
            i64c(0),
            i64c(0),
            i64c(0),
            host_x("_", vec![v(0), v(1), v(2), v(3)]),
        ]);
        let (changed, _) = run(&mut func);
        assert!(!changed, "log_from_linear_memory is deferred");
    }

    #[test]
    fn nullary_accessor_with_arg_not_recognized() {
        // get_current_contract_address with a spurious arg → malformed.
        let mut func = func_with(vec![i64c(0), host_x("7", vec![v(0)])]);
        let (changed, _) = run(&mut func);
        assert!(!changed);
    }

    #[test]
    fn contract_event_wrong_arity_not_recognized() {
        let mut func = func_with(vec![i64c(0), host_x("1", vec![v(0)])]);
        let (changed, _) = run(&mut func);
        assert!(!changed);
    }

    #[test]
    fn non_x_module_not_recognized() {
        let expr = Expr::Semantic(SemanticOp::Unknown {
            host_module: "l".to_string(),
            host_fn: "1".to_string(),
            args: vec![v(0), v(1)],
            reason: UnknownReason::UnsupportedPattern,
        });
        let mut func = func_with(vec![i64c(0), i64c(0), expr]);
        let (changed, _) = run(&mut func);
        assert!(!changed);
    }

    #[test]
    fn unknown_x_export_not_recognized() {
        let mut func = func_with(vec![host_x("zz", vec![])]);
        let (changed, _) = run(&mut func);
        assert!(!changed);
    }

    // --- idempotency + provenance ---

    #[test]
    fn second_run_reports_no_change() {
        let mut func = func_with(vec![host_x("7", vec![])]);
        assert!(run(&mut func).0);
        assert!(!run(&mut func).0, "idempotent on rerun");
    }

    #[test]
    fn provenance_source_and_note() {
        let mut func = func_with(vec![host_x("3", vec![])]);
        run(&mut func);
        let prov = func.bindings.get(v(0)).unwrap().latest_provenance();
        assert_eq!(prov.source, ProvenanceSource::HostFunctionAbi);
        assert!(prov.note.contains("get_ledger_sequence"), "note: {}", prov.note);
    }
}
