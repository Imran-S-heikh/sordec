//! C4 — the Soroban auth + address recognizer.
//!
//! Recognizes the `a`-module (address) host-call surface: the
//! authorization primitives (`require_auth`, `require_auth_for_args`,
//! `authorize_as_curr_contract`) and the address conversion / query
//! helpers (strkey ↔ address, muxed-address decomposition, executable
//! inspection). Every recognition is ABI-proven — the host-function
//! identity *is* the semantic — so bindings carry `Known` certainty and
//! `HostFunctionAbi` provenance.
//!
//! Authorization is the highest-value surface for auditors ("who is
//! allowed to call this?"). `require_auth` appears in every corpus
//! contract; turning `host:a:require_auth(v6)` into a first-class
//! `require_auth(v6)` is the point of this pass.
//!
//! ## What it does NOT do
//!
//! - No admin-gated-auth collapse (`get(Admin) → require_auth`). rustc
//!   hoists the admin read into a helper function, so the chain is
//!   inter-procedural; recognizing it needs cross-function value
//!   propagation we don't have yet. `require_auth` is still recognized;
//!   its address operand keeps its reference.
//! - No allowance flow (`read → check → conditional write`) — a
//!   separate multi-block recognizer's scope.
//! - No `VecObject` expansion for `require_auth_for_args` — the args
//!   handle is stored as-is; the collections recognizer expands it.

use sordec_common::{ProvenanceSource, ValueId};
use sordec_ir::{Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, SemanticOp};

use super::{apply_rewrites, is_recognized, Rewrite};
use crate::pass::{Pass, PassMetrics, PassResult};
use crate::val_abi;

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "auth";

// Per-op metric counter keys.
const M_REQUIRE_AUTH: &str = "require_auth";
const M_REQUIRE_AUTH_FOR_ARGS: &str = "require_auth_for_args";
const M_AUTHORIZE_AS_CURR: &str = "authorize_as_curr_contract";
const M_ADDRESS_CONVERSION: &str = "address_conversion";

/// The C4 auth + address recognizer. Stateless.
#[derive(Debug, Default, Clone, Copy)]
pub struct AuthPass;

impl Pass<HighIr> for AuthPass {
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
        if let Some(rw) = try_auth(id, &binding.expr) {
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

/// Match an `a`-module host call and build its rewrite. Arity-guarded;
/// wrong arity or a non-`a` / non-recognized export yields `None`,
/// leaving the binding as `SemanticOp::Unknown`.
fn try_auth(id: ValueId, expr: &Expr) -> Option<Rewrite> {
    let Expr::Semantic(SemanticOp::Unknown {
        host_module,
        host_fn,
        args,
        ..
    }) = expr
    else {
        return None;
    };
    if host_module != "a" {
        return None;
    }

    // Authorization primitives first (their own KnownOps); then the
    // address conversions (grouped under AddressConversion). Arity from
    // the env.json signatures verified for C4.
    let (op, ty, metric, note): (KnownOp, KnownType, &'static str, String) =
        match (host_fn.as_str(), args.len()) {
            ("0", 1) => (
                KnownOp::RequireAuth { address: args[0] },
                KnownType::Unit,
                M_REQUIRE_AUTH,
                "auth require_auth".to_string(),
            ),
            ("_", 2) => (
                KnownOp::RequireAuthForArgs {
                    address: args[0],
                    // Single VecObject handle; collections recognizer
                    // expands it later.
                    args: vec![args[1]],
                },
                KnownType::Unit,
                M_REQUIRE_AUTH_FOR_ARGS,
                "auth require_auth_for_args".to_string(),
            ),
            ("3", 1) => (
                KnownOp::AuthorizeAsCurrContract {
                    auth_entries: args[0],
                },
                KnownType::Unit,
                M_AUTHORIZE_AS_CURR,
                "auth authorize_as_curr_contract".to_string(),
            ),
            // Address conversions: all arity 1 in the ABI.
            (_, 1) => {
                let kind = val_abi::addr_fn_kind(host_module, host_fn)?;
                (
                    KnownOp::AddressConversion {
                        kind,
                        args: args.clone(),
                    },
                    val_abi::addr_kind_result_type(kind),
                    M_ADDRESS_CONVERSION,
                    format!("address-conversion {}", val_abi::addr_kind_name(kind)),
                )
            }
            _ => return None,
        };

    Some(Rewrite {
        id,
        expr: Expr::Semantic(SemanticOp::Known(op)),
        ty: Some(IrType::Known(ty)),
        source: ProvenanceSource::HostFunctionAbi,
        note,
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
    use sordec_ir::{AddressOpKind, Binding, HighBlock, Literal, Region};

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

    fn host_a(name: &str, args: Vec<ValueId>) -> Expr {
        Expr::Semantic(SemanticOp::Unknown {
            host_module: "a".to_string(),
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

    // --- auth primitives ---

    #[test]
    fn require_auth_recognized() {
        // v0 address; v1 = require_auth(v0)
        let mut func = func_with(vec![i64c(0), host_a("0", vec![v(0)])]);
        let (changed, metrics) = run(&mut func);
        assert!(changed);
        assert_eq!(metrics.get(M_REQUIRE_AUTH), Some(1));
        match expr_at(&func, v(1)) {
            Expr::Semantic(SemanticOp::Known(KnownOp::RequireAuth { address })) => {
                assert_eq!(*address, v(0));
            }
            other => panic!("expected RequireAuth, got {other:?}"),
        }
        assert_eq!(func.bindings.get(v(1)).unwrap().ty, IrType::Known(KnownType::Unit));
    }

    #[test]
    fn require_auth_for_args_stores_vec_handle() {
        // v0 address; v1 args-vec handle; v2 = require_auth_for_args(v0, v1)
        let mut func = func_with(vec![i64c(0), i64c(0), host_a("_", vec![v(0), v(1)])]);
        let (changed, metrics) = run(&mut func);
        assert!(changed);
        assert_eq!(metrics.get(M_REQUIRE_AUTH_FOR_ARGS), Some(1));
        match expr_at(&func, v(2)) {
            Expr::Semantic(SemanticOp::Known(KnownOp::RequireAuthForArgs { address, args })) => {
                assert_eq!(*address, v(0));
                assert_eq!(args.as_slice(), &[v(1)], "single VecObject handle");
            }
            other => panic!("expected RequireAuthForArgs, got {other:?}"),
        }
    }

    #[test]
    fn authorize_as_curr_contract_recognized() {
        let mut func = func_with(vec![i64c(0), host_a("3", vec![v(0)])]);
        let (changed, metrics) = run(&mut func);
        assert!(changed);
        assert_eq!(metrics.get(M_AUTHORIZE_AS_CURR), Some(1));
        assert!(matches!(
            expr_at(&func, v(1)),
            Expr::Semantic(SemanticOp::Known(KnownOp::AuthorizeAsCurrContract { .. }))
        ));
    }

    // --- address conversions ---

    #[test]
    fn get_address_from_muxed_typed_address() {
        // a.4 → GetAddressFromMuxedAddress, returns Address.
        let mut func = func_with(vec![i64c(0), host_a("4", vec![v(0)])]);
        let (changed, metrics) = run(&mut func);
        assert!(changed);
        assert_eq!(metrics.get(M_ADDRESS_CONVERSION), Some(1));
        match expr_at(&func, v(1)) {
            Expr::Semantic(SemanticOp::Known(KnownOp::AddressConversion { kind, args })) => {
                assert_eq!(*kind, AddressOpKind::GetAddressFromMuxedAddress);
                assert_eq!(args.as_slice(), &[v(0)]);
            }
            other => panic!("expected AddressConversion, got {other:?}"),
        }
        assert_eq!(func.bindings.get(v(1)).unwrap().ty, IrType::Known(KnownType::Address));
    }

    #[test]
    fn get_id_from_muxed_typed_u64() {
        // a.5 → GetIdFromMuxedAddress, returns U64.
        let mut func = func_with(vec![i64c(0), host_a("5", vec![v(0)])]);
        run(&mut func);
        assert_eq!(func.bindings.get(v(1)).unwrap().ty, IrType::Known(KnownType::U64));
    }

    #[test]
    fn strkey_to_address_typed_address() {
        let mut func = func_with(vec![i64c(0), host_a("1", vec![v(0)])]);
        run(&mut func);
        match expr_at(&func, v(1)) {
            Expr::Semantic(SemanticOp::Known(KnownOp::AddressConversion { kind, .. })) => {
                assert_eq!(*kind, AddressOpKind::StrkeyToAddress);
            }
            other => panic!("expected AddressConversion, got {other:?}"),
        }
        assert_eq!(func.bindings.get(v(1)).unwrap().ty, IrType::Known(KnownType::Address));
    }

    #[test]
    fn address_to_strkey_typed_string() {
        let mut func = func_with(vec![i64c(0), host_a("2", vec![v(0)])]);
        run(&mut func);
        assert_eq!(func.bindings.get(v(1)).unwrap().ty, IrType::Known(KnownType::String));
    }

    #[test]
    fn get_address_executable_typed_val_not_overclaimed() {
        // a.6 is declared `-> Val` — typed Val, not a guessed richer type.
        let mut func = func_with(vec![i64c(0), host_a("6", vec![v(0)])]);
        run(&mut func);
        assert_eq!(func.bindings.get(v(1)).unwrap().ty, IrType::Known(KnownType::Val));
    }

    // --- non-matches ---

    #[test]
    fn wrong_arity_require_auth_not_recognized() {
        // require_auth with 2 args is malformed → skip.
        let mut func = func_with(vec![i64c(0), i64c(0), host_a("0", vec![v(0), v(1)])]);
        let (changed, _) = run(&mut func);
        assert!(!changed);
    }

    #[test]
    fn non_a_module_not_recognized() {
        let expr = Expr::Semantic(SemanticOp::Unknown {
            host_module: "l".to_string(),
            host_fn: "0".to_string(),
            args: vec![v(0)],
            reason: UnknownReason::UnsupportedPattern,
        });
        let mut func = func_with(vec![i64c(0), expr]);
        let (changed, _) = run(&mut func);
        assert!(!changed);
    }

    #[test]
    fn unknown_a_export_not_recognized() {
        // A fabricated a-module export that isn't in the ABI.
        let mut func = func_with(vec![i64c(0), host_a("zz", vec![v(0)])]);
        let (changed, _) = run(&mut func);
        assert!(!changed);
    }

    // --- idempotency + provenance ---

    #[test]
    fn second_run_reports_no_change() {
        let mut func = func_with(vec![i64c(0), host_a("0", vec![v(0)])]);
        assert!(run(&mut func).0);
        assert!(!run(&mut func).0, "idempotent on rerun");
    }

    #[test]
    fn provenance_source_and_note() {
        let mut func = func_with(vec![i64c(0), host_a("0", vec![v(0)])]);
        run(&mut func);
        let prov = func.bindings.get(v(1)).unwrap().latest_provenance();
        assert_eq!(prov.source, ProvenanceSource::HostFunctionAbi);
        assert!(prov.note.contains("require_auth"), "note: {}", prov.note);
    }
}
