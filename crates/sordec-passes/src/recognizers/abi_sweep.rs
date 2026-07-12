//! The remaining-ABI recognizer (`c` crypto, `p` prng, `t` test, and
//! the `l`-module deploy/upgrade subset).
//!
//! The final breadth pass: with storage/auth/collections/context/
//! cross-contract landed, these four surfaces are the only host modules
//! left without `KnownOp` vocabulary. Recognizing them turns the
//! **entire 192-function ABI** into named semantic ops. Recognition is
//! ABI-proven — the `(module, export)` identity *is* the semantic — so
//! bindings carry `Known` certainty with `HostFunctionAbi` provenance,
//! into the grouped [`KnownOp::CryptoOp`] / [`KnownOp::PrngOp`] /
//! [`KnownOp::TestOp`] / [`KnownOp::DeployOp`] ops. The
//! `(module, export) → kind` tables, per-kind arity, and return types
//! live in [`crate::val_abi`], each drift-guarded against the vendored
//! catalog.
//!
//! ## Ownership of the `l` module
//!
//! The `l` (ledger) module is split: storage CRUD/TTL exports are
//! [`StoragePass`](super::storage)'s, the 7 deploy/upgrade exports are
//! this pass's. The `val_abi` `deploy_fn_kind` table rejects the
//! storage exports, and this pass runs *after* `StoragePass` (which
//! claims its exports first via `is_recognized`), so ownership is
//! unambiguous — the same "runs after" rule collections uses vs
//! linear-memory.
//!
//! ## What it does NOT do
//!
//! No operand constant recovery — operands stay `ValueId` references,
//! exactly as collections leaves them (const-prop's scope). The BLS/BN
//! `fr_*` field-arithmetic ops are named here but their wide-int
//! *fusion* is a separate deferred recognizer (C19).

use sordec_common::{ProvenanceSource, ValueId};
use sordec_ir::{Expr, HighFunction, HighIr, IrType, KnownOp, SemanticOp};

use super::{apply_rewrites, is_recognized, Rewrite};
use crate::pass::{Pass, PassMetrics, PassResult};
use crate::val_abi;

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "abi-sweep";

// Per-module metric counter keys. Per-op counters across 50 functions
// would be noise; the provenance note names the exact operation.
const M_CRYPTO: &str = "crypto_op";
const M_PRNG: &str = "prng_op";
const M_TEST: &str = "test_op";
const M_DEPLOY: &str = "deploy_op";

/// The remaining-ABI recognizer. Stateless.
#[derive(Debug, Default, Clone, Copy)]
pub struct AbiSweepPass;

impl Pass<HighIr> for AbiSweepPass {
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
        let Some(rewrite) = try_abi_sweep(id, &binding.expr) else {
            continue;
        };
        metrics.increment(rewrite.metric, 1);
        rewrites.push(rewrite);
    }

    let changed = !rewrites.is_empty();
    apply_rewrites(func, PASS_NAME, rewrites);
    (changed, metrics)
}

/// Match a `c`/`p`/`t`-module host call, or an `l`-module deploy export,
/// and build its rewrite. Wrong arity (malformed IR), a storage/TTL `l`
/// export (StoragePass's), or an export outside the tables leaves the
/// call unrecognized.
fn try_abi_sweep(id: ValueId, expr: &Expr) -> Option<Rewrite> {
    let Expr::Semantic(SemanticOp::Unknown {
        host_module,
        host_fn,
        args,
        ..
    }) = expr
    else {
        return None;
    };

    let (op, ty, name, metric) = match host_module.as_str() {
        "c" => {
            let kind = val_abi::crypto_fn_kind(host_module, host_fn)?;
            if args.len() != val_abi::crypto_kind_arity(kind) {
                return None;
            }
            (
                KnownOp::CryptoOp {
                    kind,
                    args: args.clone(),
                },
                val_abi::crypto_kind_result_type(kind),
                val_abi::crypto_kind_name(kind),
                M_CRYPTO,
            )
        }
        "p" => {
            let kind = val_abi::prng_fn_kind(host_module, host_fn)?;
            if args.len() != val_abi::prng_kind_arity(kind) {
                return None;
            }
            (
                KnownOp::PrngOp {
                    kind,
                    args: args.clone(),
                },
                val_abi::prng_kind_result_type(kind),
                val_abi::prng_kind_name(kind),
                M_PRNG,
            )
        }
        "t" => {
            let kind = val_abi::test_fn_kind(host_module, host_fn)?;
            if args.len() != val_abi::test_kind_arity(kind) {
                return None;
            }
            (
                KnownOp::TestOp {
                    kind,
                    args: args.clone(),
                },
                val_abi::test_kind_result_type(kind),
                val_abi::test_kind_name(kind),
                M_TEST,
            )
        }
        "l" => {
            // Only the deploy/upgrade subset; deploy_fn_kind returns
            // None for the storage CRUD/TTL exports (StoragePass's).
            let kind = val_abi::deploy_fn_kind(host_module, host_fn)?;
            if args.len() != val_abi::deploy_kind_arity(kind) {
                return None;
            }
            (
                KnownOp::DeployOp {
                    kind,
                    args: args.clone(),
                },
                val_abi::deploy_kind_result_type(kind),
                val_abi::deploy_kind_name(kind),
                M_DEPLOY,
            )
        }
        _ => return None,
    };

    Some(Rewrite {
        id,
        expr: Expr::Semantic(SemanticOp::Known(op)),
        ty: Some(IrType::Known(ty)),
        source: ProvenanceSource::HostFunctionAbi,
        note: format!("abi-sweep {name}"),
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
    use sordec_ir::{
        Binding, CryptoOpKind, DeployOpKind, HighBlock, KnownType, Literal, PrngOpKind, Region,
        TestOpKind,
    };

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
    fn crypto_sha256_recognized_with_bytes_result() {
        let mut func = func_with(vec![val(0), host("c", "_", vec![v(0)])]);
        let (changed, metrics) = run(&mut func);
        assert!(changed);
        assert_eq!(metrics.get(M_CRYPTO), Some(1));
        match expr_at(&func, v(1)) {
            Expr::Semantic(SemanticOp::Known(KnownOp::CryptoOp { kind, args })) => {
                assert_eq!(*kind, CryptoOpKind::ComputeHashSha256);
                assert_eq!(args, &[v(0)]);
            }
            other => panic!("expected CryptoOp, got {other:?}"),
        }
        assert_eq!(
            func.bindings.get(v(1)).unwrap().ty,
            IrType::Known(KnownType::Bytes)
        );
    }

    #[test]
    fn crypto_verify_sig_and_poseidon_arities() {
        // 3-arg ed25519 verify, 8-arg poseidon — the arity extremes.
        let mut func = func_with(vec![
            val(0),
            val(1),
            val(2),
            val(3),
            val(4),
            val(5),
            val(6),
            val(7),
            host("c", "0", vec![v(0), v(1), v(2)]),
            host("c", "p", vec![v(0), v(1), v(2), v(3), v(4), v(5), v(6), v(7)]),
        ]);
        let (changed, metrics) = run(&mut func);
        assert!(changed);
        assert_eq!(metrics.get(M_CRYPTO), Some(2));
        assert!(matches!(
            expr_at(&func, v(8)),
            Expr::Semantic(SemanticOp::Known(KnownOp::CryptoOp {
                kind: CryptoOpKind::VerifySigEd25519,
                ..
            }))
        ));
        assert!(matches!(
            expr_at(&func, v(9)),
            Expr::Semantic(SemanticOp::Known(KnownOp::CryptoOp {
                kind: CryptoOpKind::PoseidonPermutation,
                ..
            }))
        ));
    }

    #[test]
    fn prng_and_test_recognized() {
        let mut func = func_with(vec![
            val(0),
            val(1),
            host("p", "1", vec![v(0), v(1)]), // u64_in_inclusive_range
            host("t", "_", vec![]),           // dummy0
        ]);
        let (changed, metrics) = run(&mut func);
        assert!(changed);
        assert_eq!(metrics.get(M_PRNG), Some(1));
        assert_eq!(metrics.get(M_TEST), Some(1));
        assert!(matches!(
            expr_at(&func, v(2)),
            Expr::Semantic(SemanticOp::Known(KnownOp::PrngOp {
                kind: PrngOpKind::PrngU64InInclusiveRange,
                ..
            }))
        ));
        assert_eq!(
            func.bindings.get(v(2)).unwrap().ty,
            IrType::Known(KnownType::U64)
        );
        assert!(matches!(
            expr_at(&func, v(3)),
            Expr::Semantic(SemanticOp::Known(KnownOp::TestOp {
                kind: TestOpKind::Dummy0,
                ..
            }))
        ));
    }

    #[test]
    fn deploy_create_contract_recognized_with_address_result() {
        let mut func = func_with(vec![
            val(0),
            val(1),
            val(2),
            host("l", "3", vec![v(0), v(1), v(2)]),
        ]);
        let (changed, metrics) = run(&mut func);
        assert!(changed);
        assert_eq!(metrics.get(M_DEPLOY), Some(1));
        match expr_at(&func, v(3)) {
            Expr::Semantic(SemanticOp::Known(KnownOp::DeployOp { kind, args })) => {
                assert_eq!(*kind, DeployOpKind::CreateContract);
                assert_eq!(args, &[v(0), v(1), v(2)]);
            }
            other => panic!("expected DeployOp, got {other:?}"),
        }
        assert_eq!(
            func.bindings.get(v(3)).unwrap().ty,
            IrType::Known(KnownType::Address)
        );
    }

    #[test]
    fn storage_ledger_exports_left_for_storage_pass() {
        // l._ (put_contract_data) is StoragePass's, not this pass's —
        // this pass must not touch it (it stays Unknown here; StoragePass
        // runs before us in the real pipeline).
        let mut func = func_with(vec![val(0), val(1), val(2), host("l", "_", vec![v(0), v(1), v(2)])]);
        let (changed, _) = run(&mut func);
        assert!(!changed);
        assert!(matches!(
            expr_at(&func, v(3)),
            Expr::Semantic(SemanticOp::Unknown { .. })
        ));
    }

    #[test]
    fn wrong_arity_not_recognized() {
        // sha256 takes 1 arg; 2 is malformed.
        let mut func = func_with(vec![val(0), val(1), host("c", "_", vec![v(0), v(1)])]);
        let (changed, _) = run(&mut func);
        assert!(!changed);
    }

    #[test]
    fn unknown_export_not_recognized() {
        let mut func = func_with(vec![host("c", "ZZ", vec![])]);
        let (changed, _) = run(&mut func);
        assert!(!changed);
    }

    #[test]
    fn second_run_reports_no_change() {
        let mut func = func_with(vec![val(0), host("c", "_", vec![v(0)])]);
        assert!(run(&mut func).0);
        assert!(!run(&mut func).0, "idempotent on rerun");
    }

    #[test]
    fn provenance_records_source_and_name() {
        let mut func = func_with(vec![val(0), host("p", "0", vec![v(0)])]);
        run(&mut func);
        let prov = func.bindings.get(v(1)).unwrap().latest_provenance();
        assert_eq!(prov.source, ProvenanceSource::HostFunctionAbi);
        assert!(
            prov.note.contains("abi-sweep prng_bytes_new"),
            "note: {}",
            prov.note
        );
    }
}
