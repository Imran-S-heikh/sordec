//! The Soroban collections + bytes recognizer (`m`/`v`/`b` modules).
//!
//! Recognizes every map, vec, and buf (bytes / string / symbol) host
//! operation — 52 functions across the three modules — into the grouped
//! [`KnownOp::MapOp`] / [`KnownOp::VecOp`] / [`KnownOp::BufOp`] semantic
//! ops. Recognition is ABI-proven: the `(module, export)` identity *is*
//! the semantic, so bindings carry `Known` certainty with
//! `HostFunctionAbi` provenance. The `(module, export) → kind` tables,
//! per-kind arity, and return types live in [`crate::val_abi`], each
//! drift-guarded against the vendored host-call catalog.
//!
//! ## What it does NOT cover
//!
//! - The five `*_new_from_linear_memory` constructors — `(m, 9)`,
//!   `(v, g)`, `(b, 3)`, `(b, i)`, `(b, j)` — are the linear-memory
//!   recognizer's ops (they resolve rodata literals; see
//!   [`super::linear_memory`]). The tables here exclude them, and this
//!   pass runs after `LinearMemoryPass`, so ownership is unambiguous.
//! - No element / key / index constant recovery. Operands stay
//!   `ValueId` references; resolving e.g. a constant map key is the
//!   constant-propagation engine's scope.

use sordec_common::{ProvenanceSource, ValueId};
use sordec_ir::{Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, SemanticOp};

use super::{apply_rewrites, is_recognized, Rewrite};
use crate::pass::{Pass, PassMetrics, PassResult};
use crate::val_abi;

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "collections";

// Per-module metric counter keys. Per-op counters across 52 functions
// would be noise; the provenance note names the exact operation.
const M_MAP: &str = "map_op";
const M_VEC: &str = "vec_op";
const M_BUF: &str = "buf_op";

/// The collections recognizer. Stateless.
#[derive(Debug, Default, Clone, Copy)]
pub struct CollectionsPass;

impl Pass<HighIr> for CollectionsPass {
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
        let Some(rewrite) = try_collections(id, &binding.expr) else {
            continue;
        };
        metrics.increment(rewrite.metric, 1);
        rewrites.push(rewrite);
    }

    let changed = !rewrites.is_empty();
    apply_rewrites(func, PASS_NAME, rewrites);
    (changed, metrics)
}

/// Match an `m`/`v`/`b`-module host call and build its rewrite. Wrong
/// arity (malformed IR) or an export outside the tables (the excluded
/// constructors, unknown exports) leaves the call unrecognized.
fn try_collections(id: ValueId, expr: &Expr) -> Option<Rewrite> {
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
        "m" => {
            let kind = val_abi::map_fn_kind(host_module, host_fn)?;
            if args.len() != val_abi::map_kind_arity(kind) {
                return None;
            }
            (
                KnownOp::MapOp {
                    kind,
                    args: args.clone(),
                },
                val_abi::map_kind_result_type(kind),
                val_abi::map_kind_name(kind),
                M_MAP,
            )
        }
        "v" => {
            let kind = val_abi::vec_fn_kind(host_module, host_fn)?;
            if args.len() != val_abi::vec_kind_arity(kind) {
                return None;
            }
            (
                KnownOp::VecOp {
                    kind,
                    args: args.clone(),
                },
                val_abi::vec_kind_result_type(kind),
                val_abi::vec_kind_name(kind),
                M_VEC,
            )
        }
        "b" => {
            let kind = val_abi::buf_fn_kind(host_module, host_fn)?;
            if args.len() != val_abi::buf_kind_arity(kind) {
                return None;
            }
            (
                KnownOp::BufOp {
                    kind,
                    args: args.clone(),
                },
                val_abi::buf_kind_result_type(kind),
                val_abi::buf_kind_name(kind),
                M_BUF,
            )
        }
        _ => return None,
    };

    Some(Rewrite {
        id,
        expr: Expr::Semantic(SemanticOp::Known(op)),
        ty: Some(known(ty)),
        source: ProvenanceSource::HostFunctionAbi,
        note: format!("collections {name}"),
        metric,
    })
}

/// Wrap an ABI result type as a `Known` binding type.
fn known(ty: KnownType) -> IrType {
    IrType::Known(ty)
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{Arena, BlockId, FuncId, IrId, Provenance, UnknownReason};
    use sordec_ir::{
        Binding, BufOpKind, HighBlock, Literal, MapOpKind, Region, VecOpKind,
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

    // --- corpus-exercised shapes, exact-field checks ---

    #[test]
    fn map_unpack_to_linear_memory_recognized() {
        // The one m-op every token fixture has: (map, keys_pos, vals_pos, len).
        let mut func = func_with(vec![
            val(0),
            val(1),
            val(2),
            val(3),
            host("m", "a", vec![v(0), v(1), v(2), v(3)]),
        ]);
        let (changed, metrics) = run(&mut func);
        assert!(changed);
        assert_eq!(metrics.get(M_MAP), Some(1));
        match expr_at(&func, v(4)) {
            Expr::Semantic(SemanticOp::Known(KnownOp::MapOp { kind, args })) => {
                assert_eq!(*kind, MapOpKind::UnpackToLinearMemory);
                assert_eq!(args, &[v(0), v(1), v(2), v(3)]);
            }
            other => panic!("expected MapOp, got {other:?}"),
        }
        assert_eq!(
            func.bindings.get(v(4)).unwrap().ty,
            IrType::Known(KnownType::Unit)
        );
    }

    #[test]
    fn vec_len_and_get_recognized() {
        let mut func = func_with(vec![
            val(0),
            val(1),
            host("v", "3", vec![v(0)]),
            host("v", "1", vec![v(0), v(1)]),
        ]);
        let (changed, metrics) = run(&mut func);
        assert!(changed);
        assert_eq!(metrics.get(M_VEC), Some(2));
        match expr_at(&func, v(2)) {
            Expr::Semantic(SemanticOp::Known(KnownOp::VecOp { kind, .. })) => {
                assert_eq!(*kind, VecOpKind::Len);
            }
            other => panic!("expected VecOp, got {other:?}"),
        }
        assert_eq!(
            func.bindings.get(v(2)).unwrap().ty,
            IrType::Known(KnownType::U32)
        );
        match expr_at(&func, v(3)) {
            Expr::Semantic(SemanticOp::Known(KnownOp::VecOp { kind, args })) => {
                assert_eq!(*kind, VecOpKind::Get);
                assert_eq!(args, &[v(0), v(1)]);
            }
            other => panic!("expected VecOp, got {other:?}"),
        }
    }

    #[test]
    fn vec_first_index_of_recognized() {
        let mut func = func_with(vec![val(0), val(1), host("v", "d", vec![v(0), v(1)])]);
        let (changed, _) = run(&mut func);
        assert!(changed);
        match expr_at(&func, v(2)) {
            Expr::Semantic(SemanticOp::Known(KnownOp::VecOp { kind, .. })) => {
                assert_eq!(*kind, VecOpKind::FirstIndexOf);
            }
            other => panic!("expected VecOp, got {other:?}"),
        }
        // Declared -> Val upstream (index or Void).
        assert_eq!(
            func.bindings.get(v(2)).unwrap().ty,
            IrType::Known(KnownType::Val)
        );
    }

    #[test]
    fn symbol_index_in_linear_memory_recognized() {
        // (sym, slices_pos, len) — the SDK's symbol-dispatch helper.
        let mut func = func_with(vec![
            val(0),
            val(1),
            val(2),
            host("b", "m", vec![v(0), v(1), v(2)]),
        ]);
        let (changed, metrics) = run(&mut func);
        assert!(changed);
        assert_eq!(metrics.get(M_BUF), Some(1));
        match expr_at(&func, v(3)) {
            Expr::Semantic(SemanticOp::Known(KnownOp::BufOp { kind, args })) => {
                assert_eq!(*kind, BufOpKind::SymbolIndexInLinearMemory);
                assert_eq!(args, &[v(0), v(1), v(2)]);
            }
            other => panic!("expected BufOp, got {other:?}"),
        }
        assert_eq!(
            func.bindings.get(v(3)).unwrap().ty,
            IrType::Known(KnownType::U32)
        );
    }

    // --- one spot-check per family group ---

    #[test]
    fn nullary_constructors_recognized() {
        let mut func = func_with(vec![
            host("m", "_", vec![]),
            host("v", "_", vec![]),
            host("b", "4", vec![]),
        ]);
        let (changed, _) = run(&mut func);
        assert!(changed);
        assert!(matches!(
            expr_at(&func, v(0)),
            Expr::Semantic(SemanticOp::Known(KnownOp::MapOp {
                kind: MapOpKind::New,
                ..
            }))
        ));
        assert!(matches!(
            expr_at(&func, v(1)),
            Expr::Semantic(SemanticOp::Known(KnownOp::VecOp {
                kind: VecOpKind::New,
                ..
            }))
        ));
        assert!(matches!(
            expr_at(&func, v(2)),
            Expr::Semantic(SemanticOp::Known(KnownOp::BufOp {
                kind: BufOpKind::BytesNewEmpty,
                ..
            }))
        ));
        // Composite results carry Unknown inners, not guessed types.
        assert!(matches!(
            &func.bindings.get(v(0)).unwrap().ty,
            IrType::Known(KnownType::Map(_, _))
        ));
        assert!(matches!(
            &func.bindings.get(v(1)).unwrap().ty,
            IrType::Known(KnownType::Vec(_))
        ));
    }

    #[test]
    fn map_mutators_and_queries_recognized() {
        let mut func = func_with(vec![
            val(0),
            val(1),
            val(2),
            host("m", "0", vec![v(0), v(1), v(2)]), // map_put
            host("m", "4", vec![v(3), v(1)]),       // map_has
        ]);
        let (changed, _) = run(&mut func);
        assert!(changed);
        assert!(matches!(
            expr_at(&func, v(3)),
            Expr::Semantic(SemanticOp::Known(KnownOp::MapOp {
                kind: MapOpKind::Put,
                ..
            }))
        ));
        assert_eq!(
            func.bindings.get(v(4)).unwrap().ty,
            IrType::Known(KnownType::Bool)
        );
    }

    #[test]
    fn vec_binary_search_typed_raw_u64() {
        let mut func = func_with(vec![val(0), val(1), host("v", "f", vec![v(0), v(1)])]);
        run(&mut func);
        assert!(matches!(
            expr_at(&func, v(2)),
            Expr::Semantic(SemanticOp::Known(KnownOp::VecOp {
                kind: VecOpKind::BinarySearch,
                ..
            }))
        ));
        assert_eq!(
            func.bindings.get(v(2)).unwrap().ty,
            IrType::Known(KnownType::U64)
        );
    }

    #[test]
    fn buf_serialization_and_conversions_recognized() {
        let mut func = func_with(vec![
            val(0),
            host("b", "_", vec![v(0)]), // serialize_to_bytes
            host("b", "o", vec![v(1)]), // bytes_to_string
        ]);
        let (changed, _) = run(&mut func);
        assert!(changed);
        assert_eq!(
            func.bindings.get(v(1)).unwrap().ty,
            IrType::Known(KnownType::Bytes)
        );
        assert_eq!(
            func.bindings.get(v(2)).unwrap().ty,
            IrType::Known(KnownType::String)
        );
    }

    // --- exclusions + guards ---

    #[test]
    fn linear_memory_constructors_not_claimed() {
        // The five constructors belong to LinearMemoryPass; this pass
        // must leave them untouched even with correct-looking arities.
        let mut func = func_with(vec![
            val(0),
            val(1),
            val(2),
            host("m", "9", vec![v(0), v(1), v(2)]),
            host("v", "g", vec![v(0), v(1)]),
            host("b", "3", vec![v(0), v(1)]),
            host("b", "i", vec![v(0), v(1)]),
            host("b", "j", vec![v(0), v(1)]),
        ]);
        let (changed, _) = run(&mut func);
        assert!(!changed, "constructor exports are not in the tables");
    }

    #[test]
    fn wrong_arity_not_recognized() {
        // vec_len with 2 args is malformed → skip.
        let mut func = func_with(vec![val(0), val(1), host("v", "3", vec![v(0), v(1)])]);
        let (changed, _) = run(&mut func);
        assert!(!changed);
    }

    #[test]
    fn non_collections_module_untouched() {
        let mut func = func_with(vec![val(0), val(1), host("l", "1", vec![v(0), v(1)])]);
        let (changed, _) = run(&mut func);
        assert!(!changed);
    }

    // --- idempotency + provenance ---

    #[test]
    fn second_run_reports_no_change() {
        let mut func = func_with(vec![val(0), host("v", "3", vec![v(0)])]);
        assert!(run(&mut func).0);
        assert!(!run(&mut func).0, "idempotent on rerun");
    }

    #[test]
    fn provenance_records_source_and_op_name() {
        let mut func = func_with(vec![val(0), host("v", "3", vec![v(0)])]);
        run(&mut func);
        let prov = func.bindings.get(v(1)).unwrap().latest_provenance();
        assert_eq!(prov.source, ProvenanceSource::HostFunctionAbi);
        assert!(prov.note.contains("collections vec_len"), "note: {}", prov.note);
    }

    // --- exhaustive dispatch sweep ---

    #[test]
    fn every_table_export_dispatches_with_abi_arity() {
        // For each in-scope export, a host call with the ABI arity must
        // be recognized into the matching module's grouped op. This
        // sweeps all 52 arms.
        let cases: Vec<(&str, &str)> = [
            ("m", "_"), ("m", "0"), ("m", "1"), ("m", "2"), ("m", "3"), ("m", "4"),
            ("m", "5"), ("m", "6"), ("m", "7"), ("m", "8"), ("m", "a"),
            ("v", "_"), ("v", "0"), ("v", "1"), ("v", "2"), ("v", "3"), ("v", "4"),
            ("v", "5"), ("v", "6"), ("v", "7"), ("v", "8"), ("v", "9"), ("v", "a"),
            ("v", "b"), ("v", "c"), ("v", "d"), ("v", "e"), ("v", "f"), ("v", "h"),
            ("b", "_"), ("b", "0"), ("b", "1"), ("b", "2"), ("b", "4"), ("b", "5"),
            ("b", "6"), ("b", "7"), ("b", "8"), ("b", "9"), ("b", "a"), ("b", "b"),
            ("b", "c"), ("b", "d"), ("b", "e"), ("b", "f"), ("b", "g"), ("b", "h"),
            ("b", "k"), ("b", "l"), ("b", "m"), ("b", "n"), ("b", "o"),
        ]
        .to_vec();
        assert_eq!(cases.len(), 52, "the full in-scope surface");

        for (module, export) in cases {
            let arity = match module {
                "m" => val_abi::map_kind_arity(val_abi::map_fn_kind(module, export).unwrap()),
                "v" => val_abi::vec_kind_arity(val_abi::vec_fn_kind(module, export).unwrap()),
                _ => val_abi::buf_kind_arity(val_abi::buf_fn_kind(module, export).unwrap()),
            };
            // Operand slots first, then the host call using them.
            let mut exprs: Vec<Expr> = (0..arity as i64).map(val).collect();
            let args: Vec<ValueId> = (0..arity as u32).map(v).collect();
            exprs.push(host(module, export, args));
            let call_id = v(arity as u32);

            let mut func = func_with(exprs);
            let (changed, _) = run(&mut func);
            assert!(changed, "{module}.{export} must be recognized");
            let ok = matches!(
                (module, expr_at(&func, call_id)),
                ("m", Expr::Semantic(SemanticOp::Known(KnownOp::MapOp { .. })))
                    | ("v", Expr::Semantic(SemanticOp::Known(KnownOp::VecOp { .. })))
                    | ("b", Expr::Semantic(SemanticOp::Known(KnownOp::BufOp { .. })))
            );
            assert!(ok, "{module}.{export} rewrote to the wrong op family");
        }
    }
}
