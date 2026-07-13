//! C2 + C3 — the Soroban storage tier + TTL recognizer.
//!
//! Every `env.storage()` operation compiles to an `l`-module (ledger)
//! host call carrying a durability constant (`0` = temporary, `1` =
//! persistent, `2` = instance). The legacy decompiler hardcoded
//! `.persistent()` everywhere — wrong for ~40% of real call sites and
//! security-relevant, since an auditor must know what persists versus
//! what expires. This pass recognizes the eleven storage + TTL host
//! calls and, where the durability argument traces to a constant,
//! resolves the tier into [`StorageTier::Known`]. When it does not
//! (the value is a function parameter, a phi, or otherwise computed),
//! the tier is honestly [`StorageTier::Unknown`] — the pass never
//! guesses a tier from ambiguous evidence.
//!
//! ## Op recognition vs. tier recognition
//!
//! These are decoupled deliberately. The `(module = "l", fn)` identity
//! *proves* which operation this is (from the ABI), so the binding is
//! always rewritten to the semantic op. The tier is a separate
//! data-flow question layered on top; an unresolved tier yields
//! `storage_get<?>(k)`, still strictly more informative than the raw
//! `host:l:get_contract_data(k, t)`.
//!
//! ## What it does NOT do
//!
//! - No inter-procedural tier resolution. rustc hoists storage ops into
//!   helper functions that take the tier as a parameter; those sites
//!   read as `Unknown` until cross-function constant propagation exists.
//! - No `StorageTier::Inferred` — v1 emits `Known` or `Unknown` only.
//! - No TTL threshold / extend_to constant resolution (the
//!   `DAY_IN_LEDGERS` magic numbers) — a later recognizer's scope.
//! - No deploy-op recognition (`create_contract` etc.) — those `l`-module
//!   functions belong to the cross-contract/deploy recognizer.

use sordec_common::{
    Diagnostic, IrId, LiftDiagnosticCode, Location, ProvenanceSource, UnknownReason, ValueId,
};
use sordec_ir::{
    Expr, HighFunction, HighIr, IrType, KnownOp, KnownTier, KnownType, SemanticOp, StorageTier,
};

use super::{apply_rewrites, is_recognized, Rewrite};
use crate::dataflow::trace_int;
use crate::pass::{Pass, PassMetrics, PassResult};

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "storage-tier";

// Per-op metric counter keys.
const M_GET: &str = "storage_get";
const M_SET: &str = "storage_set";
const M_HAS: &str = "storage_has";
const M_REMOVE: &str = "storage_remove";
const M_EXTEND_TTL: &str = "storage_extend_ttl";
// Tier-resolution counters (seed of coverage metric F1).
const M_TIER_RESOLVED: &str = "storage_tier_resolved";
const M_TIER_UNKNOWN: &str = "storage_tier_unknown";

/// The C2+C3 storage recognizer. Stateless.
#[derive(Debug, Default, Clone, Copy)]
pub struct StoragePass;

impl Pass<HighIr> for StoragePass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        for func in &mut ir.functions {
            let (changed, metrics, diagnostics) = recognize_function(func);
            result.changed |= changed;
            for (key, value) in metrics.iter() {
                result.metrics.increment(key, value);
            }
            result.diagnostics.extend(diagnostics);
        }
        result
    }
}

fn recognize_function(func: &mut HighFunction) -> (bool, PassMetrics, Vec<Diagnostic>) {
    let mut metrics = PassMetrics::new();
    let mut diagnostics: Vec<Diagnostic> = Vec::new();
    let mut rewrites: Vec<Rewrite> = Vec::new();
    let func_id = func.id;

    for (id, binding) in func.bindings.iter() {
        if is_recognized(&binding.expr) {
            continue;
        }
        let Some(matched) = try_storage(func, id, &binding.expr) else {
            continue;
        };
        // Per-op counter, plus the tier-resolution bucket (only for
        // tier-bearing ops — the seed of coverage metric F1).
        metrics.increment(matched.rewrite.metric, 1);
        match matched.tier_resolved {
            Some(true) => metrics.increment(M_TIER_RESOLVED, 1),
            Some(false) => {
                metrics.increment(M_TIER_UNKNOWN, 1);
                diagnostics.push(
                    Diagnostic::warning(LiftDiagnosticCode::NonConstantDurabilityArg, "").at(
                        Location::Value {
                            func: func_id,
                            value: id.index(),
                        },
                    ),
                );
            }
            None => {}
        }
        rewrites.push(matched.rewrite);
    }

    let changed = !rewrites.is_empty();
    apply_rewrites(func, PASS_NAME, rewrites);
    (changed, metrics, diagnostics)
}

/// The recognized shape of one `l`-module call: the semantic op, its
/// ABI return type, the per-op metric key, and (for tier-bearing ops)
/// whether the tier resolved.
struct Recognized {
    op: KnownOp,
    ty: KnownType,
    metric: &'static str,
    /// `Some(true)` = tier resolved to Known; `Some(false)` = tier
    /// Unknown; `None` = op has no tier.
    tier_resolved: Option<bool>,
    note: String,
}

/// A matched storage call: the rewrite to apply plus the tier outcome
/// the caller needs for the tier-bucket metric.
struct StorageMatch {
    rewrite: Rewrite,
    tier_resolved: Option<bool>,
}

/// Match an `l`-module host call and build its rewrite.
fn try_storage(func: &HighFunction, id: ValueId, expr: &Expr) -> Option<StorageMatch> {
    let Expr::Semantic(SemanticOp::Unknown {
        host_module,
        host_fn,
        args,
        ..
    }) = expr
    else {
        return None;
    };
    if host_module != "l" {
        return None;
    }
    let r = classify(func, host_fn, args)?;
    Some(StorageMatch {
        rewrite: Rewrite {
            id,
            expr: Expr::Semantic(SemanticOp::Known(r.op)),
            ty: Some(IrType::Known(r.ty)),
            source: ProvenanceSource::HostFunctionAbi,
            note: r.note,
            metric: r.metric,
        },
        tier_resolved: r.tier_resolved,
    })
}

/// Dispatch on the `l`-module export letter, guarding arity. Returns
/// `None` for wrong arity or for non-storage `l` functions (the deploy
/// ops), leaving them unrecognized.
fn classify(func: &HighFunction, host_fn: &str, args: &[ValueId]) -> Option<Recognized> {
    match (host_fn, args.len()) {
        // ---- CRUD ----
        ("_", 3) => {
            let (tier, resolved) = resolve_tier(func, args[2]);
            Some(Recognized {
                op: KnownOp::StorageSet {
                    tier,
                    durability: args[2],
                    key: args[0],
                    resolved_key: None,
                    value: args[1],
                },
                ty: KnownType::Unit,
                metric: M_SET,
                tier_resolved: Some(resolved),
                note: tier_note("storage-set", func, args[2]),
            })
        }
        ("0", 2) => {
            let (tier, resolved) = resolve_tier(func, args[1]);
            Some(Recognized {
                op: KnownOp::StorageHas {
                    tier,
                    durability: args[1],
                    key: args[0],
                    resolved_key: None,
                },
                ty: KnownType::Bool,
                metric: M_HAS,
                tier_resolved: Some(resolved),
                note: tier_note("storage-has", func, args[1]),
            })
        }
        ("1", 2) => {
            let (tier, resolved) = resolve_tier(func, args[1]);
            Some(Recognized {
                op: KnownOp::StorageGet {
                    tier,
                    durability: args[1],
                    key: args[0],
                    resolved_key: None,
                },
                ty: KnownType::Val,
                metric: M_GET,
                tier_resolved: Some(resolved),
                note: tier_note("storage-get", func, args[1]),
            })
        }
        ("2", 2) => {
            let (tier, resolved) = resolve_tier(func, args[1]);
            Some(Recognized {
                op: KnownOp::StorageRemove {
                    tier,
                    durability: args[1],
                    key: args[0],
                    resolved_key: None,
                },
                ty: KnownType::Unit,
                metric: M_REMOVE,
                tier_resolved: Some(resolved),
                note: tier_note("storage-remove", func, args[1]),
            })
        }
        // ---- TTL ----
        ("7", 4) => {
            let (tier, resolved) = resolve_tier(func, args[1]);
            Some(Recognized {
                op: KnownOp::StorageExtendTtl {
                    tier,
                    durability: args[1],
                    key: args[0],
                    resolved_key: None,
                    threshold: args[2],
                    extend_to: args[3],
                    resolved_threshold: None,
                    resolved_extend_to: None,
                },
                ty: KnownType::Unit,
                metric: M_EXTEND_TTL,
                tier_resolved: Some(resolved),
                note: tier_note("storage-extend-ttl", func, args[1]),
            })
        }
        ("8", 2) => Some(Recognized {
            op: KnownOp::ExtendCurrentContractInstanceAndCodeTtl {
                threshold: args[0],
                extend_to: args[1],
                resolved_threshold: None,
                resolved_extend_to: None,
            },
            ty: KnownType::Unit,
            metric: M_EXTEND_TTL,
            tier_resolved: None,
            note: "extend-current-contract-instance-and-code-ttl".to_string(),
        }),
        ("9", 3) => Some(Recognized {
            op: KnownOp::ExtendContractInstanceAndCodeTtl {
                contract: args[0],
                threshold: args[1],
                extend_to: args[2],
            },
            ty: KnownType::Unit,
            metric: M_EXTEND_TTL,
            tier_resolved: None,
            note: "extend-contract-instance-and-code-ttl".to_string(),
        }),
        ("c", 3) => Some(Recognized {
            op: KnownOp::ExtendContractInstanceTtl {
                contract: args[0],
                threshold: args[1],
                extend_to: args[2],
            },
            ty: KnownType::Unit,
            metric: M_EXTEND_TTL,
            tier_resolved: None,
            note: "extend-contract-instance-ttl".to_string(),
        }),
        ("d", 3) => Some(Recognized {
            op: KnownOp::ExtendContractCodeTtl {
                contract: args[0],
                threshold: args[1],
                extend_to: args[2],
            },
            ty: KnownType::Unit,
            metric: M_EXTEND_TTL,
            tier_resolved: None,
            note: "extend-contract-code-ttl".to_string(),
        }),
        ("f", 5) => {
            let (tier, resolved) = resolve_tier(func, args[1]);
            Some(Recognized {
                op: KnownOp::StorageExtendTtlV2 {
                    tier,
                    durability: args[1],
                    key: args[0],
                    resolved_key: None,
                    extend_to: args[2],
                    min_extension: args[3],
                    max_extension: args[4],
                },
                ty: KnownType::Unit,
                metric: M_EXTEND_TTL,
                tier_resolved: Some(resolved),
                note: tier_note("storage-extend-ttl-v2", func, args[1]),
            })
        }
        ("g", 5) => Some(Recognized {
            op: KnownOp::ExtendContractInstanceAndCodeTtlV2 {
                contract: args[0],
                extension_scope: args[1],
                extend_to: args[2],
                min_extension: args[3],
                max_extension: args[4],
            },
            ty: KnownType::Unit,
            metric: M_EXTEND_TTL,
            tier_resolved: None,
            note: "extend-contract-instance-and-code-ttl-v2".to_string(),
        }),
        // Deploy / upload / get-id ops (`3`,`4`,`5`,`6`,`a`,`b`,`e`) are a
        // different recognizer's scope; wrong arity on any storage op is
        // malformed IR. Either way: leave unrecognized.
        _ => None,
    }
}

/// Resolve a durability argument to a tier. Returns the tier and whether
/// it resolved to `Known`.
fn resolve_tier(func: &HighFunction, durability: ValueId) -> (StorageTier, bool) {
    match trace_int(func, durability) {
        Some(0) => (StorageTier::Known(KnownTier::Temporary), true),
        Some(1) => (StorageTier::Known(KnownTier::Persistent), true),
        Some(2) => (StorageTier::Known(KnownTier::Instance), true),
        // A constant that isn't a valid discriminant is malformed — do
        // not guess a tier from it.
        Some(_) => (
            StorageTier::Unknown(UnknownReason::UnsupportedPattern),
            false,
        ),
        // Not a constant (parameter / phi / computed) — honest unknown.
        None => (
            StorageTier::Unknown(UnknownReason::InsufficientEvidence),
            false,
        ),
    }
}

/// Build a provenance note recording the tier and the evidence.
fn tier_note(op: &str, func: &HighFunction, durability: ValueId) -> String {
    match trace_int(func, durability) {
        Some(n @ 0..=2) => {
            let tier = match n {
                0 => "temporary",
                1 => "persistent",
                _ => "instance",
            };
            format!("{op} tier={tier} (durability const {n})")
        }
        Some(other) => format!("{op} tier=unknown (invalid durability const {other})"),
        None => format!("{op} tier=unknown (durability not constant)"),
    }
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{Arena, BlockId, FuncId, IrId, Provenance};
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

    fn i32c(n: i32) -> Expr {
        Expr::Literal(Literal::I32(n))
    }

    fn host_l(name: &str, args: Vec<ValueId>) -> Expr {
        Expr::Semantic(SemanticOp::Unknown {
            host_module: "l".to_string(),
            host_fn: name.to_string(),
            args,
            reason: UnknownReason::UnsupportedPattern,
        })
    }

    fn run(func: &mut HighFunction) -> (bool, PassMetrics, Vec<Diagnostic>) {
        recognize_function(func)
    }

    fn expr_at(func: &HighFunction, id: ValueId) -> &Expr {
        &func.bindings.get(id).unwrap().expr
    }

    fn tier_of(func: &HighFunction, id: ValueId) -> StorageTier {
        match expr_at(func, id) {
            Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet { tier, .. }))
            | Expr::Semantic(SemanticOp::Known(KnownOp::StorageSet { tier, .. }))
            | Expr::Semantic(SemanticOp::Known(KnownOp::StorageHas { tier, .. }))
            | Expr::Semantic(SemanticOp::Known(KnownOp::StorageRemove { tier, .. })) => tier.clone(),
            other => panic!("expected a tiered storage op, got {other:?}"),
        }
    }

    // --- CRUD + tier constants ---

    #[test]
    fn get_with_each_tier_constant() {
        for (konst, expected) in [
            (0, KnownTier::Temporary),
            (1, KnownTier::Persistent),
            (2, KnownTier::Instance),
        ] {
            // v0 key; v1 durability const; v2 = get(key, durability)
            let mut func = func_with(vec![
                i64c(100),
                i64c(konst),
                host_l("1", vec![v(0), v(1)]),
            ]);
            let (changed, metrics, _diags) = run(&mut func);
            assert!(changed);
            assert_eq!(metrics.get(M_GET), Some(1));
            assert_eq!(metrics.get(M_TIER_RESOLVED), Some(1));
            match tier_of(&func, v(2)) {
                StorageTier::Known(t) => assert_eq!(t, expected),
                other => panic!("expected Known({expected:?}), got {other:?}"),
            }
            // get returns Val.
            assert_eq!(func.bindings.get(v(2)).unwrap().ty, IrType::Known(KnownType::Val));
        }
    }

    #[test]
    fn set_maps_key_and_value_and_unit_type() {
        // v0 key; v1 value; v2 durability=1; v3 = set(key, value, dur)
        let mut func = func_with(vec![
            i64c(0),
            i64c(0),
            i64c(1),
            host_l("_", vec![v(0), v(1), v(2)]),
        ]);
        let (changed, metrics, _diags) = run(&mut func);
        assert!(changed);
        assert_eq!(metrics.get(M_SET), Some(1));
        match expr_at(&func, v(3)) {
            Expr::Semantic(SemanticOp::Known(KnownOp::StorageSet {
                tier,
                durability: _,
                key,
                resolved_key: None,
                value,
            })) => {
                assert!(matches!(tier, StorageTier::Known(KnownTier::Persistent)));
                assert_eq!(*key, v(0));
                assert_eq!(*value, v(1));
            }
            other => panic!("expected StorageSet, got {other:?}"),
        }
        assert_eq!(func.bindings.get(v(3)).unwrap().ty, IrType::Known(KnownType::Unit));
    }

    #[test]
    fn has_returns_bool() {
        let mut func = func_with(vec![i64c(0), i64c(2), host_l("0", vec![v(0), v(1)])]);
        let (changed, _, _diags) = run(&mut func);
        assert!(changed);
        assert_eq!(func.bindings.get(v(2)).unwrap().ty, IrType::Known(KnownType::Bool));
    }

    #[test]
    fn remove_recognized() {
        let mut func = func_with(vec![i64c(0), i64c(0), host_l("2", vec![v(0), v(1)])]);
        let (changed, metrics, _diags) = run(&mut func);
        assert!(changed);
        assert_eq!(metrics.get(M_REMOVE), Some(1));
    }

    // --- tier resolution edge cases ---

    #[test]
    fn non_constant_durability_is_recognized_but_tier_unknown() {
        // v1 durability is a Phi (a function parameter) — not a constant.
        let mut func = func_with(vec![
            i64c(0),
            Expr::Phi { incoming: vec![] },
            host_l("1", vec![v(0), v(1)]),
        ]);
        let (changed, metrics, diags) = run(&mut func);
        assert!(changed, "op is still recognized even when tier is unknown");
        assert_eq!(metrics.get(M_TIER_UNKNOWN), Some(1));
        assert_eq!(metrics.get(M_TIER_RESOLVED), None);
        match tier_of(&func, v(2)) {
            StorageTier::Unknown(UnknownReason::InsufficientEvidence) => {}
            other => panic!("expected Unknown(InsufficientEvidence), got {other:?}"),
        }
        // The miss also surfaces a located diagnostic (W6), not just the
        // counter.
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code.key(), "lift::non_constant_durability_arg");
        assert_eq!(
            diags[0].location,
            Some(sordec_common::Location::Value {
                func: FuncId::from_index(0),
                value: 2
            })
        );
    }

    #[test]
    fn invalid_durability_constant_never_guesses() {
        // Durability const 7 is not a valid discriminant → Unknown, not
        // a guess. This is the exact bug class the pass exists to kill.
        let mut func = func_with(vec![i64c(0), i64c(7), host_l("1", vec![v(0), v(1)])]);
        let (changed, metrics, _diags) = run(&mut func);
        assert!(changed);
        assert_eq!(metrics.get(M_TIER_UNKNOWN), Some(1));
        match tier_of(&func, v(2)) {
            StorageTier::Unknown(UnknownReason::UnsupportedPattern) => {}
            other => panic!("expected Unknown(UnsupportedPattern), got {other:?}"),
        }
    }

    #[test]
    fn i32_durability_width_accepted() {
        // Durability arrives as an i32 const rather than i64.
        let mut func = func_with(vec![i64c(0), i32c(2), host_l("1", vec![v(0), v(1)])]);
        run(&mut func);
        assert!(matches!(
            tier_of(&func, v(2)),
            StorageTier::Known(KnownTier::Instance)
        ));
    }

    // --- TTL shapes ---

    #[test]
    fn data_ttl_l7_maps_all_fields() {
        // v0 key; v1 dur=1; v2 threshold; v3 extend_to; v4 = extend(...)
        let mut func = func_with(vec![
            i64c(0),
            i64c(1),
            i64c(100),
            i64c(200),
            host_l("7", vec![v(0), v(1), v(2), v(3)]),
        ]);
        let (changed, metrics, _diags) = run(&mut func);
        assert!(changed);
        assert_eq!(metrics.get(M_EXTEND_TTL), Some(1));
        match expr_at(&func, v(4)) {
            Expr::Semantic(SemanticOp::Known(KnownOp::StorageExtendTtl {
                tier,
                durability: _,
                key,
                resolved_key: None,
                threshold,
                extend_to,
                ..
            })) => {
                assert!(matches!(tier, StorageTier::Known(KnownTier::Persistent)));
                assert_eq!(*key, v(0));
                assert_eq!(*threshold, v(2));
                assert_eq!(*extend_to, v(3));
            }
            other => panic!("expected StorageExtendTtl, got {other:?}"),
        }
    }

    #[test]
    fn current_instance_ttl_l8_has_no_tier() {
        // v0 threshold; v1 extend_to; v2 = extend_current(...)
        let mut func = func_with(vec![i64c(0), i64c(0), host_l("8", vec![v(0), v(1)])]);
        let (changed, metrics, _diags) = run(&mut func);
        assert!(changed);
        assert_eq!(metrics.get(M_EXTEND_TTL), Some(1));
        // No tier resolution counter fires for a no-tier op.
        assert_eq!(metrics.get(M_TIER_RESOLVED), None);
        assert_eq!(metrics.get(M_TIER_UNKNOWN), None);
        assert!(matches!(
            expr_at(&func, v(2)),
            Expr::Semantic(SemanticOp::Known(
                KnownOp::ExtendCurrentContractInstanceAndCodeTtl { .. }
            ))
        ));
    }

    #[test]
    fn data_ttl_v2_l_f_maps_five_args() {
        // v0 key; v1 dur=2; v2 extend_to; v3 min; v4 max; v5 = extend_v2(...)
        let mut func = func_with(vec![
            i64c(0),
            i64c(2),
            i64c(10),
            i64c(20),
            i64c(30),
            host_l("f", vec![v(0), v(1), v(2), v(3), v(4)]),
        ]);
        let (changed, _, _diags) = run(&mut func);
        assert!(changed);
        match expr_at(&func, v(5)) {
            Expr::Semantic(SemanticOp::Known(KnownOp::StorageExtendTtlV2 {
                tier,
                durability: _,
                key,
                resolved_key: None,
                extend_to,
                min_extension,
                max_extension,
            })) => {
                assert!(matches!(tier, StorageTier::Known(KnownTier::Instance)));
                assert_eq!(*key, v(0));
                assert_eq!(*extend_to, v(2));
                assert_eq!(*min_extension, v(3));
                assert_eq!(*max_extension, v(4));
            }
            other => panic!("expected StorageExtendTtlV2, got {other:?}"),
        }
    }

    // --- non-matches ---

    #[test]
    fn deploy_op_l3_not_recognized() {
        // l.3 = create_contract is a deploy op, not storage.
        let mut func = func_with(vec![i64c(0), i64c(0), i64c(0), host_l("3", vec![v(0), v(1), v(2)])]);
        let (changed, _, _diags) = run(&mut func);
        assert!(!changed, "create_contract is not this recognizer's scope");
    }

    #[test]
    fn wrong_arity_not_recognized() {
        // get with 3 args (should be 2) is malformed → skip.
        let mut func = func_with(vec![
            i64c(0),
            i64c(1),
            i64c(9),
            host_l("1", vec![v(0), v(1), v(2)]),
        ]);
        let (changed, _, _diags) = run(&mut func);
        assert!(!changed);
    }

    #[test]
    fn non_l_module_not_recognized() {
        let expr = Expr::Semantic(SemanticOp::Unknown {
            host_module: "a".to_string(),
            host_fn: "0".to_string(),
            args: vec![v(0)],
            reason: UnknownReason::UnsupportedPattern,
        });
        let mut func = func_with(vec![i64c(0), expr]);
        let (changed, _, _diags) = run(&mut func);
        assert!(!changed);
    }

    // --- idempotency + provenance ---

    #[test]
    fn second_run_reports_no_change() {
        let mut func = func_with(vec![i64c(0), i64c(1), host_l("1", vec![v(0), v(1)])]);
        assert!(run(&mut func).0);
        assert!(!run(&mut func).0, "idempotent on rerun");
    }

    #[test]
    fn provenance_note_records_tier_and_evidence() {
        let mut func = func_with(vec![i64c(0), i64c(2), host_l("1", vec![v(0), v(1)])]);
        run(&mut func);
        let prov = func.bindings.get(v(2)).unwrap().latest_provenance();
        assert_eq!(prov.source, ProvenanceSource::HostFunctionAbi);
        assert!(prov.note.contains("tier=instance"), "note: {}", prov.note);
        assert!(prov.note.contains("durability const 2"), "note: {}", prov.note);
    }
}
