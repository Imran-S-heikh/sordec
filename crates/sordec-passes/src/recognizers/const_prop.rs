//! The constant-propagation upgrade pass.
//!
//! Unlike the recognizers before it — which turn `SemanticOp::Unknown`
//! host calls into `Known` ops — this pass refines ops that are
//! **already `Known`** but carry an honestly-unresolved slot the
//! intra-procedural tracers could not fill:
//!
//! - `Storage*` ops with `tier: StorageTier::Unknown(_)` — the
//!   durability constant lives at a caller of the rustc-hoisted helper.
//!   Re-resolved from the retained `durability` operand via the
//!   inter-procedural [`Resolver`]: `Unknown → Known`.
//! - `SymbolNew` / `StringNew` / `BytesNew` with `resolved: None` — the
//!   `(lm_pos, len)` pair threads through phi chains / helper
//!   parameters. Re-resolved against the module rodata: `None → Some`.
//!
//! Both upgrade directions are exactly the monotonicity contract
//! (`Unknown → Known`, never the reverse), and the pass is idempotent:
//! a filled slot no longer matches, so a second run reports
//! `changed: false`.
//!
//! ## Shape
//!
//! Two-phase, per the codebase's scan-then-apply convention:
//! **Phase A** builds a [`CallIndex`] snapshot and walks every
//! function's bindings read-only, resolving upgradable slots through a
//! [`Resolver`] (which may read *other* functions — the reason the
//! whole phase is immutable). **Phase B** applies the collected
//! rewrites per function. Note this pass deliberately does **not** use
//! the `is_recognized` skip guard — its entire domain is already-Known
//! ops.

use sordec_common::{FuncId, ProvenanceSource};
use sordec_ir::{Expr, HighIr, KnownOp, KnownTier, SemanticOp, StorageTier};

use super::{apply_rewrites, Rewrite};
use crate::dataflow::{CallIndex, Resolver};
use crate::pass::{Pass, PassResult};

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "const-prop";

// Metric counter keys.
const M_TIER_UPGRADED: &str = "const_prop_tier_upgraded";
const M_LITERAL_RESOLVED: &str = "const_prop_literal_resolved";
/// Upgrade attempts that stayed honestly unresolved (the engine's
/// remaining-work signal).
const M_UNRESOLVED: &str = "const_prop_unresolved";

/// The constant-propagation upgrade pass. Stateless between runs.
#[derive(Debug, Default, Clone, Copy)]
pub struct ConstPropPass;

impl Pass<HighIr> for ConstPropPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();

        // Phase A — read-only: snapshot the call graph, then collect
        // rewrites per function through the whole-module resolver.
        let calls = CallIndex::build(ir);
        let mut resolver = Resolver::new(ir, &calls);
        let mut planned: Vec<(FuncId, Vec<Rewrite>)> = Vec::new();
        for func in &ir.functions {
            let mut rewrites: Vec<Rewrite> = Vec::new();
            for (id, binding) in func.bindings.iter() {
                let Expr::Semantic(SemanticOp::Known(op)) = &binding.expr else {
                    continue;
                };
                match try_upgrade(&mut resolver, func.id, op) {
                    Upgrade::Rewrite(new_op, note, metric) => {
                        rewrites.push(Rewrite {
                            id,
                            expr: Expr::Semantic(SemanticOp::Known(new_op)),
                            // The op's ABI result type was already set at
                            // recognition; nothing to refine here.
                            ty: None,
                            source: ProvenanceSource::DataFlow,
                            note,
                            metric,
                        });
                    }
                    Upgrade::StillUnresolved => {
                        result.metrics.increment(M_UNRESOLVED, 1);
                    }
                    Upgrade::NotATarget => {}
                }
            }
            if !rewrites.is_empty() {
                planned.push((func.id, rewrites));
            }
        }
        drop(resolver);

        // Phase B — apply per function.
        for (func_id, rewrites) in planned {
            for rw in &rewrites {
                result.metrics.increment(rw.metric, 1);
            }
            result.changed = true;
            if let Some(func) = ir.function_mut(func_id) {
                apply_rewrites(func, PASS_NAME, rewrites);
            }
        }
        result
    }
}

/// Outcome of inspecting one Known op.
enum Upgrade {
    /// The op had an unresolved slot and the resolver filled it.
    Rewrite(KnownOp, String, &'static str),
    /// The op had an unresolved slot but it stays honest.
    StillUnresolved,
    /// The op carries no unresolved slot.
    NotATarget,
}

/// Attempt to upgrade one already-Known op.
fn try_upgrade(resolver: &mut Resolver<'_>, func: FuncId, op: &KnownOp) -> Upgrade {
    match op {
        // ---- Storage tiers: Unknown → Known via the retained
        // durability operand ----
        KnownOp::StorageGet {
            tier: StorageTier::Unknown(_),
            durability,
            ..
        }
        | KnownOp::StorageSet {
            tier: StorageTier::Unknown(_),
            durability,
            ..
        }
        | KnownOp::StorageHas {
            tier: StorageTier::Unknown(_),
            durability,
            ..
        }
        | KnownOp::StorageRemove {
            tier: StorageTier::Unknown(_),
            durability,
            ..
        }
        | KnownOp::StorageExtendTtl {
            tier: StorageTier::Unknown(_),
            durability,
            ..
        }
        | KnownOp::StorageExtendTtlV2 {
            tier: StorageTier::Unknown(_),
            durability,
            ..
        } => {
            let Some(known) = resolve_tier(resolver, func, *durability) else {
                return Upgrade::StillUnresolved;
            };
            let mut upgraded = op.clone();
            set_tier(&mut upgraded, StorageTier::Known(known));
            Upgrade::Rewrite(
                upgraded,
                format!(
                    "const-prop tier={} (durability const via phi/caller)",
                    tier_name(known)
                ),
                M_TIER_UPGRADED,
            )
        }

        // ---- Linear-memory literals: None → Some via rodata ----
        KnownOp::SymbolNew {
            lm_pos,
            len,
            resolved: None,
        } => match resolve_text(resolver, func, op) {
            Some(text) => Upgrade::Rewrite(
                KnownOp::SymbolNew {
                    lm_pos: *lm_pos,
                    len: *len,
                    resolved: Some(text),
                },
                "const-prop resolved symbol (rodata via phi/caller)".to_string(),
                M_LITERAL_RESOLVED,
            ),
            None => Upgrade::StillUnresolved,
        },
        KnownOp::StringNew {
            lm_pos,
            len,
            resolved: None,
        } => match resolve_text(resolver, func, op) {
            Some(text) => Upgrade::Rewrite(
                KnownOp::StringNew {
                    lm_pos: *lm_pos,
                    len: *len,
                    resolved: Some(text),
                },
                "const-prop resolved string (rodata via phi/caller)".to_string(),
                M_LITERAL_RESOLVED,
            ),
            None => Upgrade::StillUnresolved,
        },
        KnownOp::BytesNew {
            lm_pos,
            len,
            resolved: None,
        } => match resolver.resolve_bytes(func, *lm_pos, *len) {
            Some(bytes) => Upgrade::Rewrite(
                KnownOp::BytesNew {
                    lm_pos: *lm_pos,
                    len: *len,
                    resolved: Some(bytes),
                },
                "const-prop resolved bytes (rodata via phi/caller)".to_string(),
                M_LITERAL_RESOLVED,
            ),
            None => Upgrade::StillUnresolved,
        },

        _ => Upgrade::NotATarget,
    }
}

/// Resolve a durability operand to a known tier, mirroring the storage
/// recognizer's discriminant mapping (an out-of-range constant is
/// malformed — never guess).
fn resolve_tier(resolver: &mut Resolver<'_>, func: FuncId, durability: sordec_common::ValueId) -> Option<KnownTier> {
    match resolver.resolve_int(func, durability)? {
        0 => Some(KnownTier::Temporary),
        1 => Some(KnownTier::Persistent),
        2 => Some(KnownTier::Instance),
        _ => None,
    }
}

/// Resolve a symbol/string op's `(lm_pos, len)` to UTF-8 text.
fn resolve_text(resolver: &mut Resolver<'_>, func: FuncId, op: &KnownOp) -> Option<String> {
    let (pos, len) = match op {
        KnownOp::SymbolNew { lm_pos, len, .. } | KnownOp::StringNew { lm_pos, len, .. } => {
            (*lm_pos, *len)
        }
        _ => return None,
    };
    String::from_utf8(resolver.resolve_bytes(func, pos, len)?).ok()
}

/// Write a resolved tier into an upgraded op clone.
fn set_tier(op: &mut KnownOp, new_tier: StorageTier) {
    match op {
        KnownOp::StorageGet { tier, .. }
        | KnownOp::StorageSet { tier, .. }
        | KnownOp::StorageHas { tier, .. }
        | KnownOp::StorageRemove { tier, .. }
        | KnownOp::StorageExtendTtl { tier, .. }
        | KnownOp::StorageExtendTtlV2 { tier, .. } => *tier = new_tier,
        _ => {}
    }
}

fn tier_name(tier: KnownTier) -> &'static str {
    match tier {
        KnownTier::Temporary => "temporary",
        KnownTier::Persistent => "persistent",
        KnownTier::Instance => "instance",
    }
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{Arena, BlockId, IrId, Provenance, UnknownReason, ValueId};
    use sordec_ir::{
        Binding, DataSegment, HighBlock, HighFunction, IrType, Literal, MemoryImage, Region,
        WasmFacts,
    };

    // Multi-function builders (same conventions as dataflow/const_prop).

    fn func(id: u32, name: Option<&str>, n_params: usize, exprs: Vec<Expr>) -> HighFunction {
        let mut bindings: Arena<ValueId, Binding> = Arena::new();
        let mut params = Vec::new();
        for _ in 0..n_params {
            let vid = ValueId::from_index(bindings.len() as u32);
            bindings.push(Binding::new(
                vid,
                IrType::Unknown(UnknownReason::InsufficientEvidence),
                Expr::Phi { incoming: vec![] },
                Provenance::new("test", ProvenanceSource::DataFlow, "param"),
            ));
            params.push(vid);
        }
        for expr in exprs {
            let vid = ValueId::from_index(bindings.len() as u32);
            bindings.push(Binding::new(
                vid,
                IrType::Unknown(UnknownReason::InsufficientEvidence),
                expr,
                Provenance::new("test", ProvenanceSource::DataFlow, "seed"),
            ));
        }
        let mut blocks: Arena<BlockId, HighBlock> = Arena::new();
        blocks.push(HighBlock {
            id: BlockId::from_index(0),
            bindings: vec![],
        });
        HighFunction {
            id: FuncId::from_index(id),
            name: name.map(str::to_string),
            signature: None,
            blocks,
            bindings,
            region: Region::Unreachable,
            params,
        }
    }

    fn module(functions: Vec<HighFunction>) -> HighIr {
        HighIr {
            facts: WasmFacts {
                imports: vec![],
                exports: vec![],
                function_type_indices: vec![],
                custom_sections: vec![],
            },
            soroban_facts: None,
            functions,
            memory: MemoryImage::empty(),
        }
    }

    fn v(i: u32) -> ValueId {
        ValueId::from_index(i)
    }

    fn f(i: u32) -> FuncId {
        FuncId::from_index(i)
    }

    fn i64c(n: i64) -> Expr {
        Expr::Literal(Literal::I64(n))
    }

    fn u32val_bits(n: u32) -> i64 {
        (((n as u64) << 32) | 4) as i64
    }

    fn run(ir: &mut HighIr) -> PassResult {
        ConstPropPass.run(ir)
    }

    /// The corpus shape: an un-exported helper takes `(key, durability)`
    /// as params; the recognized StorageGet inside carries
    /// `tier: Unknown` with the durability param retained.
    fn helper_with_unknown_tier() -> HighFunction {
        func(
            0,
            None,
            2, // v0 = key param, v1 = durability param
            vec![Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet {
                tier: StorageTier::Unknown(UnknownReason::InsufficientEvidence),
                durability: v(1),
                key: v(0),
            }))],
        )
    }

    #[test]
    fn tier_upgrades_from_caller_constant() {
        // Caller passes durability const 2 (instance).
        let mut ir = module(vec![
            helper_with_unknown_tier(),
            func(
                1,
                None,
                0,
                vec![
                    i64c(9), // key (irrelevant)
                    i64c(2), // durability const
                    Expr::Call {
                        target: f(0),
                        args: vec![v(0), v(1)],
                    },
                ],
            ),
        ]);
        let result = run(&mut ir);
        assert!(result.changed);
        assert_eq!(result.metrics.get(M_TIER_UPGRADED), Some(1));
        let helper = ir.function(f(0)).unwrap();
        match &helper.bindings.get(v(2)).unwrap().expr {
            Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet { tier, .. })) => {
                assert!(matches!(tier, StorageTier::Known(KnownTier::Instance)));
            }
            other => panic!("expected upgraded StorageGet, got {other:?}"),
        }
    }

    #[test]
    fn disagreeing_callers_stay_honestly_unknown() {
        let mut ir = module(vec![
            helper_with_unknown_tier(),
            func(
                1,
                None,
                0,
                vec![
                    i64c(0),
                    i64c(1), // persistent
                    Expr::Call {
                        target: f(0),
                        args: vec![v(0), v(1)],
                    },
                ],
            ),
            func(
                2,
                None,
                0,
                vec![
                    i64c(0),
                    i64c(2), // instance — disagrees
                    Expr::Call {
                        target: f(0),
                        args: vec![v(0), v(1)],
                    },
                ],
            ),
        ]);
        let result = run(&mut ir);
        assert!(!result.changed);
        assert_eq!(result.metrics.get(M_UNRESOLVED), Some(1));
        let helper = ir.function(f(0)).unwrap();
        assert!(matches!(
            &helper.bindings.get(v(2)).unwrap().expr,
            Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet {
                tier: StorageTier::Unknown(_),
                ..
            }))
        ));
    }

    #[test]
    fn invalid_durability_constant_never_guesses() {
        // Caller passes 7 — not a valid discriminant.
        let mut ir = module(vec![
            helper_with_unknown_tier(),
            func(
                1,
                None,
                0,
                vec![
                    i64c(0),
                    i64c(7),
                    Expr::Call {
                        target: f(0),
                        args: vec![v(0), v(1)],
                    },
                ],
            ),
        ]);
        let result = run(&mut ir);
        assert!(!result.changed);
        assert_eq!(result.metrics.get(M_UNRESOLVED), Some(1));
    }

    #[test]
    fn symbol_literal_fills_across_call_boundary() {
        // Helper builds a symbol from (pos, len) params; caller passes
        // U32Val constants; rodata holds the text.
        let mut ir = module(vec![
            func(
                0,
                None,
                2,
                vec![Expr::Semantic(SemanticOp::Known(KnownOp::SymbolNew {
                    lm_pos: v(0),
                    len: v(1),
                    resolved: None,
                }))],
            ),
            func(
                1,
                None,
                0,
                vec![
                    i64c(u32val_bits(100)),
                    i64c(u32val_bits(8)),
                    Expr::Call {
                        target: f(0),
                        args: vec![v(0), v(1)],
                    },
                ],
            ),
        ]);
        ir.memory = MemoryImage::from_segments(vec![DataSegment {
            offset: 100,
            bytes: b"transfer".to_vec(),
        }]);
        let result = run(&mut ir);
        assert!(result.changed);
        assert_eq!(result.metrics.get(M_LITERAL_RESOLVED), Some(1));
        let helper = ir.function(f(0)).unwrap();
        match &helper.bindings.get(v(2)).unwrap().expr {
            Expr::Semantic(SemanticOp::Known(KnownOp::SymbolNew { resolved, .. })) => {
                assert_eq!(resolved.as_deref(), Some("transfer"));
            }
            other => panic!("expected filled SymbolNew, got {other:?}"),
        }
    }

    #[test]
    fn unreachable_constants_stay_unresolved() {
        // No caller at all: the params never resolve.
        let mut ir = module(vec![func(
            0,
            None,
            2,
            vec![Expr::Semantic(SemanticOp::Known(KnownOp::SymbolNew {
                lm_pos: v(0),
                len: v(1),
                resolved: None,
            }))],
        )]);
        let result = run(&mut ir);
        assert!(!result.changed);
        assert_eq!(result.metrics.get(M_UNRESOLVED), Some(1));
    }

    #[test]
    fn second_run_reports_no_change() {
        let mut ir = module(vec![
            helper_with_unknown_tier(),
            func(
                1,
                None,
                0,
                vec![
                    i64c(9),
                    i64c(2),
                    Expr::Call {
                        target: f(0),
                        args: vec![v(0), v(1)],
                    },
                ],
            ),
        ]);
        assert!(run(&mut ir).changed);
        let second = run(&mut ir);
        assert!(!second.changed, "idempotent: filled slots no longer match");
        assert_eq!(second.metrics.get(M_TIER_UPGRADED), None);
    }

    #[test]
    fn provenance_appended_with_dataflow_source() {
        let mut ir = module(vec![
            helper_with_unknown_tier(),
            func(
                1,
                None,
                0,
                vec![
                    i64c(9),
                    i64c(0), // temporary
                    Expr::Call {
                        target: f(0),
                        args: vec![v(0), v(1)],
                    },
                ],
            ),
        ]);
        run(&mut ir);
        let helper = ir.function(f(0)).unwrap();
        let binding = helper.bindings.get(v(2)).unwrap();
        let prov = binding.latest_provenance();
        assert_eq!(prov.pass, PASS_NAME);
        assert_eq!(prov.source, ProvenanceSource::DataFlow);
        assert!(prov.note.contains("tier=temporary"), "note: {}", prov.note);
        // Append-only: the recognition-time entry is still there.
        assert!(binding.provenance().len() >= 2);
    }

    #[test]
    fn already_known_tier_untouched() {
        // A Known tier is not a target — nothing changes, no unresolved
        // counter fires.
        let mut ir = module(vec![func(
            0,
            None,
            2,
            vec![Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet {
                tier: StorageTier::Known(KnownTier::Persistent),
                durability: v(1),
                key: v(0),
            }))],
        )]);
        let result = run(&mut ir);
        assert!(!result.changed);
        assert_eq!(result.metrics.get(M_UNRESOLVED), None);
    }
}
