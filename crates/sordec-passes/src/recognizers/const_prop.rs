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
//! - `InvokeContract` / `TryInvokeContract` with
//!   `resolved_callee: None` — the callee symbol is a tag-14
//!   `SymbolSmall` constant or a rodata-backed `SymbolNew`; the ABI
//!   types that position as `Symbol`, so a valid decode names it.
//! - **Storage-key naming**: a storage op's `key` operand whose
//!   terminal binding is a valid tag-14 symbol literal gets that
//!   *literal binding* rewritten `Literal::I64(bits)` →
//!   `Literal::Symbol(text)` (the key position is ABI-typed `Val`).
//!   The provenance note preserves the original bits. Caveat
//!   (documented, theoretical): a binding shared between a symbol use
//!   and an unrelated raw-integer use of identical tag-shaped bits
//!   would be misrendered — rustc does not share constants across such
//!   roles, and the bits stay recoverable from provenance.
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

use std::collections::{HashMap, HashSet};

use sordec_common::{FuncId, IrId, ProvenanceSource, ValueId};
use sordec_ir::{
    Expr, HighIr, IrType, KnownOp, KnownTier, KnownType, Literal, SemanticOp,
    StorageTier,
};

use super::{apply_rewrites, Rewrite};
use crate::dataflow::{resolve_use, CallIndex, Resolver};
use crate::pass::{Pass, PassResult};
use crate::val_abi::decode_small_symbol;

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "const-prop";

// Metric counter keys.
const M_TIER_UPGRADED: &str = "const_prop_tier_upgraded";
const M_LITERAL_RESOLVED: &str = "const_prop_literal_resolved";
const M_CALLEE_NAMED: &str = "const_prop_callee_named";
const M_KEY_NAMED: &str = "const_prop_key_named";
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
        // rewrites (per owning function) through the whole-module
        // resolver.
        let calls = CallIndex::build(ir);
        let mut resolver = Resolver::new(ir, &calls);
        let mut planned: HashMap<FuncId, Vec<Rewrite>> = HashMap::new();
        // Storage-key literal rewrites plan the *literal binding*, which
        // may live in another function; dedupe globally so a shared key
        // literal is renamed once.
        let mut named_keys: HashSet<(FuncId, ValueId)> = HashSet::new();

        for func in &ir.functions {
            for (id, binding) in func.bindings.iter() {
                let Expr::Semantic(SemanticOp::Known(op)) = &binding.expr else {
                    continue;
                };
                match try_upgrade(&mut resolver, func.id, op) {
                    Upgrade::Rewrite(new_op, note, metric) => {
                        planned.entry(func.id).or_default().push(Rewrite {
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
                // Storage-key naming: collect every tag-14 symbol literal
                // reachable through the key operand (across phis, helper
                // params, and helper returns), and rename each once.
                if let Some(key) = storage_key_of(op) {
                    let mut sites = Vec::new();
                    let mut visited = HashSet::new();
                    collect_literal_sites(ir, &calls, func.id, key, &mut sites, &mut visited, 0);
                    for (site_fn, site_id, bits) in sites {
                        let Some(text) = decode_small_symbol(bits) else {
                            continue;
                        };
                        if named_keys.insert((site_fn, site_id)) {
                            planned.entry(site_fn).or_default().push(Rewrite {
                                id: site_id,
                                expr: Expr::Literal(Literal::Symbol(text.clone())),
                                ty: Some(IrType::Known(KnownType::Symbol)),
                                source: ProvenanceSource::DataFlow,
                                note: format!(
                                    "const-prop key symbol {text:?} (decoded SymbolSmall 0x{bits:x})"
                                ),
                                metric: M_KEY_NAMED,
                            });
                        }
                    }
                }
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

        // ---- Cross-contract callee naming: None → Some via the
        // symbol constant in the ABI-typed Symbol position ----
        KnownOp::InvokeContract {
            resolved_callee: None,
            function,
            ..
        }
        | KnownOp::TryInvokeContract {
            resolved_callee: None,
            function,
            ..
        } => match resolver.resolve_symbol_text(func, *function) {
            Some(callee) => {
                let note = format!("const-prop callee={callee:?} (symbol const)");
                let mut upgraded = op.clone();
                match &mut upgraded {
                    KnownOp::InvokeContract {
                        resolved_callee, ..
                    }
                    | KnownOp::TryInvokeContract {
                        resolved_callee, ..
                    } => *resolved_callee = Some(callee),
                    _ => unreachable!("cloned from an invoke variant"),
                }
                Upgrade::Rewrite(upgraded, note, M_CALLEE_NAMED)
            }
            None => Upgrade::StillUnresolved,
        },

        _ => Upgrade::NotATarget,
    }
}

/// Depth bound for the storage-key site collection (mirrors the
/// resolver's `DEFAULT_RESOLVE_DEPTH`).
const KEY_COLLECT_DEPTH: u32 = 128;

/// The `key` operand of a storage op, or `None` for a non-storage op.
fn storage_key_of(op: &KnownOp) -> Option<ValueId> {
    match op {
        KnownOp::StorageGet { key, .. }
        | KnownOp::StorageSet { key, .. }
        | KnownOp::StorageHas { key, .. }
        | KnownOp::StorageRemove { key, .. }
        | KnownOp::StorageExtendTtl { key, .. }
        | KnownOp::StorageExtendTtlV2 { key, .. } => Some(*key),
        _ => None,
    }
}

/// Collect every integer-literal binding reachable through `value`, as
/// `(owning_func, literal_binding, bits)`. Unlike the resolver's
/// value-meet, this is a **reachability collection** (union): different
/// witnessed paths legitimately reach different constants (distinct
/// `DataKey` symbols on distinct static paths), and each is independently
/// anchored by the operand's `Val`-typed position. Callers classify the
/// raw `bits` — a tag-14 `SymbolSmall`, the Void `Val`, … — and skip
/// non-matching sites. The `visited` set is global to this collection: a
/// node is expanded once (reachability is arrival-path-independent),
/// which is both complete and O(nodes+edges).
///
/// Fan-out: `resolve_use` chase → an `I64`/`U64` literal is a site → a
/// phi fans to all incoming → a parameter fans to every caller's
/// positional arg → a `Call` fans to the callee's return sites (only
/// when every site is single-valued). A non-integer terminal (an
/// already-named `Literal::Symbol` / `Literal::Unit`, a computed value)
/// is a non-site — which also makes re-runs idempotent. Malformed edges
/// are skipped, never aborting the collection.
fn collect_literal_sites(
    ir: &HighIr,
    calls: &CallIndex,
    func_id: FuncId,
    value: ValueId,
    out: &mut Vec<(FuncId, ValueId, u64)>,
    visited: &mut HashSet<(FuncId, ValueId)>,
    depth: u32,
) {
    if depth >= KEY_COLLECT_DEPTH {
        return;
    }
    let Some(func) = ir.function(func_id) else {
        return;
    };
    let terminal = resolve_use(func, value);
    if (terminal.index() as usize) >= func.bindings.len() || !visited.insert((func_id, terminal)) {
        return;
    }
    let Some(binding) = func.bindings.get(terminal) else {
        return;
    };

    // Parameter fan-out: to every caller's positional argument. (A
    // parameter is an empty-incoming Phi; fanning to callers is the
    // location analogue of the resolver's param path, sound existentially
    // even without the exported/indirect guards.)
    if let Some(index) = func.params.iter().position(|p| *p == terminal) {
        for site in calls.callers_of(func_id) {
            let Some(caller) = ir.function(site.caller) else {
                continue;
            };
            if (site.call.index() as usize) >= caller.bindings.len() {
                continue;
            }
            let Some(cb) = caller.bindings.get(site.call) else {
                continue;
            };
            let Expr::Call { args, .. } = &cb.expr else {
                continue;
            };
            let Some(arg) = args.get(index) else {
                continue;
            };
            collect_literal_sites(ir, calls, site.caller, *arg, out, visited, depth + 1);
        }
        return;
    }

    match &binding.expr {
        Expr::Literal(Literal::I64(bits)) => out.push((func_id, terminal, *bits as u64)),
        Expr::Literal(Literal::U64(bits)) => out.push((func_id, terminal, *bits)),
        Expr::Phi { incoming } => {
            for (_, v) in incoming {
                collect_literal_sites(ir, calls, func_id, *v, out, visited, depth + 1);
            }
        }
        Expr::Call { target, .. } => {
            let Some(callee) = ir.function(*target) else {
                return;
            };
            // Same single-value-site discipline as the resolver's Call
            // arm: a multi-value or diverging callee's result is not a
            // scalar the literal can flow from.
            if callee.returns.is_empty() || callee.returns.iter().any(|vs| vs.len() != 1) {
                return;
            }
            let callee_id = *target;
            let sites: Vec<ValueId> = callee.returns.iter().map(|vs| vs[0]).collect();
            for rv in sites {
                collect_literal_sites(ir, calls, callee_id, rv, out, visited, depth + 1);
            }
        }
        // Already-named literals and everything else: non-site.
        _ => {}
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
            returns: vec![],
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
                resolved_key: None,
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

    // --- callee naming ---

    fn tag14_bits(text: &str) -> i64 {
        let mut body = 0u64;
        for c in text.bytes() {
            let code = match c {
                b'_' => 1,
                b'0'..=b'9' => 2 + (c - b'0'),
                b'A'..=b'Z' => 12 + (c - b'A'),
                b'a'..=b'z' => 38 + (c - b'a'),
                _ => panic!("invalid symbol char"),
            };
            body = (body << 6) | u64::from(code);
        }
        ((body << 8) | 14) as i64
    }

    fn invoke(contract: u32, function: u32, args: u32) -> Expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::InvokeContract {
            contract: v(contract),
            function: v(function),
            args: vec![v(args)],
            resolved_callee: None,
            arg_count: None,
            resolved_args: None,
            interface: None,
        }))
    }

    #[test]
    fn callee_named_from_local_symbol_constant() {
        let mut ir = module(vec![func(
            0,
            None,
            0,
            vec![i64c(0), i64c(tag14_bits("transfer")), i64c(0), invoke(0, 1, 2)],
        )]);
        let result = run(&mut ir);
        assert!(result.changed);
        assert_eq!(result.metrics.get(M_CALLEE_NAMED), Some(1));
        let f0 = ir.function(f(0)).unwrap();
        match &f0.bindings.get(v(3)).unwrap().expr {
            Expr::Semantic(SemanticOp::Known(KnownOp::InvokeContract {
                resolved_callee, ..
            })) => assert_eq!(resolved_callee.as_deref(), Some("transfer")),
            other => panic!("expected named InvokeContract, got {other:?}"),
        }
    }

    #[test]
    fn callee_named_through_helper_parameter() {
        // The invoke sits in an un-exported helper; the caller passes
        // the symbol constant.
        let mut ir = module(vec![
            func(0, None, 3, vec![invoke(0, 1, 2)]), // params: contract, fn, args
            func(
                1,
                None,
                0,
                vec![
                    i64c(0),
                    i64c(tag14_bits("balance")),
                    i64c(0),
                    Expr::Call {
                        target: f(0),
                        args: vec![v(0), v(1), v(2)],
                    },
                ],
            ),
        ]);
        let result = run(&mut ir);
        assert_eq!(result.metrics.get(M_CALLEE_NAMED), Some(1));
        let helper = ir.function(f(0)).unwrap();
        match &helper.bindings.get(v(3)).unwrap().expr {
            Expr::Semantic(SemanticOp::Known(KnownOp::InvokeContract {
                resolved_callee, ..
            })) => assert_eq!(resolved_callee.as_deref(), Some("balance")),
            other => panic!("expected named InvokeContract, got {other:?}"),
        }
    }

    #[test]
    fn callee_named_from_symbol_new_rederivation() {
        // The callee traces to a SymbolNew whose (pos, len) resolve;
        // the text re-derives from rodata regardless of its own
        // `resolved` slot.
        let mut ir = module(vec![func(
            0,
            None,
            0,
            vec![
                i64c(0), // contract
                i64c(u32val_bits(100)),
                i64c(u32val_bits(8)),
                Expr::Semantic(SemanticOp::Known(KnownOp::SymbolNew {
                    lm_pos: v(1),
                    len: v(2),
                    resolved: None,
                })),
                i64c(0), // args vec handle
                invoke(0, 3, 4),
            ],
        )]);
        ir.memory = MemoryImage::from_segments(vec![DataSegment {
            offset: 100,
            bytes: b"transfer".to_vec(),
        }]);
        let result = run(&mut ir);
        assert_eq!(result.metrics.get(M_CALLEE_NAMED), Some(1));
        let f0 = ir.function(f(0)).unwrap();
        match &f0.bindings.get(v(5)).unwrap().expr {
            Expr::Semantic(SemanticOp::Known(KnownOp::InvokeContract {
                resolved_callee, ..
            })) => assert_eq!(resolved_callee.as_deref(), Some("transfer")),
            other => panic!("expected named InvokeContract, got {other:?}"),
        }
    }

    #[test]
    fn callee_with_invalid_bits_stays_unnamed() {
        // A non-tag-14 constant in the callee slot must not produce a
        // garbled name.
        let mut ir = module(vec![func(
            0,
            None,
            0,
            vec![i64c(0), i64c(12345), i64c(0), invoke(0, 1, 2)],
        )]);
        let result = run(&mut ir);
        assert!(!result.changed);
        assert_eq!(result.metrics.get(M_UNRESOLVED), Some(1));
    }

    // --- storage-key naming ---

    #[test]
    fn storage_key_literal_renamed_to_symbol() {
        let mut ir = module(vec![func(
            0,
            None,
            0,
            vec![
                i64c(tag14_bits("Admin")),
                i64c(2),
                Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet {
                    tier: StorageTier::Known(KnownTier::Instance),
                    durability: v(1),
                    key: v(0),
                    resolved_key: None,
                })),
            ],
        )]);
        let result = run(&mut ir);
        assert!(result.changed);
        assert_eq!(result.metrics.get(M_KEY_NAMED), Some(1));
        let f0 = ir.function(f(0)).unwrap();
        let key_binding = f0.bindings.get(v(0)).unwrap();
        match &key_binding.expr {
            Expr::Literal(Literal::Symbol(text)) => assert_eq!(text, "Admin"),
            other => panic!("expected Symbol literal, got {other:?}"),
        }
        assert_eq!(
            key_binding.ty,
            IrType::Known(sordec_ir::KnownType::Symbol)
        );
        // Provenance preserves the original bits.
        let note = &key_binding.latest_provenance().note;
        assert!(note.contains("0x"), "note: {note}");
    }

    #[test]
    fn shared_key_literal_renamed_once() {
        // Two ops share one key literal — the rewrite is planned once.
        let get = |key: u32, dur: u32| {
            Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet {
                tier: StorageTier::Known(KnownTier::Instance),
                durability: v(dur),
                key: v(key),
                resolved_key: None,
            }))
        };
        let mut ir = module(vec![func(
            0,
            None,
            0,
            vec![i64c(tag14_bits("State")), i64c(2), get(0, 1), get(0, 1)],
        )]);
        let result = run(&mut ir);
        assert_eq!(result.metrics.get(M_KEY_NAMED), Some(1));
    }

    fn call(target: u32, args: Vec<ValueId>) -> Expr {
        Expr::Call {
            target: f(target),
            args,
        }
    }

    fn with_returns(mut f: HighFunction, sites: Vec<Vec<u32>>) -> HighFunction {
        f.returns = sites
            .into_iter()
            .map(|vals| vals.into_iter().map(v).collect())
            .collect();
        f
    }

    fn storage_get(key: u32, dur: u32) -> Expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet {
            tier: StorageTier::Known(KnownTier::Instance),
            durability: v(dur),
            key: v(key),
            resolved_key: None,
        }))
    }

    #[test]
    fn key_named_through_helper_return() {
        // The exact corpus shape: func_4 returns the METADATA constant;
        // a caller's storage op uses that call result as its key.
        // f0 = the DataKey-returning helper; f1 does
        //   v0 = call f0; v1 = dur=2; v2 = storage_get(key=v0, dur=v1)
        let f0 = with_returns(
            func(0, None, 0, vec![i64c(tag14_bits("METADATA"))]),
            vec![vec![0]],
        );
        let f1 = func(
            1,
            None,
            0,
            vec![call(0, vec![]), i64c(2), storage_get(0, 1)],
        );
        let mut ir = module(vec![f0, f1]);
        let result = run(&mut ir);
        assert_eq!(result.metrics.get(M_KEY_NAMED), Some(1));
        // The rename lands on the LITERAL binding in f0, not the caller.
        let helper = ir.function(f(0)).unwrap();
        match &helper.bindings.get(v(0)).unwrap().expr {
            Expr::Literal(Literal::Symbol(text)) => assert_eq!(text, "METADATA"),
            other => panic!("expected renamed Symbol in helper, got {other:?}"),
        }
    }

    #[test]
    fn key_param_fans_to_two_helper_literals() {
        // f0(key) does storage_get(key). Two callers pass two DIFFERENT
        // DataKey symbols — collection (not meet) renames BOTH.
        let f0 = func(0, None, 1, vec![i64c(2), storage_get(0, 1)]);
        let f1 = func(
            1,
            None,
            0,
            vec![i64c(tag14_bits("Admin")), call(0, vec![v(0)])],
        );
        let f2 = func(
            2,
            None,
            0,
            vec![i64c(tag14_bits("State")), call(0, vec![v(0)])],
        );
        let mut ir = module(vec![f0, f1, f2]);
        let result = run(&mut ir);
        assert_eq!(result.metrics.get(M_KEY_NAMED), Some(2));
        assert!(matches!(
            &ir.function(f(1)).unwrap().bindings.get(v(0)).unwrap().expr,
            Expr::Literal(Literal::Symbol(t)) if t == "Admin"
        ));
        assert!(matches!(
            &ir.function(f(2)).unwrap().bindings.get(v(0)).unwrap().expr,
            Expr::Literal(Literal::Symbol(t)) if t == "State"
        ));
    }

    #[test]
    fn key_naming_through_return_is_idempotent() {
        let f0 = with_returns(
            func(0, None, 0, vec![i64c(tag14_bits("METADATA"))]),
            vec![vec![0]],
        );
        let f1 = func(1, None, 0, vec![call(0, vec![]), i64c(2), storage_get(0, 1)]);
        let mut ir = module(vec![f0, f1]);
        assert!(run(&mut ir).changed);
        assert!(!run(&mut ir).changed, "renamed literal no longer matches");
    }

    #[test]
    fn naming_is_idempotent() {
        let mut ir = module(vec![func(
            0,
            None,
            0,
            vec![
                i64c(tag14_bits("Admin")),
                i64c(2),
                Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet {
                    tier: StorageTier::Known(KnownTier::Instance),
                    durability: v(1),
                    key: v(0),
                    resolved_key: None,
                })),
                i64c(0),
                i64c(tag14_bits("transfer")),
                i64c(0),
                invoke(3, 4, 5),
            ],
        )]);
        assert!(run(&mut ir).changed);
        let second = run(&mut ir);
        assert!(!second.changed, "filled slots and Symbol literals no longer match");
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
                resolved_key: None,
            }))],
        )]);
        let result = run(&mut ir);
        assert!(!result.changed);
        assert_eq!(result.metrics.get(M_UNRESOLVED), None);
    }
}
