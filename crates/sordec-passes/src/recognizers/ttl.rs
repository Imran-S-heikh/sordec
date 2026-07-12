//! The TTL ledger-amount recognizer (spec D3).
//!
//! Soroban TTL-extension calls carry their `threshold` / `extend_to`
//! operands as `U32Val`-encoded ledger counts — the SDK's
//! `INSTANCE_BUMP_AMOUNT` / `BALANCE_BUMP_AMOUNT`-class magic numbers,
//! all multiples of [`DAY_IN_LEDGERS`](crate::ledger::DAY_IN_LEDGERS).
//! This pass resolves those operands to their constant ledger count and
//! records it in the op's `resolved_threshold` / `resolved_extend_to`
//! slots, naming the human duration in the provenance note.
//!
//! It runs **after** `const-prop`, so a `StorageExtendTtl`'s tier is
//! already resolved on the binding; filling the TTL slots here is a
//! second, independent refinement that never contends with the tier
//! rewrite. Resolution is the inter-procedural [`Resolver`] — the
//! persistent-balance bump threads its amount through a helper parameter
//! — and stays honestly `None` when the callers disagree or the operand
//! is computed (e.g. a `ledger_seq + amount` allowance TTL).

use std::collections::HashMap;

use sordec_common::{FuncId, ProvenanceSource, ValueId};
use sordec_ir::{Expr, HighIr, KnownOp, SemanticOp};

use super::{apply_rewrites, Rewrite};
use crate::dataflow::{CallIndex, Resolver};
use crate::ledger::ledger_duration_name;
use crate::pass::{Pass, PassResult};

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "ttl";

// Metric counter keys.
/// TTL ops that gained at least one resolved ledger amount.
const M_RESOLVED: &str = "ttl_resolved";
/// TTL ops with an amount that stayed honestly unresolved.
const M_UNRESOLVED: &str = "ttl_unresolved";

/// The TTL ledger-amount recognizer. Stateless between runs.
#[derive(Debug, Default, Clone, Copy)]
pub struct TtlPass;

impl Pass<HighIr> for TtlPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();

        // Phase A — read-only scan through the whole-module resolver.
        let calls = CallIndex::build(ir);
        let mut resolver = Resolver::new(ir, &calls);
        let mut planned: HashMap<FuncId, Vec<Rewrite>> = HashMap::new();

        for func in &ir.functions {
            for (id, binding) in func.bindings.iter() {
                let Expr::Semantic(SemanticOp::Known(op)) = &binding.expr else {
                    continue;
                };
                let Some(amounts) = ttl_amounts(op) else {
                    continue;
                };
                match resolve_amounts(&mut resolver, func.id, amounts) {
                    Resolution::Filled(new_op, note) => {
                        planned.entry(func.id).or_default().push(Rewrite {
                            id,
                            expr: Expr::Semantic(SemanticOp::Known(new_op)),
                            // The op's ABI result type (Unit) already stands.
                            ty: None,
                            source: ProvenanceSource::DataFlow,
                            note,
                            metric: M_RESOLVED,
                        });
                    }
                    Resolution::StillUnresolved => {
                        result.metrics.increment(M_UNRESOLVED, 1);
                    }
                    Resolution::AlreadyResolved => {}
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

/// The `(threshold, extend_to)` operands and current resolution of a TTL
/// op, or `None` for a non-TTL op. `threshold`/`extend_to` are the raw
/// operands; the `bool`s are whether each is already resolved.
struct TtlAmounts<'a> {
    op: &'a KnownOp,
    threshold: ValueId,
    threshold_done: bool,
    extend_to: ValueId,
    extend_to_done: bool,
}

fn ttl_amounts(op: &KnownOp) -> Option<TtlAmounts<'_>> {
    match op {
        KnownOp::StorageExtendTtl {
            threshold,
            extend_to,
            resolved_threshold,
            resolved_extend_to,
            ..
        }
        | KnownOp::ExtendCurrentContractInstanceAndCodeTtl {
            threshold,
            extend_to,
            resolved_threshold,
            resolved_extend_to,
        } => Some(TtlAmounts {
            op,
            threshold: *threshold,
            threshold_done: resolved_threshold.is_some(),
            extend_to: *extend_to,
            extend_to_done: resolved_extend_to.is_some(),
        }),
        _ => None,
    }
}

/// Outcome of resolving a TTL op's amounts.
enum Resolution {
    /// At least one amount was newly resolved; the upgraded op + note.
    Filled(KnownOp, String),
    /// An amount is unresolved and stayed that way.
    StillUnresolved,
    /// Both amounts were already resolved (idempotency).
    AlreadyResolved,
}

fn resolve_amounts(
    resolver: &mut Resolver<'_>,
    func: FuncId,
    amounts: TtlAmounts<'_>,
) -> Resolution {
    if amounts.threshold_done && amounts.extend_to_done {
        return Resolution::AlreadyResolved;
    }
    let new_threshold = (!amounts.threshold_done)
        .then(|| resolver.resolve_u32val(func, amounts.threshold))
        .flatten();
    let new_extend_to = (!amounts.extend_to_done)
        .then(|| resolver.resolve_u32val(func, amounts.extend_to))
        .flatten();
    if new_threshold.is_none() && new_extend_to.is_none() {
        return Resolution::StillUnresolved;
    }

    let mut upgraded = amounts.op.clone();
    if let KnownOp::StorageExtendTtl {
        resolved_threshold,
        resolved_extend_to,
        ..
    }
    | KnownOp::ExtendCurrentContractInstanceAndCodeTtl {
        resolved_threshold,
        resolved_extend_to,
        ..
    } = &mut upgraded
    {
        if let Some(v) = new_threshold {
            *resolved_threshold = Some(v);
        }
        if let Some(v) = new_extend_to {
            *resolved_extend_to = Some(v);
        }
    }
    Resolution::Filled(upgraded, amount_note(new_threshold, new_extend_to))
}

/// Provenance note recording the resolved ledger counts and their human
/// duration when they are whole-day multiples.
fn amount_note(threshold: Option<u32>, extend_to: Option<u32>) -> String {
    let mut parts = Vec::new();
    if let Some(v) = threshold {
        parts.push(format!("threshold {}", ledgers_phrase(v)));
    }
    if let Some(v) = extend_to {
        parts.push(format!("extend_to {}", ledgers_phrase(v)));
    }
    format!("ttl {}", parts.join(", "))
}

/// `518400 (30 days)` when nameable, else just the ledger count.
fn ledgers_phrase(ledgers: u32) -> String {
    match ledger_duration_name(ledgers) {
        Some(name) => format!("{ledgers} ({name})"),
        None => ledgers.to_string(),
    }
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{Arena, BlockId, IrId, Provenance, UnknownReason};
    use sordec_ir::{
        Binding, HighBlock, HighFunction, IrType, KnownTier, Literal, MemoryImage, Region,
        StorageTier, WasmFacts,
    };

    use crate::val_abi::TAG_U32_VAL;

    fn v(i: u32) -> ValueId {
        ValueId::from_index(i)
    }

    /// The raw `Literal::I64` bits of a `U32Val` carrying `n`.
    fn u32val(n: u32) -> Expr {
        Expr::Literal(Literal::I64(
            (((n as u64) << 32) | u64::from(TAG_U32_VAL)) as i64,
        ))
    }

    /// A one-function module whose bindings are `exprs` at ids `0..N`.
    fn module(exprs: Vec<Expr>) -> HighIr {
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
        let func = HighFunction {
            id: FuncId::from_index(0),
            name: None,
            signature: None,
            blocks,
            bindings,
            region: Region::Unreachable,
            params: vec![],
            returns: vec![],
        };
        HighIr {
            facts: WasmFacts {
                imports: vec![],
                exports: vec![],
                function_type_indices: vec![],
                custom_sections: vec![],
            },
            soroban_facts: None,
            functions: vec![func],
            memory: MemoryImage::from_segments(vec![]),
        }
    }

    fn op_at(ir: &HighIr, id: ValueId) -> KnownOp {
        match &ir.functions[0].bindings.get(id).unwrap().expr {
            Expr::Semantic(SemanticOp::Known(op)) => op.clone(),
            other => panic!("expected Known op, got {other:?}"),
        }
    }

    #[test]
    fn instance_bump_amounts_resolve_and_name_durations() {
        // extend_instance_and_code_ttl(U32Val(103680), U32Val(120960)).
        let mut ir = module(vec![
            u32val(103_680),
            u32val(120_960),
            Expr::Semantic(SemanticOp::Known(
                KnownOp::ExtendCurrentContractInstanceAndCodeTtl {
                    threshold: v(0),
                    extend_to: v(1),
                    resolved_threshold: None,
                    resolved_extend_to: None,
                },
            )),
        ]);
        let result = TtlPass.run(&mut ir);

        assert!(result.changed);
        assert_eq!(result.metrics.get(M_RESOLVED), Some(1));
        assert_eq!(result.metrics.get(M_UNRESOLVED), None);
        match op_at(&ir, v(2)) {
            KnownOp::ExtendCurrentContractInstanceAndCodeTtl {
                resolved_threshold,
                resolved_extend_to,
                ..
            } => {
                assert_eq!(resolved_threshold, Some(103_680));
                assert_eq!(resolved_extend_to, Some(120_960));
            }
            other => panic!("unexpected op {other:?}"),
        }
        let note = ir.functions[0].bindings.get(v(2)).unwrap().latest_provenance();
        assert_eq!(
            note.note,
            "ttl threshold 103680 (6 days), extend_to 120960 (7 days)"
        );
    }

    #[test]
    fn extend_ttl_resolves_both_amounts() {
        // StorageExtendTtl over U32Val(501120) / U32Val(518400).
        let mut ir = module(vec![
            u32val(501_120),
            u32val(518_400),
            Expr::Semantic(SemanticOp::Known(KnownOp::StorageExtendTtl {
                tier: StorageTier::Known(KnownTier::Persistent),
                durability: v(0),
                key: v(0),
                resolved_key: None,
                threshold: v(0),
                extend_to: v(1),
                resolved_threshold: None,
                resolved_extend_to: None,
            })),
        ]);
        let result = TtlPass.run(&mut ir);

        assert!(result.changed);
        assert_eq!(result.metrics.get(M_RESOLVED), Some(1));
        match op_at(&ir, v(2)) {
            KnownOp::StorageExtendTtl {
                resolved_threshold,
                resolved_extend_to,
                ..
            } => {
                assert_eq!(resolved_threshold, Some(501_120));
                assert_eq!(resolved_extend_to, Some(518_400));
            }
            other => panic!("unexpected op {other:?}"),
        }
    }

    #[test]
    fn non_constant_amount_stays_unresolved() {
        // threshold is a phi (block param): not a locally-provable const.
        let mut ir = module(vec![
            Expr::Phi { incoming: vec![] },
            u32val(120_960),
            Expr::Semantic(SemanticOp::Known(
                KnownOp::ExtendCurrentContractInstanceAndCodeTtl {
                    threshold: v(0),
                    extend_to: v(1),
                    resolved_threshold: None,
                    resolved_extend_to: None,
                },
            )),
        ]);
        let result = TtlPass.run(&mut ir);

        // extend_to still resolves, so the op changed; threshold stays None.
        assert!(result.changed);
        match op_at(&ir, v(2)) {
            KnownOp::ExtendCurrentContractInstanceAndCodeTtl {
                resolved_threshold,
                resolved_extend_to,
                ..
            } => {
                assert_eq!(resolved_threshold, None);
                assert_eq!(resolved_extend_to, Some(120_960));
            }
            other => panic!("unexpected op {other:?}"),
        }
    }

    #[test]
    fn fully_unresolved_op_bumps_unresolved_metric() {
        let mut ir = module(vec![
            Expr::Phi { incoming: vec![] },
            Expr::Phi { incoming: vec![] },
            Expr::Semantic(SemanticOp::Known(
                KnownOp::ExtendCurrentContractInstanceAndCodeTtl {
                    threshold: v(0),
                    extend_to: v(1),
                    resolved_threshold: None,
                    resolved_extend_to: None,
                },
            )),
        ]);
        let result = TtlPass.run(&mut ir);
        assert!(!result.changed);
        assert_eq!(result.metrics.get(M_RESOLVED), None);
        assert_eq!(result.metrics.get(M_UNRESOLVED), Some(1));
    }

    #[test]
    fn second_run_is_idempotent() {
        let mut ir = module(vec![
            u32val(103_680),
            u32val(120_960),
            Expr::Semantic(SemanticOp::Known(
                KnownOp::ExtendCurrentContractInstanceAndCodeTtl {
                    threshold: v(0),
                    extend_to: v(1),
                    resolved_threshold: None,
                    resolved_extend_to: None,
                },
            )),
        ]);
        assert!(TtlPass.run(&mut ir).changed);
        let second = TtlPass.run(&mut ir);
        assert!(!second.changed, "already resolved, nothing to do");
        assert_eq!(second.metrics.get(M_RESOLVED), None);
    }
}
