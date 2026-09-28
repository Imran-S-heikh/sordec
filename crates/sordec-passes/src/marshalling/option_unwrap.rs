//! Collapse the SDK's `Option` shape around a storage read back to the
//! `.unwrap()` the source wrote.
//!
//! # The shape
//!
//! `e.storage().instance().get(&DataKey::Admin).unwrap()` is one
//! expression. `Storage::get` returns an `Option`, built on wasm the only
//! way it can be — a `has` probe deciding between `Some(get(..))` and
//! `None` — and `.unwrap()` is a branch to the panic on the `None` side:
//!
//! ```text
//! h = storage_has(k)          ← the SDK's probe, proven by `option-probe`
//! if !h { panic!() }          ← the `.unwrap()`
//! v = storage_get(k)          ← the read
//! ```
//!
//! [`super::option_probe`] proves the probe and stops the emitter spelling
//! it; this pass finishes the job. The guard goes, the probe goes, and the
//! read carries the unwrap:
//!
//! ```text
//! v = storage_get(k).unwrap()  ← the same binding, so every reader keeps it
//! ```
//!
//! # Why the rewrite is exact
//!
//! The re-emitted `get(&k).unwrap()` is the SDK's own `has` then `get`,
//! and a trap when the probe fails — the same three operations in the
//! same order on the same key. The probe is not deleted so much as
//! restored to the call that generates it.
//!
//! # What it will not touch
//!
//! Only a probe whose guard is an else-less branch to a *bare* trap. A
//! `has` whose branch selects a default (`unwrap_or`, `if let`) is the
//! author's branch and stays; a `has` with no `get` on the same key is a
//! real `has` and stays. The key must be the same slot on both
//! calls, as the probe recognizer requires.
//!
//! # Why a flag on the read and not a separate operator
//!
//! The pipeline types the read as its payload throughout; an `Option` never
//! existed in the IR. A separate unwrap node would move every reader to a
//! new binding and split one source expression across two `let`s. The
//! flag keeps one binding, one name and one line: `get(&k).unwrap()`.

use std::collections::HashMap;

use sordec_common::{Provenance, ProvenanceSource, ValueId};
use sordec_ir::{Expr, HighFunction, HighIr, KnownOp, KnownTier, Literal, Region, SemanticOp, UnaryOp};

use super::metrics;
use super::option_probe::proven_tier;
use crate::dataflow::resolve_use;
use crate::pass::{Pass, PassResult};
use crate::recognizers::wrappers::chase_value;

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-option-unwrap";

/// Collapses proven `Option` probes with a trapping guard to `.unwrap()`.
#[derive(Debug, Default, Clone, Copy)]
pub struct OptionUnwrapPass;

impl Pass<HighIr> for OptionUnwrapPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        for func in &mut ir.functions {
            let plans = plan(func);
            if plans.is_empty() {
                continue;
            }
            let mut guards: HashMap<ValueId, String> = HashMap::new();
            for p in &plans {
                guards.insert(p.guard, "`.unwrap()` on a storage read: the SDK's None branch".to_string());
            }
            let empty = super::guard::empty_blocks(func);
            let region = std::mem::replace(&mut func.region, Region::Unreachable);
            let mut stripped = 0_i64;
            func.region = super::guard::strip(region, &guards, &empty, &mut stripped);
            for p in plans {
                if !guards.contains_key(&p.guard) {
                    continue;
                }
                apply(func, &p);
                result.metrics.increment(metrics::OPTIONS_UNWRAPPED, 1);
                result.changed = true;
            }
        }
        result
    }
}

/// One probe/guard/read triple.
struct Plan {
    probe: ValueId,
    /// The branch condition as the region names it.
    guard: ValueId,
    get: ValueId,
}

fn plan(func: &HighFunction) -> Vec<Plan> {
    // Probes the recognizer proved, by the key value they test.
    let probes: Vec<(ValueId, ValueId, KnownTier)> = func
        .bindings
        .iter()
        .filter_map(|(id, b)| match &b.expr {
            Expr::Semantic(SemanticOp::Known(KnownOp::StorageHas { probe: true, key, tier, .. })) => {
                Some((id, chase_value(func, *key), proven_tier(tier)?))
            }
            _ => None,
        })
        .collect();
    if probes.is_empty() {
        return Vec::new();
    }
    // Else-less branches whose condition negates a probe and whose arm is
    // a bare trap.
    let mut guards: Vec<(ValueId, ValueId)> = Vec::new();
    func.region.for_each_node(|node| {
        let Region::If { cond, then_region, else_region: None } = node else {
            return;
        };
        if !matches!(**then_region, Region::Panic { kind: sordec_ir::PanicKind::Bare | sordec_ir::PanicKind::Unwrap }) {
            return;
        }
        let Some(Expr::Unary { op: UnaryOp::Not | UnaryOp::Eqz, value }) =
            func.bindings.get(resolve_use(func, *cond)).map(|b| &b.expr)
        else {
            return;
        };
        let negated = resolve_use(func, *value);
        if probes.iter().any(|(p, _, _)| *p == negated) {
            guards.push((*cond, negated));
        }
    });
    let mut plans = Vec::new();
    for (guard, probe) in guards {
        let Some((_, key, tier)) = probes.iter().find(|(p, _, _)| *p == probe) else {
            continue;
        };
        // The read on the same key at the same tier, not yet unwrapped.
        let get = func.bindings.iter().find_map(|(id, b)| match &b.expr {
            Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet { key: k, tier: t, missing: sordec_ir::Missing::Option, .. }))
                if super::option_probe::same_key(func, chase_value(func, *k), *key)
                    && proven_tier(t) == Some(*tier) =>
            {
                Some(id)
            }
            _ => None,
        });
        if let Some(get) = get {
            plans.push(Plan { probe, guard, get });
        }
    }
    plans
}

fn apply(func: &mut HighFunction, p: &Plan) {
    // The read keeps its binding, its type and its name; it gains the
    // unwrap. Every reader already names the payload.
    if let Some(b) = func.bindings.get_mut(p.get) {
        if let Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet { missing, .. })) = &mut b.expr {
            *missing = sordec_ir::Missing::Unwrap;
        }
        b.add_provenance(Provenance::new(
            PASS_NAME,
            ProvenanceSource::SdkPattern,
            "`.unwrap()`: the SDK's has-probe and its None branch, restored to the read",
        ));
    }
    if let Some(b) = func.bindings.get_mut(p.probe) {
        b.expr = Expr::Literal(Literal::Unit);
        b.add_provenance(Provenance::new(
            PASS_NAME,
            ProvenanceSource::SdkPattern,
            "SDK Option probe, regenerated by `get(..).unwrap()`",
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, module, v};
    use sordec_common::{BlockId, IrId};
    use sordec_ir::{KnownTier, PanicKind, StorageTier};

    fn tier() -> StorageTier {
        StorageTier::Known(KnownTier::Instance)
    }

    /// `h = has(k); if !h { panic }; g = get(k)` with a reader of `g`.
    fn shape(probe: bool, with_get: bool) -> HighFunction {
        let mut exprs = vec![
            Expr::Phi { incoming: vec![] }, // v0 key
            Expr::Semantic(SemanticOp::Known(KnownOp::StorageHas {
                tier: tier(),
                durability: v(0),
                key: v(0),
                resolved_key: None,
                probe,
            })), // v1
            Expr::Unary { op: UnaryOp::Not, value: v(1) }, // v2
        ];
        let mut sched = vec![1, 2];
        if with_get {
            exprs.push(Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet {
                tier: tier(),
                durability: v(0),
                key: v(0),
                resolved_key: None,
                missing: sordec_ir::Missing::Option,
            }))); // v3
            exprs.push(Expr::Unary { op: UnaryOp::Not, value: v(3) }); // v4 a reader
            sched.extend([3, 4]);
        }
        let mut f = func_with(exprs, vec![v(0)], sched);
        f.region = Region::Sequence(vec![
            Region::Basic(BlockId::from_index(0)),
            Region::If {
                cond: v(2),
                then_region: Box::new(Region::Panic { kind: PanicKind::Bare }),
                else_region: None,
            },
        ]);
        f
    }

    fn contains_if(region: &Region) -> bool {
        let mut found = false;
        region.for_each_node(|n| {
            if matches!(n, Region::If { .. }) {
                found = true;
            }
        });
        found
    }

    #[test]
    fn a_proven_probe_with_a_trapping_guard_and_a_read_becomes_unwrap() {
        let mut m = module(vec![shape(true, true)]);
        let r = OptionUnwrapPass.run(&mut m);
        assert!(r.changed);
        let f = &m.functions[0];
        assert!(!contains_if(&f.region), "the None branch is gone");
        // The read is the same binding, now flagged as unwrapped.
        assert!(matches!(
            f.bindings.get(v(3)).unwrap().expr,
            Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet { missing: sordec_ir::Missing::Unwrap, .. }))
        ));
        // The reader still names v3.
        assert!(matches!(f.bindings.get(v(4)).unwrap().expr, Expr::Unary { value, .. } if value == v(3)));
        // The probe is gone.
        assert!(matches!(f.bindings.get(v(1)).unwrap().expr, Expr::Literal(Literal::Unit)));
    }

    /// A `has` the recognizer did not prove is the author's.
    #[test]
    fn an_unproven_has_is_left_alone() {
        let mut m = module(vec![shape(false, true)]);
        assert!(!OptionUnwrapPass.run(&mut m).changed);
    }

    /// A probe with no read on its key is a real existence check.
    #[test]
    fn a_probe_without_a_read_is_left_alone() {
        let mut m = module(vec![shape(true, false)]);
        assert!(!OptionUnwrapPass.run(&mut m).changed);
        assert!(contains_if(&m.functions[0].region));
    }

    #[test]
    fn the_pass_is_idempotent() {
        let mut m = module(vec![shape(true, true)]);
        assert!(OptionUnwrapPass.run(&mut m).changed);
        assert!(!OptionUnwrapPass.run(&mut m).changed);
    }
}
