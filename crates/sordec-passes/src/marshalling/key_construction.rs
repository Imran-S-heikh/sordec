//! The `#[contracttype]` enum-to-`Val` converter, elided once its key is
//! known.
//!
//! # The shape
//!
//! The source writes one line:
//!
//! ```ignore
//! let admin: Address = e.storage().instance().get(&DataKey::Admin).unwrap();
//! ```
//!
//! `#[contracttype]` derives `TryFromVal` for `DataKey`, rustc inlines it
//! into a converter helper, and we recover four statements:
//!
//! ```ignore
//! let v9 = func2(e, v8);            // build the key Val
//! let v11 = func46(e, v9);          // validate it
//! if !v11 { func12(e); panic!(); }  // trap if invalid
//! let admin = e.storage().instance().get(&DataKey::Admin);
//! ```
//!
//! The last line is already right — [`crate::recognizers::enum_key`] proved
//! which variant the frame slot holds and the emitter spells the key from
//! that, not from `v9`. So the first three statements produce a value the
//! output no longer reads, and one of them is an `if`.
//!
//! On token-v23 the converter is **`func2`: nine control-flow constructs
//! reachable from ten of thirteen entrypoints, 90 weighted structure
//! tokens — 22% of what remains after the symbol encoder went.**
//!
//! # Why deleting the trap is sound
//!
//! Same argument as [`super::guard`], and it is worth stating rather than
//! inheriting. The reconstruction emits `&DataKey::Admin` — the *typed*
//! value — inside a module that re-declares `#[contracttype] enum DataKey`.
//! The macro regenerates that conversion and its failure path verbatim, so
//! a wrong-typed key still traps, in derived code, exactly as before. The
//! trap is **relocated, not removed**.
//!
//! What licenses it here specifically is that the key is *resolved*: the
//! recognizer proved the variant from the discriminant the caller stored,
//! so the emitted `DataKey::Admin` is that same key rather than a guess. An
//! unresolved key gets none of this and keeps its converter.
//!
//! # What it does not touch
//!
//! Only a converter whose result reaches a storage op with a resolved key,
//! and only a guard whose taken arm is a bare trap. A converter feeding
//! anything else, or a branch doing real work, stays: an interior
//! conversion may be a `try_into` the author wrote, and this pass has no
//! way to tell those apart.
//!
//! Payload values are deliberately untouched. `DataKey::Allowance(v0, v1)`
//! renders its operands, so eliding the converter must not take the values
//! it consumed with it — they are the emitted key's arguments.

use std::collections::{HashMap, HashSet};

use sordec_common::{Diagnostic, LiftDiagnosticCode, Location, Provenance, ProvenanceSource};
use sordec_common::ValueId;
use sordec_ir::{Expr, HighFunction, HighIr, KnownOp, Literal, SemanticOp, UnaryOp};

use crate::dataflow::resolve_use;
use crate::pass::{Pass, PassResult};

/// Pass name, also its provenance `pass` field.
pub const PASS_NAME: &str = "key-construction-elision";

/// Converter calls elided.
const M_CONVERTER: &str = "key_converter_elided";

/// Validation guards elided with them.
const M_GUARD: &str = "key_guard_elided";

/// Elides the derived enum-to-`Val` converter behind a resolved storage key.
#[derive(Debug, Default, Clone, Copy)]
pub struct KeyConstructionElisionPass;

impl Pass<HighIr> for KeyConstructionElisionPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();

        for func in &mut ir.functions {
            let Some(plan) = plan_for(func) else { continue };

            // Drop the guards first: `strip` rewrites the region tree, and
            // doing it before the bindings change keeps the two steps
            // independent of each other's ordering.
            let empty = super::guard::empty_blocks(func);
            let mut elided_guards = 0_i64;
            if !plan.guards.is_empty() {
                let region = std::mem::replace(&mut func.region, sordec_ir::Region::Unreachable);
                func.region = super::guard::strip(region, &plan.guards, &empty, &mut elided_guards);
            }

            // Then the calls. Rewriting to a pure literal rather than
            // deleting is this module's elision idiom: nothing leaves the
            // arena, provenance survives, and the backend's dead-`let` pass
            // removes whatever no longer has a reader.
            for value in &plan.calls {
                if let Some(binding) = func.bindings.get_mut(*value) {
                    binding.expr = Expr::Literal(Literal::Unit);
                    binding.add_provenance(Provenance::new(
                        PASS_NAME,
                        ProvenanceSource::SdkPattern,
                        "derived enum-to-Val converter behind a resolved key",
                    ));
                }
            }

            if !plan.calls.is_empty() {
                result.metrics.increment(M_CONVERTER, plan.calls.len() as i64);
                result.changed = true;
                result.diagnostics.push(
                    Diagnostic::info(
                        LiftDiagnosticCode::MarshallingGuardElided,
                        format!(
                            "elided {} derived key-conversion call(s) and {elided_guards} guard(s) \
                             behind resolved storage keys",
                            plan.calls.len()
                        ),
                    )
                    .at(Location::Function(func.id)),
                );
            }
            if elided_guards > 0 {
                result.metrics.increment(M_GUARD, elided_guards);
                result.changed = true;
            }
        }

        result
    }
}

/// What one function offers to elide.
struct Plan {
    /// Converter and validator calls to rewrite away.
    calls: Vec<ValueId>,
    /// Guard conditions whose trap-only `if` may go, in `strip`'s shape.
    guards: HashMap<ValueId, String>,
}

fn plan_for(func: &HighFunction) -> Option<Plan> {
    // Every key value a storage op resolved to a named variant. Only these
    // license anything: an unresolved key still needs its converter.
    let resolved: HashSet<ValueId> = func
        .bindings
        .iter()
        .filter_map(|(_, b)| match &b.expr {
            Expr::Semantic(SemanticOp::Known(
                KnownOp::StorageGet { key, resolved_key: Some(_), .. }
                | KnownOp::StorageSet { key, resolved_key: Some(_), .. }
                | KnownOp::StorageHas { key, resolved_key: Some(_), .. }
                | KnownOp::StorageExtendTtl { key, resolved_key: Some(_), .. },
            )) => Some(resolve_use(func, *key)),
            _ => None,
        })
        .collect();

    if resolved.is_empty() {
        return None;
    }

    let mut calls = Vec::new();
    let mut guards = HashMap::new();

    for (id, binding) in func.bindings.iter() {
        if !resolved.contains(&id) {
            continue;
        }
        // The producer must be a call — the derived converter. A key
        // arriving any other way (a parameter, an already-folded literal)
        // has no converter to elide.
        if !matches!(binding.expr, Expr::Call { .. }) {
            continue;
        }
        calls.push(id);

        // Anything that consumes the key is the derived validation; the
        // trap it guards is what this pass relocates.
        for (vid, vb) in func.bindings.iter() {
            let Expr::Call { args, .. } = &vb.expr else {
                continue;
            };
            if !args.iter().any(|a| resolve_use(func, *a) == id) {
                continue;
            }
            calls.push(vid);

            // `strip` matches on the `if`'s *condition*, and the condition
            // is the negation — the derived code traps when validation
            // fails. Registering the validator itself would never match,
            // and registering both polarities would be wrong: `if valid {
            // trap }` is not a validation guard, it is something else, and
            // eliding it would delete a real branch.
            for (nid, nb) in func.bindings.iter() {
                let Expr::Unary { op, value } = &nb.expr else {
                    continue;
                };
                if matches!(op, UnaryOp::Not | UnaryOp::Eqz) && resolve_use(func, *value) == vid {
                    guards.insert(nid, "derived key validation".to_string());
                }
            }
        }
    }

    if calls.is_empty() {
        return None;
    }
    Some(Plan { calls, guards })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{Arena, BlockId, FuncId, IrId, ProvenanceSource, UnknownReason};
    use sordec_ir::{
        Binding, EnumKey, HighBlock, IrType, KnownTier, MemoryImage, PanicKind, Region, StorageTier,
        WasmFacts,
    };

    fn v(i: u32) -> ValueId {
        ValueId::from_index(i)
    }

    fn seed(id: ValueId, expr: Expr) -> Binding {
        Binding::new(
            id,
            IrType::Unknown(UnknownReason::InsufficientEvidence),
            expr,
            Provenance::new("seed", ProvenanceSource::DataFlow, "seed"),
        )
    }

    fn key(variant: &str) -> EnumKey {
        EnumKey {
            enum_name: "DataKey".into(),
            variant: variant.into(),
            payload: vec![],
        }
    }

    /// `v0` builds the key, `v1` validates it, `v2` negates, the region
    /// traps under `v2`, and `v3` is the storage read.
    ///
    /// `resolved` controls whether the recognizer proved the variant —
    /// the single fact that licenses any of this.
    fn func_with(resolved: bool) -> HighFunction {
        let mut bindings: Arena<ValueId, Binding> = Arena::new();
        for (i, expr) in [
            Expr::Call { target: FuncId::from_index(9), args: vec![] },
            Expr::Call { target: FuncId::from_index(8), args: vec![v(0)] },
            Expr::Unary { op: UnaryOp::Not, value: v(1) },
            Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet {
                tier: StorageTier::Known(KnownTier::Instance),
                durability: v(0),
                key: v(0),
                resolved_key: resolved.then(|| key("Admin")),
            })),
        ]
        .into_iter()
        .enumerate()
        {
            bindings.push(seed(ValueId::from_index(i as u32), expr));
        }

        let mut blocks: Arena<BlockId, HighBlock> = Arena::new();
        blocks.push(HighBlock { id: BlockId::from_index(0), bindings: vec![] });

        HighFunction {
            id: FuncId::from_index(0),
            name: None,
            signature: None,
            blocks,
            bindings,
            region: Region::Sequence(vec![Region::If {
                cond: v(2),
                then_region: Box::new(Region::Panic { kind: PanicKind::Bare }),
                else_region: None,
            }]),
            params: vec![],
            returns: vec![],
        }
    }

    fn ir(func: HighFunction) -> HighIr {
        HighIr {
            facts: WasmFacts {
                imports: vec![],
                exports: vec![],
                function_type_indices: vec![],
                function_bodies: vec![],
                function_fingerprints: vec![],
                custom_sections: vec![],
            },
            soroban_facts: None,
            functions: vec![func],
            memory: MemoryImage::empty(),
        }
    }

    fn expr_at(ir: &HighIr, value: u32) -> &Expr {
        &ir.functions[0].bindings.get(v(value)).unwrap().expr
    }

    #[test]
    fn a_resolved_key_elides_its_converter_and_guard() {
        let mut m = ir(func_with(true));
        let r = KeyConstructionElisionPass.run(&mut m);

        assert!(r.changed);
        assert_eq!(r.metrics.get(M_CONVERTER), Some(2)); // converter + validator
        assert_eq!(r.metrics.get(M_GUARD), Some(1));
        assert!(matches!(expr_at(&m, 0), Expr::Literal(Literal::Unit)));
        assert!(matches!(expr_at(&m, 1), Expr::Literal(Literal::Unit)));
        // The trap-only `if` is gone from the region tree.
        assert!(matches!(&m.functions[0].region, Region::Sequence(items) if items.is_empty()));
    }

    /// The whole licence is that the recognizer proved the variant. Without
    /// that the emitted key is not a name, so the converter is load-bearing
    /// and stays — along with its trap.
    #[test]
    fn an_unresolved_key_keeps_everything() {
        let mut m = ir(func_with(false));
        let r = KeyConstructionElisionPass.run(&mut m);

        assert!(!r.changed);
        assert!(matches!(expr_at(&m, 0), Expr::Call { .. }));
        assert!(matches!(expr_at(&m, 1), Expr::Call { .. }));
        assert!(matches!(&m.functions[0].region, Region::Sequence(items) if items.len() == 1));
    }

    /// Polarity is load-bearing. The derived code traps when validation
    /// *fails*, so `if !valid { trap }` is the guard. An `if valid { trap }`
    /// is a different branch and deleting it would remove real control flow.
    #[test]
    fn an_unnegated_guard_is_not_elided() {
        let mut f = func_with(true);
        // Point the `if` straight at the validator, without the negation.
        f.region = Region::Sequence(vec![Region::If {
            cond: v(1),
            then_region: Box::new(Region::Panic { kind: PanicKind::Bare }),
            else_region: None,
        }]);
        let mut m = ir(f);
        let r = KeyConstructionElisionPass.run(&mut m);

        assert_eq!(r.metrics.get(M_GUARD), None, "wrong-polarity guard must stay");
        // `seq` collapses a one-element sequence into the element, so look
        // for the branch itself rather than the wrapper it arrived in.
        assert!(
            contains_if(&m.functions[0].region),
            "the branch must survive"
        );
    }

    /// A branch that does real work before trapping is not a guard.
    /// Whether a branch survives anywhere in the tree.
    fn contains_if(region: &Region) -> bool {
        match region {
            Region::If { .. } => true,
            Region::Sequence(items) => items.iter().any(contains_if),
            Region::Scope { body, .. } | Region::Loop { body, .. } => contains_if(body),
            _ => false,
        }
    }

    #[test]
    fn a_branch_doing_work_is_not_elided() {
        let mut f = func_with(true);
        f.blocks.push(HighBlock {
            id: BlockId::from_index(1),
            bindings: vec![v(3)],
        });
        f.region = Region::Sequence(vec![Region::If {
            cond: v(2),
            then_region: Box::new(Region::Sequence(vec![
                Region::Basic(BlockId::from_index(1)),
                Region::Panic { kind: PanicKind::Bare },
            ])),
            else_region: None,
        }]);
        let mut m = ir(f);
        let r = KeyConstructionElisionPass.run(&mut m);
        assert_eq!(r.metrics.get(M_GUARD), None);
        assert!(contains_if(&m.functions[0].region), "work before a trap is not a guard");
    }

    #[test]
    fn the_pass_is_idempotent() {
        let mut m = ir(func_with(true));
        assert!(KeyConstructionElisionPass.run(&mut m).changed);
        assert!(!KeyConstructionElisionPass.run(&mut m).changed);
    }
}
