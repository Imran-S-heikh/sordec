//! Name the existence check the SDK wrote, not the source.
//!
//! `Storage::get::<K, V>` returns `Option<V>`, and on wasm that Option is
//! built the only way it can be:
//!
//! ```text
//! if has(k, tier) { Some(decode(get(k, tier))) } else { None }
//! ```
//!
//! So a source line as ordinary as
//! `e.storage().instance().get(&DataKey::ReserveA).unwrap()` reaches us as
//! **two** host calls. Both are real, both are correctly recognized, and
//! exactly one of them corresponds to something the author typed. Spelling
//! the other as `e.storage().instance().has(&DataKey::ReserveA)` reports a
//! call that does not exist in the source — a false claim of exactly the
//! kind the storage recognizer refuses to make about an unproven tier.
//!
//! This pass proves which `has` calls are the SDK's and sets
//! [`KnownOp::StorageHas::probe`]. It deletes nothing: the op, its tier and
//! its resolved key all stay, with provenance, so the has/get pair remains
//! available to a later wave that collapses the whole `Option` shape into
//! the single `get` the source wrote. All the flag does is stop the
//! emitter spelling a probe as a source-level call.
//!
//! ## Why this only became visible now
//!
//! Before [`SpecializePass`](crate::interproc::SpecializePass), the SDK's
//! probes sat in one shared helper whose durability was a parameter, so
//! their tier never resolved and the emitter declined them for that
//! reason. De-sharing resolved the tier and the key — and promptly
//! surfaced five storage facts on dex that its source never wrote. The
//! probes were always there; only now are they well enough recovered to
//! be wrong out loud.
//!
//! ## The evidence gate
//!
//! Within one function, a `has` is a probe when a `get` in that same
//! function reads the **same key value** at the **same resolved tier**.
//! Key identity is by `ValueId` after the shared
//! [`chase_value`] walk, so it
//! is the literal same SSA value feeding both calls — not two keys that
//! merely name the same variant. That is what makes the pairing a fact
//! about this code rather than an inference from the vocabulary.
//!
//! Two shapes carry the pair, and both are checked from the *`get` side*,
//! looking outward:
//!
//! - **Inlined**: `has` and `get` are bindings in the same function.
//! - **Wrapped**: the `has` is alone in a tiny helper the function calls
//!   with that key. rustc outlines the probe into
//!   `fn(key) -> bool { has(key, tier) }`; after specialization each such
//!   helper is sole-called, so the caller's key value identifies the
//!   probe unambiguously.
//!
//! A `has` with no `get` on its key stays exactly as it is — timelock's
//! `is_initialized` is a real `env.storage().instance().has(&DataKey::Init)`
//! and must keep scoring as one.

use std::collections::HashSet;

use sordec_common::{FuncId, Provenance, ProvenanceSource, ValueId};
use sordec_ir::{Expr, HighFunction, HighIr, KnownOp, KnownTier, Literal, SemanticOp, StorageTier};

use crate::pass::{Pass, PassResult};
use crate::recognizers::wrappers::chase_value;

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "option-probe";

/// `has` calls proven to be the SDK's `Option` discriminant.
const M_PROBES: &str = "storage_option_probe";


/// Whether two key operands provably address the same storage slot.
///
/// SSA identity is the strong case and the common one, but rustc is under
/// no obligation to share the constant between the probe and the read it
/// guards. Measured on `phoenix-vesting`: of four probe sites, two feed
/// both calls from one value and two materialise the key twice —
/// `has(v6)` beside `get(v10)`, both the constant `U32Val(2)`. ValueId
/// equality alone therefore missed half of them, and each miss cost three
/// things at once: a `has` the source never wrote reported as a storage
/// fact, the branch it guards left in the output, and the `get` left as an
/// `Option` whose consumers then fail to type-check.
///
/// Comparing the *constants* stays inside this pass's standing rule that a
/// pairing must be a fact about this code. Two literals with equal value
/// address one slot — that is bit equality, strictly stronger than the
/// "two keys that merely name the same variant" case the gate refuses,
/// which is about separately *constructed* keys whose contents were never
/// proven. A key that is not a constant is compared by identity exactly as
/// before.
pub(crate) fn same_key(func: &HighFunction, a: ValueId, b: ValueId) -> bool {
    if a == b {
        return true;
    }
    match (key_constant(func, a), key_constant(func, b)) {
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

/// A key operand's constant form, normalised so the integer widths the
/// wasm happened to use cannot make one slot look like two.
fn key_constant(func: &HighFunction, value: ValueId) -> Option<KeyConst> {
    match &func.bindings.get(value)?.expr {
        Expr::Literal(Literal::I32(n)) => Some(KeyConst::Int(i128::from(*n))),
        Expr::Literal(Literal::I64(n)) => Some(KeyConst::Int(i128::from(*n))),
        Expr::Literal(Literal::U32(n)) => Some(KeyConst::Int(i128::from(*n))),
        Expr::Literal(Literal::U64(n)) => Some(KeyConst::Int(i128::from(*n))),
        Expr::Literal(Literal::Symbol(s)) => Some(KeyConst::Symbol(s.clone())),
        _ => None,
    }
}

/// The comparable form of a constant key.
#[derive(PartialEq)]
enum KeyConst {
    /// Any integer width, widened so `I32(2)` and `U32(2)` are one slot.
    Int(i128),
    /// A short symbol, compared by its text.
    Symbol(String),
}

/// The SDK `Option`-probe recognizer. Stateless.
#[derive(Debug, Default, Clone, Copy)]
pub struct OptionProbePass;

impl Pass<HighIr> for OptionProbePass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();

        // Phase A — read-only. Every (function, has-binding) the gate
        // proves, including probes reached through a one-op wrapper.
        let mut proven: HashSet<(FuncId, ValueId)> = HashSet::new();
        for func in &ir.functions {
            for (key, tier) in get_keys(func) {
                // Inlined: the probe is a sibling binding.
                for (id, has_key, has_tier) in has_ops(func) {
                    if same_key(func, has_key, key) && has_tier == tier {
                        proven.insert((func.id, id));
                    }
                }
                // Wrapped: the probe is alone inside a helper this
                // function calls with the same key value.
                for (_, binding) in func.bindings.iter() {
                    let Expr::Call { target, args } = &binding.expr else {
                        continue;
                    };
                    if !args
                        .iter()
                        .any(|arg| same_key(func, chase_value(func, *arg), key))
                    {
                        continue;
                    }
                    let Some(callee) = ir.function(*target) else {
                        continue;
                    };
                    if let Some((id, _, has_tier)) = sole_has(callee)
                        && has_tier == tier
                    {
                        proven.insert((callee.id, id));
                    }
                }
            }
        }

        // Phase B — mark.
        for (func_id, value) in proven {
            let Some(func) = ir.function_mut(func_id) else {
                continue;
            };
            let Some(binding) = func.bindings.get_mut(value) else {
                continue;
            };
            let Expr::Semantic(SemanticOp::Known(KnownOp::StorageHas { probe, .. })) =
                &mut binding.expr
            else {
                continue;
            };
            if *probe {
                continue; // idempotent
            }
            *probe = true;
            binding.add_provenance(Provenance::new(
                PASS_NAME,
                ProvenanceSource::SdkPattern,
                "SDK Option discriminant: a get on this key and tier is guarded by it",
            ));
            result.metrics.increment(M_PROBES, 1);
            result.changed = true;
        }
        result
    }
}

/// The `(key, tier)` pairs read by `storage_get` in this function.
/// Unresolved tiers are skipped: an unproven tier cannot witness that two
/// calls address the same entry.
fn get_keys(func: &HighFunction) -> Vec<(ValueId, KnownTier)> {
    func.bindings
        .iter()
        .filter_map(|(_, binding)| match &binding.expr {
            Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet { key, tier, .. })) => {
                Some((chase_value(func, *key), proven_tier(tier)?))
            }
            _ => None,
        })
        .collect()
}

/// The tier of an operation, but only when it was *proved*. An unproven
/// tier cannot witness that two calls address the same entry.
pub(super) fn proven_tier(tier: &StorageTier) -> Option<KnownTier> {
    match tier {
        StorageTier::Known(t) => Some(*t),
        StorageTier::Inferred(_) | StorageTier::Unknown(_) => None,
    }
}

/// The `has` ops in this function, with their chased key and tier.
fn has_ops(func: &HighFunction) -> Vec<(ValueId, ValueId, KnownTier)> {
    func.bindings
        .iter()
        .filter_map(|(id, binding)| match &binding.expr {
            Expr::Semantic(SemanticOp::Known(KnownOp::StorageHas { key, tier, .. })) => {
                Some((id, chase_value(func, *key), proven_tier(tier)?))
            }
            _ => None,
        })
        .collect()
}

/// A helper whose only storage op is one `has` on a parameter — the
/// outlined probe. `None` when the function does anything else with
/// storage, which would make the pairing ambiguous.
fn sole_has(func: &HighFunction) -> Option<(ValueId, ValueId, KnownTier)> {
    // An exported function is a contract entrypoint, never SDK glue.
    if func.name.is_some() {
        return None;
    }
    let mut found = None;
    for (id, binding) in func.bindings.iter() {
        let Expr::Semantic(SemanticOp::Known(op)) = &binding.expr else {
            continue;
        };
        match op {
            KnownOp::StorageHas { key, tier, .. } => {
                if found.is_some() {
                    return None;
                }
                let tier = proven_tier(tier)?;
                // The probe reads the helper's own key parameter.
                let chased = chase_value(func, *key);
                if !func.params.contains(&chased) {
                    return None;
                }
                found = Some((id, chased, tier));
            }
            KnownOp::StorageGet { .. }
            | KnownOp::StorageSet { .. }
            | KnownOp::StorageRemove { .. }
            | KnownOp::StorageExtendTtl { .. }
            | KnownOp::StorageExtendTtlV2 { .. } => return None,
            _ => {}
        }
    }
    found
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{Arena, BlockId, IrId, Provenance, UnknownReason};
    use sordec_ir::{
        Binding, HighBlock, IrType, MemoryImage, Region, SorobanFacts, WasmFacts,
    };

    fn func(id: u32, name: Option<&str>, n_params: usize, exprs: Vec<Expr>) -> HighFunction {
        let mut bindings: Arena<ValueId, Binding> = Arena::new();
        let mut params = Vec::new();
        let mut scheduled = Vec::new();
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
            scheduled.push(vid);
        }
        let mut blocks: Arena<BlockId, HighBlock> = Arena::new();
        let bid = blocks.push(HighBlock {
            id: BlockId::from_index(0),
            bindings: scheduled,
        });
        HighFunction {
            id: FuncId::from_index(id),
            name: name.map(str::to_string),
            signature: None,
            blocks,
            bindings,
            region: Region::Basic(bid),
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
                function_bodies: vec![],
                function_fingerprints: vec![],
                custom_sections: vec![],
            },
            soroban_facts: Some(SorobanFacts::default()),
            functions,
            memory: MemoryImage::empty(),
        }
    }

    fn v(i: u32) -> ValueId {
        ValueId::from_index(i)
    }

    fn tier(t: KnownTier) -> StorageTier {
        StorageTier::Known(t)
    }

    fn get(key: ValueId, t: KnownTier) -> Expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet {
            tier: tier(t),
            durability: key,
            key,
            resolved_key: None,
            missing: sordec_ir::Missing::Option,
        }))
    }

    fn has(key: ValueId, t: KnownTier) -> Expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::StorageHas {
            tier: tier(t),
            durability: key,
            key,
            resolved_key: None,
            probe: false,
        }))
    }

    fn is_probe(ir: &HighIr, func: u32, value: ValueId) -> bool {
        match &ir.functions[func as usize].bindings.get(value).unwrap().expr {
            Expr::Semantic(SemanticOp::Known(KnownOp::StorageHas { probe, .. })) => *probe,
            other => panic!("expected StorageHas, got {other:?}"),
        }
    }

    fn run(ir: &mut HighIr) -> PassResult {
        OptionProbePass.run(ir)
    }

    #[test]
    fn inlined_has_guarding_a_get_on_the_same_key_is_a_probe() {
        // v0 key; v1 = has(k); v2 = get(k) — the SDK's `Option` shape
        // after rustc inlined the probe.
        let f = func(
            0,
            Some("main"),
            1,
            vec![has(v(0), KnownTier::Instance), get(v(0), KnownTier::Instance)],
        );
        let mut ir = module(vec![f]);
        let result = run(&mut ir);
        assert!(result.changed);
        assert_eq!(result.metrics.get(M_PROBES), Some(1));
        assert!(is_probe(&ir, 0, v(1)));
    }

    #[test]
    fn wrapped_has_is_a_probe_when_its_caller_gets_the_same_key() {
        // f1 is the outlined probe `fn(key) -> bool { has(key) }`; f0
        // calls it with the key it then reads.
        let probe = func(1, None, 1, vec![has(v(0), KnownTier::Instance)]);
        let caller = func(
            0,
            Some("main"),
            1,
            vec![
                Expr::Call {
                    target: FuncId::from_index(1),
                    args: vec![v(0)],
                },
                get(v(0), KnownTier::Instance),
            ],
        );
        let mut ir = module(vec![caller, probe]);
        let result = run(&mut ir);
        assert!(result.changed);
        assert!(is_probe(&ir, 1, v(1)), "the probe is marked in the helper");
    }

    #[test]
    fn a_has_with_no_matching_get_stays_a_source_level_call() {
        // timelock's `is_initialized`: a real
        // `env.storage().instance().has(&DataKey::Init)`, which must keep
        // scoring as one.
        let f = func(0, Some("is_initialized"), 1, vec![has(v(0), KnownTier::Instance)]);
        let mut ir = module(vec![f]);
        let result = run(&mut ir);
        assert!(!result.changed);
        assert!(!is_probe(&ir, 0, v(1)));
    }

    #[test]
    fn a_get_on_a_different_key_does_not_pair() {
        // Two parameters, two different keys: nothing witnesses that the
        // has and the get address the same entry.
        let f = func(
            0,
            Some("main"),
            2,
            vec![has(v(0), KnownTier::Instance), get(v(1), KnownTier::Instance)],
        );
        let mut ir = module(vec![f]);
        assert!(!run(&mut ir).changed);
        assert!(!is_probe(&ir, 0, v(2)));
    }

    #[test]
    fn a_get_at_a_different_tier_does_not_pair() {
        let f = func(
            0,
            Some("main"),
            1,
            vec![has(v(0), KnownTier::Instance), get(v(0), KnownTier::Persistent)],
        );
        let mut ir = module(vec![f]);
        assert!(!run(&mut ir).changed);
        assert!(!is_probe(&ir, 0, v(1)));
    }

    #[test]
    fn an_unproven_tier_cannot_witness_a_pair() {
        // Without a proved tier there is no evidence the two calls touch
        // the same entry, so the pass declines rather than guessing.
        let mut f = func(
            0,
            Some("main"),
            1,
            vec![has(v(0), KnownTier::Instance), get(v(0), KnownTier::Instance)],
        );
        if let Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet { tier, .. })) =
            &mut f.bindings.get_mut(v(2)).unwrap().expr
        {
            *tier = StorageTier::Unknown(UnknownReason::InsufficientEvidence);
        }
        let mut ir = module(vec![f]);
        assert!(!run(&mut ir).changed);
    }

    #[test]
    fn a_helper_that_also_writes_storage_is_not_a_bare_probe() {
        // Ambiguous: the helper does more than probe, so its `has` is not
        // provably the SDK's.
        let mixed = func(
            1,
            None,
            1,
            vec![
                has(v(0), KnownTier::Instance),
                Expr::Semantic(SemanticOp::Known(KnownOp::StorageSet {
                    tier: tier(KnownTier::Instance),
                    durability: v(0),
                    key: v(0),
                    resolved_key: None,
                    value: v(0),
                })),
            ],
        );
        let caller = func(
            0,
            Some("main"),
            1,
            vec![
                Expr::Call {
                    target: FuncId::from_index(1),
                    args: vec![v(0)],
                },
                get(v(0), KnownTier::Instance),
            ],
        );
        let mut ir = module(vec![caller, mixed]);
        assert!(!run(&mut ir).changed);
        assert!(!is_probe(&ir, 1, v(1)));
    }

    #[test]
    fn second_run_reports_no_change() {
        let f = func(
            0,
            Some("main"),
            1,
            vec![has(v(0), KnownTier::Instance), get(v(0), KnownTier::Instance)],
        );
        let mut ir = module(vec![f]);
        assert!(run(&mut ir).changed);
        assert!(!run(&mut ir).changed, "idempotent on rerun");
    }
}
