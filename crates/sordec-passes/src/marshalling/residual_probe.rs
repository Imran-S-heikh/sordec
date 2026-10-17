//! A storage probe and read that no `Option` fold claimed, spelled as the
//! two calls they are.
//!
//! # The shape
//!
//! `Storage::get` is a `has` on the key and a guarded `get`, and the
//! `Option` passes fold the pair back into one read once they prove which
//! combinator the source applied: `unwrap`, `unwrap_or`, an `if let`. Until
//! then the `has` is marked as the SDK's own (not printed) and the read is
//! the bare `get(&k)`, an `Option`.
//!
//! Some pairs no fold claims. Library code checks presence itself and
//! panics with its own error, then reads:
//!
//! ```text
//! p = has(k)                         if !e.storage().instance().has(&k) {
//! if !p { panic_with_error(..) }  →      ..panic_with_error..
//! v: BytesN<32> = get(k)             }
//!                                    let v: BytesN<32> = e.storage().instance().get(&k).unwrap();
//! ```
//!
//! Left as they were, both facts are wrong at once: the `has` is not printed
//! (`todo!("storage_has..")`) though the branch on it is real code, and the
//! read is an `Option` while its value is used as what is stored.
//!
//! # The two rewrites
//!
//! - **A probe no read claims is the source's check.** A probe a fold took
//!   is either gone (its branch with it) or named by the `if let` read it
//!   guards (`Missing::Present`). One still standing and named by none is a
//!   `has` the output must print — unless the function hands it back with no
//!   read of its own key beside it. That is the SDK's outlined `has`, whose
//!   read is in the caller and folds there once the wrapper is pasted in; it
//!   stays the SDK's. The mark itself can be wrong the other way: a `has`
//!   wrapper shared by a `get` and by the author's own check is marked once,
//!   and inlining copies the mark into both callers.
//! - **A read typed as what is stored unwraps.** The host's read returns the
//!   stored value and traps on a missing key; `get(&k).unwrap()` is that.
//!   Only for a read typed as a value: one typed `Option` is a fold's real
//!   `get(&k)`, and one typed nothing or `Val` names no value to unwrap to.
//!
//! After every fold and type recovery, so it sees only what they left.

use std::collections::HashSet;

use sordec_common::{Provenance, ProvenanceSource, ValueId};
use sordec_ir::{Expr, HighIr, IrType, KnownOp, KnownTier, KnownType, Missing, SemanticOp};

use super::option_probe::{proven_tier, same_key};
use crate::dataflow::high_uses::HighUseIndex;
use crate::dataflow::resolve_use;
use crate::pass::{Pass, PassResult};

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-residual-probe";

/// Probes no fold claimed, now printed as `has`.
const M_PROBES: &str = "residual_probes_spelled";
/// Reads typed as a value, now `.unwrap()`.
const M_READS: &str = "residual_reads_unwrapped";

/// Spells the probe/read pairs the `Option` folds left alone.
#[derive(Debug, Default, Clone, Copy)]
pub struct ResidualProbePass;

impl Pass<HighIr> for ResidualProbePass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        for func in &mut ir.functions {
            let uses = HighUseIndex::build(func);
            let claimed: HashSet<ValueId> = func
                .bindings
                .iter()
                .filter_map(|(_, b)| match &b.expr {
                    Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet {
                        missing: Missing::Present(probe),
                        ..
                    })) => Some(*probe),
                    _ => None,
                })
                .collect();
            // Every read's tier and key, to pair a probe with a read of its
            // own in this function — the same pairing the probe was marked by.
            let gets: Vec<(KnownTier, ValueId)> = func
                .bindings
                .iter()
                .filter_map(|(_, b)| match &b.expr {
                    Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet { tier, key, .. })) => {
                        Some((proven_tier(tier)?, *key))
                    }
                    _ => None,
                })
                .collect();
            let mut probes = Vec::new();
            let mut reads = Vec::new();
            for (id, binding) in func.bindings.iter() {
                match &binding.expr {
                    Expr::Semantic(SemanticOp::Known(KnownOp::StorageHas { probe: true, tier, key, .. }))
                        if !claimed.contains(&id) && !uses.is_unused(id) =>
                    {
                        let read_beside = proven_tier(tier)
                            .is_some_and(|t| gets.iter().any(|(gt, gk)| *gt == t && same_key(func, *gk, *key)));
                        let handed_back =
                            func.returns.iter().flatten().any(|r| resolve_use(func, *r) == id);
                        if read_beside || !handed_back {
                            probes.push(id);
                        }
                    }
                    Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet { missing: Missing::Option, .. }))
                        if stored_value(&binding.ty) =>
                    {
                        reads.push(id);
                    }
                    _ => {}
                }
            }
            for id in probes {
                let Some(binding) = func.bindings.get_mut(id) else {
                    continue;
                };
                if let Expr::Semantic(SemanticOp::Known(KnownOp::StorageHas { probe, .. })) = &mut binding.expr {
                    *probe = false;
                    binding.add_provenance(Provenance::new(
                        PASS_NAME,
                        ProvenanceSource::SdkPattern,
                        "no `Option` fold claimed this probe: the source's own `has`",
                    ));
                    result.metrics.increment(M_PROBES, 1);
                    result.changed = true;
                }
            }
            for id in reads {
                let Some(binding) = func.bindings.get_mut(id) else {
                    continue;
                };
                if let Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet { missing, .. })) = &mut binding.expr {
                    *missing = Missing::Unwrap;
                    binding.add_provenance(Provenance::new(
                        PASS_NAME,
                        ProvenanceSource::HostFunctionAbi,
                        "a read typed as the stored value: the host's read traps on a missing key, as `unwrap` does",
                    ));
                    result.metrics.increment(M_READS, 1);
                    result.changed = true;
                }
            }
        }
        result
    }
}

/// Whether a read's type names a stored value: not an `Option`, not the
/// host's bare `Val`, not unrecovered.
fn stored_value(ty: &IrType) -> bool {
    match ty {
        IrType::Known(k) | IrType::Inferred(k) => !matches!(k, KnownType::Option(_) | KnownType::Val),
        IrType::Unknown(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, module, v};
    use sordec_ir::StorageTier;

    fn has() -> Expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::StorageHas {
            tier: StorageTier::Known(KnownTier::Instance),
            durability: v(0),
            key: v(0),
            resolved_key: None,
            probe: true,
        }))
    }

    fn get(missing: Missing) -> Expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet {
            tier: StorageTier::Known(KnownTier::Instance),
            durability: v(0),
            key: v(0),
            resolved_key: None,
            missing,
        }))
    }

    /// v0 key, v1 probe, v2 a reader of the probe, v3 the read typed `ty`.
    fn pair(read: Missing, ty: IrType) -> HighIr {
        let mut f = func_with(
            vec![
                Expr::Phi { incoming: vec![] },
                has(),
                Expr::Unary { op: sordec_ir::UnaryOp::Eqz, value: v(1) },
                get(read),
            ],
            vec![],
            vec![0, 1, 2, 3],
        );
        f.bindings.get_mut(v(3)).unwrap().ty = ty;
        module(vec![f])
    }

    #[test]
    fn an_unclaimed_probe_is_spelled_and_its_typed_read_unwraps() {
        let mut ir = pair(Missing::Option, IrType::Known(KnownType::BytesN(32)));
        assert!(ResidualProbePass.run(&mut ir).changed);
        let f = &ir.functions[0];
        assert!(matches!(
            &f.bindings.get(v(1)).unwrap().expr,
            Expr::Semantic(SemanticOp::Known(KnownOp::StorageHas { probe: false, .. }))
        ));
        assert!(matches!(
            &f.bindings.get(v(3)).unwrap().expr,
            Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet { missing: Missing::Unwrap, .. }))
        ));
    }

    #[test]
    fn a_probe_whose_read_is_in_another_function_stays_the_sdk_s() {
        // A `has` wrapper: the probe handed back, the read in its caller.
        let mut ir = pair(Missing::Option, IrType::Known(KnownType::BytesN(32)));
        ir.functions[0].bindings.get_mut(v(3)).unwrap().expr = Expr::Literal(sordec_ir::Literal::Unit);
        ir.functions[0].returns = vec![vec![v(1)]];
        ResidualProbePass.run(&mut ir);
        assert!(matches!(
            &ir.functions[0].bindings.get(v(1)).unwrap().expr,
            Expr::Semantic(SemanticOp::Known(KnownOp::StorageHas { probe: true, .. }))
        ));
    }

    #[test]
    fn a_copied_mark_on_the_author_s_own_check_is_dropped() {
        // `if has(&k) { panic }` with no read: inlining copied the mark.
        let mut ir = pair(Missing::Option, IrType::Known(KnownType::BytesN(32)));
        ir.functions[0].bindings.get_mut(v(3)).unwrap().expr = Expr::Literal(sordec_ir::Literal::Unit);
        assert!(ResidualProbePass.run(&mut ir).changed);
        assert!(matches!(
            &ir.functions[0].bindings.get(v(1)).unwrap().expr,
            Expr::Semantic(SemanticOp::Known(KnownOp::StorageHas { probe: false, .. }))
        ));
    }

    #[test]
    fn a_probe_an_if_let_claims_stays_the_sdk_s() {
        let mut ir = pair(Missing::Present(v(1)), IrType::Known(KnownType::I128));
        assert!(!ResidualProbePass.run(&mut ir).changed);
    }

    #[test]
    fn an_option_typed_read_stays_an_option() {
        let mut ir = pair(Missing::Present(v(1)), IrType::Unknown(sordec_common::UnknownReason::InsufficientEvidence));
        if let Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet { missing, .. })) =
            &mut ir.functions[0].bindings.get_mut(v(3)).unwrap().expr
        {
            *missing = Missing::Option;
        }
        ir.functions[0].bindings.get_mut(v(3)).unwrap().ty =
            IrType::Inferred(KnownType::Option(Box::new(IrType::Known(KnownType::U32))));
        ResidualProbePass.run(&mut ir);
        assert!(matches!(
            &ir.functions[0].bindings.get(v(3)).unwrap().expr,
            Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet { missing: Missing::Option, .. }))
        ));
    }
}
