//! Collapse an entrypoint's return-value encode back to the value.
//!
//! The mirror of [`super::decode`]. `add` returns `u64` per
//! `contractspecv0`, but the ABI carries a tagged `Val`, so the SDK packs
//! the result on the way out — and because a `u64` has two legal
//! encodings the packing is a branch:
//!
//! ```text
//! if v > 0x00FF_FFFF_FFFF_FFFF { r = obj_from_u64(v) }   ← too wide for a body
//! else                         { r = val_encode<u64>(v) } ← fits inline
//! return r
//! ```
//!
//! Every path returns *the same value* in a different wrapper, so the
//! branch carries no information about the contract. The source wrote
//! `a + b`.
//!
//! ## The gate
//!
//! **Only a value on its way out of an ABI entrypoint, and only when the
//! encoded type is the one `contractspecv0` declares that entrypoint
//! returns.** This is not incidental — it is the whole safety argument. An
//! encode is collapsible precisely because the boundary it crosses is
//! typed: the host unpacks the returned `Val` to the declared type, so
//! naming the value instead of its wrapper loses nothing.
//!
//! Anywhere else the wrapper is load-bearing. A `Val` handed to
//! `storage().set(..)` or pushed into a `Vec<Val>` really is a `Val`, and
//! rewriting it to its payload would change what gets stored. So the
//! transform is anchored on the return, never on the encode alone.

use sordec_common::ValueId;
use sordec_ir::{
    Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, Region, SemanticOp, ValObjectKind,
};

use super::{apply_elisions, metrics, Elision};
use crate::dataflow::resolve_use;
use crate::pass::{Pass, PassResult};
use crate::type_infer::known_of_type_ref;

/// Pass name — also the provenance `pass` field for every elision.
pub const PASS_NAME: &str = "marshalling-encode-collapse";

/// Collapses return-value encodes at the ABI boundary.
#[derive(Debug, Default, Clone, Copy)]
pub struct ValEncodeCollapsePass;

impl Pass<HighIr> for ValEncodeCollapsePass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        for func in &mut ir.functions {
            let elisions = plan(func);
            if !elisions.is_empty() {
                result.changed = true;
                result
                    .metrics
                    .increment(metrics::ENCODE_COLLAPSED, elisions.len() as i64);
                apply_elisions(func, PASS_NAME, elisions);
            }
            // Collapsing both arms of the width dispatch leaves a branch
            // that no longer decides anything. Fold it here, while the
            // evidence that the arms agree is local.
            let mut folded = 0;
            let region = std::mem::replace(&mut func.region, Region::Unreachable);
            func.region = fold_dead_branches(func, region, &mut folded);
            if folded > 0 {
                result.changed = true;
                result
                    .metrics
                    .increment(metrics::DISPATCH_FOLDED, folded);
            }
        }
        crate::refine::debug_validate(ir, PASS_NAME);
        result
    }
}

// ---------------------------------------------------------------------
// Dead-branch folding
// ---------------------------------------------------------------------

/// Drop an `If` that decides nothing.
///
/// After the collapse above, the SDK's small-vs-object width dispatch
/// reads:
///
/// ```text
/// if v > MAX_SMALL_BODY { r = v; break 'out }
/// r = v; break 'out
/// ```
///
/// Both paths assign the same value to the same phi and leave through the
/// same exit, so the branch is unobservable and the comparison feeding it
/// is dead. Removing it is also what retires the comparison itself: while
/// the `If` survives, the region counts its condition as read, so no
/// amount of dead-`let` cleanup downstream can reach it.
///
/// ## Both gates are needed, for opposite reasons
///
/// Folding changes *which* bindings execute in both directions, so purity
/// is required on both sides and neither gate covers the other:
///
/// - the `then` arm's bindings stop executing when the condition holds, so
///   dropping them must lose no effect;
/// - the following bindings start executing when the condition holds, so
///   running them must add no effect.
///
/// `is_pure_total` is the right bar here, unlike in [`super::decode`]: a
/// trapping binding moved across a branch changes whether the contract
/// traps.
fn fold_dead_branches(func: &HighFunction, region: Region, folded: &mut i64) -> Region {
    match region {
        Region::Sequence(items) => {
            let items: Vec<Region> = items
                .into_iter()
                .map(|item| fold_dead_branches(func, item, folded))
                .collect();
            let mut kept: Vec<Region> = Vec::with_capacity(items.len());
            for (index, item) in items.iter().enumerate() {
                let taken = match item {
                    Region::If {
                        else_region: None,
                        then_region,
                        ..
                    } if decides_nothing(func, then_region, &items[index + 1..]) => then_region,
                    _ => {
                        kept.push(item.clone());
                        continue;
                    }
                };
                *folded += 1;
                // Splice the arm's basic blocks in where the branch was,
                // and drop only its exit. Deleting them instead would
                // leave a *reachable* block absent from the region tree,
                // which the structuring corpus lock rightly rejects —
                // the tree is supposed to account for every block. The
                // bindings are already proven pure and total, and the
                // value the dropped transfer carried is the one the
                // fallthrough carries, so running them unconditionally
                // changes nothing observable. Once nothing reads them,
                // the backend's dead-`let` pass takes them out of the
                // emitted source.
                kept.extend(flatten(std::slice::from_ref(taken.as_ref()))
                    .into_iter()
                    .filter(|r| matches!(r, Region::Basic(_)))
                    .cloned());
            }
            crate::structuring::seq(kept)
        }
        Region::Scope { out, body } => Region::Scope {
            out,
            body: Box::new(fold_dead_branches(func, *body, folded)),
        },
        Region::Loop { header, body, kind } => Region::Loop {
            header,
            body: Box::new(fold_dead_branches(func, *body, folded)),
            kind,
        },
        Region::Switch {
            index,
            arms,
            default,
            dispatch,
        } => Region::Switch {
            index,
            arms: arms
                .into_iter()
                .map(|mut arm| {
                    arm.body = fold_dead_branches(func, arm.body, folded);
                    arm
                })
                .collect(),
            default: Box::new(fold_dead_branches(func, *default, folded)),
            dispatch,
        },
        Region::If {
            cond,
            then_region,
            else_region,
        } => Region::If {
            cond,
            then_region: Box::new(fold_dead_branches(func, *then_region, folded)),
            else_region: else_region.map(|e| Box::new(fold_dead_branches(func, *e, folded))),
        },
        leaf @ (Region::Basic(_)
        | Region::Break { .. }
        | Region::Continue { .. }
        | Region::Transfer { .. }
        | Region::Return { .. }
        | Region::Unreachable
        | Region::Panic { .. }
        | Region::Unstructured { .. }) => leaf,
    }
}

/// Whether taking `taken` is indistinguishable from falling through to
/// `fallthrough`.
fn decides_nothing(func: &HighFunction, taken: &Region, fallthrough: &[Region]) -> bool {
    let Some(taken_exit) = exit_signature(func, std::slice::from_ref(taken)) else {
        return false;
    };
    let Some(fallthrough_exit) = exit_signature(func, fallthrough) else {
        return false;
    };
    taken_exit == fallthrough_exit
        && side_effect_free(func, std::slice::from_ref(taken))
        && side_effect_free(func, fallthrough)
}

/// Where a straight-line region sequence leaves, and with which phi
/// values — sources resolved through alias chains and ordered by
/// destination so two spellings of the same transfer compare equal.
///
/// `None` for anything that is not a plain `Break`-terminated run: a
/// nested branch, a loop, a return, a trap. Those may differ in ways this
/// signature does not model, so they are never folded.
fn exit_signature(
    func: &HighFunction,
    regions: &[Region],
) -> Option<(sordec_common::BlockId, Vec<(ValueId, ValueId)>)> {
    let flat = flatten(regions);
    let (last, rest) = flat.split_last()?;
    // Everything before the exit must be straight-line basic blocks.
    if !rest.iter().all(|r| matches!(r, Region::Basic(_))) {
        return None;
    }
    let Region::Break { target, transfer } = last else {
        return None;
    };
    let mut resolved: Vec<(ValueId, ValueId)> = transfer
        .iter()
        .map(|(dest, src)| (*dest, resolve_use(func, *src)))
        .collect();
    resolved.sort_unstable();
    Some((*target, resolved))
}

/// One level of `Sequence` unwrapping, so a single-item arm and an
/// inlined tail compare on equal terms.
fn flatten(regions: &[Region]) -> Vec<&Region> {
    let mut flat = Vec::new();
    for region in regions {
        match region {
            Region::Sequence(items) => flat.extend(items.iter()),
            other => flat.push(other),
        }
    }
    flat
}

/// Whether every binding these regions schedule is pure and total.
fn side_effect_free(func: &HighFunction, regions: &[Region]) -> bool {
    let mut clean = true;
    for region in regions {
        region.for_each_node(|node| {
            if let Region::Basic(b) = node
                && let Some(block) = func.blocks.get(*b)
            {
                for vid in &block.bindings {
                    if let Some(binding) = func.bindings.get(*vid)
                        && !crate::effects::expr_effects(&binding.expr).is_pure_total()
                    {
                        clean = false;
                    }
                }
            }
        });
    }
    clean
}

/// Plan every return-encode collapse in one function.
fn plan(func: &HighFunction) -> Vec<Elision> {
    let mut elisions = Vec::new();
    let Some(declared) = declared_return_type(func) else {
        return elisions;
    };

    for returned in returned_values(func) {
        // Each site that produces the returned value on some path.
        let sites = producing_sites(func, returned);
        if sites.is_empty() {
            continue;
        }
        // Every path must encode the *same* value to the declared type;
        // a disagreement means this is not a single value in a wrapper.
        let mut payload: Option<ValueId> = None;
        let mut ok = true;
        for (_, encoded) in &sites {
            match encoded_payload(func, *encoded, &declared) {
                Some(value) if payload.is_none_or(|p| p == value) => payload = Some(value),
                _ => {
                    ok = false;
                    break;
                }
            }
        }
        let (true, Some(payload)) = (ok, payload) else {
            continue;
        };
        for (binding, _) in sites {
            elisions.push(Elision {
                id: binding,
                expr: Expr::Use(payload),
                ty: Some(IrType::Known(declared.clone())),
                note: format!(
                    "return-value encode collapsed at the ABI boundary \
                     (contractspecv0 declares this entrypoint returns {declared:?})"
                ),
                metric: metrics::ENCODE_COLLAPSED,
            });
        }
    }
    elisions
}

/// The single type `contractspecv0` declares this entrypoint returns.
///
/// `None` for a helper, for a `void` entrypoint, and for the exotic
/// multi-value case — all of which lack the one-value ABI boundary the
/// collapse is anchored on.
fn declared_return_type(func: &HighFunction) -> Option<KnownType> {
    let sig = func.signature.as_ref()?;
    let [only] = sig.outputs.as_slice() else {
        return None;
    };
    known_of_type_ref(only)
}

/// Every value this function returns.
fn returned_values(func: &HighFunction) -> Vec<ValueId> {
    let mut values = Vec::new();
    func.region.for_each_node(|node| {
        if let Region::Return { values: returned } = node
            && let [only] = returned.as_slice()
            && !values.contains(only)
        {
            values.push(*only);
        }
    });
    values
}

/// The bindings that produce `value` on each path: a phi's incoming
/// definitions, or the value itself when it is not a phi.
///
/// Returned as `(binding to rewrite, definition to inspect)` — the same
/// id in the non-phi case, and the incoming's own binding otherwise, so
/// the phi machinery is left completely untouched. Each arm is rewritten
/// where it is defined; the phi keeps collecting them.
fn producing_sites(func: &HighFunction, value: ValueId) -> Vec<(ValueId, ValueId)> {
    let id = resolve_use(func, value);
    let Some(binding) = func.bindings.get(id) else {
        return vec![];
    };
    match &binding.expr {
        Expr::Phi { incoming } => incoming
            .iter()
            .map(|(_, v)| {
                let def = resolve_use(func, *v);
                (def, def)
            })
            .collect(),
        _ => vec![(id, id)],
    }
}

/// The payload `encoded` wraps, when it is a `Val` encode producing
/// `declared`. `None` for anything else — including an encode to a
/// *different* type, which would mean our reading of the boundary is
/// wrong.
fn encoded_payload(
    func: &HighFunction,
    encoded: ValueId,
    declared: &KnownType,
) -> Option<ValueId> {
    let binding = func.bindings.get(resolve_use(func, encoded))?;
    let (payload, encoded_ty) = match &binding.expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty, value })) => {
            (*value, ty.clone())
        }
        Expr::Semantic(SemanticOp::Known(KnownOp::ValObject { kind, args }))
            if args.len() == 1 =>
        {
            (args[0], object_ctor_payload_type(*kind)?)
        }
        _ => return None,
    };
    (encoded_ty == *declared).then(|| resolve_use(func, payload))
}

/// The payload type of a single-argument `obj_from_*` constructor.
///
/// The multi-piece constructors (`obj_from_i128_pieces` and friends) are
/// absent on purpose: they take limbs rather than a value, so there is no
/// single payload to collapse to. Rejoining those is a separate transform.
fn object_ctor_payload_type(kind: ValObjectKind) -> Option<KnownType> {
    Some(match kind {
        ValObjectKind::ObjFromU64 => KnownType::U64,
        ValObjectKind::ObjFromI64 => KnownType::I64,
        ValObjectKind::TimepointObjFromU64 => KnownType::Timepoint,
        ValObjectKind::DurationObjFromU64 => KnownType::Duration,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, v};
    use sordec_common::{BlockId, IrId as _};
    use sordec_ir::{FunctionSignature, Literal, PrimitiveType, TypeRef};

    fn encode_small(value: ValueId, ty: KnownType) -> Expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty, value }))
    }

    fn obj_from_u64(value: ValueId) -> Expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::ValObject {
            kind: ValObjectKind::ObjFromU64,
            args: vec![value],
        }))
    }

    /// `add`'s tail: a phi over the object and small encodings of one
    /// value, returned.
    fn returning(out: PrimitiveType, exprs: Vec<Expr>, ret: ValueId) -> HighFunction {
        let mut func = func_with(exprs, vec![], vec![0]);
        func.signature = Some(FunctionSignature {
            name: "add".to_string(),
            inputs: vec![],
            outputs: vec![TypeRef::Primitive(out)],
        });
        func.region = Region::Sequence(vec![
            Region::Basic(BlockId::from_index(0)),
            Region::Return { values: vec![ret] },
        ]);
        func
    }

    fn both_encodings(out: PrimitiveType) -> HighFunction {
        returning(
            out,
            vec![
                Expr::Literal(Literal::U64(7)), // v0 the computed value
                obj_from_u64(v(0)),             // v1 wide encoding
                encode_small(v(0), KnownType::U64), // v2 inline encoding
                Expr::Phi {
                    incoming: vec![(BlockId::from_index(1), v(1)), (BlockId::from_index(2), v(2))],
                }, // v3
            ],
            v(3),
        )
    }

    #[test]
    fn both_arms_of_a_return_encode_collapse_to_the_value() {
        let elisions = plan(&both_encodings(PrimitiveType::U64));
        assert_eq!(elisions.len(), 2, "one per encoding arm");
        for el in &elisions {
            assert!(matches!(el.expr, Expr::Use(p) if p == v(0)));
            assert_eq!(el.ty, Some(IrType::Known(KnownType::U64)));
        }
    }

    #[test]
    fn the_phi_itself_is_left_untouched() {
        let elisions = plan(&both_encodings(PrimitiveType::U64));
        assert!(
            elisions.iter().all(|e| e.id != v(3)),
            "phis are `let mut` declarations materialised from transfers; \
             rewriting one would desynchronise them"
        );
    }

    #[test]
    fn an_encode_to_a_type_the_spec_does_not_declare_is_left_alone() {
        // The spec says i64, the encodes produce u64 — our reading of the
        // boundary is wrong somewhere, so collapse nothing.
        let elisions = plan(&both_encodings(PrimitiveType::I64));
        assert!(elisions.is_empty());
    }

    #[test]
    fn arms_encoding_different_values_are_left_alone() {
        let mut func = both_encodings(PrimitiveType::U64);
        // v2 now encodes a different value, so the branch *does* carry
        // information and the return is not one value in a wrapper.
        let other = func.bindings.push(sordec_ir::Binding::new(
            v(4),
            IrType::Known(KnownType::U64),
            Expr::Literal(Literal::U64(9)),
            sordec_common::Provenance::new(
                "seed",
                sordec_common::ProvenanceSource::DataFlow,
                "seed",
            ),
        ));
        func.bindings.get_mut(v(2)).unwrap().expr = encode_small(other, KnownType::U64);
        assert!(plan(&func).is_empty(), "differing payloads must not collapse");
    }

    #[test]
    fn a_helper_return_is_left_alone() {
        // No signature means no typed ABI boundary to lean on.
        let mut func = both_encodings(PrimitiveType::U64);
        func.signature = None;
        assert!(plan(&func).is_empty());
    }

    #[test]
    fn a_direct_return_encode_collapses() {
        let func = returning(
            PrimitiveType::U64,
            vec![
                Expr::Literal(Literal::U64(7)),
                encode_small(v(0), KnownType::U64),
            ],
            v(1),
        );
        let elisions = plan(&func);
        assert_eq!(elisions.len(), 1);
        assert!(matches!(elisions[0].expr, Expr::Use(p) if p == v(0)));
    }

    #[test]
    fn second_run_reports_no_work() {
        let mut func = both_encodings(PrimitiveType::U64);
        let first = plan(&func);
        assert!(!first.is_empty());
        apply_elisions(&mut func, PASS_NAME, first);
        assert!(plan(&func).is_empty(), "idempotent: the encodes are gone");
    }
}
