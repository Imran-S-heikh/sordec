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
//!
//! ## An encode outlined into a helper
//!
//! rustc often outlines the `u64` dispatch above into a helper the
//! entrypoints share, and the entrypoint returns `func1(a + b).1`. When that
//! helper does nothing but encode its argument on every path
//! ([`super::encode_helper`]), the component *is* the encode, and collapses
//! as the inline one does — only when nothing but the return reads it, since
//! it is rewritten in place. The call, left with no reader, is dropped: the
//! helper has no effect to keep.
//!
//! A `Result<T, E>`'s `Err` path returns an error value — a constant tagged
//! `Error`, or a value typed one — which is no encoding of `T`. It is left
//! be, and the other paths still collapse.
//!
//! ## A unit enum with integer discriminants, returned as a constant
//!
//! `#[contracttype] enum EnumIntA { V1 = 1, V2 = 2, V3 = 3 }` crosses the
//! ABI as the `U32Val` of its discriminant, so `EnumIntA::V3` returned is
//! the constant word `3 << 32 | U32Val`. A path returning such a word from
//! an entrypoint the spec declares to return the enum returns the variant
//! whose discriminant is the word's payload — the derive writes exactly
//! that word for that variant and no other, since the discriminants of one
//! enum are distinct. A payload no variant carries is left as it is.

use sordec_common::ValueId;
use sordec_ir::{
    EnumDef, Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, Literal, Region, SemanticOp,
    UnaryOp, ValObjectKind,
};

use super::encode_helper::{elide_spent_calls, encoder_calls, EncoderTable};
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
        let encoders = EncoderTable::build(ir);
        let enums: Vec<EnumDef> = ir.soroban_facts.as_ref().map(|f| f.types.enums.clone()).unwrap_or_default();
        for func in &mut ir.functions {
            let elisions = plan(func, &encoders, &enums);
            if !elisions.is_empty() {
                result.changed = true;
                result
                    .metrics
                    .increment(metrics::ENCODE_COLLAPSED, elisions.len() as i64);
                apply_elisions(func, PASS_NAME, elisions);
            }
            // A call to a helper that only encodes, once nothing reads what
            // it returned — its result collapsed here, or its status checked
            // only by a guard since removed — has no effect left to keep.
            let calls = encoder_calls(func, &encoders);
            if elide_spent_calls(func, &encoders, &calls, PASS_NAME) > 0 {
                result.changed = true;
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
fn plan(func: &HighFunction, encoders: &EncoderTable, enums: &[EnumDef]) -> Vec<Elision> {
    let mut elisions = Vec::new();
    let Some(declared) = declared_return_type(func) else {
        return elisions;
    };
    let result = matches!(
        func.signature.as_ref().map(|s| s.outputs.as_slice()),
        Some([only]) if matches!(known_of_type_ref(only), Some(KnownType::Result(..)))
    );
    // A constant already in its encoded form: a number, or the variant of
    // an integer enum whose discriminant it carries.
    let constant = |encoded: ValueId| {
        encoded_constant(func, encoded, &declared)
            .map(Expr::Literal)
            .or_else(|| encoded_variant(func, encoded, &declared, enums).map(|name| Expr::Variant { name }))
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
        // A constant the path returns already encoded — `4`, `U32Val(0)` —
        // stands for its payload, whatever the other paths encode.
        let mut constants: Vec<(ValueId, Expr)> = Vec::new();
        for (binding, encoded) in &sites {
            // A `Result`'s `Err` path returns an error value, which is no
            // encoding of the `Ok` type: left be, as the emitter wraps it.
            if result && is_error_value(func, *encoded) {
                continue;
            }
            if let Some(expr) = constant(*encoded) {
                // Rewritten in place, so only a constant nothing else reads.
                if read_count(func, *binding) != 1 {
                    ok = false;
                    break;
                }
                constants.push((*binding, expr));
                continue;
            }
            // A path returning a value already of the declared type is the
            // payload as it stands.
            if matches!(
                func.bindings.get(*encoded).map(|b| &b.ty),
                Some(IrType::Known(k) | IrType::Inferred(k)) if *k == declared
            ) {
                continue;
            }
            // The encode outlined into a helper the entrypoints share: the
            // call's component *is* the encode, on every path. Rewritten in
            // place, so only a component nothing but the return reads.
            let outlined = || {
                let (value, ty) = encoders.encoded_by_call(func, *encoded)?;
                (ty == declared && read_count(func, *binding) == 1).then_some(value)
            };
            match encoded_payload(func, *encoded, &declared).or_else(outlined) {
                Some(value) if payload.is_none_or(|p| p == value) => payload = Some(value),
                _ => {
                    ok = false;
                    break;
                }
            }
        }
        if !ok {
            continue;
        }
        let note = format!(
            "return-value encode collapsed at the ABI boundary \
             (contractspecv0 declares this entrypoint returns {declared:?})"
        );
        for (binding, expr) in constants {
            elisions.push(Elision {
                id: binding,
                expr,
                ty: Some(IrType::Known(declared.clone())),
                note: note.clone(),
                metric: metrics::ENCODE_COLLAPSED,
            });
        }
        let Some(payload) = payload else {
            continue;
        };
        for (binding, encoded) in sites {
            if result && is_error_value(func, encoded) {
                continue;
            }
            let typed = matches!(
                func.bindings.get(encoded).map(|b| &b.ty),
                Some(IrType::Known(k) | IrType::Inferred(k)) if *k == declared
            );
            if typed || constant(encoded).is_some() {
                continue;
            }
            elisions.push(Elision {
                id: binding,
                expr: Expr::Use(payload),
                ty: Some(IrType::Known(declared.clone())),
                note: note.clone(),
                metric: metrics::ENCODE_COLLAPSED,
            });
        }
    }
    elisions
}

/// An error value: one typed `Error`, or a constant whose tag is
/// `Error`'s. No `Ok` type encodes to that tag.
fn is_error_value(func: &HighFunction, value: ValueId) -> bool {
    let Some(b) = func.bindings.get(resolve_use(func, value)) else { return false };
    if matches!(b.ty, IrType::Known(KnownType::Error) | IrType::Inferred(KnownType::Error)) {
        return true;
    }
    match &b.expr {
        Expr::Literal(Literal::I64(n)) => (*n as u64 & 0xFF) as u8 == crate::val_abi::TAG_ERROR,
        Expr::Literal(Literal::U64(n)) => (*n & 0xFF) as u8 == crate::val_abi::TAG_ERROR,
        _ => false,
    }
}

/// The single type `contractspecv0` declares this entrypoint returns.
///
/// `None` for a helper, for a `void` entrypoint, and for the exotic
/// multi-value case — all of which lack the one-value ABI boundary the
/// collapse is anchored on.
///
/// For `Result<T, E>` it is `T`. The host reads a returned `Val` back as
/// the `Result` by its tag: an error is `Err`, anything else is the `Ok`
/// payload's own encoding — so a path returning an encoded `T` returns
/// `Ok(t)`, and the emitter wraps a returned `T` in exactly that. The
/// `Err` paths return an error value, which is no encode and is left be.
pub(super) fn declared_return_type(func: &HighFunction) -> Option<KnownType> {
    let sig = func.signature.as_ref()?;
    let [only] = sig.outputs.as_slice() else {
        return None;
    };
    match known_of_type_ref(only)? {
        KnownType::Result(ok, _) => match *ok {
            IrType::Known(k) | IrType::Inferred(k) => Some(k),
            IrType::Unknown(_) => None,
        },
        other => Some(other),
    }
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
        // A returned `select` returns one of its arms.
        Expr::Select { if_true, if_false, .. } => [*if_true, *if_false]
            .iter()
            .map(|v| {
                let def = resolve_use(func, *v);
                (def, def)
            })
            .collect(),
        _ => vec![(id, id)],
    }
}

/// How often scheduled bindings and the region tree read `value`.
///
/// A reader that is itself read by nothing and has no effect does not
/// count: the `select` a returned select was branched from stays scheduled
/// until the sweep, reading both arms.
fn read_count(func: &HighFunction, value: ValueId) -> usize {
    let order = super::sret::emission_order(func);
    let raw = |v: ValueId| {
        let mut n = 0;
        for id in &order {
            if let Some(b) = func.bindings.get(*id) {
                b.expr.for_each_value_use(|u| n += usize::from(u == v));
            }
        }
        func.region.for_each_value_use(|u| n += usize::from(u == v));
        n
    };
    let mut n = 0;
    for id in &order {
        let Some(b) = func.bindings.get(*id) else { continue };
        let mut reads = 0;
        b.expr.for_each_value_use(|u| reads += usize::from(u == value));
        if reads == 0 {
            continue;
        }
        let dead = raw(*id) == 0 && crate::effects::expr_effects(&b.expr).is_pure_total();
        if !dead {
            n += reads;
        }
    }
    func.region.for_each_value_use(|u| n += usize::from(u == value));
    n
}

/// A constant that is a returned value's encoding already: the bits of a
/// small `Val` of the declared type, read back as its payload. Only a raw
/// 64-bit constant — one already given a narrower type has been decoded.
pub(super) fn encoded_constant(func: &HighFunction, value: ValueId, declared: &KnownType) -> Option<Literal> {
    let binding = func.bindings.get(resolve_use(func, value))?;
    let bits = match &binding.expr {
        Expr::Literal(Literal::I64(n)) => *n as u64,
        Expr::Literal(Literal::U64(n)) => *n,
        _ => return None,
    };
    let tag = (bits & 0xFF) as u8;
    let body_low = (bits >> 8) & 0xFF_FFFF;
    match declared {
        KnownType::U32 if tag == crate::val_abi::TAG_U32_VAL && body_low == 0 => {
            Some(Literal::U32((bits >> 32) as u32))
        }
        KnownType::I32 if tag == crate::val_abi::TAG_I32_VAL && body_low == 0 => {
            Some(Literal::I32((bits >> 32) as u32 as i32))
        }
        KnownType::Bool if bits == u64::from(crate::val_abi::TAG_FALSE) => Some(Literal::Bool(false)),
        KnownType::Bool if bits == u64::from(crate::val_abi::TAG_TRUE) => Some(Literal::Bool(true)),
        _ => None,
    }
}

/// The variant a constant returned as an integer enum is: the one whose
/// discriminant the `U32Val` word carries. `None` when `declared` is not
/// such an enum, the word is not a `U32Val`, or no variant has that
/// discriminant.
fn encoded_variant(func: &HighFunction, value: ValueId, declared: &KnownType, enums: &[EnumDef]) -> Option<String> {
    let KnownType::UserDefined(id) = declared else { return None };
    let def = enums.iter().find(|e| e.id == *id)?;
    let Literal::U32(n) = encoded_constant(func, value, &KnownType::U32)? else { return None };
    def.cases.iter().find(|c| c.value == n).map(|c| c.name.clone())
}

/// The payload `encoded` wraps, when it is a `Val` encode producing
/// `declared`. `None` for anything else — including an encode to a
/// *different* type, which would mean our reading of the boundary is
/// wrong.
///
/// A 128-bit small encode is declined too. What it takes is the *low
/// limb*, one 64-bit half of the value, so naming its operand as the
/// returned `i128` would declare a half to be the whole. The value is the
/// pair of limbs, and [`super::wide_encode`] is what folds that.
fn encoded_payload(
    func: &HighFunction,
    encoded: ValueId,
    declared: &KnownType,
) -> Option<ValueId> {
    let binding = func.bindings.get(resolve_use(func, encoded))?;
    let (payload, encoded_ty) = match &binding.expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall {
            ty: KnownType::I128 | KnownType::U128,
            ..
        })) => return None,
        Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty, value })) => {
            (*value, ty.clone())
        }
        Expr::Semantic(SemanticOp::Known(KnownOp::ValObject { kind, args }))
            if args.len() == 1 =>
        {
            (args[0], object_ctor_payload_type(*kind)?)
        }
        // A `bool` is its own tag, `0` or `1`: widening it to the word *is*
        // its encoding.
        Expr::Unary { op: UnaryOp::ExtendU32, value }
            if matches!(
                func.bindings.get(resolve_use(func, *value)).map(|b| &b.ty),
                Some(IrType::Known(KnownType::Bool) | IrType::Inferred(KnownType::Bool))
            ) =>
        {
            (*value, KnownType::Bool)
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
        let elisions = plan(&both_encodings(PrimitiveType::U64), &EncoderTable::default(), &[]);
        assert_eq!(elisions.len(), 2, "one per encoding arm");
        for el in &elisions {
            assert!(matches!(el.expr, Expr::Use(p) if p == v(0)));
            assert_eq!(el.ty, Some(IrType::Known(KnownType::U64)));
        }
    }

    /// `Result<T, E>`: the `Ok` path's encode of a `T` is the `Ok` payload,
    /// and the emitter wraps a returned `T` in `Ok`.
    #[test]
    fn a_result_returns_ok_payload_encode_collapses_too() {
        let mut f = both_encodings(PrimitiveType::U64);
        if let Some(sig) = f.signature.as_mut() {
            sig.outputs = vec![TypeRef::Composite(sordec_ir::CompositeType::Result(
                Box::new(TypeRef::Primitive(PrimitiveType::U64)),
                Box::new(TypeRef::Primitive(PrimitiveType::Error)),
            ))];
        }
        let elisions = plan(&f, &EncoderTable::default(), &[]);
        assert_eq!(elisions.len(), 2, "one per encoding arm");
        assert!(elisions.iter().all(|el| el.ty == Some(IrType::Known(KnownType::U64))));
    }

    /// A path returning `4` from a `u32` function returns `U32Val(0)`
    /// already encoded: it is the constant `0`.
    #[test]
    fn a_returned_encoded_constant_is_its_payload() {
        let f = returning(PrimitiveType::U32, vec![Expr::Literal(Literal::I64(4))], v(0));
        let elisions = plan(&f, &EncoderTable::default(), &[]);
        assert_eq!(elisions.len(), 1);
        assert!(matches!(elisions[0].expr, Expr::Literal(Literal::U32(0))));
    }

    /// `EnumIntA { V1 = 1, V2 = 2, V3 = 3 }`, declared as the return.
    fn returning_enum(word: i64) -> (HighFunction, Vec<EnumDef>) {
        use sordec_common::TypeId;
        let mut f = returning(PrimitiveType::U32, vec![Expr::Literal(Literal::I64(word))], v(0));
        f.signature.as_mut().unwrap().outputs = vec![TypeRef::UserDefined(TypeId::new(12))];
        let enums = vec![EnumDef {
            id: TypeId::new(12),
            name: "EnumIntA".to_string(),
            cases: (1..=3)
                .map(|n| sordec_ir::EnumCase { name: format!("V{n}"), value: n })
                .collect(),
        }];
        (f, enums)
    }

    /// `3 << 32 | U32Val` returned as `EnumIntA` is `EnumIntA::V3`.
    #[test]
    fn a_returned_encoded_discriminant_is_its_variant() {
        let (f, enums) = returning_enum((3 << 32) | 4);
        let elisions = plan(&f, &EncoderTable::default(), &enums);
        assert_eq!(elisions.len(), 1);
        assert!(matches!(&elisions[0].expr, Expr::Variant { name } if name == "V3"), "{:?}", elisions[0].expr);
        assert!(matches!(
            elisions[0].ty,
            Some(IrType::Known(KnownType::UserDefined(id))) if id == sordec_common::TypeId::new(12)
        ));
    }

    /// A discriminant no variant carries, or a word with another tag, is
    /// left as it is.
    #[test]
    fn a_word_naming_no_variant_is_left_alone() {
        for word in [(7 << 32) | 4, (3 << 32) | 5] {
            let (f, enums) = returning_enum(word);
            assert!(plan(&f, &EncoderTable::default(), &enums).is_empty(), "{word:#x}");
        }
    }

    #[test]
    fn the_phi_itself_is_left_untouched() {
        let elisions = plan(&both_encodings(PrimitiveType::U64), &EncoderTable::default(), &[]);
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
        let elisions = plan(&both_encodings(PrimitiveType::I64), &EncoderTable::default(), &[]);
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
        assert!(plan(&func, &EncoderTable::default(), &[]).is_empty(), "differing payloads must not collapse");
    }

    #[test]
    fn a_helper_return_is_left_alone() {
        // No signature means no typed ABI boundary to lean on.
        let mut func = both_encodings(PrimitiveType::U64);
        func.signature = None;
        assert!(plan(&func, &EncoderTable::default(), &[]).is_empty());
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
        let elisions = plan(&func, &EncoderTable::default(), &[]);
        assert_eq!(elisions.len(), 1);
        assert!(matches!(elisions[0].expr, Expr::Use(p) if p == v(0)));
    }

    /// `add`: `return func1(v0).1`, where func 1 only encodes its argument.
    fn outlined(declared: TypeRef, extra_reader: bool) -> sordec_ir::HighIr {
        use crate::marshalling::test_support::module;
        let mut helper = func_with(
            vec![
                Expr::Phi { incoming: vec![] }, // v0: x
                obj_from_u64(v(0)),             // v1
                encode_small(v(0), KnownType::U64), // v2
                Expr::Phi { incoming: vec![(BlockId::from_index(0), v(1)), (BlockId::from_index(1), v(2))] }, // v3
                Expr::Literal(Literal::I64(0)), // v4
            ],
            vec![v(0)],
            vec![1, 2, 4],
        );
        helper.id = sordec_common::FuncId::from_index(1);
        helper.region = Region::Sequence(vec![
            Region::Basic(BlockId::from_index(0)),
            Region::Return { values: vec![v(4), v(3)] },
        ]);
        let mut entry = func_with(
            vec![
                Expr::Phi { incoming: vec![] }, // v0: the sum
                Expr::Call { target: sordec_common::FuncId::from_index(1), args: vec![v(0)] }, // v1
                Expr::Project { value: v(1), index: 1 }, // v2
                store(v(0), v(2)),               // v3, only with `extra_reader`
            ],
            vec![v(0)],
            if extra_reader { vec![1, 2, 3] } else { vec![1, 2] },
        );
        entry.signature = Some(FunctionSignature { name: "add".to_string(), inputs: vec![], outputs: vec![declared] });
        entry.region = Region::Sequence(vec![
            Region::Basic(BlockId::from_index(0)),
            Region::Return { values: vec![v(2)] },
        ]);
        module(vec![entry, helper])
    }

    fn store(addr: ValueId, value: ValueId) -> Expr {
        crate::marshalling::test_support::store(addr, value, 8)
    }

    #[test]
    fn an_encode_outlined_into_a_helper_collapses_and_the_call_goes() {
        let mut ir = outlined(TypeRef::Primitive(PrimitiveType::U64), false);
        assert!(ValEncodeCollapsePass.run(&mut ir).changed);
        let f = &ir.functions[0];
        assert!(matches!(f.bindings.get(v(2)).unwrap().expr, Expr::Use(p) if p == v(0)));
        assert!(matches!(f.bindings.get(v(1)).unwrap().expr, Expr::Literal(Literal::Unit)), "the spent call is dropped");
    }

    #[test]
    fn an_outlined_encode_something_else_reads_stays() {
        let mut ir = outlined(TypeRef::Primitive(PrimitiveType::U64), true);
        ValEncodeCollapsePass.run(&mut ir);
        let f = &ir.functions[0];
        assert!(matches!(f.bindings.get(v(2)).unwrap().expr, Expr::Project { .. }));
        assert!(matches!(f.bindings.get(v(1)).unwrap().expr, Expr::Call { .. }));
    }

    #[test]
    fn an_err_arm_is_left_be_and_the_ok_arm_collapses() {
        let mut f = both_encodings(PrimitiveType::U64);
        if let Some(sig) = f.signature.as_mut() {
            sig.outputs = vec![TypeRef::Composite(sordec_ir::CompositeType::Result(
                Box::new(TypeRef::Primitive(PrimitiveType::U64)),
                Box::new(TypeRef::Primitive(PrimitiveType::Error)),
            ))];
        }
        // A third arm: the contract error 1, `(1 << 32) | 3`.
        let err = f.bindings.push(sordec_ir::Binding::new(
            v(4),
            IrType::Known(KnownType::I64),
            Expr::Literal(Literal::I64((1 << 32) | 3)),
            sordec_common::Provenance::new("seed", sordec_common::ProvenanceSource::DataFlow, "seed"),
        ));
        if let Some(Expr::Phi { incoming }) = f.bindings.get_mut(v(3)).map(|b| &mut b.expr) {
            incoming.push((BlockId::from_index(2), err));
        }
        let elisions = plan(&f, &EncoderTable::default(), &[]);
        assert_eq!(elisions.len(), 2, "the two encodes; the error stands");
        assert!(elisions.iter().all(|e| e.id != err));
    }

    #[test]
    fn second_run_reports_no_work() {
        let mut func = both_encodings(PrimitiveType::U64);
        let first = plan(&func, &EncoderTable::default(), &[]);
        assert!(!first.is_empty());
        apply_elisions(&mut func, PASS_NAME, first);
        assert!(plan(&func, &EncoderTable::default(), &[]).is_empty(), "idempotent: the encodes are gone");
    }
}
