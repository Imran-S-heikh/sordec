//! An entrypoint declared `-> Option<T>` merges `None` and `Some(t)`, not
//! their encodings.
//!
//! # The shape
//!
//! The SDK encodes an `Option<T>` as `T`'s own `Val` for `Some`, and as
//! `Void` — the whole word is `2` — for `None`. When the arms of an
//! entrypoint merge before its one `return`, each arm hands the merge the
//! encoding:
//!
//! ```text
//! if let Some(v) = get(&k) { r = v }        if let Some(v) = get(&k) { r = Some(v) }
//! else { r = 2 }                       →    else { r = None }
//! return r                                  return r
//! ```
//!
//! The merge is typed `Option<T>` by the spec, so left alone one arm puts
//! a `T` in it and the other an `i64`.
//!
//! An arm may also be the encode itself — the SDK's `obj_from_u64` /
//! `val_encode` pair inline, or a call to a helper that does nothing else
//! ([`super::encode_helper`]) — and then it is `Some` of what it encodes.
//! So is a value returned directly that is such an encode.
//!
//! # Why it is exact
//!
//! `Void` is the encoding of `None` and of nothing else an `Option<T>` can
//! hold — no `T` encodes to it — and a `T`'s `Val` is the encoding of
//! `Some` of it. The spec says the host reads the returned word back as an
//! `Option<T>`, so each arm is that `Option`: the same word either way.
//!
//! # Gates
//!
//! - **The spec's one output is `Option<T>`**, with `T` named.
//! - **Every arm is one of four things**, through merges that are read by
//!   nothing but the return and each other: the constant `2`, a value typed
//!   exactly `T`, an encode of a `T`, or a value already an `Option`.
//!   Anything else — a `Val`, a number of another type — and the return is
//!   left alone.
//! - **An encode read only on the way out** is rewritten in place to the
//!   `Some`, and a helper call left with no reader is dropped (the helper
//!   does nothing else). One something else also reads — a store of the
//!   `Val` — keeps its `Val`, and its edge carries a fresh `Some`.
//! - **A `2` read only by those merges**, rewritten in place to `None`.
//! - **A `T` arm leaves from a block the body schedules.** Its `Some(t)` is
//!   built at the end of that block and the edge carries it; an edge whose
//!   block cannot be told from the region tree leaves the return alone.

use std::collections::{HashMap, HashSet};

use sordec_common::{BlockId, IrId, Provenance, ProvenanceSource, ValueId};
use sordec_ir::{Binding, Expr, HighFunction, HighIr, IrType, KnownType, Literal, Region};

use super::encode_helper::{elide_spent_calls, encoder_calls, inline_encode, EncoderTable};
use crate::dataflow::resolve_use;
use crate::metrics_catalog::MARSHALLING_OPTION_RETURNS as M_OPTION_RETURNS;
use crate::pass::{Pass, PassResult};
use crate::type_infer::known_of_type_ref;
use crate::val_abi::TAG_VOID;

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-option-return";

/// Rewrites the encoded arms of a returned `Option` merge to `None`/`Some`.
#[derive(Debug, Default, Clone, Copy)]
pub struct OptionReturnPass;

impl Pass<HighIr> for OptionReturnPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let encoders = EncoderTable::build(ir);
        for func in &mut ir.functions {
            let Some(option) = declared_option(func) else { continue };
            for plan in plans(func, &option, &encoders) {
                apply(func, &option, plan);
                result.metrics.increment(M_OPTION_RETURNS, 1);
                result.changed = true;
            }
            // A helper call whose component became the `Some` in place has
            // nothing left reading it, and the helper does nothing else.
            let calls = encoder_calls(func, &encoders);
            elide_spent_calls(func, &encoders, &calls, PASS_NAME);
        }
        result
    }
}

/// The rewrite of one returned merge.
#[derive(Debug, Default)]
struct Plan {
    /// The merges the arms flow through, the returned one first.
    merges: Vec<ValueId>,
    /// `2` constants becoming `None`.
    nones: Vec<ValueId>,
    /// `(merge, predecessor block, value, payload)` edges whose value
    /// becomes `Some(payload)`: a `T` is its own payload, an encode of a
    /// `T` the value it encodes.
    somes: Vec<(ValueId, BlockId, ValueId, ValueId)>,
    /// Encodes of a `T` read only on the way out: each becomes
    /// `Some(payload)` in place.
    in_place: Vec<(ValueId, ValueId)>,
}

/// `Option<T>` when the spec's one output is that, with `T` named.
fn declared_option(func: &HighFunction) -> Option<KnownType> {
    let [out] = func.signature.as_ref()?.outputs.as_slice() else { return None };
    let option @ KnownType::Option(_) = known_of_type_ref(out)? else { return None };
    payload(&option).map(|_| option)
}

/// `T` of an `Option<T>`, when it is named.
fn payload(option: &KnownType) -> Option<KnownType> {
    match option {
        KnownType::Option(inner) => match inner.as_ref() {
            IrType::Known(k) | IrType::Inferred(k) => Some(k.clone()),
            IrType::Unknown(_) => None,
        },
        _ => None,
    }
}

fn plans(func: &HighFunction, option: &KnownType, encoders: &EncoderTable) -> Vec<Plan> {
    let Some(t) = payload(option) else { return Vec::new() };
    let mut returned = Vec::new();
    func.region.for_each_node(|node| {
        if let Region::Return { values } = node
            && let [one] = values.as_slice()
        {
            let v = resolve_use(func, *one);
            if !returned.contains(&v) {
                returned.push(v);
            }
        }
    });
    let scheduled: HashSet<BlockId> = scheduled_blocks(func);
    returned
        .into_iter()
        .filter_map(|r| plan(func, r, &t, &scheduled, encoders))
        .filter(|p| !p.nones.is_empty() || !p.somes.is_empty() || !p.in_place.is_empty())
        .collect()
}

/// The payload `v` encodes as `t`: an inline encode, or the component of a
/// helper that only encodes ([`EncoderTable`]).
fn encode_of(func: &HighFunction, encoders: &EncoderTable, v: ValueId, t: &KnownType) -> Option<ValueId> {
    let (payload, ty) = inline_encode(func, v).or_else(|| encoders.encoded_by_call(func, v))?;
    (ty == *t).then_some(payload)
}

/// The rewrite for the value `r` returns, or `None` when an arm is not one
/// of the shapes.
fn plan(
    func: &HighFunction,
    r: ValueId,
    t: &KnownType,
    scheduled: &HashSet<BlockId>,
    encoders: &EncoderTable,
) -> Option<Plan> {
    let mut plan = Plan::default();
    if !matches!(func.bindings.get(r)?.expr, Expr::Phi { .. }) {
        // Returned directly: only an encode, read by the return alone.
        let payload = encode_of(func, encoders, r, t)?;
        if !read_only_by(func, r, &HashSet::new()) {
            return None;
        }
        plan.in_place.push((r, payload));
        return Some(plan);
    }
    let mut encodes: Vec<(ValueId, BlockId, ValueId, ValueId)> = Vec::new();
    let mut work = vec![r];
    let mut seen = HashSet::new();
    while let Some(m) = work.pop() {
        if !seen.insert(m) {
            continue;
        }
        plan.merges.push(m);
        let Expr::Phi { incoming } = &func.bindings.get(m)?.expr else { return None };
        for (pred, arm) in incoming {
            let a = resolve_use(func, *arm);
            let b = func.bindings.get(a)?;
            // An encode first: its own type may already say `Option` or
            // `T`, taken from the very return being repaired.
            if let Some(payload) = encode_of(func, encoders, a, t) {
                encodes.push((m, *pred, *arm, payload));
                continue;
            }
            match &b.expr {
                Expr::Phi { incoming } if !incoming.is_empty() => work.push(a),
                Expr::Literal(Literal::I64(n)) if *n == i64::from(TAG_VOID) => {
                    if !plan.nones.contains(&a) {
                        plan.nones.push(a);
                    }
                }
                Expr::Optional { .. } => {}
                _ if matches!(&b.ty, IrType::Known(KnownType::Option(_)) | IrType::Inferred(KnownType::Option(_))) => {}
                _ if matches!(&b.ty, IrType::Known(k) | IrType::Inferred(k) if k == t) => {
                    if !scheduled.contains(pred) {
                        return None;
                    }
                    plan.somes.push((m, *pred, *arm, *arm));
                }
                _ => return None,
            }
        }
    }
    let merges: HashSet<ValueId> = plan.merges.iter().copied().collect();
    // An encode read only on the way out becomes the `Some` in place; one
    // something else also reads (a store of the `Val`) keeps its `Val`, and
    // the edge carries a fresh `Some` of the payload instead.
    for (m, pred, arm, payload) in encodes {
        let a = resolve_use(func, arm);
        if read_only_by(func, a, &merges) {
            if !plan.in_place.iter().any(|(x, _)| *x == a) {
                plan.in_place.push((a, payload));
            }
        } else {
            if !scheduled.contains(&pred) {
                return None;
            }
            plan.somes.push((m, pred, arm, payload));
        }
    }
    // Each merge but the returned one, and each `2`, is read only on the
    // way to the return.
    for &m in &plan.merges[1..] {
        if !read_only_by(func, m, &merges) {
            return None;
        }
    }
    for &n in &plan.nones {
        if !read_only_by(func, n, &merges) {
            return None;
        }
    }
    if !read_only_by(func, r, &merges) {
        return None;
    }
    // Every `Some` edge must be found in the region, where it is carried.
    let expected: HashMap<(ValueId, BlockId), ValueId> =
        plan.somes.iter().map(|(m, p, v, _)| ((*m, *p), *v)).collect();
    let mut found = 0;
    let mut probe = func.region.clone();
    retarget(&mut probe, &mut None, &expected, &HashMap::new(), &mut found);
    (found >= plan.somes.len()).then_some(plan)
}

/// Every block the region tree schedules.
fn scheduled_blocks(func: &HighFunction) -> HashSet<BlockId> {
    let mut blocks = HashSet::new();
    func.region.for_each_node(|node| {
        if let Region::Basic(b) = node {
            blocks.insert(*b);
        }
    });
    blocks
}

/// Nothing reads `v` but the merges in `merges`, the return, and the edges
/// into those merges. Pruning residue left unscheduled is not a reader; a
/// merge is, scheduled or not.
fn read_only_by(func: &HighFunction, v: ValueId, merges: &HashSet<ValueId>) -> bool {
    let live: HashSet<ValueId> =
        scheduled_blocks(func).iter().filter_map(|b| func.blocks.get(*b)).flat_map(|b| b.bindings.iter().copied()).collect();
    for (id, b) in func.bindings.iter() {
        let phi = matches!(b.expr, Expr::Phi { .. });
        if merges.contains(&id) || !(live.contains(&id) || phi) {
            continue;
        }
        let mut reads = false;
        b.expr.for_each_value_use(|u| reads |= resolve_use(func, u) == v);
        if reads {
            return false;
        }
    }
    let mut ok = true;
    func.region.for_each_node(|node| match node {
        Region::If { cond, .. } => ok &= resolve_use(func, *cond) != v,
        Region::Switch { index, .. } => ok &= resolve_use(func, *index) != v,
        Region::Break { transfer, .. } | Region::Continue { transfer, .. } | Region::Transfer { transfer, .. } => {
            ok &= transfer.iter().all(|(dest, src)| resolve_use(func, *src) != v || merges.contains(dest));
        }
        _ => {}
    });
    ok
}

fn apply(func: &mut HighFunction, option: &KnownType, plan: Plan) {
    let ty = IrType::Inferred(option.clone());
    for n in &plan.nones {
        if let Some(b) = func.bindings.get_mut(*n) {
            b.expr = Expr::Optional { payload: None };
            b.ty = IrType::Known(option.clone());
            b.add_provenance(Provenance::new(
                PASS_NAME,
                ProvenanceSource::SdkPattern,
                "`Void` merged into an `Option` the spec returns is `None`",
            ));
        }
    }
    for (a, payload) in &plan.in_place {
        if let Some(b) = func.bindings.get_mut(*a) {
            b.expr = Expr::Optional { payload: Some(vec![*payload]) };
            b.ty = ty.clone();
            b.add_provenance(Provenance::new(
                PASS_NAME,
                ProvenanceSource::SdkPattern,
                "the encode of a `T` returned as an `Option<T>` is its `Some`: the SDK encodes `Some(t)` as `t`'s `Val`",
            ));
        }
    }
    // One `Some(t)` per edge, built at the end of the block the edge leaves.
    let mut built: HashMap<(ValueId, BlockId), ValueId> = HashMap::new();
    for (m, pred, value, payload) in &plan.somes {
        let id = ValueId::from_index(func.bindings.len() as u32);
        func.bindings.push(Binding::new(
            id,
            ty.clone(),
            Expr::Optional { payload: Some(vec![*payload]) },
            Provenance::new(
                PASS_NAME,
                ProvenanceSource::SdkPattern,
                "a `T` merged into an `Option<T>` the spec returns is its `Some`: the SDK encodes `Some(t)` as `t`'s `Val`",
            ),
        ));
        if let Some(block) = func.blocks.get_mut(*pred) {
            block.bindings.push(id);
        }
        built.insert((*m, *pred), id);
        if let Some(Binding { expr: Expr::Phi { incoming }, .. }) = func.bindings.get_mut(*m) {
            for (p, v) in incoming.iter_mut() {
                if p == pred && v == value {
                    *v = id;
                }
            }
        }
    }
    let expected: HashMap<(ValueId, BlockId), ValueId> =
        plan.somes.iter().map(|(m, p, v, _)| ((*m, *p), *v)).collect();
    let mut found = 0;
    retarget(&mut func.region, &mut None, &expected, &built, &mut found);
    for m in &plan.merges {
        if let Some(b) = func.bindings.get_mut(*m)
            && !matches!(&b.ty, IrType::Known(KnownType::Option(_)) | IrType::Inferred(KnownType::Option(_)))
        {
            b.ty = ty.clone();
            b.add_provenance(Provenance::new(PASS_NAME, ProvenanceSource::SdkPattern, "the `Option` the spec returns"));
        }
    }
}

/// Rewrite each edge into a merge from the block it leaves, as `built`
/// says, counting the edges `expected` names. `last` is the block the walk
/// most recently left, which is the edge's predecessor at a transfer.
fn retarget(
    region: &mut Region,
    last: &mut Option<BlockId>,
    expected: &HashMap<(ValueId, BlockId), ValueId>,
    built: &HashMap<(ValueId, BlockId), ValueId>,
    found: &mut usize,
) {
    match region {
        Region::Basic(b) => *last = Some(*b),
        Region::Sequence(items) => {
            for item in items {
                retarget(item, last, expected, built, found);
            }
        }
        Region::Scope { body, .. } | Region::Loop { body, .. } => {
            retarget(body, last, expected, built, found);
            *last = None;
        }
        Region::If { then_region, else_region, .. } => {
            let entry = *last;
            retarget(then_region, last, expected, built, found);
            *last = entry;
            if let Some(e) = else_region {
                retarget(e, last, expected, built, found);
            }
            *last = None;
        }
        Region::Switch { arms, default, .. } => {
            let entry = *last;
            retarget(default, last, expected, built, found);
            for arm in arms {
                *last = entry;
                retarget(&mut arm.body, last, expected, built, found);
            }
            *last = None;
        }
        Region::Break { transfer, .. } | Region::Continue { transfer, .. } | Region::Transfer { transfer, .. } => {
            let Some(pred) = *last else { return };
            for (dest, src) in transfer.iter_mut() {
                if expected.get(&(*dest, pred)) == Some(src) {
                    *found += 1;
                    if let Some(new) = built.get(&(*dest, pred)) {
                        *src = *new;
                    }
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, module, v};

    use sordec_ir::{CompositeType, FunctionSignature, PrimitiveType, TypeRef};

    /// `if c { r = s } else { r = 2 }; return r` from a function declared
    /// `-> out`, `s` typed `Symbol`. bb0 holds `c` and `s`, bb1 the `2`.
    fn shape(out: TypeRef) -> HighIr {
        let (b0, b1) = (BlockId::from_index(0), BlockId::from_index(1));
        let mut f = func_with(
            vec![
                Expr::Phi { incoming: vec![] },                           // v0: c
                Expr::Phi { incoming: vec![] },                           // v1: s
                Expr::Literal(Literal::I64(2)),                           // v2
                Expr::Phi { incoming: vec![(b0, v(1)), (b1, v(2))] },     // v3: r
            ],
            vec![v(0), v(1)],
            vec![],
        );
        f.bindings.get_mut(v(1)).unwrap().ty = IrType::Inferred(KnownType::Symbol);
        f.blocks.push(sordec_ir::HighBlock { id: b1, bindings: vec![v(2)] });
        f.region = Region::Sequence(vec![
            Region::Scope {
                out: BlockId::from_index(2),
                body: Box::new(Region::Sequence(vec![
                    Region::Basic(b0),
                    Region::If {
                        cond: v(0),
                        then_region: Box::new(Region::Transfer { target: BlockId::from_index(2), transfer: vec![(v(3), v(1))] }),
                        else_region: Some(Box::new(Region::Sequence(vec![
                            Region::Basic(b1),
                            Region::Transfer { target: BlockId::from_index(2), transfer: vec![(v(3), v(2))] },
                        ]))),
                    },
                ])),
            },
            Region::Return { values: vec![v(3)] },
        ]);
        f.signature = Some(FunctionSignature { name: "get".into(), inputs: vec![], outputs: vec![out] });
        module(vec![f])
    }

    fn option_of(p: PrimitiveType) -> TypeRef {
        TypeRef::Composite(CompositeType::Option(Box::new(TypeRef::Primitive(p))))
    }

    #[test]
    fn the_arms_of_a_returned_option_are_none_and_some() {
        let mut ir = shape(option_of(PrimitiveType::Symbol));
        assert!(OptionReturnPass.run(&mut ir).changed);
        let f = &ir.functions[0];
        assert!(matches!(f.bindings.get(v(2)).unwrap().expr, Expr::Optional { payload: None }));
        let Expr::Phi { incoming } = &f.bindings.get(v(3)).unwrap().expr else { unreachable!() };
        let some = incoming[0].1;
        assert!(matches!(&f.bindings.get(some).unwrap().expr, Expr::Optional { payload: Some(p) } if p == &vec![v(1)]));
        assert!(f.blocks.get(BlockId::from_index(0)).unwrap().bindings.contains(&some));
        let mut carried = false;
        f.region.for_each_node(|n| {
            if let Region::Transfer { transfer, .. } = n {
                carried |= transfer.contains(&(v(3), some));
            }
        });
        assert!(carried, "the edge carries the `Some`");
        assert!(!OptionReturnPass.run(&mut ir).changed, "idempotent");
    }

    /// The `Symbol` arm replaced by `val_encode<u64>(x)` from a function
    /// declared `-> Option<u64>`.
    fn encoded_arm() -> HighIr {
        let mut ir = shape(option_of(PrimitiveType::U64));
        let f = &mut ir.functions[0];
        let x = ValueId::from_index(f.bindings.len() as u32);
        f.bindings.push(Binding::new(
            x,
            IrType::Known(KnownType::U64),
            Expr::Phi { incoming: vec![] },
            Provenance::new("seed", ProvenanceSource::DataFlow, "seed"),
        ));
        f.params.push(x);
        f.bindings.get_mut(v(1)).unwrap().expr =
            Expr::Semantic(sordec_ir::SemanticOp::Known(sordec_ir::KnownOp::ValEncodeSmall { ty: KnownType::U64, value: x }));
        f.bindings.get_mut(v(1)).unwrap().ty = IrType::Inferred(KnownType::Val);
        f.params.retain(|p| *p != v(1));
        f.blocks.get_mut(BlockId::from_index(0)).unwrap().bindings.push(v(1));
        ir
    }

    #[test]
    fn an_encoded_arm_is_some_of_what_it_encodes() {
        let mut ir = encoded_arm();
        assert!(OptionReturnPass.run(&mut ir).changed);
        let f = &ir.functions[0];
        let x = *f.params.last().unwrap();
        assert!(matches!(&f.bindings.get(v(1)).unwrap().expr, Expr::Optional { payload: Some(p) } if p == &vec![x]));
    }

    #[test]
    fn an_encoded_arm_also_stored_keeps_its_val() {
        let mut ir = encoded_arm();
        let f = &mut ir.functions[0];
        let store = ValueId::from_index(f.bindings.len() as u32);
        f.bindings.push(Binding::new(
            store,
            IrType::Unknown(sordec_common::UnknownReason::InsufficientEvidence),
            crate::marshalling::test_support::store(v(0), v(1), 8),
            Provenance::new("seed", ProvenanceSource::DataFlow, "seed"),
        ));
        f.blocks.get_mut(BlockId::from_index(0)).unwrap().bindings.push(store);
        assert!(OptionReturnPass.run(&mut ir).changed);
        let f = &ir.functions[0];
        assert!(matches!(f.bindings.get(v(1)).unwrap().expr, Expr::Semantic(_)), "the stored Val stays");
        let Expr::Phi { incoming } = &f.bindings.get(v(3)).unwrap().expr else { unreachable!() };
        assert!(matches!(&f.bindings.get(incoming[0].1).unwrap().expr, Expr::Optional { payload: Some(_) }));
    }

    #[test]
    fn another_return_type_is_left_alone() {
        let mut ir = shape(TypeRef::Primitive(PrimitiveType::Symbol));
        assert!(!OptionReturnPass.run(&mut ir).changed);
    }

    #[test]
    fn an_arm_of_another_type_leaves_the_return_alone() {
        // `Option<u32>`: the `Symbol` arm is not a `T`.
        let mut ir = shape(option_of(PrimitiveType::U32));
        assert!(!OptionReturnPass.run(&mut ir).changed);
        assert!(matches!(ir.functions[0].bindings.get(v(2)).unwrap().expr, Expr::Literal(Literal::I64(2))));
    }

    #[test]
    fn a_void_read_elsewhere_is_left_alone() {
        let mut ir = shape(option_of(PrimitiveType::Symbol));
        let f = &mut ir.functions[0];
        f.bindings.get_mut(v(0)).unwrap().expr = Expr::Phi { incoming: vec![(BlockId::from_index(1), v(2))] };
        assert!(!OptionReturnPass.run(&mut ir).changed);
    }
}
