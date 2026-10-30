//! An `Option` parameter tested against `Void` is tested for `None`.
//!
//! # The shape
//!
//! `pub fn option(e: Env, option: Option<u32>) -> Option<u32> { option }`
//! decodes its argument and encodes it again. An `Option` travels as its
//! payload's `Val`, or as `Void` (tag 2, body 0 — the whole `Val` is `2`)
//! for `None`, so both directions test and produce that constant:
//!
//! ```text
//! if option == 2 { return 2 }        if !option.is_some() { return None }
//! …payload tag check…           →    …
//! return option                      return option
//! ```
//!
//! The decode collapse ([`super::decode`]) has already named the parameter
//! and typed it `Option<u32>`, so left alone the test compares an `Option`
//! with an `i64` and the early return hands back an `i64` for one.
//!
//! # Why it is exact
//!
//! `Void` is the encoding of `None` and of nothing else an `Option<T>` can
//! hold — no `T` encodes to it — so equality with it is `is_none()`. And a
//! function declared to return an `Option` returning `Void` returns `None`.
//!
//! # Gates
//!
//! - **The parameter's type is the spec's.** An entrypoint parameter
//!   declared `Option<T>`.
//! - **A returned `2` only where the spec returns an `Option`**, and only
//!   when every use of that constant is a return.
//!
//! # A struct field built as `Void` or an encode
//!
//! The same encoding going into a `#[contracttype]` field: a field
//! declared `Option<u64>` is filled from a merge whose arms are the `Void`
//! word and the encode of a `u64` (often through the helper rustc outlines
//! the encode into):
//!
//! ```text
//! if t.is_none() { f = 2 }                 if t.is_none() { g = None }
//! else { f = encode::<u64>(x) }      →     else { g = Some(x) }
//! S { time_limit: f }                      S { time_limit: g }
//! ```
//!
//! The literal's field becomes a new merge with `None` on each `Void` arm
//! and `Some(x)` on each encode arm. The old merge stays for any other
//! reader (the derive's slot store).
//!
//! Why it is exact: the SDK encodes `None` as `Void` and `Some(x)` as the
//! encode of `x`, so on every edge the old merge is the encoding of the new
//! one, and a field declared `Option<T>` holds the value whose encoding the
//! derive writes.
//!
//! Gates: the field is declared `Option<T>`; the merge is a phi whose every
//! arm is the `Void` word or an encode of a value as exactly `T` (an
//! outlined encode helper's component, or a small encode); at least one
//! arm is an encode; no two arms hand over the same value.
//!
//! # A parameter's payload, returned where it is present
//!
//! `match input { Some(v) => Ok(v), None => Err(e) }` hands the parameter's
//! own word to the return on the `Some` path: the SDK encodes `Some(v)` as
//! `v`'s `Val`, so nothing is unwrapped on wasm.
//!
//! ```text
//! if !input.is_some() { r = e }            if !input.is_some() { r = e }
//! else { r = input }               →       else { p = input.unwrap(); r = p }
//! return r                                 return r
//! ```
//!
//! Left alone, the merge typed `Result<Vec<u64>, Error>` is handed an
//! `Option<Vec<u64>>`. The edge now carries the payload, which the emitter
//! wraps in `Ok(..)` as it wraps any `Ok` payload.
//!
//! Why it is exact: on that edge the path has tested the parameter present,
//! so its word is the encoding of the payload, and the spec says the host
//! reads the returned word as `T` (or a `Result`'s `Ok` of `T`): the same
//! word either way. The `unwrap()` is placed in a block that runs only
//! where the test holds, so it never traps.
//!
//! Gates: an entrypoint whose one output is `T` or `Result<T, E>`; the
//! parameter is declared `Option<T>` with the same `T`, not a type that can
//! itself encode to `Void`; the edge's block is reached only through the
//! branch of an `is_some()` test of that parameter that holds (through
//! `!`); the merges on the way are read by nothing but the return and each
//! other; every such edge is found in the region tree, or none is
//! rewritten.

use std::collections::{HashMap, HashSet};

use sordec_common::{BlockId, IrId, Provenance, ProvenanceSource, ValueId};
use sordec_ir::{
    BinaryOp, Binding, Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, Literal, Region, SemanticOp,
    StructDef, UnaryOp,
};

use super::encode_helper::EncoderTable;

use crate::dataflow::resolve_use;
use crate::metrics_catalog::MARSHALLING_OPTION_PARAMS as M_OPTION;
use crate::pass::{Pass, PassResult};
use crate::type_infer::known_of_type_ref;
use crate::val_abi::TAG_VOID;

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-option-param";

/// Folds `Void` tests of an `Option` parameter, and `Void` returned as one.
#[derive(Debug, Default, Clone, Copy)]
pub struct OptionParamPass;

impl Pass<HighIr> for OptionParamPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let structs: Vec<StructDef> =
            ir.soroban_facts.as_ref().map(|f| f.types.structs.clone()).unwrap_or_default();
        let encoders = if structs.is_empty() { EncoderTable::default() } else { EncoderTable::build(ir) };
        for func in &mut ir.functions {
            let fields = option_fields(func, &structs, &encoders);
            for field in &fields {
                apply_field(func, field);
            }
            let tests = tests(func);
            let nones = returned_nones(func);
            let count = tests.len() + nones.len() + fields.len();
            for (id, expr) in tests {
                rewrite(func, id, expr, IrType::Inferred(KnownType::Bool), "an `Option` compared with `Void` is tested for `None`");
            }
            for (id, ty) in nones {
                rewrite(func, id, Expr::Optional { payload: None }, ty, "`Void` returned as an `Option` is `None`");
            }
            // After the tests above: they are what proves a path present.
            let payloads = payload_edges(func);
            let count = count + payloads.len();
            apply_payloads(func, payloads);
            if count > 0 {
                result.metrics.increment(M_OPTION, count as i64);
                result.changed = true;
            }
        }
        result
    }
}

fn rewrite(func: &mut HighFunction, id: ValueId, expr: Expr, ty: IrType, note: &'static str) {
    if let Some(b) = func.bindings.get_mut(id) {
        b.expr = expr;
        b.ty = ty;
        b.add_provenance(Provenance::new(PASS_NAME, ProvenanceSource::SdkPattern, note));
    }
}

/// `p == Void` and `p != Void` for an `Option` parameter `p`, as the
/// bindings to rewrite. `!=` is `p.is_some()` in place. `==` needs the
/// `is_some()` as an operand of its `!`, and takes the `Void` literal's
/// binding for it — only when the comparison is that literal's one reader.
fn tests(func: &HighFunction) -> Vec<(ValueId, Expr)> {
    let returned = returned_values(func);
    let mut out = Vec::new();
    for (id, b) in func.bindings.iter() {
        let Expr::Binary { op: op @ (BinaryOp::Eq | BinaryOp::Ne), lhs, rhs } = &b.expr else {
            continue;
        };
        let (l, r) = (resolve_use(func, *lhs), resolve_use(func, *rhs));
        let (value, void) = if is_void(func, r) && is_option_param(func, l) {
            (l, r)
        } else if is_void(func, l) && is_option_param(func, r) {
            (r, l)
        } else {
            continue;
        };
        if *op == BinaryOp::Ne {
            out.push((id, Expr::IsSome { value }));
        } else if readers(func, void) == 1 && !returned.contains(&void) {
            out.push((void, Expr::IsSome { value }));
            out.push((id, Expr::Unary { op: UnaryOp::Not, value: void }));
        }
    }
    out
}

/// Every value a `return` in the structured body hands back.
fn returned_values(func: &HighFunction) -> Vec<ValueId> {
    let mut values = Vec::new();
    func.region.for_each_node(|node| {
        if let Region::Return { values: returned } = node {
            values.extend(returned.iter().map(|v| resolve_use(func, *v)));
        }
    });
    values
}

/// How many bindings the body still executes read `v`. Pruning residue
/// left unscheduled in the arena is not a reader; a phi is, scheduled or
/// not — the `Void` flowing into one is a number there, not this `None`.
fn readers(func: &HighFunction, v: ValueId) -> usize {
    let scheduled: std::collections::HashSet<ValueId> =
        func.blocks.iter().flat_map(|(_, b)| b.bindings.iter().copied()).collect();
    func.bindings
        .iter()
        .filter(|(id, b)| {
            if !scheduled.contains(id) && !matches!(b.expr, Expr::Phi { .. }) {
                return false;
            }
            let mut reads = false;
            b.expr.for_each_value_use(|u| reads |= resolve_use(func, u) == v);
            reads
        })
        .count()
}

/// Literal `Void` bindings used only by return sites of a function whose
/// spec returns an `Option`, with that `Option`'s type.
fn returned_nones(func: &HighFunction) -> Vec<(ValueId, IrType)> {
    let Some(sig) = &func.signature else {
        return Vec::new();
    };
    let [out] = sig.outputs.as_slice() else {
        return Vec::new();
    };
    let Some(ty @ KnownType::Option(_)) = known_of_type_ref(out) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for v in returned_values(func) {
        if out.iter().any(|(o, _)| *o == v) || !is_void(func, v) {
            continue;
        }
        // Read anywhere but a return, it is the number, not the `None`.
        if readers(func, v) == 0 {
            out.push((v, IrType::Known(ty.clone())));
        }
    }
    out
}

/// A struct literal's field built as `Void` or an encode ("A struct field
/// built as `Void` or an encode").
struct FieldOption {
    literal: ValueId,
    index: usize,
    merge: ValueId,
    /// Each edge into the merge: its block, the value it hands over, and
    /// the payload when that value is an encode.
    arms: Vec<(BlockId, ValueId, Option<ValueId>)>,
    ty: IrType,
}

fn option_fields(func: &HighFunction, structs: &[StructDef], encoders: &EncoderTable) -> Vec<FieldOption> {
    let mut out = Vec::new();
    for (id, b) in func.bindings.iter() {
        let Expr::Struct { fields } = &b.expr else { continue };
        let (IrType::Known(KnownType::UserDefined(ty)) | IrType::Inferred(KnownType::UserDefined(ty))) = &b.ty else {
            continue;
        };
        let Some(def) = structs.iter().find(|s| s.id == *ty) else { continue };
        for (index, (name, value)) in fields.iter().enumerate() {
            let Some(KnownType::Option(inner)) =
                def.fields.iter().find(|f| f.name == *name).and_then(|f| known_of_type_ref(&f.ty))
            else {
                continue;
            };
            let (IrType::Known(payload) | IrType::Inferred(payload)) = inner.as_ref() else { continue };
            let merge = resolve_use(func, *value);
            let Some(Expr::Phi { incoming }) = func.bindings.get(merge).map(|b| &b.expr) else { continue };
            let mut arms = Vec::with_capacity(incoming.len());
            for (block, arm) in incoming {
                let encoded = if is_void(func, resolve_use(func, *arm)) {
                    None
                } else if let Some(x) = encode_of(func, *arm, payload, encoders) {
                    Some(x)
                } else {
                    arms.clear();
                    break;
                };
                arms.push((*block, *arm, encoded));
            }
            let distinct = arms.iter().all(|(_, a, _)| arms.iter().filter(|(_, b, _)| b == a).count() == 1);
            if arms.is_empty() || !distinct || arms.iter().all(|(_, _, x)| x.is_none()) {
                continue;
            }
            let ty = IrType::Inferred(KnownType::Option(Box::new(IrType::Inferred(payload.clone()))));
            out.push(FieldOption { literal: id, index, merge, arms, ty });
        }
    }
    out
}

/// An edge into a returned merge that hands over an `Option` parameter
/// where the path proves it present ("A parameter's payload, returned
/// where it is present").
struct PayloadEdge {
    merge: ValueId,
    pred: BlockId,
    /// The value the edge hands over now: the parameter, or a rename.
    arm: ValueId,
    param: ValueId,
    payload: KnownType,
}

/// Every such edge, or none when one the plan names is not in the region.
fn payload_edges(func: &HighFunction) -> Vec<PayloadEdge> {
    let Some(sig) = &func.signature else { return Vec::new() };
    let [out] = sig.outputs.as_slice() else { return Vec::new() };
    let known = |t: &IrType| match t {
        IrType::Known(k) | IrType::Inferred(k) => Some(k.clone()),
        IrType::Unknown(_) => None,
    };
    let declared = match known_of_type_ref(out) {
        Some(KnownType::Result(ok, _)) => known(&ok),
        other => other,
    };
    let Some(declared) = declared else { return Vec::new() };
    // `Option<T>` parameters with the declared `T`, which cannot be `Void`.
    let params: Vec<ValueId> = func
        .params
        .iter()
        .zip(&sig.inputs)
        .filter(|(_, input)| {
            matches!(known_of_type_ref(&input.ty), Some(KnownType::Option(inner))
                if known(&inner).is_some_and(|t| t == declared
                    && !matches!(t, KnownType::Val | KnownType::Unit | KnownType::Option(_))))
        })
        .map(|(p, _)| *p)
        .collect();
    if params.is_empty() {
        return Vec::new();
    }
    // The merges the return reads, through merges.
    let mut merges: Vec<ValueId> = Vec::new();
    let mut work: Vec<ValueId> = Vec::new();
    func.region.for_each_node(|node| {
        if let Region::Return { values } = node
            && let [one] = values.as_slice()
        {
            work.push(resolve_use(func, *one));
        }
    });
    while let Some(m) = work.pop() {
        let Some(Expr::Phi { incoming }) = func.bindings.get(m).map(|b| &b.expr) else { continue };
        if incoming.is_empty() || merges.contains(&m) {
            continue;
        }
        merges.push(m);
        work.extend(incoming.iter().map(|(_, a)| resolve_use(func, *a)));
    }
    let chain: HashSet<ValueId> = merges.iter().copied().collect();
    if merges.iter().any(|m| !super::option_return::read_only_by(func, *m, &chain)) {
        return Vec::new();
    }
    let present = present_at(func, &params);
    let mut edges = Vec::new();
    for &merge in &merges {
        let Some(Expr::Phi { incoming }) = func.bindings.get(merge).map(|b| &b.expr) else { continue };
        for &(pred, arm) in incoming {
            let param = resolve_use(func, arm);
            if present.get(&pred).is_some_and(|ps| ps.contains(&param)) {
                edges.push(PayloadEdge { merge, pred, arm, param, payload: declared.clone() });
            }
        }
    }
    // Every edge must be found where it is carried.
    let expected: HashMap<(ValueId, BlockId), ValueId> = edges.iter().map(|e| ((e.merge, e.pred), e.arm)).collect();
    let mut found = 0;
    let mut probe = func.region.clone();
    super::option_return::retarget(&mut probe, &mut None, &expected, &HashMap::new(), &mut found);
    if found < edges.len() {
        return Vec::new();
    }
    edges
}

/// The parameters each scheduled block runs only where present: the
/// block sits in the branch of an `is_some()` test of it that holds.
fn present_at(func: &HighFunction, params: &[ValueId]) -> HashMap<BlockId, Vec<ValueId>> {
    fn walk(
        func: &HighFunction,
        region: &Region,
        facts: &mut Vec<(ValueId, bool)>,
        params: &[ValueId],
        out: &mut HashMap<BlockId, Vec<ValueId>>,
    ) {
        match region {
            Region::Basic(b) => {
                let held: Vec<ValueId> = params
                    .iter()
                    .copied()
                    .filter(|p| facts.iter().any(|(c, holds)| proves_present(func, *c, *holds, *p, 0)))
                    .collect();
                out.insert(*b, held);
            }
            Region::Sequence(items) => items.iter().for_each(|r| walk(func, r, facts, params, out)),
            Region::Scope { body, .. } | Region::Loop { body, .. } => walk(func, body, facts, params, out),
            Region::If { cond, then_region, else_region } => {
                facts.push((*cond, true));
                walk(func, then_region, facts, params, out);
                facts.pop();
                if let Some(e) = else_region {
                    facts.push((*cond, false));
                    walk(func, e, facts, params, out);
                    facts.pop();
                }
            }
            Region::Switch { arms, default, .. } => {
                walk(func, default, facts, params, out);
                for arm in arms {
                    walk(func, &arm.body, facts, params, out);
                }
            }
            _ => {}
        }
    }
    let mut out = HashMap::new();
    walk(func, &func.region, &mut Vec::new(), params, &mut out);
    out
}

/// Whether `cond` evaluating to `holds` proves `param` present: it is
/// `param.is_some()`, or the negation of something that proves it the
/// other way round.
fn proves_present(func: &HighFunction, cond: ValueId, holds: bool, param: ValueId, depth: u32) -> bool {
    if depth > 4 {
        return false;
    }
    match func.bindings.get(resolve_use(func, cond)).map(|b| &b.expr) {
        Some(Expr::IsSome { value }) => holds && resolve_use(func, *value) == param,
        Some(Expr::Unary { op: UnaryOp::Not, value }) => proves_present(func, *value, !holds, param, depth + 1),
        _ => false,
    }
}

/// Each edge hands over `param.unwrap()`, built at the end of the block it
/// leaves.
fn apply_payloads(func: &mut HighFunction, edges: Vec<PayloadEdge>) {
    if edges.is_empty() {
        return;
    }
    let mut built: HashMap<(ValueId, BlockId), ValueId> = HashMap::new();
    let mut expected: HashMap<(ValueId, BlockId), ValueId> = HashMap::new();
    for e in &edges {
        let id = ValueId::from_index(func.bindings.len() as u32);
        func.bindings.push(Binding::new(
            id,
            IrType::Inferred(e.payload.clone()),
            Expr::Unwrap { value: e.param, index: 0, arity: 1 },
            Provenance::new(
                PASS_NAME,
                ProvenanceSource::SdkPattern,
                "an `Option` parameter handed to the return where it is tested present is its payload: the SDK encodes `Some(v)` as `v`'s `Val`",
            ),
        ));
        if let Some(block) = func.blocks.get_mut(e.pred) {
            block.bindings.push(id);
        }
        if let Some(Binding { expr: Expr::Phi { incoming }, .. }) = func.bindings.get_mut(e.merge) {
            for (p, v) in incoming.iter_mut() {
                if *p == e.pred && *v == e.arm {
                    *v = id;
                }
            }
        }
        built.insert((e.merge, e.pred), id);
        expected.insert((e.merge, e.pred), e.arm);
    }
    let mut found = 0;
    super::option_return::retarget(&mut func.region, &mut None, &expected, &built, &mut found);
}

/// The value `arm` encodes as exactly `payload`: an outlined encode
/// helper's component, or a small encode.
fn encode_of(func: &HighFunction, arm: ValueId, payload: &KnownType, encoders: &EncoderTable) -> Option<ValueId> {
    if let Some((x, ty)) = encoders.encoded_by_call(func, arm) {
        return (ty == *payload).then_some(x);
    }
    match &func.bindings.get(resolve_use(func, arm))?.expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty, value })) if ty == payload => {
            Some(resolve_use(func, *value))
        }
        _ => None,
    }
}

/// The new merge: `None` or `Some(x)` placed on each edge, handed over
/// beside the old merge's value, and read by the field.
fn apply_field(func: &mut HighFunction, field: &FieldOption) {
    let note = |what: &str| Provenance::new(PASS_NAME, ProvenanceSource::SdkPattern, what.to_string());
    let mut by_arm: HashMap<ValueId, ValueId> = HashMap::new();
    let mut incoming = Vec::with_capacity(field.arms.len());
    for (block, arm, payload) in &field.arms {
        let id = ValueId::from_index(func.bindings.len() as u32);
        let (expr, what) = match payload {
            None => (Expr::Optional { payload: None }, "`Void` going into an `Option` field is `None`"),
            Some(x) => (
                Expr::Optional { payload: Some(vec![*x]) },
                "the encode of `x` going into an `Option` field is `Some(x)`",
            ),
        };
        func.bindings.push(Binding::new(id, field.ty.clone(), expr, note(what)));
        if let Some(b) = func.blocks.get_mut(*block) {
            b.bindings.push(id);
        }
        by_arm.insert(*arm, id);
        incoming.push((*block, id));
    }
    let option = ValueId::from_index(func.bindings.len() as u32);
    func.bindings.push(Binding::new(
        option,
        field.ty.clone(),
        Expr::Phi { incoming },
        note("the `Option` whose encoding the field's merge is"),
    ));
    hand_over(&mut func.region, field.merge, option, &by_arm);
    if let Some(b) = func.bindings.get_mut(field.literal) {
        if let Expr::Struct { fields } = &mut b.expr {
            fields[field.index].1 = option;
        }
        b.add_provenance(note("an `Option` field built as `Void` or an encode is the `Option`"));
    }
}

/// Beside every edge's assignment to `merge`, assign the `Option` the
/// value handed over stands for.
fn hand_over(region: &mut Region, merge: ValueId, option: ValueId, by_arm: &HashMap<ValueId, ValueId>) {
    match region {
        Region::Sequence(items) => items.iter_mut().for_each(|r| hand_over(r, merge, option, by_arm)),
        Region::Scope { body, .. } | Region::Loop { body, .. } => hand_over(body, merge, option, by_arm),
        Region::If { then_region, else_region, .. } => {
            hand_over(then_region, merge, option, by_arm);
            if let Some(e) = else_region {
                hand_over(e, merge, option, by_arm);
            }
        }
        Region::Switch { arms, default, .. } => {
            hand_over(default, merge, option, by_arm);
            for arm in arms {
                hand_over(&mut arm.body, merge, option, by_arm);
            }
        }
        Region::Break { transfer, .. } | Region::Continue { transfer, .. } | Region::Transfer { transfer, .. } => {
            let added: Vec<(ValueId, ValueId)> = transfer
                .iter()
                .filter(|(phi, _)| *phi == merge)
                .filter_map(|(_, value)| by_arm.get(value).map(|o| (option, *o)))
                .collect();
            transfer.extend(added);
        }
        _ => {}
    }
}

fn is_void(func: &HighFunction, v: ValueId) -> bool {
    matches!(
        func.bindings.get(v).map(|b| &b.expr),
        Some(Expr::Literal(Literal::I64(n))) if *n == i64::from(TAG_VOID)
    )
}

/// An entrypoint parameter the spec declares `Option<T>`.
fn is_option_param(func: &HighFunction, v: ValueId) -> bool {
    let Some(sig) = &func.signature else {
        return false;
    };
    func.params
        .iter()
        .position(|p| *p == v)
        .and_then(|i| sig.inputs.get(i))
        .and_then(|input| known_of_type_ref(&input.ty))
        .is_some_and(|t| matches!(t, KnownType::Option(_)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, module, v};
    use sordec_ir::{CompositeType, FunctionParam, FunctionSignature, PrimitiveType, TypeRef};

    /// `option == 2` over a parameter declared `Option<u32>`, then a
    /// separate `2` returned from a function declared to return one.
    fn shape(op: BinaryOp) -> HighIr {
        let mut f = func_with(
            vec![
                Expr::Phi { incoming: vec![] },                     // v0: option
                Expr::Literal(Literal::I64(2)),                     // v1
                Expr::Binary { op, lhs: v(0), rhs: v(1) },          // v2
                Expr::Literal(Literal::I64(2)),                     // v3: returned
            ],
            vec![v(0)],
            vec![1, 2, 3],
        );
        let opt = TypeRef::Composite(CompositeType::Option(Box::new(TypeRef::Primitive(PrimitiveType::U32))));
        f.signature = Some(FunctionSignature {
            name: "option".into(),
            inputs: vec![FunctionParam { name: "option".into(), ty: opt.clone() }],
            outputs: vec![opt],
        });
        f.region = Region::Sequence(vec![
            Region::Return { values: vec![v(3)] },
            Region::Return { values: vec![v(0)] },
        ]);
        module(vec![f])
    }

    /// `S { t: f }`, `t` declared `Option<field>`, where `f` merges the
    /// `Void` word (from bb0) and `encode::<u32>(x)` (from bb1).
    fn field_shape(field: PrimitiveType) -> HighIr {
        use sordec_common::TypeId;
        use sordec_ir::{EnvCompatibility, HighBlock, SorobanFacts, StructField, TypeRegistry};
        let (b0, b1, b2) = (BlockId::from_index(0), BlockId::from_index(1), BlockId::from_index(2));
        let mut f = func_with(
            vec![
                Expr::Phi { incoming: vec![] },                                                     // v0 x
                Expr::Literal(Literal::I64(2)),                                                     // v1 Void
                Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty: KnownType::U32, value: v(0) })), // v2
                Expr::Phi { incoming: vec![(b0, v(1)), (b1, v(2))] },                              // v3 f
                Expr::Struct { fields: vec![("t".into(), v(3))] },                                 // v4
                Expr::Phi { incoming: vec![] },                                                     // v5 cond
            ],
            vec![v(0), v(5)],
            vec![1],
        );
        f.blocks.push(HighBlock { id: b1, bindings: vec![v(2)] });
        f.blocks.push(HighBlock { id: b2, bindings: vec![v(4)] });
        f.bindings.get_mut(v(4)).unwrap().ty = IrType::Known(KnownType::UserDefined(TypeId::new(9)));
        f.region = Region::Sequence(vec![
            Region::Basic(b0),
            Region::If {
                cond: v(5),
                then_region: Box::new(Region::Transfer { target: b2, transfer: vec![(v(3), v(1))] }),
                else_region: Some(Box::new(Region::Sequence(vec![
                    Region::Basic(b1),
                    Region::Transfer { target: b2, transfer: vec![(v(3), v(2))] },
                ]))),
            },
            Region::Basic(b2),
        ]);
        let mut ir = module(vec![f]);
        ir.soroban_facts = Some(SorobanFacts {
            functions: std::collections::BTreeMap::new(),
            types: TypeRegistry {
                structs: vec![StructDef {
                    id: TypeId::new(9),
                    name: "S".into(),
                    fields: vec![StructField {
                        name: "t".into(),
                        ty: TypeRef::Composite(CompositeType::Option(Box::new(TypeRef::Primitive(field)))),
                    }],
                }],
                ..Default::default()
            },
            contract_meta: std::collections::BTreeMap::new(),
            env_meta: EnvCompatibility::default(),
        });
        ir
    }

    /// The field is a new merge of `None` and `Some(x)`, handed over beside
    /// the old one on each edge.
    #[test]
    fn an_option_field_built_as_void_or_an_encode_is_none_or_some() {
        let mut ir = field_shape(PrimitiveType::U32);
        assert!(OptionParamPass.run(&mut ir).changed);
        let f = &ir.functions[0];
        let Expr::Struct { fields } = &f.bindings.get(v(4)).unwrap().expr else { panic!() };
        let option = fields[0].1;
        let Expr::Phi { incoming } = &f.bindings.get(option).unwrap().expr else { panic!("a merge") };
        let arm = |block: u32| incoming.iter().find(|(b, _)| *b == BlockId::from_index(block)).unwrap().1;
        assert!(matches!(f.bindings.get(arm(0)).unwrap().expr, Expr::Optional { payload: None }));
        assert!(matches!(&f.bindings.get(arm(1)).unwrap().expr, Expr::Optional { payload: Some(p) } if p == &vec![v(0)]));
        let mut handed = Vec::new();
        f.region.for_each_node(|n| {
            if let Region::Transfer { transfer, .. } = n {
                handed.extend(transfer.iter().filter(|(phi, _)| *phi == option).map(|(_, x)| *x));
            }
        });
        assert_eq!(handed, vec![arm(0), arm(1)], "each edge assigns the new merge too");
        assert!(matches!(f.bindings.get(v(3)).unwrap().expr, Expr::Phi { .. }), "the old merge stays");
    }

    /// An encode of another type than the field's payload is not that
    /// field's `Some`.
    #[test]
    fn an_encode_of_another_type_than_the_payload_is_left_alone() {
        let mut ir = field_shape(PrimitiveType::U64);
        assert!(!OptionParamPass.run(&mut ir).changed);
    }

    #[test]
    fn a_void_test_of_an_option_parameter_is_a_none_test() {
        let mut ir = shape(BinaryOp::Eq);
        assert!(OptionParamPass.run(&mut ir).changed);
        let f = &ir.functions[0];
        assert!(matches!(f.bindings.get(v(1)).unwrap().expr, Expr::IsSome { value } if value == v(0)));
        assert!(matches!(f.bindings.get(v(2)).unwrap().expr, Expr::Unary { op: UnaryOp::Not, value } if value == v(1)));
        assert!(matches!(f.bindings.get(v(3)).unwrap().expr, Expr::Optional { payload: None }));
    }

    #[test]
    fn a_not_void_test_is_is_some() {
        let mut ir = shape(BinaryOp::Ne);
        assert!(OptionParamPass.run(&mut ir).changed);
        let f = &ir.functions[0];
        assert!(matches!(f.bindings.get(v(2)).unwrap().expr, Expr::IsSome { value } if value == v(0)));
        assert!(matches!(f.bindings.get(v(1)).unwrap().expr, Expr::Literal(_)), "the literal is left alone");
    }

    #[test]
    fn a_void_a_phi_also_reads_is_left_alone() {
        // Both `2`s flow into a phi as well: there they are numbers.
        let mut ir = shape(BinaryOp::Eq);
        let f = &mut ir.functions[0];
        let phi = ValueId::from_index(f.bindings.len() as u32);
        f.bindings.push(sordec_ir::Binding::new(
            phi,
            IrType::Inferred(KnownType::I64),
            Expr::Phi { incoming: vec![(BlockId::from_index(0), v(1)), (BlockId::from_index(1), v(3))] },
            Provenance::new("seed", ProvenanceSource::DataFlow, "seed"),
        ));
        OptionParamPass.run(&mut ir);
        let f = &ir.functions[0];
        assert!(matches!(f.bindings.get(v(1)).unwrap().expr, Expr::Literal(_)));
        assert!(matches!(f.bindings.get(v(2)).unwrap().expr, Expr::Binary { .. }));
        assert!(matches!(f.bindings.get(v(3)).unwrap().expr, Expr::Literal(_)));
    }

    #[test]
    fn a_parameter_declared_otherwise_is_left_alone() {
        let mut ir = shape(BinaryOp::Eq);
        let sig = ir.functions[0].signature.as_mut().unwrap();
        sig.inputs[0].ty = TypeRef::Primitive(PrimitiveType::U32);
        sig.outputs[0] = TypeRef::Primitive(PrimitiveType::U32);
        assert!(!OptionParamPass.run(&mut ir).changed);
    }

    /// `if !input.is_some() { r = err } else { r = input }; return r`,
    /// `input: Option<u64>`, declared `-> Result<u64, Error>`. With
    /// `swapped`, the parameter is handed over on the `None` side instead.
    fn payload_shape(swapped: bool) -> HighIr {
        use sordec_ir::HighBlock;
        let (b0, b1, out) = (BlockId::from_index(0), BlockId::from_index(1), BlockId::from_index(2));
        let mut f = func_with(
            vec![
                Expr::Phi { incoming: vec![] },                            // v0: input
                Expr::IsSome { value: v(0) },                              // v1
                Expr::Unary { op: UnaryOp::Not, value: v(1) },             // v2
                Expr::Literal(Literal::I64((1 << 32) | 3)),                // v3: an error
                Expr::Phi { incoming: vec![(b0, v(3)), (b1, v(0))] },     // v4: r
            ],
            vec![v(0)],
            vec![1, 2, 3],
        );
        f.blocks.push(HighBlock { id: b1, bindings: vec![] });
        let to_r = |value: ValueId| Region::Transfer { target: out, transfer: vec![(v(4), value)] };
        let (then_value, else_value) = if swapped { (v(0), v(3)) } else { (v(3), v(0)) };
        if swapped {
            f.bindings.get_mut(v(4)).unwrap().expr = Expr::Phi { incoming: vec![(b0, v(0)), (b1, v(3))] };
        }
        f.region = Region::Sequence(vec![
            Region::Scope {
                out,
                body: Box::new(Region::Sequence(vec![
                    Region::Basic(b0),
                    Region::If {
                        cond: v(2),
                        then_region: Box::new(to_r(then_value)),
                        else_region: Some(Box::new(Region::Sequence(vec![Region::Basic(b1), to_r(else_value)]))),
                    },
                ])),
            },
            Region::Return { values: vec![v(4)] },
        ]);
        f.signature = Some(FunctionSignature {
            name: "double_wrapped".into(),
            inputs: vec![FunctionParam {
                name: "input".into(),
                ty: TypeRef::Composite(CompositeType::Option(Box::new(TypeRef::Primitive(PrimitiveType::U64)))),
            }],
            outputs: vec![TypeRef::Composite(CompositeType::Result(
                Box::new(TypeRef::Primitive(PrimitiveType::U64)),
                Box::new(TypeRef::Primitive(PrimitiveType::Error)),
            ))],
        });
        module(vec![f])
    }

    #[test]
    fn a_parameter_handed_over_where_present_is_its_payload() {
        let mut ir = payload_shape(false);
        assert!(OptionParamPass.run(&mut ir).changed);
        let f = &ir.functions[0];
        let Expr::Phi { incoming } = &f.bindings.get(v(4)).unwrap().expr else { unreachable!() };
        let (pred, payload) = incoming[1];
        assert!(matches!(f.bindings.get(payload).unwrap().expr, Expr::Unwrap { value, index: 0, arity: 1 } if value == v(0)));
        assert!(f.blocks.get(pred).unwrap().bindings.contains(&payload), "built in the block the edge leaves");
        let mut carried = false;
        f.region.for_each_node(|n| {
            if let Region::Transfer { transfer, .. } = n {
                carried |= transfer.contains(&(v(4), payload));
            }
        });
        assert!(carried);
        assert_eq!(incoming[0].1, v(3), "the error arm is left to the Result");
        assert!(!OptionParamPass.run(&mut ir).changed, "idempotent");
    }

    #[test]
    fn a_parameter_handed_over_where_absent_is_left_alone() {
        let mut ir = payload_shape(true);
        assert!(!OptionParamPass.run(&mut ir).changed);
        let Expr::Phi { incoming } = &ir.functions[0].bindings.get(v(4)).unwrap().expr else { unreachable!() };
        assert_eq!(incoming[0].1, v(0));
    }
}
