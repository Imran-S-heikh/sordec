//! Recover `Event { … }.publish(&e)` from the helper `#[contractevent]`
//! generates.
//!
//! # The shape
//!
//! ```rust,ignore
//! Transfer { from, to, to_muxed_id: to_muxed.id(), amount }.publish(&e);
//! ```
//!
//! builds the struct in the caller's frame and hands the helper a pointer
//! to it. The helper reads each field back, builds the topics vec from
//! the event's prefix symbols and its `#[topic]` fields, encodes the rest
//! as the data, and calls the host:
//!
//! ```text
//! caller:  store f+32 <- from; store f+40 <- to; store f+16/+24 <- amount
//!          store f+0 <- is_some; store f+8 <- id
//!          func38(f)
//! helper:  topics = vec[symbol("transfer"), load p+32, load p+40]
//!          data   = map{ amount: wide(load p+16, load p+24), to_muxed_id: … }
//!          publish_event(topics, data)
//! ```
//!
//! Left alone, the caller prints six stores into memory and a call, and the
//! helper prints the `Option` encode and a map built from raw pointers —
//! neither of which compiles, and none of which the author wrote.
//!
//! # How a field is located
//!
//! The spec declares the event: its name, prefix topics, and each field's
//! type and whether it is a topic. The helper says where each field sits:
//!
//! - a **topic** field is the word the helper puts in that topic position,
//!   read straight from the struct — position is the evidence;
//! - a **data** field is matched by its *shape* among the remaining reads
//!   of the struct: an `i128` is two words joined, an `Option<u64>` a
//!   discriminant beside a word, anything else one word. Only where each
//!   shape occurs once: two data fields of one shape cannot be told apart
//!   by shape, and that event is left alone.
//!
//! The struct's layout is rustc's choice (it reorders fields), so it is
//! read off the helper rather than computed.
//!
//! # The call sites
//!
//! Each field's value is what the caller stored at its offset. An `i128`
//! is the value whose two halves were stored; an `Option<u64>` is `None`
//! when the discriminant stored is the constant `0`, and `to_muxed.id()`
//! when the pair is the inlined `MuxedAddress::id()` — which is then
//! removed with its branch, being the same call.

use std::collections::{BTreeMap, HashMap, HashSet};

use sordec_common::{FuncId, IrId, Provenance, ProvenanceSource, ValueId};
use sordec_ir::{
    AddressOpKind, Binding, EventDef, EventParamLocation, Expr, HighFunction, HighIr, IrType,
    KnownOp, KnownType, Literal, MemWidth, PrimitiveType, Region, SemanticOp, TypeRef, UnaryOp,
};

use super::muxed_address::{is_two_tag_check, sole_transfer, tag_dispatch};
use super::sret::emission_order;
use crate::dataflow::{block_containing, resolve_use};
use crate::effects::expr_effects;
use crate::pass::{Pass, PassResult};
use crate::val_abi::decode_small_symbol;

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-contract-event";

/// Generated publish helpers identified, with their event.
const M_HELPERS: &str = "marshalling_contract_event_helpers";
/// Call sites rewritten as `Event { … }.publish(&e)`.
const M_RECOVERED: &str = "marshalling_contract_events_recovered";
/// Call sites of an identified helper whose stores did not line up.
const M_SITE_DECLINED: &str = "marshalling_contract_event_sites_declined";
/// Inlined `MuxedAddress::id()` branches folded into the field value.
const M_MUXED_ID: &str = "marshalling_contract_event_muxed_ids";

/// Recovers `#[contractevent]` publishes from their generated helper.
#[derive(Debug, Default, Clone, Copy)]
pub struct ContractEventPass;

/// How a field occupies the struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// One 8-byte word.
    Word,
    /// Two words, low then high.
    Wide,
    /// A discriminant, then the payload word 8 bytes on.
    OptionWord,
}

/// Where a helper's event keeps each field: declaration order.
#[derive(Debug, Clone)]
struct Layout {
    event: String,
    fields: Vec<(String, u32, Shape)>,
}

impl Pass<HighIr> for ContractEventPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let Some(events) = ir.soroban_facts.as_ref().map(|f| f.types.events.clone()) else {
            return result;
        };
        if events.is_empty() {
            return result;
        }
        let layouts: HashMap<FuncId, Layout> = ir
            .functions
            .iter()
            .filter_map(|h| Some((h.id, helper_layout(ir, h, &events)?)))
            .collect();
        if layouts.is_empty() {
            return result;
        }
        result.metrics.increment(M_HELPERS, layouts.len() as i64);
        for func in &mut ir.functions {
            let sites: Vec<(ValueId, FuncId)> = emission_order(func)
                .into_iter()
                .filter_map(|id| match &func.bindings.get(id)?.expr {
                    Expr::Call { target, args } if args.len() == 1 && layouts.contains_key(target) => {
                        Some((id, *target))
                    }
                    _ => None,
                })
                .collect();
            for (call, target) in sites {
                let layout = &layouts[&target];
                match plan_site(func, call, layout) {
                    Some(plan) => {
                        if plan.muxed.is_some() {
                            result.metrics.increment(M_MUXED_ID, 1);
                        }
                        apply(func, call, layout, plan);
                        result.metrics.increment(M_RECOVERED, 1);
                        result.changed = true;
                    }
                    None => result.metrics.increment(M_SITE_DECLINED, 1),
                }
            }
        }
        result
    }
}

// ---------------------------------------------------------------------
// The helper
// ---------------------------------------------------------------------

/// The event a helper publishes and where it reads each field from, when
/// the helper is exactly one event's generated publish.
fn helper_layout(ir: &HighIr, h: &HighFunction, events: &[EventDef]) -> Option<Layout> {
    let [p] = h.params[..] else {
        return None;
    };
    let order = emission_order(h);
    let mut publish = None;
    for &id in &order {
        if let Expr::Semantic(SemanticOp::Known(KnownOp::PublishEvent { topics, data })) =
            &h.bindings.get(id)?.expr
            && publish.replace((*topics, *data)).is_some()
        {
            return None;
        }
    }
    let (topic_vec, _data) = publish?;
    let (topic_values, builder) = topic_elements(ir, h, topic_vec)?;

    // Nothing else with a host effect: the helper publishes, and builds
    // the topics vec to publish.
    for &id in &order {
        let b = h.bindings.get(id)?;
        if !expr_effects(&b.expr).writes_host {
            continue;
        }
        let is_publish = matches!(b.expr, Expr::Semantic(SemanticOp::Known(KnownOp::PublishEvent { .. })));
        let is_builder = builder.is_some_and(|c| c == id);
        if !is_publish && !is_builder {
            return None;
        }
    }

    // Every read of the struct, by offset.
    let mut loads: BTreeMap<u32, (ValueId, MemWidth)> = BTreeMap::new();
    for (id, b) in h.bindings.iter() {
        if let Expr::Load { addr, offset, width, .. } = &b.expr
            && resolve_use(h, *addr) == p
            && order.contains(&id)
            && loads.insert(*offset, (id, *width)).is_some()
        {
            return None;
        }
    }

    let mut matched = None;
    for event in events {
        if let Some(layout) = layout_for(h, event, &topic_values, &loads)
            && matched.replace(layout).is_some()
        {
            return None;
        }
    }
    matched
}

/// The topics vec's elements, in the helper's own values, and the call
/// that built it when a builder did.
fn topic_elements(
    ir: &HighIr,
    h: &HighFunction,
    topics: ValueId,
) -> Option<(Vec<ValueId>, Option<ValueId>)> {
    let t = resolve_use(h, topics);
    match &h.bindings.get(t)?.expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::VecNew { elements: Some(es), .. })) => Some((es.clone(), None)),
        Expr::Call { target, args } => {
            let callee = ir.function(*target)?;
            let mut returned = None;
            for site in callee.returns.iter().filter(|s| !s.is_empty()) {
                let [x] = site[..] else {
                    return None;
                };
                let x = resolve_use(callee, x);
                if returned.replace(x).is_some_and(|prev| prev != x) {
                    return None;
                }
            }
            let Expr::Semantic(SemanticOp::Known(KnownOp::VecNew { elements: Some(es), .. })) =
                &callee.bindings.get(returned?)?.expr
            else {
                return None;
            };
            let mapped = es
                .iter()
                .map(|e| {
                    let e = resolve_use(callee, *e);
                    let index = callee.params.iter().position(|p| *p == e)?;
                    args.get(index).copied()
                })
                .collect::<Option<Vec<_>>>()?;
            Some((mapped, Some(t)))
        }
        _ => None,
    }
}

/// `event`'s layout in the helper, when the helper's reads are exactly
/// that event's fields.
fn layout_for(
    h: &HighFunction,
    event: &EventDef,
    topics: &[ValueId],
    loads: &BTreeMap<u32, (ValueId, MemWidth)>,
) -> Option<Layout> {
    // The prefix symbols, then one struct word per `#[topic]` field.
    let k = event.prefix_topics.len();
    if topics.len() < k {
        return None;
    }
    for (value, want) in topics.iter().zip(&event.prefix_topics) {
        if symbol_constant(h, *value).as_deref() != Some(want.as_str()) {
            return None;
        }
    }
    let topic_params: Vec<_> =
        event.params.iter().filter(|p| p.location == EventParamLocation::Topic).collect();
    if topics.len() - k != topic_params.len() {
        return None;
    }
    let mut claimed: HashSet<u32> = HashSet::new();
    let mut at: HashMap<String, (u32, Shape)> = HashMap::new();
    for (param, value) in topic_params.iter().zip(&topics[k..]) {
        let offset = loads
            .iter()
            .find(|(_, (id, w))| *id == resolve_use(h, *value) && *w == MemWidth::W8)
            .map(|(o, _)| *o)?;
        claimed.insert(offset);
        at.insert(param.name.clone(), (offset, Shape::Word));
    }

    // What remains, by shape.
    let mut shapes: Vec<(u32, Shape)> = Vec::new();
    for (_, b) in h.bindings.iter() {
        let Expr::WideJoin { lo, hi } = &b.expr else { continue };
        let (Some(lo), Some(hi)) = (offset_of(h, loads, *lo), offset_of(h, loads, *hi)) else {
            continue;
        };
        if hi == lo + 8 && !claimed.contains(&lo) && !claimed.contains(&hi) {
            claimed.insert(lo);
            claimed.insert(hi);
            shapes.push((lo, Shape::Wide));
        }
    }
    let rest: Vec<(u32, MemWidth)> =
        loads.iter().filter(|(o, _)| !claimed.contains(o)).map(|(o, (_, w))| (*o, *w)).collect();
    let mut taken: HashSet<u32> = HashSet::new();
    for &(o, w) in &rest {
        if taken.contains(&o) {
            continue;
        }
        if w == MemWidth::W4 && rest.iter().any(|&(o2, w2)| o2 == o + 8 && w2 == MemWidth::W8) {
            taken.insert(o);
            taken.insert(o + 8);
            shapes.push((o, Shape::OptionWord));
        }
    }
    for &(o, w) in &rest {
        if taken.contains(&o) {
            continue;
        }
        if w != MemWidth::W8 {
            return None; // a read this pass cannot explain
        }
        shapes.push((o, Shape::Word));
    }

    // Data fields by shape, each shape at most once.
    let data_params: Vec<_> =
        event.params.iter().filter(|p| p.location == EventParamLocation::Data).collect();
    if data_params.len() != shapes.len() {
        return None;
    }
    for param in &data_params {
        let want = shape_of(&param.ty)?;
        let mut candidates = shapes.iter().filter(|(_, s)| *s == want);
        let (Some(&(offset, shape)), None) = (candidates.next(), candidates.next()) else {
            return None;
        };
        at.insert(param.name.clone(), (offset, shape));
    }

    let fields = event
        .params
        .iter()
        .map(|p| at.get(&p.name).map(|&(o, s)| (p.name.clone(), o, s)))
        .collect::<Option<Vec<_>>>()?;
    Some(Layout { event: event.name.clone(), fields })
}

/// The offset of the struct read `value` is, if it is one.
fn offset_of(h: &HighFunction, loads: &BTreeMap<u32, (ValueId, MemWidth)>, value: ValueId) -> Option<u32> {
    let v = resolve_use(h, value);
    loads.iter().find(|(_, (id, w))| *id == v && *w == MemWidth::W8).map(|(o, _)| *o)
}

/// The shape a declared field type takes in the struct.
fn shape_of(ty: &TypeRef) -> Option<Shape> {
    use sordec_ir::CompositeType;
    match ty {
        TypeRef::Primitive(PrimitiveType::I128 | PrimitiveType::U128) => Some(Shape::Wide),
        TypeRef::Composite(CompositeType::Option(inner))
            if matches!(**inner, TypeRef::Primitive(PrimitiveType::U64 | PrimitiveType::I64)) =>
        {
            Some(Shape::OptionWord)
        }
        TypeRef::Primitive(
            PrimitiveType::Address
            | PrimitiveType::MuxedAddress
            | PrimitiveType::Symbol
            | PrimitiveType::String
            | PrimitiveType::Bytes
            | PrimitiveType::U64
            | PrimitiveType::I64,
        ) => Some(Shape::Word),
        _ => None,
    }
}

/// The symbol a constant names, packed or already decoded.
fn symbol_constant(h: &HighFunction, value: ValueId) -> Option<String> {
    match &h.bindings.get(resolve_use(h, value))?.expr {
        Expr::Literal(Literal::Symbol(s)) => Some(s.clone()),
        Expr::Literal(Literal::I64(bits)) => decode_small_symbol(*bits as u64),
        Expr::Literal(Literal::U64(bits)) => decode_small_symbol(*bits),
        _ => None,
    }
}

// ---------------------------------------------------------------------
// The call sites
// ---------------------------------------------------------------------

/// What one call site's stores say.
struct SitePlan {
    /// Field values in declaration order; `None` for a literal `None`.
    values: Vec<Option<ValueId>>,
    /// The stores the struct was built with, now spent.
    stores: Vec<ValueId>,
    /// The muxed address whose inlined `id()` supplies a field, with the
    /// branch to remove and the field's index.
    muxed: Option<MuxedId>,
}

struct MuxedId {
    muxed: ValueId,
    field: usize,
    /// The id branch's condition — its identity in the region tree.
    branch_cond: ValueId,
    /// The branch's two merges, which nothing reads once the stores go.
    phis: [ValueId; 2],
}

fn plan_site(func: &HighFunction, call: ValueId, layout: &Layout) -> Option<SitePlan> {
    let Expr::Call { args, .. } = &func.bindings.get(call)?.expr else {
        return None;
    };
    let base = resolve_use(func, *args.first()?);
    let block = block_containing(func, call)?;
    let scheduled = &func.blocks.get(block)?.bindings;
    let call_pos = scheduled.iter().position(|v| *v == call)?;

    // The stores into the struct, all before the call in its block. A
    // store into it anywhere else is a use this reading does not model.
    let mut stores: BTreeMap<u32, (ValueId, ValueId, MemWidth)> = BTreeMap::new();
    let order = emission_order(func);
    for &id in &order {
        let Some(Expr::Store { addr, value, offset, width }) = func.bindings.get(id).map(|b| &b.expr) else {
            continue;
        };
        if resolve_use(func, *addr) != base {
            continue;
        }
        let pos = scheduled.iter().position(|v| *v == id)?;
        if pos > call_pos || stores.insert(*offset, (id, *value, *width)).is_some() {
            return None;
        }
    }

    let mut values = Vec::new();
    let mut spent = Vec::new();
    let mut muxed = None;
    let word = |o: u32, spent: &mut Vec<ValueId>| -> Option<ValueId> {
        let &(id, value, width) = stores.get(&o)?;
        (width == MemWidth::W8).then_some(())?;
        spent.push(id);
        Some(resolve_use(func, value))
    };
    for (index, (_, offset, shape)) in layout.fields.iter().enumerate() {
        match shape {
            Shape::Word => values.push(Some(word(*offset, &mut spent)?)),
            Shape::Wide => {
                let lo = word(*offset, &mut spent)?;
                let hi = word(offset + 8, &mut spent)?;
                let whole = halves_of(func, lo, hi)?;
                values.push(Some(whole));
            }
            Shape::OptionWord => {
                let &(disc_store, disc, _) = stores.get(offset)?;
                spent.push(disc_store);
                if int_literal(func, disc) == Some(0) {
                    // The payload a `None` carries is never read.
                    if let Some(&(payload_store, _, _)) = stores.get(&(offset + 8)) {
                        spent.push(payload_store);
                    }
                    values.push(None);
                    continue;
                }
                let payload = word(offset + 8, &mut spent)?;
                let id = muxed_id(func, resolve_use(func, disc), payload)?;
                muxed = Some(MuxedId { field: index, ..id });
                values.push(None); // filled in when the read is created
            }
        }
    }
    // Every store into the struct is a field; anything else is something
    // this reading does not account for.
    if spent.len() != stores.len() {
        return None;
    }
    // The id branch goes with the read that replaces it, so its merges
    // must feed nothing but the struct.
    if let Some(id) = &muxed
        && !id.phis.iter().all(|phi| only_read_by(func, &order, *phi, &spent))
    {
        return None;
    }
    Some(SitePlan { values, stores: spent, muxed })
}

/// Whether every live read of `value` is one of `readers`.
fn only_read_by(func: &HighFunction, order: &[ValueId], value: ValueId, readers: &[ValueId]) -> bool {
    let reads = |e: &Expr| {
        let mut r = false;
        e.for_each_value_use(|u| r |= u == value);
        r
    };
    let scheduled_ok = order
        .iter()
        .filter(|id| !readers.contains(id))
        .all(|id| func.bindings.get(*id).is_none_or(|b| !reads(&b.expr)));
    let phis_ok = func
        .bindings
        .iter()
        .filter(|(_, b)| matches!(b.expr, Expr::Phi { .. }))
        .all(|(_, b)| !reads(&b.expr));
    let mut region_reads = false;
    func.region.for_each_value_use(|u| region_reads |= u == value);
    scheduled_ok && phis_ok && !region_reads
}

/// The value whose low and high halves these are.
fn halves_of(func: &HighFunction, lo: ValueId, hi: ValueId) -> Option<ValueId> {
    let half = |v: ValueId, want: UnaryOp| match &func.bindings.get(v)?.expr {
        Expr::Unary { op, value } if *op == want => Some(resolve_use(func, *value)),
        _ => None,
    };
    let a = half(lo, UnaryOp::WideLo)?;
    let b = half(hi, UnaryOp::WideHi)?;
    (a == b).then_some(a)
}

fn int_literal(func: &HighFunction, v: ValueId) -> Option<i64> {
    match &func.bindings.get(resolve_use(func, v))?.expr {
        Expr::Literal(Literal::I32(n)) => Some(i64::from(*n)),
        Expr::Literal(Literal::I64(n)) => Some(*n),
        Expr::Literal(Literal::U32(n)) => Some(i64::from(*n)),
        Expr::Literal(Literal::U64(n)) => i64::try_from(*n).ok(),
        _ => None,
    }
}

/// The inlined `MuxedAddress::id()`: a branch on whether `m` is muxed,
/// merging `(1, get_id(m))` from one side and `(0, _)` from the other.
///
/// Sound only if the `0` side runs exactly when `m` is a plain address,
/// so the branch must test the flag the two-tag dispatch on `m` sets: `0`
/// for the address tag, nonzero for the muxed one.
fn muxed_id(func: &HighFunction, disc: ValueId, payload: ValueId) -> Option<MuxedId> {
    let Expr::Phi { incoming: disc_in } = &func.bindings.get(disc)?.expr else {
        return None;
    };
    let Expr::Phi { incoming: payload_in } = &func.bindings.get(payload)?.expr else {
        return None;
    };
    let mut muxed = None;
    let mut some_blocks = Vec::new();
    let mut none_blocks = Vec::new();
    for (block, value) in disc_in {
        match int_literal(func, *value)? {
            0 => none_blocks.push(*block),
            1 => {
                let (_, got) = payload_in.iter().find(|(b, _)| b == block)?;
                let Expr::Semantic(SemanticOp::Known(KnownOp::AddressConversion {
                    kind: AddressOpKind::GetIdFromMuxedAddress,
                    args,
                })) = &func.bindings.get(resolve_use(func, *got))?.expr
                else {
                    return None;
                };
                let m = resolve_use(func, *args.first()?);
                if muxed.replace(m).is_some_and(|prev| prev != m) {
                    return None;
                }
                some_blocks.push(*block);
            }
            _ => return None,
        }
    }
    let m = muxed?;
    if none_blocks.is_empty() {
        return None;
    }
    let flag = dispatch_flag(func, m)?;

    // The branch: muxed blocks under its `then`, plain ones under `else`,
    // tested on the flag.
    let mut found = None;
    func.region.for_each_node(|node| {
        let Region::If { cond, then_region, else_region: Some(else_region) } = node else {
            return;
        };
        let under = |r: &Region, blocks: &[sordec_common::BlockId]| {
            let mut all = true;
            for b in blocks {
                let mut hit = false;
                r.for_each_node(|n| hit |= matches!(n, Region::Basic(x) if x == b));
                all &= hit;
            }
            all
        };
        if resolve_use(func, *cond) == flag
            && under(then_region, &some_blocks)
            && under(else_region, &none_blocks)
            && self_contained(func, node, [disc, payload])
        {
            found = Some(*cond);
        }
    });
    Some(MuxedId { muxed: m, field: 0, branch_cond: found?, phis: [disc, payload] })
}

/// Whether every value the branch computes is read only inside it or by
/// its two merges, and nothing in it but the id read touches the host —
/// so removing it removes nothing anyone else sees.
fn self_contained(func: &HighFunction, branch: &Region, merges: [ValueId; 2]) -> bool {
    let mut blocks = HashSet::new();
    branch.for_each_node(|n| {
        if let Region::Basic(b) = n {
            blocks.insert(*b);
        }
    });
    let inside: HashSet<ValueId> = blocks
        .iter()
        .filter_map(|b| func.blocks.get(*b))
        .flat_map(|b| b.bindings.iter().copied())
        .collect();
    for id in &inside {
        let Some(b) = func.bindings.get(*id) else { return false };
        let fx = expr_effects(&b.expr);
        let id_read = matches!(
            b.expr,
            Expr::Semantic(SemanticOp::Known(KnownOp::AddressConversion {
                kind: AddressOpKind::GetIdFromMuxedAddress,
                ..
            }))
        );
        if (fx.writes_host || fx.writes_memory || fx.writes_globals) && !id_read {
            return false;
        }
    }
    for (id, b) in func.bindings.iter() {
        if inside.contains(&id) || merges.contains(&id) {
            continue;
        }
        let mut leaks = false;
        b.expr.for_each_value_use(|u| leaks |= inside.contains(&u));
        if leaks && (emission_order(func).contains(&id) || matches!(b.expr, Expr::Phi { .. })) {
            return false;
        }
    }
    true
}

/// The flag the two-tag dispatch on `m` sets: zero on the address tag,
/// nonzero on the muxed one.
fn dispatch_flag(func: &HighFunction, m: ValueId) -> Option<ValueId> {
    let mut flag = None;
    func.region.for_each_node(|node| {
        let Region::Switch { index, arms, default, .. } = node else { return };
        if !is_two_tag_check(arms, default) || tag_dispatch(func, *index) != Some(m) {
            return;
        }
        let mut phi = None;
        let mut ok = true;
        for arm in arms {
            let Some((p, src)) = sole_transfer(&arm.body) else {
                ok = false;
                continue;
            };
            if phi.replace(p).is_some_and(|prev| prev != p) {
                ok = false;
            }
            let value = int_literal(func, src);
            // Case 0 is the address tag (the dispatch is rebased on it).
            let fits = if arm.cases == [0] { value == Some(0) } else { value.is_some_and(|v| v != 0) };
            ok &= fits;
        }
        if ok {
            flag = phi;
        }
    });
    flag
}

// ---------------------------------------------------------------------
// The rewrite
// ---------------------------------------------------------------------

fn apply(func: &mut HighFunction, call: ValueId, layout: &Layout, mut plan: SitePlan) {
    if let Some(id) = &plan.muxed {
        let read = ValueId::from_index(func.bindings.len() as u32);
        func.bindings.push(Binding::new(
            read,
            IrType::Known(KnownType::Option(Box::new(IrType::Known(KnownType::U64)))),
            Expr::Semantic(SemanticOp::Known(KnownOp::MuxedAddressId { muxed: id.muxed })),
            Provenance::new(
                PASS_NAME,
                ProvenanceSource::SdkPattern,
                "`MuxedAddress::id()`: the branch on the muxed tag reading the id, or `None`",
            ),
        ));
        for (_, block) in func.blocks.iter_mut() {
            if let Some(pos) = block.bindings.iter().position(|v| *v == call) {
                block.bindings.insert(pos, read);
                break;
            }
        }
        plan.values[id.field] = Some(read);
        remove_branch(&mut func.region, id.branch_cond);
    }
    for store in &plan.stores {
        if let Some(b) = func.bindings.get_mut(*store) {
            b.expr = Expr::Literal(Literal::Unit);
            b.ty = IrType::Known(KnownType::Unit);
            b.add_provenance(Provenance::new(
                PASS_NAME,
                ProvenanceSource::SdkPattern,
                format!("a field of the `{}` the publish helper is handed", layout.event),
            ));
        }
    }
    if let Some(b) = func.bindings.get_mut(call) {
        b.expr = Expr::Semantic(SemanticOp::Known(KnownOp::PublishContractEvent {
            event: layout.event.clone(),
            fields: layout.fields.iter().map(|(n, _, _)| n.clone()).zip(plan.values).collect(),
        }));
        b.ty = IrType::Known(KnownType::Unit);
        b.add_provenance(Provenance::new(
            PASS_NAME,
            ProvenanceSource::SdkPattern,
            format!(
                "`{} {{ … }}.publish(&e)`: the struct built in the frame and the \
                 `#[contractevent]` helper it was handed to",
                layout.event
            ),
        ));
    }
}

/// Drop the inlined `id()` branch, now the read it stood for exists.
fn remove_branch(region: &mut Region, cond: ValueId) -> bool {
    match region {
        Region::Sequence(items) => {
            if let Some(i) = items.iter().position(|r| matches!(r, Region::If { cond: c, .. } if *c == cond)) {
                items.remove(i);
                return true;
            }
            items.iter_mut().any(|r| remove_branch(r, cond))
        }
        Region::If { cond: c, .. } if *c == cond => {
            *region = Region::Sequence(Vec::new());
            true
        }
        Region::Scope { body, .. } | Region::Loop { body, .. } => remove_branch(body, cond),
        Region::If { then_region, else_region, .. } => {
            remove_branch(then_region, cond)
                || else_region.as_deref_mut().is_some_and(|e| remove_branch(e, cond))
        }
        Region::Switch { arms, default, .. } => {
            arms.iter_mut().any(|a| remove_branch(&mut a.body, cond)) || remove_branch(default, cond)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, module, v};
    use sordec_common::TypeId;
    use sordec_ir::{EventParam, SorobanFacts};

    fn load(offset: u32) -> Expr {
        Expr::Load {
            addr: v(0),
            offset,
            width: MemWidth::W8,
            signed: None,
            ty: IrType::Unknown(sordec_common::UnknownReason::InsufficientEvidence),
        }
    }

    fn store(value: u32, offset: u32) -> Expr {
        Expr::Store { addr: v(2), value: v(value), offset, width: MemWidth::W8 }
    }

    /// `#[contractevent] struct Ev { #[topic] a: Address, amount: i128 }`.
    fn event() -> EventDef {
        EventDef {
            id: TypeId::from_index(0),
            name: "Ev".into(),
            prefix_topics: vec!["ev".into()],
            params: vec![
                EventParam {
                    name: "a".into(),
                    ty: TypeRef::Primitive(PrimitiveType::Address),
                    location: EventParamLocation::Topic,
                },
                EventParam {
                    name: "amount".into(),
                    ty: TypeRef::Primitive(PrimitiveType::I128),
                    location: EventParamLocation::Data,
                },
            ],
            data_format: "single-value".into(),
        }
    }

    /// The generated helper: `a` read at +0 into the topics, `amount`'s
    /// halves at +8/+16 joined into the data.
    fn helper() -> HighFunction {
        let mut h = func_with(
            vec![
                Expr::Phi { incoming: vec![] },                     // v0 the struct
                Expr::Literal(Literal::Symbol("ev".into())),         // v1
                load(0),                                             // v2 a
                Expr::Semantic(SemanticOp::Known(KnownOp::VecNew {
                    vals_pos: v(1),
                    len: v(1),
                    elements: Some(vec![v(1), v(2)]),
                })), // v3 topics
                load(8),                                     // v4
                load(16),                                    // v5
                Expr::WideJoin { lo: v(4), hi: v(5) },       // v6 amount
                Expr::Semantic(SemanticOp::Known(KnownOp::PublishEvent { topics: v(3), data: v(6) })), // v7
            ],
            vec![v(0)],
            (1..8).collect(),
        );
        h.id = FuncId::from_index(1);
        h
    }

    /// A caller building `Ev { a, amount }` in its frame at `v2`; `extra`
    /// adds a store the event does not account for.
    fn caller(extra: bool) -> HighFunction {
        let mut exprs = vec![
            Expr::Phi { incoming: vec![] },                  // v0 a
            Expr::Phi { incoming: vec![] },                  // v1 amount
            Expr::Literal(Literal::I32(1024)),               // v2 the frame
            Expr::Unary { op: UnaryOp::WideLo, value: v(1) }, // v3
            Expr::Unary { op: UnaryOp::WideHi, value: v(1) }, // v4
            store(0, 0),                                     // v5
            store(3, 8),                                     // v6
            store(4, 16),                                    // v7
            Expr::Call { target: FuncId::from_index(1), args: vec![v(2)] }, // v8
        ];
        let mut scheduled: Vec<u32> = (2..9).collect();
        if extra {
            exprs.push(store(0, 24)); // v9
            scheduled.insert(scheduled.len() - 1, 9);
        }
        func_with(exprs, vec![v(0), v(1)], scheduled)
    }

    fn with_event(mut ir: HighIr) -> HighIr {
        let mut facts = SorobanFacts::default();
        facts.types.events.push(event());
        ir.soroban_facts = Some(facts);
        ir
    }

    /// The whole point: the call is the struct literal, published, and the
    /// stores that built it are spent.
    #[test]
    fn a_helper_call_becomes_the_struct_published() {
        let mut ir = with_event(module(vec![caller(false), helper()]));
        let result = ContractEventPass.run(&mut ir);
        assert_eq!(result.metrics.get(M_RECOVERED), Some(1));
        let f = &ir.functions[0];
        let Expr::Semantic(SemanticOp::Known(KnownOp::PublishContractEvent { event, fields })) =
            &f.bindings.get(v(8)).expect("the call").expr
        else {
            panic!("not rewritten: {:?}", f.bindings.get(v(8)).map(|b| &b.expr));
        };
        assert_eq!(event, "Ev");
        assert_eq!(
            fields,
            &vec![("a".to_string(), Some(v(0))), ("amount".to_string(), Some(v(1)))],
            "the topic by position, the wide field as the value whose halves were stored"
        );
        for store in [5, 6, 7] {
            assert!(matches!(f.bindings.get(v(store)).map(|b| &b.expr), Some(Expr::Literal(Literal::Unit))));
        }
    }

    /// A store the event does not explain means the struct is not what the
    /// spec says, and the call is left as it is.
    #[test]
    fn an_unexplained_store_declines_the_site() {
        let mut ir = with_event(module(vec![caller(true), helper()]));
        let result = ContractEventPass.run(&mut ir);
        assert_eq!(result.metrics.get(M_RECOVERED), None);
        assert_eq!(result.metrics.get(M_SITE_DECLINED), Some(1));
    }

    /// The helper must name the event: a prefix symbol that is not the
    /// event's leaves it unidentified.
    #[test]
    fn a_different_prefix_is_not_this_event() {
        let mut h = helper();
        if let Some(b) = h.bindings.get_mut(v(1)) {
            b.expr = Expr::Literal(Literal::Symbol("other".into()));
        }
        let mut ir = with_event(module(vec![caller(false), h]));
        assert!(!ContractEventPass.run(&mut ir).changed);
    }
}
