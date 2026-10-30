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
//! # Written out inline
//!
//! When rustc inlines the generated publish into the caller there is no
//! helper and no struct: the caller builds the topics vec and the data map
//! itself and calls the host.
//!
//! ```text
//! topics = vec[symbol("auth"), addr]
//! store fp+16 <- world
//! data   = map_new_from_linear_memory(&KEYS, fp+16, 1)   ← KEYS = ["world"]
//! publish_event(topics, data)          →  AuthEvent { hello: addr, world }.publish(&e)
//! ```
//!
//! The event is named by both halves: its prefix symbols lead the topics
//! (as for a helper), and its data map's key table, read out of rodata, is
//! exactly the names of its `#[topic]`-less fields. A `Map`-format event
//! encodes its data as just that map, so a key table naming exactly those
//! fields and a topics vec opening with exactly that prefix is that
//! event's publish; when two declared events fit, nothing is rewritten.
//! Each topic field is the topics element at its position, each data
//! field the word stored in its key's slot, read through its `Val` encode.
//!
//! Why it is exact: the re-emitted `#[contractevent]` derive builds the
//! same two values from the literal — the prefix and the topic fields'
//! encodings as the topics vec, the data fields' encodings keyed by name
//! as the map — and publishes them, so the host receives the same words.
//! That holds only if each field value encodes to the word that was
//! stored, so every value must already be typed as the field's declared
//! type by the contract's own metadata (`Known`, never inferred). The map,
//! and a topics vec built in the caller, are then read by nothing but the
//! publish, and go with it; a construction read anywhere else stops the
//! rewrite. So does a helper call that built the topics, when the helper
//! does nothing else, and a prefix symbol built only for them.
//!
//! A field the caller stored as a constant word has no typed value to
//! name. The word is a `Val`'s bits — what the derive stores for a field
//! is its encoding — so it is read back through its decode as the field's
//! declared type and planted before the publish: a number, `bool` or short
//! symbol in its small form, an integer enum's variant by the discriminant
//! its `U32Val` carries, a 128-bit integer's small form as its two halves.
//! A word of any other tag, or a type with no such reading, stops the
//! rewrite. A prefix too long to pack is read from its recovered
//! `Symbol::new(&e, "…")`.
//!
//! A field declared a `#[contracttype]` struct may hold that struct's
//! derived encode still unread — a map built from a key table that
//! several structs share (`{ inner }`, `{ val }`), which the struct pass
//! leaves for want of a name. The event's declaration names it, and the
//! named struct's own declaration names each struct field inside it, the
//! naming by destination the struct pass already does for a return or a
//! recovered literal's field; each table must still fit the struct it is
//! named as field for field, and every level must be readable, or nothing
//! is rewritten. The literals are written with the publish.
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
        // The publishes rustc inlined, planned while the whole module can
        // still be read (a topics vec may come from a helper).
        let inline: Vec<(usize, Vec<InlineSite>)> = ir
            .functions
            .iter()
            .enumerate()
            .map(|(i, f)| (i, inline_sites(ir, f, &events)))
            .filter(|(_, sites)| !sites.is_empty())
            .collect();
        let structs: Vec<sordec_ir::StructDef> =
            ir.soroban_facts.as_ref().map(|f| f.types.structs.clone()).unwrap_or_default();
        for (i, sites) in inline {
            let memory = &ir.memory;
            let Some(func) = ir.functions.get_mut(i) else { continue };
            for site in sites {
                for (at, id) in &site.rebuilds {
                    super::udt_encode::rebuild_as(func, memory, &structs, *at, *id);
                }
                apply_inline(func, site);
                result.metrics.increment(M_RECOVERED, 1);
                result.changed = true;
            }
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
        // `Symbol::new(&e, "…")` with its text recovered: a prefix too long
        // to pack into a word.
        Expr::Semantic(SemanticOp::Known(KnownOp::SymbolNew { resolved: Some(s), .. })) => Some(s.clone()),
        _ => None,
    }
}

// ---------------------------------------------------------------------
// The publish written out inline
// ---------------------------------------------------------------------

/// One inlined publish to rewrite.
struct InlineSite {
    publish: ValueId,
    event: String,
    /// Every field in declaration order, with its value.
    fields: Vec<(String, Option<ValueId>)>,
    /// The data map and a topics vec built here, with the renames between
    /// them and the publish: read by nothing else, they go with it.
    spent: Vec<ValueId>,
    /// Fields whose stored word is a constant: the field's index and the
    /// value that word decodes to, planted just before the publish.
    constants: Vec<(usize, Constant)>,
    /// Struct encodes among the field values, with the struct the event's
    /// declaration names for each, outermost first.
    rebuilds: Vec<(ValueId, sordec_common::TypeId)>,
}

/// The value a constant word stored for a field decodes to, as the field's
/// declared type.
#[derive(Debug, Clone, PartialEq)]
enum Constant {
    /// A number, a `bool` or a short symbol.
    Scalar(Literal, KnownType),
    /// An integer enum's variant, by the discriminant its `U32Val` carries.
    Variant(String, KnownType),
    /// A 128-bit integer from its small form: low and high halves.
    Wide(i64, i64, KnownType),
}

/// The constant `value` is, read through its decode as `declared`: the
/// word is a `Val`'s bits — what the derive stores for a field is the
/// field's encoding — so it is read back only as one of that type.
fn constant_field(func: &HighFunction, value: ValueId, declared: &KnownType, enums: &[sordec_ir::EnumDef]) -> Option<Constant> {
    if let Some(lit) = super::encode::encoded_constant(func, value, declared) {
        return Some(Constant::Scalar(lit, declared.clone()));
    }
    if let Some(name) = super::encode::encoded_variant(func, value, declared, enums) {
        return Some(Constant::Variant(name, declared.clone()));
    }
    let bits = match &func.bindings.get(resolve_use(func, value))?.expr {
        Expr::Literal(Literal::I64(n)) => *n as u64,
        Expr::Literal(Literal::U64(n)) => *n,
        _ => return None,
    };
    let tag = (bits & 0xFF) as u8;
    // The small forms keep the number in the 56-bit body: signed for an
    // `i128` (an arithmetic shift restores the sign, which fills the high
    // half), unsigned for a `u128`.
    match declared {
        KnownType::I128 if tag == crate::val_abi::TAG_I128_SMALL => {
            let n = (bits as i64) >> 8;
            Some(Constant::Wide(n, n >> 63, KnownType::I128))
        }
        KnownType::U128 if tag == crate::val_abi::TAG_U128_SMALL => {
            Some(Constant::Wide((bits >> 8) as i64, 0, KnownType::U128))
        }
        _ => None,
    }
}

fn inline_sites(ir: &HighIr, func: &HighFunction, events: &[EventDef]) -> Vec<InlineSite> {
    let uses = crate::dataflow::HighUseIndex::build(func);
    emission_order(func)
        .into_iter()
        .filter_map(|id| {
            let Expr::Semantic(SemanticOp::Known(KnownOp::PublishEvent { topics, data })) =
                &func.bindings.get(id)?.expr
            else {
                return None;
            };
            inline_site(ir, func, &uses, events, id, *topics, *data)
        })
        .collect()
}

/// The contract's integer enums, for a constant field's variant.
fn enums_of(ir: &HighIr) -> &[sordec_ir::EnumDef] {
    ir.soroban_facts.as_ref().map_or(&[], |f| f.types.enums.as_slice())
}

fn inline_site(
    ir: &HighIr,
    func: &HighFunction,
    uses: &crate::dataflow::HighUseIndex,
    events: &[EventDef],
    publish: ValueId,
    topics: ValueId,
    data: ValueId,
) -> Option<InlineSite> {
    use crate::dataflow::{canon_addr, facts_at, trace_u32val};
    // The data: a map built from the frame, keyed by a rodata table.
    let map = resolve_use(func, data);
    let Expr::Semantic(SemanticOp::Known(KnownOp::MapNew { keys_pos, vals_pos, len })) =
        &func.bindings.get(map)?.expr
    else {
        return None;
    };
    let len = trace_u32val(func, *len)?;
    let keys = super::udt_decode::read_keys(&ir.memory, trace_u32val(func, *keys_pos)?, len)?;
    let Some((elements, builder)) = topic_elements(ir, func, topics) else {
        trace(func, publish, &format!("data keys {keys:?}, topics not a vec of known elements"));
        return None;
    };
    // Exactly one declared event has this prefix and these data fields.
    let mut hits = events.iter().filter(|e| inline_fits(func, e, &keys, &elements));
    let Some(event) = hits.next() else {
        trace(func, publish, &format!("data keys {keys:?}: no event has that prefix and those fields"));
        return None;
    };
    if hits.next().is_some() {
        trace(func, publish, "two events fit");
        return None;
    }
    let (base, start) = canon_addr(func, super::udt_decode::raw_address(func, *vals_pos));
    let facts = facts_at(func, map, base);
    let mut topic_values = elements.get(event.prefix_topics.len()..)?.iter();
    let mut fields = Vec::with_capacity(event.params.len());
    let mut constants = Vec::new();
    let mut rebuilds = Vec::new();
    for param in &event.params {
        let value = match param.location {
            EventParamLocation::Topic => resolve_use(func, *topic_values.next()?),
            EventParamLocation::Data => {
                let index = u32::try_from(keys.iter().position(|k| *k == param.name)?).ok()?;
                let slot = facts.value_at(start.checked_add(index.checked_mul(8)?)?, MemWidth::W8)?;
                super::udt_encode::encoded_value(func, slot)
            }
        };
        let declared = crate::type_infer::known_of_type_ref(&param.ty)?;
        let ty = &func.bindings.get(value)?.ty;
        // Typed by the metadata: on its binding, or as one of this
        // entrypoint's parameters, which the spec declares.
        let as_param = func.params.iter().position(|p| *p == value).and_then(|i| {
            crate::type_infer::known_of_type_ref(&func.signature.as_ref()?.inputs.get(i)?.ty)
        });
        if *ty != IrType::Known(declared.clone()) && as_param.as_ref() != Some(&declared) {
            if let Some(c) = constant_field(func, value, &declared, enums_of(ir)) {
                constants.push((fields.len(), c));
            } else if !matches!(declared, KnownType::UserDefined(id) if struct_constructions(ir, func, value, id, &mut rebuilds))
            {
                trace(func, publish, &format!("{}: {value:?} is {ty:?}, not the declared type", param.name));
                return None;
            }
        }
        fields.push((param.name.clone(), Some(value)));
    }
    let mut spent = Vec::new();
    if !read_only_by(func, uses, map, publish, &mut spent)
        || (builder.is_none() && !read_only_by(func, uses, resolve_use(func, topics), publish, &mut spent))
    {
        trace(func, publish, "the data map or the topics vec is read elsewhere");
        return None;
    }
    // A helper that does nothing but build the topics vec: its call, read
    // only by the publish, goes too (and the helper with its last caller).
    if let Some(call) = builder
        && let Some(Expr::Call { target, .. }) = func.bindings.get(call).map(|b| &b.expr)
        && ir.function(*target).is_some_and(only_builds_a_vec)
    {
        let mut more = Vec::new();
        if read_only_by(func, uses, call, publish, &mut more) {
            spent.extend(more);
        }
    }
    // A prefix symbol built for the topics alone goes with them.
    for value in elements.iter().take(event.prefix_topics.len()) {
        let v = resolve_use(func, *value);
        let built = matches!(
            func.bindings.get(v).map(|b| &b.expr),
            Some(Expr::Semantic(SemanticOp::Known(KnownOp::SymbolNew { resolved: Some(_), .. })))
        );
        let sites = uses.uses_of(v);
        let only_spent = !sites.is_empty()
            && sites.iter().all(|s| matches!(s, crate::dataflow::HighUseSite::Binding { user } if spent.contains(user)));
        if built && only_spent {
            spent.push(v);
        }
    }
    Some(InlineSite { publish, event: event.name.clone(), fields, spent, constants, rebuilds })
}

/// Whether the map built at `at` is struct `id`'s derived encode, and so
/// is every field of it that is itself a struct's map; each such
/// construction, outermost first, into `out`.
///
/// The key table alone may fit several structs; here the event's
/// declaration names the field's struct, and the outer struct's
/// declaration each inner one — the same naming by destination
/// `udt_encode` does for a return or a recovered literal's field, and the
/// table must still fit the named struct field for field.
fn struct_constructions(
    ir: &HighIr,
    func: &HighFunction,
    at: ValueId,
    id: sordec_common::TypeId,
    out: &mut Vec<(ValueId, sordec_common::TypeId)>,
) -> bool {
    let at = resolve_use(func, at);
    let Some(structs) = ir.soroban_facts.as_ref().map(|f| f.types.structs.as_slice()) else { return false };
    let Some(def) = structs.iter().find(|s| s.id == id) else { return false };
    let Some(fields) = super::udt_encode::literal_fields(func, &ir.memory, structs, at, id) else { return false };
    out.push((at, id));
    for (name, value) in fields {
        let v = resolve_use(func, value);
        let is_map = matches!(
            func.bindings.get(v).map(|b| &b.expr),
            Some(Expr::Semantic(SemanticOp::Known(KnownOp::MapNew { .. })))
        );
        if !is_map {
            continue;
        }
        let Some(TypeRef::UserDefined(inner)) = def.fields.iter().find(|f| f.name == name).map(|f| &f.ty) else {
            return false;
        };
        if !struct_constructions(ir, func, v, *inner, out) {
            return false;
        }
    }
    true
}

/// Whether a helper's only effect is the vec it returns: every other
/// binding it runs is pure and total.
fn only_builds_a_vec(h: &HighFunction) -> bool {
    h.blocks.iter().all(|(_, block)| {
        block.bindings.iter().all(|id| match h.bindings.get(*id).map(|b| &b.expr) {
            Some(Expr::Semantic(SemanticOp::Known(KnownOp::VecNew { elements: Some(_), .. }))) => true,
            Some(other) => expr_effects(other).is_pure_total(),
            None => false,
        })
    })
}

/// Why an inlined publish was left, printed when `SORDEC_EVENT_TRACE` is
/// set.
#[allow(clippy::print_stderr)]
fn trace(func: &HighFunction, publish: ValueId, why: &str) {
    if std::env::var_os("SORDEC_EVENT_TRACE").is_some() {
        eprintln!("contract-event: func_{} {publish:?}: {why}", func.id.index());
    }
}

/// Whether `event` is the one an inlined publish of a map keyed `keys`
/// with topics `elements` names: a `Map`-format event whose prefix leads
/// the topics, followed by one element per `#[topic]` field, and whose
/// other fields are exactly the keys.
fn inline_fits(func: &HighFunction, event: &EventDef, keys: &[String], elements: &[ValueId]) -> bool {
    if !event.data_format.eq_ignore_ascii_case("map") {
        return false;
    }
    let topics = event.params.iter().filter(|p| p.location == EventParamLocation::Topic).count();
    if elements.len() != event.prefix_topics.len() + topics {
        return false;
    }
    let prefix_ok = elements
        .iter()
        .zip(&event.prefix_topics)
        .all(|(v, want)| symbol_constant(func, *v).as_deref() == Some(want.as_str()));
    let mut want: Vec<&str> = keys.iter().map(String::as_str).collect();
    want.sort_unstable();
    let mut have: Vec<&str> = event
        .params
        .iter()
        .filter(|p| p.location == EventParamLocation::Data)
        .map(|p| p.name.as_str())
        .collect();
    have.sort_unstable();
    prefix_ok && want == have
}

/// Whether `value` is read by nothing but `publish`, directly or through
/// renames; collects it and those renames into `spent`.
fn read_only_by(
    func: &HighFunction,
    uses: &crate::dataflow::HighUseIndex,
    value: ValueId,
    publish: ValueId,
    spent: &mut Vec<ValueId>,
) -> bool {
    use crate::dataflow::HighUseSite;
    spent.push(value);
    uses.uses_of(value).iter().all(|site| match site {
        HighUseSite::Binding { user } if *user == publish => true,
        HighUseSite::Binding { user } if matches!(func.bindings.get(*user).map(|b| &b.expr), Some(Expr::Use(_))) => {
            read_only_by(func, uses, *user, publish, spent)
        }
        _ => false,
    })
}

/// Schedule `expr` just before `at`; its id.
fn plant_before(func: &mut HighFunction, at: ValueId, expr: Expr, ty: KnownType, note: &str) -> Option<ValueId> {
    let block = block_containing(func, at)?;
    let id = ValueId::from_index(func.bindings.len() as u32);
    func.bindings.push(Binding::new(
        id,
        IrType::Known(ty),
        expr,
        Provenance::new(PASS_NAME, ProvenanceSource::SdkPattern, note.to_string()),
    ));
    let block = func.blocks.get_mut(block)?;
    let pos = block.bindings.iter().position(|b| *b == at)?;
    block.bindings.insert(pos, id);
    Some(id)
}

/// Plant a constant field's decoded value before the publish.
fn plant_constant(func: &mut HighFunction, at: ValueId, c: Constant) -> Option<ValueId> {
    let note = "a constant event field, its stored word read through its decode as the declared type";
    match c {
        Constant::Scalar(lit, ty) => plant_before(func, at, Expr::Literal(lit), ty, note),
        Constant::Variant(name, ty) => plant_before(func, at, Expr::Variant { name, payload: Vec::new() }, ty, note),
        Constant::Wide(lo, hi, ty) => {
            let lo = plant_before(func, at, Expr::Literal(Literal::I64(lo)), KnownType::I64, note)?;
            let hi = plant_before(func, at, Expr::Literal(Literal::I64(hi)), KnownType::I64, note)?;
            plant_before(func, at, Expr::WideJoin { lo, hi }, ty, note)
        }
    }
}

/// Rewrite the publish as the event literal and drop what built its
/// arguments.
fn apply_inline(func: &mut HighFunction, mut site: InlineSite) {
    for (index, c) in std::mem::take(&mut site.constants) {
        let Some(id) = plant_constant(func, site.publish, c) else { return };
        if let Some(field) = site.fields.get_mut(index) {
            field.1 = Some(id);
        }
    }
    for id in &site.spent {
        if let Some(b) = func.bindings.get_mut(*id) {
            b.expr = Expr::Literal(Literal::Unit);
            b.ty = IrType::Known(KnownType::Unit);
            b.add_provenance(Provenance::new(
                PASS_NAME,
                ProvenanceSource::SdkPattern,
                format!("built only for the inlined `{}` publish, which the derive regenerates", site.event),
            ));
        }
    }
    if let Some(b) = func.bindings.get_mut(site.publish) {
        b.expr = Expr::Semantic(SemanticOp::Known(KnownOp::PublishContractEvent {
            event: site.event.clone(),
            fields: site.fields,
        }));
        b.ty = IrType::Known(KnownType::Unit);
        b.add_provenance(Provenance::new(
            PASS_NAME,
            ProvenanceSource::SdkPattern,
            format!(
                "`{} {{ … }}.publish(&e)`, inlined: its prefix leads the topics and its data fields \
                 are the data map's key table",
                site.event
            ),
        ));
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

    // -----------------------------------------------------------------
    // Written out inline
    // -----------------------------------------------------------------

    /// `#[contractevent] struct Auth { #[topic] a: Address, world: Symbol }`.
    fn map_event() -> EventDef {
        EventDef {
            id: TypeId::from_index(1),
            name: "Auth".into(),
            prefix_topics: vec!["auth".into()],
            params: vec![
                EventParam {
                    name: "a".into(),
                    ty: TypeRef::Primitive(PrimitiveType::Address),
                    location: EventParamLocation::Topic,
                },
                EventParam {
                    name: "world".into(),
                    ty: TypeRef::Primitive(PrimitiveType::Symbol),
                    location: EventParamLocation::Data,
                },
            ],
            data_format: "map".into(),
        }
    }

    /// The publish inlined into its caller: topics `vec[auth, a]`, `world`
    /// stored at the frame and the data map built from it by the key table
    /// at 2000.
    fn inlined() -> HighIr {
        let mut f = func_with(
            vec![
                Expr::Phi { incoming: vec![] },                  // v0 a
                Expr::Phi { incoming: vec![] },                  // v1 world
                Expr::Literal(Literal::I32(1024)),               // v2 the frame
                Expr::Literal(Literal::Symbol("auth".into())),   // v3
                Expr::Semantic(SemanticOp::Known(KnownOp::VecNew {
                    vals_pos: v(2),
                    len: v(2),
                    elements: Some(vec![v(3), v(0)]),
                })), // v4 topics
                store(1, 0),                                     // v5
                Expr::Literal(Literal::U32(2000)),               // v6 keys
                Expr::Literal(Literal::U32(1)),                  // v7 len
                Expr::Semantic(SemanticOp::Known(KnownOp::MapNew { keys_pos: v(6), vals_pos: v(2), len: v(7) })), // v8
                Expr::Use(v(8)),                                 // v9 a rename
                Expr::Semantic(SemanticOp::Known(KnownOp::PublishEvent { topics: v(4), data: v(9) })), // v10
            ],
            vec![v(0), v(1)],
            (2..11).collect(),
        );
        f.bindings.get_mut(v(0)).unwrap().ty = IrType::Known(KnownType::Address);
        f.bindings.get_mut(v(1)).unwrap().ty = IrType::Known(KnownType::Symbol);
        let mut ir = module(vec![f]);
        let mut table = Vec::new();
        table.extend_from_slice(&2100u32.to_le_bytes());
        table.extend_from_slice(&5u32.to_le_bytes());
        ir.memory = sordec_ir::MemoryImage::from_segments(vec![
            sordec_ir::DataSegment { offset: 2000, bytes: table },
            sordec_ir::DataSegment { offset: 2100, bytes: b"world".to_vec() },
        ]);
        let mut facts = SorobanFacts::default();
        facts.types.events.push(map_event());
        ir.soroban_facts = Some(facts);
        ir
    }

    fn expr(ir: &HighIr, id: u32) -> &Expr {
        &ir.functions[0].bindings.get(v(id)).expect("binding").expr
    }

    /// The prefix leads the topics and the key table names the data field:
    /// the literal, published, with what built its arguments gone.
    #[test]
    fn an_inlined_publish_becomes_the_event_published() {
        let mut ir = inlined();
        assert!(ContractEventPass.run(&mut ir).changed);
        let Expr::Semantic(SemanticOp::Known(KnownOp::PublishContractEvent { event, fields })) = expr(&ir, 10) else {
            panic!("not rewritten: {:?}", expr(&ir, 10));
        };
        assert_eq!(event, "Auth");
        assert_eq!(fields, &vec![("a".to_string(), Some(v(0))), ("world".to_string(), Some(v(1)))]);
        for spent in [4, 8, 9] {
            assert!(matches!(expr(&ir, spent), Expr::Literal(Literal::Unit)), "v{spent}");
        }
    }

    /// A value the metadata does not type as the field is not known to
    /// encode to the word that was stored.
    #[test]
    fn an_untyped_field_value_leaves_the_publish() {
        let mut ir = inlined();
        ir.functions[0].bindings.get_mut(v(1)).unwrap().ty =
            IrType::Unknown(sordec_common::UnknownReason::InsufficientEvidence);
        assert!(!ContractEventPass.run(&mut ir).changed);
    }

    /// `inlined()` with `world` declared a `u32` and stored as `word`.
    fn with_constant(word: i64) -> HighIr {
        let mut ir = inlined();
        ir.soroban_facts.as_mut().unwrap().types.events[0].params[1].ty = TypeRef::Primitive(PrimitiveType::U32);
        let f = &mut ir.functions[0];
        f.bindings.get_mut(v(1)).unwrap().expr = Expr::Literal(Literal::I64(word));
        f.bindings.get_mut(v(1)).unwrap().ty = IrType::Known(KnownType::I64);
        ir
    }

    /// A constant stored for a `u32` field is a `U32Val`'s bits: the field
    /// is the number it carries.
    #[test]
    fn a_constant_field_is_its_decoded_value() {
        let mut ir = with_constant((7 << 32) | 4);
        assert!(ContractEventPass.run(&mut ir).changed);
        let Expr::Semantic(SemanticOp::Known(KnownOp::PublishContractEvent { fields, .. })) = expr(&ir, 10) else {
            panic!("not rewritten: {:?}", expr(&ir, 10));
        };
        let world = fields[1].1.expect("a value");
        assert!(matches!(ir.functions[0].bindings.get(world).unwrap().expr, Expr::Literal(Literal::U32(7))));
    }

    /// A word of another type's tag is not this field's encoding.
    #[test]
    fn a_constant_of_another_tag_leaves_the_publish() {
        let mut ir = with_constant((7 << 32) | 5);
        assert!(!ContractEventPass.run(&mut ir).changed);
    }

    /// `Nest { #[topic] a: Address, payload: Inner }` published inline, its
    /// payload a struct encode whose key table `Inner` shares with `Twin`.
    fn nested() -> HighIr {
        use sordec_ir::{StructDef, StructField};
        let st = |addr: u32, value: u32, offset: u32| Expr::Store { addr: v(addr), value: v(value), offset, width: MemWidth::W8 };
        let mut f = func_with(
            vec![
                Expr::Phi { incoming: vec![] },                  // v0 a
                Expr::Phi { incoming: vec![] },                  // v1 the frame
                Expr::Literal(Literal::Symbol("nest".into())),   // v2
                Expr::Semantic(SemanticOp::Known(KnownOp::VecNew {
                    vals_pos: v(1),
                    len: v(1),
                    elements: Some(vec![v(2), v(0)]),
                })), // v3 topics
                Expr::Literal(Literal::I64((42 << 32) | 4)),     // v4 U32Val(42)
                st(1, 4, 16),                                    // v5 the inner slot
                Expr::Literal(Literal::U32(2008)),               // v6 inner keys
                Expr::Literal(Literal::U32(1)),                  // v7 len
                Expr::Literal(Literal::I32(16)),                 // v8
                Expr::Binary { op: sordec_ir::BinaryOp::Add, lhs: v(1), rhs: v(8) }, // v9
                Expr::Semantic(SemanticOp::Known(KnownOp::MapNew { keys_pos: v(6), vals_pos: v(9), len: v(7) })), // v10
                st(1, 10, 0),                                    // v11 the data slot
                Expr::Literal(Literal::U32(2000)),               // v12 data keys
                Expr::Semantic(SemanticOp::Known(KnownOp::MapNew { keys_pos: v(12), vals_pos: v(1), len: v(7) })), // v13
                Expr::Semantic(SemanticOp::Known(KnownOp::PublishEvent { topics: v(3), data: v(13) })), // v14
            ],
            vec![v(0)],
            (1..15).collect(),
        );
        f.bindings.get_mut(v(0)).unwrap().ty = IrType::Known(KnownType::Address);
        let mut ir = module(vec![f]);
        let mut table = Vec::new();
        for (ptr, n) in [(2100u32, 7u32), (2110, 3)] {
            table.extend_from_slice(&ptr.to_le_bytes());
            table.extend_from_slice(&n.to_le_bytes());
        }
        ir.memory = sordec_ir::MemoryImage::from_segments(vec![
            sordec_ir::DataSegment { offset: 2000, bytes: table },
            sordec_ir::DataSegment { offset: 2100, bytes: b"payload".to_vec() },
            sordec_ir::DataSegment { offset: 2110, bytes: b"val".to_vec() },
        ]);
        let one = |id: u32, name: &str| StructDef {
            id: TypeId::from_index(id),
            name: name.into(),
            fields: vec![StructField { name: "val".into(), ty: TypeRef::Primitive(PrimitiveType::U32) }],
        };
        let mut facts = SorobanFacts::default();
        facts.types.structs = vec![one(10, "Inner"), one(11, "Twin")];
        facts.types.events.push(EventDef {
            id: TypeId::from_index(12),
            name: "Nest".into(),
            prefix_topics: vec!["nest".into()],
            params: vec![
                EventParam {
                    name: "a".into(),
                    ty: TypeRef::Primitive(PrimitiveType::Address),
                    location: EventParamLocation::Topic,
                },
                EventParam {
                    name: "payload".into(),
                    ty: TypeRef::UserDefined(TypeId::from_index(10)),
                    location: EventParamLocation::Data,
                },
            ],
            data_format: "map".into(),
        });
        ir.soroban_facts = Some(facts);
        ir
    }

    /// The event declares the payload an `Inner`: the shared table is
    /// `Inner`'s, its literal written with the publish.
    #[test]
    fn a_struct_field_is_named_by_the_events_declaration() {
        let mut ir = nested();
        assert!(ContractEventPass.run(&mut ir).changed);
        assert!(matches!(expr(&ir, 14), Expr::Semantic(SemanticOp::Known(KnownOp::PublishContractEvent { .. }))));
        assert!(matches!(expr(&ir, 10), Expr::Struct { .. }));
        assert_eq!(
            ir.functions[0].bindings.get(v(10)).unwrap().ty,
            IrType::Known(KnownType::UserDefined(TypeId::from_index(10)))
        );
    }

    /// A field declared as neither struct is not named by guessing.
    #[test]
    fn a_struct_field_whose_table_fits_no_declared_field_type_leaves_the_publish() {
        let mut ir = nested();
        ir.soroban_facts.as_mut().unwrap().types.structs[0].fields[0].name = "other".into();
        assert!(!ContractEventPass.run(&mut ir).changed);
    }

    /// A key table naming other fields is another map.
    #[test]
    fn a_key_table_naming_other_fields_leaves_the_publish() {
        let mut ir = inlined();
        ir.soroban_facts.as_mut().unwrap().types.events[0].params[1].name = "other".into();
        assert!(!ContractEventPass.run(&mut ir).changed);
    }

    /// The map read anywhere else cannot go with the publish.
    #[test]
    fn a_data_map_read_elsewhere_leaves_the_publish() {
        let mut ir = inlined();
        let f = &mut ir.functions[0];
        let id = ValueId::from_index(f.bindings.len() as u32);
        f.bindings.push(Binding::new(
            id,
            IrType::Unknown(sordec_common::UnknownReason::InsufficientEvidence),
            store(8, 64),
            Provenance::new("seed", ProvenanceSource::DataFlow, "seed"),
        ));
        f.blocks.iter_mut().next().unwrap().1.bindings.push(id);
        assert!(!ContractEventPass.run(&mut ir).changed);
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
