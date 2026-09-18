//! Recover a `#[contracttype]` struct decode as the typed value and its
//! field accesses.
//!
//! # The shape
//!
//! `let cb: ClaimableBalance = e.storage().instance().get(&key).unwrap();`
//! then `cb.time_bound` is two lines of source. The derived `TryFromVal`
//! that `#[contracttype]` generates unpacks the map into a frame of `Val`
//! slots, one per field in the order of a key table in rodata, and then
//! decodes each slot by its field type:
//!
//! ```text
//! map_unpack_to_linear_memory(map, &KEYS, fp, 4)   ← KEYS = ["amount", "claimants", "time_bound", "token"]
//! v49 = load fp+0      → cb.amount    (then the i128 decode helper)
//! v55 = load fp+8      → cb.claimants (then `!has_tag(VecObject)`)
//! v65 = load fp+16     → cb.time_bound (then the nested TimeBound decode)
//! v71 = load fp+24     → cb.token     (then `!has_tag(AddressObject)`)
//! ```
//!
//! # What this pass does
//!
//! It reads the key table, finds the one declared struct whose field
//! names are exactly those keys, and rewrites: the unpack becomes nothing,
//! each slot load becomes a field access on the map value, and the map
//! value itself is typed as the struct. The per-field decodes that follow
//! are then the shapes the other elisions already own — the wide codec for
//! an `i128` field, the tag-guard elision for an `Address` or `Vec` — and
//! they get a value whose type is proven rather than a load they cannot
//! see through.
//!
//! # Why the rewrite is exact
//!
//! The re-emitted crate re-declares the struct with `#[contracttype]`, so
//! the derived conversion, key table, unpack and per-field checks are all
//! regenerated from `let cb: ClaimableBalance = …`. Same argument as every
//! marshalling elision: the check is relocated into derived code, not
//! removed. What licenses it here is the key table — a struct is named
//! only when its field set matches the keys exactly, and a `Val` of
//! unknown provenance is left alone: it must be a host operation's result
//! (the decode is then the proof of the stored type), an entrypoint
//! parameter declared with the type, or a field of a struct already
//! recovered this way.

use std::collections::{BTreeMap, HashMap};

use sordec_common::{FuncId, TypeId, ValueId};
use sordec_ir::{
    Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, Literal, MapOpKind, SemanticOp,
    StructDef, UnionDef, WasmOpcodeKind,
};

use super::{apply_elisions, metrics, sret, Elision};
use crate::dataflow::{canon_addr, resolve_use, trace_int, trace_u32val, CallIndex};
use crate::pass::{Pass, PassResult};
use crate::type_infer::known_of_type_ref;

/// Pass name — also the provenance `pass` field for every elision.
pub const PASS_NAME: &str = "marshalling-udt-decode";

/// Bytes per `Val` slot in the unpacked frame.
const SLOT: u32 = 8;

/// Recovers `#[contracttype]` struct decodes.
#[derive(Debug, Default, Clone, Copy)]
pub struct UdtDecodePass;

impl Pass<HighIr> for UdtDecodePass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let Some(facts) = ir.soroban_facts.as_ref() else {
            return result;
        };
        let structs: Vec<StructDef> = facts.types.structs.clone();
        if structs.is_empty() {
            return result;
        }
        let memory = ir.memory.clone();
        // What each helper's callers pass for each parameter, when every
        // caller agrees on a struct type. A helper decoding a field of a
        // struct its caller recovered has no signature to consult; the
        // callers are its evidence.
        let param_types = caller_param_types(ir);
        let unions: Vec<UnionDef> = facts.types.unions.clone();
        // Helpers whose own body has already been recognised as a struct
        // decode, so their out-parameter can be read as the struct's
        // fields at every call site.
        let helpers: HashMap<FuncId, DecoderHelper> = ir
            .functions
            .iter()
            .filter_map(|f| classify_helper(f, &structs, &unions).map(|h| (f.id, h)))
            .collect();
        for func in &mut ir.functions {
            let planned = plan(func, &memory, &structs, &unions, &param_types, &helpers);
            if planned.elisions.is_empty() {
                continue;
            }
            result.changed = true;
            for el in &planned.elisions {
                result.metrics.increment(el.metric, 1);
            }
            // The derived `Result` test on a niche-carrying field, first:
            // `strip` rewrites the region tree and must see the
            // condition bindings as they are.
            if !planned.guards.is_empty() {
                let empty = super::guard::empty_blocks(func);
                let region = std::mem::replace(&mut func.region, sordec_ir::Region::Unreachable);
                let mut stripped = 0_i64;
                func.region = super::guard::strip(region, &planned.guards, &empty, &mut stripped);
                result.metrics.increment(metrics::GUARDS_ELIDED, stripped);
            }
            apply_elisions(func, PASS_NAME, planned.elisions);
            // Type-only: the value's own latest note stays the recognizer
            // that produced it.
            for (v, ty) in planned.typed {
                if let Some(b) = func.bindings.get_mut(v) {
                    b.ty = ty;
                }
            }
        }
        result
    }
}

/// Everything one caller's walk decided.
struct Planned {
    elisions: Vec<Elision>,
    typed: Vec<(ValueId, IrType)>,
    /// Guard conditions (in `guard::strip`'s shape) that test a niche
    /// discriminant the collapse has just made a field.
    guards: HashMap<ValueId, String>,
}

/// One decode whose result is live in the caller's frame: an unpack's
/// slot region, or a helper's out-parameter.
struct Frame<'a> {
    base: ValueId,
    start: u32,
    size: u32,
    /// The unpack or the helper call, elided once a slot was read.
    producer: ValueId,
    map: ValueId,
    def: &'a StructDef,
    /// Byte offset -> field name.
    fields: BTreeMap<u32, String>,
    /// Offsets holding a `Result` discriminant, read as the Ok value.
    discs: Vec<u32>,
    consumed: bool,
}

/// `(helper, parameter index) -> the struct type every caller passes`.
fn caller_param_types(ir: &HighIr) -> HashMap<(FuncId, usize), TypeId> {
    let calls = CallIndex::build(ir);
    let mut out: HashMap<(FuncId, usize), TypeId> = HashMap::new();
    for callee in &ir.functions {
        let sites = calls.callers_of(callee.id);
        if sites.is_empty() || callee.signature.is_some() {
            continue;
        }
        for index in 0..callee.params.len() {
            let mut agreed: Option<TypeId> = None;
            let mut ok = true;
            for site in sites {
                let Some(caller) = ir.function(site.caller) else {
                    ok = false;
                    break;
                };
                let Some(Expr::Call { args, .. }) = caller.bindings.get(site.call).map(|b| &b.expr) else {
                    ok = false;
                    break;
                };
                let ty = args.get(index).and_then(|a| udt_of(caller, resolve_use(caller, *a)));
                match (ty, agreed) {
                    (Some(t), None) => agreed = Some(t),
                    (Some(t), Some(prev)) if t == prev => {}
                    _ => {
                        ok = false;
                        break;
                    }
                }
            }
            if ok && let Some(t) = agreed {
                out.insert((callee.id, index), t);
            }
        }
    }
    out
}

/// The struct a caller's value is known to be: typed on its binding by an
/// earlier decode, or declared by the caller's own `contractspecv0`
/// signature when the value is one of its parameters.
fn udt_of(func: &HighFunction, value: ValueId) -> Option<TypeId> {
    if let Some(b) = func.bindings.get(value)
        && let IrType::Known(KnownType::UserDefined(id)) = &b.ty
    {
        return Some(*id);
    }
    let sig = func.signature.as_ref()?;
    let index = func.params.iter().position(|p| *p == value)?;
    match known_of_type_ref(&sig.inputs.get(index)?.ty)? {
        KnownType::UserDefined(id) => Some(id),
        _ => None,
    }
}

fn plan<'a>(
    func: &HighFunction,
    memory: &sordec_ir::MemoryImage,
    structs: &'a [StructDef],
    unions: &[UnionDef],
    param_types: &HashMap<(FuncId, usize), TypeId>,
    helpers: &HashMap<FuncId, DecoderHelper>,
) -> Planned {
    let mut elisions = Vec::new();
    let mut typed = Vec::new();
    let mut guards = HashMap::new();
    let mut active: Vec<Frame<'a>> = Vec::new();
    let mut finished: Vec<Frame<'a>> = Vec::new();
    // Loads rebound to a field, with the field's type, for the niche test.
    let mut rebound: Vec<(ValueId, KnownType)> = Vec::new();
    let overlaps = |f: &Frame<'_>, base: ValueId, off: u32| {
        f.base == base && off >= f.start && off < f.start + f.size
    };

    for id in sret::emission_order(func) {
        let Some(binding) = func.bindings.get(id) else {
            continue;
        };
        match &binding.expr {
            Expr::Semantic(SemanticOp::Known(KnownOp::MapOp {
                kind: MapOpKind::UnpackToLinearMemory,
                args,
            })) => {
                let Some((map, keys_pos, vals, len)) = unpack_operands(func, args) else {
                    continue;
                };
                let Some(keys) = read_keys(memory, keys_pos, len) else {
                    continue;
                };
                let Some(def) = struct_for(structs, &keys) else {
                    continue;
                };
                let map = resolve_use(func, map);
                let Some(evidence) = value_evidence(func, map, def.id, param_types) else {
                    continue;
                };
                let (base, start) = canon_addr(func, vals);
                // A second decode into the same region displaces the first.
                let (dropped, kept): (Vec<_>, Vec<_>) =
                    active.drain(..).partition(|f| f.base == base && f.start == start);
                active = kept;
                finished.extend(dropped);
                typed.push((map, evidence));
                let fields = keys.into_iter().enumerate().map(|(i, k)| (SLOT * i as u32, k)).collect();
                active.push(Frame {
                    base,
                    start,
                    size: SLOT * len,
                    producer: id,
                    map,
                    def,
                    fields,
                    discs: Vec::new(),
                    consumed: false,
                });
            }
            Expr::Call { target, args } => {
                for a in args {
                    let (b, o) = canon_addr(func, *a);
                    let (dropped, kept): (Vec<_>, Vec<_>) = active.drain(..).partition(|f| overlaps(f, b, o));
                    active = kept;
                    finished.extend(dropped);
                }
                // A helper-shaped decode: its out-parameter now holds the
                // struct's fields, provided the value it was handed is
                // already proven to be that struct.
                let Some(h) = helpers.get(target) else { continue };
                if args.len() != 2 {
                    trace(func, "helper call arity");
                    continue;
                }
                let map = resolve_use(func, args[1]);
                if udt_of(func, map) != Some(h.ty) {
                    trace(func, &format!("helper call: value {:?} is {:?}, wanted {:?}", map, udt_of(func, map), h.ty));
                    continue;
                }
                let Some(def) = structs.iter().find(|s| s.id == h.ty) else { trace(func, "helper struct missing"); continue };
                trace(func, &format!("helper frame claimed for func_{}", sordec_common::IrId::index(*target)));
                let (base, start) = canon_addr(func, args[0]);
                active.push(Frame {
                    base,
                    start,
                    size: h.size,
                    producer: id,
                    map,
                    def,
                    fields: h.fields.clone(),
                    discs: h.discs.clone(),
                    consumed: false,
                });
            }
            Expr::Load { addr, offset, .. } => {
                let (b, o) = canon_addr(func, *addr);
                let o = o.wrapping_add(*offset);
                let Some(frame) = active.iter_mut().find(|f| overlaps(f, b, o)) else {
                    continue;
                };
                let rel = o - frame.start;
                if frame.discs.contains(&rel) {
                    frame.consumed = true;
                    elisions.push(Elision {
                        id,
                        expr: Expr::Literal(ok_discriminant(&binding.ty)),
                        ty: None,
                        note: format!(
                            "derived `{}` decode discriminant is Ok: the value was proven at its boundary",
                            frame.def.name
                        ),
                        metric: metrics::UDT_FIELDS_RECOVERED,
                    });
                    continue;
                }
                let Some(field) = frame.fields.get(&rel) else { continue };
                let known = frame
                    .def
                    .fields
                    .iter()
                    .find(|f| f.name == *field)
                    .and_then(|f| known_of_type_ref(&f.ty));
                if let Some(k) = &known {
                    rebound.push((id, k.clone()));
                }
                frame.consumed = true;
                elisions.push(Elision {
                    id,
                    expr: Expr::Field { base: frame.map, field: field.clone() },
                    ty: known.map(IrType::Known),
                    note: format!("{}.{field}: slot +{rel} of the derived struct decode", frame.def.name),
                    metric: metrics::UDT_FIELDS_RECOVERED,
                });
            }
            Expr::Store { addr, offset, .. } => {
                let (b, o) = canon_addr(func, *addr);
                let o = o.wrapping_add(*offset);
                let (dropped, kept): (Vec<_>, Vec<_>) = active.drain(..).partition(|f| overlaps(f, b, o));
                active = kept;
                finished.extend(dropped);
            }
            _ => {}
        }
    }
    finished.extend(active);
    for frame in finished.into_iter().filter(|f| f.consumed) {
        let is_call = matches!(func.bindings.get(frame.producer).map(|b| &b.expr), Some(Expr::Call { .. }));
        let (note, metric) = if is_call {
            (
                format!("call to the derived `{}` decode helper, elided with its out-parameter", frame.def.name),
                metrics::UDT_HELPERS_COLLAPSED,
            )
        } else {
            (
                format!("derived `{}` decode: the unpack, elided with its slots", frame.def.name),
                metrics::UDT_DECODES_COLLAPSED,
            )
        };
        elisions.push(Elision {
            id: frame.producer,
            expr: Expr::Literal(Literal::Unit),
            ty: Some(IrType::Known(KnownType::Unit)),
            note,
            metric,
        });
    }

    // The derived `Result` test on a niche: rustc folds the discriminant
    // into a unit-enum field, whose next code past the variants means
    // `Err`. The caller compares the field's code against that constant
    // and traps. With the field recovered the check is the derived
    // `TryFromVal`'s, relocated with the rest.
    for (load, known) in &rebound {
        let KnownType::UserDefined(uid) = known else { continue };
        let Some(union) = unions.iter().find(|u| u.id == *uid) else { continue };
        if union.cases.is_empty() || union.cases.iter().any(|c| !c.fields.is_empty()) {
            continue;
        }
        let niche = union.cases.len() as i128;
        for (cid, cb) in func.bindings.iter() {
            let Expr::Binary { op: sordec_ir::BinaryOp::Eq, lhs, rhs } = &cb.expr else { continue };
            let (l, r) = (resolve_use(func, *lhs), resolve_use(func, *rhs));
            let hit = (l == *load && crate::dataflow::trace_int(func, r) == Some(niche))
                || (r == *load && crate::dataflow::trace_int(func, l) == Some(niche));
            if hit {
                guards.insert(
                    cid,
                    format!("derived `Result` niche test on {}: regenerated by `TryFromVal`", union.name),
                );
            }
        }
    }
    Planned { elisions, typed, guards }
}

/// A zero discriminant in the width the load claimed.
fn ok_discriminant(ty: &IrType) -> Literal {
    match ty {
        IrType::Known(KnownType::I64 | KnownType::U64)
        | IrType::Inferred(KnownType::I64 | KnownType::U64) => Literal::I64(0),
        _ => Literal::I32(0),
    }
}

/// `(map, keys_pos, vals_ptr, len)` from the host call's operands, in
/// either the four-operand host order or the five-operand wrapper order.
fn unpack_operands(func: &HighFunction, args: &[ValueId]) -> Option<(ValueId, u32, ValueId, u32)> {
    match args {
        [map, keys, vals, len] => {
            let keys = trace_u32val(func, *keys)?;
            let len = trace_u32val(func, *len)?;
            Some((*map, keys, raw_address(func, *vals), len))
        }
        [map, keys, klen, vals, vlen] => {
            let keys = trace_u32val(func, *keys)?;
            let (klen, vlen) = (trace_u32val(func, *klen)?, trace_u32val(func, *vlen)?);
            if klen != vlen {
                return None;
            }
            Some((*map, keys, raw_address(func, *vals), klen))
        }
        _ => None,
    }
}

/// The frame address behind a `U32Val`-encoded, width-converted pointer.
pub(crate) fn raw_address(func: &HighFunction, v: ValueId) -> ValueId {
    let mut cur = resolve_use(func, v);
    for _ in 0..4 {
        match func.bindings.get(cur).map(|b| &b.expr) {
            Some(Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { value, .. }))) => {
                cur = resolve_use(func, *value);
            }
            Some(Expr::Unknown { op_kind: WasmOpcodeKind::Conversion, args, .. }) if args.len() == 1 => {
                cur = resolve_use(func, args[0]);
            }
            Some(Expr::Unary { op: sordec_ir::UnaryOp::Wrap32 | sordec_ir::UnaryOp::ExtendU32 | sordec_ir::UnaryOp::ExtendS32, value }) => cur = resolve_use(func, *value),
            _ => break,
        }
    }
    cur
}

/// The key table: `len` entries of `(u32 pointer, u32 length)` naming the
/// fields, read as UTF-8 identifiers.
pub(crate) fn read_keys(memory: &sordec_ir::MemoryImage, pos: u32, len: u32) -> Option<Vec<String>> {
    let table = memory.read(pos, len.checked_mul(8)?)?;
    let mut keys = Vec::with_capacity(len as usize);
    for entry in table.as_chunks::<8>().0 {
        let ptr = u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]);
        let n = u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]);
        let text = core::str::from_utf8(memory.read(ptr, n)?).ok()?;
        if text.is_empty() || !text.bytes().all(|b| b == b'_' || b.is_ascii_alphanumeric()) {
            return None;
        }
        keys.push(text.to_owned());
    }
    Some(keys)
}

/// The one declared struct whose field names are exactly `keys`.
pub(crate) fn struct_for<'a>(structs: &'a [StructDef], keys: &[String]) -> Option<&'a StructDef> {
    let mut want: Vec<&str> = keys.iter().map(String::as_str).collect();
    want.sort_unstable();
    let mut hits = structs.iter().filter(|s| {
        let mut have: Vec<&str> = s.fields.iter().map(|f| f.name.as_str()).collect();
        have.sort_unstable();
        have == want
    });
    let first = hits.next()?;
    if hits.next().is_some() {
        return None;
    }
    Some(first)
}

/// Why the map value may be read as the struct: a host operation's result
/// (the decode is the proof of what was stored), an entrypoint parameter
/// declared with the type, or a field of a struct recovered this way.
fn value_evidence(
    func: &HighFunction,
    map: ValueId,
    id: TypeId,
    param_types: &HashMap<(FuncId, usize), TypeId>,
) -> Option<IrType> {
    let ty = IrType::Known(KnownType::UserDefined(id));
    if let Some(index) = func.params.iter().position(|p| *p == map) {
        if let Some(sig) = func.signature.as_ref() {
            let declared = known_of_type_ref(&sig.inputs.get(index)?.ty)?;
            return (declared == KnownType::UserDefined(id)).then_some(ty);
        }
        // A helper parameter: every caller passes a value already proven
        // to be this struct.
        if param_types.get(&(func.id, index)) == Some(&id) {
            return Some(ty);
        }
    }
    let binding = func.bindings.get(map)?;
    // A helper parameter the caller already proved: the type travels in
    // on the binding, planted by the caller-side decode that passed a
    // field of a recovered struct.
    if let IrType::Known(KnownType::UserDefined(known)) = &binding.ty
        && *known == id
    {
        return Some(ty);
    }
    match &binding.expr {
        Expr::Semantic(SemanticOp::Known(_)) | Expr::Field { .. } => Some(ty),
        _ => None,
    }
}

// ---------------------------------------------------------------------
// Helper-shape decoders
// ---------------------------------------------------------------------

/// A helper proven to be `<T as TryFromVal<Env, Val>>::try_from_val` for a
/// struct `T`, once its own body has been recognised: it takes
/// `(out, val)`, `val` is typed as the struct by the inner decode, it
/// touches no host state, and every slot it writes through `out` is
/// computed from exactly one field of `val` — or is a constant, which
/// makes it the `Result` discriminant.
///
/// rustc may fold the discriminant into a field with spare values (a unit
/// enum's next code means `Err`), so a field slot's arms can include a
/// constant beside the field-derived value. The caller's check of that
/// constant is the derived `Result` test, stripped with the collapse.
struct DecoderHelper {
    ty: TypeId,
    fields: BTreeMap<u32, String>,
    discs: Vec<u32>,
    size: u32,
}

fn classify_helper(func: &HighFunction, structs: &[StructDef], unions: &[UnionDef]) -> Option<DecoderHelper> {
    if func.signature.is_some() || func.params.len() != 2 {
        { trace(func, "not a two-parameter helper"); return None; }
    }
    let (out, val) = (func.params[0], func.params[1]);
    let IrType::Known(KnownType::UserDefined(ty)) = func.bindings.get(val)?.ty else {
        trace(func, "value parameter not yet typed as a struct");
        return None;
    };
    let Some(def) = structs.iter().find(|s| s.id == ty) else {
        trace(func, &format!("typed as {ty:?} but no struct has that id"));
        return None;
    };

    let mut slots: BTreeMap<u32, Vec<ValueId>> = BTreeMap::new();
    let mut size = 0_u32;
    for id in sret::emission_order(func) {
        let binding = func.bindings.get(id)?;
        match &binding.expr {
            Expr::Store { addr, value, offset, width } if resolve_use(func, *addr) == out => {
                slots.entry(*offset).or_default().push(*value);
                size = size.max(offset + width.bytes());
            }
            Expr::Call { target, .. } => {
                trace(func, &format!("still calls func_{}", sordec_common::IrId::index(*target)));
                return None;
            }
            Expr::IndirectCall { .. } => {
                trace(func, "indirect call");
                return None;
            }
            other => {
                let mut escapes = false;
                other.for_each_value_use(|u| {
                    if resolve_use(func, u) == out {
                        escapes = true;
                    }
                });
                if escapes || touches_state(other) {
                    { trace(func, "out-pointer escapes or the body touches host state"); return None; }
                }
            }
        }
    }
    let mut region_reads = false;
    func.region.for_each_value_use(|u| {
        if resolve_use(func, u) == out {
            region_reads = true;
        }
    });
    if region_reads || slots.is_empty() {
        { trace(func, "region reads the out-pointer, or nothing is stored through it"); return None; }
    }

    let mut fields: BTreeMap<u32, String> = BTreeMap::new();
    let mut discs: Vec<u32> = Vec::new();
    for (offset, values) in &slots {
        let mut names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let mut consts: std::collections::BTreeSet<i128> = std::collections::BTreeSet::new();
        let mut arms: Vec<ValueId> = Vec::new();
        for v in values {
            flat_arms(func, *v, 6, &mut arms);
        }
        for arm in &arms {
            match field_source(func, *arm, val) {
                Some(name) => {
                    names.insert(name);
                }
                None => match trace_int(func, *arm) {
                    Some(n) => {
                        consts.insert(n);
                    }
                    None => {
                        trace(func, &format!("slot +{offset}: arm {arm:?} is neither a field nor a constant"));
                        return None;
                    }
                },
            }
        }
        match names.len() {
            1 => {
                fields.insert(*offset, names.pop_first()?);
            }
            // Every arm a constant. A unit enum's codes with its niche —
            // the code past the last variant, meaning `Err` — name the
            // enum field the dispatch on that field selected; anything
            // else is the `Result` discriminant.
            0 if !arms.is_empty() => match niche_enum_field(def, unions, &consts, &fields) {
                Some(name) => {
                    fields.insert(*offset, name);
                }
                None => discs.push(*offset),
            },
            n => {
                trace(func, &format!("slot +{offset}: {n} field sources {names:?}, {consts:?} constants"));
                return None;
            }
        }
    }
    if fields.is_empty() || fields.values().any(|n| !def.fields.iter().any(|f| f.name == *n)) {
        { trace(func, "no slot names a declared field"); return None; }
    }
    trace(func, &format!("decoder helper for {}: fields {fields:?} discs {discs:?} size {size}", def.name));
    Some(DecoderHelper { ty, fields, discs, size })
}

/// Trace for the helper classifier and the call-site walk, printed when
/// `SORDEC_UDT_TRACE` is set: which gate declined a helper, and where a
/// call site was claimed.
#[allow(clippy::print_stderr)]
fn trace(func: &HighFunction, why: &str) {
    if std::env::var_os("SORDEC_UDT_TRACE").is_some() {
        eprintln!("udt-decode: func_{}: {why}", sordec_common::IrId::index(func.id));
    }
}

/// The per-path values of `value` through nested phis: a switch arm's
/// constant reaches the out-slot through the merge of the switch and
/// then the merge of the guards, one block parameter per level.
fn flat_arms(func: &HighFunction, value: ValueId, depth: u32, out: &mut Vec<ValueId>) {
    let id = resolve_use(func, value);
    match func.bindings.get(id).map(|b| &b.expr) {
        Some(Expr::Phi { incoming }) if depth > 0 && !incoming.is_empty() => {
            for (_, v) in incoming {
                flat_arms(func, *v, depth - 1, out);
            }
        }
        _ => out.push(id),
    }
}

/// The struct's unit-enum field a set of constant slot values stands for:
/// the enum's variant codes plus its niche (`cases.len()`, the `Err`
/// marker rustc folds into the spare code), and no other field already
/// claimed. `None` when the constants are not such a set — then the slot
/// is a plain `Result` discriminant.
fn niche_enum_field(
    def: &StructDef,
    unions: &[UnionDef],
    consts: &std::collections::BTreeSet<i128>,
    taken: &BTreeMap<u32, String>,
) -> Option<String> {
    let mut hits: Vec<String> = Vec::new();
    for field in &def.fields {
        if taken.values().any(|t| *t == field.name) {
            continue;
        }
        let Some(KnownType::UserDefined(uid)) = known_of_type_ref(&field.ty) else { continue };
        let Some(union) = unions.iter().find(|u| u.id == uid) else { continue };
        if union.cases.is_empty() || union.cases.iter().any(|c| !c.fields.is_empty()) {
            continue;
        }
        let niche = union.cases.len() as i128;
        if consts.contains(&niche) && consts.iter().all(|c| *c >= 0 && *c <= niche) {
            hits.push(field.name.clone());
        }
    }
    match hits.len() {
        1 => hits.pop(),
        _ => None,
    }
}

/// Whether an expression reaches state a decode helper never touches:
/// anything written to the host, or read from it beyond the object and
/// collection accessors a derived `TryFromVal` is built from.
fn touches_state(expr: &Expr) -> bool {
    let effects = crate::effects::expr_effects(expr);
    if effects.writes_host {
        return true;
    }
    if !effects.reads_host {
        return false;
    }
    !matches!(
        expr,
        Expr::Semantic(SemanticOp::Known(
            KnownOp::VecOp { .. }
                | KnownOp::MapOp { .. }
                | KnownOp::ValObject { .. }
                | KnownOp::ValTagCheck { .. }
                | KnownOp::ValDecodeSmall { .. }
                | KnownOp::ValEncodeSmall { .. }
                | KnownOp::SymbolDispatch { .. }
                | KnownOp::SymbolNew { .. }
        ))
    )
}

/// The one field of `val` that `value` is computed from, walking operands
/// backwards through the field's own decode (tag checks, object
/// extractors, vector reads, symbol dispatch, phis). `None` when it
/// reaches no field, or more than one.
fn field_source(func: &HighFunction, value: ValueId, val: ValueId) -> Option<String> {
    let mut found: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut seen: std::collections::HashSet<ValueId> = std::collections::HashSet::new();
    let mut queue: std::collections::VecDeque<ValueId> = std::collections::VecDeque::from([value]);
    while let Some(v) = queue.pop_front() {
        let id = resolve_use(func, v);
        if !seen.insert(id) {
            continue;
        }
        if seen.len() > 96 {
            return None;
        }
        let Some(binding) = func.bindings.get(id) else {
            continue;
        };
        match &binding.expr {
            Expr::Field { base, field } if resolve_use(func, *base) == val => {
                found.insert(field.clone());
            }
            Expr::Literal(_) => {}
            other => other.for_each_value_use(|u| queue.push_back(u)),
        }
    }
    if found.len() == 1 { found.pop_first() } else { None }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, load, module, store, v};
    use sordec_common::IrId;
    use sordec_ir::{
        DataSegment, KnownTier, MemoryImage, PrimitiveType, SorobanFacts, StorageTier, StructField,
        TypeRef, TypeRegistry,
    };

    /// `KEYS` at 2000: two entries pointing at "amount" (2100) and "token" (2110).
    fn memory() -> MemoryImage {
        let mut table = Vec::new();
        for (ptr, n) in [(2100u32, 6u32), (2110, 5)] {
            table.extend_from_slice(&ptr.to_le_bytes());
            table.extend_from_slice(&n.to_le_bytes());
        }
        MemoryImage::from_segments(vec![
            DataSegment { offset: 2000, bytes: table },
            DataSegment { offset: 2100, bytes: b"amount".to_vec() },
            DataSegment { offset: 2110, bytes: b"token".to_vec() },
        ])
    }

    fn registry() -> Vec<StructDef> {
        vec![StructDef {
            id: TypeId::new(7),
            name: "Balance".to_string(),
            fields: vec![
                StructField { name: "amount".to_string(), ty: TypeRef::Primitive(PrimitiveType::I128) },
                StructField { name: "token".to_string(), ty: TypeRef::Primitive(PrimitiveType::Address) },
            ],
        }]
    }

    fn u32val(n: u32) -> Expr {
        Expr::Literal(Literal::U32(n))
    }

    /// A storage read, the unpack into `fp`, and loads of both slots.
    fn decoder() -> HighFunction {
        func_with(
            vec![
                Expr::Phi { incoming: vec![] }, // v0 fp
                Expr::Phi { incoming: vec![] }, // v1 key
                Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet {
                    tier: StorageTier::Known(KnownTier::Instance),
                    durability: v(1),
                    key: v(1),
                    resolved_key: None,
                    missing: sordec_ir::Missing::Option,
                })), // v2 map
                u32val(2000), // v3 keys
                u32val(2),    // v4 len
                Expr::Semantic(SemanticOp::Known(KnownOp::MapOp {
                    kind: MapOpKind::UnpackToLinearMemory,
                    args: vec![v(2), v(3), v(0), v(4)],
                })), // v5
                load(v(0), 0), // v6 amount
                load(v(0), 8), // v7 token
            ],
            vec![v(0), v(1)],
            vec![2, 3, 4, 5, 6, 7],
        )
    }

    fn ir(f: HighFunction) -> HighIr {
        let mut m = module(vec![f]);
        m.memory = memory();
        m.soroban_facts = Some(SorobanFacts {
            functions: std::collections::BTreeMap::new(),
            types: TypeRegistry { structs: registry(), ..Default::default() },
            contract_meta: std::collections::BTreeMap::new(),
            env_meta: sordec_ir::EnvCompatibility::default(),
        });
        m
    }

    fn expr_at(m: &HighIr, value: u32) -> &Expr {
        &m.functions[0].bindings.get(v(value)).unwrap().expr
    }

    #[test]
    fn the_key_table_names_the_struct_and_its_slots_become_fields() {
        let mut m = ir(decoder());
        let r = UdtDecodePass.run(&mut m);
        assert!(r.changed);
        assert!(matches!(expr_at(&m, 6), Expr::Field { base, field } if *base == v(2) && field == "amount"));
        assert!(matches!(expr_at(&m, 7), Expr::Field { base, field } if *base == v(2) && field == "token"));
        assert!(matches!(expr_at(&m, 5), Expr::Literal(Literal::Unit)));
        assert!(matches!(
            m.functions[0].bindings.get(v(2)).unwrap().ty,
            IrType::Known(KnownType::UserDefined(id)) if id == TypeId::new(7)
        ));
        assert!(matches!(m.functions[0].bindings.get(v(6)).unwrap().ty, IrType::Known(KnownType::I128)));
    }

    /// A key set no declared struct has is not a struct decode.
    #[test]
    fn unknown_keys_decline() {
        let mut m = ir(decoder());
        m.soroban_facts.as_mut().unwrap().types.structs[0].fields[0].name = "value".to_string();
        assert!(!UdtDecodePass.run(&mut m).changed);
    }

    /// A map of unknown provenance has no boundary to relocate the check to.
    #[test]
    fn an_unproven_map_declines() {
        let mut f = decoder();
        f.bindings.get_mut(v(2)).unwrap().expr = load(v(0), 64);
        let mut m = ir(f);
        assert!(!UdtDecodePass.run(&mut m).changed);
    }


    /// A helper-shaped decoder: `(out, val)` with `val` already typed as
    /// the struct, storing `val.token` (through a tag check the field's own
    /// decode makes) at `out+0` and a `Result` discriminant at `out+8`.
    fn decoder_helper(id: u32) -> HighFunction {
        let mut f = func_with(
            vec![
                Expr::Phi { incoming: vec![] },                               // v0 out
                Expr::Phi { incoming: vec![] },                               // v1 val
                Expr::Field { base: v(1), field: "token".to_string() },      // v2
                store(v(0), v(2), 0),                                         // v3
                Expr::Literal(Literal::I64(0)),                               // v4
                store(v(0), v(4), 8),                                         // v5
            ],
            vec![v(0), v(1)],
            vec![2, 3, 4, 5],
        );
        f.id = FuncId::from_index(id);
        f.bindings.get_mut(v(1)).unwrap().ty = IrType::Known(KnownType::UserDefined(TypeId::new(7)));
        f
    }

    /// An entrypoint `f(b: Balance)` calling the helper on its parameter
    /// and reading both out slots.
    fn helper_caller(id: u32, helper: u32) -> HighFunction {
        let mut f = func_with(
            vec![
                Expr::Phi { incoming: vec![] },                               // v0 b
                Expr::Phi { incoming: vec![] },                               // v1 fp
                Expr::Call { target: FuncId::from_index(helper), args: vec![v(1), v(0)] }, // v2
                load(v(1), 0),                                                // v3 token
                load(v(1), 8),                                                // v4 disc
            ],
            vec![v(0)],
            vec![2, 3, 4],
        );
        f.id = FuncId::from_index(id);
        f.signature = Some(sordec_ir::FunctionSignature {
            name: "f".to_string(),
            inputs: vec![sordec_ir::FunctionParam {
                name: "b".to_string(),
                ty: TypeRef::UserDefined(TypeId::new(7)),
            }],
            outputs: vec![],
        });
        f
    }

    #[test]
    fn a_helper_shaped_decoder_collapses_at_its_call_site() {
        // Functions are looked up by index, so the caller sits at 0 and
        // the helper at 1, matching their ids.
        let mut m = ir(helper_caller(0, 1));
        m.functions.push(decoder_helper(1));
        let r = UdtDecodePass.run(&mut m);
        assert!(r.changed);
        let caller = m.function(FuncId::from_index(0)).unwrap();
        assert!(matches!(&caller.bindings.get(v(3)).unwrap().expr, Expr::Field { base, field } if *base == v(0) && field == "token"));
        // The load's own type was unknown, so the Ok discriminant takes the
        // narrower literal.
        assert!(matches!(caller.bindings.get(v(4)).unwrap().expr, Expr::Literal(Literal::I32(0))));
        assert!(matches!(caller.bindings.get(v(2)).unwrap().expr, Expr::Literal(Literal::Unit)));
        assert_eq!(r.metrics.get(metrics::UDT_HELPERS_COLLAPSED), Some(1));
    }

    #[test]
    fn the_pass_is_idempotent() {
        let mut m = ir(decoder());
        assert!(UdtDecodePass.run(&mut m).changed);
        assert!(!UdtDecodePass.run(&mut m).changed);
    }
}
