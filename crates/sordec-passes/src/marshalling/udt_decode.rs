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

use std::collections::HashMap;

use sordec_common::{FuncId, TypeId, ValueId};
use sordec_ir::{
    Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, Literal, MapOpKind, SemanticOp,
    StructDef, WasmOpcodeKind,
};

use super::{apply_elisions, metrics, sret, Elision};
use crate::dataflow::{canon_addr, resolve_use, trace_u32val, CallIndex};
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
        for func in &mut ir.functions {
            let (elisions, typed) = plan(func, &memory, &structs, &param_types);
            if elisions.is_empty() {
                continue;
            }
            result.changed = true;
            for el in &elisions {
                result.metrics.increment(el.metric, 1);
            }
            apply_elisions(func, PASS_NAME, elisions);
            // Type-only: the value's own latest note stays the recognizer
            // that produced it.
            for (v, ty) in typed {
                if let Some(b) = func.bindings.get_mut(v) {
                    b.ty = ty;
                }
            }
        }
        result
    }
}

/// One unpack whose slots are live in the caller's frame.
struct Frame<'a> {
    base: ValueId,
    start: u32,
    unpack: ValueId,
    map: ValueId,
    def: &'a StructDef,
    /// Field name per slot, in key-table order.
    slots: Vec<String>,
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

fn plan(
    func: &HighFunction,
    memory: &sordec_ir::MemoryImage,
    structs: &[StructDef],
    param_types: &HashMap<(FuncId, usize), TypeId>,
) -> (Vec<Elision>, Vec<(ValueId, IrType)>) {
    let mut elisions = Vec::new();
    let mut typed = Vec::new();
    let mut active: Vec<Frame<'_>> = Vec::new();
    let mut finished: Vec<Frame<'_>> = Vec::new();
    let overlaps = |f: &Frame<'_>, base: ValueId, off: u32| {
        f.base == base && off >= f.start && off < f.start + SLOT * f.slots.len() as u32
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
                // A second unpack into the same region displaces the first.
                let (dropped, kept): (Vec<_>, Vec<_>) =
                    active.drain(..).partition(|f| f.base == base && f.start == start);
                active = kept;
                finished.extend(dropped);
                typed.push((map, evidence));
                active.push(Frame { base, start, unpack: id, map, def, slots: keys, consumed: false });
            }
            Expr::Call { args, .. } => {
                for a in args {
                    let (b, o) = canon_addr(func, *a);
                    let (dropped, kept): (Vec<_>, Vec<_>) = active.drain(..).partition(|f| overlaps(f, b, o));
                    active = kept;
                    finished.extend(dropped);
                }
            }
            Expr::Load { addr, offset, .. } => {
                let (b, o) = canon_addr(func, *addr);
                let o = o.wrapping_add(*offset);
                let Some(frame) = active.iter_mut().find(|f| overlaps(f, b, o)) else {
                    continue;
                };
                let rel = o - frame.start;
                if rel % SLOT != 0 {
                    continue;
                }
                let index = (rel / SLOT) as usize;
                let Some(field) = frame.slots.get(index) else { continue };
                let ty = frame
                    .def
                    .fields
                    .iter()
                    .find(|f| f.name == *field)
                    .and_then(|f| known_of_type_ref(&f.ty))
                    .map(IrType::Known);
                frame.consumed = true;
                elisions.push(Elision {
                    id,
                    expr: Expr::Field { base: frame.map, field: field.clone() },
                    ty,
                    note: format!("{}.{field}: slot {index} of the derived struct decode", frame.def.name),
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
        elisions.push(Elision {
            id: frame.unpack,
            expr: Expr::Literal(Literal::Unit),
            ty: Some(IrType::Known(KnownType::Unit)),
            note: format!("derived `{}` decode: the unpack, elided with its slots", frame.def.name),
            metric: metrics::UDT_DECODES_COLLAPSED,
        });
    }
    (elisions, typed)
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
fn raw_address(func: &HighFunction, v: ValueId) -> ValueId {
    let mut cur = resolve_use(func, v);
    for _ in 0..4 {
        match func.bindings.get(cur).map(|b| &b.expr) {
            Some(Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { value, .. }))) => {
                cur = resolve_use(func, *value);
            }
            Some(Expr::Unknown { op_kind: WasmOpcodeKind::Conversion, args, .. }) if args.len() == 1 => {
                cur = resolve_use(func, args[0]);
            }
            _ => break,
        }
    }
    cur
}

/// The key table: `len` entries of `(u32 pointer, u32 length)` naming the
/// fields, read as UTF-8 identifiers.
fn read_keys(memory: &sordec_ir::MemoryImage, pos: u32, len: u32) -> Option<Vec<String>> {
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
fn struct_for<'a>(structs: &'a [StructDef], keys: &[String]) -> Option<&'a StructDef> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, load, module, v};
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

    #[test]
    fn the_pass_is_idempotent() {
        let mut m = ir(decoder());
        assert!(UdtDecodePass.run(&mut m).changed);
        assert!(!UdtDecodePass.run(&mut m).changed);
    }
}
