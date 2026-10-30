//! Recover a `#[contracttype]` struct *literal* — the construction side of
//! [`super::udt_decode`].
//!
//! # The shape
//!
//! `State { count, last_incr }` is one expression in the source. The
//! `TryIntoVal` that `#[contracttype]` derives writes each field's `Val`
//! into a frame slot and hands the host the slot array beside a key table
//! of the field names, in rodata:
//!
//! ```text
//! store fp+0  <- val_encode<U32>(a)                 KEYS = ["count", "last_incr"]
//! store fp+8  <- val_encode<U32>(b)
//! m = map_new_from_linear_memory(&KEYS, fp, 2)   →  m = State { count: a, last_incr: b }
//! ```
//!
//! # What this pass does
//!
//! It reads the same key table [`super::udt_decode`] reads, finds the one
//! declared struct whose field names are exactly those keys, and rewrites
//! the map construction to the struct literal, taking each field's value
//! from the slot store at its offset and stripping the `Val` encode from
//! it. The stores are then dead and the frame elision drops them, along
//! with the shadow-stack bracket that reserved the slots.
//!
//! # Why the rewrite is exact
//!
//! The re-emitted crate declares the struct with `#[contracttype]`, so
//! writing the literal regenerates the derived conversion: the key table,
//! the slot stores and this very host call. The same relocation argument
//! as every marshalling elision, in the direction the decode pass does not
//! cover.
//!
//! # Gates
//!
//! - **The keys name exactly one declared struct.** A table matching no
//!   struct is left alone — it may be a `Map` the source really built. A
//!   table matching several (`StructA { f1, f2 }` beside `StructB { f1,
//!   f2 }`) is named only by where the value goes, below; with no such
//!   place it is left alone too.
//! - **Every field has a slot.** The vals array is `len` slots at 8-byte
//!   stride from the base, and every one must hold a value proven at the
//!   construction point. A missing slot means the frame analysis lost the
//!   store, and half a literal is worse than none.
//! - **The field order is the declaration's.** The key table is sorted by
//!   the derive, so the literal is spelled in the struct's own order
//!   rather than the table's.
//!
//! # Field names several structs share
//!
//! Field names are not unique across a contract's types: `{ val: u32 }`
//! is a common shape, and three structs may carry it. The key table then
//! says only "one of these". Where the value goes can say which:
//!
//! - **an entrypoint's return**, which the spec declares as one of them —
//!   bare, as a `Result`'s `Ok` (a map is never an error's encoding), or
//!   as an `Option`'s `Some` (a map is never `Void`, `None`'s encoding) —
//!   the returned value itself or, through the merges before the return,
//!   any of their arms: on its path, an arm is the value returned;
//! - **a field of a recovered struct literal**, which the outer struct's
//!   declaration gives one of them.
//!
//! Why that is exact: at those places the contract's own metadata says
//! the value *is* that struct, so the encode that produced it is that
//! struct's derive. The key table must still match it field for field —
//! the declaration picks among the candidates, it never overrides them —
//! and two places naming different structs name none.
//!
//! # A field encoded by a helper
//!
//! A `u64` field's encode is a branch (small form or object), and rustc
//! often outlines it into a helper the constructions share
//! ([`super::encode_helper`]): the field then holds `func1(x).1`, not an
//! encode this pass can see. When that helper returns, in that component
//! and on every path, the encode of its parameter as the type the struct
//! declares for the field, the component *is* `encode(x)`, and the field
//! is `x` — the same strip as the inline case. It is done on literals
//! already written: the helper is recognised only once its own frame
//! bracket is gone, a round of the group after the construction was.
//!
//! Why it is exact: the helper encodes nothing but its argument and does
//! nothing else (the recogniser's gates), so the slot holds exactly what
//! the derive writes for a field of value `x`, and the re-emitted derive
//! writes it again. The call is left in place; once the frame elision has
//! dropped the slot stores nothing reads it, and the return-encode
//! collapse's later run drops it as it drops every spent call to such a
//! helper: it has no effect to keep.
//!
//! The gate, beyond the recogniser's own: **the helper's encode type is the
//! field's declared type.** A `u64` encoder in a field declared anything
//! else is not what the derive wrote for that field, and is left as the
//! value it is.
//!
//! # The renames
//!
//! A construction is often reached through renames — the inliner's
//! `v21 = v46` where a wrapper call stood — typed `Map` while it was one.
//! A rename is the same value, so each takes the struct's type with the
//! literal. Left as `Map`, a helper returning the rename is declared to
//! return a `Map`, and every caller inherits the mistake.

use std::collections::HashMap;

use sordec_common::{IrId, Provenance, ProvenanceSource, TypeId, ValueId};
use sordec_ir::{
    CompositeType, Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, MemWidth, SemanticOp,
    StructDef, TypeRef,
};

use super::encode_helper::EncoderTable;
use super::udt_decode::{raw_address, read_keys, struct_for};
use crate::dataflow::{canon_addr, facts_at, resolve_use};
use crate::dataflow::trace_bytes::trace_u32val;
use crate::metrics_catalog::MARSHALLING_UDT_ENCODES as M_ENCODES;
use crate::pass::{Pass, PassResult};
use crate::type_infer::known_of_type_ref;

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-udt-encode";

/// Folds a derived struct encode into the struct literal it came from.
#[derive(Debug, Default, Clone, Copy)]
pub struct UdtEncodePass;

impl Pass<HighIr> for UdtEncodePass {
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
        let encoders = EncoderTable::build(ir);
        for func in &mut ir.functions {
            // A literal recovered this round declares its fields' structs,
            // which may name an inner construction the next round can
            // read. Each round rewrites at least one `MapNew`, which no
            // later round matches again, so the loop ends.
            loop {
                let declared = declared_structs(func, &structs);
                let literals: Vec<_> = func
                    .bindings
                    .iter()
                    .filter_map(|(id, _)| literal_at(func, &memory, &structs, &declared, id))
                    .collect();
                if literals.is_empty() {
                    break;
                }
                for literal in literals {
                    if write_literal(func, &structs, literal) {
                        result.metrics.increment(M_ENCODES, 1);
                        result.changed = true;
                    }
                }
            }
            if strip_helper_encodes(func, &structs, &encoders) > 0 {
                result.changed = true;
            }
            for (at, whole) in rebuilds(func, &structs) {
                if let Some(b) = func.bindings.get_mut(at) {
                    b.expr = Expr::Use(whole);
                    b.add_provenance(Provenance::new(
                        PASS_NAME,
                        ProvenanceSource::SdkPattern,
                        "a struct literal of every field of one value of that struct is the value",
                    ));
                    result.changed = true;
                }
            }
        }
        result
    }
}

/// Rewrite the construction to the literal, its renames retyped with it.
fn write_literal(func: &mut HighFunction, structs: &[StructDef], mut literal: Literal) -> bool {
    decode_constant_fields(func, structs, &mut literal);
    retype_renames(func, literal.at, &literal.ty);
    let Some(b) = func.bindings.get_mut(literal.at) else { return false };
    b.expr = Expr::Struct { fields: literal.fields };
    b.ty = literal.ty;
    b.add_provenance(Provenance::new(
        PASS_NAME,
        ProvenanceSource::SdkPattern,
        if literal.named_by_use {
            "the derived struct encode, as the literal of the one struct its destination declares among those its key table fits"
        } else {
            "the derived struct encode: its key table and slot stores, as the literal"
        },
    ));
    true
}

/// Whether the map construction at `at` is struct `id`'s derive: its key
/// table fits that struct's fields and every slot is proven. For a
/// destination this pass cannot see — a tuple's component, known only
/// once the tuple's buffer is read back, after this pass has run.
pub(super) fn encodes(
    func: &HighFunction,
    memory: &sordec_ir::MemoryImage,
    structs: &[StructDef],
    at: ValueId,
    id: TypeId,
) -> bool {
    let declared = HashMap::from([(at, id)]);
    literal_at(func, memory, structs, &declared, at)
        .is_some_and(|l| l.ty == IrType::Known(KnownType::UserDefined(id)))
}

/// The field values of struct `id`'s literal at `at`, when [`encodes`]
/// holds: what [`rebuild_as`] would write, read without writing it.
pub(super) fn literal_fields(
    func: &HighFunction,
    memory: &sordec_ir::MemoryImage,
    structs: &[StructDef],
    at: ValueId,
    id: TypeId,
) -> Option<Vec<(String, ValueId)>> {
    let declared = HashMap::from([(at, id)]);
    literal_at(func, memory, structs, &declared, at)
        .filter(|l| l.ty == IrType::Known(KnownType::UserDefined(id)))
        .map(|l| l.fields)
}

/// Rewrite the map construction at `at` to struct `id`'s literal, when
/// [`encodes`] holds.
pub(super) fn rebuild_as(
    func: &mut HighFunction,
    memory: &sordec_ir::MemoryImage,
    structs: &[StructDef],
    at: ValueId,
    id: TypeId,
) -> bool {
    let declared = HashMap::from([(at, id)]);
    match literal_at(func, memory, structs, &declared, at) {
        Some(l) if l.ty == IrType::Known(KnownType::UserDefined(id)) => write_literal(func, structs, l),
        _ => false,
    }
}

/// The values a return hands back: the returned value, or, through the
/// merges before it, each of their arms.
fn returned_arms(func: &HighFunction, value: ValueId) -> Vec<ValueId> {
    let mut out = Vec::new();
    let mut work = vec![resolve_use(func, value)];
    let mut seen = std::collections::HashSet::new();
    while let Some(v) = work.pop() {
        if !seen.insert(v) {
            continue;
        }
        match func.bindings.get(v).map(|b| &b.expr) {
            Some(Expr::Phi { incoming }) if !incoming.is_empty() => {
                work.extend(incoming.iter().map(|(_, a)| resolve_use(func, *a)));
            }
            _ => out.push(v),
        }
    }
    out
}

/// The struct each value is declared to be where it goes: what an
/// entrypoint returns, where the spec names a struct (bare, as a
/// `Result`'s `Ok` or as an `Option`'s `Some`, directly or through the
/// merges before the return), and what fills a recovered literal's field
/// that the declaration gives a struct type. A value two places name
/// differently is named by neither.
fn declared_structs(func: &HighFunction, structs: &[StructDef]) -> HashMap<ValueId, TypeId> {
    let is_struct = |id: &TypeId| structs.iter().any(|s| s.id == *id);
    let mut found: Vec<(ValueId, TypeId)> = Vec::new();
    // A struct, bare or as an `Option`'s `Some`.
    let named = |t: &TypeRef| match t {
        TypeRef::UserDefined(id) => Some(*id),
        TypeRef::Composite(CompositeType::Option(inner)) => match inner.as_ref() {
            TypeRef::UserDefined(id) => Some(*id),
            _ => None,
        },
        _ => None,
    };
    let returned = match func.signature.as_ref().map(|s| s.outputs.as_slice()) {
        Some([TypeRef::Composite(CompositeType::Result(ok, _))]) => named(ok),
        Some([one]) => named(one),
        _ => None,
    };
    if let Some(id) = returned.filter(is_struct) {
        for site in &func.returns {
            if let [value] = site.as_slice() {
                found.extend(returned_arms(func, *value).into_iter().map(|arm| (arm, id)));
            }
        }
    }
    for (_, b) in func.bindings.iter() {
        let Expr::Struct { fields } = &b.expr else { continue };
        let (IrType::Known(KnownType::UserDefined(outer)) | IrType::Inferred(KnownType::UserDefined(outer))) =
            &b.ty
        else {
            continue;
        };
        let Some(def) = structs.iter().find(|s| s.id == *outer) else { continue };
        for (name, value) in fields {
            if let Some(TypeRef::UserDefined(id)) = def.fields.iter().find(|f| f.name == *name).map(|f| &f.ty)
                && is_struct(id)
            {
                found.push((resolve_use(func, *value), *id));
            }
        }
    }
    let mut declared: HashMap<ValueId, Option<TypeId>> = HashMap::new();
    for (value, id) in found {
        let slot = declared.entry(value).or_insert(Some(id));
        if *slot != Some(id) {
            *slot = None;
        }
    }
    declared.into_iter().filter_map(|(v, id)| Some((v, id?))).collect()
}

/// The renames of `at` — `Use` chains ending there — take the type it is
/// about to have, where they were typed as the map it was, or not at all.
/// A rename typed anything else keeps it, and the disagreement shows.
fn retype_renames(func: &mut HighFunction, at: ValueId, ty: &IrType) {
    let renames: Vec<ValueId> = func
        .bindings
        .iter()
        .filter(|(id, b)| {
            *id != at
                && matches!(b.expr, Expr::Use(_))
                && resolve_use(func, *id) == at
                && matches!(
                    &b.ty,
                    IrType::Unknown(_)
                        | IrType::Known(KnownType::Map(..) | KnownType::Val)
                        | IrType::Inferred(KnownType::Map(..) | KnownType::Val)
                )
        })
        .map(|(id, _)| id)
        .collect();
    for id in renames {
        if let Some(b) = func.bindings.get_mut(id) {
            b.ty = ty.clone();
            b.add_provenance(Provenance::new(
                PASS_NAME,
                ProvenanceSource::SdkPattern,
                "a rename of a recovered struct literal is that struct",
            ));
        }
    }
}

/// A field stored as a constant `Val` word is the number inside it.
///
/// A `u32` or `i32` `Val` is the payload in the high 32 bits and the tag
/// (`U32Val` 4, `I32Val` 5) alone in the low 32 — that is the encoding's
/// definition, so a constant of exactly that shape, stored in a field the
/// struct declares of the matching type, is that field's number. The
/// literal printed as the raw word would be a 64-bit value in a 32-bit
/// field. Only a slot holding the constant itself counts — a constant
/// behind a `Val` encode is already the number. The decoded constant is a new binding scheduled before the
/// construction.
fn decode_constant_fields(func: &mut HighFunction, structs: &[StructDef], literal: &mut Literal) {
    use sordec_ir::{Literal as Lit, PrimitiveType as P, TypeRef};
    let IrType::Known(KnownType::UserDefined(id)) = &literal.ty else { return };
    let Some(def) = structs.iter().find(|s| s.id == *id) else { return };
    for (name, value) in &mut literal.fields {
        let Some(field) = def.fields.iter().find(|f| f.name == *name) else { continue };
        // Only the raw stored word: a number found behind a stripped encode
        // is the field's value itself, whatever its low bits are.
        if !literal.plain.contains(name) {
            continue;
        }
        let bits: u64 = match func.bindings.get(resolve_use(func, *value)).map(|b| &b.expr) {
            Some(Expr::Literal(Lit::I64(n))) => *n as u64,
            Some(Expr::Literal(Lit::U64(n))) => *n,
            _ => continue,
        };
        let payload = (bits >> 32) as u32;
        let (lit, ty) = match (&field.ty, bits & 0xFFFF_FFFF) {
            (TypeRef::Primitive(P::U32), 4) => (Lit::U32(payload), KnownType::U32),
            (TypeRef::Primitive(P::I32), 5) => (Lit::I32(payload as i32), KnownType::I32),
            _ => continue,
        };
        let fresh = ValueId::from_index(func.bindings.len() as u32);
        func.bindings.push(sordec_ir::Binding::new(
            fresh,
            IrType::Known(ty),
            Expr::Literal(lit),
            Provenance::new(PASS_NAME, ProvenanceSource::SdkPattern, "a constant field stored in its encoded form, decoded"),
        ));
        for (_, block) in func.blocks.iter_mut() {
            if let Some(pos) = block.bindings.iter().position(|v| *v == literal.at) {
                block.bindings.insert(pos, fresh);
                break;
            }
        }
        *value = fresh;
    }
}

/// Struct literals that put back together, field for field, a value of the
/// same struct: `MinterConfig { epoch_length: c.epoch_length, limit:
/// c.limit }` is `c`. What a decode and an encode helper leave around a
/// value the source only passed along.
fn rebuilds(func: &HighFunction, structs: &[StructDef]) -> Vec<(ValueId, ValueId)> {
    let named = |ty: &IrType| match ty {
        IrType::Known(KnownType::UserDefined(id)) | IrType::Inferred(KnownType::UserDefined(id)) => Some(*id),
        _ => None,
    };
    func.bindings
        .iter()
        .filter_map(|(id, b)| {
            let Expr::Struct { fields } = &b.expr else { return None };
            let ty = named(&b.ty)?;
            let def = structs.iter().find(|s| s.id == ty)?;
            if fields.len() != def.fields.len() {
                return None;
            }
            let mut whole: Option<ValueId> = None;
            for (name, value) in fields {
                let Expr::Field { base, field } = &func.bindings.get(resolve_use(func, *value))?.expr else {
                    return None;
                };
                let base = resolve_use(func, *base);
                if field != name || whole.replace(base).is_some_and(|w| w != base) {
                    return None;
                }
            }
            let whole = whole?;
            // Typed on its binding, or declared by the spec when it is one
            // of the entrypoint's own parameters.
            (super::udt_decode::udt_of(func, whole) == Some(ty)).then_some((id, whole))
        })
        .collect()
}

/// One recovered construction: the value it binds, the struct it is, and
/// the field values it is made of.
struct Literal {
    at: ValueId,
    ty: IrType,
    fields: Vec<(String, ValueId)>,
    /// The fields whose slot held the value itself, with no `Val` encode
    /// stripped from it — the only ones a constant word can be decoded in.
    plain: Vec<String>,
    /// The key table fit several structs, and the value's destination
    /// named this one.
    named_by_use: bool,
}

/// The struct literal a map construction is, if it is one.
fn literal_at(
    func: &HighFunction,
    memory: &sordec_ir::MemoryImage,
    structs: &[StructDef],
    declared: &HashMap<ValueId, TypeId>,
    id: ValueId,
) -> Option<Literal> {
    let Expr::Semantic(SemanticOp::Known(KnownOp::MapNew { keys_pos, vals_pos, len })) =
        &func.bindings.get(id)?.expr
    else {
        return None;
    };
    let len = trace_u32val(func, *len)?;
    let keys = read_keys(memory, trace_u32val(func, *keys_pos)?, len)?;
    let (def, named_by_use) = match struct_for(structs, &keys) {
        Some(def) => (def, false),
        // Several structs carry these names: the destination picks one of
        // them, never one outside them.
        None => {
            let want = declared.get(&id)?;
            let def = structs.iter().find(|s| s.id == *want)?;
            (struct_for(std::slice::from_ref(def), &keys)?, true)
        }
    };
    // Where the slots live, and what each holds at the construction.
    let (base, start) = canon_addr(func, raw_address(func, *vals_pos));
    let facts = facts_at(func, id, base);
    let mut by_key = Vec::with_capacity(keys.len());
    let mut plain = Vec::new();
    for (i, key) in keys.iter().enumerate() {
        let offset = start.checked_add(u32::try_from(i).ok()?.checked_mul(8)?)?;
        let slot = facts.value_at(offset, MemWidth::W8)?;
        let value = encoded_value(func, slot);
        if value == resolve_use(func, slot) {
            plain.push(key.clone());
        }
        by_key.push((key.clone(), value));
    }
    // Spelled in the struct's declared order, not the key table's.
    let fields = def
        .fields
        .iter()
        .map(|f| by_key.iter().find(|(k, _)| *k == f.name).map(|(_, v)| (f.name.clone(), *v)))
        .collect::<Option<Vec<_>>>()?;
    Some(Literal { at: id, ty: IrType::Known(KnownType::UserDefined(def.id)), fields, plain, named_by_use })
}

/// Take each recovered literal's field from behind a helper that only
/// encodes it as the field's declared type ("A field encoded by a
/// helper"). Returns how many fields it took.
///
/// On literals already written, not inside [`literal_at`]: a helper is
/// recognised only once its own frame bracket is gone, which is after the
/// construction it serves was rewritten — the group's next round.
fn strip_helper_encodes(func: &mut HighFunction, structs: &[StructDef], encoders: &EncoderTable) -> usize {
    let mut found: Vec<(ValueId, usize, ValueId)> = Vec::new();
    for (id, b) in func.bindings.iter() {
        let Expr::Struct { fields } = &b.expr else { continue };
        let (IrType::Known(KnownType::UserDefined(ty)) | IrType::Inferred(KnownType::UserDefined(ty))) = &b.ty else {
            continue;
        };
        let Some(def) = structs.iter().find(|s| s.id == *ty) else { continue };
        for (index, (name, value)) in fields.iter().enumerate() {
            let declared = def.fields.iter().find(|f| f.name == *name).and_then(|f| known_of_type_ref(&f.ty));
            if let Some((payload, encoded)) = encoders.encoded_by_call(func, *value)
                && Some(&encoded) == declared.as_ref()
            {
                found.push((id, index, payload));
            }
        }
    }
    for &(id, index, payload) in &found {
        let Some(b) = func.bindings.get_mut(id) else { continue };
        let Expr::Struct { fields } = &mut b.expr else { continue };
        let name = fields[index].0.clone();
        fields[index].1 = payload;
        b.add_provenance(Provenance::new(
            PASS_NAME,
            ProvenanceSource::SdkPattern,
            format!("field `{name}` taken from behind a helper that only encodes it as the declared type"),
        ));
    }
    found.len()
}

/// The value behind a field's `Val` encode. A field whose type is already
/// a `Val` — an object handle — is stored as itself and comes back
/// unchanged.
///
/// A `u64` has two encodings, one for values that fit beside the tag and
/// one that allocates an object, and rustc picks between them with a
/// branch whose arms merge. Both arms encode the same number, so the merge
/// is that number's encoding and the field is the number — which is what
/// the struct declares it to hold. The derive picks the form again when
/// the reconstruction writes the literal.
pub(super) fn encoded_value(func: &HighFunction, slot: ValueId) -> ValueId {
    strip(func, resolve_use(func, slot), 0)
}

fn strip(func: &HighFunction, value: ValueId, depth: u32) -> ValueId {
    const MAX_DEPTH: u32 = 3;
    if depth > MAX_DEPTH {
        return value;
    }
    let next = |v: ValueId| strip(func, resolve_use(func, v), depth + 1);
    match func.bindings.get(value).map(|b| &b.expr) {
        Some(Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { value, .. }))) => next(*value),
        Some(Expr::Semantic(SemanticOp::Known(KnownOp::ValObject {
            kind:
                sordec_ir::ValObjectKind::ObjFromU64
                | sordec_ir::ValObjectKind::ObjFromI64
                | sordec_ir::ValObjectKind::TimepointObjFromU64
                | sordec_ir::ValObjectKind::DurationObjFromU64,
            args,
        }))) if args.len() == 1 => next(args[0]),
        // The small/object choice: every arm encodes the same number.
        Some(Expr::Phi { incoming }) if !incoming.is_empty() => {
            let mut arms = incoming.iter().map(|(_, v)| next(*v));
            let first = arms.next().unwrap_or(value);
            if arms.all(|v| v == first) && first != value {
                first
            } else {
                value
            }
        }
        _ => value,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, module, v};
    use sordec_common::TypeId;
    use sordec_ir::{
        DataSegment, EnvCompatibility, Literal, MemoryImage, PrimitiveType, SorobanFacts,
        StructField, TypeRef, TypeRegistry,
    };

    /// `KEYS` at 2000: two entries pointing at "count" (2100) and
    /// "last_incr" (2110).
    fn memory() -> MemoryImage {
        let mut table = Vec::new();
        for (ptr, n) in [(2100u32, 5u32), (2110, 9)] {
            table.extend_from_slice(&ptr.to_le_bytes());
            table.extend_from_slice(&n.to_le_bytes());
        }
        MemoryImage::from_segments(vec![
            DataSegment { offset: 2000, bytes: table },
            DataSegment { offset: 2100, bytes: b"count".to_vec() },
            DataSegment { offset: 2110, bytes: b"last_incr".to_vec() },
        ])
    }

    fn registry() -> Vec<StructDef> {
        vec![StructDef {
            id: TypeId::new(7),
            name: "State".to_string(),
            fields: vec![
                StructField { name: "count".to_string(), ty: TypeRef::Primitive(PrimitiveType::U32) },
                StructField {
                    name: "last_incr".to_string(),
                    ty: TypeRef::Primitive(PrimitiveType::U32),
                },
            ],
        }]
    }

    /// `store fp+0 <- enc(count); store fp+8 <- enc(last_incr);
    /// map_new(&KEYS, fp, len)`.
    fn encoder(len: u32) -> HighFunction {
        let enc = |value: ValueId| {
            Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty: KnownType::U32, value }))
        };
        let store = |value: ValueId, offset: u32| Expr::Store {
            addr: v(0),
            value,
            offset,
            width: MemWidth::W8,
        };
        func_with(
            vec![
                Expr::Phi { incoming: vec![] }, // v0 frame base
                Expr::Phi { incoming: vec![] }, // v1 count
                Expr::Phi { incoming: vec![] }, // v2 last_incr
                enc(v(1)),                      // v3
                store(v(3), 0),                 // v4
                enc(v(2)),                      // v5
                store(v(5), 8),                 // v6
                Expr::Literal(Literal::U32(2000)), // v7 keys
                Expr::Literal(Literal::U32(len)),  // v8 len
                Expr::Semantic(SemanticOp::Known(KnownOp::MapNew {
                    keys_pos: v(7),
                    vals_pos: v(0),
                    len: v(8),
                })), // v9
            ],
            vec![v(0), v(1), v(2)],
            vec![3, 4, 5, 6, 7, 8, 9],
        )
    }

    fn ir(f: HighFunction) -> HighIr {
        let mut m = module(vec![f]);
        m.memory = memory();
        m.soroban_facts = Some(SorobanFacts {
            functions: std::collections::BTreeMap::new(),
            types: TypeRegistry { structs: registry(), ..Default::default() },
            contract_meta: std::collections::BTreeMap::new(),
            env_meta: EnvCompatibility::default(),
        });
        m
    }

    #[test]
    fn a_key_table_and_its_slots_become_the_struct_literal() {
        let mut m = ir(encoder(2));
        assert!(UdtEncodePass.run(&mut m).changed);
        let binding = m.functions[0].bindings.get(v(9)).unwrap();
        let Expr::Struct { fields } = &binding.expr else {
            panic!("the construction is the literal, got {:?}", binding.expr);
        };
        assert_eq!(
            fields,
            &vec![("count".to_string(), v(1)), ("last_incr".to_string(), v(2))],
            "declared order, each value from behind its encode"
        );
        assert!(matches!(binding.ty, IrType::Known(KnownType::UserDefined(id)) if id == TypeId::new(7)));
    }

    /// A table whose length names no declared struct is a `Map` the source
    /// really built.
    #[test]
    fn a_table_that_names_no_struct_declines() {
        let mut m = ir(encoder(1));
        assert!(!UdtEncodePass.run(&mut m).changed);
    }

    /// A `u32` field stored as the constant `5 << 32 | U32Val` is `5`; a
    /// constant with another tag in the low word is left as it is.
    #[test]
    fn a_constant_field_in_encoded_form_is_its_number() {
        let build = |word: i64| {
            let mut f = encoder(2);
            f.bindings.get_mut(v(5)).unwrap().expr = Expr::Literal(Literal::I64(word));
            f
        };
        let mut m = ir(build((5i64 << 32) | 4));
        assert!(UdtEncodePass.run(&mut m).changed);
        let f = &m.functions[0];
        let Expr::Struct { fields } = &f.bindings.get(v(9)).unwrap().expr else { panic!() };
        let decoded = f.bindings.get(fields[1].1).unwrap();
        assert!(matches!(decoded.expr, Expr::Literal(Literal::U32(5))), "{:?}", decoded.expr);
        assert!(f.blocks.iter().any(|(_, b)| b.bindings.contains(&fields[1].1)), "scheduled");
        let mut m = ir(build((5i64 << 32) | 5));
        assert!(UdtEncodePass.run(&mut m).changed);
        let f = &m.functions[0];
        let Expr::Struct { fields } = &f.bindings.get(v(9)).unwrap().expr else { panic!() };
        assert!(matches!(f.bindings.get(fields[1].1).unwrap().expr, Expr::Literal(Literal::I64(_))));
    }

    /// A number that merely looks like a tag, found behind an encode, is the
    /// number: `last_incr: u32 = 4` must not decode to 0.
    #[test]
    fn a_number_behind_an_encode_is_not_decoded() {
        let mut f = encoder(2);
        f.bindings.get_mut(v(2)).unwrap().expr = Expr::Literal(Literal::I64(4));
        let mut m = ir(f);
        assert!(UdtEncodePass.run(&mut m).changed);
        let f = &m.functions[0];
        let Expr::Struct { fields } = &f.bindings.get(v(9)).unwrap().expr else { panic!() };
        assert_eq!(fields[1].1, v(2), "the stripped value is kept as it is");
    }

    /// The `i32` field takes tag 5, and only an `i32` field does.
    #[test]
    fn an_i32_field_decodes_its_tag_five_word() {
        let mut f = encoder(2);
        f.bindings.get_mut(v(5)).unwrap().expr = Expr::Literal(Literal::I64((7i64 << 32) | 5));
        let mut m = ir(f);
        m.soroban_facts.as_mut().unwrap().types.structs[0].fields[1].ty =
            TypeRef::Primitive(PrimitiveType::I32);
        assert!(UdtEncodePass.run(&mut m).changed);
        let f = &m.functions[0];
        let Expr::Struct { fields } = &f.bindings.get(v(9)).unwrap().expr else { panic!() };
        assert!(matches!(f.bindings.get(fields[1].1).unwrap().expr, Expr::Literal(Literal::I32(7))));
    }

    /// `t = func1(last_incr); store fp+0 <- enc(count); store fp+8 <- t.1;
    /// map_new(..)`, beside func1, the outlined `u64` encode:
    /// `r = phi [obj_from_u64(x), val_encode<u64>(x)]; return (0, r)`.
    /// `last_incr` declared as `field`.
    fn helper_encoded(field: PrimitiveType) -> HighIr {
        use sordec_common::{BlockId, FuncId, IrId};
        use sordec_ir::{Region, ValObjectKind};
        let construct = func_with(
            vec![
                Expr::Phi { incoming: vec![] }, // v0 frame base
                Expr::Phi { incoming: vec![] }, // v1 count
                Expr::Phi { incoming: vec![] }, // v2 last_incr
                Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty: KnownType::U32, value: v(1) })), // v3
                Expr::Store { addr: v(0), value: v(3), offset: 0, width: MemWidth::W8 }, // v4
                Expr::Call { target: FuncId::from_index(1), args: vec![v(2)] }, // v5
                Expr::Project { value: v(5), index: 1 },                        // v6
                Expr::Store { addr: v(0), value: v(6), offset: 8, width: MemWidth::W8 }, // v7
                Expr::Literal(Literal::U32(2000)),                              // v8 keys
                Expr::Literal(Literal::U32(2)),                                 // v9 len
                Expr::Semantic(SemanticOp::Known(KnownOp::MapNew { keys_pos: v(8), vals_pos: v(0), len: v(9) })), // v10
            ],
            vec![v(0), v(1), v(2)],
            vec![5, 6, 3, 4, 7, 8, 9, 10],
        );
        let mut helper = func_with(
            vec![
                Expr::Phi { incoming: vec![] }, // v0: x
                Expr::Semantic(SemanticOp::Known(KnownOp::ValObject { kind: ValObjectKind::ObjFromU64, args: vec![v(0)] })), // v1
                Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty: KnownType::U64, value: v(0) })), // v2
                Expr::Phi { incoming: vec![(BlockId::from_index(0), v(1)), (BlockId::from_index(1), v(2))] }, // v3
                Expr::Literal(Literal::I64(0)), // v4
            ],
            vec![v(0)],
            vec![1, 2, 4],
        );
        helper.id = FuncId::from_index(1);
        helper.region =
            Region::Sequence(vec![Region::Basic(BlockId::from_index(0)), Region::Return { values: vec![v(4), v(3)] }]);
        let mut m = ir(construct);
        m.functions.push(helper);
        m.soroban_facts.as_mut().unwrap().types.structs[0].fields[1].ty = TypeRef::Primitive(field);
        m
    }

    /// A `u64` field whose slot holds the component of a helper that only
    /// encodes its argument as a `u64` is that argument.
    #[test]
    fn a_field_encoded_by_a_helper_is_the_helper_s_argument() {
        let mut m = helper_encoded(PrimitiveType::U64);
        assert!(UdtEncodePass.run(&mut m).changed);
        let b = m.functions[0].bindings.get(v(10)).unwrap();
        let Expr::Struct { fields } = &b.expr else { panic!("{:?}", b.expr) };
        assert_eq!(fields, &vec![("count".to_string(), v(1)), ("last_incr".to_string(), v(2))]);
        assert!(b.provenance().iter().any(|p| p.note.contains("last_incr")), "the field taken from the helper is recorded");
    }

    /// The same helper in a field declared `u32` is not what the derive
    /// writes for it: the field keeps the component it holds.
    #[test]
    fn a_helper_encoding_another_type_than_the_field_s_is_not_stripped() {
        let mut m = helper_encoded(PrimitiveType::U32);
        assert!(UdtEncodePass.run(&mut m).changed);
        let Expr::Struct { fields } = &m.functions[0].bindings.get(v(10)).unwrap().expr else { panic!() };
        assert_eq!(fields[1], ("last_incr".to_string(), v(6)));
    }

    #[test]
    fn the_pass_is_idempotent() {
        let mut m = ir(encoder(2));
        assert!(UdtEncodePass.run(&mut m).changed);
        assert!(!UdtEncodePass.run(&mut m).changed);
    }

    /// `State { count: s.count, last_incr: s.last_incr }` is `s`; with one
    /// field taken from another value it is not.
    #[test]
    fn a_struct_rebuilt_from_its_own_fields_is_the_value() {
        let build = |second_base: u32| {
            let mut f = func_with(
                vec![
                    Expr::Phi { incoming: vec![] },                                  // v0 s
                    Expr::Phi { incoming: vec![] },                                  // v1 t
                    Expr::Field { base: v(0), field: "count".to_string() },         // v2
                    Expr::Field { base: v(second_base), field: "last_incr".to_string() }, // v3
                    Expr::Struct {
                        fields: vec![("count".to_string(), v(2)), ("last_incr".to_string(), v(3))],
                    },                                                               // v4
                ],
                vec![v(0), v(1)],
                vec![2, 3, 4],
            );
            let state = IrType::Known(KnownType::UserDefined(TypeId::new(7)));
            for id in [0, 1, 4] {
                f.bindings.get_mut(v(id)).unwrap().ty = state.clone();
            }
            f
        };
        let mut m = ir(build(0));
        assert!(UdtEncodePass.run(&mut m).changed);
        assert!(matches!(m.functions[0].bindings.get(v(4)).unwrap().expr, Expr::Use(w) if w == v(0)));
        let mut m = ir(build(1));
        assert!(!UdtEncodePass.run(&mut m).changed);
    }

    // -----------------------------------------------------------------
    // Field names several structs share
    // -----------------------------------------------------------------

    /// A second struct with `State`'s field names, and a third with other
    /// names: the key table fits `State` (7) and `Twin` (8).
    fn twins(m: &mut HighIr) {
        let mut twin = registry().remove(0);
        twin.id = TypeId::new(8);
        twin.name = "Twin".to_string();
        let mut other = registry().remove(0);
        other.id = TypeId::new(9);
        other.name = "Other".to_string();
        other.fields[0].name = "elsewhere".to_string();
        let structs = &mut m.soroban_facts.as_mut().unwrap().types.structs;
        structs.push(twin);
        structs.push(other);
    }

    /// The encoder, returned through a rename from an entrypoint the spec
    /// declares to return `output`.
    fn returned_as(output: TypeRef) -> HighIr {
        let mut f = encoder(2);
        let id = ValueId::from_index(f.bindings.len() as u32);
        f.bindings.push(sordec_ir::Binding::new(
            id,
            IrType::Known(KnownType::Map(
                Box::new(IrType::Unknown(sordec_common::UnknownReason::InsufficientEvidence)),
                Box::new(IrType::Unknown(sordec_common::UnknownReason::InsufficientEvidence)),
            )),
            Expr::Use(v(9)),
            Provenance::new("seed", ProvenanceSource::DataFlow, "seed"),
        )); // v10 the rename
        f.blocks.iter_mut().next().unwrap().1.bindings.push(id);
        f.returns = vec![vec![id]];
        f.signature = Some(sordec_ir::FunctionSignature {
            name: "get".to_string(),
            inputs: vec![],
            outputs: vec![output],
        });
        let mut m = ir(f);
        twins(&mut m);
        m
    }

    fn named(m: &HighIr, at: u32) -> Option<TypeId> {
        let b = m.functions[0].bindings.get(v(at)).unwrap();
        match (&b.expr, &b.ty) {
            (Expr::Struct { .. }, IrType::Known(KnownType::UserDefined(id))) => Some(*id),
            _ => None,
        }
    }

    /// Two structs fit the keys; the spec's return names `Twin`, and the
    /// rename the value is returned through takes its type.
    #[test]
    fn a_shared_key_table_is_named_by_the_declared_return() {
        let mut m = returned_as(TypeRef::UserDefined(TypeId::new(8)));
        assert!(UdtEncodePass.run(&mut m).changed);
        assert_eq!(named(&m, 9), Some(TypeId::new(8)));
        let rename = m.functions[0].bindings.get(v(10)).unwrap();
        assert!(matches!(rename.ty, IrType::Known(KnownType::UserDefined(id)) if id == TypeId::new(8)));
    }

    /// `Result<Twin, E>`: a map is never the error's encoding, so it is
    /// the `Ok`.
    #[test]
    fn a_result_return_names_its_ok_struct() {
        let ok = TypeRef::Composite(CompositeType::Result(
            Box::new(TypeRef::UserDefined(TypeId::new(8))),
            Box::new(TypeRef::Primitive(PrimitiveType::Error)),
        ));
        let mut m = returned_as(ok);
        assert!(UdtEncodePass.run(&mut m).changed);
        assert_eq!(named(&m, 9), Some(TypeId::new(8)));
    }

    /// `Option<Twin>` returned through a merge of the rename and `Void`: a
    /// map is never `None`'s encoding, so on its path it is the `Some`.
    #[test]
    fn an_option_return_names_its_struct_through_a_merge() {
        let option = TypeRef::Composite(CompositeType::Option(Box::new(TypeRef::UserDefined(TypeId::new(8)))));
        let mut m = returned_as(option);
        let f = &mut m.functions[0];
        let void = f.bindings.push(sordec_ir::Binding::new(
            ValueId::from_index(11),
            IrType::Unknown(sordec_common::UnknownReason::InsufficientEvidence),
            Expr::Literal(Literal::I64(2)),
            Provenance::new("seed", ProvenanceSource::DataFlow, "seed"),
        ));
        let merge = f.bindings.push(sordec_ir::Binding::new(
            ValueId::from_index(12),
            IrType::Unknown(sordec_common::UnknownReason::InsufficientEvidence),
            Expr::Phi {
                incoming: vec![(sordec_common::BlockId::new(0), v(10)), (sordec_common::BlockId::new(1), void)],
            },
            Provenance::new("seed", ProvenanceSource::DataFlow, "seed"),
        ));
        f.returns = vec![vec![merge]];
        assert!(UdtEncodePass.run(&mut m).changed);
        assert_eq!(named(&m, 9), Some(TypeId::new(8)));
        // The same merge from an entrypoint declaring a struct the keys do
        // not fit names nothing.
        let mut m = returned_as(TypeRef::Composite(CompositeType::Option(Box::new(TypeRef::UserDefined(TypeId::new(9))))));
        assert!(!UdtEncodePass.run(&mut m).changed);
    }

    /// No destination, or one declaring a struct the keys do not fit:
    /// the table says only "one of these", and the map is left alone.
    #[test]
    fn a_shared_key_table_with_nothing_to_name_it_declines() {
        let mut m = ir(encoder(2));
        twins(&mut m);
        assert!(!UdtEncodePass.run(&mut m).changed);
        let mut m = returned_as(TypeRef::UserDefined(TypeId::new(9)));
        assert!(!UdtEncodePass.run(&mut m).changed);
        let mut m = returned_as(TypeRef::Primitive(PrimitiveType::U32));
        assert!(!UdtEncodePass.run(&mut m).changed);
    }

    /// The field of a recovered literal names the struct its value is:
    /// `Outer { inner: <map> }` with `inner: Twin` declared.
    #[test]
    fn a_shared_key_table_is_named_by_the_field_it_fills() {
        let build = |declared: TypeId| {
            let mut f = encoder(2);
            let id = ValueId::from_index(f.bindings.len() as u32);
            f.bindings.push(sordec_ir::Binding::new(
                id,
                IrType::Known(KnownType::UserDefined(TypeId::new(10))),
                Expr::Struct { fields: vec![("inner".to_string(), v(9))] },
                Provenance::new("seed", ProvenanceSource::DataFlow, "seed"),
            )); // v10 Outer { inner: v9 }
            f.blocks.iter_mut().next().unwrap().1.bindings.push(id);
            let mut m = ir(f);
            twins(&mut m);
            m.soroban_facts.as_mut().unwrap().types.structs.push(StructDef {
                id: TypeId::new(10),
                name: "Outer".to_string(),
                fields: vec![StructField { name: "inner".to_string(), ty: TypeRef::UserDefined(declared) }],
            });
            m
        };
        let mut m = build(TypeId::new(7));
        assert!(UdtEncodePass.run(&mut m).changed);
        assert_eq!(named(&m, 9), Some(TypeId::new(7)));
        let mut m = build(TypeId::new(9));
        assert!(!UdtEncodePass.run(&mut m).changed);
    }

    /// Two destinations naming different structs name neither.
    #[test]
    fn destinations_that_disagree_name_nothing() {
        let mut m = returned_as(TypeRef::UserDefined(TypeId::new(8)));
        let f = &mut m.functions[0];
        let id = ValueId::from_index(f.bindings.len() as u32);
        f.bindings.push(sordec_ir::Binding::new(
            id,
            IrType::Known(KnownType::UserDefined(TypeId::new(10))),
            Expr::Struct { fields: vec![("inner".to_string(), v(9))] },
            Provenance::new("seed", ProvenanceSource::DataFlow, "seed"),
        ));
        f.blocks.iter_mut().next().unwrap().1.bindings.push(id);
        m.soroban_facts.as_mut().unwrap().types.structs.push(StructDef {
            id: TypeId::new(10),
            name: "Outer".to_string(),
            fields: vec![StructField { name: "inner".to_string(), ty: TypeRef::UserDefined(TypeId::new(7)) }],
        });
        assert!(!UdtEncodePass.run(&mut m).changed);
    }
}
