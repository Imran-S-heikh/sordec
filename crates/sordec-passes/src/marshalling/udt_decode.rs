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
//! # Why it is exact
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
//!
//! **Field names several structs share.** `{ val }` is a common shape, and
//! a key table matching three structs says only "one of these". The
//! value's own declaration says which: an entrypoint parameter declared
//! with the type, a value an earlier decode or the tuple-parameter pass
//! typed from the spec (a field of a recovered struct, a tuple element),
//! or a helper parameter every caller hands a value proven to be that
//! struct. That is the same evidence the decode needs anyway, so the
//! choice adds no claim: the declaration picks among the structs the
//! table matches, and the table must still match it field for field.
//!
//! **An `Option<T>` parameter's payload.** `o: Option<T>` arrives as
//! `Void` or as a `T`'s map, and the derived conversion unpacks it only on
//! the `Some` path. The unpack itself proves which: the host traps on
//! anything but a map, and `Void` is not one, so where it returns the
//! value is a `T` — and the spec says it is one of those two. The decode
//! is taken only when no read needs a name for the payload's field (there
//! is no `o.f` to write): every read must be the field's derived check —
//! its tag byte as below, or the whole word with every use a tag test
//! against the field type's one tag, a mismatch test guarding
//! `if t { trap }` or a match test guarding `if t { .. } else { trap }`
//! (which gives way to its `then` arm). Arithmetic on the word that
//! nothing reads (the `word & 255` a tag test was recognised from) goes
//! with it. The regenerated `#[contractimpl]` wrapper converts the
//! `Option<T>` — the unpack and each field check — so all of it is
//! relocated, and the parameter keeps its `Option` type.
//!
//! Rewriting a read and removing the decode are two more claims, and each
//! has its own argument.
//!
//! - **A rewritten read reads exactly one field.** A load becomes `v.f`
//!   only when it reads the whole of `f`'s slot and nothing else: its
//!   address is the slot's address and its width is the slot's width — 8
//!   bytes for an unpacked `Val`, the width of the helper's store for a
//!   helper's slot. A wider load spans two fields, or a field and bytes
//!   nothing wrote; a narrower one reads part of a slot (the tag byte of a
//!   `Val`, say); neither is the field. A narrow read that widens its value
//!   must widen it the way the field's type does (zero for `u32`, sign for
//!   `i32`). One exception: a `bool` is 0 or 1 with zeros above it — as a
//!   `Val` too, where `false` and `true` are tags 0 and 1 with an empty
//!   body — so a read of its low bytes is the whole value. And the slot
//!   must hold the decode's value on *every* path to the read: the decode
//!   ran on all of them, and nothing since may have written the slot.
//! - **A `Result` discriminant reads as `Ok`.** The value was proven at its
//!   boundary, so the decode takes its `Ok` path and the slot holds the
//!   `Ok` code, 0. A read at the slot's address no wider than the slot is
//!   that 0 in its own width (the low bytes of zero are zero). The helper
//!   must write the slot on every path it returns by; a constant slot it
//!   writes on some paths only explains no read.
//! - **A field's tag byte, read only to trap on a mismatch, is the derived
//!   check.** Where a field's value is never used, rustc keeps only the
//!   check its conversion makes: `if load8(slot) != 4 { trap }` for a
//!   `u32`. That is not the field's value (the old rewrite printed it as
//!   `s.a != 4`, wrong for every `a` but 4); it is the derived
//!   `TryFromVal`'s type check, and the re-emitted derive regenerates it
//!   with the unpack, so it is relocated with the decode exactly as a
//!   declared parameter's tag check is (`guard`). Taken only when the
//!   slots hold `Val`s (a host unpack, not a helper's decoded values),
//!   the byte is the first of a slot the decode wrote whole on every path,
//!   the field's declared type is carried by exactly one tag (`u32`,
//!   `i32`, `Address`, `Bytes`, `String`, `Vec`, `Map` — a two-tag type
//!   such as `u64` or `Symbol`, a `bool`, `BytesN` (its length) or a
//!   contract type have no one-byte check that is their whole
//!   conversion), every use of the byte is `byte != that tag`, and every
//!   use of that comparison is a guard `if c { trap }` with no else arm.
//!   Anything else that reads the byte refuses the whole site.
//! - **Removing the decode loses no read.** Once the unpack or the helper
//!   call is gone nothing writes its slots, so every read that could still
//!   see a byte it wrote must have been rewritten. A load the decode *may*
//!   reach — on some path, before that byte is overwritten — that is not an
//!   exact field read refuses the whole site: nothing is rewritten and the
//!   decode stays. So does any other operation that may read those bytes
//!   in that time, such as a call handed their address. A site is taken
//!   whole or not at all. Keeping the call and rewriting only the proven
//!   reads would also be exact, but it leaves a call whose results are half
//!   consumed — the source wrote neither.
//!
//! "Every path" and "some path" come from one forward walk of the
//! function's region tree per decode (the `reach` module below): which
//! slots hold the decode's value whole on every path (`must`), and which
//! bytes hold it on
//! some path (`may`), met at every merge and iterated round loops until
//! nothing changes. `may` is kept per byte because a slot overwritten in
//! part keeps the rest of the decode's bytes, and a later read of only the
//! overwritten part — a callee's tag byte in the slot the decode used —
//! does not see them.
//!
//! **A field decoded by an outlined scalar decoder.** rustc outlines the
//! `TryFromVal<Env, Val>` of an `i64` or `u64` field (two encodings, so a
//! branch) into a helper `(x) -> (tag, value)` the struct decoder calls
//! with the field's slot and tests the tag of, storing the value. That
//! helper is `soroban-env-common`'s conversion and nothing else: `(0,
//! obj_to_*(x))` under the object tag, `(0, body)` under the small tag,
//! a non-zero tag otherwise. On a value proven to be the struct, the
//! field is a `Val` of its declared type — one of those two forms — so
//! the call returns `Ok` with the field's number, and the slot the
//! struct decoder stores it in holds `val.f` exactly as an inlined
//! decode's would. The re-emitted derive regenerates the call with the
//! rest of the conversion. A slot stored from the tag, or from a decoder
//! of another type than the field's, explains no read.
//!
//! # Gates
//!
//! - The key table reads out of rodata as identifiers, and exactly one
//!   declared struct has those field names — or several do, and the
//!   value's declaration names one of them.
//! - The decoded value is proven to be that struct (see above), or is an
//!   entrypoint parameter declared `Option` of it, read only by checks.
//! - A helper is `(out, val)`, `val` typed as the struct, touches no host
//!   state, uses `out` only as a store address, and stores each slot from
//!   exactly one field of `val` or a constant; each slot is stored at one
//!   width and no two slots overlap. It calls nothing but a two-encoding
//!   scalar decoder (`enum_match::two_form_decoder`: `i64` or `u64`),
//!   handed one field of `val` that the struct declares at that type; a
//!   slot stored from such a call is its value component `.1`, never its
//!   tag, and nothing else the call returns reaches a slot.
//! - Every read the decode may reach is an exact read of a field, half of
//!   a wide field, or a discriminant written on every path; nothing else
//!   that may read memory is handed the decode's bytes while they may still
//!   hold its value; and the function's control flow is structured.
//! - A byte stops holding the decode's value only on a certain overwrite:
//!   a store at the same base and a constant offset covering it, another
//!   decode into the same place (an unpack writes all its slots; a helper
//!   on a proven value writes every field and discriminant slot), a host
//!   unpack into linear memory, a call to a helper that stores it on
//!   every path it returns by, or a 128-bit decode of a value its codec
//!   proves (`wide_codec`): that decode takes its `Ok` path, which stores
//!   the discriminant and both limbs, as the codec's own collapse holds.
//!   Anything that may write it only ends the `must` side.
//! - A call to a helper that uses a parameter only as a load or store
//!   address touches what it is handed there at exactly those offsets.
//!   Any other call or memory operation is taken to read and write from
//!   the address it is handed upward. Handed an address below the
//!   decode's bytes, it reads the local that address belongs to, not the
//!   decode's: the decode writes into a local of its own (the derived
//!   conversion's `[Val; N]`, or the `Result` a helper returns into), and
//!   two locals share memory only when one of them is dead, when what it
//!   held can no longer be read through the other. It may still have
//!   written there, so the `must` side ends.
//!
//! What it does not see: memory is matched by address, as the frame base
//! plus a constant or anything computed from the base (a run-time offset,
//! a phi, a select — taken to point anywhere at or above the base, or at
//! or above `x` for `x | y`). A store through a pointer not computed from
//! the base is taken not to touch the frame — the frame is this function's
//! own stack space, and a pointer it did not derive from its frame pointer
//! does not point into it. A pointer into the frame stored to memory and
//! loaded back is not followed; rustc addresses its frame slots from the
//! frame pointer.

use std::collections::{BTreeMap, HashMap};

use sordec_common::{FuncId, IrId, TypeId, UnknownReason, ValueId};
use sordec_ir::{
    Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, Literal, MapOpKind, MemWidth, SemanticOp,
    SorobanFacts, StructDef, StructField, TypeRef, UnionDef, WasmOpcodeKind,
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
        // With no spec there is nothing to match a key table against —
        // but the key table is itself most of the declaration, so
        // recover one. A module that declares its structs is left alone:
        // it has said what they are.
        if !ir.soroban_facts.as_ref().is_some_and(|f| !f.types.structs.is_empty()) {
            let recovered = synthesize_structs(ir);
            if recovered == 0 {
                return result;
            }
            result.metrics.increment(metrics::UDT_STRUCTS_SYNTHESIZED, recovered);
            result.changed = true;
        }
        let facts = ir.soroban_facts.as_ref().expect("synthesized above or already present");
        let structs: Vec<StructDef> = facts.types.structs.clone();
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
        // The derived decoders of a two-encoding scalar (`i64`, `u64`)
        // rustc outlines; a struct decoder hands each such field to one.
        let scalars: HashMap<FuncId, KnownType> = ir
            .functions
            .iter()
            .filter_map(|f| super::enum_match::two_form_decoder(f).map(|t| (f.id, t)))
            .collect();
        let helpers: HashMap<FuncId, DecoderHelper> = ir
            .functions
            .iter()
            .filter_map(|f| classify_helper(f, &structs, &unions, &scalars).map(|h| (f.id, h)))
            .collect();
        // What each helper reads and writes through each pointer it is
        // handed: a call touches a decode's slots only there.
        let access: HashMap<FuncId, Vec<Option<ParamAccess>>> =
            ir.functions.iter().map(|f| (f.id, param_accesses(f))).collect();
        // A 128-bit decode of a proven value writes its limbs for certain.
        let wide = super::wide_codec::WideDecoders::of(ir);
        for func in &mut ir.functions {
            let wide_writes = wide.certain_writes(func);
            let planned = plan(func, &memory, &structs, &unions, &param_types, &helpers, &access, &wide_writes);
            for key in &planned.declines {
                result.metrics.increment(key, 1);
            }
            if planned.elisions.is_empty() && planned.limbs.is_empty() {
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
            if !planned.inverted.is_empty() {
                let empty = super::guard::empty_blocks(func);
                let region = std::mem::replace(&mut func.region, sordec_ir::Region::Unreachable);
                let mut stripped = 0_i64;
                func.region = strip_inverted(region, &planned.inverted, &empty, &mut stripped);
                result.metrics.increment(metrics::GUARDS_ELIDED, stripped);
            }
            apply_elisions(func, PASS_NAME, planned.elisions);
            let mut shared: HashMap<(ValueId, String), ValueId> = HashMap::new();
            for (load, base, field, ty, half) in planned.limbs {
                result.metrics.increment(metrics::UDT_FIELDS_RECOVERED, 1);
                apply_limb(func, &mut shared, load, base, field, ty, half);
            }
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
    /// Why unpacks that looked like this pass's shape were not taken,
    /// keyed by counter. Successes alone cannot say whether a contract is
    /// fully recovered or barely touched.
    declines: Vec<&'static str>,
    typed: Vec<(ValueId, IrType)>,
    /// Guard conditions (in `guard::strip`'s shape) that test a niche
    /// discriminant the collapse has just made a field.
    guards: HashMap<ValueId, String>,
    /// Conditions of guards written the other way round, `if c { .. }
    /// else { trap }`, whose test is a derived check: the `if` gives way
    /// to its `then` arm.
    inverted: HashMap<ValueId, String>,
    /// Loads of one half of a wide field: `(load, struct value, field,
    /// field type, WideLo/WideHi)`. Each needs the field as a binding of
    /// its own, which an [`Elision`] cannot create.
    limbs: Vec<(ValueId, ValueId, String, KnownType, sordec_ir::UnaryOp)>,
}

/// What one slot of a decode's output holds.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum Role {
    /// The whole of a field.
    Field(String),
    /// One half of a wide field, which crosses a helper's out-parameter
    /// as two words.
    Limb(String, sordec_ir::UnaryOp),
    /// The `Result` discriminant, written on every path the helper
    /// returns by; read as the `Ok` code.
    Disc,
    /// A constant the helper writes on some paths only. On the `Ok` path
    /// it may hold anything, so no read of it is explained.
    Unexplained,
}

/// One slot of a decode's output: `width` bytes at `rel` from the frame
/// start.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct Slot {
    pub(super) rel: u32,
    pub(super) width: u32,
    pub(super) role: Role,
}

/// One decode whose result lands in the caller's frame: an unpack's slot
/// region, or a helper's out-parameter. Whether its reads are rewritten,
/// and it removed, is decided by [`reach::check`].
pub(super) struct Candidate<'a> {
    /// The frame pointer and the byte offset the output starts at.
    pub(super) base: ValueId,
    pub(super) start: u32,
    /// The unpack or the helper call.
    pub(super) producer: ValueId,
    pub(super) map: ValueId,
    pub(super) def: &'a StructDef,
    /// Ascending by offset, none overlapping.
    pub(super) slots: Vec<Slot>,
    /// The slots hold the fields' `Val`s (a host unpack), not decoded
    /// values (a helper's out-parameter): only then is a slot's first
    /// byte its field's tag.
    pub(super) vals: bool,
    /// The map is an `Option<T>` parameter, unpacked on its `Some` path:
    /// no expression spells "this field of the payload", so the decode is
    /// taken only when every read of it is a relocated check.
    pub(super) payload: bool,
}

impl Candidate<'_> {
    /// `[lo, hi)` of slot `i`, in bytes from the base.
    fn span(&self, i: usize) -> (u64, u64) {
        let s = &self.slots[i];
        let lo = u64::from(self.start) + u64::from(s.rel);
        (lo, lo + u64::from(s.width))
    }

    /// The byte ranges `(offset from base, width)` the producer writes on
    /// every path the caller continues on: every slot of an unpack (the
    /// host writes them all or traps), and every field and discriminant
    /// slot of a helper on a proven value, whose decode therefore takes
    /// its `Ok` path.
    pub(super) fn certain_writes(&self) -> Vec<(u32, u32)> {
        self.slots
            .iter()
            .filter(|s| s.role != Role::Unexplained)
            .map(|s| (self.start.saturating_add(s.rel), s.width))
            .collect()
    }

    /// The slot a load of `width` bytes at `offset` (from the base) reads
    /// exactly, or `None` when it reads anything else.
    fn exact_read(&self, offset: u32, width: MemWidth, signed: Option<bool>) -> Option<usize> {
        let rel = offset.checked_sub(self.start)?;
        let i = self.slots.iter().position(|s| s.rel == rel)?;
        let slot = &self.slots[i];
        let w = width.bytes();
        let fits = match &slot.role {
            // A `bool` is 0 or 1 with zeros above it — as a `Val` (`false`
            // and `true` are tags 0 and 1 with an empty body) and decoded
            // alike — so a read of its low bytes is the whole value.
            Role::Field(name) if self.field_type(name) == Some(KnownType::Bool) => w <= slot.width,
            Role::Field(name) => {
                w == slot.width && (signed.is_none() || widens_as_declared(self.field_type(name), signed))
            }
            Role::Limb(name, _) => w == 8 && slot.width == 8 && self.field_type(name).is_some(),
            Role::Disc => w <= slot.width,
            Role::Unexplained => false,
        };
        fits.then_some(i)
    }

    fn field_type(&self, name: &str) -> Option<KnownType> {
        self.def.fields.iter().find(|f| f.name == name).and_then(|f| known_of_type_ref(&f.ty))
    }

    /// The slot whose tag byte a one-byte load at `offset` reads, with the
    /// one tag the field's declared type is carried by — when the slots
    /// hold `Val`s and the field's type has exactly one tag.
    fn tag_read(&self, offset: u32, width: MemWidth) -> Option<(usize, u8)> {
        if !self.vals || width != MemWidth::W1 {
            return None;
        }
        let rel = offset.checked_sub(self.start)?;
        let i = self.slots.iter().position(|s| s.rel == rel && s.width == SLOT)?;
        let Role::Field(name) = &self.slots[i].role else { return None };
        Some((i, sole_tag(&self.field_type(name)?)?))
    }
}

/// The one tag a `Val` of type `ty` is carried by, when it has exactly
/// one: then "the tag byte is `t`" is the whole of the derived
/// conversion's check for it, which is what lets a check of the byte
/// alone stand for that conversion. A type with a small and an object
/// form (`u64`, `i128`, `Symbol`, ...), a `bool` (two tags), and a type
/// whose conversion reads past the tag (`BytesN<N>` checks its length,
/// a `#[contracttype]` type unpacks or matches its body) have no entry.
pub(super) fn sole_tag(ty: &KnownType) -> Option<u8> {
    use crate::val_abi::{
        TAG_ADDRESS_OBJECT, TAG_BYTES_OBJECT, TAG_I32_VAL, TAG_MAP_OBJECT, TAG_STRING_OBJECT, TAG_U32_VAL,
        TAG_VEC_OBJECT,
    };
    Some(match ty {
        KnownType::U32 => TAG_U32_VAL,
        KnownType::I32 => TAG_I32_VAL,
        KnownType::Address => TAG_ADDRESS_OBJECT,
        KnownType::Bytes => TAG_BYTES_OBJECT,
        KnownType::String => TAG_STRING_OBJECT,
        KnownType::Vec(_) => TAG_VEC_OBJECT,
        KnownType::Map(..) => TAG_MAP_OBJECT,
        _ => return None,
    })
}

/// Whether a narrow load's widening (`signed`: sign- or zero-extension)
/// gives the field's own value: zero for an unsigned field, sign for a
/// signed one. A `bool` or a unit enum's code is a small non-negative
/// number, the same under either. A field of no known type gives no
/// answer, so the read is not taken.
fn widens_as_declared(ty: Option<KnownType>, signed: Option<bool>) -> bool {
    matches!(
        (ty, signed),
        (_, None)
            | (Some(KnownType::Bool | KnownType::UserDefined(_)), _)
            | (Some(KnownType::U32 | KnownType::U64), Some(false))
            | (Some(KnownType::I32 | KnownType::I64), Some(true))
    )
}

/// Another decode in the same function, as its producer, its frame base,
/// and the `(offset from base, width)` ranges it certainly writes.
pub(super) type CertainWrite = (ValueId, ValueId, Vec<(u32, u32)>);

/// What every caller hands each helper parameter, when they agree: a
/// value proven to be one struct (`Some`), or — `None` — only host
/// operation results and fields, whose stored type the helper's own decode
/// is the proof of, exactly as it is for a decode in the caller's body. A
/// parameter some caller feeds anything else has no entry.
fn caller_param_types(ir: &HighIr) -> HashMap<(FuncId, usize), Option<TypeId>> {
    let calls = CallIndex::build(ir);
    let mut out: HashMap<(FuncId, usize), Option<TypeId>> = HashMap::new();
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
                let Some(arg) = args.get(index).map(|a| resolve_use(caller, *a)) else {
                    ok = false;
                    break;
                };
                match (udt_of(caller, arg), agreed) {
                    (Some(t), None) => agreed = Some(t),
                    (Some(t), Some(prev)) if t == prev => {}
                    (None, _) if host_result(caller, arg) => {}
                    _ => {
                        ok = false;
                        break;
                    }
                }
            }
            if ok {
                out.insert((callee.id, index), agreed);
            }
        }
    }
    out
}

/// A host operation's result or a recovered field: a value whose stored
/// type a struct decode of it proves.
fn host_result(func: &HighFunction, value: ValueId) -> bool {
    matches!(
        func.bindings.get(value).map(|b| &b.expr),
        Some(Expr::Semantic(SemanticOp::Known(_)) | Expr::Field { .. })
    )
}

/// The struct a caller's value is known to be: typed on its binding by an
/// earlier decode, or declared by the caller's own `contractspecv0`
/// signature when the value is one of its parameters.
pub(super) fn udt_of(func: &HighFunction, value: ValueId) -> Option<TypeId> {
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

#[allow(clippy::too_many_arguments)]
fn plan<'a>(
    func: &HighFunction,
    memory: &sordec_ir::MemoryImage,
    structs: &'a [StructDef],
    unions: &[UnionDef],
    param_types: &HashMap<(FuncId, usize), Option<TypeId>>,
    helpers: &HashMap<FuncId, DecoderHelper>,
    access: &HashMap<FuncId, Vec<Option<ParamAccess>>>,
    wide_writes: &[CertainWrite],
) -> Planned {
    let mut elisions = Vec::new();
    let mut declines: Vec<&'static str> = Vec::new();
    let mut typed = Vec::new();
    let mut guards = HashMap::new();
    let mut limbs = Vec::new();
    let mut candidates: Vec<Candidate<'a>> = Vec::new();
    let order = sret::emission_order(func);

    for &id in &order {
        let Some(binding) = func.bindings.get(id) else {
            continue;
        };
        match &binding.expr {
            Expr::Semantic(SemanticOp::Known(KnownOp::MapOp {
                kind: MapOpKind::UnpackToLinearMemory,
                args,
            })) => {
                let Some((map, keys_pos, vals, len)) = unpack_operands(func, args) else {
                    declines.push(metrics::UDT_DECLINED_OPERANDS);
                    trace(func, "unpack operands not resolved");
                    continue;
                };
                let Some(keys) = read_keys(memory, keys_pos, len) else {
                    declines.push(metrics::UDT_DECLINED_KEYS);
                    trace(func, "key table not readable");
                    continue;
                };
                let map = resolve_use(func, map);
                // Field names several structs share say only "one of
                // these"; the value's own declaration says which.
                let payload_of = option_payload(func, map);
                let Some(def) = struct_for(structs, &keys)
                    .or_else(|| declared_struct(func, map, structs, &keys, param_types))
                    .or_else(|| {
                        let def = structs.iter().find(|s| Some(s.id) == payload_of)?;
                        has_keys(def, &keys).then_some(def)
                    })
                else {
                    declines.push(metrics::UDT_DECLINED_NO_STRUCT);
                    trace(func, &format!("no struct has exactly these keys {keys:?}, and {map:?} declares none of them"));
                    continue;
                };
                // An `Option<T>` parameter's payload: the unpack traps on
                // `None` (`Void` is no map), so where it returns the value is
                // a `T`. The parameter itself stays typed `Option<T>`.
                let payload = payload_of == Some(def.id);
                if !payload {
                    let Some(evidence) = value_evidence(func, map, def.id, param_types) else {
                        declines.push(metrics::UDT_DECLINED_EVIDENCE);
                        trace(func, "map value not proven to be the struct");
                        continue;
                    };
                    typed.push((map, evidence));
                }
                let (base, start) = canon_addr(func, vals);
                let slots = keys
                    .into_iter()
                    .enumerate()
                    .map(|(i, k)| Slot { rel: SLOT * i as u32, width: SLOT, role: Role::Field(k) })
                    .collect();
                candidates.push(Candidate { base, start, producer: id, map, def, slots, vals: true, payload });
            }
            // A helper-shaped decode: its out-parameter holds the struct's
            // fields, provided the value it was handed is proven to be
            // that struct.
            Expr::Call { target, args } => {
                let Some(h) = helpers.get(target) else { continue };
                if args.len() != 2 {
                    trace(func, "helper call arity");
                    continue;
                }
                let map = resolve_use(func, args[1]);
                match udt_of(func, map) {
                    Some(t) if t == h.ty => {}
                    // A host result the helper decodes: the decode is the
                    // proof of what was stored, as it is in a body.
                    None if host_result(func, map) => {
                        typed.push((map, IrType::Known(KnownType::UserDefined(h.ty))));
                    }
                    other => {
                        trace(func, &format!("helper call: value {map:?} is {other:?}, wanted {:?}", h.ty));
                        continue;
                    }
                }
                let Some(def) = structs.iter().find(|s| s.id == h.ty) else {
                    trace(func, "helper struct missing");
                    continue;
                };
                trace(func, &format!("helper frame claimed for func_{}", IrId::index(*target)));
                let (base, start) = canon_addr(func, args[0]);
                candidates.push(Candidate {
                    base,
                    start,
                    producer: id,
                    map,
                    def,
                    slots: h.slots.clone(),
                    vals: false,
                    payload: false,
                });
            }
            _ => {}
        }
    }
    if candidates.is_empty() {
        return Planned { elisions, declines, typed, guards, inverted: HashMap::new(), limbs };
    }

    // Each decode's reads, or why the site is refused. The other decodes
    // are certain overwrites of what they write.
    let mut certain: Vec<CertainWrite> =
        candidates.iter().map(|c| (c.producer, c.base, c.certain_writes())).collect();
    certain.extend(wide_writes.iter().cloned());
    let mut accepted: Vec<(usize, Vec<(ValueId, usize)>)> = Vec::new();
    // The derived per-field tag checks each accepted decode carries, as
    // `(decode, load, guard conditions, field, tag)`.
    let mut checks: Vec<(usize, ValueId, Vec<ValueId>, String, u8)> = Vec::new();
    let uses = crate::dataflow::HighUseIndex::build(func);
    let traps = trap_guards(func);
    let inverted_traps = inverted_trap_guards(func);
    // Whole-word reads of an `Option` payload's slots, each only tested by
    // its field's derived check: `(decode, load, field, tag, check)`.
    let mut words: Vec<(usize, ValueId, String, u8, WordCheck)> = Vec::new();
    let mut inverted: HashMap<ValueId, String> = HashMap::new();
    for (ci, cand) in candidates.iter().enumerate() {
        match reach::check(func, cand, &certain, access) {
            Ok(reads) if reads.fields.is_empty() && reads.tags.is_empty() => {}
            Ok(reads) => {
                let mut found = Vec::new();
                let mut why = None;
                for (load, slot, tag) in &reads.tags {
                    let Role::Field(field) = &cand.slots[*slot].role else { continue };
                    match derived_tag_check(func, &uses, &traps, *load, *tag) {
                        Some(conds) => found.push((ci, *load, conds, field.clone(), *tag)),
                        None => {
                            why = Some(format!("{load:?} reads {field}'s tag for something other than its derived check"));
                            break;
                        }
                    }
                }
                // An `Option`'s payload has no field to read into: each
                // read must be its field's derived check, relocated whole.
                let mut held = Vec::new();
                if why.is_none() && cand.payload {
                    for (load, slot) in &reads.fields {
                        let Role::Field(field) = &cand.slots[*slot].role else { continue };
                        let tag = cand.field_type(field).as_ref().and_then(sole_tag);
                        match tag.and_then(|t| Some((t, checked_word(func, &uses, &traps, &inverted_traps, *load, t)?))) {
                            Some((t, found)) => held.push((ci, *load, field.clone(), t, found)),
                            None => {
                                why = Some(format!("{load:?} reads the payload's {field}, which no expression spells"));
                                break;
                            }
                        }
                    }
                }
                if let Some(why) = why {
                    declines.push(metrics::UDT_DECLINED_READS);
                    trace(func, &format!("decode {:?} refused: {why}", cand.producer));
                    continue;
                }
                checks.extend(found);
                if cand.payload {
                    words.extend(held);
                    accepted.push((ci, Vec::new()));
                } else {
                    accepted.push((ci, reads.fields));
                }
            }
            Err(why) => {
                declines.push(metrics::UDT_DECLINED_READS);
                trace(func, &format!("decode {:?} refused: {why}", cand.producer));
            }
        }
    }
    // A read two decodes both claim is explained by neither: refuse both.
    // (The overwrite rules make this unreachable; it is the backstop.)
    let mut claims: HashMap<ValueId, usize> = HashMap::new();
    for (_, reads) in &accepted {
        for (load, _) in reads {
            *claims.entry(*load).or_default() += 1;
        }
    }
    for load in checks.iter().map(|c| c.1).chain(words.iter().map(|w| w.1)) {
        *claims.entry(load).or_default() += 1;
    }
    accepted.retain(|(ci, reads)| {
        let alone = reads.iter().all(|(load, _)| claims.get(load) == Some(&1))
            && checks.iter().map(|c| (c.0, c.1)).chain(words.iter().map(|w| (w.0, w.1))).filter(|c| c.0 == *ci).all(|(_, load)| claims.get(&load) == Some(&1));
        if !alone {
            trace(func, &format!("decode {:?} refused: a read is claimed twice", candidates[*ci].producer));
        }
        alone
    });
    checks.retain(|c| accepted.iter().any(|(ci, _)| *ci == c.0));
    words.retain(|c| accepted.iter().any(|(ci, _)| *ci == c.0));
    for (ci, load, field, tag, check) in &words {
        let def = &candidates[*ci].def.name;
        let what = crate::val_abi::tag_name(*tag).unwrap_or("its tag");
        let note = format!(
            "derived `{def}` decode of an `Option`'s payload: `{field}` is checked to be a {what}, regenerated by `TryFromVal`"
        );
        for cond in &check.guards {
            guards.insert(*cond, note.clone());
        }
        for cond in &check.inverted {
            inverted.insert(*cond, note.clone());
        }
        for id in std::iter::once(load).chain(&check.tests) {
            elisions.push(Elision {
                id: *id,
                expr: Expr::Literal(Literal::Unit),
                ty: Some(IrType::Known(KnownType::Unit)),
                note: note.clone(),
                metric: metrics::UDT_FIELDS_RECOVERED,
            });
        }
    }
    // The derived per-field type check: relocated with the decode, as a
    // declared parameter's own tag check is (`guard`). The byte read goes
    // with it; nothing else reads it.
    for (ci, load, conds, field, tag) in &checks {
        let def = &candidates[*ci].def.name;
        let what = crate::val_abi::tag_name(*tag).unwrap_or("its tag");
        for cond in conds {
            guards.insert(
                *cond,
                format!("derived `{def}` decode: `{field}` is checked to be a {what}, regenerated by `TryFromVal`"),
            );
        }
        elisions.push(Elision {
            id: *load,
            expr: Expr::Literal(Literal::Unit),
            ty: Some(IrType::Known(KnownType::Unit)),
            note: format!("derived `{def}` decode: the tag byte of `{field}`, read only by its type check"),
            metric: metrics::UDT_FIELDS_RECOVERED,
        });
    }

    // Rewrite the reads in emission order: a wide field's two halves share
    // one binding when the second follows the first.
    let position: HashMap<ValueId, usize> = order.iter().enumerate().map(|(i, v)| (*v, i)).collect();
    let mut reads: Vec<(ValueId, usize, usize)> = accepted
        .iter()
        .flat_map(|(ci, reads)| reads.iter().map(move |(load, slot)| (*load, *ci, *slot)))
        .collect();
    reads.sort_by_key(|(load, ..)| position.get(load).copied().unwrap_or(usize::MAX));
    // Loads rebound to a field, with the field's type, for the niche test.
    let mut rebound: Vec<(ValueId, KnownType)> = Vec::new();
    for (id, ci, si) in reads {
        let cand = &candidates[ci];
        let slot = &cand.slots[si];
        let Some(binding) = func.bindings.get(id) else { continue };
        match &slot.role {
            Role::Disc => elisions.push(Elision {
                id,
                expr: Expr::Literal(ok_discriminant(&binding.ty)),
                ty: None,
                note: format!(
                    "derived `{}` decode discriminant is Ok: the value was proven at its boundary",
                    cand.def.name
                ),
                metric: metrics::UDT_FIELDS_RECOVERED,
            }),
            Role::Limb(field, half) => {
                // `exact_read` takes a half only when the field's type is
                // known.
                let Some(k) = cand.field_type(field) else { continue };
                limbs.push((id, cand.map, field.clone(), k, *half));
            }
            Role::Field(field) => {
                let known = cand.field_type(field);
                if let Some(k) = &known {
                    rebound.push((id, k.clone()));
                }
                elisions.push(Elision {
                    id,
                    expr: Expr::Field { base: cand.map, field: field.clone() },
                    ty: known.map(IrType::Known),
                    note: format!("{}.{field}: slot +{} of the derived struct decode", cand.def.name, slot.rel),
                    metric: metrics::UDT_FIELDS_RECOVERED,
                });
            }
            Role::Unexplained => {}
        }
    }
    for (ci, _) in &accepted {
        let cand = &candidates[*ci];
        let is_call = matches!(func.bindings.get(cand.producer).map(|b| &b.expr), Some(Expr::Call { .. }));
        let (note, metric) = if is_call {
            (
                format!("call to the derived `{}` decode helper, elided with its out-parameter", cand.def.name),
                metrics::UDT_HELPERS_COLLAPSED,
            )
        } else {
            (
                format!("derived `{}` decode: the unpack, elided with its slots", cand.def.name),
                metrics::UDT_DECODES_COLLAPSED,
            )
        };
        elisions.push(Elision {
            id: cand.producer,
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
    Planned { elisions, declines, typed, guards, inverted, limbs }
}

/// The conditions of every `if c { trap }` with no else arm, by how many
/// such guards test each.
pub(super) fn trap_guards(func: &HighFunction) -> HashMap<ValueId, usize> {
    let empty = super::guard::empty_blocks(func);
    let mut out: HashMap<ValueId, usize> = HashMap::new();
    func.region.for_each_node(|r| {
        if let sordec_ir::Region::If { cond, then_region, else_region: None } = r
            && super::guard::is_trap(then_region, &empty)
        {
            *out.entry(*cond).or_default() += 1;
        }
    });
    out
}

/// The conditions of every `if c { .. } else { trap }`, by how many such
/// guards test each.
fn inverted_trap_guards(func: &HighFunction) -> HashMap<ValueId, usize> {
    let empty = super::guard::empty_blocks(func);
    let mut out: HashMap<ValueId, usize> = HashMap::new();
    func.region.for_each_node(|r| {
        if let sordec_ir::Region::If { cond, else_region: Some(e), .. } = r
            && super::guard::is_trap(e, &empty)
        {
            *out.entry(*cond).or_default() += 1;
        }
    });
    out
}

/// How a whole-slot read is only its field's derived check.
#[derive(Debug, Default)]
struct WordCheck {
    /// The tag tests on the word.
    tests: Vec<ValueId>,
    /// Their uses as `if t { trap }` (a mismatch test).
    guards: Vec<ValueId>,
    /// Their uses as `if t { .. } else { trap }` (a match test).
    inverted: Vec<ValueId>,
}

/// The tag tests through which a whole-slot read is only its field's
/// derived check, or `None` when the word is used for anything else.
///
/// Every use of the word must be a tag test against `tag`, the one tag
/// the field's declared type is carried by; a mismatch test may only be
/// the condition of `if t { trap }`, a match test only of
/// `if t { .. } else { trap }`. Then the word decides nothing but "trap
/// unless the field is a `tag`".
fn checked_word(
    func: &HighFunction,
    uses: &crate::dataflow::HighUseIndex,
    traps: &HashMap<ValueId, usize>,
    inverted: &HashMap<ValueId, usize>,
    load: ValueId,
    tag: u8,
) -> Option<WordCheck> {
    use crate::dataflow::HighUseSite;
    let sites = uses.uses_of(load);
    if sites.is_empty() {
        return None;
    }
    let mut out = WordCheck::default();
    for site in sites {
        let HighUseSite::Binding { user } = site else { return None };
        let expr = func.bindings.get(*user).map(|b| &b.expr);
        // Arithmetic on the word that nothing reads — the `word & 255` the
        // tag test was recognised from — decides nothing; it goes too.
        if matches!(expr, Some(Expr::Binary { .. } | Expr::Unary { .. })) && uses.uses_of(*user).is_empty() {
            out.tests.push(*user);
            continue;
        }
        let Some(Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck { value, tag: t, negated }))) = expr else {
            return None;
        };
        if resolve_use(func, *value) != load || *t != tag {
            return None;
        }
        let n = uses.uses_of(*user);
        if n.is_empty() || !n.iter().all(|s| matches!(s, HighUseSite::Region)) {
            return None;
        }
        let (table, into) = if *negated { (traps, &mut out.guards) } else { (inverted, &mut out.inverted) };
        if table.get(user).copied().unwrap_or(0) != n.len() {
            return None;
        }
        into.push(*user);
        out.tests.push(*user);
    }
    Some(out)
}

/// `if c { then } else { trap }` with `c` in `conds` becomes `then`: the
/// trap is a derived check that moved into the regenerated conversion.
fn strip_inverted(
    region: sordec_ir::Region,
    conds: &HashMap<ValueId, String>,
    empty: &std::collections::HashSet<sordec_common::BlockId>,
    elided: &mut i64,
) -> sordec_ir::Region {
    use sordec_ir::Region;
    let go = |r: Region, elided: &mut i64| strip_inverted(r, conds, empty, elided);
    match region {
        Region::Sequence(items) => {
            crate::structuring::seq(items.into_iter().map(|i| go(i, elided)).collect())
        }
        Region::Scope { out, body } => Region::Scope { out, body: Box::new(go(*body, elided)) },
        Region::Loop { header, body, kind } => Region::Loop { header, body: Box::new(go(*body, elided)), kind },
        Region::Switch { index, arms, default, dispatch } => Region::Switch {
            index,
            arms: arms
                .into_iter()
                .map(|mut arm| {
                    arm.body = go(arm.body, elided);
                    arm
                })
                .collect(),
            default: Box::new(go(*default, elided)),
            dispatch,
        },
        Region::If { cond, then_region, else_region: Some(e) }
            if conds.contains_key(&cond) && super::guard::is_trap(&e, empty) =>
        {
            *elided += 1;
            go(*then_region, elided)
        }
        Region::If { cond, then_region, else_region } => Region::If {
            cond,
            then_region: Box::new(go(*then_region, elided)),
            else_region: else_region.map(|e| Box::new(go(*e, elided))),
        },
        other => other,
    }
}

/// The guard conditions through which a one-byte read of a field's tag
/// is the derived conversion's check of that field, or `None` when it is
/// read for anything else.
///
/// Every use of the byte must be `byte != tag`, against the one tag the
/// field's declared type is carried by, and every use of each such
/// comparison must be the condition of a guard whose arm is a bare trap
/// with no else: then the byte decides nothing but "trap unless the field
/// is a `tag`", which is the derived `TryFromVal`'s check for that type.
pub(super) fn derived_tag_check(
    func: &HighFunction,
    uses: &crate::dataflow::HighUseIndex,
    traps: &HashMap<ValueId, usize>,
    load: ValueId,
    tag: u8,
) -> Option<Vec<ValueId>> {
    use crate::dataflow::HighUseSite;
    let sites = uses.uses_of(load);
    if sites.is_empty() {
        return None;
    }
    let mut conds = Vec::new();
    for site in sites {
        let HighUseSite::Binding { user } = site else { return None };
        let Some(Expr::Binary { op: sordec_ir::BinaryOp::Ne, lhs, rhs }) = func.bindings.get(*user).map(|b| &b.expr)
        else {
            return None;
        };
        let (l, r) = (resolve_use(func, *lhs), resolve_use(func, *rhs));
        let other = if l == load {
            r
        } else if r == load {
            l
        } else {
            return None;
        };
        if trace_int(func, other) != Some(i128::from(tag)) {
            return None;
        }
        // Every use of the comparison is a trap guard's condition.
        let n = uses.uses_of(*user);
        if n.is_empty() || !n.iter().all(|s| matches!(s, HighUseSite::Region)) {
            return None;
        }
        if traps.get(user).copied().unwrap_or(0) != n.len() {
            return None;
        }
        conds.push(*user);
    }
    Some(conds)
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

// ---------------------------------------------------------------------
// Recovering the struct itself, where the module carries no spec
// ---------------------------------------------------------------------

/// Name given to a struct recovered from its own key table.
///
/// The key table names every *field*; nothing names the type. A
/// synthesized name says that much and no more — the alternative is to
/// guess an identifier from the storage key the value happens to be
/// filed under, which is a different thing from recovering it.
const SYNTHESIZED_STRUCT: &str = "Record";

/// Recover a `#[contracttype]` struct from each derived unpack, for a
/// module that carries no `contractspecv0`.
///
/// The key table is already the thing this pass matches a declaration
/// against — `#[contracttype]` writes the field names into rodata so the
/// derived `TryFromVal` can unpack a map by them. With a spec the table
/// only has to *identify* a declared struct; without one it is the
/// declaration, minus the type's name and its field types.
///
/// Returns how many structs were recovered.
fn synthesize_structs(ir: &mut HighIr) -> i64 {
    let mut tables: Vec<Vec<String>> = Vec::new();
    for func in &ir.functions {
        for (_, binding) in func.bindings.iter() {
            let Expr::Semantic(SemanticOp::Known(KnownOp::MapOp {
                kind: MapOpKind::UnpackToLinearMemory,
                args,
            })) = &binding.expr
            else {
                continue;
            };
            let Some((_, keys_pos, _, len)) = unpack_operands(func, args) else {
                continue;
            };
            let Some(keys) = read_keys(&ir.memory, keys_pos, len) else {
                continue;
            };
            // A field set is a field set: two unpacks of the same struct
            // read the same table, and one struct is what they name.
            if keys.len() > 1 && !tables.contains(&keys) {
                tables.push(keys);
            }
        }
    }
    if tables.is_empty() {
        return 0;
    }
    let facts = ir.soroban_facts.get_or_insert_with(SorobanFacts::default);
    let base = facts.types.next_id();
    for (i, keys) in tables.iter().enumerate() {
        let name = if i == 0 {
            SYNTHESIZED_STRUCT.to_owned()
        } else {
            format!("{SYNTHESIZED_STRUCT}{i}")
        };
        facts.types.structs.push(StructDef {
            id: TypeId::from_index(base + i as u32),
            name,
            fields: keys
                .iter()
                .map(|field| StructField {
                    name: field.clone(),
                    ty: TypeRef::Unknown(UnknownReason::InsufficientEvidence),
                })
                .collect(),
        });
    }
    tables.len() as i64
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

/// The struct `map`'s own declaration names, when its field names are
/// exactly `keys`: the type an earlier decode or the tuple-parameter
/// pass put on its binding from the contract spec, an entrypoint
/// parameter's declared type, or — for a helper parameter — the struct
/// every caller agrees it is handed.
///
/// This is how a key table several structs share (`{ val }` is a common
/// shape) is told apart: the spec says what the value is, and the table
/// must still match that struct field for field. The declaration picks
/// among the candidates; it never overrides the keys.
fn declared_struct<'a>(
    func: &HighFunction,
    map: ValueId,
    structs: &'a [StructDef],
    keys: &[String],
    param_types: &HashMap<(FuncId, usize), Option<TypeId>>,
) -> Option<&'a StructDef> {
    let id = udt_of(func, map).or_else(|| {
        let index = func.params.iter().position(|p| *p == map)?;
        match param_types.get(&(func.id, index)) {
            Some(Some(t)) if func.signature.is_none() => Some(*t),
            _ => None,
        }
    })?;
    let def = structs.iter().find(|s| s.id == id)?;
    has_keys(def, keys).then_some(def)
}

/// Whether `def`'s field names are exactly `keys`.
fn has_keys(def: &StructDef, keys: &[String]) -> bool {
    let mut want: Vec<&str> = keys.iter().map(String::as_str).collect();
    want.sort_unstable();
    let mut have: Vec<&str> = def.fields.iter().map(|f| f.name.as_str()).collect();
    have.sort_unstable();
    have == want
}

/// The struct `T` when `map` is an entrypoint parameter the spec declares
/// `Option<T>`.
fn option_payload(func: &HighFunction, map: ValueId) -> Option<TypeId> {
    let sig = func.signature.as_ref()?;
    let index = func.params.iter().position(|p| *p == map)?;
    match known_of_type_ref(&sig.inputs.get(index)?.ty)? {
        KnownType::Option(inner) => match *inner {
            IrType::Known(KnownType::UserDefined(id)) => Some(id),
            _ => None,
        },
        _ => None,
    }
}

/// Why the map value may be read as the struct: a host operation's result
/// (the decode is the proof of what was stored), an entrypoint parameter
/// declared with the type, or a field of a struct recovered this way.
fn value_evidence(
    func: &HighFunction,
    map: ValueId,
    id: TypeId,
    param_types: &HashMap<(FuncId, usize), Option<TypeId>>,
) -> Option<IrType> {
    let ty = IrType::Known(KnownType::UserDefined(id));
    if let Some(index) = func.params.iter().position(|p| *p == map) {
        if let Some(sig) = func.signature.as_ref() {
            let declared = known_of_type_ref(&sig.inputs.get(index)?.ty)?;
            return (declared == KnownType::UserDefined(id)).then_some(ty);
        }
        // A helper parameter: every caller passes a value already proven
        // to be this struct, or one whose type only this decode can prove.
        match param_types.get(&(func.id, index)) {
            Some(Some(known)) if *known == id => return Some(ty),
            Some(None) => return Some(ty),
            _ => {}
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
    host_result(func, map).then_some(ty)
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
///
/// Each slot is stored at one width, and no two slots overlap, so a read
/// of a slot can be checked against exactly the bytes the helper wrote.
struct DecoderHelper {
    ty: TypeId,
    /// Ascending by offset.
    slots: Vec<Slot>,
}

fn classify_helper(
    func: &HighFunction,
    structs: &[StructDef],
    unions: &[UnionDef],
    scalars: &HashMap<FuncId, KnownType>,
) -> Option<DecoderHelper> {
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
    let mut widths: BTreeMap<u32, u32> = BTreeMap::new();
    for id in sret::emission_order(func) {
        let binding = func.bindings.get(id)?;
        match &binding.expr {
            Expr::Store { addr, value, offset, width } if resolve_use(func, *addr) == out => {
                slots.entry(*offset).or_default().push(*value);
                // One width per slot: two would leave a read of it
                // matching one store and not the other.
                if *widths.entry(*offset).or_insert(width.bytes()) != width.bytes() {
                    trace(func, &format!("slot +{offset} is stored at two widths"));
                    return None;
                }
            }
            // A field's derived scalar decode, handed that field and
            // nothing of `out`; `field_source` reads its value component.
            Expr::Call { target, args } if scalars.contains_key(target) && args.len() == 1 => {
                if resolve_use(func, args[0]) == out {
                    trace(func, "out-pointer handed to a scalar decoder");
                    return None;
                }
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
    let mut limbs: BTreeMap<u32, sordec_ir::UnaryOp> = BTreeMap::new();
    let mut discs: Vec<u32> = Vec::new();
    for (offset, values) in &slots {
        let mut names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let mut consts: std::collections::BTreeSet<i128> = std::collections::BTreeSet::new();
        let mut arms: Vec<ValueId> = Vec::new();
        for v in values {
            flat_arms(func, *v, 6, &mut arms);
        }
        for arm in &arms {
            match field_source(func, *arm, val, scalars, def) {
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
                // Every arm the same half of the field, or every arm the
                // whole of it.
                let mut halves: Vec<Option<sordec_ir::UnaryOp>> = Vec::new();
                for a in arms.iter().filter(|a| field_source(func, **a, val, scalars, def).is_some()) {
                    let half = half_of(func, *a, val);
                    if !halves.contains(&half) {
                        halves.push(half);
                    }
                }
                match halves.as_slice() {
                    [None] => {}
                    [Some(half)] => {
                        limbs.insert(*offset, *half);
                    }
                    _ => {
                        trace(func, &format!("slot +{offset}: arms disagree on which half of the field"));
                        return None;
                    }
                }
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
    // A discriminant is read as `Ok` only if every returning path wrote
    // it; a constant some paths leave unwritten explains no read.
    let must: Vec<(u32, u32)> = param_accesses(func)
        .into_iter()
        .next()
        .flatten()
        .map(|a| a.must_writes)
        .unwrap_or_default();
    let mut out_slots: Vec<Slot> = Vec::new();
    for (offset, width) in &widths {
        let role = if let Some(name) = fields.get(offset) {
            match limbs.get(offset) {
                Some(half) => Role::Limb(name.clone(), *half),
                None => Role::Field(name.clone()),
            }
        } else if discs.contains(offset) && must.contains(&(*offset, *width)) {
            Role::Disc
        } else {
            Role::Unexplained
        };
        if let Some(prev) = out_slots.last()
            && u64::from(prev.rel) + u64::from(prev.width) > u64::from(*offset)
        {
            trace(func, &format!("slots +{} and +{offset} overlap", prev.rel));
            return None;
        }
        out_slots.push(Slot { rel: *offset, width: *width, role });
    }
    trace(func, &format!("decoder helper for {}: slots {out_slots:?}", def.name));
    Some(DecoderHelper { ty, slots: out_slots })
}

/// What a function does through one of its parameters, when that
/// parameter is only ever the address of a load or a store in it: a call
/// to it touches the memory it is handed there at these offsets and no
/// others.
#[derive(Debug, Clone, Default)]
pub(super) struct ParamAccess {
    /// `(offset, width)` of every load through the parameter.
    pub(super) reads: Vec<(u32, u32)>,
    /// `(offset, width)` of every store through it.
    pub(super) writes: Vec<(u32, u32)>,
    /// The stores made on every path the function returns by.
    pub(super) must_writes: Vec<(u32, u32)>,
}

/// [`ParamAccess`] for each parameter of a helper, `None` for one used any
/// other way (passed on, stored, computed with). Entrypoints get none:
/// their parameters are ABI values, never caller memory.
pub(super) fn param_accesses(func: &HighFunction) -> Vec<Option<ParamAccess>> {
    if func.signature.is_some() {
        return Vec::new();
    }
    let params = &func.params;
    let index = |v: ValueId| {
        let v = resolve_use(func, v);
        params.iter().position(|p| *p == v)
    };
    let mut access: Vec<Option<ParamAccess>> = vec![Some(ParamAccess::default()); params.len()];
    for id in sret::emission_order(func) {
        let Some(binding) = func.bindings.get(id) else {
            return vec![None; params.len()];
        };
        match &binding.expr {
            Expr::Load { addr, offset, width, .. } => {
                if let Some(k) = index(*addr)
                    && let Some(a) = &mut access[k]
                {
                    a.reads.push((*offset, width.bytes()));
                }
            }
            Expr::Store { addr, value, offset, width } => {
                if let Some(k) = index(*addr)
                    && let Some(a) = &mut access[k]
                {
                    a.writes.push((*offset, width.bytes()));
                }
                if let Some(k) = index(*value) {
                    access[k] = None;
                }
            }
            other => other.for_each_value_use(|u| {
                if let Some(k) = index(u) {
                    access[k] = None;
                }
            }),
        }
    }
    func.region.for_each_value_use(|u| {
        if let Some(k) = index(u) {
            access[k] = None;
        }
    });
    for (k, slot) in access.iter_mut().enumerate() {
        let Some(a) = slot else { continue };
        if a.writes.is_empty() {
            continue;
        }
        let mut flow = reach::StoresThrough { func, param: params[k] };
        let walked = reach::walk(func, &mut flow, BTreeMap::new());
        if let Some(stored) = walked.returned
            && walked.complete
        {
            a.must_writes = stored.into_iter().collect();
        }
    }
    access
}

/// Which reads a decode reaches, by a forward walk of the region tree.
///
/// [`walk`] is the walk: it runs a [`Flow`] over every scheduled binding in
/// execution order, with the state of each path. Both arms of a branch
/// start from the state at the branch and meet where they join; a `break`
/// carries its state to the end of the scope it leaves, a `continue` back
/// to the loop's head, and a loop body is walked again from the meet of
/// its entry and its back edges until that stops changing. Code after a
/// `return`, `break` or trap is not reached and not walked.
///
/// [`check`] is the decode's flow over that walk (see the module docs for
/// what it decides and why).
pub(super) mod reach {
    use std::collections::{BTreeMap, BTreeSet, HashMap};

    use sordec_common::{BlockId, FuncId, ValueId};
    use sordec_ir::{Expr, HighFunction, KnownOp, MapOpKind, MemWidth, Region, SemanticOp, VecOpKind};

    use super::{raw_address, unpack_operands, Candidate, CertainWrite, ParamAccess, Role};
    use crate::dataflow::{canon_addr, resolve_use, trace_u32val};

    /// How many times one loop body is walked before the walk gives up.
    const LOOP_LIMIT: usize = 64;
    /// How many bindings [`DecodeFlow::derived`] looks through before it
    /// assumes the worst.
    const DERIVE_BUDGET: usize = 64;

    /// A forward analysis the walk drives.
    pub(in crate::marshalling) trait Flow {
        type State: Clone + PartialEq;
        /// Meet two paths' states where they join.
        fn join(into: &mut Self::State, other: &Self::State);
        /// Advance the state over one binding.
        fn step(&mut self, id: ValueId, state: &mut Self::State);
        /// Enter one side of an `if` on `cond`: `taken` is the `then` side.
        fn branch(&mut self, _cond: ValueId, _taken: bool, _state: &mut Self::State) {}
        /// Enter one arm of a switch on `index`: `cases` are the arm's
        /// (`None` for the default arm), `all` every arm's.
        fn arm(&mut self, _index: ValueId, _cases: Option<&[u32]>, _all: &[u32], _state: &mut Self::State) {}
    }

    /// The meet of the states at every `return` (falling off the end
    /// included), and whether the whole tree was walked: an unstructured
    /// remnant, a missing block or a loop that did not settle leaves it
    /// incomplete, and nothing it says can be relied on.
    pub(in crate::marshalling) struct Walked<S> {
        pub returned: Option<S>,
        pub complete: bool,
    }

    pub(in crate::marshalling) fn walk<F: Flow>(func: &HighFunction, flow: &mut F, entry: F::State) -> Walked<F::State> {
        let mut walker = Walker { func, flow, breaks: HashMap::new(), continues: HashMap::new(), returned: None, complete: true };
        let end = walker.region(&func.region, Some(entry));
        walker.returned = merge::<F>(walker.returned.take(), end);
        // A `break` or `continue` no enclosing construct took: its path
        // was dropped, so the walk saw less than the function does.
        if !walker.breaks.is_empty() || !walker.continues.is_empty() {
            walker.complete = false;
        }
        Walked { returned: walker.returned, complete: walker.complete }
    }

    fn merge<F: Flow>(a: Option<F::State>, b: Option<F::State>) -> Option<F::State> {
        match (a, b) {
            (Some(mut x), Some(y)) => {
                F::join(&mut x, &y);
                Some(x)
            }
            (x, None) => x,
            (None, y) => y,
        }
    }

    struct Walker<'w, F: Flow> {
        func: &'w HighFunction,
        flow: &'w mut F,
        /// The meet of the states at `break`s to each scope still open.
        breaks: HashMap<BlockId, F::State>,
        /// The meet of the states at `continue`s to each loop still open.
        continues: HashMap<BlockId, F::State>,
        returned: Option<F::State>,
        complete: bool,
    }

    impl<F: Flow> Walker<'_, F> {
        /// Walk `region` from `state` (`None`: not reached); the state
        /// falling out of its bottom.
        fn region(&mut self, region: &Region, state: Option<F::State>) -> Option<F::State> {
            let mut state = state?;
            match region {
                Region::Basic(b) => {
                    let Some(block) = self.func.blocks.get(*b) else {
                        self.complete = false;
                        return Some(state);
                    };
                    for &id in &block.bindings {
                        self.flow.step(id, &mut state);
                    }
                    Some(state)
                }
                Region::Sequence(items) => {
                    let mut cur = Some(state);
                    for item in items {
                        cur = self.region(item, cur);
                    }
                    cur
                }
                Region::Scope { out, body } => {
                    // A scope inside with the same label takes its own
                    // breaks; ours are kept apart until it closes.
                    let outer = self.breaks.remove(out);
                    let fall = self.region(body, Some(state));
                    let broke = self.breaks.remove(out);
                    if let Some(o) = outer {
                        self.breaks.insert(*out, o);
                    }
                    merge::<F>(fall, broke)
                }
                Region::If { cond, then_region, else_region } => {
                    let mut then_in = state.clone();
                    self.flow.branch(*cond, true, &mut then_in);
                    let then_out = self.region(then_region, Some(then_in));
                    self.flow.branch(*cond, false, &mut state);
                    let else_out = match else_region {
                        Some(e) => self.region(e, Some(state)),
                        None => Some(state),
                    };
                    merge::<F>(then_out, else_out)
                }
                Region::Switch { index, arms, default, .. } => {
                    let all: Vec<u32> = arms.iter().flat_map(|a| a.cases.iter().copied()).collect();
                    let mut default_in = state.clone();
                    self.flow.arm(*index, None, &all, &mut default_in);
                    let mut out = self.region(default, Some(default_in));
                    for arm in arms {
                        let mut arm_in = state.clone();
                        self.flow.arm(*index, Some(&arm.cases), &all, &mut arm_in);
                        let arm_out = self.region(&arm.body, Some(arm_in));
                        out = merge::<F>(out, arm_out);
                    }
                    out
                }
                Region::Loop { header, body, .. } => {
                    let entry = state;
                    let mut head = entry.clone();
                    for _ in 0..LOOP_LIMIT {
                        let outer = self.continues.remove(header);
                        // Falling off the bottom of the body runs it again.
                        let fall = self.region(body, Some(head.clone()));
                        let back = merge::<F>(fall, self.continues.remove(header));
                        if let Some(o) = outer {
                            self.continues.insert(*header, o);
                        }
                        let mut next = entry.clone();
                        if let Some(b) = &back {
                            F::join(&mut next, b);
                        }
                        if next == head {
                            // A loop is left only by a `break`.
                            return None;
                        }
                        head = next;
                    }
                    self.complete = false;
                    None
                }
                Region::Break { target, .. } => {
                    let prev = self.breaks.remove(target);
                    if let Some(s) = merge::<F>(prev, Some(state)) {
                        self.breaks.insert(*target, s);
                    }
                    None
                }
                Region::Continue { target, .. } => {
                    let prev = self.continues.remove(target);
                    if let Some(s) = merge::<F>(prev, Some(state)) {
                        self.continues.insert(*target, s);
                    }
                    None
                }
                Region::Transfer { .. } => Some(state),
                Region::Return { .. } => {
                    self.returned = merge::<F>(self.returned.take(), Some(state));
                    None
                }
                Region::Unreachable | Region::Panic { .. } => None,
                Region::Unstructured { .. } => {
                    self.complete = false;
                    None
                }
            }
        }
    }

    /// The `(offset, width)` stores through `param` made on every path.
    pub(super) struct StoresThrough<'f> {
        pub func: &'f HighFunction,
        pub param: ValueId,
    }

    impl Flow for StoresThrough<'_> {
        type State = BTreeMap<u32, u32>;

        fn join(into: &mut Self::State, other: &Self::State) {
            into.retain(|offset, width| other.get(offset) == Some(width));
        }

        fn step(&mut self, id: ValueId, stored: &mut Self::State) {
            let Some(binding) = self.func.bindings.get(id) else { return };
            if let Expr::Store { addr, offset, width, .. } = &binding.expr
                && resolve_use(self.func, *addr) == self.param
            {
                let (lo, hi) = (u64::from(*offset), u64::from(*offset) + u64::from(width.bytes()));
                stored.retain(|o, w| {
                    let (a, b) = (u64::from(*o), u64::from(*o) + u64::from(*w));
                    b <= lo || hi <= a
                });
                stored.insert(*offset, width.bytes());
            }
        }
    }

    /// Where a decode's value still is. `must`: the slots that hold it
    /// whole on every path. `may`: per slot, a bit for each byte that
    /// holds it on some path (absent when none does) — a slot overwritten
    /// in part still has the rest of the decode's bytes in it.
    #[derive(Debug, Clone, Default, PartialEq)]
    pub(super) struct Live {
        must: BTreeSet<usize>,
        may: BTreeMap<usize, u8>,
        /// Tag words a [`Gated`] helper wrote, by offset from the base,
        /// not overwritten since: what the helper also wrote unless the
        /// tag is its `none` constant.
        pending: BTreeMap<u32, Pending>,
    }

    /// What a helper writes through a pointer parameter on every path on
    /// which the tag word it leaves at the pointer is not `none`: a
    /// helper handing back an `Option`-like result writes its payload
    /// only when it has one. Offsets are from the pointer.
    #[derive(Debug, Clone, PartialEq)]
    pub(in crate::marshalling) struct Gated {
        /// Width of the tag store at offset 0.
        pub width: u32,
        /// The tag that says nothing else was written.
        pub none: i128,
        /// `(offset, width)` written whenever the tag is anything else.
        pub writes: Vec<(u32, u32)>,
    }

    /// A [`Gated`] call's tag word as it sits in the frame, with its
    /// writes as offsets from the decode's base.
    #[derive(Debug, Clone, PartialEq)]
    struct Pending {
        width: u32,
        none: i128,
        writes: Vec<(u32, u32)>,
    }

    /// What a decode's value is read for, once every read it may reach
    /// is accounted for.
    #[derive(Debug, Default)]
    pub(in crate::marshalling) struct Reads {
        /// Exact reads of a slot, as `(load, slot)`.
        pub fields: Vec<(ValueId, usize)>,
        /// One-byte reads of a `Val` slot's tag, as `(load, slot, the
        /// field type's one tag)`. Each is the derived check only if every
        /// use of it is that check — which the caller decides, having the
        /// region tree.
        pub tags: Vec<(ValueId, usize, u8)>,
    }

    /// A decode's reads, when every read it may reach is an exact read of
    /// a slot, or of a `Val` slot's tag byte, that it wrote on every path,
    /// and nothing else may read its bytes meanwhile; otherwise why not.
    ///
    /// `certain` names every decode in the function with its base and the
    /// bytes it certainly writes; `access`, what each helper does through
    /// each of its parameters.
    pub(in crate::marshalling) fn check(
        func: &HighFunction,
        cand: &Candidate<'_>,
        certain: &[CertainWrite],
        access: &HashMap<FuncId, Vec<Option<ParamAccess>>>,
    ) -> Result<Reads, String> {
        check_gated(func, cand, certain, access, &HashMap::new())
    }

    /// [`check`], seeing through helpers whose writes a tag word gates
    /// ([`Gated`]): on the side of a branch where the tag the helper left
    /// is not its `none` constant, the helper made its gated writes.
    ///
    /// Exact because the walk knows the tag only as a load of it: a load
    /// of the whole tag store, made while nothing has written its bytes
    /// since the call, is the tag the helper left. A branch on that load
    /// — directly, or on its low 32 bits, which equal `none`'s whenever
    /// the word is `none`, so a side taken on their being different is
    /// one on which the word is not `none` — applies the writes only
    /// while the tag word is still unwritten, so they are that call's.
    pub(in crate::marshalling) fn check_gated(
        func: &HighFunction,
        cand: &Candidate<'_>,
        certain: &[CertainWrite],
        access: &HashMap<FuncId, Vec<Option<ParamAccess>>>,
        gated: &HashMap<FuncId, Vec<Option<Gated>>>,
    ) -> Result<Reads, String> {
        let mut flow = DecodeFlow {
            func,
            cand,
            certain,
            access,
            gated,
            tag_words: HashMap::new(),
            derived: HashMap::new(),
            reads: BTreeMap::new(),
            tags: BTreeMap::new(),
            refused: None,
        };
        let walked = walk(func, &mut flow, Live::default());
        if let Some(why) = flow.refused {
            return Err(why);
        }
        if !walked.complete {
            return Err("the control flow is not fully structured".to_string());
        }
        Ok(Reads {
            fields: flow.reads.into_iter().collect(),
            tags: flow.tags.into_iter().map(|(load, (slot, tag))| (load, slot, tag)).collect(),
        })
    }

    /// Where an operand points relative to the decode's frame base.
    enum Points {
        /// At the base plus this constant.
        At(u32),
        /// Somewhere computed from the base, at least this many bytes above
        /// it: `x | y` is never below `x`; a run-time offset, a phi or a
        /// select is known only to be somewhere (0).
        From(u32),
        /// Not at anything derived from the base.
        Elsewhere,
    }

    struct DecodeFlow<'c, 'a> {
        func: &'c HighFunction,
        cand: &'c Candidate<'a>,
        certain: &'c [CertainWrite],
        access: &'c HashMap<FuncId, Vec<Option<ParamAccess>>>,
        gated: &'c HashMap<FuncId, Vec<Option<Gated>>>,
        /// Loads of a [`Gated`] call's tag word: the tag's offset and what
        /// was pending there, the same on every visit (`None` once a visit
        /// disagrees, or saw nothing pending).
        tag_words: HashMap<ValueId, Option<(u32, Pending)>>,
        /// Memo for [`Self::derived`].
        derived: HashMap<ValueId, bool>,
        /// Exact reads seen so far, load -> slot.
        reads: BTreeMap<ValueId, usize>,
        /// Tag-byte reads seen so far, load -> (slot, tag).
        tags: BTreeMap<ValueId, (usize, u8)>,
        refused: Option<String>,
    }

    impl Flow for DecodeFlow<'_, '_> {
        type State = Live;

        fn join(into: &mut Live, other: &Live) {
            into.must.retain(|i| other.must.contains(i));
            for (i, bits) in &other.may {
                *into.may.entry(*i).or_default() |= *bits;
            }
            into.pending.retain(|at, p| other.pending.get(at) == Some(p));
        }

        fn branch(&mut self, cond: ValueId, taken: bool, live: &mut Live) {
            let Some(Expr::Binary { op, lhs, rhs }) =
                self.func.bindings.get(resolve_use(self.func, cond)).map(|b| &b.expr)
            else {
                return;
            };
            if !matches!((op, taken), (sordec_ir::BinaryOp::Ne, true) | (sordec_ir::BinaryOp::Eq, false)) {
                return;
            }
            for (word, other) in [(*lhs, *rhs), (*rhs, *lhs)] {
                if let Some((at, p)) = self.tag_word(word, live)
                    && crate::dataflow::trace_int(self.func, other) == Some(p.none)
                {
                    self.overwrite(live, &p.writes, true);
                    live.pending.remove(&at);
                    return;
                }
            }
        }

        fn arm(&mut self, index: ValueId, cases: Option<&[u32]>, all: &[u32], live: &mut Live) {
            let mut word = resolve_use(self.func, index);
            if let Some(Expr::Unary { op: sordec_ir::UnaryOp::Wrap32, value }) =
                self.func.bindings.get(word).map(|b| &b.expr)
            {
                word = resolve_use(self.func, *value);
            }
            let Some((at, p)) = self.tag_word(word, live) else { return };
            let Ok(none) = u32::try_from(p.none) else { return };
            // The arm is taken only when the selector is one of its cases
            // (the default: none of any arm's); a selector that is not
            // `none`'s low 32 bits comes from a word that is not `none`.
            let not_none = match cases {
                Some(cases) => !cases.contains(&none),
                None => all.contains(&none),
            };
            if not_none {
                self.overwrite(live, &p.writes, true);
                live.pending.remove(&at);
            }
        }

        fn step(&mut self, id: ValueId, live: &mut Live) {
            if self.refused.is_some() {
                return;
            }
            let cand = self.cand;
            if id == cand.producer {
                live.may = (0..cand.slots.len()).map(|i| (i, self.whole(i))).collect();
                live.must = (0..cand.slots.len()).filter(|i| cand.slots[*i].role != Role::Unexplained).collect();
                live.pending.clear();
                return;
            }
            if let Some((_, _, writes)) = self.certain.iter().find(|(p, b, _)| *p == id && *b == cand.base) {
                self.overwrite(live, writes, true);
                return;
            }
            let Some(binding) = self.func.bindings.get(id) else { return };
            match &binding.expr {
                Expr::Load { addr, offset, width, signed, .. } => match self.points(*addr) {
                    Points::Elsewhere => {}
                    Points::At(at) => self.load(id, live, at, *offset, *width, *signed),
                    Points::From(lowest) => {
                        if self.may_hold(live, u64::from(lowest), u64::MAX) {
                            self.refuse(format!("{id:?} reads the frame at a run-time offset"));
                        }
                    }
                },
                Expr::Store { addr, offset, width, .. } => match self.points(*addr) {
                    Points::Elsewhere => {}
                    Points::At(at) => match at.checked_add(*offset) {
                        Some(at) => self.overwrite(live, &[(at, width.bytes())], true),
                        None => live.must.clear(),
                    },
                    Points::From(lowest) => self.may_write_above(live, u64::from(lowest)),
                },
                other => self.operation(id, live, other),
            }
        }
    }

    impl DecodeFlow<'_, '_> {
        fn refuse(&mut self, why: String) {
            if self.refused.is_none() {
                self.refused = Some(why);
            }
        }

        /// The bits of slot `i` that `[a, b)` (bytes from the base) covers.
        fn cover(&self, i: usize, a: u64, b: u64) -> u8 {
            let (lo, hi) = self.cand.span(i);
            let (x, y) = (a.max(lo), b.min(hi));
            if x >= y {
                return 0;
            }
            // A slot is at most 8 bytes: one store's width.
            let mask = ((1_u16 << (y - x)) - 1) << (x - lo);
            u8::try_from(mask & 0xff).unwrap_or(u8::MAX)
        }

        fn whole(&self, i: usize) -> u8 {
            let (lo, hi) = self.cand.span(i);
            self.cover(i, lo, hi)
        }

        /// Whether any byte in `[a, b)` may still hold the decode's value.
        fn may_hold(&self, live: &Live, a: u64, b: u64) -> bool {
            live.may.iter().any(|(i, bits)| bits & self.cover(*i, a, b) != 0)
        }

        /// Every slot reaching above `lowest` stops being certain.
        fn may_write_above(&self, live: &mut Live, lowest: u64) {
            for i in 0..self.cand.slots.len() {
                if self.cand.span(i).1 > lowest {
                    live.must.remove(&i);
                }
            }
            live.pending.retain(|at, p| u64::from(*at) + u64::from(p.width) <= lowest);
        }

        /// The pending tag word `value` is a load of, while it is still
        /// what that load read.
        fn tag_word(&self, value: ValueId, live: &Live) -> Option<(u32, Pending)> {
            let (at, p) = self.tag_words.get(&resolve_use(self.func, value))?.clone()?;
            (live.pending.get(&at) == Some(&p)).then_some((at, p))
        }

        /// Where `value` points relative to the decode's base.
        fn points(&mut self, value: ValueId) -> Points {
            let raw = raw_address(self.func, value);
            let (base, at) = canon_addr(self.func, raw);
            if base == self.cand.base {
                return Points::At(at);
            }
            if !self.derived(raw) {
                return Points::Elsewhere;
            }
            // `x | y` as an unsigned address is at least `x`.
            if let Some(Expr::Binary { op: sordec_ir::BinaryOp::BitOr, lhs, rhs }) =
                self.func.bindings.get(base).map(|b| &b.expr)
            {
                for side in [*lhs, *rhs] {
                    let (b, k) = canon_addr(self.func, side);
                    if b == self.cand.base {
                        return Points::From(k.saturating_add(at));
                    }
                }
            }
            Points::From(0)
        }

        /// Whether `value` is computed from the decode's base: through
        /// arithmetic, a conversion, a phi or a select. Running out of
        /// budget counts as yes.
        fn derived(&mut self, value: ValueId) -> bool {
            let value = resolve_use(self.func, value);
            if let Some(known) = self.derived.get(&value) {
                return *known;
            }
            let mut seen = std::collections::HashSet::new();
            let mut stack = vec![value];
            let mut found = false;
            while let Some(v) = stack.pop() {
                let v = resolve_use(self.func, v);
                if v == self.cand.base {
                    found = true;
                    break;
                }
                if !seen.insert(v) {
                    continue;
                }
                if seen.len() > DERIVE_BUDGET {
                    found = true;
                    break;
                }
                match self.func.bindings.get(v).map(|b| &b.expr) {
                    Some(Expr::Binary { lhs, rhs, .. }) => stack.extend([*lhs, *rhs]),
                    Some(Expr::Unary { value, .. }) => stack.push(*value),
                    Some(Expr::Select { if_true, if_false, .. }) => stack.extend([*if_true, *if_false]),
                    Some(Expr::Phi { incoming }) => stack.extend(incoming.iter().map(|(_, v)| *v)),
                    Some(Expr::Unknown { args, .. }) => stack.extend(args.iter().copied()),
                    Some(Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { value, .. }))) => stack.push(*value),
                    _ => {}
                }
            }
            self.derived.insert(value, found);
            found
        }

        /// The slots `ranges` (`(offset from base, width)`) touch leave the
        /// `must` side; when the write is certain, the bytes they cover
        /// leave the `may` side.
        fn overwrite(&self, live: &mut Live, ranges: &[(u32, u32)], certain: bool) {
            live.pending.retain(|at, p| {
                ranges.iter().all(|&(lo, w)| {
                    let (a, b) = (u64::from(*at), u64::from(*at) + u64::from(p.width));
                    let (x, y) = (u64::from(lo), u64::from(lo) + u64::from(w));
                    b <= x || y <= a
                })
            });
            for i in 0..self.cand.slots.len() {
                for &(at, width) in ranges {
                    let bits = self.cover(i, u64::from(at), u64::from(at) + u64::from(width));
                    if bits == 0 {
                        continue;
                    }
                    live.must.remove(&i);
                    if certain && let Some(held) = live.may.get_mut(&i) {
                        *held &= !bits;
                        if *held == 0 {
                            live.may.remove(&i);
                        }
                    }
                }
            }
        }

        fn load(&mut self, id: ValueId, live: &Live, at: u32, offset: u32, width: MemWidth, signed: Option<bool>) {
            // A whole load of a pending tag word is that tag; recorded only
            // while every visit agrees.
            let word = at
                .checked_add(offset)
                .and_then(|o| live.pending.get(&o).filter(|p| p.width == width.bytes()).map(|p| (o, p.clone())));
            let seen = self.tag_words.entry(id).or_insert_with(|| word.clone());
            if *seen != word {
                *seen = None;
            }
            if live.may.is_empty() {
                return;
            }
            let Some(at) = at.checked_add(offset) else {
                self.refuse(format!("{id:?}: a read at an offset past the address space"));
                return;
            };
            let (lo, hi) = (u64::from(at), u64::from(at) + u64::from(width.bytes()));
            let touched: Vec<usize> = live
                .may
                .iter()
                .filter(|(i, bits)| *bits & self.cover(**i, lo, hi) != 0)
                .map(|(i, _)| *i)
                .collect();
            if touched.is_empty() {
                return;
            }
            // The first byte of a `Val` slot the decode wrote whole on
            // every path is that field's tag.
            let exact = self.cand.exact_read(at, width, signed).filter(|i| touched == [*i] && live.must.contains(i));
            let tag = self.cand.tag_read(at, width).filter(|(i, _)| touched == [*i] && live.must.contains(i));
            match (exact, tag) {
                (Some(i), _) => {
                    self.reads.insert(id, i);
                }
                (None, Some(t)) => {
                    self.tags.insert(id, t);
                }
                (None, None) => self.refuse(format!(
                    "{id:?} reads {} bytes at +{at}: not one whole slot the decode wrote on every path",
                    width.bytes()
                )),
            }
        }

        /// Any operation other than a load or a store: it can touch only
        /// memory it is handed an address of.
        fn operation(&mut self, id: ValueId, live: &mut Live, expr: &Expr) {
            let effects = crate::effects::expr_effects(expr);
            if !effects.reads_memory && !effects.writes_memory {
                return;
            }
            let mut operands: Vec<ValueId> = Vec::new();
            expr.for_each_value_use(|u| operands.push(u));
            let mut pointers: Vec<(usize, Points)> = Vec::new();
            for (k, u) in operands.iter().enumerate() {
                match self.points(*u) {
                    Points::Elsewhere => {}
                    p => pointers.push((k, p)),
                }
            }
            if pointers.is_empty() {
                return;
            }
            // A host unpack writes exactly `len` `Val`s at its address and
            // reads nothing there.
            if let Some((vals, len)) = unpack_extent(self.func, expr)
                && let Some(bytes) = len.checked_mul(8)
            {
                let (b, at) = canon_addr(self.func, vals);
                if b == self.cand.base {
                    let func = self.func;
                    pointers.retain(|(k, _)| raw_address(func, operands[*k]) != vals);
                    self.overwrite(live, &[(at, bytes)], true);
                }
            }
            // A helper whose parameter is only a load or store address
            // touches what it is handed there at known offsets.
            let summaries = match expr {
                Expr::Call { target, .. } => self.access.get(target),
                _ => None,
            };
            let mut writes: Vec<(u32, u32, bool)> = Vec::new();
            let (start, end) = self.extent();
            for (k, p) in &pointers {
                let summary = summaries.and_then(|s| s.get(*k)).and_then(Option::as_ref);
                match (p, summary) {
                    (Points::Elsewhere, _) => {}
                    (Points::At(at), Some(acc)) => {
                        let read = acc.reads.iter().any(|(o, w)| {
                            let lo = u64::from(*at) + u64::from(*o);
                            self.may_hold(live, lo, lo + u64::from(*w))
                        });
                        if read {
                            self.refuse(format!("{id:?} reads the decode's bytes through the frame at +{at}"));
                            return;
                        }
                        let shift = |o: u32| at.checked_add(o);
                        writes.extend(acc.writes.iter().filter_map(|(o, w)| Some((shift(*o)?, *w, false))));
                        writes.extend(acc.must_writes.iter().filter_map(|(o, w)| Some((shift(*o)?, *w, true))));
                    }
                    (Points::From(lowest), Some(acc)) => {
                        if !acc.reads.is_empty() && self.may_hold(live, u64::from(*lowest), u64::MAX) {
                            self.refuse(format!("{id:?} reads the frame at a run-time offset"));
                            return;
                        }
                        if !acc.writes.is_empty() {
                            self.may_write_above(live, u64::from(*lowest));
                        }
                    }
                    // Anything else may read and write from the address it
                    // is handed upward. It reads the decode's bytes only if
                    // that address is among them: one below them belongs to
                    // another local (see the module docs).
                    (Points::At(at), None) => {
                        let at = u64::from(*at);
                        if effects.reads_memory && start <= at && at < end && self.may_hold(live, at, u64::MAX) {
                            self.refuse(format!("{id:?} is handed the decode's bytes at +{at} and may read them"));
                            return;
                        }
                        if effects.writes_memory {
                            self.may_write_above(live, at);
                        }
                    }
                    (Points::From(lowest), None) => {
                        let lowest = u64::from(*lowest);
                        if effects.reads_memory && self.may_hold(live, lowest, u64::MAX) {
                            self.refuse(format!("{id:?} is handed the frame at a run-time offset and may read the decode's bytes"));
                            return;
                        }
                        if effects.writes_memory {
                            self.may_write_above(live, lowest);
                        }
                    }
                }
            }
            for (at, width, certain) in writes {
                self.overwrite(live, &[(at, width)], certain);
            }
            // A gated helper's tag word, left at the pointer it was handed.
            if let Expr::Call { target, .. } = expr
                && let Some(params) = self.gated.get(target)
            {
                for (k, p) in &pointers {
                    let (Points::At(at), Some(Some(g))) = (p, params.get(*k)) else { continue };
                    let shifted: Option<Vec<(u32, u32)>> =
                        g.writes.iter().map(|(o, w)| Some((at.checked_add(*o)?, *w))).collect();
                    if let Some(writes) = shifted {
                        live.pending.insert(*at, Pending { width: g.width, none: g.none, writes });
                    }
                }
            }
        }

        /// `[start, end)` of the decode's slots, in bytes from the base.
        fn extent(&self) -> (u64, u64) {
            let n = self.cand.slots.len();
            if n == 0 {
                return (0, 0);
            }
            (self.cand.span(0).0, self.cand.span(n - 1).1)
        }
    }

    /// The address and `Val` count of a host unpack into linear memory.
    fn unpack_extent(func: &HighFunction, expr: &Expr) -> Option<(ValueId, u32)> {
        match expr {
            Expr::Semantic(SemanticOp::Known(KnownOp::MapOp { kind: MapOpKind::UnpackToLinearMemory, args })) => {
                let (_, _, vals, len) = unpack_operands(func, args)?;
                Some((vals, len))
            }
            Expr::Semantic(SemanticOp::Known(KnownOp::VecOp { kind: VecOpKind::UnpackToLinearMemory, args })) => {
                let [_, vals, len] = args.as_slice() else { return None };
                Some((raw_address(func, *vals), trace_u32val(func, *len)?))
            }
            _ => None,
        }
    }
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
/// Which half of a wide field of `val` this value is, when it is exactly
/// `wide_lo(val.f)` or `wide_hi(val.f)`; `None` for anything else.
fn half_of(func: &HighFunction, value: ValueId, val: ValueId) -> Option<sordec_ir::UnaryOp> {
    use sordec_ir::UnaryOp;
    let Expr::Unary { op: op @ (UnaryOp::WideLo | UnaryOp::WideHi), value } =
        &func.bindings.get(resolve_use(func, value))?.expr
    else {
        return None;
    };
    let field = func.bindings.get(resolve_use(func, *value))?;
    matches!(&field.expr, Expr::Field { base, .. } if resolve_use(func, *base) == val).then_some(*op)
}

/// Rewrite `load` as one half of `base.field`: the field becomes a binding
/// of its own, scheduled just before the load, and the load its half. The
/// other half read earlier in the same block shares that binding, so the
/// two halves are visibly of one value and a join of them folds.
fn apply_limb(
    func: &mut HighFunction,
    shared: &mut HashMap<(ValueId, String), ValueId>,
    load: ValueId,
    base: ValueId,
    field: String,
    ty: KnownType,
    half: sordec_ir::UnaryOp,
) {
    use sordec_common::{Provenance, ProvenanceSource};
    let Some(block_id) = crate::dataflow::block_containing(func, load) else {
        return;
    };
    let earlier = shared.get(&(base, field.clone())).copied().filter(|f| {
        func.blocks.get(block_id).is_some_and(|b| {
            let pos = |v: ValueId| b.bindings.iter().position(|x| *x == v);
            matches!((pos(*f), pos(load)), (Some(a), Some(b)) if a < b)
        })
    });
    let id = match earlier {
        Some(id) => id,
        None => {
            let id = ValueId::from_index(func.bindings.len() as u32);
            let note = format!("{field}: the wide field one half of which a decode helper's slot holds");
            func.bindings.push(sordec_ir::Binding::new(
                id,
                IrType::Known(ty),
                Expr::Field { base, field: field.clone() },
                Provenance::new(PASS_NAME, ProvenanceSource::SdkPattern, note),
            ));
            let Some(block) = func.blocks.get_mut(block_id) else {
                return;
            };
            let Some(at) = block.bindings.iter().position(|b| *b == load) else {
                return;
            };
            block.bindings.insert(at, id);
            shared.insert((base, field.clone()), id);
            id
        }
    };
    if let Some(b) = func.bindings.get_mut(load) {
        b.expr = Expr::Unary { op: half, value: id };
        b.ty = IrType::Inferred(KnownType::I64);
        b.add_provenance(Provenance::new(
            PASS_NAME,
            ProvenanceSource::SdkPattern,
            format!("one half of {field}, slot of the derived decode helper"),
        ));
    }
}

///
/// Through a call only one way: the value component (`.1`) of a field's
/// derived scalar decoder (`scalars`), whose argument must be exactly that
/// field, declared at the decoder's type. Its `Ok` value is the field's
/// number; its tag, or any other call, is not a field at all.
fn field_source(
    func: &HighFunction,
    value: ValueId,
    val: ValueId,
    scalars: &HashMap<FuncId, KnownType>,
    def: &StructDef,
) -> Option<String> {
    let mut found: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut seen: std::collections::HashSet<ValueId> = std::collections::HashSet::new();
    let mut queue: std::collections::VecDeque<ValueId> = std::collections::VecDeque::from([value]);
    let expr = |v: ValueId| func.bindings.get(resolve_use(func, v)).map(|b| &b.expr);
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
            Expr::Project { value: call, index } if matches!(expr(*call), Some(Expr::Call { .. })) => {
                let Some(Expr::Call { target, args }) = expr(*call) else { return None };
                let ty = scalars.get(target)?;
                let [arg] = args.as_slice() else { return None };
                let Some(Expr::Field { base, field }) = expr(*arg) else { return None };
                let declared = def.fields.iter().find(|f| f.name == *field).and_then(|f| known_of_type_ref(&f.ty));
                if *index != 1 || resolve_use(func, *base) != val || declared.as_ref() != Some(ty) {
                    return None;
                }
                found.insert(field.clone());
            }
            Expr::Call { .. } | Expr::IndirectCall { .. } => return None,
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

    /// The same helper storing `val.amount`, an `i128`, as its two halves
    /// at `out+16` / `out+24`; the caller passes a storage read.
    #[test]
    fn a_wide_field_crosses_a_helper_as_its_halves() {
        let mut helper = func_with(
            vec![
                Expr::Phi { incoming: vec![] },                                          // v0 out
                Expr::Phi { incoming: vec![] },                                          // v1 val
                Expr::Field { base: v(1), field: "amount".to_string() },                // v2
                Expr::Unary { op: sordec_ir::UnaryOp::WideLo, value: v(2) },            // v3
                Expr::Unary { op: sordec_ir::UnaryOp::WideHi, value: v(2) },            // v4
                store(v(0), v(3), 16),                                                   // v5
                store(v(0), v(4), 24),                                                   // v6
                Expr::Literal(Literal::I64(0)),                                          // v7
                store(v(0), v(7), 0),                                                    // v8
            ],
            vec![v(0), v(1)],
            vec![2, 3, 4, 5, 6, 7, 8],
        );
        helper.id = FuncId::from_index(1);
        helper.bindings.get_mut(v(1)).unwrap().ty = IrType::Known(KnownType::UserDefined(TypeId::new(7)));
        let mut caller = func_with(
            vec![
                Expr::Phi { incoming: vec![] },                                          // v0 fp
                Expr::Semantic(SemanticOp::Known(KnownOp::StorageGet {
                    tier: StorageTier::Known(KnownTier::Instance),
                    durability: v(0),
                    key: v(0),
                    resolved_key: None,
                    missing: sordec_ir::Missing::Unwrap,
                })),                                                                     // v1 the read
                Expr::Call { target: FuncId::from_index(1), args: vec![v(0), v(1)] },   // v2
                load(v(0), 16),                                                          // v3 lo
                load(v(0), 24),                                                          // v4 hi
            ],
            vec![v(0)],
            vec![1, 2, 3, 4],
        );
        caller.id = FuncId::from_index(0);
        let mut m = ir(caller);
        m.functions.push(helper);
        assert!(UdtDecodePass.run(&mut m).changed);
        let c = m.function(FuncId::from_index(0)).unwrap();
        let half = |id: u32| match &c.bindings.get(v(id)).unwrap().expr {
            Expr::Unary { op, value } => match &c.bindings.get(*value).unwrap().expr {
                Expr::Field { base, field } if *base == v(1) && field == "amount" => Some(*op),
                _ => None,
            },
            _ => None,
        };
        assert_eq!(half(3), Some(sordec_ir::UnaryOp::WideLo));
        assert_eq!(half(4), Some(sordec_ir::UnaryOp::WideHi));
        assert!(
            matches!(c.bindings.get(v(1)).unwrap().ty, IrType::Known(KnownType::UserDefined(id)) if id == TypeId::new(7)),
            "the read the helper decodes is the struct"
        );
    }

    #[test]
    fn the_pass_is_idempotent() {
        let mut m = ir(decoder());
        assert!(UdtDecodePass.run(&mut m).changed);
        assert!(!UdtDecodePass.run(&mut m).changed);
    }

    // -----------------------------------------------------------------
    // Reads must be exact, and the decode stays unless all of them are
    // -----------------------------------------------------------------

    fn load_w(addr: ValueId, offset: u32, width: MemWidth, signed: Option<bool>) -> Expr {
        Expr::Load { addr, offset, width, signed, ty: IrType::Unknown(UnknownReason::InsufficientEvidence) }
    }

    fn store_w(addr: ValueId, value: ValueId, offset: u32, width: MemWidth) -> Expr {
        Expr::Store { addr, value, offset, width }
    }

    /// The decode was left exactly as it was: the unpack (or call) at
    /// `producer` and every load in `loads` untouched.
    fn untouched(m: &HighIr, func: usize, producer: u32, loads: &[u32]) {
        let f = &m.functions[func];
        assert!(
            !matches!(f.bindings.get(v(producer)).unwrap().expr, Expr::Literal(Literal::Unit)),
            "the decode was removed"
        );
        for l in loads {
            assert!(matches!(f.bindings.get(v(*l)).unwrap().expr, Expr::Load { .. }), "v{l} was rewritten");
        }
    }

    /// `decoder()` with the two field reads replaced and `extra` appended.
    fn decoder_with(reads: [Expr; 2], extra: Vec<Expr>) -> HighFunction {
        let mut f = decoder();
        let [a, b] = reads;
        f.bindings.get_mut(v(6)).unwrap().expr = a;
        f.bindings.get_mut(v(7)).unwrap().expr = b;
        for e in extra {
            let id = ValueId::from_index(f.bindings.len() as u32);
            f.bindings.push(sordec_ir::Binding::new(
                id,
                IrType::Unknown(UnknownReason::InsufficientEvidence),
                e,
                sordec_common::Provenance::new("seed", sordec_common::ProvenanceSource::DataFlow, "seed"),
            ));
            f.blocks.get_mut(sordec_common::BlockId::from_index(0)).unwrap().bindings.push(id);
        }
        f
    }

    /// The tag byte of a `Val` slot is not the field: `load8 fp+8 != 4`
    /// tests the tag, and reading it as `b.token != 4` would compare the
    /// value.
    #[test]
    fn a_tag_byte_read_keeps_the_decode() {
        let mut m = ir(decoder_with([load(v(0), 0), load_w(v(0), 8, MemWidth::W1, Some(false))], vec![]));
        UdtDecodePass.run(&mut m);
        untouched(&m, 0, 5, &[6, 7]);
    }

    /// A word read starting in the middle of one slot spans two fields and
    /// is neither.
    #[test]
    fn a_read_across_two_slots_keeps_the_decode() {
        let mut m = ir(decoder_with([load(v(0), 0), load(v(0), 4)], vec![]));
        UdtDecodePass.run(&mut m);
        untouched(&m, 0, 5, &[6, 7]);
    }

    /// A `bool` is 0 or 1 with zeros above it, so its low byte is the
    /// whole value.
    #[test]
    fn a_narrow_read_of_a_bool_is_the_bool() {
        let mut m = ir(decoder_with([load(v(0), 0), load_w(v(0), 8, MemWidth::W1, Some(false))], vec![]));
        m.soroban_facts.as_mut().unwrap().types.structs[0].fields[1].ty = TypeRef::Primitive(PrimitiveType::Bool);
        assert!(UdtDecodePass.run(&mut m).changed);
        assert!(matches!(expr_at(&m, 7), Expr::Field { field, .. } if field == "token"));
        assert!(matches!(m.functions[0].bindings.get(v(7)).unwrap().ty, IrType::Known(KnownType::Bool)));
        assert!(matches!(expr_at(&m, 5), Expr::Literal(Literal::Unit)));
    }

    /// After the reads, a call handed the slots may read them again: the
    /// decode cannot be removed under it.
    #[test]
    fn a_call_handed_the_slots_keeps_the_decode() {
        let call = Expr::Call { target: FuncId::from_index(9), args: vec![v(0)] };
        let mut m = ir(decoder_with([load(v(0), 0), load(v(0), 8)], vec![call]));
        UdtDecodePass.run(&mut m);
        untouched(&m, 0, 5, &[6, 7]);
    }

    /// A slot overwritten whole and then read again is the store's value,
    /// not the decode's: that read is not the decode's to rewrite, and it
    /// does not stop the decode being removed.
    #[test]
    fn a_read_after_an_overwrite_is_not_the_decodes() {
        let mut m = ir(decoder_with([load(v(0), 0), load(v(0), 8)], vec![store(v(0), v(1), 8), load(v(0), 8)]));
        assert!(UdtDecodePass.run(&mut m).changed);
        assert!(matches!(expr_at(&m, 7), Expr::Field { field, .. } if field == "token"));
        assert!(matches!(expr_at(&m, 9), Expr::Load { .. }));
        assert!(matches!(expr_at(&m, 5), Expr::Literal(Literal::Unit)));
    }

    /// Half a slot overwritten leaves the other half the decode's; a read
    /// of that half is a read the decode reaches and cannot explain.
    #[test]
    fn a_read_of_a_half_overwritten_slot_keeps_the_decode() {
        let mut m = ir(decoder_with(
            [load(v(0), 0), load(v(0), 8)],
            vec![store_w(v(0), v(1), 8, MemWidth::W4), load_w(v(0), 12, MemWidth::W4, None)],
        ));
        UdtDecodePass.run(&mut m);
        untouched(&m, 0, 5, &[6, 7, 9]);
    }

    /// A call to a function that only stores through its first parameter
    /// overwrites without reading, and a read of a byte it always writes
    /// is its value.
    #[test]
    fn a_write_only_callee_overwrites_without_reading() {
        let callee = {
            let mut f = func_with(
                vec![
                    Expr::Phi { incoming: vec![] },  // v0 out
                    Expr::Literal(Literal::I32(2)),  // v1
                    store_w(v(0), v(1), 0, MemWidth::W1),
                ],
                vec![v(0)],
                vec![1, 2],
            );
            f.id = FuncId::from_index(1);
            f
        };
        let call = Expr::Call { target: FuncId::from_index(1), args: vec![v(0)] };
        let mut m = ir(decoder_with(
            [load(v(0), 0), load(v(0), 8)],
            vec![call, load_w(v(0), 0, MemWidth::W1, Some(false))],
        ));
        m.functions.push(callee);
        assert!(UdtDecodePass.run(&mut m).changed);
        assert!(matches!(expr_at(&m, 5), Expr::Literal(Literal::Unit)));
        assert!(matches!(expr_at(&m, 9), Expr::Load { .. }), "the tag byte the callee wrote is its own");
    }

    // -----------------------------------------------------------------
    // A key table several structs share, named by the value's declaration
    // -----------------------------------------------------------------

    /// `Balance` plus `Wallet`, a second struct with the same field names
    /// (its `amount` a `u64`, so the two can be told apart).
    fn with_twin(m: &mut HighIr) {
        let structs = &mut m.soroban_facts.as_mut().unwrap().types.structs;
        let mut twin = structs[0].clone();
        twin.id = TypeId::new(8);
        twin.name = "Wallet".to_string();
        twin.fields[0].ty = TypeRef::Primitive(PrimitiveType::U64);
        structs.push(twin);
    }

    /// The map is already typed `Wallet` by its declaration (a recovered
    /// field, a tuple element): the shared table is `Wallet`'s.
    #[test]
    fn a_shared_key_table_is_named_by_the_values_declared_type() {
        let mut f = decoder();
        f.bindings.get_mut(v(2)).unwrap().expr = Expr::Phi { incoming: vec![] };
        f.bindings.get_mut(v(2)).unwrap().ty = IrType::Known(KnownType::UserDefined(TypeId::new(8)));
        let mut m = ir(f);
        with_twin(&mut m);
        assert!(UdtDecodePass.run(&mut m).changed);
        assert!(matches!(expr_at(&m, 6), Expr::Field { base, field } if *base == v(2) && field == "amount"));
        assert!(matches!(m.functions[0].bindings.get(v(6)).unwrap().ty, IrType::Known(KnownType::U64)));
        assert!(matches!(expr_at(&m, 5), Expr::Literal(Literal::Unit)));
    }

    /// A storage read says nothing about which of the two it is.
    #[test]
    fn a_shared_key_table_with_no_declaration_declines() {
        let mut m = ir(decoder());
        with_twin(&mut m);
        UdtDecodePass.run(&mut m);
        untouched(&m, 0, 5, &[6, 7]);
    }

    /// A declaration whose fields are not exactly the keys names nothing.
    #[test]
    fn a_declared_type_with_other_fields_declines() {
        let mut f = decoder();
        f.bindings.get_mut(v(2)).unwrap().expr = Expr::Phi { incoming: vec![] };
        f.bindings.get_mut(v(2)).unwrap().ty = IrType::Known(KnownType::UserDefined(TypeId::new(8)));
        let mut m = ir(f);
        with_twin(&mut m);
        m.soroban_facts.as_mut().unwrap().types.structs[1].fields[1].name = "owner".to_string();
        // Only `Balance` has these keys now, and the value is declared a
        // `Wallet`: the evidence gate refuses the mismatch.
        UdtDecodePass.run(&mut m);
        untouched(&m, 0, 5, &[6, 7]);
    }

    // -----------------------------------------------------------------
    // The derived per-field tag check
    // -----------------------------------------------------------------

    /// `decoder()` where the token slot is read only for its tag byte,
    /// compared with `tag` under a guard `if byte != tag { trap }`.
    fn tag_checked(tag: i64) -> HighFunction {
        let mut exprs: Vec<Expr> = decoder().bindings.iter().map(|(_, b)| b.expr.clone()).collect();
        exprs[7] = load_w(v(0), 8, MemWidth::W1, Some(false)); // v7 token's tag byte
        exprs.push(Expr::Literal(Literal::I64(tag))); // v8
        exprs.push(Expr::Binary { op: sordec_ir::BinaryOp::Ne, lhs: v(7), rhs: v(8) }); // v9
        let region = sordec_ir::Region::Sequence(vec![
            bb(0),
            sordec_ir::Region::If {
                cond: v(9),
                then_region: Box::new(sordec_ir::Region::Unreachable),
                else_region: None,
            },
            bb(1),
        ]);
        func_regions(exprs, vec![v(0), v(1)], vec![vec![2, 3, 4, 5, 6, 7, 8, 9], vec![]], region)
    }

    fn has_guard(f: &HighFunction) -> bool {
        let mut found = false;
        f.region.for_each_node(|r| found |= matches!(r, sordec_ir::Region::If { .. }));
        found
    }

    /// `token: Address` is carried only by an `AddressObject` (77): the
    /// byte test is the derived check, relocated with the decode.
    #[test]
    fn the_fields_own_tag_check_goes_with_the_decode() {
        let mut m = ir(tag_checked(77));
        assert!(UdtDecodePass.run(&mut m).changed);
        assert!(matches!(expr_at(&m, 5), Expr::Literal(Literal::Unit)));
        assert!(matches!(expr_at(&m, 6), Expr::Field { field, .. } if field == "amount"));
        assert!(matches!(expr_at(&m, 7), Expr::Literal(Literal::Unit)));
        assert!(!has_guard(&m.functions[0]), "the derived check is relocated");
    }

    /// A test against another tag is not `Address`'s check.
    #[test]
    fn a_tag_test_the_type_does_not_make_keeps_the_decode() {
        let mut m = ir(tag_checked(75));
        UdtDecodePass.run(&mut m);
        untouched(&m, 0, 5, &[6, 7]);
        assert!(has_guard(&m.functions[0]));
    }

    /// A type with two tags (`i128`: small or object) has no one-byte
    /// check that is the whole of its conversion.
    #[test]
    fn a_tag_byte_of_a_two_tag_type_keeps_the_decode() {
        let mut m = ir(tag_checked(11));
        m.soroban_facts.as_mut().unwrap().types.structs[0].fields[1].ty = TypeRef::Primitive(PrimitiveType::I128);
        UdtDecodePass.run(&mut m);
        untouched(&m, 0, 5, &[6, 7]);
    }

    /// The byte read for anything besides the check is a value the
    /// decode's removal would lose.
    #[test]
    fn a_tag_byte_with_another_use_keeps_the_decode() {
        let mut f = tag_checked(77);
        let id = ValueId::from_index(f.bindings.len() as u32);
        f.bindings.push(sordec_ir::Binding::new(
            id,
            IrType::Unknown(UnknownReason::InsufficientEvidence),
            store(v(1), v(7), 0),
            sordec_common::Provenance::new("seed", sordec_common::ProvenanceSource::DataFlow, "seed"),
        ));
        f.blocks.get_mut(sordec_common::BlockId::from_index(1)).unwrap().bindings.push(id);
        let mut m = ir(f);
        UdtDecodePass.run(&mut m);
        untouched(&m, 0, 5, &[6, 7]);
    }

    /// A comparison that steers real work, not a trap, is the author's.
    #[test]
    fn a_tag_test_that_does_not_guard_a_trap_keeps_the_decode() {
        let mut f = tag_checked(77);
        f.region = sordec_ir::Region::Sequence(vec![
            bb(0),
            sordec_ir::Region::If { cond: v(9), then_region: Box::new(bb(1)), else_region: None },
        ]);
        let mut m = ir(f);
        UdtDecodePass.run(&mut m);
        untouched(&m, 0, 5, &[6, 7]);
    }

    // -----------------------------------------------------------------
    // An `Option<T>` parameter's payload, read only by its checks
    // -----------------------------------------------------------------

    /// `f(o: Option<Balance>)`: the unpack of `o` (v2, the parameter), the
    /// token slot read whole (v7) and tested for an `AddressObject` (v8)
    /// under `if v8 { } else { trap }`; `amount` (v6) is `read`.
    fn option_payload_fn(read: Expr) -> HighFunction {
        use sordec_ir::{CompositeType, FunctionParam, FunctionSignature};
        let mut exprs: Vec<Expr> = decoder().bindings.iter().map(|(_, b)| b.expr.clone()).collect();
        exprs[2] = Expr::Phi { incoming: vec![] }; // v2: the parameter
        exprs[6] = read;
        exprs.push(Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck {
            value: v(7),
            tag: crate::val_abi::TAG_ADDRESS_OBJECT,
            negated: false,
        }))); // v8
        let region = sordec_ir::Region::Sequence(vec![
            bb(0),
            sordec_ir::Region::If {
                cond: v(8),
                then_region: Box::new(bb(1)),
                else_region: Some(Box::new(sordec_ir::Region::Unreachable)),
            },
        ]);
        let mut f = func_regions(exprs, vec![v(2), v(0), v(1)], vec![vec![3, 4, 5, 6, 7, 8], vec![]], region);
        let opt = TypeRef::Composite(CompositeType::Option(Box::new(TypeRef::UserDefined(TypeId::new(7)))));
        f.signature = Some(FunctionSignature {
            name: "f".into(),
            inputs: vec![FunctionParam { name: "o".into(), ty: opt }],
            outputs: vec![],
        });
        f
    }

    /// Every read of the payload is its field's derived check: the unpack
    /// and the check go, and the parameter keeps its `Option` type.
    #[test]
    fn an_option_payload_read_only_by_its_checks_is_relocated() {
        let mut f = option_payload_fn(Expr::Literal(Literal::Unit));
        f.bindings.get_mut(v(2)).unwrap().ty = IrType::Known(KnownType::Option(Box::new(IrType::Known(
            KnownType::UserDefined(TypeId::new(7)),
        ))));
        let mut m = ir(f);
        assert!(UdtDecodePass.run(&mut m).changed);
        assert!(matches!(expr_at(&m, 5), Expr::Literal(Literal::Unit)));
        assert!(matches!(expr_at(&m, 7), Expr::Literal(Literal::Unit)));
        assert!(matches!(expr_at(&m, 8), Expr::Literal(Literal::Unit)));
        assert!(!has_guard(&m.functions[0]), "the inverted guard gives way to its then arm");
        assert!(matches!(m.functions[0].bindings.get(v(2)).unwrap().ty, IrType::Known(KnownType::Option(_))));
    }

    /// A payload field read for its value has no expression to become.
    #[test]
    fn an_option_payload_read_for_its_value_keeps_the_decode() {
        let mut f = option_payload_fn(load(v(0), 0));
        let id = ValueId::from_index(f.bindings.len() as u32);
        f.bindings.push(sordec_ir::Binding::new(
            id,
            IrType::Unknown(UnknownReason::InsufficientEvidence),
            store(v(1), v(6), 0),
            sordec_common::Provenance::new("seed", sordec_common::ProvenanceSource::DataFlow, "seed"),
        ));
        f.blocks.get_mut(sordec_common::BlockId::from_index(1)).unwrap().bindings.push(id);
        let mut m = ir(f);
        UdtDecodePass.run(&mut m);
        untouched(&m, 0, 5, &[6, 7]);
        assert!(has_guard(&m.functions[0]));
    }

    /// A function with the given blocks (binding ids per block) and region.
    fn func_regions(exprs: Vec<Expr>, params: Vec<ValueId>, blocks: Vec<Vec<u32>>, region: sordec_ir::Region) -> HighFunction {
        let mut f = func_with(exprs, params, vec![]);
        let mut arena: sordec_common::Arena<sordec_common::BlockId, sordec_ir::HighBlock> = sordec_common::Arena::new();
        for (i, b) in blocks.into_iter().enumerate() {
            let id = sordec_common::BlockId::from_index(i as u32);
            arena.push(sordec_ir::HighBlock { id, bindings: b.into_iter().map(v).collect() });
        }
        f.blocks = arena;
        f.region = region;
        f
    }

    fn bb(i: u32) -> sordec_ir::Region {
        sordec_ir::Region::Basic(sordec_common::BlockId::from_index(i))
    }

    /// `decoder()`'s bindings plus a branch condition (v8), laid out over
    /// three blocks: the read in b0, the unpack in b1 under `if v8`, b2
    /// after the merge.
    fn branching(b1: Vec<u32>, b2: Vec<u32>) -> HighFunction {
        let mut exprs: Vec<Expr> = decoder().bindings.iter().map(|(_, b)| b.expr.clone()).collect();
        exprs.push(Expr::Phi { incoming: vec![] }); // v8 cond
        let region = sordec_ir::Region::Sequence(vec![
            bb(0),
            sordec_ir::Region::If { cond: v(8), then_region: Box::new(bb(1)), else_region: None },
            bb(2),
        ]);
        func_regions(exprs, vec![v(0), v(1)], vec![vec![2, 3, 4], b1, b2], region)
    }

    /// Both reads under the decode, inside the arm it runs in.
    #[test]
    fn reads_in_the_decodes_own_arm_are_its_fields() {
        let mut m = ir(branching(vec![5, 6, 7], vec![]));
        assert!(UdtDecodePass.run(&mut m).changed);
        assert!(matches!(expr_at(&m, 7), Expr::Field { field, .. } if field == "token"));
        assert!(matches!(expr_at(&m, 5), Expr::Literal(Literal::Unit)));
    }

    /// A read after the merge is reached on the path the decode never ran:
    /// it is not the field, and the decode cannot go without it.
    #[test]
    fn a_read_after_the_merge_keeps_the_decode() {
        let mut m = ir(branching(vec![5, 6], vec![7]));
        UdtDecodePass.run(&mut m);
        untouched(&m, 0, 5, &[6, 7]);
    }

    /// A read before the decode in a loop body reads the previous
    /// iteration's decode.
    #[test]
    fn a_read_before_the_decode_in_a_loop_keeps_it() {
        let exprs: Vec<Expr> = decoder().bindings.iter().map(|(_, b)| b.expr.clone()).collect();
        let region = sordec_ir::Region::Sequence(vec![
            bb(0),
            sordec_ir::Region::Loop {
                header: sordec_common::BlockId::from_index(1),
                body: Box::new(sordec_ir::Region::Sequence(vec![bb(1), bb(2)])),
                kind: sordec_ir::LoopKind::Unclassified,
            },
        ]);
        let mut m = ir(func_regions(exprs, vec![v(0), v(1)], vec![vec![2, 3, 4], vec![7], vec![5, 6]], region));
        UdtDecodePass.run(&mut m);
        untouched(&m, 0, 5, &[6, 7]);
    }

    /// A helper storing a `u32` field in four bytes at `out+8`.
    fn narrow_helper() -> HighFunction {
        let mut f = func_with(
            vec![
                Expr::Phi { incoming: vec![] },                          // v0 out
                Expr::Phi { incoming: vec![] },                          // v1 val
                Expr::Field { base: v(1), field: "token".to_string() }, // v2
                store_w(v(0), v(2), 8, MemWidth::W4),                    // v3
                Expr::Literal(Literal::I64(0)),                          // v4
                store(v(0), v(4), 0),                                    // v5
            ],
            vec![v(0), v(1)],
            vec![2, 3, 4, 5],
        );
        f.id = FuncId::from_index(1);
        f.bindings.get_mut(v(1)).unwrap().ty = IrType::Known(KnownType::UserDefined(TypeId::new(7)));
        f
    }

    fn narrow_module(read: Expr) -> HighIr {
        let mut caller = helper_caller(0, 1);
        caller.bindings.get_mut(v(3)).unwrap().expr = read;
        caller.bindings.get_mut(v(4)).unwrap().expr = load(v(1), 0);
        let mut m = ir(caller);
        m.soroban_facts.as_mut().unwrap().types.structs[0].fields[1].ty = TypeRef::Primitive(PrimitiveType::U32);
        m.functions.push(narrow_helper());
        m
    }

    /// A four-byte field read in four bytes is the field.
    #[test]
    fn a_narrow_slot_read_at_its_width_is_the_field() {
        let mut m = narrow_module(load_w(v(1), 8, MemWidth::W4, None));
        assert!(UdtDecodePass.run(&mut m).changed);
        assert!(matches!(expr_at(&m, 3), Expr::Field { field, .. } if field == "token"));
        assert!(matches!(expr_at(&m, 2), Expr::Literal(Literal::Unit)));
    }

    /// Eight bytes over a four-byte field read four bytes nothing wrote.
    #[test]
    fn a_wide_read_of_a_narrow_slot_keeps_the_call() {
        let mut m = narrow_module(load(v(1), 8));
        UdtDecodePass.run(&mut m);
        untouched(&m, 0, 2, &[3, 4]);
    }

    /// A `u32` read with sign extension is not the `u32`.
    #[test]
    fn a_narrow_read_that_widens_the_wrong_way_keeps_the_call() {
        let mut m = narrow_module(load_w(v(1), 8, MemWidth::W4, Some(true)));
        UdtDecodePass.run(&mut m);
        untouched(&m, 0, 2, &[3, 4]);
    }

    /// A constant the helper stores on one path only is no discriminant:
    /// on the path that skips it the slot holds whatever was there.
    #[test]
    fn a_constant_written_on_some_paths_explains_no_read() {
        let mut helper = func_regions(
            vec![
                Expr::Phi { incoming: vec![] },                          // v0 out
                Expr::Phi { incoming: vec![] },                          // v1 val
                Expr::Field { base: v(1), field: "token".to_string() }, // v2
                store(v(0), v(2), 0),                                    // v3
                Expr::Literal(Literal::I64(0)),                          // v4
                store(v(0), v(4), 8),                                    // v5
                Expr::Phi { incoming: vec![] },                          // v6 cond
            ],
            vec![v(0), v(1)],
            vec![vec![2, 3], vec![4, 5]],
            sordec_ir::Region::Sequence(vec![
                bb(0),
                sordec_ir::Region::If { cond: v(6), then_region: Box::new(bb(1)), else_region: None },
            ]),
        );
        helper.id = FuncId::from_index(1);
        helper.bindings.get_mut(v(1)).unwrap().ty = IrType::Known(KnownType::UserDefined(TypeId::new(7)));
        let mut m = ir(helper_caller(0, 1));
        m.functions.push(helper);
        UdtDecodePass.run(&mut m);
        untouched(&m, 0, 2, &[3, 4]);
    }

    /// `Counter { count: i64, owner: Address }`, id 9, beside `Balance`.
    fn with_counter(m: &mut HighIr, count: PrimitiveType) {
        m.soroban_facts.as_mut().unwrap().types.structs.push(StructDef {
            id: TypeId::new(9),
            name: "Counter".to_string(),
            fields: vec![
                StructField { name: "count".to_string(), ty: TypeRef::Primitive(count) },
                StructField { name: "owner".to_string(), ty: TypeRef::Primitive(PrimitiveType::Address) },
            ],
        });
    }

    /// A `Counter` decoder helper that hands `val.count` to the outlined
    /// `i64` decoder `func_2` and stores component `component` of its
    /// result at `out+8`, `val.owner` at `out+16`, and the `Ok` code at
    /// `out+0`; an entrypoint `f(c: Counter)` calls it and reads all three.
    fn scalar_helper_module(component: u32, count: PrimitiveType) -> HighIr {
        let mut helper = func_with(
            vec![
                Expr::Phi { incoming: vec![] },                                          // v0 out
                Expr::Phi { incoming: vec![] },                                          // v1 val
                Expr::Field { base: v(1), field: "count".to_string() },                 // v2
                Expr::Call { target: FuncId::from_index(2), args: vec![v(2)] },         // v3
                Expr::Project { value: v(3), index: component },                        // v4
                store(v(0), v(4), 8),                                                    // v5
                Expr::Field { base: v(1), field: "owner".to_string() },                 // v6
                store(v(0), v(6), 16),                                                   // v7
                Expr::Literal(Literal::I64(0)),                                          // v8
                store(v(0), v(8), 0),                                                    // v9
            ],
            vec![v(0), v(1)],
            (2..10).collect(),
        );
        helper.id = FuncId::from_index(1);
        helper.bindings.get_mut(v(1)).unwrap().ty = IrType::Known(KnownType::UserDefined(TypeId::new(9)));
        let mut caller = helper_caller(0, 1);
        caller.signature.as_mut().unwrap().inputs[0].ty = TypeRef::UserDefined(TypeId::new(9));
        caller.bindings.push(sordec_ir::Binding::new(
            v(5),
            IrType::Unknown(UnknownReason::InsufficientEvidence),
            load(v(1), 16),
            sordec_common::Provenance::new("seed", sordec_common::ProvenanceSource::DataFlow, "seed"),
        ));
        caller.blocks.get_mut(sordec_common::BlockId::from_index(0)).unwrap().bindings.push(v(5));
        // The helper's reads: +8 the count, +0 the discriminant, +16 the owner.
        caller.bindings.get_mut(v(3)).unwrap().expr = load(v(1), 8);
        caller.bindings.get_mut(v(4)).unwrap().expr = load(v(1), 0);
        let mut m = ir(caller);
        with_counter(&mut m, count);
        m.functions.push(helper);
        m.functions.push(crate::marshalling::test_support::two_form_decoder_fn(
            2,
            crate::val_abi::TAG_I64_OBJECT,
            crate::val_abi::TAG_I64_SMALL,
            sordec_ir::ValObjectKind::ObjToI64,
        ));
        m
    }

    /// The `Ok` value of a field's outlined scalar decoder is the field.
    #[test]
    fn a_helper_handing_a_field_to_its_scalar_decoder_collapses() {
        let mut m = scalar_helper_module(1, PrimitiveType::I64);
        assert!(UdtDecodePass.run(&mut m).changed);
        let c = m.function(FuncId::from_index(0)).unwrap();
        let field = |id: u32| match &c.bindings.get(v(id)).unwrap().expr {
            Expr::Field { base, field } if *base == v(0) => Some(field.clone()),
            _ => None,
        };
        assert_eq!(field(3).as_deref(), Some("count"));
        assert_eq!(field(5).as_deref(), Some("owner"));
        assert!(matches!(c.bindings.get(v(4)).unwrap().expr, Expr::Literal(Literal::I32(0))));
        assert!(matches!(c.bindings.get(v(2)).unwrap().expr, Expr::Literal(Literal::Unit)));
    }

    /// The decoder's tag is not the field: a helper storing it keeps
    /// every call site.
    #[test]
    fn a_helper_storing_a_decoders_tag_keeps_the_call() {
        let mut m = scalar_helper_module(0, PrimitiveType::I64);
        UdtDecodePass.run(&mut m);
        untouched(&m, 0, 2, &[3, 4]);
    }

    /// An `i64` decoder on a field declared another type is not that
    /// field's derived conversion.
    #[test]
    fn a_decoder_of_another_type_than_the_field_keeps_the_call() {
        let mut m = scalar_helper_module(1, PrimitiveType::U64);
        UdtDecodePass.run(&mut m);
        untouched(&m, 0, 2, &[3, 4]);
    }
}
