//! Take apart a `#[contracttype]` enum decoded inline through the SDK's
//! vector iterator: the decode and the switch on its variant become a
//! `match` on the value that binds each variant's payload.
//!
//! # The shape
//!
//! ```rust,ignore
//! pub fn get_data(env: Env, key: DataKey) -> Option<i64> {
//!     match key {
//!         DataKey::Persistent(_) => env.storage().persistent().get(&key),
//!         DataKey::Temp(_) => ..,
//!     }
//! }
//! ```
//!
//! A `#[contracttype]` enum travels as a vector: the variant's name as a
//! symbol, then its payload. When rustc inlines the derived `TryFromVal`
//! into the entrypoint it walks that vector with the SDK's iterator, whose
//! state (the vector, the next index, the length) sits in the frame and
//! whose `next` is a small helper writing `Option<Val>` into memory the
//! caller provides:
//!
//! ```text
//! len = vec_len(key)
//! store fp+0 <- key ; store fp+8 <- 0 ; store fp+12 <- len
//! next(fp+16, fp) ; if load fp+16 != 0 { trap }      ; element 0
//! s = load fp+24 ; <s is a symbol, else trap>
//! i = symbol_index(s, ["Persistent", "Temp", ...]) ; if i > 2 { trap }
//! match i {
//!     1 => { if len - idx > 1 { trap }                ; one payload element
//!            next(fp+16, fp) ; if load fp+16 != 0 { trap }
//!            x = load fp+24 ; <x is a u32, else trap> ; p = decode(x) ; .. }
//!     ..
//! }
//! ```
//!
//! # The rewrite
//!
//! The switch selects on `key` itself (`index` and `dispatch` both `key`,
//! see `Region::Switch::dispatch`); an arm whose variant has a payload opens
//! with it (`Expr::VariantPayload`), and the element's reads become the
//! payload — `decode(x)` of a `u32` (or a unit enum's code) its value
//! widened, any other use the payload itself. The iterator, its state, the
//! symbol, the lookup and every check made on them go:
//!
//! ```text
//! match key { DataKey::Temp(p) => { .. p .. }, .. }
//! ```
//!
//! # Why it is exact
//!
//! The value is proven to be the enum: an entrypoint parameter the spec
//! declares with it, or a value an earlier decode typed (`udt_of`). Its
//! `Val` is then a vector holding the variant's name and its payload's
//! `Val`s, one each — and the code that reads it is the derived decode,
//! which the re-emitted `#[contracttype]` regenerates in the entrypoint
//! wrapper, as every marshalling elision relocates its decode:
//!
//! - **The iterator is the SDK's.** `next` reads the state it is handed
//!   (vector at +0, index at +8, length at +12), and on the paths that
//!   leave a tag other than `2` (`None`) it writes `vec_get(vector, index)`
//!   to +8 of its out-pointer and `index + 1` back; its tags are `0` and
//!   `2` only. The state is set from the value (`v`, `0`, `vec_len(v)`)
//!   and nothing but these calls and loads of the index and length touches
//!   those 16 bytes, so the state is the iterator's own.
//! - **The k-th call reads element k.** The first call is the one whose
//!   element the lookup reads: no other call can run before the switch on
//!   that lookup, so it is the first on every path, and reads element 0.
//!   Every other call sits in exactly one arm of the switch, at most one
//!   per arm, and none in a loop: on that arm's path it is the second
//!   call, and reads element 1. A variant has at most one payload
//!   component (larger ones are refused), so every call reads an index
//!   below the vector's length and returns `Some`: its element slot holds
//!   that element. A read of the slot is that element where the reach
//!   check (`udt_decode::reach`) proves it reads the call's write whole on
//!   every path. A helper writing a `Result` the caller then tests (the
//!   payload's own decoder) writes its fields where the reach check is told
//!   so: on the side of the test where its tag is not the failing one
//!   (`gated_summary`, as `enum_match` uses it).
//! - **The switch is on the variant.** Element 0 is the variant's name;
//!   the lookup's table is the enum's variant names in declared order, so
//!   it returns the variant's position, and the switch on it takes the arm
//!   for that position. The rewritten switch selects on the value's
//!   variant, which is that position.
//! - **Element 1 is the payload.** On the arm of a variant with one
//!   component, element 1 is that component's `Val`. `decode(x)` of a
//!   `u32`'s `Val` is its body, the `u32` zero-extended; a unit enum's is
//!   its code, the same. Any other use takes the `Val`, which for a type
//!   carried as its own `Val` (a contract type, a handle) is the value.
//!   rustc folds a unit enum's check into `select(chain, k, is_u32(x))`,
//!   the chain sending each declared discriminant of `x`'s code to itself
//!   and anything else to a code no case has, `k` no case's code either:
//!   on the payload `x` is a `U32Val` holding a declared code, so the
//!   select is that code, the payload's discriminant (`p as i32`).
//! - **The checks go.** Every value computed only from the decode's own
//!   data — the iterator state, the `next` tags, the elements' tags, the
//!   symbol, the lookup — is invisible to the source, which sees only the
//!   variant and the payload; a trap such a value guards is the derived
//!   decode's failure path, never taken on a proven value. So `if c { trap }`
//!   goes, `if c { x } else { trap }` becomes `x`, and a branch both of whose
//!   ways are then empty goes. The lookup's position is the one such value
//!   the source does see (it is the variant): a test of it goes only when it
//!   is `position > k` with `k` at least the last position, false for every
//!   variant.
//! - **Removing the decode loses no read.** Every read of the state and of
//!   each call's slot is one of the above (the reach check refuses a call
//!   otherwise), and every use of the values derived from them is removed
//!   or rewritten, all or nothing.
//!
//! When the variant whose code follows the switch (its default arm, falling
//! through into the rest of the sequence because no other arm does) has a
//! payload, the rest moves into the default arm — it runs exactly when
//! control falls out of the switch, which only the default does — and that
//! arm names the variant: no other position is left for it to take.
//!
//! # Gates
//!
//! - `next`: no spec, `(out, state)`; `out` only stored at +0 (8 bytes,
//!   every path) and +8 (8 bytes); `state` only read at +0/8, +8/4,
//!   +12/4 and written at +8/4; the tag a merge of `0` and `2`, the element
//!   and index stores together on the paths whose tag is not `2`; the
//!   element `vec_get(load +0, U32Val(load +8))`, the index that load
//!   plus one.
//! - The value proven to be a declared enum every variant of which has at
//!   most one payload component.
//! - The state: three stores of the value, `0` and its `vec_len`; nothing
//!   else touches its 16 bytes but `next` calls handed it and loads of the
//!   index and length.
//! - One lookup over the enum's variant names, on an element of the first
//!   call; one switch on its position; every other call in a single-case
//!   arm (or the default) of that switch whose variant has a payload, one
//!   per arm, none in a loop.
//! - Each call: the reach check accepts its slot; its element read whole.
//! - A payload's uses: in its arm; `decode` only for a `u32` or unit enum;
//!   a unit enum's checked code only as the select chain above, its codes
//!   exactly the declared ones; other non-check uses only for a type
//!   carried as its own `Val`.
//!
//! Not taken yet: a variant of several components (`X(a, b)`), a payload
//! of a numeric type other than `u32` (`i64`, `i128`: their two-form
//! decodes), a tuple payload, a payload carried out of its arm by a merge,
//! and a frame slot two decodes reuse for their iterators (the check of
//! the state is flow-insensitive).
//! - Every removed value's uses removed with it; each condition is a trap
//!   guard, an inverted trap guard, or a branch left empty.

use std::collections::{BTreeSet, HashMap, HashSet};

use sordec_common::{BlockId, FuncId, Provenance, ProvenanceSource, TypeId, ValueId};
use sordec_ir::{
    BinaryOp, BufOpKind, Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, Literal, MemWidth, Region,
    SemanticOp, StructDef, SwitchArm, TypeRegistry, UnaryOp, UnionDef, VecOpKind,
};

use super::enum_match::{blocks_in, expr_of, falls_through, gated_summary, open_arm, scheduled};
use super::udt_decode::reach::{self, Gated};
use super::udt_decode::{param_accesses, raw_address, read_keys, udt_of, Candidate, CertainWrite, ParamAccess, Role, Slot};
use super::{apply_elisions, Elision};
use crate::dataflow::{canon_addr, resolve_use, trace_int, trace_u32val, HighUseIndex, HighUseSite};
use crate::metrics_catalog as mc;
use crate::pass::{Pass, PassResult};
use crate::type_infer::known_of_type_ref;

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-enum-iter";

/// Takes inline enum decodes apart into a `match`; see the module docs.
#[derive(Debug, Default, Clone, Copy)]
pub struct EnumIterPass;

impl Pass<HighIr> for EnumIterPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let Some(facts) = ir.soroban_facts.as_ref() else {
            return result;
        };
        let types = facts.types.clone();
        if types.unions.is_empty() {
            return result;
        }
        let access: HashMap<FuncId, Vec<Option<ParamAccess>>> =
            ir.functions.iter().map(|f| (f.id, param_accesses(f))).collect();
        let nexts: HashSet<FuncId> =
            ir.functions.iter().filter(|f| is_next(ir, f, access.get(&f.id))).map(|f| f.id).collect();
        if nexts.is_empty() {
            return result;
        }
        // Every helper whose writes a tag word gates: `next`, and the
        // decoders of a payload that write a `Result` into the frame.
        let gated: HashMap<FuncId, Vec<Option<Gated>>> =
            ir.functions.iter().map(|f| (f.id, gated_summary(ir, f, access.get(&f.id)))).collect();
        let memory = ir.memory.clone();
        for func in &mut ir.functions {
            let mut tried: HashSet<ValueId> = HashSet::new();
            // A site rewrites the region, so the next is planned afresh.
            for _ in 0..16 {
                let (site, refused) = plan(func, &memory, &types, &nexts, &access, &gated, &mut tried);
                result.metrics.increment(mc::MARSHALLING_ENUM_ITER_REFUSED, refused);
                let Some(site) = site else { break };
                let payloads = apply(func, site);
                result.metrics.increment(mc::MARSHALLING_ENUM_ITER_SITES, 1);
                result.metrics.increment(mc::MARSHALLING_ENUM_ITER_PAYLOADS, payloads);
                result.changed = true;
            }
        }
        result
    }
}

#[allow(clippy::print_stderr)]
fn trace(func: &HighFunction, why: &str) {
    if std::env::var_os("SORDEC_ENUM_TRACE").is_some() {
        eprintln!("enum-iter: func_{}: {why}", sordec_common::IrId::index(func.id));
    }
}

// ---------------------------------------------------------------------
// The iterator's `next`
// ---------------------------------------------------------------------

/// Whether `f` is the SDK vector iterator's `next` (see *Gates*).
fn is_next(ir: &HighIr, f: &HighFunction, access: Option<&Vec<Option<ParamAccess>>>) -> bool {
    if f.signature.is_some() || f.params.len() != 2 {
        return false;
    }
    let Some(acc) = access else { return false };
    let (Some(Some(out)), Some(Some(it))) = (acc.first(), acc.get(1)) else { return false };
    let set = |v: &[(u32, u32)]| v.iter().copied().collect::<BTreeSet<_>>();
    if !out.reads.is_empty() || set(&out.writes) != BTreeSet::from([(0, 8), (8, 8)]) {
        return false;
    }
    if set(&it.reads) != BTreeSet::from([(0, 8), (8, 4), (12, 4)]) || set(&it.writes) != BTreeSet::from([(8, 4)]) {
        return false;
    }
    let gated = gated_summary(ir, f, Some(acc));
    let Some(Some(g)) = gated.first() else { return false };
    if g.width != 8 || g.none != 2 || g.writes != [(8, 8)] {
        return false;
    }
    let (out_p, it_p) = (f.params[0], f.params[1]);
    let mut elem: Option<(BlockId, ValueId)> = None;
    let mut next_idx: Option<(BlockId, ValueId)> = None;
    let mut tag: Option<ValueId> = None;
    for (b, v) in scheduled(f) {
        let Some(Expr::Store { addr, value, offset, width }) = f.bindings.get(v).map(|b| &b.expr) else { continue };
        let a = resolve_use(f, *addr);
        match (a == out_p, a == it_p, *offset, *width) {
            (true, _, 0, MemWidth::W8) => tag = Some(*value),
            (true, _, 8, MemWidth::W8) if elem.is_none() => elem = Some((b, *value)),
            (_, true, 8, MemWidth::W4) if next_idx.is_none() => next_idx = Some((b, *value)),
            _ => return false,
        }
    }
    let (Some((eb, elem)), Some((ib, next_idx)), Some(tag)) = (elem, next_idx, tag) else { return false };
    if eb != ib {
        return false;
    }
    // The tags: `0` and `2`, nothing else.
    let Some(Expr::Phi { incoming }) = expr_of(f, tag) else { return false };
    if incoming.is_empty() || !incoming.iter().all(|(_, x)| matches!(trace_int(f, *x), Some(0 | 2))) {
        return false;
    }
    let load_of = |v: ValueId, off: u32, w: MemWidth| -> Option<ValueId> {
        let v = resolve_use(f, v);
        match &f.bindings.get(v)?.expr {
            Expr::Load { addr, offset, width, .. } if resolve_use(f, *addr) == it_p && *offset == off && *width == w => {
                Some(v)
            }
            _ => None,
        }
    };
    let Some(Expr::Semantic(SemanticOp::Known(KnownOp::VecOp { kind: VecOpKind::Get, args }))) = expr_of(f, elem)
    else {
        return false;
    };
    let [vec, at] = args.as_slice() else { return false };
    if load_of(*vec, 0, MemWidth::W8).is_none() {
        return false;
    }
    let Some(Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { value: index, .. }))) = expr_of(f, *at) else {
        return false;
    };
    let Some(index) = load_of(*index, 8, MemWidth::W4) else { return false };
    let Some(Expr::Binary { op: BinaryOp::Add, lhs, rhs }) = expr_of(f, next_idx) else { return false };
    [(*lhs, *rhs), (*rhs, *lhs)].iter().any(|(a, k)| resolve_use(f, *a) == index && trace_int(f, *k) == Some(1))
}

// ---------------------------------------------------------------------
// A site
// ---------------------------------------------------------------------

/// One inline decode taken apart.
#[derive(Debug)]
struct Site {
    value: ValueId,
    /// The bindings that go, with every use.
    removed: HashSet<ValueId>,
    /// `decode(x)` of a payload element: `(binding, arm key)`.
    decodes: Vec<(ValueId, ArmKey)>,
    /// A unit enum payload's checked code: `(binding, arm key)`.
    codes: Vec<(ValueId, ArmKey)>,
    /// Conditions of `if c { trap }` (no else), `if c { trap } else { x }`,
    /// `if c { x } else { trap }` and `if c { .. } else { .. }` left empty.
    strip: HashSet<ValueId>,
    keep_else: HashSet<ValueId>,
    keep_then: HashSet<ValueId>,
    dissolve: HashSet<ValueId>,
    /// The dispatch switch's selector binding.
    selector: ValueId,
    /// Per arm with a payload: the variant, its position, the component's
    /// declared type, and the element loads it reads.
    payloads: Vec<ArmPayload>,
    /// The default arm becomes an explicit arm for this position; with
    /// `true`, the rest of the sequence after the switch moves into it.
    explicit_default: Option<(u32, bool)>,
}

/// An explicit arm by its index among the switch's arms, or the default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ArmKey {
    Arm(usize),
    Default,
}

#[derive(Debug)]
struct ArmPayload {
    arm: ArmKey,
    variant: String,
    ty: KnownType,
    loads: Vec<ValueId>,
}

/// The regions' loop-enclosed blocks.
fn loop_blocks(region: &Region) -> HashSet<BlockId> {
    let mut out = HashSet::new();
    region.for_each_node(|node| {
        if let Region::Loop { body, .. } = node {
            out.extend(blocks_in(body));
        }
    });
    out
}

/// A switch found, with the sequence holding it and its position there.
type Found<'r> = (&'r Region, Option<(&'r [Region], usize)>);

/// The switch whose selector is `decoded` (directly or its low 32 bits),
/// with the region sequence holding it and its position there (`None`
/// when it is not an item of a sequence).
fn find_switch<'r>(func: &HighFunction, region: &'r Region, decoded: ValueId, out: &mut Vec<Found<'r>>) {
    let selects = |index: ValueId| {
        let mut sel = resolve_use(func, index);
        if let Some(Expr::Unary { op: UnaryOp::Wrap32, value }) = func.bindings.get(sel).map(|b| &b.expr) {
            sel = resolve_use(func, *value);
        }
        sel == decoded
    };
    match region {
        Region::Sequence(items) => {
            for (i, item) in items.iter().enumerate() {
                if let Region::Switch { index, .. } = item
                    && selects(*index)
                {
                    out.push((item, Some((items.as_slice(), i))));
                    if let Region::Switch { arms, default, .. } = item {
                        arms.iter().for_each(|a| find_switch(func, &a.body, decoded, out));
                        find_switch(func, default, decoded, out);
                    }
                } else {
                    find_switch(func, item, decoded, out);
                }
            }
        }
        Region::Switch { index, arms, default, .. } => {
            if selects(*index) {
                out.push((region, None));
            }
            arms.iter().for_each(|a| find_switch(func, &a.body, decoded, out));
            find_switch(func, default, decoded, out);
        }
        Region::Scope { body, .. } | Region::Loop { body, .. } => find_switch(func, body, decoded, out),
        Region::If { then_region, else_region, .. } => {
            find_switch(func, then_region, decoded, out);
            if let Some(e) = else_region {
                find_switch(func, e, decoded, out);
            }
        }
        _ => {}
    }
}

/// Where `v` points, as `(base, offset)` through a `U32Val` wrapping.
fn addr(func: &HighFunction, v: ValueId) -> (ValueId, u32) {
    canon_addr(func, raw_address(func, v))
}

/// Whether `v` is computed from `base` (arithmetic, conversions, merges).
fn derived_from(func: &HighFunction, v: ValueId, base: ValueId) -> bool {
    let mut seen = HashSet::new();
    let mut stack = vec![v];
    while let Some(x) = stack.pop() {
        let x = resolve_use(func, x);
        if x == base {
            return true;
        }
        if !seen.insert(x) {
            continue;
        }
        if seen.len() > 64 {
            return true;
        }
        match func.bindings.get(x).map(|b| &b.expr) {
            Some(Expr::Binary { lhs, rhs, .. }) => stack.extend([*lhs, *rhs]),
            Some(Expr::Unary { value, .. }) => stack.push(*value),
            Some(Expr::Select { if_true, if_false, .. }) => stack.extend([*if_true, *if_false]),
            Some(Expr::Phi { incoming }) => stack.extend(incoming.iter().map(|(_, v)| *v)),
            Some(Expr::Unknown { args, .. }) => stack.extend(args.iter().copied()),
            Some(Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { value, .. }))) => stack.push(*value),
            _ => {}
        }
    }
    false
}

/// Whether anything but `allowed` may touch the 16 state bytes at
/// `base + at`: a load, a store, or an operation handed a pointer that may
/// reach them. Flow-insensitive, so it refuses more than it must.
fn foreign_touch(
    func: &HighFunction,
    base: ValueId,
    at: u32,
    allowed: &HashSet<ValueId>,
    access: &HashMap<FuncId, Vec<Option<ParamAccess>>>,
) -> Option<ValueId> {
    let (lo, hi) = (u64::from(at), u64::from(at) + 16);
    let overlaps = |a: u64, b: u64| a < hi && lo < b;
    for (_, id) in scheduled(func) {
        if allowed.contains(&id) {
            continue;
        }
        let Some(expr) = func.bindings.get(id).map(|b| &b.expr) else { continue };
        let effects = crate::effects::expr_effects(expr);
        if !effects.reads_memory && !effects.writes_memory {
            continue;
        }
        let hit = match expr {
            Expr::Load { addr: a, offset, width, .. } => {
                let (b, k) = canon_addr(func, *a);
                if b == base {
                    let s = u64::from(k) + u64::from(*offset);
                    overlaps(s, s + u64::from(width.bytes()))
                } else {
                    derived_from(func, *a, base)
                }
            }
            Expr::Store { addr: a, value, offset, width } => {
                let (b, k) = canon_addr(func, *a);
                let into = if b == base {
                    let s = u64::from(k) + u64::from(*offset);
                    overlaps(s, s + u64::from(width.bytes()))
                } else {
                    derived_from(func, *a, base)
                };
                into || derived_from(func, *value, base)
            }
            Expr::Call { target, args } => args.iter().enumerate().any(|(k, a)| {
                if !derived_from(func, *a, base) {
                    return false;
                }
                let (b, off) = addr(func, *a);
                if b != base {
                    return true;
                }
                // Another iterator's `next`, or any summarised helper:
                // exactly the bytes it touches through this parameter.
                let summary = access.get(target).and_then(|s| s.get(k)).and_then(Option::as_ref);
                match summary {
                    Some(acc) => acc.reads.iter().chain(&acc.writes).any(|(o, w)| {
                        let s = u64::from(off) + u64::from(*o);
                        overlaps(s, s + u64::from(*w))
                    }),
                    None => u64::from(off) < hi,
                }
            }),
            other => {
                let mut hit = false;
                other.for_each_value_use(|u| {
                    if hit || !derived_from(func, u, base) {
                        return;
                    }
                    let (b, off) = addr(func, u);
                    hit = b != base || u64::from(off) < hi;
                });
                hit
            }
        };
        if hit {
            return Some(id);
        }
    }
    None
}

/// The enum's variant names, if `lookup` is the derived decode's symbol
/// lookup on `sym` and its table is exactly them in declared order.
fn lookup_on(func: &HighFunction, memory: &sordec_ir::MemoryImage, lookup: ValueId, union: &UnionDef) -> Option<ValueId> {
    let names: Vec<String> = union.cases.iter().map(|c| c.name.clone()).collect();
    match func.bindings.get(lookup).map(|b| &b.expr)? {
        Expr::Semantic(SemanticOp::Known(KnownOp::SymbolDispatch { sym, table, .. })) => {
            (table.cases == names).then_some(resolve_use(func, *sym))
        }
        Expr::Semantic(SemanticOp::Known(KnownOp::BufOp { kind: BufOpKind::SymbolIndexInLinearMemory, args }))
            if args.len() == 3 =>
        {
            let pos = trace_u32val(func, args[1])?;
            let len = trace_u32val(func, args[2])?;
            (read_keys(memory, pos, len)? == names).then_some(resolve_use(func, args[0]))
        }
        _ => None,
    }
}

/// Whether `expr` computes a value and nothing else.
fn pure(expr: &Expr) -> bool {
    if matches!(expr, Expr::Phi { .. } | Expr::Literal(_)) {
        return false;
    }
    let e = crate::effects::expr_effects(expr);
    !(e.may_trap || e.reads_memory || e.writes_memory || e.reads_globals || e.writes_globals || e.reads_host || e.writes_host)
}

/// A payload component's type when its `Val` is the value itself.
fn val_is_value(ty: &KnownType) -> bool {
    matches!(
        ty,
        KnownType::UserDefined(_)
            | KnownType::Address
            | KnownType::Bytes
            | KnownType::String
            | KnownType::Vec(_)
            | KnownType::Map(..)
            | KnownType::BytesN(_)
            | KnownType::Symbol
    )
}

/// Whether `decode(x)` of the component's `Val` is the value zero-extended.
fn decodes_as_u32(ty: &KnownType, types: &TypeRegistry) -> bool {
    match ty {
        KnownType::U32 => true,
        KnownType::UserDefined(id) => types.enums.iter().any(|e| e.id == *id),
        _ => false,
    }
}

/// A region that does nothing once the site's checks are gone: blocks
/// holding only removed bindings and constants, and conditions the site
/// removes.
fn empty_after(func: &HighFunction, r: &Region, removed: &HashSet<ValueId>, empty: &HashSet<BlockId>) -> bool {
    match r {
        Region::Basic(b) => func.blocks.get(*b).is_some_and(|blk| {
            blk.bindings
                .iter()
                .all(|v| removed.contains(v) || matches!(func.bindings.get(*v).map(|b| &b.expr), Some(Expr::Literal(_))))
        }),
        Region::Sequence(items) => items.iter().all(|i| empty_after(func, i, removed, empty)),
        Region::Transfer { transfer, .. } => transfer.is_empty(),
        Region::If { cond, then_region, else_region } if removed.contains(cond) => {
            let then_trap = super::guard::is_trap(then_region, empty);
            match else_region {
                None => then_trap || empty_after(func, then_region, removed, empty),
                Some(e) => {
                    let else_trap = super::guard::is_trap(e, empty);
                    (then_trap || empty_after(func, then_region, removed, empty))
                        && (else_trap || empty_after(func, e, removed, empty))
                        && !(then_trap && else_trap)
                }
            }
        }
        _ => false,
    }
}

#[allow(clippy::too_many_lines)]
fn plan(
    func: &HighFunction,
    memory: &sordec_ir::MemoryImage,
    types: &TypeRegistry,
    nexts: &HashSet<FuncId>,
    access: &HashMap<FuncId, Vec<Option<ParamAccess>>>,
    gated: &HashMap<FuncId, Vec<Option<Gated>>>,
    tried: &mut HashSet<ValueId>,
) -> (Option<Site>, i64) {
    let order = scheduled(func);
    let mut refused = 0;
    for (_, len) in &order {
        let Some(Expr::Semantic(SemanticOp::Known(KnownOp::VecOp { kind: VecOpKind::Len, args }))) =
            func.bindings.get(*len).map(|b| &b.expr)
        else {
            continue;
        };
        let [arg] = args.as_slice() else { continue };
        let value = resolve_use(func, *arg);
        let Some(uid) = udt_of(func, value) else { continue };
        let Some(union) = types.unions.iter().find(|u| u.id == uid) else { continue };
        if !tried.insert(*len) {
            continue;
        }
        match site(func, memory, types, nexts, access, gated, &order, *len, value, union) {
            Ok(s) => return (Some(s), refused),
            Err(why) => {
                refused += 1;
                trace(func, &format!("decode of {value:?} refused: {why}"));
            }
        }
    }
    (None, refused)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn site(
    func: &HighFunction,
    memory: &sordec_ir::MemoryImage,
    types: &TypeRegistry,
    nexts: &HashSet<FuncId>,
    access: &HashMap<FuncId, Vec<Option<ParamAccess>>>,
    gated: &HashMap<FuncId, Vec<Option<Gated>>>,
    order: &[(BlockId, ValueId)],
    len: ValueId,
    value: ValueId,
    union: &UnionDef,
) -> Result<Site, String> {
    if union.cases.iter().any(|c| c.fields.len() > 1) {
        return Err("a variant with several payload components".into());
    }
    let block_of: HashMap<ValueId, BlockId> = order.iter().map(|(b, v)| (*v, *b)).collect();
    let in_loop = loop_blocks(&func.region);
    let store = |v: ValueId| match func.bindings.get(v).map(|b| &b.expr) {
        Some(Expr::Store { addr: a, value: x, offset, width }) => {
            let (b, k) = canon_addr(func, *a);
            Some((b, k.checked_add(*offset)?, *width, resolve_use(func, *x)))
        }
        _ => None,
    };

    // The state: the value, 0 and its length, at +0, +8, +12.
    let vec_stores: Vec<(ValueId, ValueId, u32)> = order
        .iter()
        .filter_map(|(_, v)| match store(*v)? {
            (b, at, MemWidth::W8, x) if x == value => Some((*v, b, at)),
            _ => None,
        })
        .collect();
    let [(s_vec, base, at)] = vec_stores.as_slice() else {
        return Err(format!("{} stores of the value into memory", vec_stores.len()));
    };
    let (base, at) = (*base, *at);
    let find = |off: u32, ok: &dyn Fn(ValueId) -> bool| -> Option<ValueId> {
        let hits: Vec<ValueId> = order
            .iter()
            .filter(|(_, v)| matches!(store(*v), Some((b, k, MemWidth::W4, x)) if b == base && k == off && ok(x)))
            .map(|(_, v)| *v)
            .collect();
        match hits.as_slice() {
            [one] => Some(*one),
            _ => None,
        }
    };
    let s_idx = find(at + 8, &|x| trace_int(func, x) == Some(0)).ok_or("no single zero index store")?;
    let s_len = find(at + 12, &|x| x == len).ok_or("no single length store")?;
    for s in [*s_vec, s_idx, s_len] {
        if block_of.get(&s).is_some_and(|b| in_loop.contains(b)) {
            return Err("the state is set in a loop".into());
        }
    }

    // The `next` calls on it, and the loads of its index and length.
    let mut calls: Vec<(ValueId, u32)> = Vec::new();
    let mut state_loads: Vec<ValueId> = Vec::new();
    for (b, v) in order {
        match func.bindings.get(*v).map(|b| &b.expr) {
            Some(Expr::Call { target, args }) if nexts.contains(target) && args.len() == 2 => {
                if addr(func, args[1]) != (base, at) {
                    continue;
                }
                let (ob, r) = addr(func, args[0]);
                if ob != base || (r < at + 16 && at < r + 16) {
                    return Err("a next call's out-pointer is not a frame slot of its own".into());
                }
                if in_loop.contains(b) {
                    return Err("a next call in a loop".into());
                }
                calls.push((*v, r));
            }
            Some(Expr::Load { addr: a, offset, width: MemWidth::W4, .. }) => {
                let (lb, k) = canon_addr(func, *a);
                if lb == base && matches!(k.checked_add(*offset), Some(o) if o == at + 8 || o == at + 12) {
                    state_loads.push(*v);
                }
            }
            _ => {}
        }
    }
    if calls.is_empty() {
        return Err("no next call on the state".into());
    }
    let mut allowed: HashSet<ValueId> = [*s_vec, s_idx, s_len].into_iter().collect();
    allowed.extend(calls.iter().map(|(c, _)| *c));
    allowed.extend(state_loads.iter().copied());
    if let Some(other) = foreign_touch(func, base, at, &allowed, access) {
        return Err(format!("{other:?} may touch the iterator state"));
    }

    // Each call's slot: its tag and element reads.
    let dummy = StructDef { id: TypeId::new(0), name: String::new(), fields: Vec::new() };
    let cands: Vec<Candidate<'_>> = calls
        .iter()
        .map(|(c, r)| Candidate {
            base,
            start: *r,
            producer: *c,
            map: *c,
            def: &dummy,
            slots: vec![
                Slot { rel: 0, width: 8, role: Role::Disc },
                Slot { rel: 8, width: 8, role: Role::Disc },
            ],
            vals: false,
            payload: false,
        })
        .collect();
    let certain: Vec<CertainWrite> = cands.iter().map(|c| (c.producer, c.base, c.certain_writes())).collect();
    let mut tags: Vec<ValueId> = Vec::new();
    let mut elements: HashMap<ValueId, Vec<ValueId>> = HashMap::new();
    for cand in &cands {
        let reads = reach::check_gated(func, cand, &certain, access, gated)?;
        if !reads.tags.is_empty() {
            return Err("a tag-byte read of a next slot".into());
        }
        for (load, slot) in reads.fields {
            if slot == 0 {
                tags.push(load);
            } else {
                let whole = matches!(func.bindings.get(load).map(|b| &b.expr),
                    Some(Expr::Load { width: MemWidth::W8, .. }));
                if !whole {
                    return Err(format!("{load:?} reads part of an element"));
                }
                elements.entry(cand.producer).or_default().push(load);
            }
        }
    }

    // The lookup on element 0, its position, the switch on it.
    let element_of: HashMap<ValueId, ValueId> =
        elements.iter().flat_map(|(c, ls)| ls.iter().map(move |l| (*l, *c))).collect();
    let lookups: Vec<(ValueId, ValueId)> = order
        .iter()
        .filter_map(|(_, v)| {
            let sym = lookup_on(func, memory, *v, union)?;
            let call = element_of.get(&sym)?;
            Some((*v, *call))
        })
        .collect();
    let [(lookup, first)] = lookups.as_slice() else {
        return Err(format!("{} lookups of the variant name on an element", lookups.len()));
    };
    let (lookup, first) = (*lookup, *first);
    let decodeds: Vec<ValueId> = order
        .iter()
        .filter(|(_, v)| {
            matches!(expr_of(func, *v), Some(Expr::Semantic(SemanticOp::Known(KnownOp::ValDecodeSmall { value })))
                if resolve_use(func, *value) == lookup)
        })
        .map(|(_, v)| *v)
        .collect();
    let [decoded] = decodeds.as_slice() else { return Err("the position is not decoded once".into()) };
    let decoded = *decoded;
    let mut found = Vec::new();
    find_switch(func, &func.region, decoded, &mut found);
    let [(switch, holder)] = found.as_slice() else {
        return Err(format!("{} switches on the position", found.len()));
    };
    let Region::Switch { index: selector, arms, default, dispatch } = switch else { unreachable!() };
    let selector = *selector;
    // The dispatcher's link to the lookup it names the arms by.
    let linked = dispatch.filter(|d| resolve_use(func, *d) == lookup);
    let n = union.cases.len() as u32;
    if arms.iter().flat_map(|a| &a.cases).any(|c| *c >= n) {
        return Err("a switch case that is no variant".into());
    }
    let named: HashSet<u32> = arms.iter().flat_map(|a| a.cases.iter().copied()).collect();
    let missing: Vec<u32> = (0..n).filter(|c| !named.contains(c)).collect();

    // The blocks only each arm reaches; the default's take the rest of
    // the sequence when no other arm falls out of the switch.
    let mut arm_blocks: Vec<(ArmKey, HashSet<BlockId>)> =
        arms.iter().enumerate().map(|(i, a)| (ArmKey::Arm(i), blocks_in(&a.body))).collect();
    let mut default_blocks = blocks_in(default);
    let rest_blocks: HashSet<BlockId> = match holder {
        Some((items, i)) if !arms.iter().any(|a| falls_through(&a.body)) => {
            items[i + 1..].iter().flat_map(blocks_in).collect()
        }
        _ => HashSet::new(),
    };
    default_blocks.extend(rest_blocks.iter().copied());
    arm_blocks.push((ArmKey::Default, default_blocks));
    let first_block = *block_of.get(&first).ok_or("the first call is not scheduled")?;
    if arm_blocks.iter().any(|(_, bs)| bs.contains(&first_block)) || blocks_in(switch).contains(&first_block) {
        return Err("the first call is inside the switch".into());
    }

    // Every other call: in one arm of a variant with a payload, one each.
    let mut by_arm: HashMap<ArmKey, ValueId> = HashMap::new();
    for (c, _) in &calls {
        if *c == first {
            continue;
        }
        let b = block_of.get(c).ok_or("a call is not scheduled")?;
        let Some((key, _)) = arm_blocks.iter().find(|(_, bs)| bs.contains(b)) else {
            return Err(format!("{c:?} is in no arm of the switch"));
        };
        if by_arm.insert(*key, *c).is_some() {
            return Err("two next calls in one arm".into());
        }
    }
    let case_of = |key: ArmKey| -> Option<u32> {
        match key {
            ArmKey::Arm(i) => match arms[i].cases.as_slice() {
                [c] => Some(*c),
                _ => None,
            },
            ArmKey::Default => match missing.as_slice() {
                [c] => Some(*c),
                _ => None,
            },
        }
    };
    let mut payloads: Vec<ArmPayload> = Vec::new();
    let mut kept: HashSet<ValueId> = HashSet::new();
    let mut decodes: Vec<(ValueId, ArmKey)> = Vec::new();
    // In arm order, so the payloads are numbered the same on every run.
    let mut in_order: Vec<(&ArmKey, &ValueId)> = by_arm.iter().collect();
    in_order.sort_by_key(|(k, _)| match k {
        ArmKey::Arm(i) => *i,
        ArmKey::Default => usize::MAX,
    });
    for (key, call) in in_order {
        let case = case_of(*key).ok_or("a next call in an arm of several variants")?;
        let variant = &union.cases[case as usize];
        let [field] = variant.fields.as_slice() else {
            return Err(format!("a next call in the arm of `{}`, which has no payload", variant.name));
        };
        let ty = known_of_type_ref(field).ok_or("a payload type with no known form")?;
        let loads = elements.get(call).cloned().unwrap_or_default();
        payloads.push(ArmPayload { arm: *key, variant: variant.name.clone(), ty, loads });
    }
    // A variant with a payload whose arm makes no call has not read it.
    for (key, _) in &arm_blocks {
        let Some(case) = case_of(*key) else { continue };
        if !union.cases[case as usize].fields.is_empty() && !by_arm.contains_key(key) {
            return Err(format!("the arm of `{}` reads no payload", union.cases[case as usize].name));
        }
    }

    // What goes: the length, the state, the calls, their tags, element 0,
    // the lookup and its position, the payload elements — and every pure
    // value computed only from them.
    let uses = HighUseIndex::build(func);
    // A binding counts as a reader when it runs: scheduled, or a merge.
    let live = |v: ValueId| {
        block_of.contains_key(&v) || matches!(func.bindings.get(v).map(|b| &b.expr), Some(Expr::Phi { .. }))
    };
    let mut removed: HashSet<ValueId> = HashSet::new();
    removed.insert(len);
    removed.extend([*s_vec, s_idx, s_len]);
    removed.extend(calls.iter().map(|(c, _)| *c));
    removed.extend(tags.iter().copied());
    removed.extend(state_loads.iter().copied());
    removed.extend(elements.values().flatten().copied());
    removed.insert(lookup);
    // A `Use` alias of the length (the decoded `u32`) goes with it.
    for (_, v) in order {
        if resolve_use(func, *v) == len {
            removed.insert(*v);
        }
    }
    // The payload elements' uses: a `u32` decode is the value; a value
    // carried as its own `Val` is the payload; pure work joins `removed`.
    for p in &payloads {
        for load in &p.loads {
            for site in uses.uses_of(*load) {
                let HighUseSite::Binding { user } = site else {
                    return Err(format!("{load:?}, a payload element, is used by the region"));
                };
                if !live(*user) {
                    continue;
                }
                let Some(expr) = func.bindings.get(*user).map(|b| &b.expr) else { continue };
                let user_block = block_of.get(user).copied();
                let in_arm = user_block.is_some_and(|b| {
                    arm_blocks.iter().find(|(k, _)| *k == p.arm).is_some_and(|(_, bs)| bs.contains(&b))
                });
                match expr {
                    Expr::Semantic(SemanticOp::Known(KnownOp::ValDecodeSmall { .. })) if decodes_as_u32(&p.ty, types) => {
                        if !in_arm {
                            return Err(format!("{user:?} decodes a payload outside its arm"));
                        }
                        kept.insert(*user);
                        decodes.push((*user, p.arm));
                    }
                    e if pure(e) => {}
                    Expr::Use(_) => {}
                    _ if val_is_value(&p.ty) => {
                        if !in_arm {
                            return Err(format!("{user:?} uses a payload outside its arm"));
                        }
                        kept.insert(*user);
                    }
                    _ => return Err(format!("{user:?} uses a payload element of a type not carried as its own Val")),
                }
            }
        }
    }
    // A unit enum's code, checked as rustc folds it: `select(chain, k,
    // is_u32(x))` where the chain sends each declared discriminant of the
    // decoded code to itself and anything else to a code no case has, and
    // `k` is no case's code either. On the payload `x` is a `U32Val` and its
    // code a declared one, so the select is that code: the payload's
    // discriminant.
    let mut codes: Vec<(ValueId, ArmKey)> = Vec::new();
    for p in &payloads {
        let KnownType::UserDefined(id) = &p.ty else { continue };
        let Some(def) = types.enums.iter().find(|e| e.id == *id) else { continue };
        let declared: HashSet<i128> = def.cases.iter().map(|c| i128::from(c.value)).collect();
        let of_payload = |v: ValueId| p.loads.contains(&resolve_use(func, v));
        for (b, sel) in order {
            let (if_true, if_false, cond) = match func.bindings.get(*sel).map(|b| &b.expr) {
                Some(Expr::Select { cond, if_true, if_false }) => (*if_true, *if_false, *cond),
                Some(Expr::Unknown { op_kind: sordec_ir::WasmOpcodeKind::Select, args, .. }) if args.len() == 3 => {
                    (args[0], args[1], args[2])
                }
                _ => continue,
            };
            let tested = matches!(expr_of(func, cond),
                Some(Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck { value, tag, negated: false })))
                    if of_payload(*value) && *tag == crate::val_abi::TAG_U32_VAL);
            if !tested || trace_int(func, if_false).is_none_or(|k| declared.contains(&k)) {
                continue;
            }
            let Some((found, parts)) = super::enum_match::code_chain_parts(func, if_true) else { continue };
            let word_ok = parts.last().is_some_and(|w| {
                matches!(func.bindings.get(*w).map(|b| &b.expr), Some(Expr::Unary { op: UnaryOp::Wrap32, value })
                    if matches!(expr_of(func, *value),
                        Some(Expr::Semantic(SemanticOp::Known(KnownOp::ValDecodeSmall { value: x }))) if of_payload(*x)))
            });
            if found != declared || !word_ok {
                continue;
            }
            let here = arm_blocks.iter().find(|(k, _)| *k == p.arm).is_some_and(|(_, bs)| bs.contains(b));
            if !here {
                return Err(format!("{sel:?} reads a payload's code outside its arm"));
            }
            kept.insert(*sel);
            codes.push((*sel, p.arm));
            removed.extend(parts.iter().copied());
            removed.insert(resolve_use(func, cond));
        }
    }
    // The position: only the switch and a bound test no variant passes.
    let aliases: Vec<ValueId> =
        func.bindings.iter().map(|(id, _)| id).filter(|id| resolve_use(func, *id) == decoded).collect();
    let mut bound_tests: HashSet<ValueId> = HashSet::new();
    for d in &aliases {
        removed.insert(*d);
        for site in uses.uses_of(*d) {
            let HighUseSite::Binding { user } = site else {
                if resolve_use(func, selector) == decoded {
                    continue;
                }
                return Err("the position is used by the region other than as the switch".into());
            };
            if !live(*user) || aliases.contains(user) {
                continue;
            }
            match func.bindings.get(*user).map(|b| &b.expr) {
                Some(Expr::Unary { op: UnaryOp::Wrap32, .. }) if resolve_use(func, selector) == *user => {
                    removed.insert(*user);
                }
                Some(Expr::Binary { op: BinaryOp::GtU, lhs, rhs })
                    if resolve_use(func, *lhs) == decoded
                        && trace_int(func, *rhs).is_some_and(|k| k >= i128::from(n) - 1) =>
                {
                    removed.insert(*user);
                    bound_tests.insert(*user);
                }
                _ => return Err(format!("{user:?} reads the position other than as the switch or a bound test")),
            }
        }
    }
    removed.insert(resolve_use(func, selector));
    // Pure work on what goes, forward and back, to a fixpoint. The
    // position's own uses are settled above.
    // Nothing joins through the position: the source sees the variant, so
    // a test of it is the source's unless it is the bound test above.
    let mut protected: HashSet<ValueId> = aliases.iter().copied().collect();
    protected.insert(resolve_use(func, selector));
    protected.extend(bound_tests.iter().copied());
    loop {
        let mut grew = false;
        for (_, v) in order {
            if removed.contains(v) || kept.contains(v) || resolve_use(func, *v) == value {
                continue;
            }
            let Some(expr) = func.bindings.get(*v).map(|b| &b.expr) else { continue };
            if !pure(expr) && !matches!(expr, Expr::Use(_)) {
                continue;
            }
            let mut operands = Vec::new();
            expr.for_each_value_use(|u| operands.push(u));
            let from_removed = operands.iter().any(|u| removed.contains(u))
                && operands
                    .iter()
                    .all(|u| removed.contains(u) || matches!(expr_of(func, *u), Some(Expr::Literal(_))));
            if from_removed && !operands.iter().any(|u| protected.contains(u)) {
                removed.insert(*v);
                grew = true;
                continue;
            }
            // Built from constants and feeding only what goes: the
            // lookup's table operands.
            let sites: Vec<&HighUseSite> =
                uses.uses_of(*v).iter().filter(|s| !matches!(s, HighUseSite::Binding { user } if !live(*user))).collect();
            let feeds = !sites.is_empty()
                && sites.iter().all(|s| matches!(s, HighUseSite::Binding { user } if removed.contains(user)));
            let constant = operands
                .iter()
                .all(|u| removed.contains(u) || matches!(expr_of(func, *u), Some(Expr::Literal(_))));
            if feeds && constant && !operands.is_empty() {
                removed.insert(*v);
                grew = true;
            }
        }
        if !grew {
            break;
        }
    }

    // Every use of what goes goes too: by a removed binding, a decode or
    // a payload use rewritten above, or a condition the region drops.
    let mut conds: HashSet<ValueId> = HashSet::new();
    for r in &removed {
        for s in uses.uses_of(*r) {
            match s {
                HighUseSite::Binding { user } if removed.contains(user) || kept.contains(user) || !live(*user) => {}
                HighUseSite::Binding { user } => {
                    return Err(format!("{user:?} uses {r:?}, which the decode removes"));
                }
                HighUseSite::Return => return Err(format!("{r:?} is returned")),
                HighUseSite::Region => {
                    conds.insert(*r);
                }
            }
        }
    }
    let empty = super::guard::empty_blocks(func);
    let mut strip = HashSet::new();
    let mut keep_else = HashSet::new();
    let mut keep_then = HashSet::new();
    let mut dissolve = HashSet::new();
    let mut bad: Option<String> = None;
    let mut index_seen = false;
    func.region.for_each_node(|node| match node {
        Region::If { cond, then_region, else_region } if conds.contains(cond) => {
            let then_trap = super::guard::is_trap(then_region, &empty);
            let else_trap = else_region.as_ref().is_some_and(|e| super::guard::is_trap(e, &empty));
            // A test of the position goes only as a trap guard.
            if bound_tests.contains(cond) && !(then_trap && else_region.is_none()) {
                bad = Some(format!("the bound test {cond:?} is not a trap guard"));
                return;
            }
            match (then_trap, else_region.is_some(), else_trap) {
                (true, false, _) => {
                    strip.insert(*cond);
                }
                (true, true, false) => {
                    keep_else.insert(*cond);
                }
                (false, true, true) => {
                    keep_then.insert(*cond);
                }
                _ if empty_after(func, node, &removed, &empty) => {
                    dissolve.insert(*cond);
                }
                _ => bad = Some(format!("{cond:?} branches to work the decode does not explain")),
            }
        }
        Region::Switch { index, .. } if conds.contains(index) || *index == selector => {
            if *index == selector {
                index_seen = true;
            } else {
                bad = Some("another switch on a removed value".into());
            }
        }
        _ => {}
    });
    if let Some(why) = bad {
        return Err(why);
    }
    let mut region_uses: Vec<ValueId> = Vec::new();
    func.region.for_each_value_use(|u| {
        if conds.contains(&u) {
            region_uses.push(u);
        }
    });
    for u in region_uses {
        let handled = strip.contains(&u)
            || keep_else.contains(&u)
            || keep_then.contains(&u)
            || dissolve.contains(&u)
            || (u == selector && index_seen)
            || Some(u) == linked;
        if !handled {
            return Err(format!("{u:?} is read by the region other than as a condition it drops"));
        }
    }
    // Conditions are tested once each: two `if`s on one could disagree on
    // what the rewrite keeps.
    let mut counted: HashMap<ValueId, usize> = HashMap::new();
    func.region.for_each_node(|node| {
        if let Region::If { cond, .. } = node
            && conds.contains(cond)
        {
            *counted.entry(*cond).or_default() += 1;
        }
    });
    if counted.values().any(|n| *n > 1) {
        return Err("one removed condition guards two branches".into());
    }

    // The default arm names its variant when it reads a payload.
    let explicit_default = match by_arm.get(&ArmKey::Default) {
        Some(c) => {
            let case = case_of(ArmKey::Default).ok_or("the default arm stands for several variants")?;
            let b = block_of.get(c).ok_or("a call is not scheduled")?;
            let moves = rest_blocks.contains(b);
            if moves && !falls_through(default) {
                return Err("the default arm does not fall into the rest".into());
            }
            Some((case, moves))
        }
        None => None,
    };
    // Every payload read sits in its arm.
    for p in &payloads {
        let bs = &arm_blocks.iter().find(|(k, _)| *k == p.arm).expect("an arm").1;
        for load in &p.loads {
            if !block_of.get(load).is_some_and(|b| bs.contains(b)) {
                return Err(format!("{load:?} reads a payload outside its arm"));
            }
        }
    }
    trace(
        func,
        &format!(
            "decode of {value:?} as {}: {} calls, {} payload arms, {} removed",
            union.name,
            calls.len(),
            payloads.len(),
            removed.len()
        ),
    );
    Ok(Site {
        value,
        removed,
        decodes,
        codes,
        strip,
        keep_else,
        keep_then,
        dissolve,
        selector,
        payloads,
        explicit_default,
    })
}

// ---------------------------------------------------------------------
// The rewrite
// ---------------------------------------------------------------------

fn apply(func: &mut HighFunction, site: Site) -> i64 {
    let prov = |note: String| Provenance::new(PASS_NAME, ProvenanceSource::SdkPattern, note);
    // The payloads, one per arm that reads one.
    let mut opening: HashMap<ArmKey, (ValueId, HashMap<ValueId, ValueId>)> = HashMap::new();
    for p in &site.payloads {
        let id = ValueId::new(func.bindings.len() as u32);
        func.bindings.push(sordec_ir::Binding::new(
            id,
            IrType::Known(p.ty.clone()),
            Expr::VariantPayload { value: site.value, variant: p.variant.clone(), index: 0 },
            prov(format!("the payload of `{}`, bound by its arm of the match on the decoded enum", p.variant)),
        ));
        let map: HashMap<ValueId, ValueId> = p.loads.iter().map(|l| (*l, id)).collect();
        opening.insert(p.arm, (id, map));
    }
    // Decodes of a payload's `Val`: the value, widened.
    let mut elisions = Vec::new();
    for (d, arm) in &site.decodes {
        let Some((p, _)) = opening.get(arm) else { continue };
        elisions.push(Elision {
            id: *d,
            expr: Expr::Unary { op: UnaryOp::ExtendU32, value: *p },
            ty: Some(IrType::Inferred(KnownType::I64)),
            note: "the payload's `Val` decoded is its value: the body of a `U32Val`".into(),
            metric: mc::MARSHALLING_ENUM_ITER_PAYLOADS,
        });
    }
    for (c, arm) in &site.codes {
        let Some((p, _)) = opening.get(arm) else { continue };
        elisions.push(Elision {
            id: *c,
            expr: Expr::Unary { op: UnaryOp::Wrap32, value: *p },
            ty: Some(IrType::Inferred(KnownType::I32)),
            note: "the payload's checked code is its discriminant: its `Val` is a `U32Val` of a declared case".into(),
            metric: mc::MARSHALLING_ENUM_ITER_PAYLOADS,
        });
    }
    for v in &site.removed {
        elisions.push(Elision {
            id: *v,
            expr: Expr::Literal(Literal::Unit),
            ty: Some(IrType::Known(KnownType::Unit)),
            note: "the enum's derived decode through the vector iterator, elided: the match names the variant and \
                   binds the payload"
                .into(),
            metric: mc::MARSHALLING_ENUM_ITER_SITES,
        });
    }
    apply_elisions(func, PASS_NAME, elisions);
    // The region: checks drop, the switch selects on the value, its arms
    // open with their payloads.
    let empty = super::guard::empty_blocks(func);
    let region = std::mem::replace(&mut func.region, Region::Unreachable);
    let region = drop_checks(region, &site, &empty);
    func.region = rewrite_switch(func, region, &site, &opening);
    site.payloads.len() as i64
}

/// The site's conditions, dropped: a trap guard goes, an inverted one
/// keeps its other side, a branch left empty keeps only its blocks.
fn drop_checks(region: Region, site: &Site, empty: &HashSet<BlockId>) -> Region {
    let rec = |r: Region| drop_checks(r, site, empty);
    match region {
        Region::Sequence(items) => Region::Sequence(items.into_iter().map(rec).collect()),
        Region::Scope { out, body } => Region::Scope { out, body: Box::new(rec(*body)) },
        Region::Loop { header, body, kind } => Region::Loop { header, body: Box::new(rec(*body)), kind },
        Region::Switch { index, arms, default, dispatch } => Region::Switch {
            index,
            arms: arms
                .into_iter()
                .map(|a| SwitchArm { cases: a.cases, body: rec(a.body) })
                .collect(),
            default: Box::new(rec(*default)),
            dispatch,
        },
        Region::If { cond, then_region, else_region } => {
            if site.strip.contains(&cond) {
                return Region::Sequence(Vec::new());
            }
            if site.keep_else.contains(&cond)
                && let Some(e) = else_region
            {
                return rec(*e);
            }
            if site.keep_then.contains(&cond) {
                return rec(*then_region);
            }
            if site.dissolve.contains(&cond) {
                let mut blocks: Vec<Region> = Vec::new();
                let whole = Region::If { cond, then_region, else_region };
                whole.for_each_node(|n| {
                    if let Region::Basic(b) = n
                        && !empty.contains(b)
                    {
                        blocks.push(Region::Basic(*b));
                    }
                });
                return Region::Sequence(blocks);
            }
            Region::If { cond, then_region: Box::new(rec(*then_region)), else_region: else_region.map(|e| Box::new(rec(*e))) }
        }
        leaf => leaf,
    }
}

/// The dispatch switch, on the value; the default made the payload
/// variant's arm when it reads one; arms opened with their payloads.
fn rewrite_switch(
    func: &mut HighFunction,
    region: Region,
    site: &Site,
    opening: &HashMap<ArmKey, (ValueId, HashMap<ValueId, ValueId>)>,
) -> Region {
    match region {
        Region::Sequence(items) => {
            let mut out: Vec<Region> = Vec::new();
            let mut it = items.into_iter();
            while let Some(item) = it.next() {
                let ours = matches!(&item, Region::Switch { index, .. } if *index == site.selector);
                if ours && matches!(site.explicit_default, Some((_, true))) {
                    // The rest runs only when control falls out of the
                    // switch, which only the default does.
                    let rest: Vec<Region> = it.by_ref().collect();
                    let Region::Switch { index, arms, default, dispatch } = item else { unreachable!() };
                    let default = Region::Sequence(std::iter::once(*default).chain(rest).collect());
                    let moved = Region::Switch { index, arms, default: Box::new(default), dispatch };
                    out.push(rewrite_switch(func, moved, site, opening));
                    break;
                }
                out.push(rewrite_switch(func, item, site, opening));
            }
            Region::Sequence(out)
        }
        Region::Scope { out, body } => Region::Scope { out, body: Box::new(rewrite_switch(func, *body, site, opening)) },
        Region::Loop { header, body, kind } => {
            Region::Loop { header, body: Box::new(rewrite_switch(func, *body, site, opening)), kind }
        }
        Region::If { cond, then_region, else_region } => Region::If {
            cond,
            then_region: Box::new(rewrite_switch(func, *then_region, site, opening)),
            else_region: else_region.map(|e| Box::new(rewrite_switch(func, *e, site, opening))),
        },
        Region::Switch { index, arms, default, dispatch } => {
            let ours = index == site.selector;
            let mut new_arms: Vec<SwitchArm> = Vec::new();
            for (i, arm) in arms.into_iter().enumerate() {
                let body = rewrite_switch(func, arm.body, site, opening);
                let body = match opening.get(&ArmKey::Arm(i)) {
                    Some((p, map)) if ours => open_arm(func, body, &[*p], map),
                    _ => body,
                };
                new_arms.push(SwitchArm { cases: arm.cases, body });
            }
            let default = rewrite_switch(func, *default, site, opening);
            if !ours {
                return Region::Switch { index, arms: new_arms, default: Box::new(default), dispatch };
            }
            let default = match (site.explicit_default, opening.get(&ArmKey::Default)) {
                (Some((case, _)), Some((p, map))) => {
                    let body = open_arm(func, default, &[*p], map);
                    new_arms.push(SwitchArm { cases: vec![case], body });
                    new_arms.sort_by_key(|a| a.cases.first().copied());
                    Region::Unreachable
                }
                _ => default,
            };
            Region::Switch { index: site.value, arms: new_arms, default: Box::new(default), dispatch: Some(site.value) }
        }
        leaf => leaf,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{Arena, IrId, UnknownReason};
    use sordec_ir::{Binding, DispatchTable, HighBlock, MemoryImage, PanicKind, PrimitiveType, TypeRef, UnionCase};

    use crate::marshalling::test_support::v;

    const NEXT: u32 = 1;

    fn bb(i: u32) -> BlockId {
        BlockId::new(i)
    }

    fn untyped() -> IrType {
        IrType::Unknown(UnknownReason::InsufficientEvidence)
    }

    fn trap() -> Box<Region> {
        Box::new(Region::Panic { kind: PanicKind::Bare })
    }

    fn guard(cond: u32) -> Region {
        Region::If { cond: v(cond), then_region: trap(), else_region: None }
    }

    /// `enum E { A, B(<payload>) }`.
    fn types(payload: PrimitiveType) -> TypeRegistry {
        let mut reg = TypeRegistry::default();
        reg.unions.push(UnionDef {
            id: TypeId::new(0),
            name: "E".into(),
            cases: vec![
                UnionCase { name: "A".into(), fields: vec![] },
                UnionCase { name: "B".into(), fields: vec![TypeRef::Primitive(payload)] },
            ],
            exported: true,
        });
        reg
    }

    /// What `next` does through each parameter, and its gated element.
    type Summaries = (HashMap<FuncId, Vec<Option<ParamAccess>>>, HashMap<FuncId, Vec<Option<Gated>>>);

    fn summaries() -> Summaries {
        let out = ParamAccess { reads: vec![], writes: vec![(0, 8), (8, 8)], must_writes: vec![(0, 8)] };
        let state = ParamAccess { reads: vec![(0, 8), (8, 4), (12, 4)], writes: vec![(8, 4)], must_writes: vec![(8, 4)] };
        let id = FuncId::from_index(NEXT);
        let gated = Gated { width: 8, none: 2, writes: vec![(8, 8)] };
        (HashMap::from([(id, vec![Some(out), Some(state)])]), HashMap::from([(id, vec![Some(gated), None])]))
    }

    /// Departures from the plain shape, each a reason to refuse.
    struct Shape {
        /// Two `next` calls in the payload arm.
        twice: bool,
        /// The default arm also tests the position (`position == 0`).
        reads_position: bool,
        /// Something else stores into the iterator's index.
        foreign_store: bool,
        /// The payload's code checked by a select chain whose fallback is
        /// this constant (`B(U)` with `enum U { X = 1, Y = 2 }`).
        code: Option<i32>,
    }

    const PLAIN: Shape = Shape { twice: false, reads_position: false, foreign_store: false, code: None };

    struct Builder {
        b: Arena<ValueId, Binding>,
    }

    impl Builder {
        fn seed(&mut self, ty: IrType, expr: Expr) -> u32 {
            let id = self.b.len() as u32;
            self.b.push(Binding::new(v(id), ty, expr, Provenance::new("seed", ProvenanceSource::DataFlow, "seed")));
            id
        }

        fn untyped(&mut self, expr: Expr) -> u32 {
            self.seed(untyped(), expr)
        }

        fn lit32(&mut self, n: i32) -> u32 {
            self.seed(IrType::Known(KnownType::I32), Expr::Literal(Literal::I32(n)))
        }

        fn lit64(&mut self, n: i64) -> u32 {
            self.seed(IrType::Known(KnownType::I64), Expr::Literal(Literal::I64(n)))
        }

        fn load(&mut self, base: u32, offset: u32, width: MemWidth) -> u32 {
            self.untyped(Expr::Load { addr: v(base), offset, width, signed: None, ty: untyped() })
        }

        fn store(&mut self, base: u32, value: u32, offset: u32, width: MemWidth) -> u32 {
            self.untyped(Expr::Store { addr: v(base), value: v(value), offset, width })
        }

        fn bin(&mut self, op: BinaryOp, lhs: u32, rhs: u32) -> u32 {
            self.untyped(Expr::Binary { op, lhs: v(lhs), rhs: v(rhs) })
        }

        fn known(&mut self, op: KnownOp) -> u32 {
            self.untyped(Expr::Semantic(SemanticOp::Known(op)))
        }

        fn func(self, id: u32, blocks: Vec<Vec<u32>>, region: Region) -> HighFunction {
            let mut arena: Arena<BlockId, HighBlock> = Arena::new();
            for (i, ids) in blocks.into_iter().enumerate() {
                arena.push(HighBlock { id: bb(i as u32), bindings: ids.into_iter().map(v).collect() });
            }
            HighFunction {
                id: FuncId::from_index(id),
                name: None,
                signature: None,
                aliases: Vec::new(),
                blocks: arena,
                bindings: self.b,
                region,
                params: vec![v(0), v(1)],
                returns: vec![],
            }
        }
    }

    /// The entrypoint: `e: E` (v0), the frame (v1); the inline decode, then
    /// `match position { 1 => { remaining check; next; x + x }, _ => {} }`.
    fn entry(shape: &Shape) -> HighFunction {
        let mut f = Builder { b: Arena::new() };
        let e = f.seed(IrType::Known(KnownType::UserDefined(TypeId::new(0))), Expr::Phi { incoming: vec![] });
        let fp = f.seed(IrType::Known(KnownType::I32), Expr::Phi { incoming: vec![] });
        let len = f.known(KnownOp::VecOp { kind: VecOpKind::Len, args: vec![v(e)] });
        let zero = f.lit32(0);
        let s0 = f.store(fp, e, 0, MemWidth::W8);
        let s1 = f.store(fp, zero, 8, MemWidth::W4);
        let s2 = f.store(fp, len, 12, MemWidth::W4);
        let sixteen = f.lit32(16);
        let out = f.bin(BinaryOp::Add, fp, sixteen);
        let next = Expr::Call { target: FuncId::from_index(NEXT), args: vec![v(out), v(fp)] };
        let c0 = f.untyped(next.clone());
        let t0 = f.load(fp, 16, MemWidth::W8);
        let z64 = f.lit64(0);
        let t0_bad = f.bin(BinaryOp::Ne, t0, z64);
        let sym = f.load(fp, 24, MemWidth::W8);
        let pos = f.lit32(0);
        let n = f.lit32(2);
        let lookup = f.known(KnownOp::SymbolDispatch {
            sym: v(sym),
            table_pos: v(pos),
            len: v(n),
            table: DispatchTable { cases: vec!["A".into(), "B".into()], enum_name: Some("E".into()) },
        });
        let decoded = f.known(KnownOp::ValDecodeSmall { value: v(lookup) });
        let one64 = f.lit64(1);
        let bound = f.bin(BinaryOp::GtU, decoded, one64);
        let sel = f.untyped(Expr::Unary { op: UnaryOp::Wrap32, value: v(decoded) });
        // Arm `B`: one element left, then the payload.
        let idx = f.load(fp, 8, MemWidth::W4);
        let end = f.load(fp, 12, MemWidth::W4);
        let left = f.bin(BinaryOp::Sub, end, idx);
        let one32 = f.lit32(1);
        let too_many = f.bin(BinaryOp::GtU, left, one32);
        let c1 = f.untyped(next.clone());
        let t1 = f.load(fp, 16, MemWidth::W8);
        let t1_bad = f.bin(BinaryOp::Ne, t1, z64);
        let x = f.load(fp, 24, MemWidth::W8);
        let not_u32 = f.known(KnownOp::ValTagCheck { value: v(x), tag: 4, negated: true });
        let body = f.known(KnownOp::ValDecodeSmall { value: v(x) });
        let user = f.bin(BinaryOp::Add, body, body);
        let mut arm_tail = vec![body, user];
        if let Some(fallback) = shape.code {
            let word = f.untyped(Expr::Unary { op: UnaryOp::Wrap32, value: v(body) });
            let (one, two, none, k) = (f.lit32(1), f.lit32(2), f.lit32(0), f.lit32(fallback));
            let is2 = f.bin(BinaryOp::Eq, word, two);
            let s2 = f.untyped(Expr::Select { cond: v(is2), if_true: v(two), if_false: v(none) });
            let is1 = f.bin(BinaryOp::Eq, word, one);
            let s1 = f.untyped(Expr::Select { cond: v(is1), if_true: v(one), if_false: v(s2) });
            let tagged = f.known(KnownOp::ValTagCheck { value: v(x), tag: 4, negated: false });
            let code = f.untyped(Expr::Select { cond: v(tagged), if_true: v(s1), if_false: v(k) });
            let used = f.bin(BinaryOp::Add, code, code);
            arm_tail.extend([word, one, two, none, k, is2, s2, is1, s1, tagged, code, used]);
        }
        if shape.twice {
            arm_tail.push(f.untyped(next));
        }
        let mut default_block = Vec::new();
        if shape.reads_position {
            let z = f.lit64(0);
            default_block.extend([z, f.bin(BinaryOp::Eq, decoded, z)]);
        }
        if shape.foreign_store {
            let k = f.lit32(7);
            default_block.extend([k, f.store(fp, k, 8, MemWidth::W4)]);
        }
        let blocks = vec![
            vec![len, zero, s0, s1, s2, sixteen, out, c0, t0, z64, t0_bad],
            vec![sym, pos, n, lookup, decoded, one64, bound, sel],
            vec![idx, end, left, one32, too_many],
            vec![c1, t1, t1_bad],
            vec![x, not_u32],
            arm_tail,
            default_block,
        ];
        let arm = Region::Sequence(vec![
            Region::Basic(bb(2)),
            guard(too_many),
            Region::Basic(bb(3)),
            guard(t1_bad),
            Region::Basic(bb(4)),
            guard(not_u32),
            Region::Basic(bb(5)),
            Region::Return { values: vec![v(user)] },
        ]);
        let region = Region::Sequence(vec![
            Region::Basic(bb(0)),
            guard(t0_bad),
            Region::Basic(bb(1)),
            guard(bound),
            Region::Switch {
                index: v(sel),
                arms: vec![SwitchArm { cases: vec![1], body: arm }],
                default: Box::new(Region::Basic(bb(6))),
                dispatch: Some(v(lookup)),
            },
            Region::Return { values: vec![] },
        ]);
        f.func(0, blocks, region)
    }

    fn run(func: &mut HighFunction, payload: PrimitiveType) -> Result<i64, ()> {
        run_with(func, &types(payload))
    }

    fn run_with(func: &mut HighFunction, types: &TypeRegistry) -> Result<i64, ()> {
        let (access, gated) = summaries();
        let nexts = HashSet::from([FuncId::from_index(NEXT)]);
        let mut tried = HashSet::new();
        let (site, _) = plan(func, &MemoryImage::empty(), types, &nexts, &access, &gated, &mut tried);
        site.map(|s| apply(func, s)).ok_or(())
    }

    /// `enum E { A, B(U) }`, `enum U { X = 1, Y = 2 }`.
    fn unit_payload() -> TypeRegistry {
        let mut reg = types(PrimitiveType::U32);
        reg.unions[0].cases[1].fields = vec![TypeRef::UserDefined(TypeId::new(1))];
        reg.enums.push(sordec_ir::EnumDef {
            id: TypeId::new(1),
            name: "U".into(),
            cases: vec![
                sordec_ir::EnumCase { name: "X".into(), value: 1 },
                sordec_ir::EnumCase { name: "Y".into(), value: 2 },
            ],
        });
        reg
    }

    #[test]
    fn a_unit_enum_payloads_checked_code_is_its_discriminant() {
        let mut func = entry(&Shape { code: Some(0), ..PLAIN });
        assert_eq!(run_with(&mut func, &unit_payload()), Ok(1));
        let code = func.bindings.iter().find(|(_, b)| matches!(b.expr, Expr::Unary { op: UnaryOp::Wrap32, value }
            if matches!(func.bindings.get(value).map(|p| &p.expr), Some(Expr::VariantPayload { .. }))));
        assert!(code.is_some(), "the checked code is the payload as its discriminant");
    }

    #[test]
    fn a_code_chain_falling_back_to_a_declared_code_keeps_the_decode() {
        let mut func = entry(&Shape { code: Some(2), ..PLAIN });
        assert_eq!(run_with(&mut func, &unit_payload()), Err(()));
    }

    fn expr(func: &HighFunction, id: ValueId) -> &Expr {
        &func.bindings.get(id).expect("binding").expr
    }

    #[test]
    fn an_inline_decode_becomes_a_match_binding_the_payload() {
        let mut func = entry(&PLAIN);
        assert_eq!(run(&mut func, PrimitiveType::U32), Ok(1));
        let Region::Sequence(items) = &func.region else { panic!("sequence") };
        let switch = items.iter().find(|r| matches!(r, Region::Switch { .. })).expect("the switch");
        let Region::Switch { index, dispatch, arms, .. } = switch else { unreachable!() };
        assert_eq!((*index, *dispatch), (v(0), Some(v(0))));
        // The arm opens with `B`'s payload, and the decode of its `Val` is it.
        let Region::Sequence(arm) = &arms[0].body else { panic!("arm sequence") };
        let Region::Basic(first) = &arm[0] else { panic!("arm block") };
        let p = func.blocks.get(*first).expect("block").bindings[0];
        assert!(matches!(expr(&func, p), Expr::VariantPayload { variant, index: 0, .. } if variant == "B"));
        let widened = func.bindings.iter().any(|(_, b)| matches!(b.expr, Expr::Unary { op: UnaryOp::ExtendU32, value } if value == p));
        assert!(widened, "the payload's decode is the payload widened");
        // The iterator, its checks and the lookup are gone.
        let mut ifs = 0;
        func.region.for_each_node(|n| ifs += usize::from(matches!(n, Region::If { .. })));
        assert_eq!(ifs, 0, "every check of the decode is dropped");
        for id in [2, 4, 5, 6] {
            assert!(matches!(expr(&func, v(id)), Expr::Literal(Literal::Unit)), "v{id} is the decode's");
        }
    }

    #[test]
    fn a_payload_whose_val_decode_is_not_its_value_keeps_the_decode() {
        let mut func = entry(&PLAIN);
        assert_eq!(run(&mut func, PrimitiveType::I64), Err(()));
    }

    #[test]
    fn a_test_of_the_variant_outside_the_switch_keeps_the_decode() {
        let mut func = entry(&Shape { reads_position: true, ..PLAIN });
        assert_eq!(run(&mut func, PrimitiveType::U32), Err(()));
    }

    #[test]
    fn a_second_next_call_in_an_arm_keeps_the_decode() {
        let mut func = entry(&Shape { twice: true, ..PLAIN });
        assert_eq!(run(&mut func, PrimitiveType::U32), Err(()));
    }

    #[test]
    fn another_write_to_the_iterator_state_keeps_the_decode() {
        let mut func = entry(&Shape { foreign_store: true, ..PLAIN });
        assert_eq!(run(&mut func, PrimitiveType::U32), Err(()));
    }

    /// `next(out, state)` as rustc emits it; `bump` is what it adds to the
    /// index.
    fn next_helper(bump: i32) -> HighFunction {
        let mut f = Builder { b: Arena::new() };
        let out = f.seed(IrType::Known(KnownType::I32), Expr::Phi { incoming: vec![] });
        let st = f.seed(IrType::Known(KnownType::I32), Expr::Phi { incoming: vec![] });
        let none = f.lit64(2);
        let idx = f.load(st, 8, MemWidth::W4);
        let end = f.load(st, 12, MemWidth::W4);
        let done = f.bin(BinaryOp::GeU, idx, end);
        let vec = f.load(st, 0, MemWidth::W8);
        let at = f.known(KnownOp::ValEncodeSmall { ty: KnownType::U32, value: v(idx) });
        let get = f.known(KnownOp::VecOp { kind: VecOpKind::Get, args: vec![v(vec), v(at)] });
        let put = f.store(out, get, 8, MemWidth::W8);
        let k = f.lit32(bump);
        let bumped = f.bin(BinaryOp::Add, idx, k);
        let save = f.store(st, bumped, 8, MemWidth::W4);
        let some = f.lit64(0);
        let tag = f.untyped(Expr::Phi { incoming: vec![(bb(0), v(none)), (bb(1), v(some))] });
        let write = f.store(out, tag, 0, MemWidth::W8);
        let blocks = vec![vec![none, idx, end, done], vec![vec, at, get, put, k, bumped, save, some], vec![write]];
        let region = Region::Sequence(vec![
            Region::Scope {
                out: bb(2),
                body: Box::new(Region::Sequence(vec![
                    Region::Basic(bb(0)),
                    Region::If {
                        cond: v(done),
                        then_region: Box::new(Region::Break { target: bb(2), transfer: vec![(v(tag), v(none))] }),
                        else_region: Some(Box::new(Region::Sequence(vec![
                            Region::Basic(bb(1)),
                            Region::Break { target: bb(2), transfer: vec![(v(tag), v(some))] },
                        ]))),
                    },
                ])),
            },
            Region::Basic(bb(2)),
            Region::Return { values: vec![] },
        ]);
        f.func(NEXT, blocks, region)
    }

    fn classified(f: &HighFunction) -> bool {
        let ir = crate::marshalling::test_support::module(vec![f.clone()]);
        let access = param_accesses(f);
        is_next(&ir, f, Some(&access))
    }

    #[test]
    fn the_sdk_iterators_next_is_recognised() {
        assert!(classified(&next_helper(1)));
    }

    #[test]
    fn a_next_that_skips_an_element_is_not_the_iterator() {
        assert!(!classified(&next_helper(2)));
    }
}
