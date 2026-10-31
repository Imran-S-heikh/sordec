//! Take a `#[contracttype]` enum apart: the derived decode a helper writes
//! into its caller's memory, and the caller's `match` on it, become a
//! `match` on the value that binds each variant's payload.
//!
//! # The shape
//!
//! ```rust,ignore
//! pub fn add(a: UdtEnum, b: UdtEnum) -> i64 {
//!     let a = match a {
//!         UdtEnum::UdtA => 0,
//!         UdtEnum::UdtB(udt) => udt.a + udt.b,
//!         UdtEnum::UdtC(val) => val as i64,
//!         UdtEnum::UdtD(tup) => tup.0 + ..,
//!     };
//!     ..
//! }
//! ```
//!
//! The SDK's entrypoint wrapper decodes `a` with the derived `TryFromVal`,
//! which rustc outlines into a helper writing a `Result<UdtEnum, _>` into
//! memory the caller provides: a tag byte (the variant's position, or the
//! next code past the last variant for `Err`) and, per variant, its
//! payload's fields at offsets rustc chose. The caller traps on the `Err`
//! code, loads the payload words (often before the `match`, unconditionally
//! — the same bytes are padding on the variants that do not use them), and
//! switches on the tag:
//!
//! ```text
//! call decode(fp+16, a)              ; writes tag, +1, +8, +16, +24
//! t = load8_u fp+16 ; if t == 4 { trap }
//! x = load fp+32 ; y = load fp+24 ; z = load8_u fp+17
//! match t { 1 => y + x, 2 => z, 3 => .. y .. x .., _ => 0 }
//! ```
//!
//! # The rewrite
//!
//! The switch selects on `a` itself (`index` and `dispatch` both `a`, see
//! `Region::Switch::dispatch`), each arm that reads a payload word opens
//! with the variant's payload (`Expr::VariantPayload`) and the field the
//! word is, and the word's reads in that arm read the field instead. The
//! trap on the `Err` code, the call, and the loads go:
//!
//! ```text
//! match a { UdtB(p) => p.a + p.b, UdtC(q) => q as u32 as i64, UdtD(r) => .. r.0 .. r.1 .., UdtA => 0 }
//! ```
//!
//! The helper is then called by nothing and is not emitted.
//!
//! # Why it is exact
//!
//! The value handed to the helper is proven to be the enum: an entrypoint
//! parameter the spec declares with it, or a value an earlier decode typed.
//! The helper reads a symbol and looks it up in a rodata table whose names
//! are exactly the enum's variants, in declared order — the derived
//! `TryFromVal` of that enum, which the re-emitted `#[contracttype]`
//! regenerates in the entrypoint wrapper, as every marshalling elision
//! relocates its decode. On such a value the decode takes a variant's path
//! and writes, through its out-pointer, at the merge every such path
//! reaches:
//!
//! - **The tag is the variant.** Each path into the merge hands the tag
//!   store a constant `t`, and that path runs inside the dispatch's arm for
//!   case `t` (or its default arm, when `t` is the one table position no
//!   arm names: the lookup returns a position in the table or traps). That
//!   arm is taken when the symbol is the table's `t`-th name, the enum's
//!   `t`-th variant. The failing paths store the code past the last
//!   variant instead, and none of them is taken on a proven value — so the
//!   caller's test against that code is false and its trap goes.
//! - **A payload word is the field it is read as.** On variant `t`'s path
//!   a slot holds one of: the `i64` an exact `i64` decoder (two `Ok` paths:
//!   `obj_to_i64(x)` under the `I64Object` tag, the small value's body
//!   under the `I64Small` tag, tried in that order, any other tag an
//!   error) returns for an unpacked slot; an unpacked slot itself, for a
//!   field whose value is its handle (`Vec`, `Map`, `Address`, `Bytes`,
//!   `String`); or, for a unit-enum payload, a `select` chain sending each
//!   declared discriminant to itself and anything else to a code no
//!   variant has, stored as one byte. An unpacked slot is a field by the
//!   unpack's key table (a map: the struct's field names; a vector: a tuple
//!   struct of that many fields) and the unpack runs in that variant's
//!   dispatch arm, where the derived conversion unpacks nothing but the
//!   payload. Each read of an unpacked slot is the unpack's on every
//!   path (the `udt_decode` reach check). Anything else in a slot is
//!   padding, and no read of it is explained.
//! - **Each payload read is on its variant's path.** A word the caller
//!   reads is the decode's, whole, on every path (the reach check: nothing
//!   wrote its bytes since, and nothing else may read them meanwhile), and
//!   every use of it sits inside the switch's arm for exactly one case `t`,
//!   whose variant has a field at that offset and width. The switch's
//!   selector is the tag that same decode wrote, so the arm runs only on
//!   variant `t`, where the word is that field: `p.f` there has the same
//!   value. A read of a narrow code is its byte widened: zero-extended, or
//!   sign-extended when every code is below 128, both the code itself — the
//!   discriminant the source cast with `as`.
//! - **Removing the decode loses no read.** Every read the decode's bytes
//!   may reach is one of the above (the reach check refuses the site
//!   otherwise), and each is rewritten; the payload reads, the tag reads
//!   and the call go together, all or nothing. The check sees through one
//!   more kind of overwrite: a helper that leaves a tag word at the
//!   address it is handed and writes its payload unless that tag is one
//!   `none` constant — the SDK's vector iterator, handing back
//!   `Option<Result<T, _>>` — has written its payload on the side of a
//!   branch where the tag it left is not `none` (`check_gated` in
//!   `udt_decode`; the helper's summary is `gated_summary`'s).
//! - **The test on the failing code is false.** Not only where it guards
//!   a trap: the code is never the tag on a proven value, so the test is
//!   `false` wherever it is read, and a trap it guards goes.
//!
//! # Gates
//!
//! - The helper: no spec, two parameters `(out, value)`; `out` only ever
//!   a store address; one symbol lookup whose table is exactly one
//!   declared enum's variant names, in order, and one switch on its
//!   decoded result; every store through `out` either the failing code at
//!   the tag, or one per slot at one merge block, the tag's a merge of
//!   constants, one per variant, each on its variant's dispatch path; the
//!   tag stored on every path; no two slots overlapping.
//! - A payload slot: one of the three shapes above, on that variant's
//!   path; the unpack in the variant's dispatch arm; the payload a single
//!   component of a declared struct or unit enum (a field of `i64` or a
//!   handle type; a unit enum whose discriminants fit a byte).
//! - The call site: the value proven to be that enum (`udt_of`); the call
//!   not inside a loop; the reach check accepts it; the tag's every use is
//!   a test against the failing code, or the selector of a switch, not
//!   already linked to a dispatch, whose cases are all positions of the
//!   enum; every payload read's every use inside an arm of one case of
//!   such a switch whose variant has that slot, read at its width; a
//!   merge fed a payload read only from one such arm; no read claimed by
//!   two sites.

use std::collections::{BTreeMap, HashMap, HashSet};

use sordec_common::{BlockId, FuncId, Provenance, ProvenanceSource, TypeId, ValueId};
use sordec_ir::{
    BinaryOp, BufOpKind, Expr, HighBlock, HighFunction, HighIr, IrType, KnownOp, KnownType, Literal, MapOpKind,
    MemWidth, Region, SemanticOp, StructDef, TypeRef, UnaryOp, UnionDef, ValObjectKind, VecOpKind, WasmOpcodeKind,
};

use super::udt_decode::reach::{self, Gated};
use super::udt_decode::{param_accesses, read_keys, udt_of, Candidate, CertainWrite, ParamAccess, Role, Slot};
use super::{apply_elisions, Elision};
use crate::dataflow::{canon_addr, resolve_use, trace_int, trace_u32val};
use crate::metrics_catalog as mc;
use crate::pass::{Pass, PassResult};
use crate::type_infer::known_of_type_ref;
use crate::val_abi::{TAG_I64_OBJECT, TAG_I64_SMALL, TAG_U64_OBJECT, TAG_U64_SMALL};

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-enum-match";

/// Takes enum decodes apart into a `match`; see the module docs.
#[derive(Debug, Default, Clone, Copy)]
pub struct EnumMatchPass;

impl Pass<HighIr> for EnumMatchPass {
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
        let helpers: HashMap<FuncId, EnumHelper> = ir
            .functions
            .iter()
            .filter_map(|f| classify_helper(ir, f, &types).map(|h| (f.id, h)))
            .collect();
        if helpers.is_empty() {
            return result;
        }
        let access: HashMap<FuncId, Vec<Option<ParamAccess>>> =
            ir.functions.iter().map(|f| (f.id, param_accesses(f))).collect();
        let gated: HashMap<FuncId, Vec<Option<Gated>>> =
            ir.functions.iter().map(|f| (f.id, gated_summary(ir, f, access.get(&f.id)))).collect();
        for func in &mut ir.functions {
            let (sites, refused) = plan(func, &helpers, &types, &access, &gated);
            result.metrics.increment(mc::MARSHALLING_ENUM_MATCH_REFUSED, refused);
            if sites.is_empty() {
                continue;
            }
            for site in sites {
                let payloads = apply(func, site);
                result.metrics.increment(mc::MARSHALLING_ENUM_MATCH_SITES, 1);
                result.metrics.increment(mc::MARSHALLING_ENUM_MATCH_PAYLOADS, payloads);
            }
            result.changed = true;
        }
        result
    }
}

/// What one slot of a decoded enum holds on one variant's path.
#[derive(Debug, Clone, PartialEq)]
enum Part {
    /// Field `field` of payload component `index`, a struct; typed `ty`.
    Field { index: u32, field: String, ty: KnownType },
    /// Payload component `index`, a unit enum, as its discriminant in one
    /// byte; every discriminant is below `bound`.
    Code { index: u32, bound: i128 },
}

/// A helper recognised as an enum's derived decode into caller memory.
#[derive(Debug, Clone)]
struct EnumHelper {
    union: TypeId,
    /// `(offset, width)` of each slot stored on a variant's path,
    /// ascending; the tag `(0, 1)` is the first.
    slots: Vec<(u32, u32)>,
    /// The tag every failing path stores: the code past the last variant.
    niche: i128,
    /// Per declared case, what each slot holds on that variant's path.
    layout: Vec<HashMap<(u32, u32), Part>>,
}

/// Trace for the classifier and the call sites, printed when
/// `SORDEC_ENUM_TRACE` is set.
#[allow(clippy::print_stderr)]
fn trace(func: &HighFunction, why: &str) {
    if std::env::var_os("SORDEC_ENUM_TRACE").is_some() {
        eprintln!("enum-match: func_{}: {why}", sordec_common::IrId::index(func.id));
    }
}

/// The bindings the region schedules, by block, in emission order.
pub(super) fn scheduled(func: &HighFunction) -> Vec<(BlockId, ValueId)> {
    let mut out = Vec::new();
    func.region.for_each_node(|node| {
        if let Region::Basic(b) = node
            && let Some(block) = func.blocks.get(*b)
        {
            out.extend(block.bindings.iter().map(|v| (*b, *v)));
        }
    });
    out
}

/// Every block in `region`'s subtree.
pub(super) fn blocks_in(region: &Region) -> HashSet<BlockId> {
    let mut out = HashSet::new();
    region.for_each_node(|node| {
        if let Region::Basic(b) = node {
            out.insert(*b);
        }
    });
    out
}

/// A binding's expression, through renames.
pub(super) fn expr_of(func: &HighFunction, v: ValueId) -> Option<&Expr> {
    func.bindings.get(resolve_use(func, v)).map(|b| &b.expr)
}

fn classify_helper(ir: &HighIr, func: &HighFunction, types: &sordec_ir::TypeRegistry) -> Option<EnumHelper> {
    if func.signature.is_some() || func.params.len() != 2 {
        return None;
    }
    let out = func.params[0];
    // `out` is only ever stored through.
    let access = param_accesses(func).into_iter().next().flatten()?;
    if !access.reads.is_empty() {
        trace(func, "the out-pointer is read");
        return None;
    }
    let order = scheduled(func);

    // The one symbol lookup, over a table naming the variants in order.
    let mut lookups = order.iter().filter_map(|(_, v)| match &func.bindings.get(*v)?.expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::BufOp { kind: BufOpKind::SymbolIndexInLinearMemory, args }))
            if args.len() == 3 =>
        {
            Some((*v, args.clone()))
        }
        _ => None,
    });
    let (lookup, args) = lookups.next()?;
    if lookups.next().is_some() {
        trace(func, "more than one symbol lookup");
        return None;
    }
    let pos = trace_u32val(func, args[1])?;
    let len = trace_u32val(func, args[2])?;
    let names = read_keys(&ir.memory, pos, len)?;
    // The one declared enum whose variants the table names, in order. The
    // value it decodes is proven to be that enum at each call site.
    let mut named = types.unions.iter().filter(|u| u.cases.iter().map(|c| &c.name).eq(names.iter()));
    let (Some(union), None) = (named.next(), named.next()) else {
        trace(func, &format!("lookup table {names:?} names no one declared enum's variants"));
        return None;
    };
    let n = union.cases.len();
    // The lookup's position, decoded: the dispatch's selector.
    let decoded: HashSet<ValueId> = order
        .iter()
        .filter(|(_, v)| {
            matches!(expr_of(func, *v), Some(Expr::Semantic(SemanticOp::Known(KnownOp::ValDecodeSmall { value })))
                if resolve_use(func, *value) == lookup)
        })
        .map(|(_, v)| *v)
        .collect();
    let mut found: Vec<Dispatch> = Vec::new();
    find_dispatch(func, &func.region, &decoded, &mut found);
    let Ok([(arms, default)]) = <[_; 1]>::try_from(found) else {
        trace(func, "not exactly one switch on the lookup");
        return None;
    };

    // The stores through `out`: the failing code at the tag, or one per
    // slot at one merge block.
    let niche = n as i128;
    let mut merge: Option<BlockId> = None;
    let mut slots: BTreeMap<(u32, u32), ValueId> = BTreeMap::new();
    for (b, v) in &order {
        let Some(Expr::Store { addr, value, offset, width }) = func.bindings.get(*v).map(|b| &b.expr) else {
            continue;
        };
        if resolve_use(func, *addr) != out {
            continue;
        }
        if *offset == 0 && *width == MemWidth::W1 && trace_int(func, *value) == Some(niche) {
            continue;
        }
        let phi = resolve_use(func, *value);
        if !matches!(func.bindings.get(phi).map(|b| &b.expr), Some(Expr::Phi { .. })) {
            trace(func, &format!("store {v:?} through out is neither the failing code nor a merge"));
            return None;
        }
        if *merge.get_or_insert(*b) != *b || slots.insert((*offset, width.bytes()), phi).is_some() {
            trace(func, "slot stores are not one per slot at one merge");
            return None;
        }
    }
    let mut prev_end = 0_u64;
    for (o, w) in slots.keys() {
        if u64::from(*o) < prev_end {
            trace(func, "slots overlap");
            return None;
        }
        prev_end = u64::from(*o) + u64::from(*w);
    }
    let tag_phi = *slots.get(&(0, 1))?;
    if !access.must_writes.contains(&(0, 1)) {
        trace(func, "the tag is not stored on every path");
        return None;
    }

    // Each path into the merge: its variant, by the tag it stores and the
    // dispatch arm it runs in.
    let Some(Expr::Phi { incoming }) = func.bindings.get(tag_phi).map(|b| &b.expr) else { return None };
    let mut paths: HashMap<usize, BlockId> = HashMap::new();
    let covered: HashSet<u32> = arms.iter().flat_map(|(c, _)| c.iter().copied()).collect();
    for (b, x) in incoming {
        let t = trace_int(func, *x).filter(|t| (0..niche).contains(t))? as usize;
        let inside = match arms.iter().find(|(cases, _)| cases.contains(&(t as u32))) {
            Some((cases, blocks)) => cases.len() == 1 && blocks.contains(b),
            None => {
                let missing: Vec<u32> = (0..len).filter(|c| !covered.contains(c)).collect();
                missing == [t as u32] && default.contains(b)
            }
        };
        if !inside || paths.insert(t, *b).is_some() {
            trace(func, &format!("tag {t} is not stored on its variant's dispatch arm"));
            return None;
        }
    }
    let arm_blocks = |t: usize| -> HashSet<BlockId> {
        match arms.iter().find(|(cases, _)| cases.contains(&(t as u32))) {
            Some((_, blocks)) => blocks.clone(),
            None => default.clone(),
        }
    };

    // The unpacks, and which of their slots each load reads on every path.
    let unpacks = unpacks(func, &order, &ir.memory);
    let mut layout: Vec<HashMap<(u32, u32), Part>> = vec![HashMap::new(); n];
    for (t, b) in &paths {
        let fields = &union.cases[*t].fields;
        let [TypeRef::UserDefined(pid)] = fields.as_slice() else { continue };
        let here = arm_blocks(*t);
        for ((o, w), phi) in &slots {
            if (*o, *w) == (0, 1) {
                continue;
            }
            let Some(Expr::Phi { incoming }) = func.bindings.get(*phi).map(|b| &b.expr) else { continue };
            let Some((_, x)) = incoming.iter().find(|(p, _)| p == b) else { continue };
            if let Some(part) = classify_part(ir, func, types, *pid, *x, *w, &unpacks, &here) {
                layout[*t].insert((*o, *w), part);
            }
        }
    }
    trace(func, &format!("decoder for {}: slots {slots:?}, layout {layout:?}", union.name));
    Some(EnumHelper { union: union.id, slots: slots.keys().copied().collect(), niche, layout })
}

/// A dispatch switch: each arm's cases and blocks, and the blocks only its
/// default arm reaches.
type Dispatch = (Vec<(Vec<u32>, HashSet<BlockId>)>, HashSet<BlockId>);

/// What one arm reads of a decode: the variant's name, its payload's
/// declared type, and each payload load with what it is.
type ArmReads = (String, TypeId, Vec<(ValueId, Part)>);

/// Every switch whose selector is one of `decoded` (directly or as its
/// low 32 bits), as its arms' cases and blocks and the blocks only its
/// default arm reaches: its own, and — when no other arm falls through —
/// the rest of the sequence it ends, which only falling out of the switch
/// reaches.
fn find_dispatch(
    func: &HighFunction,
    region: &Region,
    decoded: &HashSet<ValueId>,
    found: &mut Vec<Dispatch>,
) {
    let selects = |index: &ValueId| {
        let mut sel = resolve_use(func, *index);
        if let Some(Expr::Unary { op: UnaryOp::Wrap32, value }) = func.bindings.get(sel).map(|b| &b.expr) {
            sel = resolve_use(func, *value);
        }
        decoded.contains(&sel)
    };
    let mut record = |r: &Region, after: &[Region]| {
        let Region::Switch { index, arms, default, .. } = r else { return };
        if !selects(index) {
            return;
        }
        let mut only_default = blocks_in(default);
        if !arms.iter().any(|a| falls_through(&a.body)) {
            for item in after {
                only_default.extend(blocks_in(item));
            }
        }
        found.push((arms.iter().map(|a| (a.cases.clone(), blocks_in(&a.body))).collect(), only_default));
    };
    match region {
        Region::Sequence(items) => {
            for (i, item) in items.iter().enumerate() {
                record(item, &items[i + 1..]);
            }
        }
        other => record(other, &[]),
    }
    match region {
        Region::Sequence(items) => items.iter().for_each(|i| match i {
            Region::Switch { arms, default, .. } => {
                arms.iter().for_each(|a| find_dispatch(func, &a.body, decoded, found));
                find_dispatch(func, default, decoded, found);
            }
            other => find_dispatch(func, other, decoded, found),
        }),
        Region::Scope { body, .. } | Region::Loop { body, .. } => find_dispatch(func, body, decoded, found),
        Region::If { then_region, else_region, .. } => {
            find_dispatch(func, then_region, decoded, found);
            if let Some(e) = else_region {
                find_dispatch(func, e, decoded, found);
            }
        }
        Region::Switch { arms, default, .. } => {
            arms.iter().for_each(|a| find_dispatch(func, &a.body, decoded, found));
            find_dispatch(func, default, decoded, found);
        }
        _ => {}
    }
}

/// Whether control may fall out of the bottom of `region`. Conservative:
/// only a region that ends every path in a branch, a return or a trap is
/// said not to.
pub(super) fn falls_through(region: &Region) -> bool {
    match region {
        Region::Break { .. } | Region::Continue { .. } | Region::Return { .. } | Region::Unreachable | Region::Panic { .. } => {
            false
        }
        // A loop is left only by a `break`, to a scope that encloses it.
        Region::Loop { .. } => false,
        Region::Sequence(items) => items.iter().all(falls_through),
        Region::If { then_region, else_region, .. } => {
            falls_through(then_region) || else_region.as_ref().is_none_or(|e| falls_through(e))
        }
        Region::Switch { arms, default, .. } => arms.iter().any(|a| falls_through(&a.body)) || falls_through(default),
        Region::Scope { out, body } => {
            let mut broke = false;
            body.for_each_node(|n| broke |= matches!(n, Region::Break { target, .. } if target == out));
            broke || falls_through(body)
        }
        Region::Basic(_) | Region::Transfer { .. } | Region::Unstructured { .. } => true,
    }
}

/// A host unpack into the frame: its block, its keys (a map's) or its
/// length (a vector's), and the slot each load of it reads.
struct Unpack {
    block: BlockId,
    keys: Option<Vec<String>>,
    len: u32,
    reads: HashMap<ValueId, usize>,
}

fn unpacks(func: &HighFunction, order: &[(BlockId, ValueId)], memory: &sordec_ir::MemoryImage) -> Vec<Unpack> {
    let mut found = Vec::new();
    for (b, v) in order {
        let Some(binding) = func.bindings.get(*v) else { continue };
        let (vals, keys, len) = match &binding.expr {
            Expr::Semantic(SemanticOp::Known(KnownOp::MapOp { kind: MapOpKind::UnpackToLinearMemory, args })) => {
                let [_, keys, vals, len] = args.as_slice() else { continue };
                let (Some(pos), Some(len)) = (trace_u32val(func, *keys), trace_u32val(func, *len)) else { continue };
                let Some(keys) = read_keys(memory, pos, len) else { continue };
                (*vals, Some(keys), len)
            }
            Expr::Semantic(SemanticOp::Known(KnownOp::VecOp { kind: VecOpKind::UnpackToLinearMemory, args })) => {
                let [_, vals, len] = args.as_slice() else { continue };
                let Some(len) = trace_u32val(func, *len) else { continue };
                (*vals, None, len)
            }
            _ => continue,
        };
        found.push((*b, *v, super::udt_decode::raw_address(func, vals), keys, len));
    }
    let dummy = StructDef { id: TypeId::new(0), name: String::new(), fields: Vec::new() };
    let cands: Vec<Candidate<'_>> = found
        .iter()
        .map(|(_, v, vals, _, len)| {
            let (base, start) = canon_addr(func, *vals);
            Candidate {
                base,
                start,
                producer: *v,
                map: *v,
                def: &dummy,
                slots: (0..*len).map(|i| Slot { rel: 8 * i, width: 8, role: Role::Disc }).collect(),
                vals: false,
                payload: false,
            }
        })
        .collect();
    let certain: Vec<CertainWrite> = cands.iter().map(|c| (c.producer, c.base, c.certain_writes())).collect();
    let none = HashMap::new();
    found
        .iter()
        .zip(&cands)
        .filter_map(|((b, _, _, keys, len), cand)| {
            let reads = reach::check(func, cand, &certain, &none).ok()?;
            Some(Unpack { block: *b, keys: keys.clone(), len: *len, reads: reads.fields.into_iter().collect() })
        })
        .collect()
}

/// What a slot written from `x` holds on a variant whose payload is the
/// declared type `payload`, when it is one of the shapes in the module
/// docs.
#[allow(clippy::too_many_arguments)]
fn classify_part(
    ir: &HighIr,
    func: &HighFunction,
    types: &sordec_ir::TypeRegistry,
    payload: TypeId,
    x: ValueId,
    width: u32,
    unpacks: &[Unpack],
    here: &HashSet<BlockId>,
) -> Option<Part> {
    if let Some(def) = types.structs.iter().find(|s| s.id == payload) {
        if width != 8 {
            return None;
        }
        // The field an unpacked slot `load` is, when the unpack ran in this
        // arm and its table names this struct.
        let field_of = |load: ValueId| -> Option<(String, KnownType)> {
            let Some(Expr::Load { width: MemWidth::W8, .. }) = func.bindings.get(load).map(|b| &b.expr) else {
                return None;
            };
            let u = unpacks.iter().find(|u| u.reads.contains_key(&load) && here.contains(&u.block))?;
            let i = u.reads[&load];
            let name = match &u.keys {
                Some(keys) => {
                    let mut a: Vec<&String> = keys.iter().collect();
                    let mut b: Vec<&String> = def.fields.iter().map(|f| &f.name).collect();
                    a.sort();
                    b.sort();
                    (a == b).then(|| keys.get(i).cloned())??
                }
                None => {
                    let tuple = def.fields.len() == u.len as usize
                        && def.fields.iter().enumerate().all(|(k, f)| f.name == k.to_string());
                    tuple.then(|| i.to_string())?
                }
            };
            let ty = known_of_type_ref(&def.fields.iter().find(|f| f.name == name)?.ty)?;
            Some((name, ty))
        };
        let x = resolve_use(func, x);
        return match func.bindings.get(x).map(|b| &b.expr)? {
            // The `i64` an exact decoder returns for the slot.
            Expr::Project { value, index: 1 } => {
                let Expr::Call { target, args } = expr_of(func, *value)? else { return None };
                let [arg] = args.as_slice() else { return None };
                let decoder = ir.function(*target)?;
                if !is_i64_decoder(decoder) {
                    return None;
                }
                let (field, ty) = field_of(resolve_use(func, *arg))?;
                (ty == KnownType::I64).then_some(Part::Field { index: 0, field, ty })
            }
            // A handle-typed field's slot, as it is.
            Expr::Load { .. } => {
                let (field, ty) = field_of(x)?;
                let handle = matches!(
                    ty,
                    KnownType::Vec(_) | KnownType::Map(..) | KnownType::Address | KnownType::Bytes | KnownType::String
                );
                handle.then_some(Part::Field { index: 0, field, ty })
            }
            _ => None,
        };
    }
    if let Some(def) = types.enums.iter().find(|e| e.id == payload) {
        if width != 1 {
            return None;
        }
        let values: HashSet<i128> = def.cases.iter().map(|c| i128::from(c.value)).collect();
        if values.iter().any(|v| !(0..256).contains(v)) {
            return None;
        }
        let codes = code_chain(func, x)?;
        return (codes == values).then(|| Part::Code { index: 0, bound: values.iter().max().copied().unwrap_or(0) + 1 });
    }
    None
}

/// The discriminants a `select` chain sends to themselves — `c1` when
/// `w == c1`, else `c2` when `w == c2`, .., else a constant that is none of
/// them — over one code `w`, the `u32` body of a small value.
fn code_chain(func: &HighFunction, x: ValueId) -> Option<HashSet<i128>> {
    code_chain_parts(func, x).map(|(codes, _)| codes)
}

/// [`code_chain`], with the chain's own bindings (its selects, their
/// tests, and the code `w`).
pub(super) fn code_chain_parts(func: &HighFunction, x: ValueId) -> Option<(HashSet<i128>, Vec<ValueId>)> {
    let mut parts: Vec<ValueId> = Vec::new();
    let mut codes = HashSet::new();
    let mut word: Option<ValueId> = None;
    let mut at = resolve_use(func, x);
    for _ in 0..64 {
        let (if_true, if_false, cond) = match func.bindings.get(at).map(|b| &b.expr)? {
            Expr::Select { cond, if_true, if_false } => (*if_true, *if_false, *cond),
            Expr::Unknown { op_kind: WasmOpcodeKind::Select, args, .. } if args.len() == 3 => (args[0], args[1], args[2]),
            _ => {
                let rest = trace_int(func, at)?;
                if codes.contains(&rest) {
                    return None;
                }
                // The code `w` last; the caller checks what it is.
                parts.extend(word);
                return Some((codes, parts));
            }
        };
        let c = trace_int(func, if_true)?;
        parts.push(at);
        parts.push(resolve_use(func, cond));
        let Some(Expr::Binary { op: BinaryOp::Eq, lhs, rhs }) = expr_of(func, cond) else { return None };
        let w = match (trace_int(func, *lhs), trace_int(func, *rhs)) {
            (None, Some(k)) if k == c => resolve_use(func, *lhs),
            (Some(k), None) if k == c => resolve_use(func, *rhs),
            _ => return None,
        };
        if *word.get_or_insert(w) != w || !codes.insert(c) {
            return None;
        }
        at = resolve_use(func, if_false);
    }
    let w = word?;
    // The code is a small value's 32-bit body.
    let Some(Expr::Unary { op: UnaryOp::Wrap32, value }) = func.bindings.get(w).map(|b| &b.expr) else { return None };
    parts.push(w);
    matches!(expr_of(func, *value), Some(Expr::Semantic(SemanticOp::Known(KnownOp::ValDecodeSmall { .. }))))
        .then_some((codes, parts))
}

/// The derived `i64` decoder: `(x) -> (tag, value)` that returns
/// `(0, obj_to_i64(x))` when `x` has the `I64Object` tag, else `(0, body)`
/// when it has the `I64Small` tag, else a non-zero tag. Checked as the
/// straight sequence rustc emits: pure blocks, each `if` on one tag test
/// with no `else` and a `then` that returns its `Ok`, then the error
/// return.
fn is_i64_decoder(g: &HighFunction) -> bool {
    two_form_decoder(g) == Some(KnownType::I64)
}

/// The derived decoder of a 64-bit scalar with two encodings, `i64` or
/// `u64` — `TryFromVal<Env, Val>` from `soroban-env-common`, outlined as
/// `(x) -> (tag, value)`: `(0, obj_to_*(x))` under the type's object tag,
/// `(0, body)` under its small tag, any other tag a non-zero `Err` tag.
/// The type it decodes, or `None` for anything else. Checked as
/// [`is_i64_decoder`] describes.
pub(super) fn two_form_decoder(g: &HighFunction) -> Option<KnownType> {
    for (ty, object, small, extract) in [
        (KnownType::I64, TAG_I64_OBJECT, TAG_I64_SMALL, ValObjectKind::ObjToI64),
        (KnownType::U64, TAG_U64_OBJECT, TAG_U64_SMALL, ValObjectKind::ObjToU64),
    ] {
        if decodes_two_forms(g, object, small, extract) {
            return Some(ty);
        }
    }
    None
}

fn decodes_two_forms(g: &HighFunction, object: u8, small: u8, extract: ValObjectKind) -> bool {
    if g.signature.is_some() || g.params.len() != 1 {
        return false;
    }
    let x = g.params[0];
    let Region::Sequence(items) = &g.region else { return false };
    // A block on the way to a tag test may not trap or write; one on the
    // way to a return under a passed test may not write (the conversion
    // it makes is the value returned).
    let quiet_block = |b: &BlockId, may_trap: bool| {
        g.blocks.get(*b).is_some_and(|blk| {
            blk.bindings.iter().all(|v| {
                g.bindings.get(*v).is_some_and(|bd| {
                    let e = crate::effects::expr_effects(&bd.expr);
                    !e.writes_memory && (may_trap || !e.may_trap)
                })
            })
        })
    };
    let pure_block = |b: &BlockId| quiet_block(b, false);
    let ok_return = |r: &Region, tag: u8| -> bool {
        let leaves: Vec<&Region> = match r {
            Region::Sequence(items) => items.iter().collect(),
            other => vec![other],
        };
        let Some((Region::Return { values }, before)) = leaves.split_last() else { return false };
        if !before.iter().all(|l| matches!(l, Region::Basic(b) if quiet_block(b, true))) {
            return false;
        }
        let [t, v] = values.as_slice() else { return false };
        if trace_int(g, *t) != Some(0) {
            return false;
        }
        match expr_of(g, *v) {
            Some(Expr::Semantic(SemanticOp::Known(KnownOp::ValObject { kind, args }))) if *kind == extract => {
                tag == object && args.len() == 1 && resolve_use(g, args[0]) == x
            }
            Some(Expr::Semantic(SemanticOp::Known(KnownOp::ValDecodeSmall { value }))) => {
                tag == small && resolve_use(g, *value) == x
            }
            _ => false,
        }
    };
    let mut handled: Vec<u8> = Vec::new();
    let Some((last, body)) = items.split_last() else { return false };
    for item in body {
        match item {
            Region::Basic(b) if pure_block(b) => {}
            Region::If { cond, then_region, else_region: None } => {
                let Some(Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck { value, tag, negated: false }))) =
                    expr_of(g, *cond)
                else {
                    return false;
                };
                if resolve_use(g, *value) != x || !ok_return(then_region, *tag) {
                    return false;
                }
                handled.push(*tag);
            }
            _ => return false,
        }
    }
    let Region::Return { values } = last else { return false };
    let failing = values.first().and_then(|t| trace_int(g, *t)).is_some_and(|t| t != 0);
    // Source order tests the small form first; rustc may test the object
    // form first. Either order is the same conversion.
    failing && handled.len() == 2 && handled.contains(&object) && handled.contains(&small)
}

/// The constants a value may be: a constant, or a component of a call
/// whose every return hands a constant there.
fn constants(ir: &HighIr, func: &HighFunction, v: ValueId) -> Option<HashSet<i128>> {
    if let Some(n) = trace_int(func, v) {
        return Some(HashSet::from([n]));
    }
    let Some(Expr::Project { value, index }) = expr_of(func, v) else { return None };
    let Some(Expr::Call { target, .. }) = expr_of(func, *value) else { return None };
    let callee = ir.function(*target)?;
    let mut out = HashSet::new();
    let mut ok = true;
    callee.region.for_each_node(|node| {
        if let Region::Return { values } = node {
            match values.get(*index as usize).and_then(|r| trace_int(callee, *r)) {
                Some(n) => {
                    out.insert(n);
                }
                None => ok = false,
            }
        }
    });
    (ok && !out.is_empty()).then_some(out)
}

/// For each pointer parameter of `func`, what it writes there gated by the
/// tag it leaves at offset 0 ([`Gated`]).
///
/// The tag is stored once, from a merge at the block the function returns
/// from, which stores nothing else through the pointer. Every path into
/// that block arrives by an edge of the merge, so the tag the function
/// leaves is the value its edge hands over: one edge hands a constant
/// `none`, and every other edge a value that cannot be `none` (a constant,
/// or a callee's component every return of which is a constant), from a
/// block that itself stores the gated writes. A path that leaves a tag
/// other than `none` therefore came through one of those blocks, and
/// nothing between it and the return writes over what it stored.
pub(super) fn gated_summary(ir: &HighIr, func: &HighFunction, access: Option<&Vec<Option<ParamAccess>>>) -> Vec<Option<Gated>> {
    let Some(access) = access else { return Vec::new() };
    let mut out = vec![None; func.params.len()];
    // The block the function returns from, at the top level.
    let Region::Sequence(items) = &func.region else { return out };
    let [.., Region::Basic(last), Region::Return { .. }] = items.as_slice() else { return out };
    let Some(last_block) = func.blocks.get(*last) else { return out };
    for (k, p) in func.params.iter().enumerate() {
        let Some(Some(acc)) = access.get(k) else { continue };
        let through = |v: &ValueId| -> Option<(u32, MemWidth, ValueId)> {
            match &func.bindings.get(*v)?.expr {
                Expr::Store { addr, value, offset, width } if resolve_use(func, *addr) == *p => {
                    Some((*offset, *width, *value))
                }
                _ => None,
            }
        };
        let stores: Vec<(u32, MemWidth, ValueId)> = last_block.bindings.iter().filter_map(through).collect();
        let [(0, width, tag)] = stores.as_slice() else { continue };
        if !acc.must_writes.contains(&(0, width.bytes())) {
            continue;
        }
        let Some(Expr::Phi { incoming }) = expr_of(func, *tag) else { continue };
        let sets: Option<Vec<(BlockId, HashSet<i128>)>> =
            incoming.iter().map(|(b, x)| Some((*b, constants(ir, func, *x)?))).collect();
        let Some(sets) = sets else { continue };
        let nones: Vec<i128> =
            sets.iter().filter(|(_, s)| s.len() == 1).filter_map(|(_, s)| s.iter().next().copied()).collect();
        for none in nones {
            let others: Vec<&BlockId> = sets.iter().filter(|(_, s)| *s != HashSet::from([none])).map(|(b, _)| b).collect();
            if others.is_empty() || sets.iter().any(|(_, s)| s.len() > 1 && s.contains(&none)) {
                continue;
            }
            let mut writes: Option<HashSet<(u32, u32)>> = None;
            for b in others {
                let here: HashSet<(u32, u32)> = func
                    .blocks
                    .get(*b)
                    .map(|blk| blk.bindings.iter().filter_map(through).map(|(o, w, _)| (o, w.bytes())).collect())
                    .unwrap_or_default();
                writes = Some(match writes {
                    None => here,
                    Some(w) => w.intersection(&here).copied().collect(),
                });
            }
            let mut writes: Vec<(u32, u32)> = writes.unwrap_or_default().into_iter().filter(|(o, _)| *o != 0).collect();
            if writes.is_empty() {
                continue;
            }
            writes.sort_unstable();
            out[k] = Some(Gated { width: width.bytes(), none, writes });
            break;
        }
    }
    out
}

/// One call site taken apart.
struct Site {
    producer: ValueId,
    value: ValueId,
    union: TypeId,
    /// Switch numbers (pre-order among the function's switches) selecting
    /// on the tag.
    switches: HashSet<usize>,
    /// Tag loads, and the failing-code tests on them guarding a trap.
    tags: Vec<ValueId>,
    tests: Vec<ValueId>,
    /// Per `(switch, arm)`: the variant's name, payload type of component
    /// 0, and each payload load read there with what it is.
    arms: BTreeMap<(usize, usize), ArmReads>,
    loads: Vec<ValueId>,
    /// Merge inputs fed a payload load: `(merge, load, switch, arm)`.
    merges: Vec<(ValueId, ValueId, usize, usize)>,
}

/// Where a use sits: the enclosing `(switch, arm)` pairs, outermost first;
/// the arm is `None` for the default.
type Ctx = Vec<(usize, Option<usize>)>;

/// Every use in the region tree and its blocks, with its context; the
/// switches by number; the transfers, as `(merge, source, ctx)`.
struct Uses {
    /// `(used value, user binding or None for the region, ctx)`.
    uses: Vec<(ValueId, Option<ValueId>, Ctx)>,
    switches: Vec<(ValueId, Vec<Vec<u32>>, Option<ValueId>)>,
    transfers: Vec<(ValueId, ValueId, Ctx)>,
    /// Switch selectors, as `(selector, switch)`: not in `uses`.
    selectors: Vec<(ValueId, usize)>,
    in_loop: HashSet<BlockId>,
}

fn collect_uses(func: &HighFunction) -> Uses {
    fn walk(func: &HighFunction, r: &Region, ctx: &mut Ctx, looped: bool, u: &mut Uses) {
        match r {
            Region::Basic(b) => {
                if looped {
                    u.in_loop.insert(*b);
                }
                if let Some(block) = func.blocks.get(*b) {
                    for &v in &block.bindings {
                        if let Some(binding) = func.bindings.get(v) {
                            binding.expr.for_each_value_use(|x| u.uses.push((x, Some(v), ctx.clone())));
                        }
                    }
                }
            }
            Region::Sequence(items) => items.iter().for_each(|i| walk(func, i, ctx, looped, u)),
            Region::Scope { body, .. } => walk(func, body, ctx, looped, u),
            Region::Loop { body, .. } => walk(func, body, ctx, true, u),
            Region::If { cond, then_region, else_region } => {
                u.uses.push((*cond, None, ctx.clone()));
                walk(func, then_region, ctx, looped, u);
                if let Some(e) = else_region {
                    walk(func, e, ctx, looped, u);
                }
            }
            Region::Switch { index, arms, default, dispatch } => {
                let no = u.switches.len();
                u.selectors.push((*index, no));
                if let Some(d) = dispatch {
                    u.uses.push((*d, None, ctx.clone()));
                }
                u.switches.push((*index, arms.iter().map(|a| a.cases.clone()).collect(), *dispatch));
                for (i, arm) in arms.iter().enumerate() {
                    ctx.push((no, Some(i)));
                    walk(func, &arm.body, ctx, looped, u);
                    ctx.pop();
                }
                ctx.push((no, None));
                walk(func, default, ctx, looped, u);
                ctx.pop();
            }
            Region::Break { transfer, .. } | Region::Continue { transfer, .. } | Region::Transfer { transfer, .. } => {
                for (phi, src) in transfer {
                    u.uses.push((*src, None, ctx.clone()));
                    u.transfers.push((*phi, *src, ctx.clone()));
                }
            }
            Region::Return { values } => values.iter().for_each(|v| u.uses.push((*v, None, ctx.clone()))),
            Region::Unreachable | Region::Panic { .. } | Region::Unstructured { .. } => {}
        }
    }
    let mut u = Uses {
        uses: Vec::new(),
        switches: Vec::new(),
        transfers: Vec::new(),
        selectors: Vec::new(),
        in_loop: HashSet::new(),
    };
    walk(func, &func.region, &mut Vec::new(), false, &mut u);
    u
}

fn plan(
    func: &HighFunction,
    helpers: &HashMap<FuncId, EnumHelper>,
    types: &sordec_ir::TypeRegistry,
    access: &HashMap<FuncId, Vec<Option<ParamAccess>>>,
    gated: &HashMap<FuncId, Vec<Option<Gated>>>,
) -> (Vec<Site>, i64) {
    let order = scheduled(func);
    let calls: Vec<(BlockId, ValueId, &EnumHelper, ValueId, ValueId)> = order
        .iter()
        .filter_map(|(b, v)| match &func.bindings.get(*v)?.expr {
            Expr::Call { target, args } if args.len() == 2 => {
                let h = helpers.get(target)?;
                Some((*b, *v, h, args[0], resolve_use(func, args[1])))
            }
            _ => None,
        })
        .collect();
    if calls.is_empty() {
        return (Vec::new(), 0);
    }
    let uses = collect_uses(func);
    let dummy = StructDef { id: TypeId::new(0), name: String::new(), fields: Vec::new() };
    let cands: Vec<Candidate<'_>> = calls
        .iter()
        .map(|(_, v, h, out, _)| {
            let (base, start) = canon_addr(func, *out);
            Candidate {
                base,
                start,
                producer: *v,
                map: *v,
                def: &dummy,
                slots: h.slots.iter().map(|(o, w)| Slot { rel: *o, width: *w, role: Role::Disc }).collect(),
                vals: false,
                payload: false,
            }
        })
        .collect();
    // On a proven value every decode takes a variant's path and writes
    // every slot.
    let certain: Vec<CertainWrite> = cands.iter().map(|c| (c.producer, c.base, c.certain_writes())).collect();
    let mut sites = Vec::new();
    let mut refused = 0;
    for ((b, v, h, _, value), cand) in calls.iter().zip(&cands) {
        match site(func, types, &uses, *b, *v, h, *value, cand, &certain, access, gated) {
            Ok(s) => sites.push(s),
            Err(why) => {
                refused += 1;
                trace(func, &format!("decode {v:?} refused: {why}"));
            }
        }
    }
    // A load two sites both claim is explained by neither.
    let mut seen: HashSet<ValueId> = HashSet::new();
    let mut twice: HashSet<ValueId> = HashSet::new();
    for s in &sites {
        for l in s.loads.iter().chain(&s.tags).chain(&s.tests) {
            if !seen.insert(*l) {
                twice.insert(*l);
            }
        }
    }
    let before = sites.len();
    sites.retain(|s| !s.loads.iter().chain(&s.tags).chain(&s.tests).any(|l| twice.contains(l)));
    refused += (before - sites.len()) as i64;
    (sites, refused)
}

#[allow(clippy::too_many_arguments)]
fn site(
    func: &HighFunction,
    types: &sordec_ir::TypeRegistry,
    uses: &Uses,
    block: BlockId,
    producer: ValueId,
    h: &EnumHelper,
    value: ValueId,
    cand: &Candidate<'_>,
    certain: &[CertainWrite],
    access: &HashMap<FuncId, Vec<Option<ParamAccess>>>,
    gated: &HashMap<FuncId, Vec<Option<Gated>>>,
) -> Result<Site, String> {
    if udt_of(func, value) != Some(h.union) {
        return Err("the value is not proven to be the enum".into());
    }
    if uses.in_loop.contains(&block) {
        return Err("the decode runs in a loop".into());
    }
    let union: &UnionDef = types.unions.iter().find(|u| u.id == h.union).ok_or("enum missing")?;
    let reads = reach::check_gated(func, cand, certain, access, gated)?;
    if !reads.tags.is_empty() {
        return Err("a tag-byte read".into());
    }
    let mut tags = Vec::new();
    let mut loads: Vec<(ValueId, (u32, u32))> = Vec::new();
    for (load, i) in &reads.fields {
        let slot = h.slots[*i];
        if slot == (0, 1) {
            tags.push(*load);
        } else {
            loads.push((*load, slot));
        }
    }
    if tags.is_empty() {
        return Err("no read of the tag".into());
    }
    let tag_set: HashSet<ValueId> = tags.iter().copied().collect();
    // Every use of a tag: a failing-code test guarding a trap, or the
    // selector of a switch over the enum's positions.
    let mut switches: HashSet<usize> = HashSet::new();
    let mut tests: Vec<ValueId> = Vec::new();
    let n = union.cases.len() as u32;
    for (used, user, _) in &uses.uses {
        if !tag_set.contains(used) {
            continue;
        }
        match user {
            Some(t) => {
                let ok = matches!(func.bindings.get(*t).map(|b| &b.expr), Some(Expr::Binary { op: BinaryOp::Eq, lhs, rhs })
                    if (tag_set.contains(&resolve_use(func, *lhs)) && trace_int(func, *rhs) == Some(h.niche))
                        || (tag_set.contains(&resolve_use(func, *rhs)) && trace_int(func, *lhs) == Some(h.niche)));
                if !ok {
                    return Err(format!("tag read used by {t:?}"));
                }
                tests.push(*t);
            }
            None => return Err("the tag is read by the region other than as a switch selector".into()),
        }
    }
    for (sel, no) in &uses.selectors {
        if !tag_set.contains(sel) {
            continue;
        }
        let (_, arms, dispatch) = &uses.switches[*no];
        if dispatch.is_some() || !arms.iter().flatten().all(|c| *c < n) {
            return Err("a switch on the tag over codes that are not variants".into());
        }
        switches.insert(*no);
    }
    if switches.is_empty() {
        return Err("no switch on the tag".into());
    }
    // Every use of a payload load: inside one single-case arm of such a
    // switch whose variant has the slot.
    let mut arms: BTreeMap<(usize, usize), ArmReads> = BTreeMap::new();
    let load_set: HashMap<ValueId, (u32, u32)> = loads.iter().copied().collect();
    if uses.selectors.iter().any(|(sel, _)| load_set.contains_key(sel)) {
        return Err("a payload read selects a switch".into());
    }
    let arm_of = |ctx: &Ctx| -> Option<(usize, usize)> {
        ctx.iter().rev().find(|(s, _)| switches.contains(s)).and_then(|(s, a)| Some((*s, (*a)?)))
    };
    for (used, user, ctx) in &uses.uses {
        let Some(slot) = load_set.get(used) else { continue };
        if user.is_some_and(|u| tag_set.contains(&u) || load_set.contains_key(&u)) {
            return Err("a decode read feeds another".into());
        }
        let (s, a) = arm_of(ctx).ok_or_else(|| format!("{used:?} is used outside the variant arms"))?;
        let [case] = uses.switches[s].1[a].as_slice() else {
            return Err(format!("{used:?} is used in an arm of several variants"));
        };
        let part = h.layout.get(*case as usize).and_then(|l| l.get(slot)).ok_or_else(|| {
            format!("{used:?} reads +{} on variant {case}'s path, where that is not its payload", slot.0)
        })?;
        check_width(func, *used, part)?;
        let variant = &union.cases[*case as usize];
        let [TypeRef::UserDefined(pid)] = variant.fields.as_slice() else {
            return Err("payload of several components".into());
        };
        let entry = arms.entry((s, a)).or_insert_with(|| (variant.name.clone(), *pid, Vec::new()));
        if !entry.2.iter().any(|(l, _)| l == used) {
            entry.2.push((*used, part.clone()));
        }
    }
    // A merge fed a payload load: only from one arm.
    let mut merges = Vec::new();
    for (phi_id, phi) in func.bindings.iter() {
        let Expr::Phi { incoming } = &phi.expr else { continue };
        for (_, x) in incoming {
            if !load_set.contains_key(x) {
                continue;
            }
            let from: HashSet<(usize, usize)> = uses
                .transfers
                .iter()
                .filter(|(p, src, _)| *p == phi_id && src == x)
                .map(|(_, _, ctx)| arm_of(ctx).ok_or("a merge input outside the arms"))
                .collect::<Result<_, _>>()?;
            let [(s, a)] = from.into_iter().collect::<Vec<_>>()[..] else {
                return Err("a merge is fed a payload read from several places".into());
            };
            if !merges.iter().any(|(p, l, _, _): &(ValueId, ValueId, usize, usize)| *p == phi_id && l == x) {
                merges.push((phi_id, *x, s, a));
            }
        }
    }
    Ok(Site {
        producer,
        value,
        union: h.union,
        switches,
        tags,
        tests,
        arms,
        loads: loads.iter().map(|(l, _)| *l).collect(),
        merges,
    })
}

/// A payload read's width and widening give the slot's value: a whole
/// word for a field; for a code, its byte widened either way when every
/// code is below 128, zero-extended otherwise, into an integer the
/// rewrite can spell.
fn check_width(func: &HighFunction, load: ValueId, part: &Part) -> Result<(), String> {
    let Some(b) = func.bindings.get(load) else { return Err("missing load".into()) };
    let Expr::Load { width, signed, ty, .. } = &b.expr else { return Err("not a load".into()) };
    let ok = match part {
        Part::Field { .. } => *width == MemWidth::W8 && signed.is_none(),
        Part::Code { bound, .. } => {
            // The machine word the opcode reads the byte into.
            let word = machine_word(ty).is_some();
            *width == MemWidth::W1 && word && (*signed == Some(false) || (*signed == Some(true) && *bound <= 128))
        }
    };
    if ok { Ok(()) } else { Err(format!("{load:?} reads its slot at the wrong width")) }
}

/// The integer word a load's opcode produces, `i32` or `i64`.
fn machine_word(ty: &IrType) -> Option<KnownType> {
    match ty {
        IrType::Known(k @ (KnownType::I64 | KnownType::I32)) | IrType::Inferred(k @ (KnownType::I64 | KnownType::I32)) => {
            Some(k.clone())
        }
        _ => None,
    }
}

/// Rewrite one site; returns the payload bindings made.
fn apply(func: &mut HighFunction, site: Site) -> i64 {
    let prov = |note: String| Provenance::new(PASS_NAME, ProvenanceSource::SdkPattern, note);
    let mut made = 0;
    // Per arm: the payload, then each read's field or code.
    let mut openings: HashMap<(usize, usize), Vec<ValueId>> = HashMap::new();
    let mut replace: HashMap<(usize, usize), HashMap<ValueId, ValueId>> = HashMap::new();
    for ((s, a), (variant, pid, reads)) in &site.arms {
        let payload = ValueId::new(func.bindings.len() as u32);
        func.bindings.push(sordec_ir::Binding::new(
            payload,
            IrType::Known(KnownType::UserDefined(*pid)),
            Expr::VariantPayload { value: site.value, variant: variant.clone(), index: 0 },
            prov(format!("the payload of `{variant}`, bound by its arm of the match on the decoded enum")),
        ));
        made += 1;
        let mut opening = vec![payload];
        let mut map = HashMap::new();
        for (load, part) in reads {
            let word = match func.bindings.get(*load).map(|b| &b.expr) {
                Some(Expr::Load { ty, .. }) => machine_word(ty),
                _ => None,
            };
            let (expr, ty, note) = match part {
                Part::Field { field, ty, .. } => (
                    Expr::Field { base: payload, field: field.clone() },
                    IrType::Known(ty.clone()),
                    format!("`{variant}`'s payload field `{field}`: the decode wrote it to the slot this arm read"),
                ),
                Part::Code { .. } => {
                    // `p as u32 as i64`, or `p as i32`: the discriminant in
                    // the word the read widened its byte into.
                    let (op, k) = match word {
                        Some(KnownType::I32) => (UnaryOp::Wrap32, KnownType::I32),
                        _ => (UnaryOp::ExtendU32, KnownType::I64),
                    };
                    (
                        Expr::Unary { op, value: payload },
                        IrType::Inferred(k),
                        format!("`{variant}`'s payload discriminant: the decode wrote its code to the byte this arm read"),
                    )
                }
            };
            let id = ValueId::new(func.bindings.len() as u32);
            func.bindings.push(sordec_ir::Binding::new(id, ty, expr, prov(note)));
            opening.push(id);
            map.insert(*load, id);
        }
        openings.insert((*s, *a), opening);
        replace.insert((*s, *a), map);
    }
    // The region: switches select on the value; arms open with their
    // payload and read it.
    let mut no = 0;
    let region = std::mem::replace(&mut func.region, Region::Unreachable);
    func.region = rewrite_region(func, region, &site, &openings, &replace, &mut no);
    // Merges fed a payload read take the arm's value.
    for (phi, load, s, a) in &site.merges {
        let Some(to) = replace.get(&(*s, *a)).and_then(|m| m.get(load)).copied() else { continue };
        if let Some(b) = func.bindings.get_mut(*phi)
            && let Expr::Phi { incoming } = &mut b.expr
        {
            for (_, x) in incoming.iter_mut() {
                if x == load {
                    *x = to;
                }
            }
        }
    }
    // The trap on the failing code.
    let guards: HashMap<ValueId, String> =
        site.tests.iter().map(|t| (*t, "the enum decode's failing-code test: regenerated by `TryFromVal`".to_string())).collect();
    if !guards.is_empty() {
        let empty = super::guard::empty_blocks(func);
        let region = std::mem::replace(&mut func.region, Region::Unreachable);
        let mut stripped = 0_i64;
        func.region = super::guard::strip(region, &guards, &empty, &mut stripped);
    }
    let mut elisions = Vec::new();
    for t in &site.tests {
        elisions.push(Elision {
            id: *t,
            expr: Expr::Literal(Literal::Bool(false)),
            ty: Some(IrType::Known(KnownType::Bool)),
            note: "the enum decode's failing-code test is false: the value was proven at its boundary".into(),
            metric: mc::MARSHALLING_ENUM_MATCH_SITES,
        });
    }
    for v in site.tags.iter().chain(&site.loads).chain(std::iter::once(&site.producer)) {
        elisions.push(Elision {
            id: *v,
            expr: Expr::Literal(Literal::Unit),
            ty: Some(IrType::Known(KnownType::Unit)),
            note: "the enum decode, elided: its tag is the match's variant and its payload reads the arms' payloads"
                .into(),
            metric: mc::MARSHALLING_ENUM_MATCH_SITES,
        });
    }
    apply_elisions(func, PASS_NAME, elisions);
    let _ = site.union;
    made
}

fn rewrite_region(
    func: &mut HighFunction,
    region: Region,
    site: &Site,
    openings: &HashMap<(usize, usize), Vec<ValueId>>,
    replace: &HashMap<(usize, usize), HashMap<ValueId, ValueId>>,
    no: &mut usize,
) -> Region {
    match region {
        Region::Sequence(items) => {
            Region::Sequence(items.into_iter().map(|i| rewrite_region(func, i, site, openings, replace, no)).collect())
        }
        Region::Scope { out, body } => {
            Region::Scope { out, body: Box::new(rewrite_region(func, *body, site, openings, replace, no)) }
        }
        Region::Loop { header, body, kind } => {
            Region::Loop { header, body: Box::new(rewrite_region(func, *body, site, openings, replace, no)), kind }
        }
        Region::If { cond, then_region, else_region } => Region::If {
            cond,
            then_region: Box::new(rewrite_region(func, *then_region, site, openings, replace, no)),
            else_region: else_region.map(|e| Box::new(rewrite_region(func, *e, site, openings, replace, no))),
        },
        Region::Switch { index, arms, default, dispatch } => {
            let me = *no;
            *no += 1;
            let ours = site.switches.contains(&me);
            let arms = arms
                .into_iter()
                .enumerate()
                .map(|(i, mut arm)| {
                    let body = rewrite_region(func, arm.body, site, openings, replace, no);
                    arm.body = match (openings.get(&(me, i)), replace.get(&(me, i))) {
                        (Some(opening), Some(map)) if ours => open_arm(func, body, opening, map),
                        _ => body,
                    };
                    arm
                })
                .collect();
            let default = Box::new(rewrite_region(func, *default, site, openings, replace, no));
            if ours {
                Region::Switch { index: site.value, arms, default, dispatch: Some(site.value) }
            } else {
                Region::Switch { index, arms, default, dispatch }
            }
        }
        leaf => leaf,
    }
}

/// An arm reading the payload: its uses of each load read the arm's
/// value, and it opens with the payload and those values.
pub(super) fn open_arm(func: &mut HighFunction, body: Region, opening: &[ValueId], map: &HashMap<ValueId, ValueId>) -> Region {
    let swap = |v: &mut ValueId| {
        if let Some(to) = map.get(v) {
            *v = *to;
        }
    };
    for b in blocks_in(&body) {
        let ids: Vec<ValueId> = func.blocks.get(b).map(|blk| blk.bindings.clone()).unwrap_or_default();
        for id in ids {
            if let Some(binding) = func.bindings.get_mut(id) {
                binding.expr.for_each_value_use_mut(swap);
            }
        }
    }
    let body = swap_region(body, &swap);
    let first = match &body {
        Region::Basic(b) => Some(*b),
        Region::Sequence(items) => match items.first() {
            Some(Region::Basic(b)) => Some(*b),
            _ => None,
        },
        _ => None,
    };
    if let Some(b) = first
        && let Some(blk) = func.blocks.get_mut(b)
    {
        let mut bindings = opening.to_vec();
        bindings.append(&mut blk.bindings);
        blk.bindings = bindings;
        return body;
    }
    let id = BlockId::new(func.blocks.len() as u32);
    func.blocks.push(HighBlock { id, bindings: opening.to_vec() });
    match body {
        Region::Sequence(mut items) => {
            items.insert(0, Region::Basic(id));
            Region::Sequence(items)
        }
        other => Region::Sequence(vec![Region::Basic(id), other]),
    }
}

/// `region` with every value it reads itself (conditions, selectors,
/// transfer sources, returns) passed through `swap`.
fn swap_region(region: Region, swap: &impl Fn(&mut ValueId)) -> Region {
    match region {
        Region::Sequence(items) => Region::Sequence(items.into_iter().map(|i| swap_region(i, swap)).collect()),
        Region::Scope { out, body } => Region::Scope { out, body: Box::new(swap_region(*body, swap)) },
        Region::Loop { header, body, kind } => Region::Loop { header, body: Box::new(swap_region(*body, swap)), kind },
        Region::If { mut cond, then_region, else_region } => {
            swap(&mut cond);
            Region::If {
                cond,
                then_region: Box::new(swap_region(*then_region, swap)),
                else_region: else_region.map(|e| Box::new(swap_region(*e, swap))),
            }
        }
        Region::Switch { mut index, arms, default, mut dispatch } => {
            swap(&mut index);
            if let Some(d) = &mut dispatch {
                swap(d);
            }
            Region::Switch {
                index,
                arms: arms
                    .into_iter()
                    .map(|mut a| {
                        a.body = swap_region(a.body, swap);
                        a
                    })
                    .collect(),
                default: Box::new(swap_region(*default, swap)),
                dispatch,
            }
        }
        Region::Break { target, mut transfer } => {
            transfer.iter_mut().for_each(|(_, s)| swap(s));
            Region::Break { target, transfer }
        }
        Region::Continue { target, mut transfer } => {
            transfer.iter_mut().for_each(|(_, s)| swap(s));
            Region::Continue { target, transfer }
        }
        Region::Transfer { target, mut transfer } => {
            transfer.iter_mut().for_each(|(_, s)| swap(s));
            Region::Transfer { target, transfer }
        }
        Region::Return { mut values } => {
            values.iter_mut().for_each(swap);
            Region::Return { values }
        }
        leaf => leaf,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{Arena, IrId, UnknownReason};
    use sordec_ir::{Binding, StructField, SwitchArm, TypeRegistry, UnionCase};

    use crate::marshalling::test_support::{module, v};

    fn bb(i: u32) -> BlockId {
        BlockId::new(i)
    }

    fn seed(bindings: &mut Arena<ValueId, Binding>, ty: IrType, expr: Expr) {
        let id = v(bindings.len() as u32);
        bindings.push(Binding::new(id, ty, expr, Provenance::new("seed", ProvenanceSource::DataFlow, "seed")));
    }

    fn untyped() -> IrType {
        IrType::Unknown(UnknownReason::InsufficientEvidence)
    }

    fn function(bindings: Arena<ValueId, Binding>, blocks: Vec<Vec<u32>>, region: Region) -> HighFunction {
        let mut arena: Arena<BlockId, HighBlock> = Arena::new();
        for (i, b) in blocks.into_iter().enumerate() {
            arena.push(HighBlock { id: bb(i as u32), bindings: b.into_iter().map(v).collect() });
        }
        HighFunction {
            id: FuncId::from_index(0),
            name: None,
            signature: None,
            aliases: Vec::new(),
            blocks: arena,
            bindings,
            region,
            params: vec![v(0), v(1)],
            returns: vec![],
        }
    }

    /// `enum E { A, B(S) }`, `struct S { x: i64 }`.
    fn types() -> TypeRegistry {
        let mut reg = TypeRegistry::default();
        reg.unions.push(UnionDef {
            id: TypeId::new(0),
            name: "E".into(),
            cases: vec![
                sordec_ir::UnionCase { name: "A".into(), fields: vec![] },
                UnionCase { name: "B".into(), fields: vec![TypeRef::UserDefined(TypeId::new(1))] },
            ],
            exported: true,
        });
        reg.structs.push(StructDef {
            id: TypeId::new(1),
            name: "S".into(),
            fields: vec![StructField { name: "x".into(), ty: TypeRef::Primitive(sordec_ir::PrimitiveType::I64) }],
        });
        reg
    }

    /// The decode helper `func_1`: the tag at +0, `B`'s `S.x` at +8.
    fn helper() -> HashMap<FuncId, EnumHelper> {
        let mut layout = vec![HashMap::new(), HashMap::new()];
        layout[1].insert((8, 8), Part::Field { index: 0, field: "x".into(), ty: KnownType::I64 });
        HashMap::from([(
            FuncId::from_index(1),
            EnumHelper { union: TypeId::new(0), slots: vec![(0, 1), (8, 8)], niche: 2, layout },
        )])
    }

    /// `decode(fp, e); t = load8_u fp; w = load fp+8; if t == 2 { trap }
    /// match t { <cases> => { bb1 }, _ => { bb2 } }`, with `w + w` (v7)
    /// scheduled before the switch (0), in the arm (1) or the default (2).
    fn caller(user_in: u32, cases: Vec<u32>) -> HighFunction {
        let mut b: Arena<ValueId, Binding> = Arena::new();
        seed(&mut b, IrType::Known(KnownType::I32), Expr::Phi { incoming: vec![] }); // v0 fp
        seed(&mut b, IrType::Known(KnownType::UserDefined(TypeId::new(0))), Expr::Phi { incoming: vec![] }); // v1 e
        seed(&mut b, untyped(), Expr::Call { target: FuncId::from_index(1), args: vec![v(0), v(1)] }); // v2
        let word = |offset, width, signed, k| Expr::Load { addr: v(0), offset, width, signed, ty: IrType::Known(k) };
        seed(&mut b, untyped(), word(0, MemWidth::W1, Some(false), KnownType::I32)); // v3 tag
        seed(&mut b, untyped(), word(8, MemWidth::W8, None, KnownType::I64)); // v4 payload word
        seed(&mut b, IrType::Known(KnownType::I32), Expr::Literal(Literal::I32(2))); // v5
        seed(&mut b, untyped(), Expr::Binary { op: BinaryOp::Eq, lhs: v(3), rhs: v(5) }); // v6
        seed(&mut b, untyped(), Expr::Binary { op: BinaryOp::Add, lhs: v(4), rhs: v(4) }); // v7
        seed(&mut b, IrType::Known(KnownType::I64), Expr::Literal(Literal::I64(0))); // v8
        let mut blocks = vec![vec![2, 3, 4, 5, 6], vec![], vec![8]];
        blocks[user_in as usize].push(7);
        let region = Region::Sequence(vec![
            Region::Basic(bb(0)),
            Region::If {
                cond: v(6),
                then_region: Box::new(Region::Panic { kind: sordec_ir::PanicKind::Bare }),
                else_region: None,
            },
            Region::Switch {
                index: v(3),
                arms: vec![SwitchArm { cases, body: Region::Basic(bb(1)) }],
                default: Box::new(Region::Basic(bb(2))),
                dispatch: None,
            },
            Region::Return { values: vec![] },
        ]);
        function(b, blocks, region)
    }

    fn run(func: &mut HighFunction) -> usize {
        let (sites, _) = plan(func, &helper(), &types(), &HashMap::new(), &HashMap::new());
        let n = sites.len();
        for s in sites {
            apply(func, s);
        }
        n
    }

    #[test]
    fn a_payload_read_in_its_variants_arm_becomes_the_payloads_field() {
        let mut func = caller(1, vec![1]);
        assert_eq!(run(&mut func), 1);
        let Region::Sequence(items) = &func.region else { panic!("a sequence") };
        // The trap on the failing code went with the decode.
        assert!(!items.iter().any(|r| matches!(r, Region::If { .. })), "{items:?}");
        let Some(Region::Switch { index, dispatch, arms, .. }) =
            items.iter().find(|r| matches!(r, Region::Switch { .. }))
        else {
            panic!("a switch")
        };
        assert_eq!((*index, *dispatch), (v(1), Some(v(1))));
        assert_eq!(arms[0].body, Region::Basic(bb(1)));
        let opening = &func.blocks.get(bb(1)).expect("the arm's block").bindings;
        let (payload, field) = (opening[0], opening[1]);
        assert!(matches!(&func.bindings.get(payload).expect("payload").expr,
            Expr::VariantPayload { value, variant, index: 0 } if *value == v(1) && variant == "B"));
        assert!(matches!(&func.bindings.get(field).expect("field").expr,
            Expr::Field { base, field } if *base == payload && field == "x"));
        assert!(matches!(func.bindings.get(v(7)).expect("the reader").expr,
            Expr::Binary { lhs, rhs, .. } if lhs == field && rhs == field));
        for gone in [2, 3, 4] {
            assert!(
                matches!(func.bindings.get(v(gone)).expect("elided").expr, Expr::Literal(Literal::Unit)),
                "v{gone}"
            );
        }
        assert!(matches!(func.bindings.get(v(6)).expect("the test").expr, Expr::Literal(Literal::Bool(false))));
        sordec_ir::validate_high(&module(vec![func])).expect("valid after the rewrite");
    }

    #[test]
    fn a_payload_read_on_another_variants_path_is_refused() {
        // The default arm is variant `A`, which has nothing at +8: there the
        // word is padding.
        let mut func = caller(2, vec![1]);
        let before = format!("{:?}", func.region);
        assert_eq!(run(&mut func), 0);
        assert_eq!(format!("{:?}", func.region), before);
        assert!(matches!(func.bindings.get(v(4)).expect("the load").expr, Expr::Load { .. }));
    }

    #[test]
    fn a_payload_read_outside_the_variant_arms_is_refused() {
        let mut func = caller(0, vec![1]);
        assert_eq!(run(&mut func), 0);
        assert!(matches!(func.bindings.get(v(2)).expect("the call").expr, Expr::Call { .. }));
    }

    #[test]
    fn a_payload_read_in_an_arm_of_several_variants_is_refused() {
        let mut func = caller(1, vec![0, 1]);
        assert_eq!(run(&mut func), 0);
    }

    #[test]
    fn an_unproven_value_keeps_the_decode() {
        let mut func = caller(1, vec![1]);
        func.bindings.get_mut(v(1)).expect("the value").ty = untyped();
        assert_eq!(run(&mut func), 0);
    }

    /// After the decode's `match`, `g(fp)` — a gated helper: tag at +0,
    /// +8 written unless the tag is 2 — then `match wrap32(load fp) { 2 =>
    /// { bb4 }, _ => { bb5 } }`, with a read of +8 (v9) in the arm
    /// `read_in` (4 or 5).
    fn after_gated_helper(read_in: usize) -> HighFunction {
        let mut b: Arena<ValueId, Binding> = Arena::new();
        seed(&mut b, IrType::Known(KnownType::I32), Expr::Phi { incoming: vec![] }); // v0 fp
        seed(&mut b, IrType::Known(KnownType::UserDefined(TypeId::new(0))), Expr::Phi { incoming: vec![] }); // v1 e
        seed(&mut b, untyped(), Expr::Call { target: FuncId::from_index(1), args: vec![v(0), v(1)] }); // v2
        let word = |offset, width, signed, k| Expr::Load { addr: v(0), offset, width, signed, ty: IrType::Known(k) };
        seed(&mut b, untyped(), word(0, MemWidth::W1, Some(false), KnownType::I32)); // v3 tag
        seed(&mut b, untyped(), word(8, MemWidth::W8, None, KnownType::I64)); // v4 payload word
        seed(&mut b, untyped(), Expr::Binary { op: BinaryOp::Add, lhs: v(4), rhs: v(4) }); // v5
        seed(&mut b, untyped(), Expr::Call { target: FuncId::from_index(2), args: vec![v(0)] }); // v6 g(fp)
        seed(&mut b, untyped(), word(0, MemWidth::W8, None, KnownType::I64)); // v7 g's tag
        seed(&mut b, untyped(), Expr::Unary { op: UnaryOp::Wrap32, value: v(7) }); // v8
        seed(&mut b, untyped(), word(8, MemWidth::W8, None, KnownType::I64)); // v9
        let mut blocks = vec![vec![2, 3, 4], vec![5], vec![], vec![6, 7, 8], vec![], vec![]];
        blocks[read_in].push(9);
        let region = Region::Sequence(vec![
            Region::Basic(bb(0)),
            Region::Switch {
                index: v(3),
                arms: vec![SwitchArm { cases: vec![1], body: Region::Basic(bb(1)) }],
                default: Box::new(Region::Basic(bb(2))),
                dispatch: None,
            },
            Region::Basic(bb(3)),
            Region::Switch {
                index: v(8),
                arms: vec![SwitchArm { cases: vec![2], body: Region::Basic(bb(4)) }],
                default: Box::new(Region::Basic(bb(5))),
                dispatch: None,
            },
            Region::Return { values: vec![] },
        ]);
        function(b, blocks, region)
    }

    fn run_gated(func: &mut HighFunction) -> usize {
        let g = FuncId::from_index(2);
        let access = HashMap::from([(
            g,
            vec![Some(ParamAccess { reads: vec![], writes: vec![(0, 8), (8, 8)], must_writes: vec![(0, 8)] })],
        )]);
        let gated = HashMap::from([(g, vec![Some(Gated { width: 8, none: 2, writes: vec![(8, 8)] })])]);
        let (sites, _) = plan(func, &helper(), &types(), &access, &gated);
        let n = sites.len();
        for s in sites {
            apply(func, s);
        }
        n
    }

    #[test]
    fn a_read_where_a_gated_helpers_tag_is_not_none_is_the_helpers() {
        let mut func = after_gated_helper(5);
        assert_eq!(run_gated(&mut func), 1);
        assert!(matches!(func.bindings.get(v(9)).expect("the read").expr, Expr::Load { .. }));
    }

    #[test]
    fn a_read_where_a_gated_helpers_tag_may_be_none_keeps_the_decode() {
        // On the `none` arm the helper wrote nothing at +8: the decode's
        // word may still be there.
        let mut func = after_gated_helper(4);
        assert_eq!(run_gated(&mut func), 0);
    }

    /// `g(p, c)`: `if c { t = 2 } else { store p+8 <- x; t = 0 }; store p <- t`.
    fn gated_helper(store_payload: bool) -> HighFunction {
        let mut b: Arena<ValueId, Binding> = Arena::new();
        seed(&mut b, untyped(), Expr::Phi { incoming: vec![] }); // v0 p
        seed(&mut b, untyped(), Expr::Phi { incoming: vec![] }); // v1 c
        seed(&mut b, untyped(), Expr::Literal(Literal::I64(2))); // v2
        seed(&mut b, untyped(), Expr::Literal(Literal::I64(7))); // v3 x
        seed(&mut b, untyped(), Expr::Store { addr: v(0), value: v(3), offset: 8, width: MemWidth::W8 }); // v4
        seed(&mut b, untyped(), Expr::Literal(Literal::I64(0))); // v5
        seed(&mut b, untyped(), Expr::Phi { incoming: vec![(bb(0), v(2)), (bb(1), v(5))] }); // v6 t
        seed(&mut b, untyped(), Expr::Store { addr: v(0), value: v(6), offset: 0, width: MemWidth::W8 }); // v7
        let payload = if store_payload { vec![3, 4, 5] } else { vec![3, 5] };
        let region = Region::Sequence(vec![
            Region::Basic(bb(0)),
            Region::If {
                cond: v(1),
                then_region: Box::new(Region::Transfer { target: bb(2), transfer: vec![(v(6), v(2))] }),
                else_region: Some(Box::new(Region::Sequence(vec![
                    Region::Basic(bb(1)),
                    Region::Transfer { target: bb(2), transfer: vec![(v(6), v(5))] },
                ]))),
            },
            Region::Basic(bb(2)),
            Region::Return { values: vec![] },
        ]);
        function(b, vec![vec![2], payload, vec![7]], region)
    }

    #[test]
    fn a_helper_writing_its_payload_unless_its_tag_says_none_is_gated() {
        let g = gated_helper(true);
        let ir = module(vec![g.clone()]);
        let summary = gated_summary(&ir, &g, Some(&param_accesses(&g)));
        assert_eq!(summary[0], Some(Gated { width: 8, none: 2, writes: vec![(8, 8)] }));
        assert_eq!(summary[1], None);
    }

    #[test]
    fn a_helper_that_may_skip_its_payload_whatever_its_tag_is_not_gated() {
        let g = gated_helper(false);
        let ir = module(vec![g.clone()]);
        assert_eq!(gated_summary(&ir, &g, Some(&param_accesses(&g)))[0], None);
    }

    /// `select(c1, select(c2, niche, w == c2), w == c1)` over
    /// `w = wrap32(val_decode(x))`; the outer select is `v9`.
    fn chain(c1: i32, c2: i32, niche: i32) -> HighFunction {
        let sel = |k: u32, rest: u32, eq: u32| Expr::Unknown {
            op_kind: WasmOpcodeKind::Select,
            args: vec![v(k), v(rest), v(eq)],
            reason: UnknownReason::UnsupportedPattern,
        };
        let exprs: Vec<Expr> = vec![
            Expr::Phi { incoming: vec![] },                                             // v0 x
            Expr::Semantic(SemanticOp::Known(KnownOp::ValDecodeSmall { value: v(0) })), // v1
            Expr::Unary { op: UnaryOp::Wrap32, value: v(1) },                           // v2 w
            Expr::Literal(Literal::I32(niche)),                                         // v3
            Expr::Literal(Literal::I32(c2)),                                            // v4
            Expr::Binary { op: BinaryOp::Eq, lhs: v(2), rhs: v(4) },                    // v5
            sel(4, 3, 5),                                                               // v6
            Expr::Literal(Literal::I32(c1)),                                            // v7
            Expr::Binary { op: BinaryOp::Eq, lhs: v(2), rhs: v(7) },                    // v8
            sel(7, 6, 8),                                                               // v9
        ];
        crate::marshalling::test_support::func_with(exprs, vec![v(0)], (0..10).collect())
    }

    #[test]
    fn a_select_chain_sending_each_code_to_itself_is_the_discriminant() {
        let f = chain(10, 15, 9);
        assert_eq!(code_chain(&f, v(9)), Some(HashSet::from([10, 15])));
    }

    #[test]
    fn a_select_chain_whose_fallback_is_a_code_is_not() {
        let f = chain(10, 15, 15);
        assert_eq!(code_chain(&f, v(9)), None);
    }

    #[test]
    fn the_two_form_decoders_name_their_scalar() {
        use crate::marshalling::test_support::two_form_decoder_fn;
        let i = two_form_decoder_fn(0, TAG_I64_OBJECT, TAG_I64_SMALL, ValObjectKind::ObjToI64);
        assert_eq!(two_form_decoder(&i), Some(KnownType::I64));
        assert!(is_i64_decoder(&i));
        let u = two_form_decoder_fn(0, TAG_U64_OBJECT, TAG_U64_SMALL, ValObjectKind::ObjToU64);
        assert_eq!(two_form_decoder(&u), Some(KnownType::U64));
        assert!(!is_i64_decoder(&u));
    }

    /// An object extractor of another type under the tag is not the
    /// conversion: `obj_to_u64` of an `I64Object` traps.
    #[test]
    fn a_decoder_extracting_another_type_is_none() {
        use crate::marshalling::test_support::two_form_decoder_fn;
        let f = two_form_decoder_fn(0, TAG_I64_OBJECT, TAG_I64_SMALL, ValObjectKind::ObjToU64);
        assert_eq!(two_form_decoder(&f), None);
        let g = two_form_decoder_fn(0, TAG_I64_OBJECT, TAG_U64_SMALL, ValObjectKind::ObjToI64);
        assert_eq!(two_form_decoder(&g), None);
    }
}
