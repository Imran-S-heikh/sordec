//! Helpers that encode the value behind a pointer.
//!
//! # The shape
//!
//! SDK 27 converts a number to a `Val` through a reference — `IntoVal` is
//! implemented for `&T` and the derives call it on `&self.field` — and
//! rustc outlines the conversion into a helper handed the number's
//! address. The small form is itself an outlined attempt that
//! [`super::optional_out`] has already turned into an `Option`:
//!
//! ```text
//! fn func41(env, p) {                              caller:  t = func41(env, p)
//!     x = load p                                            a = t.0
//!     r = match small(x) {                                  b = t.1
//!         Some(v) => v,                 // val_encode<u64>(x)
//!         None    => obj_from_u64(x),
//!     }
//!     return (0, r)
//! }
//! ```
//!
//! [`super::encode_helper`] recognises a helper that encodes one of its
//! parameters, and [`super::wide_codec`] the 128-bit one handed its two
//! halves; both find the encoded value among the call's arguments. Here
//! it is behind the pointer, and nothing at the call site holds it. Left
//! alone, the call's component is the encode while every caller uses it
//! as the number — a struct field declared `u64`, an `i128` handed on —
//! and the helper's own merge of two `Val`s is typed as that number.
//!
//! So the call site reads the value itself: the encoded component becomes
//! a load through the pointer (two loads joined, for a 128-bit number),
//! typed as what the helper encodes; the status becomes the `0` every
//! return reports; and the call, with nothing left to read it, is elided.
//!
//! # Why it is exact
//!
//! - **The helper does nothing but read and encode.** Every binding it runs
//!   is pure and total, a load through the pointer, or a call to a helper
//!   that does nothing but build an `Option` of a small encode. It writes
//!   no memory, so loads placed immediately before the call read exactly
//!   what the helper's loads read.
//! - **Every path returns the encode of that one value as one type.** Each
//!   arm of the encoded component is the object constructor of the loaded
//!   value, its small form, or the payload of the small-form attempt handed
//!   it — and every return's status is the constant `0`.
//! - **The value for its encode** is the relocation every encode collapse
//!   makes ([`super::wide_codec`], [`super::encode`]): the SDK takes
//!   `IntoVal` wherever it consumes the value, and the re-emitted source
//!   regenerates the conversion. The 128-bit small form encodes the low
//!   limb alone, as [`super::wide_codec`] reads it; the object constructor
//!   names which load is which limb.
//!
//! # Gates
//!
//! - **A helper**: no spec signature; every return of one arity, either
//!   the encoded `Val` alone or `(status, Val)` with the status `0` on
//!   every path.
//! - **One pointer, one value, one type**: every arm agrees on the
//!   parameter, the offsets and the encoded type; a 128-bit encode needs
//!   its object arm, which is what names the high limb.
//! - **The encode is only passed on.** At a call site, every reader of the
//!   encoded component, through copies, hands it to a store, a call, a
//!   host operation or a struct field, or returns it. None computes on
//!   its bits (arithmetic, a tag test, a decode) — there the word is the
//!   encoding, and the number would change what is computed — and none
//!   merges it: the other arm of a merge may be a different `Val`, an
//!   error's encoding beside an `Ok`'s, and the number would stand beside
//!   it. A helper that returns the component hands it to its callers, so
//!   the same is asked at every one of them, and one whose callers are not
//!   all visible (the function table may call it) refuses; an entrypoint
//!   returns what its spec declares, whose encode the re-emitted wrapper
//!   writes again. Such a site is left as it is.
//! - **The call has no other reader** than the components rewritten.

use std::collections::{HashMap, HashSet};

use sordec_common::{FuncId, IrId, Provenance, ProvenanceSource, ValueId};
use sordec_ir::{
    Binding, Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, Literal, MemWidth, Region, SemanticOp,
    ValObjectKind,
};

use super::sret::emission_order;
use crate::dataflow::{resolve_use, trace_int};
use crate::effects::expr_effects;
use crate::metrics_catalog::MARSHALLING_ENCODE_BY_REF_COLLAPSED as M_COLLAPSED;
use crate::pass::{Pass, PassResult};

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-encode-by-ref";

/// Reads a call site's encoded component as the value behind the pointer.
#[derive(Debug, Default, Clone, Copy)]
pub struct EncodeByRefPass;

impl Pass<HighIr> for EncodeByRefPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let small: HashMap<FuncId, (usize, KnownType)> =
            ir.functions.iter().filter_map(|f| small_encoder(f).map(|s| (f.id, s))).collect();
        if small.is_empty() {
            return result;
        }
        let encoders: HashMap<FuncId, RefEncoder> =
            ir.functions.iter().filter_map(|f| classify(f, &small).map(|e| (f.id, e))).collect();
        if encoders.is_empty() {
            return result;
        }
        // Planned on the whole module before anything changes: a site's
        // gate reads the callers of the function it sits in.
        let callers = Callers::build(ir);
        let plans: Vec<Vec<Site>> =
            ir.functions.iter().map(|f| plan_sites(ir, &callers, f, &encoders)).collect();
        for (func, sites) in ir.functions.iter_mut().zip(plans) {
            let n = rewrite_sites(func, sites);
            if n > 0 {
                result.changed = true;
                result.metrics.increment(M_COLLAPSED, n as i64);
            }
        }
        result
    }
}

/// One load the helper makes through its pointer parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Read {
    offset: u32,
    width: MemWidth,
    signed: Option<bool>,
}

/// What the helper encodes: one word, or a 128-bit number's two limbs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pointee {
    Word(Read),
    Wide { lo: Read, hi: Read },
}

/// A helper proven to return the encode of the value behind one of its
/// pointer parameters.
#[derive(Debug, Clone, PartialEq)]
struct RefEncoder {
    /// Which argument carries the pointer.
    ptr_index: usize,
    /// The component holding the encoded `Val`.
    payload_index: usize,
    /// The component holding the status, `0` on every path; `None` when the
    /// helper returns the `Val` alone.
    status_index: Option<usize>,
    pointee: Pointee,
    ty: KnownType,
}

/// The parameter and type a helper's `Some` holds the small encode of,
/// when it does nothing but build `None` or `Some(val_encode<T>(p))`.
fn small_encoder(func: &HighFunction) -> Option<(usize, KnownType)> {
    if func.signature.is_some() {
        return None;
    }
    let mut sites: Vec<Vec<ValueId>> = Vec::new();
    func.region.for_each_node(|node| {
        if let Region::Return { values } = node {
            sites.push(values.clone());
        }
    });
    if sites.is_empty() {
        return None;
    }
    if !emission_order(func).into_iter().all(|id| func.bindings.get(id).is_none_or(|b| expr_effects(&b.expr).is_pure_total())) {
        return None;
    }
    let mut found: Option<(usize, KnownType)> = None;
    for site in &sites {
        let [value] = site.as_slice() else { return None };
        for arm in arms(func, *value) {
            match &func.bindings.get(arm)?.expr {
                Expr::Optional { payload: None } => {}
                Expr::Optional { payload: Some(items) } => {
                    let [item] = items.as_slice() else { return None };
                    let Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty, value })) =
                        &func.bindings.get(resolve_use(func, *item))?.expr
                    else {
                        return None;
                    };
                    let param = func.params.iter().position(|p| *p == resolve_use(func, *value))?;
                    match &found {
                        None => found = Some((param, ty.clone())),
                        Some(prev) if *prev == (param, ty.clone()) => {}
                        Some(_) => return None,
                    }
                }
                _ => return None,
            }
        }
    }
    found
}

/// What an arm of the encoded component encodes, relative to the loads it
/// reads: the small form or object constructor of a word, the object
/// constructor of two limbs, or the small form of a 128-bit low limb.
#[derive(Debug, Clone, PartialEq)]
enum ArmEncode {
    Word { load: ValueId, ty: KnownType },
    Wide { lo: ValueId, hi: ValueId, ty: KnownType },
    WideLow { lo: ValueId, ty: KnownType },
}

fn arm_encode(func: &HighFunction, arm: ValueId, small: &HashMap<FuncId, (usize, KnownType)>) -> Option<ArmEncode> {
    let wide = |ty: &KnownType| matches!(ty, KnownType::I128 | KnownType::U128);
    let small_form = |ty: &KnownType, value: ValueId| {
        let v = resolve_use(func, value);
        if wide(ty) {
            ArmEncode::WideLow { lo: v, ty: ty.clone() }
        } else {
            ArmEncode::Word { load: v, ty: ty.clone() }
        }
    };
    match &func.bindings.get(resolve_use(func, arm))?.expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty, value })) => Some(small_form(ty, *value)),
        Expr::Semantic(SemanticOp::Known(KnownOp::ValObject { kind, args })) => {
            let one = |ty: KnownType| match args.as_slice() {
                [x] => Some(ArmEncode::Word { load: resolve_use(func, *x), ty }),
                _ => None,
            };
            let two = |ty: KnownType| match args.as_slice() {
                // The host ABI's order: high limb first.
                [hi, lo] => Some(ArmEncode::Wide { lo: resolve_use(func, *lo), hi: resolve_use(func, *hi), ty }),
                _ => None,
            };
            match kind {
                ValObjectKind::ObjFromU64 => one(KnownType::U64),
                ValObjectKind::ObjFromI64 => one(KnownType::I64),
                ValObjectKind::TimepointObjFromU64 => one(KnownType::Timepoint),
                ValObjectKind::DurationObjFromU64 => one(KnownType::Duration),
                ValObjectKind::ObjFromI128Pieces => two(KnownType::I128),
                ValObjectKind::ObjFromU128Pieces => two(KnownType::U128),
                _ => None,
            }
        }
        // The small-form attempt's payload, read where its tag proved it
        // present: the small encode of the argument it was handed.
        Expr::Unwrap { value, index: 0, arity: 1 } => {
            let Expr::Call { target, args } = &func.bindings.get(resolve_use(func, *value))?.expr else {
                return None;
            };
            let (param, ty) = small.get(target)?;
            Some(small_form(ty, *args.get(*param)?))
        }
        _ => None,
    }
}

/// The parameter index and read a value is, when it is a load straight
/// through one of `func`'s parameters.
fn load_through_param(func: &HighFunction, value: ValueId) -> Option<(usize, Read)> {
    let Expr::Load { addr, offset, width, signed, .. } = &func.bindings.get(resolve_use(func, value))?.expr else {
        return None;
    };
    let param = func.params.iter().position(|p| *p == resolve_use(func, *addr))?;
    Some((param, Read { offset: *offset, width: *width, signed: *signed }))
}

/// `func`'s description as a helper encoding the value behind a pointer.
fn classify(func: &HighFunction, small: &HashMap<FuncId, (usize, KnownType)>) -> Option<RefEncoder> {
    if func.signature.is_some() || small.contains_key(&func.id) {
        return None;
    }
    let mut sites: Vec<Vec<ValueId>> = Vec::new();
    func.region.for_each_node(|node| {
        if let Region::Return { values } = node {
            sites.push(values.clone());
        }
    });
    let arity = sites.first()?.len();
    if sites.iter().any(|s| s.len() != arity) {
        return None;
    }
    // `(status, Val)` with the status 0 everywhere, or the `Val` alone.
    let all_zero = |k: usize| sites.iter().all(|s| trace_int(func, s[k]) == Some(0));
    let (status_index, payload_index) = match arity {
        1 => (None, 0),
        2 => match (all_zero(0), all_zero(1)) {
            (true, false) => (Some(0), 1),
            (false, true) => (Some(1), 0),
            _ => return None,
        },
        _ => return None,
    };
    let mut ptr: Option<usize> = None;
    let mut ty: Option<KnownType> = None;
    let mut word: Option<Read> = None;
    let mut lo: Option<Read> = None;
    let mut hi: Option<Read> = None;
    let agree = |slot: &mut Option<Read>, value: ValueId, ptr: &mut Option<usize>| -> Option<()> {
        let (param, read) = load_through_param(func, value)?;
        if ptr.replace(param).is_some_and(|p| p != param) || slot.replace(read).is_some_and(|r| r != read) {
            return None;
        }
        Some(())
    };
    for site in &sites {
        for arm in arms(func, site[payload_index]) {
            let enc = arm_encode(func, arm, small)?;
            let arm_ty = match &enc {
                ArmEncode::Word { ty, .. } | ArmEncode::Wide { ty, .. } | ArmEncode::WideLow { ty, .. } => ty.clone(),
            };
            if ty.replace(arm_ty.clone()).is_some_and(|t| t != arm_ty) {
                return None;
            }
            match enc {
                ArmEncode::Word { load, .. } => agree(&mut word, load, &mut ptr)?,
                ArmEncode::Wide { lo: l, hi: h, .. } => {
                    agree(&mut lo, l, &mut ptr)?;
                    agree(&mut hi, h, &mut ptr)?;
                }
                ArmEncode::WideLow { lo: l, .. } => agree(&mut lo, l, &mut ptr)?,
            }
        }
    }
    let ptr_index = ptr?;
    let pointer = func.params[ptr_index];
    let pointee = match (word, lo, hi) {
        (Some(w), None, None) => Pointee::Word(w),
        (None, Some(lo), Some(hi)) if lo != hi => Pointee::Wide { lo, hi },
        _ => return None,
    };
    // Nothing else happens: pure work, loads through the pointer, and the
    // small-form attempts — so the helper writes no memory.
    let clean = emission_order(func).into_iter().all(|id| {
        func.bindings.get(id).is_none_or(|b| match &b.expr {
            Expr::Load { addr, .. } => resolve_use(func, *addr) == pointer,
            Expr::Call { target, .. } => small.contains_key(target),
            other => expr_effects(other).is_pure_total(),
        })
    });
    if !clean {
        return None;
    }
    Some(RefEncoder { ptr_index, payload_index, status_index, pointee, ty: ty? })
}

/// The definitions that produce `value`: a merge's arms, through merges.
fn arms(func: &HighFunction, value: ValueId) -> Vec<ValueId> {
    let mut out = Vec::new();
    let mut work = vec![resolve_use(func, value)];
    let mut seen = HashSet::new();
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

/// The bindings code that runs: the scheduled ones and the merges.
fn live_bindings(func: &HighFunction) -> HashSet<ValueId> {
    emission_order(func)
        .into_iter()
        .chain(func.bindings.iter().filter(|(_, b)| matches!(b.expr, Expr::Phi { .. })).map(|(id, _)| id))
        .collect()
}

/// Callers of each function, and whether a function's caller set is
/// closed: no spec signature (the host calls those), and not reachable
/// through the function table when the module calls through one.
struct Callers {
    sites: HashMap<FuncId, Vec<(usize, ValueId)>>,
    open: HashSet<FuncId>,
}

impl Callers {
    fn build(ir: &HighIr) -> Self {
        let has_indirect =
            ir.functions.iter().any(|f| f.bindings.iter().any(|(_, b)| matches!(b.expr, Expr::IndirectCall { .. })));
        let table: Option<HashSet<FuncId>> =
            ir.facts.table_functions.as_ref().map(|t| t.iter().map(|i| FuncId::new(*i)).collect());
        let mut sites: HashMap<FuncId, Vec<(usize, ValueId)>> = HashMap::new();
        let mut open = HashSet::new();
        for (index, func) in ir.functions.iter().enumerate() {
            if func.signature.is_some() || (has_indirect && table.as_ref().is_none_or(|t| t.contains(&func.id))) {
                open.insert(func.id);
            }
            for (id, b) in func.bindings.iter() {
                if let Expr::Call { target, .. } = &b.expr {
                    sites.entry(*target).or_default().push((index, id));
                }
            }
        }
        Callers { sites, open }
    }
}

/// How far a returned encode is followed into callers.
const MAX_RETURN_DEPTH: u32 = 4;

/// Whether every live reader of `value` only passes it on: through copies,
/// into a store, a call, a host operation or a struct field, or out of the
/// function — and then, out of a helper, the same at every caller. A merge
/// may join the encode with a different `Val` (an error's), and an
/// operation on the word reads the encoding; either refuses the site.
fn passed_on(ir: &HighIr, callers: &Callers, func: &HighFunction, value: ValueId, depth: u32) -> bool {
    let live = live_bindings(func);
    let mut work = vec![value];
    let mut seen = HashSet::new();
    while let Some(v) = work.pop() {
        if !seen.insert(v) {
            continue;
        }
        for (id, b) in func.bindings.iter() {
            if !live.contains(&id) {
                continue;
            }
            let mut reads = false;
            b.expr.for_each_value_use(|u| reads |= u == v);
            if !reads {
                continue;
            }
            match &b.expr {
                Expr::Use(_) => work.push(id),
                Expr::Phi { .. }
                | Expr::Binary { .. }
                | Expr::Unary { .. }
                | Expr::Select { .. }
                | Expr::Semantic(SemanticOp::Known(
                    KnownOp::ValTagCheck { .. } | KnownOp::ValDecodeSmall { .. } | KnownOp::ValObject { .. },
                )) => return false,
                _ => {}
            }
        }
        let mut returned: Vec<(usize, usize)> = Vec::new();
        func.region.for_each_node(|node| {
            if let Region::Return { values } = node {
                for (k, r) in values.iter().enumerate() {
                    if *r == v {
                        returned.push((k, values.len()));
                    }
                }
            }
        });
        for (k, arity) in returned {
            // An entrypoint's return is what the spec declares: its encode
            // is regenerated there as at any other return.
            if func.signature.is_some() {
                continue;
            }
            if depth == 0 || !callers_pass_on(ir, callers, func.id, k, arity, depth - 1) {
                return false;
            }
        }
    }
    true
}

/// Whether, at every call of `callee`, component `k` of `arity` is only
/// passed on ([`passed_on`]).
fn callers_pass_on(ir: &HighIr, callers: &Callers, callee: FuncId, k: usize, arity: usize, depth: u32) -> bool {
    if callers.open.contains(&callee) {
        return false;
    }
    let Some(sites) = callers.sites.get(&callee) else { return true };
    sites.iter().all(|&(index, call)| {
        let caller = &ir.functions[index];
        if caller.id == callee {
            return false;
        }
        if arity == 1 {
            return passed_on(ir, callers, caller, call, depth);
        }
        caller.bindings.iter().all(|(id, b)| match &b.expr {
            Expr::Project { value, index } if resolve_use(caller, *value) == call && *index as usize == k => {
                passed_on(ir, callers, caller, id, depth)
            }
            _ => true,
        })
    })
}

/// One call to rewrite: the call, the helper's description, the pointer it
/// was handed, and the bindings reading its encoded component and status.
struct Site {
    call: ValueId,
    enc: RefEncoder,
    pointer: ValueId,
    payloads: Vec<ValueId>,
    statuses: Vec<ValueId>,
}

/// The calls in `func` to a helper in `encoders` that pass the gates.
fn plan_sites(ir: &HighIr, callers: &Callers, func: &HighFunction, encoders: &HashMap<FuncId, RefEncoder>) -> Vec<Site> {
    let mut out = Vec::new();
    for call in emission_order(func) {
        let Some(Expr::Call { target, args }) = func.bindings.get(call).map(|b| &b.expr) else { continue };
        let Some(enc) = encoders.get(target) else { continue };
        let Some(&pointer) = args.get(enc.ptr_index) else { continue };
        // Every reader of the call is one of its components.
        let mut payloads: Vec<ValueId> = Vec::new();
        let mut statuses: Vec<ValueId> = Vec::new();
        let mut other = false;
        for (id, b) in func.bindings.iter() {
            if id == call {
                continue;
            }
            let mut reads = false;
            b.expr.for_each_value_use(|u| reads |= u == call);
            if !reads {
                continue;
            }
            match &b.expr {
                Expr::Project { index, .. } if enc.status_index.is_some() && *index as usize == enc.payload_index => {
                    payloads.push(id)
                }
                Expr::Project { index, .. } if enc.status_index == Some(*index as usize) => statuses.push(id),
                _ => other = true,
            }
        }
        let single = enc.status_index.is_none();
        if other && !single {
            continue;
        }
        let encoded: Vec<ValueId> = if single { vec![call] } else { payloads.clone() };
        if !encoded.iter().all(|v| passed_on(ir, callers, func, *v, MAX_RETURN_DEPTH)) {
            continue;
        }
        out.push(Site { call, enc: enc.clone(), pointer, payloads, statuses });
    }
    out
}

/// Rewrite the planned sites of `func`. Returns how many it rewrote.
fn rewrite_sites(func: &mut HighFunction, sites: Vec<Site>) -> usize {
    let mut count = 0;
    for Site { call, enc, pointer, payloads, statuses } in sites {
        let value = read_value(func, call, pointer, &enc);
        let ty = IrType::Known(enc.ty.clone());
        count += 1;
        if enc.status_index.is_none() {
            if let Some(b) = func.bindings.get_mut(call) {
                b.expr = Expr::Use(value);
                b.ty = ty;
                b.add_provenance(Provenance::new(
                    PASS_NAME,
                    ProvenanceSource::SdkPattern,
                    "call to a helper encoding the value behind a pointer: that value, read here",
                ));
            }
            continue;
        }
        for id in payloads {
            if let Some(b) = func.bindings.get_mut(id) {
                b.expr = Expr::Use(value);
                b.ty = ty.clone();
                b.add_provenance(Provenance::new(
                    PASS_NAME,
                    ProvenanceSource::SdkPattern,
                    "the encode of the value behind a pointer: that value, read here",
                ));
            }
        }
        for id in statuses {
            if let Some(b) = func.bindings.get_mut(id) {
                b.expr = Expr::Literal(Literal::I64(0));
                b.add_provenance(Provenance::new(
                    PASS_NAME,
                    ProvenanceSource::SdkPattern,
                    "status of an encode that cannot fail",
                ));
            }
        }
        if let Some(b) = func.bindings.get_mut(call) {
            b.expr = Expr::Literal(Literal::Unit);
            b.ty = IrType::Known(KnownType::Unit);
            b.add_provenance(Provenance::new(
                PASS_NAME,
                ProvenanceSource::SdkPattern,
                "call to a helper encoding the value behind a pointer, elided with its results",
            ));
        }
    }
    count
}


/// Place the loads the helper makes, through `pointer`, immediately
/// before `call`, joined for a 128-bit value. Returns the value read.
fn read_value(func: &mut HighFunction, call: ValueId, pointer: ValueId, enc: &RefEncoder) -> ValueId {
    let mut fresh: Vec<ValueId> = Vec::new();
    let mut push = |func: &mut HighFunction, ty: IrType, expr: Expr, note: &'static str| {
        let id = ValueId::from_index(func.bindings.len() as u32);
        func.bindings.push(Binding::new(id, ty, expr, Provenance::new(PASS_NAME, ProvenanceSource::SdkPattern, note)));
        fresh.push(id);
        id
    };
    let load = |read: Read, ty: IrType| Expr::Load {
        addr: pointer,
        offset: read.offset,
        width: read.width,
        signed: read.signed,
        ty,
    };
    let value = match enc.pointee {
        Pointee::Word(read) => {
            let ty = IrType::Known(enc.ty.clone());
            push(func, ty.clone(), load(read, ty), "the value a by-reference encode reads, read at its call")
        }
        Pointee::Wide { lo, hi } => {
            let (lo_ty, hi_ty) = match enc.ty {
                KnownType::U128 => (KnownType::U64, KnownType::U64),
                _ => (KnownType::U64, KnownType::I64),
            };
            let l = push(
                func,
                IrType::Inferred(lo_ty.clone()),
                load(lo, IrType::Inferred(lo_ty)),
                "the low limb a by-reference encode reads, read at its call",
            );
            let h = push(
                func,
                IrType::Inferred(hi_ty.clone()),
                load(hi, IrType::Inferred(hi_ty)),
                "the high limb a by-reference encode reads, read at its call",
            );
            push(
                func,
                IrType::Known(enc.ty.clone()),
                Expr::WideJoin { lo: l, hi: h },
                "the 128-bit value a by-reference encode reads, joined from its limbs",
            )
        }
    };
    for (_, block) in func.blocks.iter_mut() {
        if let Some(pos) = block.bindings.iter().position(|v| *v == call) {
            for (k, id) in fresh.iter().enumerate() {
                block.bindings.insert(pos + k, *id);
            }
            break;
        }
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, load, module, v};
    use sordec_common::BlockId;

    /// func 0: `fn small(x) { if .. { None } else { Some(val_encode<T>(x)) } }`.
    fn small_attempt(ty: KnownType) -> HighFunction {
        let mut f = func_with(
            vec![
                Expr::Phi { incoming: vec![] },                                                            // v0: x
                Expr::Optional { payload: None },                                                          // v1
                Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty, value: v(0) })),            // v2
                Expr::Optional { payload: Some(vec![v(2)]) },                                              // v3
                Expr::Phi { incoming: vec![(BlockId::from_index(0), v(1)), (BlockId::from_index(1), v(3))] }, // v4
            ],
            vec![v(0)],
            vec![1, 2, 3],
        );
        f.region = Region::Sequence(vec![Region::Basic(BlockId::from_index(0)), Region::Return { values: vec![v(4)] }]);
        f
    }

    /// func 1: `fn enc(env, p) { x = load p; r = match small(x) { Some(v) => v, None => obj_from_u64(x) }; (0, r) }`.
    fn u64_by_ref() -> HighFunction {
        let mut f = func_with(
            vec![
                Expr::Phi { incoming: vec![] },                                         // v0: env
                Expr::Phi { incoming: vec![] },                                         // v1: p
                load(v(1), 0),                                                          // v2: x
                Expr::Call { target: FuncId::from_index(0), args: vec![v(2)] },         // v3
                Expr::Unwrap { value: v(3), index: 0, arity: 1 },                       // v4
                Expr::Semantic(SemanticOp::Known(KnownOp::ValObject {
                    kind: ValObjectKind::ObjFromU64,
                    args: vec![v(2)],
                })),                                                                    // v5
                Expr::Phi { incoming: vec![(BlockId::from_index(0), v(4)), (BlockId::from_index(1), v(5))] }, // v6
                Expr::Literal(Literal::I64(0)),                                         // v7
            ],
            vec![v(0), v(1)],
            vec![2, 3, 4, 5, 7],
        );
        f.id = FuncId::from_index(1);
        f.region = Region::Sequence(vec![Region::Basic(BlockId::from_index(0)), Region::Return { values: vec![v(7), v(6)] }]);
        f
    }

    /// func 2: `fn caller(env, q) { t = enc(env, q); return (t.0, t.1) }`.
    fn caller() -> HighFunction {
        let mut f = func_with(
            vec![
                Expr::Phi { incoming: vec![] },                                              // v0: env
                Expr::Phi { incoming: vec![] },                                              // v1: q
                Expr::Call { target: FuncId::from_index(1), args: vec![v(0), v(1)] },        // v2
                Expr::Project { value: v(2), index: 0 },                                     // v3
                Expr::Project { value: v(2), index: 1 },                                     // v4
            ],
            vec![v(0), v(1)],
            vec![2, 3, 4],
        );
        f.id = FuncId::from_index(2);
        f.region = Region::Sequence(vec![Region::Basic(BlockId::from_index(0)), Region::Return { values: vec![v(3), v(4)] }]);
        f
    }

    #[test]
    fn a_helper_encoding_the_value_behind_its_pointer_is_classified() {
        let ir = module(vec![small_attempt(KnownType::U64), u64_by_ref(), caller()]);
        let small = HashMap::from([(FuncId::from_index(0), small_encoder(&ir.functions[0]).unwrap())]);
        assert_eq!(small[&FuncId::from_index(0)], (0, KnownType::U64));
        let enc = classify(&ir.functions[1], &small).unwrap();
        assert_eq!(enc.ptr_index, 1);
        assert_eq!((enc.status_index, enc.payload_index), (Some(0), 1));
        assert_eq!(enc.ty, KnownType::U64);
        assert!(matches!(enc.pointee, Pointee::Word(Read { offset: 0, .. })));
    }

    #[test]
    fn the_call_site_reads_the_value() {
        let mut ir = module(vec![small_attempt(KnownType::U64), u64_by_ref(), caller()]);
        assert!(EncodeByRefPass.run(&mut ir).changed);
        let f = &ir.functions[2];
        let Expr::Use(read) = f.bindings.get(v(4)).unwrap().expr else { panic!("{:?}", f.bindings.get(v(4))) };
        assert!(matches!(f.bindings.get(read).unwrap().expr, Expr::Load { addr, offset: 0, .. } if addr == v(1)));
        assert_eq!(f.bindings.get(v(4)).unwrap().ty, IrType::Known(KnownType::U64));
        assert!(matches!(f.bindings.get(v(3)).unwrap().expr, Expr::Literal(Literal::I64(0))));
        assert!(matches!(f.bindings.get(v(2)).unwrap().expr, Expr::Literal(Literal::Unit)));
        // The load runs where the call did.
        assert_eq!(f.blocks.get(BlockId::from_index(0)).unwrap().bindings.first(), Some(&read));
        // Idempotent: no call is left to rewrite.
        assert!(!EncodeByRefPass.run(&mut ir).changed);
    }

    #[test]
    fn a_128_bit_encode_reads_both_limbs() {
        let mut enc = u64_by_ref();
        // v5 becomes `obj_from_i128_pieces(hi, lo)` with hi = load p+8 (v7
        // is the status, so the high limb's load is added as v8).
        enc.bindings.push(Binding::new(
            v(8),
            IrType::Unknown(sordec_common::UnknownReason::InsufficientEvidence),
            load(v(1), 8),
            Provenance::new("seed", ProvenanceSource::DataFlow, "seed"),
        ));
        enc.blocks.get_mut(BlockId::from_index(0)).unwrap().bindings.insert(1, v(8));
        enc.bindings.get_mut(v(5)).unwrap().expr = Expr::Semantic(SemanticOp::Known(KnownOp::ValObject {
            kind: ValObjectKind::ObjFromI128Pieces,
            args: vec![v(8), v(2)],
        }));
        enc.bindings.get_mut(v(3)).unwrap().expr = Expr::Call { target: FuncId::from_index(0), args: vec![v(2), v(8)] };
        let mut ir = module(vec![small_attempt(KnownType::I128), enc, caller()]);
        assert!(EncodeByRefPass.run(&mut ir).changed);
        let f = &ir.functions[2];
        let Expr::Use(joined) = f.bindings.get(v(4)).unwrap().expr else { panic!() };
        let Expr::WideJoin { lo, hi } = f.bindings.get(joined).unwrap().expr else { panic!() };
        assert!(matches!(f.bindings.get(lo).unwrap().expr, Expr::Load { offset: 0, .. }));
        assert!(matches!(f.bindings.get(hi).unwrap().expr, Expr::Load { offset: 8, .. }));
        assert_eq!(f.bindings.get(v(4)).unwrap().ty, IrType::Known(KnownType::I128));
    }

    #[test]
    fn a_helper_that_writes_memory_is_not_classified() {
        let mut enc = u64_by_ref();
        enc.bindings.get_mut(v(7)).unwrap().expr = crate::marshalling::test_support::store(v(1), v(2), 0);
        let ir = module(vec![small_attempt(KnownType::U64), enc]);
        let small = HashMap::from([(FuncId::from_index(0), (0, KnownType::U64))]);
        assert!(classify(&ir.functions[1], &small).is_none());
    }

    #[test]
    fn arms_reading_different_offsets_are_not_classified() {
        let mut enc = u64_by_ref();
        enc.bindings.push(Binding::new(
            v(8),
            IrType::Unknown(sordec_common::UnknownReason::InsufficientEvidence),
            load(v(1), 8),
            Provenance::new("seed", ProvenanceSource::DataFlow, "seed"),
        ));
        enc.blocks.get_mut(BlockId::from_index(0)).unwrap().bindings.insert(1, v(8));
        enc.bindings.get_mut(v(5)).unwrap().expr = Expr::Semantic(SemanticOp::Known(KnownOp::ValObject {
            kind: ValObjectKind::ObjFromU64,
            args: vec![v(8)],
        }));
        let small = HashMap::from([(FuncId::from_index(0), (0, KnownType::U64))]);
        let ir = module(vec![small_attempt(KnownType::U64), enc]);
        assert!(classify(&ir.functions[1], &small).is_none());
    }

    #[test]
    fn a_site_that_computes_on_the_encode_is_left_alone() {
        let mut c = caller();
        // v5 = t.1 & 255: the encode's tag, read off its bits.
        c.bindings.push(Binding::new(
            v(5),
            IrType::Unknown(sordec_common::UnknownReason::InsufficientEvidence),
            Expr::Binary { op: sordec_ir::BinaryOp::BitAnd, lhs: v(4), rhs: v(3) },
            Provenance::new("seed", ProvenanceSource::DataFlow, "seed"),
        ));
        c.blocks.get_mut(BlockId::from_index(0)).unwrap().bindings.push(v(5));
        let mut ir = module(vec![small_attempt(KnownType::U64), u64_by_ref(), c]);
        assert!(!EncodeByRefPass.run(&mut ir).changed);
        assert!(matches!(ir.functions[2].bindings.get(v(2)).unwrap().expr, Expr::Call { .. }));
    }

    #[test]
    fn an_encode_returned_into_a_merge_is_left_alone() {
        // func 3: `r = caller(env, q); x = merge [r.1, 3]; return x` — the
        // encode `caller` returns meets another `Val` (an error's word).
        let mut outer = func_with(
            vec![
                Expr::Phi { incoming: vec![] },                                          // v0: env
                Expr::Phi { incoming: vec![] },                                          // v1: q
                Expr::Call { target: FuncId::from_index(2), args: vec![v(0), v(1)] },    // v2
                Expr::Project { value: v(2), index: 1 },                                 // v3
                Expr::Literal(Literal::I64(3)),                                          // v4
                Expr::Phi { incoming: vec![(BlockId::from_index(0), v(3)), (BlockId::from_index(1), v(4))] }, // v5
            ],
            vec![v(0), v(1)],
            vec![2, 3, 4],
        );
        outer.id = FuncId::from_index(3);
        outer.region =
            Region::Sequence(vec![Region::Basic(BlockId::from_index(0)), Region::Return { values: vec![v(5)] }]);
        let mut ir = module(vec![small_attempt(KnownType::U64), u64_by_ref(), caller(), outer]);
        assert!(!EncodeByRefPass.run(&mut ir).changed);
        // Handed on untouched instead, the caller's site is rewritten.
        let mut ir = module(vec![small_attempt(KnownType::U64), u64_by_ref(), caller()]);
        assert!(EncodeByRefPass.run(&mut ir).changed);
    }
}
