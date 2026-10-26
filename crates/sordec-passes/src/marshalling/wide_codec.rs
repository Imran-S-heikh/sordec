//! Collapse the SDK's 128-bit `Val` codecs to the value they carry.
//!
//! # The two shapes
//!
//! `amount: i128` is one parameter in the source. The wasm receives a
//! tagged `Val` and hands it to `<i128 as TryFromVal<Env, Val>>`, which
//! rustc outlines into a helper writing a `Result<i128, ConversionError>`
//! into the caller's frame — **four** slots, because the payload is two
//! limbs:
//!
//! ```text
//! call decode(fp, amount)   →  (nothing)
//! load fp+0   discriminant  →  0
//! load fp+16  low limb      →  wide_lo(amount)
//! load fp+24  high limb     →  wide_hi(amount)
//! ```
//!
//! The mirror is `IntoVal`: a helper taking the two limbs and returning
//! `(status, Val)`, the small encoding on the fast path and an
//! `obj_from_i128_pieces` host object otherwise:
//!
//! ```text
//! t = encode(lo, hi);  t.0, t.1   →   0, wide(lo, hi)
//! ```
//!
//! [`super::decode`] and [`super::encode`] own the one-limb versions of
//! these and decline the wide ones on purpose — the `hi64`/`lo64` piece
//! extractors are excluded there because "a single piece is not the whole
//! value". [`sordec_ir::Expr::WideJoin`] and the limb extractors are what
//! make the whole value expressible, and this pass is the transform that
//! note deferred.
//!
//! # Why the collapse is exact
//!
//! Same relocation argument as the scalar collapse. The decoded value
//! *is* the parameter: the host validated it against `contractspecv0`
//! before dispatch, and the re-emitted `#[contractimpl]` wrapper
//! regenerates the identical conversion and its failure path. For a `Val`
//! that came out of a host operation (a storage read, a map lookup) the
//! decode is the proof of the stored type, so the collapse plants
//! `Known(i128)` on that operation's result — which is what the emitter
//! needs to spell `get::<_, i128>` — and the SDK's typed API regenerates
//! the conversion again. A `Val` of any other provenance is left alone:
//! there is no boundary to relocate the check to.
//!
//! The encode direction needs no ABI at all. The helper's own body says
//! the value is an `i128` (`val_encode<i128>` on one arm, the i128
//! object constructor on the other), and every SDK consumer of the result
//! takes `IntoVal`, so a typed `i128` where a `Val` was is the same
//! store, the same event, the same return.
//!
//! # Gates
//!
//! Each declines rather than approximating: helpers only, no host state
//! in the codec body, every Ok-path limb traces to the `Val` parameter
//! through decode operations only, the tags tested are the one wide type's
//! pair, and the caller-side evidence above. A frame the caller writes to
//! or hands to another call between the decode and its loads is dropped
//! from tracking, the same discipline [`super::decode`] uses.
//!
//! And a load is collapsed only where its decode **dominates** it. The scan
//! is linear over the emission order, so a decode on one arm of an `if`
//! and a load after the join look adjacent; `account` decodes the spend
//! limit into one slot on each arm (a map read on one, a storage read on
//! the other) and reads it after the join, and the collapse bound that read
//! to the `else` arm's value alone, dropping the stored limit. A load its
//! decode does not dominate stays a load, and its decode's call is then
//! kept too, since the load still reads what the call writes.

use std::collections::{BTreeMap, HashMap};

use sordec_common::{FuncId, IrId, Provenance, ProvenanceSource, ValueId};
use sordec_ir::{
    BinaryOp, Binding, Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, Literal, Region,
    SemanticOp, UnaryOp, ValObjectKind,
};

use super::{apply_elisions, metrics, sret, Elision};
use crate::dataflow::{canon_addr, resolve_use, trace_int};
use crate::effects::expr_effects;
use crate::pass::{Pass, PassResult};
use crate::type_infer::known_of_type_ref;
use crate::val_abi;

/// Pass name — also the provenance `pass` field for every elision.
pub const PASS_NAME: &str = "marshalling-wide-codec";

/// Bytes a four-slot `Result<i128, _>` occupies in the caller's frame.
const RESULT_BYTES: u32 = 32;

/// A helper proven to be `<T as TryFromVal<Env, Val>>::try_from_val` for a
/// 128-bit `T`, results written through an out-pointer.
#[derive(Debug, Clone)]
struct WideDecoder {
    disc: u32,
    lo: u32,
    hi: u32,
    ty: KnownType,
    tags: Vec<u8>,
}

/// A helper proven to be `<T as IntoVal<Env, Val>>` for a 128-bit `T`,
/// results returned as `(status, Val)`.
#[derive(Debug, Clone)]
struct WideEncoder {
    lo_index: usize,
    hi_index: usize,
    /// Which returned component is the status, when the helper returns
    /// one. Some SDK versions return the encoded `Val` alone.
    disc_index: Option<usize>,
    payload_index: usize,
    ty: KnownType,
}

/// The 128-bit type a helper decodes, and which argument carries the
/// `Val` it decodes, when `func` is one of those helpers.
///
/// Shared with [`super::spec_from_guards`], which reads it the other way
/// round: with no spec section the helper's own tags are what says how
/// the argument was declared.
pub(crate) fn decoded_wide_type(func: &HighFunction) -> Option<(usize, KnownType)> {
    classify_decoder(func).map(|d| (VAL_ARGUMENT, d.ty))
}

/// Which argument of a wide decode helper carries the `Val`; the first
/// is the out-pointer, as [`classify_decoder`] requires.
const VAL_ARGUMENT: usize = 1;

/// Collapses 128-bit `Val` decodes and encodes.
#[derive(Debug, Default, Clone, Copy)]
pub struct WideCodecPass;

impl Pass<HighIr> for WideCodecPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let decoders: HashMap<FuncId, WideDecoder> = ir
            .functions
            .iter()
            .filter_map(|f| classify_decoder(f).map(|d| (f.id, d)))
            .collect();
        let encoders: HashMap<FuncId, WideEncoder> = ir
            .functions
            .iter()
            .filter_map(|f| classify_encoder(f).map(|e| (f.id, e)))
            .collect();
        if decoders.is_empty() && encoders.is_empty() {
            return result;
        }
        for func in &mut ir.functions {
            if decoders.contains_key(&func.id) || encoders.contains_key(&func.id) {
                continue;
            }
            let (elisions, typed) = plan_decodes(func, &decoders);
            if !elisions.is_empty() {
                result.changed = true;
                for el in &elisions {
                    result.metrics.increment(el.metric, 1);
                }
                apply_elisions(func, PASS_NAME, elisions);
                // The decode was the proof of the value's type. A type-only
                // refinement, recorded on the rebound limbs and the elided
                // call rather than here: the value's own latest note is
                // the recognizer that produced it, and that is the one
                // `dump-hir` shows.
                for (val, ty) in typed {
                    if let Some(b) = func.bindings.get_mut(val) {
                        b.ty = ty;
                    }
                }
            }
            let encoded = rewrite_encodes(func, &encoders);
            if encoded > 0 {
                result.changed = true;
                result.metrics.increment(metrics::WIDE_ENCODE_COLLAPSED, encoded);
            }
        }
        result
    }
}

// ---------------------------------------------------------------------
// Callee classification
// ---------------------------------------------------------------------

/// What one value stored into an out-slot is, relative to the `Val`
/// parameter being decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Limb {
    /// The low 64 bits: `val_decode(v)` or `obj_to_*_lo64(v)`.
    Lo(Option<KnownType128>),
    /// The high 64 bits: `shr v, 63` (the small encoding's sign
    /// extension) or `obj_to_*_hi64(v)`.
    Hi(Option<KnownType128>),
    /// A constant — the `Result` discriminant or the error `Val`.
    Const,
    Other,
}

/// The two wide types the codecs come in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KnownType128 {
    I128,
    U128,
}

impl KnownType128 {
    fn known(self) -> KnownType {
        match self {
            Self::I128 => KnownType::I128,
            Self::U128 => KnownType::U128,
        }
    }
    fn of_tags(tags: &[u8]) -> Option<Self> {
        if tags.iter().all(|t| *t == val_abi::TAG_I128_SMALL || *t == val_abi::TAG_I128_OBJECT) {
            Some(Self::I128)
        } else if tags.iter().all(|t| *t == val_abi::TAG_U128_SMALL || *t == val_abi::TAG_U128_OBJECT) {
            Some(Self::U128)
        } else {
            None
        }
    }
}

fn classify_decoder(func: &HighFunction) -> Option<WideDecoder> {
    if func.signature.is_some() || func.params.len() != 2 {
        return None;
    }
    let out = func.params[0];
    let val = func.params[1];

    // Stores through the out-pointer, several per offset allowed: each Ok
    // path writes the limbs itself. Any other use of the pointer, or any
    // host state, disqualifies.
    let mut slots: BTreeMap<u32, Vec<ValueId>> = BTreeMap::new();
    for id in sret::emission_order(func) {
        let Some(binding) = func.bindings.get(id) else {
            continue;
        };
        match &binding.expr {
            Expr::Store { addr, value, offset, .. } if resolve_use(func, *addr) == out => {
                slots.entry(*offset).or_default().push(*value);
            }
            other => {
                let mut escapes = false;
                other.for_each_value_use(|u| {
                    if resolve_use(func, u) == out {
                        escapes = true;
                    }
                });
                if escapes {
                    return None;
                }
                let effects = expr_effects(other);
                if effects.reads_host || effects.writes_host {
                    return None;
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
    if region_reads || slots.len() < 3 {
        return None;
    }

    let tags = tested_tags(func, val);
    let ty = KnownType128::of_tags(&tags)?;
    if tags.is_empty() {
        return None;
    }

    let (mut disc, mut lo, mut hi) = (None, None, None);
    for (offset, values) in &slots {
        let roles: Vec<Limb> = values.iter().map(|v| limb_of(func, *v, val, 2)).collect();
        if roles.iter().all(|r| *r == Limb::Const)
            && values.iter().any(|v| has_zero_arm(func, *v))
            && values.iter().all(|v| all_arms_are_flags(func, *v))
        {
            if disc.replace(*offset).is_some() {
                return None;
            }
        } else if roles.iter().all(|r| matches!(r, Limb::Lo(_))) {
            if !roles.iter().all(|r| matches!(r, Limb::Lo(None | Some(_)) if limb_ty(*r).is_none_or(|t| t == ty))) {
                return None;
            }
            if lo.replace(*offset).is_some() {
                return None;
            }
        } else if roles.iter().all(|r| matches!(r, Limb::Hi(_))) {
            if !roles.iter().all(|r| limb_ty(*r).is_none_or(|t| t == ty)) {
                return None;
            }
            if hi.replace(*offset).is_some() {
                return None;
            }
        } else if roles.iter().all(|r| *r == Limb::Const) {
            // The error `Val`, written on the Err path only.
        } else {
            return None;
        }
    }
    Some(WideDecoder {
        disc: disc?,
        lo: lo?,
        hi: hi?,
        ty: ty.known(),
        tags,
    })
}

fn limb_ty(limb: Limb) -> Option<KnownType128> {
    match limb {
        Limb::Lo(t) | Limb::Hi(t) => t,
        _ => None,
    }
}

/// Classify one stored value. Recurses through a phi so a merged Ok path
/// still reads as one limb.
fn limb_of(func: &HighFunction, value: ValueId, val: ValueId, depth: u32) -> Limb {
    let id = resolve_use(func, value);
    let Some(binding) = func.bindings.get(id) else {
        return Limb::Other;
    };
    let from_val = |v: ValueId| resolve_use(func, v) == val;
    match &binding.expr {
        Expr::Literal(_) => Limb::Const,
        Expr::Semantic(SemanticOp::Known(KnownOp::ValDecodeSmall { value })) if from_val(*value) => {
            Limb::Lo(None)
        }
        Expr::Semantic(SemanticOp::Known(KnownOp::ValObject { kind, args }))
            if args.len() == 1 && from_val(args[0]) =>
        {
            match kind {
                ValObjectKind::ObjToI128Lo64 => Limb::Lo(Some(KnownType128::I128)),
                ValObjectKind::ObjToU128Lo64 => Limb::Lo(Some(KnownType128::U128)),
                ValObjectKind::ObjToI128Hi64 => Limb::Hi(Some(KnownType128::I128)),
                ValObjectKind::ObjToU128Hi64 => Limb::Hi(Some(KnownType128::U128)),
                _ => Limb::Other,
            }
        }
        Expr::Binary { op: BinaryOp::Shr, lhs, rhs }
            if from_val(*lhs) && trace_int(func, *rhs) == Some(63) =>
        {
            Limb::Hi(None)
        }
        Expr::Phi { incoming } if depth > 0 && !incoming.is_empty() => {
            let mut roles = incoming.iter().map(|(_, v)| limb_of(func, *v, val, depth - 1));
            let first = roles.next().unwrap_or(Limb::Other);
            if roles.all(|r| r == first) { first } else { Limb::Other }
        }
        _ => Limb::Other,
    }
}

/// Whether every arm of `value` is `0` or `1` — a `Result` discriminant.
fn all_arms_are_flags(func: &HighFunction, value: ValueId) -> bool {
    match arms_of(func, value) {
        Some(values) if !values.is_empty() => {
            values.iter().all(|v| matches!(trace_int(func, *v), Some(0 | 1)))
        }
        _ => false,
    }
}

fn has_zero_arm(func: &HighFunction, value: ValueId) -> bool {
    arms_of(func, value).is_some_and(|vs| vs.iter().any(|v| trace_int(func, *v) == Some(0)))
}

/// The per-path values of `value`: a phi's incoming values, or itself.
fn arms_of(func: &HighFunction, value: ValueId) -> Option<Vec<ValueId>> {
    let id = resolve_use(func, value);
    let binding = func.bindings.get(id)?;
    Some(match &binding.expr {
        Expr::Phi { incoming } => incoming.iter().map(|(_, v)| *v).collect(),
        _ => vec![id],
    })
}

/// Every tag tested against `param` in this function.
fn tested_tags(func: &HighFunction, param: ValueId) -> Vec<u8> {
    let mut tags = Vec::new();
    for (_, binding) in func.bindings.iter() {
        if let Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck { value, tag, .. })) =
            &binding.expr
            && resolve_use(func, *value) == param
            && !tags.contains(tag)
        {
            tags.push(*tag);
        }
    }
    tags
}

fn classify_encoder(func: &HighFunction) -> Option<WideEncoder> {
    classify_encoder_inner(func)
}

fn classify_encoder_inner(func: &HighFunction) -> Option<WideEncoder> {
    if func.params.len() != 2 {
        return None;
    }
    // Two components (status, `Val`), or the `Val` alone — a shape the
    // multi-value analysis leaves to ordinary returns, so read here.
    let single: Option<Vec<ValueId>> = if func.signature.is_none() {
        let mut values = Vec::new();
        let mut ok = true;
        func.region.for_each_node(|node| {
            if let sordec_ir::Region::Return { values: v } = node {
                match v.as_slice() {
                    [one] => values.push(*one),
                    _ => ok = false,
                }
            }
        });
        (ok && !values.is_empty()).then_some(values)
    } else {
        None
    };
    let shape = sret::analyze_returns(func);
    if shape.as_ref().is_some_and(|s| s.arity() != 2) || (shape.is_none() && single.is_none()) {
        return None;
    }
    for id in sret::emission_order(func) {
        if let Some(b) = func.bindings.get(id) {
            let e = expr_effects(&b.expr);
            if e.reads_host || e.writes_host {
                return None;
            }
        }
    }
    let all_zero = |index: usize| {
        shape
            .as_ref()
            .and_then(|s| s.component(index))
            .is_some_and(|vs| vs.iter().all(|v| trace_int(func, *v) == Some(0)))
    };
    let (disc_index, payload_index) = if shape.is_none() {
        (None, 0)
    } else {
        match (all_zero(0), all_zero(1)) {
            (true, false) => (Some(0), 1),
            (false, true) => (Some(1), 0),
            _ => return None,
        }
    };
    let (p0, p1) = (func.params[0], func.params[1]);

    // Every arm of the payload is one of the two encodings of the same
    // wide value. The object constructor's argument order — `(hi, lo)` in
    // the host ABI — is what says which parameter is which limb; the small
    // encoding takes the low limb alone and must agree.
    let mut ty: Option<KnownType128> = None;
    let mut lo: Option<ValueId> = None;
    let mut hi: Option<ValueId> = None;
    let mut arms: Vec<ValueId> = Vec::new();
    let payloads: Vec<ValueId> = match &shape {
        Some(s) => s.component(payload_index)?,
        None => single?,
    };
    for v in payloads {
        arms.extend(arms_of(func, v)?);
    }
    if arms.is_empty() {
        return None;
    }
    for arm in arms {
        match &func.bindings.get(arm)?.expr {
            Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty: t, value })) => {
                let t = match t {
                    KnownType::I128 => KnownType128::I128,
                    KnownType::U128 => KnownType128::U128,
                    _ => return None,
                };
                if ty.replace(t).is_some_and(|prev| prev != t) {
                    return None;
                }
                let v = resolve_use(func, *value);
                if v != p0 && v != p1 {
                    return None;
                }
                if lo.replace(v).is_some_and(|prev| prev != v) {
                    return None;
                }
            }
            Expr::Semantic(SemanticOp::Known(KnownOp::ValObject { kind, args })) if args.len() == 2 => {
                let t = match kind {
                    ValObjectKind::ObjFromI128Pieces => KnownType128::I128,
                    ValObjectKind::ObjFromU128Pieces => KnownType128::U128,
                    _ => return None,
                };
                if ty.replace(t).is_some_and(|prev| prev != t) {
                    return None;
                }
                let (h, l) = (resolve_use(func, args[0]), resolve_use(func, args[1]));
                if !((h == p0 && l == p1) || (h == p1 && l == p0)) {
                    return None;
                }
                if hi.replace(h).is_some_and(|prev| prev != h) || lo.replace(l).is_some_and(|prev| prev != l) {
                    return None;
                }
            }
            _ => return None,
        }
    }
    let ty = ty?;
    let lo = lo?;
    let hi = hi.unwrap_or(if lo == p0 { p1 } else { p0 });
    if lo == hi {
        return None;
    }
    Some(WideEncoder {
        lo_index: usize::from(lo == p1),
        hi_index: usize::from(hi == p1),
        disc_index,
        payload_index,
        ty: ty.known(),
    })
}

// ---------------------------------------------------------------------
// Call-site planning
// ---------------------------------------------------------------------

/// A decode whose four-slot result is currently live in the caller's frame.
struct Frame<'a> {
    base: ValueId,
    start: u32,
    call: ValueId,
    val: ValueId,
    evidence: IrType,
    dec: &'a WideDecoder,
    consumed: bool,
    /// A load of this frame the decode does not dominate was left as a
    /// load, so the call that writes it must stay.
    kept_load: bool,
}

/// For every block, the conditional arms around it, outermost first: each
/// `if` branch, switch arm, loop body and scope body (a `break` can leave
/// one early) is one arm. Block `a` is reached on every path to a later
/// block `b` when `a`'s arms are a prefix of `b`'s — the structured form
/// of dominance, over a region tree with no other way to skip code.
fn arm_paths(func: &HighFunction) -> HashMap<sordec_common::BlockId, Vec<u32>> {
    fn walk(r: &Region, path: &mut Vec<u32>, next: &mut u32, out: &mut HashMap<sordec_common::BlockId, Vec<u32>>) {
        let arm = |r: &Region, path: &mut Vec<u32>, next: &mut u32, out: &mut HashMap<_, _>| {
            path.push(*next);
            *next += 1;
            walk(r, path, next, out);
            path.pop();
        };
        match r {
            Region::Basic(b) => {
                out.insert(*b, path.clone());
            }
            Region::Sequence(items) => items.iter().for_each(|i| walk(i, path, next, out)),
            Region::Scope { body, .. } | Region::Loop { body, .. } => arm(body, path, next, out),
            Region::If { then_region, else_region, .. } => {
                arm(then_region, path, next, out);
                if let Some(e) = else_region {
                    arm(e, path, next, out);
                }
            }
            Region::Switch { arms, default, .. } => {
                for a in arms {
                    arm(&a.body, path, next, out);
                }
                arm(default, path, next, out);
            }
            _ => {}
        }
    }
    let mut out = HashMap::new();
    walk(&func.region, &mut Vec::new(), &mut 0, &mut out);
    out
}

/// Every collapse in one caller, plus the values whose type the decode
/// proved.
fn plan_decodes(
    func: &HighFunction,
    decoders: &HashMap<FuncId, WideDecoder>,
) -> (Vec<Elision>, Vec<(ValueId, IrType)>) {
    let mut elisions = Vec::new();
    let mut typed = Vec::new();
    if decoders.is_empty() {
        return (elisions, typed);
    }
    let paths = arm_paths(func);
    let block_of: HashMap<ValueId, sordec_common::BlockId> = func
        .blocks
        .iter()
        .flat_map(|(b, block)| block.bindings.iter().map(move |v| (*v, b)))
        .collect();
    let arms = |v: ValueId| block_of.get(&v).and_then(|b| paths.get(b));
    let dominates = |call: ValueId, load: ValueId| match (arms(call), arms(load)) {
        (Some(c), Some(l)) => l.starts_with(c),
        _ => false,
    };
    let mut active: Vec<Frame<'_>> = Vec::new();
    let mut finished: Vec<Frame<'_>> = Vec::new();
    let overlaps = |f: &Frame<'_>, base: ValueId, off: u32| {
        f.base == base && off >= f.start && off < f.start + RESULT_BYTES
    };

    for id in sret::emission_order(func) {
        let Some(binding) = func.bindings.get(id) else {
            continue;
        };
        match &binding.expr {
            Expr::Call { target, args } => {
                // Any argument aliasing a tracked result region ends that
                // tracking: the callee may write through it.
                for a in args {
                    let (b, o) = canon_addr(func, *a);
                    let (dropped, kept): (Vec<_>, Vec<_>) =
                        active.drain(..).partition(|f| overlaps(f, b, o));
                    active = kept;
                    finished.extend(dropped);
                }
                let Some(dec) = decoders.get(target) else {
                    continue;
                };
                if args.len() != 2 {
                    continue;
                }
                let val = resolve_use(func, args[1]);
                let Some(evidence) = value_evidence(func, val, &dec.ty, &dec.tags) else {
                    continue;
                };
                let (base, start) = canon_addr(func, args[0]);
                active.push(Frame { base, start, call: id, val, evidence, dec, consumed: false, kept_load: false });
            }
            Expr::Load { addr, offset, .. } => {
                let (b, o) = canon_addr(func, *addr);
                let o = o.wrapping_add(*offset);
                let Some(frame) = active.iter_mut().find(|f| overlaps(f, b, o)) else {
                    continue;
                };
                if !dominates(frame.call, id) {
                    frame.kept_load = true;
                    continue;
                }
                let rel = o - frame.start;
                let (expr, ty, note) = if rel == frame.dec.disc {
                    (
                        Expr::Literal(ok_discriminant(&binding.ty)),
                        None,
                        "wide decode discriminant is Ok: the value was validated at its boundary",
                    )
                } else if rel == frame.dec.lo {
                    (
                        Expr::Unary { op: UnaryOp::WideLo, value: frame.val },
                        Some(IrType::Inferred(KnownType::I64)),
                        "low limb of a wide argument decode, collapsed to the value",
                    )
                } else if rel == frame.dec.hi {
                    (
                        Expr::Unary { op: UnaryOp::WideHi, value: frame.val },
                        Some(IrType::Inferred(KnownType::I64)),
                        "high limb of a wide argument decode, collapsed to the value",
                    )
                } else {
                    // The error slot: only read on the Err path, which the
                    // Ok discriminant has just made unreachable.
                    continue;
                };
                frame.consumed = true;
                elisions.push(Elision {
                    id,
                    expr,
                    ty,
                    note: note.to_string(),
                    metric: metrics::WIDE_DECODE_COLLAPSED,
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

    // A frame whose slot a later load may still read uncollapsed keeps its
    // call: that load reads what the call writes. A load is past this
    // frame's reach when another write of the slot — a decode call handed
    // it, or a store into it — falls between the two and dominates the
    // load, so that every path to the load rewrites the slot first. Slots
    // are reused across decodes in a straight line, and that is the case
    // this lets through; `account`'s two arms writing one slot before a
    // join is the case it stops.
    let order: HashMap<ValueId, usize> =
        sret::emission_order(func).into_iter().enumerate().map(|(i, v)| (v, i)).collect();
    let collapsed: std::collections::HashSet<ValueId> = elisions.iter().map(|e| e.id).collect();
    let writes = |f: &Frame<'_>, id: ValueId, b: &Binding| match &b.expr {
        Expr::Call { args, .. } => args.iter().any(|a| {
            let (base, o) = canon_addr(func, *a);
            overlaps(f, base, o)
        }),
        Expr::Store { addr, offset, .. } => {
            let (base, o) = canon_addr(func, *addr);
            id != f.call && overlaps(f, base, o.wrapping_add(*offset))
        }
        _ => false,
    };
    let read_later = |f: &Frame<'_>| {
        let at = |v: ValueId| order.get(&v).copied();
        func.bindings.iter().any(|(load, b)| {
            let Expr::Load { addr, offset, .. } = &b.expr else {
                return false;
            };
            let (base, o) = canon_addr(func, *addr);
            if !overlaps(f, base, o.wrapping_add(*offset)) || collapsed.contains(&load) || at(load) <= at(f.call) {
                return false;
            }
            let covered = func.bindings.iter().any(|(w, wb)| {
                w != f.call
                    && at(w) > at(f.call)
                    && at(w) < at(load)
                    && writes(f, w, wb)
                    && dominates(w, load)
            });
            !covered
        })
    };
    for frame in finished.into_iter().filter(|f| f.consumed && !f.kept_load && !read_later(f)) {
        elisions.push(Elision {
            id: frame.call,
            expr: Expr::Literal(Literal::Unit),
            ty: Some(IrType::Known(KnownType::Unit)),
            note: format!(
                "call to a wide argument-decode helper ({}), elided with its results",
                tag_list(&frame.dec.tags)
            ),
            metric: metrics::WIDE_CODEC_CALLS_ELIDED,
        });
        if func.bindings.get(frame.val).is_some_and(|b| b.ty != frame.evidence) {
            typed.push((frame.val, frame.evidence));
        }
    }
    (elisions, typed)
}

/// Why the caller may treat `val` as already being the decoded value.
///
/// An entrypoint parameter declared with the codec's type carries the
/// host's validation; a host operation's result carries the decode
/// itself as evidence of what was stored. Anything else has no boundary
/// to relocate the check to.
fn value_evidence(func: &HighFunction, val: ValueId, ty: &KnownType, tags: &[u8]) -> Option<IrType> {
    if let Some(declared) = declared_param_type(func, val) {
        if declared == *ty && tags.iter().all(|t| val_abi::tag_carries(*t, &declared)) {
            return Some(IrType::Known(declared));
        }
        return None;
    }
    let binding = func.bindings.get(val)?;
    // Already proven wide by another elision — a field of a recovered
    // struct, or a helper parameter its caller typed.
    if let IrType::Known(known) = &binding.ty
        && known == ty
    {
        return Some(IrType::Known(ty.clone()));
    }
    match &binding.expr {
        Expr::Semantic(SemanticOp::Known(_)) | Expr::Field { .. } => Some(IrType::Known(ty.clone())),
        _ => None,
    }
}

/// The `contractspecv0` type of `value`, when it is one of this
/// entrypoint's parameters.
fn declared_param_type(func: &HighFunction, value: ValueId) -> Option<KnownType> {
    let sig = func.signature.as_ref()?;
    let index = func.params.iter().position(|p| *p == value)?;
    known_of_type_ref(&sig.inputs.get(index)?.ty)
}

/// A zero discriminant in the width the load claimed.
fn ok_discriminant(ty: &IrType) -> Literal {
    match ty {
        IrType::Known(KnownType::I64 | KnownType::U64)
        | IrType::Inferred(KnownType::I64 | KnownType::U64) => Literal::I64(0),
        _ => Literal::I32(0),
    }
}

fn tag_list(tags: &[u8]) -> String {
    tags.iter()
        .map(|t| val_abi::tag_name(*t).unwrap_or("?"))
        .collect::<Vec<_>>()
        .join("/")
}

// ---------------------------------------------------------------------
// Encode rewriting
// ---------------------------------------------------------------------

/// Rewrite every call to a wide encoder in `func`; returns how many.
fn rewrite_encodes(func: &mut HighFunction, encoders: &HashMap<FuncId, WideEncoder>) -> i64 {
    if encoders.is_empty() {
        return 0;
    }
    let sites: Vec<(ValueId, WideEncoder, Vec<ValueId>)> = func
        .bindings
        .iter()
        .filter_map(|(id, b)| match &b.expr {
            Expr::Call { target, args } if args.len() == 2 => {
                encoders.get(target).map(|e| (id, e.clone(), args.clone()))
            }
            _ => None,
        })
        .collect();
    let mut count = 0;
    for (call, enc, args) in sites {
        // A helper returning the encoded `Val` alone: the call *is* the
        // value, joined from the limbs it was handed.
        if enc.disc_index.is_none() {
            if let Some(b) = func.bindings.get_mut(call) {
                b.expr = Expr::WideJoin { lo: args[enc.lo_index], hi: args[enc.hi_index] };
                b.ty = IrType::Known(enc.ty.clone());
                b.add_provenance(Provenance::new(
                    PASS_NAME,
                    ProvenanceSource::SdkPattern,
                    "call to a wide IntoVal helper: the value it encodes, joined from its limbs",
                ));
            }
            count += 1;
            continue;
        }
        let projections: Vec<(ValueId, u32)> = func
            .bindings
            .iter()
            .filter_map(|(id, b)| match &b.expr {
                Expr::Project { value, index } if resolve_use(func, *value) == call => Some((id, *index)),
                _ => None,
            })
            .collect();
        let joined = ValueId::from_index(func.bindings.len() as u32);
        func.bindings.push(Binding::new(
            joined,
            IrType::Known(enc.ty.clone()),
            Expr::WideJoin { lo: args[enc.lo_index], hi: args[enc.hi_index] },
            Provenance::new(
                PASS_NAME,
                ProvenanceSource::SdkPattern,
                "the wide value an IntoVal helper encoded, joined from its limbs",
            ),
        ));
        for (_, block) in func.blocks.iter_mut() {
            if let Some(pos) = block.bindings.iter().position(|v| *v == call) {
                block.bindings.insert(pos, joined);
                break;
            }
        }
        for (id, index) in projections {
            let Some(b) = func.bindings.get_mut(id) else { continue };
            if Some(index as usize) == enc.disc_index {
                b.expr = Expr::Literal(Literal::I64(0));
                b.add_provenance(Provenance::new(
                    PASS_NAME,
                    ProvenanceSource::SdkPattern,
                    "IntoVal status: the wide encoding cannot fail",
                ));
            } else if index as usize == enc.payload_index {
                b.expr = Expr::Use(joined);
                b.ty = IrType::Known(enc.ty.clone());
                b.add_provenance(Provenance::new(
                    PASS_NAME,
                    ProvenanceSource::SdkPattern,
                    "wide value encode collapsed to the value",
                ));
            }
        }
        if let Some(b) = func.bindings.get_mut(call) {
            b.expr = Expr::Literal(Literal::Unit);
            b.add_provenance(Provenance::new(
                PASS_NAME,
                ProvenanceSource::SdkPattern,
                "call to a wide IntoVal helper, elided with its results",
            ));
        }
        count += 1;
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, load, module, store, v};
    use sordec_common::{BlockId, IrId};
    use sordec_ir::{FunctionParam, FunctionSignature, PrimitiveType, Region, TypeRef};

    fn tag_check(value: ValueId, tag: u8) -> Expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck { value, tag, negated: false }))
    }
    fn obj(kind: ValObjectKind, args: Vec<ValueId>) -> Expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::ValObject { kind, args }))
    }
    fn lit(n: i64) -> Expr {
        Expr::Literal(Literal::I64(n))
    }

    /// token-v23's `func15`: `i128::try_from_val`. Object path stores the
    /// two pieces; small path stores the decode and its sign extension;
    /// the Err path stores the error `Val`; the discriminant is a phi.
    fn i128_decoder(id: u32) -> HighFunction {
        let bb = |i: u32| BlockId::from_index(i);
        let mut f = func_with(
            vec![
                Expr::Phi { incoming: vec![] },                                   // v0 out
                Expr::Phi { incoming: vec![] },                                   // v1 val
                tag_check(v(1), val_abi::TAG_I128_OBJECT),                        // v2
                obj(ValObjectKind::ObjToI128Hi64, vec![v(1)]),                    // v3
                obj(ValObjectKind::ObjToI128Lo64, vec![v(1)]),                    // v4
                store(v(0), v(3), 24),                                            // v5
                store(v(0), v(4), 16),                                            // v6
                tag_check(v(1), val_abi::TAG_I128_SMALL),                         // v7
                lit(63),                                                          // v8
                Expr::Binary { op: BinaryOp::Shr, lhs: v(1), rhs: v(8) },         // v9
                Expr::Semantic(SemanticOp::Known(KnownOp::ValDecodeSmall { value: v(1) })), // v10
                store(v(0), v(9), 24),                                            // v11
                store(v(0), v(10), 16),                                           // v12
                lit(34_359_740_419),                                              // v13 error Val
                store(v(0), v(13), 8),                                            // v14
                lit(0),                                                           // v15
                lit(1),                                                           // v16
                Expr::Phi { incoming: vec![(bb(1), v(15)), (bb(2), v(15)), (bb(3), v(16))] }, // v17
                store(v(0), v(17), 0),                                            // v18
            ],
            vec![v(0), v(1)],
            vec![2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18],
        );
        f.id = FuncId::from_index(id);
        f
    }

    /// An entrypoint `mint(amount: i128)` decoding through a 32-byte frame
    /// at `fp+8`, then reading all three live slots.
    fn caller(id: u32, decoder: u32, declared: PrimitiveType) -> HighFunction {
        let mut f = func_with(
            vec![
                Expr::Phi { incoming: vec![] },                                // v0 amount
                Expr::Phi { incoming: vec![] },                                // v1 fp
                Expr::Literal(Literal::I32(8)),                                // v2
                Expr::Binary { op: BinaryOp::Add, lhs: v(1), rhs: v(2) },      // v3 fp+8
                Expr::Call { target: FuncId::from_index(decoder), args: vec![v(3), v(0)] }, // v4
                load(v(1), 8),                                                 // v5 disc  (fp+8+0)
                load(v(1), 24),                                                // v6 lo    (fp+8+16)
                load(v(3), 24),                                                // v7 hi    (fp+8+24)
            ],
            vec![v(0)],
            vec![2, 3, 4, 5, 6, 7],
        );
        f.id = FuncId::from_index(id);
        f.signature = Some(FunctionSignature {
            name: "mint".to_string(),
            inputs: vec![FunctionParam { name: "amount".to_string(), ty: TypeRef::Primitive(declared) }],
            outputs: vec![],
        });
        f
    }

    fn expr_at(ir: &HighIr, func: u32, value: u32) -> &Expr {
        &ir.function(FuncId::from_index(func)).unwrap().bindings.get(v(value)).unwrap().expr
    }

    #[test]
    fn the_i128_decoder_is_classified() {
        let d = classify_decoder(&i128_decoder(0)).expect("decoder");
        assert_eq!((d.disc, d.lo, d.hi), (0, 16, 24));
        assert_eq!(d.ty, KnownType::I128);
    }

    #[test]
    fn a_decoder_reading_storage_is_not_marshalling() {
        let mut f = i128_decoder(0);
        f.bindings.get_mut(v(13)).unwrap().expr = Expr::Semantic(SemanticOp::Known(KnownOp::StorageHas {
            tier: sordec_ir::StorageTier::Known(sordec_ir::KnownTier::Instance),
            durability: v(1),
            key: v(1),
            resolved_key: None,
            probe: false,
        }));
        assert!(classify_decoder(&f).is_none());
    }

    #[test]
    fn a_declared_i128_argument_collapses_to_its_limbs() {
        let mut m = module(vec![i128_decoder(0), caller(1, 0, PrimitiveType::I128)]);
        let r = WideCodecPass.run(&mut m);
        assert!(r.changed);
        assert!(matches!(expr_at(&m, 1, 5), Expr::Literal(Literal::I32(0))));
        assert!(matches!(expr_at(&m, 1, 6), Expr::Unary { op: UnaryOp::WideLo, value } if *value == v(0)));
        assert!(matches!(expr_at(&m, 1, 7), Expr::Unary { op: UnaryOp::WideHi, value } if *value == v(0)));
        assert!(matches!(expr_at(&m, 1, 4), Expr::Literal(Literal::Unit)));
        assert_eq!(r.metrics.get(metrics::WIDE_CODEC_CALLS_ELIDED), Some(1));
    }

    /// `account`: the decode runs on one arm of an `if`, and its slots are
    /// read after the join, on paths where it never ran. Those loads are not
    /// its value, so nothing collapses and the call stays.
    #[test]
    fn a_decode_on_one_arm_does_not_collapse_a_load_after_the_join() {
        let mut f = caller(1, 0, PrimitiveType::I128);
        f.blocks.get_mut(BlockId::from_index(0)).unwrap().bindings = vec![v(2), v(3)];
        f.blocks.push(sordec_ir::HighBlock { id: BlockId::from_index(1), bindings: vec![v(4)] });
        f.blocks.push(sordec_ir::HighBlock { id: BlockId::from_index(2), bindings: vec![v(5), v(6), v(7)] });
        f.region = Region::Sequence(vec![
            Region::Basic(BlockId::from_index(0)),
            Region::If {
                cond: v(2),
                then_region: Box::new(Region::Basic(BlockId::from_index(1))),
                else_region: None,
            },
            Region::Basic(BlockId::from_index(2)),
        ]);
        let mut m = module(vec![i128_decoder(0), f]);
        WideCodecPass.run(&mut m);
        assert!(matches!(expr_at(&m, 1, 6), Expr::Load { .. }), "{:?}", expr_at(&m, 1, 6));
        assert!(matches!(expr_at(&m, 1, 4), Expr::Call { .. }), "the call still writes the slot");
    }

    /// The declared type is the licence. A `u64` argument fed to an
    /// `i128` decoder means our picture is wrong, so nothing moves.
    #[test]
    fn a_mismatched_declaration_declines() {
        let mut m = module(vec![i128_decoder(0), caller(1, 0, PrimitiveType::U64)]);
        assert!(!WideCodecPass.run(&mut m).changed);
        assert!(matches!(expr_at(&m, 1, 4), Expr::Call { .. }));
    }

    /// A `Val` of unknown provenance has no boundary to relocate the check to.
    #[test]
    fn an_unproven_value_declines() {
        let mut m = module(vec![i128_decoder(0), caller(1, 0, PrimitiveType::I128)]);
        m.functions[1].signature = None;
        assert!(!WideCodecPass.run(&mut m).changed);
    }

    /// token-v23's `func19`: `i128::into_val` as `(status, Val)`.
    fn i128_encoder(id: u32) -> HighFunction {
        let bb = |i: u32| BlockId::from_index(i);
        let mut f = func_with(
            vec![
                Expr::Phi { incoming: vec![] },                                   // v0 lo
                Expr::Phi { incoming: vec![] },                                   // v1 hi
                Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty: KnownType::I128, value: v(0) })), // v2
                obj(ValObjectKind::ObjFromI128Pieces, vec![v(1), v(0)]),          // v3
                Expr::Phi { incoming: vec![(bb(1), v(2)), (bb(2), v(3))] },        // v4
                lit(0),                                                           // v5
            ],
            vec![v(0), v(1)],
            vec![2, 3, 5],
        );
        f.id = FuncId::from_index(id);
        f.region = Region::Sequence(vec![
            Region::Basic(BlockId::from_index(0)),
            Region::Return { values: vec![v(5), v(4)] },
        ]);
        f
    }

    fn encode_caller(id: u32, encoder: u32) -> HighFunction {
        let mut f = func_with(
            vec![
                Expr::Phi { incoming: vec![] }, // v0 lo
                Expr::Phi { incoming: vec![] }, // v1 hi
                Expr::Call { target: FuncId::from_index(encoder), args: vec![v(0), v(1)] }, // v2
                Expr::Project { value: v(2), index: 0 }, // v3 status
                Expr::Project { value: v(2), index: 1 }, // v4 val
            ],
            vec![v(0), v(1)],
            vec![2, 3, 4],
        );
        f.id = FuncId::from_index(id);
        f
    }

    #[test]
    fn the_i128_encoder_is_classified() {
        let e = classify_encoder(&i128_encoder(0)).expect("encoder");
        assert_eq!((e.lo_index, e.hi_index, e.disc_index, e.payload_index), (0, 1, Some(0), 1));
        assert_eq!(e.ty, KnownType::I128);
    }

    #[test]
    fn an_encode_call_becomes_a_join() {
        let mut m = module(vec![i128_encoder(0), encode_caller(1, 0)]);
        let r = WideCodecPass.run(&mut m);
        assert!(r.changed);
        assert!(matches!(expr_at(&m, 1, 3), Expr::Literal(Literal::I64(0))));
        let Expr::Use(j) = expr_at(&m, 1, 4) else { panic!("payload should be the join") };
        assert!(matches!(expr_at(&m, 1, j.index()), Expr::WideJoin { lo, hi } if *lo == v(0) && *hi == v(1)));
        assert!(matches!(expr_at(&m, 1, 2), Expr::Literal(Literal::Unit)));
        let block = &m.functions[1].blocks.get(BlockId::from_index(0)).unwrap().bindings;
        assert!(block.iter().position(|x| *x == *j) < block.iter().position(|x| *x == v(2)));
    }

    #[test]
    fn the_pass_is_idempotent() {
        let mut m = module(vec![i128_decoder(0), caller(1, 0, PrimitiveType::I128), i128_encoder(2), encode_caller(3, 2)]);
        assert!(WideCodecPass.run(&mut m).changed);
        assert!(!WideCodecPass.run(&mut m).changed);
    }
}
