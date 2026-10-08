//! `Option<T>` returned through an out-parameter — the shape
//! [`crate::memory::sret`] and [`super::option_sret`] both refuse.
//!
//! # The shape
//!
//! A helper returning "a value, or nothing" hands it back through a
//! pointer to its caller's frame: a **tag** written on every path, the
//! **value** written only on the paths that have one. `account`'s
//! `BytesN<32>::try_from_val`:
//!
//! ```text
//! fn func2(out, v) {                       caller:
//!     if !is_bytes(v)       { t = 1 }          func2(fp, v)
//!     else if len(v) != 32  { t = 1 }          if load(fp+0) & 1 == 0 {
//!     else { store out+8 <- v; t = 0 }             use load(fp+8)
//!     store out+0 <- t                         }
//! }
//! ```
//!
//! `memory::sret` refuses it because the absent paths have no value to
//! return, and `option_sret` takes only storage reads whose caller
//! `unwrap()`s. `plan/NOTES.md` ("W4", 2026-08-06) records why a
//! placeholder for the missing value is not an answer: a `todo!()` traps on
//! a live path, and a zero is a claim about every caller. The answer is the
//! sum type the source wrote.
//!
//! # The rewrite
//!
//! The helper returns `Option<T>`: each path builds its `Some(..)` or
//! `None` where it leaves, the merged tag carries it to the one `return`,
//! and the writes through the out-pointer retire with the parameter. Each
//! caller stops passing its frame: a read of the tag becomes the tag read
//! back from `is_some()` (or the test itself, when it is only branched on),
//! and a read of the value becomes `unwrap()` — placed only where a test on
//! the tag proves it present, so it never traps.
//!
//! A signature changes, so it is every call site or none, and nothing when
//! the module has an indirect call. It runs after the elision group, so
//! [`super::option_sret`]'s `get(..).unwrap()` keeps every helper it can
//! take.
//!
//! # What makes a helper
//!
//! - Not exported (no spec signature).
//! - One parameter used only as a store address: the out-pointer.
//! - One store of the tag, after every arm has merged, of a phi whose
//!   inputs are all constants. Each arm that assigns the phi is a path to
//!   the result: the stores through the out-pointer on that path are its
//!   payload. Arms with a payload are *present*, arms without *absent*; one
//!   tag constant each, and different.
//! - Every present arm writes the same slots, and none of the values is a
//!   raw memory read: inside an `Option` its type would be pinned to a
//!   storage width the caller did not use.
//! - After the merge, nothing but the tag store, constant stores and the
//!   shadow-stack epilogue.
//!
//! # What makes a call site
//!
//! Every read of the result's slots after the call is one of them exactly,
//! is reached by this call and no other write, and — for a value read — sits
//! where a test on the tag proves it present. Any other use of the frame by
//! another call refuses the site: the rewrite stops writing that memory,
//! and a callee reading it would see something else.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

use sordec_common::{BlockId, FuncId, IrId, Provenance, ProvenanceSource, UnknownReason, ValueId};
use sordec_ir::{BinaryOp, Binding, Expr, HighFunction, HighIr, IrType, KnownType, Literal, Region, UnaryOp};

use super::sret::emission_order;
use crate::dataflow::{block_containing, canon_addr, resolve_use, trace_int};
use crate::effects::expr_effects;
use crate::metrics_catalog::{
    MARSHALLING_OPTIONAL_OUT_HELPERS as M_HELPERS, MARSHALLING_OPTIONAL_OUT_REWRITTEN as M_REWRITTEN,
    MARSHALLING_OPTIONAL_OUT_SITES as M_SITES, MARSHALLING_OPTIONAL_OUT_SITES_REFUSED as M_SITES_REFUSED,
};
use crate::pass::{Pass, PassResult};

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-optional-out";

/// How deep a tag test may be evaluated (`t & 1`, `== 0`, a rename, …).
const EVAL_DEPTH: usize = 6;

/// Rewrites `Option` out-parameter helpers to return `Option<T>`.
#[derive(Debug, Default, Clone, Copy)]
pub struct OptionalOutParamPass;

impl Pass<HighIr> for OptionalOutParamPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let mut helpers: HashMap<FuncId, Helper> = ir
            .functions
            .iter()
            .filter_map(|f| match classify(f) {
                Ok(h) => {
                    trace(f, "classified");
                    Some((f.id, h))
                }
                Err(why) => {
                    if why != NOT_A_CANDIDATE {
                        trace(f, why);
                    }
                    None
                }
            })
            .collect();
        result.metrics.increment(M_HELPERS, helpers.len() as i64);
        if helpers.is_empty() {
            return result;
        }
        let structs = ir.soroban_facts.as_ref().map(|f| f.types.structs.clone()).unwrap_or_default();
        for (id, helper) in &mut helpers {
            let (Some(parts), Some(func)) = (&helper.whole, ir.functions.iter().find(|f| f.id == *id)) else {
                continue;
            };
            let def = helper.arms.iter().find_map(|a| whole_of(func, a)).and_then(|base| {
                match &func.bindings.get(base)?.ty {
                    IrType::Known(KnownType::UserDefined(t)) | IrType::Inferred(KnownType::UserDefined(t)) => {
                        structs.iter().find(|s| s.id == *t)
                    }
                    _ => None,
                }
            });
            helper.part_types = parts
                .iter()
                .map(|(field, _)| {
                    let f = def?.fields.iter().find(|f| f.name == *field)?;
                    crate::type_infer::known_of_type_ref(&f.ty)
                })
                .collect();
        }

        // Census: every call site of every helper, planned or refused.
        let mut plans: HashMap<FuncId, Vec<(usize, SitePlan)>> = HashMap::new();
        let mut refused: HashSet<FuncId> = HashSet::new();
        {
            let frames = Frames { ir, helpers: &helpers, extents: RefCell::new(HashMap::new()) };
            for (index, caller) in ir.functions.iter().enumerate() {
                let order = emission_order(caller);
                for &id in &order {
                    let Some(Expr::Call { target, args }) = caller.bindings.get(id).map(|b| &b.expr) else {
                        continue;
                    };
                    let Some(helper) = helpers.get(target) else {
                        continue;
                    };
                    let planned = if *target == caller.id {
                        Err("the helper calls itself")
                    } else {
                        site(&frames, caller, &order, id, args, helper)
                    };
                    match planned {
                        Ok(plan) => {
                            trace(caller, &format!("site v{} -> func_{} ok", id.index(), target.index()));
                            result.metrics.increment(M_SITES, 1);
                            plans.entry(*target).or_default().push((index, plan));
                        }
                        Err(why) => {
                            trace(caller, &format!("site v{} -> func_{}: {why}", id.index(), target.index()));
                            result.metrics.increment(M_SITES_REFUSED, 1);
                            refused.insert(*target);
                        }
                    }
                }
            }
        }

        // The rewrite changes a signature, so it is every site or none. An
        // indirect call anywhere means callers this pass cannot see.
        let indirect = ir
            .functions
            .iter()
            .any(|f| f.bindings.iter().any(|(_, b)| matches!(b.expr, Expr::IndirectCall { .. })));
        if indirect {
            return result;
        }
        let mut targets: Vec<FuncId> = plans.keys().copied().filter(|t| !refused.contains(t)).collect();
        targets.sort_unstable();
        for target in targets {
            let helper = &helpers[&target];
            let Some(at) = ir.functions.iter().position(|f| f.id == target) else {
                continue;
            };
            let arity = ir.functions[at].params.len();
            for (index, plan) in &plans[&target] {
                if let Some(caller) = ir.functions.get_mut(*index) {
                    rewrite_site(caller, plan, helper);
                }
            }
            // A call no block schedules still names the old signature, and
            // the type pass reads every binding: drop its frame too.
            for func in &mut ir.functions {
                for (_, binding) in func.bindings.iter_mut() {
                    if let Expr::Call { target: t, args } = &mut binding.expr
                        && *t == target
                        && args.len() == arity
                    {
                        args.remove(helper.out);
                    }
                }
            }
            rewrite_helper(&mut ir.functions[at], helper);
            result.metrics.increment(M_REWRITTEN, 1);
            result.changed = true;
        }
        result
    }
}

/// Print a classification line when `SORDEC_OPTION_TRACE` is set — the
/// switch [`super::option_sret`] already reads.
#[allow(clippy::print_stderr)]
fn trace(func: &HighFunction, what: &str) {
    if std::env::var_os("SORDEC_OPTION_TRACE").is_some() {
        eprintln!("optional-out: func_{}: {what}", func.id.index());
    }
}

// ---------------------------------------------------------------------
// The helper
// ---------------------------------------------------------------------

/// No tag-shaped store at all: an ordinary function, not worth a line.
const NOT_A_CANDIDATE: &str = "no tag store";

/// One slot of the out-parameter, as an offset and a width in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct Slot {
    offset: u32,
    bytes: u32,
}

impl Slot {
    fn overlaps(self, other: Slot) -> bool {
        self.offset < other.offset + other.bytes && other.offset < self.offset + self.bytes
    }

    fn shifted(self, by: u32) -> Option<Slot> {
        Some(Slot { offset: self.offset.checked_add(by)?, bytes: self.bytes })
    }
}

/// A store through the out-pointer: the binding, its slot, the value.
type Store = (ValueId, Slot, ValueId);

/// One path to the result: the tag it sets, the stores on its way, and the
/// block it leaves from — where the rewrite builds its `Option`.
struct Arm {
    tag: i128,
    stores: Vec<Store>,
    pred: BlockId,
}

/// A helper proven to return `Option<T>` through an out-parameter.
struct Helper {
    /// Which parameter is the out-pointer.
    out: usize,
    tag: Slot,
    present: i128,
    absent: i128,
    /// The value's slots, ascending, each with the type stored there.
    payload: Vec<(Slot, IrType)>,
    /// Slots written with the same constant whatever the path.
    consts: Vec<(Slot, Literal)>,
    arms: Vec<Arm>,
    /// The merged tag, which becomes the returned `Option`.
    tag_phi: ValueId,
    /// Everything that writes through the out-pointer or computes an
    /// address into it, retired by the rewrite.
    retired: Vec<ValueId>,
    /// When every present arm writes nothing but fields of one struct
    /// value — a decoded `MinterConfig` copied out field by field, an
    /// `i128` field as its two halves — that struct is the payload, and
    /// each slot is a part of it: `(field, half)`, by payload component.
    whole: Option<Vec<(String, Option<UnaryOp>)>>,
    /// The declared type of each of those fields, filled from the spec.
    part_types: Vec<Option<KnownType>>,
}

impl Helper {
    fn slots(&self) -> impl Iterator<Item = Slot> + '_ {
        std::iter::once(self.tag)
            .chain(self.payload.iter().map(|(s, _)| *s))
            .chain(self.consts.iter().map(|(s, _)| *s))
    }
}

fn classify(func: &HighFunction) -> Result<Helper, &'static str> {
    if func.signature.is_some() {
        return Err(NOT_A_CANDIDATE);
    }
    let order = emission_order(func);

    // The tag store: through a parameter, of a phi of constants.
    let mut tag = None;
    for &id in &order {
        let Some(Expr::Store { addr, value, offset, width }) = func.bindings.get(id).map(|b| &b.expr) else {
            continue;
        };
        let (base, off) = canon_addr(func, *addr);
        let Some(out) = func.params.iter().position(|p| *p == base) else {
            continue;
        };
        let phi = resolve_use(func, *value);
        let Some(Expr::Phi { incoming }) = func.bindings.get(phi).map(|b| &b.expr) else {
            continue;
        };
        if incoming.is_empty() || !incoming.iter().all(|(_, v)| trace_int(func, *v).is_some()) {
            continue;
        }
        let slot = Slot { offset: off.checked_add(*offset).ok_or(NOT_A_CANDIDATE)?, bytes: width.bytes() };
        if tag.replace((id, out, base, phi, slot)).is_some() {
            return Err("two tag-shaped stores");
        }
    }
    let (tag_store, out, out_param, tag_phi, tag_slot) = tag.ok_or(NOT_A_CANDIDATE)?;
    if escapes(func, &order, out_param) {
        return Err("the out-pointer is used other than as a store address");
    }

    let mut walk = Walk {
        func,
        out_param,
        tag_store,
        tag_phi,
        join: None,
        arms: Vec::new(),
        pending: HashMap::new(),
        tail: None,
        last: None,
    };
    walk.region(&func.region, Flow::Falls(Vec::new()))?;
    let tail = walk.tail.ok_or("no merge after the arms")?;
    let Some(Expr::Phi { incoming }) = func.bindings.get(tag_phi).map(|b| &b.expr) else {
        return Err("the tag is not a phi");
    };
    let mut preds: Vec<BlockId> = walk.arms.iter().map(|a| a.pred).collect();
    let mut inputs: Vec<BlockId> = incoming.iter().map(|(b, _)| *b).collect();
    preds.sort_unstable();
    inputs.sort_unstable();
    if preds != inputs || preds.windows(2).any(|w| w[0] == w[1]) {
        return Err("the merge's inputs do not match its arms");
    }

    let (present, absent): (Vec<&Arm>, Vec<&Arm>) = walk.arms.iter().partition(|a| !a.stores.is_empty());
    let present_tag = single(present.iter().map(|a| a.tag)).ok_or("present arms disagree on the tag")?;
    let absent_tag = single(absent.iter().map(|a| a.tag)).ok_or("absent arms disagree on the tag")?;
    if present_tag == absent_tag {
        return Err("present and absent share a tag");
    }

    // Every present arm writes the same slots, once each, of known types.
    let mut payload: Vec<(Slot, IrType)> = Vec::new();
    for (i, arm) in present.iter().enumerate() {
        let mut slots: Vec<(Slot, IrType)> = Vec::new();
        for &(_, slot, value) in &arm.stores {
            if slots.iter().any(|(s, _)| s.overlaps(slot)) {
                return Err("an arm writes one slot twice");
            }
            if slot.overlaps(tag_slot) {
                return Err("a payload store overlaps the tag");
            }
            // Types are not a gate here: this runs before `type_infer`, so
            // most values are still untyped. The rewrite settles the
            // payload type after inference.
            let ty = func.bindings.get(value).map(|b| b.ty.clone()).ok_or("a stored value has no binding")?;
            slots.push((slot, ty));
        }
        slots.sort_by_key(|(s, _)| *s);
        if i == 0 {
            payload = slots;
        } else if slots.iter().map(|(s, _)| *s).ne(payload.iter().map(|(s, _)| *s)) {
            return Err("present arms write different slots");
        } else if slots
            .iter()
            .zip(&payload)
            .any(|((_, a), (_, b))| matches!((known(a), known(b)), (Some(x), Some(y)) if x != y))
        {
            return Err("present arms store different types in one slot");
        }
    }
    // A value read raw out of memory has no type of its own. As a hole it
    // takes whatever its use needs; inside an `Option` it is pinned to a
    // storage width (`i32` where the field is a `u32`, `Val` where it is a
    // limb), and the caller stops compiling. Left as it is until the
    // memory it comes from is recovered.
    let raw = |v: ValueId| {
        matches!(
            func.bindings.get(resolve_use(func, v)).map(|b| &b.expr),
            Some(Expr::Load { .. } | Expr::Unknown { .. })
        )
    };
    if present.iter().flat_map(|a| &a.stores).any(|(_, _, v)| raw(*v)) {
        return Err("a value read raw out of memory");
    }
    if tail.iter().any(|(s, _)| payload.iter().any(|(p, _)| p.overlaps(*s)) || s.overlaps(tag_slot)) {
        return Err("a constant store overlaps the result");
    }

    let whole = struct_parts(func, &present);
    let arms = walk.arms;
    let retired = order
        .iter()
        .copied()
        .filter(|id| match func.bindings.get(*id).map(|b| &b.expr) {
            Some(Expr::Store { addr, .. }) => canon_addr(func, *addr).0 == out_param,
            Some(Expr::Binary { op: BinaryOp::Add, .. }) => *id != out_param && canon_addr(func, *id).0 == out_param,
            _ => false,
        })
        .collect();
    Ok(Helper {
        out,
        tag: tag_slot,
        present: present_tag,
        absent: absent_tag,
        payload,
        consts: tail,
        arms,
        tag_phi,
        retired,
        whole,
        part_types: Vec::new(),
    })
}

/// A field of a struct value, or one half of a wide one: `(value, field,
/// half)`.
fn part_of(func: &HighFunction, value: ValueId) -> Option<(ValueId, String, Option<UnaryOp>)> {
    let field = |v: ValueId| match &func.bindings.get(resolve_use(func, v))?.expr {
        Expr::Field { base, field } => Some((resolve_use(func, *base), field.clone())),
        _ => None,
    };
    match &func.bindings.get(resolve_use(func, value))?.expr {
        Expr::Unary { op: op @ (UnaryOp::WideLo | UnaryOp::WideHi), value } => {
            field(*value).map(|(base, f)| (base, f, Some(*op)))
        }
        _ => field(value).map(|(base, f)| (base, f, None)),
    }
}

/// The parts of one struct value every present arm writes, in payload
/// order, when each arm writes nothing else — see [`Helper::whole`].
fn struct_parts(func: &HighFunction, present: &[&Arm]) -> Option<Vec<(String, Option<UnaryOp>)>> {
    let mut agreed: Option<Vec<(String, Option<UnaryOp>)>> = None;
    for arm in present {
        let mut stores = arm.stores.clone();
        stores.sort_by_key(|(_, slot, _)| *slot);
        let mut base: Option<ValueId> = None;
        let mut parts = Vec::new();
        for (_, _, value) in &stores {
            let (b, field, half) = part_of(func, *value)?;
            if base.replace(b).is_some_and(|prev| prev != b) {
                return None;
            }
            parts.push((field, half));
        }
        if agreed.replace(parts.clone()).is_some_and(|prev| prev != parts) {
            return None;
        }
    }
    agreed.filter(|p| !p.is_empty())
}

/// The struct value an arm's stores are parts of.
fn whole_of(func: &HighFunction, arm: &Arm) -> Option<ValueId> {
    arm.stores.first().and_then(|(_, _, v)| part_of(func, *v)).map(|(base, _, _)| base)
}

/// The one value an iterator yields, if it yields exactly one (repeats
/// allowed).
fn single(mut values: impl Iterator<Item = i128>) -> Option<i128> {
    let first = values.next()?;
    values.all(|v| v == first).then_some(first)
}

fn known(ty: &IrType) -> Option<&sordec_ir::KnownType> {
    match ty {
        IrType::Known(t) | IrType::Inferred(t) => Some(t),
        _ => None,
    }
}

/// Whether `param` is read by anything but the address of a store — or
/// address arithmetic feeding one.
fn escapes(func: &HighFunction, order: &[ValueId], param: ValueId) -> bool {
    let mut derived: HashSet<ValueId> = HashSet::from([param]);
    for &id in order {
        if let Some(Expr::Binary { op: BinaryOp::Add, lhs, rhs }) = func.bindings.get(id).map(|b| &b.expr)
            && derived.contains(&resolve_use(func, *lhs))
            && trace_int(func, *rhs).is_some()
        {
            derived.insert(id);
        }
    }
    let is_derived = |v: ValueId| derived.contains(&resolve_use(func, v));
    for &id in order {
        let Some(binding) = func.bindings.get(id) else {
            return true;
        };
        let fine = match &binding.expr {
            Expr::Store { value, .. } => !is_derived(*value),
            Expr::Binary { op: BinaryOp::Add, .. } if derived.contains(&id) => true,
            Expr::Use(v) if is_derived(*v) => {
                // A rename of an address is itself an address.
                true
            }
            other => {
                let mut reads = false;
                other.for_each_value_use(|u| reads |= is_derived(u));
                !reads
            }
        };
        if !fine {
            return true;
        }
    }
    let mut region_reads = false;
    func.region.for_each_value_use(|u| region_reads |= is_derived(u));
    region_reads
}

/// Where control can be at the end of a region, for the walk below.
#[derive(Debug, Clone, PartialEq)]
enum Flow {
    /// Falls through, having stored these through the out-pointer.
    Falls(Vec<Store>),
    /// Every path reached the merge, each recorded as an arm.
    Joined,
    /// No path continues (return, trap, a break recorded elsewhere).
    Leaves,
}

/// Join two flows that meet after a branch.
fn merge(a: Flow, b: Flow) -> Result<Flow, &'static str> {
    Ok(match (a, b) {
        (Flow::Leaves, x) | (x, Flow::Leaves) => x,
        (Flow::Joined, Flow::Joined) => Flow::Joined,
        (Flow::Joined, f @ Flow::Falls(_)) | (f @ Flow::Falls(_), Flow::Joined) => f,
        (Flow::Falls(a), Flow::Falls(b)) if a == b => Flow::Falls(a),
        (Flow::Falls(_), Flow::Falls(_)) => {
            return Err("a store through the out-pointer on one side of a branch that rejoins");
        }
    })
}

/// Walks the helper's region tree, recording each path to the merge.
struct Walk<'f> {
    func: &'f HighFunction,
    out_param: ValueId,
    tag_store: ValueId,
    tag_phi: ValueId,
    /// The block the tag phi belongs to, once an edge into it is seen.
    join: Option<BlockId>,
    arms: Vec<Arm>,
    /// Paths breaking to a scope that is not the merge, by its label.
    pending: HashMap<BlockId, Vec<Vec<Store>>>,
    /// The constant stores after the merge, once the merge is walked.
    tail: Option<Vec<(Slot, Literal)>>,
    /// The last block on the current path: the source of an edge met next.
    last: Option<BlockId>,
}

impl Walk<'_> {
    fn region(&mut self, region: &Region, flow: Flow) -> Result<Flow, &'static str> {
        let path = match flow {
            Flow::Falls(path) => path,
            // Only the merge's own block may follow the arms.
            Flow::Joined => {
                return match region {
                    Region::Basic(b) if Some(*b) == self.join => self.tail(*b),
                    Region::Return { values } if values.is_empty() && self.tail.is_some() => Ok(Flow::Leaves),
                    Region::Sequence(items) => {
                        let mut flow = Flow::Joined;
                        for item in items {
                            if flow == Flow::Leaves {
                                break;
                            }
                            flow = self.region(item, flow)?;
                        }
                        Ok(flow)
                    }
                    _ => Err("code between the arms and the merge"),
                };
            }
            Flow::Leaves => return Ok(Flow::Leaves),
        };
        match region {
            Region::Basic(b) => {
                if Some(*b) == self.join {
                    return Err("a path reaches the merge without setting the tag");
                }
                let mut path = path;
                self.last = Some(*b);
                for &id in &self.func.blocks.get(*b).ok_or("a missing block")?.bindings {
                    if let Some(store) = self.store(id)? {
                        path.push(store);
                    }
                }
                Ok(Flow::Falls(path))
            }
            Region::Sequence(items) => {
                let mut flow = Flow::Falls(path);
                for item in items {
                    if flow == Flow::Leaves {
                        break;
                    }
                    flow = self.region(item, flow)?;
                }
                Ok(flow)
            }
            Region::Scope { out, body } => {
                let body = self.region(body, Flow::Falls(path))?;
                let mut flow = body;
                for p in self.pending.remove(out).unwrap_or_default() {
                    flow = merge(flow, Flow::Falls(p))?;
                }
                self.last = None;
                Ok(flow)
            }
            Region::If { then_region, else_region, .. } => {
                let entry = self.last;
                let t = self.region(then_region, Flow::Falls(path.clone()))?;
                self.last = entry;
                let e = match else_region {
                    Some(e) => self.region(e, Flow::Falls(path))?,
                    None => Flow::Falls(path),
                };
                self.last = None;
                merge(t, e)
            }
            Region::Switch { arms, default, .. } => {
                let entry = self.last;
                let mut flow = self.region(default, Flow::Falls(path.clone()))?;
                for arm in arms {
                    self.last = entry;
                    let f = self.region(&arm.body, Flow::Falls(path.clone()))?;
                    flow = merge(flow, f)?;
                }
                self.last = None;
                Ok(flow)
            }
            Region::Break { target, transfer } | Region::Transfer { target, transfer } => {
                if let Some(&(_, v)) = transfer.iter().find(|(phi, _)| *phi == self.tag_phi) {
                    if self.join.is_some_and(|j| j != *target) {
                        return Err("the tag merges in two places");
                    }
                    self.join = Some(*target);
                    if transfer.len() != 1 {
                        return Err("the merge carries more than the tag");
                    }
                    let tag = trace_int(self.func, v).ok_or("the tag is not a constant")?;
                    let pred = self.last.ok_or("an edge into the merge from an unknown block")?;
                    self.arms.push(Arm { tag, stores: path, pred });
                    return Ok(Flow::Joined);
                }
                if Some(*target) == self.join {
                    return Err("an edge into the merge that does not set the tag");
                }
                if matches!(region, Region::Transfer { .. }) {
                    Ok(Flow::Falls(path))
                } else {
                    self.pending.entry(*target).or_default().push(path);
                    Ok(Flow::Leaves)
                }
            }
            Region::Loop { body, .. } => {
                if self.writes_inside(body) {
                    return Err("the out-pointer is written inside a loop");
                }
                self.last = None;
                Ok(Flow::Falls(path))
            }
            Region::Continue { .. } | Region::Panic { .. } | Region::Unreachable => Ok(Flow::Leaves),
            Region::Return { .. } => Err("a return before the tag is set"),
            Region::Unstructured { .. } => Err("unstructured control flow"),
        }
    }

    /// The merge block: the tag store, constant stores, and the epilogue.
    fn tail(&mut self, block: BlockId) -> Result<Flow, &'static str> {
        let mut consts = Vec::new();
        let mut tag_seen = false;
        for &id in &self.func.blocks.get(block).ok_or("a missing block")?.bindings {
            if id == self.tag_store {
                tag_seen = true;
                continue;
            }
            if let Some((_, slot, value)) = self.store(id)? {
                let lit = literal(self.func, value).ok_or("a store after the merge that is not a constant")?;
                consts.push((slot, lit));
                continue;
            }
            let expr = &self.func.bindings.get(id).ok_or("a missing binding")?.expr;
            let epilogue = matches!(expr, Expr::Unknown { op_kind: sordec_ir::WasmOpcodeKind::GlobalSet, .. });
            if !epilogue && !expr_effects(expr).is_pure_total() {
                return Err("the merge does more than finish the result");
            }
        }
        if !tag_seen {
            return Err("the tag is stored outside the merge");
        }
        self.tail = Some(consts);
        Ok(Flow::Joined)
    }

    /// The store through the out-pointer at `id`, if it is one.
    fn store(&self, id: ValueId) -> Result<Option<Store>, &'static str> {
        let Some(Expr::Store { addr, value, offset, width }) = self.func.bindings.get(id).map(|b| &b.expr) else {
            return Ok(None);
        };
        let (base, off) = canon_addr(self.func, *addr);
        if base != self.out_param {
            return Ok(None);
        }
        if id == self.tag_store {
            return Err("the tag is stored before the merge");
        }
        let offset = off.checked_add(*offset).ok_or("an offset overflows")?;
        Ok(Some((id, Slot { offset, bytes: width.bytes() }, resolve_use(self.func, *value))))
    }

    fn writes_inside(&self, region: &Region) -> bool {
        let mut writes = false;
        region.for_each_node(|node| {
            if let Region::Basic(b) = node
                && let Some(block) = self.func.blocks.get(*b)
            {
                writes |= block.bindings.iter().any(|id| matches!(self.store(*id), Ok(Some(_)) | Err(_)));
            }
        });
        writes
    }
}

fn literal(func: &HighFunction, value: ValueId) -> Option<Literal> {
    match &func.bindings.get(resolve_use(func, value))?.expr {
        Expr::Literal(lit) => Some(lit.clone()),
        _ => None,
    }
}

// ---------------------------------------------------------------------
// The rewrite
// ---------------------------------------------------------------------

/// A new binding in `func`, unscheduled; the caller places it.
fn push(func: &mut HighFunction, expr: Expr, ty: IrType, note: &str) -> ValueId {
    let id = ValueId::from_index(func.bindings.len() as u32);
    func.bindings.push(Binding::new(
        id,
        ty,
        expr,
        Provenance::new(PASS_NAME, ProvenanceSource::SdkPattern, note.to_string()),
    ));
    id
}

/// Schedule `new` next to `anchor` in `anchor`'s block, before or after it.
fn place(func: &mut HighFunction, anchor: ValueId, new: ValueId, after: bool) {
    let Some(block) = block_containing(func, anchor).and_then(|b| func.blocks.get_mut(b)) else {
        return;
    };
    if let Some(at) = block.bindings.iter().position(|b| *b == anchor) {
        block.bindings.insert(at + usize::from(after), new);
    }
}

/// Replace `id`'s expression, resetting its type for `type_infer` to settle.
fn rewrite(func: &mut HighFunction, id: ValueId, expr: Expr, ty: Option<IrType>, note: &str) {
    if let Some(binding) = func.bindings.get_mut(id) {
        binding.expr = expr;
        if let Some(ty) = ty {
            binding.ty = ty;
        }
        binding.add_provenance(Provenance::new(PASS_NAME, ProvenanceSource::SdkPattern, note.to_string()));
    }
}

fn untyped() -> IrType {
    IrType::Unknown(UnknownReason::InsufficientEvidence)
}

/// The helper returns its `Option` instead of writing it.
fn rewrite_helper(func: &mut HighFunction, helper: &Helper) {
    // One `Option` per arm, built where the arm leaves.
    let mut by_pred: HashMap<BlockId, ValueId> = HashMap::new();
    for arm in &helper.arms {
        let payload = (!arm.stores.is_empty()).then(|| match (&helper.whole, whole_of(func, arm)) {
            (Some(_), Some(value)) => vec![value],
            _ => {
                let mut stores = arm.stores.clone();
                stores.sort_by_key(|(_, slot, _)| *slot);
                stores.into_iter().map(|(_, _, value)| value).collect()
            }
        });
        let note = if payload.is_some() {
            "the value this path wrote through the out-pointer, returned as `Some`"
        } else {
            "this path wrote no value through the out-pointer: `None`"
        };
        let id = push(func, Expr::Optional { payload }, untyped(), note);
        if let Some(block) = func.blocks.get_mut(arm.pred) {
            block.bindings.push(id);
        }
        by_pred.insert(arm.pred, id);
    }

    // The merged tag becomes the merged `Option`.
    if let Some(binding) = func.bindings.get_mut(helper.tag_phi)
        && let Expr::Phi { incoming } = &mut binding.expr
    {
        for (pred, value) in incoming.iter_mut() {
            if let Some(option) = by_pred.get(pred) {
                *value = *option;
            }
        }
        binding.ty = untyped();
        binding.add_provenance(Provenance::new(
            PASS_NAME,
            ProvenanceSource::SdkPattern,
            "the out-parameter's tag, merged as the `Option` it encoded",
        ));
    }
    retarget(&mut func.region, &mut None, helper.tag_phi, &by_pred);

    for &id in &helper.retired {
        rewrite(
            func,
            id,
            Expr::Literal(Literal::Unit),
            Some(IrType::Known(KnownType::Unit)),
            "out-parameter write, now the returned `Option`",
        );
    }
    give_back(&mut func.region, helper.tag_phi);
    for site in &mut func.returns {
        *site = vec![helper.tag_phi];
    }
    if helper.out < func.params.len() {
        func.params.remove(helper.out);
    }
}

/// Point every edge into the merge at its arm's `Option` instead of a tag.
fn retarget(region: &mut Region, last: &mut Option<BlockId>, tag_phi: ValueId, by_pred: &HashMap<BlockId, ValueId>) {
    match region {
        Region::Basic(b) => *last = Some(*b),
        Region::Sequence(items) => {
            for item in items {
                retarget(item, last, tag_phi, by_pred);
            }
        }
        Region::Scope { body, .. } | Region::Loop { body, .. } => {
            retarget(body, last, tag_phi, by_pred);
            *last = None;
        }
        Region::If { then_region, else_region, .. } => {
            let entry = *last;
            retarget(then_region, last, tag_phi, by_pred);
            *last = entry;
            if let Some(e) = else_region {
                retarget(e, last, tag_phi, by_pred);
            }
            *last = None;
        }
        Region::Switch { arms, default, .. } => {
            let entry = *last;
            retarget(default, last, tag_phi, by_pred);
            for arm in arms {
                *last = entry;
                retarget(&mut arm.body, last, tag_phi, by_pred);
            }
            *last = None;
        }
        Region::Break { transfer, .. } | Region::Transfer { transfer, .. } => {
            for (phi, value) in transfer.iter_mut() {
                if *phi == tag_phi
                    && let Some(option) = last.and_then(|b| by_pred.get(&b))
                {
                    *value = *option;
                }
            }
        }
        _ => {}
    }
}

/// Every bare `return` hands the `Option` back.
fn give_back(region: &mut Region, value: ValueId) {
    match region {
        Region::Return { values } if values.is_empty() => values.push(value),
        Region::Sequence(items) => items.iter_mut().for_each(|r| give_back(r, value)),
        Region::Scope { body, .. } | Region::Loop { body, .. } => give_back(body, value),
        Region::If { then_region, else_region, .. } => {
            give_back(then_region, value);
            if let Some(e) = else_region {
                give_back(e, value);
            }
        }
        Region::Switch { arms, default, .. } => {
            arms.iter_mut().for_each(|a| give_back(&mut a.body, value));
            give_back(default, value);
        }
        _ => {}
    }
}

/// The call yields the `Option`; its reads become questions about it.
fn rewrite_site(func: &mut HighFunction, plan: &SitePlan, helper: &Helper) {
    if let Some(binding) = func.bindings.get_mut(plan.call)
        && let Expr::Call { args, .. } = &mut binding.expr
        && helper.out < args.len()
    {
        args.remove(helper.out);
    }
    rewrite_ty(func, plan.call, "the call yields the `Option` its frame used to receive");

    let is_some = push(func, Expr::IsSome { value: plan.call }, IrType::Known(KnownType::Bool), "whether the call returned a value");
    place(func, plan.call, is_some, true);

    // The tag, read back exactly: the present tag when it holds a value.
    // A tag only ever branched on is that question itself, as a `bool` —
    // a wasm `br_if` on an integer is a test for non-zero.
    for &tag in &plan.tags {
        if cond_only(func, tag) {
            let (expr, note) = match (helper.present != 0, helper.absent != 0) {
                (true, false) => (Expr::Use(is_some), "the tag, tested: whether the call returned a value"),
                (false, true) => (
                    Expr::Unary { op: UnaryOp::Not, value: is_some },
                    "the tag, tested: whether the call returned nothing",
                ),
                _ => (Expr::Literal(Literal::Bool(helper.present != 0)), "the tag, tested, is the same either way"),
            };
            rewrite(func, tag, expr, Some(IrType::Known(KnownType::Bool)), note);
            continue;
        }
        let wide = matches!(func.bindings.get(tag).map(|b| &b.expr), Some(Expr::Load { width: sordec_ir::MemWidth::W8, .. }));
        let lit = |n: i128| {
            if wide {
                (Literal::I64(n as i64), IrType::Known(KnownType::I64))
            } else {
                (Literal::I32(n as i32), IrType::Known(KnownType::I32))
            }
        };
        let (p, pt) = lit(helper.present);
        let (a, at) = lit(helper.absent);
        let present = push(func, Expr::Literal(p), pt, "the tag the helper wrote when it had a value");
        let absent = push(func, Expr::Literal(a), at, "the tag the helper wrote when it had none");
        place(func, tag, present, false);
        place(func, tag, absent, false);
        rewrite(
            func,
            tag,
            Expr::Select { cond: is_some, if_true: present, if_false: absent },
            None,
            "the out-parameter's tag, read from the returned `Option`",
        );
    }
    let arity = helper.payload.len() as u32;
    for &(load, index) in &plan.values {
        if let Some((field, half)) = helper.whole.as_ref().and_then(|w| w.get(index)) {
            let whole = push(
                func,
                Expr::Unwrap { value: plan.call, index: 0, arity: 1 },
                untyped(),
                "the struct the helper returned, where the `Option` is proven present",
            );
            place(func, load, whole, false);
            let declared = helper.part_types.get(index).cloned().flatten();
            let part = push(
                func,
                Expr::Field { base: whole, field: field.clone() },
                declared.map_or_else(untyped, IrType::Known),
                "the field of the returned struct this slot held",
            );
            place(func, load, part, false);
            let (expr, ty) = match half {
                Some(op) => (Expr::Unary { op: *op, value: part }, Some(IrType::Inferred(KnownType::I64))),
                None => (Expr::Use(part), Some(untyped())),
            };
            rewrite(func, load, expr, ty, "the out-parameter's slot, read from the returned struct");
            continue;
        }
        rewrite(
            func,
            load,
            Expr::Unwrap { value: plan.call, index: index as u32, arity },
            Some(untyped()),
            "the out-parameter's value, read from the returned `Option` where it is proven present",
        );
    }
    for (load, lit) in &plan.consts {
        rewrite(func, *load, Expr::Literal(lit.clone()), None, "a slot the helper always wrote this constant to");
    }
}

/// Whether `value` is read only as the condition of an `if`.
fn cond_only(func: &HighFunction, value: ValueId) -> bool {
    let mut bound = false;
    for id in emission_order(func) {
        if let Some(b) = func.bindings.get(id) {
            b.expr.for_each_value_use(|u| bound |= u == value);
        }
    }
    let mut all = 0usize;
    func.region.for_each_value_use(|u| all += usize::from(u == value));
    let mut conds = 0usize;
    func.region.for_each_node(|node| {
        if let Region::If { cond, .. } = node {
            conds += usize::from(*cond == value);
        }
    });
    !bound && conds > 0 && conds == all
}

fn rewrite_ty(func: &mut HighFunction, id: ValueId, note: &str) {
    if let Some(binding) = func.bindings.get_mut(id) {
        binding.ty = untyped();
        binding.add_provenance(Provenance::new(PASS_NAME, ProvenanceSource::SdkPattern, note.to_string()));
    }
}

// ---------------------------------------------------------------------
// What a call can touch through a pointer
// ---------------------------------------------------------------------

/// Module-wide context for the call-site gates: the classified helpers,
/// and a memo of what each function can touch through each parameter.
struct Frames<'ir> {
    ir: &'ir HighIr,
    helpers: &'ir HashMap<FuncId, Helper>,
    /// `(function, parameter) -> bytes read and bytes written through it`,
    /// relative to the parameter; `None` when unknown. An in-progress entry
    /// is `None`, which is what makes recursion answer "unknown" rather than
    /// loop.
    extents: RefCell<HashMap<(FuncId, usize), Option<Extent>>>,
}

/// One access range a call has into a frame, and whether it only writes.
type Touch = (Slot, bool);

/// What a function does through one pointer parameter: the bytes it reads
/// and the bytes it writes, each `None` when it does neither.
#[derive(Debug, Clone, Copy, Default)]
struct Extent {
    reads: Option<Slot>,
    writes: Option<Slot>,
}

/// The smallest slot covering both.
fn cover(a: Option<Slot>, b: Slot) -> Slot {
    match a {
        None => b,
        Some(a) => {
            let lo = a.offset.min(b.offset);
            let hi = (a.offset + a.bytes).max(b.offset + b.bytes);
            Slot { offset: lo, bytes: hi - lo }
        }
    }
}

impl Frames<'_> {
    /// What the call at `binding` can touch in the frame at `base`, or
    /// `None` when it is handed a pointer into it and the extent is not
    /// known. Empty for a call handed nothing of the frame.
    fn touches(&self, func: &HighFunction, binding: ValueId, base: ValueId) -> Option<Vec<Touch>> {
        let (target, args) = match func.bindings.get(binding).map(|b| &b.expr) {
            Some(Expr::Call { target, args }) => (Some(*target), args),
            Some(Expr::IndirectCall { args, .. }) => (None, args),
            _ => return Some(Vec::new()),
        };
        let mut out = Vec::new();
        for (i, arg) in args.iter().enumerate() {
            let (b, at) = canon_addr(func, *arg);
            if b != base {
                continue;
            }
            let target = target?;
            if let Some(h) = self.helpers.get(&target)
                && h.out == i
            {
                for slot in h.slots() {
                    out.push((slot.shifted(at)?, true));
                }
                continue;
            }
            let extent = self.param_extent(target, i)?;
            if let Some(read) = extent.reads {
                out.push((read.shifted(at)?, false));
            }
            if let Some(written) = extent.writes {
                out.push((written.shifted(at)?, true));
            }
        }
        Some(out)
    }

    /// What `target` does through parameter `index`, relative to it, or
    /// `None` when that cannot be told.
    fn param_extent(&self, target: FuncId, index: usize) -> Option<Extent> {
        if let Some(known) = self.extents.borrow().get(&(target, index)) {
            return *known;
        }
        self.extents.borrow_mut().insert((target, index), None);
        let found = self.compute_extent(target, index);
        self.extents.borrow_mut().insert((target, index), found);
        found
    }

    fn compute_extent(&self, target: FuncId, index: usize) -> Option<Extent> {
        let func = self.ir.functions.iter().find(|f| f.id == target)?;
        if func.signature.is_some() {
            return None;
        }
        let param = *func.params.get(index)?;
        let order = emission_order(func);
        let mut addresses: HashSet<ValueId> = HashSet::from([param]);
        for &id in &order {
            match func.bindings.get(id).map(|b| &b.expr) {
                Some(Expr::Binary { op: BinaryOp::Add, lhs, rhs })
                    if addresses.contains(&resolve_use(func, *lhs)) && trace_int(func, *rhs).is_some() =>
                {
                    addresses.insert(id);
                }
                Some(Expr::Use(v)) if addresses.contains(&resolve_use(func, *v)) => {
                    addresses.insert(id);
                }
                _ => {}
            }
        }
        let is_address = |v: ValueId| addresses.contains(&resolve_use(func, v));
        let mut extent = Extent::default();
        for &id in &order {
            if addresses.contains(&id) {
                continue;
            }
            let expr = &func.bindings.get(id)?.expr;
            match expr {
                Expr::Load { addr, offset, width, .. } if is_address(*addr) => {
                    let (_, o) = canon_addr(func, *addr);
                    extent.reads = Some(cover(extent.reads, Slot { offset: o.checked_add(*offset)?, bytes: width.bytes() }));
                }
                Expr::Store { addr, value, offset, width } if is_address(*addr) => {
                    if is_address(*value) {
                        return None;
                    }
                    let (_, o) = canon_addr(func, *addr);
                    extent.writes = Some(cover(extent.writes, Slot { offset: o.checked_add(*offset)?, bytes: width.bytes() }));
                }
                Expr::Call { target, args } => {
                    for (j, arg) in args.iter().enumerate() {
                        if !is_address(*arg) {
                            continue;
                        }
                        let (_, o) = canon_addr(func, *arg);
                        let inner = self.param_extent(*target, j)?;
                        if let Some(r) = inner.reads {
                            extent.reads = Some(cover(extent.reads, r.shifted(o)?));
                        }
                        if let Some(w) = inner.writes {
                            extent.writes = Some(cover(extent.writes, w.shifted(o)?));
                        }
                    }
                }
                other => {
                    let mut reads = false;
                    other.for_each_value_use(|u| reads |= is_address(u));
                    if reads {
                        return None;
                    }
                }
            }
        }
        let mut region_reads = false;
        func.region.for_each_value_use(|u| region_reads |= is_address(u));
        if region_reads {
            return None;
        }
        Some(extent)
    }
}

// ---------------------------------------------------------------------
// The call site
// ---------------------------------------------------------------------

fn site(
    frames: &Frames<'_>,
    func: &HighFunction,
    order: &[ValueId],
    call: ValueId,
    args: &[ValueId],
    helper: &Helper,
) -> Result<SitePlan, &'static str> {
    let ptr = *args.get(helper.out).ok_or("the call has no out-pointer argument")?;
    let (base, at) = canon_addr(func, ptr);
    let tag = helper.tag.shifted(at).ok_or("an offset overflows")?;
    let payload: Vec<Slot> = helper.payload.iter().map(|(s, _)| s.shifted(at)).collect::<Option<_>>().ok_or("an offset overflows")?;
    let all: Vec<Slot> = helper.slots().map(|s| s.shifted(at)).collect::<Option<_>>().ok_or("an offset overflows")?;
    let lo = all.iter().map(|s| s.offset).min().ok_or("no slots")?;
    let hi = all.iter().map(|s| s.offset + s.bytes).max().ok_or("no slots")?;
    let range = Slot { offset: lo, bytes: hi - lo };

    // Another call handed this frame may read the result, which the
    // rewrite stops writing. Allowed only where what it can touch is known
    // and misses the result — a key passed by reference sits beside it —
    // or where all it is handed is another helper's out-pointer, which it
    // only stores through.
    // The call's own other arguments too: an in-out pointer overlapping the
    // result would read what the rewrite no longer writes.
    for (i, arg) in args.iter().enumerate() {
        let (b, o) = canon_addr(func, *arg);
        if i == helper.out || b != base {
            continue;
        }
        let Some(target) = (match func.bindings.get(call).map(|b| &b.expr) {
            Some(Expr::Call { target, .. }) => Some(*target),
            _ => None,
        }) else {
            return Err("the call is not direct");
        };
        let extent = frames.param_extent(target, i).ok_or("the call takes the frame twice, extent unknown")?;
        for slot in extent.reads.into_iter().chain(extent.writes) {
            if slot.shifted(o).is_none_or(|s| s.overlaps(range)) {
                return Err("the call reads or writes the result through another argument");
            }
        }
    }
    for &id in order {
        if id == call {
            continue;
        }
        let Some(touched) = frames.touches(func, id, base) else {
            trace(func, &format!("  call v{} into the frame, extent unknown", id.index()));
            return Err("the frame is handed to a call that may read anything");
        };
        if touched.iter().any(|(slot, write_only)| !write_only && slot.overlaps(range)) {
            trace(func, &format!("  call v{} may read the result", id.index()));
            return Err("another call may read the result");
        }
    }

    let mut tag_loads = Vec::new();
    let mut payload_loads = Vec::new();
    let mut const_loads = Vec::new();
    for &id in order {
        let Some(Expr::Load { addr, offset, width, .. }) = func.bindings.get(id).map(|b| &b.expr) else {
            continue;
        };
        let (b, o) = canon_addr(func, *addr);
        if b != base {
            continue;
        }
        let slot = Slot { offset: o.checked_add(*offset).ok_or("an offset overflows")?, bytes: width.bytes() };
        if !slot.overlaps(range) {
            continue;
        }
        // A read another write reaches belongs to that write — the next
        // call to the same helper, reusing the slot — and the rewrite leaves
        // it alone. Only a read whose writer depends on the path is a
        // problem.
        if nearest_writer(frames, func, id, base, slot)? != Some(call) {
            continue;
        }
        // The low bytes of a small tag are the tag: wasm is little-endian,
        // and a caller reads an 8-byte discriminant as an `i32`.
        let low_bits = |t: i128| slot.bytes >= 16 || (0..(1i128 << (8 * slot.bytes))).contains(&t);
        let tag_prefix = slot.offset == tag.offset
            && slot.bytes < tag.bytes
            && low_bits(helper.present)
            && low_bits(helper.absent);
        if slot == tag || tag_prefix {
            tag_loads.push(id);
        } else if let Some(index) = payload.iter().position(|s| *s == slot) {
            payload_loads.push((id, index));
        } else if let Some((_, lit)) = helper.consts.iter().find(|(s, _)| s.shifted(at) == Some(slot)) {
            const_loads.push((id, lit.clone()));
        } else {
            trace(func, &format!("  read v{} at {:?}; slots {:?}", id.index(), slot, all));
            return Err("a read that is not one of the result's slots");
        }
    }
    for &(load, _) in &payload_loads {
        if !guarded(func, load, &tag_loads, helper) {
            return Err("a value read not proven present");
        }
    }
    Ok(SitePlan { call, tags: tag_loads, values: payload_loads, consts: const_loads })
}

/// What a qualifying call site reads of the result, for the rewrite.
struct SitePlan {
    call: ValueId,
    /// Reads of the tag (or its low bytes).
    tags: Vec<ValueId>,
    /// Reads of the value, each with its payload component.
    values: Vec<(ValueId, usize)>,
    /// Reads of a slot the helper always writes the same constant to.
    consts: Vec<(ValueId, Literal)>,
}

/// Whether `binding` writes memory at `base` that may overlap `range`: a
/// store there, or a call handed a pointer into the frame.
fn writes(frames: &Frames<'_>, func: &HighFunction, binding: ValueId, base: ValueId, range: Slot) -> bool {
    match func.bindings.get(binding).map(|b| &b.expr) {
        Some(Expr::Store { addr, offset, width, .. }) => {
            let (b, o) = canon_addr(func, *addr);
            b == base && o.checked_add(*offset).is_none_or(|start| Slot { offset: start, bytes: width.bytes() }.overlaps(range))
        }
        Some(Expr::Call { .. } | Expr::IndirectCall { .. }) => frames
            .touches(func, binding, base)
            .is_none_or(|touched| touched.iter().any(|(slot, _)| slot.overlaps(range))),
        _ => false,
    }
}

/// The write that `load` reads: the last write on every path to it, when
/// that is one binding. `Err` when it depends on the path.
fn nearest_writer(
    frames: &Frames<'_>,
    func: &HighFunction,
    load: ValueId,
    base: ValueId,
    range: Slot,
) -> Result<Option<ValueId>, &'static str> {
    let block = block_containing(func, load).ok_or("an unscheduled read")?;
    let bindings = &func.blocks.get(block).ok_or("a missing block")?.bindings;
    let at = bindings.iter().position(|b| *b == load).ok_or("an unscheduled read")?;
    if let Some(w) = bindings[..at].iter().rev().find(|b| writes(frames, func, **b, base, range)) {
        return Ok(Some(*w));
    }
    let path = path_to(&func.region, block).ok_or("a read outside the region tree")?;
    let writes_in = |region: &Region| -> Vec<ValueId> {
        let mut found = Vec::new();
        region.for_each_node(|node| {
            if let Region::Basic(b) = node
                && let Some(block) = func.blocks.get(*b)
            {
                found.extend(block.bindings.iter().copied().filter(|v| writes(frames, func, *v, base, range)));
            }
        });
        found
    };
    for (region, child) in path.iter().rev() {
        match region {
            Region::Sequence(items) => {
                for item in items[..*child].iter().rev() {
                    let found = writes_in(item);
                    match (item, found.last()) {
                        (_, None) => {}
                        (Region::Basic(_), Some(w)) => return Ok(Some(*w)),
                        _ => return Err("a write inside an earlier branch"),
                    }
                }
            }
            Region::Loop { .. } if !writes_in(region).is_empty() => {
                return Err("a write inside the enclosing loop");
            }
            _ => {}
        }
    }
    Ok(None)
}

/// The chain of regions from `root` down to the `Basic` region of
/// `block`, each with the index of the child taken (0 for single-child
/// regions; for an `If`, 0 is `then` and 1 is `else`).
fn path_to(root: &Region, block: BlockId) -> Option<Vec<(&Region, usize)>> {
    fn go<'r>(region: &'r Region, block: BlockId, path: &mut Vec<(&'r Region, usize)>) -> bool {
        let children: Vec<&Region> = match region {
            Region::Basic(b) => return *b == block,
            Region::Sequence(items) => items.iter().collect(),
            Region::Scope { body, .. } | Region::Loop { body, .. } => vec![&**body],
            Region::If { then_region, else_region, .. } => {
                std::iter::once(&**then_region).chain(else_region.as_deref()).collect()
            }
            Region::Switch { arms, default, .. } => {
                arms.iter().map(|a| &a.body).chain(std::iter::once(&**default)).collect()
            }
            _ => return false,
        };
        for (i, child) in children.into_iter().enumerate() {
            path.push((region, i));
            if go(child, block, path) {
                return true;
            }
            path.pop();
        }
        false
    }
    let mut path = Vec::new();
    go(root, block, &mut path).then_some(path)
}

/// Whether `load` sits where a test on one of `tag_loads` proves the value
/// present: inside the arm the test sends `present` to, or after an `if`
/// whose `absent` arm leaves.
fn guarded(func: &HighFunction, load: ValueId, tag_loads: &[ValueId], helper: &Helper) -> bool {
    let Some(block) = block_containing(func, load) else {
        return false;
    };
    let Some(path) = path_to(&func.region, block) else {
        return false;
    };
    let polarity = |cond: ValueId| -> Option<bool> {
        let p = eval(func, cond, tag_loads, helper.present, 0)?;
        let a = eval(func, cond, tag_loads, helper.absent, 0)?;
        ((p != 0) != (a != 0)).then_some(p != 0)
    };
    for (region, child) in &path {
        match region {
            Region::If { cond, .. } => {
                if let Some(present_takes_then) = polarity(*cond)
                    && present_takes_then == (*child == 0)
                {
                    return true;
                }
            }
            Region::Sequence(items) => {
                for item in &items[..*child] {
                    if let Region::If { cond, then_region, else_region: None } = item
                        && polarity(*cond) == Some(false)
                        && leaves(then_region)
                    {
                        return true;
                    }
                }
            }
            _ => {}
        }
    }
    false
}

/// Whether control never falls out of the bottom of `region`.
fn leaves(region: &Region) -> bool {
    match region {
        Region::Return { .. }
        | Region::Break { .. }
        | Region::Continue { .. }
        | Region::Panic { .. }
        | Region::Unreachable => true,
        Region::Sequence(items) => items.last().is_some_and(leaves),
        Region::Scope { body, .. } => leaves(body),
        Region::If { then_region, else_region: Some(e), .. } => leaves(then_region) && leaves(e),
        _ => false,
    }
}

/// `value` evaluated with every tag load reading `tag`, when it is a short
/// enough chain of integer operators over them and constants.
fn eval(func: &HighFunction, value: ValueId, tag_loads: &[ValueId], tag: i128, depth: usize) -> Option<i128> {
    let value = resolve_use(func, value);
    if tag_loads.contains(&value) {
        return Some(tag);
    }
    if depth >= EVAL_DEPTH {
        return None;
    }
    let sub = |v: ValueId| eval(func, v, tag_loads, tag, depth + 1);
    match &func.bindings.get(value)?.expr {
        Expr::Literal(Literal::Bool(b)) => Some(i128::from(*b)),
        Expr::Literal(_) => trace_int(func, value),
        Expr::Unary { op: UnaryOp::Eqz | UnaryOp::Not, value } => Some(i128::from(sub(*value)? == 0)),
        Expr::Unary { op: UnaryOp::Wrap32 | UnaryOp::ExtendU32 | UnaryOp::ExtendS32, value } => sub(*value),
        Expr::Unknown { op_kind: sordec_ir::WasmOpcodeKind::Conversion, args, .. } if args.len() == 1 => sub(args[0]),
        Expr::Binary { op, lhs, rhs } => {
            let (l, r) = (sub(*lhs)?, sub(*rhs)?);
            Some(match op {
                BinaryOp::BitAnd => l & r,
                BinaryOp::BitOr => l | r,
                BinaryOp::BitXor => l ^ r,
                BinaryOp::Eq => i128::from(l == r),
                BinaryOp::Ne => i128::from(l != r),
                BinaryOp::Add => l.checked_add(r)?,
                BinaryOp::Sub => l.checked_sub(r)?,
                _ => return None,
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{module, v};
    use sordec_common::{Arena, Provenance, ProvenanceSource, UnknownReason};
    use sordec_ir::{Binding, HighBlock, MemWidth, PanicKind};

    fn bb(i: u32) -> BlockId {
        BlockId::from_index(i)
    }

    /// A function over `exprs` (ids `0..N`) with blocks laid out by
    /// `layout` and the given region; `params` are binding ids.
    fn func(id: u32, exprs: Vec<Expr>, params: Vec<u32>, layout: Vec<Vec<u32>>, region: Region) -> HighFunction {
        let mut bindings: Arena<ValueId, Binding> = Arena::new();
        for expr in exprs {
            let vid = ValueId::from_index(bindings.len() as u32);
            bindings.push(Binding::new(
                vid,
                IrType::Unknown(UnknownReason::InsufficientEvidence),
                expr,
                Provenance::new("seed", ProvenanceSource::DataFlow, "seed"),
            ));
        }
        let mut blocks: Arena<BlockId, sordec_ir::HighBlock> = Arena::new();
        for (i, ids) in layout.into_iter().enumerate() {
            blocks.push(HighBlock { id: bb(i as u32), bindings: ids.into_iter().map(v).collect() });
        }
        HighFunction {
            id: FuncId::from_index(id),
            name: None,
            signature: None,
            aliases: Vec::new(),
            blocks,
            bindings,
            region,
            params: params.into_iter().map(v).collect(),
            returns: vec![],
        }
    }

    fn store(addr: u32, value: u32, offset: u32) -> Expr {
        Expr::Store { addr: v(addr), value: v(value), offset, width: MemWidth::W8 }
    }

    fn load(addr: u32, offset: u32, width: MemWidth) -> Expr {
        Expr::Load {
            addr: v(addr),
            offset,
            width,
            signed: None,
            ty: IrType::Unknown(UnknownReason::InsufficientEvidence),
        }
    }

    /// func_1, `BytesN::try_from_val`'s shape: tag 1 and nothing else on
    /// the failing arm, tag 0 and the value at `+8` on the other.
    /// `absent_writes` makes the failing arm write `+8` too.
    fn helper(absent_writes: bool) -> HighFunction {
        let exprs = vec![
            Expr::Phi { incoming: vec![] },          // v0 out-pointer
            Expr::Phi { incoming: vec![] },          // v1 the value
            Expr::Literal(Literal::I64(1)),          // v2 absent tag
            Expr::Literal(Literal::Bool(true)),      // v3 the test
            Expr::Literal(Literal::I64(0)),          // v4 present tag
            store(0, 1, 8),                          // v5 the payload
            Expr::Phi { incoming: vec![(bb(1), v(2)), (bb(2), v(4))] }, // v6
            store(0, 6, 0),                          // v7 the tag
            store(0, 2, 8),                          // v8 a write on the failing arm
        ];
        let absent = if absent_writes { vec![8] } else { vec![] };
        let arm = |block: u32, tag: u32| {
            Region::Sequence(vec![
                Region::Basic(bb(block)),
                Region::Transfer { target: bb(3), transfer: vec![(v(6), v(tag))] },
            ])
        };
        func(
            1,
            exprs,
            vec![0, 1],
            vec![vec![2, 3, 4], absent, vec![5], vec![7]],
            Region::Sequence(vec![
                Region::Basic(bb(0)),
                Region::If {
                    cond: v(3),
                    then_region: Box::new(arm(1, 2)),
                    else_region: Some(Box::new(arm(2, 4))),
                },
                Region::Basic(bb(3)),
                Region::Return { values: vec![] },
            ]),
        )
    }

    /// func_0: `func_1(fp, x); if eqz(load32(fp+0)) { return load(fp+8) }
    /// panic!()`. `early` reads the value before the test instead.
    fn caller(early: bool) -> HighFunction {
        let exprs = vec![
            Expr::Phi { incoming: vec![] },                                         // v0 frame
            Expr::Phi { incoming: vec![] },                                         // v1 x
            Expr::Call { target: FuncId::from_index(1), args: vec![v(0), v(1)] }, // v2
            load(0, 0, MemWidth::W4),                                               // v3 tag, low half
            Expr::Unary { op: UnaryOp::Eqz, value: v(3) },                          // v4 present?
            load(0, 8, MemWidth::W8),                                               // v5 the value
        ];
        let (entry, present) = if early { (vec![2, 3, 4, 5], vec![]) } else { (vec![2, 3, 4], vec![5]) };
        func(
            0,
            exprs,
            vec![1],
            vec![entry, present],
            Region::Sequence(vec![
                Region::Basic(bb(0)),
                Region::If {
                    cond: v(4),
                    then_region: Box::new(Region::Sequence(vec![
                        Region::Basic(bb(1)),
                        Region::Return { values: vec![v(5)] },
                    ])),
                    else_region: None,
                },
                Region::Panic { kind: PanicKind::Bare },
            ]),
        )
    }

    fn site_of(caller: HighFunction) -> Result<(), &'static str> {
        let ir = module(vec![caller, helper(false)]);
        let helpers: HashMap<FuncId, Helper> = ir
            .functions
            .iter()
            .filter_map(|f| classify(f).ok().map(|h| (f.id, h)))
            .collect();
        let frames = Frames { ir: &ir, helpers: &helpers, extents: RefCell::new(HashMap::new()) };
        let f = &ir.functions[0];
        let order = emission_order(f);
        let Some(Expr::Call { args, .. }) = f.bindings.get(v(2)).map(|b| &b.expr) else {
            panic!("v2 is the call");
        };
        site(&frames, f, &order, v(2), args, &helpers[&FuncId::from_index(1)]).map(|_| ())
    }

    #[test]
    fn a_try_from_val_shaped_helper_is_classified() {
        let h = classify(&helper(false)).expect("an Option out-parameter helper");
        assert_eq!(h.out, 0);
        assert_eq!((h.present, h.absent), (0, 1));
        assert_eq!(h.tag, Slot { offset: 0, bytes: 8 });
        assert_eq!(h.payload.iter().map(|(s, _)| *s).collect::<Vec<_>>(), [Slot { offset: 8, bytes: 8 }]);
    }

    #[test]
    fn an_absent_arm_that_writes_is_not_a_helper() {
        // Both arms write, so both read as present, with different tags:
        // that is a `Result` with two payloads, not this shape.
        assert_eq!(classify(&helper(true)).err(), Some("present arms disagree on the tag"));
    }

    #[test]
    fn a_value_read_on_the_present_arm_qualifies() {
        // The tag is read as an `i32`, its low half: still the tag.
        assert_eq!(site_of(caller(false)), Ok(()));
    }

    #[test]
    fn a_value_read_before_the_test_is_refused() {
        assert_eq!(site_of(caller(true)), Err("a value read not proven present"));
    }

    #[test]
    fn the_helper_returns_an_option_and_its_caller_asks_it() {
        let mut ir = module(vec![caller(false), helper(false)]);
        let result = OptionalOutParamPass.run(&mut ir);
        assert!(result.changed, "every site qualifies, so the helper is rewritten");

        // The helper: no out-pointer, one returned `Option`, built per arm.
        let h = &ir.functions[1];
        assert_eq!(h.params, vec![v(1)], "the out-pointer is no longer a parameter");
        let Region::Sequence(items) = &h.region else { panic!("a sequence") };
        assert_eq!(items.last(), Some(&Region::Return { values: vec![v(6)] }), "the merge is returned");
        let Some(Expr::Phi { incoming }) = h.bindings.get(v(6)).map(|b| &b.expr) else {
            panic!("the tag phi stays a phi");
        };
        let arms: Vec<&Expr> = incoming.iter().map(|(_, o)| &h.bindings.get(*o).unwrap().expr).collect();
        assert!(
            matches!(arms.as_slice(), [Expr::Optional { payload: None }, Expr::Optional { payload: Some(p) }] if p == &vec![v(1)]),
            "the failing arm is None, the other Some(value)"
        );
        for store in [v(5), v(7)] {
            assert!(
                matches!(h.bindings.get(store).unwrap().expr, Expr::Literal(Literal::Unit)),
                "out-pointer writes retire"
            );
        }

        // The caller: the call drops its frame, the reads ask the `Option`.
        let c = &ir.functions[0];
        let Some(Expr::Call { args, .. }) = c.bindings.get(v(2)).map(|b| &b.expr) else { panic!("v2 is the call") };
        assert_eq!(args, &vec![v(1)]);
        assert!(matches!(c.bindings.get(v(3)).unwrap().expr, Expr::Select { .. }), "the tag read is exact");
        assert!(
            matches!(c.bindings.get(v(5)).unwrap().expr, Expr::Unwrap { value, index: 0, arity: 1 } if value == v(2)),
            "the value read unwraps where it is proven present"
        );

        // Idempotent: nothing left to classify.
        assert!(!OptionalOutParamPass.run(&mut ir).changed);
    }

    #[test]
    fn one_refused_site_keeps_the_helper_as_it_is() {
        // The same helper, called once properly and once with the value
        // read before the test: the signature cannot change for one caller.
        let mut early = caller(true);
        early.id = FuncId::from_index(2);
        let mut ir = module(vec![caller(false), helper(false), early]);
        assert!(!OptionalOutParamPass.run(&mut ir).changed);
        assert_eq!(ir.functions[1].params.len(), 2, "the helper keeps its out-pointer");
    }
}
