//! Read a `for x in v.iter()` loop over a vector of a handle type, whose
//! iterator rustc left outlined, as the indexed loop it is.
//!
//! # The shape
//!
//! ```rust,ignore
//! for signer in signers.iter() {
//!     env.storage().persistent().set(&DataKey::Signer(signer), &());
//! }
//! ```
//!
//! `Vec<Address>::iter()` is a `VecIter`, whose `next` is the inner
//! `VecTryIter::next` (the element, converted) mapped through `unwrap`.
//! When rustc outlines both, the iterator's state (the vector, the next
//! index, the length) sits in the frame and each round calls them through
//! memory:
//!
//! ```text
//! store fp+0 <- v ; store fp+8 <- 0 ; store fp+12 <- vec_len(v)
//! loop {
//!     try_next(fp+32, fp)                      ; Option<Result<Address, _>>
//!     unwrap(fp+16, load fp+32, load fp+40)    ; Option<Address>
//!     if load fp+16 != 1 { …; exit }           ; None: the loop ends
//!     x = load fp+24                           ; Some(x)
//!     …body…; continue
//! }
//! ```
//!
//! # The rewrite
//!
//! A counter `i` takes the iterator's place: `0` on entry, `i + 1` on every
//! way round, the end test `i >= len`, and the element
//! `v.get_unchecked(i)`:
//!
//! ```text
//! i = 0
//! loop { if i >= len { …; exit } ; x = vec_get(v, U32Val(i)) ; …body… ; i = i + 1 ; continue }
//! ```
//!
//! The state's stores, both calls and every load of their results go.
//!
//! # Why it is exact
//!
//! - **The helpers are the SDK's.** `try_next(out, state)` reads the
//!   index and length from the state and, when the index is not below the
//!   length, leaves tag `2` (`None`) and nothing else; otherwise it writes
//!   `vec_get(vector, index)` at +8 of `out`, the index plus one back, and
//!   as the tag whether that element lacks the type's one object tag
//!   (`1`, a failed conversion) or has it (`0`). For `Address`, `Bytes` and
//!   `String` that tag test is the whole conversion. `unwrap(out, t, x)`
//!   traps for `t == 1` and any `t > 2`, leaves tag `0` for `t == 2`, and
//!   for `t == 0` writes `x` at +8 and tag `1` — `Option::map` of
//!   `Result::unwrap`, read off its region tree arm by arm.
//! - **The state is this loop's.** Its three stores sit in one block
//!   before the loop, with nothing between them and the loop's entry that
//!   touches its 16 bytes; nothing anywhere touches them but such stores
//!   and the `try_next` calls of these loops, and a forward walk confirms
//!   each call sees its own loop's setting. The calls' out-slots are read
//!   only by the loads below.
//! - **Round `k` reads element `k`.** The loop body opens with the block
//!   holding the one `try_next` call, so every round makes exactly one
//!   call, and reaching a `continue` passes the end test. The state's index
//!   starts at `0` and each call adds one while it is below the length: at
//!   round `k` it is `k`, which is `i`. So the call returns `None` exactly
//!   when `i >= len` — where the rewritten test exits — and otherwise the
//!   element at `i`, which the source's `unwrap` converts or traps on, as
//!   `get_unchecked(i)` on the typed vector does.
//! - **The element is the load right after the test.** It is the first
//!   read of the second helper's +8 on the path that passed the test, in
//!   the block that follows it, before anything there writes memory.
//! - **`i + 1` cannot overflow.** It is computed only past the test, where
//!   `i < len <= u32::MAX`.
//!
//! # Gates
//!
//! - The helpers as above; the element type one tag carries whole.
//! - The loop body a sequence of: the block with `try_next(o1, state)`,
//!   `t = load o1`, `x = load o1+8`, `unwrap(o2, t, x)`, `tag = load o2`
//!   in that order with nothing else writing memory between; an `if` on
//!   `tag != 1` whose taken arm never falls through and never continues
//!   this loop; then a block whose loads of `o2+8` come before anything in
//!   it writes memory.
//! - Every touch of the state's and the out-slots' bytes is one of these
//!   loops' stores, calls and loads; the forward walk agrees.
//! - What goes is read by nothing that stays: `t` and `x` only by the
//!   unwrap, the tag only by the test, the calls' results not at all.

use std::collections::{HashMap, HashSet};

use sordec_common::{BlockId, FuncId, Provenance, ProvenanceSource, ValueId};
use sordec_ir::{
    BinaryOp, Expr, HighFunction, HighIr, IrType, KnownOp, KnownType, Literal, MemWidth, Region, SemanticOp,
    UnaryOp, VecOpKind,
};

use super::enum_match::{expr_of, falls_through, scheduled};
use super::udt_decode::reach;
use super::udt_decode::{param_accesses, ParamAccess};
use crate::dataflow::{canon_addr, resolve_use, trace_int};
use crate::pass::{Pass, PassResult};
use crate::val_abi;

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-vec-iter";

/// Loops read as indexed.
const M_LOOPS: &str = "marshalling_vec_iter_loops";

/// Reads outlined typed-vector iteration as an indexed loop.
#[derive(Debug, Default, Clone, Copy)]
pub struct VecIterPass;

impl Pass<HighIr> for VecIterPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let access: HashMap<FuncId, Vec<Option<ParamAccess>>> =
            ir.functions.iter().map(|f| (f.id, param_accesses(f))).collect();
        let nexts: HashMap<FuncId, KnownType> = ir
            .functions
            .iter()
            .filter_map(|f| typed_next(f, access.get(&f.id)).map(|t| (f.id, t)))
            .collect();
        let unwraps: HashSet<FuncId> = ir.functions.iter().filter(|f| is_unwrap(f, access.get(&f.id))).map(|f| f.id).collect();
        if nexts.is_empty() || unwraps.is_empty() {
            return result;
        }
        for func in &mut ir.functions {
            let sites = match plan(func, &nexts, &unwraps) {
                Ok(sites) => sites,
                Err(why) => {
                    trace(func, &why);
                    continue;
                }
            };
            for site in sites {
                apply(func, site);
                result.metrics.increment(M_LOOPS, 1);
                result.changed = true;
            }
        }
        result
    }
}

#[allow(clippy::print_stderr)]
fn trace(func: &HighFunction, why: &str) {
    if std::env::var_os("SORDEC_ENUM_TRACE").is_some() {
        eprintln!("vec-iter: func_{}: {why}", sordec_common::IrId::index(func.id));
    }
}

// ---------------------------------------------------------------------
// The helpers
// ---------------------------------------------------------------------

/// The element type `f` converts to, when `f` is `VecTryIter::next` for a
/// vector of a type one object tag carries whole (see *Gates*).
fn typed_next(f: &HighFunction, access: Option<&Vec<Option<ParamAccess>>>) -> Option<KnownType> {
    if f.signature.is_some() || f.params.len() != 2 {
        return None;
    }
    let (Some(Some(out)), Some(Some(st))) = (access?.first(), access?.get(1)) else { return None };
    let set = |v: &[(u32, u32)]| v.iter().copied().collect::<HashSet<_>>();
    if !out.reads.is_empty() || set(&out.writes) != HashSet::from([(0, 8), (8, 8)]) || !out.must_writes.contains(&(0, 8)) {
        return None;
    }
    if set(&st.reads) != HashSet::from([(0, 8), (8, 4), (12, 4)]) || set(&st.writes) != HashSet::from([(8, 4)]) {
        return None;
    }
    let (out_p, st_p) = (f.params[0], f.params[1]);
    let load_of = |v: ValueId, off: u32, w: MemWidth| match expr_of(f, v) {
        Some(Expr::Load { addr, offset, width, .. }) if resolve_use(f, *addr) == st_p && *offset == off && *width == w => {
            Some(resolve_use(f, v))
        }
        _ => None,
    };
    // The region: the end test, then the read on its other side.
    let Region::Sequence(items) = &f.region else { return None };
    let (cond, then_region, else_region) = items.iter().find_map(|r| match r {
        Region::If { cond, then_region, else_region: Some(e) } => Some((*cond, then_region.as_ref(), e.as_ref())),
        _ => None,
    })?;
    let Some(Expr::Binary { op: BinaryOp::GeU, lhs, rhs }) = expr_of(f, cond) else { return None };
    let index = load_of(*lhs, 8, MemWidth::W4)?;
    load_of(*rhs, 12, MemWidth::W4)?;
    // The stores: the tag at the merge, the element and the next index on
    // the read side.
    let mut tag = None;
    let mut elem = None;
    let mut bumped = None;
    let else_blocks = super::enum_match::blocks_in(else_region);
    for (b, v) in scheduled(f) {
        let Some(Expr::Store { addr, value, offset, width }) = f.bindings.get(v).map(|b| &b.expr) else { continue };
        let a = resolve_use(f, *addr);
        match (a == out_p, a == st_p, *offset, *width) {
            (true, _, 0, MemWidth::W8) if tag.is_none() => tag = Some(*value),
            (true, _, 8, MemWidth::W8) if elem.is_none() && else_blocks.contains(&b) => elem = Some(*value),
            (_, true, 8, MemWidth::W4) if bumped.is_none() && else_blocks.contains(&b) => bumped = Some(*value),
            _ => return None,
        }
    }
    let (tag, elem, bumped) = (tag?, elem?, bumped?);
    let Some(Expr::Semantic(SemanticOp::Known(KnownOp::VecOp { kind: VecOpKind::Get, args }))) = expr_of(f, elem)
    else {
        return None;
    };
    let [vec, at] = args.as_slice() else { return None };
    load_of(*vec, 0, MemWidth::W8)?;
    let Some(Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { value, .. }))) = expr_of(f, *at) else {
        return None;
    };
    if load_of(*value, 8, MemWidth::W4)? != index {
        return None;
    }
    let Some(Expr::Binary { op: BinaryOp::Add, lhs, rhs }) = expr_of(f, bumped) else { return None };
    let plus_one =
        [(*lhs, *rhs), (*rhs, *lhs)].iter().any(|(a, k)| load_of(*a, 8, MemWidth::W4) == Some(index) && trace_int(f, *k) == Some(1));
    if !plus_one {
        return None;
    }
    // The tag: `2` from the end test's side, whether the element lacks the
    // type's tag from the read side.
    let Some(Expr::Phi { incoming }) = expr_of(f, tag) else { return None };
    let then_blocks = super::enum_match::blocks_in(then_region);
    let mut ty = None;
    let mut none_seen = false;
    for (b, x) in incoming {
        if trace_int(f, *x) == Some(2) && (then_blocks.contains(b) || !else_blocks.contains(b)) {
            none_seen = true;
            continue;
        }
        if !else_blocks.contains(b) {
            return None;
        }
        let Some(Expr::Unary { op: UnaryOp::ExtendU32, value }) = expr_of(f, *x) else { return None };
        let Some(Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck { value: checked, tag, negated: true }))) =
            expr_of(f, *value)
        else {
            return None;
        };
        if resolve_use(f, *checked) != resolve_use(f, elem) {
            return None;
        }
        let t = whole_tag_type(*tag)?;
        if ty.replace(t.clone()).is_some_and(|prev| prev != t) {
            return None;
        }
    }
    // The end test's side transfers `2` and nothing else happens there.
    if !then_side_is_none(f, then_region, tag) {
        return None;
    }
    none_seen.then_some(ty).flatten()
}

/// The type whose `TryFromVal<Env, Val>` is this one object-tag test.
fn whole_tag_type(tag: u8) -> Option<KnownType> {
    match tag {
        val_abi::TAG_ADDRESS_OBJECT => Some(KnownType::Address),
        val_abi::TAG_BYTES_OBJECT => Some(KnownType::Bytes),
        val_abi::TAG_STRING_OBJECT => Some(KnownType::String),
        _ => None,
    }
}

/// Whether `region` only hands the tag merge `2`: an empty block at most,
/// and the transfer.
fn then_side_is_none(f: &HighFunction, region: &Region, tag: ValueId) -> bool {
    let mut ok = true;
    region.for_each_node(|n| match n {
        Region::Basic(b) => ok &= f.blocks.get(*b).is_some_and(|blk| blk.bindings.iter().all(|v| {
            matches!(f.bindings.get(*v).map(|b| &b.expr), Some(Expr::Literal(_)))
        })),
        Region::Transfer { transfer, .. } | Region::Break { transfer, .. } => {
            ok &= transfer.iter().all(|(phi, x)| *phi == resolve_use(f, tag) && trace_int(f, *x) == Some(2));
        }
        Region::Sequence(_) => {}
        _ => ok = false,
    });
    ok
}

/// Whether `f` is `Option::map(Result::unwrap)` over `try_next`'s result,
/// written through `out`: `(out, t, x)`, trapping for `t == 1` and
/// `t > 2`, tag `0` for `t == 2`, `x` at +8 and tag `1` for `t == 0`.
fn is_unwrap(f: &HighFunction, access: Option<&Vec<Option<ParamAccess>>>) -> bool {
    #[allow(clippy::print_stderr)]
    let no = |why: &str| -> bool {
        if std::env::var_os("SORDEC_ENUM_TRACE").is_some() {
            eprintln!("vec-iter: func_{} is no unwrap: {why}", sordec_common::IrId::index(f.id));
        }
        false
    };
    if f.signature.is_some() || f.params.len() != 3 {
        return no("not a three-parameter helper without a spec");
    }
    let Some(Some(out)) = access.and_then(|a| a.first()) else { return no("its out-pointer is used otherwise") };
    let set = |v: &[(u32, u32)]| v.iter().copied().collect::<HashSet<_>>();
    if !out.reads.is_empty() || set(&out.writes) != HashSet::from([(0, 8), (8, 8)]) || !out.must_writes.contains(&(0, 8)) {
        return no("its out-pointer is not stored at +0 and +8 only, the tag on every path");
    }
    let (out_p, t, x) = (f.params[0], f.params[1], f.params[2]);
    // The stores: `x` at +8, the tag merge at +0.
    let mut tag = None;
    let mut payload = None;
    for (b, v) in scheduled(f) {
        let Some(Expr::Store { addr, value, offset, width: MemWidth::W8 }) = f.bindings.get(v).map(|b| &b.expr) else {
            if matches!(f.bindings.get(v).map(|b| &b.expr), Some(Expr::Store { .. })) {
                return no("a store of another width");
            }
            continue;
        };
        if resolve_use(f, *addr) != out_p {
            return no("a store through something else");
        }
        match offset {
            0 if tag.is_none() => tag = Some(resolve_use(f, *value)),
            8 if payload.is_none() && resolve_use(f, *value) == x => payload = Some(b),
            _ => return no("a store that is neither the tag nor the payload"),
        }
    }
    let (Some(tag), Some(payload_block)) = (tag, payload) else { return no("no tag or payload store") };
    let Some(Expr::Phi { incoming }) = expr_of(f, tag) else { return no("the tag is no merge") };
    // The region, arm by arm.
    let Region::Sequence(items) = &f.region else { return no("its region is not a sequence") };
    // Blocks that only compute are not arms.
    let inert = |b: &BlockId| {
        f.blocks.get(*b).is_some_and(|blk| {
            blk.bindings.iter().all(|v| f.bindings.get(*v).is_some_and(|x| crate::effects::expr_effects(&x.expr).is_pure_total()))
        })
    };
    let mut it = items.iter().filter(|r| !matches!(r, Region::Basic(b) if inert(b)));
    // `if t > 2 { trap }`.
    let Some(Region::If { cond, then_region, else_region: None }) = it.next() else { return no("it does not open with a guard") };
    let gt2 = matches!(expr_of(f, *cond), Some(Expr::Binary { op: BinaryOp::GtU, lhs, rhs })
        if resolve_use(f, *lhs) == t && trace_int(f, *rhs) == Some(2));
    if !gt2 || !traps(then_region) {
        return no("the guard is not `t > 2` trapping");
    }
    // `'s: { match t { 1 => trap, 2 => { tag = 0; break 's } } ; store x ; tag = 1 }`.
    let Some(Region::Scope { out: scope, body }) = it.next() else { return no("no scope after the guard") };
    let Region::Sequence(inner) = body.as_ref() else { return no("the scope's body is not a sequence") };
    let Some(Region::Switch { index, arms, default, .. }) =
        inner.iter().find(|r| matches!(r, Region::Switch { .. }))
    else {
        return no("no switch in the scope");
    };
    let on_t = matches!(expr_of(f, *index), Some(Expr::Unary { op: UnaryOp::Wrap32, value }) if resolve_use(f, *value) == t)
        || resolve_use(f, *index) == t;
    // The default (`t == 0`) does no work and falls through to the store.
    fn idle(r: &Region, inert: &dyn Fn(&BlockId) -> bool) -> bool {
        match r {
            Region::Basic(b) => inert(b),
            Region::Sequence(items) => items.iter().all(|i| idle(i, inert)),
            Region::Transfer { transfer, .. } => transfer.is_empty(),
            _ => false,
        }
    }
    if !on_t || arms.len() != 2 || !falls_through(default) || !idle(default, &inert) {
        return no("the switch is not on `t` with two arms and an idle default");
    }
    let mut trap_one = false;
    let mut none_two = false;
    for arm in arms {
        match arm.cases.as_slice() {
            [1] => trap_one = traps(&arm.body),
            [2] => {
                let (mut zero, mut leaves) = (false, false);
                arm.body.for_each_node(|n| match n {
                    Region::Break { target, transfer } | Region::Transfer { target, transfer } => {
                        zero |= transfer.iter().any(|(p, v)| resolve_use(f, *p) == tag && trace_int(f, *v) == Some(0));
                        leaves |= matches!(n, Region::Break { .. }) && target == scope;
                    }
                    _ => {}
                });
                none_two = zero && leaves && !falls_through(&arm.body);
            }
            _ => return no("a switch arm for another case"),
        }
    }
    if !trap_one || !none_two {
        return no("`t == 1` does not trap or `t == 2` does not leave tag 0");
    }
    // After the switch, on case `0`: the payload store, then tag `1`.
    let after = super::enum_match::blocks_in(&Region::Sequence(
        inner.iter().skip_while(|r| !matches!(r, Region::Switch { .. })).skip(1).cloned().collect(),
    ));
    if !after.contains(&payload_block) {
        return no("the payload is not stored past the switch");
    }
    let mut one = false;
    for r in inner.iter().skip_while(|r| !matches!(r, Region::Switch { .. })).skip(1) {
        r.for_each_node(|n| {
            if let Region::Transfer { transfer, .. } | Region::Break { transfer, .. } = n {
                one |= transfer.iter().any(|(p, v)| resolve_use(f, *p) == tag && trace_int(f, *v) == Some(1));
            }
        });
    }
    // The tag merge holds only these two constants.
    let constants: HashSet<i128> = incoming.iter().filter_map(|(_, v)| trace_int(f, *v)).collect();
    if !(one && incoming.len() == 2 && constants == HashSet::from([0, 1])) {
        return no("the tag is not `1` with the payload and `0` without");
    }
    true
}

/// A region that does nothing but trap.
fn traps(r: &Region) -> bool {
    match r {
        Region::Unreachable | Region::Panic { .. } => true,
        Region::Sequence(items) => items.last().is_some_and(traps) && items.iter().all(|i| matches!(i, Region::Basic(_)) || traps(i)),
        _ => false,
    }
}

// ---------------------------------------------------------------------
// The loops
// ---------------------------------------------------------------------

/// One loop to rewrite.
#[derive(Debug)]
struct Site {
    header: BlockId,
    vec: ValueId,
    len: ValueId,
    ty: KnownType,
    /// The state's stores: the vector's, the zero index's, the length's.
    stores: [ValueId; 3],
    /// The calls and the loads of their results.
    spent: Vec<ValueId>,
    /// The end test's condition binding.
    cond: ValueId,
    /// The element loads.
    elements: Vec<ValueId>,
    /// The block after the test, where the counter steps.
    step_block: BlockId,
}

/// Every loop of `func` in the shape, or why one is refused.
fn plan(func: &HighFunction, nexts: &HashMap<FuncId, KnownType>, unwraps: &HashSet<FuncId>) -> Result<Vec<Site>, String> {
    let mut loops: Vec<(BlockId, &[Region], &Region)> = Vec::new();
    collect_loops(&func.region, &mut loops);
    let mut sites = Vec::new();
    for (header, body, parent_prev) in loops {
        if let Some(site) = site(func, header, body, parent_prev, nexts, unwraps)? {
            sites.push(site);
        }
    }
    if sites.is_empty() {
        return Ok(sites);
    }
    // Every touch of the state's and the slots' bytes is the sites'.
    let mut allowed: HashSet<ValueId> = HashSet::new();
    let mut ranges: Vec<(ValueId, u32, u32)> = Vec::new();
    for s in &sites {
        allowed.extend(s.stores);
        allowed.extend(s.spent.iter().copied());
        allowed.extend(s.elements.iter().copied());
        let st = state_of(func, s).ok_or("a state with no address")?;
        ranges.push((st.0, st.1, 16));
        for (base, at) in slots_of(func, s) {
            ranges.push((base, at, 16));
        }
    }
    for (_, id) in scheduled(func) {
        if allowed.contains(&id) {
            continue;
        }
        let Some(expr) = func.bindings.get(id).map(|b| &b.expr) else { continue };
        let fx = crate::effects::expr_effects(expr);
        if !fx.reads_memory && !fx.writes_memory {
            continue;
        }
        if touches(func, expr, &ranges) {
            return Err(format!("{id:?} may touch an iterator's bytes"));
        }
    }
    // Each call sees its own loop's state.
    let mut flow = Current { calls: HashMap::new(), resets: HashMap::new() };
    for (k, s) in sites.iter().enumerate() {
        for st in s.stores {
            flow.resets.insert(st, k);
        }
        flow.calls.insert(s.spent[0], (k, None));
    }
    let walked = reach::walk(func, &mut flow, None);
    if !walked.complete {
        return Err("the region could not be walked".into());
    }
    if flow.calls.values().any(|(k, seen)| *seen != Some(Some(*k))) {
        return Err("a next call does not see its own loop's state".into());
    }
    Ok(sites)
}

/// Which loop's state is current on a path (`None`: none, or two).
struct Current {
    resets: HashMap<ValueId, usize>,
    /// Each call's loop, and the state it saw on every visit, met.
    calls: HashMap<ValueId, (usize, Option<Option<usize>>)>,
}

impl reach::Flow for Current {
    type State = Option<usize>;

    fn join(into: &mut Option<usize>, other: &Option<usize>) {
        if into != other {
            *into = None;
        }
    }

    fn step(&mut self, id: ValueId, state: &mut Option<usize>) {
        if let Some(k) = self.resets.get(&id) {
            *state = Some(*k);
        } else if let Some((_, seen)) = self.calls.get_mut(&id) {
            *seen = match seen {
                None => Some(*state),
                Some(prev) if *prev == *state => Some(*prev),
                Some(_) => Some(None),
            };
        }
    }
}

/// Every loop in `region` with its body's items and the region just
/// before it in its sequence.
fn collect_loops<'r>(region: &'r Region, out: &mut Vec<(BlockId, &'r [Region], &'r Region)>) {
    match region {
        Region::Sequence(items) => {
            for (i, item) in items.iter().enumerate() {
                if let Region::Loop { header, body, .. } = item
                    && let Region::Sequence(b) = body.as_ref()
                    && i > 0
                {
                    out.push((*header, b.as_slice(), &items[i - 1]));
                }
                collect_loops(item, out);
            }
        }
        Region::Scope { body, .. } | Region::Loop { body, .. } => collect_loops(body, out),
        Region::If { then_region, else_region, .. } => {
            collect_loops(then_region, out);
            if let Some(e) = else_region {
                collect_loops(e, out);
            }
        }
        Region::Switch { arms, default, .. } => {
            arms.iter().for_each(|a| collect_loops(&a.body, out));
            collect_loops(default, out);
        }
        _ => {}
    }
}

/// The block's bindings that may write memory, by position.
fn writes_at(func: &HighFunction, ids: &[ValueId]) -> Vec<usize> {
    ids.iter()
        .enumerate()
        .filter(|(_, v)| func.bindings.get(**v).is_some_and(|b| crate::effects::expr_effects(&b.expr).writes_memory))
        .map(|(i, _)| i)
        .collect()
}

#[allow(clippy::too_many_lines)]
fn site(
    func: &HighFunction,
    header: BlockId,
    body: &[Region],
    before: &Region,
    nexts: &HashMap<FuncId, KnownType>,
    unwraps: &HashSet<FuncId>,
) -> Result<Option<Site>, String> {
    // The body: the calls' block, the end test, the element's block.
    let (Some(Region::Basic(head)), Some(Region::If { cond, then_region, else_region: None }), Some(Region::Basic(next))) =
        (body.first(), body.get(1), body.get(2))
    else {
        return Ok(None);
    };
    let Some(head_ids) = func.blocks.get(*head).map(|b| b.bindings.clone()) else { return Ok(None) };
    let call = |id: &ValueId| match func.bindings.get(*id).map(|b| &b.expr) {
        Some(Expr::Call { target, args }) => Some((*target, args.clone())),
        _ => None,
    };
    let Some((c1_at, c1)) = head_ids.iter().enumerate().find(|(_, id)| call(id).is_some_and(|(t, _)| nexts.contains_key(&t)))
    else {
        return Ok(None);
    };
    let (t1, a1) = call(c1).expect("a call");
    let ty = nexts[&t1].clone();
    let [o1, st] = a1.as_slice() else { return Ok(None) };
    let load = |id: ValueId| match func.bindings.get(id).map(|b| &b.expr) {
        Some(Expr::Load { addr, offset, width, .. }) => {
            let (b, k) = canon_addr(func, *addr);
            Some((b, k.checked_add(*offset)?, *width))
        }
        _ => None,
    };
    let (o1b, o1k) = canon_addr(func, *o1);
    // `t`, `x`, the unwrap, the tag, in order after the call.
    let rest = &head_ids[c1_at + 1..];
    let unwrap_at = rest.iter().position(|id| call(id).is_some_and(|(t, _)| unwraps.contains(&t))).ok_or("no unwrap after next")?;
    let c2 = rest[unwrap_at];
    let (_, a2) = call(&c2).expect("a call");
    let [o2, t, x] = a2.as_slice() else { return Err("an unwrap of another arity".into()) };
    let (t, x) = (resolve_use(func, *t), resolve_use(func, *x));
    if load(t) != Some((o1b, o1k, MemWidth::W8)) || load(x) != Some((o1b, o1k + 8, MemWidth::W8)) {
        return Err("the unwrap is not handed the next call's result".into());
    }
    let (o2b, o2k) = canon_addr(func, *o2);
    let Some(Expr::Binary { op: BinaryOp::Ne, lhs, rhs }) = expr_of(func, *cond) else {
        return Err("the end test is not `tag != 1`".into());
    };
    let tag = resolve_use(func, *lhs);
    if trace_int(func, *rhs) != Some(1) || load(tag) != Some((o2b, o2k, MemWidth::W8)) {
        return Err("the end test is not on the unwrap's tag".into());
    }
    // Nothing between the call and the tag load writes memory but the two
    // calls; `t`, `x` and the tag are in this block after their writers.
    let (c1i, c2i) = (c1_at, c1_at + 1 + unwrap_at);
    let pos = |v: ValueId| head_ids.iter().position(|x| *x == v);
    let (ti, xi, gi) = (pos(t).ok_or("t elsewhere")?, pos(x).ok_or("x elsewhere")?, pos(tag).ok_or("tag elsewhere")?);
    if !(c1i < ti && c1i < xi && ti < c2i && xi < c2i && c2i < gi) {
        return Err("the loads are not between their writers".into());
    }
    if writes_at(func, &head_ids[c1i..=gi]).iter().any(|i| c1i + i != c1i && c1i + i != c2i) {
        return Err("a write between the calls and the tag".into());
    }
    // The test's taken side leaves for good.
    if falls_through(then_region) {
        return Err("the end test's side falls through".into());
    }
    let mut continues = false;
    then_region.for_each_node(|n| continues |= matches!(n, Region::Continue { target, .. } if *target == header));
    if continues {
        return Err("the end test's side continues the loop".into());
    }
    // The element: loads of `o2+8` in the next block, before any write.
    let next_ids = func.blocks.get(*next).map(|b| b.bindings.clone()).unwrap_or_default();
    let first_write = writes_at(func, &next_ids).first().copied().unwrap_or(next_ids.len());
    let mut elements = Vec::new();
    for (i, id) in next_ids.iter().enumerate() {
        if load(*id) == Some((o2b, o2k + 8, MemWidth::W8)) {
            if i > first_write {
                return Err("an element load after a write".into());
            }
            elements.push(*id);
        }
    }
    if elements.is_empty() {
        return Err("no element read".into());
    }
    // The state, set just before the loop.
    let (sb, sk) = canon_addr(func, *st);
    let Region::Basic(set_block) = before else { return Err("the loop does not follow the state's setting".into()) };
    let set_ids = func.blocks.get(*set_block).map(|b| b.bindings.clone()).unwrap_or_default();
    let store_at = |off: u32, w: MemWidth| -> Option<(ValueId, ValueId)> {
        let hits: Vec<(ValueId, ValueId)> = set_ids
            .iter()
            .filter_map(|id| match func.bindings.get(*id).map(|b| &b.expr) {
                Some(Expr::Store { addr, value, offset, width }) if *width == w => {
                    let (b, k) = canon_addr(func, *addr);
                    (b == sb && k.checked_add(*offset) == Some(sk + off)).then_some((*id, resolve_use(func, *value)))
                }
                _ => None,
            })
            .collect();
        match hits.as_slice() {
            [one] => Some(*one),
            _ => None,
        }
    };
    let (s_vec, vec) = store_at(0, MemWidth::W8).ok_or("no single vector store")?;
    let (s_idx, zero) = store_at(8, MemWidth::W4).ok_or("no single index store")?;
    let (s_len, len) = store_at(12, MemWidth::W4).ok_or("no single length store")?;
    if trace_int(func, zero) != Some(0) {
        return Err("the index starts elsewhere than 0".into());
    }
    let len_of = matches!(expr_of(func, len), Some(Expr::Semantic(SemanticOp::Known(KnownOp::VecOp { kind: VecOpKind::Len, args })))
        if args.first().is_some_and(|a| resolve_use(func, *a) == vec));
    if !len_of {
        return Err("the length stored is not the vector's".into());
    }
    // Nothing after the stores in their block touches memory.
    let last = [s_vec, s_idx, s_len].iter().filter_map(|s| set_ids.iter().position(|x| x == s)).max().unwrap_or(0);
    let after: Vec<ValueId> = set_ids[last + 1..].to_vec();
    if after.iter().any(|v| func.bindings.get(*v).is_some_and(|b| {
        let fx = crate::effects::expr_effects(&b.expr);
        fx.reads_memory || fx.writes_memory
    })) {
        return Err("memory traffic between the state's setting and the loop".into());
    }
    // What goes is read by nothing but what goes with it: `t` and `x` by
    // the unwrap, the tag by the test, the calls by nothing.
    let uses = crate::dataflow::HighUseIndex::build(func);
    // A reader runs when a block schedules it or it is a merge; anything
    // else is residue an earlier rewrite left.
    let ran: HashSet<ValueId> = scheduled(func).into_iter().map(|(_, v)| v).collect();
    let live = |u: ValueId| ran.contains(&u) || matches!(func.bindings.get(u).map(|b| &b.expr), Some(Expr::Phi { .. }));
    let only = |v: ValueId, reader: Option<ValueId>| {
        uses.uses_of(v).iter().all(|site| match site {
            crate::dataflow::HighUseSite::Binding { user } => Some(*user) == reader || !live(*user),
            _ => false,
        })
    };
    if !(only(t, Some(c2)) && only(x, Some(c2)) && only(tag, Some(resolve_use(func, *cond))) && only(*c1, None) && only(c2, None)) {
        return Err("the iterator's values are read elsewhere".into());
    }
    let mut spent = vec![*c1, t, x, c2, tag];
    spent.dedup();
    Ok(Some(Site {
        header,
        vec,
        len,
        ty,
        stores: [s_vec, s_idx, s_len],
        spent,
        cond: *cond,
        elements,
        step_block: *next,
    }))
}

/// The state's base and offset.
fn state_of(func: &HighFunction, s: &Site) -> Option<(ValueId, u32)> {
    let Some(Expr::Call { args, .. }) = func.bindings.get(s.spent[0]).map(|b| &b.expr) else { return None };
    Some(canon_addr(func, *args.get(1)?))
}

/// The two out-slots' bases and offsets.
fn slots_of(func: &HighFunction, s: &Site) -> Vec<(ValueId, u32)> {
    s.spent
        .iter()
        .filter_map(|c| match func.bindings.get(*c).map(|b| &b.expr) {
            Some(Expr::Call { args, .. }) => args.first().map(|a| canon_addr(func, *a)),
            _ => None,
        })
        .collect()
}

/// Whether `expr` may touch any of `ranges` (`(base, offset, bytes)`).
fn touches(func: &HighFunction, expr: &Expr, ranges: &[(ValueId, u32, u32)]) -> bool {
    let hit = |addr: ValueId, off: u32, w: u32| {
        let (b, k) = canon_addr(func, addr);
        ranges.iter().any(|(rb, ro, rw)| {
            if *rb != b {
                return false;
            }
            let s = u64::from(k) + u64::from(off);
            s < u64::from(*ro) + u64::from(*rw) && u64::from(*ro) < s + u64::from(w)
        })
    };
    let bases: HashSet<ValueId> = ranges.iter().map(|(b, _, _)| *b).collect();
    // An address not a constant offset from a base, but computed from one,
    // may point anywhere in that frame.
    let derived = |a: ValueId| {
        let (b, _) = canon_addr(func, a);
        !bases.contains(&b) && derived_from(func, a, &bases)
    };
    match expr {
        Expr::Load { addr, offset, width, .. } => hit(*addr, *offset, width.bytes()) || derived(*addr),
        Expr::Store { addr, offset, width, value } => {
            hit(*addr, *offset, width.bytes()) || derived(*addr) || derived_from(func, *value, &bases)
        }
        // Anything else handed a pointer into the frame may touch it all.
        other => {
            let mut any = false;
            other.for_each_value_use(|u| any |= derived_from(func, u, &bases));
            any
        }
    }
}

/// Whether `v` is computed from one of `bases` (arithmetic, conversions,
/// merges, selects); past a bound, assumed so.
fn derived_from(func: &HighFunction, v: ValueId, bases: &HashSet<ValueId>) -> bool {
    let mut seen = HashSet::new();
    let mut stack = vec![v];
    while let Some(x) = stack.pop() {
        let x = resolve_use(func, x);
        if bases.contains(&x) {
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
            Some(Expr::Select { cond, if_true, if_false }) => stack.extend([*cond, *if_true, *if_false]),
            Some(Expr::Phi { incoming }) => stack.extend(incoming.iter().map(|(_, v)| *v)),
            Some(Expr::Unknown { args, .. }) => stack.extend(args.iter().copied()),
            Some(Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { value, .. }))) => stack.push(*value),
            _ => {}
        }
    }
    false
}

// ---------------------------------------------------------------------
// The rewrite
// ---------------------------------------------------------------------

fn apply(func: &mut HighFunction, s: Site) {
    let prov = |note: &str| Provenance::new(PASS_NAME, ProvenanceSource::SdkPattern, note.to_string());
    let fresh = |func: &mut HighFunction, ty: KnownType, expr: Expr, note: &str| -> ValueId {
        let id = ValueId::new(func.bindings.len() as u32);
        func.bindings.push(sordec_ir::Binding::new(id, IrType::Known(ty), expr, prov(note)));
        id
    };
    let [s_vec, s_idx, s_len] = s.stores;
    // The counter: `0` on entry (the index store's own constant), `i + 1`
    // past the test.
    let i = fresh(func, KnownType::U32, Expr::Phi { incoming: vec![] }, "the loop's index: the iterator's position");
    if let Some(b) = func.bindings.get_mut(s_idx) {
        b.expr = Expr::Literal(Literal::U32(0));
        b.ty = IrType::Known(KnownType::U32);
        b.add_provenance(prov("the iterator's starting index, the loop counter's first value"));
    }
    let one = fresh(func, KnownType::U32, Expr::Literal(Literal::U32(1)), "the loop counter's step");
    let next_i = fresh(func, KnownType::U32, Expr::Binary { op: BinaryOp::Add, lhs: i, rhs: one }, "the next round's index");
    if let Some(blk) = func.blocks.get_mut(s.step_block) {
        blk.bindings.splice(0..0, [one, next_i]);
    }
    // The test, on the counter.
    if let Some(b) = func.bindings.get_mut(s.cond) {
        b.expr = Expr::Binary { op: BinaryOp::GeU, lhs: i, rhs: s.len };
        b.ty = IrType::Known(KnownType::Bool);
        b.add_provenance(prov("the iterator's end: its index reached the length"));
    }
    // Each element: the vector's, at the counter.
    for e in &s.elements {
        let at = fresh(func, KnownType::Val, Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall {
            ty: KnownType::U32,
            value: i,
        })), "the element's index, as the host takes it");
        if let Some(blk) = func.blocks.get_mut(s.step_block)
            && let Some(p) = blk.bindings.iter().position(|v| v == e)
        {
            blk.bindings.insert(p, at);
        }
        if let Some(b) = func.bindings.get_mut(*e) {
            b.expr = Expr::Semantic(SemanticOp::Known(KnownOp::VecOp { kind: VecOpKind::Get, args: vec![s.vec, at] }));
            b.ty = IrType::Known(s.ty.clone());
            b.add_provenance(prov("the iterator's element: the vector's, at the loop's index, converted"));
        }
    }
    // What the iterator was goes.
    for v in s.spent.iter().copied().chain([s_vec, s_len]) {
        if let Some(b) = func.bindings.get_mut(v) {
            b.expr = Expr::Literal(Literal::Unit);
            b.ty = IrType::Known(KnownType::Unit);
            b.add_provenance(prov("the outlined vector iterator, read as the indexed loop it drives"));
        }
    }
    // The transfers: `0` into the counter on entry, `i + 1` on each way
    // round.
    let region = std::mem::replace(&mut func.region, Region::Unreachable);
    func.region = thread(region, s.header, i, s_idx, next_i);
}

/// `region` with the entry transfer before loop `header` and the counter's
/// step on its every `continue`.
fn thread(region: Region, header: BlockId, i: ValueId, zero: ValueId, next_i: ValueId) -> Region {
    let rec = |r: Region| thread(r, header, i, zero, next_i);
    match region {
        Region::Sequence(items) => {
            let mut out = Vec::with_capacity(items.len() + 1);
            for item in items {
                if matches!(&item, Region::Loop { header: h, .. } if *h == header) {
                    out.push(Region::Transfer { target: header, transfer: vec![(i, zero)] });
                    let Region::Loop { header, body, kind } = item else { unreachable!() };
                    out.push(Region::Loop { header, body: Box::new(step(*body, header, i, next_i)), kind });
                } else {
                    out.push(rec(item));
                }
            }
            Region::Sequence(out)
        }
        Region::Scope { out, body } => Region::Scope { out, body: Box::new(rec(*body)) },
        Region::Loop { header: h, body, kind } => Region::Loop { header: h, body: Box::new(rec(*body)), kind },
        Region::If { cond, then_region, else_region } => Region::If {
            cond,
            then_region: Box::new(rec(*then_region)),
            else_region: else_region.map(|e| Box::new(rec(*e))),
        },
        Region::Switch { index, arms, default, dispatch } => Region::Switch {
            index,
            arms: arms.into_iter().map(|a| sordec_ir::SwitchArm { cases: a.cases, body: rec(a.body) }).collect(),
            default: Box::new(rec(*default)),
            dispatch,
        },
        leaf => leaf,
    }
}

/// `region` (a loop body) with `i <- next_i` on every `continue` of
/// `header`, nested constructs included.
fn step(region: Region, header: BlockId, i: ValueId, next_i: ValueId) -> Region {
    let rec = |r: Region| step(r, header, i, next_i);
    match region {
        Region::Continue { target, mut transfer } if target == header => {
            transfer.push((i, next_i));
            Region::Continue { target, transfer }
        }
        Region::Sequence(items) => Region::Sequence(items.into_iter().map(rec).collect()),
        Region::Scope { out, body } => Region::Scope { out, body: Box::new(rec(*body)) },
        Region::Loop { header: h, body, kind } => Region::Loop { header: h, body: Box::new(rec(*body)), kind },
        Region::If { cond, then_region, else_region } => Region::If {
            cond,
            then_region: Box::new(rec(*then_region)),
            else_region: else_region.map(|e| Box::new(rec(*e))),
        },
        Region::Switch { index, arms, default, dispatch } => Region::Switch {
            index,
            arms: arms.into_iter().map(|a| sordec_ir::SwitchArm { cases: a.cases, body: rec(a.body) }).collect(),
            default: Box::new(rec(*default)),
            dispatch,
        },
        leaf => leaf,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{Arena, IrId, UnknownReason};
    use sordec_ir::{Binding, HighBlock, LoopKind, PanicKind, SwitchArm};

    use crate::marshalling::test_support::v;

    const NEXT: u32 = 1;
    const UNWRAP: u32 = 2;

    fn bb(i: u32) -> BlockId {
        BlockId::new(i)
    }

    struct Builder {
        b: Arena<ValueId, Binding>,
    }

    impl Builder {
        fn new() -> Self {
            Self { b: Arena::new() }
        }

        fn add(&mut self, ty: IrType, expr: Expr) -> u32 {
            let id = self.b.len() as u32;
            self.b.push(Binding::new(v(id), ty, expr, Provenance::new("seed", ProvenanceSource::DataFlow, "seed")));
            id
        }

        fn raw(&mut self, expr: Expr) -> u32 {
            self.add(IrType::Unknown(UnknownReason::InsufficientEvidence), expr)
        }

        fn lit(&mut self, n: i64) -> u32 {
            self.add(IrType::Known(KnownType::I64), Expr::Literal(Literal::I64(n)))
        }

        fn load(&mut self, base: u32, offset: u32, width: MemWidth) -> u32 {
            let ty = IrType::Unknown(UnknownReason::InsufficientEvidence);
            self.raw(Expr::Load { addr: v(base), offset, width, signed: None, ty })
        }

        fn store(&mut self, base: u32, value: u32, offset: u32, width: MemWidth) -> u32 {
            self.raw(Expr::Store { addr: v(base), value: v(value), offset, width })
        }

        fn func(self, id: u32, params: Vec<u32>, blocks: Vec<Vec<u32>>, region: Region) -> HighFunction {
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
                params: params.into_iter().map(v).collect(),
                returns: vec![],
            }
        }
    }

    /// Departures from the plain loop, each a reason to refuse.
    #[derive(Default)]
    struct Shape {
        /// The body stores into the iterator's index.
        foreign_store: bool,
        /// The element is read after a call in its block.
        late_element: bool,
    }

    /// The bindings the plain loop's rewrite spends, by number in
    /// [`caller`]: the state's stores and the iterator's calls and loads.
    const SPENT: [u32; 7] = [5, 6, 9, 10, 11, 14, 15];

    /// `for x in v.iter() { use(x) }` through the outlined helpers: `v`
    /// (v0), the frame (v1).
    fn caller(shape: &Shape) -> HighFunction {
        let mut f = Builder::new();
        let addresses = IrType::Known(KnownType::Vec(Box::new(IrType::Known(KnownType::Address))));
        let vec = f.add(addresses, Expr::Phi { incoming: vec![] });
        let fp = f.add(IrType::Known(KnownType::I32), Expr::Phi { incoming: vec![] });
        // The state: v2..v6.
        let len = f.raw(Expr::Semantic(SemanticOp::Known(KnownOp::VecOp { kind: VecOpKind::Len, args: vec![v(vec)] })));
        let zero = f.add(IrType::Known(KnownType::I32), Expr::Literal(Literal::I32(0)));
        let s_idx = f.store(fp, zero, 8, MemWidth::W4);
        let s_vec = f.store(fp, vec, 0, MemWidth::W8);
        let s_len = f.store(fp, len, 12, MemWidth::W4);
        // The calls: v7..v17.
        let k32 = f.add(IrType::Known(KnownType::I32), Expr::Literal(Literal::I32(32)));
        let o1 = f.raw(Expr::Binary { op: BinaryOp::Add, lhs: v(fp), rhs: v(k32) });
        let c1 = f.raw(Expr::Call { target: FuncId::from_index(NEXT), args: vec![v(o1), v(fp)] });
        let t = f.load(fp, 32, MemWidth::W8);
        let x = f.load(fp, 40, MemWidth::W8);
        let k16 = f.add(IrType::Known(KnownType::I32), Expr::Literal(Literal::I32(16)));
        let o2 = f.raw(Expr::Binary { op: BinaryOp::Add, lhs: v(fp), rhs: v(k16) });
        let c2 = f.raw(Expr::Call { target: FuncId::from_index(UNWRAP), args: vec![v(o2), v(t), v(x)] });
        let tag = f.load(fp, 16, MemWidth::W8);
        let one = f.lit(1);
        let cond = f.raw(Expr::Binary { op: BinaryOp::Ne, lhs: v(tag), rhs: v(one) });
        // The body.
        let mut next = Vec::new();
        if shape.late_element {
            next.push(f.raw(Expr::Call { target: FuncId::from_index(9), args: vec![v(fp)] }));
        }
        let e = f.load(fp, 24, MemWidth::W8);
        next.push(e);
        next.push(f.raw(Expr::Call { target: FuncId::from_index(9), args: vec![v(e)] }));
        if shape.foreign_store {
            let seven = f.add(IrType::Known(KnownType::I32), Expr::Literal(Literal::I32(7)));
            next.extend([seven, f.store(fp, seven, 8, MemWidth::W4)]);
        }
        let blocks = vec![
            vec![len, zero, s_idx, s_vec, s_len],
            vec![k32, o1, c1, t, x, k16, o2, c2, tag, one, cond],
            next,
        ];
        let region = Region::Sequence(vec![
            Region::Basic(bb(0)),
            Region::Loop {
                header: bb(1),
                body: Box::new(Region::Sequence(vec![
                    Region::Basic(bb(1)),
                    Region::If { cond: v(cond), then_region: Box::new(Region::Return { values: vec![] }), else_region: None },
                    Region::Basic(bb(2)),
                    Region::Continue { target: bb(1), transfer: vec![] },
                ])),
                kind: LoopKind::Infinite,
            },
        ]);
        f.func(0, vec![vec, fp], blocks, region)
    }

    fn run_plan(func: &mut HighFunction) -> Result<usize, String> {
        let nexts = HashMap::from([(FuncId::from_index(NEXT), KnownType::Address)]);
        let unwraps = HashSet::from([FuncId::from_index(UNWRAP)]);
        let sites = plan(func, &nexts, &unwraps)?;
        let n = sites.len();
        for s in sites {
            apply(func, s);
        }
        Ok(n)
    }

    /// The loop counts: `0` in, `i + 1` round, `i >= len` out, and the
    /// element is the vector's at `i`.
    #[test]
    fn an_outlined_iterator_loop_becomes_indexed() {
        let mut func = caller(&Shape::default());
        assert_eq!(run_plan(&mut func), Ok(1));
        let is_get = |id: &ValueId| {
            matches!(
                func.bindings.get(*id).map(|b| &b.expr),
                Some(Expr::Semantic(SemanticOp::Known(KnownOp::VecOp { kind: VecOpKind::Get, .. })))
            )
        };
        let e = func.blocks.get(bb(2)).unwrap().bindings.iter().copied().find(is_get).expect("the element");
        assert_eq!(func.bindings.get(e).unwrap().ty, IrType::Known(KnownType::Address));
        let cond = &func.bindings.get(v(17)).unwrap().expr;
        assert!(matches!(cond, Expr::Binary { op: BinaryOp::GeU, .. }), "{cond:?}");
        let mut entry = 0;
        let mut stepped = 0;
        func.region.for_each_node(|n| match n {
            Region::Transfer { transfer, .. } => entry += transfer.len(),
            Region::Continue { transfer, .. } => stepped += transfer.len(),
            _ => {}
        });
        assert_eq!((entry, stepped), (1, 1), "the counter is set on entry and stepped on the way round");
        for spent in SPENT {
            assert!(matches!(func.bindings.get(v(spent)).unwrap().expr, Expr::Literal(Literal::Unit)), "v{spent}");
        }
    }

    #[test]
    fn another_write_to_the_state_keeps_the_loop() {
        let mut func = caller(&Shape { foreign_store: true, ..Shape::default() });
        assert!(run_plan(&mut func).is_err());
    }

    #[test]
    fn an_element_read_after_a_call_keeps_the_loop() {
        let mut func = caller(&Shape { late_element: true, ..Shape::default() });
        assert!(run_plan(&mut func).is_err());
    }

    /// `VecTryIter::next` for a vector of `tag`'s type.
    fn next_helper(tag: u8) -> HighFunction {
        let mut f = Builder::new();
        let out = f.add(IrType::Known(KnownType::I32), Expr::Phi { incoming: vec![] });
        let st = f.add(IrType::Known(KnownType::I32), Expr::Phi { incoming: vec![] });
        let none = f.lit(2);
        let idx = f.load(st, 8, MemWidth::W4);
        let end = f.load(st, 12, MemWidth::W4);
        let done = f.raw(Expr::Binary { op: BinaryOp::GeU, lhs: v(idx), rhs: v(end) });
        let vec = f.load(st, 0, MemWidth::W8);
        let at = f.raw(Expr::Semantic(SemanticOp::Known(KnownOp::ValEncodeSmall { ty: KnownType::U32, value: v(idx) })));
        let get = f.raw(Expr::Semantic(SemanticOp::Known(KnownOp::VecOp { kind: VecOpKind::Get, args: vec![v(vec), v(at)] })));
        let put = f.store(out, get, 8, MemWidth::W8);
        let one = f.add(IrType::Known(KnownType::I32), Expr::Literal(Literal::I32(1)));
        let bumped = f.raw(Expr::Binary { op: BinaryOp::Add, lhs: v(idx), rhs: v(one) });
        let save = f.store(st, bumped, 8, MemWidth::W4);
        let lacks = f.raw(Expr::Semantic(SemanticOp::Known(KnownOp::ValTagCheck { value: v(get), tag, negated: true })));
        let err = f.raw(Expr::Unary { op: UnaryOp::ExtendU32, value: v(lacks) });
        let tagged = f.raw(Expr::Phi { incoming: vec![(bb(0), v(none)), (bb(1), v(err))] });
        let write = f.store(out, tagged, 0, MemWidth::W8);
        let blocks = vec![vec![none, idx, end, done], vec![vec, at, get, put, one, bumped, save, lacks, err], vec![write]];
        let region = Region::Sequence(vec![
            Region::Basic(bb(0)),
            Region::If {
                cond: v(done),
                then_region: Box::new(Region::Transfer { target: bb(2), transfer: vec![(v(tagged), v(none))] }),
                else_region: Some(Box::new(Region::Sequence(vec![
                    Region::Basic(bb(1)),
                    Region::Transfer { target: bb(2), transfer: vec![(v(tagged), v(err))] },
                ]))),
            },
            Region::Basic(bb(2)),
            Region::Return { values: vec![] },
        ]);
        f.func(NEXT, vec![out, st], blocks, region)
    }

    fn classify_next(f: &HighFunction) -> Option<KnownType> {
        typed_next(f, Some(&param_accesses(f)))
    }

    #[test]
    fn a_typed_next_is_recognised_by_its_one_tag() {
        assert_eq!(classify_next(&next_helper(val_abi::TAG_ADDRESS_OBJECT)), Some(KnownType::Address));
        // A symbol has two forms: one tag test is not its conversion.
        assert_eq!(classify_next(&next_helper(val_abi::TAG_SYMBOL_OBJECT)), None);
    }

    /// `Option::map(Result::unwrap)` written through `out`; with
    /// `trap_on_err: false` the `Err` arm leaves a tag instead of trapping.
    fn unwrap_helper(trap_on_err: bool) -> HighFunction {
        let mut f = Builder::new();
        let out = f.add(IrType::Known(KnownType::I32), Expr::Phi { incoming: vec![] });
        let t = f.add(IrType::Known(KnownType::I64), Expr::Phi { incoming: vec![] });
        let x = f.add(IrType::Known(KnownType::Val), Expr::Phi { incoming: vec![] });
        let two = f.lit(2);
        let gt2 = f.raw(Expr::Binary { op: BinaryOp::GtU, lhs: v(t), rhs: v(two) });
        let zero = f.lit(0);
        let word = f.raw(Expr::Unary { op: UnaryOp::Wrap32, value: v(t) });
        let put = f.store(out, x, 8, MemWidth::W8);
        let one = f.lit(1);
        let tag = f.raw(Expr::Phi { incoming: vec![(bb(1), v(zero)), (bb(2), v(one))] });
        let write = f.store(out, tag, 0, MemWidth::W8);
        let blocks = vec![vec![two, gt2], vec![zero, word], vec![put, one], vec![write]];
        let scope = bb(3);
        let err_arm = if trap_on_err {
            Region::Unreachable
        } else {
            Region::Break { target: scope, transfer: vec![(v(tag), v(one))] }
        };
        let region = Region::Sequence(vec![
            Region::Basic(bb(0)),
            Region::If { cond: v(gt2), then_region: Box::new(Region::Panic { kind: PanicKind::Bare }), else_region: None },
            Region::Scope {
                out: scope,
                body: Box::new(Region::Sequence(vec![
                    Region::Basic(bb(1)),
                    Region::Switch {
                        index: v(word),
                        arms: vec![
                            SwitchArm { cases: vec![1], body: err_arm },
                            SwitchArm { cases: vec![2], body: Region::Break { target: scope, transfer: vec![(v(tag), v(zero))] } },
                        ],
                        default: Box::new(Region::Sequence(vec![])),
                        dispatch: None,
                    },
                    Region::Basic(bb(2)),
                    Region::Transfer { target: scope, transfer: vec![(v(tag), v(one))] },
                ])),
            },
            Region::Basic(bb(3)),
            Region::Return { values: vec![] },
        ]);
        f.func(UNWRAP, vec![out, t, x], blocks, region)
    }

    #[test]
    fn the_unwrap_helper_is_recognised_arm_by_arm() {
        let f = unwrap_helper(true);
        assert!(is_unwrap(&f, Some(&param_accesses(&f))));
        // An `Err` that does not trap is not `unwrap`.
        let f = unwrap_helper(false);
        assert!(!is_unwrap(&f, Some(&param_accesses(&f))));
    }
}
