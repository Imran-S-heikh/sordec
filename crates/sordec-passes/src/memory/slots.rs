//! Pointer-base aliasing analysis — the SROA half, shared.
//!
//! Both shadow-stack passes ask the same three questions about a pointer
//! before they will touch anything it addresses:
//!
//! 1. Which values *are* this pointer? (the base, its aliases, and any
//!    `add` of one with a constant)
//! 2. Does anything consume one of them that we have not accounted for?
//! 3. What does this memory operator do — load or store, how wide, at what
//!    offset?
//!
//! [`super::promote`] asks them about a **frame base**; [`super::argpromote`]
//! asks them about a **parameter**. Nothing in the analysis cares which,
//! because "an address we cannot follow may alias anything reachable from
//! it" is a property of the pointer, not of where it came from. Keeping one
//! copy is what stops the two passes disagreeing about what an escape is —
//! and they must not, because between them they decide which memory traffic
//! is safe to delete.
//!
//! ## The rule that is easy to get wrong
//!
//! Every scan here works over the **scheduled** value set, never the whole
//! arena. See [`scheduled`] for what happens otherwise; it is not a
//! micro-optimisation but the difference between 4 and 29 analysable frames
//! on one fixture.

use std::collections::HashSet;

use sordec_common::ValueId;
use sordec_ir::{LiftedFunction, LiftedTerminator, LiftedType, LiftedValueDef, WasmOp};

use super::frame::canon_addr;
use crate::dataflow::{for_each_target, CfgFacts};

/// Every value id that some reachable block actually schedules, plus the
/// block parameters.
///
/// **Every scan here works over this set, never over the whole
/// arena.** De-cluttering leaves unscheduled residue behind — alias
/// tombstones and dead phis that still name an address — and the
/// arenas are push-only, so that residue is permanent. Counting it as a use
/// made 25 of token-v23's 29 frames look like they escaped. The same
/// mistake, in its `HighIr` form, previously made every out-parameter in
/// the corpus look un-analysable.
pub(super) fn scheduled(func: &LiftedFunction, cfg: &CfgFacts) -> HashSet<ValueId> {
    let mut live: HashSet<ValueId> = HashSet::new();
    for (block_id, block) in func.blocks.iter() {
        if !cfg.is_reachable(block_id) {
            continue;
        }
        live.extend(block.instructions.iter().copied());
        live.extend(block.params.iter().copied());
    }
    live
}

/// Every value that *is* an address derived from `base`: the base
/// itself, its aliases, and any `add` of one of those with a constant.
pub(super) fn address_closure(
    func: &LiftedFunction,
    base: ValueId,
    live: &HashSet<ValueId>,
) -> HashSet<ValueId> {
    let mut closure: HashSet<ValueId> = HashSet::new();
    closure.insert(base);
    for (id, value) in func.values.iter() {
        if !live.contains(&id) {
            continue;
        }
        let derived = match &value.def {
            LiftedValueDef::Alias(from) => closure.contains(from),
            LiftedValueDef::Operator { .. } => canon_addr(func, id).0 == base,
            _ => false,
        };
        if derived {
            closure.insert(id);
        }
    }
    closure
}

/// Whether every consumer of an address derived from `base` is an access
/// we accounted for, further address arithmetic, or a frame bracket's own
/// `global.set`.
///
/// This is the aliasing gate. It is written as "what is allowed" rather
/// than "what is forbidden" so that an operator nobody thought about
/// declines instead of slipping through.
pub(super) fn addresses_only_flow_to(
    func: &LiftedFunction,
    addresses: &HashSet<ValueId>,
    accessors: &HashSet<ValueId>,
    live: &HashSet<ValueId>,
) -> bool {
    for (id, value) in func.values.iter() {
        if !live.contains(&id) || accessors.contains(&id) || addresses.contains(&id) {
            continue;
        }
        let consumes = match &value.def {
            LiftedValueDef::Operator { op, args } => {
                let mentions = args.iter().any(|a| addresses.contains(a));
                // The bracket publishes the pointer back to its global; that
                // is the frame's own bookkeeping, not an escape into code
                // that could alias a slot.
                mentions && !is_global_set(op)
            }
            LiftedValueDef::Alias(from) | LiftedValueDef::PickOutput { from, .. } => {
                addresses.contains(from)
            }
            LiftedValueDef::BlockParam { .. } => false,
        };
        if consumes {
            return false;
        }
    }
    // A frame address that leaves through a terminator escapes the function.
    !func.blocks.iter().any(|(_, block)| {
        let mut escapes = false;
        for_each_target(&block.terminator, |t| {
            escapes |= t.args.iter().any(|a| addresses.contains(a));
        });
        if let LiftedTerminator::Return { values } = &block.terminator {
            escapes |= values.iter().any(|v| addresses.contains(v));
        }
        escapes
    })
}

/// Why a frame declined, when it declined because an address escaped.
///
/// `promote` rejects a frame **whole**, so "the shadow stack is hard" is
/// all the pass itself can say. This says which *other* pass would have to
/// exist to unblock it, which is the difference between a mood and a work
/// item.
///
/// What escaped, and whether it can be pinned to particular bytes.
///
/// [`first_escape`] answers "did anything escape", which is all a
/// whole-frame decline needs. This answers the question promotion actually
/// wants: *which slots* are out of reach, so the rest can still be
/// promoted.
pub(super) enum FrameEscapes {
    /// Nothing escaped. Every slot is an ordinary local variable.
    Clean,
    /// Every escape was a call whose footprint we bounded. The ranges are
    /// half-open and in the **caller's** frame-offset space, so they can be
    /// compared against slot offsets directly.
    Bounded(Vec<(i64, i64)>),
    /// Something escaped that cannot be pinned to bytes, so no slot is safe.
    /// Carries why, for the census.
    Unbounded(EscapeReason),
}

/// Why an escape could not be pinned to particular bytes.
///
/// The census reports these, and the point of the breakdown is that each
/// one names a different piece of missing work rather than a mood.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EscapeReason {
    /// Left through something that is not a direct call at all: a host
    /// import, a return, a terminator, or stored as a value.
    NotACall,
    /// A direct call whose callee could not be resolved, or which passed
    /// the address in a position the callee has no parameter for.
    CalleeUnresolved,
    /// Inside the callee, an access through the pointer is not at a
    /// constant offset from it — an indexed write, say. Bounding these
    /// needs the index's range, which the IR does not carry.
    OffsetNotConstant,
    /// The pointer escapes the callee as well, so its footprint is
    /// whatever the next callee does.
    EscapesAgain,
}

/// Classify every escape of a frame address, bounding what can be bounded.
///
/// The shape mirrors [`first_escape`] deliberately — the two must agree
/// about what counts as an escape, or promotion and the census that explains
/// it would tell different stories.
#[allow(clippy::too_many_arguments)]
pub(super) fn frame_escapes(
    func: &LiftedFunction,
    ir: &sordec_ir::LiftedIr,
    calls: &super::calls::CallIndex,
    base: ValueId,
    addresses: &HashSet<ValueId>,
    accessors: &HashSet<ValueId>,
    live: &HashSet<ValueId>,
) -> FrameEscapes {
    let mut ranges: Vec<(i64, i64)> = Vec::new();
    let (tagged, chain) = tagged_pointers(func, addresses, base);
    for (id, value) in func.values.iter() {
        if !live.contains(&id)
            || accessors.contains(&id)
            || addresses.contains(&id)
            || chain.contains(&id)
            || tagged.contains_key(&id)
        {
            continue;
        }
        match &value.def {
            LiftedValueDef::Operator { op, args } => {
                // A tagged pointer on its way to the host. Every
                // linear-memory host function takes a `(pos, len)` pair and
                // works forward from `pos`, so what it reaches is everything
                // at or after the pointer — the length would only narrow
                // that, and slots *before* the pointer are untouched either
                // way. That is the whole gain: a frame whose tail is handed
                // to `vec_new_from_linear_memory` still promotes its head.
                if let Some(&offset) = args.iter().find_map(|a| tagged.get(a)) {
                    ranges.push((offset, REACH_ONWARD));
                    continue;
                }
                if !args.iter().any(|a| addresses.contains(a)) || is_global_set(op) {
                    continue;
                }
                let Some(target) = calls.target(op) else {
                    return FrameEscapes::Unbounded(EscapeReason::NotACall);
                };
                let mut seen = HashSet::new();
                match callee_footprint(
                    ir, calls, target, args, addresses, func, REACH_DEPTH, &mut seen,
                ) {
                    Ok(bounded) => ranges.extend(bounded),
                    Err(why) => return FrameEscapes::Unbounded(why),
                }
            }
            LiftedValueDef::Alias(from) | LiftedValueDef::PickOutput { from, .. } => {
                if addresses.contains(from) {
                    return FrameEscapes::Unbounded(EscapeReason::NotACall);
                }
            }
            LiftedValueDef::BlockParam { .. } => {}
        }
    }
    for (_, block) in func.blocks.iter() {
        let mut escapes = false;
        for_each_target(&block.terminator, |t| {
            escapes |= t.args.iter().any(|a| addresses.contains(a));
        });
        if let LiftedTerminator::Return { values } = &block.terminator {
            escapes |= values.iter().any(|v| addresses.contains(v));
        }
        if escapes {
            return FrameEscapes::Unbounded(EscapeReason::NotACall);
        }
    }
    if ranges.is_empty() {
        FrameEscapes::Clean
    } else {
        FrameEscapes::Bounded(ranges)
    }
}

/// Address-derived values that are a pointer *tagged* for the host, and the
/// intermediate values of the chains that build them.
///
/// The first maps the tagged value to the pointer's offset from `base`; the
/// second is every `extend`/`shl` on the way, which must not be mistaken for
/// an escape in its own right.
fn tagged_pointers(
    func: &LiftedFunction,
    addresses: &HashSet<ValueId>,
    base: ValueId,
) -> (std::collections::HashMap<ValueId, i64>, HashSet<ValueId>) {
    let mut tagged = std::collections::HashMap::new();
    let mut chain = HashSet::new();
    for (id, _) in func.values.iter() {
        let Some(inner) = u32val_encoded(func, id) else {
            continue;
        };
        if !addresses.contains(&inner) {
            continue;
        }
        let (canon_base, delta) = canon_addr(func, inner);
        if canon_base != canon_addr(func, base).0 {
            continue;
        }
        tagged.insert(id, i64::from(delta));
        // The `shl` and the `extend` exist only to build this value.
        if let Some((_, or_args)) = operator(func, id) {
            for &a in or_args {
                chain.insert(a);
                if let Some((_, shl_args)) = operator(func, a) {
                    for &b in shl_args {
                        chain.insert(b);
                    }
                }
            }
        }
    }
    (tagged, chain)
}

/// An offset past the end of any shadow stack, standing in for "everything
/// from here onward".
///
/// Real frames are tens of bytes; rustc's largest in this corpus is a few
/// hundred. A sentinel is used rather than `i64::MAX` so that shifting a
/// range into a caller's offsets cannot overflow.
const REACH_ONWARD: i64 = 1 << 40;

/// The `i32` a value tags as a `U32Val`, if that is what it is.
///
/// Soroban passes a linear-memory position to the host as a `U32Val`, which
/// on wasm is exactly `(extend_i32_u(x) << 32) | 4` — tag 4 being
/// `TAG_U32_VAL`. Recognising the shape is what lets a frame address reach
/// a host call without the whole frame going opaque: the chain widens and
/// tags the pointer, it does not move it.
fn u32val_encoded(func: &LiftedFunction, value: ValueId) -> Option<ValueId> {
    let (or_op, or_args) = operator(func, value)?;
    if !matches!(or_op.0, waffle::Operator::I64Or) || or_args.len() != 2 {
        return None;
    }
    // `| 4` in either position.
    let (shifted, _) = or_args
        .iter()
        .copied()
        .find(|&a| const_i64(func, a) != Some(4))
        .zip(
            or_args
                .iter()
                .copied()
                .find(|&a| const_i64(func, a) == Some(4)),
        )?;
    let (shl_op, shl_args) = operator(func, shifted)?;
    if !matches!(shl_op.0, waffle::Operator::I64Shl) || shl_args.len() != 2 {
        return None;
    }
    if const_i64(func, shl_args[1]) != Some(32) {
        return None;
    }
    let (ext_op, ext_args) = operator(func, shl_args[0])?;
    if !matches!(ext_op.0, waffle::Operator::I64ExtendI32U) || ext_args.len() != 1 {
        return None;
    }
    Some(ext_args[0])
}

/// The operator defining `value`, following alias tombstones.
fn operator(func: &LiftedFunction, value: ValueId) -> Option<(&WasmOp, &[ValueId])> {
    match &func.values.get(value)?.def {
        LiftedValueDef::Operator { op, args } => Some((op, args)),
        _ => None,
    }
}

/// `value`'s constant, when it is an `i64.const` or an `i32.const`.
fn const_i64(func: &LiftedFunction, value: ValueId) -> Option<i64> {
    match operator(func, value)?.0 .0 {
        waffle::Operator::I64Const { value } => Some(value as i64),
        waffle::Operator::I32Const { value } => Some(i64::from(value as i32)),
        _ => None,
    }
}

/// How many call levels a footprint is followed through.
///
/// rustc's shadow-stack helpers nest a few deep — an entrypoint calls a
/// converter which calls an accessor — and each level is one more function
/// to read. The bound is what stops a pathological chain, not a tuning
/// knob; a chain deeper than this declines, which is the same answer as
/// before the recursion existed.
const REACH_DEPTH: u32 = 8;

/// The caller-relative ranges one call reaches through the frame addresses
/// it was passed, or why they cannot be bounded.
#[allow(clippy::too_many_arguments)]
fn callee_footprint(
    ir: &sordec_ir::LiftedIr,
    calls: &super::calls::CallIndex,
    target: sordec_common::FuncId,
    args: &[ValueId],
    addresses: &HashSet<ValueId>,
    caller: &LiftedFunction,
    depth: u32,
    seen: &mut HashSet<sordec_common::FuncId>,
) -> Result<Vec<(i64, i64)>, EscapeReason> {
    let callee = ir.function(target).ok_or(EscapeReason::CalleeUnresolved)?;
    let params = &callee
        .blocks
        .get(callee.entry)
        .ok_or(EscapeReason::CalleeUnresolved)?
        .params;
    let mut out = Vec::new();
    for (position, arg) in args.iter().enumerate() {
        if !addresses.contains(arg) {
            continue;
        }
        let param = params
            .get(position)
            .copied()
            .ok_or(EscapeReason::CalleeUnresolved)?;
        // Where in *our* frame this argument points.
        let (_, delta) = canon_addr(caller, *arg);
        out.extend(
            param_footprint(ir, calls, callee, param, depth, seen)?.shifted(i64::from(delta)),
        );
    }
    Ok(out)
}

/// The byte ranges a callee touches through a pointer parameter, measured
/// from that pointer.
///
/// This is what turns "the frame escaped" into "these bytes escaped". A
/// helper handed `fp+16` that loads and stores only within its own 16 bytes
/// tells us nothing about `fp+0`, and the slot there is still an ordinary
/// local variable.
///
/// Reads and writes are both recorded and not distinguished, because either
/// one disqualifies a slot for the same reason: a write means a later load
/// must see the callee's value rather than ours, and a read means our store
/// is observed and cannot be deleted. What the caller needs is the union.
#[derive(Debug, Default, Clone)]
pub(super) struct Footprint {
    /// `(start, end)` byte ranges relative to the pointer, half-open.
    ranges: Vec<(i64, i64)>,
}

impl Footprint {
    /// Record one access at `offset` of `width` bytes.
    fn touch(&mut self, offset: i64, width: u32) {
        self.ranges.push((offset, offset + i64::from(width)));
    }

    /// Shift every range into the caller's frame offsets. `delta` is the
    /// constant the caller added to the frame base before passing it.
    fn shifted(&self, delta: i64) -> Vec<(i64, i64)> {
        self.ranges
            .iter()
            .map(|(s, e)| (s.saturating_add(delta), e.saturating_add(delta)))
            .collect()
    }
}

/// `param`'s footprint inside `callee`, or why it cannot be bounded.
///
/// Follows the pointer through further calls, up to [`REACH_DEPTH`].
///
/// Declines when the pointer escapes the callee as well, and for one more
/// reason of its own: an access whose address does not
/// canonicalise to *this parameter* plus a constant. A pointer that arrives
/// through a phi of two bases, or is computed by arithmetic
/// [`canon_addr`] will not fold, has no offset we can name, and a footprint
/// that silently omitted it would be a promise we cannot keep.
fn param_footprint(
    ir: &sordec_ir::LiftedIr,
    calls: &super::calls::CallIndex,
    callee: &LiftedFunction,
    param: ValueId,
    depth: u32,
    seen: &mut HashSet<sordec_common::FuncId>,
) -> Result<Footprint, EscapeReason> {
    if depth == 0 {
        return Err(EscapeReason::EscapesAgain);
    }
    // A cycle has no fixed point we can compute by descending, and a helper
    // that reaches itself reaches whatever the recursion would have found.
    if !seen.insert(callee.id) {
        return Err(EscapeReason::EscapesAgain);
    }
    let result = param_footprint_inner(ir, calls, callee, param, depth, seen);
    seen.remove(&callee.id);
    result
}

fn param_footprint_inner(
    ir: &sordec_ir::LiftedIr,
    calls: &super::calls::CallIndex,
    callee: &LiftedFunction,
    param: ValueId,
    depth: u32,
    seen: &mut HashSet<sordec_common::FuncId>,
) -> Result<Footprint, EscapeReason> {
    let live: HashSet<ValueId> = callee.values.iter().map(|(id, _)| id).collect();
    let addresses = address_closure(callee, param, &live);
    let param_base = canon_addr(callee, param).0;
    let mut accessors = HashSet::new();
    let mut footprint = Footprint::default();

    // What this function itself reads and writes through the pointer.
    for (_, block) in callee.blocks.iter() {
        for &id in &block.instructions {
            let Some(value) = callee.values.get(id) else {
                continue;
            };
            let LiftedValueDef::Operator { op, args } = &value.def else {
                continue;
            };
            let Some(shape) = access_shape(op) else { continue };
            let Some(addr) = args.first() else { continue };
            if !addresses.contains(addr) {
                continue;
            }
            accessors.insert(id);
            let (base, delta) = canon_addr(callee, *addr);
            if base != param_base {
                return Err(EscapeReason::OffsetNotConstant);
            }
            footprint.touch(i64::from(delta) + i64::from(shape.memarg_offset), shape.width);
        }
    }

    // And what it reaches by passing the pointer on. Descending here is the
    // difference between "the callee forwards it, so we know nothing" and
    // "the callee forwards it *to something that touches these bytes*" —
    // measured as the single biggest reason frames were refused.
    let (tagged, chain) = tagged_pointers(callee, &addresses, param);
    for (id, value) in callee.values.iter() {
        if !live.contains(&id)
            || accessors.contains(&id)
            || addresses.contains(&id)
            || chain.contains(&id)
            || tagged.contains_key(&id)
        {
            continue;
        }
        match &value.def {
            LiftedValueDef::Operator { op, args } => {
                // As in `frame_escapes`: a tagged pointer handed to the host
                // reaches everything at or after it.
                if let Some(&offset) = args.iter().find_map(|a| tagged.get(a)) {
                    footprint.ranges.push((offset, REACH_ONWARD));
                    continue;
                }
                if !args.iter().any(|a| addresses.contains(a)) || is_global_set(op) {
                    continue;
                }
                let Some(target) = calls.target(op) else {
                    return Err(EscapeReason::NotACall);
                };
                for (start, end) in callee_footprint(
                    ir,
                    calls,
                    target,
                    args,
                    &addresses,
                    callee,
                    depth - 1,
                    seen,
                )? {
                    footprint.ranges.push((start, end));
                }
            }
            LiftedValueDef::Alias(from) | LiftedValueDef::PickOutput { from, .. } => {
                if addresses.contains(from) {
                    return Err(EscapeReason::NotACall);
                }
            }
            LiftedValueDef::BlockParam { .. } => {}
        }
    }
    for (_, block) in callee.blocks.iter() {
        let mut escapes = false;
        for_each_target(&block.terminator, |t| {
            escapes |= t.args.iter().any(|a| addresses.contains(a));
        });
        if let LiftedTerminator::Return { values } = &block.terminator {
            escapes |= values.iter().any(|v| addresses.contains(v));
        }
        if escapes {
            return Err(EscapeReason::NotACall);
        }
    }
    Ok(footprint)
}

fn is_global_set(op: &WasmOp) -> bool {
    matches!(op.0, waffle::Operator::GlobalSet { .. })
}

/// What one memory access does.
pub(super) struct AccessShape {
    pub(super) is_store: bool,
    pub(super) width: u32,
    pub(super) memarg_offset: u32,
    pub(super) ty: LiftedType,
}

/// Classify a memory operator, or `None` for anything that is not one.
///
/// Sub-word accesses are deliberately absent. An `i64.load8_u` reads one
/// byte of a slot and sign/zero-extends it; promoting that would need the
/// slot modelled as bytes rather than as a scalar, and the corpus does not
/// contain one on a frame.
pub(super) fn access_shape(op: &WasmOp) -> Option<AccessShape> {
    let (is_store, width, ty, memarg) = match &op.0 {
        waffle::Operator::I32Load { memory } => (false, 4, LiftedType::I32, memory),
        waffle::Operator::I64Load { memory } => (false, 8, LiftedType::I64, memory),
        waffle::Operator::F32Load { memory } => (false, 4, LiftedType::F32, memory),
        waffle::Operator::F64Load { memory } => (false, 8, LiftedType::F64, memory),
        waffle::Operator::I32Store { memory } => (true, 4, LiftedType::I32, memory),
        waffle::Operator::I64Store { memory } => (true, 8, LiftedType::I64, memory),
        waffle::Operator::F32Store { memory } => (true, 4, LiftedType::F32, memory),
        waffle::Operator::F64Store { memory } => (true, 8, LiftedType::F64, memory),
        _ => return None,
    };
    Some(AccessShape {
        is_store,
        width,
        memarg_offset: memarg.offset,
        ty,
    })
}