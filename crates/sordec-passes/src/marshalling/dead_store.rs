//! Remove stores into a private frame that nothing reads back.
//!
//! [`super::frame`] can only take a shadow-stack bracket away once the
//! frame pointer has no readers. After the elisions above it, the last
//! readers are usually stores: the `Result` discriminant a wrapper wrote
//! to scratch space and then read back through a load that has since
//! become a literal. The slot is written, never read, and the write keeps
//! the whole frame alive.
//!
//! ```text
//! fp = sp - 16
//! store fp <- 0 offset=0        ← nobody loads fp+0 any more
//! …                             → (store gone; frame elision then takes
//! global.set 0, fp + 16            the bracket)
//! ```
//!
//! ## Why a private frame's dead store is really dead
//!
//! The frame is this function's own scratch space, carved out of the
//! shadow stack by the bracket and released on exit. It is private when
//! the pointer never leaves the function: every use of `fp` (and of any
//! `fp + k` derived from it) is the bracket itself, a store address or a
//! load address. Under that condition no callee, no host operation and no
//! other frame can observe the slot, so a store whose bytes no load in the
//! function overlaps has no reader anywhere. If the pointer is passed to a
//! call, stored somewhere, returned, or folded into arithmetic this pass
//! cannot follow, the frame is not private and nothing is touched.
//!
//! Loads are matched by byte range, not exact slot: a wider load covering
//! part of the store keeps it.
//!
//! One store of the pointer itself does not end the frame's privacy: a
//! frame address written into the frame's own slots, where no load reads
//! those bytes back. An address in memory is observable only by reading
//! that memory; the frame is otherwise private, so only this function's
//! own loads could, and none covers those bytes. Such a store is dead
//! like any other — it is what a helper's out-pointer result leaves in
//! the frame once its readers have been forwarded (a slice iterator's
//! `ptr` and `end`, stored back after the call that built it). A load
//! that does overlap one, and the frame is not private, as before.
//!
//! ## A frame handed to calls
//!
//! Most frames are not private: the SDK hands a slot's address to a helper
//! that reads the word behind it, writes an `Option` through it, compares
//! two values behind two pointers. The frame then outlives the elisions
//! above, and so do stores nothing will ever read — the scratch a
//! `Vec::from_array` run leaves behind after the helper that read it, the
//! element buffer of a `vec!` whose elements are recovered — each a hole.
//!
//! Such a store is still dead when **nothing that can run after it reads
//! its bytes** before they are all written over or the function returns.
//! What can read a frame slot, once the frame's address is accounted for:
//!
//! - this function's own loads from the frame, matched by byte range;
//! - a call handed an address in the frame, through that pointer: the
//!   bytes the callee reads relative to it, followed through its own calls
//!   (the extent [`super::optional_out`]'s call-site gate computes); a bulk
//!   copy, through its source, for its constant length.
//!
//! ### Why it is exact
//!
//! The frame is this function's, carved out on entry and released on
//! exit, so only code that runs before the function returns can read it,
//! and only through an address in it. Every such address the function
//! makes is `fp + k`, and every use of one is accounted for: a load or a
//! store at it, the bracket, a call whose callee reads only `param + k`
//! (never storing, returning or passing on the pointer except to a callee
//! that does the same — a known extent says exactly that), or a bulk copy
//! of constant length. An address stored as a value must go into the frame
//! itself, and that store must be dead by this same rule; no other code
//! can then ever hold one. (By induction on the run: the first read of the
//! frame through an address not handed over directly would need one read
//! out of memory, and the only ones in memory are in slots nobody reads.)
//! So the readers listed above are all the readers there are.
//!
//! Which bytes one of them may still read is the classic backward liveness
//! over the region tree: walking each block backwards, a store's bytes are
//! dead above it, a read's bytes live; an `if` or `match` joins its ways,
//! a `break` or `continue` takes what is live where it lands, a `return`
//! or a trap has nothing live (the frame is gone), and a loop is iterated
//! until its header's set stops growing (sets only grow, over the finite
//! bytes the frame and its callees reach). A callee's writes never make a
//! byte dead — its extent says what it may write, not what it must. So
//! the set after a store holds every byte some path from it reads before
//! a store of this function writes it, and a store none of whose bytes is
//! in that set is unobservable.
//!
//! ### Gates
//!
//! - The frame pointer is `global.get - k`, every address in the frame is
//!   it plus a constant, and every use of one is listed above; any other
//!   (an unknown callee, a host operation reading the buffer, a merge of
//!   addresses, a return) leaves the function untouched.
//! - Every call handed an address has a known extent (a direct call to a
//!   helper, not exported, not recursive).
//! - Every store of an address into the frame is itself dead, or the
//!   function is left untouched.
//! - The flow is structured (no fallback region), every `break` and
//!   `continue` lands inside the function's own tree, and each loop
//!   settles within `MAX_ROUNDS` rounds.

use std::collections::{BTreeSet, HashMap, HashSet};

use sordec_common::{BlockId, IrId, ValueId};
use sordec_ir::{BinaryOp, Expr, HighFunction, HighIr, IrType, KnownType, Literal, Region};

use super::optional_out::{Frames, Slot};
use super::{apply_elisions, metrics, Elision};
use crate::dataflow::{canon_addr, resolve_use, trace_int};
use crate::effects::expr_effects;
use crate::pass::{Pass, PassResult};

/// Pass name — also the provenance `pass` field for every elision.
pub const PASS_NAME: &str = "marshalling-dead-frame-store";

/// Elides stores into a private frame that no load reads back.
#[derive(Debug, Default, Clone, Copy)]
pub struct DeadFrameStorePass;

impl Pass<HighIr> for DeadFrameStorePass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        // Planned over the whole module first: what a call reads through a
        // pointer is read off its callee.
        let plans: Vec<(usize, Vec<Elision>)> = {
            let frames = Frames::new(ir);
            ir.functions.iter().enumerate().map(|(i, func)| (i, plan(&frames, func))).collect()
        };
        for (index, elisions) in plans {
            if elisions.is_empty() {
                continue;
            }
            let Some(func) = ir.functions.get_mut(index) else { continue };
            result.changed = true;
            result.metrics.increment(metrics::DEAD_FRAME_STORES, elisions.len() as i64);
            apply_elisions(func, PASS_NAME, elisions);
        }
        result
    }
}

fn plan(frames: &Frames<'_>, func: &HighFunction) -> Vec<Elision> {
    let Some(fp) = frame_pointer(func) else {
        return Vec::new();
    };
    let order = super::sret::emission_order(func);
    let derived = frame_addresses(func, fp, &order);
    match plan_private(func, fp, &order, &derived) {
        Some(elisions) => elisions,
        None => plan_handed(frames, func, fp, &order, &derived),
    }
}

/// `fp` and every `fp + k` derived from it.
pub(super) fn frame_addresses(func: &HighFunction, fp: ValueId, order: &[ValueId]) -> HashSet<ValueId> {
    let mut derived: HashSet<ValueId> = HashSet::from([fp]);
    for &id in order {
        if let Some(Expr::Binary { op: BinaryOp::Add, lhs, rhs }) = func.bindings.get(id).map(|b| &b.expr)
            && derived.contains(&resolve_use(func, *lhs))
            && trace_int(func, *rhs).is_some()
        {
            derived.insert(id);
        }
    }
    derived
}

/// The private frame's dead stores; `None` when the frame is not private.
fn plan_private(func: &HighFunction, fp: ValueId, order: &[ValueId], derived: &HashSet<ValueId>) -> Option<Vec<Elision>> {
    // Every emitted use of the frame pointer and its derived addresses
    // must be a store address, a load address, or the bracket.
    let dead = crate::dataflow::dead_residue(func, order);
    let mut loads: Vec<(u32, u32)> = Vec::new();
    let mut stores: Vec<(ValueId, u32, u32)> = Vec::new();
    let mut addresses: Vec<(u32, u32)> = Vec::new();
    for &id in order {
        let Some(binding) = func.bindings.get(id) else {
            continue;
        };
        match &binding.expr {
            Expr::Store { addr, value, offset, width } => {
                let (base, off) = canon_addr(func, *addr);
                let start = off.checked_add(*offset);
                if derived.contains(&resolve_use(func, *value)) {
                    // A frame address written into the frame itself: not
                    // an escape while nothing reads it back — checked below.
                    match start {
                        Some(start) if base == fp => addresses.push((start, width.bytes())),
                        _ => return None,
                    }
                }
                if base == fp
                    && let Some(start) = start
                {
                    stores.push((id, start, width.bytes()));
                }
            }
            Expr::Load { addr, offset, width, .. } => {
                let (base, off) = canon_addr(func, *addr);
                if base == fp
                    && let Some(start) = off.checked_add(*offset)
                {
                    loads.push((start, width.bytes()));
                }
            }
            // The bracket's own reads of the pointer: the epilogue
            // restore (`fp + size`) is a derived add with no further use,
            // and the `global.set`s consume `fp` and that add.
            Expr::Unknown { op_kind: sordec_ir::WasmOpcodeKind::GlobalSet, .. } => {}
            Expr::Binary { op: BinaryOp::Add, .. } if derived.contains(&id) => {}
            // A rename of a frame address: its own readers are judged as
            // readers of the address, through `resolve_use`, like every
            // other use above.
            Expr::Use(_) if derived.contains(&resolve_use(func, id)) => {}
            // Residue an elision left behind — the operands of a collapsed
            // unpack, say. None of it is emitted, so it cannot carry the
            // pointer anywhere.
            other if dead.contains(&id) && expr_effects(other).is_pure_total() => {}
            other => {
                let mut escapes = false;
                other.for_each_value_use(|u| {
                    if derived.contains(&resolve_use(func, u)) {
                        escapes = true;
                    }
                });
                if escapes {
                    return None;
                }
            }
        }
    }
    let mut region_reads = false;
    func.region.for_each_value_use(|u| {
        if derived.contains(&resolve_use(func, u)) {
            region_reads = true;
        }
    });
    if region_reads {
        return None;
    }
    let overlaps = |(start, width): (u32, u32)| loads.iter().any(|(ls, lw)| *ls < start + width && start < ls + lw);
    if addresses.iter().any(|a| overlaps(*a)) {
        return None;
    }

    let elisions = stores
        .into_iter()
        .filter(|(_, start, width)| {
            !loads
                .iter()
                .any(|(ls, lw)| ls < &(start + width) && start < &(ls + lw))
        })
        .map(|(id, start, _)| Elision {
            id,
            expr: Expr::Literal(Literal::Unit),
            ty: Some(IrType::Known(KnownType::Unit)),
            note: format!("store to private frame slot +{start} that nothing reads back"),
            metric: metrics::DEAD_FRAME_STORES,
        })
        .collect();
    Some(elisions)
}

/// The dead stores of a frame whose addresses are handed to calls: each one
/// nothing that can run after it reads ("A frame handed to calls"). Empty
/// when some use of an address is not accounted for.
fn plan_handed(
    frames: &Frames<'_>,
    func: &HighFunction,
    fp: ValueId,
    order: &[ValueId],
    derived: &HashSet<ValueId>,
) -> Vec<Elision> {
    let dead = crate::dataflow::dead_residue(func, order);
    let is_address = |v: ValueId| derived.contains(&resolve_use(func, v));
    let mut stores: Vec<(ValueId, Slot)> = Vec::new();
    let mut address_stores: Vec<ValueId> = Vec::new();
    let mut handed = false;
    for &id in order {
        let Some(binding) = func.bindings.get(id) else {
            continue;
        };
        match &binding.expr {
            Expr::Store { addr, value, offset, width } => {
                let (base, off) = canon_addr(func, *addr);
                let start = off.checked_add(*offset);
                if is_address(*value) {
                    // Only into the frame, where the store must be dead too.
                    if base != fp || start.is_none() {
                        trace(func, id, "an address stored outside the frame");
                        return Vec::new();
                    }
                    address_stores.push(id);
                }
                if base == fp {
                    let Some(start) = start else { return Vec::new() };
                    stores.push((id, Slot { offset: start, bytes: width.bytes() }));
                }
            }
            // A load's address is only read from; whether it reads a store
            // is the question asked below.
            Expr::Load { .. } => {}
            Expr::Unknown { op_kind: sordec_ir::WasmOpcodeKind::GlobalSet, .. } => {}
            Expr::Binary { op: BinaryOp::Add, .. } if derived.contains(&id) => {}
            Expr::Use(_) if derived.contains(&resolve_use(func, id)) => {}
            other if dead.contains(&id) && expr_effects(other).is_pure_total() => {}
            other => {
                let mut uses = false;
                other.for_each_value_use(|u| uses |= is_address(u));
                if !uses {
                    continue;
                }
                // Handed an address: what the callee does through it must be
                // known — which also says it keeps no copy of the pointer.
                let call = matches!(
                    other,
                    Expr::Call { .. } | Expr::Unknown { op_kind: sordec_ir::WasmOpcodeKind::MemoryOp, .. }
                );
                if !call || frames.touches(func, id, fp).is_none() {
                    trace(func, id, "an address handed to something whose reach is unknown");
                    return Vec::new();
                }
                handed = true;
            }
        }
    }
    // A private frame is `plan_private`'s; this one is about calls.
    if !handed {
        return Vec::new();
    }
    let mut region_reads = false;
    func.region.for_each_value_use(|u| region_reads |= is_address(u));
    if region_reads {
        trace(func, fp, "an address read by the control flow");
        return Vec::new();
    }
    let mut walk = Liveness::new(frames, func, fp);
    if walk.region(&func.region, &Live::new()).is_none() {
        trace(func, fp, "the flow or a call's reach could not be followed");
        return Vec::new();
    }
    let slot_of = |id: ValueId| stores.iter().find(|(s, _)| *s == id).map(|(_, slot)| *slot);
    // Only a store the walk reached, and after which none of its bytes is
    // live.
    let unread = |id: ValueId, slot: Slot| -> bool {
        walk.after.get(&id).is_some_and(|live| live.range(slot.offset..slot.offset + slot.bytes).next().is_none())
    };
    if let Some(read) = address_stores.iter().find(|a| !slot_of(**a).is_some_and(|slot| unread(**a, slot))) {
        trace(func, *read, "an address stored into the frame may be read back");
        return Vec::new();
    }
    stores
        .iter()
        .filter(|(id, slot)| unread(*id, *slot))
        .map(|(id, slot)| Elision {
            id: *id,
            expr: Expr::Literal(Literal::Unit),
            ty: Some(IrType::Known(KnownType::Unit)),
            note: format!(
                "store to frame slot +{} that nothing running after it reads: the frame's own loads \
                 and the calls handed its addresses miss those bytes",
                slot.offset
            ),
            metric: metrics::DEAD_FRAME_STORES,
        })
        .collect()
}

/// Why a handed frame's stores were left, printed when
/// `SORDEC_DEAD_STORE_TRACE` is set.
#[allow(clippy::print_stderr)]
fn trace(func: &HighFunction, at: ValueId, why: &str) {
    if std::env::var_os("SORDEC_DEAD_STORE_TRACE").is_some() {
        eprintln!("dead-store: func_{} v{}: {why}", func.id.index(), at.index());
    }
}

/// Rounds a loop is iterated before its liveness is given up on. Each
/// round that does not settle adds at least one byte, so a loop needing
/// more reads bytes far past any frame here.
const MAX_ROUNDS: usize = 64;

/// Byte offsets of the frame some later read may still see.
pub(super) type Live = BTreeSet<u32>;

/// The backward liveness walk over the frame's bytes ("Why it is exact").
pub(super) struct Liveness<'a, 'ir> {
    frames: &'a Frames<'ir>,
    func: &'a HighFunction,
    fp: ValueId,
    /// The bytes live right after each frame store, as the last walk over
    /// its block saw them — at a loop's settled set, for a store inside it.
    pub(super) after: HashMap<ValueId, Live>,
    /// What is live where each enclosing scope's `break` lands.
    breaks: Vec<(BlockId, Live)>,
    /// What is live at each enclosing loop's header.
    continues: Vec<(BlockId, Live)>,
    /// Bindings that are neither stores nor loads but write a known slot of
    /// the frame whenever they run — a host copy into a frame buffer. Each
    /// is a definite write, like a store; empty for this module's own walk.
    pub(super) writes: HashMap<ValueId, Slot>,
    /// Bindings that read a known slot of the frame and are neither loads
    /// nor calls — a host constructor reading a frame buffer.
    pub(super) reads: HashMap<ValueId, Slot>,
    /// Reads the walk does not count: loads a caller is about to stop
    /// reading memory with.
    pub(super) skip: HashSet<ValueId>,
}

impl<'a, 'ir> Liveness<'a, 'ir> {
    /// A walk over `func`'s frame at `fp` that counts only stores, loads
    /// and calls.
    pub(super) fn new(frames: &'a Frames<'ir>, func: &'a HighFunction, fp: ValueId) -> Self {
        Liveness {
            frames,
            func,
            fp,
            after: HashMap::new(),
            breaks: Vec::new(),
            continues: Vec::new(),
            writes: HashMap::new(),
            reads: HashMap::new(),
            skip: HashSet::new(),
        }
    }

    /// The bytes live on entry to `region`, given those live where it falls
    /// out; `None` when that cannot be told.
    pub(super) fn region(&mut self, region: &Region, out: &Live) -> Option<Live> {
        match region {
            Region::Basic(block) => self.block(*block, out),
            Region::Sequence(items) => {
                let mut live = out.clone();
                for item in items.iter().rev() {
                    live = self.region(item, &live)?;
                }
                Some(live)
            }
            Region::Scope { out: label, body } => {
                self.breaks.push((*label, out.clone()));
                let live = self.region(body, out);
                self.breaks.pop();
                live
            }
            Region::If { then_region, else_region, .. } => {
                let mut live = self.region(then_region, out)?;
                match else_region {
                    Some(other) => live.extend(self.region(other, out)?),
                    None => live.extend(out.iter().copied()),
                }
                Some(live)
            }
            Region::Switch { arms, default, .. } => {
                let mut live = self.region(default, out)?;
                for arm in arms {
                    live.extend(self.region(&arm.body, out)?);
                }
                Some(live)
            }
            Region::Loop { header, body, .. } => {
                let mut head = Live::new();
                for _ in 0..MAX_ROUNDS {
                    // Falling off the body's end goes round, and is counted
                    // as leaving too: more live is only ever safer.
                    let mut fall = out.clone();
                    fall.extend(head.iter().copied());
                    self.continues.push((*header, head.clone()));
                    let entry = self.region(body, &fall);
                    self.continues.pop();
                    let mut entry = entry?;
                    entry.extend(head.iter().copied());
                    if entry == head {
                        return Some(head);
                    }
                    head = entry;
                }
                None
            }
            Region::Break { target, .. } => self.breaks.iter().rev().find(|(l, _)| l == target).map(|(_, s)| s.clone()),
            Region::Continue { target, .. } => {
                self.continues.iter().rev().find(|(l, _)| l == target).map(|(_, s)| s.clone())
            }
            Region::Transfer { .. } => Some(out.clone()),
            // The frame is released, or the run is over.
            Region::Return { .. } | Region::Unreachable | Region::Panic { .. } => Some(Live::new()),
            Region::Unstructured { .. } => None,
        }
    }

    /// One block, backwards: a store's bytes die above it, a read's live.
    fn block(&mut self, block: BlockId, out: &Live) -> Option<Live> {
        let mut live = out.clone();
        let bindings = &self.func.blocks.get(block)?.bindings;
        for &id in bindings.iter().rev() {
            let Some(binding) = self.func.bindings.get(id) else {
                continue;
            };
            if self.skip.contains(&id) {
                continue;
            }
            if let Some(slot) = self.writes.get(&id) {
                self.after.insert(id, live.clone());
                for byte in slot.offset..slot.offset.checked_add(slot.bytes)? {
                    live.remove(&byte);
                }
                continue;
            }
            if let Some(slot) = self.reads.get(&id) {
                live.extend(slot.offset..slot.offset.checked_add(slot.bytes)?);
                continue;
            }
            match &binding.expr {
                Expr::Store { addr, offset, width, .. } => {
                    let (base, off) = canon_addr(self.func, *addr);
                    if base != self.fp {
                        continue;
                    }
                    let start = off.checked_add(*offset)?;
                    self.after.insert(id, live.clone());
                    for byte in start..start.checked_add(width.bytes())? {
                        live.remove(&byte);
                    }
                }
                Expr::Load { addr, offset, width, .. } => {
                    let (base, off) = canon_addr(self.func, *addr);
                    if base != self.fp {
                        continue;
                    }
                    let start = off.checked_add(*offset)?;
                    live.extend(start..start.checked_add(width.bytes())?);
                }
                Expr::Call { .. }
                | Expr::IndirectCall { .. }
                | Expr::Unknown {
                    op_kind: sordec_ir::WasmOpcodeKind::CallIndirect | sordec_ir::WasmOpcodeKind::MemoryOp,
                    ..
                } => {
                    for (slot, write_only) in self.frames.touches(self.func, id, self.fp)? {
                        if !write_only {
                            live.extend(slot.offset..slot.offset.checked_add(slot.bytes)?);
                        }
                    }
                }
                _ => {}
            }
        }
        Some(live)
    }
}

/// The frame pointer `fp = global.get G - size`, when the function has one.
pub(super) fn frame_pointer(func: &HighFunction) -> Option<ValueId> {
    let counts: HashMap<ValueId, usize> = HashMap::new();
    let _ = counts;
    func.bindings.iter().find_map(|(id, binding)| {
        let Expr::Binary { op: BinaryOp::Sub, lhs, rhs } = &binding.expr else {
            return None;
        };
        let sp = resolve_use(func, *lhs);
        let is_global = matches!(func.bindings.get(sp)?.expr, Expr::GlobalGet { .. });
        (is_global && trace_int(func, *rhs).is_some()).then_some(id)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, load, module, store, v};
    use sordec_common::{FuncId, UnknownReason};
    use sordec_ir::WasmOpcodeKind;

    fn global_set(value: ValueId) -> Expr {
        Expr::Unknown {
            op_kind: WasmOpcodeKind::GlobalSet,
            args: vec![value],
            reason: UnknownReason::UnsupportedPattern,
        }
    }

    /// A 16-byte frame with one store and, optionally, a load of it.
    fn framed(read_back: bool, escape: bool) -> HighFunction {
        let mut exprs = vec![
            Expr::GlobalGet { index: 0 },                                  // v0 sp
            Expr::Literal(Literal::I32(16)),                               // v1
            Expr::Binary { op: BinaryOp::Sub, lhs: v(0), rhs: v(1) },      // v2 fp
            global_set(v(2)),                                              // v3
            Expr::Literal(Literal::I64(0)),                                // v4
            store(v(2), v(4), 0),                                          // v5
            Expr::Binary { op: BinaryOp::Add, lhs: v(2), rhs: v(1) },      // v6 fp+16
            global_set(v(6)),                                              // v7
        ];
        let mut sched = vec![0, 1, 2, 3, 4, 5, 6, 7];
        if read_back {
            exprs.push(load(v(2), 0)); // v8
            sched.push(8);
        }
        if escape {
            exprs.push(Expr::Call { target: FuncId::from_index(9), args: vec![v(2)] });
            sched.push(exprs.len() as u32 - 1);
        }
        func_with(exprs, vec![], sched)
    }

    #[test]
    fn an_unread_store_into_a_private_frame_is_elided() {
        let mut m = module(vec![framed(false, false)]);
        let r = DeadFrameStorePass.run(&mut m);
        assert!(r.changed);
        assert!(matches!(m.functions[0].bindings.get(v(5)).unwrap().expr, Expr::Literal(Literal::Unit)));
    }

    #[test]
    fn a_store_with_a_reader_stays() {
        let mut m = module(vec![framed(true, false)]);
        assert!(!DeadFrameStorePass.run(&mut m).changed);
    }

    /// A frame pointer handed to a callee is not private: the callee may
    /// read the slot.
    #[test]
    fn an_escaping_frame_is_left_alone() {
        let mut m = module(vec![framed(false, true)]);
        assert!(!DeadFrameStorePass.run(&mut m).changed);
    }

    /// The frame's own address written into one of its slots: with no
    /// load of that slot it is a dead store, not an escape; read back, it
    /// is an escape and nothing is touched.
    fn address_stored(read_back: bool) -> HighIr {
        let mut f = framed(false, false);
        let id = ValueId::from_index(f.bindings.len() as u32);
        f.bindings.push(sordec_ir::Binding::new(
            id,
            IrType::Unknown(UnknownReason::InsufficientEvidence),
            store(v(2), v(2), 8),
            sordec_common::Provenance::new("seed", sordec_common::ProvenanceSource::DataFlow, "seed"),
        ));
        let block = f.blocks.iter().next().map(|(b, _)| b).unwrap();
        f.blocks.get_mut(block).unwrap().bindings.insert(6, id);
        if read_back {
            let l = ValueId::from_index(f.bindings.len() as u32);
            f.bindings.push(sordec_ir::Binding::new(
                l,
                IrType::Unknown(UnknownReason::InsufficientEvidence),
                load(v(2), 8),
                sordec_common::Provenance::new("seed", sordec_common::ProvenanceSource::DataFlow, "seed"),
            ));
            f.blocks.get_mut(block).unwrap().bindings.insert(7, l);
        }
        module(vec![f])
    }

    #[test]
    fn a_frame_address_stored_in_an_unread_slot_is_dead() {
        let mut m = address_stored(false);
        assert!(DeadFrameStorePass.run(&mut m).changed);
        let f = &m.functions[0];
        assert!(matches!(f.bindings.get(v(5)).unwrap().expr, Expr::Literal(Literal::Unit)));
        assert!(matches!(f.bindings.get(v(8)).unwrap().expr, Expr::Literal(Literal::Unit)));
    }

    #[test]
    fn a_frame_address_read_back_is_an_escape() {
        let mut m = address_stored(true);
        assert!(!DeadFrameStorePass.run(&mut m).changed);
    }

    #[test]
    fn the_pass_is_idempotent() {
        let mut m = module(vec![framed(false, false)]);
        assert!(DeadFrameStorePass.run(&mut m).changed);
        assert!(!DeadFrameStorePass.run(&mut m).changed);
    }

    // -- A frame handed to calls ------------------------------------------

    use sordec_common::{Arena, BlockId};
    use sordec_ir::HighBlock;

    fn b(i: u32) -> BlockId {
        BlockId::from_index(i)
    }

    fn is_unit(m: &HighIr, func: usize, id: u32) -> bool {
        matches!(m.functions[func].bindings.get(v(id)).unwrap().expr, Expr::Literal(Literal::Unit))
    }

    /// `func_1(p)`: reads the word at `p + read_at`; with `keeps`, it also
    /// stores `p` itself somewhere — a copy of the pointer, so what it
    /// touches is not known.
    fn reader(read_at: u32, keeps: bool) -> HighFunction {
        let mut exprs = vec![
            Expr::Phi { incoming: vec![] }, // v0 p
            load(v(0), read_at),            // v1
        ];
        let mut sched = vec![1];
        if keeps {
            exprs.push(store(v(0), v(0), 64)); // v2
            sched.push(2);
        }
        let mut f = func_with(exprs, vec![v(0)], sched);
        f.id = FuncId::from_index(1);
        f.region = Region::Sequence(vec![Region::Basic(b(0)), Region::Return { values: vec![v(1)] }]);
        f.returns = vec![vec![v(1)]];
        f
    }

    /// A 32-byte frame: a store at `fp+0`, `func_1(fp)`, a store at
    /// `fp+8`, then (with `call_after`) `func_1(fp)` again.
    fn handing(call_after: bool) -> HighFunction {
        let mut exprs = vec![
            Expr::GlobalGet { index: 0 },                                  // v0 sp
            Expr::Literal(Literal::I32(32)),                               // v1
            Expr::Binary { op: BinaryOp::Sub, lhs: v(0), rhs: v(1) },      // v2 fp
            global_set(v(2)),                                              // v3
            Expr::Literal(Literal::I64(7)),                                // v4
            store(v(2), v(4), 0),                                          // v5
            Expr::Call { target: FuncId::from_index(1), args: vec![v(2)] }, // v6
            store(v(2), v(4), 8),                                          // v7
            Expr::Binary { op: BinaryOp::Add, lhs: v(2), rhs: v(1) },      // v8 fp+32
            global_set(v(8)),                                              // v9
        ];
        let mut sched = vec![0, 1, 2, 3, 4, 5, 6, 7];
        if call_after {
            exprs.push(Expr::Call { target: FuncId::from_index(1), args: vec![v(2)] }); // v10
            sched.push(10);
        }
        sched.extend([8, 9]);
        func_with(exprs, vec![], sched)
    }

    /// The callee reads `fp+0` when it runs; nothing runs after the store
    /// at `fp+8`, so that store is dead and the one it reads stays.
    #[test]
    fn a_store_no_later_reader_sees_is_elided_though_the_frame_is_handed_on() {
        let mut m = module(vec![handing(false), reader(0, false)]);
        assert!(DeadFrameStorePass.run(&mut m).changed);
        assert!(is_unit(&m, 0, 7), "nothing after the store at fp+8 reads it");
        assert!(!is_unit(&m, 0, 5), "the callee reads fp+0 after it is written");
    }

    /// A call after the store whose reach covers it keeps it.
    #[test]
    fn a_later_call_reading_the_slot_keeps_the_store() {
        let mut m = module(vec![handing(true), reader(8, false)]);
        DeadFrameStorePass.run(&mut m);
        assert!(!is_unit(&m, 0, 7));
    }

    /// A callee that keeps a copy of the pointer may read the frame from
    /// anywhere later: nothing is touched.
    #[test]
    fn a_callee_keeping_the_pointer_leaves_the_frame_alone() {
        let mut m = module(vec![handing(false), reader(0, true)]);
        assert!(!DeadFrameStorePass.run(&mut m).changed);
    }

    /// A frame address stored into the frame, which a later callee reads:
    /// the address escapes through memory, so nothing is touched.
    #[test]
    fn a_frame_address_a_callee_reads_back_leaves_the_frame_alone() {
        let mut f = handing(true);
        f.bindings.get_mut(v(7)).unwrap().expr = store(v(2), v(2), 8);
        let mut m = module(vec![f, reader(8, false)]);
        assert!(!DeadFrameStorePass.run(&mut m).changed);
    }

    /// The store at the end of a loop body is read by the call at its top
    /// on the next trip: the loop's liveness keeps it. Outside a loop the
    /// same order would leave it dead.
    #[test]
    fn a_store_read_on_the_next_trip_round_a_loop_stays() {
        let exprs = vec![
            Expr::GlobalGet { index: 0 },                                  // v0 sp
            Expr::Literal(Literal::I32(32)),                               // v1
            Expr::Binary { op: BinaryOp::Sub, lhs: v(0), rhs: v(1) },      // v2 fp
            global_set(v(2)),                                              // v3
            Expr::Literal(Literal::I64(7)),                                // v4
            Expr::Call { target: FuncId::from_index(1), args: vec![v(2)] }, // v5
            store(v(2), v(4), 0),                                          // v6
            Expr::Phi { incoming: vec![] },                                // v7 cond
            Expr::Binary { op: BinaryOp::Add, lhs: v(2), rhs: v(1) },      // v8 fp+32
            global_set(v(8)),                                              // v9
        ];
        let mut f = func_with(exprs, vec![v(7)], vec![]);
        let mut arena: Arena<BlockId, HighBlock> = Arena::new();
        for (i, ids) in [vec![0, 1, 2, 3, 4], vec![5, 6], vec![8, 9]].into_iter().enumerate() {
            arena.push(HighBlock { id: b(i as u32), bindings: ids.into_iter().map(v).collect() });
        }
        f.blocks = arena;
        f.region = Region::Sequence(vec![
            Region::Basic(b(0)),
            Region::Scope {
                out: b(2),
                body: Box::new(Region::Loop {
                    header: b(1),
                    body: Box::new(Region::Sequence(vec![
                        Region::Basic(b(1)),
                        Region::If {
                            cond: v(7),
                            then_region: Box::new(Region::Break { target: b(2), transfer: vec![] }),
                            else_region: None,
                        },
                        Region::Continue { target: b(1), transfer: vec![] },
                    ])),
                    kind: sordec_ir::LoopKind::Unclassified,
                }),
            },
            Region::Basic(b(2)),
            Region::Return { values: vec![] },
        ]);
        let mut m = module(vec![f.clone(), reader(0, false)]);
        DeadFrameStorePass.run(&mut m);
        assert!(!is_unit(&m, 0, 6), "the next trip's call reads it");

        // Without the back edge the store is the last thing to touch fp+0.
        f.region = Region::Sequence(vec![
            Region::Basic(b(0)),
            Region::Basic(b(1)),
            Region::Basic(b(2)),
            Region::Return { values: vec![] },
        ]);
        let mut m = module(vec![f, reader(0, false)]);
        assert!(DeadFrameStorePass.run(&mut m).changed);
        assert!(is_unit(&m, 0, 6));
    }
}
