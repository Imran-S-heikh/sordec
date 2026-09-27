//! Shadow-stack slot promotion — SROA plus mem2reg.
//!
//! Once [`super::sret`] has stopped the frame escaping into callees, its
//! slots are ordinary local variables that happen to live in linear memory.
//! This pass gives them back their SSA values, which is what finally
//! removes the `Load`/`Store` traffic the Rust backend can only render as
//! holes.
//!
//! Two textbook halves, in LLVM's names:
//!
//! - **SROA** splits the frame into one scalar per `(offset, width)`. A
//!   16-byte slot pair is two independent 8-byte variables, not one
//!   aggregate — LLVM requires this first because mem2reg cannot promote
//!   aggregates.
//! - **mem2reg** replaces each scalar's loads and stores with an SSA value,
//!   inserting phis where control flow merges.
//!
//! ## Why the phis are the easy part here
//!
//! Minimal phi placement — dominance frontiers, Cytron, Braun's
//! `readVariable` recursion — is the hard half of mem2reg, and this pass
//! does none of it. The lift already calls `convert_to_max_ssa`, so the CFG
//! arrives in *maximal* SSA, and
//! [`crate::declutter::PruneTrivialPhisPass`] already implements Braun et
//! al.'s trivial-phi rule to minimise it back. So promotion gives **every
//! reachable block** a parameter for the slot and wires **every** edge —
//! obviously correct, and reviewable by inspection — and the pass already
//! sitting in the same fixpoint group prunes what turned out to be
//! redundant. Insert maximally, prune back, exactly as the lift does.
//!
//! That is also why the branch case that defeated the earlier `HighIr`
//! attempt is not a special case here. A call inside an `if` whose slot is
//! read after the join produces a merge, and a merge is a block parameter.
//!
//! ## Gates
//!
//! - **No escape.** Every use of a frame address must be a load address, a
//!   store address, further address arithmetic, or the frame bracket
//!   itself. Anything else — passed to a call, stored *as a value*,
//!   returned, branched on — declines the **whole frame**, because a
//!   pointer we cannot follow may alias any slot.
//! - **One width per offset, and no partial overlap.** A narrower read of a
//!   wider store is a reinterpretation, not a read of that variable.
//! - **Every load is dominated by a store to the same slot.** Reading an
//!   unwritten shadow-stack slot is undefined in the source program and
//!   there is no honest value to invent. With this gate the slot's initial
//!   value is provably unobserved, which is what makes materialising a zero
//!   for it sound rather than a guess.
//!
//! ## This pass creates *used* aliases — resolution must run after it
//!
//! [`crate::default_lifted_pipeline`] documents the invariant that
//! [`crate::ResolveAliasesPass`] runs once up front because "no later
//! pass creates a *used* alias". **This pass breaks that invariant.**
//! The rewrite walk below retires each forwarded load from its block and
//! leaves an `Alias` tombstone behind, but the load's readers still name
//! it — so the alias is used, and with resolution stranded at the head of
//! the pipeline nothing ever rewires them.
//!
//! The result is a value that is used but scheduled nowhere. The lifted
//! IR still validates (reference integrity is intact), so the damage
//! surfaces two stages later: lowering renders it as a `Use` binding no
//! block schedules, and the region validator's emission-order dominance
//! walk reports `UseBeforeDef` at whichever refinement pass calls
//! `debug_validate` first — `refine-polarity`, which is not the culprit.
//!
//! So wiring this pass requires moving `ResolveAliasesPass` **inside**
//! the fixpoint group. Chasing is load-bearing, not incidental:
//! `promote` runs once per slot from a slot list discovered before any
//! promotion, so a store into slot 2 whose value is slot 1's
//! already-retired load names a stale alias id. `resolve_function`
//! follows those chains; a one-shot rewrite here would not.
//!
//! `tests/memory_staged.rs` locks both halves of this.
//!
//! ## Wired — and what it took
//!
//! Registered in [`crate::default_lifted_pipeline`], after
//! [`super::sret`]. Three things had to be true first, and each was a
//! separate discovery:
//!
//! 1. `ResolveAliasesPass` moved inside the fixpoint group (above).
//! 2. [`crate::marshalling::decode`] learned the multi-value shape
//!    `sret` converts decode helpers into. Without that the SDK glue
//!    stopped being elided and came back as emitted code.
//! 3. [`crate::PruneDeadParamsPass`] had to exist. "Insert maximally,
//!    prune back" needs *two* cleanups, and only the trivial-phi half
//!    was present — see that module for the chain a single unread
//!    parameter was holding up.
//!
//! Measured `cargo check` errors per fixture, before and after:
//!
//! ```text
//! hello-add             0 →   0        token-v22           125 → 127
//! timelock             53 →  52        token-v23           125 → 127
//! dex-liquidity-pool  314 → 226        token-v23-stripped  111 → 113
//! attestation           8 →   8
//!                                      corpus total  736 → 653  (-83)
//! ```
//!
//! dex is where the memory traffic was, and it is the fixture furthest
//! from compiling. The `+2` on the token family is churn inside the
//! type-mismatch families that already dominate those three fixtures —
//! same error kinds, slightly different proportions — not a new failure
//! mode. Corpus-wide 52 slots promote across 7 fixtures.
//!
//! ## What it deliberately leaves behind
//!
//! The frame bracket itself. Once every slot is promoted, the frame pointer
//! is read only by its own prologue and epilogue, which is exactly the
//! condition [`crate::marshalling::frame::FrameElisionPass`] already tests
//! for. Removing it twice, in two layers, would be two things to keep in
//! agreement.

use std::collections::{BTreeMap, HashMap, HashSet};

use sordec_common::{BlockId, ValueId};
use sordec_ir::{
    LiftedFunction, LiftedIr, LiftedType, LiftedValue, LiftedValueDef, WasmOp,
};

use super::frame::{self, canon_addr};
use super::slots::{access_shape, address_closure, scheduled, EscapeReason, FrameEscapes};
use crate::dataflow::CfgFacts;
use crate::declutter::for_each_target_mut;
use crate::metrics_catalog::{
    MEMORY_SLOT_REFUSED_CONFLICT, MEMORY_SLOT_REFUSED_ESCAPED,
    MEMORY_SLOT_REFUSED_UNDOMINATED, MEMORY_SLOT_REFUSED_UNWRITTEN,
    MEMORY_FRAME_DECLINED_ADDRESS_ARITH, MEMORY_FRAME_DECLINED_BLOCK_PARAM,
    MEMORY_FRAME_DECLINED_ESCAPES_AGAIN, MEMORY_FRAME_DECLINED_HOST_CALL,
    MEMORY_FRAME_DECLINED_STORED_AS_VALUE,
    MEMORY_FRAME_DECLINED_OFFSET_NOT_CONST, MEMORY_FRAME_DECLINED_OPAQUE,
    MEMORY_FRAME_DECLINED_OVERLAP, MEMORY_LOADS_FORWARDED, MEMORY_SLOTS_PROMOTED,
    MEMORY_STORES_REMOVED,
};
use crate::pass::{Pass, PassResult};

/// Unique pipeline name of this pass.
pub const PASS_NAME: &str = "memory-slot-promotion";

/// One frame slot: a scalar variable that happens to live in memory.
#[derive(Debug, Clone)]
struct SlotAccess {
    /// Byte offset from the frame base.
    offset: u32,
    /// Access width in bytes; every access to this slot must agree.
    width: u32,
    /// The value type loads of this slot produce.
    ty: LiftedType,
    /// Set when accesses to this offset disagree on width or type — the
    /// bytes are being reinterpreted, not read as one variable.
    conflicted: bool,
    /// Every store to this slot.
    stores: Vec<Access>,
    /// Every load of it.
    loads: Vec<Access>,
}

/// One access to a slot.
///
/// `position` is the index in the block's instruction list **as discovered**,
/// used only to order a store against a load in the same block. Promotion
/// inserts an instruction, so positions go stale the moment it starts —
/// which is why the rewrite walk matches on `id` and never on `position`.
#[derive(Debug, Clone, Copy)]
struct Access {
    block: BlockId,
    position: usize,
    /// The load or store instruction itself.
    id: ValueId,
    /// For a store, the value written. Meaningless for a load.
    value: ValueId,
}

/// Promotes non-escaping shadow-stack slots to SSA values.
#[derive(Debug, Default, Clone, Copy)]
pub struct SlotPromotionPass;

impl Pass<LiftedIr> for SlotPromotionPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut LiftedIr) -> PassResult {
        let mut result = PassResult::default();

        // Census first, over an immutable view. A declined frame is the
        // pass's most common outcome and until now its least explicable:
        // rejection is whole-frame, so the pass could only report "no". The
        // census says which *other* pass would have to exist to unblock
        // each one, which is what turns the shadow stack from a mood into a
        // work list.
        //
        // It runs as its own phase because classifying an escape means
        // reading the *callee*, which cannot be borrowed while the caller
        // is being rewritten. That costs one extra `discover` per declined
        // frame; the pass is not hot enough for that to matter, and the
        // alternative is threading the reasons through the rewrite.
        let escapes = escape_ranges(ir);
        census(ir, &mut result, &escapes);

        // Escape analysis is its own immutable phase, for the same reason
        // the census is: bounding a callee's footprint means reading the
        // *callee*, which cannot be borrowed while its caller is being
        // rewritten. `None` here is a frame that declines wholesale.
        for func in &mut ir.functions {
            let Some(layout) = frame::detect(func) else {
                continue;
            };
            let Some(Ok(escaped)) = escapes.get(&func.id) else {
                continue;
            };
            let cfg = CfgFacts::build(func);
            let Some((slots, mut refused)) = discover(func, layout.base, &cfg, escaped) else {
                continue;
            };
            // Promotability is decided for *every* slot before any of them
            // is promoted. `every_load_is_written_first` reads instruction
            // positions, and promoting one slot inserts and removes
            // instructions — so checking lazily would test later slots
            // against stale positions and could approve a load that really
            // does precede its store.
            let approved: Vec<SlotAccess> = slots
                .into_iter()
                .filter(|slot| {
                    let ok = every_load_is_written_first(slot, &cfg);
                    if !ok {
                        refused.undominated += 1;
                    }
                    ok
                })
                .collect();
            refused.report(&mut result);
            for slot in approved {
                if promote(func, &slot, &cfg) {
                    result.changed = true;
                    result.metrics.increment(MEMORY_SLOTS_PROMOTED, 1);
                    result
                        .metrics
                        .increment(MEMORY_LOADS_FORWARDED, slot.loads.len() as i64);
                    result
                        .metrics
                        .increment(MEMORY_STORES_REMOVED, slot.stores.len() as i64);
                }
            }
        }
        result
    }
}

/// Escaped byte ranges per function, or the escape that made the frame
/// decline wholesale.
///
/// Carrying the reason is what lets the census explain an outcome without
/// re-running the analysis that produced it — and keeps the two from ever
/// disagreeing about why a frame was refused.
type EscapeMap =
    std::collections::HashMap<sordec_common::FuncId, Result<Vec<(i64, i64)>, EscapeReason>>;

/// Bound every frame's escapes, over an immutable view of the module.
///
/// Separated from the rewrite because bounding a callee's footprint reads
/// the callee, and the rewrite holds a mutable borrow of the caller. Only
/// functions that have a detectable frame appear in the map.
fn escape_ranges(ir: &LiftedIr) -> EscapeMap {
    let calls = super::calls::CallIndex::build(ir);
    let mut out = EscapeMap::new();
    for func in &ir.functions {
        let Some(layout) = frame::detect(func) else {
            continue;
        };
        let cfg = CfgFacts::build(func);
        let live = scheduled(func, &cfg);
        let addresses = address_closure(func, layout.base, &live);
        let accessors = accessors_of(func, &cfg, &addresses);
        let bounded = match super::slots::frame_escapes(
            func,
            ir,
            &calls,
            layout.base,
            &addresses,
            &accessors,
            &live,
        ) {
            FrameEscapes::Clean => Ok(Vec::new()),
            FrameEscapes::Bounded(ranges) => Ok(ranges),
            FrameEscapes::Unbounded(why) => Err(why),
        };
        out.insert(func.id, bounded);
    }
    out
}

/// Record why each frame this pass will not promote was declined.
///
/// Only declines are counted. A promoted frame needs no explanation, and
/// counting successes here as well would duplicate
/// [`MEMORY_SLOTS_PROMOTED`].
fn census(ir: &LiftedIr, result: &mut PassResult, escapes: &EscapeMap) {
    for func in &ir.functions {
        let Some(layout) = frame::detect(func) else {
            continue;
        };
        let cfg = CfgFacts::build(func);
        let escaped = match escapes.get(&func.id) {
            Some(Ok(ranges)) => ranges.as_slice(),
            // Wholesale decline: report the escape that caused it and move
            // on. There is nothing for `discover` to say about a frame whose
            // every slot is out of reach.
            Some(Err(why)) => {
                result.metrics.increment(
                    match why {
                        EscapeReason::AddressArithmetic => MEMORY_FRAME_DECLINED_ADDRESS_ARITH,
                        EscapeReason::HostCall => MEMORY_FRAME_DECLINED_HOST_CALL,
                        EscapeReason::BlockParam => MEMORY_FRAME_DECLINED_BLOCK_PARAM,
                        EscapeReason::StoredAsValue => MEMORY_FRAME_DECLINED_STORED_AS_VALUE,
                        EscapeReason::CalleeUnresolved => MEMORY_FRAME_DECLINED_OPAQUE,
                        EscapeReason::OffsetNotConstant => MEMORY_FRAME_DECLINED_OFFSET_NOT_CONST,
                        EscapeReason::EscapesAgain => MEMORY_FRAME_DECLINED_ESCAPES_AGAIN,
                    },
                    1,
                );
                continue;
            }
            None => continue,
        };
        // The escapes were all bounded, so anything still refused was
        // refused by a later gate: overlap, a width conflict, a slot nothing
        // writes, or every remaining slot sitting inside an escaped range.
        if discover(func, layout.base, &cfg, escaped).is_none() {
            result.metrics.increment(MEMORY_FRAME_DECLINED_OVERLAP, 1);
        }
    }
}

/// The values that legitimately consume a frame address: the loads and
/// stores themselves. Mirrors the accumulation inside [`discover`].
fn accessors_of(
    func: &LiftedFunction,
    cfg: &CfgFacts,
    addresses: &HashSet<ValueId>,
) -> HashSet<ValueId> {
    let mut accessors = HashSet::new();
    for (block_id, block) in func.blocks.iter() {
        if !cfg.is_reachable(block_id) {
            continue;
        }
        for &id in &block.instructions {
            let Some(value) = func.values.get(id) else {
                continue;
            };
            let LiftedValueDef::Operator { op, args } = &value.def else {
                continue;
            };
            if access_shape(op).is_none() {
                continue;
            }
            if args.first().is_some_and(|a| addresses.contains(a)) {
                accessors.insert(id);
            }
        }
    }
    accessors
}

// ---------------------------------------------------------------------
// SROA — splitting the frame into scalars
// ---------------------------------------------------------------------


/// Split the frame rooted at `base` into per-offset scalars, or `None` when
/// any gate declines.
///
/// Declining is whole-frame rather than per-slot on purpose: the reason a
/// frame is rejected is almost always an address we could not follow, and
/// such an address may alias *any* slot.
fn discover(
    func: &LiftedFunction,
    base: ValueId,
    cfg: &CfgFacts,
    escaped: &[(i64, i64)],
) -> Option<(Vec<SlotAccess>, SlotRefusals)> {
    let live = scheduled(func, cfg);
    let addresses = address_closure(func, base, &live);
    let mut slots: BTreeMap<u32, SlotAccess> = BTreeMap::new();
    // Values that legitimately consume an address: the accesses themselves,
    // plus the frame bracket's `global.set`.
    let mut accessors: HashSet<ValueId> = HashSet::new();

    for (block_id, block) in func.blocks.iter() {
        if !cfg.is_reachable(block_id) {
            continue;
        }
        for (position, &id) in block.instructions.iter().enumerate() {
            let Some(value) = func.values.get(id) else {
                continue;
            };
            let LiftedValueDef::Operator { op, args } = &value.def else {
                continue;
            };
            let Some(shape) = access_shape(op) else {
                continue;
            };
            let addr = *args.first()?;
            if !addresses.contains(&addr) {
                continue;
            }
            accessors.insert(id);
            let (_, delta) = canon_addr(func, addr);
            let offset = delta.checked_add(shape.memarg_offset)?;
            let entry = slots.entry(offset).or_insert_with(|| SlotAccess {
                offset,
                width: shape.width,
                ty: shape.ty,
                conflicted: false,
                stores: Vec::new(),
                loads: Vec::new(),
            });
            // Accesses to one offset must agree on width and type, or the
            // bytes are being reinterpreted rather than read as a variable
            // — rustc stores a `Result` discriminant as `i64` and reads it
            // back as `i32`, which is a truncation, not a load of the slot.
            //
            // This declines the *slot*, not the frame. Its bytes are still
            // accounted for in the overlap check below, so a neighbouring
            // slot is unaffected and promotes normally.
            if entry.width != shape.width || entry.ty != shape.ty {
                entry.conflicted = true;
                entry.width = entry.width.max(shape.width);
            }
            let access = Access {
                block: block_id,
                position,
                id,
                value: if shape.is_store { *args.get(1)? } else { id },
            };
            if shape.is_store {
                entry.stores.push(access);
            } else {
                entry.loads.push(access);
            }
        }
    }

    // Partial overlap means two "variables" share bytes, so a write to one
    // is a write to the other.
    let mut end = 0u64;
    for slot in slots.values() {
        if u64::from(slot.offset) < end {
            return None;
        }
        end = u64::from(slot.offset) + u64::from(slot.width);
    }
    // A slot nothing writes has no value to forward.
    //
    // A slot nothing *reads* is kept, and its stores are removed rather
    // than promoted. `SweepDeadPass` will not do it — it keeps every store
    // by design, because in general a store is observable — but here it is
    // provably not: no pointer to *these* bytes leaves the function, and a
    // write nobody in it loads cannot be seen by anyone. Leaving them
    // behind became load-bearing once [`super::forward`] started retiring
    // the loads that used to keep such slots on this path.
    //
    // That argument is exactly why a slot inside an escaped range is dropped
    // here rather than promoted: for those bytes a pointer *does* leave, so
    // a store with no local reader may well be read by the callee, and a
    // load may see what the callee wrote instead of what we stored. Dropping
    // them from the returned set leaves their loads and stores untouched,
    // which is the honest outcome, and keeps the reasoning above true of
    // every slot that survives.
    let mut refused = SlotRefusals::default();
    let kept = slots
        .into_values()
        .filter(|s| {
            if s.conflicted {
                refused.conflict += 1;
            } else if s.stores.is_empty() {
                refused.unwritten += 1;
            } else if slot_escapes(s, escaped) {
                refused.escaped += 1;
            } else {
                return true;
            }
            false
        })
        .collect();
    Some((kept, refused))
}

/// Why slots of an otherwise analysable frame were not promoted.
///
/// A frame can pass every escape gate and still yield nothing, and until
/// these were counted that outcome was indistinguishable from a frame
/// nobody looked at. `account` is the case that prompted them: zero
/// declines, zero promotions, 191 holes.
#[derive(Debug, Default)]
struct SlotRefusals {
    conflict: i64,
    unwritten: i64,
    escaped: i64,
    undominated: i64,
}

impl SlotRefusals {
    fn report(&self, result: &mut PassResult) {
        for (key, n) in [
            (MEMORY_SLOT_REFUSED_CONFLICT, self.conflict),
            (MEMORY_SLOT_REFUSED_UNWRITTEN, self.unwritten),
            (MEMORY_SLOT_REFUSED_ESCAPED, self.escaped),
            (MEMORY_SLOT_REFUSED_UNDOMINATED, self.undominated),
        ] {
            if n > 0 {
                result.metrics.increment(key, n);
            }
        }
    }
}

/// Whether a slot's bytes fall inside any range a callee can reach.
///
/// Half-open overlap on both sides: touching the byte after a slot is not
/// touching the slot.
fn slot_escapes(slot: &SlotAccess, escaped: &[(i64, i64)]) -> bool {
    let start = i64::from(slot.offset);
    let end = start + i64::from(slot.width);
    escaped.iter().any(|&(lo, hi)| start < hi && lo < end)
}


// ---------------------------------------------------------------------
// mem2reg — promoting one scalar
// ---------------------------------------------------------------------

/// Promote one slot. The caller has already established that every load is
/// written first; see the note at the call site for why that check cannot
/// happen here.
fn promote(func: &mut LiftedFunction, slot: &SlotAccess, cfg: &CfgFacts) -> bool {
    // Nothing reads the slot, so there is no value to thread and no merge
    // to express: the stores are simply unobservable (see `discover` for
    // why that is proved rather than assumed) and can go on their own.
    // Taking the general path here would insert a block parameter in every
    // block for a variable with no readers, leaving the two cleanup passes
    // to undo work that never needed doing.
    if slot.loads.is_empty() {
        let retired: HashSet<ValueId> = slot.stores.iter().map(|s| s.id).collect();
        for (_, block) in func.blocks.iter_mut() {
            block.instructions.retain(|id| !retired.contains(id));
        }
        return true;
    }

    let reachable: Vec<BlockId> = func
        .blocks
        .iter()
        .map(|(id, _)| id)
        .filter(|id| cfg.is_reachable(*id))
        .collect();

    // The slot's value on entry. Provably unobserved — that is what
    // `every_load_is_written_first` establishes — so a zero is a
    // placeholder rather than a claim about the program.
    let initial = push_zero(func, slot.ty);
    if let Some(entry) = func.blocks.get_mut(func.entry) {
        entry.instructions.insert(0, initial);
    }

    // A parameter in every reachable block but the entry, whose value on
    // entry is `initial`. Maximal, not minimal: `PruneTrivialPhisPass`
    // removes the ones that turn out to carry a single value.
    let mut incoming: HashMap<BlockId, ValueId> = HashMap::new();
    let mut parameterised: HashSet<BlockId> = HashSet::new();
    for &block_id in &reachable {
        if block_id == func.entry {
            incoming.insert(block_id, initial);
            continue;
        }
        let index = func
            .blocks
            .get(block_id)
            .map_or(0, |b| b.params.len() as u32);
        let param = func.values.push(LiftedValue {
            def: LiftedValueDef::BlockParam {
                block: block_id,
                index,
            },
            types: vec![slot.ty],
        });
        if let Some(block) = func.blocks.get_mut(block_id) {
            block.params.push(param);
        }
        parameterised.insert(block_id);
        incoming.insert(block_id, param);
    }

    // Walk each block in order: the slot's value starts at the block's
    // incoming value, each store redefines it, each load reads it.
    let mut outgoing: HashMap<BlockId, ValueId> = HashMap::new();
    for &block_id in &reachable {
        let mut current = incoming[&block_id];
        let Some(block) = func.blocks.get(block_id) else {
            continue;
        };
        let instructions = block.instructions.clone();
        let mut rewrites: Vec<(ValueId, ValueId)> = Vec::new();
        let mut retired: HashSet<ValueId> = HashSet::new();

        for id in instructions.iter().copied() {
            if let Some(store) = slot.stores.iter().find(|a| a.id == id) {
                current = store.value;
                retired.insert(id);
            } else if slot.loads.iter().any(|a| a.id == id) {
                // The load becomes an alias for whatever is in the slot
                // here. `ResolveAliasesPass` rewrites its readers; the
                // arena is push-only, so this is the established tombstone.
                rewrites.push((id, current));
                retired.insert(id);
            }
        }
        outgoing.insert(block_id, current);

        for (load, value) in rewrites {
            if let Some(target) = func.values.get_mut(load) {
                target.def = LiftedValueDef::Alias(value);
            }
        }
        if let Some(block) = func.blocks.get_mut(block_id) {
            block.instructions.retain(|id| !retired.contains(id));
        }
    }

    // Wire every edge whose *target* gained a parameter, and only those:
    // arguments are matched to parameters positionally, so an argument on
    // an edge into a block with no new parameter would shift every
    // parameter after it. Unreachable blocks deliberately got none.
    //
    // Edges *from* an unreachable block still carry the placeholder. They
    // never execute and contribute no value, but the arity has to hold —
    // the same rule `PruneTrivialPhisPass` obeys when it removes a
    // parameter.
    let block_ids: Vec<BlockId> = func.blocks.iter().map(|(id, _)| id).collect();
    for block_id in block_ids {
        let arg = outgoing.get(&block_id).copied().unwrap_or(initial);
        if let Some(block) = func.blocks.get_mut(block_id) {
            for_each_target_mut(&mut block.terminator, |t| {
                if parameterised.contains(&t.block) {
                    t.args.push(arg);
                }
            });
        }
    }
    true
}

/// Whether every load of the slot is preceded, on every path, by a store to
/// it.
///
/// Without this the slot's initial value could be observed, and there is no
/// honest value to give it: shadow-stack memory is reused, so its contents
/// before the first write are whatever the previous frame left.
fn every_load_is_written_first(slot: &SlotAccess, cfg: &CfgFacts) -> bool {
    slot.loads.iter().all(|load| {
        slot.stores.iter().any(|store| {
            if store.block == load.block {
                store.position < load.position
            } else {
                cfg.dominates(store.block, load.block)
            }
        })
    })
}

/// A zero constant of `ty`, appended to the value arena.
fn push_zero(func: &mut LiftedFunction, ty: LiftedType) -> ValueId {
    let op = match ty {
        LiftedType::I32 => waffle::Operator::I32Const { value: 0 },
        LiftedType::F32 => waffle::Operator::F32Const { value: 0 },
        LiftedType::F64 => waffle::Operator::F64Const { value: 0 },
        // I64 and anything else this pass admits: `access_shape` only ever
        // yields the four numeric types, and the two float cases are
        // handled above.
        _ => waffle::Operator::I64Const { value: 0 },
    };
    func.values.push(LiftedValue {
        def: LiftedValueDef::Operator {
            op: WasmOp(op),
            args: vec![],
        },
        types: vec![ty],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dataflow::for_each_target;
    use crate::test_util::{block, func_with, i32_const, op, target, v};
    use sordec_ir::LiftedTerminator;

    fn mem() -> waffle::Memory {
        waffle::Memory::from(0)
    }

    fn memarg(offset: u32) -> waffle::MemoryArg {
        waffle::MemoryArg {
            align: 3,
            offset,
            memory: mem(),
        }
    }

    fn store(offset: u32, addr: ValueId, value: ValueId) -> LiftedValueDef {
        op(
            waffle::Operator::I64Store {
                memory: memarg(offset),
            },
            vec![addr, value],
        )
    }

    fn load(offset: u32, addr: ValueId) -> LiftedValueDef {
        op(
            waffle::Operator::I64Load {
                memory: memarg(offset),
            },
            vec![addr],
        )
    }

    fn global_get() -> LiftedValueDef {
        op(
            waffle::Operator::GlobalGet {
                global_index: waffle::Global::from(0),
            },
            vec![],
        )
    }

    fn global_set(value: ValueId) -> LiftedValueDef {
        op(
            waffle::Operator::GlobalSet {
                global_index: waffle::Global::from(0),
            },
            vec![value],
        )
    }

    /// Straight-line: reserve a frame, store a value, load it back.
    fn straight_line() -> LiftedFunction {
        func_with(
            vec![
                global_get(),                                  // v0 sp
                i32_const(16),                                 // v1
                op(waffle::Operator::I32Sub, vec![v(0), v(1)]), // v2 fp
                global_set(v(2)),                              // v3
                i32_const(7),                                  // v4 the value
                store(0, v(2), v(4)),                          // v5
                load(0, v(2)),                                 // v6
            ],
            vec![block(
                0,
                vec![],
                (0..7).map(v).collect(),
                LiftedTerminator::Return { values: vec![v(6)] },
            )],
        )
    }

    fn slots_of(func: &LiftedFunction) -> Vec<SlotAccess> {
        let layout = frame::detect(func).expect("a frame");
        let cfg = CfgFacts::build(func);
        discover(func, layout.base, &cfg, &[]).expect("promotable").0
    }

    #[test]
    fn a_frame_splits_into_one_scalar_per_offset() {
        let slots = slots_of(&straight_line());
        assert_eq!(slots.len(), 1);
        assert_eq!(slots[0].offset, 0);
        assert_eq!(slots[0].width, 8);
        assert_eq!(slots[0].loads.len(), 1);
        assert_eq!(slots[0].stores.len(), 1);
    }

    #[test]
    fn a_straight_line_load_forwards_to_the_stored_value() {
        let mut func = straight_line();
        let slots = slots_of(&func);
        let cfg = CfgFacts::build(&func);
        assert!(every_load_is_written_first(&slots[0], &cfg));
        assert!(promote(&mut func, &slots[0], &cfg));

        // The load became an alias for the stored value...
        assert_eq!(
            func.values.get(v(6)).unwrap().def,
            LiftedValueDef::Alias(v(4))
        );
        // ...and neither access is scheduled any more.
        let scheduled = &func.blocks.get(func.entry).unwrap().instructions;
        assert!(!scheduled.contains(&v(5)), "the store is gone");
        assert!(!scheduled.contains(&v(6)), "the load is gone");
    }

    #[test]
    fn the_frame_bracket_is_left_for_the_backend_pass() {
        // Promotion's job ends at the slots. Removing the prologue and
        // epilogue is `marshalling::frame`'s, which already tests for
        // exactly the condition promotion creates.
        let mut func = straight_line();
        let slots = slots_of(&func);
        let cfg = CfgFacts::build(&func);
        promote(&mut func, &slots[0], &cfg);
        let scheduled = &func.blocks.get(func.entry).unwrap().instructions;
        assert!(scheduled.contains(&v(2)), "the frame pointer survives");
        assert!(scheduled.contains(&v(3)), "so does its global.set");
    }

    /// The case that defeated the `HighIr` attempt: the store happens in a
    /// branch, the load after the join.
    fn store_in_a_branch() -> LiftedFunction {
        func_with(
            vec![
                global_get(),                                  // v0
                i32_const(16),                                 // v1
                op(waffle::Operator::I32Sub, vec![v(0), v(1)]), // v2 fp
                global_set(v(2)),                              // v3
                i32_const(1),                                  // v4 cond
                i32_const(7),                                  // v5 value
                store(0, v(2), v(5)),                          // v6 in bb1
                load(0, v(2)),                                 // v7 in bb2
            ],
            vec![
                block(
                    0,
                    vec![],
                    vec![v(0), v(1), v(2), v(3), v(4)],
                    LiftedTerminator::BranchIf {
                        cond: v(4),
                        if_true: target(1, vec![]),
                        if_false: target(2, vec![]),
                    },
                ),
                block(1, vec![], vec![v(5), v(6)], LiftedTerminator::Branch(target(2, vec![]))),
                block(
                    2,
                    vec![],
                    vec![v(7)],
                    LiftedTerminator::Return { values: vec![v(7)] },
                ),
            ],
        )
    }

    #[test]
    fn a_load_not_written_on_every_path_is_declined() {
        // bb1 does not dominate bb2 — the `if_false` edge skips the store —
        // so the load could observe the slot's initial contents, which are
        // whatever the previous stack frame left there.
        let func = store_in_a_branch();
        let slots = slots_of(&func);
        let cfg = CfgFacts::build(&func);
        assert!(
            !every_load_is_written_first(&slots[0], &cfg),
            "an unwritten path must decline"
        );
    }

    #[test]
    fn a_merge_becomes_a_block_parameter() {
        // The same shape, but every path writes: the `else` arm stores too.
        // Promotion must insert a parameter at the join rather than bind
        // the load to one arm's value.
        let mut func = store_in_a_branch();
        // bb0 stores before branching, so bb0 dominates the load.
        func.values.push(LiftedValue {
            def: store(0, v(2), v(4)),
            types: vec![],
        });
        let pre_store = v(8);
        func.blocks
            .get_mut(BlockId::new(0))
            .unwrap()
            .instructions
            .push(pre_store);

        let slots = slots_of(&func);
        let cfg = CfgFacts::build(&func);
        assert!(promote(&mut func, &slots[0], &cfg));

        // bb2 (the join) gained a parameter, and both in-edges carry an
        // argument for it.
        let join = func.blocks.get(BlockId::new(2)).unwrap();
        assert_eq!(join.params.len(), 1, "the merge is a block parameter");
        for block_id in [BlockId::new(0), BlockId::new(1)] {
            let mut args_to_join = 0;
            for_each_target(&func.blocks.get(block_id).unwrap().terminator, |t| {
                if t.block == BlockId::new(2) {
                    args_to_join = t.args.len();
                }
            });
            assert_eq!(args_to_join, 1, "edge from {block_id:?} carries the value");
        }
    }

    /// A slot a callee can reach is refused, and only that slot.
    ///
    /// The escape gate itself now lives in
    /// [`super::slots::frame_escapes`], which hands `discover` the byte
    /// ranges a callee touches rather than a veto. So the unit under test
    /// here is the range check: the frame still resolves, and the slots
    /// inside the escaped range are the ones left out.
    #[test]
    fn a_slot_inside_an_escaped_range_is_refused() {
        let func = straight_line();
        let layout = frame::detect(&func).unwrap();
        let cfg = CfgFacts::build(&func);

        let all = discover(&func, layout.base, &cfg, &[]).expect("promotable").0;
        assert!(!all.is_empty(), "the fixture has promotable slots");

        // A callee reaching the first eight bytes.
        let partial = discover(&func, layout.base, &cfg, &[(0, 8)])
            .expect("the frame resolves")
            .0;
        assert!(
            partial.len() < all.len(),
            "the slot in the escaped range is refused: {all:?} -> {partial:?}"
        );
        assert!(
            partial.iter().all(|s| i64::from(s.offset) >= 8),
            "only slots outside the range survive: {partial:?}"
        );

        // A range covering everything leaves nothing, which is the old
        // whole-frame decline arrived at from the other direction.
        let none = discover(&func, layout.base, &cfg, &[(0, 4096)])
            .expect("the frame resolves")
            .0;
        assert!(none.is_empty(), "an unbounded reach refuses every slot");
    }

    #[test]
    fn mismatched_widths_at_one_offset_decline() {
        let mut func = straight_line();
        func.values.get_mut(v(6)).unwrap().def = op(
            waffle::Operator::I32Load {
                memory: memarg(0),
            },
            vec![v(2)],
        );
        let layout = frame::detect(&func).unwrap();
        let cfg = CfgFacts::build(&func);
        let slots = discover(&func, layout.base, &cfg, &[])
            .expect("the frame still resolves")
            .0;
        assert!(
            slots.is_empty(),
            "a narrower read of a wider store is a reinterpretation, so that \
             slot declines — without taking the rest of the frame with it"
        );
    }

    #[test]
    fn overlapping_slots_decline() {
        // A second slot at offset 4 overlaps the 8-byte slot at 0.
        let mut func = straight_line();
        func.values.push(LiftedValue {
            def: store(4, v(2), v(4)),
            types: vec![],
        });
        func.values.push(LiftedValue {
            def: load(4, v(2)),
            types: vec![LiftedType::I64],
        });
        let entry = func.blocks.get_mut(BlockId::new(0)).unwrap();
        entry.instructions.push(v(7));
        entry.instructions.push(v(8));
        let layout = frame::detect(&func).unwrap();
        let cfg = CfgFacts::build(&func);
        assert!(
            discover(&func, layout.base, &cfg, &[]).is_none(),
            "overlapping slots share bytes"
        );
    }

    #[test]
    fn second_run_reports_no_work() {
        let mut ir = LiftedIr {
            facts: sordec_ir::WasmFacts {
                imports: vec![],
                exports: vec![],
                function_type_indices: vec![],
                function_bodies: vec![],
                function_fingerprints: vec![],
                custom_sections: vec![],
            },
            soroban_facts: None,
            functions: vec![straight_line()],
            memory: sordec_ir::MemoryImage::empty(),
        };
        assert!(SlotPromotionPass.run(&mut ir).changed);
        assert!(
            !SlotPromotionPass.run(&mut ir).changed,
            "idempotent: the slot has no accesses left"
        );
    }
}
