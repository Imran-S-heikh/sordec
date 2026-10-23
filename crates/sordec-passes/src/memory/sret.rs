//! Out-parameter → real return value.
//!
//! WASM returns one machine word, so rustc compiles a function returning
//! anything wider into one that takes a caller-allocated pointer and writes
//! its result through it — the `sret` convention. `read_balance(addr) -> i128`
//! becomes `read_balance(out, addr)` writing two 8-byte halves.
//!
//! This pass converts that back:
//!
//! ```text
//! callee:  store out+0 <- hi        →   return (hi, lo)
//!          store out+8 <- lo
//!          return
//!
//! caller:  call f(fp, x)            →   t = call f(x)
//!                                       store fp+0 <- t.0
//!                                       store fp+8 <- t.1
//! ```
//!
//! ## The caller keeps its stores, deliberately
//!
//! It would look tidier to bind the caller's *loads* straight to `t.0` and
//! `t.1` and delete the memory traffic here. That is what an earlier
//! attempt did, and it is wrong: a caller may make the call inside a branch
//! and read the slots after the join, where the memory is still live but
//! the value is not. Forwarding there produces a use that its definition
//! does not dominate.
//!
//! So this pass changes only the **ABI**. It leaves stores exactly where
//! the call was, which is always sound, and the frame stops escaping into
//! the callee. Removing the memory traffic is then [`super::promote`]'s
//! job, and it does the branch case correctly because mem2reg *inserts a
//! phi* rather than declining.
//!
//! Splitting it this way is not a stylistic choice: escape is precisely
//! mem2reg's precondition, so the ABI change has to happen first and the
//! forwarding second.
//!
//! ## Wired, after two reasons were discharged
//!
//! Measured with this pass alone in the pipeline, every fixture
//! regressed: hello-add 0 → 6 `cargo check` errors, attestation 8 → 13,
//! timelock 53 → 54, token-v23 125 → 147, dex 314 → 416. That was never a
//! defect in the pass — it is what the design above predicts, for two
//! reasons, and both are now addressed:
//!
//! 1. It **moves** the out-parameter stores from callee to caller rather
//!    than removing them, and the backend renders a raw store as a hole.
//!    Forwarding them away is [`super::promote`]'s job, and the two are
//!    registered together.
//! 2. It supersedes [`crate::marshalling::decode`] for every function it
//!    converts — that pass recognised an *out-parameter* shape, which no
//!    longer exists once this one has run. `decode` now reads both
//!    shapes, so the caller-side collapse survives the conversion. On
//!    hello-add the elision fires exactly as it did before.
//!
//! The pair lands at −83 `cargo check` errors corpus-wide; see
//! [`super::promote`] for the per-fixture table.
//!
//! [`crate::marshalling::wide_return`] is the pass this supersedes
//! outright. It reconstructs the same wide returns at the HighIr layer but
//! stayed unwired because its caller-side forwarding has no dominance
//! gate — the bug this split (ABI change here, forwarding in `promote`,
//! which inserts a phi) exists to avoid. It is now dead weight rather
//! than a staged alternative.
//!
//! ## Gates
//!
//! Each declines rather than approximating:
//!
//! - **The out-parameter is written and never otherwise used.** Any read of
//!   it, any escape into a further call, and the slot picture is incomplete.
//! - **One store per offset**, and every storing block **dominates every
//!   return**. Otherwise "the value in that slot at return" is
//!   path-dependent, and this pass has no phi to express that with — the
//!   callee's own promotion runs later.
//! - **The function currently returns nothing.** A wasm return *and* an
//!   out-parameter would both have to become components, and their order is
//!   recorded nowhere.
//! - **Every call site is convertible.** A signature change is module-wide;
//!   one caller that cannot be rewritten vetoes the callee entirely.
//! - **The function is not exported, and the module has no indirect
//!   calls.** Both mean the caller set this pass can see is not the whole
//!   of it — and an exported function's signature is the contract ABI, not
//!   an internal detail. Neither fires on the current corpus (entrypoints
//!   take and return `Val`, never an out-pointer), so both are defensive;
//!   they are here because the failure they prevent is a contract whose ABI
//!   changed silently. See [`super::calls`] for the shared rule.
//!
//! ## Which gate actually refuses — and the census that misread it
//!
//! Counted per candidate, corpus-wide, over the six distinct fixtures:
//!
//! | | distinct functions |
//! |---|---|
//! | converts | 31 |
//! | refused: a storing block does not dominate every return | 13 |
//! | refused by any other gate | **0** |
//!
//! **One gate refuses every unconverted out-pointer, and it is the
//! `Result`/`Option` conditional payload.** Nothing is blocked by escape, by
//! an ambiguous slot, or by an in-out read.
//!
//! An earlier census read this as 228 declines for "the out-pointer reached
//! another call" against 9 for the payload, and concluded the payload was
//! worth ~4% of the blocked frames. Three faults in the counting produced
//! that, all now fixed and each with a test:
//!
//! 1. **Gate order.** The escape gate ran inside the store-collecting loop,
//!    so it fired on candidates the loop had not yet found any store for. Of
//!    those 228, **not one had a single store through it** — every one was an
//!    ordinary argument. "Is this an out-pointer at all" now decides first.
//! 2. **Last writer wins.** Every parameter is tried, and each decline
//!    overwrote the previous, so a real out-pointer at position 0 was filed
//!    under position 1's reason. That reported dex, timelock and attestation
//!    as *zero* path-dependent declines against a true 3, 2 and 1.
//! 3. **Counted twice.** `report_declines` was called before *and* after the
//!    call-site veto with the same vector.
//!
//! Two smaller ones with it: the `stored as a value` gate had no arm in
//! `report_declines` and so lived in `OTHER`, and the conversions themselves
//! reached no report at all — the declines had no denominator to be read
//! against. The i64 filter in `is_address_typed` closes the same hole at
//! the source: 411 of the 534 candidates tried were too wide to be addresses.
//!
//! The consequence for the roadmap is a reprioritisation, not a new design.
//! `plan/NOTES.md`'s objection to the phi/union sketch stands on its own
//! reasoning — a placeholder on the `Err` path is a behaviour regression, and
//! the real recovery is the sum type the source wrote. What changes is its
//! worth: the whole of `sret`'s remaining reach, not 4% of it.

use std::collections::{BTreeMap, HashMap, HashSet};

use sordec_common::{BlockId, FuncId, IrId as _, ValueId};
use sordec_ir::{
    LiftedFunction, LiftedIr, LiftedTerminator, LiftedType, LiftedValue, LiftedValueDef, WasmOp,
};

use super::calls::CallIndex;
use super::frame::canon_addr;
use crate::dataflow::CfgFacts;
use crate::metrics_catalog::MEMORY_SRET_CONVERTED;
use crate::pass::{Pass, PassResult};

/// Unique pipeline name of this pass.
pub const PASS_NAME: &str = "memory-sret-return";

// Why a candidate declined. Constants rather than literals repeated at the
// gate and again in [`report_declines`]: the wording *is* the key, so a typo
// in one of two copies would silently open a new bucket. Naming them keeps
// the original property — the reason reads at the site that enforces it —
// without the second copy.
/// Nothing is stored through this parameter, so it is not an out-pointer.
const DECLINED_NOT_AN_OUT_POINTER: &str = "no stores through the out-pointer";
/// A real out-pointer that also reaches a non-store operator.
const DECLINED_NON_STORE_USE: &str = "out-pointer consumed by a non-store operator";
/// The pointer itself is written to memory — an escape.
const DECLINED_STORED_AS_VALUE: &str = "out-pointer stored as a value";
/// Two stores to one offset make that slot's value at return ambiguous.
const DECLINED_TWO_STORES: &str = "two stores to one offset";
/// A storing block does not dominate every return: the `Result`/`Option`
/// conditional payload.
const DECLINED_PATH_DEPENDENT: &str = "a storing block does not dominate every return";
/// The same refusal in its narrowest and most recoverable form: exactly two
/// slots, a discriminant at `+0` and one payload word at `+8`.
///
/// Split out because it is the slice worth building first. Of the
/// path-dependent refusals on the held-out 25, **45 of 94 are this shape**;
/// the rest are 3, 4 or 5 slots (a 128-bit or multi-word payload). A
/// two-slot out-parameter is `Option<T>` or `Result<T, E>` with a
/// single-word payload, and recovering it as the sum type needs no invented
/// value for the untaken path — which is the whole of the design objection
/// recorded against this item.
const DECLINED_PATH_DEPENDENT_TWO_SLOT: &str =
    "a storing block does not dominate every return (two slots: tag + one payload)";
/// The pointer is read as well as written — an in-out parameter.
const DECLINED_READ_OUTSIDE_STORES: &str = "out-pointer read outside the stores";
/// A `?` guard in [`plan_for`] refused a shape without naming a gate.
const DECLINED_UNREPORTED: &str = "declined by a guard that names no gate";

/// One slot of a converted function's return value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Slot {
    /// Byte offset from the out-pointer.
    offset: u32,
    /// The store operator that wrote it, reused verbatim when the caller
    /// re-stores the returned component so width and alignment cannot drift.
    store_op: waffle::Operator,
    /// WASM type of the stored value.
    ty: LiftedType,
}

/// How one function's out-parameter maps onto returned components.
#[derive(Debug, Clone)]
struct SretPlan {
    /// Position of the out-pointer among the entry block's parameters.
    out_index: usize,
    /// Slots in ascending offset order; component `i` is `slots[i]`.
    slots: Vec<Slot>,
    /// What each slot returns, parallel to `slots`.
    values: Vec<SlotValue>,
    /// The store instructions, and the address arithmetic that fed them,
    /// removed once the values are returned.
    stores: Vec<ValueId>,
}

/// Where a slot's returned value comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SlotValue {
    /// One store, dominating every return: its value is the slot's value.
    Direct(ValueId),
    /// Written on every path to a return, by a different store on each —
    /// `read_allowance` writes its three fields once on each of three arms.
    /// `(store, value)` pairs, threaded to each return by
    /// [`thread_slot`].
    Threaded(Vec<(ValueId, ValueId)>),
}

/// One store through the out-pointer, as [`plan_for`] found it.
#[derive(Debug, Clone, Copy)]
struct StoreSite {
    slot: Slot,
    value: ValueId,
    id: ValueId,
    block: BlockId,
    position: usize,
}

/// Converts `sret` out-parameters into multi-value returns.
#[derive(Debug, Default, Clone, Copy)]
pub struct SretReturnPass;

impl Pass<LiftedIr> for SretReturnPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut LiftedIr) -> PassResult {
        let mut result = PassResult::default();

        let calls = CallIndex::build(ir);

        // Why each candidate declined. Counted rather than discarded so
        // "sret converts little" is a breakdown instead of an impression.
        let mut declines: Vec<&'static str> = Vec::new();
        let mut plans: HashMap<FuncId, SretPlan> = ir
            .functions
            .iter()
            // An exported function's signature is the contract ABI, and its
            // internal call sites are not the complete caller set.
            .filter(|f| !calls.is_exported(f.id))
            // A function an indirect call may reach has callers no scan can
            // see, so its signature may not change.
            .filter(|f| calls.caller_set_complete(f.id))
            .filter_map(|f| {
                let mut reason = None;
                let plan = convertible_reporting(f, &mut reason);
                if let (None, Some(reason)) = (&plan, reason) {
                    declines.push(reason);
                }
                plan.map(|plan| (f.id, plan))
            })
            .collect();
        // Once, and before the veto. Every early return below reaches this
        // point, and the veto discards plans rather than producing declines,
        // so a second call after it re-counted the same vector — every
        // decline twice on any run that converted anything.
        report_declines(&declines, &mut result);
        if plans.is_empty() {
            return result;
        }

        // Module-wide veto before any rewrite. Converting a callee whose
        // caller cannot be rewritten leaves that caller passing a frame to
        // a function that no longer takes one — a module that does not
        // type-check, produced silently.
        let vetoed: Vec<FuncId> = unconvertible_callees(ir, &calls, &plans);
        for id in vetoed {
            plans.remove(&id);
        }
        if plans.is_empty() {
            return result;
        }

        for func in &mut ir.functions {
            rewrite_call_sites(func, &plans, &calls);
        }
        for func in &mut ir.functions {
            if let Some(plan) = plans.get(&func.id) {
                convert_callee(func, plan);
                result.changed = true;
                result.metrics.increment(MEMORY_SRET_CONVERTED, 1);
            }
        }
        result
    }
}

// ---------------------------------------------------------------------
// Callee analysis
// ---------------------------------------------------------------------

/// Can one of `func`'s parameters become a return value?
///
/// The out-pointer is **searched for**, not assumed to be first.
/// [`crate::marshalling::sret::SretShape`] records `out_index` rather than
/// assuming it, on the grounds that "an assumption made in two places is an
/// assumption that can drift"; this is the other place, and it was the one
/// holding the assumption.
///
/// **Measured: every conversion on the corpus is still at index 0**, so the
/// search buys no fixture a conversion it was not already getting. What it
/// does buy is the multi-candidate case below, which *is* real — dex has a
/// function with two written parameters, and it surfaced only because an
/// earlier draft declined on ambiguity and cost that fixture a conversion.
///
/// The functions that take a frame pointer at a later position turn out not
/// to be out-parameter functions at all: they read through it, or forward
/// it onward. Recording that because "the pass never looked there" was true
/// and "so it would convert if it did" did not follow.
#[cfg(test)]
fn convertible(func: &LiftedFunction) -> Option<SretPlan> {
    convertible_reporting(func, &mut None)
}

/// [`convertible`], additionally reporting *which* gate declined.
///
/// The reasons were greppable but discarded, which made "why does sret
/// convert so little" a code-reading exercise rather than a number. They
/// are now countable, so the next pass to write falls out of a census
/// instead of a hunch — the same move `promote`'s frame-decline buckets
/// make one layer up.
///
/// `reason` is only written on decline; a conversion leaves it untouched.
fn convertible_reporting(
    func: &LiftedFunction,
    reason: &mut Option<&'static str>,
) -> Option<SretPlan> {
    // A function that already returns something is a shape this does not
    // model.
    if func.blocks.iter().any(|(_, b)| {
        matches!(&b.terminator, LiftedTerminator::Return { values } if !values.is_empty())
    }) {
        return None;
    }

    let cfg = CfgFacts::build(func);
    let returns: Vec<BlockId> = func
        .blocks
        .iter()
        .filter(|(id, b)| {
            matches!(b.terminator, LiftedTerminator::Return { .. }) && cfg.is_reachable(*id)
        })
        .map(|(id, _)| id)
        .collect();
    if returns.is_empty() {
        return None;
    }

    // The **first** qualifying parameter, not the only one. Two written
    // parameters do happen (dex has one such function), and converting one
    // of them is sound whatever the other is: the rewrite changes that
    // parameter's position alone and leaves the rest of the signature
    // exactly as it was. So there is no ambiguity about the *transform* —
    // only about which to spend, and taking them in order is deterministic
    // and matches what this pass did when the position was a constant.
    //
    // The second is then lost rather than deferred: a converted function
    // `already returns a value`, so a later fixpoint iteration declines it
    // at the first gate. No corpus function needs the second one, and
    // recovering both would mean a plan carrying several out-indices —
    // worth doing only once something asks for it.
    let candidates: Vec<(usize, ValueId)> = func
        .blocks
        .get(func.entry)?
        .params
        .iter()
        .copied()
        .enumerate()
        .filter(|(_, param)| is_address_typed(func, *param))
        .collect();
    let tried = candidates.len();
    let outcome = candidates
        .into_iter()
        .find_map(|(out_index, out_param)| plan_for(func, out_index, out_param, &cfg, &returns, reason));
    if outcome.is_none() && reason.is_none() && tried > 0 {
        // A `?` inside `plan_for` returns `None` without naming a gate, so
        // this decline used to be invisible to the census entirely — neither
        // a bucket nor part of the total.
        *reason = Some(DECLINED_UNREPORTED);
    }
    outcome
}

/// Whether a parameter is wide enough to be an address at all.
///
/// Every Soroban contract is wasm32, where an address is an `i32`. Measured
/// before this filter existed: of the 534 candidates the pass tried
/// corpus-wide, **411 were `i64`** — a `Val`, a timestamp, an amount — and
/// not one could ever have been a pointer. Trying them cost nothing but a
/// decline, and that decline is exactly what the census then reported as an
/// escaping out-pointer.
///
/// Under a `memory64` module this returns `false` for every parameter, so the
/// pass converts nothing rather than converting something wrongly. That is
/// the safe direction, and Soroban has no wasm64 target to make it matter.
fn is_address_typed(func: &LiftedFunction, param: ValueId) -> bool {
    matches!(
        func.values.get(param).and_then(|v| v.types.first()),
        Some(LiftedType::I32)
    )
}

/// Record a decline, keeping the more informative of two reasons.
///
/// [`convertible_reporting`] tries every parameter and the **last** writer
/// used to win, so a function whose out-pointer is parameter 0 was filed
/// under parameter 1's reason. Measured: that reported dex, timelock and
/// attestation as **zero** path-dependent declines when they have 3, 2 and 1,
/// and left the corpus figure at 9 against a true 13.
///
/// The rule is one-way and needs no ordering: [`DECLINED_NOT_AN_OUT_POINTER`]
/// says "this parameter is an ordinary argument", which is a fact about the
/// *candidate* rather than about the function, so it must never displace what
/// a genuine out-pointer reported.
fn record(reason: &mut Option<&'static str>, why: &'static str) {
    if why == DECLINED_NOT_AN_OUT_POINTER
        && matches!(*reason, Some(prior) if prior != DECLINED_NOT_AN_OUT_POINTER)
    {
        return;
    }
    *reason = Some(why);
}

/// The plan for treating `out_param` as the out-pointer, or `None` when any
/// gate declines.
///
/// Every decline here is about *this* parameter, so the search above moves
/// on to the next one rather than giving up on the function.
fn plan_for(
    func: &LiftedFunction,
    out_index: usize,
    out_param: ValueId,
    cfg: &CfgFacts,
    returns: &[BlockId],
    reason: &mut Option<&'static str>,
) -> Option<SretPlan> {
    macro_rules! decline {
        // Named rather than a bare `return None` so each gate is greppable,
        // the reason is visible at the site that enforces it, *and* it
        // reaches the caller for counting.
        ($why:expr) => {{
            record(reason, $why);
            return None;
        }};
    }

    // Deferred rather than returned at the offending instruction. Which gate
    // to *report* depends on whether this candidate is an out-pointer at all,
    // and that is not known until every store has been seen — the loop below
    // may meet a use long before it meets the first store.
    //
    // The decline itself is unconditional either way, so what changes is the
    // reason, not the outcome: `first-wins` keeps the same reason the
    // early-returning version reported whenever the candidate really is an
    // out-pointer.
    let mut escape: Option<&'static str> = None;
    let mut sites: BTreeMap<u32, Vec<StoreSite>> = BTreeMap::new();
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
            let Some(memarg) = store_memarg(op) else {
                // `out + 16`, computed into its own value before a store
                // through it, is a slot address rather than a use — the same
                // reading `reads_outside_stores` gives its address closure,
                // which then checks that only stores consume it.
                if canon_addr(func, id).0 == out_param {
                    continue;
                }
                // Not a store; the out-pointer must not appear in it at all.
                if args
                    .iter()
                    .any(|a| canon_addr(func, *a).0 == out_param)
                {
                    escape = escape.or(Some(DECLINED_NON_STORE_USE));
                }
                continue;
            };
            let (base, delta) = canon_addr(func, *args.first()?);
            if base != out_param {
                // A store elsewhere is fine, unless it stores the pointer
                // itself — that is an escape.
                if canon_addr(func, *args.get(1)?).0 == out_param {
                    escape = escape.or(Some(DECLINED_STORED_AS_VALUE));
                }
                continue;
            }
            let stored = *args.get(1)?;
            let slot = Slot {
                offset: delta.checked_add(memarg.offset)?,
                store_op: op.0,
                ty: *func.values.get(stored)?.types.first()?,
            };
            sites.entry(slot.offset).or_default().push(StoreSite {
                slot,
                value: stored,
                id,
                block: block_id,
                position,
            });
        }
    }
    // **First**, because every gate below is about an out-pointer and this one
    // asks whether there is one. A candidate nothing stores through is an
    // ordinary argument, and reporting one as an escape is what made 228 of
    // 237 declines read "the out-pointer reached another call" when not one of
    // the 228 was a pointer at all.
    if sites.is_empty() {
        decline!(DECLINED_NOT_AN_OUT_POINTER);
    }
    if let Some(why) = escape {
        decline!(why);
    }

    let mut values = Vec::with_capacity(sites.len());
    let mut path_dependent = false;
    for stores in sites.values() {
        let first = stores[0];
        // Two stores to one offset make the slot's value ambiguous when they
        // disagree on width, or when one is on the way to the other — a
        // value overwritten on its own path.
        let same_width = stores.iter().all(|s| {
            std::mem::discriminant(&s.slot.store_op) == std::mem::discriminant(&first.slot.store_op)
                && s.slot.ty == first.slot.ty
        });
        let shadowed = stores.iter().any(|a| {
            stores.iter().any(|b| {
                a.id != b.id
                    && if a.block == b.block {
                        a.position < b.position
                    } else {
                        cfg.dominates(a.block, b.block)
                    }
            })
        });
        if !same_width || shadowed {
            decline!(DECLINED_TWO_STORES);
        }
        if stores.len() == 1 && returns.iter().all(|r| cfg.dominates(first.block, *r)) {
            values.push(SlotValue::Direct(first.value));
        } else if written_on_every_path(func, stores, returns) {
            // Each arm writes its own value; which one reaches a return is
            // the path, so it is threaded rather than read off one store.
            // No arm returns without writing, so no value is invented.
            values.push(SlotValue::Threaded(stores.iter().map(|s| (s.id, s.value)).collect()));
        } else {
            path_dependent = true;
        }
    }
    if path_dependent {
        // Narrow the path-dependent reason to the two-slot case, which is
        // the recoverable one.
        if sites.len() == 2 && sites.contains_key(&0) && sites.contains_key(&8) {
            decline!(DECLINED_PATH_DEPENDENT_TWO_SLOT);
        }
        decline!(DECLINED_PATH_DEPENDENT);
    }

    // The entry parameter must not be read anywhere else — including by the
    // terminators, which is how a pointer gets returned or branched on.
    let store_ids: Vec<ValueId> = sites.values().flatten().map(|s| s.id).collect();
    if reads_outside_stores(func, out_param, &store_ids) {
        decline!(DECLINED_READ_OUTSIDE_STORES);
    }

    // The address arithmetic goes with the stores it fed: nothing else reads
    // it (checked just above), and left scheduled it would name the
    // parameter the conversion removes.
    let mut retired = store_ids;
    retired.extend(address_closure(func, out_param).into_iter().filter(|a| *a != out_param));

    Some(SretPlan {
        out_index,
        slots: sites.values().map(|stores| stores[0].slot).collect(),
        values,
        stores: retired,
    })
}

/// Whether every path from the entry to a return passes one of `stores`.
///
/// A path that reaches a return without writing the slot would return
/// whatever the caller's memory held, and there is no honest value to put
/// there — that is the `Option`/`Result` conditional payload, still declined.
fn written_on_every_path(func: &LiftedFunction, stores: &[StoreSite], returns: &[BlockId]) -> bool {
    let writing: HashSet<BlockId> = stores.iter().map(|s| s.block).collect();
    let mut seen: HashSet<BlockId> = HashSet::new();
    let mut work = vec![func.entry];
    while let Some(block_id) = work.pop() {
        if !seen.insert(block_id) || writing.contains(&block_id) {
            continue;
        }
        if returns.contains(&block_id) {
            return false;
        }
        if let Some(block) = func.blocks.get(block_id) {
            crate::dataflow::for_each_target(&block.terminator, |t| work.push(t.block));
        }
    }
    true
}

/// Whether `out_param` reaches anywhere but the address operand of one of
/// the recognised stores.
///
/// The subtlety worth spelling out: `fp + 8` is *itself* a frame address,
/// not a leak of `fp`. Address arithmetic is how a multi-slot out-parameter
/// is written at all, so the check works over the **address closure** —
/// `out_param` plus every `add addr, const` derived from it — and asks
/// whether anything outside that closure consumes a member of it.
fn reads_outside_stores(func: &LiftedFunction, out_param: ValueId, store_ids: &[ValueId]) -> bool {
    let addresses = address_closure(func, out_param);

    for (id, value) in func.values.iter() {
        // A store we accounted for reads the address legitimately; only its
        // *stored value* operand would be a leak, and that is checked in
        // `convertible`.
        if store_ids.contains(&id) || addresses.contains(&id) {
            continue;
        }
        let consumes = match &value.def {
            LiftedValueDef::Operator { args, .. } => args.iter().any(|a| addresses.contains(a)),
            LiftedValueDef::Alias(from) | LiftedValueDef::PickOutput { from, .. } => {
                addresses.contains(from)
            }
            LiftedValueDef::BlockParam { .. } => false,
        };
        if consumes {
            return true;
        }
    }

    // Terminators: a returned or branched-on address escapes the function.
    func.blocks.iter().any(|(_, block)| {
        let mut escapes = false;
        crate::dataflow::for_each_target(&block.terminator, |t| {
            escapes |= t.args.iter().any(|a| addresses.contains(a));
        });
        if let LiftedTerminator::Return { values } = &block.terminator {
            escapes |= values.iter().any(|v| addresses.contains(v));
        }
        escapes
    })
}

/// Every value that *is* a frame address: `out_param`, its aliases, and any
/// `add` of one of those with a constant.
fn address_closure(func: &LiftedFunction, out_param: ValueId) -> HashSet<ValueId> {
    let mut closure: HashSet<ValueId> = HashSet::new();
    closure.insert(out_param);
    // Values are in definition order and an address is always defined before
    // it is used, so one forward sweep reaches the whole chain.
    for (id, value) in func.values.iter() {
        let derived = match &value.def {
            LiftedValueDef::Alias(from) => closure.contains(from),
            LiftedValueDef::Operator { .. } => canon_addr(func, id).0 == out_param,
            _ => false,
        };
        if derived {
            closure.insert(id);
        }
    }
    closure
}

/// The `MemoryArg` of a store operator, or `None` for anything else.
fn store_memarg(op: &WasmOp) -> Option<waffle::MemoryArg> {
    match &op.0 {
        waffle::Operator::I32Store { memory }
        | waffle::Operator::I64Store { memory }
        | waffle::Operator::F32Store { memory }
        | waffle::Operator::F64Store { memory }
        | waffle::Operator::I32Store8 { memory }
        | waffle::Operator::I32Store16 { memory }
        | waffle::Operator::I64Store8 { memory }
        | waffle::Operator::I64Store16 { memory }
        | waffle::Operator::I64Store32 { memory } => Some(*memory),
        _ => None,
    }
}

// ---------------------------------------------------------------------
// Caller analysis
// ---------------------------------------------------------------------

/// Planned callees with a call site this pass cannot rewrite.
///
/// A signature change is module-wide, so one unrewritable site vetoes its
/// callee entirely — checked here, before anything is touched.
fn unconvertible_callees(
    ir: &LiftedIr,
    calls: &CallIndex,
    plans: &HashMap<FuncId, SretPlan>,
) -> Vec<FuncId> {
    let mut vetoed = Vec::new();
    for (&target, plan) in plans {
        let unrewritable = calls.sites_targeting(target).iter().any(|site| {
            let Some(caller) = ir.functions.get(site.caller.index() as usize) else {
                // A site we cannot even find is a site we cannot rewrite.
                return true;
            };
            let Some(value) = caller.values.get(site.call) else {
                return true;
            };
            let LiftedValueDef::Operator { args, .. } = &value.def else {
                return true;
            };
            // The frame argument must be there to drop.
            args.get(plan.out_index).is_none()
        });
        if unrewritable {
            vetoed.push(target);
        }
    }
    vetoed
}

/// Drop the frame argument from every converted call and re-store the
/// returned components in its place.
fn rewrite_call_sites(
    func: &mut LiftedFunction,
    plans: &HashMap<FuncId, SretPlan>,
    calls: &CallIndex,
) {
    // Collect first: the rewrite appends to `values`, which cannot happen
    // while iterating it.
    let sites: Vec<(BlockId, usize, ValueId, FuncId)> = func
        .blocks
        .iter()
        .flat_map(|(block_id, block)| {
            block
                .instructions
                .iter()
                .enumerate()
                .map(move |(position, &id)| (block_id, position, id))
        })
        .filter_map(|(block_id, position, id)| {
            let LiftedValueDef::Operator { op, .. } = &func.values.get(id)?.def else {
                return None;
            };
            let target = calls.target(op)?;
            plans.contains_key(&target).then_some((block_id, position, id, target))
        })
        .collect();

    // Later positions first, so inserting instructions does not invalidate
    // the positions still to be processed.
    for (block_id, position, call, target) in sites.into_iter().rev() {
        let plan = &plans[&target];
        let Some(frame) = drop_frame_arg(func, call, plan.out_index) else {
            continue;
        };
        // The call now yields one value per slot.
        if let Some(value) = func.values.get_mut(call) {
            value.types = plan.slots.iter().map(|s| s.ty).collect();
        }
        let mut inserted = Vec::with_capacity(plan.slots.len() * 2);
        for (index, slot) in plan.slots.iter().enumerate() {
            let component = func.values.push(LiftedValue {
                def: LiftedValueDef::PickOutput {
                    from: call,
                    index: index as u32,
                },
                types: vec![slot.ty],
            });
            // Re-store where the call was. The callee's own store operator
            // is reused so width, alignment and memory index are the ones
            // the original wrote with.
            let mut op = slot.store_op;
            op.update_memory_arg(|memarg| memarg.offset = slot.offset);
            let store = func.values.push(LiftedValue {
                def: LiftedValueDef::Operator {
                    op: WasmOp(op),
                    args: vec![frame, component],
                },
                types: vec![],
            });
            inserted.push(component);
            inserted.push(store);
        }
        if let Some(block) = func.blocks.get_mut(block_id) {
            block.instructions.splice(position + 1..position + 1, inserted);
        }
    }
}

/// Remove the frame argument from a call, returning the value it held.
fn drop_frame_arg(func: &mut LiftedFunction, call: ValueId, out_index: usize) -> Option<ValueId> {
    let LiftedValueDef::Operator { args, .. } = &mut func.values.get_mut(call)?.def else {
        return None;
    };
    (out_index < args.len()).then(|| args.remove(out_index))
}

// ---------------------------------------------------------------------
// Callee rewrite
// ---------------------------------------------------------------------

/// Drop the out-parameter, return the slot values, and neutralise the
/// stores that used to write them.
fn convert_callee(func: &mut LiftedFunction, plan: &SretPlan) {
    // Threaded first, while the stores are still in the blocks the walk
    // reads them from.
    let cfg = CfgFacts::build(func);
    let threaded: Vec<Option<Threading>> = plan
        .values
        .iter()
        .zip(&plan.slots)
        .map(|(value, slot)| match value {
            SlotValue::Direct(_) => None,
            SlotValue::Threaded(writes) => Some(thread_slot(func, &cfg, slot.ty, writes)),
        })
        .collect();

    // Entry parameters are the function's ABI; dropping one changes the
    // signature every caller was just rewritten against.
    let entry = func.entry;
    if let Some(block) = func.blocks.get_mut(entry)
        && plan.out_index < block.params.len()
    {
        block.params.remove(plan.out_index);
    }
    renumber_entry_params(func);

    for (block_id, block) in func.blocks.iter_mut() {
        if let LiftedTerminator::Return { values } = &mut block.terminator {
            *values = plan
                .values
                .iter()
                .zip(&threaded)
                .map(|(value, threading)| match (value, threading) {
                    (SlotValue::Direct(v), _) => *v,
                    (SlotValue::Threaded(_), Some(t)) => t.at_exit(block_id),
                    // Unreachable by construction: every threaded value
                    // was threaded above.
                    (SlotValue::Threaded(writes), None) => writes[0].1,
                })
                .collect();
        }
        // The stores are gone from the schedule, but the arena is push-only
        // so their definitions stay as honest, use-free residue.
        block.instructions.retain(|id| !plan.stores.contains(id));
    }
}

/// A threaded slot: its value at the end of every reachable block.
struct Threading {
    outgoing: HashMap<BlockId, ValueId>,
    initial: ValueId,
}

impl Threading {
    /// The slot's value as `block` exits. An unreachable block never
    /// returns, so it takes the placeholder.
    fn at_exit(&self, block: BlockId) -> ValueId {
        self.outgoing.get(&block).copied().unwrap_or(self.initial)
    }
}

/// Thread a slot written by different stores on different paths to the
/// end of every block — `promote`'s maximal-SSA construction, applied to an
/// out-parameter slot rather than a frame slot.
///
/// Every reachable block but the entry gets a parameter for the slot, every
/// edge into one passes the value current at the edge's source, and each
/// store redefines the current value. `PruneTrivialPhisPass` then removes
/// the parameters that carry a single value, as it does after `promote`.
///
/// The entry value is a zero, and it is a placeholder rather than a claim:
/// [`written_on_every_path`] proved no return is reached without a store,
/// so the zero can flow only into blocks a store later overwrites.
fn thread_slot(
    func: &mut LiftedFunction,
    cfg: &CfgFacts,
    ty: LiftedType,
    writes: &[(ValueId, ValueId)],
) -> Threading {
    let reachable: Vec<BlockId> = func
        .blocks
        .iter()
        .map(|(id, _)| id)
        .filter(|id| cfg.is_reachable(*id))
        .collect();

    let initial = super::promote::push_zero(func, ty);
    if let Some(entry) = func.blocks.get_mut(func.entry) {
        entry.instructions.insert(0, initial);
    }

    let mut incoming: HashMap<BlockId, ValueId> = HashMap::new();
    let mut parameterised: HashSet<BlockId> = HashSet::new();
    for &block_id in &reachable {
        if block_id == func.entry {
            incoming.insert(block_id, initial);
            continue;
        }
        let index = func.blocks.get(block_id).map_or(0, |b| b.params.len() as u32);
        let param = func.values.push(LiftedValue {
            def: LiftedValueDef::BlockParam {
                block: block_id,
                index,
            },
            types: vec![ty],
        });
        if let Some(block) = func.blocks.get_mut(block_id) {
            block.params.push(param);
        }
        parameterised.insert(block_id);
        incoming.insert(block_id, param);
    }

    let mut outgoing: HashMap<BlockId, ValueId> = HashMap::new();
    for &block_id in &reachable {
        let mut current = incoming[&block_id];
        if let Some(block) = func.blocks.get(block_id) {
            for id in &block.instructions {
                if let Some((_, value)) = writes.iter().find(|(store, _)| store == id) {
                    current = *value;
                }
            }
        }
        outgoing.insert(block_id, current);
    }

    // Only edges into a block that gained a parameter, positionally; an edge
    // from an unreachable block carries the placeholder to keep the arity.
    let block_ids: Vec<BlockId> = func.blocks.iter().map(|(id, _)| id).collect();
    for block_id in block_ids {
        let arg = outgoing.get(&block_id).copied().unwrap_or(initial);
        if let Some(block) = func.blocks.get_mut(block_id) {
            crate::declutter::for_each_target_mut(&mut block.terminator, |t| {
                if parameterised.contains(&t.block) {
                    t.args.push(arg);
                }
            });
        }
    }
    Threading { outgoing, initial }
}

/// Re-index the entry block's `BlockParam` definitions after a removal.
///
/// A parameter's `index` field is its position, and `PruneTrivialPhisPass`
/// maintains the same invariant when it drops one — leaving them stale
/// would make every later consumer read the wrong parameter.
fn renumber_entry_params(func: &mut LiftedFunction) {
    let Some(entry) = func.blocks.get(func.entry) else {
        return;
    };
    let params = entry.params.clone();
    let entry_id = func.entry;
    for (position, param) in params.into_iter().enumerate() {
        if let Some(value) = func.values.get_mut(param)
            && let LiftedValueDef::BlockParam { block, index } = &mut value.def
        {
            *block = entry_id;
            *index = position as u32;
        }
    }
}

/// Fold the decline reasons into one metric per gate.
///
/// Keyed by the gate's own reason constant so the metric and the code that
/// enforces it cannot drift apart: adding a `decline!` with a new constant
/// and no arm here lands in `OTHER` rather than silently joining a bucket it
/// does not belong to. `OTHER` reaching a non-zero count is therefore a
/// signal that this function is out of date — which is how
/// [`DECLINED_STORED_AS_VALUE`] was found sitting in it.
fn report_declines(declines: &[&'static str], result: &mut PassResult) {
    for reason in declines {
        let key = match *reason {
            DECLINED_PATH_DEPENDENT_TWO_SLOT => {
                crate::metrics_catalog::MEMORY_SRET_DECLINED_PATH_DEPENDENT_TWO_SLOT
            }
            DECLINED_PATH_DEPENDENT => {
                crate::metrics_catalog::MEMORY_SRET_DECLINED_PATH_DEPENDENT
            }
            DECLINED_NOT_AN_OUT_POINTER => {
                crate::metrics_catalog::MEMORY_SRET_DECLINED_NO_STORES
            }
            DECLINED_NON_STORE_USE => {
                crate::metrics_catalog::MEMORY_SRET_DECLINED_NON_STORE_USE
            }
            DECLINED_READ_OUTSIDE_STORES => crate::metrics_catalog::MEMORY_SRET_DECLINED_READ,
            DECLINED_TWO_STORES => crate::metrics_catalog::MEMORY_SRET_DECLINED_TWO_STORES,
            DECLINED_STORED_AS_VALUE => {
                crate::metrics_catalog::MEMORY_SRET_DECLINED_STORED_AS_VALUE
            }
            DECLINED_UNREPORTED => crate::metrics_catalog::MEMORY_SRET_DECLINED_UNREPORTED,
            _ => crate::metrics_catalog::MEMORY_SRET_DECLINED_OTHER,
        };
        result.metrics.increment(key, 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{block, func_with, i32_const, op, param, v};
    use sordec_ir::LiftedTerminator;

    fn store(memory: waffle::Memory, offset: u32, addr: ValueId, value: ValueId) -> LiftedValueDef {
        op(
            waffle::Operator::I64Store {
                memory: waffle::MemoryArg {
                    align: 3,
                    offset,
                    memory,
                },
            },
            vec![addr, value],
        )
    }

    fn mem() -> waffle::Memory {
        waffle::Memory::from(0)
    }

    /// A function whose only instruction is a `call_indirect`.
    fn indirect_caller() -> LiftedFunction {
        let mut f = func_with(
            vec![op(
                waffle::Operator::CallIndirect {
                    sig_index: waffle::Signature::from(0),
                    table_index: waffle::Table::from(0),
                },
                vec![],
            )],
            vec![block(
                0,
                vec![],
                vec![v(0)],
                LiftedTerminator::Return { values: vec![] },
            )],
        );
        f.id = FuncId::new(1);
        f
    }

    /// A module with no imports and no exports, so every function in it is
    /// a plain local callee.
    fn module(functions: Vec<LiftedFunction>) -> LiftedIr {
        LiftedIr {
            facts: sordec_ir::WasmFacts {
                imports: vec![],
                exports: vec![],
                function_type_indices: vec![],
                function_bodies: vec![],
                function_fingerprints: vec![],
                table_functions: None,
                custom_sections: vec![],
            },
            soroban_facts: None,
            functions,
            memory: sordec_ir::MemoryImage::empty(),
        }
    }

    /// `read_balance`-shaped: `(out, arg)`, two slots, one return.
    fn wide_callee() -> LiftedFunction {
        func_with(
            vec![
                param(0, 0),                      // v0 out-pointer
                param(0, 1),                      // v1 argument
                i32_const(7),                     // v2 hi
                i32_const(9),                     // v3 lo
                store(mem(), 0, v(0), v(2)),      // v4
                store(mem(), 8, v(0), v(3)),      // v5
            ],
            vec![block(
                0,
                vec![v(0), v(1)],
                vec![v(2), v(3), v(4), v(5)],
                LiftedTerminator::Return { values: vec![] },
            )],
        )
    }

    #[test]
    fn a_two_slot_out_parameter_is_convertible() {
        let plan = convertible(&wide_callee()).expect("a wide return");
        assert_eq!(plan.out_index, 0);
        assert_eq!(
            plan.slots.iter().map(|s| s.offset).collect::<Vec<_>>(),
            vec![0, 8]
        );
        assert_eq!(plan.values, vec![SlotValue::Direct(v(2)), SlotValue::Direct(v(3))]);
    }

    #[test]
    fn conversion_drops_the_parameter_and_returns_the_values() {
        let mut func = wide_callee();
        let plan = convertible(&func).unwrap();
        convert_callee(&mut func, &plan);

        let entry = func.blocks.get(func.entry).unwrap();
        assert_eq!(entry.params, vec![v(1)], "the out-pointer is gone");
        assert_eq!(
            entry.terminator,
            LiftedTerminator::Return {
                values: vec![v(2), v(3)]
            }
        );
        assert!(
            !entry.instructions.contains(&v(4)),
            "the stores leave the schedule"
        );
        // The surviving parameter is renumbered to its new position.
        assert!(matches!(
            func.values.get(v(1)).unwrap().def,
            LiftedValueDef::BlockParam { index: 0, .. }
        ));
    }

    /// Run the per-parameter gates for one parameter position.
    ///
    /// Some gates are about a single candidate rather than the function, so
    /// asserting them through `convertible` would really be asserting that
    /// *no other* parameter qualifies either — a different claim, and one
    /// that made the escape test below pass for the wrong reason.
    fn plan_at(func: &LiftedFunction, index: usize) -> Option<SretPlan> {
        let cfg = CfgFacts::build(func);
        let returns: Vec<BlockId> = func
            .blocks
            .iter()
            .filter(|(id, b)| {
                matches!(b.terminator, LiftedTerminator::Return { .. }) && cfg.is_reachable(*id)
            })
            .map(|(id, _)| id)
            .collect();
        let param = *func.blocks.get(func.entry)?.params.get(index)?;
        plan_for(func, index, param, &cfg, &returns, &mut None)
    }

    #[test]
    fn a_pointer_that_escapes_is_not_convertible() {
        // Storing the pointer itself, rather than through it.
        let mut func = wide_callee();
        func.values.get_mut(v(5)).unwrap().def = store(mem(), 8, v(1), v(0));
        assert!(
            plan_at(&func, 0).is_none(),
            "an escaping pointer declines"
        );
    }

    #[test]
    fn the_out_parameter_is_found_at_a_later_position() {
        // rustc puts it first when it is the only one; dex has one at
        // position 4 feeding 17 call sites, and assuming 0 made the pass
        // report "not an out-parameter function" rather than declining.
        let func = func_with(
            vec![
                param(0, 0),               // v0 an ordinary argument
                param(0, 1),               // v1 the out-pointer
                i32_const(7),              // v2
                i32_const(9),              // v3
                store(mem(), 0, v(1), v(2)),
                store(mem(), 8, v(1), v(3)),
            ],
            vec![block(
                0,
                vec![v(0), v(1)],
                vec![v(2), v(3), v(4), v(5)],
                LiftedTerminator::Return { values: vec![] },
            )],
        );
        let plan = convertible(&func).expect("convertible");
        assert_eq!(plan.out_index, 1);
        assert_eq!(plan.values, vec![SlotValue::Direct(v(2)), SlotValue::Direct(v(3))]);
    }

    #[test]
    fn two_written_parameters_take_the_first() {
        // Converting one is sound whatever the other is — the rewrite
        // touches that position alone. Declining instead cost dex a
        // conversion it had been getting when the position was a constant.
        let func = func_with(
            vec![
                param(0, 0),
                param(0, 1),
                i32_const(7),
                store(mem(), 0, v(0), v(2)),
                store(mem(), 0, v(1), v(2)),
            ],
            vec![block(
                0,
                vec![v(0), v(1)],
                vec![v(2), v(3), v(4)],
                LiftedTerminator::Return { values: vec![] },
            )],
        );
        let plan = convertible(&func).expect("the first one converts");
        assert_eq!(plan.out_index, 0);
        // The second stays a pointer: this pass models one wide return.
        assert!(plan_at(&func, 1).is_some(), "it qualified, it was not chosen");
    }

    /// The reason a function's decline is filed under, as the census sees it.
    fn decline_reason(func: &LiftedFunction) -> Option<&'static str> {
        let mut reason = None;
        assert!(
            convertible_reporting(func, &mut reason).is_none(),
            "this fixture is supposed to decline"
        );
        reason
    }

    #[test]
    fn an_ordinary_argument_is_not_reported_as_an_escaping_pointer() {
        // The bug this locks: the gate loop met the *use* before it met any
        // store, so every parameter that is simply an argument was filed as
        // an out-pointer that escaped. Corpus-wide that was 228 of 237
        // declines, and not one of the 228 was a pointer.
        let func = func_with(
            vec![
                param(0, 0),                                        // v0 an argument
                i32_const(7),                                       // v1
                op(waffle::Operator::I32Add, vec![v(0), v(1)]),      // v2 uses it
            ],
            vec![block(
                0,
                vec![v(0)],
                vec![v(1), v(2)],
                LiftedTerminator::Return { values: vec![] },
            )],
        );
        assert_eq!(decline_reason(&func), Some(DECLINED_NOT_AN_OUT_POINTER));
    }

    #[test]
    fn a_real_out_pointers_reason_survives_a_later_argument() {
        // `find_map` tries every parameter and the last writer used to win,
        // so parameter 1 being an ordinary argument overwrote what parameter
        // 0 — the actual out-pointer — reported. Measured: that filed dex,
        // timelock and attestation as zero path-dependent declines.
        let func = func_with(
            vec![
                param(0, 0),                                   // v0 the out-pointer
                param(0, 1),                                   // v1 an argument
                i32_const(7),                                  // v2
                store(mem(), 0, v(0), v(2)),                   // v3 slot +0
                store(mem(), 0, v(0), v(2)),                   // v4 again: ambiguous
                op(waffle::Operator::I32Add, vec![v(1), v(2)]), // v5 uses v1
            ],
            vec![block(
                0,
                vec![v(0), v(1)],
                vec![v(2), v(3), v(4), v(5)],
                LiftedTerminator::Return { values: vec![] },
            )],
        );
        assert_eq!(
            decline_reason(&func),
            Some(DECLINED_TWO_STORES),
            "the pointer's own gate must outrank a later argument's"
        );
    }

    #[test]
    fn a_conditional_store_is_reported_as_path_dependent() {
        // The `Result`/`Option` payload, and the only gate that refuses a
        // real out-pointer anywhere on the corpus — previously untested, and
        // its census figure was masked by the bug above.
        //
        //   b0: cond ? b1 : b2      b1: store out+0   b2: (nothing)
        //                           both -> b3: return
        let func = func_with(
            vec![
                param(0, 0),                 // v0 the out-pointer
                i32_const(1),                // v1 the condition
                i32_const(7),                // v2 the payload
                store(mem(), 0, v(0), v(2)), // v3 written on one path only
            ],
            vec![
                block(
                    0,
                    vec![v(0)],
                    vec![v(1), v(2)],
                    LiftedTerminator::BranchIf {
                        cond: v(1),
                        if_true: crate::test_util::target(1, vec![]),
                        if_false: crate::test_util::target(2, vec![]),
                    },
                ),
                block(
                    1,
                    vec![],
                    vec![v(3)],
                    LiftedTerminator::Branch(crate::test_util::target(3, vec![])),
                ),
                block(
                    2,
                    vec![],
                    vec![],
                    LiftedTerminator::Branch(crate::test_util::target(3, vec![])),
                ),
                block(
                    3,
                    vec![],
                    vec![],
                    LiftedTerminator::Return { values: vec![] },
                ),
            ],
        );
        assert_eq!(decline_reason(&func), Some(DECLINED_PATH_DEPENDENT));
    }

    #[test]
    fn a_slot_written_on_every_path_is_threaded_to_the_return() {
        // token-v22's `read_allowance`: each arm writes the slot, so the
        // value at return is whichever arm ran — a merge, not a guess.
        //
        //   b0: cond ? b1 : b2      b1: store out+0 <- 7   b2: store out+0 <- 9
        //                           both -> b3: return
        let mut func = func_with(
            vec![
                param(0, 0),                 // v0 the out-pointer
                i32_const(1),                // v1 the condition
                i32_const(7),                // v2
                i32_const(9),                // v3
                store(mem(), 0, v(0), v(2)), // v4 one arm
                store(mem(), 0, v(0), v(3)), // v5 the other
            ],
            vec![
                block(
                    0,
                    vec![v(0)],
                    vec![v(1), v(2), v(3)],
                    LiftedTerminator::BranchIf {
                        cond: v(1),
                        if_true: crate::test_util::target(1, vec![]),
                        if_false: crate::test_util::target(2, vec![]),
                    },
                ),
                block(1, vec![], vec![v(4)], LiftedTerminator::Branch(crate::test_util::target(3, vec![]))),
                block(2, vec![], vec![v(5)], LiftedTerminator::Branch(crate::test_util::target(3, vec![]))),
                block(3, vec![], vec![], LiftedTerminator::Return { values: vec![] }),
            ],
        );
        let plan = convertible(&func).expect("written on both arms");
        assert_eq!(plan.values, vec![SlotValue::Threaded(vec![(v(4), v(2)), (v(5), v(3))])]);
        convert_callee(&mut func, &plan);

        let join = func.blocks.get(BlockId::from_index(3)).unwrap();
        let [merged] = join.params[..] else {
            panic!("the join gains one parameter for the slot: {:?}", join.params);
        };
        assert_eq!(join.terminator, LiftedTerminator::Return { values: vec![merged] });
        let args_from = |b: u32| {
            let mut args = Vec::new();
            crate::dataflow::for_each_target(
                &func.blocks.get(BlockId::from_index(b)).unwrap().terminator,
                |t| args.extend(t.args.iter().copied()),
            );
            args
        };
        assert_eq!(args_from(1), vec![v(2)], "the first arm passes what it wrote");
        assert_eq!(args_from(2), vec![v(3)], "and the second its own");
    }

    #[test]
    fn a_parameter_too_wide_to_be_an_address_is_never_a_candidate() {
        // Every Soroban contract is wasm32, so an address is an `i32`.
        // Measured: 411 of the 534 candidates the pass used to try were
        // `i64`, and each one produced a decline the census then read as an
        // escaping out-pointer.
        let mut func = func_with(
            vec![
                param(0, 0),                 // v0 the only parameter
                i32_const(7),                // v1
                i32_const(9),                // v2
                store(mem(), 0, v(0), v(1)), // v3
                store(mem(), 8, v(0), v(2)), // v4
            ],
            vec![block(
                0,
                vec![v(0)],
                vec![v(1), v(2), v(3), v(4)],
                LiftedTerminator::Return { values: vec![] },
            )],
        );
        // Widening the parameter is the only difference between these two
        // assertions, so the filter is demonstrably what decides it.
        assert!(convertible(&func).is_some(), "convertible while i32");
        func.values.get_mut(v(0)).unwrap().types = vec![LiftedType::I64];
        let mut reason = None;
        assert!(convertible_reporting(&func, &mut reason).is_none());
        assert_eq!(
            reason, None,
            "not a candidate at all, so not a decline to explain"
        );
    }

    #[test]
    fn a_pointer_that_is_read_is_not_convertible() {
        let mut func = wide_callee();
        // v2 now loads through the out-pointer instead of being a constant.
        func.values.get_mut(v(2)).unwrap().def = op(
            waffle::Operator::I64Load {
                memory: waffle::MemoryArg { align: 3, offset: 0, memory: mem() },
            },
            vec![v(0)],
        );
        assert!(convertible(&func).is_none(), "a read of the slot declines");
    }

    #[test]
    fn two_stores_to_one_offset_decline() {
        let mut func = wide_callee();
        func.values.get_mut(v(5)).unwrap().def = store(mem(), 0, v(0), v(3));
        assert!(convertible(&func).is_none(), "an ambiguous slot declines");
    }

    #[test]
    fn a_function_that_already_returns_a_value_declines() {
        let mut func = wide_callee();
        func.blocks.get_mut(func.entry).unwrap().terminator =
            LiftedTerminator::Return { values: vec![v(2)] };
        assert!(convertible(&func).is_none());
    }

    #[test]
    fn a_caller_keeps_its_stores_and_drops_the_frame_argument() {
        // The whole point of the split: the caller's memory traffic stays
        // where the call was, so a call inside a branch cannot produce a
        // use its definition fails to dominate. `promote` removes it later,
        // with a phi.
        let plan = convertible(&wide_callee()).unwrap();
        let mut plans = HashMap::new();
        plans.insert(FuncId::new(0), plan);

        let mut caller = func_with(
            vec![
                param(0, 0),  // v0 frame
                param(0, 1),  // v1 argument
                op(
                    waffle::Operator::Call {
                        function_index: waffle::Func::from(0),
                    },
                    vec![v(0), v(1)],
                ), // v2 the call
            ],
            vec![block(
                0,
                vec![v(0), v(1)],
                vec![v(2)],
                LiftedTerminator::Return { values: vec![] },
            )],
        );
        caller.id = FuncId::new(1);
        let calls = CallIndex::build(&module(vec![wide_callee(), caller.clone()]));
        rewrite_call_sites(&mut caller, &plans, &calls);

        // The frame argument is gone.
        let LiftedValueDef::Operator { args, .. } = &caller.values.get(v(2)).unwrap().def else {
            panic!("still a call");
        };
        assert_eq!(args, &vec![v(1)]);
        // The call now yields both components.
        assert_eq!(caller.values.get(v(2)).unwrap().types.len(), 2);
        // Two projections and two stores were spliced in after it.
        let scheduled = &caller.blocks.get(caller.entry).unwrap().instructions;
        assert_eq!(scheduled.len(), 5, "call + 2 picks + 2 stores");
        let picks = scheduled
            .iter()
            .filter(|id| {
                matches!(
                    caller.values.get(**id).unwrap().def,
                    LiftedValueDef::PickOutput { .. }
                )
            })
            .count();
        assert_eq!(picks, 2);
    }

    #[test]
    fn an_exported_function_is_never_converted() {
        // Its signature is the contract ABI: the internal call sites this
        // pass can see are not the complete caller set.
        let mut ir = module(vec![wide_callee()]);
        ir.facts.exports.push(sordec_ir::Export {
            name: "read_balance".to_string(),
            kind: sordec_ir::ExportKind::Func,
            index: 0,
        });
        assert!(
            !SretReturnPass.run(&mut ir).changed,
            "an exported out-parameter must be left alone"
        );
    }

    #[test]
    fn an_indirect_call_anywhere_stops_the_pass() {
        // A table-called function has callers no scan can see, so no
        // signature in the module may change.
        let mut ir = module(vec![wide_callee(), indirect_caller()]);
        assert!(
            !SretReturnPass.run(&mut ir).changed,
            "an incomplete caller set vetoes the whole module"
        );
    }

    #[test]
    fn second_run_reports_no_work() {
        let mut ir = module(vec![wide_callee()]);
        assert!(SretReturnPass.run(&mut ir).changed);
        assert!(
            !SretReturnPass.run(&mut ir).changed,
            "idempotent: the out-parameter is gone"
        );
    }
}
