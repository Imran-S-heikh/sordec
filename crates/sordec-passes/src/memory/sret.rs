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
//! ## NOT YET WIRED — it needs [`super::promote`] to be a win
//!
//! Measured with this pass alone in the pipeline, every fixture regressed:
//! hello-add 0 → 6 `cargo check` errors, attestation 8 → 13, timelock
//! 53 → 54, token-v23 125 → 147, dex 314 → 416. That is not a defect in
//! the pass — it is what the design above predicts, for two reasons:
//!
//! 1. It **moves** the out-parameter stores from callee to caller rather
//!    than removing them, and the backend renders a raw store as a hole.
//!    Forwarding them away is [`super::promote`]'s job.
//! 2. It supersedes [`crate::marshalling::decode`] for every function it
//!    converts — that pass recognises an *out-parameter* shape, which no
//!    longer exists once this one has run — without yet replacing the
//!    caller-side value forwarding decode was doing. hello-add's decode
//!    collapse reverts wholesale.
//!
//! So this and `promote` land together, and retiring the HighIr
//! marshalling passes they supersede is part of that landing rather than a
//! follow-up.
//!
//! Measured with the pair wired (`tests/memory_staged.rs` runs exactly
//! that pipeline): reason 1 is discharged — the module validates and
//! structures across the corpus. Reason 2 is not, and promotion cannot
//! discharge it. On hello-add the caller-side traffic that survives is the
//! `Result` discriminant, stored as `i64` and read back as `i32`, which
//! [`super::promote`]'s width/type gate correctly declines as a
//! reinterpretation. The remaining work is therefore on the recognizer —
//! teach `marshalling` the multi-value call shape, or run the elision
//! before this pass transforms it away — not on either pass here.
//!
//! **Reason 2 is now discharged too.** [`crate::marshalling::decode`]
//! recognizes both shapes: it classifies the converted helper from its
//! return components and collapses the caller's `Project`s, including the
//! write-back this pass deliberately leaves behind. What remains before
//! wiring is the measurement, not a defect.
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

use std::collections::{BTreeMap, HashMap, HashSet};

use sordec_common::{BlockId, FuncId, IrId as _, ValueId};
use sordec_ir::{
    LiftedFunction, LiftedIr, LiftedTerminator, LiftedType, LiftedValue, LiftedValueDef, WasmOp,
};
use waffle::entity::EntityRef as _;

use super::frame::canon_addr;
use crate::dataflow::CfgFacts;
use crate::metrics_catalog::MEMORY_SRET_CONVERTED;
use crate::pass::{Pass, PassResult};

/// Unique pipeline name of this pass.
pub const PASS_NAME: &str = "memory-sret-return";

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
    /// Value stored in each slot, parallel to `slots`.
    values: Vec<ValueId>,
    /// The store instructions, removed once the values are returned.
    stores: Vec<ValueId>,
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

        let mut plans: HashMap<FuncId, SretPlan> = ir
            .functions
            .iter()
            .filter_map(|f| convertible(f).map(|plan| (f.id, plan)))
            .collect();
        if plans.is_empty() {
            return result;
        }

        // Module-wide veto before any rewrite. Converting a callee whose
        // caller cannot be rewritten leaves that caller passing a frame to
        // a function that no longer takes one — a module that does not
        // type-check, produced silently.
        let imported = imported_function_count(&ir.facts);
        let vetoed: Vec<FuncId> = ir
            .functions
            .iter()
            .flat_map(|f| unconvertible_callees(f, &plans, imported))
            .collect();
        for id in vetoed {
            plans.remove(&id);
        }
        if plans.is_empty() {
            return result;
        }

        for func in &mut ir.functions {
            rewrite_call_sites(func, &plans, imported);
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

/// Can `func`'s out-parameter become a return value?
fn convertible(func: &LiftedFunction) -> Option<SretPlan> {
    macro_rules! decline {
        // Named rather than a bare `return None` so each gate is greppable
        // and the reason is visible at the site that enforces it.
        ($why:literal) => {{
            let _ = $why;
            return None;
        }};
    }
    // A function that already returns something is a shape this does not
    // model.
    if func.blocks.iter().any(|(_, b)| {
        matches!(&b.terminator, LiftedTerminator::Return { values } if !values.is_empty())
    }) {
        decline!("already returns a value");
    }

    const OUT_INDEX: usize = 0;
    let entry = func.blocks.get(func.entry)?;
    let out_param = *entry.params.get(OUT_INDEX)?;

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
        decline!("no reachable return");
    }

    let mut slots: BTreeMap<u32, (Slot, ValueId, ValueId)> = BTreeMap::new();
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
            let Some(memarg) = store_memarg(op) else {
                // Not a store; the out-pointer must not appear in it at all.
                if args
                    .iter()
                    .any(|a| canon_addr(func, *a).0 == out_param)
                {
                    decline!("out-pointer consumed by a non-store operator");
                }
                continue;
            };
            let (base, delta) = canon_addr(func, *args.first()?);
            if base != out_param {
                // A store elsewhere is fine, unless it stores the pointer
                // itself — that is an escape.
                if canon_addr(func, *args.get(1)?).0 == out_param {
                    decline!("out-pointer stored as a value");
                }
                continue;
            }
            // Every storing block must dominate every return, or "the value
            // in this slot at return" is path-dependent.
            if !returns.iter().all(|r| cfg.dominates(block_id, *r)) {
                decline!("a storing block does not dominate every return");
            }
            let stored = *args.get(1)?;
            let slot = Slot {
                offset: delta.checked_add(memarg.offset)?,
                store_op: op.0,
                ty: *func.values.get(stored)?.types.first()?,
            };
            // Two stores to one offset make the slot's value ambiguous.
            if slots.insert(slot.offset, (slot, stored, id)).is_some() {
                decline!("two stores to one offset");
            }
        }
    }
    if slots.is_empty() {
        decline!("no stores through the out-pointer");
    }

    // The entry parameter must not be read anywhere else — including by the
    // terminators, which is how a pointer gets returned or branched on.
    if reads_outside_stores(func, out_param, &slots) {
        decline!("out-pointer read outside the stores");
    }

    Some(SretPlan {
        out_index: OUT_INDEX,
        slots: slots.values().map(|(s, _, _)| *s).collect(),
        values: slots.values().map(|(_, v, _)| *v).collect(),
        stores: slots.values().map(|(_, _, id)| *id).collect(),
    })
}

/// Whether `out_param` reaches anywhere but the address operand of one of
/// the recognised stores.
///
/// The subtlety worth spelling out: `fp + 8` is *itself* a frame address,
/// not a leak of `fp`. Address arithmetic is how a multi-slot out-parameter
/// is written at all, so the check works over the **address closure** —
/// `out_param` plus every `add addr, const` derived from it — and asks
/// whether anything outside that closure consumes a member of it.
fn reads_outside_stores(
    func: &LiftedFunction,
    out_param: ValueId,
    slots: &BTreeMap<u32, (Slot, ValueId, ValueId)>,
) -> bool {
    let addresses = address_closure(func, out_param);
    let store_ids: Vec<ValueId> = slots.values().map(|(_, _, id)| *id).collect();

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

/// Callees `func` calls in a way this pass cannot rewrite.
fn unconvertible_callees(
    func: &LiftedFunction,
    plans: &HashMap<FuncId, SretPlan>,
    imported: u32,
) -> Vec<FuncId> {
    let mut vetoed = Vec::new();
    for (_, value) in func.values.iter() {
        let LiftedValueDef::Operator { op, args } = &value.def else {
            continue;
        };
        let Some(target) = call_target(op, imported) else {
            continue;
        };
        let Some(plan) = plans.get(&target) else {
            continue;
        };
        // The frame argument must be there to drop.
        if args.get(plan.out_index).is_none() {
            vetoed.push(target);
        }
    }
    vetoed
}

/// The callee of a direct call operator, as a **local** [`FuncId`].
///
/// WASM's function index space puts every host import first, so a
/// `call`'s `function_index` is not the index of a local function — the
/// lift shifts by the import count when it builds `FuncId`s
/// (`lowering::lift_to_high::lower_call` does the same arithmetic).
/// Reading the raw index as a `FuncId` silently names the wrong callee,
/// which is worse than naming none: call sites stop matching their callee
/// while the callee is still rewritten, and the module quietly stops
/// type-checking.
fn call_target(op: &WasmOp, imported: u32) -> Option<FuncId> {
    let waffle::Operator::Call { function_index } = &op.0 else {
        return None;
    };
    let global = function_index.index() as u32;
    // An import is a host call; it has no body here to convert.
    global
        .checked_sub(imported)
        .map(FuncId::from_index)
}

/// How many of the module's imports are functions — the offset between
/// WASM's global function index space and our local one.
fn imported_function_count(facts: &sordec_ir::WasmFacts) -> u32 {
    facts
        .imports
        .iter()
        .filter(|i| matches!(i.kind, sordec_ir::ImportKind::Func(_)))
        .count() as u32
}

/// Drop the frame argument from every converted call and re-store the
/// returned components in its place.
fn rewrite_call_sites(
    func: &mut LiftedFunction,
    plans: &HashMap<FuncId, SretPlan>,
    imported: u32,
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
            let target = call_target(op, imported)?;
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
    // Entry parameters are the function's ABI; dropping one changes the
    // signature every caller was just rewritten against.
    let entry = func.entry;
    if let Some(block) = func.blocks.get_mut(entry)
        && plan.out_index < block.params.len()
    {
        block.params.remove(plan.out_index);
    }
    renumber_entry_params(func);

    for (_, block) in func.blocks.iter_mut() {
        if let LiftedTerminator::Return { values } = &mut block.terminator {
            values.clone_from(&plan.values);
        }
        // The stores are gone from the schedule, but the arena is push-only
        // so their definitions stay as honest, use-free residue.
        block.instructions.retain(|id| !plan.stores.contains(id));
    }
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
        assert_eq!(plan.values, vec![v(2), v(3)]);
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

    #[test]
    fn a_pointer_that_escapes_is_not_convertible() {
        // Storing the pointer itself, rather than through it.
        let mut func = wide_callee();
        func.values.get_mut(v(5)).unwrap().def = store(mem(), 8, v(1), v(0));
        assert!(convertible(&func).is_none(), "an escaping pointer declines");
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
        rewrite_call_sites(&mut caller, &plans, 0);

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
    fn second_run_reports_no_work() {
        let mut ir = LiftedIr {
            facts: sordec_ir::WasmFacts {
                imports: vec![],
                exports: vec![],
                function_type_indices: vec![],
                function_bodies: vec![],
                custom_sections: vec![],
            },
            soroban_facts: None,
            functions: vec![wide_callee()],
            memory: sordec_ir::MemoryImage::empty(),
        };
        assert!(SretReturnPass.run(&mut ir).changed);
        assert!(
            !SretReturnPass.run(&mut ir).changed,
            "idempotent: the out-parameter is gone"
        );
    }
}
