//! By-reference argument → by-value arguments.
//!
//! WASM has no aggregates in its value types, so rustc compiles a function
//! taking anything wider than a machine word *by reference* into one taking
//! a pointer into the caller's shadow-stack frame. `f(&key)` becomes
//! `f(ptr)` with the callee loading through it.
//!
//! This pass converts that back — LLVM calls it ArgumentPromotion:
//!
//! ```text
//! callee:  f(p, x)                 →   f(x, a, b)
//!            a = load p+0                a and b are parameters
//!            b = load p+8
//!
//! caller:  store fp+0 <- k              store fp+0 <- k
//!          store fp+8 <- v              store fp+8 <- v
//!          call f(fp, y)           →    a = load fp+0
//!                                       b = load fp+8
//!                                       call f(y, a, b)
//! ```
//!
//! ## Why this is the shape that mattered
//!
//! It is the exact mirror of [`super::sret`], and it exists for the same
//! reason: **escape is mem2reg's precondition.** A frame address passed to
//! a call is a pointer [`super::promote`] cannot follow, so it declines the
//! *whole frame* — measured on the corpus, that one condition accounted for
//! 40 of the 63 surviving frames, and `promote` was reaching zero of
//! token-v23's remaining slots because of it.
//!
//! The hoisted load lands immediately before the call, next to the caller's
//! own store into that slot. `promote` then forwards the store's value
//! straight to it and both die — so the pass does not merely relocate the
//! memory traffic, it is what makes the traffic removable.
//!
//! Downstream there is a second payoff. token-v23's `DataKey` converter
//! reads exactly one thing from its pointer: the enum discriminant, which
//! its callers store as a *constant* into the frame. Once that constant
//! reaches the call site as an argument,
//! [`crate::interproc::SpecializePass`] can pin it — which it could never
//! do while the value was on the other side of a pointer.
//!
//! ## Gates
//!
//! Each declines rather than approximating, and all but the last are shared
//! with [`super::promote`] through [`super::slots`] so the two passes cannot
//! drift on what an escape is:
//!
//! - **The parameter is only ever a load address.** Any other consumer —
//!   passed onward, stored as a value, returned, branched on — and the
//!   picture is incomplete. [`addresses_only_flow_to`] is written as "what
//!   is allowed", so an operator nobody thought about declines.
//! - **Nothing stores through it.** A written parameter is `sret`'s shape.
//!   Leaving it there is what stops the two passes both claiming one
//!   function.
//! - **One width and type per offset, and no partial overlap.** A narrower
//!   read of a wider one is a reinterpretation, not a read of that field.
//! - **Exactly one parameter qualifies.** Two would be sound but the corpus
//!   has none, and an untested rewrite path is worth less than an honest
//!   decline.
//! - **Every load's block dominates every reachable return.** This is the
//!   hoisting-safety gate, and the only one not shared: it establishes that
//!   the callee would have performed the load on *every* path, so moving it
//!   to the caller cannot fault where the original did not.
//!
//!   One residual premise, stated because it is not proven: a callee that
//!   traps *before* the load on some path would now fault in the caller
//!   instead of trapping in the callee. Both end the program at the same
//!   call, so no observable Soroban behaviour differs — but it is an
//!   argument, not a proof, and it is the reason the gate is written over
//!   returns rather than over "reaches the load".
//!
//! - **Not exported, no indirect calls, every call site rewritable.** The
//!   caller-set rules, shared with `sret` via [`super::calls`].
//! - **Self-recursive functions are skipped.** Sound but pointless — the
//!   recursive site would need the pointer the pass has just deleted — and
//!   skipping keeps the single-sweep structure reviewable.
//!
//! ## Order, and why the fixpoint matters
//!
//! Registered ahead of [`super::sret`] in
//! [`crate::default_lifted_pipeline`], inside the fixpoint group. The group
//! is load-bearing rather than incidental: a helper that forwards its
//! pointer to *another* helper is not a candidate on the first sweep,
//! because the forward is an escape. Once the inner callee is promoted the
//! forward is gone, and the outer one qualifies on the next iteration. 26 of
//! the corpus's 89 escaping call sites are that transitive shape.
//!
//! Like `promote`, this pass leaves **used** `Alias` tombstones behind, so
//! it depends on [`crate::ResolveAliasesPass`] running *inside* that group
//! rather than once up front — see [`super::promote`] for what breaks
//! otherwise and where the damage surfaces.

use std::collections::{BTreeMap, HashMap, HashSet};

use sordec_common::{FuncId, IrId as _, ValueId};
use sordec_ir::{LiftedFunction, LiftedIr, LiftedTerminator, LiftedType, LiftedValue, LiftedValueDef};

use super::calls::CallIndex;
use super::frame::canon_addr;
use super::slots::{access_shape, address_closure, addresses_only_flow_to, scheduled};
use crate::dataflow::CfgFacts;
use crate::declutter::drop_params;
use crate::metrics_catalog::{MEMORY_ARGS_PROMOTED, MEMORY_LOADS_HOISTED};
use crate::pass::{Pass, PassResult};

/// Unique pipeline name of this pass.
pub const PASS_NAME: &str = "memory-arg-promotion";

/// One field read through a promoted pointer parameter.
#[derive(Debug, Clone)]
struct Field {
    /// Byte offset from the pointer.
    offset: u32,
    /// Access width in bytes; every load of this field must agree.
    width: u32,
    /// The value type loads of this field produce.
    ty: LiftedType,
    /// The load operator itself, reused verbatim when the caller performs
    /// the hoisted load so width, alignment and memory index cannot drift.
    load_op: waffle::Operator,
    /// Every load of this field, retired once the field is a parameter.
    loads: Vec<ValueId>,
}

/// How one function's pointer parameter maps onto scalar parameters.
#[derive(Debug, Clone)]
struct ArgPlan {
    /// Position of the pointer among the entry block's parameters.
    param_index: usize,
    /// Fields in ascending offset order; the new parameters are appended
    /// in this order.
    fields: Vec<Field>,
}

/// Converts read-only pointer parameters into scalar parameters.
#[derive(Debug, Default, Clone, Copy)]
pub struct ArgPromotionPass;

impl Pass<LiftedIr> for ArgPromotionPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut LiftedIr) -> PassResult {
        let mut result = PassResult::default();

        let calls = CallIndex::build(ir);

        let mut plans: HashMap<FuncId, ArgPlan> = ir
            .functions
            .iter()
            // Still module-wide, unlike `sret`'s per-function rule. Enabled
            // per function on the four contracts with indirect calls, the
            // promotion was measured at +1,600 holes on import_ark_bn254's
            // big-integer helpers and a dozen compile errors, against no
            // gain elsewhere — so the narrower veto waits until it is
            // understood.
            .filter(|_| !calls.has_indirect_calls())
            // An exported function's signature is the contract ABI.
            .filter(|f| !calls.is_exported(f.id))
            // A promoted callee has no pointer left for a recursive site to
            // pass, so self-recursion is skipped rather than special-cased.
            .filter(|f| !calls.sites_targeting(f.id).iter().any(|s| s.caller == f.id))
            // Nothing calls it, so there is no load to hoist anywhere and
            // the rewrite would strand the parameter.
            .filter(|f| !calls.sites_targeting(f.id).is_empty())
            .filter_map(|f| promotable(f).map(|plan| (f.id, plan)))
            .collect();
        if plans.is_empty() {
            return result;
        }

        // Module-wide veto before any rewrite: a signature change one caller
        // cannot follow leaves that caller passing a pointer to a function
        // that no longer takes one — a module that does not type-check,
        // produced silently.
        for id in unpromotable_callees(ir, &calls, &plans) {
            plans.remove(&id);
        }
        if plans.is_empty() {
            return result;
        }

        for func in &mut ir.functions {
            let hoisted = rewrite_call_sites(func, &plans, &calls);
            if hoisted > 0 {
                result.metrics.increment(MEMORY_LOADS_HOISTED, hoisted);
            }
        }
        for func in &mut ir.functions {
            if let Some(plan) = plans.get(&func.id) {
                promote_params(func, plan);
                result.changed = true;
                result.metrics.increment(MEMORY_ARGS_PROMOTED, 1);
            }
        }
        result
    }
}

// ---------------------------------------------------------------------
// Callee analysis
// ---------------------------------------------------------------------

/// Can one of `func`'s pointer parameters become scalar parameters?
fn promotable(func: &LiftedFunction) -> Option<ArgPlan> {
    let cfg = CfgFacts::build(func);
    let params = func.blocks.get(func.entry)?.params.clone();

    let mut found: Option<ArgPlan> = None;
    for (param_index, param) in params.into_iter().enumerate() {
        let Some(fields) = loaded_fields(func, param, &cfg) else {
            continue;
        };
        if found.is_some() {
            // Two promotable parameters is a rewrite path the corpus does
            // not exercise. Declining is the honest answer.
            return None;
        }
        found = Some(ArgPlan {
            param_index,
            fields,
        });
    }
    found
}

/// The fields `param` is read through, or `None` when any gate declines.
///
/// Declining is whole-parameter rather than per-field for the reason
/// [`super::promote`]'s `discover` gives: the usual cause is an address we
/// could not follow, and such an address may alias any field.
fn loaded_fields(func: &LiftedFunction, param: ValueId, cfg: &CfgFacts) -> Option<Vec<Field>> {
    let live = scheduled(func, cfg);
    let addresses = address_closure(func, param, &live);
    let mut fields: BTreeMap<u32, Field> = BTreeMap::new();
    let mut accessors: HashSet<ValueId> = HashSet::new();

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
            let Some(shape) = access_shape(op) else {
                continue;
            };
            let addr = *args.first()?;
            if !addresses.contains(&addr) {
                continue;
            }
            // A store through the parameter is `sret`'s shape, not this
            // one. Declining here is what keeps the two passes from both
            // claiming one function.
            if shape.is_store {
                return None;
            }
            accessors.insert(id);
            let (_, delta) = canon_addr(func, addr);
            let offset = delta.checked_add(shape.memarg_offset)?;
            let entry = fields.entry(offset).or_insert_with(|| Field {
                offset,
                width: shape.width,
                ty: shape.ty,
                load_op: op.0,
                loads: Vec::new(),
            });
            // Loads of one offset must agree on width and type, or the
            // bytes are being reinterpreted rather than read as one field
            // — and there is no single parameter that stands for both.
            if entry.width != shape.width || entry.ty != shape.ty {
                return None;
            }
            entry.loads.push(id);
        }
    }

    if fields.is_empty() {
        return None;
    }
    if !addresses_only_flow_to(func, &addresses, &accessors, &live) {
        return None;
    }
    // Partial overlap means two "fields" share bytes, so they are not
    // independent values.
    let mut end = 0u64;
    for field in fields.values() {
        if u64::from(field.offset) < end {
            return None;
        }
        end = u64::from(field.offset) + u64::from(field.width);
    }
    if !every_load_is_unconditional(func, &fields, cfg) {
        return None;
    }
    Some(fields.into_values().collect())
}

/// Whether every load runs on every path to every reachable return.
///
/// The hoisting-safety gate. A load the callee performs only on some path
/// is one the caller would now perform on all of them, which can fault
/// where the original did not — so it declines. See the module doc for the
/// one premise this argument leaves standing.
fn every_load_is_unconditional(
    func: &LiftedFunction,
    fields: &BTreeMap<u32, Field>,
    cfg: &CfgFacts,
) -> bool {
    let returns: Vec<_> = func
        .blocks
        .iter()
        .filter(|(id, b)| {
            matches!(b.terminator, LiftedTerminator::Return { .. }) && cfg.is_reachable(*id)
        })
        .map(|(id, _)| id)
        .collect();
    // A function with no reachable return either loops forever or traps on
    // every path. There is no return for a load to dominate, so the gate
    // cannot be discharged and declines.
    if returns.is_empty() {
        return false;
    }
    let load_blocks: HashSet<_> = func
        .blocks
        .iter()
        .flat_map(|(block_id, block)| {
            block
                .instructions
                .iter()
                .map(move |&id| (block_id, id))
        })
        .filter(|(_, id)| fields.values().any(|f| f.loads.contains(id)))
        .map(|(block_id, _)| block_id)
        .collect();

    load_blocks
        .iter()
        .all(|b| returns.iter().all(|r| cfg.dominates(*b, *r)))
}

// ---------------------------------------------------------------------
// Caller analysis
// ---------------------------------------------------------------------

/// Planned callees with a call site this pass cannot rewrite.
fn unpromotable_callees(
    ir: &LiftedIr,
    calls: &CallIndex,
    plans: &HashMap<FuncId, ArgPlan>,
) -> Vec<FuncId> {
    let mut vetoed = Vec::new();
    for (&target, plan) in plans {
        let unrewritable = calls.sites_targeting(target).iter().any(|site| {
            let Some(caller) = ir.functions.get(site.caller.index() as usize) else {
                return true;
            };
            let Some(value) = caller.values.get(site.call) else {
                return true;
            };
            let LiftedValueDef::Operator { args, .. } = &value.def else {
                return true;
            };
            // The pointer argument must be there to replace.
            args.get(plan.param_index).is_none()
        });
        if unrewritable {
            vetoed.push(target);
        }
    }
    vetoed
}

// ---------------------------------------------------------------------
// Rewrite
// ---------------------------------------------------------------------

/// Replace the pointer argument of every promoted call with the loads the
/// callee used to perform. Returns how many loads were hoisted.
fn rewrite_call_sites(
    func: &mut LiftedFunction,
    plans: &HashMap<FuncId, ArgPlan>,
    calls: &CallIndex,
) -> i64 {
    // Collect first: the rewrite appends to `values`, which cannot happen
    // while iterating it.
    let sites: Vec<(sordec_common::BlockId, usize, ValueId, FuncId)> = func
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
            plans
                .contains_key(&target)
                .then_some((block_id, position, id, target))
        })
        .collect();

    let mut hoisted = 0i64;
    // Later positions first, so inserting instructions does not invalidate
    // the positions still to be processed.
    for (block_id, position, call, target) in sites.into_iter().rev() {
        let plan = &plans[&target];
        let Some(pointer) = drop_pointer_arg(func, call, plan.param_index) else {
            continue;
        };
        let mut loads = Vec::with_capacity(plan.fields.len());
        for field in &plan.fields {
            // The callee's own load operator, re-based onto the pointer the
            // caller holds: the whole displacement moves into the memarg,
            // so `p + delta` with memarg `m` becomes `p` with memarg
            // `delta + m` — the offset already accumulated in `field`.
            let mut op = field.load_op;
            op.update_memory_arg(|memarg| memarg.offset = field.offset);
            let load = func.values.push(LiftedValue {
                def: LiftedValueDef::Operator {
                    op: sordec_ir::WasmOp(op),
                    args: vec![pointer],
                },
                types: vec![field.ty],
            });
            loads.push(load);
        }
        // Parameters were appended in field order, so arguments are too.
        if let Some(LiftedValueDef::Operator { args, .. }) =
            func.values.get_mut(call).map(|v| &mut v.def)
        {
            args.extend(loads.iter().copied());
        }
        hoisted += loads.len() as i64;
        if let Some(block) = func.blocks.get_mut(block_id) {
            block.instructions.splice(position..position, loads);
        }
    }
    hoisted
}

/// Remove the pointer argument from a call, returning the value it held.
fn drop_pointer_arg(
    func: &mut LiftedFunction,
    call: ValueId,
    param_index: usize,
) -> Option<ValueId> {
    let LiftedValueDef::Operator { args, .. } = &mut func.values.get_mut(call)?.def else {
        return None;
    };
    (param_index < args.len()).then(|| args.remove(param_index))
}

/// Give the callee one parameter per field, bind its loads to them, and
/// drop the pointer.
///
/// New parameters are **appended** rather than spliced into the pointer's
/// position so that removing the pointer can go through
/// [`drop_params`] — the helper `PruneTrivialPhisPass` and
/// `PruneDeadParamsPass` already share, precisely because parameters and
/// edge arguments are matched positionally and a private second
/// implementation of that removal is how they drift apart.
fn promote_params(func: &mut LiftedFunction, plan: &ArgPlan) {
    let entry = func.entry;
    let base = func.blocks.get(entry).map_or(0, |b| b.params.len());

    for (offset, field) in plan.fields.iter().enumerate() {
        let param = func.values.push(LiftedValue {
            def: LiftedValueDef::BlockParam {
                block: entry,
                index: (base + offset) as u32,
            },
            types: vec![field.ty],
        });
        if let Some(block) = func.blocks.get_mut(entry) {
            block.params.push(param);
        }
        // Each load becomes an alias for the parameter that now carries the
        // value. The arena is push-only, so the retired load stays as a
        // tombstone `ResolveAliasesPass` rewires — the established shape.
        for &load in &field.loads {
            if let Some(value) = func.values.get_mut(load) {
                value.def = LiftedValueDef::Alias(param);
            }
        }
    }

    let retired: HashSet<ValueId> = plan
        .fields
        .iter()
        .flat_map(|f| f.loads.iter().copied())
        .collect();
    for (_, block) in func.blocks.iter_mut() {
        block.instructions.retain(|id| !retired.contains(id));
    }

    let mut mask = vec![true; base + plan.fields.len()];
    mask[plan.param_index] = false;
    drop_params(func, &HashMap::from([(entry, mask)]));
}

#[cfg(test)]
mod tests {
    use super::*;
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

    fn load(offset: u32, addr: ValueId) -> LiftedValueDef {
        op(
            waffle::Operator::I64Load {
                memory: memarg(offset),
            },
            vec![addr],
        )
    }

    fn store(offset: u32, addr: ValueId, value: ValueId) -> LiftedValueDef {
        op(
            waffle::Operator::I64Store {
                memory: memarg(offset),
            },
            vec![addr, value],
        )
    }

    fn param(index: u32) -> LiftedValueDef {
        LiftedValueDef::BlockParam {
            block: crate::test_util::bb(0),
            index,
        }
    }

    fn call(index: u32, args: Vec<ValueId>) -> LiftedValueDef {
        op(
            waffle::Operator::Call {
                function_index: waffle::Func::from(index),
            },
            args,
        )
    }

    /// `f(p, x)` reading two fields through `p`, in the entry block.
    fn read_only_callee() -> LiftedFunction {
        func_with(
            vec![
                param(0),        // v0 pointer
                param(1),        // v1 other argument
                load(0, v(0)),   // v2
                load(8, v(0)),   // v3
            ],
            vec![block(
                0,
                vec![v(0), v(1)],
                vec![v(2), v(3)],
                LiftedTerminator::Return {
                    values: vec![v(2)],
                },
            )],
        )
    }

    /// `caller(fp, y)` calling `func_0(fp, y)`.
    fn caller() -> LiftedFunction {
        let mut f = func_with(
            vec![
                param(0),                       // v0 frame pointer
                param(1),                       // v1 argument
                call(0, vec![v(0), v(1)]),      // v2
            ],
            vec![block(
                0,
                vec![v(0), v(1)],
                vec![v(2)],
                LiftedTerminator::Return { values: vec![] },
            )],
        );
        f.id = FuncId::new(1);
        f
    }

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

    #[test]
    fn a_read_only_pointer_parameter_is_promotable() {
        let plan = promotable(&read_only_callee()).expect("promotable");
        assert_eq!(plan.param_index, 0);
        assert_eq!(plan.fields.len(), 2);
        assert_eq!(plan.fields[0].offset, 0);
        assert_eq!(plan.fields[1].offset, 8);
    }

    #[test]
    fn a_written_pointer_is_srets_shape_not_this_one() {
        // Declining here is what keeps one function from being claimed by
        // both passes.
        let f = func_with(
            vec![param(0), param(1), load(0, v(0)), store(8, v(0), v(1))],
            vec![block(
                0,
                vec![v(0), v(1)],
                vec![v(2), v(3)],
                LiftedTerminator::Return { values: vec![] },
            )],
        );
        assert!(promotable(&f).is_none());
    }

    #[test]
    fn a_pointer_that_escapes_into_a_call_is_not_promotable() {
        let f = func_with(
            vec![param(0), load(0, v(0)), call(3, vec![v(0)])],
            vec![block(
                0,
                vec![v(0)],
                vec![v(1), v(2)],
                LiftedTerminator::Return { values: vec![] },
            )],
        );
        assert!(promotable(&f).is_none());
    }

    #[test]
    fn a_conditional_load_is_not_hoistable() {
        // The load runs on one path; the caller would run it on both, which
        // can fault where the original did not.
        let f = func_with(
            vec![
                param(0),      // v0 pointer
                param(1),      // v1 condition
                load(0, v(0)), // v2 — only in bb1
            ],
            vec![
                block(
                    0,
                    vec![v(0), v(1)],
                    vec![],
                    LiftedTerminator::BranchIf {
                        cond: v(1),
                        if_true: target(1, vec![]),
                        if_false: target(2, vec![]),
                    },
                ),
                block(1, vec![], vec![v(2)], LiftedTerminator::Branch(target(2, vec![]))),
                block(2, vec![], vec![], LiftedTerminator::Return { values: vec![] }),
            ],
        );
        assert!(promotable(&f).is_none());
    }

    #[test]
    fn two_widths_at_one_offset_decline() {
        // A narrower read of a wider one is a reinterpretation; no single
        // parameter stands for both.
        let f = func_with(
            vec![
                param(0),
                load(0, v(0)),
                op(
                    waffle::Operator::I32Load {
                        memory: waffle::MemoryArg {
                            align: 2,
                            offset: 0,
                            memory: mem(),
                        },
                    },
                    vec![v(0)],
                ),
            ],
            vec![block(
                0,
                vec![v(0)],
                vec![v(1), v(2)],
                LiftedTerminator::Return { values: vec![] },
            )],
        );
        assert!(promotable(&f).is_none());
    }

    #[test]
    fn overlapping_fields_decline() {
        // `p+0` as 8 bytes and `p+4` as 8 bytes share four of them.
        let f = func_with(
            vec![param(0), load(0, v(0)), load(4, v(0))],
            vec![block(
                0,
                vec![v(0)],
                vec![v(1), v(2)],
                LiftedTerminator::Return { values: vec![] },
            )],
        );
        assert!(promotable(&f).is_none());
    }

    #[test]
    fn two_promotable_parameters_decline() {
        let f = func_with(
            vec![param(0), param(1), load(0, v(0)), load(0, v(1))],
            vec![block(
                0,
                vec![v(0), v(1)],
                vec![v(2), v(3)],
                LiftedTerminator::Return { values: vec![] },
            )],
        );
        assert!(promotable(&f).is_none());
    }

    #[test]
    fn address_arithmetic_is_not_an_escape() {
        // `p + 8` is itself an address, not a leak of `p`.
        let f = func_with(
            vec![
                param(0),
                i32_const(8),
                op(waffle::Operator::I32Add, vec![v(0), v(1)]),
                load(0, v(2)),
            ],
            vec![block(
                0,
                vec![v(0)],
                vec![v(1), v(2), v(3)],
                LiftedTerminator::Return { values: vec![] },
            )],
        );
        let plan = promotable(&f).expect("promotable");
        assert_eq!(plan.fields.len(), 1);
        assert_eq!(plan.fields[0].offset, 8, "the add folds into the offset");
    }

    #[test]
    fn conversion_drops_the_pointer_and_binds_the_loads() {
        let mut func = read_only_callee();
        let plan = promotable(&func).expect("promotable");
        promote_params(&mut func, &plan);

        let params = &func.blocks.get(func.entry).unwrap().params;
        assert_eq!(params.len(), 3, "the other argument plus two fields");
        assert!(!params.contains(&v(0)), "the pointer is gone");
        // The loads are no longer scheduled, and each aliases a parameter.
        let scheduled = &func.blocks.get(func.entry).unwrap().instructions;
        assert!(scheduled.is_empty(), "both loads retired");
        for load in [v(2), v(3)] {
            let LiftedValueDef::Alias(to) = func.values.get(load).unwrap().def else {
                panic!("load should alias its parameter");
            };
            assert!(params.contains(&to));
        }
        // Survivors' parameter indices match their new positions.
        for (index, &p) in params.iter().enumerate() {
            let LiftedValueDef::BlockParam { index: got, .. } = func.values.get(p).unwrap().def
            else {
                panic!("not a parameter");
            };
            assert_eq!(got as usize, index);
        }
    }

    #[test]
    fn a_caller_loads_what_the_callee_no_longer_does() {
        let mut ir = module(vec![read_only_callee(), caller()]);
        assert!(ArgPromotionPass.run(&mut ir).changed);

        let caller = &ir.functions[1];
        let LiftedValueDef::Operator { args, .. } = &caller.values.get(v(2)).unwrap().def else {
            panic!("still a call");
        };
        // The pointer is replaced by the two values it used to carry.
        assert_eq!(args.len(), 3);
        assert_eq!(args[0], v(1), "the untouched argument keeps its place");
        // Both new arguments are loads of the caller's pointer, scheduled
        // before the call.
        let scheduled = &caller.blocks.get(caller.entry).unwrap().instructions;
        assert_eq!(scheduled.len(), 3, "two hoisted loads then the call");
        assert_eq!(scheduled[2], v(2), "the call still comes last");
        for &arg in &args[1..] {
            let LiftedValueDef::Operator { op, args: load_args } =
                &caller.values.get(arg).unwrap().def
            else {
                panic!("hoisted argument should be a load");
            };
            assert!(matches!(op.0, waffle::Operator::I64Load { .. }));
            assert_eq!(load_args, &vec![v(0)], "loaded from the caller's pointer");
        }
    }

    #[test]
    fn the_hoisted_load_keeps_the_callees_offset() {
        let mut ir = module(vec![read_only_callee(), caller()]);
        ArgPromotionPass.run(&mut ir);
        let caller = &ir.functions[1];
        let LiftedValueDef::Operator { args, .. } = &caller.values.get(v(2)).unwrap().def else {
            panic!("still a call");
        };
        let offsets: Vec<u32> = args[1..]
            .iter()
            .map(|&a| {
                let LiftedValueDef::Operator {
                    op: sordec_ir::WasmOp(waffle::Operator::I64Load { memory }),
                    ..
                } = caller.values.get(a).unwrap().def
                else {
                    panic!("not a load");
                };
                memory.offset
            })
            .collect();
        assert_eq!(offsets, vec![0, 8]);
    }

    #[test]
    fn an_exported_function_is_never_promoted() {
        let mut ir = module(vec![read_only_callee(), caller()]);
        ir.facts.exports.push(sordec_ir::Export {
            name: "f".to_string(),
            kind: sordec_ir::ExportKind::Func,
            index: 0,
        });
        assert!(!ArgPromotionPass.run(&mut ir).changed);
    }

    #[test]
    fn a_self_recursive_function_is_skipped() {
        let mut callee = read_only_callee();
        // Give it a call to itself, which would need the deleted pointer.
        let recursive = callee.values.push(LiftedValue {
            def: call(0, vec![v(0), v(1)]),
            types: vec![],
        });
        callee
            .blocks
            .get_mut(callee.entry)
            .unwrap()
            .instructions
            .push(recursive);
        let mut ir = module(vec![callee, caller()]);
        assert!(!ArgPromotionPass.run(&mut ir).changed);
    }

    #[test]
    fn an_indirect_call_anywhere_stops_the_pass() {
        let mut indirect = func_with(
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
        indirect.id = FuncId::new(2);
        let mut ir = module(vec![read_only_callee(), caller(), indirect]);
        assert!(!ArgPromotionPass.run(&mut ir).changed);
    }

    #[test]
    fn second_run_reports_no_work() {
        let mut ir = module(vec![read_only_callee(), caller()]);
        assert!(ArgPromotionPass.run(&mut ir).changed);
        assert!(
            !ArgPromotionPass.run(&mut ir).changed,
            "idempotent: the pointer parameter is gone"
        );
    }
}
