//! Dead block-parameter elimination: remove parameters nothing reads.
//!
//! [`super::PruneTrivialPhisPass`] removes a parameter whose in-edges all
//! carry the *same* value. That is the other classical phi cleanup: a
//! parameter whose incoming values genuinely differ, but which no
//! instruction, terminator or edge argument ever reads. Braun et al.
//! handle the first; this is plain dead-code elimination applied to the
//! parameter list.
//!
//! ## Why it earns its place
//!
//! Both cleanups were dispensable while `convert_to_max_ssa` was the only
//! thing creating parameters — it parks *live* values, so the leftovers
//! were overwhelmingly trivial rather than dead.
//! [`crate::SlotPromotionPass`] changes that. Its design is "insert
//! maximally, prune back": it gives **every reachable block** a parameter
//! for the promoted slot precisely so it never has to compute dominance
//! frontiers, and relies on the fixpoint group to remove the surplus. A
//! block that neither loads nor stores the slot, and merely sits on a path
//! between two that do, ends up with a parameter that has several distinct
//! incoming values and no readers. Trivial-phi pruning cannot touch it —
//! it is not trivial — so without this pass "prune back" only ever did
//! half its job.
//!
//! The surplus is not cosmetic. A dead parameter keeps every in-edge
//! carrying an argument for it, and a non-empty edge transfer is what
//! [`crate::refine::TrapInlinePass`] declines on, which in turn leaves a
//! guarded trap shared instead of inlined, which stops
//! [`crate::marshalling::guard`] recognising it. One unread parameter is
//! enough to keep an entire argument type-check in the output.
//!
//! ## Liveness
//!
//! A parameter is **live** when some use of it is either
//!
//! - a use that is not an edge argument — an operator operand, an alias
//!   target, a `PickOutput` source, a terminator condition, a switch
//!   index, a returned value; or
//! - an edge argument at position `i` into a block whose parameter `i` is
//!   itself live.
//!
//! Anything else is dead. The second rule is what makes this a fixpoint
//! rather than a single scan: a chain of parameters passing a value along
//! is live only if something at the end of the chain reads it, and a
//! *cycle* of them (a loop-carried slot nobody reads) is live only if
//! something outside the cycle does. Seeding with "not live" and adding
//! only on evidence gives the least fixpoint, so an unread cycle stays
//! dead — which is the case that matters, because a promoted slot crossing
//! a loop produces exactly that.
//!
//! ## Gates
//!
//! - **Entry-block parameters are never removed.** They are the function
//!   ABI, and feed `HighFunction::params` at lowering.
//! - **Unreachable blocks are left alone**, as in trivial-phi pruning: the
//!   dead sweep clears those blocks wholesale instead.
//! - **Only scheduled uses count.** De-cluttering leaves unscheduled
//!   residue — alias tombstones and dead phis — behind, and the arenas are
//!   push-only, so counting residue as a reader would make every parameter
//!   look live and this pass a no-op.
//!
//! ## Residue
//!
//! A removed parameter's [`LiftedValueDef::BlockParam`] def is left in the
//! arena, and its `index` is stale by construction. That is sound *because
//! of* the pass's own precondition — nothing reads the value — and it is
//! why the def is not rewritten to something else: unlike a pruned trivial
//! phi there is no replacement value to alias, and inventing one (a zero,
//! say) would put a fabricated constant in the arena to stand for a value
//! that is provably never observed.

use std::collections::{HashMap, HashSet};

use sordec_common::{BlockId, ValueId};
use sordec_ir::{LiftedFunction, LiftedIr, LiftedTerminator, LiftedValueDef};

use crate::dataflow::{CfgFacts, for_each_target};
use crate::pass::{Pass, PassResult};

/// Unique pipeline name of this pass.
pub const PASS_NAME: &str = "prune-dead-params";

/// Block parameters removed because nothing read them.
use crate::metrics_catalog::DECLUTTER_DEAD_PARAMS_PRUNED as M_DEAD_PARAMS_PRUNED;

/// The dead block-parameter pass. Stateless; see the module docs.
#[derive(Debug, Default, Clone, Copy)]
pub struct PruneDeadParamsPass;

impl Pass<LiftedIr> for PruneDeadParamsPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut LiftedIr) -> PassResult {
        let mut result = PassResult::default();
        let mut pruned: u64 = 0;
        for func in &mut ir.functions {
            pruned += prune_function(func);
        }
        if pruned > 0 {
            result
                .metrics
                .increment(M_DEAD_PARAMS_PRUNED, pruned as i64);
            result.changed = true;
        }
        result
    }
}

/// One parameter slot: which block, and which position in its list.
type Slot = (BlockId, usize);

/// Prune one function's dead parameters. Returns how many were removed.
fn prune_function(func: &mut LiftedFunction) -> u64 {
    let cfg = CfgFacts::build(func);

    // Every parameter that is a candidate, by value id and by slot. The
    // entry block's are excluded here rather than filtered later, so no
    // rule below can accidentally reach them.
    let mut slot_of: HashMap<ValueId, Slot> = HashMap::new();
    for (block_id, block) in func.blocks.iter() {
        if block_id == func.entry || !cfg.is_reachable(block_id) {
            continue;
        }
        for (position, &param) in block.params.iter().enumerate() {
            slot_of.insert(param, (block_id, position));
        }
    }
    if slot_of.is_empty() {
        return 0;
    }

    // Which values a *scheduled* instruction or terminator reads other
    // than through an edge argument, and — separately — the edge
    // arguments, keyed by the slot they flow into.
    let mut read_directly: HashSet<ValueId> = HashSet::new();
    // slot -> the values that edge arguments deliver into it.
    let mut feeds: HashMap<Slot, Vec<ValueId>> = HashMap::new();

    for (block_id, block) in func.blocks.iter() {
        if !cfg.is_reachable(block_id) {
            continue;
        }
        for &id in &block.instructions {
            let Some(value) = func.values.get(id) else {
                continue;
            };
            match &value.def {
                LiftedValueDef::Operator { args, .. } => read_directly.extend(args.iter().copied()),
                LiftedValueDef::Alias(from) | LiftedValueDef::PickOutput { from, .. } => {
                    read_directly.insert(*from);
                }
                LiftedValueDef::BlockParam { .. } => {}
            }
        }
        match &block.terminator {
            LiftedTerminator::BranchIf { cond, .. } => {
                read_directly.insert(*cond);
            }
            LiftedTerminator::Switch { index, .. } => {
                read_directly.insert(*index);
            }
            LiftedTerminator::Return { values } => read_directly.extend(values.iter().copied()),
            LiftedTerminator::Branch(_) | LiftedTerminator::Unreachable => {}
        }
        for_each_target(&block.terminator, |target| {
            for (position, &arg) in target.args.iter().enumerate() {
                // An argument into a slot we are not tracking (the entry
                // block, or an unreachable one) is an ordinary read: we
                // will never remove that parameter, so the value it
                // carries is genuinely needed.
                match slot_of.values().find(|s| **s == (target.block, position)) {
                    Some(_) => feeds.entry((target.block, position)).or_default().push(arg),
                    None => {
                        read_directly.insert(arg);
                    }
                }
            }
        });
    }

    // Least fixpoint: a slot is live once something reads its parameter
    // directly, or once it feeds a slot already known live.
    let mut live: HashSet<Slot> = slot_of
        .iter()
        .filter(|(param, _)| read_directly.contains(param))
        .map(|(_, slot)| *slot)
        .collect();
    loop {
        let mut grew = false;
        for (slot, args) in &feeds {
            if !live.contains(slot) {
                continue;
            }
            for arg in args {
                if let Some(source) = slot_of.get(arg)
                    && live.insert(*source)
                {
                    grew = true;
                }
            }
        }
        if !grew {
            break;
        }
    }

    let dead: HashSet<ValueId> = slot_of
        .iter()
        .filter(|(_, slot)| !live.contains(slot))
        .map(|(param, _)| *param)
        .collect();
    if dead.is_empty() {
        return 0;
    }

    let mut masks: HashMap<BlockId, Vec<bool>> = HashMap::new();
    for (block_id, block) in func.blocks.iter() {
        if block.params.iter().any(|p| dead.contains(p)) {
            masks.insert(
                block_id,
                block.params.iter().map(|p| !dead.contains(p)).collect(),
            );
        }
    }
    super::drop_params(func, &masks);

    debug_assert!(
        crate::lift::validate_lifted_function(func).is_ok(),
        "prune-dead-params broke invariants in {:?}",
        func.id
    );

    dead.len() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{block, func_with, i32_const, op, target, v};
    use sordec_ir::LiftedType;

    fn param(block: u32, index: u32) -> LiftedValueDef {
        LiftedValueDef::BlockParam {
            block: BlockId::new(block),
            index,
        }
    }

    fn ir(func: LiftedFunction) -> LiftedIr {
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
            functions: vec![func],
            memory: sordec_ir::MemoryImage::empty(),
        }
    }

    /// bb0 branches to bb1 passing two different values; bb1 reads only
    /// one of its parameters. The other is dead — and not trivial, so
    /// trivial-phi pruning leaves it.
    fn one_dead_one_live() -> LiftedFunction {
        let mut func = func_with(
            vec![
                i32_const(1),                             // v0
                i32_const(2),                             // v1
                param(1, 0),                              // v2 read
                param(1, 1),                              // v3 dead
                op(waffle::Operator::I32Eqz, vec![v(2)]), // v4 reads v2
            ],
            vec![
                block(
                    0,
                    vec![],
                    vec![v(0), v(1)],
                    LiftedTerminator::Branch(target(1, vec![v(0), v(1)])),
                ),
                block(
                    1,
                    vec![v(2), v(3)],
                    vec![v(4)],
                    LiftedTerminator::Return { values: vec![v(4)] },
                ),
            ],
        );
        func.values.get_mut(v(4)).unwrap().types = vec![LiftedType::I32];
        func
    }

    #[test]
    fn an_unread_parameter_is_removed_with_its_edge_argument() {
        let mut module = ir(one_dead_one_live());
        assert!(PruneDeadParamsPass.run(&mut module).changed);
        let func = &module.functions[0];

        let bb1 = func.blocks.get(BlockId::new(1)).unwrap();
        assert_eq!(bb1.params, vec![v(2)], "only the read parameter survives");
        // The edge argument at the dropped position went with it.
        let mut args = Vec::new();
        for_each_target(&func.blocks.get(BlockId::new(0)).unwrap().terminator, |t| {
            args = t.args.clone();
        });
        assert_eq!(args, vec![v(0)], "the argument feeding it is gone too");
        // The survivor was renumbered to its new position.
        assert_eq!(
            func.values.get(v(2)).unwrap().def,
            param(1, 0),
            "surviving parameter keeps index 0"
        );
    }

    #[test]
    fn a_live_parameter_is_kept() {
        let mut module = ir(one_dead_one_live());
        PruneDeadParamsPass.run(&mut module);
        assert!(
            module.functions[0]
                .blocks
                .get(BlockId::new(1))
                .unwrap()
                .params
                .contains(&v(2)),
            "a parameter an instruction reads must never be removed"
        );
    }

    #[test]
    fn entry_parameters_are_never_removed() {
        // The function ABI. Nothing in the body reads it, and it still
        // has to survive — it feeds `HighFunction::params` at lowering.
        let mut func = func_with(
            vec![
                param(0, 0),  // v0 entry param, unread
                i32_const(7), // v1
            ],
            vec![block(
                0,
                vec![v(0)],
                vec![v(1)],
                LiftedTerminator::Return { values: vec![v(1)] },
            )],
        );
        func.values.get_mut(v(1)).unwrap().types = vec![LiftedType::I32];
        let mut module = ir(func);
        assert!(!PruneDeadParamsPass.run(&mut module).changed);
        assert_eq!(
            module.functions[0]
                .blocks
                .get(BlockId::new(0))
                .unwrap()
                .params,
            vec![v(0)],
        );
    }

    #[test]
    fn a_chain_of_unread_parameters_all_goes() {
        // bb1's parameter feeds bb2's, and nothing reads either. The
        // least fixpoint has to declare both dead; a "live if anything
        // passes it along" rule would keep both forever.
        let mut func = func_with(
            vec![
                i32_const(1), // v0
                param(1, 0),  // v1
                param(2, 0),  // v2
                i32_const(9), // v3
            ],
            vec![
                block(
                    0,
                    vec![],
                    vec![v(0)],
                    LiftedTerminator::Branch(target(1, vec![v(0)])),
                ),
                block(
                    1,
                    vec![v(1)],
                    vec![],
                    LiftedTerminator::Branch(target(2, vec![v(1)])),
                ),
                block(
                    2,
                    vec![v(2)],
                    vec![v(3)],
                    LiftedTerminator::Return { values: vec![v(3)] },
                ),
            ],
        );
        func.values.get_mut(v(3)).unwrap().types = vec![LiftedType::I32];
        let mut module = ir(func);
        assert!(PruneDeadParamsPass.run(&mut module).changed);
        let func = &module.functions[0];
        assert!(func.blocks.get(BlockId::new(1)).unwrap().params.is_empty());
        assert!(func.blocks.get(BlockId::new(2)).unwrap().params.is_empty());
    }

    #[test]
    fn a_parameter_read_only_at_the_end_of_a_chain_keeps_the_whole_chain() {
        let mut func = func_with(
            vec![
                i32_const(1),                             // v0
                param(1, 0),                              // v1
                param(2, 0),                              // v2
                op(waffle::Operator::I32Eqz, vec![v(2)]), // v3 reads v2
            ],
            vec![
                block(
                    0,
                    vec![],
                    vec![v(0)],
                    LiftedTerminator::Branch(target(1, vec![v(0)])),
                ),
                block(
                    1,
                    vec![v(1)],
                    vec![],
                    LiftedTerminator::Branch(target(2, vec![v(1)])),
                ),
                block(
                    2,
                    vec![v(2)],
                    vec![v(3)],
                    LiftedTerminator::Return { values: vec![v(3)] },
                ),
            ],
        );
        func.values.get_mut(v(3)).unwrap().types = vec![LiftedType::I32];
        let mut module = ir(func);
        assert!(!PruneDeadParamsPass.run(&mut module).changed);
        let func = &module.functions[0];
        assert_eq!(func.blocks.get(BlockId::new(1)).unwrap().params, vec![v(1)]);
        assert_eq!(func.blocks.get(BlockId::new(2)).unwrap().params, vec![v(2)]);
    }

    #[test]
    fn second_run_reports_no_work() {
        let mut module = ir(one_dead_one_live());
        assert!(PruneDeadParamsPass.run(&mut module).changed);
        assert!(
            !PruneDeadParamsPass.run(&mut module).changed,
            "idempotent: every surviving parameter is read"
        );
    }
}
