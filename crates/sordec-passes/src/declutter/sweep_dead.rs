//! Dead sweeping: clear unreachable blocks, unschedule dead pure
//! values.
//!
//! The only declutter pass that deletes code, so the only one that
//! needs a gate (kickoff K4):
//!
//! 1. **Dead blocks** — blocks unreachable from the entry (waffle
//!    housekeeping orphans, plus blocks orphaned by threading/merging)
//!    are cleared: params and instructions emptied, terminator set to
//!    `Unreachable`. Sound regardless of effects — the code can never
//!    execute. Clearing also removes the dead block's *edges*, which
//!    un-blocks phi pruning and chain merging on its former targets in
//!    the next fixpoint-group iteration.
//! 2. **Dead values** — mark-and-sweep over the reachable schedule.
//!    Roots: every value a reachable terminator reads, plus every
//!    scheduled instruction whose
//!    [`wasm_operator_effects`](crate::effects::wasm_operator_effects)
//!    is **not** pure-total (a zero-use load may trap out-of-bounds; a
//!    call, store, or global write is observable — they all stay).
//!    Marking follows operand edges transitively. Unmarked scheduled
//!    values are removed from their block's instruction list; the defs
//!    stay in the arena as unscheduled residue
//!    ([`sordec_common::Arena`] is push-only).
//!
//! `Call`/`CallIndirect` classify WORST at the operator level, so even
//! a call to one of the 17 PURE host functions is never swept —
//! deliberate conservatism; rustc does not emit unused host calls, and
//! resolving imports here would duplicate the recognizers' job.

use sordec_common::{BlockId, IrId, ValueId};
use sordec_ir::{LiftedFunction, LiftedIr, LiftedTerminator, LiftedValueDef};

use crate::dataflow::CfgFacts;
use crate::effects::wasm_operator_effects;
use crate::pass::{Pass, PassResult};

/// Unique pipeline name of this pass.
pub const PASS_NAME: &str = "sweep-dead";

/// Unreachable blocks cleared to empty `Unreachable` tombstones.
const M_DEAD_BLOCKS: &str = "declutter_dead_blocks_cleared";
/// Pure-total zero-use instructions removed from the schedule.
const M_DEAD_VALUES: &str = "declutter_dead_values_unscheduled";

/// The dead-sweep pass. Stateless; see the module docs.
#[derive(Debug, Default, Clone, Copy)]
pub struct SweepDeadPass;

impl Pass<LiftedIr> for SweepDeadPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut LiftedIr) -> PassResult {
        let mut result = PassResult::default();
        let mut blocks_cleared: u64 = 0;
        let mut values_unscheduled: u64 = 0;
        for func in &mut ir.functions {
            let (b, v) = sweep_function(func);
            blocks_cleared += b;
            values_unscheduled += v;
        }
        if blocks_cleared > 0 {
            result.metrics.increment(M_DEAD_BLOCKS, blocks_cleared as i64);
        }
        if values_unscheduled > 0 {
            result.metrics.increment(M_DEAD_VALUES, values_unscheduled as i64);
        }
        result.changed = blocks_cleared + values_unscheduled > 0;
        result
    }
}

/// Sweep one function. Returns `(blocks cleared, values unscheduled)`.
fn sweep_function(func: &mut LiftedFunction) -> (u64, u64) {
    let cfg = CfgFacts::build(func);

    // Phase 1: clear unreachable blocks. Only counts blocks that still
    // had content or an edge — an already-cleared tombstone is not
    // re-reported (keeps `changed` honest for the fixpoint loop).
    let mut blocks_cleared: u64 = 0;
    let dead: Vec<BlockId> = func
        .blocks
        .iter()
        .filter(|(id, _)| !cfg.is_reachable(*id))
        .map(|(id, _)| id)
        .collect();
    for id in dead {
        let block = func.blocks.get_mut(id).expect("id from the block arena");
        let already_tombstone = block.params.is_empty()
            && block.instructions.is_empty()
            && matches!(block.terminator, LiftedTerminator::Unreachable);
        if already_tombstone {
            continue;
        }
        block.params.clear();
        block.instructions.clear();
        block.terminator = LiftedTerminator::Unreachable;
        blocks_cleared += 1;
    }

    // Phase 2: mark-and-sweep the reachable schedule.
    //
    // Mark state per value; roots are terminator reads and scheduled
    // non-pure instructions, marking follows def-operand edges.
    let mut marked = vec![false; func.values.len()];
    let mut worklist: Vec<ValueId> = Vec::new();

    let push = |v: ValueId, marked: &mut Vec<bool>, worklist: &mut Vec<ValueId>| {
        if let Some(slot) = marked.get_mut(v.index() as usize)
            && !*slot
        {
            *slot = true;
            worklist.push(v);
        }
    };

    for (block_id, block) in func.blocks.iter() {
        if !cfg.is_reachable(block_id) {
            continue;
        }
        for &value in &block.instructions {
            if !is_pure_total(func, value) {
                push(value, &mut marked, &mut worklist);
            }
        }
        match &block.terminator {
            LiftedTerminator::BranchIf { cond, .. } => {
                push(*cond, &mut marked, &mut worklist);
            }
            LiftedTerminator::Switch { index, .. } => {
                push(*index, &mut marked, &mut worklist);
            }
            LiftedTerminator::Return { values } => {
                for &value in values {
                    push(value, &mut marked, &mut worklist);
                }
            }
            LiftedTerminator::Branch(_) | LiftedTerminator::Unreachable => {}
        }
        crate::dataflow::for_each_target(&block.terminator, |target| {
            for &arg in &target.args {
                push(arg, &mut marked, &mut worklist);
            }
        });
    }

    while let Some(value) = worklist.pop() {
        let Some(def) = func.values.get(value) else {
            continue;
        };
        match &def.def {
            LiftedValueDef::Operator { args, .. } => {
                for &arg in args {
                    push(arg, &mut marked, &mut worklist);
                }
            }
            LiftedValueDef::Alias(target) => push(*target, &mut marked, &mut worklist),
            LiftedValueDef::PickOutput { from, .. } => push(*from, &mut marked, &mut worklist),
            LiftedValueDef::BlockParam { .. } => {}
        }
    }

    // Sweep: every scheduled-but-unmarked value is pure-total (non-pure
    // ones were rooted) and reaches nothing observable.
    let mut values_unscheduled: u64 = 0;
    for (block_id, block) in func.blocks.iter_mut() {
        if !cfg.is_reachable(block_id) {
            continue;
        }
        let before = block.instructions.len();
        block
            .instructions
            .retain(|v| marked.get(v.index() as usize).copied().unwrap_or(true));
        values_unscheduled += (before - block.instructions.len()) as u64;
    }

    if blocks_cleared + values_unscheduled > 0 {
        debug_assert!(
            crate::lift::validate_lifted_function(func).is_ok(),
            "sweep-dead broke invariants in {:?}",
            func.id
        );
    }
    (blocks_cleared, values_unscheduled)
}

/// Effect gate for the value sweep: only pure-total operators may be
/// unscheduled. Non-`Operator` defs in a schedule (`PickOutput`) are
/// projections — pure by construction, their source op carries the
/// effects.
fn is_pure_total(func: &LiftedFunction, value: ValueId) -> bool {
    match func.values.get(value).map(|v| &v.def) {
        Some(LiftedValueDef::Operator { op, .. }) => wasm_operator_effects(&op.0).is_pure_total(),
        Some(LiftedValueDef::PickOutput { .. } | LiftedValueDef::Alias(_)) => true,
        // A scheduled BlockParam or a dangling id would be malformed
        // IR; keep it — the validator's finding, not ours.
        Some(LiftedValueDef::BlockParam { .. }) | None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{bb, block, func_with, i32_const, op, param, target, v};
    use waffle::entity::EntityRef as _;

    #[test]
    fn unreachable_block_is_cleared_to_a_tombstone() {
        let mut func = func_with(
            vec![i32_const(1), i32_const(2)],
            vec![
                block(0, vec![], vec![v(0)], LiftedTerminator::Return { values: vec![] }),
                // No preds: dead, with content and an edge back into bb0.
                block(1, vec![], vec![v(1)], LiftedTerminator::Branch(target(0, vec![]))),
            ],
        );
        let (blocks, _) = sweep_function(&mut func);
        assert_eq!(blocks, 1);
        let tomb = func.blocks.get(bb(1)).unwrap();
        assert!(tomb.instructions.is_empty());
        assert!(matches!(tomb.terminator, LiftedTerminator::Unreachable));
        // Second run: tombstone not re-reported.
        assert_eq!(sweep_function(&mut func), (0, 0), "idempotent");
    }

    #[test]
    fn dead_pure_chain_is_unscheduled_transitively() {
        // v0 is returned (live); v1 -> v2 is a pure chain nothing uses.
        let mut func = func_with(
            vec![
                i32_const(1),
                i32_const(2),
                op(waffle::Operator::I32Eqz, vec![v(1)]),
            ],
            vec![block(
                0,
                vec![],
                vec![v(0), v(1), v(2)],
                LiftedTerminator::Return { values: vec![v(0)] },
            )],
        );
        let (_, values) = sweep_function(&mut func);
        assert_eq!(values, 2, "v1 and v2 both swept");
        assert_eq!(func.blocks.get(bb(0)).unwrap().instructions, vec![v(0)]);
    }

    #[test]
    fn pure_value_feeding_a_live_one_is_kept() {
        // v1 is used only by v2, and v2 is returned: both live.
        let mut func = func_with(
            vec![
                i32_const(1),
                op(waffle::Operator::I32Eqz, vec![v(0)]),
            ],
            vec![block(
                0,
                vec![],
                vec![v(0), v(1)],
                LiftedTerminator::Return { values: vec![v(1)] },
            )],
        );
        assert_eq!(sweep_function(&mut func), (0, 0));
    }

    #[test]
    fn zero_use_load_and_call_are_never_swept() {
        // A load may trap OOB; a call is observable — both stay even
        // with zero uses (the K4 gate).
        let mut func = func_with(
            vec![
                i32_const(16),
                op(
                    waffle::Operator::I32Load {
                        memory: waffle::MemoryArg {
                            align: 2,
                            offset: 0,
                            memory: waffle::Memory::new(0),
                        },
                    },
                    vec![v(0)],
                ),
                op(
                    waffle::Operator::Call {
                        function_index: waffle::Func::new(0),
                    },
                    vec![],
                ),
            ],
            vec![block(
                0,
                vec![],
                vec![v(0), v(1), v(2)],
                LiftedTerminator::Return { values: vec![] },
            )],
        );
        let (_, values) = sweep_function(&mut func);
        assert_eq!(values, 0, "trapping/observable ops pinned");
        assert_eq!(
            func.blocks.get(bb(0)).unwrap().instructions,
            vec![v(0), v(1), v(2)],
            "v0 kept alive as the load's operand"
        );
    }

    #[test]
    fn terminator_reads_root_the_mark() {
        // v0 used only as a branch condition; v1 only as an edge arg.
        let mut func = func_with(
            vec![i32_const(1), i32_const(2), param(2, 0)],
            vec![
                block(
                    0,
                    vec![],
                    vec![v(0), v(1)],
                    LiftedTerminator::BranchIf {
                        cond: v(0),
                        if_true: target(2, vec![v(1)]),
                        if_false: target(1, vec![]),
                    },
                ),
                block(1, vec![], vec![], LiftedTerminator::Unreachable),
                block(2, vec![v(2)], vec![], LiftedTerminator::Return { values: vec![v(2)] }),
            ],
        );
        assert_eq!(sweep_function(&mut func), (0, 0), "cond and edge arg both live");
    }

    #[test]
    fn dead_blocks_do_not_keep_values_alive() {
        // v1 is "used" only by the dead bb1's instruction operand list;
        // after the block clear, v1's schedule entry in bb0 must sweep.
        let mut func = func_with(
            vec![
                i32_const(1),
                i32_const(2),
                op(waffle::Operator::I32Eqz, vec![v(1)]),
            ],
            vec![
                block(
                    0,
                    vec![],
                    vec![v(0), v(1)],
                    LiftedTerminator::Return { values: vec![v(0)] },
                ),
                block(1, vec![], vec![v(2)], LiftedTerminator::Unreachable),
            ],
        );
        let (blocks, values) = sweep_function(&mut func);
        assert_eq!(blocks, 1);
        assert_eq!(values, 1, "v1 swept once its only consumer is dead");
        assert_eq!(func.blocks.get(bb(0)).unwrap().instructions, vec![v(0)]);
    }
}
