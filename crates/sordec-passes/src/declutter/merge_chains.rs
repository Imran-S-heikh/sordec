//! Straight-line block-chain merging.
//!
//! `A —Branch→ B` where `B` is not the entry, `B ≠ A`, the branch is
//! `B`'s **only** in-edge (counted with multiplicity — a `Switch`
//! hitting `B` twice is two edges), and `B` carries no parameters
//! (the trivial-phi pass guarantees single-edge blocks lose theirs
//! inside the declutter fixpoint group): splice `B`'s instructions
//! onto `A`, take `B`'s terminator, and clear `B` to an empty
//! `Unreachable` tombstone ([`sordec_common::Arena`] is push-only).
//!
//! The two blocks already executed back-to-back with nothing in
//! between, so no computation is reordered — no effect gating
//! (kickoff K4 table). Chains collapse in one invocation: after `B` is
//! spliced, `A`'s new terminator may immediately qualify for another
//! merge and is retried before moving on.

use std::collections::HashMap;

use sordec_common::{BlockId, IrId};
use sordec_ir::{LiftedFunction, LiftedIr, LiftedTerminator};

use crate::dataflow::for_each_target;
use crate::pass::{Pass, PassResult};

/// Unique pipeline name of this pass.
pub const PASS_NAME: &str = "merge-chains";

/// Block pairs spliced.
const M_CHAINS_MERGED: &str = "declutter_chains_merged";

/// The chain-merging pass. Stateless; see the module docs.
#[derive(Debug, Default, Clone, Copy)]
pub struct MergeBlockChainsPass;

impl Pass<LiftedIr> for MergeBlockChainsPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut LiftedIr) -> PassResult {
        let mut result = PassResult::default();
        let mut merged: u64 = 0;
        for func in &mut ir.functions {
            merged += merge_function(func);
        }
        if merged > 0 {
            result.metrics.increment(M_CHAINS_MERGED, merged as i64);
            result.changed = true;
        }
        result
    }
}

fn merge_function(func: &mut LiftedFunction) -> u64 {
    // In-edge counts with multiplicity, over ALL blocks (an edge from
    // an unreachable predecessor still blocks the merge — conservative
    // and cheap; the dead sweep removes those edges first inside the
    // fixpoint group).
    let mut in_count: HashMap<BlockId, u32> = HashMap::new();
    for (_id, block) in func.blocks.iter() {
        for_each_target(&block.terminator, |target| {
            *in_count.entry(target.block).or_insert(0) += 1;
        });
    }

    let mut merged: u64 = 0;
    for id in 0..func.blocks.len() as u32 {
        let a = BlockId::from_index(id);
        // Collapse the whole chain hanging off `a` before moving on.
        while let Some(block_a) = func.blocks.get(a) {
            let LiftedTerminator::Branch(target) = &block_a.terminator else {
                break;
            };
            let b = target.block;
            if b == a || b == func.entry || in_count.get(&b).copied().unwrap_or(0) != 1 {
                break;
            }
            let Some(block_b) = func.blocks.get(b) else {
                break;
            };
            if !block_b.params.is_empty() {
                // Single-edge params are trivial by construction; the
                // phi pass removes them on the next group iteration and
                // this merge fires then.
                break;
            }

            // Splice: read B, clear B, extend A.
            let spliced_instructions = block_b.instructions.clone();
            let spliced_terminator = block_b.terminator.clone();
            {
                let block_b = func.blocks.get_mut(b).expect("checked above");
                block_b.instructions.clear();
                block_b.terminator = LiftedTerminator::Unreachable;
            }
            let block_a = func.blocks.get_mut(a).expect("checked above");
            block_a.instructions.extend(spliced_instructions);
            block_a.terminator = spliced_terminator;

            // Edge bookkeeping: the A->B edge is gone; B's outgoing
            // edges now leave A instead — per-target counts unchanged.
            in_count.insert(b, 0);
            merged += 1;
        }
    }

    if merged > 0 {
        debug_assert!(
            crate::lift::validate_lifted_function(func).is_ok(),
            "merge-chains broke invariants in {:?}",
            func.id
        );
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{bb, block, func_with, i32_const, param, target, v};

    #[test]
    fn single_pred_chain_collapses_into_one_block() {
        // bb0 -> bb1 -> bb2, each single-pred: everything lands in bb0.
        let mut func = func_with(
            vec![i32_const(1), i32_const(2), i32_const(3)],
            vec![
                block(0, vec![], vec![v(0)], LiftedTerminator::Branch(target(1, vec![]))),
                block(1, vec![], vec![v(1)], LiftedTerminator::Branch(target(2, vec![]))),
                block(
                    2,
                    vec![],
                    vec![v(2)],
                    LiftedTerminator::Return { values: vec![v(2)] },
                ),
            ],
        );
        assert_eq!(merge_function(&mut func), 2);
        let merged = func.blocks.get(bb(0)).unwrap();
        assert_eq!(merged.instructions, vec![v(0), v(1), v(2)]);
        assert!(matches!(
            merged.terminator,
            LiftedTerminator::Return { .. }
        ));
        for tomb in [bb(1), bb(2)] {
            let b = func.blocks.get(tomb).unwrap();
            assert!(b.instructions.is_empty());
            assert!(matches!(b.terminator, LiftedTerminator::Unreachable));
        }
    }

    #[test]
    fn multi_pred_target_is_not_merged() {
        // bb1 and bb2 both branch to bb3: a genuine merge point.
        let mut func = func_with(
            vec![i32_const(1)],
            vec![
                block(
                    0,
                    vec![],
                    vec![v(0)],
                    LiftedTerminator::BranchIf {
                        cond: v(0),
                        if_true: target(1, vec![]),
                        if_false: target(2, vec![]),
                    },
                ),
                block(1, vec![], vec![], LiftedTerminator::Branch(target(3, vec![]))),
                block(2, vec![], vec![], LiftedTerminator::Branch(target(3, vec![]))),
                block(3, vec![], vec![], LiftedTerminator::Return { values: vec![] }),
            ],
        );
        assert_eq!(merge_function(&mut func), 0);
    }

    #[test]
    fn switch_double_edge_counts_as_two_preds() {
        // One predecessor block, but two switch slots into bb1: the
        // multiplicity rule must block the merge.
        let mut func = func_with(
            vec![i32_const(1)],
            vec![
                block(
                    0,
                    vec![],
                    vec![v(0)],
                    LiftedTerminator::Switch {
                        index: v(0),
                        targets: vec![target(1, vec![])],
                        default: target(1, vec![]),
                    },
                ),
                block(1, vec![], vec![], LiftedTerminator::Return { values: vec![] }),
            ],
        );
        assert_eq!(merge_function(&mut func), 0);
    }

    #[test]
    fn param_carrying_target_waits_for_the_phi_pass() {
        let mut func = func_with(
            vec![i32_const(1), param(1, 0)],
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
                    LiftedTerminator::Return { values: vec![v(1)] },
                ),
            ],
        );
        assert_eq!(merge_function(&mut func), 0);
    }

    #[test]
    fn entry_block_is_never_a_merge_target() {
        // bb1 branches back to bb0 (entry) as its only in-edge.
        let mut func = func_with(
            vec![i32_const(1)],
            vec![
                block(0, vec![], vec![v(0)], LiftedTerminator::Branch(target(1, vec![]))),
                block(1, vec![], vec![], LiftedTerminator::Branch(target(0, vec![]))),
            ],
        );
        // bb0 -> bb1 merges (bb1 single-pred, no params); the entry
        // itself must never be swallowed even though it also has a
        // single in-edge after the merge.
        assert_eq!(merge_function(&mut func), 1);
        let merged = func.blocks.get(bb(0)).unwrap();
        let LiftedTerminator::Branch(t) = &merged.terminator else {
            panic!("bb0 keeps bb1's branch-to-entry");
        };
        assert_eq!(t.block, bb(0), "self-loop to entry survives");
    }

    #[test]
    fn second_run_reports_no_work() {
        let mut func = func_with(
            vec![i32_const(1), i32_const(2)],
            vec![
                block(0, vec![], vec![v(0)], LiftedTerminator::Branch(target(1, vec![]))),
                block(
                    1,
                    vec![],
                    vec![v(1)],
                    LiftedTerminator::Return { values: vec![] },
                ),
            ],
        );
        assert_eq!(merge_function(&mut func), 1);
        assert_eq!(merge_function(&mut func), 0, "idempotent");
    }
}
