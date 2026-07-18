//! Jump threading: eliminate empty forwarding blocks and inline
//! terminal exits into their unconditional predecessors.
//!
//! Three rewrites, all restricted to blocks with **zero instructions**
//! (so no computation ever moves — kickoff K4 table):
//!
//! 1. **Forward skip** — an edge `P →(args) B` where `B` only forwards
//!    (`Branch(C, argsC)`) is retargeted to `C`, with `B`'s parameters
//!    substituted by `args` inside `argsC`. Applies per-edge to
//!    `Branch`, `BranchIf`, and `Switch` predecessors alike, chasing
//!    chains of empty blocks with a visited-set and hop cap.
//! 2. **Return inlining** — `P —Branch(args)→ B` where `B` is
//!    `Return { values }` becomes `P.terminator = Return` with `B`'s
//!    parameters substituted. This undoes rustc/LLVM return
//!    tail-merging (waffle's synthetic per-function return funnel, 113
//!    blocks across the corpus), restoring the source's early-return
//!    shape that guard-clause recovery feeds on (kickoff R2/R3).
//!    Conditional predecessors keep their edge — a terminator leg
//!    cannot become a `Return` — so the funnel block survives exactly
//!    where the structurer needs it.
//! 3. **Trap inlining** — same as (2) for an empty `Unreachable`
//!    block. `br_if → unreachable` edges are deliberately untouched:
//!    that shape is the W6 trap-duplication refinement's input.
//!
//! Soundness of the substitutions: any non-parameter value read by
//! `B`'s terminator dominates `B`; because the threaded edge `P → B`
//! exists, every path into `P` extends to a path into `B` and must
//! therefore already contain the definition — so the value dominates
//! `P`'s terminator too, and referencing it there is well-formed SSA.

use std::collections::{HashMap, HashSet};

use sordec_common::{BlockId, ValueId};
use sordec_ir::{BlockTarget, LiftedFunction, LiftedIr, LiftedTerminator};

use crate::declutter::for_each_target_mut;
use crate::pass::{Pass, PassResult};

/// Unique pipeline name of this pass.
pub const PASS_NAME: &str = "thread-jumps";

/// Edges retargeted past empty forwarding blocks.
const M_JUMPS_THREADED: &str = "declutter_jumps_threaded";
/// Unconditional branches to empty return blocks turned into `Return`.
const M_RETURNS_INLINED: &str = "declutter_returns_inlined";
/// Unconditional branches to empty `Unreachable` blocks inlined.
const M_TRAPS_INLINED: &str = "declutter_traps_inlined";

/// Defensive bound on forwarding-chain length; real chains are a
/// couple of hops.
const MAX_HOPS: u32 = 64;

/// The jump-threading pass. Stateless; see the module docs.
#[derive(Debug, Default, Clone, Copy)]
pub struct ThreadTrivialJumpsPass;

impl Pass<LiftedIr> for ThreadTrivialJumpsPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut LiftedIr) -> PassResult {
        let mut result = PassResult::default();
        let mut jumps: u64 = 0;
        let mut returns: u64 = 0;
        let mut traps: u64 = 0;
        for func in &mut ir.functions {
            let stats = thread_function(func);
            jumps += stats.jumps;
            returns += stats.returns;
            traps += stats.traps;
        }
        if jumps > 0 {
            result.metrics.increment(M_JUMPS_THREADED, jumps as i64);
        }
        if returns > 0 {
            result.metrics.increment(M_RETURNS_INLINED, returns as i64);
        }
        if traps > 0 {
            result.metrics.increment(M_TRAPS_INLINED, traps as i64);
        }
        result.changed = jumps + returns + traps > 0;
        result
    }
}

/// Per-function threading counters.
#[derive(Default)]
struct ThreadStats {
    jumps: u64,
    returns: u64,
    traps: u64,
}

fn thread_function(func: &mut LiftedFunction) -> ThreadStats {
    let mut stats = ThreadStats::default();

    // Snapshot the forwarding structure read-only: for every empty
    // block, its params and terminator. The mutation loop below only
    // rewrites *edges into* these blocks, never the blocks themselves,
    // so the snapshot cannot go stale within one invocation.
    #[derive(Clone)]
    enum EmptyExit {
        Forward(BlockTarget),
        Return(Vec<ValueId>),
        Trap,
    }
    let mut empty: HashMap<BlockId, (Vec<ValueId>, EmptyExit)> = HashMap::new();
    for (block_id, block) in func.blocks.iter() {
        if !block.instructions.is_empty() {
            continue;
        }
        let exit = match &block.terminator {
            LiftedTerminator::Branch(target) => EmptyExit::Forward(target.clone()),
            LiftedTerminator::Return { values } => EmptyExit::Return(values.clone()),
            LiftedTerminator::Unreachable => EmptyExit::Trap,
            LiftedTerminator::BranchIf { .. } | LiftedTerminator::Switch { .. } => continue,
        };
        empty.insert(block_id, (block.params.clone(), exit));
    }
    if empty.is_empty() {
        return stats;
    }

    // Chase one edge through empty Forward blocks. Returns the final
    // (block, args) if it differs from the input edge.
    let chase = |start: &BlockTarget| -> Option<BlockTarget> {
        let mut current = start.clone();
        let mut visited: HashSet<BlockId> = HashSet::new();
        let mut hops = 0;
        while hops < MAX_HOPS && visited.insert(current.block) {
            let Some((params, EmptyExit::Forward(next))) = empty.get(&current.block) else {
                break;
            };
            if params.len() != current.args.len() {
                break; // malformed arity: the validator's finding, not ours
            }
            if next.block == current.block {
                break; // empty self-loop: a real infinite loop, keep it
            }
            let substitution: HashMap<ValueId, ValueId> =
                params.iter().copied().zip(current.args.iter().copied()).collect();
            current = BlockTarget {
                block: next.block,
                args: next
                    .args
                    .iter()
                    .map(|a| substitution.get(a).copied().unwrap_or(*a))
                    .collect(),
            };
            hops += 1;
        }
        (current.block != start.block || current.args != start.args).then_some(current)
    };

    // Empty blocks are rewritten like any other: the chase reads the
    // pre-mutation snapshot, so an already-rewritten forwarder never
    // changes another edge's threading result. Forwarders bypassed by
    // every inbound edge go unreachable; the dead sweep clears them.
    for (_id, block) in func.blocks.iter_mut() {
        // 1. Forward skip, per edge.
        for_each_target_mut(&mut block.terminator, |target| {
            if let Some(threaded) = chase(target) {
                *target = threaded;
                stats.jumps += 1;
            }
        });

        // 2 + 3. Terminal inlining, unconditional branches only.
        if let LiftedTerminator::Branch(target) = &block.terminator {
            match empty.get(&target.block) {
                Some((params, EmptyExit::Return(values))) => {
                    if params.len() != target.args.len() {
                        continue;
                    }
                    let substitution: HashMap<ValueId, ValueId> =
                        params.iter().copied().zip(target.args.iter().copied()).collect();
                    block.terminator = LiftedTerminator::Return {
                        values: values
                            .iter()
                            .map(|v| substitution.get(v).copied().unwrap_or(*v))
                            .collect(),
                    };
                    stats.returns += 1;
                }
                Some((_params, EmptyExit::Trap)) => {
                    block.terminator = LiftedTerminator::Unreachable;
                    stats.traps += 1;
                }
                _ => {}
            }
        }
    }

    debug_assert!(
        crate::lift::validate_lifted_function(func).is_ok(),
        "thread-jumps broke invariants in {:?}",
        func.id
    );

    stats
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{bb, block, func_with, i32_const, param, target, v};

    #[test]
    fn conditional_edge_threads_past_empty_forwarder_with_arg_mapping() {
        // bb0 br_if -> bb1(v0) / bb3; bb1(p) is empty and forwards to
        // bb2(p). The br_if edge must retarget straight to bb2(v0).
        let mut func = func_with(
            vec![i32_const(7), param(1, 0), param(2, 0)],
            vec![
                block(
                    0,
                    vec![],
                    vec![v(0)],
                    LiftedTerminator::BranchIf {
                        cond: v(0),
                        if_true: target(1, vec![v(0)]),
                        if_false: target(3, vec![]),
                    },
                ),
                block(1, vec![v(1)], vec![], LiftedTerminator::Branch(target(2, vec![v(1)]))),
                block(
                    2,
                    vec![v(2)],
                    vec![],
                    LiftedTerminator::Return { values: vec![v(2)] },
                ),
                block(3, vec![], vec![], LiftedTerminator::Unreachable),
            ],
        );
        let stats = thread_function(&mut func);
        assert_eq!(stats.jumps, 1);
        let LiftedTerminator::BranchIf { if_true, .. } =
            &func.blocks.get(bb(0)).unwrap().terminator
        else {
            panic!("bb0 stays a branch_if");
        };
        assert_eq!(if_true.block, bb(2));
        assert_eq!(if_true.args, vec![v(0)], "param substituted through the hop");
    }

    #[test]
    fn chain_of_empty_forwarders_threads_in_one_pass() {
        // bb0 -> bb1 -> bb2 -> bb3, with bb1/bb2 empty forwarders.
        let mut func = func_with(
            vec![i32_const(7)],
            vec![
                block(0, vec![], vec![v(0)], LiftedTerminator::Branch(target(1, vec![]))),
                block(1, vec![], vec![], LiftedTerminator::Branch(target(2, vec![]))),
                block(2, vec![], vec![], LiftedTerminator::Branch(target(3, vec![]))),
                block(
                    3,
                    vec![],
                    vec![],
                    LiftedTerminator::Switch {
                        index: v(0),
                        targets: vec![target(0, vec![])],
                        default: target(0, vec![]),
                    },
                ),
            ],
        );
        let stats = thread_function(&mut func);
        assert!(stats.jumps >= 1);
        let LiftedTerminator::Branch(t) = &func.blocks.get(bb(0)).unwrap().terminator else {
            panic!("bb0 stays a branch");
        };
        assert_eq!(t.block, bb(3), "threaded through both hops");
    }

    #[test]
    fn unconditional_branch_to_return_funnel_becomes_return() {
        // The waffle funnel shape: bb1(p): return p, fed by branches.
        let mut func = func_with(
            vec![i32_const(7), param(1, 0)],
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
        let stats = thread_function(&mut func);
        assert_eq!(stats.returns, 1);
        let LiftedTerminator::Return { values } = &func.blocks.get(bb(0)).unwrap().terminator
        else {
            panic!("bb0 becomes a return");
        };
        assert_eq!(values, &[v(0)], "funnel param substituted");
    }

    #[test]
    fn conditional_edges_to_return_funnel_keep_the_funnel() {
        // A br_if leg cannot become a Return; the funnel must survive.
        let mut func = func_with(
            vec![i32_const(7), param(2, 0)],
            vec![
                block(
                    0,
                    vec![],
                    vec![v(0)],
                    LiftedTerminator::BranchIf {
                        cond: v(0),
                        if_true: target(2, vec![v(0)]),
                        if_false: target(1, vec![]),
                    },
                ),
                block(1, vec![], vec![], LiftedTerminator::Unreachable),
                block(
                    2,
                    vec![v(1)],
                    vec![],
                    LiftedTerminator::Return { values: vec![v(1)] },
                ),
            ],
        );
        let stats = thread_function(&mut func);
        assert_eq!(stats.returns, 0);
        assert!(matches!(
            func.blocks.get(bb(0)).unwrap().terminator,
            LiftedTerminator::BranchIf { .. }
        ));
    }

    #[test]
    fn branch_to_empty_unreachable_inlines_the_trap() {
        let mut func = func_with(
            vec![i32_const(7)],
            vec![
                block(0, vec![], vec![v(0)], LiftedTerminator::Branch(target(1, vec![]))),
                block(1, vec![], vec![], LiftedTerminator::Unreachable),
            ],
        );
        let stats = thread_function(&mut func);
        assert_eq!(stats.traps, 1);
        assert!(matches!(
            func.blocks.get(bb(0)).unwrap().terminator,
            LiftedTerminator::Unreachable
        ));
    }

    #[test]
    fn br_if_to_unreachable_is_left_for_trap_duplication() {
        // The guard shape (kickoff D2 input): br_if -> unreachable must
        // survive threading untouched.
        let mut func = func_with(
            vec![i32_const(7)],
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
                block(1, vec![], vec![], LiftedTerminator::Unreachable),
                block(2, vec![], vec![], LiftedTerminator::Return { values: vec![] }),
            ],
        );
        let stats = thread_function(&mut func);
        assert_eq!(stats.traps, 0);
        let LiftedTerminator::BranchIf { if_true, .. } =
            &func.blocks.get(bb(0)).unwrap().terminator
        else {
            panic!("bb0 stays a branch_if");
        };
        assert_eq!(if_true.block, bb(1));
    }

    #[test]
    fn empty_block_with_instructions_is_not_threaded() {
        // bb1 computes something: not a forwarder.
        let mut func = func_with(
            vec![i32_const(7), i32_const(8)],
            vec![
                block(0, vec![], vec![v(0)], LiftedTerminator::Branch(target(1, vec![]))),
                block(1, vec![], vec![v(1)], LiftedTerminator::Branch(target(2, vec![]))),
                block(2, vec![], vec![], LiftedTerminator::Return { values: vec![] }),
            ],
        );
        let stats = thread_function(&mut func);
        assert_eq!(stats.jumps, 0);
        let LiftedTerminator::Branch(t) = &func.blocks.get(bb(0)).unwrap().terminator else {
            panic!("bb0 stays a branch");
        };
        assert_eq!(t.block, bb(1));
    }

    #[test]
    fn empty_block_cycle_terminates_and_keeps_the_loop() {
        // bb1 <-> bb2 empty cycle: a genuine (if degenerate) infinite
        // loop. Threading must terminate; the entry edge may land
        // anywhere inside the cycle but the loop itself must survive.
        let mut func = func_with(
            vec![i32_const(7)],
            vec![
                block(0, vec![], vec![v(0)], LiftedTerminator::Branch(target(1, vec![]))),
                block(1, vec![], vec![], LiftedTerminator::Branch(target(2, vec![]))),
                block(2, vec![], vec![], LiftedTerminator::Branch(target(1, vec![]))),
            ],
        );
        let _ = thread_function(&mut func);
        let LiftedTerminator::Branch(t) = &func.blocks.get(bb(0)).unwrap().terminator else {
            panic!("bb0 stays a branch");
        };
        assert!(t.block == bb(1) || t.block == bb(2));
        // The cycle edges themselves still form a loop.
        let LiftedTerminator::Branch(t1) = &func.blocks.get(bb(1)).unwrap().terminator else {
            panic!("bb1 stays a branch");
        };
        let LiftedTerminator::Branch(t2) = &func.blocks.get(bb(2)).unwrap().terminator else {
            panic!("bb2 stays a branch");
        };
        assert!(
            (t1.block == bb(2) && t2.block == bb(1))
                || (t1.block == bb(1) && t2.block == bb(2))
                || (t1.block == bb(2) && t2.block == bb(2))
                || (t1.block == bb(1) && t2.block == bb(1)),
            "cycle preserved in some rotation"
        );
    }

    #[test]
    fn second_run_reports_no_work() {
        let mut func = func_with(
            vec![i32_const(7), param(1, 0)],
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
        let first = thread_function(&mut func);
        assert_eq!(first.returns, 1);
        let second = thread_function(&mut func);
        assert_eq!(second.jumps + second.returns + second.traps, 0, "idempotent");
    }
}
