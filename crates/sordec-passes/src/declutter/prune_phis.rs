//! Trivial-phi pruning: remove block parameters that only ever receive
//! one value.
//!
//! `convert_to_max_ssa(None)` parks every live value in a block param
//! at every block it crosses; 73% of all corpus block parameters are
//! trivial in the first order alone. This pass applies the trivial-phi
//! rule of Braun et al. ("Simple and Efficient Construction of Static
//! Single Assignment Form", CC 2013): a parameter whose incoming
//! arguments — across **every** in-edge, minus the parameter itself
//! (self-loop pass-through) — are a single value `v` is replaced by
//! `v`. Removing one trivial phi can make another trivial, so
//! candidates are unified into a parent map and re-resolved to a
//! fixpoint before one global rewrite sweep.
//!
//! Soundness: every in-edge passes `v`, so `v`'s definition dominates
//! every predecessor's terminator, hence dominates the block, hence
//! dominates every use of the parameter. Pure rewiring — no computation
//! moves (kickoff K4 table).
//!
//! ## Surgery invariants
//!
//! - **Entry-block parameters are never pruned**: they are the
//!   function ABI (and feed `HighFunction::params` at lowering).
//! - Dropping parameter `i` of block `B` drops argument `i` from every
//!   edge targeting `B` — including edges from *unreachable*
//!   predecessors, which contribute no triviality evidence (they never
//!   execute; their arguments may disagree) but must stay positionally
//!   consistent.
//! - Surviving parameters' [`LiftedValueDef::BlockParam`] `index`
//!   fields are renumbered.
//! - A pruned parameter's def becomes [`LiftedValueDef::Alias`]`(v)` —
//!   an honest use-free tombstone ([`sordec_common::Arena`] is
//!   push-only), self-describing in dumps and lowering to `Expr::Use`.
//! - Parameters of unreachable blocks are left alone entirely; the
//!   dead-sweep pass clears those blocks instead.

use std::collections::HashMap;

use sordec_common::{BlockId, ValueId};
use sordec_ir::{LiftedFunction, LiftedIr, LiftedValueDef};

use crate::dataflow::{for_each_target, CfgFacts};
use crate::declutter::{for_each_target_mut, rewrite_uses};
use crate::pass::{Pass, PassResult};

/// Unique pipeline name of this pass.
pub const PASS_NAME: &str = "prune-trivial-phis";

/// Block parameters removed.
const M_PHIS_PRUNED: &str = "declutter_phis_pruned";

/// Defensive bound on parent-map chains (reachable IR cannot cycle —
/// two params feeding only each other would both be undefined on first
/// entry, which SSA dominance forbids).
const MAX_CHAIN: u32 = 1024;

/// The trivial-phi pruning pass. Stateless; see the module docs.
#[derive(Debug, Default, Clone, Copy)]
pub struct PruneTrivialPhisPass;

impl Pass<LiftedIr> for PruneTrivialPhisPass {
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
            result.metrics.increment(M_PHIS_PRUNED, pruned as i64);
            result.changed = true;
        }
        result
    }
}

/// Prune one function's trivial phis. Returns how many parameters were
/// removed.
fn prune_function(func: &mut LiftedFunction) -> u64 {
    let cfg = CfgFacts::build(func);

    // Read-only phase: incoming argument vectors per reachable block,
    // one entry per in-EDGE (a Switch hitting the same target twice
    // contributes twice), collected from reachable predecessors only.
    let mut incoming: HashMap<BlockId, Vec<Vec<ValueId>>> = HashMap::new();
    for (block_id, block) in func.blocks.iter() {
        if !cfg.is_reachable(block_id) {
            continue;
        }
        for_each_target(&block.terminator, |target| {
            incoming
                .entry(target.block)
                .or_default()
                .push(target.args.clone());
        });
    }

    // Candidate phase: unify trivial params into `parent` until no new
    // ones appear. Args are compared through the parent map so a
    // cascade (p2 fed only by p1, p1 fed only by v) resolves in one
    // invocation.
    let mut parent: HashMap<ValueId, ValueId> = HashMap::new();
    loop {
        let mut grew = false;
        for (block_id, block) in func.blocks.iter() {
            if block_id == func.entry || !cfg.is_reachable(block_id) {
                continue;
            }
            let Some(edges) = incoming.get(&block_id) else {
                continue; // no reachable in-edges: dead-sweep's problem
            };
            for (position, &param) in block.params.iter().enumerate() {
                if parent.contains_key(&param) {
                    continue;
                }
                let mut unique: Option<ValueId> = None;
                let mut trivial = true;
                for args in edges {
                    // Malformed arity would already be a validator
                    // finding; skip the edge rather than panic.
                    let Some(&arg) = args.get(position) else {
                        trivial = false;
                        break;
                    };
                    let resolved = resolve(&parent, arg);
                    if resolved == param {
                        continue; // self-loop pass-through
                    }
                    match unique {
                        None => unique = Some(resolved),
                        Some(existing) if existing == resolved => {}
                        Some(_) => {
                            trivial = false;
                            break;
                        }
                    }
                }
                // `unique == None` with edges present means every edge
                // passes the param to itself — an undefined value that
                // valid reachable IR cannot contain. Leave it alone.
                if trivial && let Some(v) = unique {
                    parent.insert(param, v);
                    grew = true;
                }
            }
        }
        if !grew {
            break;
        }
    }

    if parent.is_empty() {
        return 0;
    }

    // Rewrite phase: every use of a pruned param goes to its resolved
    // replacement (including args at positions about to be dropped —
    // harmless, they are removed next).
    rewrite_uses(func, |v| resolve(&parent, v));

    // Surgery phase. Masks first (keep = true), then one sweep over ALL
    // terminators (unreachable predecessors included, for positional
    // consistency), then per-block param lists, tombstones, renumbering.
    let mut masks: HashMap<BlockId, Vec<bool>> = HashMap::new();
    for (block_id, block) in func.blocks.iter() {
        if block.params.iter().any(|p| parent.contains_key(p)) {
            masks.insert(
                block_id,
                block.params.iter().map(|p| !parent.contains_key(p)).collect(),
            );
        }
    }

    for (_id, block) in func.blocks.iter_mut() {
        for_each_target_mut(&mut block.terminator, |target| {
            if let Some(mask) = masks.get(&target.block) {
                let mut position = 0;
                target.args.retain(|_| {
                    let keep = mask.get(position).copied().unwrap_or(true);
                    position += 1;
                    keep
                });
            }
        });
    }

    for (&block_id, mask) in &masks {
        let block = func
            .blocks
            .get_mut(block_id)
            .expect("mask keys come from the block arena");
        let mut position = 0;
        block.params.retain(|_| {
            let keep = mask.get(position).copied().unwrap_or(true);
            position += 1;
            keep
        });
        // Renumber survivors' BlockParam defs to their new positions.
        for (index, &param) in block.params.clone().iter().enumerate() {
            if let Some(value) = func.values.get_mut(param) {
                value.def = LiftedValueDef::BlockParam {
                    block: block_id,
                    index: index as u32,
                };
            }
        }
    }

    // Tombstones: pruned params become use-free aliases of their
    // replacement.
    for &param in parent.keys() {
        let target = resolve(&parent, param);
        if let Some(value) = func.values.get_mut(param) {
            value.def = LiftedValueDef::Alias(target);
        }
    }

    debug_assert!(
        crate::lift::validate_lifted_function(func).is_ok(),
        "prune-trivial-phis broke invariants in {:?}",
        func.id
    );

    parent.len() as u64
}

/// Chase `v` through the parent map to its final replacement.
fn resolve(parent: &HashMap<ValueId, ValueId>, v: ValueId) -> ValueId {
    let mut current = v;
    let mut hops = 0;
    while let Some(&next) = parent.get(&current) {
        debug_assert!(hops < MAX_CHAIN, "parent chain cycle at {v:?}");
        if hops >= MAX_CHAIN {
            break;
        }
        current = next;
        hops += 1;
    }
    current
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{bb, block, func_with, i32_const, op, param, target, v};
    use sordec_ir::LiftedTerminator;

    /// Diamond where both edges into the merge pass the same value:
    /// v0 const; bb0 br_if(v0) -> bb1 / bb2; both branch to bb3(v0);
    /// bb3(p=v1) returns p.
    fn diamond_same_value() -> LiftedFunction {
        func_with(
            vec![i32_const(7), param(3, 0)],
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
                block(1, vec![], vec![], LiftedTerminator::Branch(target(3, vec![v(0)]))),
                block(2, vec![], vec![], LiftedTerminator::Branch(target(3, vec![v(0)]))),
                block(
                    3,
                    vec![v(1)],
                    vec![],
                    LiftedTerminator::Return { values: vec![v(1)] },
                ),
            ],
        )
    }

    #[test]
    fn single_source_param_is_pruned_rewired_and_tombstoned() {
        let mut func = diamond_same_value();
        assert_eq!(prune_function(&mut func), 1);

        let merge = func.blocks.get(bb(3)).unwrap();
        assert!(merge.params.is_empty(), "param removed");
        let LiftedTerminator::Return { values } = &merge.terminator else {
            panic!("bb3 stays a return");
        };
        assert_eq!(values, &[v(0)], "use rewired to source");
        for pred in [bb(1), bb(2)] {
            let LiftedTerminator::Branch(t) = &func.blocks.get(pred).unwrap().terminator else {
                panic!("preds stay branches");
            };
            assert!(t.args.is_empty(), "edge args dropped");
        }
        assert_eq!(
            func.values.get(v(1)).unwrap().def,
            LiftedValueDef::Alias(v(0)),
            "tombstone"
        );
    }

    #[test]
    fn genuine_merge_param_is_kept() {
        // Edges pass DIFFERENT values -> a real phi, untouched.
        let mut func = func_with(
            vec![i32_const(1), i32_const(2), param(3, 0)],
            vec![
                block(
                    0,
                    vec![],
                    vec![v(0), v(1)],
                    LiftedTerminator::BranchIf {
                        cond: v(0),
                        if_true: target(1, vec![]),
                        if_false: target(2, vec![]),
                    },
                ),
                block(1, vec![], vec![], LiftedTerminator::Branch(target(3, vec![v(0)]))),
                block(2, vec![], vec![], LiftedTerminator::Branch(target(3, vec![v(1)]))),
                block(
                    3,
                    vec![v(2)],
                    vec![],
                    LiftedTerminator::Return { values: vec![v(2)] },
                ),
            ],
        );
        assert_eq!(prune_function(&mut func), 0);
        assert_eq!(func.blocks.get(bb(3)).unwrap().params, vec![v(2)]);
    }

    #[test]
    fn middle_param_removal_renumbers_surviving_indices() {
        // bb1 has three params; the middle one is trivial (both edges
        // pass v0), the outer two are genuine merges.
        let mut func = func_with(
            vec![
                i32_const(1), // v0
                i32_const(2), // v1
                param(1, 0),  // v2 keep
                param(1, 1),  // v3 trivial
                param(1, 2),  // v4 keep
            ],
            vec![
                block(
                    0,
                    vec![],
                    vec![v(0), v(1)],
                    LiftedTerminator::BranchIf {
                        cond: v(0),
                        if_true: target(1, vec![v(0), v(0), v(1)]),
                        if_false: target(1, vec![v(1), v(0), v(0)]),
                    },
                ),
                block(
                    1,
                    vec![v(2), v(3), v(4)],
                    vec![],
                    LiftedTerminator::Return {
                        values: vec![v(2), v(3), v(4)],
                    },
                ),
            ],
        );
        assert_eq!(prune_function(&mut func), 1);

        let merged = func.blocks.get(bb(1)).unwrap();
        assert_eq!(merged.params, vec![v(2), v(4)]);
        assert_eq!(
            func.values.get(v(2)).unwrap().def,
            param(1, 0),
            "first survivor keeps index 0"
        );
        assert_eq!(
            func.values.get(v(4)).unwrap().def,
            param(1, 1),
            "second survivor renumbered 2 -> 1"
        );
        let LiftedTerminator::BranchIf { if_true, if_false, .. } =
            &func.blocks.get(bb(0)).unwrap().terminator
        else {
            panic!("bb0 stays a branch_if");
        };
        assert_eq!(if_true.args, vec![v(0), v(1)]);
        assert_eq!(if_false.args, vec![v(1), v(0)]);
        let LiftedTerminator::Return { values } = &merged.terminator else {
            panic!("bb1 stays a return");
        };
        assert_eq!(values, &[v(2), v(0), v(4)], "middle use rewired to v0");
    }

    #[test]
    fn entry_params_are_never_pruned() {
        // A back edge into the entry passing a constant would make the
        // entry param look trivial — the ABI rule must win.
        let mut func = func_with(
            vec![param(0, 0), i32_const(7)],
            vec![
                block(
                    0,
                    vec![v(0)],
                    vec![v(1)],
                    LiftedTerminator::Branch(target(1, vec![])),
                ),
                block(1, vec![], vec![], LiftedTerminator::Branch(target(0, vec![v(1)]))),
            ],
        );
        assert_eq!(prune_function(&mut func), 0);
        assert_eq!(func.blocks.get(bb(0)).unwrap().params, vec![v(0)]);
    }

    #[test]
    fn self_loop_pass_through_is_discarded_as_evidence() {
        // bb1(p): entry passes v0, the self-loop passes p itself.
        // Evidence minus self = {v0} -> pruned.
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
                    LiftedTerminator::BranchIf {
                        cond: v(1),
                        if_true: target(1, vec![v(1)]),
                        if_false: target(2, vec![]),
                    },
                ),
                block(2, vec![], vec![], LiftedTerminator::Return { values: vec![] }),
            ],
        );
        assert_eq!(prune_function(&mut func), 1);
        let looped = func.blocks.get(bb(1)).unwrap();
        assert!(looped.params.is_empty());
        let LiftedTerminator::BranchIf { cond, if_true, .. } = &looped.terminator else {
            panic!("bb1 stays a branch_if");
        };
        assert_eq!(*cond, v(0), "cond rewired to entry value");
        assert!(if_true.args.is_empty(), "self-edge arg dropped");
    }

    #[test]
    fn loop_carried_param_is_kept() {
        // bb1(p): entry passes v0, the self-loop passes v2 = p + 1.
        // Evidence = {v0, v2} -> genuine loop-carried phi, kept.
        let mut func = func_with(
            vec![
                i32_const(0),                              // v0
                param(1, 0),                               // v1
                op(waffle::Operator::I32Add, vec![v(1), v(0)]), // v2
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
                    vec![v(2)],
                    LiftedTerminator::BranchIf {
                        cond: v(2),
                        if_true: target(1, vec![v(2)]),
                        if_false: target(2, vec![]),
                    },
                ),
                block(2, vec![], vec![], LiftedTerminator::Return { values: vec![] }),
            ],
        );
        assert_eq!(prune_function(&mut func), 0);
        assert_eq!(func.blocks.get(bb(1)).unwrap().params, vec![v(1)]);
    }

    #[test]
    fn switch_double_edge_to_same_target_counts_both_args() {
        // A switch with two slots into bb1 passing different values: not
        // trivial even though there is only one predecessor block.
        let mut func = func_with(
            vec![i32_const(1), i32_const(2), param(1, 0)],
            vec![
                block(
                    0,
                    vec![],
                    vec![v(0), v(1)],
                    LiftedTerminator::Switch {
                        index: v(0),
                        targets: vec![target(1, vec![v(0)]), target(1, vec![v(1)])],
                        default: target(2, vec![]),
                    },
                ),
                block(
                    1,
                    vec![v(2)],
                    vec![],
                    LiftedTerminator::Return { values: vec![v(2)] },
                ),
                block(2, vec![], vec![], LiftedTerminator::Unreachable),
            ],
        );
        assert_eq!(prune_function(&mut func), 0, "conflicting switch args keep the phi");

        // Same shape but both slots pass v0: now trivial.
        let mut same = func_with(
            vec![i32_const(1), param(1, 0)],
            vec![
                block(
                    0,
                    vec![],
                    vec![v(0)],
                    LiftedTerminator::Switch {
                        index: v(0),
                        targets: vec![target(1, vec![v(0)]), target(1, vec![v(0)])],
                        default: target(2, vec![]),
                    },
                ),
                block(
                    1,
                    vec![v(1)],
                    vec![],
                    LiftedTerminator::Return { values: vec![v(1)] },
                ),
                block(2, vec![], vec![], LiftedTerminator::Unreachable),
            ],
        );
        assert_eq!(prune_function(&mut same), 1);
        let LiftedTerminator::Switch { targets, .. } =
            &same.blocks.get(bb(0)).unwrap().terminator
        else {
            panic!("bb0 stays a switch");
        };
        assert!(targets.iter().all(|t| t.args.is_empty()));
    }

    #[test]
    fn cascaded_pass_through_chain_resolves_in_one_run() {
        // v0 -> bb1(p1) -> bb2(p2), each edge forwarding the previous
        // param. Both prune to v0 in a single invocation.
        let mut func = func_with(
            vec![i32_const(7), param(1, 0), param(2, 0)],
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
                    vec![],
                    LiftedTerminator::Return { values: vec![v(2)] },
                ),
            ],
        );
        assert_eq!(prune_function(&mut func), 2);
        let LiftedTerminator::Return { values } = &func.blocks.get(bb(2)).unwrap().terminator
        else {
            panic!("bb2 stays a return");
        };
        assert_eq!(values, &[v(0)], "chain fully resolved to the source");
        assert_eq!(func.values.get(v(1)).unwrap().def, LiftedValueDef::Alias(v(0)));
        assert_eq!(func.values.get(v(2)).unwrap().def, LiftedValueDef::Alias(v(0)));
    }

    #[test]
    fn unreachable_block_params_are_left_alone_but_edges_stay_consistent() {
        // bb2 is unreachable and targets bb1 with a DISAGREEING arg; the
        // reachable evidence (v0) still prunes bb1's param, and bb2's
        // edge must lose its arg for positional consistency.
        let mut func = func_with(
            vec![i32_const(7), param(1, 0), i32_const(9), param(3, 0)],
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
                // Unreachable: not entry, no preds.
                block(
                    2,
                    vec![],
                    vec![v(2)],
                    LiftedTerminator::Branch(target(1, vec![v(2)])),
                ),
                // Unreachable with its own param: must not be pruned.
                block(
                    3,
                    vec![v(3)],
                    vec![],
                    LiftedTerminator::Return { values: vec![v(3)] },
                ),
            ],
        );
        assert_eq!(prune_function(&mut func), 1);
        assert!(func.blocks.get(bb(1)).unwrap().params.is_empty());
        let LiftedTerminator::Branch(t) = &func.blocks.get(bb(2)).unwrap().terminator else {
            panic!("bb2 stays a branch");
        };
        assert!(t.args.is_empty(), "unreachable pred edge masked too");
        assert_eq!(
            func.blocks.get(bb(3)).unwrap().params,
            vec![v(3)],
            "unreachable block's own params untouched"
        );
    }

    #[test]
    fn second_run_reports_unchanged() {
        let mut func = diamond_same_value();
        assert_eq!(prune_function(&mut func), 1);
        assert_eq!(prune_function(&mut func), 0, "idempotent");
    }
}
