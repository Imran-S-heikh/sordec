//! Control-flow structuring: a reducible `LiftedIr` CFG becomes a
//! [`Region`] tree.
//!
//! This is the Phase-3 structurer: a port of **Beyond Relooper**
//! (Norman Ramsey, *Beyond Relooper: recursive translation of
//! unstructured control flow to structured control flow*, ICFP 2022)
//! against [`LiftedFunction`] + [`CfgFacts`], emitting the Region v2
//! vocabulary. waffle 0.2.0's private `backend/stackify.rs` is the
//! reference implementation this port was verified against.
//!
//! ## How it works
//!
//! Two block roles are classified up front from the CFG: **loop
//! headers** (back-edge targets) and **merge nodes** (targets of two or
//! more forward edges, counted with per-slot multiplicity). The walk
//! then descends the dominator tree: a loop header wraps its subtree in
//! [`Region::Loop`]; each merge-node child of a block gets a labeled
//! [`Region::Scope`] placed under that block, ordered by reverse
//! postorder so branches always find their label in an enclosing
//! position; and every branch either **inlines** its target's dominator
//! subtree (when this is the target's only in-edge) or becomes a
//! [`Region::Break`] / [`Region::Continue`] to an enclosing label. No
//! code is duplicated and no synthetic variables are introduced — on
//! reducible input the translation always succeeds.
//!
//! ## Deviations from the reference
//!
//! 1. **`br_table` targets are not forced into the merge set.** waffle
//!    forces them because a WASM `br_table` can only branch to labels;
//!    [`Region::Switch`] carries region-valued arm bodies, so a
//!    single-in-edge case body inlines directly into its arm. Shared
//!    targets still classify as merge nodes through plain multiplicity
//!    counting, and case slots naming the same target with the same
//!    args group into one arm. (Approved W4 decision.)
//! 2. **Labels are `BlockId`-keyed, not de Bruijn depths.** waffle's
//!    `ctrl_stack` + `WasmLabel` machinery exists only to resolve block
//!    identities into scopes-outward counts at emission time; Region v2
//!    labels *are* the block identities (Region v2 design, DD1), so
//!    that machinery disappears. A branch is a `Continue` exactly when
//!    it is a back edge, a `Break` otherwise.
//! 3. **Direct recursion** instead of the reference's explicit
//!    work-stack state machine, guarded by the defensive [`MAX_DEPTH`]
//!    bound. (Approved W4 decision.)
//! 4. **`If` regions always carry both arms.** Dropping a redundant
//!    else arm (a bare fallthrough `Break`) is position-dependent and
//!    belongs to the refinement passes, not the structurer.
//!
//! ## Contract
//!
//! [`structure`] requires reducible input: the caller gates on
//! [`CfgFacts::irreducible_edges`] and falls back to
//! [`Region::Unstructured`] (with a `StructuringFallback` diagnostic)
//! instead of calling it. On reducible input structuring always
//! succeeds; [`StructureError`] is a defensive net for malformed IR,
//! and the corpus lock asserts it never fires on real contracts.

mod classify;
mod walk;

use sordec_common::BlockId;
use sordec_ir::{LiftedFunction, Region};

use crate::dataflow::CfgFacts;

/// Defensive bound on dominator-subtree recursion depth.
///
/// Each level costs a handful of native stack frames (a few KB in
/// debug builds); 400 keeps the guarded recursion comfortably inside
/// the 2 MiB default thread stack. Real input sits an order of
/// magnitude below it: depth tracks the dominator-chain length, the
/// declutter passes collapse straight-line chains, and the longest
/// corpus guard cascades stay well under 200 blocks. Exceeding the
/// bound returns [`StructureError::DepthLimit`] — which the lowering
/// boundary converts into an honest `Unstructured` fallback — instead
/// of risking a native stack overflow.
pub const MAX_DEPTH: u32 = 400;

/// Why structuring bailed on a function. Defensive only — see the
/// [module contract](self).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StructureError {
    /// An edge's argument count does not match its target's parameter
    /// count: malformed IR (the lifter and declutter passes maintain
    /// this invariant).
    #[error("edge into {block} carries {args} args for {params} block params")]
    PhiArityMismatch {
        /// Target block whose parameters mismatched.
        block: BlockId,
        /// Parameter count on the target block.
        params: usize,
        /// Argument count on the edge.
        args: usize,
    },
    /// Dominator-subtree recursion exceeded [`MAX_DEPTH`].
    #[error("region nesting exceeded {MAX_DEPTH} at {block}")]
    DepthLimit {
        /// Block at which the bound tripped.
        block: BlockId,
    },
}

/// Structure `func`'s CFG into a [`Region`] tree.
///
/// `cfg` must be [`CfgFacts::build`] of this same (post-cleanup)
/// function. See the [module docs](self) for the algorithm and the
/// reducibility contract.
pub fn structure(func: &LiftedFunction, cfg: &CfgFacts) -> Result<Region, StructureError> {
    let classification = classify::classify(func, cfg);
    walk::Walker::new(func, cfg, &classification).structure_root()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{bb, block, func_with, i32_const, op, param, target, v};
    use sordec_common::ValueId;
    use sordec_ir::{LiftedTerminator, LoopKind, SwitchArm};

    /// Build the CFG facts and structure, asserting success.
    fn structured(func: &LiftedFunction) -> Region {
        let cfg = CfgFacts::build(func);
        structure(func, &cfg).expect("reducible test CFG structures")
    }

    // Expected-tree shorthands: the asserts below compare whole trees
    // via `PartialEq`, and these keep them readable.
    fn basic(b: u32) -> Region {
        Region::Basic(bb(b))
    }
    fn seq(items: Vec<Region>) -> Region {
        Region::Sequence(items)
    }
    fn scope(out: u32, body: Region) -> Region {
        Region::Scope {
            out: bb(out),
            body: Box::new(body),
        }
    }
    fn if_else(cond: u32, then_region: Region, else_region: Region) -> Region {
        Region::If {
            cond: v(cond),
            then_region: Box::new(then_region),
            else_region: Some(Box::new(else_region)),
        }
    }
    fn looped(header: u32, body: Region) -> Region {
        Region::Loop {
            header: bb(header),
            body: Box::new(body),
            kind: LoopKind::Unclassified,
        }
    }
    fn brk(target: u32, transfer: Vec<(u32, u32)>) -> Region {
        Region::Break {
            target: bb(target),
            transfer: pairs(transfer),
        }
    }
    fn cont(target: u32, transfer: Vec<(u32, u32)>) -> Region {
        Region::Continue {
            target: bb(target),
            transfer: pairs(transfer),
        }
    }
    fn xfer(target: u32, transfer: Vec<(u32, u32)>) -> Region {
        Region::Transfer {
            target: bb(target),
            transfer: pairs(transfer),
        }
    }
    fn ret(values: Vec<u32>) -> Region {
        Region::Return {
            values: values.into_iter().map(v).collect(),
        }
    }
    fn pairs(raw: Vec<(u32, u32)>) -> Vec<(ValueId, ValueId)> {
        raw.into_iter().map(|(phi, src)| (v(phi), v(src))).collect()
    }

    #[test]
    fn straight_line_needs_no_scopes() {
        let func = func_with(
            vec![i32_const(1)],
            vec![block(
                0,
                vec![],
                vec![v(0)],
                LiftedTerminator::Return { values: vec![] },
            )],
        );
        assert_eq!(structured(&func), seq(vec![basic(0), ret(vec![])]));
    }

    #[test]
    fn diamond_scopes_the_merge_and_carries_phi_transfers() {
        // bb0 br_ifs to bb1/bb2; both branch to bb3 passing different
        // values; bb3(p = v2) returns p.
        let func = func_with(
            vec![i32_const(1), i32_const(2), param(3, 0)],
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
                block(2, vec![], vec![v(1)], LiftedTerminator::Branch(target(3, vec![v(1)]))),
                block(
                    3,
                    vec![v(2)],
                    vec![],
                    LiftedTerminator::Return { values: vec![v(2)] },
                ),
            ],
        );
        assert_eq!(
            structured(&func),
            seq(vec![
                scope(
                    3,
                    seq(vec![
                        basic(0),
                        if_else(
                            0,
                            seq(vec![basic(1), brk(3, vec![(2, 0)])]),
                            seq(vec![basic(2), brk(3, vec![(2, 1)])]),
                        ),
                    ]),
                ),
                basic(3),
                ret(vec![2]),
            ])
        );
    }

    #[test]
    fn shared_trap_block_appears_once_behind_breaks() {
        // Two br_if guards funnel into one unreachable block — the
        // corpus's shared-panic shape (token bb3, census R3). The trap
        // block must appear exactly once, as the scope's merge region.
        let func = func_with(
            vec![i32_const(1), i32_const(2)],
            vec![
                block(
                    0,
                    vec![],
                    vec![v(0)],
                    LiftedTerminator::BranchIf {
                        cond: v(0),
                        if_true: target(3, vec![]),
                        if_false: target(1, vec![]),
                    },
                ),
                block(
                    1,
                    vec![],
                    vec![v(1)],
                    LiftedTerminator::BranchIf {
                        cond: v(1),
                        if_true: target(3, vec![]),
                        if_false: target(2, vec![]),
                    },
                ),
                block(2, vec![], vec![], LiftedTerminator::Return { values: vec![] }),
                block(3, vec![], vec![], LiftedTerminator::Unreachable),
            ],
        );
        assert_eq!(
            structured(&func),
            seq(vec![
                scope(
                    3,
                    seq(vec![
                        basic(0),
                        if_else(
                            0,
                            brk(3, vec![]),
                            seq(vec![
                                basic(1),
                                if_else(1, brk(3, vec![]), seq(vec![basic(2), ret(vec![])])),
                            ]),
                        ),
                    ]),
                ),
                basic(3),
                Region::Unreachable,
            ])
        );
    }

    #[test]
    fn rotated_loop_gets_continue_back_edge_and_entry_transfer() {
        // bb0 enters bb1(v0); bb1(p) computes v2 and either re-enters
        // itself (passing v2) or exits — LLVM's rotated do-while.
        let func = func_with(
            vec![
                i32_const(1),
                param(1, 0),
                op(waffle::Operator::I32Eqz, vec![v(1)]),
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
        assert_eq!(
            structured(&func),
            seq(vec![
                basic(0),
                xfer(1, vec![(1, 0)]),
                looped(
                    1,
                    seq(vec![
                        basic(1),
                        if_else(2, cont(1, vec![(1, 2)]), seq(vec![basic(2), ret(vec![])])),
                    ]),
                ),
            ])
        );
    }

    #[test]
    fn guarded_do_while_keeps_guard_outside_the_loop() {
        // bb0 guards entry: either into the bottom-tested loop bb1 or
        // straight to the shared exit bb2.
        let func = func_with(
            vec![i32_const(1), i32_const(2)],
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
                block(
                    1,
                    vec![],
                    vec![v(1)],
                    LiftedTerminator::BranchIf {
                        cond: v(1),
                        if_true: target(1, vec![]),
                        if_false: target(2, vec![]),
                    },
                ),
                block(2, vec![], vec![], LiftedTerminator::Return { values: vec![] }),
            ],
        );
        assert_eq!(
            structured(&func),
            seq(vec![
                scope(
                    2,
                    seq(vec![
                        basic(0),
                        if_else(
                            0,
                            looped(
                                1,
                                seq(vec![
                                    basic(1),
                                    if_else(1, cont(1, vec![]), brk(2, vec![])),
                                ]),
                            ),
                            brk(2, vec![]),
                        ),
                    ]),
                ),
                basic(2),
                ret(vec![]),
            ])
        );
    }

    #[test]
    fn nested_loops_continue_across_the_inner_loop() {
        // Outer loop bb1, inner loop bb2; bb3 takes the outer back edge
        // from inside the inner loop's exit arm — a multi-level
        // `Continue` past the inner `Loop` frame.
        let func = func_with(
            vec![i32_const(1), i32_const(2)],
            vec![
                block(0, vec![], vec![v(0)], LiftedTerminator::Branch(target(1, vec![]))),
                block(
                    1,
                    vec![],
                    vec![],
                    LiftedTerminator::BranchIf {
                        cond: v(0),
                        if_true: target(2, vec![]),
                        if_false: target(4, vec![]),
                    },
                ),
                block(
                    2,
                    vec![],
                    vec![v(1)],
                    LiftedTerminator::BranchIf {
                        cond: v(1),
                        if_true: target(2, vec![]),
                        if_false: target(3, vec![]),
                    },
                ),
                block(3, vec![], vec![], LiftedTerminator::Branch(target(1, vec![]))),
                block(4, vec![], vec![], LiftedTerminator::Return { values: vec![] }),
            ],
        );
        assert_eq!(
            structured(&func),
            seq(vec![
                basic(0),
                looped(
                    1,
                    seq(vec![
                        basic(1),
                        if_else(
                            0,
                            looped(
                                2,
                                seq(vec![
                                    basic(2),
                                    if_else(
                                        1,
                                        cont(2, vec![]),
                                        seq(vec![basic(3), cont(1, vec![])]),
                                    ),
                                ]),
                            ),
                            seq(vec![basic(4), ret(vec![])]),
                        ),
                    ]),
                ),
            ])
        );
    }

    #[test]
    fn switch_inlines_single_use_arms_and_groups_shared_targets() {
        // Case 0 targets bb1 alone (arm body inlined — deviation 1);
        // cases 1 and 2 share bb2 (merge node, grouped `Break` arm);
        // the default's bb3 is single-use and inlines too.
        let func = func_with(
            vec![i32_const(1)],
            vec![
                block(
                    0,
                    vec![],
                    vec![v(0)],
                    LiftedTerminator::Switch {
                        index: v(0),
                        targets: vec![target(1, vec![]), target(2, vec![]), target(2, vec![])],
                        default: target(3, vec![]),
                    },
                ),
                block(1, vec![], vec![], LiftedTerminator::Return { values: vec![] }),
                block(2, vec![], vec![], LiftedTerminator::Return { values: vec![] }),
                block(3, vec![], vec![], LiftedTerminator::Unreachable),
            ],
        );
        assert_eq!(
            structured(&func),
            seq(vec![
                scope(
                    2,
                    seq(vec![
                        basic(0),
                        Region::Switch {
                            index: v(0),
                            arms: vec![
                                SwitchArm {
                                    cases: vec![0],
                                    body: seq(vec![basic(1), ret(vec![])]),
                                },
                                SwitchArm {
                                    cases: vec![1, 2],
                                    body: brk(2, vec![]),
                                },
                            ],
                            default: Box::new(seq(vec![basic(3), Region::Unreachable])),
                            dispatch: None,
                        },
                    ]),
                ),
                basic(2),
                ret(vec![]),
            ])
        );
    }

    #[test]
    fn breaks_cross_multiple_scope_levels() {
        // Two merges under bb0: bb3 (near) and bb4 (far). bb1 breaks to
        // both — the `Break { target: bb4 }` crosses the bb3 scope.
        let func = func_with(
            vec![i32_const(1), i32_const(2)],
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
                block(
                    1,
                    vec![],
                    vec![v(1)],
                    LiftedTerminator::BranchIf {
                        cond: v(1),
                        if_true: target(3, vec![]),
                        if_false: target(4, vec![]),
                    },
                ),
                block(2, vec![], vec![], LiftedTerminator::Branch(target(3, vec![]))),
                block(3, vec![], vec![], LiftedTerminator::Branch(target(4, vec![]))),
                block(4, vec![], vec![], LiftedTerminator::Return { values: vec![] }),
            ],
        );
        assert_eq!(
            structured(&func),
            seq(vec![
                scope(
                    4,
                    seq(vec![
                        scope(
                            3,
                            seq(vec![
                                basic(0),
                                if_else(
                                    0,
                                    seq(vec![
                                        basic(1),
                                        if_else(1, brk(3, vec![]), brk(4, vec![])),
                                    ]),
                                    seq(vec![basic(2), brk(3, vec![])]),
                                ),
                            ]),
                        ),
                        basic(3),
                        brk(4, vec![]),
                    ]),
                ),
                basic(4),
                ret(vec![]),
            ])
        );
    }

    #[test]
    fn entry_loop_header_wraps_the_whole_function() {
        // Back edge to the entry: the function params double as the
        // loop-carried phis and the root region is the Loop itself.
        let func = func_with(
            vec![param(0, 0), op(waffle::Operator::I32Eqz, vec![v(0)])],
            vec![
                block(
                    0,
                    vec![v(0)],
                    vec![v(1)],
                    LiftedTerminator::BranchIf {
                        cond: v(1),
                        if_true: target(0, vec![v(1)]),
                        if_false: target(1, vec![]),
                    },
                ),
                block(1, vec![], vec![], LiftedTerminator::Return { values: vec![] }),
            ],
        );
        assert_eq!(
            structured(&func),
            looped(
                0,
                seq(vec![
                    basic(0),
                    if_else(1, cont(0, vec![(0, 1)]), seq(vec![basic(1), ret(vec![])])),
                ]),
            )
        );
    }

    #[test]
    fn loop_header_that_is_also_a_merge_takes_breaks_and_continues() {
        // bb3 is entered forward by bb1 AND bb2 (merge role: the
        // forward branches become `Break { target: bb3 }` exiting its
        // scope) and re-entered by its own back edge (loop role:
        // `Continue { target: bb3 }`). Same block id, two label roles,
        // disambiguated purely by edge direction — deviation 2.
        let func = func_with(
            vec![i32_const(1), i32_const(2)],
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
                block(
                    3,
                    vec![],
                    vec![v(1)],
                    LiftedTerminator::BranchIf {
                        cond: v(1),
                        if_true: target(3, vec![]),
                        if_false: target(4, vec![]),
                    },
                ),
                block(4, vec![], vec![], LiftedTerminator::Return { values: vec![] }),
            ],
        );
        assert_eq!(
            structured(&func),
            seq(vec![
                scope(
                    3,
                    seq(vec![
                        basic(0),
                        if_else(
                            0,
                            seq(vec![basic(1), brk(3, vec![])]),
                            seq(vec![basic(2), brk(3, vec![])]),
                        ),
                    ]),
                ),
                looped(
                    3,
                    seq(vec![
                        basic(3),
                        if_else(1, cont(3, vec![]), seq(vec![basic(4), ret(vec![])])),
                    ]),
                ),
            ])
        );
    }

    #[test]
    fn branch_if_arms_to_one_target_keep_distinct_transfers() {
        // Both arms name bb1 but pass different values: two `Break`s
        // with distinct transfers, never merged.
        let func = func_with(
            vec![i32_const(1), i32_const(2), param(1, 0)],
            vec![
                block(
                    0,
                    vec![],
                    vec![v(0), v(1)],
                    LiftedTerminator::BranchIf {
                        cond: v(0),
                        if_true: target(1, vec![v(0)]),
                        if_false: target(1, vec![v(1)]),
                    },
                ),
                block(
                    1,
                    vec![v(2)],
                    vec![],
                    LiftedTerminator::Return { values: vec![v(2)] },
                ),
            ],
        );
        assert_eq!(
            structured(&func),
            seq(vec![
                scope(
                    1,
                    seq(vec![
                        basic(0),
                        if_else(0, brk(1, vec![(2, 0)]), brk(1, vec![(2, 1)])),
                    ]),
                ),
                basic(1),
                ret(vec![2]),
            ])
        );
    }

    #[test]
    fn phi_arity_mismatch_is_reported_not_panicked() {
        // Malformed by construction: the edge passes one arg into a
        // target with no params. The lifter/declutter maintain this
        // invariant; the structurer must fail closed.
        let func = func_with(
            vec![i32_const(1)],
            vec![
                block(
                    0,
                    vec![],
                    vec![v(0)],
                    LiftedTerminator::Branch(target(1, vec![v(0)])),
                ),
                block(1, vec![], vec![], LiftedTerminator::Return { values: vec![] }),
            ],
        );
        let cfg = CfgFacts::build(&func);
        assert_eq!(
            structure(&func, &cfg),
            Err(StructureError::PhiArityMismatch {
                block: bb(1),
                params: 0,
                args: 1,
            })
        );
    }

    #[test]
    fn depth_limit_fails_closed_on_pathological_nesting() {
        // A raw single-pred chain deeper than MAX_DEPTH — the declutter
        // chain merge collapses these on any real pipeline input. Run
        // on a thread with an oversized stack so the test exercises the
        // semantic bound, not the ambient thread's stack size.
        let handle = std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let len = MAX_DEPTH + 50;
                let mut blocks = Vec::new();
                for i in 0..len {
                    blocks.push(block(
                        i,
                        vec![],
                        vec![],
                        LiftedTerminator::Branch(target(i + 1, vec![])),
                    ));
                }
                blocks.push(block(
                    len,
                    vec![],
                    vec![],
                    LiftedTerminator::Return { values: vec![] },
                ));
                let func = func_with(vec![], blocks);
                let cfg = CfgFacts::build(&func);
                structure(&func, &cfg)
            })
            .expect("spawn depth-limit thread");
        assert!(matches!(
            handle.join().expect("structuring terminates"),
            Err(StructureError::DepthLimit { .. })
        ));
    }
}
