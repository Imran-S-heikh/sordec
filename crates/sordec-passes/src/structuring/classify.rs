//! Block-role classification: merge nodes and loop headers.
//!
//! Port of the classification prologue of waffle's `stackify.rs`
//! (`compute_merge_nodes_and_loop_headers`), with the two deliberate
//! differences recorded in the [module docs](super): irreducibility is
//! the caller's gate (`CfgFacts::irreducible_edges`), and `br_table`
//! targets are not forced into the merge set.

use std::collections::HashSet;

use sordec_common::BlockId;
use sordec_ir::LiftedFunction;

use crate::dataflow::{for_each_target, CfgFacts};

/// The two block roles the structuring walk branches on.
pub(super) struct Classification {
    /// Targets of two or more forward edges, counted with per-slot
    /// multiplicity (a `br_table` naming one block twice makes it a
    /// merge node — waffle parity via [`for_each_target`]). Each merge
    /// node becomes a labeled `Region::Scope` placed under its
    /// immediate dominator.
    pub(super) merge_nodes: HashSet<BlockId>,
    /// Back-edge targets. Each becomes a `Region::Loop`.
    pub(super) loop_headers: HashSet<BlockId>,
}

/// Classify every reachable block by walking all CFG edges in RPO.
pub(super) fn classify(func: &LiftedFunction, cfg: &CfgFacts) -> Classification {
    let mut merge_nodes = HashSet::new();
    let mut loop_headers = HashSet::new();
    let mut branched_once = HashSet::new();

    for &block in cfg.rpo() {
        let block_pos = cfg.rpo_pos(block).expect("RPO blocks have positions");
        let terminator = &func
            .blocks
            .get(block)
            .expect("CFG facts and function agree on block ids")
            .terminator;
        for_each_target(terminator, |target| {
            let succ_pos = cfg
                .rpo_pos(target.block)
                .expect("successor of a reachable block is reachable");
            if succ_pos <= block_pos {
                // Backward (or self) edge.
                loop_headers.insert(target.block);
            } else if !branched_once.insert(target.block) {
                // Second forward edge into the same block.
                merge_nodes.insert(target.block);
            }
        });
    }

    Classification {
        merge_nodes,
        loop_headers,
    }
}
