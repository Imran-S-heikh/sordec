//! The recursive dominator-tree walk that emits the region tree.
//!
//! Direct-recursive port of the walk half of waffle's `stackify.rs`
//! (`handle_dom_subtree` / `node_within` / `do_branch`), flattening the
//! reference's explicit work-stack state machine back into the
//! recursion the Beyond Relooper paper describes. See the
//! [module docs](super) for the correspondence and the deliberate
//! deviations.

use std::cmp::Reverse;

use sordec_common::{BlockId, ValueId};
use sordec_ir::{
    BlockTarget, LiftedBlock, LiftedFunction, LiftedTerminator, LoopKind, PhiTransfer, Region,
    SwitchArm,
};

use super::classify::Classification;
use super::{StructureError, MAX_DEPTH};
use crate::dataflow::CfgFacts;

/// One structuring walk over a single function.
pub(super) struct Walker<'a> {
    func: &'a LiftedFunction,
    cfg: &'a CfgFacts,
    cls: &'a Classification,
    /// Current dominator-subtree recursion depth (defensive bound).
    depth: u32,
    /// Stack of enclosing labeled constructs. Read only by debug
    /// assertions: every emitted `Break`/`Continue` must name an
    /// enclosing construct of the matching role. Labels are
    /// `BlockId`-keyed, so — unlike waffle's `ctrl_stack` — nothing is
    /// ever *resolved* against this stack.
    frames: Vec<Frame>,
}

/// A label role a `Break`/`Continue` can name.
#[derive(Debug, PartialEq, Eq)]
enum Frame {
    /// `Region::Scope { out }` — `Break` target.
    Scope(BlockId),
    /// `Region::Loop { header }` — `Continue` target.
    Loop(BlockId),
}

impl<'a> Walker<'a> {
    pub(super) fn new(
        func: &'a LiftedFunction,
        cfg: &'a CfgFacts,
        cls: &'a Classification,
    ) -> Self {
        Self {
            func,
            cfg,
            cls,
            depth: 0,
            frames: Vec::new(),
        }
    }

    /// Structure the whole function: the entry block's dominator
    /// subtree covers every reachable block exactly once.
    pub(super) fn structure_root(mut self) -> Result<Region, StructureError> {
        self.dom_subtree(self.cfg.entry())
    }

    /// Emit the region for `block` and everything it dominates
    /// (waffle `handle_dom_subtree`).
    fn dom_subtree(&mut self, block: BlockId) -> Result<Region, StructureError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(StructureError::DepthLimit { block });
        }
        let region = self.dom_subtree_at(block);
        self.depth -= 1;
        region
    }

    fn dom_subtree_at(&mut self, block: BlockId) -> Result<Region, StructureError> {
        // Dominator-tree children that are merge nodes get their
        // labeled scopes here, ordered so the highest-RPO merge becomes
        // the outermost scope — every forward branch out of this
        // subtree then has its label in scope.
        let mut merges: Vec<BlockId> = self
            .cfg
            .dom_children(block)
            .iter()
            .copied()
            .filter(|child| self.cls.merge_nodes.contains(child))
            .collect();
        merges.sort_unstable_by_key(|&b| Reverse(self.rpo_pos(b)));

        if self.cls.loop_headers.contains(&block) {
            self.frames.push(Frame::Loop(block));
            let body = self.node_within(block, &merges)?;
            let popped = self.frames.pop();
            debug_assert_eq!(popped, Some(Frame::Loop(block)));
            Ok(Region::Loop {
                header: block,
                body: Box::new(body),
                kind: LoopKind::Unclassified,
            })
        } else {
            self.node_within(block, &merges)
        }
    }

    /// Nest one labeled scope per pending merge child — innermost holds
    /// `block`'s own contents — with each merge child's region
    /// following its scope (waffle `node_within` + `finish_block`).
    fn node_within(
        &mut self,
        block: BlockId,
        merges: &[BlockId],
    ) -> Result<Region, StructureError> {
        match merges.split_first() {
            Some((&out, rest)) => {
                self.frames.push(Frame::Scope(out));
                let body = self.node_within(block, rest)?;
                let popped = self.frames.pop();
                debug_assert_eq!(popped, Some(Frame::Scope(out)));
                let follow = self.dom_subtree(out)?;
                Ok(seq(vec![
                    Region::Scope {
                        out,
                        body: Box::new(body),
                    },
                    follow,
                ]))
            }
            None => self.leaf(block),
        }
    }

    /// `block`'s own bindings followed by its translated terminator.
    fn leaf(&mut self, block: BlockId) -> Result<Region, StructureError> {
        let lifted = self.block(block);
        let mut items = vec![Region::Basic(block)];
        match &lifted.terminator {
            LiftedTerminator::Branch(target) => {
                items.push(self.do_branch(block, target)?);
            }
            LiftedTerminator::BranchIf {
                cond,
                if_true,
                if_false,
            } => {
                let then_region = self.do_branch(block, if_true)?;
                let else_region = self.do_branch(block, if_false)?;
                // Both arms stay faithful to the CFG. Pruning a
                // redundant else (a bare fallthrough `Break`) depends
                // on the region's position in its parent, so it
                // belongs to the refinement passes, not the structurer.
                items.push(Region::If {
                    cond: *cond,
                    then_region: Box::new(then_region),
                    else_region: Some(Box::new(else_region)),
                });
            }
            LiftedTerminator::Switch {
                index,
                targets,
                default,
            } => {
                items.push(self.do_switch(block, *index, targets, default)?);
            }
            LiftedTerminator::Return { values } => {
                items.push(Region::Return {
                    values: values.clone(),
                });
            }
            LiftedTerminator::Unreachable => items.push(Region::Unreachable),
        }
        Ok(seq(items))
    }

    /// Translate a `br_table` (waffle `do_branch_select`, minus the
    /// label ladder — module docs, deviation 1).
    fn do_switch(
        &mut self,
        block: BlockId,
        index: ValueId,
        targets: &'a [BlockTarget],
        default: &'a BlockTarget,
    ) -> Result<Region, StructureError> {
        // Group case slots sharing (target, args): one arm per distinct
        // destination-and-transfer, cases ascending by construction.
        // Slots naming the same block with different args stay separate
        // arms — their transfers differ.
        let mut groups: Vec<(&BlockTarget, Vec<u32>)> = Vec::new();
        for (slot, target) in targets.iter().enumerate() {
            let case = u32::try_from(slot).expect("br_table slot count fits u32");
            match groups
                .iter_mut()
                .find(|(t, _)| t.block == target.block && t.args == target.args)
            {
                Some((_, cases)) => cases.push(case),
                None => groups.push((target, vec![case])),
            }
        }

        let mut arms = Vec::with_capacity(groups.len());
        for (target, cases) in groups {
            let body = self.do_branch(block, target)?;
            arms.push(SwitchArm { cases, body });
        }
        let default = self.do_branch(block, default)?;
        Ok(Region::Switch {
            index,
            arms,
            default: Box::new(default),
            dispatch: None,
        })
    }

    /// Translate one CFG edge (waffle `do_branch`): a branch to a loop
    /// header (backward) or merge node becomes a labeled exit; any
    /// other target is dominated by `source` with this as its only
    /// in-edge, so its whole dominator subtree is inlined in place.
    fn do_branch(
        &mut self,
        source: BlockId,
        target: &BlockTarget,
    ) -> Result<Region, StructureError> {
        let dest = target.block;
        let transfer = self.transfer_into(dest, &target.args)?;
        if self.rpo_pos(dest) <= self.rpo_pos(source) {
            // Back edge. Reducible input guarantees `dest` is a loop
            // header whose body we are inside.
            debug_assert!(
                self.frames.contains(&Frame::Loop(dest)),
                "back edge {source} -> {dest} without an enclosing loop frame"
            );
            Ok(Region::Continue {
                target: dest,
                transfer,
            })
        } else if self.cls.merge_nodes.contains(&dest) {
            debug_assert!(
                self.frames.contains(&Frame::Scope(dest)),
                "forward branch {source} -> {dest} without an enclosing scope frame"
            );
            Ok(Region::Break {
                target: dest,
                transfer,
            })
        } else {
            debug_assert!(
                self.cfg.dominates(source, dest),
                "inline target {dest} not dominated by {source}"
            );
            let inlined = self.dom_subtree(dest)?;
            if transfer.is_empty() {
                Ok(inlined)
            } else {
                Ok(seq(vec![
                    Region::Transfer {
                        target: dest,
                        transfer,
                    },
                    inlined,
                ]))
            }
        }
    }

    /// Positional phi assignments for an edge into `dest` (waffle's
    /// `BlockParams` transfer nodes): `dest`'s params zipped against
    /// the edge args. Param ids survive the `LiftedIr → HighIr`
    /// lowering unchanged, so the left side of each pair is the
    /// `Expr::Phi` binding the high IR sees.
    fn transfer_into(
        &self,
        dest: BlockId,
        args: &[ValueId],
    ) -> Result<PhiTransfer, StructureError> {
        let params = &self.block(dest).params;
        if params.len() != args.len() {
            return Err(StructureError::PhiArityMismatch {
                block: dest,
                params: params.len(),
                args: args.len(),
            });
        }
        Ok(params.iter().copied().zip(args.iter().copied()).collect())
    }

    fn rpo_pos(&self, block: BlockId) -> u32 {
        self.cfg
            .rpo_pos(block)
            .expect("structuring only visits reachable blocks")
    }

    fn block(&self, id: BlockId) -> &'a LiftedBlock {
        self.func
            .blocks
            .get(id)
            .expect("region walk visits only existing blocks")
    }
}

/// Sequence constructor that flattens directly-nested sequences and
/// unwraps singletons, keeping the tree canonical: no `Sequence` as an
/// immediate child of a `Sequence`, no one-element `Sequence`s.
///
/// `pub(crate)`: the region-refinement passes splice subtrees and reuse
/// this to keep rebuilding against the same canonical form.
pub(crate) fn seq(items: Vec<Region>) -> Region {
    let mut flat = Vec::with_capacity(items.len());
    for item in items {
        match item {
            Region::Sequence(inner) => flat.extend(inner),
            other => flat.push(other),
        }
    }
    if flat.len() == 1 {
        flat.pop().expect("length checked")
    } else {
        Region::Sequence(flat)
    }
}
