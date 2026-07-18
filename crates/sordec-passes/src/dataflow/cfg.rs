//! Control-flow-graph facts: adjacency, dominance, loops, reducibility.
//!
//! The lifted IR stores control flow only as per-block terminators
//! ([`LiftedTerminator`]); nothing in the workspace answers "who jumps
//! here?", "does A dominate B?", or "which blocks form this loop?".
//! [`CfgFacts`] computes those answers for one function in a single
//! pass; [`LoopForest`] derives the natural-loop nesting from them.
//!
//! ## Who needs this
//!
//! - **Control-flow structuring**: the Beyond-Relooper structurer
//!   recurses over the dominator tree, distinguishes loop headers from
//!   forward-merge points, and orders children by reverse postorder.
//! - **Pre-structuring cleanup passes**: block-param pruning and chain
//!   merging need predecessor counts and reachability.
//! - **Loop-shaped refinement**: `while`/do-while classification and
//!   vec-iteration recovery consume the loop forest.
//!
//! ## The snapshot rule
//!
//! **Both types are point-in-time snapshots of the function.** If a
//! pass mutates the CFG (merges blocks, rewrites terminators) after
//! building, queries return pre-mutation answers. Rebuild after every
//! mutation round — and rebuild **both**: a [`LoopForest`] paired with
//! facts from a different function state answers for a CFG that no
//! longer exists.
//!
//! ## Adjacency conventions
//!
//! [`CfgFacts::succs`] / [`CfgFacts::preds`] are **deduplicated** edge
//! lists: a `BranchIf` whose arms both target `B` contributes one entry.
//! Dominance, reachability, and loop membership are set-shaped questions
//! and never observe multiplicity. Consumers that DO care — waffle's
//! merge-node criterion counts one edge per raw terminator target, so a
//! both-arms `BranchIf` **does** make its target a merge node — must
//! enumerate raw targets via [`for_each_target`] instead.
//!
//! [`for_each_target`] fixes the successor enumeration order
//! (`Switch` visits `default` first, matching waffle's
//! `Terminator::visit_targets`), and [`CfgFacts::rpo`] is defined by a
//! depth-first traversal in exactly that order. The differential oracle
//! test compares our RPO elementwise against waffle's, so this order is
//! load-bearing — do not reorder.
//!
//! ## Unreachable blocks
//!
//! Adjacency is *structural* (covers every block, including edges whose
//! source is unreachable from entry); order and dominance are
//! *reachable-only*:
//!
//! | query | unreachable block answers |
//! |---|---|
//! | `succs` / `preds` | real structural edges |
//! | `rpo` | absent |
//! | `rpo_pos` / `idom` | `None` |
//! | `is_reachable` / `dominates` (either side, incl. `a == b`) | `false` |
//! | `dom_children` / `back_edges` / loop membership | empty / absent |
//!
//! `dominates(b, b) == false` for unreachable `b` deliberately diverges
//! from waffle (whose `domtree::dominates` is reflexive even there):
//! "unreachable code dominates itself" is never an answer a consumer
//! can act on, and a uniform "everything about unreachable blocks is
//! negative" rule is harder to misuse.
//!
//! ## Reducibility
//!
//! With respect to the fixed DFS above, an edge `from → to` between
//! reachable blocks is **retreating** when `rpo_pos(to) <=
//! rpo_pos(from)` (self-loops included). A retreating edge whose target
//! dominates its source is a **back edge** — the natural-loop kind. A
//! retreating edge whose target does NOT dominate its source is an
//! **irreducibility witness**: the CFG has a multi-entry cycle.
//!
//! WASM's structured control flow can only express reducible CFGs, so
//! on lifter output [`CfgFacts::irreducible_edges`] must be empty — a
//! non-empty answer on corpus input indicates a lifter bug, not an
//! input property. The check defends against future non-WASM-shaped
//! frontends. Witness *identity* depends on the DFS order (only
//! emptiness is DFS-invariant); this module reports, never diagnoses —
//! per the dataflow convention, turning a witness into a
//! [`sordec_common::Diagnostic`] is the consumer's decision.
//!
//! On irreducible input the [`LoopForest`] describes the *reducible
//! skeleton* only (loops are induced by back edges alone, which keeps
//! every forest invariant intact); gate on [`CfgFacts::is_reducible`]
//! before trusting it as a complete loop account.

use std::collections::BTreeMap;

use sordec_common::{BlockId, IrId};
use sordec_ir::{BlockTarget, LiftedFunction, LiftedTerminator};

/// Enumerate a terminator's raw branch targets, in waffle's
/// `Terminator::visit_targets` order and **with multiplicity**:
///
/// - `Branch` → `[target]`
/// - `BranchIf` → `[if_true, if_false]`
/// - `Switch` → `[default, targets…]` (default FIRST — waffle parity;
///   [`CfgFacts::rpo`] depends on this order)
/// - `Return` / `Unreachable` → nothing
///
/// This is the multiplicity-preserving primitive that merge-node
/// detection requires (see the module docs); [`CfgFacts::succs`] is the
/// deduplicated view. Lives here rather than on [`LiftedTerminator`]
/// until a third consumer justifies the sordec-ir move.
pub fn for_each_target<F: FnMut(&BlockTarget)>(term: &LiftedTerminator, mut f: F) {
    match term {
        LiftedTerminator::Branch(target) => f(target),
        LiftedTerminator::BranchIf {
            if_true, if_false, ..
        } => {
            f(if_true);
            f(if_false);
        }
        LiftedTerminator::Switch {
            targets, default, ..
        } => {
            f(default);
            for target in targets {
                f(target);
            }
        }
        LiftedTerminator::Return { .. } | LiftedTerminator::Unreachable => {}
    }
}

/// One directed CFG edge.
///
/// Used for both back edges (`from` = latch, `to` = loop header) and
/// irreducibility witnesses (`to` fails to dominate `from`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CfgEdge {
    /// Source block of the edge.
    pub from: BlockId,
    /// Target block of the edge.
    pub to: BlockId,
}

/// Point-in-time CFG facts for one [`LiftedFunction`]: deduplicated
/// adjacency, reverse postorder, immediate dominators
/// (Cooper–Harvey–Kennedy), back edges, and irreducibility witnesses.
///
/// Build once with [`CfgFacts::build`], query read-only, **rebuild
/// after any CFG mutation** (see the module docs' snapshot rule).
#[derive(Debug, Clone)]
pub struct CfgFacts {
    /// Entry block id as captured at build time.
    entry: BlockId,
    /// `succs[i]` = deduplicated successors of `BlockId(i)`,
    /// first-occurrence order under [`for_each_target`].
    succs: Vec<Vec<BlockId>>,
    /// `preds[i]` = deduplicated predecessors of `BlockId(i)`,
    /// ascending block index; structural (includes unreachable sources).
    preds: Vec<Vec<BlockId>>,
    /// Reverse postorder over reachable blocks; `rpo[0]` is the entry.
    rpo: Vec<BlockId>,
    /// `rpo_pos[i]` = position of `BlockId(i)` in `rpo`, `None` when
    /// unreachable.
    rpo_pos: Vec<Option<u32>>,
    /// `idom[i]` = immediate dominator of `BlockId(i)`; `None` for the
    /// entry and for unreachable blocks.
    idom: Vec<Option<BlockId>>,
    /// `dom_children[i]` = dominator-tree children of `BlockId(i)`,
    /// ascending block index.
    dom_children: Vec<Vec<BlockId>>,
    /// Dominator-tree DFS entry counter (1-based; 0 = unreachable).
    dom_pre: Vec<u32>,
    /// Dominator-tree DFS exit counter (1-based; 0 = unreachable).
    dom_post: Vec<u32>,
    /// Retreating edges whose target dominates their source.
    back_edges: Vec<CfgEdge>,
    /// Retreating edges whose target does NOT dominate their source.
    irreducible_edges: Vec<CfgEdge>,
}

impl CfgFacts {
    /// Build the facts for one function.
    ///
    /// Cost: O(blocks + edges) for adjacency/RPO plus the CHK fixpoint
    /// (a handful of passes on real WASM CFGs).
    ///
    /// Defensive behaviour (the [`crate::dataflow::def_use`] precedent —
    /// malformed IR is the validator's concern, not ours): a
    /// `BlockTarget` referencing a block outside the arena is silently
    /// skipped; an out-of-range `entry` yields a degenerate result
    /// (empty `rpo`, everything `None`/`false`, vacuously reducible).
    /// The lifter validates entry blocks, so neither fires on its
    /// output.
    #[must_use]
    pub fn build(func: &LiftedFunction) -> Self {
        let n = func.blocks.len();

        // --- 1. Adjacency (structural: every block, deduplicated). ---
        let mut succs: Vec<Vec<BlockId>> = vec![Vec::new(); n];
        for (block, b) in func.blocks.iter() {
            let out = &mut succs[block.index() as usize];
            for_each_target(&b.terminator, |target| {
                if (target.block.index() as usize) < n && !out.contains(&target.block) {
                    out.push(target.block);
                }
            });
        }
        let mut preds: Vec<Vec<BlockId>> = vec![Vec::new(); n];
        for (i, out) in succs.iter().enumerate() {
            for s in out {
                // Outer loop ascends and `out` is deduplicated, so each
                // pred list comes out ascending and deduplicated free.
                preds[s.index() as usize].push(BlockId::from_index(i as u32));
            }
        }

        // --- 2. Postorder DFS → reverse postorder. ---
        // Mark-on-discovery iterative DFS, successor order as stored —
        // the exact shape of waffle's `cfg::postorder::calculate`, so
        // the differential oracle can compare RPO elementwise.
        let mut rpo: Vec<BlockId> = Vec::new();
        let mut rpo_pos: Vec<Option<u32>> = vec![None; n];
        if (entry_in_range(func.entry, n)).is_some() {
            let mut visited = vec![false; n];
            // (block, index of the next successor to consider)
            let mut stack: Vec<(BlockId, usize)> = Vec::new();
            visited[func.entry.index() as usize] = true;
            stack.push((func.entry, 0));
            let mut postorder: Vec<BlockId> = Vec::new();
            while let Some((block, next_succ)) = stack.last_mut() {
                let out = &succs[block.index() as usize];
                if *next_succ < out.len() {
                    let succ = out[*next_succ];
                    *next_succ += 1;
                    let slot = &mut visited[succ.index() as usize];
                    if !*slot {
                        *slot = true;
                        stack.push((succ, 0));
                    }
                } else {
                    postorder.push(*block);
                    stack.pop();
                }
            }
            postorder.reverse();
            rpo = postorder;
            for (pos, block) in rpo.iter().enumerate() {
                rpo_pos[block.index() as usize] = Some(pos as u32);
            }
        }

        // --- 3. Immediate dominators (Cooper–Harvey–Kennedy). ---
        // Iterate reachable blocks in RPO to a fixpoint; the entry is
        // its own idom internally and published as `None`. Preds that
        // are unreachable or not yet processed are skipped inside the
        // intersection — every reachable non-entry block still finds at
        // least one processed pred on the first pass, because its DFS
        // tree parent precedes it in RPO.
        let mut idom_raw: Vec<Option<BlockId>> = vec![None; n];
        if !rpo.is_empty() {
            idom_raw[func.entry.index() as usize] = Some(func.entry);
            let mut changed = true;
            while changed {
                changed = false;
                for &b in &rpo[1..] {
                    let mut new_idom: Option<BlockId> = None;
                    for &p in &preds[b.index() as usize] {
                        if rpo_pos[p.index() as usize].is_none()
                            || idom_raw[p.index() as usize].is_none()
                        {
                            continue;
                        }
                        new_idom = Some(match new_idom {
                            None => p,
                            Some(current) => intersect(&idom_raw, &rpo_pos, current, p),
                        });
                    }
                    if let Some(found) = new_idom
                        && idom_raw[b.index() as usize] != Some(found)
                    {
                        idom_raw[b.index() as usize] = Some(found);
                        changed = true;
                    }
                }
            }
        }
        let mut idom: Vec<Option<BlockId>> = idom_raw;
        if !rpo.is_empty() {
            idom[func.entry.index() as usize] = None;
        }

        // --- 4. Dominator tree + O(1)-dominance intervals. ---
        let mut dom_children: Vec<Vec<BlockId>> = vec![Vec::new(); n];
        for (i, parent) in idom.iter().enumerate() {
            if let Some(parent) = parent {
                // Ascending `i` keeps every child list ascending.
                dom_children[parent.index() as usize].push(BlockId::from_index(i as u32));
            }
        }
        let mut dom_pre: Vec<u32> = vec![0; n];
        let mut dom_post: Vec<u32> = vec![0; n];
        if !rpo.is_empty() {
            let mut counter: u32 = 0;
            let mut stack: Vec<(BlockId, usize)> = Vec::new();
            counter += 1;
            dom_pre[func.entry.index() as usize] = counter;
            stack.push((func.entry, 0));
            while let Some((block, next_child)) = stack.last_mut() {
                let children = &dom_children[block.index() as usize];
                if *next_child < children.len() {
                    let child = children[*next_child];
                    *next_child += 1;
                    counter += 1;
                    dom_pre[child.index() as usize] = counter;
                    stack.push((child, 0));
                } else {
                    counter += 1;
                    dom_post[block.index() as usize] = counter;
                    stack.pop();
                }
            }
        }

        // --- 5. Retreating-edge scan: back edges vs witnesses. ---
        let mut facts = Self {
            entry: func.entry,
            succs,
            preds,
            rpo,
            rpo_pos,
            idom,
            dom_children,
            dom_pre,
            dom_post,
            back_edges: Vec::new(),
            irreducible_edges: Vec::new(),
        };
        for &from in &facts.rpo {
            let from_pos = facts.rpo_pos[from.index() as usize];
            for &to in &facts.succs[from.index() as usize] {
                // A reachable source implies a reachable target, so
                // `to` always has a position here.
                if facts.rpo_pos[to.index() as usize] <= from_pos {
                    let edge = CfgEdge { from, to };
                    if facts.dominates(to, from) {
                        facts.back_edges.push(edge);
                    } else {
                        facts.irreducible_edges.push(edge);
                    }
                }
            }
        }
        facts
    }

    /// Entry block id, as captured at build time.
    #[must_use]
    pub fn entry(&self) -> BlockId {
        self.entry
    }

    /// Number of blocks in the snapshot, reachable or not.
    #[must_use]
    pub fn num_blocks(&self) -> usize {
        self.succs.len()
    }

    /// Deduplicated successors of `b`, in first-occurrence order under
    /// [`for_each_target`]. Empty for an out-of-range id.
    ///
    /// **Warning**: edge *multiplicity* is erased here. Merge-node
    /// detection à la waffle counts one edge per raw terminator target
    /// (a `BranchIf` with both arms on `B` makes `B` a merge node);
    /// use [`for_each_target`] for that, never this list's length.
    #[must_use]
    pub fn succs(&self, b: BlockId) -> &[BlockId] {
        self.succs
            .get(b.index() as usize)
            .map_or(&[], Vec::as_slice)
    }

    /// Deduplicated predecessors of `b`, ascending block index. Empty
    /// for an out-of-range id.
    ///
    /// Structural: includes edges whose source is unreachable from the
    /// entry. The multiplicity warning on [`CfgFacts::succs`] applies
    /// here identically.
    #[must_use]
    pub fn preds(&self, b: BlockId) -> &[BlockId] {
        self.preds
            .get(b.index() as usize)
            .map_or(&[], Vec::as_slice)
    }

    /// Reverse postorder over reachable blocks. `rpo()[0]` is the entry
    /// whenever the function has any reachable block.
    #[must_use]
    pub fn rpo(&self) -> &[BlockId] {
        &self.rpo
    }

    /// Position of `b` in [`CfgFacts::rpo`]; `None` when `b` is
    /// unreachable or out of range.
    #[must_use]
    pub fn rpo_pos(&self, b: BlockId) -> Option<u32> {
        self.rpo_pos.get(b.index() as usize).copied().flatten()
    }

    /// True iff `b` is reachable from the entry.
    #[must_use]
    pub fn is_reachable(&self, b: BlockId) -> bool {
        self.rpo_pos(b).is_some()
    }

    /// Immediate dominator of `b`; `None` for the entry, unreachable
    /// blocks, and out-of-range ids.
    #[must_use]
    pub fn idom(&self, b: BlockId) -> Option<BlockId> {
        self.idom.get(b.index() as usize).copied().flatten()
    }

    /// Reflexive dominance: does `a` dominate `b`?
    ///
    /// O(1) via dominator-tree pre/post intervals. `false` whenever
    /// either block is unreachable or out of range — **including
    /// `a == b`**, a documented divergence from waffle (see the module
    /// docs' unreachable-blocks table).
    #[must_use]
    pub fn dominates(&self, a: BlockId, b: BlockId) -> bool {
        if !self.is_reachable(a) || !self.is_reachable(b) {
            return false;
        }
        let (ai, bi) = (a.index() as usize, b.index() as usize);
        self.dom_pre[ai] <= self.dom_pre[bi] && self.dom_post[bi] <= self.dom_post[ai]
    }

    /// [`CfgFacts::dominates`] excluding equality.
    #[must_use]
    pub fn strictly_dominates(&self, a: BlockId, b: BlockId) -> bool {
        a != b && self.dominates(a, b)
    }

    /// Children of `b` in the dominator tree, ascending block index.
    /// Empty for unreachable or out-of-range blocks.
    #[must_use]
    pub fn dom_children(&self, b: BlockId) -> &[BlockId] {
        self.dom_children
            .get(b.index() as usize)
            .map_or(&[], Vec::as_slice)
    }

    /// The natural-loop back edges: retreating edges whose target
    /// dominates their source (`to` = loop header, `from` = latch).
    /// Order: source RPO position, then successor enumeration order;
    /// deduplicated per `(from, to)` pair.
    #[must_use]
    pub fn back_edges(&self) -> &[CfgEdge] {
        &self.back_edges
    }

    /// Irreducibility witnesses: retreating edges whose target does NOT
    /// dominate their source.
    ///
    /// Empty on every WASM-derived CFG — non-empty on lifter output
    /// means a lifter bug, not an input property. Witness identity is
    /// DFS-order-dependent; only emptiness is canonical.
    #[must_use]
    pub fn irreducible_edges(&self) -> &[CfgEdge] {
        &self.irreducible_edges
    }

    /// True iff no irreducibility witness exists (see
    /// [`CfgFacts::irreducible_edges`]).
    #[must_use]
    pub fn is_reducible(&self) -> bool {
        self.irreducible_edges.is_empty()
    }
}

/// `Some(())` iff `entry` indexes into an arena of `n` blocks. Tiny
/// helper so the degenerate-entry guard reads as a sentence.
fn entry_in_range(entry: BlockId, n: usize) -> Option<()> {
    ((entry.index() as usize) < n).then_some(())
}

/// CHK two-finger intersection: walk the deeper (higher-RPO) node up
/// its idom chain until the fingers meet. Both inputs are processed
/// reachable blocks, whose chains terminate at the self-idom'd entry —
/// the `expect`s encode that invariant.
fn intersect(
    idom_raw: &[Option<BlockId>],
    rpo_pos: &[Option<u32>],
    a: BlockId,
    b: BlockId,
) -> BlockId {
    let pos = |x: BlockId| rpo_pos[x.index() as usize].expect("intersect operands are reachable");
    let (mut a, mut b) = (a, b);
    while a != b {
        while pos(a) > pos(b) {
            a = idom_raw[a.index() as usize].expect("processed blocks have an idom");
        }
        while pos(b) > pos(a) {
            b = idom_raw[b.index() as usize].expect("processed blocks have an idom");
        }
    }
    a
}

/// Identifier of a loop within one [`LoopForest`].
///
/// Not portable across forests (it is an index into that forest's loop
/// list) and deliberately NOT a `sordec_common` IR id — loops are
/// analysis artifacts, not IR objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LoopId(u32);

impl LoopId {
    /// Construct from a raw index (bridging/test use).
    #[must_use]
    pub const fn new(idx: u32) -> Self {
        Self(idx)
    }

    /// Raw index into the owning forest's loop order.
    #[must_use]
    pub const fn index(self) -> u32 {
        self.0
    }
}

/// One natural loop: a header plus every block that reaches one of the
/// header's latches without passing through the header.
///
/// Invariants (guaranteed by [`LoopForest::build`], protected by field
/// privacy): the header dominates every member; `blocks` is ascending
/// and contains the header and all latches; the parent, when present,
/// is a strict superset.
#[derive(Debug, Clone)]
pub struct NaturalLoop {
    /// The loop's single entry block.
    header: BlockId,
    /// Back-edge sources targeting the header; ascending, deduplicated.
    latches: Vec<BlockId>,
    /// All member blocks, ascending block index.
    blocks: Vec<BlockId>,
    /// Immediately enclosing loop, if any.
    parent: Option<LoopId>,
    /// Loops immediately nested inside this one, ascending id.
    children: Vec<LoopId>,
    /// Nesting depth counting this loop; outermost = 1.
    depth: u32,
}

impl NaturalLoop {
    /// The loop's single entry block; dominates every member.
    #[must_use]
    pub fn header(&self) -> BlockId {
        self.header
    }

    /// Back-edge sources targeting the header. Ascending, deduplicated,
    /// never empty.
    #[must_use]
    pub fn latches(&self) -> &[BlockId] {
        &self.latches
    }

    /// All member blocks, ascending block index. Contains the header
    /// and every latch.
    #[must_use]
    pub fn blocks(&self) -> &[BlockId] {
        &self.blocks
    }

    /// Membership test; O(log members).
    #[must_use]
    pub fn contains(&self, b: BlockId) -> bool {
        self.blocks.binary_search(&b).is_ok()
    }

    /// Immediately enclosing loop, if any.
    #[must_use]
    pub fn parent(&self) -> Option<LoopId> {
        self.parent
    }

    /// Loops immediately nested inside this one, ascending id.
    #[must_use]
    pub fn children(&self) -> &[LoopId] {
        &self.children
    }

    /// Nesting depth counting this loop: outermost = 1.
    #[must_use]
    pub fn depth(&self) -> u32 {
        self.depth
    }
}

/// Natural-loop nesting forest derived from one [`CfgFacts`] snapshot.
///
/// Loop order (and therefore [`LoopId`] assignment) is ascending header
/// RPO position — deterministic across runs. Pair only with the
/// [`CfgFacts`] it was built from, and rebuild both after any CFG
/// mutation (module docs, snapshot rule). On irreducible input this is
/// the reducible skeleton — gate on [`CfgFacts::is_reducible`].
#[derive(Debug, Clone)]
pub struct LoopForest {
    /// Loops, indexed by [`LoopId`], ascending header RPO position.
    loops: Vec<NaturalLoop>,
    /// `innermost[i]` = innermost loop containing `BlockId(i)`.
    innermost: Vec<Option<LoopId>>,
    /// `header_loop[i]` = the loop headed by `BlockId(i)`, if any.
    header_loop: Vec<Option<LoopId>>,
}

impl LoopForest {
    /// Build the forest from CFG facts.
    ///
    /// One loop per distinct back-edge target; multiple back edges to
    /// one header merge into a single loop (latch union). Membership is
    /// the classic reverse walk: from each latch, follow reachable
    /// predecessors until the header stops the walk.
    #[must_use]
    pub fn build(facts: &CfgFacts) -> Self {
        let n = facts.num_blocks();

        // Group back edges by header, keyed by header RPO position so
        // loop order is deterministic. (No hash containers anywhere on
        // an output-affecting path.)
        let mut by_header: BTreeMap<u32, (BlockId, Vec<BlockId>)> = BTreeMap::new();
        for edge in facts.back_edges() {
            let pos = facts
                .rpo_pos(edge.to)
                .expect("back-edge endpoints are reachable");
            by_header
                .entry(pos)
                .or_insert_with(|| (edge.to, Vec::new()))
                .1
                .push(edge.from);
        }

        let mut loops: Vec<NaturalLoop> = Vec::with_capacity(by_header.len());
        for (header, mut latches) in by_header.into_values() {
            latches.sort_unstable();
            latches.dedup();

            // Reverse walk from the latches, stopping at the header.
            let mut member = vec![false; n];
            member[header.index() as usize] = true;
            let mut worklist: Vec<BlockId> = Vec::new();
            for &latch in &latches {
                let slot = &mut member[latch.index() as usize];
                if !*slot {
                    *slot = true;
                    worklist.push(latch);
                }
            }
            while let Some(x) = worklist.pop() {
                for &p in facts.preds(x) {
                    if !facts.is_reachable(p) {
                        continue;
                    }
                    let slot = &mut member[p.index() as usize];
                    if !*slot {
                        *slot = true;
                        worklist.push(p);
                    }
                }
            }
            let blocks: Vec<BlockId> = member
                .iter()
                .enumerate()
                .filter(|(_, in_loop)| **in_loop)
                .map(|(i, _)| BlockId::from_index(i as u32))
                .collect();

            loops.push(NaturalLoop {
                header,
                latches,
                blocks,
                parent: None,
                children: Vec::new(),
                depth: 0,
            });
        }

        // Parent = the smallest other loop containing this header.
        // Loops containing a given block form a chain (header of the
        // inner loop is a member of the outer, which forces inclusion),
        // so "smallest containing" is the immediate parent.
        for i in 0..loops.len() {
            let header = loops[i].header;
            let parent = loops
                .iter()
                .enumerate()
                .filter(|(j, candidate)| *j != i && candidate.contains(header))
                .min_by_key(|(_, candidate)| candidate.blocks.len())
                .map(|(j, _)| LoopId::new(j as u32));
            loops[i].parent = parent;
        }
        for i in 0..loops.len() {
            if let Some(parent) = loops[i].parent {
                loops[parent.index() as usize]
                    .children
                    .push(LoopId::new(i as u32));
            }
        }

        // Depth + innermost map, processing outer (larger) loops first
        // so children overwrite parents in `innermost` and always find
        // their parent's depth already computed.
        let mut by_size_desc: Vec<usize> = (0..loops.len()).collect();
        by_size_desc.sort_by_key(|&i| std::cmp::Reverse(loops[i].blocks.len()));
        let mut innermost: Vec<Option<LoopId>> = vec![None; n];
        for &i in &by_size_desc {
            loops[i].depth = match loops[i].parent {
                Some(parent) => loops[parent.index() as usize].depth + 1,
                None => 1,
            };
            for &b in &loops[i].blocks {
                innermost[b.index() as usize] = Some(LoopId::new(i as u32));
            }
        }

        let mut header_loop: Vec<Option<LoopId>> = vec![None; n];
        for (i, l) in loops.iter().enumerate() {
            header_loop[l.header.index() as usize] = Some(LoopId::new(i as u32));
        }

        Self {
            loops,
            innermost,
            header_loop,
        }
    }

    /// Number of loops in the forest.
    #[must_use]
    pub fn len(&self) -> usize {
        self.loops.len()
    }

    /// True when the function has no loops.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.loops.is_empty()
    }

    /// Loop by id; `None` for a foreign or out-of-range id.
    #[must_use]
    pub fn get(&self, id: LoopId) -> Option<&NaturalLoop> {
        self.loops.get(id.index() as usize)
    }

    /// `(LoopId, &NaturalLoop)` pairs, ascending id (= ascending header
    /// RPO position).
    pub fn iter(&self) -> impl Iterator<Item = (LoopId, &NaturalLoop)> + '_ {
        self.loops
            .iter()
            .enumerate()
            .map(|(i, l)| (LoopId::new(i as u32), l))
    }

    /// Ids of the outermost loops (those without a parent), ascending.
    pub fn roots(&self) -> impl Iterator<Item = LoopId> + '_ {
        self.iter()
            .filter(|(_, l)| l.parent.is_none())
            .map(|(id, _)| id)
    }

    /// Innermost loop containing `b`; `None` outside all loops or out
    /// of range.
    #[must_use]
    pub fn innermost(&self, b: BlockId) -> Option<LoopId> {
        self.innermost.get(b.index() as usize).copied().flatten()
    }

    /// The loop whose header is `b`, if `b` heads one.
    #[must_use]
    pub fn loop_headed_by(&self, b: BlockId) -> Option<LoopId> {
        self.header_loop.get(b.index() as usize).copied().flatten()
    }

    /// True iff `b` is some loop's header.
    #[must_use]
    pub fn is_header(&self, b: BlockId) -> bool {
        self.loop_headed_by(b).is_some()
    }

    /// Nesting depth of `b`: its innermost loop's depth, or 0 outside
    /// all loops.
    #[must_use]
    pub fn loop_depth(&self, b: BlockId) -> u32 {
        self.innermost(b)
            .and_then(|id| self.get(id))
            .map_or(0, NaturalLoop::depth)
    }
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{Arena, FuncId, ValueId};
    use sordec_ir::{LiftedBlock, LiftedType, LiftedValue, LiftedValueDef, WasmOp};

    /// Terminator spec for the CFG builder; `u32`s are block indices.
    enum T {
        Br(u32),
        BrIf(u32, u32),
        Sw(Vec<u32>, u32),
        Ret,
        Trap,
    }

    fn tgt(i: u32) -> BlockTarget {
        BlockTarget {
            block: BlockId::from_index(i),
            args: vec![],
        }
    }

    /// Build a `LiftedFunction` whose block `i` has id `BlockId(i)` and
    /// terminator `terms[i]`, with empty params/instructions and no
    /// target args. Entry = block 0. One `I32Const` value (`v0`) serves
    /// as every branch condition / switch index.
    ///
    /// NOTE: unlike def_use.rs's builder (which stamps every block id
    /// as `BlockId(0)` because nothing there reads ids), this one sets
    /// real ids — CFG analysis is entirely id-driven.
    fn func_of(terms: Vec<T>) -> LiftedFunction {
        let mut values: Arena<ValueId, LiftedValue> = Arena::new();
        values.push(LiftedValue {
            def: LiftedValueDef::Operator {
                op: WasmOp(waffle::Operator::I32Const { value: 0 }),
                args: vec![],
            },
            types: vec![LiftedType::I32],
        });
        let cond = ValueId::from_index(0);
        let mut blocks: Arena<BlockId, LiftedBlock> = Arena::new();
        for (i, t) in terms.into_iter().enumerate() {
            let terminator = match t {
                T::Br(a) => LiftedTerminator::Branch(tgt(a)),
                T::BrIf(a, b) => LiftedTerminator::BranchIf {
                    cond,
                    if_true: tgt(a),
                    if_false: tgt(b),
                },
                T::Sw(targets, default) => LiftedTerminator::Switch {
                    index: cond,
                    targets: targets.into_iter().map(tgt).collect(),
                    default: tgt(default),
                },
                T::Ret => LiftedTerminator::Return { values: vec![] },
                T::Trap => LiftedTerminator::Unreachable,
            };
            blocks.push(LiftedBlock {
                id: BlockId::from_index(i as u32),
                params: vec![],
                instructions: vec![],
                terminator,
            });
        }
        LiftedFunction {
            id: FuncId::from_index(0),
            entry: BlockId::from_index(0),
            blocks,
            values,
        }
    }

    fn bb(i: u32) -> BlockId {
        BlockId::from_index(i)
    }

    fn edge(from: u32, to: u32) -> CfgEdge {
        CfgEdge {
            from: bb(from),
            to: bb(to),
        }
    }

    fn ids(blocks: &[BlockId]) -> Vec<u32> {
        blocks.iter().map(|b| b.index()).collect()
    }

    // --- Shape tests: adjacency, RPO, dominance ---

    #[test]
    fn straight_line() {
        let facts = CfgFacts::build(&func_of(vec![T::Br(1), T::Ret]));
        assert_eq!(ids(facts.rpo()), vec![0, 1]);
        assert_eq!(facts.idom(bb(1)), Some(bb(0)));
        assert_eq!(ids(facts.preds(bb(1))), vec![0]);
        assert!(facts.back_edges().is_empty());
        assert!(facts.is_reducible());
        assert!(LoopForest::build(&facts).is_empty());
    }

    #[test]
    fn diamond() {
        let facts = CfgFacts::build(&func_of(vec![T::BrIf(1, 2), T::Br(3), T::Br(3), T::Ret]));
        // DFS visits the if_true arm first, so it FINISHES first and
        // lands later in reverse postorder: [0, 2, 1, 3].
        assert_eq!(ids(facts.rpo()), vec![0, 2, 1, 3]);
        assert_eq!(facts.idom(bb(3)), Some(bb(0)), "merge is dominated by the fork");
        assert_eq!(ids(facts.preds(bb(3))), vec![1, 2]);
        assert!(facts.dominates(bb(0), bb(3)));
        assert!(!facts.dominates(bb(1), bb(3)));
    }

    #[test]
    fn triangle_if_no_else() {
        let facts = CfgFacts::build(&func_of(vec![T::BrIf(1, 2), T::Br(2), T::Ret]));
        assert_eq!(facts.idom(bb(1)), Some(bb(0)));
        assert_eq!(facts.idom(bb(2)), Some(bb(0)));
        assert!(facts.is_reducible());
    }

    #[test]
    fn single_block_return() {
        let facts = CfgFacts::build(&func_of(vec![T::Ret]));
        assert_eq!(ids(facts.rpo()), vec![0]);
        assert_eq!(facts.idom(bb(0)), None, "the entry has no idom");
        assert!(facts.dominates(bb(0), bb(0)));
        assert!(facts.is_reducible());
        assert!(LoopForest::build(&facts).is_empty());
    }

    #[test]
    fn dominates_queries() {
        // The nested_loops shape doubles as a dominance playground.
        let facts = CfgFacts::build(&func_of(vec![
            T::Br(1),
            T::Br(2),
            T::BrIf(3, 4),
            T::Br(2),
            T::BrIf(1, 5),
            T::Ret,
        ]));
        for i in 0..6 {
            assert!(facts.dominates(bb(0), bb(i)), "entry dominates bb{i}");
            assert!(facts.dominates(bb(i), bb(i)), "reflexive on bb{i}");
        }
        assert!(facts.dominates(bb(1), bb(4)));
        assert!(facts.dominates(bb(2), bb(3)));
        assert!(!facts.dominates(bb(3), bb(4)));
        assert!(!facts.strictly_dominates(bb(1), bb(1)));
        assert!(facts.strictly_dominates(bb(1), bb(2)));
        assert!(!facts.dominates(bb(99), bb(0)), "out of range is never a dominator");
        assert!(!facts.dominates(bb(0), bb(99)));
    }

    // --- Loop tests ---

    #[test]
    fn self_loop() {
        let facts = CfgFacts::build(&func_of(vec![T::Br(1), T::BrIf(1, 2), T::Ret]));
        assert_eq!(facts.back_edges(), &[edge(1, 1)]);
        assert!(facts.is_reducible());

        let forest = LoopForest::build(&facts);
        assert_eq!(forest.len(), 1);
        let (id, l) = forest.iter().next().expect("one loop");
        assert_eq!(l.header(), bb(1));
        assert_eq!(ids(l.latches()), vec![1]);
        assert_eq!(ids(l.blocks()), vec![1]);
        assert_eq!(l.depth(), 1);
        assert_eq!(forest.innermost(bb(1)), Some(id));
        assert_eq!(forest.innermost(bb(0)), None);
        assert_eq!(forest.loop_depth(bb(2)), 0);
    }

    #[test]
    fn entry_self_loop() {
        let facts = CfgFacts::build(&func_of(vec![T::BrIf(0, 1), T::Ret]));
        assert_eq!(ids(facts.rpo()), vec![0, 1], "rpo[0] is the entry even with an entry back edge");
        assert_eq!(facts.back_edges(), &[edge(0, 0)]);
        assert_eq!(facts.idom(bb(1)), Some(bb(0)));

        let forest = LoopForest::build(&facts);
        assert_eq!(forest.len(), 1);
        let (_, l) = forest.iter().next().expect("one loop");
        assert_eq!(ids(l.blocks()), vec![0]);
    }

    #[test]
    fn while_loop() {
        let facts = CfgFacts::build(&func_of(vec![
            T::Br(1),
            T::BrIf(2, 3),
            T::Br(1),
            T::Ret,
        ]));
        assert_eq!(facts.back_edges(), &[edge(2, 1)]);

        let forest = LoopForest::build(&facts);
        let (_, l) = forest.iter().next().expect("one loop");
        assert_eq!(l.header(), bb(1));
        assert_eq!(ids(l.latches()), vec![2]);
        assert_eq!(ids(l.blocks()), vec![1, 2]);
        assert!(!l.contains(bb(3)), "the exit block is outside the loop");
        assert_eq!(forest.loop_depth(bb(3)), 0);
    }

    #[test]
    fn do_while_latch_tested() {
        let facts = CfgFacts::build(&func_of(vec![
            T::Br(1),
            T::Br(2),
            T::BrIf(1, 3),
            T::Ret,
        ]));
        assert_eq!(facts.back_edges(), &[edge(2, 1)]);
        let forest = LoopForest::build(&facts);
        let (_, l) = forest.iter().next().expect("one loop");
        assert_eq!(ids(l.blocks()), vec![1, 2]);
    }

    #[test]
    fn nested_loops() {
        let facts = CfgFacts::build(&func_of(vec![
            T::Br(1),
            T::Br(2),
            T::BrIf(3, 4),
            T::Br(2),
            T::BrIf(1, 5),
            T::Ret,
        ]));
        let forest = LoopForest::build(&facts);
        assert_eq!(forest.len(), 2);

        // LoopId order = ascending header RPO: outer (header 1) first.
        let outer_id = LoopId::new(0);
        let inner_id = LoopId::new(1);
        let outer = forest.get(outer_id).expect("outer loop");
        let inner = forest.get(inner_id).expect("inner loop");

        assert_eq!(outer.header(), bb(1));
        assert_eq!(ids(outer.blocks()), vec![1, 2, 3, 4]);
        assert_eq!(outer.depth(), 1);
        assert_eq!(outer.parent(), None);
        assert_eq!(outer.children(), &[inner_id]);

        assert_eq!(inner.header(), bb(2));
        assert_eq!(ids(inner.blocks()), vec![2, 3]);
        assert_eq!(inner.depth(), 2);
        assert_eq!(inner.parent(), Some(outer_id));

        assert_eq!(forest.innermost(bb(2)), Some(inner_id));
        assert_eq!(forest.innermost(bb(3)), Some(inner_id));
        assert_eq!(forest.innermost(bb(4)), Some(outer_id));
        assert_eq!(forest.roots().collect::<Vec<_>>(), vec![outer_id]);
        assert!(forest.is_header(bb(1)));
        assert!(forest.is_header(bb(2)));
        assert!(!forest.is_header(bb(3)));
        assert_eq!(forest.loop_depth(bb(3)), 2);
    }

    #[test]
    fn two_back_edges_one_header() {
        let facts = CfgFacts::build(&func_of(vec![
            T::Br(1),
            T::BrIf(2, 3),
            T::Br(1),
            T::BrIf(1, 4),
            T::Ret,
        ]));
        assert_eq!(facts.back_edges().len(), 2);

        let forest = LoopForest::build(&facts);
        assert_eq!(forest.len(), 1, "two back edges to one header merge into ONE loop");
        let (_, l) = forest.iter().next().expect("one loop");
        assert_eq!(ids(l.latches()), vec![2, 3]);
        assert_eq!(ids(l.blocks()), vec![1, 2, 3]);
    }

    #[test]
    fn loop_with_break_multi_exit() {
        let facts = CfgFacts::build(&func_of(vec![
            T::Br(1),
            T::BrIf(2, 4),
            T::BrIf(3, 5),
            T::Br(1),
            T::Ret,
            T::Ret,
        ]));
        assert!(facts.is_reducible());
        let forest = LoopForest::build(&facts);
        let (_, l) = forest.iter().next().expect("one loop");
        assert_eq!(ids(l.blocks()), vec![1, 2, 3]);
        assert!(!l.contains(bb(4)));
        assert!(!l.contains(bb(5)));
    }

    // --- Enumeration order + multiplicity ---

    #[test]
    fn switch_shared_targets() {
        let facts = CfgFacts::build(&func_of(vec![T::Sw(vec![1, 1, 2], 2), T::Ret, T::Ret]));
        // Default first (waffle visit_targets parity), then the cases,
        // deduplicated at first occurrence.
        assert_eq!(ids(facts.succs(bb(0))), vec![2, 1]);
        assert_eq!(ids(facts.preds(bb(1))), vec![0]);
        assert_eq!(ids(facts.preds(bb(2))), vec![0]);
        assert_eq!(ids(facts.rpo()), vec![0, 1, 2]);
    }

    #[test]
    fn branch_if_both_arms_same_target() {
        let func = func_of(vec![T::BrIf(1, 1), T::Ret]);
        let facts = CfgFacts::build(&func);
        assert_eq!(ids(facts.succs(bb(0))), vec![1], "succs are deduplicated");
        assert_eq!(ids(facts.preds(bb(1))), vec![0], "preds are deduplicated");

        // The raw view preserves multiplicity — this is what merge-node
        // detection must consume.
        let mut raw = Vec::new();
        let entry_block = func.blocks.get(bb(0)).expect("entry block");
        for_each_target(&entry_block.terminator, |t| raw.push(t.block.index()));
        assert_eq!(raw, vec![1, 1]);
    }

    #[test]
    fn for_each_target_order() {
        let collect = |term: &LiftedTerminator| {
            let mut out = Vec::new();
            for_each_target(term, |t| out.push(t.block.index()));
            out
        };
        assert_eq!(collect(&LiftedTerminator::Branch(tgt(7))), vec![7]);
        assert_eq!(
            collect(&LiftedTerminator::BranchIf {
                cond: ValueId::from_index(0),
                if_true: tgt(3),
                if_false: tgt(4),
            }),
            vec![3, 4]
        );
        assert_eq!(
            collect(&LiftedTerminator::Switch {
                index: ValueId::from_index(0),
                targets: vec![tgt(1), tgt(2)],
                default: tgt(9),
            }),
            vec![9, 1, 2],
            "Switch enumerates the default FIRST (waffle parity)"
        );
        assert_eq!(collect(&LiftedTerminator::Return { values: vec![] }), Vec::<u32>::new());
        assert_eq!(collect(&LiftedTerminator::Unreachable), Vec::<u32>::new());
    }

    // --- Unreachable blocks ---

    #[test]
    fn unreachable_block() {
        // A trap-terminated entry (the corpus's shared-panic-block
        // shape) with an unreachable block branching into it.
        let facts = CfgFacts::build(&func_of(vec![T::Trap, T::Br(0)]));
        assert_eq!(ids(facts.rpo()), vec![0]);
        assert_eq!(facts.rpo_pos(bb(1)), None);
        assert_eq!(facts.idom(bb(1)), None);
        assert!(!facts.is_reachable(bb(1)));
        assert!(!facts.dominates(bb(1), bb(1)), "unreachable never dominates, even itself");
        // Adjacency stays structural: the unreachable block's edge is real.
        assert_eq!(ids(facts.preds(bb(0))), vec![1]);
        assert!(facts.back_edges().is_empty());
    }

    #[test]
    fn unreachable_cycle() {
        let facts = CfgFacts::build(&func_of(vec![T::Ret, T::Br(2), T::Br(1)]));
        assert!(facts.back_edges().is_empty(), "unreachable cycles induce no back edges");
        assert!(facts.irreducible_edges().is_empty());
        assert!(facts.is_reducible());
        assert!(LoopForest::build(&facts).is_empty());
    }

    // --- Reducibility ---

    #[test]
    fn irreducible_two_entry() {
        // 0 branches into BOTH members of the 1↔2 cycle: a two-entry
        // loop, inexpressible in WASM, constructible only synthetically.
        let facts = CfgFacts::build(&func_of(vec![T::BrIf(1, 2), T::Br(2), T::Br(1)]));
        assert!(!facts.is_reducible());
        assert_eq!(facts.irreducible_edges(), &[edge(2, 1)]);
        assert!(facts.back_edges().is_empty());
        assert!(
            LoopForest::build(&facts).is_empty(),
            "irreducible cycles induce no natural loops (reducible-skeleton semantics)"
        );
    }

    // --- Malformed-input hardening ---

    #[test]
    fn dangling_block_target_is_skipped() {
        let facts = CfgFacts::build(&func_of(vec![T::Br(99)]));
        assert_eq!(ids(facts.succs(bb(0))), Vec::<u32>::new());
        assert_eq!(ids(facts.rpo()), vec![0]);
        assert!(facts.is_reducible());
    }

    #[test]
    fn entry_out_of_range_degenerate() {
        let mut func = func_of(vec![T::Ret]);
        func.entry = bb(5);
        let facts = CfgFacts::build(&func);
        assert_eq!(facts.num_blocks(), 1);
        assert!(facts.rpo().is_empty());
        assert_eq!(facts.rpo_pos(bb(0)), None);
        assert_eq!(facts.idom(bb(0)), None);
        assert!(!facts.dominates(bb(0), bb(0)));
        assert!(facts.is_reducible(), "vacuously reducible");
        assert!(LoopForest::build(&facts).is_empty());
    }
}
