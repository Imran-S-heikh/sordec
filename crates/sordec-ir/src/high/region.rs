//! Structured control-flow regions.
//!
//! [`Region`] is the high IR's representation of recovered structured
//! control flow: the tree the structurer builds over the linear basic
//! blocks, expressing `if` / `loop` / `match` shapes plus explicit scope
//! exits the way Rust expects. The whole function's control flow is a
//! single root [`Region`] on its [`crate::HighFunction`].
//!
//! ## Labels
//!
//! Scoped constructs are labeled by the CFG block they hand control to,
//! not by nesting depth: [`Region::Break`] targets the `out` block of an
//! enclosing [`Region::Scope`], and [`Region::Continue`] targets the
//! `header` of an enclosing [`Region::Loop`]. Block identity is stable
//! under the refinement passes that splice and re-nest subtrees (a
//! depth-based label would need renumbering on every rewrite), and it is
//! directly checkable: the validator asserts every branch names a
//! matching enclosing construct.
//!
//! ## Value flow at branches
//!
//! Values crossing region edges (WASM block parameters, surfaced as
//! [`crate::Expr::Phi`] bindings) are spelled as explicit [`PhiTransfer`]
//! assignment lists on [`Region::Break`] / [`Region::Continue`] /
//! [`Region::Transfer`]. The phi bindings themselves survive in the high
//! IR until the emit layer materializes them as mutable locals — one
//! assignment per transfer pair, immediately before the branch.
//!
//! ## Fallback
//!
//! A function whose CFG cannot be structured falls back to
//! [`Region::Unstructured`], which preserves the entry block and explains
//! why structuring failed. Renderers present the raw block listing in
//! that case. WASM control flow can only express reducible CFGs, which a
//! correct structurer always handles — on real corpus input the fallback
//! is asserted to be absent; it exists as a defensive path for exotic
//! producers.

use sordec_common::{BlockId, UnknownReason, ValueId};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Positional phi assignments carried by one branch edge.
///
/// Each pair is `(phi binding in the target block, value flowing in from
/// this edge)`: the left [`ValueId`] must resolve to an
/// [`crate::Expr::Phi`] binding owned by the branch target, and the right
/// side is the value this edge contributes to it. Emit lowers each pair
/// to one assignment before the branch.
///
/// Empty when the edge carries no values — the common case once the
/// pre-structuring cleanup passes have pruned redundant block parameters.
pub type PhiTransfer = Vec<(ValueId, ValueId)>;

/// Structured control-flow region.
///
/// Recursive: most variants nest other regions. See the [module
/// documentation](self) for the label and value-flow conventions shared
/// by the branching variants.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Region {
    /// One basic block's bindings, emitted in order. Leaf of the tree.
    Basic(BlockId),

    /// Linear sequence of regions executed in declaration order.
    Sequence(Vec<Region>),

    /// Labeled forward scope.
    ///
    /// A [`Region::Break`] inside `body` whose `target` equals `out`
    /// exits this scope; control then resumes at `out`'s region, which
    /// follows this `Scope` in the parent [`Region::Sequence`]. This is
    /// the structured form of a CFG forward-merge point.
    Scope {
        /// The merge block this scope's label jumps to. Label identity.
        out: BlockId,
        /// Scope contents.
        body: Box<Region>,
    },

    /// `if cond { then } else { else }` (the `else` is optional).
    If {
        /// Boolean condition value.
        cond: ValueId,
        /// Branch taken when `cond` is true.
        then_region: Box<Region>,
        /// Branch taken when `cond` is false. `None` means no else clause.
        else_region: Option<Box<Region>>,
    },

    /// Looping region: the single canonical loop shape.
    ///
    /// A [`Region::Continue`] inside `body` whose `target` equals
    /// `header` is the back edge. Loop exits are [`Region::Break`]s to
    /// enclosing scopes. The source-level shape (`while`, do-while,
    /// guarded do-while) is *classified*, not restructured: the
    /// structurer always emits [`LoopKind::Unclassified`] and the
    /// loop-classification refinement pass tags what it proves.
    Loop {
        /// The loop-entry block. Label identity for `Continue`.
        header: BlockId,
        /// Loop body (starts with `header`'s region).
        body: Box<Region>,
        /// Recovered source-level loop shape; rendering hint only —
        /// the region tree is identical for every kind.
        kind: LoopKind,
    },

    /// Multi-way branch recovered from `br_table`.
    Switch {
        /// Selector value.
        index: ValueId,
        /// Arms in ascending case order. Arms with a shared target are
        /// grouped (`cases` holds every selector value for the arm)
        /// rather than duplicating the target region.
        arms: Vec<SwitchArm>,
        /// Region taken when `index` matches no arm.
        default: Box<Region>,
        /// When the dispatcher recognizer linked this switch to a
        /// recovered enum, the binding carrying the
        /// `KnownOp::SymbolDispatch` table that names the arms.
        /// `None` for a plain integer switch.
        dispatch: Option<ValueId>,
    },

    /// Exit the enclosing [`Region::Scope`] whose `out` equals `target`,
    /// assigning phi inputs for the values this edge carries.
    Break {
        /// The `out` block of the scope being exited.
        target: BlockId,
        /// Phi assignments into `target`'s block parameters.
        transfer: PhiTransfer,
    },

    /// Re-enter the enclosing [`Region::Loop`] whose `header` equals
    /// `target` (the loop back edge), assigning loop-carried phi inputs.
    Continue {
        /// The `header` block of the loop being continued.
        target: BlockId,
        /// Phi assignments into the header's block parameters.
        transfer: PhiTransfer,
    },

    /// Fall through into `target`'s region without exiting a scope,
    /// assigning phi inputs first.
    ///
    /// Emitted where a CFG edge enters a merge block as straight-line
    /// control flow — the value-transfer half of a branch with no `br`.
    Transfer {
        /// Block whose phis receive the values.
        target: BlockId,
        /// Phi assignments into `target`'s block parameters.
        transfer: PhiTransfer,
    },

    /// Return from the enclosing function.
    Return {
        /// Values to return; arity matches the function's return type.
        values: Vec<ValueId>,
    },

    /// Trap on execute.
    Unreachable,

    /// Structuring fell back to a goto-style block reference. The
    /// [`UnknownReason`] explains why; the fallback surfaces a
    /// `StructuringFallback` diagnostic and renderers show the raw
    /// block listing from `entry`.
    Unstructured {
        /// Block at which the unstructured fragment starts.
        entry: BlockId,
        /// Why structuring did not succeed for this region.
        reason: UnknownReason,
    },
}

/// Source-level loop shape recorded on [`Region::Loop`].
///
/// Written only by the loop-classification refinement pass; the
/// structurer emits [`LoopKind::Unclassified`] unconditionally. The tag
/// is a rendering/emit hint — consumers must treat every kind as the
/// same canonical `Loop` region and may ignore the tag entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum LoopKind {
    /// Not yet visited by the classification pass.
    Unclassified,
    /// No conditional exit reachable from the body: `loop { .. }`.
    Infinite,
    /// Exit test at the head: renders as `while cond { .. }`.
    WhileTop,
    /// Exit test at the latch (LLVM's rotated do-while). Rust has no
    /// do-while; renders as `loop { .. if !cond { break } }`.
    DoWhileBottom,
    /// Rotated do-while behind an entry guard where the guard condition
    /// matches the latch condition on entry state — re-derivable as
    /// `while` / `for` at emit.
    GuardedDoWhile,
}

/// One arm of a [`Region::Switch`].
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SwitchArm {
    /// Every selector value that lands on this arm, ascending. Never
    /// empty; more than one entry when `br_table` slots share a target.
    pub cases: Vec<u32>,
    /// Region executed for these cases.
    pub body: Region,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bb(i: u32) -> BlockId {
        BlockId::new(i)
    }

    fn v(i: u32) -> ValueId {
        ValueId::new(i)
    }

    /// The guard shape D-refinement targets: entry block, a conditional
    /// early exit out of a scope, then the merge block.
    fn guard_tree() -> Region {
        Region::Sequence(vec![
            Region::Scope {
                out: bb(2),
                body: Box::new(Region::Sequence(vec![
                    Region::Basic(bb(0)),
                    Region::If {
                        cond: v(4),
                        then_region: Box::new(Region::Break {
                            target: bb(2),
                            transfer: vec![],
                        }),
                        else_region: None,
                    },
                    Region::Basic(bb(1)),
                    Region::Break {
                        target: bb(2),
                        transfer: vec![(v(9), v(7))],
                    },
                ])),
            },
            Region::Basic(bb(2)),
            Region::Return { values: vec![v(9)] },
        ])
    }

    #[test]
    fn identical_trees_compare_equal() {
        assert_eq!(guard_tree(), guard_tree());
    }

    #[test]
    fn differing_break_targets_compare_unequal() {
        let mut other = guard_tree();
        if let Region::Sequence(items) = &mut other
            && let Region::Scope { out, .. } = &mut items[0]
        {
            *out = bb(3);
        }
        assert_ne!(guard_tree(), other);
    }

    #[test]
    fn rotated_loop_carries_continue_transfer_and_unclassified_kind() {
        let region = Region::Loop {
            header: bb(1),
            body: Box::new(Region::Sequence(vec![
                Region::Basic(bb(1)),
                Region::If {
                    cond: v(5),
                    // Back edge with one loop-carried value.
                    then_region: Box::new(Region::Continue {
                        target: bb(1),
                        transfer: vec![(v(2), v(6))],
                    }),
                    else_region: Some(Box::new(Region::Break {
                        target: bb(3),
                        transfer: vec![],
                    })),
                },
            ])),
            kind: LoopKind::Unclassified,
        };

        let Region::Loop { header, kind, .. } = &region else {
            panic!("constructed a loop");
        };
        assert_eq!(*header, bb(1));
        assert_eq!(*kind, LoopKind::Unclassified);
    }

    #[test]
    fn switch_arms_group_shared_targets() {
        let region = Region::Switch {
            index: v(0),
            arms: vec![
                SwitchArm {
                    cases: vec![0, 2],
                    body: Region::Basic(bb(1)),
                },
                SwitchArm {
                    cases: vec![1],
                    body: Region::Basic(bb(2)),
                },
            ],
            default: Box::new(Region::Unreachable),
            dispatch: None,
        };

        let Region::Switch { arms, .. } = &region else {
            panic!("constructed a switch");
        };
        assert_eq!(arms[0].cases, vec![0, 2]);
        assert_eq!(arms[1].cases, vec![1]);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn region_tree_round_trips_through_serde_json() {
        let tree = guard_tree();
        let json = serde_json::to_string(&tree).expect("region tree serializes");
        let back: Region = serde_json::from_str(&json).expect("region tree deserializes");
        assert_eq!(tree, back);
    }
}
