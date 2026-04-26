//! Structured control-flow regions.
//!
//! [`Region`] is the high IR's representation of recovered structured
//! control flow. It overlays the linear basic-block soup with `if`,
//! `loop`, `switch`, etc. the way Rust expects.
//!
//! A function whose CFG cannot be cleanly structured falls back to
//! [`Region::Unstructured`], which preserves the basic-block reference
//! and explains why structuring failed. The emit step renders these as
//! `loop { match block_id { ... } }` jump-table emulation.

use sordec_common::{BlockId, UnknownReason, ValueId};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Structured control-flow region.
///
/// Recursive: most variants nest other regions. The whole function's
/// control flow is a single root [`Region`] on its [`crate::HighFunction`].
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Region {
    /// Reference to a basic block whose linear bindings should be emitted
    /// in order. Leaf of the region tree.
    Block(BlockId),

    /// Linear sequence of regions executed in declaration order.
    Sequence(Vec<Region>),

    /// `if cond { then } else { else }` (the `else` is optional).
    If {
        /// Boolean condition value.
        cond: ValueId,
        /// Branch taken when `cond` is true.
        then_region: Box<Region>,
        /// Branch taken when `cond` is false. `None` means no else clause.
        else_region: Option<Box<Region>>,
    },

    /// Looping region.
    ///
    /// `header` runs once on entry and once after every iteration of
    /// `body`; the loop continues iff the most recent header evaluation
    /// reached its terminating `Continue`. We treat `while`-style and
    /// `loop`-style alike here; pattern matchers downstream (in emit)
    /// distinguish the two when generating Rust syntax.
    Loop {
        /// Loop header (the condition computation in a `while`).
        header: Box<Region>,
        /// Loop body.
        body: Box<Region>,
    },

    /// Multi-way `switch` (recovered from `br_table`).
    Switch {
        /// Selector value.
        index: ValueId,
        /// Indexed cases. Each is the region taken when `index` matches
        /// the corresponding zero-based slot.
        cases: Vec<Region>,
        /// Region taken when `index` is out of range.
        default: Box<Region>,
    },

    /// Return from the enclosing function.
    Return {
        /// Values to return; arity matches the function's return type.
        values: Vec<ValueId>,
    },

    /// Trap on execute.
    Unreachable,

    /// Structuring fell back to a goto-style block reference. The emit
    /// step turns these into a `loop { match dispatch { ... } }`
    /// pattern. The [`UnknownReason`] explains why structuring failed.
    Unstructured {
        /// Block at which the unstructured fragment starts.
        entry: BlockId,
        /// Why structuring did not succeed for this region.
        reason: UnknownReason,
    },
}
