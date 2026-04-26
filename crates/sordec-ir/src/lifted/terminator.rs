//! Block terminators for the lifted IR.
//!
//! Each [`crate::lifted::LiftedBlock`] ends with exactly one
//! [`LiftedTerminator`]. Terminators describe the control-flow exit:
//! return, branch, or trap.
//!
//! This is a typed mirror of `waffle::Terminator`, but it goes through our
//! [`sordec_common::BlockId`] / [`sordec_common::ValueId`] newtypes so
//! cross-function ID misuse fails to compile.

use sordec_common::{BlockId, ValueId};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// How a block exits to its successors.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum LiftedTerminator {
    /// Unconditional jump.
    Branch(BlockTarget),

    /// Conditional jump. The condition is a single [`ValueId`] of i32 type
    /// (non-zero means take `if_true`).
    BranchIf {
        /// Truthy/falsy SSA value.
        cond: ValueId,
        /// Successor when `cond` is non-zero.
        if_true: BlockTarget,
        /// Successor when `cond` is zero.
        if_false: BlockTarget,
    },

    /// `br_table`: indexed jump used by `match`/`switch` lowering.
    Switch {
        /// Index value selecting one of `targets`.
        index: ValueId,
        /// Indexed targets, in WASM order.
        targets: Vec<BlockTarget>,
        /// Target taken when `index` is out of bounds.
        default: BlockTarget,
    },

    /// Return from the enclosing function.
    Return {
        /// Values to return; length must equal the function's return arity.
        values: Vec<ValueId>,
    },

    /// Trap on execute.
    Unreachable,
}

/// Successor block plus the SSA arguments to pass to its block parameters.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BlockTarget {
    /// Successor block.
    pub block: BlockId,
    /// Arguments to pass to that block's parameters, positionally matched.
    pub args: Vec<ValueId>,
}
