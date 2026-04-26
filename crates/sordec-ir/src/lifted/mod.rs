//! Layer 2 of the IR pipeline: SSA + CFG, close to WASM operators.
//!
//! [`LiftedIr`] is the output of the lifting pass over [`crate::WasmFacts`]
//! (the lifting itself lives in `sordec-passes`; this module only defines
//! the data types). It is the first IR layer where:
//!
//! - WASM stack semantics have been converted to SSA values with stable
//!   [`ValueId`]s.
//! - Control flow is an explicit graph of [`LiftedBlock`]s connected by
//!   [`LiftedTerminator`]s.
//! - Operators are typed via the [`WasmOp`] newtype rather than raw
//!   waffle types, so a waffle upgrade can never silently change the
//!   meaning of an opcode.
//!
//! Semantic recovery (storage tier, auth, Val-encoding, cross-contract
//! calls) does not happen here — those become passes producing the
//! richer [`crate::HighIr`].

pub mod op;
pub mod terminator;

pub use op::{WasmOp, WasmOpcodeKind};
pub use terminator::{BlockTarget, LiftedTerminator};

use sordec_common::{Arena, BlockId, FuncId, IrId, ValueId};

use crate::WasmFacts;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

// NOTE on `serde`: the lifted IR is intentionally `Serialize`-only.
// `WasmOp` wraps `waffle::Operator`, which provides no `Deserialize` impl
// of its own; we serialise WasmOp lossily (Debug repr) for inspection
// but do not support round-tripping. Every type below that transitively
// contains a `WasmOp` therefore opts in to `Serialize` only.

/// Top-level lifted IR for a whole module.
///
/// Owns its [`WasmFacts`] (the originating frontend output) so the lifter
/// is the single authoritative producer of `LiftedIr`. Downstream passes
/// receive it by `&mut LiftedIr` and refine it in place.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct LiftedIr {
    /// Frontend-decoded facts about the original module.
    pub facts: WasmFacts,

    /// Local (non-imported) functions in module order. Each is keyed by
    /// its [`FuncId`]; function index `i` lives at position `i` in the
    /// vector. Imported functions are tracked separately on `facts`.
    pub functions: Vec<LiftedFunction>,
}

impl LiftedIr {
    /// Look up a function by its module-global [`FuncId`].
    #[inline]
    #[must_use]
    pub fn function(&self, id: FuncId) -> Option<&LiftedFunction> {
        self.functions.get(id.index() as usize)
    }

    /// Mutable counterpart to [`function`](Self::function).
    #[inline]
    #[must_use]
    pub fn function_mut(&mut self, id: FuncId) -> Option<&mut LiftedFunction> {
        self.functions.get_mut(id.index() as usize)
    }
}

/// One local function lifted to SSA + CFG form.
///
/// All [`BlockId`] and [`ValueId`] values appearing inside `blocks` and
/// `values` are scoped to *this* `LiftedFunction`; they are not portable
/// to another function. See `docs/architecture.md` §1 on identifier
/// scoping.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct LiftedFunction {
    /// Module-global identifier of this function.
    pub id: FuncId,

    /// Block at which execution begins. Always present in well-formed IR.
    pub entry: BlockId,

    /// All basic blocks in this function. Block lookup is via the
    /// [`Arena`].
    pub blocks: Arena<BlockId, LiftedBlock>,

    /// All SSA value definitions in this function. The result of an
    /// instruction lives at the same id as the instruction (in SSA the
    /// instruction *is* the value).
    pub values: Arena<ValueId, LiftedValue>,
}

/// One basic block in the lifted CFG.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct LiftedBlock {
    /// Identifier of this block within its enclosing function.
    pub id: BlockId,

    /// Block parameters — the SSA representation of phi nodes. When a
    /// predecessor branches to this block via a [`BlockTarget`], its
    /// arguments are bound positionally to these parameter ids.
    pub params: Vec<ValueId>,

    /// Instructions in execution order. Each id refers to a definition
    /// in the enclosing function's `values` arena.
    pub instructions: Vec<ValueId>,

    /// How the block exits.
    pub terminator: LiftedTerminator,
}

/// One SSA value (the result of an instruction, or a parameter).
///
/// The value's identifier is *implicit*: this struct lives in
/// [`LiftedFunction::values`] keyed by its [`ValueId`], so duplicating the
/// id inside the struct would be redundant. To recover the id when
/// iterating, use `function.values.iter()` which yields `(ValueId, &LiftedValue)`.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct LiftedValue {
    /// What this value is.
    pub def: LiftedValueDef,

    /// WASM types produced by this value. Most operators produce zero or
    /// one types; multi-result operators (multi-value WASM) produce
    /// multiple. The vector is empty for a non-producing instruction
    /// such as `Store`.
    pub types: Vec<LiftedType>,
}

/// Origin of a [`LiftedValue`].
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub enum LiftedValueDef {
    /// Result of a WASM operator with its operand value ids.
    ///
    /// Operands are listed positionally; pattern-match on the [`WasmOp`]
    /// to know how many to expect for a given opcode.
    Operator {
        /// The operator itself.
        op: WasmOp,
        /// Operand SSA values, in WASM stack-popped order.
        args: Vec<ValueId>,
    },

    /// Block parameter (the SSA encoding of a phi node).
    ///
    /// The `index` is the position of this parameter in the block's
    /// `params` list; the actual values flowing into it come from each
    /// predecessor's [`crate::lifted::BlockTarget::args`].
    BlockParam {
        /// Block this parameter belongs to.
        block: BlockId,
        /// Position within the block's parameter list.
        index: u32,
    },

    /// Multi-result projection: pick one output of a multi-result operator.
    ///
    /// `from` produced multiple result types; this value selects index
    /// `index` of those.
    PickOutput {
        /// Source value with multiple results.
        from: ValueId,
        /// Which output to select (zero-based).
        index: u32,
    },

    /// Alias for another value. Used by waffle for transparent indirection;
    /// most passes can resolve aliases via [`crate::lifted::LiftedFunction::values`]
    /// before doing semantic work.
    Alias(ValueId),
}

/// WASM-level numeric type of a [`LiftedValue`].
///
/// We deliberately do not collapse this into [`crate::PrimitiveType`]:
/// the lifted layer reflects WASM's type system (`i32`/`i64`/`f32`/`f64`/`v128`,
/// plus references), not Soroban's richer Val-tagged hierarchy. The
/// [`crate::HighIr`] is where we lift to Soroban semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum LiftedType {
    /// 32-bit integer.
    I32,
    /// 64-bit integer.
    I64,
    /// 32-bit float.
    F32,
    /// 64-bit float.
    F64,
    /// 128-bit SIMD vector.
    V128,
    /// Function reference.
    FuncRef,
    /// External reference (host object handle).
    ExternRef,
}
