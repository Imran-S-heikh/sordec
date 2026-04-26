//! High-level expression syntax for [`crate::Binding`]s.
//!
//! [`Expr`] is what gets emitted as Rust code by the backend. Every
//! [`crate::Binding`] has exactly one. Pattern matchers in `sordec-passes`
//! progressively replace lower-level [`Expr::WasmOp`] / [`Expr::Load`]
//! variants with the richer [`Expr::Semantic`] when they recognise a
//! pattern.

use sordec_common::{FuncId, UnknownReason, ValueId};

use crate::lifted::WasmOpcodeKind;

use super::semantic::SemanticOp;
use super::ty::IrType;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// One expression in the high IR.
///
/// The variants are ordered roughly from most-recovered (top) to
/// least-recovered (bottom). Passes refine bindings by replacing lower
/// variants with higher ones; the [`Unknown`](Expr::Unknown) variant is
/// the honest "we couldn't figure this out" fallback.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Expr {
    /// Recovered Soroban semantic operation. Highest level of recovery.
    Semantic(SemanticOp),

    /// Constant literal of a known type.
    Literal(Literal),

    /// Reference to another binding's value (no transformation).
    Use(ValueId),

    /// Unary operation (negation, bit-not, count-leading-zeros, etc.).
    Unary {
        /// Which unary operation.
        op: UnaryOp,
        /// Operand.
        value: ValueId,
    },

    /// Binary operation (add, sub, eq, lt, etc.).
    Binary {
        /// Which binary operation.
        op: BinaryOp,
        /// Left-hand operand.
        lhs: ValueId,
        /// Right-hand operand.
        rhs: ValueId,
    },

    /// Direct call to a local function (not a host call).
    Call {
        /// Target function in the same module.
        target: FuncId,
        /// Argument values.
        args: Vec<ValueId>,
    },

    /// Indirect call via WASM table.
    IndirectCall {
        /// Function table index.
        table: u32,
        /// Type signature index in the WASM type section.
        sig: u32,
        /// SSA value selecting the function index in the table.
        callee: ValueId,
        /// Argument values.
        args: Vec<ValueId>,
    },

    /// Phi node (block parameter that takes a value from each predecessor).
    /// In structured IR these are usually erased into let-bindings; this
    /// variant survives only when structuring fails for some reason.
    Phi {
        /// Predecessor → value mapping.
        ///
        /// Each entry is `(predecessor block, value flowing in)`. Stored
        /// flat as a vector to preserve insertion order (which mirrors
        /// the WASM CFG iteration order).
        incoming: Vec<(sordec_common::BlockId, ValueId)>,
    },

    /// Read a global variable.
    GlobalGet {
        /// WASM global index.
        index: u32,
    },

    /// Memory load (raw, not yet collapsed into something semantic).
    Load {
        /// Address operand.
        addr: ValueId,
        /// Memory offset baked into the load instruction.
        offset: u32,
        /// Inferred or known result type.
        ty: IrType,
    },

    /// Memory store (raw, not yet collapsed).
    Store {
        /// Address operand.
        addr: ValueId,
        /// Value being stored.
        value: ValueId,
        /// Memory offset baked into the store instruction.
        offset: u32,
    },

    /// Unrecovered WASM operation. The opcode kind is preserved so the
    /// emit step can render `// UNRECOVERED: <kind>` instead of silently
    /// guessing.
    Unknown {
        /// Best categorisation of the underlying WASM operator.
        op_kind: WasmOpcodeKind,
        /// Argument values to the original operator.
        args: Vec<ValueId>,
        /// Why we couldn't recover this expression.
        reason: UnknownReason,
    },
}

/// Constant value of a known Soroban type.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Literal {
    /// `i32` constant.
    I32(i32),
    /// `i64` constant.
    I64(i64),
    /// `u32` constant.
    U32(u32),
    /// `u64` constant.
    U64(u64),
    /// `f32` constant.
    F32(f32),
    /// `f64` constant.
    F64(f64),
    /// Boolean constant.
    Bool(bool),
    /// Symbol literal (short Soroban symbol).
    // JUSTIFY: Symbol contents are arbitrary user-supplied identifiers.
    Symbol(String),
    /// String literal.
    // JUSTIFY: String contents are arbitrary.
    String(String),
    /// Byte literal.
    Bytes(Vec<u8>),
    /// Unit `()`.
    Unit,
}

/// Unary operations after recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum UnaryOp {
    /// Arithmetic negation.
    Neg,
    /// Logical NOT (boolean).
    Not,
    /// Bitwise NOT.
    BitNot,
    /// Count leading zeros.
    Clz,
    /// Count trailing zeros.
    Ctz,
    /// Population count.
    Popcnt,
    /// Absolute value (float).
    Abs,
    /// Square root.
    Sqrt,
    /// Floor.
    Floor,
    /// Ceiling.
    Ceil,
    /// Truncation toward zero.
    Trunc,
}

/// Binary operations after recovery.
///
/// Sign and bit-width are erased from these names; the result and
/// operand types on the surrounding [`crate::Binding`] preserve that
/// information. This avoids `AddU32`/`AddI32`/`AddU64`/... duplication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum BinaryOp {
    /// Addition.
    Add,
    /// Subtraction.
    Sub,
    /// Multiplication.
    Mul,
    /// Division.
    Div,
    /// Remainder.
    Rem,
    /// Bitwise AND.
    BitAnd,
    /// Bitwise OR.
    BitOr,
    /// Bitwise XOR.
    BitXor,
    /// Logical shift left.
    Shl,
    /// Arithmetic / logical shift right (sign captured by surrounding type).
    Shr,
    /// Rotate left.
    Rotl,
    /// Rotate right.
    Rotr,
    /// Equality.
    Eq,
    /// Inequality.
    Ne,
    /// Less-than.
    Lt,
    /// Less-than-or-equal.
    Le,
    /// Greater-than.
    Gt,
    /// Greater-than-or-equal.
    Ge,
}
