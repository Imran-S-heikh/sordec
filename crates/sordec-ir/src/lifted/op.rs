//! WASM operator wrapper for sordec.
//!
//! The decompiler does not maintain its own enumeration of every WASM
//! opcode (there are seventy-plus). Instead, [`WasmOp`] is a thin newtype
//! around [`waffle::Operator`], with sordec owning two contributions:
//!
//! 1. [`WasmOpcodeKind`] — a non-exhaustive view enum that groups
//!    operators into the categories sordec passes actually care about
//!    (constants, calls, loads, etc.).
//! 2. A `Display` implementation we control, plus a serde `Serialize`
//!    impl that preserves the operator for inspection in JSON dumps.
//!
//! The legacy decompiler's `format!("{op:?}").split(...)` opcode-name
//! extraction is precisely the anti-pattern this module is designed to
//! prevent. **Never** parse the `Debug` output of [`WasmOp`] to derive
//! semantic meaning. Use [`WasmOp::kind`] or pattern-match on the inner
//! [`waffle::Operator`].

use core::fmt;

#[cfg(feature = "serde")]
use serde::{Serialize, Serializer};

/// Newtype wrapping [`waffle::Operator`].
///
/// Owning a wrapper rather than re-exporting `waffle::Operator` directly
/// means a `waffle` upgrade can change opcodes without breaking sordec's
/// public API more than it should: every consumer that wants opcode
/// information goes through [`WasmOp::kind`] or the explicit pattern-match.
#[derive(Debug, Clone, PartialEq)]
pub struct WasmOp(pub waffle::Operator);

impl WasmOp {
    /// Return the broad operator category most sordec passes care about.
    ///
    /// `WasmOpcodeKind` is `#[non_exhaustive]` so additional categories
    /// can be added without breaking matchers that handle the cases they
    /// know. Operators that do not yet fit a defined category fall to
    /// [`WasmOpcodeKind::Other`]; passes that need precise discrimination
    /// (e.g. specific arithmetic ops for Val-encoding pattern matching)
    /// must inspect the inner [`waffle::Operator`] directly.
    #[allow(clippy::too_many_lines)]
    #[must_use]
    pub fn kind(&self) -> WasmOpcodeKind {
        use WasmOpcodeKind as K;
        use waffle::Operator as W;
        match &self.0 {
            // Constants
            W::I32Const { .. } | W::I64Const { .. } | W::F32Const { .. } | W::F64Const { .. } => {
                K::Const
            }

            // Integer arithmetic
            W::I32Add
            | W::I32Sub
            | W::I32Mul
            | W::I32DivS
            | W::I32DivU
            | W::I32RemS
            | W::I32RemU
            | W::I64Add
            | W::I64Sub
            | W::I64Mul
            | W::I64DivS
            | W::I64DivU
            | W::I64RemS
            | W::I64RemU => K::Arithmetic,

            // Float arithmetic
            W::F32Add
            | W::F32Sub
            | W::F32Mul
            | W::F32Div
            | W::F64Add
            | W::F64Sub
            | W::F64Mul
            | W::F64Div => K::Arithmetic,

            // Integer bitwise
            W::I32And
            | W::I32Or
            | W::I32Xor
            | W::I32Shl
            | W::I32ShrS
            | W::I32ShrU
            | W::I32Rotl
            | W::I32Rotr
            | W::I64And
            | W::I64Or
            | W::I64Xor
            | W::I64Shl
            | W::I64ShrS
            | W::I64ShrU
            | W::I64Rotl
            | W::I64Rotr => K::Bitwise,

            // Comparisons (integer + float, including eqz)
            W::I32Eqz
            | W::I64Eqz
            | W::I32Eq
            | W::I32Ne
            | W::I32LtS
            | W::I32LtU
            | W::I32GtS
            | W::I32GtU
            | W::I32LeS
            | W::I32LeU
            | W::I32GeS
            | W::I32GeU
            | W::I64Eq
            | W::I64Ne
            | W::I64LtS
            | W::I64LtU
            | W::I64GtS
            | W::I64GtU
            | W::I64LeS
            | W::I64LeU
            | W::I64GeS
            | W::I64GeU
            | W::F32Eq
            | W::F32Ne
            | W::F32Lt
            | W::F32Gt
            | W::F32Le
            | W::F32Ge
            | W::F64Eq
            | W::F64Ne
            | W::F64Lt
            | W::F64Gt
            | W::F64Le
            | W::F64Ge => K::Comparison,

            // Unary numeric ops
            W::I32Clz
            | W::I32Ctz
            | W::I32Popcnt
            | W::I64Clz
            | W::I64Ctz
            | W::I64Popcnt
            | W::F32Abs
            | W::F32Neg
            | W::F32Sqrt
            | W::F32Ceil
            | W::F32Floor
            | W::F32Trunc
            | W::F32Nearest
            | W::F64Abs
            | W::F64Neg
            | W::F64Sqrt
            | W::F64Ceil
            | W::F64Floor
            | W::F64Trunc
            | W::F64Nearest => K::Unary,

            // Type conversions
            W::I32WrapI64
            | W::I64ExtendI32S
            | W::I64ExtendI32U
            | W::I32TruncF32S
            | W::I32TruncF32U
            | W::I32TruncF64S
            | W::I32TruncF64U
            | W::I64TruncF32S
            | W::I64TruncF32U
            | W::I64TruncF64S
            | W::I64TruncF64U
            | W::F32ConvertI32S
            | W::F32ConvertI32U
            | W::F32ConvertI64S
            | W::F32ConvertI64U
            | W::F64ConvertI32S
            | W::F64ConvertI32U
            | W::F64ConvertI64S
            | W::F64ConvertI64U
            | W::F32DemoteF64
            | W::F64PromoteF32
            | W::I32ReinterpretF32
            | W::I64ReinterpretF64
            | W::F32ReinterpretI32
            | W::F64ReinterpretI64 => K::Conversion,

            // Memory loads
            W::I32Load { .. }
            | W::I64Load { .. }
            | W::F32Load { .. }
            | W::F64Load { .. }
            | W::I32Load8S { .. }
            | W::I32Load8U { .. }
            | W::I32Load16S { .. }
            | W::I32Load16U { .. }
            | W::I64Load8S { .. }
            | W::I64Load8U { .. }
            | W::I64Load16S { .. }
            | W::I64Load16U { .. }
            | W::I64Load32S { .. }
            | W::I64Load32U { .. } => K::Load,

            // Memory stores
            W::I32Store { .. }
            | W::I64Store { .. }
            | W::F32Store { .. }
            | W::F64Store { .. }
            | W::I32Store8 { .. }
            | W::I32Store16 { .. }
            | W::I64Store8 { .. }
            | W::I64Store16 { .. }
            | W::I64Store32 { .. } => K::Store,

            // Bulk memory operations
            W::MemorySize { .. }
            | W::MemoryGrow { .. }
            | W::MemoryCopy { .. }
            | W::MemoryFill { .. } => K::MemoryOp,

            // Globals
            W::GlobalGet { .. } => K::GlobalGet,
            W::GlobalSet { .. } => K::GlobalSet,

            // Calls
            W::Call { .. } => K::Call,
            W::CallIndirect { .. } => K::CallIndirect,

            // Stack
            W::Select | W::TypedSelect { .. } => K::Select,

            // Trap / nop
            W::Unreachable => K::Unreachable,
            W::Nop => K::Nop,

            // Anything else (table ops, reference ops, SIMD, exotic atomics)
            // is bucketed as Other. Passes that care can match the inner
            // operator directly.
            _ => K::Other,
        }
    }
}

/// Display delegates to the inner operator's `Debug` for human inspection.
///
/// **This output is for humans only.** It must never be parsed to extract
/// opcode names or kinds. Use [`WasmOp::kind`] for typed discrimination.
impl fmt::Display for WasmOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

/// Lossy serialisation for inspection only.
///
/// Serialises as the `Debug` representation of the inner [`waffle::Operator`].
/// **No `Deserialize` impl is provided** — round-tripping is intentionally
/// unsupported because the format is not a stable contract. Use this
/// only when dumping IR to JSON for human inspection.
#[cfg(feature = "serde")]
impl Serialize for WasmOp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&format_args!("{:?}", self.0))
    }
}

/// Broad classification of WASM operators.
///
/// `#[non_exhaustive]` so future categories can be added without breaking
/// downstream matchers. Passes that need precise discrimination should
/// match on the inner [`waffle::Operator`] of [`WasmOp`] instead.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum WasmOpcodeKind {
    /// Constant push (e.g. `i32.const`, `i64.const`).
    Const,
    /// Integer or float arithmetic (`add`, `sub`, `mul`, `div`, `rem`).
    Arithmetic,
    /// Integer bitwise operation (`and`, `or`, `xor`, `shl`, `shr`, `rotl`, `rotr`).
    Bitwise,
    /// Numeric comparison (`eq`, `ne`, `lt`, `gt`, `le`, `ge`, `eqz`).
    Comparison,
    /// Unary numeric operation (`clz`, `ctz`, `popcnt`, `abs`, `neg`, etc.).
    Unary,
    /// Numeric type conversion (`wrap`, `extend`, `trunc`, `convert`, `reinterpret`).
    Conversion,
    /// Memory load (`i32.load`, `i64.load`, etc.).
    Load,
    /// Memory store (`i32.store`, `i64.store`, etc.).
    Store,
    /// Bulk memory operation (`memory.size`, `memory.grow`, `memory.copy`, `memory.fill`).
    MemoryOp,
    /// Read a global variable.
    GlobalGet,
    /// Write a global variable.
    GlobalSet,
    /// Direct function call (`call`).
    Call,
    /// Indirect function call (`call_indirect`).
    CallIndirect,
    /// Stack `select` (typed or untyped).
    Select,
    /// Trap-on-execute (`unreachable`).
    Unreachable,
    /// No-op.
    Nop,
    /// Operators not yet categorised by sordec (table, reference, SIMD,
    /// atomics, etc.). Pattern-match on the inner operator for precision.
    Other,
}
