//! High-level expression syntax for [`crate::Binding`]s.
//!
//! [`Expr`] is what gets emitted as Rust code by the backend. Every
//! [`crate::Binding`] has exactly one. Pattern matchers in `sordec-passes`
//! progressively replace lower-level [`Expr::Unknown`] / [`Expr::Load`]
//! expressions with recovered semantic operations (`KnownOp`) when they
//! recognise a pattern.

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

    /// A 128-bit integer assembled from its two 64-bit limbs.
    ///
    /// WASM has no 128-bit value type, so rustc carries every `i128` as a
    /// pair of `i64`s: two parameters, two return slots, two stores. The
    /// source wrote one value. This node is that value — the point where
    /// the pipeline stops reasoning about limbs and starts reasoning about
    /// the integer the contract's author named.
    ///
    /// Its inverse is [`UnaryOp::WideLo`] / [`UnaryOp::WideHi`], and the
    /// two cancel: a join of the limbs of `x` *is* `x`, which is the
    /// identity that lets a decoded `amount` flow through arithmetic and
    /// back into an encode without a single limb surviving to the output.
    /// The type on the binding says whether it is `i128` or `u128`; the
    /// limbs are the same bits either way.
    WideJoin {
        /// Low 64 bits.
        lo: ValueId,
        /// High 64 bits.
        hi: ValueId,
    },

    /// One named field of a recovered `#[contracttype]` struct value,
    /// rendered `base.field`.
    ///
    /// The derived `TryFromVal` unpacks a struct into frame slots and
    /// reads each back; once the struct is named, a slot read *is* the
    /// field. The base carries the struct type on its binding, and the
    /// field's own type comes from the declaration, so no further
    /// inference is needed for either.
    Field {
        /// The struct value.
        base: ValueId,
        /// Field name as declared.
        // JUSTIFY: field names come from the contract's own spec.
        field: String,
    },

    /// A `#[contracttype]` struct built field by field — the construction
    /// side of [`Expr::Field`]. The struct itself is named by the
    /// binding's type, so only the field values live here.
    Struct {
        /// Field values in declaration order, by field name.
        // JUSTIFY: field names come from the contract's own spec.
        fields: Vec<(String, ValueId)>,
    },

    /// A value chosen between two, by a condition — what the source
    /// wrote as an `if`/`else` expression and the compiler computed both
    /// arms of.
    ///
    /// Distinct from a [`Region::If`](crate::Region::If) with a merge:
    /// there is no branch here, and there was none in the wasm either —
    /// LLVM picks with `select` when both arms are cheap. Recovering the
    /// choice as an expression says what the source said without
    /// claiming a control-flow edge the binary does not have.
    Select {
        /// The condition, a boolean.
        cond: ValueId,
        /// The value taken when the condition holds.
        if_true: ValueId,
        /// The value taken otherwise.
        if_false: ValueId,
    },

    /// One variant of a `#[contracttype]` enum, named. The enum is named
    /// by the binding's type, as for [`Expr::Struct`], so a variant of a
    /// type the registry cannot name has nothing to print.
    Variant {
        /// Variant name as declared.
        // JUSTIFY: variant names come from the contract's own spec.
        name: String,
        /// The values the variant carries, in declaration order: empty
        /// for a unit variant, `[a, b]` for `Name(a, b)`.
        payload: Vec<ValueId>,
    },

    /// Payload component `index` of variant `variant` of the enum value
    /// `value` — the name a `match` arm's pattern binds: `p` in
    /// `E::X(p) => ..`.
    ///
    /// Rust has no expression for "the payload of `v`'s variant `X`"
    /// outside a pattern, so this value is legal only where the pattern
    /// binds it: scheduled at the start of the first block of an arm of a
    /// [`Region::Switch`](crate::Region::Switch) whose `index` and
    /// `dispatch` are both `value` (a switch on the variant of `value`),
    /// in the arm whose one case is `variant`'s position among the enum's
    /// declared cases. The emitter prints that switch as
    /// `match value { E::X(p0, ..) => .. }` and this binding as the
    /// pattern's `p<index>`. Passes that do not know it treat it as an
    /// opaque, pure value.
    ///
    /// The first step of a general pattern match: this is the binding a
    /// pattern introduces, and the switch on `value` is a `match` without
    /// nested patterns.
    VariantPayload {
        /// The enum value whose variant the enclosing switch selects.
        value: ValueId,
        /// Variant name as declared.
        // JUSTIFY: variant names come from the contract's own spec.
        variant: String,
        /// Zero-based payload component: `0` for `X(p)`, `1` for the
        /// second of `X(a, b)`.
        index: u32,
    },

    /// `width` bytes of a `[u8; N]` value read as one little-endian
    /// integer, starting at byte `offset` — what a wasm load of those
    /// bytes reads, once the frame slots it read are known to hold the
    /// array. Renders `i64::from_le_bytes(a[o..o + 8].try_into().unwrap())`
    /// for a full word, `a[o]` for one byte, with the load's own sign or
    /// zero extension to the binding's word.
    ///
    /// Pure: the array is a value, and `offset + width` never passes its
    /// length (the pass that builds this proves the read inside it).
    ArrayRead {
        /// The `[u8; N]` value.
        array: ValueId,
        /// First byte read.
        offset: u32,
        /// How many bytes, as the load that read them.
        width: MemWidth,
        /// The load's extension: `Some(true)` sign, `Some(false)` zero,
        /// `None` for a full-word read.
        signed: Option<bool>,
    },

    /// Direct call to a local function (not a host call).
    Call {
        /// Target function in the same module.
        target: FuncId,
        /// Argument values.
        args: Vec<ValueId>,
    },

    /// One component of a multi-value producer, rendered `value.index`.
    ///
    /// WASM has no multi-value return in the shape rustc needs, so a
    /// function returning anything wider than a machine word takes a
    /// pointer to caller-allocated space and writes through it. Recovering
    /// that as what the source wrote — a function *returning* a wide value
    /// — means the call yields several values at once, and each consumer
    /// needs to name the one it wants.
    ///
    /// Deliberately a projection rather than a destructuring `let`: the
    /// body walk emits exactly one `let` per binding, and a pattern-binding
    /// statement would be a second shape for the emitter to carry. `let t =
    /// f(x); let a = t.0; let b = t.1;` fits the existing model, and the
    /// dead-`let` pass removes whichever components go unread.
    Project {
        /// The multi-value producer.
        value: ValueId,
        /// Zero-based component index.
        index: u32,
    },

    /// `Some(..)` or `None`: the `Option` a helper hands back, once the
    /// out-parameter it was compiled to write is recovered as the sum type
    /// the source returned. One payload component renders `Some(x)`,
    /// several `Some((a, b, ..))`.
    Optional {
        /// The value's components; `None` for the absent variant.
        payload: Option<Vec<ValueId>>,
    },

    /// A tuple built from its components: `(a, b, c)`. A Soroban tuple's
    /// wire form is a `Vec` of the encoded components, so the SDK builds
    /// one where the source wrote a tuple; this is that `Vec` recovered as
    /// what was written, once the declared ABI says the value is a tuple.
    Tuple {
        /// The components, in order, each the value before its encode.
        items: Vec<ValueId>,
    },

    /// Whether an `Option` holds a value: `r.is_some()`.
    IsSome {
        /// The `Option`.
        value: ValueId,
    },

    /// Component `index` of an `Option` proven present: `r.unwrap()`, or
    /// `r.unwrap().N` for a payload of several components. Placed only
    /// where a test on the same `Option` proves it present, so it never
    /// traps.
    Unwrap {
        /// The `Option`.
        value: ValueId,
        /// Zero-based payload component.
        index: u32,
        /// How many components the payload has.
        arity: u32,
    },

    /// The value of a one-component `Option`, or `default` when it holds
    /// none: `r.unwrap_or(default)`. What a choice between the payload and
    /// a fallback, made on the `Option`'s own tag, says.
    UnwrapOr {
        /// The `Option`.
        value: ValueId,
        /// The value taken when the `Option` is `None`.
        default: ValueId,
    },

    /// Whether a `Result` holds an error: `r.is_err()`. What a test of the
    /// tag word rustc keeps for the `Result` says.
    IsErr {
        /// The `Result`.
        value: ValueId,
    },

    /// The discriminant of a `Result`'s error, proven present:
    /// `r.unwrap_err() as u32`. The error is a `#[repr(u32)]` enum (a
    /// `#[contracterror]`), so this is the word rustc keeps beside the tag
    /// on the `Err` side. Placed only where a test on the same `Result`
    /// proves it an error, so it never traps.
    ErrCode {
        /// The `Result`.
        value: ValueId,
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
    /// Phis survive in the high IR by design: structured regions spell
    /// per-edge value flow as [`crate::PhiTransfer`] assignments that
    /// reference these bindings, and the emit layer later materializes
    /// them as mutable locals (one assignment per transfer pair).
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
        /// Access width in bytes, preserved from the WASM opcode
        /// (`i64.load` = 8, `i64.load32_u` = 4, …). Store→load
        /// forwarding is only sound when widths match exactly.
        width: MemWidth,
        /// Sign extension for sub-word loads (`load8_s` vs `load8_u`).
        /// `None` for full-width loads, which have no extension.
        signed: Option<bool>,
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
        /// Access width in bytes, preserved from the WASM opcode
        /// (`i64.store` = 8, `i64.store32` = 4, …). Determines exactly
        /// which bytes the store writes.
        width: MemWidth,
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

impl Expr {
    /// Visit every [`ValueId`] this expression **reads**, in field
    /// declaration order. [`Expr::Semantic`] delegates to
    /// [`super::semantic::KnownOp::for_each_value_use`]; a
    /// [`Expr::Phi`]'s incoming values count as reads (they flow in at
    /// predecessor edges).
    ///
    /// Same drift rule as the `KnownOp` visitor: every variant is
    /// destructured without a `..` rest pattern, so a new field or
    /// variant fails to compile here instead of silently under-counting
    /// uses.
    pub fn for_each_value_use<F: FnMut(ValueId)>(&self, mut f: F) {
        match self {
            Expr::Semantic(SemanticOp::Known(op)) => op.for_each_value_use(f),
            Expr::Semantic(SemanticOp::Unknown {
                host_module: _,
                host_fn: _,
                reason: _,
                args,
            }) => {
                for &value in args {
                    f(value);
                }
            }
            Expr::Literal(_) => {}
            Expr::Use(value) => f(*value),
            Expr::Unary { op: _, value } => f(*value),
            Expr::Binary { op: _, lhs, rhs } => {
                f(*lhs);
                f(*rhs);
            }
            Expr::Call { target: _, args } => {
                for &value in args {
                    f(value);
                }
            }
            Expr::Project { value, index: _ } => f(*value),
            Expr::Optional { payload } => {
                for &value in payload.iter().flatten() {
                    f(value);
                }
            }
            Expr::Tuple { items } => {
                for &value in items {
                    f(value);
                }
            }
            Expr::IsSome { value } | Expr::Unwrap { value, .. } | Expr::IsErr { value } | Expr::ErrCode { value } => {
                f(*value)
            }
            Expr::UnwrapOr { value, default } => {
                f(*value);
                f(*default);
            }
            Expr::WideJoin { lo, hi } => {
                f(*lo);
                f(*hi);
            }
            Expr::Field { base, field: _ } => f(*base),
            Expr::Struct { fields } => {
                for (_, value) in fields {
                    f(*value);
                }
            }
            Expr::Select { cond, if_true, if_false } => {
                f(*cond);
                f(*if_true);
                f(*if_false);
            }
            Expr::Variant { name: _, payload } => {
                for &value in payload {
                    f(value);
                }
            }
            Expr::VariantPayload { value, variant: _, index: _ } => f(*value),
            Expr::ArrayRead { array, offset: _, width: _, signed: _ } => f(*array),
            Expr::IndirectCall {
                table: _,
                sig: _,
                callee,
                args,
            } => {
                f(*callee);
                for &value in args {
                    f(value);
                }
            }
            Expr::Phi { incoming } => {
                for &(_block, value) in incoming {
                    f(value);
                }
            }
            Expr::GlobalGet { index: _ } => {}
            Expr::Load {
                addr,
                offset: _,
                width: _,
                signed: _,
                ty: _,
            } => f(*addr),
            Expr::Store {
                addr,
                value,
                offset: _,
                width: _,
            } => {
                f(*addr);
                f(*value);
            }
            Expr::Unknown {
                op_kind: _,
                args,
                reason: _,
            } => {
                for &value in args {
                    f(value);
                }
            }
        }
    }
}

impl Expr {
    /// Visit every [`ValueId`] this expression reads, mutably — the same
    /// walk as [`Self::for_each_value_use`], for renaming operands when a
    /// binding is copied from one function into another.
    pub fn for_each_value_use_mut<F: FnMut(&mut ValueId)>(&mut self, mut f: F) {
        match self {
            Expr::Semantic(SemanticOp::Known(op)) => op.for_each_value_use_mut(f),
            Expr::Semantic(SemanticOp::Unknown {
                host_module: _,
                host_fn: _,
                reason: _,
                args,
            }) => {
                for value in args {
                    f(value);
                }
            }
            Expr::Literal(_) => {}
            Expr::Use(value) => f(value),
            Expr::Struct { fields } => {
                for (_, value) in fields {
                    f(value);
                }
            }
            Expr::Select { cond, if_true, if_false } => {
                f(cond);
                f(if_true);
                f(if_false);
            }
            Expr::Variant { name: _, payload } => {
                for value in payload {
                    f(value);
                }
            }
            Expr::VariantPayload { value, variant: _, index: _ } => f(value),
            Expr::ArrayRead { array, offset: _, width: _, signed: _ } => f(array),
            Expr::Unary { op: _, value } => f(value),
            Expr::Binary { op: _, lhs, rhs } => {
                f(lhs);
                f(rhs);
            }
            Expr::Call { target: _, args } => {
                for value in args {
                    f(value);
                }
            }
            Expr::Project { value, index: _ } => f(value),
            Expr::Optional { payload } => {
                for value in payload.iter_mut().flatten() {
                    f(value);
                }
            }
            Expr::Tuple { items } => {
                for value in items {
                    f(value);
                }
            }
            Expr::IsSome { value } | Expr::Unwrap { value, .. } | Expr::IsErr { value } | Expr::ErrCode { value } => {
                f(value)
            }
            Expr::UnwrapOr { value, default } => {
                f(value);
                f(default);
            }
            Expr::WideJoin { lo, hi } => {
                f(lo);
                f(hi);
            }
            Expr::Field { base, field: _ } => f(base),
            Expr::IndirectCall {
                table: _,
                sig: _,
                callee,
                args,
            } => {
                f(callee);
                for value in args {
                    f(value);
                }
            }
            Expr::Phi { incoming } => {
                for (_block, value) in incoming {
                    f(value);
                }
            }
            Expr::GlobalGet { index: _ } => {}
            Expr::Load {
                addr,
                offset: _,
                width: _,
                signed: _,
                ty: _,
            } => f(addr),
            Expr::Store {
                addr,
                value,
                offset: _,
                width: _,
            } => {
                f(addr);
                f(value);
            }
            Expr::Unknown {
                op_kind: _,
                args,
                reason: _,
            } => {
                for value in args {
                    f(value);
                }
            }
        }
    }
}

/// Byte width of a raw memory access, preserved from the WASM opcode.
///
/// The lowering previously collapsed all 14 load / 9 store forms into
/// width-less [`Expr::Load`] / [`Expr::Store`], erasing which bytes an
/// access touches (`i64.store` vs `i64.store8` were indistinguishable).
/// Analyses that reason about memory — store→load forwarding in
/// particular — need the exact byte range, so the width is a permanent
/// fact on the expression, not something to re-infer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum MemWidth {
    /// 1 byte (`load8` / `store8`).
    W1,
    /// 2 bytes (`load16` / `store16`).
    W2,
    /// 4 bytes (`i32.load`, `f32.load`, `i64.load32`, `i32.store`,
    /// `f32.store`, `i64.store32`).
    W4,
    /// 8 bytes (`i64.load`, `f64.load`, `i64.store`, `f64.store`).
    W8,
}

impl MemWidth {
    /// The access width in bytes.
    #[inline]
    #[must_use]
    pub fn bytes(self) -> u32 {
        match self {
            Self::W1 => 1,
            Self::W2 => 2,
            Self::W4 => 4,
            Self::W8 => 8,
        }
    }
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
    /// WASM `i32.eqz` / `i64.eqz` — "the operand is zero".
    ///
    /// Distinct from [`Not`](Self::Not) because the two are only the same
    /// operation on a boolean. rustc spells both `!flag` and `n == 0` as
    /// `eqz`, and which one it meant is a question about the operand's
    /// type, not about the opcode. Keeping the opcode's own identity here
    /// leaves that question to the emitter, which is where the recovered
    /// type is known — rendering `!x` for a `Bool` and `x == 0` otherwise.
    /// Collapsing it into `Not` at lift time would emit Rust's *bitwise*
    /// `!` for every integer operand, which is a different value.
    ///
    /// Unary despite meaning a comparison, so the one-op-to-one-`Expr`
    /// lowering contract holds without minting a zero literal it has no
    /// way to schedule.
    Eqz,
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
    /// Low 64 bits of a 128-bit value, as an `i64`.
    ///
    /// The inverse of [`Expr::WideJoin`]; see there for why the pipeline
    /// wants both directions. Renders as `x as i64`, which truncates.
    WideLo,
    /// High 64 bits of a 128-bit value, as an `i64`.
    ///
    /// Renders as `(x >> 64) as i64`.
    WideHi,
    /// `i32.wrap_i64`: the low 32 bits of a 64-bit integer.
    Wrap32,
    /// `i64.extend_i32_u`: a 32-bit integer zero-extended to 64 bits.
    ExtendU32,
    /// `i64.extend_i32_s`: a 32-bit integer sign-extended to 64 bits.
    ExtendS32,
}

/// Binary operations after recovery.
///
/// Bit-width is erased from these names; the types on the surrounding
/// [`crate::Binding`] carry it, which avoids `AddU32`/`AddI32`/`AddU64`/...
/// duplication. Signedness is not erased, because it is not a property of
/// the operands: `i64.shr_u` and `i64.shr_s` are two different operations
/// on the same bits, and a value's recovered type cannot stand in for the
/// opcode — a `Val` word is an `i64` to the lowering and a `u64` to the
/// shift that extracts its payload. The operators whose result depends on
/// the reading (division, remainder, right shift, the four orderings) come
/// in two: the signed one keeps the short name, the unsigned one ends in
/// `U`. Float operators, which have no sign, use the short name.
/// [`BinaryOp::sign`] says which reading an operator takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum BinaryOp {
    /// Addition.
    Add,
    /// Subtraction.
    Sub,
    /// Multiplication.
    Mul,
    /// Signed division (`div_s`), or a float one.
    Div,
    /// Unsigned division (`div_u`).
    DivU,
    /// Signed remainder (`rem_s`).
    Rem,
    /// Unsigned remainder (`rem_u`).
    RemU,
    /// Bitwise AND.
    BitAnd,
    /// Bitwise OR.
    BitOr,
    /// Bitwise XOR.
    BitXor,
    /// Shift left.
    Shl,
    /// Arithmetic shift right (`shr_s`): the sign bit fills in from the left.
    Shr,
    /// Logical shift right (`shr_u`): zeros fill in from the left.
    ShrU,
    /// Rotate left.
    Rotl,
    /// Rotate right.
    Rotr,
    /// Equality.
    Eq,
    /// Inequality.
    Ne,
    /// Signed less-than (`lt_s`), or a float one.
    Lt,
    /// Unsigned less-than (`lt_u`).
    LtU,
    /// Signed less-than-or-equal (`le_s`), or a float one.
    Le,
    /// Unsigned less-than-or-equal (`le_u`).
    LeU,
    /// Signed greater-than (`gt_s`), or a float one.
    Gt,
    /// Unsigned greater-than (`gt_u`).
    GtU,
    /// Signed greater-than-or-equal (`ge_s`), or a float one.
    Ge,
    /// Unsigned greater-than-or-equal (`ge_u`).
    GeU,
    /// Whether `lhs * rhs` overflows the operands' type — the boolean
    /// rustc tests under `overflow-checks = true` before it lets a
    /// product through.
    ///
    /// For a 128-bit multiply that test is not a comparison the caller
    /// can spell: rustc outlines it into the `__muloti4` runtime helper,
    /// which hands the flag back through a pointer. Recovering the helper
    /// as a plain [`Mul`](Self::Mul) leaves that flag needing a
    /// producer, and this is it. Renders as `lhs.checked_mul(rhs).is_none()`,
    /// which is what the guard around it means; the overflow-guard
    /// elision then removes the guard on the same relocation argument it
    /// uses for the 64-bit carry test, because the re-emitted `*`
    /// regenerates the check.
    MulOverflows,
}

/// How an operator reads its operands' bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Sign {
    /// As two's-complement numbers.
    Signed,
    /// As natural numbers.
    Unsigned,
}

impl BinaryOp {
    /// The reading this operator gives its operands, for the operators
    /// whose result depends on it. `None` for the rest: addition, the
    /// bitwise operators, equality and the others come out the same on
    /// either reading.
    pub fn sign(self) -> Option<Sign> {
        use BinaryOp as B;
        match self {
            B::Div | B::Rem | B::Shr | B::Lt | B::Le | B::Gt | B::Ge => Some(Sign::Signed),
            B::DivU | B::RemU | B::ShrU | B::LtU | B::LeU | B::GtU | B::GeU => Some(Sign::Unsigned),
            B::Add
            | B::Sub
            | B::Mul
            | B::BitAnd
            | B::BitOr
            | B::BitXor
            | B::Shl
            | B::Rotl
            | B::Rotr
            | B::Eq
            | B::Ne
            | B::MulOverflows => None,
        }
    }

    /// The same operator read unsigned; itself when it has no sign.
    pub fn unsigned(self) -> Self {
        use BinaryOp as B;
        match self {
            B::Div => B::DivU,
            B::Rem => B::RemU,
            B::Shr => B::ShrU,
            B::Lt => B::LtU,
            B::Le => B::LeU,
            B::Gt => B::GtU,
            B::Ge => B::GeU,
            other => other,
        }
    }

    /// The same operator read signed; itself when it has no sign.
    pub fn signed(self) -> Self {
        use BinaryOp as B;
        match self {
            B::DivU => B::Div,
            B::RemU => B::Rem,
            B::ShrU => B::Shr,
            B::LtU => B::Lt,
            B::LeU => B::Le,
            B::GtU => B::Gt,
            B::GeU => B::Ge,
            other => other,
        }
    }

    /// Whether this is one of the ten comparisons, which yield a `bool`.
    /// [`MulOverflows`](Self::MulOverflows) yields one too but compares
    /// nothing.
    pub fn is_comparison(self) -> bool {
        matches!(self, BinaryOp::Eq | BinaryOp::Ne) || self.is_ordered()
    }

    /// Whether this orders its operands: `<`, `<=`, `>` or `>=`, on either
    /// reading.
    pub fn is_ordered(self) -> bool {
        use BinaryOp as B;
        matches!(self, B::Lt | B::LtU | B::Le | B::LeU | B::Gt | B::GtU | B::Ge | B::GeU)
    }

    /// The comparison that holds exactly when this one does not, on the
    /// same reading; `None` for a non-comparison.
    pub fn inverted(self) -> Option<Self> {
        use BinaryOp as B;
        Some(match self {
            B::Eq => B::Ne,
            B::Ne => B::Eq,
            B::Lt => B::Ge,
            B::Ge => B::Lt,
            B::Le => B::Gt,
            B::Gt => B::Le,
            B::LtU => B::GeU,
            B::GeU => B::LtU,
            B::LeU => B::GtU,
            B::GtU => B::LeU,
            _ => return None,
        })
    }

    /// This comparison with its operands swapped, on the same reading;
    /// `None` for a non-comparison.
    pub fn flipped(self) -> Option<Self> {
        use BinaryOp as B;
        Some(match self {
            B::Eq | B::Ne => self,
            B::Lt => B::Gt,
            B::Gt => B::Lt,
            B::Le => B::Ge,
            B::Ge => B::Le,
            B::LtU => B::GtU,
            B::GtU => B::LtU,
            B::LeU => B::GeU,
            B::GeU => B::LeU,
            _ => return None,
        })
    }
}
