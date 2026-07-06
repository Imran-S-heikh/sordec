//! Backward folding of a `ValueId` to a concrete constant literal.
//!
//! This is the foundation primitive every Phase 2 pattern recognizer
//! depends on. Storage-tier resolution needs to find the constant
//! `0`/`1`/`2` fed to `put_contract_data`; cross-contract call typing
//! needs the callee `Address` and function `Symbol`; panic recognition
//! needs the error code fed to `fail_with_error`. All of them ask the
//! same question: "given this `ValueId`, what constant produced it?"
//!
//! ## Semantics
//!
//! [`trace_const`] walks the SSA def-use chain backward from a given
//! [`ValueId`], transparently following `Alias` and `PickOutput` links,
//! until it reaches one of:
//!
//! - A `waffle::Operator::I32Const` / `I64Const` / `F32Const` /
//!   `F64Const` — returns `Ok(Literal::...)`.
//! - A `waffle::Operator::V128Const` — returns
//!   `Err(TraceStop::UnsupportedConstantType)` because [`sordec_ir::Literal`]
//!   has no `V128` variant (SIMD is not used in Soroban contracts).
//! - A `LiftedValueDef::BlockParam` — returns
//!   `Err(TraceStop::BlockParam)` because a phi/argument value depends
//!   on runtime control flow.
//! - Any other operator — returns `Err(TraceStop::NotConstant)` with the
//!   operator's kind category.
//! - Depth or arena-lookup failure — returns
//!   `Err(TraceStop::TooDeep)` / `Err(TraceStop::DanglingValueId)`.
//!
//! ## What this does NOT do
//!
//! - **No arithmetic folding.** `(x << 8) | 42` where `x` is a constant
//!   does not resolve to `(const_val << 8) | 42`. Recognizers that need
//!   arithmetic constant folding (Val bit-packing, symbol short-form
//!   packing) build that on top of `trace_const`.
//! - **No cross-function tracing.** Function arguments (entry block
//!   parameters) terminate the trace with `TraceStop::BlockParam`, not
//!   with a value tracked from the caller.
//! - **No global constant propagation.** WASM `global.get` reads
//!   terminate with `TraceStop::NotConstant` (kind `GlobalGet`).
//! - **No signedness reinterpretation.** `I32Const { value: u32 }` becomes
//!   `Literal::I32(value as i32)`. Callers that want `u32` do the cast
//!   at their site — Rust's `as` conversion between same-width types is
//!   bit-exact.
//!
//! ## Complexity
//!
//! O(chain length). Waffle's SSA converter produces reasonably shallow
//! alias chains in practice; the default [`DEFAULT_MAX_DEPTH`] of `128`
//! is far more than any real Soroban contract exercises.

use sordec_common::{Arena, BlockId, IrId, ValueId};
use sordec_ir::{
    LiftedFunction, LiftedValue, LiftedValueDef, Literal, WasmOp, WasmOpcodeKind,
};

/// Default maximum chase depth for [`trace_const`].
///
/// A defensive bound against SSA-invariant violations (cycles in
/// aliases / PickOutputs). Real waffle-lifted contracts have chains
/// well under this depth. Callers that need a different bound use
/// [`trace_const_with_limit`].
pub const DEFAULT_MAX_DEPTH: u32 = 128;

/// Why a [`trace_const`] call could not resolve to a [`Literal`].
///
/// Each variant is a distinct terminal state; recognizers use the
/// specific variant to decide whether to emit a
/// [`sordec_common::LiftDiagnosticCode`], fall back to a
/// `SemanticOp::Unknown` result, or skip the recognition entirely.
///
/// Not `#[non_exhaustive]` — the five variants are stable data-flow
/// categories. If a new stop reason is needed, that's a semver bump
/// within the `sordec-passes` crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceStop {
    /// Reached a [`LiftedValueDef::BlockParam`] — either a phi node or
    /// a function argument. The value depends on runtime control flow
    /// and cannot be resolved to a single constant. Recognizers
    /// typically translate this into an
    /// `UnknownReason::InsufficientEvidence` if the pattern requires
    /// the arg to be constant.
    BlockParam {
        /// The block owning the phi/argument.
        block: BlockId,
        /// Position within the block's parameter list.
        index: u32,
    },

    /// Reached a [`LiftedValueDef::Operator`] whose operator is not a
    /// `*Const` variant. The `op_kind` field carries the operator's
    /// typed category — useful for diagnostics and for future
    /// arithmetic-folding utilities that might want to fold through
    /// `Arithmetic` / `Bitwise` ops.
    NotConstant {
        /// The operator's kind category. See [`WasmOpcodeKind`].
        op_kind: WasmOpcodeKind,
    },

    /// Reached a [`waffle::Operator::V128Const`] — WASM's 128-bit SIMD
    /// constant. [`Literal`] has no `V128` variant because SIMD is
    /// not used in Soroban contracts. If a real contract ever
    /// exercises this path, add `Literal::V128` and handle here.
    UnsupportedConstantType {
        /// The WASM type name that has no `Literal` landing spot.
        type_name: &'static str,
    },

    /// The `ValueId` referenced does not exist in the function's
    /// arena. Should not occur on well-formed IR (waffle produces a
    /// dense value space); reserved for defensive coding.
    DanglingValueId(ValueId),

    /// Exceeded the chase-depth limit. Guards against SSA-invariant
    /// violations (cycles). Not expected to fire on well-formed IR.
    TooDeep {
        /// The limit that was exceeded.
        limit: u32,
    },
}

/// Backward-fold a `ValueId` to a concrete [`Literal`], using the
/// default depth limit ([`DEFAULT_MAX_DEPTH`]).
///
/// See the module documentation for the operational contract and the
/// list of what this does and does NOT resolve.
///
/// # Errors
///
/// Returns a [`TraceStop`] with the specific terminal state when the
/// trace cannot resolve to a literal.
///
/// # Example
///
/// ```ignore
/// use sordec_passes::dataflow::trace_const;
/// use sordec_ir::Literal;
///
/// // Given a `LiftedFunction` where `v3` is a constant `i32` of value 1
/// // (the Soroban `StorageType::Persistent` discriminant):
/// match trace_const(&func, v3) {
///     Ok(Literal::I32(1)) => { /* recognized as persistent storage */ }
///     Ok(Literal::I32(n)) => { /* recognized, but a different tier */ }
///     Err(stop) => { /* emit a diagnostic or fall back to Unknown */ }
///     _ => { /* unexpected type — recognize as opaque */ }
/// }
/// ```
pub fn trace_const(func: &LiftedFunction, value: ValueId) -> Result<Literal, TraceStop> {
    trace_const_with_limit(func, value, DEFAULT_MAX_DEPTH)
}

/// Backward-fold a `ValueId` to a concrete [`Literal`], with a
/// caller-specified depth limit.
///
/// Use [`trace_const`] unless you have a specific reason to override
/// the default depth. Larger limits cost more on pathological input;
/// smaller limits may fail on legitimate but long alias chains.
///
/// # Errors
///
/// Same as [`trace_const`]. If `max_depth` is exceeded, returns
/// [`TraceStop::TooDeep`] with the limit as its payload.
pub fn trace_const_with_limit(
    func: &LiftedFunction,
    value: ValueId,
    max_depth: u32,
) -> Result<Literal, TraceStop> {
    let values: &Arena<ValueId, LiftedValue> = &func.values;
    let mut current = value;
    let mut depth: u32 = 0;

    loop {
        if depth >= max_depth {
            return Err(TraceStop::TooDeep { limit: max_depth });
        }
        depth += 1;

        // Bounds-check before calling `Arena::get`. In debug builds the
        // arena fires a `debug_assert!` on out-of-bounds ids (before it
        // would return `None` in release), so a naive `.get(...).ok_or`
        // panics under `cargo test`. Checking `index < len` ourselves
        // makes the defensive path uniform across debug and release.
        if (current.index() as usize) >= values.len() {
            return Err(TraceStop::DanglingValueId(current));
        }
        let v = values
            .get(current)
            .ok_or(TraceStop::DanglingValueId(current))?;

        match &v.def {
            // Transparent indirection: keep chasing.
            LiftedValueDef::Alias(target) => {
                current = *target;
            }
            // PickOutput selects one output of a multi-result op. For
            // `*Const` operators there is only one output, so `index`
            // is effectively meaningless; we chase `from` and let the
            // inner logic handle the terminating case.
            LiftedValueDef::PickOutput { from, .. } => {
                current = *from;
            }
            // BlockParam is a phi node (or a function argument on the
            // entry block). Runtime-dependent — trace terminates.
            LiftedValueDef::BlockParam { block, index } => {
                return Err(TraceStop::BlockParam {
                    block: *block,
                    index: *index,
                });
            }
            // Operator: either a `*Const` (success) or something else
            // (typed failure).
            LiftedValueDef::Operator { op, .. } => {
                return classify_operator(op);
            }
        }
    }
}

/// Extract a [`Literal`] from a `*Const` operator, or return the
/// appropriate [`TraceStop`] for anything else.
fn classify_operator(op: &WasmOp) -> Result<Literal, TraceStop> {
    use waffle::Operator as W;
    match &op.0 {
        W::I32Const { value } => Ok(Literal::I32(*value as i32)),
        W::I64Const { value } => Ok(Literal::I64(*value as i64)),
        W::F32Const { value } => Ok(Literal::F32(f32::from_bits(*value))),
        W::F64Const { value } => Ok(Literal::F64(f64::from_bits(*value))),
        W::V128Const { .. } => Err(TraceStop::UnsupportedConstantType {
            type_name: "v128",
        }),
        _ => Err(TraceStop::NotConstant {
            op_kind: op.kind(),
        }),
    }
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_common::{Arena, BlockId, FuncId, IrId, ValueId};
    use sordec_ir::{LiftedBlock, LiftedTerminator, LiftedType};

    /// Build a minimal `LiftedFunction` containing the supplied
    /// `LiftedValueDef`s as consecutive values (indices 0..N).
    ///
    /// The function has one empty block for `entry` validity, but
    /// tests only inspect the values arena.
    fn func_with_values(defs: Vec<LiftedValueDef>) -> LiftedFunction {
        let mut values: Arena<ValueId, LiftedValue> = Arena::new();
        for def in defs {
            values.push(LiftedValue {
                def,
                types: vec![LiftedType::I32],
            });
        }
        let mut blocks: Arena<BlockId, LiftedBlock> = Arena::new();
        let entry = blocks.push(LiftedBlock {
            id: BlockId::from_index(0),
            params: vec![],
            instructions: vec![],
            terminator: LiftedTerminator::Unreachable,
        });
        LiftedFunction {
            id: FuncId::from_index(0),
            entry,
            blocks,
            values,
        }
    }

    fn op(w: waffle::Operator) -> LiftedValueDef {
        LiftedValueDef::Operator {
            op: WasmOp(w),
            args: vec![],
        }
    }

    fn v(idx: u32) -> ValueId {
        ValueId::from_index(idx)
    }

    // --- Direct constants ---

    #[test]
    fn trace_direct_i32_const() {
        let func = func_with_values(vec![op(waffle::Operator::I32Const { value: 42 })]);
        assert_eq!(trace_const(&func, v(0)), Ok(Literal::I32(42)));
    }

    #[test]
    fn trace_direct_i64_const() {
        let func = func_with_values(vec![op(waffle::Operator::I64Const { value: 100 })]);
        assert_eq!(trace_const(&func, v(0)), Ok(Literal::I64(100)));
    }

    #[test]
    fn trace_direct_f32_const() {
        let bits = std::f32::consts::PI.to_bits();
        let func = func_with_values(vec![op(waffle::Operator::F32Const { value: bits })]);
        match trace_const(&func, v(0)) {
            Ok(Literal::F32(x)) => assert!((x - std::f32::consts::PI).abs() < f32::EPSILON),
            other => panic!("expected F32 literal, got {other:?}"),
        }
    }

    #[test]
    fn trace_direct_f64_const() {
        let bits = std::f64::consts::PI.to_bits();
        let func = func_with_values(vec![op(waffle::Operator::F64Const { value: bits })]);
        match trace_const(&func, v(0)) {
            Ok(Literal::F64(x)) => {
                assert!((x - std::f64::consts::PI).abs() < f64::EPSILON);
            }
            other => panic!("expected F64 literal, got {other:?}"),
        }
    }

    #[test]
    fn trace_v128_const_returns_unsupported() {
        let func = func_with_values(vec![op(waffle::Operator::V128Const { value: 0 })]);
        assert_eq!(
            trace_const(&func, v(0)),
            Err(TraceStop::UnsupportedConstantType { type_name: "v128" })
        );
    }

    // --- Transparent indirection ---

    #[test]
    fn trace_through_alias_chain() {
        // v0 = I32Const(42); v1 = Alias(v0); v2 = Alias(v1)
        let func = func_with_values(vec![
            op(waffle::Operator::I32Const { value: 42 }),
            LiftedValueDef::Alias(v(0)),
            LiftedValueDef::Alias(v(1)),
        ]);
        assert_eq!(trace_const(&func, v(2)), Ok(Literal::I32(42)));
    }

    #[test]
    fn trace_through_pick_output() {
        // v0 = I32Const(7); v1 = PickOutput { from: v0, index: 0 }
        let func = func_with_values(vec![
            op(waffle::Operator::I32Const { value: 7 }),
            LiftedValueDef::PickOutput {
                from: v(0),
                index: 0,
            },
        ]);
        assert_eq!(trace_const(&func, v(1)), Ok(Literal::I32(7)));
    }

    // --- Terminal stops ---

    #[test]
    fn trace_block_param_returns_block_param_stop() {
        // v0 = BlockParam { block: bb0, index: 1 }
        let func = func_with_values(vec![LiftedValueDef::BlockParam {
            block: BlockId::from_index(0),
            index: 1,
        }]);
        assert_eq!(
            trace_const(&func, v(0)),
            Err(TraceStop::BlockParam {
                block: BlockId::from_index(0),
                index: 1
            })
        );
    }

    #[test]
    fn trace_non_const_op_returns_not_constant() {
        // v0 = I32Const(1); v1 = I32Const(2); v2 = I32Add(v0, v1)
        // I32Add is not `*Const`, so tracing v2 stops with NotConstant.
        let func = func_with_values(vec![
            op(waffle::Operator::I32Const { value: 1 }),
            op(waffle::Operator::I32Const { value: 2 }),
            LiftedValueDef::Operator {
                op: WasmOp(waffle::Operator::I32Add),
                args: vec![v(0), v(1)],
            },
        ]);
        assert_eq!(
            trace_const(&func, v(2)),
            Err(TraceStop::NotConstant {
                op_kind: WasmOpcodeKind::Arithmetic
            })
        );
    }

    #[test]
    fn trace_dangling_value_id_is_reported() {
        // Empty function — v(0) doesn't exist.
        let func = func_with_values(vec![]);
        assert_eq!(
            trace_const(&func, v(0)),
            Err(TraceStop::DanglingValueId(v(0)))
        );
    }

    #[test]
    fn trace_too_deep_bounded_alias_chain() {
        // Build a chain longer than the limit we'll pass.
        // v0 = I32Const(0); v1 = Alias(v0); v2 = Alias(v1); v3 = Alias(v2);
        // v4 = Alias(v3); v5 = Alias(v4).
        // With max_depth=4, chase from v5 exceeds the limit.
        let mut defs = vec![op(waffle::Operator::I32Const { value: 0 })];
        for i in 0..5 {
            defs.push(LiftedValueDef::Alias(v(i)));
        }
        let func = func_with_values(defs);
        assert_eq!(
            trace_const_with_limit(&func, v(5), 4),
            Err(TraceStop::TooDeep { limit: 4 })
        );
    }

    // --- Boundary behaviour ---

    #[test]
    fn trace_at_exactly_max_depth_succeeds() {
        // Boundary semantics: a trace that needs exactly `max_depth`
        // arena lookups succeeds; one more lookup fails with TooDeep.
        //
        // v0 = I32Const(99); v1 = Alias(v0); v2 = Alias(v1).
        // Chasing from v2 takes 3 lookups (v2, v1, v0), so
        // max_depth = 3 succeeds and max_depth = 2 fails.
        let defs = vec![
            op(waffle::Operator::I32Const { value: 99 }),
            LiftedValueDef::Alias(v(0)),
            LiftedValueDef::Alias(v(1)),
        ];
        let func = func_with_values(defs);
        assert_eq!(trace_const_with_limit(&func, v(2), 3), Ok(Literal::I32(99)));
        assert_eq!(
            trace_const_with_limit(&func, v(2), 2),
            Err(TraceStop::TooDeep { limit: 2 })
        );
    }
}
