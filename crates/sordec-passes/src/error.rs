//! Error types used across `sordec-passes`.
//!
//! Currently houses [`LiftError`] (for the WASM → [`sordec_ir::LiftedIr`]
//! boundary). Future passes that need their own failure modes can either
//! reuse this pattern or add per-pass error enums alongside it.
//!
//! All variants carry enough context to diagnose without re-running the
//! pipeline. Upstream `anyhow::Error`s from `waffle` are stringified at
//! the boundary so this enum stays stable across `waffle` releases —
//! we do not pull `anyhow` into the public surface.

use sordec_common::FuncId;

/// Failures that can occur during [`crate::lift_with_waffle`].
///
/// Two design notes that govern the variants below:
///
/// 1. After `body.convert_to_max_ssa(None)` followed by
///    `body.recompute_edges()`, neither `ValueDef::Placeholder`,
///    `ValueDef::None`, nor `Terminator::None` should appear. If they
///    do, that is either malformed WASM or a `waffle` bug — both
///    surface as their own variants here so the diagnostic trail is
///    actionable.
/// 2. `LiftError` deliberately uses our typed [`FuncId`] rather than the
///    raw `waffle::Func` index. The lifter's first pass establishes the
///    mapping; every error variant after that point references the
///    sordec-side identifier.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum LiftError {
    /// `waffle::Module::from_wasm_bytes` rejected the input.
    #[error("waffle failed to parse WASM: {0}")]
    WaffleParseFailed(String),

    /// `waffle::Module::expand_all_funcs` failed (or any later
    /// `per_func_body` mutation panicked through `anyhow`).
    #[error("waffle failed to expand function bodies: {0}")]
    WaffleExpandFailed(String),

    /// A function declaration lacked a `Body` after expansion. Should
    /// only happen if the WASM was malformed in a way that nevertheless
    /// passed `wasmparser`.
    #[error("function {func} has no body after expansion")]
    MissingFunctionBody {
        /// Local function identifier whose body was missing.
        func: FuncId,
    },

    /// A basic block emerged from waffle's lifting without a real
    /// terminator (`Terminator::None`). After SSA conversion every
    /// block must end with a real terminator; this would indicate a
    /// `waffle` bug.
    #[error(
        "function {func} block {block_index} has uninitialized terminator after SSA conversion"
    )]
    UninitializedTerminator {
        /// Local function identifier of the offending block.
        func: FuncId,
        /// `waffle::Block::index()` of the offending block.
        block_index: u32,
    },

    /// A SSA value was still in `ValueDef::Placeholder` form after
    /// `convert_to_max_ssa`. Indicates the SSA conversion did not
    /// terminate normally.
    #[error("function {func} value {value_index} is a Placeholder after SSA conversion")]
    PlaceholderValueAfterSsa {
        /// Local function identifier.
        func: FuncId,
        /// `waffle::Value::index()` of the offending value.
        value_index: u32,
    },

    /// A SSA value was still in `ValueDef::None` form after lifting.
    #[error("function {func} value {value_index} is uninitialized after SSA conversion")]
    UninitializedValueAfterSsa {
        /// Local function identifier.
        func: FuncId,
        /// `waffle::Value::index()` of the offending value.
        value_index: u32,
    },

    /// A terminator referenced a block id that does not exist in the
    /// enclosing function. Caught by the post-lift invariant validator.
    #[error(
        "function {func} block {block_index} terminator references unknown block {target_index}"
    )]
    DanglingBlockTarget {
        /// Local function identifier.
        func: FuncId,
        /// Source block whose terminator pointed somewhere bogus.
        block_index: u32,
        /// The dangling target id.
        target_index: u32,
    },

    /// `waffle` produced a non-monotonic value arena (a value index that
    /// does not equal its position in iteration order). Would break our
    /// `Arena::push`-based construction.
    #[error("waffle produced a sparse value arena in function {func}")]
    SparseValueArena {
        /// Local function identifier.
        func: FuncId,
    },

    /// `waffle` produced a `Type` variant we do not know how to map to
    /// our [`sordec_ir::LiftedType`]. The wrapped string carries the
    /// `Display` of the unsupported type for diagnostics.
    #[error("waffle produced an unsupported WASM type: {kind}")]
    UnsupportedWasmType {
        /// `Display` of the offending `waffle::Type` variant.
        kind: String,
    },
}

/// Convenience alias for results returned by the lifter and friends.
pub type LiftResult<T> = Result<T, LiftError>;
