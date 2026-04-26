//! Lowering steps between IR layers.
//!
//! A "lowering" converts IR from one layer to another (typically
//! [`sordec_ir::LiftedIr`] → [`sordec_ir::HighIr`]). Lowerings are
//! **not** [`crate::Pass`]es because they produce a different output
//! type than they consume; they cannot fit a `&mut Ir` signature.
//!
//! Each lowering runs exactly once at a phase boundary in the
//! [`Driver`](https://example.invalid). Implementations consume their
//! input by value and return the new IR (or an error explaining why the
//! lowering could not be performed).

/// Phase-boundary IR transformation.
///
/// Implemented by, for example, the `LiftedIr → HighIr` lowering that
/// runs after all lifted-IR passes complete. The `Input` and `Output`
/// associated types make the boundary explicit in the type system: the
/// driver cannot accidentally feed a `LiftedIr` to a high-IR
/// lowering.
pub trait LoweringStep {
    /// IR layer this step consumes.
    type Input;
    /// IR layer this step produces.
    type Output;

    /// Compile-time name of the lowering step (used in diagnostics).
    fn name(&self) -> &'static str;

    /// Perform the lowering. Consumes `input` by value; the input layer
    /// is no longer needed after the boundary.
    fn lower(&self, input: Self::Input) -> Result<Self::Output, LoweringError>;
}

/// Reason a lowering step failed.
///
/// `#[non_exhaustive]` so additional failure modes can land without
/// breaking downstream matchers.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoweringError {
    /// The input IR violates a structural assumption the lowering
    /// makes (e.g. a phi node references a non-existent block).
    StructuralMismatch {
        /// Lowering that detected the problem.
        step: &'static str,
        /// Human-readable description.
        // JUSTIFY: free-form diagnostic, not load-bearing logic.
        details: String,
    },

    /// The lowering encountered an IR construct it does not yet know
    /// how to handle. Reserved for partial-implementation states; a
    /// production-ready lowering should never produce this.
    Unsupported {
        /// Lowering that gave up.
        step: &'static str,
        /// What it could not handle.
        // JUSTIFY: free-form diagnostic.
        details: String,
    },
}
