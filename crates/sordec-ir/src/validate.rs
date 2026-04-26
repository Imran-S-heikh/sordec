//! IR invariant validation.
//!
//! Each IR layer has structural invariants that passes are responsible
//! for preserving. The functions in this module check those invariants;
//! the [`Pipeline`](https://example.invalid)`::run` driver in
//! `sordec-passes` calls them after each pass *in debug builds* via
//! `debug_assert!`, with negligible release-build cost.
//!
//! Validation produces a [`Result`]: a failure-mode struct rather than a
//! panic. This makes the validator usable from a future
//! `ValidationPass` (in CI or under a `--validate` CLI flag) and from
//! tests that want to assert specific failure modes.
//!
//! ## Status
//!
//! For the Phase 1.2 scaffolding, the bodies of [`validate_lifted`] and
//! [`validate_high`] return `Ok(())` and document the invariants they
//! will enforce in `// TODO(phase-1.3):` comments. Locking the API in
//! place now means Pass authors in 1.3+ get validation hooks for free.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{HighIr, LiftedIr};

/// Validation contract implemented by every IR layer.
///
/// Implementing this trait lets the pass-manager hook validation
/// generically:
///
/// ```ignore
/// // In sordec-passes::Pipeline (added in Task 1.3):
/// for pass in &self.passes {
///     pass.run(ir);
///     debug_assert!(ir.validate().is_ok(), "pass {} broke an invariant", pass.name());
/// }
/// ```
pub trait Validate {
    /// Run all invariant checks. `Ok(())` if every invariant holds.
    fn validate(&self) -> Result<(), ValidateError>;
}

impl Validate for LiftedIr {
    #[inline]
    fn validate(&self) -> Result<(), ValidateError> {
        validate_lifted(self)
    }
}

impl Validate for HighIr {
    #[inline]
    fn validate(&self) -> Result<(), ValidateError> {
        validate_high(self)
    }
}

/// Validate every invariant of a [`LiftedIr`].
///
/// Currently a stub returning `Ok(())`. The invariants this function
/// will enforce in Phase 1.3:
///
/// - Every [`crate::LiftedBlock`] in every function has exactly one
///   terminator (encoded by the struct, but the validator should assert
///   no `LiftedTerminator::Unreachable` is produced where a real exit
///   was expected).
/// - Every [`sordec_common::ValueId`] referenced (from instructions,
///   block params, terminator args) has a definition in the enclosing
///   function's `values` arena.
/// - Every [`sordec_common::BlockId`] in a terminator's targets refers
///   to a block that exists in the same function.
/// - The CFG entry block is reachable (trivially) and at least one
///   `Return` or `Unreachable` terminator dominates every other block.
///
/// Once these checks are implemented, the
/// [`Pipeline`](https://example.invalid) driver will call this after
/// every lifted-IR pass; failure aborts the pipeline with a diagnostic.
pub fn validate_lifted(_ir: &LiftedIr) -> Result<(), ValidateError> {
    // TODO(phase-1.3): implement the four invariants documented above.
    Ok(())
}

/// Validate every invariant of a [`HighIr`].
///
/// Currently a stub returning `Ok(())`. The invariants this function
/// will enforce in Phase 1.3:
///
/// - All control flow is structured: every reachable block is referenced
///   from the function's [`crate::Region`] tree.
/// - Every binding's `provenance` vector is non-empty (the constructor
///   enforces this on creation, but in-place mutation could violate
///   it).
/// - Every `Unknown` variant in [`crate::IrType`], [`crate::SemanticOp`],
///   and [`crate::StorageTier`] carries an [`sordec_common::UnknownReason`]
///   (encoded by the type, but the validator should still assert the
///   payload is meaningful, not a placeholder).
/// - Every [`sordec_common::ValueId`] referenced from a region or
///   binding has a definition in the enclosing function's `bindings`
///   arena.
pub fn validate_high(_ir: &HighIr) -> Result<(), ValidateError> {
    // TODO(phase-1.3): implement the four invariants documented above.
    Ok(())
}

/// Reason a [`Validate::validate`] call failed.
///
/// `#[non_exhaustive]` so additional structural checks can land in
/// future passes without breaking downstream matchers.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ValidateError {
    /// A `ValueId` was referenced but no binding for it exists in the
    /// enclosing function.
    DanglingValue {
        /// Function in which the dangling reference appears.
        function: sordec_common::FuncId,
        /// The unresolved value id.
        value: sordec_common::ValueId,
    },

    /// A `BlockId` was referenced but no block for it exists.
    DanglingBlock {
        /// Function in which the dangling reference appears.
        function: sordec_common::FuncId,
        /// The unresolved block id.
        block: sordec_common::BlockId,
    },

    /// A binding had an empty `provenance` vector, violating the
    /// non-empty invariant.
    EmptyProvenance {
        /// Function containing the offending binding.
        function: sordec_common::FuncId,
        /// The binding's value id.
        value: sordec_common::ValueId,
    },

    /// Some IR-layer-specific invariant failed; the message describes which.
    /// Used as a catch-all while the validator is being fleshed out.
    // JUSTIFY: free-form diagnostic; not load-bearing logic.
    Other(String),
}
