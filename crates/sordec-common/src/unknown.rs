//! Explicit reasons why a piece of IR information could not be determined.
//!
//! Every `Unknown` variant in the IR carries an [`UnknownReason`]. This is
//! the architectural commitment that no information is silently lost or
//! defaulted — see `docs/architecture.md` §3 and §11.
//!
//! ## How to construct
//!
//! Inline the variant at the call site that produces the [`UnknownReason`]:
//!
//! ```
//! use sordec_common::UnknownReason;
//!
//! // Good: the caller can read why this is unknown.
//! let reason = UnknownReason::UnrecognizedHostCall {
//!     module: "x".to_string(),
//!     name: "23".to_string(),
//! };
//!
//! // Avoid: a free helper like `fn unknown_reason() -> UnknownReason { ... }`
//! // hides which pass decided this and why. The variant must appear at the
//! // pass call site, not behind an indirection.
//! # let _ = reason;
//! ```

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Reason an IR field is `Unknown`.
///
/// Every value of an `Unknown` variant in the IR — types, semantic
/// operations, storage tiers — is paired with one of these. Variants are
/// chosen to be useful to a human reading the decompiled output, not
/// merely to satisfy the type system.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum UnknownReason {
    /// The contract's metadata sections did not include this entity.
    NoMetadata,

    /// The host-function table does not recognise this `module::name` pair.
    /// The strings preserve the actual import names so they can be displayed
    /// in `// UNRECOVERED:` comments in the emitted Rust.
    UnrecognizedHostCall {
        /// Soroban host module letter (e.g. `"l"`, `"x"`, `"i"`).
        module: String,
        /// Host function name as imported (e.g. `"23"` or a friendlier ID).
        name: String,
    },

    /// We saw a multi-instruction sequence that does not match any known
    /// SDK pattern. The source instructions are still present in the IR;
    /// the high-level meaning is what we could not determine.
    UnsupportedPattern,

    /// An analysis pass ran but did not gather enough evidence to commit
    /// to a refinement (e.g. a phi node merged values from too many
    /// possibilities).
    InsufficientEvidence,

    /// A required upstream value was itself `Unknown`, so we could not
    /// propagate further. Forms a chain back to the original cause.
    UpstreamUnknown,

    /// The function's CFG contains an irreducible edge (a back edge whose
    /// target does not dominate its source), so control-flow structuring
    /// was not attempted. WASM cannot express irreducible control flow,
    /// so this never fires on real compiler output — it defends against
    /// exotic producers and hand-written modules.
    IrreducibleControlFlow,
}
