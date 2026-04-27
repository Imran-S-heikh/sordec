//! Error type returned by the frontend's [`crate::parse`] function.
//!
//! All variants surface fatal failure modes — situations where the
//! frontend cannot produce a usable [`crate::ParseOutput`]. Recoverable
//! conditions (unresolved type references, duplicate names, malformed
//! contractmetav0) become [`sordec_common::Diagnostic`]s in
//! `ParseOutput.diagnostics` instead of error returns. See the
//! [diagnostic module documentation](sordec_common::diagnostic) for the
//! migration principle.

/// All fatal error modes the frontend can surface.
///
/// Every variant carries enough context to diagnose the failure without
/// re-running the parser. The wrapping types use `String` rather than
/// `#[from]` on upstream errors (e.g., `stellar_xdr::Error`) to keep
/// `FrontendError` stable across upstream feature flags.
///
/// `#[non_exhaustive]` — adding a new variant is API-additive.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum FrontendError {
    /// Input byte slice is empty.
    #[error("input WASM is empty")]
    Empty,

    /// `wasmparser` rejected the byte slice.
    #[error("invalid WASM: {0}")]
    InvalidWasm(#[from] wasmparser::BinaryReaderError),

    /// The `contractspecv0` custom section bytes failed to decode.
    /// Stays a fatal error because every later pass keys off the spec;
    /// we cannot proceed past a corrupt one.
    #[error("malformed contractspecv0 section: {0}")]
    MalformedSpec(String),

    /// The `contractenvmetav0` custom section bytes failed to decode.
    /// Stays a fatal error because the protocol-version pinning it
    /// carries is needed for downstream compatibility checks.
    #[error("malformed contractenvmetav0 section: {0}")]
    MalformedEnvMeta(String),

    /// A `Symbol` or `StringM<N>` field in the spec was not valid UTF-8.
    /// Soroban-sdk requires identifiers to be valid Rust idents at compile
    /// time, so any non-UTF-8 content here is a sign of a hand-crafted or
    /// corrupted contract.
    #[error("name is not valid UTF-8")]
    InvalidUtf8Name,
}

/// Convenience alias for results returned by the frontend.
pub type FrontendResult<T> = Result<T, FrontendError>;
