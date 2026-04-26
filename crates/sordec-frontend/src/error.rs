//! Error type returned by the frontend's [`crate::parse`] function.
//!
//! All variants surface specific failure modes; the frontend deliberately
//! refuses to "unwrap_or_default" on malformed sections (the legacy
//! decompiler did, and silently corrupted output downstream).

/// All error modes the frontend can surface.
///
/// Every variant carries enough context to diagnose the failure without
/// re-running the parser. The wrapping types use `String` rather than
/// `#[from]` on upstream errors (e.g., `stellar_xdr::Error`) to keep
/// `FrontendError` stable across upstream feature flags.
#[derive(Debug, thiserror::Error)]
pub enum FrontendError {
    /// Input byte slice is empty.
    #[error("input WASM is empty")]
    Empty,

    /// `wasmparser` rejected the byte slice.
    #[error("invalid WASM: {0}")]
    InvalidWasm(#[from] wasmparser::BinaryReaderError),

    /// The `contractspecv0` custom section bytes failed to decode.
    #[error("malformed contractspecv0 section: {0}")]
    MalformedSpec(String),

    /// The `contractenvmetav0` custom section bytes failed to decode.
    #[error("malformed contractenvmetav0 section: {0}")]
    MalformedEnvMeta(String),

    /// The `contractmetav0` custom section bytes failed to decode.
    #[error("malformed contractmetav0 section: {0}")]
    MalformedContractMeta(String),

    /// A type reference inside `contractspecv0` named a UDT not declared
    /// elsewhere in the spec.
    #[error("contractspecv0 references undefined type {name:?}")]
    UnresolvedTypeReference {
        /// Name of the missing type.
        name: String,
    },

    /// `contractspecv0` declared the same UDT name twice.
    #[error("contractspecv0 declares duplicate type {name:?}")]
    DuplicateTypeName {
        /// Conflicting name.
        name: String,
    },

    /// `contractspecv0` declared the same function name twice.
    #[error("contractspecv0 declares duplicate function {name:?}")]
    DuplicateFunctionName {
        /// Conflicting name.
        name: String,
    },

    /// A `Symbol` or `StringM<N>` field in the spec was not valid UTF-8.
    /// Soroban-sdk requires identifiers to be valid Rust idents at compile
    /// time, so any non-UTF-8 content here is a sign of a hand-crafted or
    /// corrupted contract.
    #[error("name is not valid UTF-8")]
    InvalidUtf8Name,
}

/// Convenience alias for results returned by the frontend.
pub type FrontendResult<T> = Result<T, FrontendError>;
