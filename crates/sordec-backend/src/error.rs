//! Error type returned by the backend emitters.
//!
//! Following the frontend's `FrontendError` convention, variants here are
//! *fatal* failures — the emitter could not produce output at all. Partial
//! recovery (an `Unknown` binding, an unresolved type) is never an error:
//! it is emitted as an explicit `;; unrecognized` annotation so the reader
//! always sees where certainty ran out.

/// All fatal error modes the backend can surface.
///
/// `#[non_exhaustive]` — adding a new variant is API-additive.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    /// `wasmprinter` could not disassemble the module. The wrapped string
    /// is the printer's own message; we flatten it to `String` (rather
    /// than carrying `anyhow::Error`) to keep `BackendError` free of an
    /// `anyhow` dependency in our public API.
    #[error("WAT disassembly failed: {0}")]
    Print(String),
}

/// Convenience alias for results returned by the backend.
pub type BackendResult<T> = Result<T, BackendError>;
