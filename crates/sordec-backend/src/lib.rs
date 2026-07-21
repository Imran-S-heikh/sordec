//! Backend: emit human-readable artifacts from the final IR.
//!
//! Produces two outputs (only the first is implemented today):
//! - **Annotated WAT** for low-level auditing — [`emit_annotated_wat`].
//! - **Compilable Rust** for contract review workflows (Phase 4).
//!
//! `Unknown` bindings in the IR are never dropped: the emitter renders
//! them as explicit `;; unrecognized` annotations so the reader always
//! knows where the decompiler was uncertain.
//!
//! The WAT emitter is kept self-contained (the private `wat` module) so
//! the future Rust emitter can reuse its fact-extraction and annotation
//! vocabulary without entangling the two output formats.

mod error;
mod wat;

pub use error::{BackendError, BackendResult};
pub use wat::{emit_annotated_wat, extract_annotated_facts, AnnotatedFunction};
