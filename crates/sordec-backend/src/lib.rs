//! Backend: emit human-readable artifacts from the final IR.
//!
//! Produces two outputs:
//! - **Annotated WAT** for low-level auditing
//! - **Compilable Rust** for contract review workflows
//!
//! `Unknown` bindings in the IR are emitted as explicit comments so the
//! reader always knows where the decompiler was uncertain.
