//! Pattern-recovery passes over `HighIr`.
//!
//! Each recognizer is a [`crate::Pass`]`<HighIr>` that matches a Soroban
//! SDK idiom in the lowered IR and rewrites the matching bindings into
//! [`sordec_ir::SemanticOp`]s, attaching provenance. Recognizers are
//! monotonic and idempotent (a second run over already-recognized IR
//! reports `changed: false`), so they compose in the fixpoint pipeline
//! group.
//!
//! The C-series recognizers land here as separate modules:
//!
//! - [`val_encoding`] (C1) — Soroban `Val` encode/decode/tag-check and
//!   object-conversion patterns.

pub mod val_encoding;

pub use val_encoding::ValEncodingPass;
