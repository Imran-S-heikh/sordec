//! Typed intermediate representations for the sordec pipeline.
//!
//! This crate defines every IR used during decompilation. It contains only
//! type definitions — no logic. All IR types use explicit `Unknown` variants
//! and carry confidence + provenance per the project's preserve-everything
//! philosophy.
