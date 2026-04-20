//! Pipeline orchestration for sordec.
//!
//! The driver wires the frontend → pass pipeline → backend together. It
//! owns the pass manager, which schedules passes and runs them to
//! fixpoint, and exposes the top-level `Decompiler` API.
