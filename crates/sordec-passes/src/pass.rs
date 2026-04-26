//! The [`Pass`] trait and its associated result types.
//!
//! A pass is a unit of analysis or transformation that operates on a
//! single IR layer. Passes mutate the IR in place via `&mut Ir`. They
//! must be **monotonic**: every refinement either adds information or
//! replaces an `Unknown` with a `Known`/`Inferred`, never the reverse.
//! This is what makes the [`crate::Pipeline`] fixpoint loop terminate.
//!
//! The trait is deliberately minimal — `name` and `run` only. Pass
//! ordering and dependencies are managed by the [`crate::Pipeline`]
//! manifest, not declared on the trait. This is the same pattern
//! `rustc_mir_transform`, Cranelift, Ghidra, and angr converged on
//! after experience with string-keyed dependency graphs (see
//! `docs/architecture.md` §11 for the rejected alternatives).

use std::collections::HashMap;

/// A single analysis or transformation step over IR of type `Ir`.
///
/// Every pass is parameterised by the IR layer it consumes (typically
/// [`sordec_ir::LiftedIr`] or [`sordec_ir::HighIr`]). The type
/// parameter prevents accidentally running a high-IR pass against a
/// lifted-IR value at compile time — the architecture's compile-time
/// safety promise.
pub trait Pass<Ir> {
    /// Unique compile-time pass name.
    ///
    /// Must be unique across every [`crate::Pipeline`] containing this
    /// pass; the pipeline panics at construction if it detects
    /// duplicates. Used in diagnostics, [`crate::PipelineReport`]
    /// entries, and [`sordec_common::Provenance::pass`].
    fn name(&self) -> &'static str;

    /// Run the pass on the IR.
    ///
    /// Must be **monotonic**: only adds information or refines existing
    /// information; never contradicts or removes. Must be safe to call
    /// repeatedly (passes inside a fixpoint group may be invoked many
    /// times until none reports `changed`).
    fn run(&self, ir: &mut Ir) -> PassResult;
}

/// Result of a single [`Pass::run`] invocation.
///
/// Used by the [`crate::Pipeline`] to detect fixpoint termination
/// (when no pass in a group reports `changed`) and by tooling to track
/// per-pass diagnostics.
#[derive(Debug, Clone, Default)]
pub struct PassResult {
    /// `true` if the pass modified the IR's structure, types,
    /// expressions, or operations in a way another pass might care about.
    ///
    /// Provenance/notes/metrics changes do **not** count as `changed`.
    /// This precise definition is what keeps the fixpoint loop honest:
    /// a pass that updates only metadata cannot cause another iteration
    /// to fire.
    pub changed: bool,

    /// Optional per-pass counters.
    pub metrics: PassMetrics,

    /// Free-form human-readable diagnostic notes.
    pub notes: Vec<String>,
}

/// Named diagnostic counters reported by a pass.
///
/// Convention for keys: `"unknowns_reduced"`, `"dead_blocks_removed"`,
/// `"patterns_matched"`, etc. The string-keyed map is accepted here
/// (despite our architectural ban on strings as identifiers) because
/// metrics are diagnostic-only and never participate in control flow.
#[derive(Debug, Clone, Default)]
pub struct PassMetrics {
    counters: HashMap<&'static str, i64>,
}

impl PassMetrics {
    /// Create an empty metrics container.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add `delta` to the named counter (creating it if absent).
    #[inline]
    pub fn increment(&mut self, key: &'static str, delta: i64) {
        *self.counters.entry(key).or_insert(0) += delta;
    }

    /// Set the named counter to `value`, replacing any prior value.
    #[inline]
    pub fn set(&mut self, key: &'static str, value: i64) {
        self.counters.insert(key, value);
    }

    /// Read the named counter, or `None` if it was never set.
    #[inline]
    #[must_use]
    pub fn get(&self, key: &'static str) -> Option<i64> {
        self.counters.get(key).copied()
    }

    /// Iterate `(key, value)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&'static str, i64)> + '_ {
        self.counters.iter().map(|(&k, &v)| (k, v))
    }

    /// Whether any counter has been recorded.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.counters.is_empty()
    }
}
