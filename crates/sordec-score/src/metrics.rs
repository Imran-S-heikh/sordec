//! Category names and the default category weights — the one place these
//! constants are defined.
//!
//! The overall score is a weighted mean of the four category sub-scores.
//! Compilation is deliberately *not* among them — it is a pass/fail gate
//! ([`CompilationGate`]) that can veto the verdict. See [`BEHAVIOR`], which
//! took its slot.
//!
//! The **default** weights live here as named consts (not scattered
//! literals); a change to one is a single, reviewable, version-bumping edit.
//! Runtime overrides come from a [`WeightProfile`], which defaults to these
//! values. The category **names** live here too and are the exact JSON
//! object keys the report emits.
//!
//! ## Drift protection
//!
//! This mirrors the `sordec-passes` `metrics_catalog` idiom: one owner for
//! the strings, guarded rather than trusted. [`WEIGHTS`] pairs every
//! category name with its default weight. A unit test here asserts the names
//! are unique; `report`'s drift test asserts the report's serialized keys
//! equal these names; and the "default weights sum to 1.0" guard lives with
//! the default profile ([`WeightProfile::rfp_default`], now that weights are
//! runtime-configurable). Renaming a category or nudging a default weight
//! trips those tests — and, by the freeze policy, a default-weight change
//! must bump [`SCORER_VERSION`].
//!
//! [`CompilationGate`]: crate::report::CompilationGate
//! [`SCORER_VERSION`]: crate::report::SCORER_VERSION
//! [`WeightProfile`]: crate::WeightProfile
//! [`WeightProfile::rfp_default`]: crate::WeightProfile::rfp_default

/// Interface category: public entrypoint signatures + `#[contracttype]`
/// shapes. Highest-weighted alongside semantic — the contract's declared
/// surface is ground truth.
pub const INTERFACE: &str = "interface";

/// Structure category: per-function control-flow-skeleton similarity.
pub const STRUCTURE: &str = "structure";

/// Semantic category: precision/recall over recovered Soroban-operation
/// facts.
pub const SEMANTIC: &str = "semantic";

/// Behavior category: does the reconstruction *do* what the original does,
/// measured by differential execution of both wasms.
///
/// Took compilation's slot in T19. Compilation is not a category — it is a
/// pass/fail gate ([`CompilationGate`]), because a binary flag has no spectrum
/// to score, because behavior already presupposes it, and because `todo!()`
/// compiles: a scored compilation category paid for recovering nothing.
///
/// [`CompilationGate`]: crate::report::CompilationGate
pub const BEHAVIOR: &str = "behavior";

/// Weight of the interface category in the overall mean.
pub const INTERFACE_WEIGHT: f64 = 0.30;
/// Weight of the structure category in the overall mean.
pub const STRUCTURE_WEIGHT: f64 = 0.25;
/// Weight of the semantic category in the overall mean.
pub const SEMANTIC_WEIGHT: f64 = 0.30;
/// Weight of the behavior category in the overall mean.
///
/// Inherited unchanged from the compilation category it replaced, so T19 moved
/// no scores. Behavior is the dimension the RFP actually asks about and 0.15
/// arguably undersells it, but re-weighting shifts the other three categories'
/// ratios and is therefore its own explicit change — held until the "what does
/// 90% attach to" question is settled with ABS.
pub const BEHAVIOR_WEIGHT: f64 = 0.15;

/// The `(name, weight)` table, in report order. The single source of truth
/// the aggregator and the drift-guard test both read.
pub const WEIGHTS: [(&str, f64); 4] = [
    (INTERFACE, INTERFACE_WEIGHT),
    (STRUCTURE, STRUCTURE_WEIGHT),
    (SEMANTIC, SEMANTIC_WEIGHT),
    (BEHAVIOR, BEHAVIOR_WEIGHT),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn category_names_are_unique() {
        let mut names: Vec<&str> = WEIGHTS.iter().map(|(n, _)| *n).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "duplicate category name in WEIGHTS");
    }
}
