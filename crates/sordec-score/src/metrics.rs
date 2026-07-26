//! Category names and the default category weights — the one place these
//! constants are defined.
//!
//! The overall score is a weighted mean of the four category sub-scores.
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

/// Compilation category: does the reconstructed source `cargo check`
/// against `soroban-sdk`. The honest stand-in for "behavior".
pub const COMPILATION: &str = "compilation";

/// Weight of the interface category in the overall mean.
pub const INTERFACE_WEIGHT: f64 = 0.30;
/// Weight of the structure category in the overall mean.
pub const STRUCTURE_WEIGHT: f64 = 0.25;
/// Weight of the semantic category in the overall mean.
pub const SEMANTIC_WEIGHT: f64 = 0.30;
/// Weight of the compilation category in the overall mean.
pub const COMPILATION_WEIGHT: f64 = 0.15;

/// The `(name, weight)` table, in report order. The single source of truth
/// the aggregator and the drift-guard test both read.
pub const WEIGHTS: [(&str, f64); 4] = [
    (INTERFACE, INTERFACE_WEIGHT),
    (STRUCTURE, STRUCTURE_WEIGHT),
    (SEMANTIC, SEMANTIC_WEIGHT),
    (COMPILATION, COMPILATION_WEIGHT),
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
