//! Category weights and canonical category names — the one place these
//! constants are defined.
//!
//! The overall score is a weighted mean of the four category sub-scores.
//! Weights live here as named consts (not scattered literals) so a change
//! is a single, reviewable, version-bumping edit. The category **names**
//! live here too and are the exact JSON object keys the report emits.
//!
//! ## Drift protection
//!
//! This mirrors the `sordec-passes` `metrics_catalog` idiom: one owner for
//! the strings, guarded rather than trusted. [`WEIGHTS`] pairs every
//! category name with its weight; a unit test asserts the weights sum to
//! 1.0 and that the report's serialized keys equal these names. Renaming a
//! category or nudging a weight without updating this table trips that
//! test — and, by the freeze policy, must bump [`SCORER_VERSION`].
//!
//! [`SCORER_VERSION`]: crate::report::SCORER_VERSION

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

/// Look up a category's weight by name. Panics on an unknown name — the
/// names are compile-time consts from this module, so a miss is a bug, not
/// a runtime condition.
#[must_use]
pub fn weight_of(category: &str) -> f64 {
    WEIGHTS
        .iter()
        .find(|(name, _)| *name == category)
        .map(|(_, w)| *w)
        .unwrap_or_else(|| panic!("unknown scorer category: {category}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weights_sum_to_one() {
        let total: f64 = WEIGHTS.iter().map(|(_, w)| *w).sum();
        assert!(
            (total - 1.0).abs() < f64::EPSILON,
            "category weights must sum to 1.0, got {total}"
        );
    }

    #[test]
    fn category_names_are_unique() {
        let mut names: Vec<&str> = WEIGHTS.iter().map(|(n, _)| *n).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "duplicate category name in WEIGHTS");
    }
}
