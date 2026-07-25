//! The scoring report and its weighted aggregation.
//!
//! [`ScoreReport`] is the single output of a scoring run: an overall
//! number, a pass/fail against the threshold, and the four category
//! sub-scores. Both the CLI and the calibration tests read it.
//!
//! Every report carries [`SCORER_VERSION`]. The metric is *frozen +
//! versioned* (K6): once the Phase 4 emitter is scored against it, the
//! algorithm and the *default* weights do not change without bumping this
//! string. A non-default weights profile is recorded per-report in
//! [`ScoreReport::weights_profile`] and takes the score outside the frozen
//! default contract. A golden-snapshot test (added with the calibration
//! battery) pins the version to a recorded calibration vector so an
//! accidental change trips at test time.

use serde::Serialize;

use crate::config::WeightProfile;
use crate::metrics;

/// Version of the scoring algorithm + the default weights. Bumped on any
/// change that can move the *default* score (a new category, a
/// canonicalization or extractor change, a change to the default weights).
/// A custom weights profile is recorded per-report in
/// [`ScoreReport::weights_profile`], not by this string. Stamped into every
/// [`ScoreReport`].
pub const SCORER_VERSION: &str = "score-1.0.0";

/// One category's contribution to the overall score.
///
/// The JSON schema is **append-only** (the `sordec coverage` convention):
/// later stages add fields (interface/semantic `precision`/`recall`,
/// compilation `diagnostics`) but never remove or rename one already here.
#[derive(Debug, Clone, Serialize)]
pub struct CategoryScore {
    /// Sub-score in `[0.0, 1.0]`.
    pub score: f64,
    /// This category's weight in the overall mean. Populated by
    /// [`ScoreReport::aggregate`] from the active [`WeightProfile`]; `0.0`
    /// until then.
    pub weight: f64,
    /// Whether this category contributed to `overall`. Always `true` for
    /// interface / structure / semantic. `false` for compilation when the
    /// check was not requested or the toolchain was unavailable — such a
    /// category is excluded from the weighted mean rather than scored `0`.
    pub checked: bool,
    /// Human-readable notes explaining the sub-score (missing functions,
    /// tier mismatches, compile diagnostics, …).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

impl CategoryScore {
    /// A checked category with the given score. Its weight is assigned at
    /// aggregation from the active [`WeightProfile`].
    #[must_use]
    pub fn checked(score: f64) -> Self {
        Self {
            score,
            weight: 0.0,
            checked: true,
            notes: Vec::new(),
        }
    }

    /// An unchecked category (excluded from the overall mean), scored `0`
    /// with a note explaining why it was skipped. Its weight is assigned at
    /// aggregation from the active [`WeightProfile`].
    #[must_use]
    pub fn unchecked(reason: impl Into<String>) -> Self {
        Self {
            score: 0.0,
            weight: 0.0,
            checked: false,
            notes: vec![reason.into()],
        }
    }

    /// Attach a note, builder-style.
    #[must_use]
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.notes.push(note.into());
        self
    }
}

/// The four category sub-scores. Field names are the canonical category
/// names in [`metrics`]; serde emits them as the JSON object keys.
#[derive(Debug, Clone, Serialize)]
pub struct Categories {
    /// Public entrypoint + type-shape match.
    pub interface: CategoryScore,
    /// Control-flow-skeleton similarity.
    pub structure: CategoryScore,
    /// Recovered-fact precision/recall.
    pub semantic: CategoryScore,
    /// `cargo check` against `soroban-sdk`.
    pub compilation: CategoryScore,
}

impl Categories {
    /// The categories paired with their canonical names, in
    /// [`metrics::WEIGHTS`] order. The aggregator and the drift-guard test
    /// both iterate this so the name↔category mapping has one owner.
    fn pairs(&self) -> [(&'static str, &CategoryScore); 4] {
        [
            (metrics::INTERFACE, &self.interface),
            (metrics::STRUCTURE, &self.structure),
            (metrics::SEMANTIC, &self.semantic),
            (metrics::COMPILATION, &self.compilation),
        ]
    }

    /// The categories paired with their canonical names, mutably, in
    /// [`metrics::WEIGHTS`] order — the seam through which
    /// [`ScoreReport::aggregate`] injects profile weights. The four are
    /// distinct fields, so the simultaneous `&mut` borrows are sound.
    fn pairs_mut(&mut self) -> [(&'static str, &mut CategoryScore); 4] {
        [
            (metrics::INTERFACE, &mut self.interface),
            (metrics::STRUCTURE, &mut self.structure),
            (metrics::SEMANTIC, &mut self.semantic),
            (metrics::COMPILATION, &mut self.compilation),
        ]
    }
}

/// A completed scoring run.
#[derive(Debug, Clone, Serialize)]
pub struct ScoreReport {
    /// The scoring algorithm version this report was produced by.
    pub scorer_version: &'static str,
    /// The weights profile this report was scored under. Together with
    /// `scorer_version` it reproduces the score.
    pub weights_profile: String,
    /// Weighted mean of the *checked* category sub-scores.
    pub overall: f64,
    /// `overall >= threshold`.
    pub passed: bool,
    /// The pass threshold this run used.
    pub threshold: f64,
    /// The four category sub-scores.
    pub categories: Categories,
    /// Run-level notes not tied to a single category.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

impl ScoreReport {
    /// Aggregate the four categories into an overall score and pass/fail,
    /// weighting them by `profile`.
    ///
    /// Each category's weight is taken from `profile` — the single owner of
    /// the weights, already validated at load. `overall` is then the
    /// weight-normalized mean over the *checked* categories only: a category
    /// with `checked == false` (compilation, when not run) drops out of both
    /// the numerator and the denominator, so the number never silently
    /// credits an unrun check. When no category is checked, `overall` is
    /// `0.0`.
    #[must_use]
    pub fn aggregate(mut categories: Categories, profile: &WeightProfile, threshold: f64) -> Self {
        // Inject each category's weight from the profile. A canonical category
        // name is always present in a profile, so `weight_of` is `Some`;
        // `unwrap_or(0.0)` keeps it panic-free regardless.
        for (name, cat) in categories.pairs_mut() {
            cat.weight = profile.weight_of(name).unwrap_or(0.0);
        }
        let mut weighted_sum = 0.0;
        let mut weight_total = 0.0;
        for (_name, cat) in categories.pairs() {
            if cat.checked {
                weighted_sum += cat.score * cat.weight;
                weight_total += cat.weight;
            }
        }
        let overall = if weight_total > 0.0 {
            weighted_sum / weight_total
        } else {
            0.0
        };
        Self {
            scorer_version: SCORER_VERSION,
            weights_profile: profile.name.clone(),
            overall,
            passed: overall >= threshold,
            threshold,
            categories,
            notes: Vec::new(),
        }
    }

    /// Attach a run-level note, builder-style.
    #[must_use]
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.notes.push(note.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cat(score: f64) -> CategoryScore {
        CategoryScore::checked(score)
    }

    #[test]
    fn all_perfect_scores_one() {
        let categories = Categories {
            interface: cat(1.0),
            structure: cat(1.0),
            semantic: cat(1.0),
            compilation: cat(1.0),
        };
        let report = ScoreReport::aggregate(categories, &WeightProfile::rfp_default(), 0.90);
        assert!((report.overall - 1.0).abs() < 1e-9);
        assert!(report.passed);
    }

    #[test]
    fn unchecked_compilation_is_excluded_from_the_mean() {
        // Three perfect checked categories + an unchecked compilation must
        // still be 1.0 — the unrun check does not drag the number down.
        let categories = Categories {
            interface: cat(1.0),
            structure: cat(1.0),
            semantic: cat(1.0),
            compilation: CategoryScore::unchecked("compile check not requested"),
        };
        let report = ScoreReport::aggregate(categories, &WeightProfile::rfp_default(), 0.90);
        assert!((report.overall - 1.0).abs() < 1e-9);
        assert!(report.passed);
    }

    #[test]
    fn category_names_match_the_weights_table() {
        // Drift guard: the report's serialized keys must equal the
        // canonical names in `metrics::WEIGHTS`, in order.
        let categories = Categories {
            interface: cat(1.0),
            structure: cat(1.0),
            semantic: cat(1.0),
            compilation: cat(1.0),
        };
        let names: Vec<&'static str> = categories.pairs().iter().map(|(n, _)| *n).collect();
        let weight_names: Vec<&'static str> =
            metrics::WEIGHTS.iter().map(|(n, _)| *n).collect();
        assert_eq!(names, weight_names);

        let value = serde_json::to_value(&categories).expect("serialize");
        let object = value.as_object().expect("categories is a JSON object");
        for name in weight_names {
            assert!(object.contains_key(name), "missing JSON key: {name}");
        }
        assert_eq!(object.len(), metrics::WEIGHTS.len());
    }

    #[test]
    fn weighted_mean_is_normalized() {
        // A single 0.5 category among perfect ones lands between 0.5 and 1.
        let categories = Categories {
            interface: cat(0.5),
            structure: cat(1.0),
            semantic: cat(1.0),
            compilation: CategoryScore::unchecked("skipped"),
        };
        let report = ScoreReport::aggregate(categories, &WeightProfile::rfp_default(), 0.90);
        // checked weights: 0.30 + 0.25 + 0.30 = 0.85; sum = 0.5*0.30 + 0.55 = 0.70
        let expected = (0.5 * 0.30 + 1.0 * 0.25 + 1.0 * 0.30) / 0.85;
        assert!((report.overall - expected).abs() < 1e-9);
        assert!(!report.passed);
    }

    #[test]
    fn profile_drives_the_weighting() {
        // Same categories, two profiles: all weight on the perfect category
        // vs all weight on the zero category. Proves the profile — not the
        // category construction — decides the overall.
        let cats = || Categories {
            interface: cat(1.0),
            structure: cat(0.0),
            semantic: cat(0.0),
            compilation: CategoryScore::unchecked("skipped"),
        };
        let heavy_interface = WeightProfile {
            name: "heavy-interface".to_owned(),
            interface: 1.0,
            structure: 0.0,
            semantic: 0.0,
            compilation: 0.0,
        };
        let heavy_structure = WeightProfile {
            name: "heavy-structure".to_owned(),
            interface: 0.0,
            structure: 1.0,
            semantic: 0.0,
            compilation: 0.0,
        };
        let a = ScoreReport::aggregate(cats(), &heavy_interface, 0.90);
        let b = ScoreReport::aggregate(cats(), &heavy_structure, 0.90);
        assert!((a.overall - 1.0).abs() < 1e-9, "all weight on the perfect category");
        assert!((b.overall - 0.0).abs() < 1e-9, "all weight on the zero category");
    }

    #[test]
    fn aggregate_records_the_profile_name() {
        let cats = || Categories {
            interface: cat(1.0),
            structure: cat(1.0),
            semantic: cat(1.0),
            compilation: CategoryScore::unchecked("skipped"),
        };
        let default = ScoreReport::aggregate(cats(), &WeightProfile::rfp_default(), 0.90);
        assert_eq!(default.weights_profile, "rfp-default");

        let named = WeightProfile {
            name: "aggressive".to_owned(),
            interface: 0.5,
            structure: 0.1,
            semantic: 0.3,
            compilation: 0.1,
        };
        let report = ScoreReport::aggregate(cats(), &named, 0.90);
        assert_eq!(report.weights_profile, "aggressive");
    }
}
