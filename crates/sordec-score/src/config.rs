//! Configurable per-category weights (`score-2.0.0`, milestone M1).
//!
//! `score-1.0.0` baked the four category weights into compile-time consts
//! ([`metrics::INTERFACE_WEIGHT`] and friends) and wired them into each
//! sub-score at construction. This module lifts them into a runtime
//! [`WeightProfile`] the team can supply from a TOML file, so re-weighting a
//! category is a config edit rather than a recompile.
//!
//! [`WeightProfile::rfp_default`] reproduces the frozen score-1.0.0 weights
//! exactly — sourced from [`metrics`], the single owner of the numbers — so a
//! run that supplies no profile scores identically to before.
//!
//! Weights are **relative**: the aggregator normalizes over the checked
//! categories (`report::ScoreReport::aggregate`), so a profile's weights need
//! not sum to `1.0` — only their ratios matter.
//!
//! The profile is applied at aggregation (`ScoreReport::aggregate`) and its
//! name is recorded in every report. A run that supplies no profile uses
//! [`WeightProfile::rfp_default`], so the default path scores identically to
//! `score-1.0.0` and moves no score.
//!
//! [`metrics::INTERFACE_WEIGHT`]: crate::metrics::INTERFACE_WEIGHT

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::{error::ScoreError, metrics};

/// A named set of per-category weights for the overall mean.
///
/// Field names are the canonical category names in [`metrics`]. `name` is
/// recorded in every report (milestone T4) so a score is reproducible from
/// its `(scorer_version, profile name)`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WeightProfile {
    /// Identifier recorded in the report, e.g. `"rfp-default"`.
    pub name: String,
    /// Weight of the interface category.
    pub interface: f64,
    /// Weight of the structure category.
    pub structure: f64,
    /// Weight of the semantic category.
    pub semantic: f64,
    /// Weight of the compilation category (the honest "behavior" stand-in;
    /// renamed to `behavior` in milestone M6).
    pub compilation: f64,
}

impl WeightProfile {
    /// The built-in default: the frozen score-1.0.0 weights, sourced from
    /// [`metrics`] so the numbers have a single owner.
    #[must_use]
    pub fn rfp_default() -> Self {
        Self {
            name: "rfp-default".to_owned(),
            interface: metrics::INTERFACE_WEIGHT,
            structure: metrics::STRUCTURE_WEIGHT,
            semantic: metrics::SEMANTIC_WEIGHT,
            compilation: metrics::COMPILATION_WEIGHT,
        }
    }

    /// Parse and validate a profile from TOML text. `origin` names the source
    /// (a file path, or a marker like `"<inline>"`) for error messages.
    ///
    /// # Errors
    ///
    /// [`ScoreError::Config`] if `text` is not valid TOML for this schema, or
    /// if the parsed weights fail [`validate`](Self::validate).
    pub fn from_toml_str(text: &str, origin: &str) -> Result<Self, ScoreError> {
        let profile: Self = toml::from_str(text).map_err(|source| ScoreError::Config {
            path: origin.to_owned(),
            reason: source.to_string(),
        })?;
        profile.validate(origin)?;
        Ok(profile)
    }

    /// Load, parse, and validate a profile from a TOML file.
    ///
    /// # Errors
    ///
    /// [`ScoreError::Io`] if the file cannot be read; [`ScoreError::Config`]
    /// if its contents are not a valid profile.
    pub fn load(path: &Path) -> Result<Self, ScoreError> {
        let origin = path.display().to_string();
        let text = std::fs::read_to_string(path).map_err(|source| ScoreError::Io {
            path: origin.clone(),
            source,
        })?;
        Self::from_toml_str(&text, &origin)
    }

    /// Check that every weight is finite and non-negative and that at least
    /// one is positive. Weights need **not** sum to `1.0` — they are relative
    /// and normalized at aggregation. `origin` names the source for errors.
    ///
    /// # Errors
    ///
    /// [`ScoreError::Config`] naming the offending category and value.
    pub fn validate(&self, origin: &str) -> Result<(), ScoreError> {
        let fail = |reason: String| ScoreError::Config {
            path: origin.to_owned(),
            reason,
        };
        for (name, weight) in self.pairs() {
            if !weight.is_finite() {
                return Err(fail(format!("weight '{name}' must be finite, got {weight}")));
            }
            if weight < 0.0 {
                return Err(fail(format!(
                    "weight '{name}' must be non-negative, got {weight}"
                )));
            }
        }
        if self.pairs().iter().all(|(_, weight)| *weight == 0.0) {
            return Err(fail(
                "at least one weight must be greater than 0".to_owned(),
            ));
        }
        Ok(())
    }

    /// The weight for a canonical category name (see [`metrics`]), or `None`
    /// if `category` is not one of the four categories. Returns `None` rather
    /// than panicking on an unknown name, since the name may come from runtime
    /// input.
    #[must_use]
    pub fn weight_of(&self, category: &str) -> Option<f64> {
        self.pairs()
            .into_iter()
            .find(|(name, _)| *name == category)
            .map(|(_, weight)| weight)
    }

    /// The `(name, weight)` pairs in [`metrics::WEIGHTS`] order — the single
    /// owner of this profile's name↔weight mapping (mirrors
    /// `report::Categories::pairs`).
    fn pairs(&self) -> [(&'static str, f64); 4] {
        [
            (metrics::INTERFACE, self.interface),
            (metrics::STRUCTURE, self.structure),
            (metrics::SEMANTIC, self.semantic),
            (metrics::COMPILATION, self.compilation),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a valid profile with each weight substituted verbatim, so the
    /// rejection tests exercise `validate` (not the TOML parser).
    fn profile_toml(interface: &str, structure: &str, semantic: &str, compilation: &str) -> String {
        format!(
            "name = \"t\"\ninterface = {interface}\nstructure = {structure}\n\
             semantic = {semantic}\ncompilation = {compilation}\n"
        )
    }

    fn assert_config_err(text: &str) {
        let err = WeightProfile::from_toml_str(text, "<test>").expect_err("must be rejected");
        assert!(
            matches!(err, ScoreError::Config { .. }),
            "expected ScoreError::Config, got {err:?}"
        );
    }

    #[test]
    fn rfp_default_matches_metrics_consts() {
        let p = WeightProfile::rfp_default();
        assert_eq!(p.name, "rfp-default");
        assert_eq!(p.interface, metrics::INTERFACE_WEIGHT);
        assert_eq!(p.structure, metrics::STRUCTURE_WEIGHT);
        assert_eq!(p.semantic, metrics::SEMANTIC_WEIGHT);
        assert_eq!(p.compilation, metrics::COMPILATION_WEIGHT);
    }

    #[test]
    fn rfp_default_sums_to_one_and_validates() {
        let p = WeightProfile::rfp_default();
        let sum = p.interface + p.structure + p.semantic + p.compilation;
        assert!(
            (sum - 1.0).abs() < f64::EPSILON,
            "default should sum to 1.0, got {sum}"
        );
        p.validate("<default>").expect("default must validate");
    }

    #[test]
    fn shipped_profile_matches_default() {
        let text = include_str!("../profiles/rfp-default.toml");
        let p = WeightProfile::from_toml_str(text, "rfp-default.toml")
            .expect("shipped profile must parse");
        assert_eq!(p, WeightProfile::rfp_default());
    }

    #[test]
    fn round_trips_through_toml() {
        let original = WeightProfile::rfp_default();
        let text = toml::to_string(&original).expect("serialize");
        let parsed = WeightProfile::from_toml_str(&text, "<round-trip>").expect("parse");
        assert_eq!(parsed, original);
    }

    #[test]
    fn accepts_unnormalized_weights() {
        // Weights are relative; a profile summing to 2.0 is valid.
        let p = WeightProfile::from_toml_str(&profile_toml("0.6", "0.5", "0.6", "0.3"), "<x>")
            .expect("unnormalized weights should load");
        assert_eq!(p.name, "t");
    }

    #[test]
    fn rejects_negative_weight() {
        assert_config_err(&profile_toml("-0.1", "0.25", "0.30", "0.15"));
    }

    #[test]
    fn rejects_all_zero() {
        assert_config_err(&profile_toml("0.0", "0.0", "0.0", "0.0"));
    }

    #[test]
    fn rejects_non_finite() {
        // TOML has a `nan` float literal; it parses, then `validate` rejects it.
        assert_config_err(&profile_toml("nan", "0.25", "0.30", "0.15"));
    }

    #[test]
    fn rejects_unknown_field() {
        // `deny_unknown_fields` catches the misspelling before validation.
        assert_config_err(
            "name = \"t\"\ninterface = 0.30\nstructure = 0.25\nsemantic = 0.30\n\
             compilation = 0.15\nsematic = 0.10\n",
        );
    }

    #[test]
    fn rejects_missing_field() {
        assert_config_err("name = \"t\"\ninterface = 0.30\nstructure = 0.25\nsemantic = 0.30\n");
    }

    #[test]
    fn rejects_malformed_toml() {
        assert_config_err("name = = 0.3");
    }

    #[test]
    fn weight_of_known_and_unknown() {
        let p = WeightProfile::rfp_default();
        assert_eq!(
            p.weight_of(metrics::INTERFACE),
            Some(metrics::INTERFACE_WEIGHT)
        );
        assert_eq!(
            p.weight_of(metrics::COMPILATION),
            Some(metrics::COMPILATION_WEIGHT)
        );
        assert_eq!(p.weight_of("behavior"), None);
    }
}
