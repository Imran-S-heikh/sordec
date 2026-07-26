//! Configurable per-category weights and source bases (`score-2.0.0`,
//! milestones M1 and M2).
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

/// Which rendering of the sources a category is scored against.
///
/// The RFP mandates a **macro-expanded** comparison
/// (`OFFICIAL_TRANCHES.md:63-64`), but that is not the right basis for every
/// category — see [`BasisProfile::rfp_default`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Basis {
    /// The sources as written, before macro expansion.
    Source,
    /// The sources after `cargo expand`, with SDK glue stripped
    /// (`crate::expand` + `crate::glue`).
    Expanded,
}

/// A named assignment of a source [`Basis`] to each AST category.
///
/// Recorded in every report alongside the weights profile, so
/// `(scorer_version, weights_profile, basis_profile)` reproduces a score.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BasisProfile {
    /// Identifier recorded in the report, e.g. `"source-only"`.
    pub name: String,
    /// Basis for the interface category.
    pub interface: Basis,
    /// Basis for the structure category.
    pub structure: Basis,
    /// Basis for the semantic category.
    pub semantic: Basis,
}

impl BasisProfile {
    /// Every category on the pre-expansion sources — the built-in default.
    ///
    /// Keeps the fast path toolchain-free and reproduces `score-1.0.0`
    /// exactly. The default flips to [`rfp_default`](Self::rfp_default) once
    /// the interface category can read the expanded basis (milestone M3, T10).
    #[must_use]
    pub fn source_only() -> Self {
        Self {
            name: "source-only".to_owned(),
            interface: Basis::Source,
            structure: Basis::Source,
            semantic: Basis::Source,
        }
    }

    /// The RFP-aligned split: interface and structure on the expanded basis,
    /// **semantic on the pre-expansion sources**.
    ///
    /// Semantic is the deliberate exception. `crate::extract` recognizes
    /// panics only in their *macro* form (`visit_macro` on `panic` /
    /// `panic_with_error`), and expansion rewrites those to
    /// `::core::panicking::*` calls it cannot see. Scoring semantic on
    /// expanded input therefore drops panic facts from **both** sides — but
    /// far from equally: measured on token-v23 the reconstruction sheds 60
    /// facts and the original 5, lifting precision 0.3049 → 0.9091 purely by
    /// hiding our own over-production. That is measurement error flattering
    /// the tool, so semantic stays where the facts are visible.
    ///
    /// Revisit when T16 teaches `extract` the post-expansion forms;
    /// `extract`'s `panic_macro_is_recognized_but_expanded_call_is_not` test
    /// fails when that happens, forcing this decision to be re-argued rather
    /// than silently inherited.
    #[must_use]
    pub fn rfp_default() -> Self {
        Self {
            name: "rfp-default".to_owned(),
            interface: Basis::Expanded,
            structure: Basis::Expanded,
            semantic: Basis::Source,
        }
    }

    /// Whether any category asks for the expanded basis. When false the
    /// scorer never shells out to `cargo expand`.
    #[must_use]
    pub fn needs_expansion(&self) -> bool {
        [self.interface, self.structure, self.semantic].contains(&Basis::Expanded)
    }

    /// Parse and validate a profile from TOML text. `origin` names the source
    /// for error messages.
    ///
    /// # Errors
    ///
    /// [`ScoreError::Config`] if `text` is not valid TOML for this schema.
    pub fn from_toml_str(text: &str, origin: &str) -> Result<Self, ScoreError> {
        toml::from_str(text).map_err(|source| ScoreError::Config {
            path: origin.to_owned(),
            reason: source.to_string(),
        })
    }
}

impl Default for BasisProfile {
    fn default() -> Self {
        Self::source_only()
    }
}

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
                return Err(fail(format!(
                    "weight '{name}' must be finite, got {weight}"
                )));
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

    // -----------------------------------------------------------------
    // BasisProfile
    // -----------------------------------------------------------------

    #[test]
    fn the_default_basis_is_source_only() {
        // Keeps the fast path toolchain-free and score-1.0.0-identical until
        // interface can read the expanded basis (M3/T10).
        let p = BasisProfile::default();
        assert_eq!(p, BasisProfile::source_only());
        assert_eq!(p.name, "source-only");
        assert!(!p.needs_expansion(), "the default must never shell out");
    }

    #[test]
    fn rfp_default_expands_interface_and_structure_but_not_semantic() {
        // The semantic exception is the whole point of T9: `extract` sees
        // panics only as macros, so expansion would hide our over-production.
        let p = BasisProfile::rfp_default();
        assert_eq!(p.interface, Basis::Expanded);
        assert_eq!(p.structure, Basis::Expanded);
        assert_eq!(p.semantic, Basis::Source);
        assert!(p.needs_expansion());
    }

    #[test]
    fn basis_profile_round_trips_through_toml() {
        let original = BasisProfile::rfp_default();
        let text = toml::to_string(&original).expect("serialize");
        let parsed = BasisProfile::from_toml_str(&text, "<round-trip>").expect("parse");
        assert_eq!(parsed, original);
    }

    #[test]
    fn basis_profile_rejects_an_unknown_basis() {
        let err = BasisProfile::from_toml_str(
            "name = \"t\"\ninterface = \"wasm\"\nstructure = \"source\"\nsemantic = \"source\"\n",
            "<test>",
        )
        .expect_err("`wasm` is not a basis");
        assert!(matches!(err, ScoreError::Config { .. }), "got {err:?}");
    }
}
