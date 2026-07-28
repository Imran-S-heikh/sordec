//! The behavior category's input: a differential-execution result, injected.
//!
//! # Why injected rather than computed
//!
//! Every other category is computed inside this crate. Behavior cannot be, because
//! it needs to *run* two wasm modules in a Soroban host, and this crate's manifest
//! states the rule it will not break: it "never touches WASM or our IR — the
//! instrument must be independent of the pipeline it grades."
//!
//! Note this is not the pattern the compilation gate follows. That gate is computed
//! here (`compile::check`) because it only needs a source *path*. Behavior needs a
//! host, so it is produced by `sordec-diffexec` and handed in — the CLI is where the
//! two meet.
//!
//! # The rule this module exists to enforce
//!
//! A behavior number is only *our* score when the compared side is our decompiler's
//! output. The harness can also run a contract against itself, against its own
//! recompiled source, or against a deliberately mutated copy — all valuable, none of
//! them a measurement of sordec.
//!
//! Letting a calibration figure reach `overall` would be self-scoring: the same line
//! T17 held when it refused to count `todo!()` holes as recovered facts, and T18 held
//! when it stopped crediting our arg-decode traps as recovered panics. So the origin
//! of the compared side travels with the number as a [`BSide`], and
//! [`Behavior::counts_as_our_score`] is what [`crate::ScoreReport`] consults. A
//! calibration run is *reported in full* and *excluded from the mean*.
//!
//! # And the rule about coverage
//!
//! A match rate without its denominator is the failure we called out in a
//! competitor's harness: "99.2%" is not a 99.2% result when it was measured over
//! three of thirty entrypoints. [`Behavior::new`] therefore takes the coverage
//! fraction as required arguments — there is no way to construct a score here
//! without saying what it was measured over.

use serde::Serialize;

use crate::report::CategoryScore;

/// Where the side that was compared against the original came from.
///
/// Only one of these is a statement about our decompiler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BSide {
    /// Our decompiler's output, recompiled to wasm. **The only variant that scores.**
    Reconstruction,
    /// The contract's own source, recompiled. Measures our toolchain policy, not our
    /// recovery — a 1.0 here says the harness and the build are sound.
    OriginalSourceRecompiled,
    /// The original wasm compared against itself. Measures the comparator's own
    /// plumbing; a result below 1.0 means the harness is broken.
    ShippedWasm,
    /// A deliberately mutated contract with a known-correct verdict. Proves the
    /// comparator can *detect*, which self-comparison cannot.
    Calibration {
        /// The divergence class the mutation demonstrates.
        class: String,
    },
}

impl BSide {
    /// Whether a score from this side is a measurement of our decompiler.
    #[must_use]
    pub fn is_our_reconstruction(&self) -> bool {
        matches!(self, Self::Reconstruction)
    }

    /// Short label for reports.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::Reconstruction => "reconstruction".to_owned(),
            Self::OriginalSourceRecompiled => "original-source-recompiled".to_owned(),
            Self::ShippedWasm => "shipped-wasm".to_owned(),
            Self::Calibration { class } => format!("calibration:{class}"),
        }
    }
}

/// How one observation tuple fared.
///
/// Reported separately rather than blended, because "events 94%, storage 87%" says
/// where to work and a single "93%" does not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TupleScore {
    /// `return`, `events`, `auth` or `storage`.
    pub name: String,
    /// Checks on this tuple that agreed.
    pub matched: usize,
    /// Checks on this tuple that were exercised at all. Zero means the contract
    /// never used this facility, which is not a match.
    pub exercised: usize,
}

/// A differential-execution result.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Behavior {
    /// Match rate over exercised observations, in `[0.0, 1.0]`.
    pub score: f64,
    /// Where the compared side came from. Decides whether `score` counts.
    pub b_side: BSide,
    /// Entrypoints actually driven.
    pub entrypoints_driven: usize,
    /// Entrypoints the contract declares. The denominator that has to travel with
    /// the rate.
    pub entrypoints_total: usize,
    /// Per-tuple breakdown.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tuples: Vec<TupleScore>,
    /// Calls both sides failed identically, excluded from the rate. Counted so the
    /// exclusion is visible rather than silent.
    pub trivial_agreements: usize,
    /// Anything qualifying the run.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

impl Behavior {
    /// A behavior result.
    ///
    /// Coverage is required, not optional: a rate with no denominator is the exact
    /// shape of claim this project has committed to never publishing.
    ///
    /// `score` is clamped to `[0.0, 1.0]`; a harness that reported something outside
    /// that range is buggy, and the honest response is to bound it here rather than
    /// let it distort the weighted mean.
    #[must_use]
    pub fn new(
        score: f64,
        b_side: BSide,
        entrypoints_driven: usize,
        entrypoints_total: usize,
    ) -> Self {
        Self {
            score: score.clamp(0.0, 1.0),
            b_side,
            entrypoints_driven,
            entrypoints_total,
            tuples: Vec::new(),
            trivial_agreements: 0,
            notes: Vec::new(),
        }
    }

    /// Attach the per-tuple breakdown, builder-style.
    #[must_use]
    pub fn with_tuples(mut self, tuples: Vec<TupleScore>) -> Self {
        self.tuples = tuples;
        self
    }

    /// Record how many calls were excluded as trivial agreement, builder-style.
    #[must_use]
    pub fn with_trivial_agreements(mut self, count: usize) -> Self {
        self.trivial_agreements = count;
        self
    }

    /// Attach a note, builder-style.
    #[must_use]
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.notes.push(note.into());
        self
    }

    /// Whether this result may contribute to the overall score.
    ///
    /// The whole point of the module. A calibration or self-comparison result is
    /// reported in full and excluded from the mean.
    #[must_use]
    pub fn counts_as_our_score(&self) -> bool {
        self.b_side.is_our_reconstruction()
    }

    /// The coverage fraction, rendered for a report.
    #[must_use]
    pub fn coverage(&self) -> String {
        format!("{} of {} entrypoints", self.entrypoints_driven, self.entrypoints_total)
    }

    /// Why this result does not score, when it does not.
    #[must_use]
    pub fn exclusion_reason(&self) -> Option<String> {
        if self.counts_as_our_score() {
            return None;
        }
        Some(format!(
            "behavior measured against {} ({:.4} over {}), which is calibration of the \
             harness and not a measurement of our reconstruction; excluded from the mean",
            self.b_side.label(),
            self.score,
            self.coverage()
        ))
    }
}

/// What the caller supplied for the behavior category.
///
/// Three outcomes, mirroring [`crate::CompilationGate`] and
/// `sordec-diffexec`'s own `Unavailable`, so an unrun check can never pose as a
/// failed one.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum BehaviorInput {
    /// Not asked for. The default, so the fast path stays host-free.
    #[default]
    NotRequested,
    /// Asked for and could not be produced — no toolchain, the reconstruction did
    /// not build, the module would not load. Never a verdict on the reconstruction.
    Unavailable {
        /// Why, phrased so a report can print it.
        reason: String,
    },
    /// Produced.
    Measured(Behavior),
}

impl BehaviorInput {
    /// The result, when one was produced.
    #[must_use]
    pub fn measured(&self) -> Option<&Behavior> {
        match self {
            Self::Measured(behavior) => Some(behavior),
            _ => None,
        }
    }

    /// The category score this input yields.
    ///
    /// The rule lives here, next to [`BSide`] and its tests, rather than in the
    /// aggregator: a result only becomes a *checked* category when the compared side
    /// was our own reconstruction. Everything else reports `unchecked` with the
    /// reason, so a calibration figure is visible in the report and absent from the
    /// mean.
    #[must_use]
    pub fn category(&self) -> CategoryScore {
        match self {
            Self::NotRequested => CategoryScore::unchecked(
                "behavior not requested; differential execution needs a toolchain and \
                 both wasm modules",
            ),
            Self::Unavailable { reason } => {
                CategoryScore::unchecked(format!("behavior unavailable: {reason}"))
            }
            Self::Measured(behavior) => match behavior.exclusion_reason() {
                Some(reason) => CategoryScore::unchecked(reason),
                None => CategoryScore::checked(behavior.score)
                    .with_note(format!("differential execution over {}", behavior.coverage())),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn measured(b_side: BSide) -> Behavior {
        Behavior::new(0.875, b_side, 7, 8)
    }

    #[test]
    fn only_our_reconstruction_scores() {
        assert!(measured(BSide::Reconstruction).counts_as_our_score());

        for other in [
            BSide::OriginalSourceRecompiled,
            BSide::ShippedWasm,
            BSide::Calibration {
                class: "overflow".to_owned(),
            },
        ] {
            let behavior = measured(other.clone());
            assert!(
                !behavior.counts_as_our_score(),
                "{} must not count as our score",
                other.label()
            );
            // And it says why, rather than vanishing.
            let reason = behavior.exclusion_reason().expect("an excluded result explains itself");
            assert!(reason.contains(&other.label()), "{reason}");
            assert!(reason.contains("not a measurement of our reconstruction"), "{reason}");
        }
    }

    #[test]
    fn a_scoring_result_has_no_exclusion_reason() {
        assert_eq!(measured(BSide::Reconstruction).exclusion_reason(), None);
    }

    #[test]
    fn a_score_cannot_exist_without_its_denominator() {
        // Structural, not conventional: `new` takes coverage as required arguments,
        // so there is no way to build a rate that does not know what it covered.
        let behavior = measured(BSide::Reconstruction);
        assert_eq!(behavior.coverage(), "7 of 8 entrypoints");
    }

    #[test]
    fn an_out_of_range_score_is_bounded_rather_than_trusted() {
        // A harness reporting 1.4 is buggy; letting it through would distort the
        // weighted mean and read as better-than-perfect recovery.
        assert!((Behavior::new(1.4, BSide::Reconstruction, 1, 1).score - 1.0).abs() < f64::EPSILON);
        assert!((Behavior::new(-0.2, BSide::Reconstruction, 1, 1).score).abs() < f64::EPSILON);
    }

    #[test]
    fn a_calibration_result_is_reported_but_never_scored() {
        // The guard, end to end: the number is present in the report and the category
        // is unchecked, so it cannot reach the weighted mean.
        let input = BehaviorInput::Measured(measured(BSide::Calibration {
            class: "overflow".to_owned(),
        }));
        let category = input.category();

        assert!(!category.checked, "a calibration result must not be checked");
        assert!(
            category.notes.iter().any(|n| n.contains("calibration:overflow")),
            "{:?}",
            category.notes
        );
        assert!(input.measured().is_some(), "and the number is still reported");
    }

    #[test]
    fn our_reconstruction_scores_and_carries_its_coverage() {
        let input = BehaviorInput::Measured(measured(BSide::Reconstruction));
        let category = input.category();

        assert!(category.checked);
        assert!((category.score - 0.875).abs() < f64::EPSILON);
        assert!(
            category.notes.iter().any(|n| n.contains("7 of 8 entrypoints")),
            "a rate must never render without its denominator: {:?}",
            category.notes
        );
    }

    #[test]
    fn an_unavailable_behavior_is_unchecked_and_says_why() {
        // T21: never a silent zero. It renormalises out of the mean instead.
        let input = BehaviorInput::Unavailable {
            reason: "rustc 1.89 is not installed".to_owned(),
        };
        let category = input.category();
        assert!(!category.checked);
        assert!(
            category.notes.iter().any(|n| n.contains("rustc 1.89 is not installed")),
            "{:?}",
            category.notes
        );
        assert!(input.measured().is_none());
    }

    #[test]
    fn the_default_input_is_not_requested() {
        // So the default path stays host-free and cannot accidentally fail a run.
        assert_eq!(BehaviorInput::default(), BehaviorInput::NotRequested);
    }

    #[test]
    fn tuple_breakdown_and_trivial_agreements_survive_the_builders() {
        let behavior = measured(BSide::Reconstruction)
            .with_tuples(vec![TupleScore {
                name: "events".to_owned(),
                matched: 3,
                exercised: 4,
            }])
            .with_trivial_agreements(2)
            .with_note("one entrypoint needs constructor arguments");

        assert_eq!(behavior.tuples.len(), 1);
        assert_eq!(behavior.trivial_agreements, 2);
        assert_eq!(behavior.notes.len(), 1);
    }
}
