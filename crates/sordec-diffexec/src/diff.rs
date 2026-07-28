//! Comparing what two contracts did.
//!
//! # The four observations stay separate
//!
//! Each call yields four independent verdicts — return value, events,
//! authorizations, storage — and they are never blended into one number here.
//! "events 94%, storage 87%" says where to work; "93%" says nothing.
//!
//! # Nothing-versus-nothing is not agreement
//!
//! A tuple neither side exercised reports [`Verdict::NotExercised`] and is left
//! out of both halves of the ratio. Counting it as a match is the same mistake
//! `sordec-score` made before T8 — an extraction that found nothing scored a
//! perfect 1.0 — and the same one T13d fixed for structure. A contract with no
//! events must not earn credit for matching on events.
//!
//! # Mutual failure is not agreement either
//!
//! Two contracts that both panic on garbage input agree perfectly and demonstrate
//! nothing. Such a call is flagged [`CallDiff::trivial_agreement`] and excluded
//! from the match rate entirely, never folded into it. This is a recognised
//! limitation of differential testing, not a private worry, and the honest
//! response is a separate bucket.
//!
//! Note the precondition: *both failed the same way*. A side that returns error
//! code 4 against one that traps is a genuine divergence, not trivial agreement —
//! that is precisely the class our emitter produces when it drops an error code.
//!
//! # What this module does not do
//!
//! Stop at the first divergence. Lockstep execution with early exit is the
//! driver's job; the comparator compares whatever sequence it is handed.

use crate::exec::{Call, Observation};

/// Which of the four observations a verdict is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tuple {
    /// The value the call returned, or the failure it produced.
    Return,
    /// The events it published.
    Events,
    /// The authorizations it required.
    Auth,
    /// The storage it left behind.
    Storage,
}

impl Tuple {
    /// A short stable name, for reports.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Return => "return",
            Self::Events => "events",
            Self::Auth => "auth",
            Self::Storage => "storage",
        }
    }
}

/// One tuple's verdict for one call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Both sides produced the same thing.
    Match,
    /// The sides differ. Both renderings are kept, because which side has what is
    /// the whole diagnostic.
    Divergent {
        /// What the original produced.
        original: String,
        /// What the reconstruction produced.
        reconstruction: String,
    },
    /// Neither side produced anything for this tuple, so there was nothing to
    /// compare. Excluded from the ratio rather than scored either way.
    NotExercised,
}

impl Verdict {
    /// Whether this verdict contributes to the ratio at all.
    #[must_use]
    pub fn is_exercised(&self) -> bool {
        !matches!(self, Self::NotExercised)
    }

    /// Whether this verdict is an agreement.
    #[must_use]
    pub fn is_match(&self) -> bool {
        matches!(self, Self::Match)
    }
}

/// One call's comparison across all four tuples.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallDiff {
    /// The function that was called.
    pub function: String,
    /// Both sides failed in the same way, so this call demonstrates nothing.
    /// Excluded from the match rate; reported so the exclusion is visible.
    pub trivial_agreement: bool,
    /// Verdict on the returned value.
    pub return_value: Verdict,
    /// Verdict on the published events.
    pub events: Verdict,
    /// Verdict on the required authorizations.
    pub auth: Verdict,
    /// Verdict on the resulting storage.
    pub storage: Verdict,
}

impl CallDiff {
    /// The four verdicts with their tuple names, in canonical order.
    ///
    /// One owner for the tuple↔verdict mapping, so a report and the arithmetic
    /// cannot disagree about which is which — the same discipline
    /// `sordec-score`'s `Categories::pairs` keeps.
    #[must_use]
    pub fn verdicts(&self) -> [(Tuple, &Verdict); 4] {
        [
            (Tuple::Return, &self.return_value),
            (Tuple::Events, &self.events),
            (Tuple::Auth, &self.auth),
            (Tuple::Storage, &self.storage),
        ]
    }

    /// Whether every exercised tuple agreed.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.verdicts()
            .iter()
            .all(|(_, verdict)| !matches!(verdict, Verdict::Divergent { .. }))
    }
}

/// A whole sequence's comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Comparison {
    /// Per-call results, in call order.
    pub calls: Vec<CallDiff>,
    /// Anything that qualifies the comparison itself.
    pub notes: Vec<String>,
}

impl Comparison {
    /// Tuple checks that were exercised, over calls that were not trivial
    /// agreements.
    #[must_use]
    pub fn exercised(&self) -> usize {
        self.scored_calls()
            .flat_map(|call| call.verdicts())
            .filter(|(_, verdict)| verdict.is_exercised())
            .count()
    }

    /// Exercised tuple checks that agreed.
    #[must_use]
    pub fn matched(&self) -> usize {
        self.scored_calls()
            .flat_map(|call| call.verdicts())
            .filter(|(_, verdict)| verdict.is_match())
            .count()
    }

    /// Calls excluded because both sides failed identically.
    #[must_use]
    pub fn trivial_agreements(&self) -> usize {
        self.calls
            .iter()
            .filter(|call| call.trivial_agreement)
            .count()
    }

    /// The match rate, or `None` when nothing was exercised.
    ///
    /// `None` rather than `0.0` or `1.0`: a comparison that measured nothing has
    /// no rate, and forcing one would mean inventing a number. Callers map it to
    /// an *unchecked* category.
    #[must_use]
    pub fn score(&self) -> Option<f64> {
        let exercised = self.exercised();
        if exercised == 0 {
            return None;
        }
        #[allow(clippy::cast_precision_loss)]
        Some(self.matched() as f64 / exercised as f64)
    }

    /// Which tuples were exercised at all, and how each fared — the per-tuple
    /// breakdown a report needs.
    #[must_use]
    pub fn by_tuple(&self, tuple: Tuple) -> TupleSummary {
        let mut summary = TupleSummary {
            tuple,
            exercised: 0,
            matched: 0,
        };
        // Selected by comparing the tuple, not by indexing into `verdicts()`.
        // Indexing would silently start reporting the wrong tuple if that array's
        // order ever changed, which is exactly the coupling `verdicts()` exists
        // to prevent.
        let selected = self
            .scored_calls()
            .flat_map(CallDiff::verdicts)
            .filter(|(candidate, _)| *candidate == tuple)
            .map(|(_, verdict)| verdict);

        for verdict in selected {
            if verdict.is_exercised() {
                summary.exercised += 1;
                if verdict.is_match() {
                    summary.matched += 1;
                }
            }
        }
        summary
    }

    /// Calls that count toward the rate.
    fn scored_calls(&self) -> impl Iterator<Item = &CallDiff> {
        self.calls.iter().filter(|call| !call.trivial_agreement)
    }
}

/// How one tuple fared across a whole sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TupleSummary {
    /// Which tuple.
    pub tuple: Tuple,
    /// Calls where this tuple was exercised.
    pub exercised: usize,
    /// Of those, how many agreed.
    pub matched: usize,
}

impl TupleSummary {
    /// The rate for this tuple, or `None` when it was never exercised.
    #[must_use]
    pub fn rate(self) -> Option<f64> {
        if self.exercised == 0 {
            return None;
        }
        #[allow(clippy::cast_precision_loss)]
        Some(self.matched as f64 / self.exercised as f64)
    }
}

/// Compare two observation sequences produced by the same calls.
///
/// Both observation slices must already be canonicalised
/// ([`crate::canon::Canonicalizer::observation`]); comparing raw observations
/// would report every address as a divergence.
#[must_use]
pub fn compare(
    calls: &[Call],
    original: &[Observation],
    reconstruction: &[Observation],
) -> Comparison {
    let mut notes = Vec::new();
    // A length mismatch is a harness fault, not a finding: both sides are driven
    // by the same call list. Say so rather than silently comparing a prefix.
    if original.len() != reconstruction.len() {
        notes.push(format!(
            "observation counts differ (original {}, reconstruction {}); \
             compared the common prefix only",
            original.len(),
            reconstruction.len()
        ));
    }

    let diffs = original
        .iter()
        .zip(reconstruction.iter())
        .enumerate()
        .map(|(index, (left, right))| {
            let function = calls
                .get(index)
                .map_or_else(|| format!("call[{index}]"), |call| call.function.clone());
            diff_call(function, left, right)
        })
        .collect();

    Comparison {
        calls: diffs,
        notes,
    }
}

/// Compare one call's observations.
fn diff_call(function: String, left: &Observation, right: &Observation) -> CallDiff {
    // Both failed the same way: agreement that proves nothing.
    let trivial_agreement =
        left.outcome.is_failure() && right.outcome.is_failure() && left.outcome == right.outcome;

    CallDiff {
        function,
        trivial_agreement,
        // The return tuple is always exercised: every call produced an outcome,
        // even if that outcome was a failure.
        return_value: verdict_always(&left.outcome, &right.outcome),
        events: verdict_if_either_nonempty(&left.events, &right.events),
        auth: verdict_if_either_nonempty(&left.auths, &right.auths),
        storage: verdict_if_either_nonempty(&left.storage, &right.storage),
    }
}

/// A verdict for a tuple that is always present.
fn verdict_always<T: PartialEq + std::fmt::Debug>(left: &T, right: &T) -> Verdict {
    if left == right {
        Verdict::Match
    } else {
        Verdict::Divergent {
            original: format!("{left:?}"),
            reconstruction: format!("{right:?}"),
        }
    }
}

/// A verdict for a tuple only one or both sides may have produced.
///
/// Empty on both sides is [`Verdict::NotExercised`]. Empty on *one* side is a
/// divergence, and an important one: a reconstruction that publishes no events
/// where the original published three has lost behaviour.
fn verdict_if_either_nonempty<T: PartialEq + std::fmt::Debug>(left: &[T], right: &[T]) -> Verdict {
    if left.is_empty() && right.is_empty() {
        return Verdict::NotExercised;
    }
    verdict_always(&left, &right)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::{ObservedEvent, Outcome};
    use soroban_sdk::xdr::ScVal;

    fn observation(outcome: Outcome) -> Observation {
        Observation {
            outcome,
            events: Vec::new(),
            auths: Vec::new(),
            storage: Vec::new(),
        }
    }

    fn event(data: u32) -> ObservedEvent {
        ObservedEvent {
            contract: ScVal::Void,
            topics: vec![ScVal::U32(1)],
            data: ScVal::U32(data),
        }
    }

    fn calls() -> Vec<Call> {
        vec![Call::new("f", Vec::new())]
    }

    #[test]
    fn identical_observations_match_on_the_tuples_they_exercise() {
        let left = vec![observation(Outcome::Value(ScVal::U32(5)))];
        let right = left.clone();
        let comparison = compare(&calls(), &left, &right);

        assert_eq!(comparison.score(), Some(1.0));
        // Only the return tuple was exercised — this contract published no
        // events, required no auth and wrote no storage.
        assert_eq!(comparison.exercised(), 1);
        assert_eq!(comparison.by_tuple(Tuple::Events).exercised, 0);
        assert_eq!(comparison.by_tuple(Tuple::Events).rate(), None);
    }

    #[test]
    fn an_unexercised_tuple_is_not_a_free_match() {
        // The T8 lesson: nothing-versus-nothing must not read as perfect. Here it
        // must not even be counted.
        let left = vec![observation(Outcome::Value(ScVal::U32(5)))];
        let comparison = compare(&calls(), &left, &left.clone());

        for (tuple, verdict) in comparison.calls[0].verdicts() {
            if tuple == Tuple::Return {
                continue;
            }
            assert_eq!(*verdict, Verdict::NotExercised, "{}", tuple.name());
        }
        assert_eq!(comparison.exercised(), 1, "3 empty tuples must not inflate this");
    }

    #[test]
    fn a_differing_return_value_is_a_divergence() {
        let left = vec![observation(Outcome::Value(ScVal::U32(5)))];
        let right = vec![observation(Outcome::Value(ScVal::U32(6)))];
        let comparison = compare(&calls(), &left, &right);

        assert_eq!(comparison.score(), Some(0.0));
        assert!(matches!(
            comparison.calls[0].return_value,
            Verdict::Divergent { .. }
        ));
        assert!(!comparison.calls[0].is_clean());
    }

    #[test]
    fn both_panicking_is_trivial_agreement_and_scores_nothing() {
        let left = vec![observation(Outcome::Aborted)];
        let right = vec![observation(Outcome::Aborted)];
        let comparison = compare(&calls(), &left, &right);

        assert_eq!(comparison.trivial_agreements(), 1);
        // Excluded entirely: not a match, not a miss, and no rate at all, because
        // this was the only call.
        assert_eq!(comparison.exercised(), 0);
        assert_eq!(comparison.matched(), 0);
        assert_eq!(comparison.score(), None);
    }

    #[test]
    fn different_failures_are_a_real_divergence_not_trivial_agreement() {
        // The class our emitter produces when it drops an error code: the original
        // returns a coded error, ours bare-traps. Both "failed", and that is not
        // agreement.
        let left = vec![observation(Outcome::ContractError(4))];
        let right = vec![observation(Outcome::Aborted)];
        let comparison = compare(&calls(), &left, &right);

        assert_eq!(comparison.trivial_agreements(), 0);
        assert_eq!(comparison.score(), Some(0.0));
    }

    #[test]
    fn losing_all_events_is_a_divergence_not_an_unexercised_tuple() {
        let mut left = observation(Outcome::Value(ScVal::Void));
        left.events = vec![event(1)];
        let right = observation(Outcome::Value(ScVal::Void));

        let comparison = compare(&calls(), &[left], &[right]);
        assert!(matches!(comparison.calls[0].events, Verdict::Divergent { .. }));
        // Return matched, events diverged.
        assert_eq!(comparison.exercised(), 2);
        assert_eq!(comparison.matched(), 1);
        assert_eq!(comparison.score(), Some(0.5));
    }

    #[test]
    fn per_tuple_rates_are_reported_independently() {
        let mut left = observation(Outcome::Value(ScVal::U32(1)));
        left.events = vec![event(1)];
        let mut right = observation(Outcome::Value(ScVal::U32(1)));
        right.events = vec![event(2)];

        let comparison = compare(&calls(), &[left], &[right]);
        assert_eq!(comparison.by_tuple(Tuple::Return).rate(), Some(1.0));
        assert_eq!(comparison.by_tuple(Tuple::Events).rate(), Some(0.0));
        assert_eq!(comparison.by_tuple(Tuple::Storage).rate(), None);
    }

    #[test]
    fn a_length_mismatch_is_noted_rather_than_hidden() {
        let left = vec![
            observation(Outcome::Value(ScVal::U32(1))),
            observation(Outcome::Value(ScVal::U32(2))),
        ];
        let right = vec![observation(Outcome::Value(ScVal::U32(1)))];
        let comparison = compare(&calls(), &left, &right);

        assert_eq!(comparison.calls.len(), 1);
        assert!(
            comparison.notes.iter().any(|n| n.contains("counts differ")),
            "{:?}",
            comparison.notes
        );
    }
}
