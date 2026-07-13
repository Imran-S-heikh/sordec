//! Ordered pipeline of [`Pass`]es with optional fixpoint groups.
//!
//! Pass ordering is hand-written into the manifest passed to
//! [`Pipeline::new`]. Within `fixpoint_groups`, the listed contiguous
//! range of passes is repeatedly invoked until no pass reports
//! `changed: true`. The architecture's monotonicity invariant
//! guarantees this loop terminates.

use std::collections::{BTreeMap, HashSet};
use std::ops::Range;

use sordec_common::Diagnostic;

use crate::pass::{Pass, PassResult};

/// Manifest-ordered pipeline of [`Pass`]es operating on the same IR layer.
///
/// Constructed via [`Pipeline::new`]. Validates at construction time
/// that pass names are unique and that fixpoint groups do not overlap
/// or fall outside the pass list — both panic immediately if violated,
/// surfacing programmer error at startup rather than during a long
/// decompilation run.
pub struct Pipeline<Ir> {
    passes: Vec<Box<dyn Pass<Ir>>>,
    fixpoint_groups: Vec<Range<usize>>,
}

impl<Ir> Pipeline<Ir> {
    /// Build a pipeline.
    ///
    /// # Panics
    ///
    /// - If two passes share a name. Pass names are used as dictionary
    ///   keys in [`sordec_common::Provenance`]; duplicates would silently
    ///   conflate distinct passes and corrupt the audit trail.
    /// - If a `fixpoint_groups` entry is empty, exceeds the pass count,
    ///   or overlaps another group. These would all be silent
    ///   correctness bugs at runtime.
    #[must_use]
    pub fn new(
        passes: Vec<Box<dyn Pass<Ir>>>,
        fixpoint_groups: Vec<Range<usize>>,
    ) -> Self {
        // Reject duplicate pass names.
        let mut seen: HashSet<&'static str> = HashSet::with_capacity(passes.len());
        for pass in &passes {
            assert!(
                seen.insert(pass.name()),
                "Pipeline::new: duplicate pass name `{}`",
                pass.name()
            );
        }

        // Reject malformed fixpoint groups.
        let mut covered: Vec<bool> = vec![false; passes.len()];
        for group in &fixpoint_groups {
            assert!(
                group.start < group.end,
                "Pipeline::new: empty fixpoint group {group:?}"
            );
            assert!(
                group.end <= passes.len(),
                "Pipeline::new: fixpoint group {group:?} exceeds pass count {}",
                passes.len()
            );
            for idx in group.clone() {
                assert!(
                    !covered[idx],
                    "Pipeline::new: fixpoint groups overlap at index {idx}"
                );
                covered[idx] = true;
            }
        }

        Self {
            passes,
            fixpoint_groups,
        }
    }

    /// Number of distinct passes in the pipeline.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.passes.len()
    }

    /// Whether the pipeline has any passes.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.passes.is_empty()
    }

    /// Execute the pipeline on `ir`, looping fixpoint groups to convergence.
    ///
    /// Within a fixpoint group, all passes in the group's index range
    /// are run in declaration order; the group repeats until no pass in
    /// it returns `changed: true`. Passes outside any fixpoint group
    /// run exactly once in declaration order.
    pub fn run(&self, ir: &mut Ir) -> PipelineReport {
        let mut report = PipelineReport::default();
        let mut idx = 0;
        while idx < self.passes.len() {
            if let Some(group) = self.fixpoint_groups.iter().find(|g| g.start == idx) {
                let mut iterations = 0u32;
                loop {
                    iterations += 1;
                    let mut any_changed = false;
                    for slot in group.clone() {
                        let pass = &self.passes[slot];
                        let result = pass.run(ir);
                        if result.changed {
                            any_changed = true;
                        }
                        report.per_pass.push((pass.name(), result));
                    }
                    if !any_changed {
                        break;
                    }
                }
                report.fixpoint_iterations.push(iterations);
                idx = group.end;
            } else {
                let pass = &self.passes[idx];
                let result = pass.run(ir);
                report.per_pass.push((pass.name(), result));
                idx += 1;
            }
        }
        report.passes_run = report.per_pass.len();
        report
    }
}

/// Diagnostic record produced by [`Pipeline::run`].
///
/// `per_pass` records every pass invocation in order — including
/// repeated invocations from fixpoint groups, which is what makes this
/// useful for analysing why a particular fixpoint loop took so many
/// iterations.
#[derive(Debug, Default, Clone)]
pub struct PipelineReport {
    /// Total pass invocations (including fixpoint repetitions).
    pub passes_run: usize,

    /// One entry per fixpoint group, in declaration order, recording how
    /// many iterations that group required to converge.
    pub fixpoint_iterations: Vec<u32>,

    /// Every pass invocation: `(pass_name, result)`.
    pub per_pass: Vec<(&'static str, PassResult)>,
}

impl PipelineReport {
    /// Every diagnostic every pass surfaced, in invocation order.
    pub fn diagnostics(&self) -> impl Iterator<Item = &Diagnostic> {
        self.per_pass
            .iter()
            .flat_map(|(_, result)| result.diagnostics.iter())
    }

    /// Per-code diagnostic counts, keyed on the stable
    /// [`DiagnosticCode::key`](sordec_common::DiagnosticCode::key)
    /// (`<layer>::snake_case`) — the aggregation feeding `sordec coverage`.
    /// Sorted by key for deterministic output.
    #[must_use]
    pub fn diagnostic_counts_by_code(&self) -> BTreeMap<&'static str, usize> {
        let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
        for diagnostic in self.diagnostics() {
            *counts.entry(diagnostic.code.key()).or_insert(0) += 1;
        }
        counts
    }

    /// Every pass's [`PassMetrics`](crate::PassMetrics) counters summed
    /// across all invocations into one `counter-key → total` map — the
    /// per-pattern recognition signal feeding the `sordec coverage`
    /// recognition + headline sections (spec F1–F8).
    ///
    /// A counter emitted by a fixpoint-repeated pass accumulates across
    /// every invocation, matching [`Self::diagnostics`]'s invocation-order
    /// semantics. Keys are the stable `&'static str`s catalogued in
    /// [`crate::metrics_catalog`]; sorted for deterministic output.
    #[must_use]
    pub fn metric_totals(&self) -> BTreeMap<&'static str, i64> {
        let mut totals: BTreeMap<&'static str, i64> = BTreeMap::new();
        for (_pass, result) in &self.per_pass {
            for (key, value) in result.metrics.iter() {
                *totals.entry(key).or_insert(0) += value;
            }
        }
        totals
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pass::PassMetrics;

    struct CountUp {
        name: &'static str,
        target: u32,
    }
    impl Pass<u32> for CountUp {
        fn name(&self) -> &'static str {
            self.name
        }
        fn run(&self, ir: &mut u32) -> PassResult {
            if *ir < self.target {
                *ir += 1;
                PassResult {
                    changed: true,
                    ..Default::default()
                }
            } else {
                PassResult::default()
            }
        }
    }

    #[test]
    fn diagnostic_counts_aggregate_by_code_across_passes() {
        use sordec_common::{Diagnostic, LiftDiagnosticCode};
        let mut report = PipelineReport::default();
        let mk = |code| PassResult {
            diagnostics: vec![Diagnostic::warning(code, "x")],
            ..Default::default()
        };
        report.per_pass.push(("a", mk(LiftDiagnosticCode::NonConstantTtlAmount)));
        report.per_pass.push(("b", mk(LiftDiagnosticCode::NonConstantTtlAmount)));
        report
            .per_pass
            .push(("c", mk(LiftDiagnosticCode::UnrecognisedHostCall)));

        assert_eq!(report.diagnostics().count(), 3);
        let counts = report.diagnostic_counts_by_code();
        assert_eq!(counts.get("lift::non_constant_ttl_amount"), Some(&2));
        assert_eq!(counts.get("lift::unrecognised_host_call"), Some(&1));
    }

    #[test]
    fn metric_totals_sum_counters_across_pass_invocations() {
        let mut report = PipelineReport::default();
        let mk = |k1: &'static str, v1, k2: &'static str, v2| {
            let mut metrics = PassMetrics::new();
            metrics.increment(k1, v1);
            metrics.increment(k2, v2);
            PassResult {
                metrics,
                ..Default::default()
            }
        };
        // Same key ("shared") emitted by two passes must accumulate; a
        // fixpoint-repeated pass would land here as another entry too.
        report.per_pass.push(("a", mk("shared", 2, "only_a", 1)));
        report.per_pass.push(("b", mk("shared", 3, "only_b", 5)));

        let totals = report.metric_totals();
        assert_eq!(totals.get("shared"), Some(&5));
        assert_eq!(totals.get("only_a"), Some(&1));
        assert_eq!(totals.get("only_b"), Some(&5));
        assert_eq!(totals.get("never"), None);
    }

    #[test]
    fn empty_pipeline_runs_no_passes() {
        let pipeline = Pipeline::<u32>::new(vec![], vec![]);
        let mut value = 0u32;
        let report = pipeline.run(&mut value);
        assert_eq!(report.passes_run, 0);
        assert_eq!(value, 0);
    }

    #[test]
    fn linear_pipeline_runs_each_pass_once() {
        let pipeline = Pipeline::<u32>::new(
            vec![
                Box::new(CountUp {
                    name: "a",
                    target: 100,
                }),
                Box::new(CountUp {
                    name: "b",
                    target: 100,
                }),
            ],
            vec![],
        );
        let mut value = 0u32;
        let report = pipeline.run(&mut value);
        assert_eq!(report.passes_run, 2);
        assert_eq!(value, 2); // each pass added 1
    }

    #[test]
    #[allow(clippy::single_range_in_vec_init)]
    fn fixpoint_group_loops_until_no_change() {
        let pipeline = Pipeline::<u32>::new(
            vec![Box::new(CountUp {
                name: "loop_pass",
                target: 5,
            })],
            vec![0..1],
        );
        let mut value = 0u32;
        let report = pipeline.run(&mut value);
        // Loops six times: five changes + one no-op iteration that breaks.
        assert_eq!(report.passes_run, 6);
        assert_eq!(report.fixpoint_iterations, vec![6]);
        assert_eq!(value, 5);
    }

    #[test]
    #[should_panic(expected = "duplicate pass name")]
    fn duplicate_pass_name_panics_at_construction() {
        let _ = Pipeline::<u32>::new(
            vec![
                Box::new(CountUp {
                    name: "shared",
                    target: 0,
                }),
                Box::new(CountUp {
                    name: "shared",
                    target: 0,
                }),
            ],
            vec![],
        );
    }

    #[test]
    #[should_panic(expected = "exceeds pass count")]
    #[allow(clippy::single_range_in_vec_init)]
    fn out_of_bounds_fixpoint_group_panics() {
        let _ = Pipeline::<u32>::new(
            vec![Box::new(CountUp {
                name: "only",
                target: 0,
            })],
            vec![0..2],
        );
    }

    #[test]
    #[should_panic(expected = "overlap")]
    fn overlapping_fixpoint_groups_panic() {
        let _ = Pipeline::<u32>::new(
            vec![
                Box::new(CountUp {
                    name: "a",
                    target: 0,
                }),
                Box::new(CountUp {
                    name: "b",
                    target: 0,
                }),
                Box::new(CountUp {
                    name: "c",
                    target: 0,
                }),
            ],
            vec![0..2, 1..3],
        );
    }
}
