//! Similarity primitives shared by the category scorers.
//!
//! Salvaged from the legacy scorer's `evaluate.rs` (ported to `f64` and
//! with an explicit multiset builder): longest-common-subsequence sequence
//! similarity for ordered token streams, and Sørensen–Dice multiset
//! similarity for bag-of-features overlap. Both return `1.0` when both
//! inputs are empty (nothing to reproduce, perfectly reproduced) and `0.0`
//! when exactly one is empty.
//!
//! Those two operate on a *single function's* token stream, where "both
//! empty" means both sides are straight-line code — a genuine perfect
//! match. That is deliberately different from [`prf`], which operates on a
//! *whole category's* population and treats "both empty" as *nothing was
//! measured*. See [`prf`] for why the distinction is load-bearing.

use std::collections::BTreeMap;

/// Sørensen–Dice similarity over two ordered token streams via their
/// longest common subsequence: `2·|LCS| / (|a| + |b|)`.
pub(crate) fn sequence_similarity(a: &[String], b: &[String]) -> f64 {
    match (a.is_empty(), b.is_empty()) {
        (true, true) => return 1.0,
        (true, false) | (false, true) => return 0.0,
        _ => {}
    }
    let lcs = lcs_len(a, b);
    2.0 * lcs as f64 / (a.len() + b.len()) as f64
}

/// Sørensen–Dice similarity over two multisets: `2·|overlap| / (|a| + |b|)`
/// where overlap sums the per-key minimum counts.
pub(crate) fn multiset_similarity(a: &Multiset, b: &Multiset) -> f64 {
    let total_a: usize = a.values().sum();
    let total_b: usize = b.values().sum();
    match (total_a, total_b) {
        (0, 0) => return 1.0,
        (0, _) | (_, 0) => return 0.0,
        _ => {}
    }
    2.0 * multiset_overlap(a, b) as f64 / (total_a + total_b) as f64
}

/// How many token occurrences the two bags share: the per-key minimum count,
/// summed.
///
/// Shared with the structure category's token census (T13e), which reports
/// this as control-flow precision/recall alongside the score — the same
/// overlap the similarity above divides by.
pub(crate) fn multiset_overlap(a: &Multiset, b: &Multiset) -> usize {
    a.iter()
        .map(|(key, count)| *count.min(b.get(key).unwrap_or(&0)))
        .sum()
}

/// A bag of tokens with per-token counts.
pub(crate) type Multiset = BTreeMap<String, usize>;

/// Build a [`Multiset`] from a token stream.
pub(crate) fn multiset(tokens: &[String]) -> Multiset {
    let mut bag = Multiset::new();
    for token in tokens {
        *bag.entry(token.clone()).or_insert(0) += 1;
    }
    bag
}

/// Precision / recall / F1 over two populations — the shared arithmetic
/// behind the interface and semantic categories.
///
/// A ratio whose denominator is zero is **undefined**, not `1.0`. An empty
/// side has nothing to get wrong, but it equally has nothing to get *right*,
/// and reporting a vacuous perfect score is how a degenerate extraction came
/// to read as a flawless reconstruction (score-2.0.0 T8).
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Prf {
    /// `overlap / reconstructed`, or `None` when nothing was reconstructed.
    pub precision: Option<f64>,
    /// `overlap / original`, or `None` when the original held nothing.
    pub recall: Option<f64>,
    /// Harmonic mean of precision and recall, counting an undefined side as
    /// `0.0` — so a one-sided population always scores `0.0`.
    pub f1: f64,
}

/// Precision/recall/F1 for `overlap` items shared between a reconstruction
/// of `recon_total` items and an original of `orig_total`.
///
/// Returns `None` when **both** populations are empty: nothing was compared,
/// so there is no score to report. Callers turn that into an *unchecked*
/// category (excluded from the weighted mean) rather than a perfect one —
/// "nothing was compared" is not "everything matched".
pub(crate) fn prf(overlap: usize, recon_total: usize, orig_total: usize) -> Option<Prf> {
    if recon_total == 0 && orig_total == 0 {
        return None;
    }
    let precision = ratio(overlap, recon_total);
    let recall = ratio(overlap, orig_total);
    // An undefined side contributes 0.0: one-sided populations score 0.0,
    // which is what a wholly-missing or wholly-invented set deserves.
    let (p, r) = (precision.unwrap_or(0.0), recall.unwrap_or(0.0));
    let f1 = if p + r == 0.0 {
        0.0
    } else {
        2.0 * p * r / (p + r)
    };
    Some(Prf {
        precision,
        recall,
        f1,
    })
}

/// `numerator / denominator`, or `None` when the denominator is zero — the
/// ratio is undefined, not perfect.
fn ratio(numerator: usize, denominator: usize) -> Option<f64> {
    (denominator != 0).then(|| numerator as f64 / denominator as f64)
}

/// Render a possibly-undefined ratio for a report note: four decimals, or
/// `n/a` when the ratio has no denominator to divide by.
pub(crate) fn render_ratio(value: Option<f64>) -> String {
    value.map_or_else(|| "n/a".to_string(), |v| format!("{v:.4}"))
}

/// Length of the longest common subsequence, in `O(|a|·|b|)` time and
/// `O(|b|)` space. Salvaged from the legacy scorer.
fn lcs_len(a: &[String], b: &[String]) -> usize {
    let mut prev = vec![0usize; b.len() + 1];
    let mut curr = vec![0usize; b.len() + 1];
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            if a[i - 1] == b[j - 1] {
                curr[j] = prev[j - 1] + 1;
            } else {
                curr[j] = curr[j - 1].max(prev[j]);
            }
        }
        std::mem::swap(&mut prev, &mut curr);
        curr.fill(0);
    }
    prev[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toks(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn identical_sequences_are_one() {
        let a = toks(&["branch:2", "return", "loop:while"]);
        assert!((sequence_similarity(&a, &a) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn both_empty_is_one_one_empty_is_zero() {
        assert!((sequence_similarity(&[], &[]) - 1.0).abs() < 1e-9);
        assert_eq!(sequence_similarity(&toks(&["x"]), &[]), 0.0);
    }

    #[test]
    fn partial_overlap_between_zero_and_one() {
        let a = toks(&["branch:2", "return"]);
        let b = toks(&["branch:2", "loop:while", "return"]);
        let s = sequence_similarity(&a, &b);
        assert!(s > 0.0 && s < 1.0, "similarity was {s}");
    }

    #[test]
    fn multiset_counts_repeats() {
        let a = multiset(&toks(&["branch:2", "branch:2", "return"]));
        let b = multiset(&toks(&["branch:2", "return"]));
        let s = multiset_similarity(&a, &b);
        // overlap = min(2,1) + min(1,1) = 2; total = 3 + 2 = 5 → 4/5.
        assert!((s - 0.8).abs() < 1e-9, "similarity was {s}");
    }

    // -----------------------------------------------------------------
    // prf: precision / recall / F1
    // -----------------------------------------------------------------

    #[test]
    fn both_populations_empty_is_unmeasurable() {
        // The T8 guard: nothing compared is not a perfect comparison.
        assert_eq!(prf(0, 0, 0), None);
    }

    #[test]
    fn a_perfect_overlap_is_one() {
        let p = prf(5, 5, 5).expect("measurable");
        assert_eq!(p.precision, Some(1.0));
        assert_eq!(p.recall, Some(1.0));
        assert!((p.f1 - 1.0).abs() < 1e-9);
    }

    #[test]
    fn nothing_reconstructed_leaves_precision_undefined() {
        // 18 original items, 0 reconstructed: recall is a real 0.0, but
        // precision has no denominator — it must not report 1.0.
        let p = prf(0, 0, 18).expect("measurable");
        assert_eq!(p.precision, None);
        assert_eq!(p.recall, Some(0.0));
        assert_eq!(p.f1, 0.0);
    }

    #[test]
    fn nothing_original_leaves_recall_undefined() {
        // The mirror case: facts invented against an empty original.
        let p = prf(0, 5, 0).expect("measurable");
        assert_eq!(p.precision, Some(0.0));
        assert_eq!(p.recall, None);
        assert_eq!(p.f1, 0.0);
    }

    #[test]
    fn partial_overlap_is_the_harmonic_mean() {
        // overlap 2 of 4 reconstructed, 2 of 8 original.
        let p = prf(2, 4, 8).expect("measurable");
        assert_eq!(p.precision, Some(0.5));
        assert_eq!(p.recall, Some(0.25));
        // 2 * 0.5 * 0.25 / 0.75
        assert!((p.f1 - 1.0 / 3.0).abs() < 1e-9, "f1 was {}", p.f1);
    }

    #[test]
    fn render_ratio_marks_undefined() {
        assert_eq!(render_ratio(Some(0.5)), "0.5000");
        assert_eq!(render_ratio(None), "n/a");
    }

    #[test]
    fn multiset_overlap_sums_per_key_minimums() {
        let bag = |tokens: &[&str]| multiset(&tokens.iter().map(|t| (*t).to_owned()).collect::<Vec<_>>());

        // Disjoint bags share nothing.
        assert_eq!(multiset_overlap(&bag(&["a"]), &bag(&["b"])), 0);
        // Repeats count, capped at the smaller side: two `a` vs three is two.
        assert_eq!(multiset_overlap(&bag(&["a", "a"]), &bag(&["a", "a", "a"])), 2);
        // Partial overlap sums per key: min(2,1) for `a` plus min(1,1) for `b`.
        assert_eq!(
            multiset_overlap(&bag(&["a", "a", "b"]), &bag(&["a", "b", "c"])),
            2
        );
        // Symmetric.
        assert_eq!(
            multiset_overlap(&bag(&["a", "b", "c"]), &bag(&["a", "a", "b"])),
            2
        );
        // An empty side shares nothing.
        assert_eq!(multiset_overlap(&bag(&[]), &bag(&["a"])), 0);
    }
}
