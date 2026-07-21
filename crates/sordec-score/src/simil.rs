//! Similarity primitives shared by the category scorers.
//!
//! Salvaged from the legacy scorer's `evaluate.rs` (ported to `f64` and
//! with an explicit multiset builder): longest-common-subsequence sequence
//! similarity for ordered token streams, and Sørensen–Dice multiset
//! similarity for bag-of-features overlap. Both return `1.0` when both
//! inputs are empty (nothing to reproduce, perfectly reproduced) and `0.0`
//! when exactly one is empty.

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
    let overlap: usize = a
        .iter()
        .map(|(key, count)| *count.min(b.get(key).unwrap_or(&0)))
        .sum();
    2.0 * overlap as f64 / (total_a + total_b) as f64
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
}
