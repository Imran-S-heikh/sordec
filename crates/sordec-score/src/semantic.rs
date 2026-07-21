//! Semantic category: precision/recall over recovered Soroban-operation
//! facts.
//!
//! Both sides are reduced to a multiset of [`SemanticFact`] keys by the
//! [`extract`](crate::extract) idiom matcher. The overlap is the sum of
//! per-key minimum counts; precision = overlap / reconstructed total,
//! recall = overlap / original total, and the sub-score is their F1. This
//! is the category that moves when a `require_auth` is dropped, a storage
//! tier is swapped, or an `events().publish` goes missing.

use crate::extract;
use crate::facts::SemanticFact;
use crate::metrics;
use crate::report::CategoryScore;
use crate::simil::{self, Multiset};

/// Score the semantic category.
pub(crate) fn evaluate(reconstructed: &syn::File, original: &syn::File) -> CategoryScore {
    let recon = bag(&extract::extract(reconstructed));
    let orig = bag(&extract::extract(original));

    let recon_total: usize = recon.values().sum();
    let orig_total: usize = orig.values().sum();

    if recon_total == 0 && orig_total == 0 {
        return CategoryScore::checked(1.0, metrics::SEMANTIC_WEIGHT)
            .with_note("no semantic facts on either side");
    }

    let overlap: usize = orig
        .iter()
        .map(|(key, count)| *count.min(recon.get(key).unwrap_or(&0)))
        .sum();
    let precision = ratio(overlap, recon_total);
    let recall = ratio(overlap, orig_total);
    let f1 = if precision + recall == 0.0 {
        0.0
    } else {
        2.0 * precision * recall / (precision + recall)
    };

    let mut score = CategoryScore::checked(f1, metrics::SEMANTIC_WEIGHT).with_note(format!(
        "precision={precision:.4} recall={recall:.4} ({orig_total} original facts, {recon_total} reconstructed)"
    ));
    if let Some(note) = missing_note(&orig, &recon) {
        score = score.with_note(note);
    }
    score
}

/// Build a multiset of fact keys.
fn bag(facts: &[SemanticFact]) -> Multiset {
    let keys: Vec<String> = facts.iter().map(SemanticFact::key).collect();
    simil::multiset(&keys)
}

/// `numerator / denominator`, or `1.0` when the denominator is zero.
fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        1.0
    } else {
        numerator as f64 / denominator as f64
    }
}

/// A note naming original facts under-reproduced in the reconstruction
/// (recall misses), capped for readability.
fn missing_note(orig: &Multiset, recon: &Multiset) -> Option<String> {
    let mut missing: Vec<String> = orig
        .iter()
        .filter(|(key, count)| recon.get(*key).unwrap_or(&0) < *count)
        .map(|(key, _)| key.clone())
        .collect();
    if missing.is_empty() {
        return None;
    }
    missing.sort();
    const CAP: usize = 8;
    let shown = missing.len().min(CAP);
    let mut list = missing[..shown].join(", ");
    if missing.len() > CAP {
        list.push_str(&format!(", … (+{})", missing.len() - CAP));
    }
    Some(format!("under-recovered: {list}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(src: &str) -> syn::File {
        syn::parse_str(src).expect("source parses")
    }

    const CONTRACT: &str = r#"
        fn transfer(e: Env, from: Address, to: Address, amount: i128) {
            from.require_auth();
            let key = DataKey::Balance(from);
            let b = e.storage().persistent().get::<DataKey, i128>(&key);
            e.storage().persistent().set(&key, &amount);
            SetAdmin { from }.publish(&e);
        }
    "#;

    #[test]
    fn identical_semantics_score_one() {
        let f = file(CONTRACT);
        assert!((evaluate(&f, &f).score - 1.0).abs() < 1e-9);
    }

    #[test]
    fn a_dropped_require_auth_lowers_the_score() {
        let orig = file(CONTRACT);
        let recon = file(
            r#"
            fn transfer(e: Env, from: Address, to: Address, amount: i128) {
                let key = DataKey::Balance(from);
                let b = e.storage().persistent().get::<DataKey, i128>(&key);
                e.storage().persistent().set(&key, &amount);
                SetAdmin { from }.publish(&e);
            }
            "#,
        );
        assert!(evaluate(&recon, &orig).score < 1.0);
    }

    #[test]
    fn a_swapped_tier_lowers_the_score() {
        let orig = file(CONTRACT);
        let recon = file(
            r#"
            fn transfer(e: Env, from: Address, to: Address, amount: i128) {
                from.require_auth();
                let key = DataKey::Balance(from);
                let b = e.storage().instance().get::<DataKey, i128>(&key);
                e.storage().instance().set(&key, &amount);
                SetAdmin { from }.publish(&e);
            }
            "#,
        );
        assert!(evaluate(&recon, &orig).score < 1.0);
    }

    #[test]
    fn a_dropped_event_lowers_the_score() {
        let orig = file(CONTRACT);
        let recon = file(
            r#"
            fn transfer(e: Env, from: Address, to: Address, amount: i128) {
                from.require_auth();
                let key = DataKey::Balance(from);
                let b = e.storage().persistent().get::<DataKey, i128>(&key);
                e.storage().persistent().set(&key, &amount);
            }
            "#,
        );
        assert!(evaluate(&recon, &orig).score < 1.0);
    }

    #[test]
    fn empty_semantics_score_one() {
        let f = file("fn helper(a: u32) -> u32 { a + 1 }");
        assert!((evaluate(&f, &f).score - 1.0).abs() < 1e-9);
    }
}
