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
use crate::report::CategoryScore;
use crate::simil::{self, Multiset};

/// Score the semantic category.
pub(crate) fn evaluate(reconstructed: &syn::File, original: &syn::File) -> CategoryScore {
    let recon = bag(&extract::extract(reconstructed));
    let orig = bag(&extract::extract(original));

    let recon_total: usize = recon.values().sum();
    let orig_total: usize = orig.values().sum();

    let overlap: usize = orig
        .iter()
        .map(|(key, count)| *count.min(recon.get(key).unwrap_or(&0)))
        .sum();

    let Some(outcome) = simil::prf(overlap, recon_total, orig_total) else {
        return CategoryScore::unchecked("no semantic facts on either side — nothing to measure");
    };

    let mut score = CategoryScore::checked(outcome.f1).with_note(format!(
        "precision={} recall={} ({orig_total} original facts, {recon_total} reconstructed)",
        simil::render_ratio(outcome.precision),
        simil::render_ratio(outcome.recall),
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
    fn empty_semantics_are_unchecked_not_perfect() {
        // Pure arithmetic carries no Soroban-operation facts. Nothing was
        // recovered because there was nothing to recover — unmeasurable,
        // not perfect. This is the hello-add fixture's shape.
        let f = file("fn helper(a: u32) -> u32 { a + 1 }");
        let score = evaluate(&f, &f);
        assert!(!score.checked, "a 0-fact comparison must not be checked");
        assert_ne!(score.score, 1.0);
    }

    #[test]
    fn facts_invented_against_a_factless_original_score_zero() {
        // The original has no facts but the reconstruction claims some:
        // recall is undefined, precision is a real 0.0, and the category
        // stays checked — inventing facts is a measurable failure.
        let orig = file("fn helper(a: u32) -> u32 { a + 1 }");
        let recon = file(CONTRACT);
        let score = evaluate(&recon, &orig);
        assert!(score.checked, "invented facts are measurable");
        assert_eq!(score.score, 0.0);
        let note = score.notes.first().expect("a summary note");
        assert!(
            note.contains("recall=n/a"),
            "recall must read as undefined, got: {note}"
        );
    }
}
