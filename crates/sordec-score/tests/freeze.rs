//! Version-freeze guard (K6/G6).
//!
//! The metric is frozen + versioned: once the Phase 4 emitter is scored
//! against it, the algorithm and the *default* weights must not change
//! silently (a custom `--weights` profile is recorded per-report, not
//! frozen). This test pins [`SCORER_VERSION`] and a golden calibration
//! vector (scored under the default profile) — a fixed
//! reconstructed/original pair with deliberate, partial mismatches whose
//! per-category and overall scores are recorded to four decimals.
//!
//! Any change that can move a score (a re-weighting, an extractor or
//! canonicalization change, a new category) shifts these numbers and fails
//! this test. That failure is the point: it forces the change to be
//! conscious — bump [`SCORER_VERSION`] and update this snapshot in the same
//! commit.

use sordec_score::{score_str, ScoreOptions, SCORER_VERSION};

/// The frozen original.
const GOLDEN_ORIGINAL: &str = r#"
#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    Balance(Address),
    Admin,
}

#[contract]
pub struct Token;

#[contractimpl]
impl Token {
    pub fn transfer(e: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        let key = DataKey::Balance(from);
        let b = e.storage().persistent().get::<DataKey, i128>(&key).unwrap();
        if b < amount {
            panic!("insufficient");
        }
        e.storage().persistent().set(&key, &(b - amount));
    }

    pub fn balance(e: Env, id: Address) -> i128 {
        let key = DataKey::Balance(id);
        e.storage().persistent().get::<DataKey, i128>(&key).unwrap()
    }

    pub fn admin(e: Env) -> Address {
        e.storage().instance().get::<DataKey, Address>(&DataKey::Admin).unwrap()
    }
}
"#;

/// The frozen reconstruction: `admin` entrypoint dropped (interface +
/// structure miss), and `transfer`'s tier swapped persistent → instance
/// (semantic miss).
const GOLDEN_RECONSTRUCTED: &str = r#"
#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    Balance(Address),
    Admin,
}

#[contract]
pub struct Token;

#[contractimpl]
impl Token {
    pub fn transfer(e: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        let key = DataKey::Balance(from);
        let b = e.storage().instance().get::<DataKey, i128>(&key).unwrap();
        if b < amount {
            panic!("insufficient");
        }
        e.storage().instance().set(&key, &(b - amount));
    }

    pub fn balance(e: Env, id: Address) -> i128 {
        let key = DataKey::Balance(id);
        e.storage().persistent().get::<DataKey, i128>(&key).unwrap()
    }
}
"#;

fn assert_close(actual: f64, expected: f64, label: &str) {
    assert!(
        (actual - expected).abs() < 5e-5,
        "{label}: {actual:.6} drifted from the frozen {expected:.4} — if this \
         change is intentional, bump SCORER_VERSION and update the snapshot"
    );
}

#[test]
fn scorer_version_is_frozen() {
    assert_eq!(
        SCORER_VERSION, "score-2.1.0",
        "SCORER_VERSION changed — update the golden vector below to match"
    );
}

#[test]
fn golden_calibration_vector_is_stable() {
    let opts = ScoreOptions {
        threshold: 0.90,
        check_compile: false,
        ..Default::default()
    };
    let report = score_str(GOLDEN_RECONSTRUCTED, GOLDEN_ORIGINAL, &opts).expect("score");

    assert_eq!(report.scorer_version, "score-2.1.0");
    assert_eq!(report.weights_profile, "rfp-default");
    // Re-frozen 2026-07-27 for score-2.0.0, when T11 split the ABI F1 into
    // entrypoints and types. Hand-checkable: interface drops `admin`, so
    // entrypoints are 2 matched of 3 (F1 0.8) while the one `#[contracttype]`
    // is reproduced exactly (1.0) — the category is their mean, 0.9000, up
    // from the pooled 0.8571 because the correct type no longer shares a
    // denominator with the missing entrypoint. Semantic loses the
    // swapped-tier storage ops + `admin`'s facts (0.6250).
    //
    // Structure re-frozen again at T13d, 0.6667 -> 0.5000. Also
    // hand-checkable, and the drop is the intended effect:
    //
    //   transfer  both sides carry `if b < amount`  -> 1.0, measured
    //   balance   straight-line on both sides       -> drops out entirely
    //   admin     missing from the reconstruction   -> 0.0, measured
    //
    // Before T13d, `balance` contributed a free 1.0 for having no control
    // flow, which diluted the missing `admin` and reported 2/3. Of the
    // entrypoints structure could actually measure, one was reproduced and
    // one was not: 1/2. A category is neither penalized nor credited for
    // control flow the contract does not have.
    //
    // Amended in the same release: semantic compares fact *presence*,
    // not multiplicity (0.5714 -> 0.6000, overall 0.6664 -> 0.6765).
    // Which operations a contract performs is compiled into it; how
    // many times each is written out is the compiler's decision, since
    // it inlines a helper into its callers or outlines repeats into
    // one. In this vector the reconstruction swapped a storage tier on
    // `transfer`, so it still loses both of those facts — what it stops
    // losing is the second copy of the wrong one.
    //
    // Re-frozen 2026-09-20 for **score-2.1.0**, and this one is a
    // version bump rather than a re-freeze: the rule it lands is that a
    // fact whose only evidence the compiler deletes is dropped from
    // *both* sides rather than scored as a miss. Semantic 0.6250 ->
    // 0.5714, overall 0.6853 -> 0.6664 — the number goes **down** here,
    // because this vector's panic was one of the two facts the
    // reconstruction got right, and dropping a matched fact from both
    // sides costs a reconstruction that had recovered it.
    //
    // That direction is worth keeping in view. The rule is not leniency:
    // it removes a fact from the comparison whichever way it was going,
    // and on the corpus it happens to help because there we miss these
    // and here we match one. See `SemanticFact::is_recoverable` for what
    // qualifies and the measurement behind it (0 of 24 authored panic
    // messages survive into the deployed wasm).
    //
    // Earlier: no SCORER_VERSION bump through T9/T10/T11, because
    // `score-2.0.0` was the in-progress rebuild version and the
    // convention was to re-freeze this
    // vector as the definition lands, not to bump per task.
    //
    // T19 (compilation -> gate, behavior takes the category slot) deliberately
    // moved NOTHING here, and that is the point: `check_compile` is false in
    // this vector, so compilation was already `unchecked` and excluded from the
    // mean. Swapping one unchecked category for another at the same weight
    // (0.15, inherited) cannot change a weight-normalized mean over the checked
    // three. The four numbers below holding unchanged is what verifies T19 was a
    // pure restructuring. Re-weighting the other three *would* move them, which
    // is precisely why it was split into its own change.
    assert_close(report.categories.interface.score, 0.900000, "interface");
    assert_close(report.categories.structure.score, 0.500000, "structure");
    assert_close(report.categories.semantic.score, 0.600000, "semantic");
    assert_close(report.overall, 0.676471, "overall");
}
