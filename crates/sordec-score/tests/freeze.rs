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
        SCORER_VERSION, "score-2.0.0",
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

    assert_eq!(report.scorer_version, "score-2.0.0");
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
    // No SCORER_VERSION bump: `score-2.0.0` is the in-progress rebuild
    // version and the convention through T9/T10/T11 is to re-freeze this
    // vector as the definition lands, not to bump per task.
    assert_close(report.categories.interface.score, 0.900000, "interface");
    assert_close(report.categories.structure.score, 0.500000, "structure");
    assert_close(report.categories.semantic.score, 0.625000, "semantic");
    assert_close(report.overall, 0.685294, "overall");
}
