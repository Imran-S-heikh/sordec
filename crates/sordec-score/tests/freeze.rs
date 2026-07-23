//! Version-freeze guard (K6/G6).
//!
//! The metric is frozen + versioned: once the Phase 4 emitter is scored
//! against it, the algorithm and weights must not change silently. This
//! test pins [`SCORER_VERSION`] and a golden calibration vector — a fixed
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
        SCORER_VERSION, "score-1.0.0",
        "SCORER_VERSION changed — update the golden vector below to match"
    );
}

#[test]
fn golden_calibration_vector_is_stable() {
    let opts = ScoreOptions {
        threshold: 0.90,
        check_compile: false,
    };
    let report = score_str(GOLDEN_RECONSTRUCTED, GOLDEN_ORIGINAL, &opts).expect("score");

    assert_eq!(report.scorer_version, "score-1.0.0");
    // Frozen 2026-07-23 for score-1.0.0. Hand-checkable: interface drops
    // `admin` (recall 3/4 → F1 0.8571); structure is 2 matched of 3 names
    // (0.6667); semantic loses the swapped-tier storage ops + `admin`'s
    // facts (0.6250); overall is the weight-normalized mean over the three
    // checked categories (0.7192).
    assert_close(report.categories.interface.score, 0.857143, "interface");
    assert_close(report.categories.structure.score, 0.666667, "structure");
    assert_close(report.categories.semantic.score, 0.625000, "semantic");
    assert_close(report.overall, 0.719188, "overall");
}
