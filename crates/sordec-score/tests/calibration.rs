//! Calibration battery — the anti-Goodhart guards (K6/G5).
//!
//! A self-graded ≥90% is only credible if the instrument is shown not to
//! be gameable. These tests pin the three properties that make the score
//! trustworthy:
//!
//! - **identity** — a source scored against itself is `1.0`, on every real
//!   fixture and every category.
//! - **invariance** — transformations that preserve meaning (import
//!   qualifiers, formatting, local-variable names) do not cost score.
//! - **mutation** — a real semantic change degrades the score, in the
//!   *right* category, and monotonically with the number of changes.
//!
//! The `_legacy` decompiler's output is the documented baseline-to-beat;
//! generating it needs the legacy binary, so that number lives in the
//! metric writeup rather than a hermetic test here.

use std::path::PathBuf;

use sordec_score::{score_paths, score_str, ScoreOptions};

/// Every fixture that ships Rust source under `source/src`.
const FIXTURES: [&str; 7] = [
    "attestation",
    "dex-liquidity-pool",
    "hello-add",
    "timelock",
    "token-v22",
    "token-v23",
    "token-v23-stripped",
];

fn fixture_src(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../samples/contracts")
        .join(name)
        .join("source/src")
}

fn opts() -> ScoreOptions {
    // The compilation category is opt-in and needs a toolchain; the
    // calibration guards are about the three AST categories.
    ScoreOptions {
        threshold: 0.90,
        check_compile: false,
    }
}

// ---------------------------------------------------------------------
// Identity: score(x, x) == 1.0
// ---------------------------------------------------------------------

#[test]
fn identity_is_perfect_on_every_fixture() {
    for name in FIXTURES {
        let dir = fixture_src(name);
        let report = score_paths(&dir, &dir, &opts()).expect("score fixture");
        assert!(
            (report.overall - 1.0).abs() < 1e-9,
            "{name}: overall {} != 1.0",
            report.overall
        );
        assert_eq!(report.categories.interface.score, 1.0, "{name} interface");
        assert_eq!(report.categories.structure.score, 1.0, "{name} structure");
        assert_eq!(report.categories.semantic.score, 1.0, "{name} semantic");
        assert!(report.passed, "{name} must pass identity");
    }
}

// ---------------------------------------------------------------------
// A small, realistic contract the invariance + mutation tests transform.
// ---------------------------------------------------------------------

const BASE: &str = r#"
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
        e.storage().persistent().set(&key, &(b - amount));
        TransferEvent { to, amount }.publish(&e);
    }

    pub fn balance(e: Env, id: Address) -> i128 {
        let key = DataKey::Balance(id);
        e.storage().persistent().get::<DataKey, i128>(&key).unwrap()
    }
}
"#;

fn score_against_base(variant: &str) -> sordec_score::ScoreReport {
    score_str(variant, BASE, &opts()).expect("score variant")
}

// ---------------------------------------------------------------------
// Invariance: meaning-preserving edits cost nothing
// ---------------------------------------------------------------------

#[test]
fn invariant_to_import_qualifiers() {
    // Fully-qualified paths instead of imported names — same ABI + behavior.
    let qualified = BASE
        .replace(": Address", ": soroban_sdk::Address")
        .replace("(Address)", "(soroban_sdk::Address)");
    let report = score_against_base(&qualified);
    assert!(
        report.overall >= 0.999,
        "qualifier change cost score: {}",
        report.overall
    );
}

#[test]
fn invariant_to_local_variable_names() {
    // Rename the local `key` → `k`: the storage key still resolves to
    // `DataKey::Balance`, so no category should move.
    let renamed = BASE.replace("key", "k");
    let report = score_against_base(&renamed);
    assert!(
        report.overall >= 0.999,
        "local rename cost score: {}",
        report.overall
    );
    assert_eq!(report.categories.semantic.score, 1.0);
}

#[test]
fn invariant_to_formatting() {
    // Reformatting (whitespace only) can never move an AST-structural score.
    let reflowed = BASE.replace("\n", "\n    ").replace("    ", " ");
    let report = score_against_base(&reflowed);
    assert!((report.overall - 1.0).abs() < 1e-9);
}

// ---------------------------------------------------------------------
// Mutation: real changes degrade the right category
// ---------------------------------------------------------------------

#[test]
fn mutation_dropping_require_auth_hits_semantic_only() {
    let mutant = BASE.replace("from.require_auth();", "");
    let report = score_against_base(&mutant);
    assert!(
        report.categories.semantic.score < 1.0,
        "dropped auth must lower semantic"
    );
    // The ABI and control flow are unchanged.
    assert_eq!(report.categories.interface.score, 1.0);
    assert_eq!(report.categories.structure.score, 1.0);
}

#[test]
fn mutation_swapping_a_storage_tier_hits_semantic() {
    let mutant = BASE.replacen(".persistent()", ".instance()", 1);
    let report = score_against_base(&mutant);
    assert!(
        report.categories.semantic.score < 1.0,
        "swapped tier must lower semantic"
    );
    assert_eq!(report.categories.interface.score, 1.0);
}

#[test]
fn mutation_dropping_an_event_hits_semantic() {
    let mutant = BASE.replace("TransferEvent { to, amount }.publish(&e);", "");
    let report = score_against_base(&mutant);
    assert!(
        report.categories.semantic.score < 1.0,
        "dropped event must lower semantic"
    );
}

#[test]
fn mutation_removing_a_function_hits_interface_and_structure() {
    // Drop the whole `balance` entrypoint.
    let mutant = BASE.replace(
        r#"    pub fn balance(e: Env, id: Address) -> i128 {
        let key = DataKey::Balance(id);
        e.storage().persistent().get::<DataKey, i128>(&key).unwrap()
    }"#,
        "",
    );
    let report = score_against_base(&mutant);
    assert!(
        report.categories.interface.score < 1.0,
        "removed entrypoint must lower interface"
    );
    assert!(
        report.categories.structure.score < 1.0,
        "removed function must lower structure"
    );
}

#[test]
fn mutation_degrades_monotonically() {
    let one = BASE.replace("from.require_auth();", "");
    let two = one.replacen(".persistent()", ".instance()", 1);
    let three = two.replace("TransferEvent { to, amount }.publish(&e);", "");

    let s1 = score_against_base(&one).categories.semantic.score;
    let s2 = score_against_base(&two).categories.semantic.score;
    let s3 = score_against_base(&three).categories.semantic.score;

    assert!(s1 < 1.0, "one mutation: {s1}");
    assert!(s2 < s1, "two mutations {s2} !< one {s1}");
    assert!(s3 < s2, "three mutations {s3} !< two {s2}");
}
