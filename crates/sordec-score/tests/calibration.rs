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

use sordec_score::{ScoreOptions, score_paths, score_str};

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

/// Fixtures whose semantic category is *unmeasurable* — zero facts on
/// either side, so identity leaves it **unchecked** rather than claiming a
/// perfect 1.0 (score-2.0.0 T8).
///
/// The list is exact, not a floor. `hello-add` genuinely performs no Soroban
/// operations (`a + b`), so there is nothing for any scorer to recover — a
/// property of the contract, not a gap in the instrument.
///
/// **`attestation` was removed at T17.** It had been here for the opposite
/// reason: it *does* perform host operations, but the fact vocabulary could
/// not see crypto or PRNG, so a contract built specifically to exercise those
/// surfaces measured as if it were empty. Teaching the extractor
/// `env.crypto().<op>` and `env.prng().<op>` made it measurable — five facts
/// on the identity run — which is the whole point of this list being exact:
/// a category becoming measurable is a deliberate change to the instrument
/// and has to be recorded here consciously, by a failing test.
///
/// Note this is about *measurability*, not recovery. Scoring the real
/// reconstruction, attestation still reads 0 — our emitter has no lowering
/// for crypto host calls and emits `todo!("crypto::ComputeHashSha256")`
/// holes. The difference is that the gap is now a measured 0-of-5 rather
/// than invisible.
const SEMANTICALLY_UNMEASURABLE: [&str; 1] = ["hello-add"];

/// Fixtures whose *structure* category is unmeasurable on identity — no
/// entrypoint carries control flow on either side, so there is nothing to
/// compare and the category is **unchecked** rather than a false 1.0
/// (score-2.0.0 T13d).
///
/// Exact, not a floor, for the same reason as the list above. `hello-add`'s
/// only entrypoint is `a + b`: no branch, no loop, nothing for a
/// control-flow metric to say. Note this applies to *identity* — scoring the
/// real reconstruction, our side emits marshalling branches the source does
/// not have, so the pair is measurable and correctly scores 0.
const STRUCTURALLY_UNMEASURABLE: [&str; 1] = ["hello-add"];

fn opts() -> ScoreOptions {
    // The compilation gate is opt-in and needs a toolchain; the
    // calibration guards are about the three AST categories.
    ScoreOptions {
        threshold: 0.90,
        check_compile: false,
        ..Default::default()
    }
}

// ---------------------------------------------------------------------
// Identity: score(x, x) == 1.0
// ---------------------------------------------------------------------

/// Identity holds on every fixture: everything the scorer *measured* is
/// exactly perfect, and the overall is 1.0.
///
/// Stated over the **checked** categories, because a category that extracted
/// nothing is unchecked rather than falsely perfect (T8). On its own that
/// phrasing could pass vacuously — if a bug made every category unchecked,
/// "all checked categories are perfect" would be trivially true and this
/// anti-Goodhart guard would quietly stop guarding. So the measurement floor
/// below is load-bearing, not decoration: it pins exactly which categories
/// must still be measurable on which fixtures.
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
        assert!(report.passed, "{name} must pass identity");

        // Everything measured must be exactly perfect.
        let categories = [
            ("interface", &report.categories.interface),
            ("structure", &report.categories.structure),
            ("semantic", &report.categories.semantic),
        ];
        for (label, category) in categories {
            if category.checked {
                assert_eq!(category.score, 1.0, "{name} {label}");
            }
        }

        // The measurement floor — guards against a vacuous pass.
        assert!(
            report.categories.interface.checked,
            "{name}: interface must stay measurable"
        );
        let structure_expected = !STRUCTURALLY_UNMEASURABLE.contains(&name);
        assert_eq!(
            report.categories.structure.checked, structure_expected,
            "{name}: structure checked={} but expected {structure_expected} — \
             update STRUCTURALLY_UNMEASURABLE if this change is intended",
            report.categories.structure.checked
        );
        let semantic_expected = !SEMANTICALLY_UNMEASURABLE.contains(&name);
        assert_eq!(
            report.categories.semantic.checked, semantic_expected,
            "{name}: semantic checked={} but expected {semantic_expected} — \
             update SEMANTICALLY_UNMEASURABLE if this change is intended",
            report.categories.semantic.checked
        );
    }
}

/// Identity must survive the change of basis (score-2.0.0 T6).
///
/// The macro-expanded basis is a different comparison entirely — generated
/// glue, desugared control flow, inlined ABI statics — so the anti-Goodhart
/// guarantee has to be re-established on it, not assumed to carry over. A
/// source scored against itself is still perfectly reconstructed no matter
/// which basis it is read on.
///
/// `#[ignore]`d because it shells out to `cargo expand` (the `compile`
/// convention). Run with:
///   cargo test -p sordec-score -- --ignored
#[test]
#[ignore = "shells out to cargo expand against soroban-sdk (slow)"]
fn identity_is_perfect_on_the_expanded_basis() {
    // hello-add is the cheapest fixture to expand and exercises the whole
    // path: crate-root walk-up, expansion of both sides, `load_str`.
    let dir = fixture_src("hello-add");
    let opts = ScoreOptions {
        basis: sordec_score::BasisProfile::rfp_default(),
        ..opts()
    };
    let report = score_paths(&dir, &dir, &opts).expect("score fixture");

    assert!(
        report
            .notes
            .iter()
            .any(|note| note.contains("basis: macro-expanded")),
        "expansion did not actually run — notes: {:?}",
        report.notes
    );
    assert!(
        (report.overall - 1.0).abs() < 1e-9,
        "expanded identity overall {} != 1.0",
        report.overall
    );
    for (label, category) in [
        ("interface", &report.categories.interface),
        ("structure", &report.categories.structure),
        ("semantic", &report.categories.semantic),
    ] {
        if category.checked {
            assert_eq!(category.score, 1.0, "expanded {label}");
        }
    }
}

/// The split basis is live: structure moves with expansion, semantic does not
/// (score-2.0.0 T9).
///
/// Semantic staying on the pre-expansion sources is the whole point of the
/// per-category basis — `extract` recognizes panics only as macros, so scoring
/// it on expanded input would hide the reconstruction's over-production and
/// inflate precision. This pins that the router actually keeps semantic where
/// it belongs when the rest of the run is expanded.
///
/// `#[ignore]`d because it shells out to `cargo expand`.
#[test]
#[ignore = "shells out to cargo expand against soroban-sdk (slow)"]
fn the_split_basis_moves_structure_but_not_semantic() {
    let dir = fixture_src("token-v23");
    let source_only = score_paths(&dir, &dir, &opts()).expect("source-basis score");
    let split = score_paths(
        &dir,
        &dir,
        &ScoreOptions {
            basis: sordec_score::BasisProfile::rfp_default(),
            ..opts()
        },
    )
    .expect("split-basis score");

    assert!(
        split
            .notes
            .iter()
            .any(|note| note.contains("basis: macro-expanded")),
        "expansion did not run — notes: {:?}",
        split.notes
    );
    assert_eq!(split.basis_profile, "rfp-default");

    // Semantic read the same (pre-expansion) sources in both runs.
    assert_eq!(
        split.categories.semantic.score, source_only.categories.semantic.score,
        "semantic must stay on the pre-expansion basis"
    );
    assert_eq!(
        split.categories.semantic.notes, source_only.categories.semantic.notes,
        "identical basis must yield identical fact counts"
    );
}

/// The interface category survives macro expansion by reading the spec-XDR
/// (score-2.0.0 T10).
///
/// Before T10 this reported `unchecked` on every fixture: expansion consumes
/// the `#[contractimpl]` / `#[contracttype]` attributes the extractor keyed
/// on, and T8 correctly refuses to score a zero-item extraction. That was the
/// blocker holding back the default-basis flip.
///
/// `#[ignore]`d because it shells out to `cargo expand`.
#[test]
#[ignore = "shells out to cargo expand against soroban-sdk (slow)"]
fn interface_is_measurable_on_the_expanded_basis() {
    let dir = fixture_src("token-v23");
    let report = score_paths(
        &dir,
        &dir,
        &ScoreOptions {
            basis: sordec_score::BasisProfile::rfp_default(),
            ..opts()
        },
    )
    .expect("score");

    assert!(
        report.categories.interface.checked,
        "interface must read the ABI from the spec, not from consumed attributes: {:?}",
        report.categories.interface.notes
    );
    // Identity: the fixture against itself is a perfect ABI match.
    assert_eq!(report.categories.interface.score, 1.0);
}

/// Doc comments do not cost interface score, end to end (score-2.0.0 T10).
///
/// attestation is the only corpus fixture whose entrypoints carry doc
/// comments, and they land in the spec-XDR. Comparing raw spec bytes scores it
/// 0 of 7 purely for docs our reconstruction does not emit; docs are excluded
/// at every nesting level, so a reconstruction with a correct ABI scores as
/// correct. This is the fixture that proves it on real expanded output rather
/// than on hand-built bytes.
#[test]
#[ignore = "shells out to cargo expand against soroban-sdk (slow)"]
fn documented_entrypoints_do_not_cost_interface_score() {
    let dir = fixture_src("attestation");
    let report = score_paths(
        &dir,
        &dir,
        &ScoreOptions {
            basis: sordec_score::BasisProfile::rfp_default(),
            ..opts()
        },
    )
    .expect("score");

    assert!(report.categories.interface.checked);
    assert_eq!(
        report.categories.interface.score, 1.0,
        "documented entrypoints must still compare equal: {:?}",
        report.categories.interface.notes
    );
}

// ---------------------------------------------------------------------
// A small, realistic contract the invariance + mutation tests transform.
//
// `transfer`'s guard is load-bearing, not decoration: since T13d a category
// with no control flow anywhere reports `unchecked`, so without a branch here
// every structure assertion below would pass vacuously against an unmeasured
// category. The guard is a bare `return` rather than a `panic!` so it adds
// control flow without adding a semantic fact, keeping the two categories
// independent.
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
        if amount < 0 { return; }
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
