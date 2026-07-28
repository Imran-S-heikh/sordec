//! The divergence-vector corpus: does the comparator actually *detect* anything?
//!
//! Every other test in this crate compares a contract against itself, which can
//! only ever prove the harness does not report false differences. That is half the
//! job. These vectors prove the other half — that a real behavioural difference is
//! seen, and seen in the *right* tuple.
//!
//! # Why known-answer vectors, rather than waiting for the emitter
//!
//! Each vector is a pair of contracts differing in exactly one observable way, so
//! the correct verdict is known before the harness runs. That is what makes this a
//! test rather than a measurement. Our emitter's output can never do this job: when
//! a diff against it fails you cannot tell a harness bug from an emitter bug, and
//! when it passes you have not established that the comparator can fail.
//!
//! These vectors therefore stay useful permanently — they are not scaffolding for
//! the emitter's absence. Once the emitter compiles, they remain the only thing
//! that catches the comparator silently losing a tuple.
//!
//! # What a vector may never be used for
//!
//! A number produced here is a *calibration* result and must never be reported as
//! sordec's behaviour score. Same line T17 held when it refused to count `todo!()`
//! holes as recovered facts. The typed guard for that lives in the scorer bridge;
//! here the point is simply that these contracts are ours, not our emitter's.
//!
//! Run: `cargo test -p sordec-diffexec --test vectors -- --ignored --nocapture`

// Vectors report the divergence they found; that is the point of `--nocapture`.
#![allow(clippy::print_stdout)]

mod common;

use sordec_diffexec::canon::{AddressBook, Canonicalizer, SELF_LABEL};
use sordec_diffexec::diff::{self, Comparison, Tuple, Verdict};
use sordec_diffexec::exec::{Call, Session};
use sordec_diffexec::recompile;
use soroban_sdk::xdr::ScVal;

/// What a vector is supposed to prove.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    /// Exactly this tuple diverges, and every other exercised tuple agrees.
    ///
    /// "Every other" is the half that catches over-reporting: a comparator that
    /// flagged everything would pass a weaker assertion.
    Diverges(Tuple),
    /// Both sides fail identically, so the call proves nothing and must be
    /// excluded from the rate rather than counted as a match.
    TrivialAgreement,
}

/// One pair of contracts differing in one observable way.
struct Vector {
    /// Directory name under `vectors/`, and the divergence class it demonstrates.
    class: &'static str,
    /// The unmutated contract.
    base: &'static str,
    /// The contract with exactly one observable change.
    mutant: &'static str,
    /// The calls to drive both sides with. Hand-written: we author the contract, so
    /// there is nothing to infer and no input generation is needed.
    calls: fn() -> Vec<Call>,
    /// Role→address bindings for the [`AddressBook`], for vectors that take
    /// addresses.
    ///
    /// The addresses are ours, chosen as fixed bytes rather than generated, so both
    /// sides receive literally the same ones and each has a role to be labelled by.
    /// That is what makes `argument_swap` detectable — see [`crate::canon`].
    bindings: fn() -> Vec<(&'static str, soroban_sdk::xdr::ScAddress)>,
    /// The verdict this vector exists to produce.
    expect: Expect,
}

/// No addresses to bind — the common case.
fn no_bindings() -> Vec<(&'static str, soroban_sdk::xdr::ScAddress)> {
    Vec::new()
}

/// A stable account address for role `n`.
fn account(n: u8) -> soroban_sdk::xdr::ScAddress {
    use soroban_sdk::xdr::{AccountId, PublicKey, ScAddress, Uint256};
    ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([n; 32]))))
}

fn vectors() -> Vec<Vector> {
    vec![
        Vector {
            class: "return_value",
            base: include_str!("../vectors/return_value/base.rs"),
            mutant: include_str!("../vectors/return_value/mutant.rs"),
            calls: || vec![Call::new("compute", vec![ScVal::U32(10)])],
            bindings: no_bindings,
            expect: Expect::Diverges(Tuple::Return),
        },
        Vector {
            class: "overflow",
            base: include_str!("../vectors/overflow/base.rs"),
            mutant: include_str!("../vectors/overflow/mutant.rs"),
            // Chosen so `x * 4` overflows u32 and `x << 2` does not complain:
            // 0x4000_0000 * 4 is 2^32, one past the top.
            calls: || vec![Call::new("scale", vec![ScVal::U32(0x4000_0000)])],
            bindings: no_bindings,
            expect: Expect::Diverges(Tuple::Return),
        },
        Vector {
            class: "error_code",
            base: include_str!("../vectors/error_code/base.rs"),
            mutant: include_str!("../vectors/error_code/mutant.rs"),
            // 0 takes the error branch on both sides; only the code differs.
            calls: || vec![Call::new("check", vec![ScVal::U32(0)])],
            bindings: no_bindings,
            expect: Expect::Diverges(Tuple::Return),
        },
        Vector {
            class: "storage_tier",
            base: include_str!("../vectors/storage_tier/base.rs"),
            mutant: include_str!("../vectors/storage_tier/mutant.rs"),
            calls: || vec![Call::new("put", vec![ScVal::U32(7)])],
            bindings: no_bindings,
            expect: Expect::Diverges(Tuple::Storage),
        },
        Vector {
            class: "ttl",
            base: include_str!("../vectors/ttl/base.rs"),
            mutant: include_str!("../vectors/ttl/mutant.rs"),
            calls: || vec![Call::new("put_and_extend", vec![ScVal::U32(7)])],
            bindings: no_bindings,
            expect: Expect::Diverges(Tuple::Storage),
        },
        Vector {
            class: "event_layout",
            base: include_str!("../vectors/event_layout/base.rs"),
            mutant: include_str!("../vectors/event_layout/mutant.rs"),
            calls: || vec![Call::new("emit", Vec::new())],
            bindings: no_bindings,
            expect: Expect::Diverges(Tuple::Events),
        },
        Vector {
            class: "auth_shape",
            base: include_str!("../vectors/auth_shape/base.rs"),
            mutant: include_str!("../vectors/auth_shape/mutant.rs"),
            calls: || {
                vec![Call::new(
                    "act",
                    vec![ScVal::Address(account(0x11)), ScVal::U32(5)],
                )]
            },
            bindings: || vec![("user_0", account(0x11))],
            expect: Expect::Diverges(Tuple::Auth),
        },
        Vector {
            class: "argument_swap",
            base: include_str!("../vectors/argument_swap/base.rs"),
            mutant: include_str!("../vectors/argument_swap/mutant.rs"),
            calls: || {
                vec![Call::new(
                    "transfer",
                    vec![
                        ScVal::Address(account(0x11)),
                        ScVal::Address(account(0x22)),
                        ScVal::U32(100),
                    ],
                )]
            },
            // Both addresses bound, which is the point: role-based labelling is what
            // keeps the swap visible.
            bindings: || vec![("user_0", account(0x11)), ("user_1", account(0x22))],
            expect: Expect::Diverges(Tuple::Events),
        },
        Vector {
            class: "trivial_agreement",
            base: include_str!("../vectors/trivial_agreement/base.rs"),
            mutant: include_str!("../vectors/trivial_agreement/mutant.rs"),
            calls: || vec![Call::new("always_fails", vec![ScVal::U32(1)])],
            bindings: no_bindings,
            expect: Expect::TrivialAgreement,
        },
    ]
}

/// Build one side of a vector and run the calls against it, canonicalised.
fn run_side(vector: &Vector, side: &str, source: &str, calls: &[Call]) -> Vec<sordec_diffexec::exec::Observation> {
    let class = vector.class;
    let package = format!("vector-{class}-{side}").replace('_', "-");
    let dir = common::unique_dir(&format!("sordec-vector-{class}-{side}"));
    common::write_contract_crate(&dir, &package, common::DEFAULT_SDK, source);

    // One target directory for the whole corpus: every vector shares the same
    // soroban-sdk graph, so it is built once and each vector is then an
    // incremental crate. Per-vector directories would mean 16 cold builds.
    let wasm = recompile::build(&dir, &recompile::persistent_target_dir("vectors"))
        .unwrap_or_else(|failure| panic!("{class}/{side}: {}", failure.reason()));
    let _ = std::fs::remove_dir_all(&dir);

    let mut session = Session::register(&wasm)
        .unwrap_or_else(|unavailable| panic!("{class}/{side}: {unavailable}"));
    session.mock_all_auths();

    let mut book = AddressBook::new();
    book.bind(SELF_LABEL, session.contract_address());
    for (role, address) in (vector.bindings)() {
        book.bind(role, address);
    }
    let mut canon = Canonicalizer::new(&book);

    calls
        .iter()
        .map(|call| {
            let raw = session.call(call);
            canon.observation(&raw)
        })
        .collect()
}

/// Compare a vector's two sides.
fn compare_vector(vector: &Vector) -> Comparison {
    let calls = (vector.calls)();
    let base = run_side(vector, "base", vector.base, &calls);
    let mutant = run_side(vector, "mutant", vector.mutant, &calls);
    diff::compare(&calls, &base, &mutant)
}

/// Assert a vector produced exactly the verdict it exists to produce.
fn assert_expected(vector: &Vector, comparison: &Comparison) {
    println!("\n=== {} ===", vector.class);
    for call in &comparison.calls {
        for (tuple, verdict) in call.verdicts() {
            let label = match verdict {
                Verdict::Match => "match".to_owned(),
                Verdict::NotExercised => "not exercised".to_owned(),
                Verdict::Divergent {
                    original,
                    reconstruction,
                } => format!("DIVERGENT\n      base:   {original}\n      mutant: {reconstruction}"),
            };
            println!("  {}.{:<8} {label}", call.function, tuple.name());
        }
        if call.trivial_agreement {
            println!("  (trivial agreement — excluded from the rate)");
        }
    }
    println!(
        "  score {:?}  matched {}/{}",
        comparison.score(),
        comparison.matched(),
        comparison.exercised()
    );

    match vector.expect {
        Expect::Diverges(expected) => {
            for call in &comparison.calls {
                assert!(
                    !call.trivial_agreement,
                    "{}: expected a real divergence, got trivial agreement",
                    vector.class
                );
                for (tuple, verdict) in call.verdicts() {
                    if tuple == expected {
                        assert!(
                            matches!(verdict, Verdict::Divergent { .. }),
                            "{}: {} should have diverged, got {verdict:?}",
                            vector.class,
                            tuple.name()
                        );
                    } else {
                        // The other half of the claim: a comparator that flagged
                        // everything would satisfy the assertion above and still be
                        // useless.
                        assert!(
                            !matches!(verdict, Verdict::Divergent { .. }),
                            "{}: {} diverged but only {} should have — {verdict:?}",
                            vector.class,
                            tuple.name(),
                            expected.name()
                        );
                    }
                }
            }
        }
        Expect::TrivialAgreement => {
            assert_eq!(
                comparison.trivial_agreements(),
                comparison.calls.len(),
                "{}: every call should be trivial agreement",
                vector.class
            );
            assert_eq!(
                comparison.score(),
                None,
                "{}: mutual failure must produce no rate at all, not a perfect one",
                vector.class
            );
        }
    }
}

/// Run: `cargo test -p sordec-diffexec --test vectors -- --ignored --nocapture`
#[ignore = "shells out to cargo build --target wasm32v1-none (slow, toolchain-dependent)"]
#[test]
fn every_vector_diverges_in_exactly_its_own_tuple() {
    for vector in vectors() {
        let comparison = compare_vector(&vector);
        assert_expected(&vector, &comparison);
    }
}

/// Run: `cargo test -p sordec-diffexec --test vectors -- --ignored --nocapture`
#[ignore = "shells out to cargo build --target wasm32v1-none (slow, toolchain-dependent)"]
#[test]
fn a_vector_agrees_with_itself() {
    // The control. If base-against-base is not clean then a divergence reported
    // above might be an artefact of building the same source twice, not of the
    // mutation — so this has to hold before the mutations mean anything.
    for vector in vectors() {
        let calls = (vector.calls)();
        let left = run_side(&vector, "base", vector.base, &calls);
        let right = run_side(&vector, "base", vector.base, &calls);
        let comparison = diff::compare(&calls, &left, &right);

        assert!(
            comparison.calls.iter().all(|call| call.is_clean()),
            "{}: a contract must agree with itself — {comparison:#?}",
            vector.class
        );
    }
}

/// A fast structural check that runs in the default suite, so a broken corpus is
/// caught by `tools/gate.sh` rather than only by the slow path.
#[test]
fn every_vector_declares_both_sides_and_a_distinct_class() {
    let all = vectors();
    assert!(!all.is_empty());

    let mut classes: Vec<&str> = all.iter().map(|v| v.class).collect();
    classes.sort_unstable();
    let before = classes.len();
    classes.dedup();
    assert_eq!(before, classes.len(), "vector classes must be distinct");

    for vector in &all {
        assert!(
            vector.base.contains("#[contractimpl]"),
            "{}: base is not a contract",
            vector.class
        );
        assert!(
            vector.mutant.contains("#[contractimpl]"),
            "{}: mutant is not a contract",
            vector.class
        );
        assert_ne!(
            vector.base, vector.mutant,
            "{}: a vector whose sides are identical proves nothing",
            vector.class
        );
        assert!(
            !(vector.calls)().is_empty(),
            "{}: a vector with no calls cannot be observed",
            vector.class
        );
    }
}
