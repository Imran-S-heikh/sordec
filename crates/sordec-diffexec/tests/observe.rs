//! End-to-end observation and comparison against real corpus wasm.
//!
//! The B-side here is the *shipped wasm itself* — the first and weakest rung of
//! the validation ladder, and the one that has to hold before any other result
//! means anything. If a contract compared against itself is not identical, the
//! harness is broken, and we want to know that before an emitter's output can
//! disguise it.
//!
//! These run in the **default** suite, not behind `#[ignore]`. Nothing here shells
//! out to cargo: the wasm is committed and the host is in-process, which the B1
//! probe measured at ~0.02 s per invocation. `tools/gate.sh` therefore covers
//! them, which is where a comparator this load-bearing belongs.

use sordec_diffexec::canon::{AddressBook, Canonicalizer, SELF_LABEL};
use sordec_diffexec::diff::{self, Tuple, Verdict};
use sordec_diffexec::exec::{Call, Observation, Outcome, Session};
use soroban_sdk::xdr::ScVal;

/// `add(u64, u64) -> u64`, SDK 21.7.7, protocol 21 — deliberately the oldest
/// contract in the corpus, so the cross-protocol claim (a protocol-21 contract on
/// a protocol-23 host) is exercised by every test in this file.
const HELLO_ADD: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../samples/contracts/hello-add/hello-add.wasm"
));

/// The stripped token: **zero** custom sections. The stripping took
/// `contractenvmetav0` and `contractspecv0` along with `contractmetav0`, so the
/// host refuses to load it at all.
const STRIPPED: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../samples/contracts/token-v23-stripped/token-v23-stripped.wasm"
));

/// Run `calls` against `wasm` in a fresh host and return canonicalised
/// observations.
///
/// Canonicalising here rather than in the test bodies is deliberate: raw
/// observations from two hosts are *expected* to differ (different contract
/// addresses), so a test that compared them raw would be testing the wrong thing.
fn observe(wasm: &[u8], calls: &[Call]) -> Vec<Observation> {
    let mut session = Session::register(wasm).expect("hello-add must load");

    let mut book = AddressBook::new();
    book.bind(SELF_LABEL, session.contract_address());
    let mut canon = Canonicalizer::new(&book);

    calls
        .iter()
        .map(|call| {
            let raw = session.call(call);
            canon.observation(&raw)
        })
        .collect()
}

fn add(a: u64, b: u64) -> Call {
    Call::new("add", vec![ScVal::U64(a), ScVal::U64(b)])
}

#[test]
fn a_contract_returns_what_it_computes() {
    let calls = vec![add(2, 3)];
    let observed = observe(HELLO_ADD, &calls);

    assert_eq!(
        observed[0].outcome,
        Outcome::Value(ScVal::U64(5)),
        "add(2,3) must return 5, not {:?}",
        observed[0].outcome
    );
}

#[test]
fn the_same_wasm_observed_twice_agrees_exactly() {
    let calls = vec![add(2, 3), add(0, 0), add(u64::MAX, 0)];
    let comparison = diff::compare(&calls, &observe(HELLO_ADD, &calls), &observe(HELLO_ADD, &calls));

    assert!(comparison.notes.is_empty(), "{:?}", comparison.notes);
    assert_eq!(comparison.score(), Some(1.0));
    assert_eq!(comparison.trivial_agreements(), 0);
}

#[test]
fn identity_is_honest_about_what_it_did_not_measure() {
    // The whole point of separating coverage from rate. hello-add has no events,
    // no auth and no storage, so a 1.0 here is a 1.0 over *one* of four tuples —
    // and the report has to be able to say so.
    let calls = vec![add(2, 3)];
    let comparison = diff::compare(&calls, &observe(HELLO_ADD, &calls), &observe(HELLO_ADD, &calls));

    assert_eq!(comparison.by_tuple(Tuple::Return).rate(), Some(1.0));
    for empty in [Tuple::Events, Tuple::Auth, Tuple::Storage] {
        assert_eq!(
            comparison.by_tuple(empty).rate(),
            None,
            "{} was never exercised and must not report a rate",
            empty.name()
        );
    }
    assert_eq!(comparison.exercised(), 1, "one call, one exercised tuple");
}

#[test]
fn repeated_runs_produce_identical_observations() {
    // B6's criterion. Anything time-dependent, address-dependent or
    // iteration-order-dependent shows up here as a flake, which is exactly why it
    // is asserted rather than assumed.
    let calls = vec![add(7, 35), add(1, 1)];
    let first = observe(HELLO_ADD, &calls);

    for run in 1..10 {
        assert_eq!(
            observe(HELLO_ADD, &calls),
            first,
            "run {run} diverged from run 0"
        );
    }
}

#[test]
fn a_changed_argument_changes_the_observation() {
    // Guards against the comparator agreeing vacuously: if this passes while
    // `the_same_wasm_observed_twice_agrees_exactly` also passes, the comparison is
    // actually looking at the values.
    let left = observe(HELLO_ADD, &[add(2, 3)]);
    let right = observe(HELLO_ADD, &[add(2, 4)]);
    let comparison = diff::compare(&[add(2, 3)], &left, &right);

    assert_eq!(comparison.score(), Some(0.0));
    assert!(matches!(
        comparison.calls[0].return_value,
        Verdict::Divergent { .. }
    ));
}

#[test]
fn overflow_traps_rather_than_wrapping() {
    // Not a determinism check — a statement about the corpus that the harness has
    // to represent faithfully. hello-add was built with `overflow-checks = true`,
    // so `u64::MAX + 1` traps. A recompile that lost that flag would return a
    // value here instead, which is divergence class 3 and the reason S4 exists.
    let observed = observe(HELLO_ADD, &[add(u64::MAX, 1)]);
    assert_eq!(
        observed[0].outcome,
        Outcome::Aborted,
        "overflow must trap, not wrap: {:?}",
        observed[0].outcome
    );
}

#[test]
fn a_module_the_host_cannot_load_is_unavailable_not_a_panic() {
    // Q5, asserted rather than documented. `token-v23-stripped` is a permanent
    // behaviour exclusion, and it has to surface as a reason a report can print —
    // not as a panic inside the SDK halfway through a corpus run.
    let error = Session::register(STRIPPED).expect_err("stripped wasm must not load");
    assert!(
        error.reason.contains("contractenvmetav0"),
        "the reason must name the missing section: {}",
        error.reason
    );
}
