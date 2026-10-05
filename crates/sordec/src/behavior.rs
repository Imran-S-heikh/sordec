//! The seam between the two crates that must not know about each other.
//!
//! `sordec-diffexec` runs wasm and knows nothing about scoring; `sordec-score`
//! scores and never touches wasm, so that "the instrument is independent of the
//! pipeline it grades" is a property of the dependency graph rather than a promise.
//! Something has to map one onto the other, and this module is it — the CLI package
//! is the only place entitled to depend on both.
//!
//! # Why this is a library and not a private module of `main.rs`
//!
//! The corpus benchmark (`tests/benchmark.rs`) has to inject a measured behaviour
//! result into [`sordec_score::ScoreOptions`] to report the category at all. It
//! cannot get one by shelling out to `sordec score --json`: [`ScoreReport`] is
//! `Serialize` but not `Deserialize`, deliberately — a report is a record we
//! produce, not a format we consume — so there is nothing to parse the CLI's output
//! back into. The mapping therefore has to be callable in-process, which means it
//! has to live in a library, and this is the only library that may hold it.
//!
//! [`ScoreReport`]: sordec_score::ScoreReport

use std::path::Path;

use sordec_score::BehaviorInput;

/// Whether this machine can measure behaviour at all, independent of any one fixture.
///
/// [`measure`] folds every failure into `Unavailable`, which is right for scoring a
/// single contract — "no toolchain" and "this reconstruction does not build" are both
/// non-verdicts. A caller measuring a *corpus* needs to tell them apart: the first
/// means every result it is about to record is missing a category, and it should say
/// so loudly rather than publish a degraded report.
///
/// # Errors
///
/// The actionable reason from [`preflight::detect`], naming the command that fixes it.
///
/// [`preflight::detect`]: sordec_diffexec::preflight::detect
pub fn toolchain_ready() -> Result<(), String> {
    sordec_diffexec::preflight::detect()
        .map(|_plan| ())
        .map_err(|missing| missing.reason)
}

/// Measure the `behavior` category by differential execution.
///
/// `reconstructed` is a crate *directory* — it has to be recompiled to wasm before it
/// can be run — and `original_wasm` is the oracle: behaviour is compared against what
/// the deployed contract actually does, not against its source.
///
/// Every failure path returns `Unavailable` carrying the reason rather than a zero. A
/// behaviour score of 0.0 says "the reconstruction does the wrong thing"; a missing
/// toolchain says nothing of the kind, and conflating them would let an environment
/// problem read as a decompiler failure.
///
/// One failure is *not* a non-verdict: when the original registers with the
/// harness's constructor arguments and the reconstruction does not, the reconstruction
/// has changed what the contract does, and that scores `0`. Otherwise this reports how
/// far it got. The stages are worth distinguishing because each names a different
/// piece of work.
#[must_use]
pub fn measure(reconstructed: &Path, original_wasm: &Path) -> BehaviorInput {
    use sordec_diffexec::{diff, drive, exec, preflight, recompile, wasm};

    let unavailable = |reason: String| BehaviorInput::Unavailable { reason };

    // 1. A toolchain to recompile with. The reason names the command that fixes it.
    if let Err(missing) = preflight::detect() {
        return unavailable(missing.reason);
    }

    // 2. The oracle: the original contract's own wasm.
    let original = match std::fs::read(original_wasm) {
        Ok(bytes) => bytes,
        Err(e) => {
            return unavailable(format!("cannot read {}: {e}", original_wasm.display()));
        }
    };
    if !wasm::is_loadable(&original) {
        return unavailable(format!(
            "{} has no `{}` section, so the host cannot load it and it cannot serve as \
             a behaviour oracle",
            original_wasm.display(),
            wasm::ENV_META_SECTION
        ));
    }

    // 3. Our side, recompiled. `--behavior` needs a crate directory, not a bare file,
    //    because a lone `lib.rs` cannot be built.
    if !reconstructed.join("Cargo.toml").is_file() {
        return unavailable(format!(
            "{} is not a crate directory (no Cargo.toml); behaviour needs a crate to \
             recompile, not a single source file",
            reconstructed.display()
        ));
    }
    let cache = recompile::persistent_target_dir("cli-behavior");
    let rebuilt = match recompile::build(reconstructed, &cache) {
        Ok(bytes) => bytes,
        Err(failure) => return unavailable(failure.reason()),
    };

    // 4. Arguments, built from the contract's own declared ABI — the
    //    constructor's included, since registration is what runs it.
    let plan = match drive::plan(&original) {
        Ok(plan) => plan,
        Err(missing) => return unavailable(missing.reason),
    };
    let constructor_args = match plan.constructor_args() {
        Ok(args) => args,
        Err(why) => return unavailable(why),
    };

    // 5. Both sides have to load, and construct, before anything can be compared.
    if let Err(refused) = exec::Session::register_with(&original, &constructor_args) {
        return unavailable(format!("original wasm: {refused}"));
    }
    if let Err(refused) = exec::Session::register_with(&rebuilt, &constructor_args) {
        // The original accepted these arguments and the reconstruction did not.
        // That is a behavioural difference, not a harness limit, so it scores.
        return BehaviorInput::Measured(
            sordec_score::Behavior::new(
                0.0,
                sordec_score::BSide::Reconstruction,
                plan.drivable(),
                plan.total(),
            )
            .with_note(format!(
                "the original registered and the recompiled reconstruction did not: {refused}"
            ))
            .with_note(plan.coverage()),
        );
    }
    let calls = plan.calls();
    if calls.is_empty() {
        // Not a zero: nothing was tested, which is a different statement
        // about the reconstruction than "it behaved wrongly".
        return unavailable(format!(
            "both modules build and load, but no entrypoint could be driven — {}",
            plan.coverage()
        ));
    }

    // 6. Drive both sides with identical arguments and compare.
    let original_run = observe(&original, &plan, &calls);
    let reconstruction_run = observe(&rebuilt, &plan, &calls);
    let comparison = diff::compare(&calls, &original_run, &reconstruction_run);

    let exercised = comparison.exercised();
    if exercised == 0 {
        return unavailable(format!(
            "both modules ran, but every call was a trivial agreement (both sides \
             failed identically), so nothing was actually compared — {}",
            plan.coverage()
        ));
    }

    #[allow(clippy::cast_precision_loss)]
    let score = comparison.matched() as f64 / exercised as f64;
    let tuples = [
        diff::Tuple::Return,
        diff::Tuple::Events,
        diff::Tuple::Auth,
        diff::Tuple::Storage,
    ]
    .into_iter()
    .map(|tuple| {
        let summary = comparison.by_tuple(tuple);
        sordec_score::TupleScore {
            name: tuple.name().to_string(),
            matched: summary.matched,
            exercised: summary.exercised,
        }
    })
    .collect();

    let mut behavior = sordec_score::Behavior::new(
        score,
        sordec_score::BSide::Reconstruction,
        plan.drivable(),
        plan.total(),
    )
    .with_tuples(tuples)
    .with_trivial_agreements(comparison.trivial_agreements())
    .with_note(plan.coverage());
    for note in comparison.notes {
        behavior = behavior.with_note(note);
    }
    BehaviorInput::Measured(behavior)
}

/// Run `calls` against `wasm` and return canonicalised observations.
///
/// Canonicalisation is not optional: an address is a fresh random value per
/// registration, so raw observations from two independently registered
/// modules disagree on every address even when the contracts are identical.
fn observe(
    wasm: &[u8],
    plan: &sordec_diffexec::drive::DrivePlan,
    calls: &[sordec_diffexec::exec::Call],
) -> Vec<sordec_diffexec::exec::Observation> {
    use sordec_diffexec::canon::{AddressBook, Canonicalizer, SELF_LABEL};
    use sordec_diffexec::drive::{ACCOUNTS, account};
    use sordec_diffexec::exec::Session;

    let constructor_args = plan.constructor_args().expect("built above");
    let mut session = Session::register_with(wasm, &constructor_args)
        .expect("registered above with these arguments");
    let mut book = AddressBook::new();
    book.bind(SELF_LABEL, session.contract_address());
    for label in ACCOUNTS {
        book.bind(label, account(label));
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
