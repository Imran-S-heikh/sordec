//! Corpus accuracy benchmark harness (Phase 4 · D4.2).
//!
//! Decompiles every corpus fixture in-memory ([`sordec_driver::Driver`]) and
//! scores the reconstruction against its vendored source
//! ([`sordec_score::score_paths`], directory-vs-directory so the multi-file
//! loader flattens both sides). Two entry points share one measurement:
//!
//! - [`accuracy_regression`] runs in the normal suite and asserts each
//!   fixture's overall score stays within a committed band — it catches a
//!   silent regression *or* an unearned jump (the CI accuracy guard).
//! - [`generate_report`] is `#[ignore]`d (like `token_v23_cargo_check_rate`);
//!   run explicitly, it writes `docs/benchmarks/report.{md,json}` — the honest
//!   per-fixture + aggregate accuracy report.
//!
//! **This measures reconstruction quality; it does not chase it.** The gap
//! analysis (`docs/benchmarks/gap_analysis.md`) reads these numbers.

use std::path::{Path, PathBuf};

use sordec_score::{
    score_paths, BehaviorInput, CategoryScore, ScoreOptions, ScoreReport,
};

/// The corpus fixtures with vendored source, in report order.
const FIXTURES: &[&str] = &[
    "hello-add",
    "token-v22",
    "token-v23",
    "token-v23-stripped",
    "timelock",
    "dex-liquidity-pool",
    "attestation",
];

/// The repo root, normalised.
///
/// Normalised because these paths reach `docs/benchmarks/report.{md,json}`,
/// which ships as Deliverable 4.2: a diagnostic quoting a fixture path has to
/// render the same on every machine, and `CARGO_MANIFEST_DIR/../..` left
/// unresolved would embed `…/crates/sordec/../../samples/…` verbatim.
fn repo_root() -> PathBuf {
    let manifest_relative = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    std::fs::canonicalize(&manifest_relative).unwrap_or(manifest_relative)
}

/// `samples/contracts/` under the repo root.
fn samples_dir() -> PathBuf {
    repo_root().join("samples/contracts")
}

/// A report note with this machine's repo path removed.
///
/// The scorer and the behaviour harness quote real paths in their reasons,
/// which is right for a terminal and wrong for `docs/benchmarks/report.md`:
/// a published artifact must not carry the author's home directory, and two
/// people regenerating it must produce the same bytes.
fn relative_to_repo(note: &str) -> String {
    let root = format!("{}/", repo_root().display());
    note.replace(&root, "")
}

/// One fixture's measurement, or `None` when it could not be decompiled or
/// scored (surfaced in the report, never silently dropped).
struct Measured {
    name: &'static str,
    report: ScoreReport,
}

/// The scoring configuration every measurement here uses, with `behavior`
/// injected by the caller.
///
/// One definition, because the report also has to re-run the aggregator to
/// derive its AST-only figure ([`ast_only_overall`]) and a second copy of the
/// weights or basis would let the two disagree silently.
fn score_options(behavior: BehaviorInput, abi_declared: bool) -> ScoreOptions {
    ScoreOptions {
        threshold: 0.9,
        check_compile: false,
        behavior,
        abi_declared,
        ..Default::default()
    }
}

/// Decompile a fixture in-memory and score the reconstruction against its
/// vendored source directory.
///
/// `want_behavior` is the *only* difference between what the accuracy guard
/// measures and what the report measures. It is off for the guard because
/// differential execution needs a wasm toolchain that CI does not install, and
/// a band that means one thing on a provisioned machine and another on a bare
/// one is not a guard.
fn measure_inner(name: &'static str, want_behavior: bool) -> Result<Measured, String> {
    let wasm_path = samples_dir().join(name).join(format!("{name}.wasm"));
    let wasm = std::fs::read(&wasm_path).map_err(|e| format!("read wasm: {e}"))?;
    measure_wasm(name, &wasm, want_behavior.then_some(wasm_path.as_path()), name)
}

/// Decompile `wasm` and score it against fixture `name`'s vendored source.
///
/// `oracle` is the original wasm to measure behaviour against, when wanted.
/// `label` names the scratch directory, so two measurements of one fixture
/// running in parallel test threads do not share one.
fn measure_wasm(
    name: &'static str,
    wasm: &[u8],
    oracle: Option<&Path>,
    label: &str,
) -> Result<Measured, String> {
    let base = samples_dir().join(name);
    let output = sordec_driver::Driver::standard()
        .run(wasm)
        .map_err(|e| format!("decompile: {e}"))?;

    // Lay the reconstruction out as the crate we actually ship: the manifest at
    // the root, the source under `src/`. `decompile --out-dir` writes exactly
    // this, and behaviour needs the manifest because `recompile::build` builds
    // the manifest it is handed and never writes one.
    //
    // The *scored* path stays `<tmp>/src`, not `<tmp>`. Handing the crate root
    // to `score_paths` would silently change every number: the expansion
    // harness copies a source directory verbatim into its scratch crate's
    // `src/`, so a crate root lands as `scratch/src/src/lib.rs`, leaving no lib
    // target for `cargo expand --lib` to find and dropping the whole run back
    // to the pre-expansion basis.
    let tmp = std::env::temp_dir().join(format!("sordec-bench-{label}-{}", std::process::id()));
    let src = tmp.join("src");
    std::fs::create_dir_all(&src).map_err(|e| format!("scratch dir: {e}"))?;
    std::fs::write(src.join("lib.rs"), &output.rust).map_err(|e| format!("write recon: {e}"))?;
    std::fs::write(tmp.join("Cargo.toml"), &output.cargo_toml)
        .map_err(|e| format!("write manifest: {e}"))?;

    // Before the scratch directory goes away, and against the original wasm
    // rather than its source: the deployed contract is the oracle.
    let behavior = match oracle {
        Some(wasm_path) => sordec::behavior::measure(&tmp, wasm_path),
        None => BehaviorInput::NotRequested,
    };

    // Whether the module declared its own ABI is a fact about the wasm,
    // and the scorer never reads wasm. Without `contractspecv0` there
    // are no parameter names in the module at all, so comparing them
    // would mark the reconstruction down for the build's settings.
    let abi_declared = sordec_frontend::parse(wasm)
        .is_ok_and(|p| p.soroban_facts.is_some_and(|f| !f.functions.is_empty()));
    let opts = score_options(behavior, abi_declared);
    let report =
        score_paths(&src, &base.join("source/src"), &opts).map_err(|e| format!("score: {e}"));
    let _ = std::fs::remove_dir_all(&tmp);
    Ok(Measured { name, report: report? })
}

/// Score a fixture on the three AST categories, as the accuracy guard does.
fn measure(name: &'static str) -> Result<Measured, String> {
    measure_inner(name, false)
}

/// Measure every fixture, panicking with the fixture name on any failure so
/// a broken fixture is loud, not skipped.
fn measure_all() -> Vec<Measured> {
    FIXTURES
        .iter()
        .map(|&name| measure(name).unwrap_or_else(|e| panic!("{name}: {e}")))
        .collect()
}

/// Measure every fixture with differential execution as well.
///
/// Panics up front if the wasm toolchain is missing, rather than producing a
/// report that quietly lost a category. The same rule the accuracy bands
/// follow: a run that measured something other than what it says it measured
/// has to fail loudly.
fn measure_all_with_behavior() -> Vec<Measured> {
    if let Err(reason) = sordec::behavior::toolchain_ready() {
        panic!(
            "the benchmark report includes the behavior category and this machine \
             cannot measure it: {reason}\n\nProvision it with `tools/setup-toolchains.sh`, \
             or the report would silently be a three-category document."
        );
    }
    FIXTURES
        .iter()
        .map(|&name| measure_inner(name, true).unwrap_or_else(|e| panic!("{name}: {e}")))
        .collect()
}

/// A report's overall score with `behavior` excluded.
///
/// Re-runs the scorer's own aggregator rather than reimplementing the weighted
/// mean here, so the AST-only figure cannot drift from the four-category one it
/// sits beside. Both are reported because they answer different questions: the
/// AST-only number is comparable with every measurement in this file's history
/// and with the committed bands, and the other is what the metric says today.
fn ast_only_overall(report: &ScoreReport) -> f64 {
    let opts = score_options(BehaviorInput::NotRequested, true);
    ScoreReport::aggregate(
        sordec_score::Categories {
            behavior: CategoryScore::unchecked("excluded from the AST-only aggregate"),
            ..report.categories.clone()
        },
        report.compilation_gate.clone(),
        None,
        &opts.weights,
        &opts.basis,
        opts.threshold,
    )
    .overall
}

/// The expected overall-score band for a fixture: `(low, high)`. Set from the
/// measured baseline with slack — a real recovery win or regression breaches
/// it and must be reviewed (and the band + report regenerated).
fn overall_band(name: &str) -> (f64, f64) {
    // Bands are the measured baseline ±~0.02. Scoring is deterministic, so a
    // breach means an intended change — update these and regenerate the report.
    //
    // Re-derived 2026-07-27 at M3 close-out, when the default basis became
    // `rfp-default` (interface + structure macro-expanded, semantic
    // pre-expansion). Aggregate 0.3205 -> 0.3896.
    //
    // Re-derived again 2026-07-27 at T13c, when structure stopped averaging
    // over the union of function *names* and started scoring per ABI
    // entrypoint over call closures. Aggregate 0.3896 -> 0.3850. The small
    // drop is the metric becoming honest: the old number was inflated by
    // name-matching artifacts. The load-bearing evidence is token-v23 and
    // token-v23-stripped, two builds of the same contract differing only in
    // the name section — structure scored 0.0522 vs 0.0045 (11.6x) before,
    // and 0.0480 vs 0.0480 after. That pair is now the regression test for
    // name-independence: if their bands ever diverge again, structure has
    // started measuring debug info.
    //
    // token-v22 re-derived 2026-07-27 at T16, when the semantic extractor
    // learned SDK v22's `TokenUtils::new(&e).events().<name>(…)` event API.
    // Its seven emissions had been producing zero facts, so the five events
    // our reconstruction correctly recovered scored as fabrications against an
    // original credited with none: semantic 0.3361 -> 0.3968. No other fixture
    // uses that API, and none moved — which is the argument for keeping a
    // multi-SDK-version corpus, since a token-v23-only check would have missed
    // this entirely.
    //
    // Re-derived across the board 2026-07-27 at T18, when an argument-less
    // `panic!()` stopped being a semantic fact. Aggregate 0.3880 -> 0.4589.
    //
    // Read the direction, not just the size. Our reconstructions emit bare
    // arg-decode traps in bulk (60 on token-v23 against the source's 5
    // authored, message-carrying panics) and both used to key as `panic:bare`,
    // so our traps were credited as *recovering* their panics. Removing that
    // false match moves the two halves opposite ways: token-v23 precision
    // 0.3049 -> 0.9091, recall 0.5814 -> 0.4651, and `panic:bare` now appears
    // in the under-recovered list. We report worse recovery and stop counting
    // marshalling as behaviour.
    //
    // hello-add moves most (0.3529 -> 0.5455) because its only semantic facts
    // were five such traps: with them gone, neither side has any operation and
    // the category renormalizes out as unmeasurable rather than scoring 0.
    // These bands are also the guard against a *silent* fallback: a machine
    // that cannot run `cargo expand` degrades every category to the source
    // basis, which moves hello-add off 0.5455 and breaches its band loudly
    // rather than quietly reporting a different metric.
    //
    // Re-measured 2026-07-28 at T23, and **not re-derived**: every fixture sits
    // inside the band it already had. Aggregate 0.4611.
    //
    // Two things had been true of the committed artifacts and are worth recording,
    // because the second is easy to misread as a regression:
    //
    // 1. `docs/benchmarks/report.{md,json}` were stale from *before* T13f — they
    //    still carried a `compilation` category key, which T19 removed. Regenerated
    //    here. They are generated measurement records, so hand-editing them would
    //    have fabricated data.
    // 2. The aggregate they recorded was 0.4589, and the current measurement is
    //    0.4611. That delta is **not** new: T13f's own commit message records
    //    "structure 0.0480 -> 0.0589 (aggregate 0.4589 -> 0.4611)". The artifacts
    //    simply predated it. Regenerating reproduces T13f's figure exactly, which is
    //    the check that nothing since has moved a score — E1 (`246abdc`) recorded
    //    "no score moved" and this confirms it, as does the whole T20-T22 behavior
    //    wiring: behavior is an *unchecked* category corpus-wide, so it renormalizes
    //    out of the mean exactly as the unchecked compilation category did before it.
    //
    // Behavior will stay unchecked here until the emitter produces a crate that
    // compiles. That is not a gap in the harness — it is validated against nine
    // known-answer divergence vectors and against each fixture's own recompiled
    // source — it is the emitter's turn.
    //
    // **attestation re-derived 2026-07-29, and only attestation.** 0.3856 ->
    // 0.7468, from the packed-`U32Val` comparison recognizer plus the crypto /
    // prng / symbol / bytes-len lowerings and the emitter's hole-aware dead-hole
    // sweep. The move is `semantic` 0.0000 -> 1.0000: attestation's five facts
    // were all `crypto:*` / `prng:*` ops that the pipeline named correctly in a
    // hole string and the emitter had no idiom for, so it scored zero against a
    // source credited with five. `structure` also moved 0.1111 -> 0.1390 as the
    // dead holes went (bloat 9.0x -> 8.0x).
    //
    // Every other fixture stayed inside the band it already had — checked, not
    // assumed. That is the expected shape: holes score no semantic facts, so
    // deleting a dead one cannot move the number, and the crypto/prng vocabulary
    // is exercised by no other fixture in the corpus. Corpus `cargo check` went
    // 248 -> 243 diagnostics over the same change (attestation 3 -> 0, token-v23
    // 53 -> 52, token-v23-stripped 44 -> 43, the rest flat), so attestation is
    // now the second fixture that compiles, after hello-add.
    //
    // Its behaviour is measured rather than unchecked, and is 1.0000 over 2 of 6
    // entrypoints (20 of 20 return checks). It does not appear in this band:
    // `measure` scores without `--behavior`, so the category renormalizes out
    // here exactly as it does for every other fixture. The number is reproduced
    // by `sordec score <recon-dir> <src> --behavior <orig.wasm>`; the other four
    // entrypoints need `Bytes` argument construction (B9/B10), not emitter work.
    // **hello-add and attestation re-derived 2026-07-30, lever 2 step one.**
    // Three compiler-inserted control-flow shapes stopped being emitted:
    // rustc's arithmetic overflow guard (`refine::overflow_guard`), a merge
    // scope whose single `break` was a fallthrough
    // (`refine::scope_fallthrough`), and the explicit trailing `return`
    // where Rust source writes a tail expression. None is in the source;
    // all three were measured against an original that never wrote them.
    //
    // hello-add **0.5455 -> 1.0000**, and the mechanism is worth recording
    // because the number looks too good otherwise. Its source is `a + b`,
    // i.e. *zero* control-flow tokens, and it emitted three. At zero on
    // both sides `structure` takes `structure.rs`'s flowless branch, drops
    // out of numerator and denominator, and the category reports
    // `unchecked` — 1.0000 is unreachable there by construction. `semantic`
    // and `behavior` were already unchecked, so `interface` (1.0000, and
    // unchanged) is all that remains in the mean. The category did not
    // score perfectly; it stopped being measurable, which is exactly what
    // score-2.0.0 T13d chose for a contract with no control flow.
    //
    // attestation **0.7468 -> 0.7794**, structure 0.1390 -> 0.2500, from
    // the same three shapes.
    //
    // Every other fixture moved *within* its band and none was re-derived:
    // token-v22 0.5626 -> 0.5656, token-v23 0.4778 -> 0.4806,
    // token-v23-stripped 0.1694 -> 0.1721, timelock 0.5799 -> 0.5811,
    // dex 0.5086 -> 0.5106. Small because the trailing `return` is the only
    // one of the three that is common (205 of 206 returns the corpus emits
    // are trailing); the overflow guard hits 6 sites corpus-wide and the
    // vacuous scope 2, rustc having outlined most overflow checks into
    // shared helpers. Aggregate 0.5129 -> 0.5842.
    //
    // Corpus `cargo check` went 243 -> 240 diagnostics with no fixture
    // rising, and both behaviour measurements held at 1.0000 — including
    // hello-add's, which is the oracle for the overflow elision: its
    // argument sweep drives `(u64::MAX, 1)` deliberately, and the three
    // calls that trap still "fail identically" on both sides.
    // Re-derived 2026-07-30 with `SpecializePass` + `OptionProbePass`.
    //
    // rustc's identical-code folding merges source helpers that differ
    // only in a constant into one body, with the constant demoted to a
    // parameter — dex's `get_total_shares`/`get_reserve_a`/`get_reserve_b`
    // are one function called with 2, 3, 4. Every recognizer then
    // declined correctly, because a meet over disagreeing callers is
    // `None`. The specializer splits those bodies back apart, which is
    // the exact inverse of the transform that lost the information, and
    // the existing recognizers resolve with no change to them.
    //
    // The two fixtures with merged storage families move; the rest are
    // untouched. timelock 0.5811 -> 0.6493 (semantic 0.5926 -> 0.7857,
    // and its enum keys go 2/4 -> 6/6 named); dex 0.5106 -> 0.5639
    // (semantic 0.4000 -> 0.5517, enum keys 1/6 -> 10/16). Aggregate
    // 0.5842 -> 0.6016.
    //
    // The tokens land back exactly where they were, and that is the
    // interesting part rather than a null result. De-sharing first
    // *cost* them ~0.01 each, because `Storage::get` returns `Option`
    // and compiles to a `has` guarding a `get`: recovering those probes
    // well enough to name them made the emitter report `.has()` calls
    // that appear in no source. `OptionProbePass` proves which `has`
    // calls are the SDK's and stops the emitter spelling them.
    // timelock's `is_initialized` is a real `.has()` and still scores as
    // one — which is why the probe is proven per site rather than
    // assumed from the op.
    // Re-centred 2026-07-31 after Job A — the labeled-scope tax.
    //
    // Wasm spells `if`/`else` as `block` + `br`, the structurer reproduces
    // that faithfully, and nothing converted it back: 246 emitted `break`s
    // against sources containing none at all. Two transforms, both in
    // `refine` because that is the layer that produced the shape. The
    // first deletes breaks at a *tail exit* — where falling off the end
    // reaches the same continuation — which is the reading the old
    // predicate had backwards. The second turns a guarded break into the
    // `else` arm it skips past.
    //
    // 246 breaks -> 103. Structure moved on every fixture: token-v23
    // 0.0707 -> 0.0920, dex 0.0551 -> 0.0723, token-v22 0.0703 -> 0.0940,
    // timelock 0.0647 -> 0.0740. Aggregate 0.6016 -> 0.6054.
    //
    // Small against the size of the gap, and the reason is worth keeping
    // rather than dressing up: structure is Dice over streams still ~20x
    // the source's, so removing 20 tokens of 774 cannot move it far. The
    // breaks were never the bulk — the `if`s are (68 emitted against the
    // source's 10 on token-v23). Corpus `cargo check` 238 -> 236, gate
    // unchanged at 2/7, behaviour 1.0000 on both measured fixtures.
    // Re-centred 2026-09-19 — 128-bit operands the function never named.
    //
    // A difference over four loose registers (a balance loaded out of
    // storage, an amount arriving in two parameters) is still a
    // difference: the borrow names the two low limbs in operand order,
    // so the pairing is read off the pattern and each pair is joined
    // into the operand it is the halves of. That reaches the whole
    // chain behind it — a helper can take the value instead of two
    // registers, the comparison on it stops being a `select` over
    // unrelated registers, and the guard it feeds recovers its polarity.
    // A sum still needs operands the function already names, because
    // its carry compares the result and leaves the pairing open.
    //
    // token-v22 structure 0.8615 -> 0.9063, token-v23 0.8123 -> 0.8565.
    // Aggregate 0.7988 -> 0.8025. Held-out mean unchanged at 0.7090.
    // Amended same day — and its field *types*.
    //
    // A struct recovered from a key table starts with `Val` fields,
    // because the table carries names and nothing else. The derived
    // conversion then checks each field against the tag its declared
    // type implies — the same evidence `#[contractimpl]` leaves for a
    // parameter — so reading it back types the field, and `field_type`
    // and `guard` can retire the check. Fields wide enough to need a
    // decode helper are read from the helper, as parameters are.
    //
    //     Record  { decimal: u32, name: String, symbol: String }
    //     Record1 { amount: i128, expiration_ledger: u32 }
    //
    // which are `TokenMetadata` and `AllowanceValue`, field for field,
    // name and type. Only the type names are missing, and those are not
    // in the binary. structure 0.6220 -> 0.6448, the fixture 0.4199 ->
    // 0.4266, aggregate 0.8353 -> 0.8362.
    //
    // 2026-09-20 — the overflow check rustc writes the other way round.
    //
    // For a *signed* `+`/`-` there is no carry to test, so rustc emits
    // the sign-mask test — and that test reads "no overflow", which puts
    // the work in the taken arm and the trap on the fall-through:
    //
    //     if ((a^b) & (a^r)) >= 0 { …; return }
    //     panic!()
    //
    // `panic_recover` only ever classified a trap sitting *inside* an
    // arm, so this one stayed `Bare` and `overflow_guard` had nothing to
    // act on. Both halves now read the inverted spelling, and only that
    // one: the classification still turns on the condition being one
    // arithmetic binding's own mask, which a contract's comparison is
    // not.
    //
    // Same relocation argument as the rest of that pass — the emitted
    // manifest pins `overflow-checks = true` and rustc regenerates the
    // check from `a - b`. hello-add's behaviour score is the live test
    // of it and stays 1.0000.
    //
    // token-v22 structure 0.9063 -> 0.9724, token-v23 and
    // token-v23-stripped 0.8598 -> 0.9069. Aggregate 0.9292 -> 0.9359.
    //
    // 2026-09-20 — a field is read at the type its struct declares.
    //
    // `field_type` typed a field access only when the declared type was
    // a small scalar, because only those have a decode for it to fold.
    // But typing and folding are different jobs: an `Address` or
    // `String` field is not decoded by that instruction, and the
    // recognizers that *do* own it — the tag-guard elision above all —
    // need a type rather than a bare `Val` to act on.
    //
    // It went unnoticed while every struct came from a spec, because
    // there the declaration reaches the binding another way. On a
    // stripped build the struct is recovered mid-pipeline, so the field
    // accesses were left untyped and their conversions stayed.
    //
    // token-v23-stripped structure 0.6448 -> 0.8598 (its three metadata
    // accessors were the worst entrypoints on the board), interface
    // 0.5275 -> 0.6044 as `name` and `symbol` recover `String` returns,
    // the fixture 0.7036 -> 0.7939. Aggregate 0.9163 -> 0.9292.
    //
    // Also score-2.1.0 — how many times a fact is written down.
    //
    // *Which* operations a contract performs is compiled into it.
    // *How many times each one is written out* is not: rustc inlines a
    // helper into its callers or outlines repeated code into one, and
    // the author's choice leaves no trace. Measured both directions on
    // one contract — dex's transfer helper appears once in the binary
    // against four call sites in the source, its reserve setter four
    // times against one, and the two helpers are structurally
    // identical. Counting occurrences scored the compiler's decisions.
    //
    // It is also what `structure` already refuses to measure on the
    // same artifact ("merging five helpers into one entrypoint body, or
    // splitting one into five, compares equal"), so the two categories
    // now agree about whether decomposition counts.
    //
    // Every fixture gains: timelock 0.9600 -> 1.0000 semantic and
    // **1.0000 overall**, dex 0.7826 -> 1.0000, token-v23 0.8861 ->
    // 0.9286, token-v22 0.9136 -> 0.9286, stripped 0.9189 -> 0.9286.
    // Aggregate 0.8999 -> 0.9163 — the first run over the 0.90 bar.
    //
    // The golden vector moves only a little (0.5714 -> 0.6000): its
    // reconstruction swapped a storage tier, so it still loses both of
    // those facts and only stops losing the second copy of the wrong
    // one.
    //
    // Also score-2.1.0 — and a type's own name.
    //
    // The last of the same rule. A `#[contracttype]`'s *shape* is
    // compiled in — a struct's field names and types in the key table
    // its derived conversion unpacks by, a union's variant names in its
    // converter's switch arms — and both are now recovered from a
    // stripped build. Its *name* is only in `contractspecv0`.
    //
    // So where the module declared no ABI, a user-defined type is
    // compared by shape rather than by name; two types of the same
    // shape then agree whatever they are called, which is the most the
    // module can be asked to support. token-v23-stripped interface
    // 0.3846 -> 0.5275 and the fixture 0.6497 -> 0.7001. Aggregate
    // 0.8927 -> 0.8999.
    //
    // Also score-2.1.0 — and the enum name in front of a storage key.
    //
    // A storage fact reads `storage:get:instance:DataKey::Admin`: an
    // enum's name and one of its variants. The variant is compiled in —
    // it is the rodata symbol the derived converter builds, and the
    // recovery above reads it back exactly. The enum's own name is only
    // in `contractspecv0`.
    //
    // So on the stripped build every storage fact was counted twice
    // wrong, once as a miss and once as a false positive, on nothing but
    // the synthesized qualifier:
    //
    //     ours   storage:set:temporary:StorageKey::Allowance
    //     theirs storage:set:temporary:DataKey::Allowance
    //
    // Nine such pairs. Dropped from both sides where the module
    // declared no ABI, leaving what the module does record: which
    // variant, at which tier, under which operation. semantic 0.6757 ->
    // 0.9189, the fixture 0.5639 -> 0.6497, aggregate 0.8804 -> 0.8927.
    //
    // Also score-2.1.0 — a name that is nowhere in the module.
    //
    // On the spec basis a signature's value is `name:type` per
    // parameter, and `contractspecv0` is the only place a parameter name
    // is recorded. A build that strips it leaves names nowhere in the
    // module, so a reconstruction cannot recover them however good it
    // is. The scorer is now told whether the module declared an ABI —
    // the caller read the wasm and knows — and where it did not, reads
    // parameter types alone, which is what `interface`'s own docs call
    // the reliable identity and what its source-basis extractor always
    // did.
    //
    // This fires on exactly one fixture, which is the test of it: every
    // other contract here ships a spec, so its names *are* recoverable
    // and still count. token-v23-stripped interface 0.0385 -> 0.3846 —
    // eleven of its thirteen entrypoints had every type right and were
    // scoring zero on `arg0` against `new_admin`. Its types stay at 0,
    // because a recovered struct's own *name* is missing too and that
    // is a separate thing. The fixture 0.4417 -> 0.5639, aggregate
    // 0.8630 -> 0.8804.
    //
    // Also score-2.1.0 — a `#[derive]`d body is the compiler's code.
    //
    // The same rule, in `structure`. The closure walker followed a
    // `.clone()` edge into the `#[automatically_derived] impl Clone`
    // rustc writes for a `#[contracttype]` enum, and counted that
    // derive's `match` as the entrypoint's own control flow. Both sides
    // generate it identically from the same `#[derive]`, and it is
    // reached asymmetrically, because cloning an SDK handle compiles to
    // nothing and so cannot be recovered from a binary.
    //
    // Excluded on both sides, by rustc's own marker. dex structure
    // 0.6362 -> 0.8059 and the fixture 0.8163 -> 0.8662; nothing else
    // moves, because nothing else clones. Aggregate 0.8558 -> 0.8630.
    //
    // Re-centred 2026-09-20 for **score-2.1.0** — what the compiler
    // deleted is not a miss.
    //
    // A fact scores a reconstruction on what it recovered from a binary.
    // A fact whose only evidence the compiler destroys is not a thing to
    // recover, and scoring it marks the decompiler down for the build's
    // settings. Such a fact is now dropped from both sides, which is the
    // discipline every category here already applied to what it cannot
    // measure — an absent ABI kind drops out of `interface`'s mean, a
    // control-flow-free entrypoint out of `structure`'s, an unmeasurable
    // category out of the overall.
    //
    // One fact qualifies: an authored `panic!("…")`, whose message is
    // the whole of what distinguishes it from the argument-less trap
    // that already yields nothing. Measured across the four fixtures
    // that write them, **0 of 24** distinct multi-word panic messages
    // appear anywhere in the deployed wasm.
    //
    // timelock 0.9391 -> 0.9859, token-v22 0.9063 -> 0.9167, dex
    // 0.7783 -> 0.8163, token-v23 0.8362 -> 0.8303 [sic: 0.8117 ->
    // 0.8303], stripped 0.4266 -> 0.4417. Aggregate 0.8362 -> 0.8558.
    //
    // The golden calibration vector moves the other way (overall 0.6853
    // -> 0.6664), because there the panic was one of the two facts the
    // reconstruction got right. The rule is not leniency — it removes a
    // fact whichever way it was going.
    //
    // Re-centred 2026-09-20 — the struct a stripped build still names.
    //
    // Same evidence as the union below, one derive along.
    // `#[contracttype]` writes a struct's *field* names into rodata as
    // the key table its derived `TryFromVal` unpacks a map by, and
    // `udt_decode` was already reading that table — it only wanted a
    // declared struct to match it against. Without a spec the table is
    // the declaration, minus the type's name and its field types.
    //
    // token-v23-stripped gives back `Record { decimal, name, symbol }`
    // and `Record1 { amount, expiration_ledger }`, which are its
    // `TokenMetadata` and `AllowanceValue`, fields and order exact.
    //
    // The three metadata accessors were its worst entrypoints — thirteen
    // emitted tokens each against sources with none, because the real
    // accessors live in `soroban_token_sdk` and the scorer never opens
    // it. structure 0.4870 -> 0.6220, holes 199 -> 129, the fixture
    // 0.3802 -> 0.4199. Aggregate 0.8296 -> 0.8353.
    //
    // Re-centred 2026-09-20 — the union a stripped build still names.
    //
    // `enum_key`'s registry gate wanted "exactly one `contractspecv0`
    // union whose case-name set equals the constructed text set", and
    // said that without a spec it recognizes nothing. Most of what it
    // wanted is still in the code: `#[contracttype]` compiles a union's
    // variant names into the converter as rodata symbols, one per switch
    // arm, and the arm's case value is the discriminant — so the names
    // *and* their declaration order are readable. token-v23-stripped
    // gives back
    //
    //     enum StorageKey { Allowance(Val, Val), Balance(Val),
    //                       State(Val), Admin }
    //
    // against a source that declares `DataKey { Allowance(..),
    // Balance(Address), State(Address), Admin }`. Every variant, in
    // order. What is not in the binary is the type's own name and its
    // field types, and neither is invented.
    //
    // With the key resolved, `key_construction` elides the converter it
    // was keeping alive in ten of thirteen entrypoint closures:
    // structure 0.3071 -> 0.4870, holes 251 -> 199, overall 0.3273 ->
    // 0.3802. Held-out structure 0.2395 -> 0.2511. Aggregate 0.8221 ->
    // 0.8296.
    //
    // Amended same day — the `Env` a helper is handed is borrowed.
    //
    // Cloning it at every call site compiled, but it is not what the
    // sources write: a Soroban helper takes `&Env`, and so does ours
    // now. That costs dex 0.7922 -> 0.7736 and the aggregate 0.8240 ->
    // 0.8214, every point of it through the `.clone()` closure edge in
    // `plan/NOTES.md` — the clones were dragging a derived `Clone` impl
    // into our closures, which happened to match the original's. Taken
    // anyway: emitting a clone the code does not need, because the
    // scorer rewards it, is the one thing that edge is recorded so we
    // do not do.
    //
    // Re-centred 2026-09-20 — call arguments the caller still needs.
    //
    // Every emitted helper takes its arguments by value, which is what
    // the wasm says, but Rust reads that as a move: a caller that uses
    // the value again no longer owns it, and the crate does not build.
    // Cloning at the call site, where the value is read more than once
    // and its type is not `Copy`, is what the source avoids by taking
    // `&Env` and `&Address` in its helpers.
    //
    // **timelock now builds and loads.** Its behaviour still cannot be
    // measured, for a different reason: the differential driver cannot
    // construct an `Address` argument against a live host, so 0 of its
    // 2 entrypoints are drivable.
    //
    // dex 0.7668 -> 0.7922 (structure 0.5970 -> 0.6836), and that part
    // is only half earned. A `.clone()` anywhere in a file pulls the
    // derived `Clone` impl's `match` into every closure that reaches it
    // — the scorer edge recorded in `plan/NOTES.md`, which until now
    // cost us because the *original* clones and we did not. Emitting
    // the clones the code needs happens to line the two sides up.
    // Aggregate 0.8204 -> 0.8240.
    //
    // Re-centred 2026-09-20 — the conversions a proven type licenses.
    //
    // A recognizer that proved a host result's type from the ABI has
    // proved what the SDK accessor around it is declared to return, and
    // that accessor unwraps its own conversion — so both halves of the
    // conversion are regenerated by emitting the accessor. The tag check
    // goes ([`marshalling::guard`]), and so does the two-form unpack a
    // 64-bit-or-wider scalar needs, which is a *branch* rather than one
    // check and is why `typed_read` had to decline it.
    //
    // timelock structure 0.8750 -> 1.0000 and the fixture reaches
    // 0.9391: both categories perfect, and what is left of its semantic
    // is the panic messages rustc deleted and one outlined helper.
    // token-v23 0.8107 -> 0.8117. Aggregate 0.8150 -> 0.8204.
    //
    // Re-centred 2026-09-20 — the check on a cross-contract call's result.
    //
    // `#[contractclient]` generates a method per entrypoint whose body
    // runs `T::try_from_val` on the raw `Val` the host handed back, so
    // the tag check after `Client::transfer(…)` is regenerated by
    // emitting the call — the same relocation argument as a typed
    // storage read, one boundary further out. It was the only control
    // flow left in the transfer wrapper on two fixtures.
    //
    // timelock 0.8607 -> 0.9024 (structure 0.7333 -> 0.8750, its first
    // fixture over the 0.90 threshold that is not a two-liner), dex
    // 0.7574 -> 0.7668. Held-out mean 0.7090 -> 0.7106.
    //
    // Re-centred 2026-09-20 — a contract with no spec section.
    //
    // The export table names every entrypoint and gives its arity, and
    // `#[contractimpl]` compiles each declared parameter type into a
    // check the body still carries. Reading both back gives the stripped
    // fixture the dispatch wrapper it really has and the declarations
    // the marshalling gates need, so its argument conversions relocate
    // like any other contract's: structure 0.2322 -> 0.3057, bloat 5.5x
    // -> 4.1x, overall 0.2917 -> 0.3133.
    //
    // Its interface stays 0.0000, and not for want of types: on the
    // spec-XDR basis a signature's value includes each parameter's
    // *name*, which no stripped binary carries. That contradicts the
    // interface module's own stated rule (names excluded, types are the
    // identity) and the source-basis extractor, which does exclude them
    // — recorded in `plan/NOTES.md` for the basis negotiation rather
    // than changed here, because changing it raises our own number.
    match name {
        "hello-add" => (0.99, 1.00),
        "token-v22" => (0.92, 0.96),
        "token-v23" => (0.84, 0.88),
        "token-v23-stripped" => (0.79, 0.83),
        "timelock" => (0.98, 1.00),
        "dex-liquidity-pool" => (0.92, 0.96),
        "attestation" => (0.98, 1.0),
        _ => (0.00, 1.00),
    }
}

/// CI accuracy guard: every fixture's overall score stays within its band.
#[test]
fn accuracy_regression() {
    for m in measure_all() {
        let (lo, hi) = overall_band(m.name);
        let overall = m.report.overall;
        assert!(
            (lo..=hi).contains(&overall),
            "{}: overall {overall:.4} outside band {lo:.2}..={hi:.2} — \
             if this is an intended change, update overall_band() and \
             regenerate docs/benchmarks/ (SORDEC_BENCH_WRITE=1 … --ignored)",
            m.name
        );
    }
}

/// Recovering the ABI must never make structure worse.
///
/// `token-v23-stripped` is `token-v23` without its custom sections, and the
/// only custom sections `token-v23` carries are the contract's own —
/// `contractspecv0`, `contractenvmetav0`, `contractmetav0`; it has no name
/// section. So the gap between the two measures exactly what the ABI lets
/// the pipeline recover: argument decodes proven the identity, enum keys
/// named from the spec's unions, struct fields named from its structs. That
/// gap is supposed to be large, and it grows as recovery does.
///
/// What must hold is that it runs one way: more evidence, never a worse
/// reconstruction. Independence from function *names* — the failure mode
/// the per-entrypoint closure scoring (score-2.0.0 T13c) was built against
/// — is tested directly by [`structure_does_not_depend_on_function_names`].
#[test]
fn structure_degrades_gracefully_without_the_abi() {
    let named = measure("token-v23").expect("token-v23");
    let stripped = measure("token-v23-stripped").expect("token-v23-stripped");

    let (a, b) = (
        named.report.categories.structure.score,
        stripped.report.categories.structure.score,
    );
    assert!(
        a >= b - 1e-9,
        "structure {a:.4} (with ABI) < {b:.4} (stripped) — recovering the ABI \
         must never make the reconstruction worse"
    );
}

/// Structure must not depend on the binary's function names (score-2.0.0
/// T13c).
///
/// The name-keyed algorithm scored one contract 0.0522 with its name
/// section and 0.0045 without — an 11.6x swing on nothing but debug info.
/// This measures `token-v23` as shipped (no name section) and again with a
/// name section naming every function, and requires the same structure
/// score: neither the pipeline nor the scorer may read names the compiler
/// is free to drop.
#[test]
fn structure_does_not_depend_on_function_names() {
    let wasm_path = samples_dir().join("token-v23/token-v23.wasm");
    let wasm = std::fs::read(&wasm_path).expect("read token-v23");
    let plain = measure_wasm("token-v23", &wasm, None, "t23-plain").expect("plain");
    let named = measure_wasm("token-v23", &with_function_names(&wasm), None, "t23-names").expect("named");
    let (a, b) = (
        plain.report.categories.structure.score,
        named.report.categories.structure.score,
    );
    assert!(
        (a - b).abs() < 1e-9,
        "structure {a:.4} without names vs {b:.4} with — the reconstruction or \
         its score reads function names from the name section"
    );
}

/// `wasm` with a `name` custom section appended, naming every function —
/// imported and defined — `helper_{index}`.
fn with_function_names(wasm: &[u8]) -> Vec<u8> {
    fn leb(mut n: u32, out: &mut Vec<u8>) {
        loop {
            let byte = (n & 0x7f) as u8;
            n >>= 7;
            if n == 0 {
                out.push(byte);
                return;
            }
            out.push(byte | 0x80);
        }
    }
    let parsed = sordec_frontend::parse(wasm).expect("fixture parses");
    let facts = &parsed.wasm_facts;
    let imported = facts
        .imports
        .iter()
        .filter(|i| matches!(i.kind, sordec_ir::ImportKind::Func(_)))
        .count();
    let total = u32::try_from(imported + facts.function_type_indices.len()).expect("function count");

    // Subsection 1: the function name map.
    let mut map = Vec::new();
    leb(total, &mut map);
    for index in 0..total {
        let name = format!("helper_{index}");
        leb(index, &mut map);
        leb(u32::try_from(name.len()).expect("short name"), &mut map);
        map.extend_from_slice(name.as_bytes());
    }
    let mut payload = Vec::new();
    leb(4, &mut payload);
    payload.extend_from_slice(b"name");
    payload.push(1);
    leb(u32::try_from(map.len()).expect("map size"), &mut payload);
    payload.extend_from_slice(&map);

    let mut out = wasm.to_vec();
    out.push(0);
    leb(u32::try_from(payload.len()).expect("section size"), &mut out);
    out.extend_from_slice(&payload);
    out
}

/// Regenerate `docs/benchmarks/report.{md,json}`. `#[ignore]`d so the fast
/// suite stays filesystem-light; run explicitly to refresh the deliverable:
///   SORDEC_BENCH_WRITE=1 cargo test -p sordec --test benchmark -- --ignored --nocapture
#[test]
#[ignore = "regenerates docs/benchmarks/report.{md,json}; run explicitly"]
#[allow(clippy::print_stdout)]
fn generate_report() {
    let measured = measure_all_with_behavior();
    let agg = Aggregates::of(&measured);

    // Always print, so a --nocapture run shows the numbers even without write.
    println!(
        "\n{:<20} {:>8} {:>8} {:>8} {:>8} {:>10}",
        "fixture", "overall", "iface", "struct", "seman", "behavior"
    );
    for m in &measured {
        let c = &m.report.categories;
        println!(
            "{:<20} {:>8.4} {:>8.4} {:>8.4} {:>8.4} {:>10}",
            m.name,
            ast_only_overall(&m.report),
            c.interface.score,
            c.structure.score,
            c.semantic.score,
            behavior_cell(&m.report),
        );
    }
    println!("{:<20} {:>8.4}  (aggregate mean, AST only)", "ALL", agg.ast_only);
    println!(
        "{:<20} {:>8.4}  (aggregate mean, incl. behaviour on {} of {} fixtures)\n",
        "ALL", agg.with_behavior, agg.behavior_measured, agg.fixtures
    );

    if std::env::var("SORDEC_BENCH_WRITE").is_err() {
        println!("(set SORDEC_BENCH_WRITE=1 to write docs/benchmarks/report.{{md,json}})");
        return;
    }

    let out = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/benchmarks");
    std::fs::create_dir_all(&out).expect("benchmarks dir");
    std::fs::write(out.join("report.md"), render_markdown(&measured, &agg)).expect("write md");
    std::fs::write(out.join("report.json"), render_json(&measured, &agg)).expect("write json");
    println!("wrote {}/report.{{md,json}}", out.display());
}

/// The corpus means, both of them.
struct Aggregates {
    /// Mean of the three AST categories — comparable with the committed bands
    /// and with every earlier measurement. The headline.
    ast_only: f64,
    /// Mean including `behavior` wherever it was measured.
    with_behavior: f64,
    /// How many fixtures contributed a behaviour score. Reported with the mean
    /// for the same reason [`sordec_score::Behavior`] refuses to exist without
    /// its denominator: a rate without its coverage is not a result.
    behavior_measured: usize,
    fixtures: usize,
}

impl Aggregates {
    fn of(measured: &[Measured]) -> Self {
        #[allow(clippy::cast_precision_loss)]
        let n = measured.len() as f64;
        Self {
            ast_only: measured.iter().map(|m| ast_only_overall(&m.report)).sum::<f64>() / n,
            with_behavior: measured.iter().map(|m| m.report.overall).sum::<f64>() / n,
            behavior_measured: measured.iter().filter(|m| m.report.behavior.is_some()).count(),
            fixtures: measured.len(),
        }
    }
}

/// A fixture's behaviour score, or `n/a` when the category is unchecked.
///
/// Never `0.0000`: a zero is a verdict on the reconstruction, and an
/// unavailable measurement is the absence of one.
fn behavior_cell(report: &ScoreReport) -> String {
    report
        .behavior
        .as_ref()
        .filter(|_| report.categories.behavior.checked)
        .map_or_else(|| "n/a".to_owned(), |b| format!("{:.4}", b.score))
}

/// The human-readable report: a score table + a per-fixture details block
/// carrying the precision/recall/count notes that make the gaps legible.
fn render_markdown(measured: &[Measured], agg: &Aggregates) -> String {
    let mut s = String::new();
    s.push_str("# Reconstruction accuracy report\n\n");
    s.push_str(&format!(
        "Scorer `{}`, threshold 0.90. Reconstruction (`sordec decompile`) scored \
         directory-vs-directory against each fixture's vendored source. \
         Compilation is a gate and is not evaluated here. Regenerate with \
         `SORDEC_BENCH_WRITE=1 cargo test -p sordec --test benchmark -- --ignored`.\n\n",
        sordec_score::SCORER_VERSION
    ));
    s.push_str(&format!(
        "**Two aggregates, and they answer different questions.** The AST-only mean \
         covers interface, structure and semantic; it is the figure comparable with \
         the committed accuracy bands and with every earlier measurement, so it stays \
         the headline. The second adds `behavior` — differential execution of the \
         recompiled reconstruction against the original wasm — which is measurable on \
         {} of {} fixtures today, because the other {} do not yet compile. An \
         unmeasurable category is reported `n/a` and renormalises out of that \
         fixture's mean; it is never a zero, since \"does not build\" and \"does the \
         wrong thing\" are different findings.\n\n",
        agg.behavior_measured,
        agg.fixtures,
        agg.fixtures - agg.behavior_measured,
    ));
    s.push_str("| fixture | overall (AST) | interface | structure | semantic | behavior |\n");
    s.push_str("|---|---|---|---|---|---|\n");
    for m in measured {
        let c = &m.report.categories;
        s.push_str(&format!(
            "| {} | {:.4} | {:.4} | {:.4} | {:.4} | {} |\n",
            m.name,
            ast_only_overall(&m.report),
            c.interface.score,
            c.structure.score,
            c.semantic.score,
            behavior_cell(&m.report),
        ));
    }
    s.push_str(&format!(
        "| **aggregate (mean, AST)** | **{:.4}** | | | | |\n",
        agg.ast_only
    ));
    s.push_str(&format!(
        "| **aggregate (mean, incl. behaviour)** | **{:.4}** | | | | |\n\n",
        agg.with_behavior
    ));
    s.push_str("## Per-fixture detail\n\n");
    for m in measured {
        s.push_str(&format!("### {}\n\n", m.name));
        for (cat, cs) in [
            ("interface", &m.report.categories.interface),
            ("structure", &m.report.categories.structure),
            ("semantic", &m.report.categories.semantic),
        ] {
            s.push_str(&format!("- **{cat}** {:.4}", cs.score));
            for note in &cs.notes {
                s.push_str(&format!(" — {}", relative_to_repo(note)));
            }
            s.push('\n');
        }
        s.push_str(&render_behavior_detail(&m.report));
        s.push('\n');
    }
    s
}

/// The `behavior` bullet: a rate with its coverage and per-tuple breakdown, or
/// the reason there is no rate.
///
/// The reason is not filler. "reconstruction does not build (4 diagnostics):
/// error[E0369]…" is the sharpest emitter-progress signal the corpus produces,
/// and it is the whole content of this category for the fixtures that do not
/// compile yet.
fn render_behavior_detail(report: &ScoreReport) -> String {
    let Some(behavior) = report.behavior.as_ref() else {
        let reason = report
            .categories
            .behavior
            .notes
            .first()
            .map_or("not requested", String::as_str);
        return format!("- **behavior** n/a — {}\n", relative_to_repo(reason));
    };

    let mut s = format!(
        "- **behavior** {:.4} — {} of {} entrypoints driven",
        behavior.score, behavior.entrypoints_driven, behavior.entrypoints_total
    );
    let exercised: Vec<String> = behavior
        .tuples
        .iter()
        .filter(|t| t.exercised > 0)
        .map(|t| format!("{} {}/{}", t.name, t.matched, t.exercised))
        .collect();
    if !exercised.is_empty() {
        s.push_str(&format!("; {}", exercised.join(", ")));
    }
    if behavior.trivial_agreements > 0 {
        s.push_str(&format!(
            "; {} trivial agreement(s) excluded",
            behavior.trivial_agreements
        ));
    }
    s.push('\n');
    s
}

/// Machine-readable report: the `ScoreReport`s keyed by fixture, plus both
/// aggregate means, for CI diffing / trend tracking.
fn render_json(measured: &[Measured], agg: &Aggregates) -> String {
    let fixtures: serde_json::Map<String, serde_json::Value> = measured
        .iter()
        .map(|m| (m.name.to_string(), serde_json::to_value(&m.report).expect("serialize")))
        .collect();
    let doc = serde_json::json!({
        "scorer_version": sordec_score::SCORER_VERSION,
        // Kept under its original key so existing consumers and trend series
        // do not silently switch basis: this is still the AST-only mean.
        "aggregate_overall": agg.ast_only,
        "aggregate_overall_with_behavior": agg.with_behavior,
        "behavior_measured_fixtures": agg.behavior_measured,
        "fixtures": fixtures,
    });
    // Applied to the rendered document rather than to individual notes: this
    // serializes whole `ScoreReport`s, so any field may carry a quoted path and
    // enumerating them would be a list that goes stale. Safe as a plain string
    // substitution because a repo path contains nothing JSON escapes.
    let rendered = serde_json::to_string_pretty(&doc).expect("serialize");
    format!("{}\n", relative_to_repo(&rendered))
}
