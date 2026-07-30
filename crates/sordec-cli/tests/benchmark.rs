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

use sordec_score::{score_paths, ScoreOptions, ScoreReport};

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

/// `samples/contracts/` under the repo root.
fn samples_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../samples/contracts")
}

/// One fixture's measurement, or `None` when it could not be decompiled or
/// scored (surfaced in the report, never silently dropped).
struct Measured {
    name: &'static str,
    report: ScoreReport,
}

/// Decompile a fixture in-memory and score the reconstruction against its
/// vendored source directory.
fn measure(name: &'static str) -> Result<Measured, String> {
    let base = samples_dir().join(name);
    let wasm = std::fs::read(base.join(format!("{name}.wasm")))
        .map_err(|e| format!("read wasm: {e}"))?;
    let output = sordec_driver::Driver::standard()
        .run(&wasm)
        .map_err(|e| format!("decompile: {e}"))?;

    // The reconstruction is one `lib.rs`; write it to a temp source dir so
    // `score_paths` treats both sides as directories.
    let tmp = std::env::temp_dir().join(format!("sordec-bench-{name}-{}", std::process::id()));
    let src = tmp.join("src");
    std::fs::create_dir_all(&src).map_err(|e| format!("scratch dir: {e}"))?;
    std::fs::write(src.join("lib.rs"), &output.rust).map_err(|e| format!("write recon: {e}"))?;

    let opts = ScoreOptions { threshold: 0.9, check_compile: false, ..Default::default() };
    let report = score_paths(&src, &base.join("source/src"), &opts).map_err(|e| format!("score: {e}"));
    let _ = std::fs::remove_dir_all(&tmp);
    Ok(Measured { name, report: report? })
}

/// Measure every fixture, panicking with the fixture name on any failure so
/// a broken fixture is loud, not skipped.
fn measure_all() -> Vec<Measured> {
    FIXTURES
        .iter()
        .map(|&name| measure(name).unwrap_or_else(|e| panic!("{name}: {e}")))
        .collect()
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
    match name {
        "hello-add" => (0.99, 1.00),
        "token-v22" => (0.54, 0.58),
        "token-v23" => (0.45, 0.49),
        "token-v23-stripped" => (0.15, 0.19),
        "timelock" => (0.56, 0.60),
        "dex-liquidity-pool" => (0.49, 0.53),
        "attestation" => (0.76, 0.80),
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

/// Structure must not depend on the binary's name section (score-2.0.0 T13c).
///
/// `token-v23` and `token-v23-stripped` are the same contract, and the old
/// name-keyed algorithm scored them 0.0522 and 0.0045 — an 11.6x swing on
/// nothing but debug info, which is what motivated per-entrypoint closure
/// scoring. This guards that regression.
///
/// **Exact equality no longer holds, and the reason is not the metric.**
/// `wasm-tools strip --all` removes *every* custom section, `contractspecv0`
/// included, so the stripped build recovers no ABI at all. Marshalling
/// elision needs that ABI — it will only collapse an argument decode whose
/// declared parameter type proves the decode is the identity — so on the
/// stripped build it correctly declines and the surplus control flow stays
/// (measured: 17 argument guards elided on the named build, 0 on the
/// stripped one). The reconstructions genuinely differ because one of them
/// had more evidence to work from.
///
/// So the invariant is restated as the two properties that actually matter,
/// which together are sharper than the old equality was on its own:
///
/// 1. **Monotone in evidence** — more recovered information must never make
///    the reconstruction worse.
/// 2. **Not name-keyed** — the gap must stay nowhere near the 11.6x the
///    old algorithm produced.
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
        "structure {a:.4} (named) < {b:.4} (stripped) — recovering the ABI \
         must never make the reconstruction worse"
    );
    assert!(
        a < b * 2.0,
        "structure {a:.4} (named) vs {b:.4} (stripped) — a gap this wide is \
         the name-keyed failure mode, not the ABI-driven one (elision \
         accounts for a few percent, never a multiple)"
    );
}

/// Regenerate `docs/benchmarks/report.{md,json}`. `#[ignore]`d so the fast
/// suite stays filesystem-light; run explicitly to refresh the deliverable:
///   SORDEC_BENCH_WRITE=1 cargo test -p sordec-cli --test benchmark -- --ignored --nocapture
#[test]
#[ignore = "regenerates docs/benchmarks/report.{md,json}; run explicitly"]
#[allow(clippy::print_stdout)]
fn generate_report() {
    let measured = measure_all();

    // Always print, so a --nocapture run shows the numbers even without write.
    println!("\n{:<20} {:>8} {:>8} {:>8} {:>8}", "fixture", "overall", "iface", "struct", "seman");
    for m in &measured {
        let c = &m.report.categories;
        println!(
            "{:<20} {:>8.4} {:>8.4} {:>8.4} {:>8.4}",
            m.name, m.report.overall, c.interface.score, c.structure.score, c.semantic.score
        );
    }
    let mean = measured.iter().map(|m| m.report.overall).sum::<f64>() / measured.len() as f64;
    println!("{:<20} {:>8.4}  (aggregate mean)\n", "ALL", mean);

    if std::env::var("SORDEC_BENCH_WRITE").is_err() {
        println!("(set SORDEC_BENCH_WRITE=1 to write docs/benchmarks/report.{{md,json}})");
        return;
    }

    let out = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/benchmarks");
    std::fs::create_dir_all(&out).expect("benchmarks dir");
    std::fs::write(out.join("report.md"), render_markdown(&measured, mean)).expect("write md");
    std::fs::write(out.join("report.json"), render_json(&measured, mean)).expect("write json");
    println!("wrote {}/report.{{md,json}}", out.display());
}

/// The human-readable report: a score table + a per-fixture details block
/// carrying the precision/recall/count notes that make the gaps legible.
fn render_markdown(measured: &[Measured], mean: f64) -> String {
    let mut s = String::new();
    s.push_str("# Reconstruction accuracy report\n\n");
    s.push_str(&format!(
        "Scorer `{}`, threshold 0.90. Reconstruction (`sordec decompile`) scored \
         directory-vs-directory against each fixture's vendored source. \
         Compilation is a gate and is not evaluated here; behavior is unchecked \
         until the emitter produces a crate that compiles, so these are AST-diff \
         numbers over three categories. Regenerate with \
         `SORDEC_BENCH_WRITE=1 cargo test -p sordec-cli --test benchmark -- --ignored`.\n\n",
        sordec_score::SCORER_VERSION
    ));
    s.push_str("| fixture | overall | interface | structure | semantic |\n");
    s.push_str("|---|---|---|---|---|\n");
    for m in measured {
        let c = &m.report.categories;
        s.push_str(&format!(
            "| {} | {:.4} | {:.4} | {:.4} | {:.4} |\n",
            m.name, m.report.overall, c.interface.score, c.structure.score, c.semantic.score
        ));
    }
    s.push_str(&format!("| **aggregate (mean)** | **{mean:.4}** | | | |\n\n"));
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
                s.push_str(&format!(" — {note}"));
            }
            s.push('\n');
        }
        s.push('\n');
    }
    s
}

/// Machine-readable report: the `ScoreReport`s keyed by fixture, plus the
/// aggregate mean, for CI diffing / trend tracking.
fn render_json(measured: &[Measured], mean: f64) -> String {
    let fixtures: serde_json::Map<String, serde_json::Value> = measured
        .iter()
        .map(|m| (m.name.to_string(), serde_json::to_value(&m.report).expect("serialize")))
        .collect();
    let doc = serde_json::json!({
        "scorer_version": sordec_score::SCORER_VERSION,
        "aggregate_overall": mean,
        "fixtures": fixtures,
    });
    format!("{}\n", serde_json::to_string_pretty(&doc).expect("serialize"))
}
