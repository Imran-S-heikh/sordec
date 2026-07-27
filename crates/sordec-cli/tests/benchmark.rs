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
    // These bands are also the guard against a *silent* fallback: a machine
    // that cannot run `cargo expand` degrades every category to the source
    // basis, which drops hello-add from 0.353 to 0.000 and breaches its band
    // loudly rather than quietly reporting a different metric.
    match name {
        "hello-add" => (0.33, 0.37),
        "token-v22" => (0.43, 0.47),
        "token-v23" => (0.38, 0.42),
        "token-v23-stripped" => (0.09, 0.13),
        "timelock" => (0.50, 0.54),
        "dex-liquidity-pool" => (0.45, 0.49),
        "attestation" => (0.41, 0.45),
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
         Compilation category off (AST-diff only). Regenerate with \
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
