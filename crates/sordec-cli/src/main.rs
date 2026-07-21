//! `sordec` — command-line interface to the Soroban decompiler.
//!
//! Four inspection subcommands:
//!
//! - `sordec dump-facts <wasm>` — parse a WASM module and emit
//!   `WasmFacts` + `SorobanFacts` + diagnostics as JSON on stdout.
//! - `sordec dump-ir <wasm>` — parse + lift, then emit a waffle-style
//!   text rendering of the CFG/SSA IR on stdout.
//! - `sordec dump-hir <wasm>` — parse + lift + lower to HighIr, then
//!   emit a text rendering of the typed bindings (with provenance).
//! - `sordec dump-wat <wasm>` — run the full pipeline, then emit the
//!   Soroban-annotated WAT (flat disassembly with recovered semantics as
//!   `;;` comments) on stdout.
//! - `sordec decompile <wasm> --out-dir <dir>` — run the full pipeline
//!   via the [`sordec_driver::Driver`] and write `<dir>/<name>/<name>.wat`
//!   (compilable Rust joins it in Phase 4).
//! - `sordec coverage <wasm>` — parse + lift, then emit a coverage
//!   report (host-call recognition %, lift completeness, parse +
//!   metadata health) as text or `--json`.
//! - `sordec score <reconstructed.rs> <original.rs>` — score a
//!   reconstructed Rust source against the original across four
//!   categories (interface / structure / semantic / compilation) as text
//!   or `--json`. The accuracy measuring instrument (D4.1).
//!
//! Output convention (Unix-standard):
//!
//! - **stdout**: primary output (JSON for `dump-facts`, text for
//!   `dump-ir`). Pipe-friendly.
//! - **stderr**: non-fatal diagnostics from the pipeline, plus error
//!   messages on failure.
//!
//! Exit codes:
//!
//! - **0** — success (output produced; non-fatal diagnostics on stderr
//!   are not failures)
//! - **1** — pipeline error (`FrontendError` or `LiftError` returned)
//! - **2** — usage error (clap's default for argv-parse failure)
//! - **3** — I/O error (couldn't read input file)

use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use sordec_passes::LoweringStep;

mod coverage;
mod diagnostics;
mod pretty;
mod pretty_hir;

// ---------------------------------------------------------------------
// Exit codes
// ---------------------------------------------------------------------

const EXIT_OK: u8 = 0;
const EXIT_PIPELINE_ERR: u8 = 1;
const EXIT_IO_ERR: u8 = 3;

// ---------------------------------------------------------------------
// CLI surface
// ---------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "sordec", version, about = "Soroban WASM-to-Rust decompiler")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Parse a WASM module and emit WasmFacts + SorobanFacts as JSON.
    DumpFacts(DumpFactsArgs),
    /// Lift a WASM module and emit the waffle-style CFG/SSA IR as text.
    DumpIr(DumpIrArgs),
    /// Lift + lower to HighIr and emit the typed bindings as text.
    DumpHir(DumpHirArgs),
    /// Run the full pipeline and emit Soroban-annotated WAT on stdout.
    DumpWat(DumpWatArgs),
    /// Decompile a WASM module, writing artifacts under `--out-dir`
    /// (annotated WAT now; compilable Rust in Phase 4).
    Decompile(DecompileArgs),
    /// Report how much of a contract this pipeline currently understands:
    /// per-pattern recognition (storage tiers, enum keys, TTL, client
    /// calls, dispatcher, auth, events, collections, panics, Val
    /// boilerplate), a two-number semantic-recovery headline (host
    /// interactions vs deep facts), host-call recognition %, and
    /// recogniser-miss diagnostics by code.
    Coverage(CoverageArgs),
    /// Score a reconstructed Rust source against the original across four
    /// categories (interface / structure / semantic / compilation).
    Score(ScoreArgs),
}

#[derive(clap::Args)]
struct DumpFactsArgs {
    /// Path to the WASM module to inspect.
    wasm: PathBuf,
}

#[derive(clap::Args)]
struct DumpIrArgs {
    /// Path to the WASM module to inspect.
    wasm: PathBuf,

    /// Prepend a module-info header (imports/exports counts, metadata
    /// presence) before rendering functions.
    #[arg(long)]
    with_header: bool,

    /// Skip the de-cluttering pipeline and show the pristine post-lift
    /// IR (waffle-shaped max-SSA: trivial phis, forwarding blocks, the
    /// synthetic return funnel all intact). Useful for debugging the
    /// lift and the de-cluttering passes themselves.
    #[arg(long)]
    raw: bool,
}

#[derive(clap::Args)]
struct DumpHirArgs {
    /// Path to the WASM module to inspect.
    wasm: PathBuf,

    /// Skip every pipeline — de-cluttering AND pattern recovery — and
    /// show the raw lowered IR (the mechanical `LiftedIr → HighIr`
    /// output of the pristine lift, with no semantic recognition).
    /// Useful for debugging the lowering itself.
    #[arg(long)]
    raw: bool,
}

#[derive(clap::Args)]
struct DumpWatArgs {
    /// Path to the WASM module to decompile.
    wasm: PathBuf,
}

#[derive(clap::Args)]
struct DecompileArgs {
    /// Path to the WASM module to decompile.
    wasm: PathBuf,

    /// Directory to write decompilation artifacts into. A per-contract
    /// subdirectory `<name>/` is created inside it holding `<name>.wat`
    /// (and, in Phase 4, `<name>.rs`).
    #[arg(long)]
    out_dir: PathBuf,
}

#[derive(clap::Args)]
struct CoverageArgs {
    /// Path to the WASM module to inspect.
    wasm: PathBuf,

    /// Emit machine-readable JSON instead of the human-readable text
    /// report. Schema is append-only across releases — see
    /// `coverage.rs` module docs.
    #[arg(long)]
    json: bool,
}

#[derive(clap::Args)]
struct ScoreArgs {
    /// Path to the reconstructed Rust source (a `.rs` file; a source
    /// directory once the multi-file loader lands).
    reconstructed: PathBuf,

    /// Path to the original Rust source to score against.
    original: PathBuf,

    /// Emit machine-readable JSON instead of the human-readable text
    /// report. Schema is append-only across releases.
    #[arg(long)]
    json: bool,

    /// Run the opt-in compilation category (`cargo check` against
    /// `soroban-sdk`). Off by default so the fast path stays
    /// toolchain-free.
    #[arg(long)]
    check_compile: bool,

    /// Overall pass threshold. Defaults to the D4.1 contractual bar.
    #[arg(long, default_value_t = 0.90)]
    threshold: f64,
}

// ---------------------------------------------------------------------
// main
// ---------------------------------------------------------------------

fn main() -> ExitCode {
    let cli = Cli::parse();
    let exit = match cli.command {
        Command::DumpFacts(args) => run_dump_facts(&args),
        Command::DumpIr(args) => run_dump_ir(&args),
        Command::DumpHir(args) => run_dump_hir(&args),
        Command::DumpWat(args) => run_dump_wat(&args),
        Command::Decompile(args) => run_decompile(&args),
        Command::Coverage(args) => run_coverage(&args),
        Command::Score(args) => run_score(&args),
    };
    ExitCode::from(exit)
}

// ---------------------------------------------------------------------
// Subcommand handlers
// ---------------------------------------------------------------------

fn run_dump_facts(args: &DumpFactsArgs) -> u8 {
    // 1. Read the input file. I/O errors get a dedicated exit code so
    //    they don't conflate with pipeline failures.
    let bytes = match std::fs::read(&args.wasm) {
        Ok(b) => b,
        Err(e) => {
            let _ = writeln!(
                std::io::stderr(),
                "sordec: could not read {}: {e}",
                args.wasm.display()
            );
            return EXIT_IO_ERR;
        }
    };

    // 2. Run the frontend.
    let parse_output = match sordec_frontend::parse(&bytes) {
        Ok(out) => out,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "sordec: parse failed: {e}");
            return EXIT_PIPELINE_ERR;
        }
    };

    // 3. Serialise to pretty JSON on stdout. Lock stdout to avoid
    //    interleaving with anything else this process might write.
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    if let Err(e) = serde_json::to_writer_pretty(&mut out, &parse_output) {
        let _ = writeln!(std::io::stderr(), "sordec: JSON serialisation failed: {e}");
        return EXIT_IO_ERR;
    }
    // serde_json::to_writer_pretty doesn't append a trailing newline;
    // adding one keeps shell prompts tidy.
    let _ = writeln!(out);

    // 4. Print non-fatal diagnostics to stderr (warnings/info). Goes
    //    AFTER the stdout payload so a caller piping stdout to a file
    //    sees the diagnostics immediately on the terminal.
    diagnostics::print_diagnostics(parse_output.diagnostics.as_slice());

    EXIT_OK
}

fn run_dump_ir(args: &DumpIrArgs) -> u8 {
    // 1. Read the input file.
    let bytes = match std::fs::read(&args.wasm) {
        Ok(b) => b,
        Err(e) => {
            let _ = writeln!(
                std::io::stderr(),
                "sordec: could not read {}: {e}",
                args.wasm.display()
            );
            return EXIT_IO_ERR;
        }
    };

    // 2. Parse.
    let parse_output = match sordec_frontend::parse(&bytes) {
        Ok(out) => out,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "sordec: parse failed: {e}");
            return EXIT_PIPELINE_ERR;
        }
    };

    // 3. Lift.
    let mut lift_output = match sordec_passes::lift_with_waffle(
        &bytes,
        &parse_output.wasm_facts,
        parse_output.soroban_facts.as_ref(),
    ) {
        Ok(out) => out,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "sordec: lift failed: {e}");
            return EXIT_PIPELINE_ERR;
        }
    };

    // 3b. De-clutter unless `--raw`: the default view is the lifted IR
    //     the rest of the pipeline actually consumes.
    let mut declutter_diagnostics = Vec::new();
    if !args.raw {
        let report = sordec_passes::default_lifted_pipeline().run(&mut lift_output.lifted);
        declutter_diagnostics = report.diagnostics().cloned().collect();
    }

    // 4. Render to stdout.
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let options = pretty::RenderOptions {
        with_header: args.with_header,
        skip_unreachable: !args.raw,
    };
    if let Err(e) = pretty::render_lifted_ir(&mut out, &lift_output.lifted, &options) {
        let _ = writeln!(std::io::stderr(), "sordec: write failed: {e}");
        return EXIT_IO_ERR;
    }

    // 5. Diagnostics from parse, lift, and de-cluttering on stderr, in
    //    pipeline order. Concatenated into a single pass so a
    //    downstream piping caller sees them together.
    let mut combined = parse_output.diagnostics.into_vec();
    combined.extend(lift_output.diagnostics.into_vec());
    combined.extend(declutter_diagnostics);
    diagnostics::print_diagnostics(&combined);

    EXIT_OK
}

fn run_dump_hir(args: &DumpHirArgs) -> u8 {
    // 1. Read the input file.
    let bytes = match std::fs::read(&args.wasm) {
        Ok(b) => b,
        Err(e) => {
            let _ = writeln!(
                std::io::stderr(),
                "sordec: could not read {}: {e}",
                args.wasm.display()
            );
            return EXIT_IO_ERR;
        }
    };

    // 2. Parse.
    let parse_output = match sordec_frontend::parse(&bytes) {
        Ok(out) => out,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "sordec: parse failed: {e}");
            return EXIT_PIPELINE_ERR;
        }
    };

    // 3. Lift.
    let mut lift_output = match sordec_passes::lift_with_waffle(
        &bytes,
        &parse_output.wasm_facts,
        parse_output.soroban_facts.as_ref(),
    ) {
        Ok(out) => out,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "sordec: lift failed: {e}");
            return EXIT_PIPELINE_ERR;
        }
    };

    // 3b. De-clutter the lifted IR unless `--raw` (which shows the
    //     mechanical lowering of the pristine lift).
    let mut pipeline_diagnostics = Vec::new();
    if !args.raw {
        let report = sordec_passes::default_lifted_pipeline().run(&mut lift_output.lifted);
        pipeline_diagnostics.extend(report.diagnostics().cloned());
    }

    // 4. Lower to HighIr (mechanical boundary step). Consumes the lifted
    //    IR by value per the `LoweringStep` contract.
    let mut high = match sordec_passes::LiftToHigh.lower(lift_output.lifted) {
        Ok(high) => high,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "sordec: lowering failed: {e:?}");
            return EXIT_PIPELINE_ERR;
        }
    };

    // 4b. Run the pattern-recovery pipeline unless `--raw`. Recognizers
    //     rewrite bindings into semantic ops in place; `--raw` preserves
    //     the mechanical lowering view for debugging.
    if !args.raw {
        let report = sordec_passes::default_high_pipeline().run(&mut high);
        pipeline_diagnostics.extend(report.diagnostics().cloned());
    }

    // 5. Render to stdout.
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mode = if args.raw {
        pretty_hir::RenderMode::Raw
    } else {
        pretty_hir::RenderMode::Structured
    };
    if let Err(e) = pretty_hir::render_high_ir(&mut out, &high, mode) {
        let _ = writeln!(std::io::stderr(), "sordec: write failed: {e}");
        return EXIT_IO_ERR;
    }

    // 6. Parse + lift + recogniser-pipeline diagnostics to stderr, after
    //    stdout.
    let mut combined = parse_output.diagnostics.into_vec();
    combined.extend(lift_output.diagnostics.into_vec());
    combined.extend(pipeline_diagnostics);
    diagnostics::print_diagnostics(&combined);

    EXIT_OK
}

fn run_dump_wat(args: &DumpWatArgs) -> u8 {
    // 1. Read the input file.
    let bytes = match std::fs::read(&args.wasm) {
        Ok(b) => b,
        Err(e) => {
            let _ = writeln!(
                std::io::stderr(),
                "sordec: could not read {}: {e}",
                args.wasm.display()
            );
            return EXIT_IO_ERR;
        }
    };

    // 2. Parse.
    let parse_output = match sordec_frontend::parse(&bytes) {
        Ok(out) => out,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "sordec: parse failed: {e}");
            return EXIT_PIPELINE_ERR;
        }
    };

    // 3. Lift.
    let mut lift_output = match sordec_passes::lift_with_waffle(
        &bytes,
        &parse_output.wasm_facts,
        parse_output.soroban_facts.as_ref(),
    ) {
        Ok(out) => out,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "sordec: lift failed: {e}");
            return EXIT_PIPELINE_ERR;
        }
    };

    // 4. De-clutter, lower to HighIr, and run pattern recovery — the full
    //    pipeline the annotated WAT is a view of (no `--raw`: unrecognised
    //    IR emits as honest `;; unrecognized` annotations, not a raw dump).
    let declutter = sordec_passes::default_lifted_pipeline().run(&mut lift_output.lifted);
    let mut high = match sordec_passes::LiftToHigh.lower(lift_output.lifted) {
        Ok(high) => high,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "sordec: lowering failed: {e:?}");
            return EXIT_PIPELINE_ERR;
        }
    };
    let recover = sordec_passes::default_high_pipeline().run(&mut high);

    // 5. Emit annotated WAT to stdout.
    let wat = match sordec_backend::emit_annotated_wat(&high, &bytes) {
        Ok(wat) => wat,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "sordec: WAT emission failed: {e}");
            return EXIT_PIPELINE_ERR;
        }
    };
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    if let Err(e) = out.write_all(wat.as_bytes()) {
        let _ = writeln!(std::io::stderr(), "sordec: write failed: {e}");
        return EXIT_IO_ERR;
    }

    // 6. Pipeline diagnostics to stderr, after stdout.
    let mut combined = parse_output.diagnostics.into_vec();
    combined.extend(lift_output.diagnostics.into_vec());
    combined.extend(declutter.diagnostics().cloned());
    combined.extend(recover.diagnostics().cloned());
    diagnostics::print_diagnostics(&combined);

    EXIT_OK
}

fn run_decompile(args: &DecompileArgs) -> u8 {
    // 1. Read the input file.
    let bytes = match std::fs::read(&args.wasm) {
        Ok(b) => b,
        Err(e) => {
            let _ = writeln!(
                std::io::stderr(),
                "sordec: could not read {}: {e}",
                args.wasm.display()
            );
            return EXIT_IO_ERR;
        }
    };

    // 2. Run the whole pipeline through the driver.
    let output = match sordec_driver::Driver::standard().run(&bytes) {
        Ok(output) => output,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "sordec: decompile failed: {e}");
            return EXIT_PIPELINE_ERR;
        }
    };

    // 3. Write artifacts to `<out-dir>/<name>/`. `<name>` is the WASM
    //    file stem; fall back to "contract" for a stemless path.
    let name = args
        .wasm
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("contract");
    let contract_dir = args.out_dir.join(name);
    if let Err(e) = std::fs::create_dir_all(&contract_dir) {
        let _ = writeln!(
            std::io::stderr(),
            "sordec: could not create {}: {e}",
            contract_dir.display()
        );
        return EXIT_IO_ERR;
    }
    let wat_path = contract_dir.join(format!("{name}.wat"));
    if let Err(e) = std::fs::write(&wat_path, output.wat.as_bytes()) {
        let _ = writeln!(
            std::io::stderr(),
            "sordec: could not write {}: {e}",
            wat_path.display()
        );
        return EXIT_IO_ERR;
    }

    // 4. Report the written path on stdout; pipeline diagnostics on stderr.
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    if let Err(e) = writeln!(out, "{}", wat_path.display()) {
        let _ = writeln!(std::io::stderr(), "sordec: write failed: {e}");
        return EXIT_IO_ERR;
    }
    if let Some(report) = output.report {
        diagnostics::print_diagnostics(&report.diagnostics);
    }

    EXIT_OK
}

fn run_coverage(args: &CoverageArgs) -> u8 {
    // 1. Read the input file.
    let bytes = match std::fs::read(&args.wasm) {
        Ok(b) => b,
        Err(e) => {
            let _ = writeln!(
                std::io::stderr(),
                "sordec: could not read {}: {e}",
                args.wasm.display()
            );
            return EXIT_IO_ERR;
        }
    };

    // 2. Parse.
    let parse_output = match sordec_frontend::parse(&bytes) {
        Ok(out) => out,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "sordec: parse failed: {e}");
            return EXIT_PIPELINE_ERR;
        }
    };

    // 3. Lift.
    let mut lift_output = match sordec_passes::lift_with_waffle(
        &bytes,
        &parse_output.wasm_facts,
        parse_output.soroban_facts.as_ref(),
    ) {
        Ok(out) => out,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "sordec: lift failed: {e}");
            return EXIT_PIPELINE_ERR;
        }
    };

    // 3b. De-clutter: coverage always reports on the IR the real
    //     pipeline consumes. The declutter counters ride along in
    //     `metric_totals` (surfacing is a W8 concern).
    let declutter_report =
        sordec_passes::default_lifted_pipeline().run(&mut lift_output.lifted);

    // 4. Run the recogniser pipeline (on a lowered clone of the lifted
    //    IR; the original is borrowed by `compute_coverage`) and harvest
    //    both signals from the one report: per-code diagnostics (the
    //    E3/F9 signal) and per-pass metric totals (the F1–F8 + headline
    //    signal).
    let (recognizer_diagnostics, mut metric_totals) =
        match sordec_passes::LiftToHigh.lower(lift_output.lifted.clone()) {
            Ok(mut high) => {
                let report = sordec_passes::default_high_pipeline().run(&mut high);
                (report.diagnostic_counts_by_code(), report.metric_totals())
            }
            // A lowering failure here is not fatal to coverage — report the
            // lift-layer numbers with empty recognition sections.
            Err(_) => (
                std::collections::BTreeMap::new(),
                std::collections::BTreeMap::new(),
            ),
        };
    for (key, value) in declutter_report.metric_totals() {
        *metric_totals.entry(key).or_insert(0) += value;
    }

    // 5. Compute the report. Pure — no failure modes.
    let report = coverage::compute_coverage(
        &args.wasm,
        parse_output.diagnostics.as_slice(),
        parse_output.soroban_facts.is_some(),
        &lift_output.lifted,
        lift_output.diagnostics.as_slice(),
        &recognizer_diagnostics,
        &metric_totals,
    );

    // 5. Render to stdout in the requested format. Lock stdout to
    //    avoid interleaving with anything else this process writes.
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let render_result: io::Result<()> = if args.json {
        match coverage::render_json(&mut out, &report) {
            Ok(()) => writeln!(out),
            Err(e) => Err(io::Error::other(e)),
        }
    } else {
        coverage::render_text(&mut out, &report)
    };
    if let Err(e) = render_result {
        let _ = writeln!(std::io::stderr(), "sordec: write failed: {e}");
        return EXIT_IO_ERR;
    }

    // 6. Diagnostics from BOTH parse and lift on stderr, same pattern
    //    as `dump-ir`. Goes after stdout so a piping caller sees them
    //    together on the terminal.
    let mut combined = parse_output.diagnostics.into_vec();
    combined.extend(lift_output.diagnostics.into_vec());
    diagnostics::print_diagnostics(&combined);

    EXIT_OK
}

fn run_score(args: &ScoreArgs) -> u8 {
    // 1. Load + score. The loader reads both inputs (a `.rs` file or a
    //    source directory); an I/O failure gets the dedicated exit code so
    //    it doesn't conflate with a parse failure.
    let opts = sordec_score::ScoreOptions {
        threshold: args.threshold,
        check_compile: args.check_compile,
    };
    let report = match sordec_score::score_paths(&args.reconstructed, &args.original, &opts) {
        Ok(report) => report,
        Err(e @ sordec_score::ScoreError::Io { .. }) => {
            let _ = writeln!(std::io::stderr(), "sordec: {e}");
            return EXIT_IO_ERR;
        }
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "sordec: scoring failed: {e}");
            return EXIT_PIPELINE_ERR;
        }
    };

    // 3. Render to stdout. The `passed` verdict lives in the report; the
    //    exit code reflects only whether scoring ran (Unix convention,
    //    matching `coverage`).
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let render_result: io::Result<()> = if args.json {
        match serde_json::to_writer_pretty(&mut out, &report) {
            Ok(()) => writeln!(out),
            Err(e) => Err(io::Error::other(e)),
        }
    } else {
        render_score_text(&mut out, &report)
    };
    if let Err(e) = render_result {
        let _ = writeln!(std::io::stderr(), "sordec: write failed: {e}");
        return EXIT_IO_ERR;
    }

    EXIT_OK
}

/// Render a [`sordec_score::ScoreReport`] as a human-readable report.
fn render_score_text(
    out: &mut impl Write,
    report: &sordec_score::ScoreReport,
) -> io::Result<()> {
    use sordec_score::metrics;

    writeln!(out, "scorer version: {}", report.scorer_version)?;
    let verdict = if report.passed { "PASS" } else { "FAIL" };
    writeln!(
        out,
        "overall:        {:.4}  (threshold {:.2})  {verdict}",
        report.overall, report.threshold
    )?;

    let cats = &report.categories;
    for (label, cat) in [
        (metrics::INTERFACE, &cats.interface),
        (metrics::STRUCTURE, &cats.structure),
        (metrics::SEMANTIC, &cats.semantic),
        (metrics::COMPILATION, &cats.compilation),
    ] {
        render_category_line(out, label, cat)?;
    }

    if !report.notes.is_empty() {
        writeln!(out, "notes:")?;
        for note in &report.notes {
            writeln!(out, "  - {note}")?;
        }
    }
    Ok(())
}

/// Render one category line: score + weight, or an em dash + reason when
/// the category was not checked.
fn render_category_line(
    out: &mut impl Write,
    label: &str,
    cat: &sordec_score::CategoryScore,
) -> io::Result<()> {
    if cat.checked {
        write!(out, "  {label:<13} {:.4}  (w {:.2})", cat.score, cat.weight)?;
    } else {
        write!(out, "  {label:<13} —       (w {:.2}, not checked)", cat.weight)?;
    }
    if let Some(note) = cat.notes.first() {
        write!(out, "  {note}")?;
    }
    writeln!(out)
}
