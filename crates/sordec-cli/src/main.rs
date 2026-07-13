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
//! - `sordec coverage <wasm>` — parse + lift, then emit a coverage
//!   report (host-call recognition %, lift completeness, parse +
//!   metadata health) as text or `--json`.
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
    /// Report how much of a contract this pipeline currently understands.
    Coverage(CoverageArgs),
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
}

#[derive(clap::Args)]
struct DumpHirArgs {
    /// Path to the WASM module to inspect.
    wasm: PathBuf,

    /// Skip the pattern-recovery pipeline and show the raw lowered IR
    /// (the mechanical `LiftedIr → HighIr` output with no semantic
    /// recognition). Useful for debugging the lowering itself.
    #[arg(long)]
    raw: bool,
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

// ---------------------------------------------------------------------
// main
// ---------------------------------------------------------------------

fn main() -> ExitCode {
    let cli = Cli::parse();
    let exit = match cli.command {
        Command::DumpFacts(args) => run_dump_facts(&args),
        Command::DumpIr(args) => run_dump_ir(&args),
        Command::DumpHir(args) => run_dump_hir(&args),
        Command::Coverage(args) => run_coverage(&args),
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
    let lift_output = match sordec_passes::lift_with_waffle(
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

    // 4. Render to stdout.
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let options = pretty::RenderOptions {
        with_header: args.with_header,
    };
    if let Err(e) = pretty::render_lifted_ir(&mut out, &lift_output.lifted, &options) {
        let _ = writeln!(std::io::stderr(), "sordec: write failed: {e}");
        return EXIT_IO_ERR;
    }

    // 5. Diagnostics from BOTH parse and lift on stderr, in pipeline
    //    order (parse first, then lift). Concatenated into a single
    //    pass so a downstream piping caller sees them together.
    let mut combined = parse_output.diagnostics.into_vec();
    combined.extend(lift_output.diagnostics.into_vec());
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
    let lift_output = match sordec_passes::lift_with_waffle(
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
    let mut pipeline_diagnostics = Vec::new();
    if !args.raw {
        let report = sordec_passes::default_high_pipeline().run(&mut high);
        pipeline_diagnostics = report.diagnostics().cloned().collect();
    }

    // 5. Render to stdout.
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    if let Err(e) = pretty_hir::render_high_ir(&mut out, &high) {
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
    let lift_output = match sordec_passes::lift_with_waffle(
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

    // 4. Run the recogniser pipeline (on a lowered clone of the lifted
    //    IR; the original is borrowed by `compute_coverage`) and harvest
    //    both signals from the one report: per-code diagnostics (the
    //    E3/F9 signal) and per-pass metric totals (the F1–F8 + headline
    //    signal).
    let (recognizer_diagnostics, metric_totals) =
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
