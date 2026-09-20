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
//! - `sordec dump-rust <wasm>` — run the full pipeline, then emit the
//!   reconstructed Rust (`src/lib.rs`) on stdout. Debug view of the Rust
//!   emitter; `decompile` writes it to disk.
//! - `sordec decompile <wasm> --out-dir <dir>` — run the full pipeline
//!   via the [`sordec_driver::Driver`] and write a buildable crate
//!   (`Cargo.toml`, `src/lib.rs`) beside `<name>.wat`.
//! - `sordec coverage <wasm>` — parse + lift, then emit a coverage
//!   report (host-call recognition %, lift completeness, parse +
//!   metadata health) as text or `--json`.
//! - `sordec score <reconstructed.rs> <original.rs>` — score a
//!   reconstructed Rust source against the original across four
//!   categories (interface / structure / semantic / behavior) plus the
//!   compilation gate, as text
//!   or `--json`. The accuracy measuring instrument (D4.1).
//!
//! Output convention (Unix-standard):
//!
//! - **stdout**: primary output. Pipe-friendly.
//! - **stderr**: non-fatal diagnostics from the pipeline, plus error
//!   messages on failure. Silence the diagnostics with `--quiet`; errors
//!   always print.
//!
//! Any subcommand taking a module accepts `-` in place of a path and reads
//! stdin, so the tool composes in a pipeline.
//!
//! # Which subcommands emit JSON, and why not all of them
//!
//! The rule is what the subcommand *has*, not a preference:
//!
//! - `dump-facts` is JSON only. The facts are structured data; a text
//!   rendering would be a worse view of the same thing.
//! - `dump-ir`, `dump-hir`, `coverage` and `score` are text by default with
//!   `--json` opt-in. Each has a reading view worth defaulting to and an
//!   underlying structure worth serialising.
//! - `dump-wat` and `dump-rust` have no `--json`. They emit WAT and Rust —
//!   source text, where the only JSON form is a one-field envelope around a
//!   string, which tells a consumer nothing the text did not.
//!
//! Exit codes:
//!
//! - **0** — success (output produced; non-fatal diagnostics on stderr
//!   are not failures)
//! - **1** — pipeline error (`FrontendError` or `LiftError` returned)
//! - **2** — usage error (clap's default for argv-parse failure)
//! - **3** — I/O error (couldn't read input file)

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use sordec::behavior;
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

    /// Suppress non-fatal diagnostics on stderr.
    ///
    /// Errors still print and the exit code is unchanged — this silences the
    /// pipeline's warnings, not its failures. Accepted after any subcommand.
    #[arg(long, short = 'q', global = true)]
    quiet: bool,
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
    /// Run the full pipeline and emit reconstructed Rust (`src/lib.rs`) on
    /// stdout. Debug view of the emitter; `decompile` writes it to disk.
    DumpRust(DumpRustArgs),
    /// Decompile a WASM module, writing a buildable crate and the
    /// annotated WAT under `--out-dir`.
    Decompile(DecompileArgs),
    /// Report how much of a contract this pipeline currently understands:
    /// per-pattern recognition (storage tiers, enum keys, TTL, client
    /// calls, dispatcher, auth, events, collections, panics, Val
    /// boilerplate), a two-number semantic-recovery headline (host
    /// interactions vs deep facts), host-call recognition %, and
    /// recogniser-miss diagnostics by code.
    Coverage(CoverageArgs),
    /// Score a reconstructed Rust source against the original across four
    /// categories (interface / structure / semantic / behavior), plus a
    /// pass/fail compilation gate.
    Score(ScoreArgs),
    /// Print a shell completion script on stdout.
    ///
    /// Eight subcommands and six flags on `score` make this worth wiring up:
    ///
    ///   sordec completions zsh  > ~/.zfunc/_sordec
    ///   sordec completions bash > /etc/bash_completion.d/sordec
    Completions(CompletionsArgs),
    /// Print a roff man page on stdout, for a packager to install.
    #[command(hide = true)]
    Man,
}

#[derive(clap::Args)]
struct CompletionsArgs {
    /// Shell to generate for.
    shell: clap_complete::Shell,
}

#[derive(clap::Args)]
struct DumpFactsArgs {
    /// Path to the WASM module to inspect, or `-` for stdin.
    wasm: PathBuf,
}

#[derive(clap::Args)]
struct DumpIrArgs {
    /// Path to the WASM module to inspect, or `-` for stdin.
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

    /// Emit the IR as JSON instead of the text rendering.
    ///
    /// The text form is shaped for reading; this is the same IR shaped for a
    /// program. `--with-header` and `--raw`'s presentation choices do not
    /// apply, since JSON has no presentation — though `--raw` still selects
    /// *which* IR is emitted, pristine or de-cluttered.
    #[arg(long)]
    json: bool,
}

#[derive(clap::Args)]
struct DumpHirArgs {
    /// Path to the WASM module to inspect, or `-` for stdin.
    wasm: PathBuf,

    /// Skip every pipeline — de-cluttering AND pattern recovery — and
    /// show the raw lowered IR (the mechanical `LiftedIr → HighIr`
    /// output of the pristine lift, with no semantic recognition).
    /// Useful for debugging the lowering itself.
    #[arg(long)]
    raw: bool,

    /// Emit the IR as JSON instead of the text rendering.
    ///
    /// The text form is shaped for reading; this is the same IR shaped for a
    /// program. Ignores `--raw`'s presentation choices, since JSON has no
    /// presentation.
    #[arg(long)]
    json: bool,
}

#[derive(clap::Args)]
struct DumpWatArgs {
    /// Path to the WASM module to decompile, or `-` for stdin.
    wasm: PathBuf,
}

#[derive(clap::Args)]
struct DumpRustArgs {
    /// Path to the WASM module to decompile, or `-` for stdin.
    wasm: PathBuf,
}

#[derive(clap::Args)]
struct DecompileArgs {
    /// Path to the WASM module to decompile, or `-` for stdin.
    ///
    /// The output directory is named after the input's file stem. A pipe
    /// carries no filename, so `-` writes to `<out-dir>/contract/`.
    wasm: PathBuf,

    /// Directory to write decompilation artifacts into. A per-contract
    /// subdirectory `<name>/` is created inside it holding `<name>.wat`,
    /// `Cargo.toml` and `src/lib.rs` — a crate you can `cargo build`.
    #[arg(long)]
    out_dir: PathBuf,

    /// Overwrite existing artifacts.
    ///
    /// Without this, `decompile` refuses to write over any of the three files
    /// it produces. The emitted crate is meant to be edited, and silently
    /// replacing an edited `src/lib.rs` loses work.
    #[arg(long)]
    force: bool,
}

#[derive(clap::Args)]
struct CoverageArgs {
    /// Path to the WASM module to inspect, or `-` for stdin.
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

    /// Evaluate the compilation gate (`cargo check` against `soroban-sdk`).
    /// Off by default so the fast path stays toolchain-free.
    ///
    /// The gate is a precondition, not a score: passing this flag cannot raise
    /// the overall number, but a reconstruction that fails to build reports
    /// FAIL regardless of how well it scores.
    #[arg(long)]
    check_compile: bool,

    /// Evaluate the `behavior` category by differential execution against the
    /// original contract's wasm.
    ///
    /// Takes the path to the **original** wasm, which is the oracle: behaviour is
    /// compared against what the deployed contract actually does, not against its
    /// source. The reconstruction argument must then be a crate *directory*, since it
    /// has to be recompiled to wasm before it can be run.
    ///
    /// Off by default — it needs the wasm toolchain (`tools/setup-toolchains.sh`) and
    /// a release build of the reconstruction. Only one build: the oracle side is the
    /// wasm you pass, already compiled.
    ///
    /// Honest about its current reach. Where the reconstruction compiles and its
    /// entrypoints can be driven, this is a number — hello-add and attestation both
    /// score 1.0000, the latter over 2 of its 6 entrypoints. Everywhere else it
    /// reports *why* it could not be measured, never a zero, because "does not build"
    /// and "does the wrong thing" are different findings. Those reasons are the useful
    /// part — "reconstruction does not build (4 diagnostics): error\[E0369\]…" is the
    /// sharpest emitter-progress signal we have.
    #[arg(long, value_name = "ORIGINAL_WASM")]
    behavior: Option<PathBuf>,

    /// Which source basis to score on.
    ///
    /// `rfp-default` (the default) is the basis the RFP mandates: interface
    /// and structure on macro-expanded sources (`cargo expand`), semantic on
    /// the sources as written. Semantic is the deliberate exception —
    /// expansion rewrites `panic!` into calls the fact extractor cannot see,
    /// which would inflate its precision. It needs a toolchain, and falls
    /// back to `source-only` — saying so in the report — when expansion is
    /// unavailable.
    ///
    /// `source-only` scores everything on the sources as written. Needs no
    /// toolchain, and is what the fallback lands on; ask for it explicitly
    /// when you want that guarantee rather than a degraded RFP run.
    #[arg(long, value_name = "PROFILE", default_value = "rfp-default")]
    basis: BasisArg,

    /// Overall pass threshold. Defaults to the D4.1 contractual bar.
    #[arg(long, default_value_t = 0.90)]
    threshold: f64,

    /// Path to a TOML weights profile (see
    /// `crates/sordec-score/profiles/rfp-default.toml`). Absent → the
    /// built-in default weights.
    #[arg(long, value_name = "FILE")]
    weights: Option<PathBuf>,
}

/// The two built-in basis profiles, as a CLI value.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum BasisArg {
    /// Interface + structure macro-expanded, semantic pre-expansion.
    RfpDefault,
    /// Everything on the sources as written; no toolchain needed.
    SourceOnly,
}

impl From<BasisArg> for sordec_score::BasisProfile {
    fn from(arg: BasisArg) -> Self {
        match arg {
            BasisArg::RfpDefault => Self::rfp_default(),
            BasisArg::SourceOnly => Self::source_only(),
        }
    }
}

// ---------------------------------------------------------------------
// main
// ---------------------------------------------------------------------

fn main() -> ExitCode {
    let cli = Cli::parse();
    diagnostics::set_quiet(cli.quiet);
    let exit = match cli.command {
        Command::DumpFacts(args) => run_dump_facts(&args),
        Command::DumpIr(args) => run_dump_ir(&args),
        Command::DumpHir(args) => run_dump_hir(&args),
        Command::DumpWat(args) => run_dump_wat(&args),
        Command::DumpRust(args) => run_dump_rust(&args),
        Command::Decompile(args) => run_decompile(&args),
        Command::Coverage(args) => run_coverage(&args),
        Command::Score(args) => run_score(&args),
        Command::Completions(args) => run_completions(args.shell),
        Command::Man => run_man(),
    };
    ExitCode::from(exit)
}

// ---------------------------------------------------------------------
// Shared input handling
// ---------------------------------------------------------------------

/// The conventional stand-in for standard input.
const STDIN_ARG: &str = "-";

/// Read a WASM input: a filesystem path, or `-` for standard input.
///
/// Every subcommand that takes a module reads it through here, so the error
/// wording and the exit code are decided once. `Err` carries the exit code to
/// return, which is always [`EXIT_IO_ERR`] — a path we cannot read is an
/// environment problem, not a pipeline failure, and conflating the two would
/// make a typo look like a decompiler bug.
fn read_wasm(path: &Path) -> Result<Vec<u8>, u8> {
    if path.as_os_str() == STDIN_ARG {
        let mut bytes = Vec::new();
        return match std::io::stdin().lock().read_to_end(&mut bytes) {
            Ok(_) => Ok(bytes),
            Err(e) => {
                let _ = writeln!(std::io::stderr(), "sordec: could not read stdin: {e}");
                Err(EXIT_IO_ERR)
            }
        };
    }
    std::fs::read(path).map_err(|e| {
        let _ = writeln!(
            std::io::stderr(),
            "sordec: could not read {}: {e}",
            path.display()
        );
        EXIT_IO_ERR
    })
}

// ---------------------------------------------------------------------
// Generated shell integration
// ---------------------------------------------------------------------

/// Write a completion script for `shell` to stdout.
///
/// Generated from the `Parser` derive, so it cannot describe a flag the binary
/// does not have — which is the whole reason not to hand-write these.
fn run_completions(shell: clap_complete::Shell) -> u8 {
    let mut cmd = <Cli as clap::CommandFactory>::command();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    clap_complete::generate(shell, &mut cmd, "sordec", &mut out);
    EXIT_OK
}

/// Write a roff man page to stdout.
fn run_man() -> u8 {
    let cmd = <Cli as clap::CommandFactory>::command();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    if let Err(e) = clap_mangen::Man::new(cmd).render(&mut out) {
        let _ = writeln!(std::io::stderr(), "sordec: write failed: {e}");
        return EXIT_IO_ERR;
    }
    EXIT_OK
}

// ---------------------------------------------------------------------
// Subcommand handlers
// ---------------------------------------------------------------------

fn run_dump_facts(args: &DumpFactsArgs) -> u8 {
    // 1. Read the input file. I/O errors get a dedicated exit code so
    //    they don't conflate with pipeline failures.
    let bytes = match read_wasm(&args.wasm) {
        Ok(b) => b,
        Err(code) => return code,
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
    let bytes = match read_wasm(&args.wasm) {
        Ok(b) => b,
        Err(code) => return code,
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
    let render_result = if args.json {
        serde_json::to_writer_pretty(&mut out, &lift_output.lifted)
            .map_err(io::Error::other)
            .and_then(|()| writeln!(out))
    } else {
        let options = pretty::RenderOptions {
            with_header: args.with_header,
            skip_unreachable: !args.raw,
        };
        pretty::render_lifted_ir(&mut out, &lift_output.lifted, &options)
    };
    if let Err(e) = render_result {
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
    let bytes = match read_wasm(&args.wasm) {
        Ok(b) => b,
        Err(code) => return code,
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
    let render_result = if args.json {
        serde_json::to_writer_pretty(&mut out, &high)
            .map_err(io::Error::other)
            .and_then(|()| writeln!(out))
    } else {
        let mode = if args.raw {
            pretty_hir::RenderMode::Raw
        } else {
            pretty_hir::RenderMode::Structured
        };
        pretty_hir::render_high_ir(&mut out, &high, mode)
    };
    if let Err(e) = render_result {
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
    let bytes = match read_wasm(&args.wasm) {
        Ok(b) => b,
        Err(code) => return code,
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

fn run_dump_rust(args: &DumpRustArgs) -> u8 {
    // 1. Read the input file.
    let bytes = match read_wasm(&args.wasm) {
        Ok(b) => b,
        Err(code) => return code,
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
    //    pipeline the emitter consumes (unrecovered facts degrade to honest
    //    holes, never a raw dump).
    let declutter = sordec_passes::default_lifted_pipeline().run(&mut lift_output.lifted);
    let mut high = match sordec_passes::LiftToHigh.lower(lift_output.lifted) {
        Ok(high) => high,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "sordec: lowering failed: {e:?}");
            return EXIT_PIPELINE_ERR;
        }
    };
    let recover = sordec_passes::default_high_pipeline().run(&mut high);

    // 5. Emit reconstructed Rust to stdout.
    let rust = match sordec_backend::emit_rust(&high) {
        Ok(rust) => rust,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "sordec: Rust emission failed: {e}");
            return EXIT_PIPELINE_ERR;
        }
    };
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    if let Err(e) = out.write_all(rust.as_bytes()) {
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
    let bytes = match read_wasm(&args.wasm) {
        Ok(b) => b,
        Err(code) => return code,
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
    //    file stem; fall back to "contract" when there is no usable stem,
    //    which is also the stdin case — a pipe carries no filename.
    let name = if args.wasm.as_os_str() == STDIN_ARG {
        "contract"
    } else {
        args.wasm
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("contract")
    };
    let contract_dir = args.out_dir.join(name);
    if let Err(e) = std::fs::create_dir_all(&contract_dir) {
        let _ = writeln!(
            std::io::stderr(),
            "sordec: could not create {}: {e}",
            contract_dir.display()
        );
        return EXIT_IO_ERR;
    }
    // Artifacts: `<name>.wat`, the crate manifest, and `src/lib.rs` — a
    // buildable crate directory (`cargo build` from `<out-dir>/<name>`).
    let src_dir = contract_dir.join("src");
    if let Err(e) = std::fs::create_dir_all(&src_dir) {
        let _ = writeln!(
            std::io::stderr(),
            "sordec: could not create {}: {e}",
            src_dir.display()
        );
        return EXIT_IO_ERR;
    }
    let artifacts = [
        (contract_dir.join(format!("{name}.wat")), &output.wat),
        (contract_dir.join("Cargo.toml"), &output.cargo_toml),
        (src_dir.join("lib.rs"), &output.rust),
    ];

    // Refuse to clobber. The emitted crate is something people edit — filling
    // in a `todo!()` hole, adding a test — and a second `decompile` used to
    // overwrite that work with no warning at all. Naming the file that blocked
    // it matters more than naming the flag: the user needs to know what they
    // nearly lost.
    if !args.force
        && let Some((path, _)) = artifacts.iter().find(|(path, _)| path.exists())
    {
        let _ = writeln!(
            std::io::stderr(),
            "sordec: {} already exists; refusing to overwrite it.\n\
             sordec: pass --force to overwrite, or choose a different --out-dir.",
            path.display()
        );
        return EXIT_IO_ERR;
    }

    for (path, contents) in &artifacts {
        if let Err(e) = std::fs::write(path, contents.as_bytes()) {
            let _ = writeln!(
                std::io::stderr(),
                "sordec: could not write {}: {e}",
                path.display()
            );
            return EXIT_IO_ERR;
        }
    }

    // 4. Report the written paths on stdout; pipeline diagnostics on stderr.
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for (path, _) in &artifacts {
        if let Err(e) = writeln!(out, "{}", path.display()) {
            let _ = writeln!(std::io::stderr(), "sordec: write failed: {e}");
            return EXIT_IO_ERR;
        }
    }
    if let Some(report) = output.report {
        diagnostics::print_diagnostics(&report.diagnostics);
    }

    EXIT_OK
}

fn run_coverage(args: &CoverageArgs) -> u8 {
    // 1. Read the input file.
    let bytes = match read_wasm(&args.wasm) {
        Ok(b) => b,
        Err(code) => return code,
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

/// Whether a wasm module declares its own ABI (`contractspecv0`).
///
/// A module that does not carries no parameter names anywhere, so they
/// are not something a reconstruction could have recovered; the scorer
/// is told so and compares parameter types alone. Unreadable bytes
/// answer "it did", which is the stricter reading.
fn declares_abi(wasm: &std::path::Path) -> bool {
    let Ok(bytes) = std::fs::read(wasm) else {
        return true;
    };
    sordec_frontend::parse(&bytes)
        .is_ok_and(|p| p.soroban_facts.is_some_and(|f| !f.functions.is_empty()))
}

fn run_score(args: &ScoreArgs) -> u8 {
    // 1. Load + score. The loader reads both inputs (a `.rs` file or a
    //    source directory); an I/O failure gets the dedicated exit code so
    //    it doesn't conflate with a parse failure.
    let weights = match &args.weights {
        Some(path) => match sordec_score::WeightProfile::load(path) {
            Ok(profile) => profile,
            Err(e) => {
                let _ = writeln!(std::io::stderr(), "sordec: {e}");
                return EXIT_IO_ERR;
            }
        },
        None => sordec_score::WeightProfile::rfp_default(),
    };
    let opts = sordec_score::ScoreOptions {
        threshold: args.threshold,
        check_compile: args.check_compile,
        weights,
        basis: args.basis.into(),
        behavior: match &args.behavior {
            None => sordec_score::BehaviorInput::NotRequested,
            Some(original_wasm) => behavior::measure(&args.reconstructed, original_wasm),
        },
        // Only a module can say whether it declared its own ABI, and
        // the only module this command is ever given is the behaviour
        // oracle. Without one, assume it did: that is the common case
        // and the stricter reading.
        abi_declared: args.behavior.as_ref().is_none_or(|wasm| declares_abi(wasm)),
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
    writeln!(out, "weights profile: {}", report.weights_profile)?;
    writeln!(out, "basis profile:   {}", report.basis_profile)?;
    render_compilation_gate(out, &report.compilation_gate)?;
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
        (metrics::BEHAVIOR, &cats.behavior),
    ] {
        render_category_line(out, label, cat)?;
    }

    render_behavior_detail(out, report.behavior.as_ref())?;

    if !report.notes.is_empty() {
        writeln!(out, "notes:")?;
        for note in &report.notes {
            writeln!(out, "  - {note}")?;
        }
    }
    Ok(())
}

/// Render the differential-execution detail behind the `behavior` category.
///
/// Two rules this function exists to keep, both of them the difference between an
/// honest number and a marketing one:
///
/// **The rate never appears without its denominator.** "99.2% behavioural match" is
/// not a 99.2% result if it was measured over three of thirty entrypoints, and that
/// is precisely the shape of claim we criticised in a competitor's harness. So the
/// coverage fraction is printed on the same line, not below it and not optionally.
///
/// **The four observations are reported separately.** "events 94%, storage 87%" says
/// where to work; a blended "93%" says nothing and hides which facility regressed. A
/// tuple the contract never exercised prints `—`, not a free 100%.
fn render_behavior_detail(
    out: &mut impl Write,
    behavior: Option<&sordec_score::Behavior>,
) -> io::Result<()> {
    let Some(behavior) = behavior else {
        return Ok(());
    };

    writeln!(
        out,
        "behavior:       {:.4} over {}  [{}]",
        behavior.score,
        behavior.coverage(),
        behavior.b_side.label()
    )?;

    // Stated on its own line rather than folded into the rate, because a run whose
    // agreement is mostly mutual failure has demonstrated very little.
    if behavior.trivial_agreements > 0 {
        writeln!(
            out,
            "  {} call(s) excluded as trivial agreement (both sides failed identically)",
            behavior.trivial_agreements
        )?;
    }

    for tuple in &behavior.tuples {
        if tuple.exercised == 0 {
            writeln!(out, "  {:<9} —       (never exercised)", tuple.name)?;
        } else {
            #[allow(clippy::cast_precision_loss)]
            let rate = tuple.matched as f64 / tuple.exercised as f64;
            writeln!(
                out,
                "  {:<9} {rate:.4}  ({} of {} checks)",
                tuple.name, tuple.matched, tuple.exercised
            )?;
        }
    }

    for note in &behavior.notes {
        writeln!(out, "  - {note}")?;
    }
    Ok(())
}

/// Render the compilation gate.
///
/// Placed above `overall` because it is a *precondition* on the verdict, not a
/// contributor to the score: a failed gate means FAIL whatever the categories
/// say. Diagnostics are summarized by count on the gate line and listed
/// beneath — they are the sharpest emitter-progress signal available, so they
/// stay visible even though they no longer earn a score.
fn render_compilation_gate(
    out: &mut impl Write,
    gate: &sordec_score::CompilationGate,
) -> io::Result<()> {
    use sordec_score::CompilationGate;

    match gate {
        CompilationGate::Passed => writeln!(out, "compile gate:   PASS"),
        CompilationGate::Failed { diagnostics } => {
            let n = diagnostics.len();
            let plural = if n == 1 { "" } else { "s" };
            writeln!(out, "compile gate:   FAIL  ({n} diagnostic{plural})")?;
            for line in diagnostics {
                writeln!(out, "  {line}")?;
            }
            Ok(())
        }
        CompilationGate::Unchecked { reason } => {
            writeln!(out, "compile gate:   not checked  ({reason})")
        }
    }
}

/// Render one category line: score + weight, or an em dash + reason when
/// the category was not checked.
///
/// The first note rides on the score line; any further notes are indented
/// beneath it. Interface reports a summary per ABI kind (entrypoints, types)
/// plus their diffs, and showing only the first would hide half of what the
/// category measured — which is precisely what the per-kind split exists to
/// surface.
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
    for note in cat.notes.iter().skip(1) {
        write!(out, "\n{:<17}{note}", "")?;
    }
    writeln!(out)
}
