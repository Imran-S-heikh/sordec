//! Shared scaffolding for backend integration tests: build a fully
//! recovered [`HighIr`] from fixture bytes by running the same pipeline
//! the CLI does (parse → lift → declutter → lower → recognisers).
//!
//! Shared across integration-test binaries; not every binary uses every
//! helper, so unused-item warnings here are expected.
#![allow(dead_code)]

use sordec_ir::HighIr;
use sordec_passes::LoweringStep;

/// What `cargo check` said about an emitted crate.
pub struct CheckReport {
    /// Number of `error…` lines cargo printed. Zero means it compiled.
    pub error_lines: usize,
    /// Cargo's stderr, for a failing assertion to quote.
    pub output: String,
}

/// Where every emitted crate's `cargo check` puts its build artifacts.
///
/// One directory, shared across fixtures and across runs, because the
/// expensive part of checking an emitted crate is building `soroban-sdk`
/// and that build is identical every time. A scratch target dir per
/// fixture made the corpus compile rate seven consecutive SDK builds —
/// minutes of wall clock and gigabytes of churn on a disk that does not
/// have gigabytes spare, which is reason enough not to run the
/// measurement, and a measurement nobody runs drifts.
///
/// Overridable so a machine with its own layout, or CI wanting a cold
/// build, can say so.
pub fn shared_target_dir() -> std::path::PathBuf {
    std::env::var_os("SORDEC_CHECK_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("sordec-check-target"))
}

/// Emit `wasm` as a standalone crate and `cargo check` it offline.
///
/// The manifest is written **verbatim** as the emitter produced it — never
/// patched — so a passing check is a claim about the crate we actually
/// ship, not about a repaired copy of it.
#[must_use]
pub fn cargo_check_emitted(wasm: &[u8]) -> CheckReport {
    let high = build_high(wasm);
    let rust = sordec_backend::emit_rust(&high).expect("emits");
    let cargo_toml = sordec_backend::emit_cargo_toml(&high);

    let dir = std::env::temp_dir().join(format!(
        "sordec-check-{}-{}",
        std::process::id(),
        wasm.len()
    ));
    let src = dir.join("src");
    std::fs::create_dir_all(&src).expect("scratch dir");
    std::fs::write(dir.join("Cargo.toml"), &cargo_toml).expect("manifest");
    std::fs::write(src.join("lib.rs"), &rust).expect("source");

    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let output = std::process::Command::new(cargo)
        .args(["check", "--offline", "--quiet", "--manifest-path"])
        .arg(dir.join("Cargo.toml"))
        .env("CARGO_TARGET_DIR", shared_target_dir())
        .output()
        .expect("cargo runs");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let error_lines = stderr
        .lines()
        .filter(|l| l.trim_start().starts_with("error"))
        .count();

    let _ = std::fs::remove_dir_all(&dir);
    CheckReport {
        error_lines,
        output: stderr,
    }
}

/// Run the full front-to-high pipeline on `wasm`, mirroring the CLI's
/// `dump-hir` path.
#[must_use]
pub fn build_high(wasm: &[u8]) -> HighIr {
    let parsed = sordec_frontend::parse(wasm).expect("fixture parses");
    let mut lift = sordec_passes::lift_with_waffle(
        wasm,
        &parsed.wasm_facts,
        parsed.soroban_facts.as_ref(),
    )
    .expect("lift succeeds");
    sordec_passes::default_lifted_pipeline().run(&mut lift.lifted);
    let mut high = sordec_passes::LiftToHigh
        .lower(lift.lifted)
        .expect("lowering succeeds");
    sordec_passes::default_high_pipeline().run(&mut high);
    high
}

macro_rules! fixture_bytes {
    ($name:literal) => {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../samples/contracts/",
            $name,
            "/",
            $name,
            ".wasm"
        ))
    };
}

/// Every committed fixture as `(name, bytes)`, in the order the corpus
/// tooling reports them.
#[must_use]
pub fn fixtures() -> Vec<(&'static str, &'static [u8])> {
    vec![
        ("hello-add", fixture_bytes!("hello-add")),
        ("token-v22", fixture_bytes!("token-v22")),
        ("token-v23", fixture_bytes!("token-v23")),
        ("token-v23-stripped", fixture_bytes!("token-v23-stripped")),
        ("timelock", fixture_bytes!("timelock")),
        ("attestation", fixture_bytes!("attestation")),
        ("dex-liquidity-pool", fixture_bytes!("dex-liquidity-pool")),
    ]
}

/// The SEP-41 token fixture — the canonical benchmark.
pub const TOKEN_V23: &[u8] = fixture_bytes!("token-v23");

/// The attestation fixture — the corpus's `#[contracterror]` + `Result`
/// contract (the S2b error-return benchmark).
pub const ATTESTATION: &[u8] = fixture_bytes!("attestation");
