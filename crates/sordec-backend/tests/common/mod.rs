//! Shared scaffolding for backend integration tests: build a fully
//! recovered [`HighIr`] from fixture bytes by running the same pipeline
//! the CLI does (parse → lift → declutter → lower → recognisers).

use sordec_ir::HighIr;
use sordec_passes::LoweringStep;

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
