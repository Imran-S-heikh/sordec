//! End-to-end tests for the wired [`Driver::run`].
//!
//! The corpus smoke tests (`corpus.rs`) hand-wire the front half of the
//! pipeline; these exercise the whole thing through the public
//! [`Driver`] entry point — parse → lift → declutter → lower → recover →
//! emit — on every committed fixture.

use sordec_driver::{Driver, DriverError};

macro_rules! fixture {
    ($name:literal) => {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../samples/contracts/",
            $name,
            "/",
            $name,
            ".wasm"
        )) as &[u8]
    };
}

fn fixtures() -> Vec<(&'static str, &'static [u8])> {
    vec![
        ("hello-add", fixture!("hello-add")),
        ("token-v22", fixture!("token-v22")),
        ("token-v23", fixture!("token-v23")),
        ("token-v23-stripped", fixture!("token-v23-stripped")),
        ("timelock", fixture!("timelock")),
        ("attestation", fixture!("attestation")),
        ("dex-liquidity-pool", fixture!("dex-liquidity-pool")),
    ]
}

#[test]
fn standard_driver_decompiles_every_fixture_to_annotated_wat() {
    let driver = Driver::standard();
    for (name, wasm) in fixtures() {
        let output = driver
            .run(wasm)
            .unwrap_or_else(|e| panic!("{name}: driver run failed: {e}"));

        assert!(
            output.wat.contains("Soroban annotated WAT"),
            "{name}: output carries the annotated-WAT banner"
        );
        assert!(
            output.wat.contains("(module"),
            "{name}: output wraps the disassembled module"
        );
        // The driver now emits both artifacts: reconstructed Rust and its
        // crate manifest, alongside the annotated WAT.
        assert!(
            output.rust.starts_with("#![no_std]"),
            "{name}: reconstructed Rust module present"
        );
        assert!(
            output.cargo_toml.contains("crate-type = [\"cdylib\"]"),
            "{name}: a buildable crate manifest"
        );
        // The report is populated (diagnostics + per-pipeline reports).
        assert!(output.report.is_some(), "{name}: run produces a report");
    }
}

#[test]
fn driver_run_surfaces_frontend_error_on_garbage() {
    let err = Driver::standard()
        .run(b"definitely not wasm")
        .expect_err("garbage input must not decompile");
    assert!(
        matches!(err, DriverError::Frontend(_)),
        "expected a frontend error, got {err:?}"
    );
}
