//! Source-to-source accuracy scorer for the sordec decompiler.
//!
//! Compares a **reconstructed** Rust source against the **original** and
//! reports a versioned, per-category accuracy breakdown — the measuring
//! instrument for the ≥90% AST-diff acceptance criterion (D4.1). Built
//! before the Rust emitter so the emitter is gradeable from day one.
//!
//! ## Design
//!
//! The scorer is a pure `.rs` × `.rs` comparator. It parses both sides
//! with [`syn`] and never touches WASM or our IR — the instrument stays
//! independent of the pipeline it grades. The score is **not** a single
//! blended tree-edit distance (the anti-pattern the legacy scorer was);
//! it is four independently reported categories, so one category can never
//! mask another:
//!
//! - **interface** — public entrypoint signatures + `#[contracttype]` shapes
//! - **structure** — per-function control-flow-skeleton similarity
//! - **semantic** — precision/recall over recovered Soroban-operation facts
//! - **compilation** — does the reconstruction `cargo check` (opt-in)
//!
//! See [`score_files`] for the entry point and [`ScoreReport`] for the
//! output. The metric is frozen + versioned: see [`SCORER_VERSION`].

mod compile;
mod error;
mod interface;
mod loader;
pub mod metrics;
mod report;
mod semantic;
mod structure;

use std::path::Path;

pub use error::ScoreError;
pub use report::{Categories, CategoryScore, ScoreReport, SCORER_VERSION};

/// Knobs for a scoring run.
#[derive(Debug, Clone, Copy)]
pub struct ScoreOptions {
    /// Pass threshold for the overall score. Default `0.90` (the D4.1
    /// contractual bar).
    pub threshold: f64,
    /// Whether to run the opt-in compilation category (`cargo check`
    /// against `soroban-sdk`). Off by default so the fast path — and the
    /// default test suite — stays toolchain-free.
    pub check_compile: bool,
}

impl Default for ScoreOptions {
    fn default() -> Self {
        Self {
            threshold: 0.90,
            check_compile: false,
        }
    }
}

/// Score a reconstructed source file against the original, both already
/// parsed. The primary entry point once inputs are loaded.
#[must_use]
pub fn score_files(
    reconstructed: &syn::File,
    original: &syn::File,
    opts: &ScoreOptions,
) -> ScoreReport {
    let categories = Categories {
        interface: interface::evaluate(reconstructed, original),
        structure: structure::evaluate(reconstructed, original),
        semantic: semantic::evaluate(reconstructed, original),
        compilation: compile::evaluate(reconstructed, original, opts.check_compile),
    };
    ScoreReport::aggregate(categories, opts.threshold)
}

/// Score two scoring inputs given by path. Each path may be a single
/// `.rs` file or a source directory (flattened by the loader). The CLI
/// entry point.
///
/// # Errors
///
/// [`ScoreError::Io`] if a path can't be read; [`ScoreError::Parse`] if
/// either input is not parseable Rust (`side` names which one).
pub fn score_paths(
    reconstructed: &Path,
    original: &Path,
    opts: &ScoreOptions,
) -> Result<ScoreReport, ScoreError> {
    let recon = loader::load(reconstructed, "reconstructed")?;
    let orig = loader::load(original, "original")?;
    Ok(score_files(&recon, &orig, opts))
}

/// Parse two Rust sources and score them.
///
/// # Errors
///
/// [`ScoreError::Parse`] if either input is not parseable Rust; `side`
/// names which one.
pub fn score_str(
    reconstructed: &str,
    original: &str,
    opts: &ScoreOptions,
) -> Result<ScoreReport, ScoreError> {
    let recon = syn::parse_file(reconstructed).map_err(|source| ScoreError::Parse {
        side: "reconstructed",
        source,
    })?;
    let orig = syn::parse_file(original).map_err(|source| ScoreError::Parse {
        side: "original",
        source,
    })?;
    Ok(score_files(&recon, &orig, opts))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: &str = r#"
        #![no_std]
        pub fn add(a: u32, b: u32) -> u32 {
            if a > b { a - b } else { b - a }
        }
    "#;

    #[test]
    fn identity_scores_one_and_passes() {
        let report = score_str(SRC, SRC, &ScoreOptions::default()).expect("parse");
        assert!((report.overall - 1.0).abs() < 1e-9);
        assert!(report.passed);
        assert_eq!(report.scorer_version, SCORER_VERSION);
    }

    #[test]
    fn unparseable_input_is_a_parse_error() {
        let err = score_str("fn (", SRC, &ScoreOptions::default()).expect_err("must fail");
        assert!(matches!(
            err,
            ScoreError::Parse {
                side: "reconstructed",
                ..
            }
        ));
    }
}
