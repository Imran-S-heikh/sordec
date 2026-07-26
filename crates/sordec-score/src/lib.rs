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

mod canon;
mod compile;
pub mod config;
mod error;
mod expand;
mod extract;
mod facts;
mod interface;
mod loader;
pub mod metrics;
mod report;
mod scratch;
mod semantic;
mod simil;
mod structure;

use std::path::Path;

pub use config::WeightProfile;
pub use error::ScoreError;
pub use report::{Categories, CategoryScore, ScoreReport, SCORER_VERSION};

/// Knobs for a scoring run.
#[derive(Debug, Clone)]
pub struct ScoreOptions {
    /// Pass threshold for the overall score. Default `0.90` (the D4.1
    /// contractual bar).
    pub threshold: f64,
    /// Whether to run the opt-in compilation category (`cargo check`
    /// against `soroban-sdk`). Off by default so the fast path — and the
    /// default test suite — stays toolchain-free.
    pub check_compile: bool,
    /// Per-category weights for the overall mean. Defaults to
    /// [`WeightProfile::rfp_default`] (the frozen score-1.0.0 weights).
    pub weights: WeightProfile,
    /// Score the AST categories on **macro-expanded** sources rather than the
    /// sources as written — the basis the RFP mandates.
    ///
    /// Off by default while the harness lands (milestone M2, T6): enabling it
    /// moves every score, so flipping the default belongs with the
    /// per-category basis decision and its version bump (T9). Needs a
    /// toolchain; when expansion is unavailable the run falls back to the
    /// pre-expansion basis and says so in [`ScoreReport::notes`].
    ///
    /// Only [`score_paths`] can honor this — expansion needs source *paths*,
    /// which a parsed AST does not carry.
    pub expand: bool,
}

impl Default for ScoreOptions {
    fn default() -> Self {
        Self {
            threshold: 0.90,
            check_compile: false,
            weights: WeightProfile::rfp_default(),
            expand: false,
        }
    }
}

/// Score a reconstructed source file against the original, both already
/// parsed. The compilation category is reported *unchecked* here: it needs
/// the reconstructed source *path* (see [`score_paths`]), which a parsed
/// AST does not carry.
#[must_use]
pub fn score_files(
    reconstructed: &syn::File,
    original: &syn::File,
    opts: &ScoreOptions,
) -> ScoreReport {
    let compilation = CategoryScore::unchecked(
        "compile check needs a source path (use score_paths or the CLI)",
    );
    assemble(reconstructed, original, compilation, &opts.weights, opts.threshold)
}

/// Score two scoring inputs given by path. Each path may be a single
/// `.rs` file or a source directory (flattened by the loader). The CLI
/// entry point; the only path that can run the compilation category.
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
    let basis = load_basis(reconstructed, original, opts)?;
    let compilation = if opts.check_compile {
        compile::check(reconstructed)
    } else {
        CategoryScore::unchecked("compile check not requested")
    };
    let report = assemble(
        &basis.recon,
        &basis.orig,
        compilation,
        &opts.weights,
        opts.threshold,
    );
    Ok(match basis.note {
        Some(note) => report.with_note(note),
        None => report,
    })
}

/// The parsed sources the AST categories are scored against, plus a note
/// recording which basis they came from when it is not the default.
struct Basis {
    recon: syn::File,
    orig: syn::File,
    note: Option<String>,
}

/// Load both sides, macro-expanding them when requested.
///
/// Expansion is best-effort by design: a missing toolchain or an unresolvable
/// dependency degrades to the pre-expansion basis with the reason recorded,
/// rather than failing the run or silently scoring zero. Both sides must
/// expand or neither does — scoring an expanded reconstruction against an
/// un-expanded original would compare two different kinds of thing.
fn load_basis(
    reconstructed: &Path,
    original: &Path,
    opts: &ScoreOptions,
) -> Result<Basis, ScoreError> {
    if opts.expand {
        match (expand::expand(reconstructed), expand::expand(original)) {
            (Ok(recon_text), Ok(orig_text)) => {
                return Ok(Basis {
                    recon: loader::load_str(&recon_text, "reconstructed")?,
                    orig: loader::load_str(&orig_text, "original")?,
                    note: Some("basis: macro-expanded".to_owned()),
                });
            }
            (Err(why), _) | (_, Err(why)) => {
                return Ok(Basis {
                    recon: loader::load(reconstructed, "reconstructed")?,
                    orig: loader::load(original, "original")?,
                    note: Some(format!(
                        "basis: pre-expansion — macro expansion unavailable ({why})"
                    )),
                });
            }
        }
    }
    Ok(Basis {
        recon: loader::load(reconstructed, "reconstructed")?,
        orig: loader::load(original, "original")?,
        note: None,
    })
}

/// Assemble the three AST categories plus a supplied compilation category
/// into a report.
fn assemble(
    reconstructed: &syn::File,
    original: &syn::File,
    compilation: CategoryScore,
    profile: &WeightProfile,
    threshold: f64,
) -> ScoreReport {
    let categories = Categories {
        interface: interface::evaluate(reconstructed, original),
        structure: structure::evaluate(reconstructed, original),
        semantic: semantic::evaluate(reconstructed, original),
        compilation,
    };
    ScoreReport::aggregate(categories, profile, threshold)
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

    #[test]
    fn default_options_use_rfp_weights() {
        let report = score_str(SRC, SRC, &ScoreOptions::default()).expect("parse");
        assert_eq!(report.categories.interface.weight, 0.30);
        assert_eq!(report.categories.structure.weight, 0.25);
        assert_eq!(report.categories.semantic.weight, 0.30);
        assert_eq!(report.categories.compilation.weight, 0.15);
    }

    #[test]
    fn custom_options_weights_reach_the_report() {
        // A custom profile on ScoreOptions must flow through
        // assemble -> aggregate -> report.
        let custom = WeightProfile {
            name: "custom".to_owned(),
            interface: 0.70,
            structure: 0.10,
            semantic: 0.10,
            compilation: 0.10,
        };
        let opts = ScoreOptions {
            weights: custom,
            ..ScoreOptions::default()
        };
        let report = score_str(SRC, SRC, &opts).expect("parse");
        assert_eq!(report.categories.interface.weight, 0.70);
        assert_eq!(report.categories.structure.weight, 0.10);
    }
}
