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
mod glue;
mod interface;
mod loader;
pub mod metrics;
mod report;
mod scratch;
mod semantic;
mod simil;
mod spec;
mod structure;

use std::path::Path;

pub use config::{Basis, BasisProfile, WeightProfile};
pub use error::ScoreError;
pub use report::{Categories, CategoryScore, SCORER_VERSION, ScoreReport};

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
    /// Which source basis each AST category is scored against. Defaults to
    /// [`BasisProfile::source_only`], which needs no toolchain and reproduces
    /// `score-1.0.0` exactly.
    ///
    /// [`BasisProfile::rfp_default`] selects the RFP-aligned split. The
    /// default flips to it once the interface category can read the expanded
    /// basis (milestone M3, T10) — until then it would report `unchecked`,
    /// blanking the strongest category.
    ///
    /// Only [`score_paths`] can honor an expanded basis: expansion needs
    /// source *paths*, which a parsed AST does not carry.
    pub basis: BasisProfile,
}

impl Default for ScoreOptions {
    fn default() -> Self {
        Self {
            threshold: 0.90,
            check_compile: false,
            weights: WeightProfile::rfp_default(),
            basis: BasisProfile::source_only(),
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
    let compilation =
        CategoryScore::unchecked("compile check needs a source path (use score_paths or the CLI)");
    // No paths, so no expansion is possible: everything is source-basis.
    let sources = Sources::source_only(reconstructed.clone(), original.clone());
    assemble(&sources, compilation, opts)
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
    let sources = Sources::load(reconstructed, original, &opts.basis)?;
    let compilation = if opts.check_compile {
        compile::check(reconstructed)
    } else {
        CategoryScore::unchecked("compile check not requested")
    };
    let mut report = assemble(&sources, compilation, opts);
    for note in &sources.notes {
        report = report.with_note(note.clone());
    }
    Ok(report)
}

/// Both renderings of the two inputs, so each category can be scored on the
/// basis it belongs on.
///
/// Holding both is the point of T9: interface and structure want the
/// macro-expanded form (the RFP's basis, and the only place the ABI is
/// visible), while semantic wants the sources as written — see
/// [`BasisProfile::rfp_default`] for why.
struct Sources {
    /// The sources as written. Always available.
    source: (syn::File, syn::File),
    /// The expanded, glue-stripped sources; `None` when no category asked for
    /// them or expansion was unavailable.
    expanded: Option<(syn::File, syn::File)>,
    /// The spec-XDR entries harvested while stripping glue, in the same order
    /// as `expanded`. The contract's declared ABI, and what the interface
    /// category scores against on the expanded basis (T10) — the attributes it
    /// would otherwise key on do not survive expansion.
    spec: Option<(spec::SpecMap, spec::SpecMap)>,
    /// Run-level notes recording which basis was used, and why if it was not
    /// the one requested.
    notes: Vec<String>,
}

impl Sources {
    /// Wrap an already-parsed pair; nothing can be expanded without paths.
    fn source_only(recon: syn::File, orig: syn::File) -> Self {
        Self {
            source: (recon, orig),
            expanded: None,
            spec: None,
            notes: Vec::new(),
        }
    }

    /// Load both sides, macro-expanding as well when `profile` asks for it.
    ///
    /// Expansion is best-effort by design: a missing toolchain or an
    /// unresolvable dependency degrades to the pre-expansion basis with the
    /// reason recorded, rather than failing the run or silently scoring zero.
    /// Both sides expand or neither does — scoring an expanded reconstruction
    /// against an un-expanded original would compare two different kinds of
    /// thing.
    fn load(
        reconstructed: &Path,
        original: &Path,
        profile: &BasisProfile,
    ) -> Result<Self, ScoreError> {
        let source = (
            loader::load(reconstructed, "reconstructed")?,
            loader::load(original, "original")?,
        );
        if !profile.needs_expansion() {
            return Ok(Self {
                source,
                expanded: None,
                spec: None,
                notes: Vec::new(),
            });
        }

        match (expand::expand(reconstructed), expand::expand(original)) {
            (Ok(recon_text), Ok(orig_text)) => {
                // Expanded source is mostly SDK-generated glue; scoring it raw
                // would count macro output as failed reconstruction. The same
                // pass harvests the ABI ground truth (consumed from T10).
                let recon = glue::canonicalize(loader::load_str(&recon_text, "reconstructed")?);
                let orig = glue::canonicalize(loader::load_str(&orig_text, "original")?);
                let mut note = "basis: macro-expanded".to_owned();
                if let Some(summary) = orig.abi_summary() {
                    note.push_str(&format!(" — original {summary}"));
                }
                Ok(Self {
                    source,
                    expanded: Some((recon.file, orig.file)),
                    spec: Some((recon.spec, orig.spec)),
                    notes: vec![note],
                })
            }
            (Err(why), _) | (_, Err(why)) => Ok(Self {
                source,
                expanded: None,
                spec: None,
                notes: vec![format!(
                    "basis: pre-expansion — macro expansion unavailable ({why})"
                )],
            }),
        }
    }

    /// The pair a category should be scored against.
    ///
    /// A request for [`Basis::Expanded`] falls back to the source pair when
    /// expansion was unavailable; `Sources::load` has already recorded why.
    fn pair(&self, basis: Basis) -> (&syn::File, &syn::File) {
        let (recon, orig) = match basis {
            Basis::Expanded => self.expanded.as_ref().unwrap_or(&self.source),
            Basis::Source => &self.source,
        };
        (recon, orig)
    }

    /// The harvested spec-XDR pair, when a category is scoring on the expanded
    /// basis and expansion actually produced one.
    ///
    /// `None` on the source basis, or when expansion fell back — in both cases
    /// the caller must use its own source-level extractor, since the spec is
    /// only visible after expansion.
    fn spec_for(&self, basis: Basis) -> Option<(&spec::SpecMap, &spec::SpecMap)> {
        match basis {
            Basis::Expanded => self.spec.as_ref().map(|(recon, orig)| (recon, orig)),
            Basis::Source => None,
        }
    }
}

/// Assemble the three AST categories — each on its own basis — plus a
/// supplied compilation category into a report.
fn assemble(sources: &Sources, compilation: CategoryScore, opts: &ScoreOptions) -> ScoreReport {
    let basis = &opts.basis;
    let (recon, orig) = sources.pair(basis.interface);
    let interface = interface::evaluate(recon, orig, sources.spec_for(basis.interface));
    let (recon, orig) = sources.pair(basis.structure);
    let structure = structure::evaluate(recon, orig);
    let (recon, orig) = sources.pair(basis.semantic);
    let semantic = semantic::evaluate(recon, orig);

    let categories = Categories {
        interface,
        structure,
        semantic,
        compilation,
    };
    ScoreReport::aggregate(categories, &opts.weights, &opts.basis, opts.threshold)
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
    fn the_default_basis_is_recorded_and_needs_no_toolchain() {
        let report = score_str(SRC, SRC, &ScoreOptions::default()).expect("parse");
        assert_eq!(report.basis_profile, "source-only");
        assert!(!ScoreOptions::default().basis.needs_expansion());
    }

    #[test]
    fn the_router_consults_the_profile_per_category() {
        // Proves `assemble` actually routes rather than being incidentally
        // correct: two `Sources` differing *only* in their expanded pair,
        // scored under a profile that sends structure to `Expanded` and
        // semantic to `Source`. Structure must see the expanded pair and
        // semantic must not.
        let source_side = syn::parse_file("fn f() { panic!(); }").expect("parse");
        // The "expanded" stand-in has different control flow and no panic.
        let expanded_side = syn::parse_file("fn f() { if true { g(); } }").expect("parse");

        let sources = Sources {
            source: (source_side.clone(), source_side.clone()),
            expanded: Some((expanded_side.clone(), expanded_side)),
            spec: None,
            notes: Vec::new(),
        };
        let opts = ScoreOptions {
            basis: BasisProfile {
                name: "split".to_owned(),
                interface: Basis::Source,
                structure: Basis::Expanded,
                semantic: Basis::Source,
            },
            ..ScoreOptions::default()
        };
        let report = assemble(&sources, CategoryScore::unchecked("n/a"), &opts);

        // Semantic read the source pair, which has a panic on both sides.
        assert!(report.categories.semantic.checked, "source pair has facts");
        // Structure read the expanded pair: identical to itself, so 1.0.
        assert!((report.categories.structure.score - 1.0).abs() < 1e-9);
        assert_eq!(report.basis_profile, "split");
    }

    #[test]
    fn an_expanded_request_falls_back_to_source_when_unavailable() {
        // `Sources` with no expanded pair: a category asking for `Expanded`
        // must still score, on the source pair, rather than erroring or
        // silently reporting nothing.
        let file = syn::parse_file(SRC).expect("parse");
        let sources = Sources::source_only(file.clone(), file);
        let opts = ScoreOptions {
            basis: BasisProfile::rfp_default(),
            ..ScoreOptions::default()
        };
        let report = assemble(&sources, CategoryScore::unchecked("n/a"), &opts);
        assert!(
            (report.overall - 1.0).abs() < 1e-9,
            "identity still scores 1.0"
        );
        assert_eq!(report.basis_profile, "rfp-default");
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
