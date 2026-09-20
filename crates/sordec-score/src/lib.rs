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
//! - **behavior** — differential execution of the original wasm against the
//!   recompiled reconstruction. Produced by `sordec-diffexec` and injected; see
//!   [`behavior`] for why, and for the rule that keeps a calibration run out of the
//!   mean.
//!
//! Alongside those sits the [`CompilationGate`]: does the reconstruction build
//! at all? A pass/fail **precondition**, not a fifth category. It earns no share
//! of the mean but it can veto the verdict — you do not get a grade for an exam
//! you did not sit. It is not scored because a binary flag has no spectrum to
//! score, because behavior already presupposes it, and because `todo!()`
//! compiles: a scored compilation category paid weight for recovering nothing.
//!
//! See [`score_files`] for the entry point and [`ScoreReport`] for the
//! output. The metric is frozen + versioned: see [`SCORER_VERSION`].

pub mod behavior;
mod canon;
mod closure;
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

pub use behavior::{BSide, Behavior, BehaviorInput, TupleScore};
pub use config::{Basis, BasisProfile, WeightProfile};
pub use error::ScoreError;
pub use report::{Categories, CategoryScore, CompilationGate, SCORER_VERSION, ScoreReport};

/// Knobs for a scoring run.
#[derive(Debug, Clone)]
pub struct ScoreOptions {
    /// Pass threshold for the overall score. Default `0.90` (the D4.1
    /// contractual bar).
    pub threshold: f64,
    /// Whether to evaluate the opt-in compilation *gate* (`cargo check`
    /// against `soroban-sdk`). Off by default so the fast path — and the
    /// default test suite — stays toolchain-free.
    ///
    /// When off the gate is `Unchecked` and cannot veto the verdict. When on, a
    /// failed compile makes the run fail whatever the score.
    pub check_compile: bool,
    /// Per-category weights for the overall mean. Defaults to
    /// [`WeightProfile::rfp_default`] (the frozen score-1.0.0 weights).
    pub weights: WeightProfile,
    /// Which source basis each AST category is scored against. Defaults to
    /// [`BasisProfile::rfp_default`] — the basis the RFP mandates: interface
    /// and structure on macro-expanded sources, semantic on the sources as
    /// written.
    ///
    /// This needs a toolchain. When expansion is unavailable every category
    /// falls back to [`BasisProfile::source_only`] with the reason recorded in
    /// [`ScoreReport::notes`]; the scores that produces are materially
    /// different, so a run that silently fell back is meant to be caught by the
    /// corpus accuracy bands rather than accepted.
    ///
    /// Only [`score_paths`] can honor an expanded basis: expansion needs
    /// source *paths*, which a parsed AST does not carry. [`score_files`] and
    /// [`score_str`] are therefore always source-basis — which is why the
    /// frozen calibration vector is unaffected by this default.
    pub basis: BasisProfile,
    /// The differential-execution result for the `behavior` category.
    ///
    /// Injected rather than computed: behavior needs to run two wasm modules in a
    /// Soroban host, and this crate deliberately never touches wasm — the instrument
    /// stays independent of the pipeline it grades. `sordec-diffexec` produces the
    /// result and the CLI hands it over.
    ///
    /// Defaults to [`BehaviorInput::NotRequested`], which reports the category
    /// `unchecked` so it renormalises out of the mean rather than scoring zero.
    pub behavior: BehaviorInput,
    /// Whether the binary under test declared its own ABI — a
    /// `contractspecv0` section.
    ///
    /// Injected for the same reason as [`Self::behavior`]: it is a fact
    /// about the wasm, and this crate never touches wasm. The caller
    /// that read the module knows, and the default assumes it did, so
    /// nothing changes unless a caller says otherwise.
    ///
    /// It matters because `contractspecv0` is the only place a
    /// parameter's *name* is recorded. A build that strips it leaves
    /// names nowhere in the module, so a reconstruction cannot recover
    /// them however good it is — and comparing them would mark it down
    /// for the build's settings. Set `false` and the interface
    /// comparison reads parameter types alone, which is what
    /// the interface extractor documents as the reliable identity and
    /// what its source-basis half has always done.
    pub abi_declared: bool,
}

impl Default for ScoreOptions {
    fn default() -> Self {
        Self {
            threshold: 0.90,
            check_compile: false,
            weights: WeightProfile::rfp_default(),
            basis: BasisProfile::rfp_default(),
            behavior: BehaviorInput::NotRequested,
            abi_declared: true,
        }
    }
}

/// Score a reconstructed source file against the original, both already
/// parsed. The compilation gate is reported *unchecked* here: it needs the
/// reconstructed source *path* (see [`score_paths`]), which a parsed AST does
/// not carry.
#[must_use]
pub fn score_files(
    reconstructed: &syn::File,
    original: &syn::File,
    opts: &ScoreOptions,
) -> ScoreReport {
    let gate = CompilationGate::Unchecked {
        reason: "compile check needs a source path (use score_paths or the CLI)".to_owned(),
    };
    // No paths, so no expansion is possible: everything is source-basis.
    let sources = Sources::source_only(reconstructed.clone(), original.clone());
    assemble(&sources, gate, opts)
}

/// Score two scoring inputs given by path. Each path may be a single
/// `.rs` file or a source directory (flattened by the loader). The CLI
/// entry point; the only path that can evaluate the compilation gate.
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
    let gate = if opts.check_compile {
        compile::check(reconstructed)
    } else {
        CompilationGate::Unchecked {
            reason: "compile check not requested".to_owned(),
        }
    };
    let mut report = assemble(&sources, gate, opts);
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

/// Assemble the three AST categories — each on its own basis — plus the
/// supplied compilation gate into a report.
///
/// The gate is passed in rather than computed here for the same reason
/// compilation always was: only [`score_paths`] can reach a toolchain. Behavior
/// comes from [`ScoreOptions::behavior`] for a stronger reason — it needs a Soroban
/// host, and this crate does not touch wasm. When it could not be measured, or was
/// measured against something other than our own reconstruction, the category is an
/// honest hole rather than a zero and stays out of the weighted mean entirely.
fn assemble(sources: &Sources, gate: CompilationGate, opts: &ScoreOptions) -> ScoreReport {
    let basis = &opts.basis;
    let (recon, orig) = sources.pair(basis.interface);
    let interface =
        interface::evaluate(recon, orig, sources.spec_for(basis.interface), opts.abi_declared);
    let (recon, orig) = sources.pair(basis.structure);
    let structure = structure::evaluate(recon, orig, sources.spec_for(basis.structure));
    let (recon, orig) = sources.pair(basis.semantic);
    let semantic = semantic::evaluate(recon, orig, opts.abi_declared);

    // Injected, not computed: behavior needs a Soroban host, and this crate does not
    // touch wasm. `category()` is also where the self-scoring guard lives — a
    // calibration result is reported in full and excluded from the mean.
    let behavior = opts.behavior.category();

    let categories = Categories {
        interface,
        structure,
        semantic,
        behavior,
    };
    ScoreReport::aggregate(
        categories,
        gate,
        opts.behavior.measured().cloned(),
        &opts.weights,
        &opts.basis,
        opts.threshold,
    )
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

    /// An unevaluated compilation gate, for tests routing on basis rather than
    /// on the gate. `Unchecked` never vetoes, so the verdict stays a pure
    /// function of the score.
    fn unchecked_gate() -> CompilationGate {
        CompilationGate::Unchecked {
            reason: "not evaluated in this test".to_owned(),
        }
    }

    /// A minimal but *real* contract. It has to declare an ABI: since T13c
    /// the structure category is anchored on entrypoints, so a bare `pub fn`
    /// with no `#[contractimpl]` correctly reports "nothing to measure"
    /// rather than scoring — which would make these routing tests pass
    /// vacuously.
    const SRC: &str = r#"
        #![no_std]
        use soroban_sdk::{contract, contractimpl, Env};

        #[contract]
        pub struct C;

        #[contractimpl]
        impl C {
            pub fn add(e: Env, a: u32, b: u32) -> u32 {
                if a > b { a - b } else { b - a }
            }
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

    /// A calibration result cannot raise the overall score, end to end.
    ///
    /// The behavior harness can compare a contract against itself, against its own
    /// recompiled source, or against a deliberately mutated copy. All are useful and
    /// none is a measurement of our decompiler, so none may reach `overall` — letting
    /// one through would be self-scoring, the line T17 and T18 both held.
    ///
    /// Asserted as *equality with the not-requested run*, which is stronger than
    /// checking a flag: a perfect 1.0 from the wrong B-side must move the number by
    /// exactly nothing.
    #[test]
    fn a_calibration_b_side_cannot_move_the_overall_score() {
        let baseline = score_str(SRC, SRC, &ScoreOptions::default()).expect("parse");

        for b_side in [
            BSide::ShippedWasm,
            BSide::OriginalSourceRecompiled,
            BSide::Calibration {
                class: "overflow".to_owned(),
            },
        ] {
            let opts = ScoreOptions {
                behavior: BehaviorInput::Measured(Behavior::new(1.0, b_side.clone(), 9, 9)),
                ..ScoreOptions::default()
            };
            let report = score_str(SRC, SRC, &opts).expect("parse");

            assert!(
                !report.categories.behavior.checked,
                "{} must not be a checked category",
                b_side.label()
            );
            assert!(
                (report.overall - baseline.overall).abs() < 1e-12,
                "{} moved overall {} -> {}",
                b_side.label(),
                baseline.overall,
                report.overall
            );
            // Excluded, but not hidden: the number is still in the report.
            let reported = report.behavior.as_ref().expect("the result is still reported");
            assert!((reported.score - 1.0).abs() < f64::EPSILON);
            assert_eq!(reported.b_side, b_side);
        }
    }

    /// Our own reconstruction *does* score, so the guard above is not vacuous.
    #[test]
    fn our_reconstruction_b_side_does_move_the_overall_score() {
        let baseline = score_str(SRC, SRC, &ScoreOptions::default()).expect("parse");
        let opts = ScoreOptions {
            behavior: BehaviorInput::Measured(Behavior::new(0.5, BSide::Reconstruction, 4, 9)),
            ..ScoreOptions::default()
        };
        let report = score_str(SRC, SRC, &opts).expect("parse");

        assert!(report.categories.behavior.checked);
        assert!(
            report.overall < baseline.overall,
            "a 0.5 behavior score against a perfect baseline must lower the mean: \
             {} -> {}",
            baseline.overall,
            report.overall
        );
        // And the rate never renders without its denominator.
        assert!(
            report
                .categories
                .behavior
                .notes
                .iter()
                .any(|n| n.contains("4 of 9 entrypoints")),
            "{:?}",
            report.categories.behavior.notes
        );
    }

    /// An unavailable harness renormalises out rather than scoring zero (T21).
    #[test]
    fn an_unavailable_behavior_leaves_the_score_untouched() {
        let baseline = score_str(SRC, SRC, &ScoreOptions::default()).expect("parse");
        let opts = ScoreOptions {
            behavior: BehaviorInput::Unavailable {
                reason: "rustc 1.89 is not installed".to_owned(),
            },
            ..ScoreOptions::default()
        };
        let report = score_str(SRC, SRC, &opts).expect("parse");

        assert!(!report.categories.behavior.checked);
        assert!((report.overall - baseline.overall).abs() < 1e-12);
        assert!(report.behavior.is_none(), "nothing was measured");
        assert!(
            report
                .categories
                .behavior
                .notes
                .iter()
                .any(|n| n.contains("rustc 1.89 is not installed")),
            "the reason must reach the report: {:?}",
            report.categories.behavior.notes
        );
    }

    #[test]
    fn default_options_use_rfp_weights() {
        let report = score_str(SRC, SRC, &ScoreOptions::default()).expect("parse");
        assert_eq!(report.categories.interface.weight, 0.30);
        assert_eq!(report.categories.structure.weight, 0.25);
        assert_eq!(report.categories.semantic.weight, 0.30);
        assert_eq!(report.categories.behavior.weight, 0.15);
    }

    #[test]
    fn the_default_basis_is_the_rfp_basis() {
        // M3 close-out: the default is the basis the RFP mandates, so a plain
        // `sordec score` reports the contractual number rather than an
        // approximation of it.
        assert_eq!(
            ScoreOptions::default().basis,
            BasisProfile::rfp_default(),
            "the default must be the RFP basis"
        );
        assert!(
            ScoreOptions::default().basis.needs_expansion(),
            "which means the default path needs a toolchain"
        );
    }

    #[test]
    fn source_only_stays_toolchain_free() {
        // Still worth pinning even though it is no longer the default: this is
        // the profile every category falls back to when expansion is
        // unavailable, so it must never itself want a toolchain.
        assert!(!BasisProfile::source_only().needs_expansion());
    }

    #[test]
    fn ast_entry_points_are_always_source_basis() {
        // `score_str` carries no paths, so nothing can be expanded regardless
        // of the profile. This is *why* the frozen calibration vector does not
        // move when the default basis changes — the evidence for not bumping
        // SCORER_VERSION at M3 close-out.
        let report = score_str(SRC, SRC, &ScoreOptions::default()).expect("parse");
        assert_eq!(
            report.basis_profile, "rfp-default",
            "the profile is recorded"
        );
        assert!(
            (report.overall - 1.0).abs() < 1e-9,
            "and identity still scores 1.0 on the source pair it actually used"
        );
    }

    #[test]
    fn the_router_consults_the_profile_per_category() {
        // Proves `assemble` actually routes rather than being incidentally
        // correct: two `Sources` differing *only* in their expanded pair,
        // scored under a profile that sends structure to `Expanded` and
        // semantic to `Source`. Structure must see the expanded pair and
        // semantic must not.
        // Both stand-ins declare an ABI, so structure has entrypoints to
        // anchor on (T13c) and this test cannot pass vacuously.
        // The source side performs an authorization, which is a fact the
        // comparison counts. It needs to be one that survives: an
        // authored `panic!(\"…\")` no longer yields a fact at all, since
        // its message is the whole of what distinguishes it and the
        // compiler deletes that — which would leave semantic unchecked
        // and make this routing assertion vacuous.
        let source_side = syn::parse_file(
            "#[contract] pub struct C;
             #[contractimpl] impl C { pub fn f(a: Address) { a.require_auth(); } }",
        )
        .expect("parse");
        // The "expanded" stand-in has different control flow and no facts.
        let expanded_side = syn::parse_file(
            "#[contract] pub struct C;
             #[contractimpl] impl C { pub fn f() { if true { g(); } } }",
        )
        .expect("parse");

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
        let report = assemble(&sources, unchecked_gate(), &opts);

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
        let report = assemble(&sources, unchecked_gate(), &opts);
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
            behavior: 0.10,
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
