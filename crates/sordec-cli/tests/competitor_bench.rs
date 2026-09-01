//! Score an *external* decompiler's output on our corpus, with our scorer.
//!
//! The point is a like-for-like comparison. Published accuracy figures are not
//! comparable across projects: each tool defines its own categories, weights
//! and corpus, so "98.3%" and "61%" can describe very different achievements.
//! Running a competitor's output through the same ruler as ours removes that
//! objection entirely.
//!
//! Reuses [`score_paths`] exactly as `benchmark.rs` does — same options, same
//! `source/src` originals, same `rfp-default` basis. Running inside `cargo test`
//! is load-bearing: the macro-expanded basis needs `cargo expand`, which only
//! resolves in cargo's own environment (from a bare shell the scorer silently
//! falls back to pre-expansion and every number lands on a different footing).
//!
//! Point it at a directory laid out as `<dir>/<fixture>/src/lib.rs`:
//!
//! ```bash
//! SORDEC_EXT_DIR=/path/to/theirs \
//!   cargo test -p sordec-cli --test competitor_bench -- --ignored --nocapture
//! ```
//!
//! **Read the structure column with care.** Structure is a dice similarity over
//! control-flow tokens, so it penalises emitting *too much* as well as too
//! little. A tool that drops guard conditions can therefore score *better* on
//! structure than one that keeps them all — which is why this harness prints
//! precision and recall, not just the score. Recall is the honest "did it find
//! the logic" number.

use std::path::{Path, PathBuf};

use sordec_score::{score_paths, ScoreOptions};

const FIXTURES: &[&str] = &[
    "hello-add",
    "token-v22",
    "token-v23",
    "token-v23-stripped",
    "timelock",
    "dex-liquidity-pool",
    "attestation",
];

fn samples_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../samples/contracts")
}

/// Pull `precision=… recall=…` out of the structure notes, where the scorer
/// already reports them, so the caveat above is visible in the output.
fn cf_signal(notes: &[String]) -> String {
    for n in notes {
        if let Some(i) = n.find("control flow: ") {
            return n[i + "control flow: ".len()..].to_string();
        }
    }
    "—".to_string()
}

#[test]
#[ignore = "needs SORDEC_EXT_DIR pointing at an external tool's output; run explicitly"]
#[allow(clippy::print_stdout)]
fn score_external_reconstructions() {
    let ext = std::env::var("SORDEC_EXT_DIR").expect("set SORDEC_EXT_DIR=<dir of <fixture>/src/lib.rs>");
    let ext = PathBuf::from(ext);

    println!(
        "\n{:<22}{:>9}{:>9}{:>9}{:>9}  {:<12} control flow",
        "fixture", "overall", "iface", "struct", "seman", "basis"
    );

    let mut scored = Vec::new();
    for &name in FIXTURES {
        let recon = ext.join(name).join("src");
        if !recon.join("lib.rs").exists() {
            println!("{name:<22}   (no lib.rs — tool produced nothing)");
            continue;
        }
        let original = samples_dir().join(name).join("source/src");
        let opts = ScoreOptions { threshold: 0.9, check_compile: false, ..Default::default() };
        match score_paths(&recon, &original, &opts) {
            Ok(r) => {
                let c = &r.categories;
                let f = |cs: &sordec_score::CategoryScore| {
                    if cs.checked { format!("{:.4}", cs.score) } else { "n/a".to_string() }
                };
                println!(
                    "{:<22}{:>9.4}{:>9}{:>9}{:>9}  {:<12} {}",
                    name,
                    r.overall,
                    f(&c.interface),
                    f(&c.structure),
                    f(&c.semantic),
                    r.basis_profile,
                    cf_signal(&c.structure.notes)
                );
                scored.push(r.overall);
            }
            Err(e) => println!("{name:<22}   SCORE ERROR: {e}"),
        }
    }

    if !scored.is_empty() {
        let mean = scored.iter().sum::<f64>() / scored.len() as f64;
        println!("\n{:<22}{:>9.4}  (mean over {} scored)", "ALL", mean, scored.len());
    }
}
