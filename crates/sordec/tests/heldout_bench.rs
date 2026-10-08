//! Score the decompiler on contracts it was never tuned on.
//!
//! The corpus in `samples/contracts` is what every recognizer was built
//! against, so a gain there can be a recognizer fitted to five contracts. This
//! harness measures the same way on a directory of contracts nobody tuned for —
//! by default Stellar's `soroban-examples`, built by
//! `tools/build_heldout.sh` — and reports the same categories, so a change can
//! be judged on both sets: one that helps the corpus and nothing here is a
//! warning sign.
//!
//! Layout: `<dir>/<name>/<name>.wasm` and `<dir>/<name>/source/{Cargo.toml,src}`.
//!
//! ```bash
//! SORDEC_HELDOUT_DIR=/path/to/heldout \
//!   cargo test -p sordec --test heldout_bench -- --ignored --nocapture
//! ```
//!
//! Build the set with `tools/build_heldout.sh`. Keep it outside any
//! temporary directory — it costs a clone and 25 wasm builds to recreate,
//! and the canonical spot is `~/.cache/sordec-heldout`:
//!
//! ```bash
//! git clone --depth 1 https://github.com/stellar/soroban-examples ~/.cache/soroban-examples
//! tools/build_heldout.sh ~/.cache/soroban-examples ~/.cache/sordec-heldout
//! ```
//!
//! Scoring runs inside `cargo test` for the same reason `benchmark.rs` does:
//! the macro-expanded basis needs `cargo expand`, which only resolves in
//! cargo's environment. A decompile that fails or panics is reported, never
//! skipped, because on unseen input it is a finding in its own right.
//!
//! ## This is a guard, not only a report
//!
//! It used to print and assert nothing, which made it a number someone had to
//! remember to read. Twice that was not enough: a change landed with the
//! corpus green at 0.9359 while `auth`, `custom_types` and `events` each fell
//! from 1.0000 to 0.7059 here, and the mean moved only 0.028. Both were found
//! late and one was written up with the wrong cause. So the measured values
//! are committed, in [`heldout_floor`] and [`HELDOUT_AGGREGATE`], and a drop
//! fails.
//!
//! **The per-contract bounds are one-sided on purpose**, which is a deliberate
//! departure from `benchmark.rs`'s two-sided `overall_band`. The corpus is
//! seven *tuned* fixtures where any movement is meaningful. These twenty-five
//! are untuned, and improvement lands on them unevenly by design — that is
//! what the set is for — so a two-sided bound would fail on every genuine gain,
//! twenty-five times over, which is how a guard teaches people to skip it.
//!
//! [`HELDOUT_AGGREGATE`] is the two-sided half, and it covers what
//! two-sidedness is actually for on the corpus: a machine that cannot run
//! `cargo expand` degrades every category to the source basis, which moves
//! every contract at once and breaches the mean loudly rather than quietly
//! reporting a different metric.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};

use sordec_score::{score_paths, ScoreOptions};

/// One contract's outcome.
enum Outcome {
    Scored { overall: f64, interface: f64, structure: Option<f64>, semantic: Option<f64>, cf: String, holes: usize },
    Failed(String),
}

fn cf_signal(notes: &[String]) -> String {
    notes
        .iter()
        .find_map(|n| n.find("control flow: ").map(|i| n[i + "control flow: ".len()..].to_string()))
        .map_or_else(|| "—".to_string(), |s| s.split(" — ").next().unwrap_or("").to_string())
}

fn measure(dir: &Path, name: &str) -> Outcome {
    let wasm_path = dir.join(format!("{name}.wasm"));
    let Ok(wasm) = std::fs::read(&wasm_path) else {
        return Outcome::Failed("no wasm".to_string());
    };
    let output = match catch_unwind(AssertUnwindSafe(|| sordec_driver::Driver::standard().run(&wasm))) {
        Ok(Ok(output)) => output,
        Ok(Err(e)) => return Outcome::Failed(format!("decompile: {e}")),
        Err(_) => return Outcome::Failed("decompile panicked".to_string()),
    };
    let tmp = std::env::temp_dir().join(format!("sordec-heldout-{name}-{}", std::process::id()));
    let src = tmp.join("src");
    if std::fs::create_dir_all(&src).is_err()
        || std::fs::write(src.join("lib.rs"), &output.rust).is_err()
        || std::fs::write(tmp.join("Cargo.toml"), &output.cargo_toml).is_err()
    {
        return Outcome::Failed("scratch write".to_string());
    }
    let opts = ScoreOptions { threshold: 0.9, check_compile: false, ..Default::default() };
    let report = score_paths(&src, &dir.join("source/src"), &opts);
    let _ = std::fs::remove_dir_all(&tmp);
    match report {
        Ok(r) => {
            let c = &r.categories;
            Outcome::Scored {
                overall: r.overall,
                interface: c.interface.score,
                structure: c.structure.checked.then_some(c.structure.score),
                semantic: c.semantic.checked.then_some(c.semantic.score),
                cf: cf_signal(&c.structure.notes),
                holes: output.rust.matches("todo!(").count(),
            }
        }
        Err(e) => Outcome::Failed(format!("score: {e}")),
    }
}

fn fmt(v: Option<f64>) -> String {
    v.map_or_else(|| "—".to_string(), |x| format!("{x:.4}"))
}

fn mean(values: impl Iterator<Item = f64>) -> Option<f64> {
    let v: Vec<f64> = values.collect();
    (!v.is_empty()).then(|| v.iter().sum::<f64>() / v.len() as f64)
}

/// The lowest overall score a contract may report.
///
/// Measured at the commit that introduced this guard, less ~0.02 — the same
/// derivation `benchmark.rs`'s `overall_band` entries use. One-sided: see the
/// module docs for why a gain must not fail.
///
/// An unlisted contract floors at `0.0`, so adding one to the corpus reports
/// it without failing until someone commits its number — mirroring
/// `overall_band`'s `_ => (0.00, 1.00)` wildcard.
fn heldout_floor(name: &str) -> f64 {
    match name {
        "account" => 0.54,
        "alloc" => 0.54,
        "atomic_swap" => 0.98,
        "auth" => 0.98,
        // Lowered 2026-10-03 (0.7390 -> 0.6873) for a correct fold. The
        // outlined `BytesN<96>` conversion of the owners read became the
        // typed read the source wrote, taking three conversion checks with
        // it; one had been lining up with the source's `if !pairing_check`
        // by position. What is left unmatched is `if ok { Ok(()) } else
        // { Err(e) }` against the source's guard-clause spelling of the same
        // returned select — which attestation spells our way, so the binary
        // cannot choose between them.
        "bls_signature" => 0.67,
        "custom_types" => 0.98,
        "deep_contract_auth" => 0.59,
        "errors" => 0.86,
        "eth_abi" => 0.52,
        "events" => 0.98,
        "fuzzing" => 0.51, // 0.5350: Option helpers returned as `Option<T>`
        "hello_world" => 0.98,
        "import_ark_bn254" => 0.33,
        "increment" => 0.68,
        // 0.7059, as `increment` (the same source): no branch left, and the
        // one the yardstick counts is `log!`'s `if cfg!(debug_assertions)`,
        // which a release wasm does not contain. 0.8655 before, when a
        // spurious overflow guard and `if let` paired with it.
        "increment_with_fuzz" => 0.68,
        "increment_with_pause" => 0.80,
        "logging" => 0.86,
        "merkle_distribution" => 0.50,
        "mint-lock" => 0.48,
        "modular_account" => 0.40,
        "other_custom_types" => 0.70,
        "pause" => 0.98,
        "simple_account" => 0.94,
        "single_offer" => 0.77,
        "ttl" => 0.98,
        _ => 0.0,
    }
}

/// Two-sided band on the mean overall score, `(low, high)`.
///
/// The upper bound is not pedantry: it is the detector for a run that measured
/// something other than what it says it measured. See the module docs.
const HELDOUT_AGGREGATE: (f64, f64) = (0.73, 0.78);

#[test]
#[ignore = "needs SORDEC_HELDOUT_DIR pointing at a built held-out corpus; run explicitly"]
#[allow(clippy::print_stdout)]
fn score_heldout_corpus() {
    let root = PathBuf::from(std::env::var("SORDEC_HELDOUT_DIR").expect("set SORDEC_HELDOUT_DIR"));
    let mut names: Vec<String> = std::fs::read_dir(&root)
        .expect("read held-out dir")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();

    println!(
        "\n{:<22}{:>9}{:>9}{:>9}{:>9}{:>7}  control flow",
        "contract", "overall", "iface", "struct", "seman", "holes"
    );
    let mut scored = Vec::new();
    let mut failed = 0;
    for name in &names {
        match measure(&root.join(name), name) {
            Outcome::Scored { overall, interface, structure, semantic, cf, holes } => {
                println!(
                    "{name:<22}{overall:>9.4}{interface:>9.4}{:>9}{:>9}{holes:>7}  {cf}",
                    fmt(structure),
                    fmt(semantic)
                );
                scored.push((name.clone(), overall, structure, semantic, holes));
            }
            Outcome::Failed(why) => {
                failed += 1;
                println!("{name:<22}  FAILED: {why}");
            }
        }
    }
    println!(
        "\n{} scored, {failed} failed — mean overall {}, structure {} (over {} measured), semantic {} (over {}), holes {}",
        scored.len(),
        fmt(mean(scored.iter().map(|s| s.1))),
        fmt(mean(scored.iter().filter_map(|s| s.2))),
        scored.iter().filter(|s| s.2.is_some()).count(),
        fmt(mean(scored.iter().filter_map(|s| s.3))),
        scored.iter().filter(|s| s.3.is_some()).count(),
        scored.iter().map(|s| s.4).sum::<usize>(),
    );

    // Asserted after the table, so a failing run still prints every number
    // someone needs to decide whether the change was intended.
    for (name, overall, ..) in &scored {
        let floor = heldout_floor(name);
        assert!(
            *overall >= floor,
            "{name}: overall {overall:.4} below floor {floor:.2} — if this is an \
             intended change, update heldout_floor() with the new measurement"
        );
    }

    let overall_mean = mean(scored.iter().map(|s| s.1)).expect("the corpus is not empty");
    let (lo, hi) = HELDOUT_AGGREGATE;
    assert!(
        (lo..=hi).contains(&overall_mean),
        "mean overall {overall_mean:.4} outside band {lo:.2}..={hi:.2} — a breach of the \
         upper bound usually means the run measured something else (no `cargo expand`, \
         so every category fell back to the source basis); if the gain is real, update \
         HELDOUT_AGGREGATE"
    );

    assert_eq!(
        failed, 0,
        "{failed} contract(s) failed to decompile or score; on unseen input that is a \
         finding in its own right, not an environment problem — see the table above"
    );
}
