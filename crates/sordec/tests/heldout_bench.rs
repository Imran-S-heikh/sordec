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
//! Scoring runs inside `cargo test` for the same reason `benchmark.rs` does:
//! the macro-expanded basis needs `cargo expand`, which only resolves in
//! cargo's environment. A decompile that fails or panics is reported, never
//! skipped, because on unseen input it is a finding in its own right.

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
                scored.push((overall, structure, semantic, holes));
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
        fmt(mean(scored.iter().map(|s| s.0))),
        fmt(mean(scored.iter().filter_map(|s| s.1))),
        scored.iter().filter(|s| s.1.is_some()).count(),
        fmt(mean(scored.iter().filter_map(|s| s.2))),
        scored.iter().filter(|s| s.2.is_some()).count(),
        scored.iter().map(|s| s.3).sum::<usize>(),
    );
}
