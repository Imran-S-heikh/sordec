//! Compilation category: does the reconstructed source `cargo check`
//! against `soroban-sdk`? The honest stand-in for "behavior" (K6).
//!
//! Opt-in (`--check-compile`) and worked from the **raw source**, not the
//! flattened/normalized AST — re-emitting the AST would drop `#![no_std]`,
//! `use`s, and the module tree, none of which round-trip, so a real
//! compile must see the files as written. The harness copies the source
//! into a scratch crate that depends on `soroban-sdk` and runs
//! `cargo check --offline`.
//!
//! Three outcomes, mapped so an unrun or unrunnable check never poses as a
//! failure:
//! - **compiled** → checked, score `1.0`.
//! - **failed** (cargo ran, the source did not type-check) → checked,
//!   score `0.0`, with the first diagnostics attached.
//! - **unavailable** (no cargo, or the offline registry lacks the SDK / a
//!   contract-specific dependency) → *unchecked*, excluded from the mean.
//!
//! The soroban-sdk-only scratch manifest is deliberately minimal: a
//! contract that pulls extra crates (e.g. `soroban-token-sdk`) reports
//! *unavailable*, not *failed* — the harness cannot vouch for a compile it
//! could not attempt.
//!
//! ## Deferred to Phase 4
//!
//! - **Differential execution.** Recompilation proves the reconstruction is
//!   well-formed Soroban code, not that it *behaves* like the original.
//!   Executing both against the same inputs and comparing results is the
//!   true behavioral check — a Phase-4 extension once the Rust emitter exists.
//! - **Baseline-to-beat.** The prior-generation decompiler's Rust output is
//!   the intended baseline; regenerating it needs that older codebase's
//!   toolchain restored (a transitive dependency no longer compiles under the
//!   current Rust release). Recorded in `docs/scoring_metric.md` §7.

use std::path::Path;
use std::process::Command;

use crate::metrics;
use crate::report::CategoryScore;

/// The soroban-sdk version requirement the scratch crate depends on. A
/// caret requirement so `cargo` resolves to whatever compatible version is
/// cached offline.
const SOROBAN_SDK_VERSION: &str = "23";

/// Number of leading cargo diagnostic lines to attach to a failure.
const MAX_DIAGNOSTIC_LINES: usize = 12;

/// Run the opt-in compilation check on the reconstructed source path.
pub(crate) fn check(reconstructed: &Path) -> CategoryScore {
    let weight = metrics::COMPILATION_WEIGHT;
    match run(reconstructed) {
        Ok(Outcome::Compiled) => {
            CategoryScore::checked(1.0, weight).with_note("cargo check succeeded")
        }
        Ok(Outcome::Failed(diagnostics)) => {
            let mut score =
                CategoryScore::checked(0.0, weight).with_note("cargo check failed");
            for line in diagnostics {
                score = score.with_note(line);
            }
            score
        }
        Err(reason) => CategoryScore::unchecked(weight, format!("compile check unavailable: {reason}")),
    }
}

/// The result of an attempted compile.
enum Outcome {
    Compiled,
    Failed(Vec<String>),
}

/// Assemble a scratch crate and run `cargo check --offline`.
fn run(reconstructed: &Path) -> Result<Outcome, String> {
    let scratch = ScratchCrate::new(reconstructed)?;

    let output = Command::new(cargo_bin())
        .args(["check", "--offline", "--quiet", "--manifest-path"])
        .arg(scratch.manifest())
        .output()
        .map_err(|e| format!("could not launch cargo: {e}"))?;

    if output.status.success() {
        return Ok(Outcome::Compiled);
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    // Distinguish a real type-check failure from an environment problem
    // (offline registry can't provide the SDK or a contract-specific dep).
    if is_dependency_problem(&stderr) {
        return Err("offline registry is missing a required crate".to_string());
    }
    Ok(Outcome::Failed(first_diagnostics(&stderr)))
}

/// Whether cargo's failure is an environment/dependency problem rather than
/// a source type-check error.
fn is_dependency_problem(stderr: &str) -> bool {
    const MARKERS: [&str; 5] = [
        "failed to select a version",
        "no matching package",
        "unable to get packages from source",
        "failed to get `",
        "not found in the registry",
    ];
    MARKERS.iter().any(|marker| stderr.contains(marker))
}

/// The leading diagnostic lines (`error[..]` / `error:` / `warning:` and
/// their location arrows), capped.
fn first_diagnostics(stderr: &str) -> Vec<String> {
    stderr
        .lines()
        .filter(|line| {
            let t = line.trim_start();
            t.starts_with("error") || t.starts_with("warning:") || t.starts_with("-->")
        })
        .take(MAX_DIAGNOSTIC_LINES)
        .map(|line| line.trim().to_string())
        .collect()
}

/// A temporary cargo crate holding a copy of the reconstructed source. The
/// directory is removed on drop.
struct ScratchCrate {
    dir: std::path::PathBuf,
}

impl ScratchCrate {
    fn new(source: &Path) -> Result<Self, String> {
        let dir = unique_scratch_dir();
        let src_dir = dir.join("src");
        std::fs::create_dir_all(&src_dir).map_err(|e| format!("scratch dir: {e}"))?;

        copy_source(source, &src_dir)?;
        std::fs::write(dir.join("Cargo.toml"), manifest_toml())
            .map_err(|e| format!("write manifest: {e}"))?;

        Ok(Self { dir })
    }

    fn manifest(&self) -> std::path::PathBuf {
        self.dir.join("Cargo.toml")
    }
}

impl Drop for ScratchCrate {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Copy the reconstructed source into the scratch crate's `src/`. A single
/// file becomes `src/lib.rs`; a directory tree is copied verbatim so
/// `mod foo;` declarations resolve.
fn copy_source(source: &Path, dst_src: &Path) -> Result<(), String> {
    if source.is_dir() {
        copy_dir(source, dst_src)
    } else {
        std::fs::copy(source, dst_src.join("lib.rs"))
            .map(|_| ())
            .map_err(|e| format!("copy source: {e}"))
    }
}

/// Recursively copy `.rs` files under `from` into `to`.
fn copy_dir(from: &Path, to: &Path) -> Result<(), String> {
    for entry in std::fs::read_dir(from).map_err(|e| format!("read {}: {e}", from.display()))? {
        let entry = entry.map_err(|e| format!("read dir entry: {e}"))?;
        let path = entry.path();
        let target = to.join(entry.file_name());
        if path.is_dir() {
            std::fs::create_dir_all(&target).map_err(|e| format!("mkdir: {e}"))?;
            copy_dir(&path, &target)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            std::fs::copy(&path, &target).map_err(|e| format!("copy: {e}"))?;
        }
    }
    Ok(())
}

/// The scratch crate's `Cargo.toml`: a `cdylib` depending on `soroban-sdk`,
/// opted out of any parent workspace.
fn manifest_toml() -> String {
    format!(
        "[package]\n\
         name = \"sordec-compile-check\"\n\
         version = \"0.0.0\"\n\
         edition = \"2021\"\n\
         \n\
         [lib]\n\
         crate-type = [\"cdylib\"]\n\
         \n\
         [dependencies]\n\
         soroban-sdk = \"{SOROBAN_SDK_VERSION}\"\n\
         \n\
         [workspace]\n"
    )
}

fn unique_scratch_dir() -> std::path::PathBuf {
    // pid + clock + a process-wide counter. The counter is load-bearing:
    // macOS clock resolution is coarse, so two scratch dirs created in
    // quick succession (parallel scoring, or the parallel `#[ignore]`
    // tests) would otherwise collide and delete each other's build mid-check.
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "sordec-compile-{}-{nanos}-{seq}",
        std::process::id()
    ))
}

/// The cargo binary to invoke, honoring `$CARGO` when the harness is run
/// from within a cargo process (as tests are).
fn cargo_bin() -> String {
    std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dependency_problems_are_not_source_failures() {
        assert!(is_dependency_problem(
            "error: failed to select a version for `soroban-sdk`"
        ));
        assert!(is_dependency_problem(
            "error: no matching package named `soroban-token-sdk` found"
        ));
        // A genuine type error is a source failure, not an env problem.
        assert!(!is_dependency_problem("error[E0308]: mismatched types"));
    }

    #[test]
    fn first_diagnostics_keeps_only_diagnostic_lines() {
        let stderr = "\
   Compiling foo v0.0.0
error[E0425]: cannot find value `x`
  --> src/lib.rs:3:5
   |
   = note: some note
warning: unused import";
        let diags = first_diagnostics(stderr);
        assert_eq!(diags[0], "error[E0425]: cannot find value `x`");
        assert!(diags.iter().any(|l| l.starts_with("-->")));
        assert!(diags.iter().any(|l| l.starts_with("warning:")));
        assert!(!diags.iter().any(|l| l.contains("Compiling")));
    }

    #[test]
    fn manifest_declares_soroban_sdk_and_opts_out_of_workspace() {
        let toml = manifest_toml();
        assert!(toml.contains("soroban-sdk = \"23\""));
        assert!(toml.contains("crate-type = [\"cdylib\"]"));
        assert!(toml.contains("[workspace]"));
    }

    // The remaining tests shell out to `cargo check` against the cached
    // `soroban-sdk`; they are slow and toolchain-dependent, so they are
    // `#[ignore]`d out of the fast suite. Run with:
    //   cargo test -p sordec-score -- --ignored
    const MINIMAL_CONTRACT: &str = r#"
        #![no_std]
        use soroban_sdk::{contract, contractimpl, Env};
        #[contract]
        pub struct C;
        #[contractimpl]
        impl C {
            pub fn add(_e: Env, a: u32, b: u32) -> u32 { a + b }
        }
    "#;

    fn temp_source(name: &str, body: &str) -> std::path::PathBuf {
        let path = unique_scratch_dir().join(format!("{name}.rs"));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, body).unwrap();
        path
    }

    #[test]
    #[ignore = "shells out to cargo check against soroban-sdk (slow)"]
    fn a_valid_contract_compiles() {
        let src = temp_source("ok", MINIMAL_CONTRACT);
        let score = check(&src);
        assert!(score.checked, "expected a checked result: {:?}", score.notes);
        assert!(
            (score.score - 1.0).abs() < 1e-9,
            "score={} notes={:#?}",
            score.score,
            score.notes
        );
        let _ = std::fs::remove_dir_all(src.parent().unwrap());
    }

    #[test]
    #[ignore = "shells out to cargo check against soroban-sdk (slow)"]
    fn a_broken_contract_fails() {
        let broken = format!("{MINIMAL_CONTRACT}\nfn bad() -> u32 {{ \"not a u32\" }}\n");
        let src = temp_source("bad", &broken);
        let score = check(&src);
        assert!(score.checked, "expected a checked result: {:?}", score.notes);
        assert_eq!(score.score, 0.0);
        let _ = std::fs::remove_dir_all(src.parent().unwrap());
    }
}
