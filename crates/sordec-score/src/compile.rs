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
//! The scratch crate itself is built by [`crate::scratch`], shared with the
//! macro-expansion harness. Its soroban-sdk-only manifest is deliberately
//! minimal: a contract that pulls extra crates (e.g. `soroban-token-sdk`)
//! reports *unavailable*, not *failed* — the harness cannot vouch for a
//! compile it could not attempt.
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

use crate::report::CategoryScore;
use crate::scratch::{self, ScratchCrate};

/// Number of leading cargo diagnostic lines to attach to a failure.
const MAX_DIAGNOSTIC_LINES: usize = 12;

/// Run the opt-in compilation check on the reconstructed source path.
pub(crate) fn check(reconstructed: &Path) -> CategoryScore {
    match run(reconstructed) {
        Ok(Outcome::Compiled) => {
            CategoryScore::checked(1.0).with_note("cargo check succeeded")
        }
        Ok(Outcome::Failed(diagnostics)) => {
            let mut score = CategoryScore::checked(0.0).with_note("cargo check failed");
            for line in diagnostics {
                score = score.with_note(line);
            }
            score
        }
        Err(reason) => {
            CategoryScore::unchecked(format!("compile check unavailable: {reason}"))
        }
    }
}

/// The result of an attempted compile.
enum Outcome {
    Compiled,
    Failed(Vec<String>),
}

/// Assemble a scratch crate and run `cargo check --offline`.
fn run(reconstructed: &Path) -> Result<Outcome, String> {
    let scratch = ScratchCrate::new(reconstructed, "sordec-compile")?;

    let output = Command::new(scratch::cargo_bin())
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
    if scratch::is_dependency_problem(&stderr) {
        return Err("offline registry is missing a required crate".to_string());
    }
    Ok(Outcome::Failed(first_diagnostics(&stderr)))
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

#[cfg(test)]
mod tests {
    use super::*;

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
        let path = scratch::unique_scratch_dir("sordec-compile-src").join(format!("{name}.rs"));
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
