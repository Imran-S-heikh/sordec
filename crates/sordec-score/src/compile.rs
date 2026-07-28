//! Compilation **gate**: does the reconstructed source `cargo check`
//! against `soroban-sdk`?
//!
//! A gate, not a scored category (T19). Compilation is the precondition every
//! other measurement rests on — if the source does not build, behavior cannot
//! be observed at all. Grading it would be meaningless (one type error and three
//! hundred both fail) and would double-count, and since `todo!()` compiles, a
//! *scored* compilation category paid weight for recovering nothing. So this
//! module answers pass/fail and hands the diagnostics along; the score it used
//! to hold now belongs to `behavior`.
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
//! - **compiled** → [`CompilationGate::Passed`].
//! - **failed** (cargo ran, the source did not type-check) →
//!   [`CompilationGate::Failed`], carrying the first diagnostics. Those are the
//!   sharpest emitter-progress signal we have, so they are reported even though
//!   they are no longer scored.
//! - **unavailable** (no cargo, or the offline registry lacks the SDK / a
//!   contract-specific dependency) → [`CompilationGate::Unchecked`], which does
//!   *not* veto the verdict.
//!
//! The scratch crate itself is built by [`crate::scratch`], shared with the
//! macro-expansion harness. Its soroban-sdk-only manifest is deliberately
//! minimal: a contract that pulls extra crates (e.g. `soroban-token-sdk`)
//! reports *unavailable*, not *failed* — the harness cannot vouch for a
//! compile it could not attempt.
//!
//! ## The behavior category this gate used to stand in for
//!
//! - **Differential execution** is the real behavioral check: run the original
//!   wasm and the recompiled reconstruction against the same inputs and compare.
//!   Built in `sordec-diffexec` and injected via `ScoreOptions::behavior` (T20);
//!   see [`crate::behavior`] for why it is injected rather than computed here.
//!   Recompilation only ever proved the reconstruction was well-formed Soroban
//!   code, never that it did the same thing.
//! - **Baseline-to-beat.** The prior-generation decompiler's Rust output is
//!   the intended baseline; regenerating it needs that older codebase's
//!   toolchain restored (a transitive dependency no longer compiles under the
//!   current Rust release). Recorded in `docs/scoring_metric.md` §7.

use std::path::Path;
use std::process::Command;

use crate::report::CompilationGate;
use crate::scratch::{self, ScratchCrate};

/// Number of leading cargo diagnostic lines to attach to a failure.
const MAX_DIAGNOSTIC_LINES: usize = 12;

/// Run the opt-in compilation check on the reconstructed source path.
pub(crate) fn check(reconstructed: &Path) -> CompilationGate {
    match run(reconstructed) {
        Ok(Outcome::Compiled) => CompilationGate::Passed,
        Ok(Outcome::Failed(diagnostics)) => CompilationGate::Failed { diagnostics },
        Err(reason) => CompilationGate::Unchecked {
            reason: format!("compile check unavailable: {reason}"),
        },
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
    fn a_valid_contract_passes_the_gate() {
        let src = temp_source("ok", MINIMAL_CONTRACT);
        let gate = check(&src);
        assert!(
            matches!(gate, CompilationGate::Passed),
            "expected Passed, got {gate:#?}"
        );
        assert!(!gate.is_failed(), "a passing gate must not veto");
        let _ = std::fs::remove_dir_all(src.parent().unwrap());
    }

    #[test]
    #[ignore = "shells out to cargo check against soroban-sdk (slow)"]
    fn a_broken_contract_fails_the_gate_and_keeps_its_diagnostics() {
        let broken = format!("{MINIMAL_CONTRACT}\nfn bad() -> u32 {{ \"not a u32\" }}\n");
        let src = temp_source("bad", &broken);
        let gate = check(&src);
        let CompilationGate::Failed { diagnostics } = &gate else {
            panic!("expected Failed, got {gate:#?}");
        };
        // Diagnostics are the whole reason a failed gate carries a payload:
        // the error count is our emitter-progress signal.
        assert!(
            diagnostics.iter().any(|d| d.contains("error")),
            "a failed gate must report why: {diagnostics:#?}"
        );
        assert!(gate.is_failed(), "a failed gate must veto the verdict");
        let _ = std::fs::remove_dir_all(src.parent().unwrap());
    }
}
