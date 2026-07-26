//! Macro-expansion harness: produce the **macro-expanded** basis the RFP
//! mandates (`OFFICIAL_TRANCHES.md:63-64`), via `cargo expand`.
//!
//! `score-1.0.0` compares sources *before* macro expansion. That is the wrong
//! basis and it is what craters the structure category: a Soroban contract's
//! real shape lives inside `#[contractimpl]`, and comparing an un-expanded
//! original against our flat emitted functions measures almost nothing
//! (token-v23 structure scores 0.005 pre-expansion, 0.49 post).
//!
//! ## Why this works on source that does not compile
//!
//! `cargo expand` runs `-Zunpretty=expanded`, which happens **before**
//! type-check. Our current reconstruction of token-v23 has 149 `cargo check`
//! errors and still expands cleanly — measured, not assumed. That is the one
//! assumption the whole basis change rests on, so
//! `type_errors_do_not_block_expansion` pins it as a test.
//!
//! ## Build caching
//!
//! [`crate::compile`] discards its scratch directory on every run, so each
//! check rebuilds all of soroban-sdk — which is why its tests are `#[ignore]`d
//! as slow. Expansion must not inherit that: it points `CARGO_TARGET_DIR` at a
//! **persistent** directory (see [`target_dir`]) so dependencies build once per
//! machine. Measured: ~30s cold, 0.25s warm. Scratch *source* dirs are still
//! per-run and still deleted; only build output persists.
//!
//! ## Failure is degradation, never error
//!
//! A missing toolchain, an offline registry without the SDK, or a malformed
//! source all yield [`Unavailable`]. The caller falls back to the
//! pre-expansion basis and records why — mirroring how `compile` reports an
//! unrun check rather than a failed one.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::scratch::{self, ScratchCrate};

/// How far up from the given path to look for a `Cargo.toml`.
///
/// Callers pass a crate's `src/` directory (`benchmark.rs` and
/// `calibration.rs` both score `source/src`), so the manifest is typically one
/// level up. The bound keeps a stray path from walking to the filesystem root
/// and adopting an unrelated manifest.
const MAX_CRATE_ROOT_DEPTH: usize = 3;

/// Environment variable overriding the persistent build directory, so CI can
/// point it at a warm cache.
const TARGET_DIR_ENV: &str = "SORDEC_EXPAND_TARGET_DIR";

/// Why an expansion could not be produced.
///
/// Always a degradation — the caller falls back to the pre-expansion basis
/// and records the reason. Never a scoring failure.
#[derive(Debug, Clone)]
pub(crate) struct Unavailable {
    /// Human-readable explanation, surfaced in the report's notes.
    pub reason: String,
}

impl std::fmt::Display for Unavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}

/// Expand a scoring input to macro-expanded Rust source text.
///
/// `path` may be a crate directory, a crate's `src/` directory, or a bare
/// `.rs` file. When no `Cargo.toml` is reachable (the emitter produces a lone
/// `lib.rs`), the source is wrapped in a scratch crate.
///
/// # Errors
///
/// [`Unavailable`] when cargo is missing, the offline registry cannot supply a
/// dependency, or the source cannot be expanded.
pub(crate) fn expand(path: &Path) -> Result<String, Unavailable> {
    match crate_root(path) {
        Some(root) => run(&root.join("Cargo.toml")),
        None => {
            // No manifest in reach: wrap the bare source in a scratch crate.
            let scratch = ScratchCrate::new(path, "sordec-expand")
                .map_err(|reason| Unavailable { reason })?;
            run(&scratch.manifest())
        }
    }
}

/// The nearest ancestor of `path` (inclusive) holding a `Cargo.toml`, within
/// [`MAX_CRATE_ROOT_DEPTH`] levels.
fn crate_root(path: &Path) -> Option<PathBuf> {
    let start = if path.is_dir() { path } else { path.parent()? };
    start
        .ancestors()
        .take(MAX_CRATE_ROOT_DEPTH + 1)
        .find(|dir| dir.join("Cargo.toml").is_file())
        .map(Path::to_path_buf)
}

/// Environment variables that must not leak from an outer `cargo` process
/// into the expansion.
///
/// The scorer is normally *itself* run under cargo (the CLI, the test
/// suites), and cargo exports its own toolchain and flag decisions to child
/// processes. Inheriting them makes the inner build compile the target crate
/// under the outer crate's settings.
///
/// `RUSTUP_TOOLCHAIN` is the one that actually bites: it takes precedence
/// over a directory's `rust-toolchain.toml`, so the vendored fixtures — which
/// pin 1.89 to match the soroban-sdk release they were built against — get
/// compiled by whatever toolchain the workspace happens to use, and
/// soroban-sdk fails with `E0512: cannot transmute between types of different
/// sizes`. Measured, not hypothetical. The rest are cleared on the same
/// principle: the inner build decides for itself.
const INHERITED_ENV_TO_CLEAR: [&str; 7] = [
    "RUSTUP_TOOLCHAIN",
    "RUSTC",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "RUSTFLAGS",
    "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_BUILD_TARGET",
];

/// The cargo binary to invoke for expansion: resolved from `PATH`, which under
/// rustup is the *shim*.
///
/// Deliberately **not** `scratch::cargo_bin()` (`$CARGO`), which `compile` uses.
/// Inside an outer cargo process `$CARGO` is a toolchain-bound binary that does
/// not consult the target crate's `rust-toolchain.toml` — while the `rustc` it
/// drives, reached through the rustup shim, does. The vendored fixtures pin
/// 1.89, so that split pairs a newer cargo with an older rustc and expansion
/// dies on `error: Unrecognized option: 'check-cfg'`. The shim resolves both
/// consistently. Measured, not hypothetical.
///
/// Resolution is per-directory, so [`run`] also sets the working directory to
/// the crate root — rustup reads `rust-toolchain.toml` relative to the cwd, not
/// to `--manifest-path`.
const CARGO_SHIM: &str = "cargo";

/// Run `cargo expand` against a manifest and return its stdout.
fn run(manifest: &Path) -> Result<String, Unavailable> {
    // Absolute, because the working directory is changed below: a relative
    // manifest path would then resolve against the wrong directory.
    let manifest = std::fs::canonicalize(manifest).map_err(|e| Unavailable {
        reason: format!("manifest {}: {e}", manifest.display()),
    })?;

    let mut command = Command::new(CARGO_SHIM);
    command
        .args(["expand", "--lib", "--offline", "--manifest-path"])
        .arg(&manifest)
        .env("CARGO_TARGET_DIR", target_dir());
    // rustup picks the toolchain from the working directory, so run from the
    // crate root for its `rust-toolchain.toml` to apply.
    if let Some(root) = manifest.parent() {
        command.current_dir(root);
    }
    for key in INHERITED_ENV_TO_CLEAR {
        command.env_remove(key);
    }

    let output = command.output().map_err(|e| Unavailable {
        reason: format!("could not launch cargo expand: {e}"),
    })?;

    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        return Err(Unavailable {
            reason: classify(&stderr),
        });
    }

    let expanded = String::from_utf8_lossy(&output.stdout).into_owned();
    // A zero exit with no output means cargo found nothing to expand (no lib
    // target, say). Treat it as unavailable rather than as an empty crate,
    // which would read as a contract with no items at all.
    if expanded.trim().is_empty() {
        return Err(Unavailable {
            reason: "cargo expand produced no output".to_owned(),
        });
    }
    Ok(expanded)
}

/// Turn cargo's stderr into a report-worthy reason, distinguishing an
/// environment problem from a problem with the source.
fn classify(stderr: &str) -> String {
    if scratch::is_dependency_problem(stderr) {
        return "offline registry is missing a required crate".to_owned();
    }
    // Match only cargo's own "unknown subcommand" phrasing. Testing for the
    // substring `cargo-expand` would swallow any error that merely *mentions*
    // the tool and misreport it as a missing install.
    if stderr.contains("no such command") || stderr.contains("Did you mean") {
        return "cargo-expand is not installed".to_owned();
    }
    let detail = stderr
        .lines()
        .find(|line| line.trim_start().starts_with("error"))
        .unwrap_or("cargo expand failed")
        .trim();
    format!("cargo expand failed: {detail}")
}

/// The persistent build directory shared across expansions.
///
/// Deliberately *not* removed between runs: dependencies build once per
/// machine, turning a ~30s cold expansion into a 0.25s warm one. Concurrent
/// invocations serialize on cargo's own lock for this directory.
fn target_dir() -> PathBuf {
    std::env::var_os(TARGET_DIR_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("sordec-expand-target"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_dir(name: &str) -> PathBuf {
        let dir = scratch::unique_scratch_dir(&format!("sordec-expand-test-{name}"));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    // -----------------------------------------------------------------
    // crate_root
    // -----------------------------------------------------------------

    #[test]
    fn crate_root_walks_up_from_a_src_dir() {
        // The shape every caller actually passes: `<crate>/src`.
        let root = scratch_dir("walkup");
        let src = root.join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(root.join("Cargo.toml"), "[package]").unwrap();

        assert_eq!(crate_root(&src).as_deref(), Some(root.as_path()));
        // And from a file inside it.
        std::fs::write(src.join("lib.rs"), "pub fn f() {}").unwrap();
        assert_eq!(
            crate_root(&src.join("lib.rs")).as_deref(),
            Some(root.as_path())
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn crate_root_finds_a_manifest_in_the_dir_itself() {
        let root = scratch_dir("selfroot");
        std::fs::write(root.join("Cargo.toml"), "[package]").unwrap();
        assert_eq!(crate_root(&root).as_deref(), Some(root.as_path()));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn crate_root_is_none_without_a_manifest() {
        // A bare source dir with no manifest anywhere near it takes the
        // scratch-crate path instead.
        let dir = scratch_dir("nomanifest");
        let deep = dir.join("a/b/c/d/e");
        std::fs::create_dir_all(&deep).unwrap();
        assert_eq!(crate_root(&deep), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------
    // classify
    // -----------------------------------------------------------------

    #[test]
    fn classify_separates_environment_from_source_problems() {
        assert_eq!(
            classify("error: failed to select a version for `soroban-sdk`"),
            "offline registry is missing a required crate"
        );
        assert!(classify("error: no such command: `expand`").contains("not installed"));
        // A malformed source is the source's problem, reported verbatim.
        let source_failure = classify("error: this file contains an unclosed delimiter");
        assert!(
            source_failure.contains("unclosed delimiter"),
            "got: {source_failure}"
        );
    }

    #[test]
    fn target_dir_is_overridable() {
        // Default is stable across calls — that is what makes the build cache
        // survive between runs.
        assert_eq!(target_dir(), target_dir());
        assert!(target_dir().ends_with("sordec-expand-target"));
    }

    // -----------------------------------------------------------------
    // The remaining tests shell out to `cargo expand`; they are slow and
    // toolchain-dependent, so they are `#[ignore]`d out of the fast suite
    // (the `compile` convention). Run with:
    //   cargo test -p sordec-score -- --ignored
    // -----------------------------------------------------------------

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

    fn temp_source(name: &str, body: &str) -> PathBuf {
        let path = scratch_dir(name).join("input.rs");
        std::fs::write(&path, body).unwrap();
        path
    }

    #[test]
    #[ignore = "shells out to cargo expand against soroban-sdk (slow)"]
    fn a_bare_file_expands_through_the_scratch_crate() {
        let src = temp_source("bare", MINIMAL_CONTRACT);
        let expanded = expand(&src).expect("expansion should succeed");

        // Expansion must surface the ABI ground truth the macros generate —
        // this is what M3 will read the interface from.
        assert!(
            expanded.contains("__SPEC_XDR_FN_ADD"),
            "expected the spec-XDR static in:\n{expanded}"
        );
        // And it must still be parseable Rust.
        syn::parse_file(&expanded).expect("expanded output must parse");

        let _ = std::fs::remove_dir_all(src.parent().unwrap());
    }

    #[test]
    #[ignore = "shells out to cargo expand against soroban-sdk (slow)"]
    fn type_errors_do_not_block_expansion() {
        // THE load-bearing assumption of the whole macro-expanded basis:
        // `cargo expand` runs `-Zunpretty=expanded`, which precedes
        // type-check. Our real reconstruction of token-v23 carries 149
        // `cargo check` errors and still expands. If this ever regresses,
        // the expanded basis silently stops being reachable for exactly the
        // inputs we most need it for.
        let broken = format!("{MINIMAL_CONTRACT}\nfn bad() -> u32 {{ \"not a u32\" }}\n");
        let src = temp_source("typeerr", &broken);

        let expanded = expand(&src).expect("type errors must not block expansion");
        assert!(expanded.contains("__SPEC_XDR_FN_ADD"));

        let _ = std::fs::remove_dir_all(src.parent().unwrap());
    }

    #[test]
    #[ignore = "shells out to cargo expand (slow)"]
    fn an_unresolvable_dependency_is_unavailable_not_a_failure() {
        let root = scratch_dir("baddep");
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/lib.rs"), "pub fn f() {}").unwrap();
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname=\"baddep\"\nversion=\"0.0.0\"\nedition=\"2021\"\n\n\
             [dependencies]\nsoroban-token-sdk = \"99\"\n\n[workspace]\n",
        )
        .unwrap();

        let err = expand(&root).expect_err("an unresolvable dep must not expand");
        assert!(
            err.reason.contains("missing a required crate"),
            "got: {}",
            err.reason
        );

        let _ = std::fs::remove_dir_all(&root);
    }
}
