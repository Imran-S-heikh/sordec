//! Building a crate to wasm, the way the corpus contracts were built.
//!
//! This is the B-side supplier. Given a crate directory it produces wasm bytes
//! that [`crate::exec`] can register, which is the only thing standing between a
//! Rust source and a behavioural comparison.
//!
//! # It builds the manifest it is given
//!
//! [`build`] never writes or patches a `Cargo.toml`. That restraint is the whole
//! point when the crate under test is our emitter's output: if the harness quietly
//! substituted a manifest it liked better, then "the reconstruction compiles and
//! behaves" would be a claim about a crate we do not ship. A crate that cannot be
//! built as emitted is a finding about the emitter, and it is supposed to show up
//! here as a failure.
//!
//! # Two failures, and the difference matters
//!
//! [`BuildFailure`] separates *we could not attempt this* from *this does not
//! build*, mirroring [`crate::preflight`] and `sordec-score`'s compilation gate.
//! A missing toolchain must never be reported as a broken reconstruction — the
//! first maps to an unchecked category, the second is a real result.
//!
//! # Shelling out
//!
//! Conventions here were established by B1's probe and by `sordec-score`'s
//! expansion harness, and each one exists because its absence broke something:
//!
//! - **The bare `cargo` on `PATH`**, never `$CARGO`. `$CARGO` is bound to the
//!   toolchain running the outer process, so it pairs a newer cargo with 1.89's
//!   rustc and dies on flags that rustc does not recognise. The bare binary is the
//!   rustup shim, which resolves cargo and rustc together.
//! - **`RUSTUP_TOOLCHAIN` is set, not cleared.** This is the one deliberate
//!   inversion of `sordec-score`'s `expand::INHERITED_ENV_TO_CLEAR`, which clears
//!   it so a fixture's own `rust-toolchain.toml` wins. Here the toolchain is *our*
//!   decision (`preflight`'s D-B1a), so ours has to win instead.
//! - **`CARGO_BUILD_TARGET` is cleared**, either way: inherited, it fights the
//!   `--target` we pass.
//! - **The target directory is persistent.** A cold wasm build of soroban-sdk runs
//!   ~84 s and a warm one ~1.9 s. Throwing it away per invocation would make the
//!   corpus unrunnable.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::preflight::{self, Unavailable, RECONSTRUCTION_CHANNEL, RECONSTRUCTION_TARGET};

/// Number of leading cargo diagnostic lines kept on a failure.
///
/// Matches `sordec-score`'s compilation gate, and for the same reason: the error
/// count is the sharpest emitter-progress signal available (hello-add at 4 against
/// dex-liquidity-pool at 314), so it is reported even where it is not scored.
const MAX_DIAGNOSTIC_LINES: usize = 12;

/// Environment that must not leak from the outer cargo process into the build.
///
/// `RUSTUP_TOOLCHAIN` is deliberately absent — see the module docs.
const INHERITED_ENV_TO_CLEAR: [&str; 6] = [
    "RUSTC",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "RUSTFLAGS",
    "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_BUILD_TARGET",
];

/// Why a build produced no wasm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildFailure {
    /// The build could not be attempted: no toolchain, no wasm target, an
    /// unreadable crate, or a dependency the offline registry cannot supply.
    ///
    /// Callers map this to an *unchecked* category. It is never a verdict on the
    /// crate.
    Unavailable(Unavailable),
    /// Cargo ran and the crate did not build. A real result.
    Failed {
        /// Leading cargo diagnostics.
        diagnostics: Vec<String>,
    },
}

impl BuildFailure {
    /// The human-readable reason, whichever kind of failure this is.
    #[must_use]
    pub fn reason(&self) -> String {
        match self {
            Self::Unavailable(unavailable) => unavailable.reason.clone(),
            Self::Failed { diagnostics } => {
                let count = diagnostics.len();
                let first = diagnostics.first().map_or("no diagnostics", String::as_str);
                format!("crate does not build ({count} diagnostics): {first}")
            }
        }
    }

    /// Whether the crate itself is at fault, as opposed to the environment.
    #[must_use]
    pub fn is_crate_fault(&self) -> bool {
        matches!(self, Self::Failed { .. })
    }
}

impl From<Unavailable> for BuildFailure {
    fn from(unavailable: Unavailable) -> Self {
        Self::Unavailable(unavailable)
    }
}

/// A persistent cargo target directory, keyed so unrelated builds do not evict
/// each other.
///
/// Per-key rather than shared: distinct soroban-sdk majors are distinct dependency
/// graphs, and pointing them at one directory makes every alternating run a cold
/// build as they overwrite each other's fingerprints. B1 measured that difference
/// as ~84 s against ~1.9 s.
#[must_use]
pub fn persistent_target_dir(key: &str) -> PathBuf {
    // Non-alphanumerics collapse to `-` so a version string or a crate path can be
    // passed straight in without producing nested directories.
    let sanitized: String = key
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    std::env::temp_dir().join(format!("sordec-diffexec-target-{sanitized}"))
}

/// Build the crate at `crate_dir` for the reconstruction target and return its
/// wasm.
///
/// `target_dir` should come from [`persistent_target_dir`] so dependencies are
/// built once rather than once per call.
///
/// # Errors
///
/// [`BuildFailure::Unavailable`] when the toolchain is missing, the manifest
/// cannot be read, the offline registry lacks a dependency, or the build produced
/// no single wasm artifact. [`BuildFailure::Failed`] when cargo ran and the crate
/// did not compile.
pub fn build(crate_dir: &Path, target_dir: &Path) -> Result<Vec<u8>, BuildFailure> {
    let plan = preflight::detect()?;

    // Canonicalised because cargo resolves a relative `--manifest-path` against
    // its own working directory, which we also override.
    let manifest = crate_dir.join("Cargo.toml");
    let manifest = std::fs::canonicalize(&manifest).map_err(|e| {
        BuildFailure::Unavailable(Unavailable {
            reason: format!("cannot read {}: {e}", manifest.display()),
        })
    })?;

    let mut command = Command::new("cargo");
    command
        .args(["build", "--release", "--offline", "--target", RECONSTRUCTION_TARGET])
        .arg("--manifest-path")
        .arg(&manifest)
        .env("RUSTUP_TOOLCHAIN", RECONSTRUCTION_CHANNEL)
        .env("CARGO_TARGET_DIR", target_dir)
        .current_dir(crate_dir);
    for key in INHERITED_ENV_TO_CLEAR {
        command.env_remove(key);
    }

    let output = command.output().map_err(|e| {
        BuildFailure::Unavailable(Unavailable {
            reason: format!("could not launch cargo: {e}"),
        })
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // A dependency the offline registry cannot supply is an environment
        // problem, not a broken crate. Reporting it as *failed* would blame the
        // reconstruction for the harness's own missing cache.
        if is_environment_problem(&stderr) {
            return Err(BuildFailure::Unavailable(Unavailable {
                reason: format!(
                    "cargo could not build offline against rustc {}: {}",
                    plan.rustc_version,
                    first_diagnostics(&stderr).join(" | ")
                ),
            }));
        }
        return Err(BuildFailure::Failed {
            diagnostics: first_diagnostics(&stderr),
        });
    }

    read_sole_wasm(&target_dir.join(RECONSTRUCTION_TARGET).join("release"))
}

/// The one wasm in `dir`.
///
/// Found by scanning rather than by deriving it from the package name, so no TOML
/// parsing — and therefore no second dependency — is needed. A crate emits exactly
/// one `cdylib`, so more than one wasm means the directory is being shared and the
/// bytes we picked would be arbitrary. That is worth an error rather than a coin
/// flip.
fn read_sole_wasm(dir: &Path) -> Result<Vec<u8>, BuildFailure> {
    let entries = std::fs::read_dir(dir).map_err(|e| {
        BuildFailure::Unavailable(Unavailable {
            reason: format!("build reported success but {} is unreadable: {e}", dir.display()),
        })
    })?;

    let mut wasms: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|e| e.to_str()) == Some("wasm"))
        .collect();
    wasms.sort();

    let [wasm] = wasms.as_slice() else {
        return Err(BuildFailure::Unavailable(Unavailable {
            reason: format!(
                "expected exactly one wasm in {}, found {}: {:?}",
                dir.display(),
                wasms.len(),
                wasms
            ),
        }));
    };

    std::fs::read(wasm).map_err(|e| {
        BuildFailure::Unavailable(Unavailable {
            reason: format!("cannot read {}: {e}", wasm.display()),
        })
    })
}

/// Whether a cargo failure is the environment's fault rather than the crate's.
///
/// Deliberately a separate list from `sordec-score`'s `scratch::is_dependency_problem`,
/// which classifies `cargo check` failures on a scratch crate. The two crates must
/// not depend on each other — the scorer's independence from the pipeline it grades
/// is a stated rule — and a wasm build fails in ways a check does not, notably a
/// missing target. Kept side by side rather than shared on purpose.
fn is_environment_problem(stderr: &str) -> bool {
    const MARKERS: [&str; 7] = [
        "failed to select a version",
        "no matching package",
        "unable to get packages from source",
        "failed to get `",
        "not found in the registry",
        "can't find crate for `std`",
        "may not be installed",
    ];
    MARKERS.iter().any(|marker| stderr.contains(marker))
}

/// The leading diagnostic lines from cargo's stderr, capped.
fn first_diagnostics(stderr: &str) -> Vec<String> {
    stderr
        .lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            trimmed.starts_with("error") || trimmed.starts_with("warning:") || trimmed.starts_with("-->")
        })
        .take(MAX_DIAGNOSTIC_LINES)
        .map(|line| line.trim().to_owned())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_dependency_is_the_environment_not_the_crate() {
        assert!(is_environment_problem(
            "error: no matching package named `soroban-sdk` found"
        ));
        assert!(is_environment_problem(
            "error[E0463]: can't find crate for `std`\n  = note: the `wasm32v1-none` target may not be installed"
        ));
    }

    #[test]
    fn a_type_error_is_the_crate_not_the_environment() {
        // The distinction that decides whether a reconstruction is reported as
        // unmeasurable or as broken.
        assert!(!is_environment_problem(
            "error[E0308]: mismatched types\n  --> src/lib.rs:3:5"
        ));
    }

    #[test]
    fn diagnostics_keep_only_diagnostic_lines() {
        let stderr = "   Compiling foo v0.0.0\n\
                      error[E0369]: cannot add `i32` to `Val`\n\
                      \x20 --> src/lib.rs:9:14\n\
                      \x20  |\n\
                      \x20  = note: some note\n\
                      warning: unused import";
        let diagnostics = first_diagnostics(stderr);
        assert_eq!(diagnostics[0], "error[E0369]: cannot add `i32` to `Val`");
        assert!(diagnostics.iter().any(|l| l.starts_with("-->")));
        assert!(!diagnostics.iter().any(|l| l.contains("Compiling")));
        assert!(!diagnostics.iter().any(|l| l.contains("= note")));
    }

    #[test]
    fn a_failure_names_which_kind_it_is() {
        let unavailable = BuildFailure::Unavailable(Unavailable {
            reason: "rustc 1.89 is not installed".to_owned(),
        });
        assert!(!unavailable.is_crate_fault());
        assert_eq!(unavailable.reason(), "rustc 1.89 is not installed");

        let failed = BuildFailure::Failed {
            diagnostics: vec!["error[E0308]: mismatched types".to_owned()],
        };
        assert!(failed.is_crate_fault());
        assert!(failed.reason().contains("does not build (1 diagnostics)"));
    }

    #[test]
    fn target_directories_are_distinct_per_key_and_path_safe() {
        assert_ne!(persistent_target_dir("21"), persistent_target_dir("23"));
        let from_path = persistent_target_dir("vectors/overflow/base");
        assert_eq!(
            from_path.parent(),
            Some(std::env::temp_dir().as_path()),
            "a key containing separators must not nest directories"
        );
    }

    #[test]
    fn an_unreadable_crate_is_unavailable_not_a_build_failure() {
        let missing = std::env::temp_dir().join("sordec-diffexec-does-not-exist");
        let error = build(&missing, &persistent_target_dir("test")).unwrap_err();
        assert!(!error.is_crate_fault(), "{error:?}");
    }
}
