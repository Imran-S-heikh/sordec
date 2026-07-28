//! Throwaway cargo crates for the subprocess-backed categories.
//!
//! Two scorer stages need to hand a Rust source to `cargo`: the compilation
//! gate (`cargo check`, [`crate::compile`]) and the macro-expansion
//! harness (`cargo expand`, [`crate::expand`]). Both face the same problem —
//! the emitter produces a bare `lib.rs`, not a crate — so both need a
//! scratch package with a `soroban-sdk` dependency wrapped around it.
//!
//! The machinery lives here rather than in either caller so there is exactly
//! one copy. (The T8 lesson: `interface` and `semantic` each carried an
//! identical, identically-buggy `ratio` helper, and fixing it twice is how
//! the bug grew back.)
//!
//! The scratch *source* directory is removed on drop. Any build output is a
//! separate concern owned by the caller — `expand` deliberately points
//! `CARGO_TARGET_DIR` at a persistent location so dependencies are built once
//! rather than once per invocation.

use std::path::{Path, PathBuf};

/// The soroban-sdk version requirement the scratch crate depends on. A
/// caret requirement so `cargo` resolves to whatever compatible version is
/// cached offline.
const SOROBAN_SDK_VERSION: &str = "23";

/// A temporary cargo crate holding a copy of a Rust source. The directory is
/// removed on drop.
pub(crate) struct ScratchCrate {
    dir: PathBuf,
}

impl ScratchCrate {
    /// Assemble a scratch crate around `source` (a single `.rs` file or a
    /// directory tree).
    ///
    /// # Errors
    ///
    /// A human-readable reason if the directory or manifest cannot be written.
    pub(crate) fn new(source: &Path, prefix: &str) -> Result<Self, String> {
        let dir = unique_scratch_dir(prefix);
        let src_dir = dir.join("src");
        std::fs::create_dir_all(&src_dir).map_err(|e| format!("scratch dir: {e}"))?;

        copy_source(source, &src_dir)?;
        std::fs::write(dir.join("Cargo.toml"), manifest_toml())
            .map_err(|e| format!("write manifest: {e}"))?;

        Ok(Self { dir })
    }

    /// Path to the scratch crate's `Cargo.toml`.
    pub(crate) fn manifest(&self) -> PathBuf {
        self.dir.join("Cargo.toml")
    }
}

impl Drop for ScratchCrate {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Copy a Rust source into the scratch crate's `src/`. A single file becomes
/// `src/lib.rs`; a directory tree is copied verbatim so `mod foo;`
/// declarations resolve.
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
///
/// Deliberately minimal. A contract pulling extra crates (e.g.
/// `soroban-token-sdk`) resolves to *unavailable* rather than *failed* — the
/// harness does not vouch for work it could not attempt.
pub(crate) fn manifest_toml() -> String {
    format!(
        "[package]\n\
         name = \"sordec-scratch\"\n\
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

/// A unique scratch directory under the system temp dir.
///
/// pid + clock + a process-wide counter. The counter is load-bearing: macOS
/// clock resolution is coarse, so two scratch dirs created in quick
/// succession (parallel scoring, or the parallel `#[ignore]` tests) would
/// otherwise collide and delete each other's build mid-run.
pub(crate) fn unique_scratch_dir(prefix: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("{prefix}-{}-{nanos}-{seq}", std::process::id()))
}

/// The cargo binary to invoke, honoring `$CARGO` when the harness is run from
/// within a cargo process (as tests are).
pub(crate) fn cargo_bin() -> String {
    std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string())
}

/// Whether a cargo failure is an environment/dependency problem rather than a
/// problem with the source itself.
///
/// The distinction decides whether a category reports *unavailable* (excluded
/// from the score) or a genuine *failure*, so a missing offline crate never
/// poses as a broken reconstruction.
pub(crate) fn is_dependency_problem(stderr: &str) -> bool {
    const MARKERS: [&str; 5] = [
        "failed to select a version",
        "no matching package",
        "unable to get packages from source",
        "failed to get `",
        "not found in the registry",
    ];
    MARKERS.iter().any(|marker| stderr.contains(marker))
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
        // So is a parse error, which is what a malformed source produces.
        assert!(!is_dependency_problem(
            "error: this file contains an unclosed delimiter"
        ));
    }

    #[test]
    fn manifest_declares_soroban_sdk_and_opts_out_of_workspace() {
        let toml = manifest_toml();
        assert!(toml.contains("soroban-sdk = \"23\""));
        assert!(toml.contains("crate-type = [\"cdylib\"]"));
        assert!(toml.contains("[workspace]"));
    }

    #[test]
    fn scratch_dirs_are_unique_and_prefixed() {
        let a = unique_scratch_dir("sordec-test");
        let b = unique_scratch_dir("sordec-test");
        assert_ne!(a, b, "the counter must break clock-resolution ties");
        assert!(
            a.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("sordec-test-")
        );
    }

    #[test]
    fn a_bare_file_becomes_lib_rs_and_is_cleaned_up() {
        let src = unique_scratch_dir("sordec-scratch-src").join("input.rs");
        std::fs::create_dir_all(src.parent().unwrap()).unwrap();
        std::fs::write(&src, "pub fn f() {}").unwrap();

        let dir = {
            let scratch = ScratchCrate::new(&src, "sordec-scratch-test").expect("scratch crate");
            let dir = scratch.manifest().parent().unwrap().to_path_buf();
            assert!(
                dir.join("src/lib.rs").exists(),
                "single file becomes lib.rs"
            );
            assert!(scratch.manifest().exists(), "manifest written");
            dir
        };
        assert!(!dir.exists(), "scratch dir removed on drop");
        let _ = std::fs::remove_dir_all(src.parent().unwrap());
    }
}
