//! Assembling a throwaway contract crate on disk, shared by the integration
//! tests that need one.
//!
//! Test-only, and deliberately not in the library: `recompile::build` builds the
//! manifest it is handed and never writes one, precisely so that a claim about the
//! emitter's crate is a claim about the crate we ship. Fixture assembly is the
//! tests' business.
//!
//! The `[profile.release]` block lives here in one copy because the flags are
//! load-bearing rather than decorative, and two copies would drift. Full
//! reasoning on [`CORPUS_RELEASE_PROFILE`].

// A `tests/common/` module is compiled into every test binary that declares it, and
// each one uses a different subset — `identity.rs` needs only `unique_dir`, while
// `vectors.rs` needs the crate assembly. Every item here is live in at least one
// binary, but the compiler cannot see that, and `tools/gate.sh` runs clippy with
// `-D warnings`.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

/// The `[profile.release]` block every contract in the corpus was built with.
///
/// Verified identical across all seven fixture sources. Three of these flags
/// change observable behaviour or loadability, so a fixture built without them is
/// not a fair comparison subject:
///
/// - **`overflow-checks = true`** makes arithmetic trap instead of wrapping.
///   Cargo's release default is *off*, so a naive recompile wraps where the
///   original traps and manufactures a divergence on every boundary input. This is
///   the flag the `overflow` vector exists to demonstrate.
/// - **`lto = true`** and **`codegen-units = 1`** devirtualise indirect calls. Without
///   them a module can carry a function table, which the host rejects outright
///   because it disables the `reference-types` proposal — so this is a *load*
///   blocker, not a tuning knob.
/// - **`panic = "abort"`** is what turns a `panic!` into the trap that
///   `Outcome::Aborted` observes.
pub const CORPUS_RELEASE_PROFILE: &str = "\
[profile.release]
opt-level = \"z\"
overflow-checks = true
debug = 0
strip = \"symbols\"
debug-assertions = false
panic = \"abort\"
codegen-units = 1
lto = true
";

/// The soroban-sdk version fixture crates build against unless they say otherwise.
///
/// Pinned with `=` rather than a caret for the reason `preflight::SdkRequirement`
/// documents: a caret silently resolves to a newer patch once the network is
/// reachable, changing behaviour underneath a test that named a version.
pub const DEFAULT_SDK: &str = "23.0.1";

/// A minimal contract-crate manifest.
///
/// The trailing `[workspace]` is required, not tidiness: without it cargo refuses
/// to build a crate that sits inside another workspace, and the scratch directory
/// may well.
pub fn contract_manifest(package: &str, sdk_version: &str) -> String {
    format!(
        "[package]\n\
         name = \"{package}\"\n\
         version = \"0.0.0\"\n\
         edition = \"2021\"\n\
         \n\
         [lib]\n\
         crate-type = [\"cdylib\"]\n\
         \n\
         [dependencies]\n\
         soroban-sdk = \"={sdk_version}\"\n\
         \n\
         {CORPUS_RELEASE_PROFILE}\n\
         [workspace]\n"
    )
}

/// Write a single-file contract crate into `dir` and return the directory.
///
/// # Panics
///
/// If the crate cannot be written. A fixture that cannot be laid down is a broken
/// test, not a finding.
pub fn write_contract_crate(dir: &Path, package: &str, sdk_version: &str, source: &str) -> PathBuf {
    std::fs::create_dir_all(dir.join("src")).expect("create crate src/");
    std::fs::write(dir.join("src/lib.rs"), source).expect("write lib.rs");
    std::fs::write(dir.join("Cargo.toml"), contract_manifest(package, sdk_version))
        .expect("write Cargo.toml");
    dir.to_path_buf()
}

/// A unique scratch directory under the system temp dir.
///
/// pid + clock + a process-wide counter, mirroring `sordec-score`'s
/// `scratch::unique_scratch_dir`. The counter is load-bearing rather than
/// defensive: macOS clock resolution is coarse enough that two directories created
/// in quick succession — which is what parallel tests do — would otherwise collide
/// and delete each other's build mid-run.
pub fn unique_dir(prefix: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("{prefix}-{}-{nanos}-{seq}", std::process::id()))
}
