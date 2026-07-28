//! What the harness needs from the machine, resolved before anything is built.
//!
//! **Which rustc and which wasm target do we recompile a reconstruction with?**
//! One global answer ([`RECONSTRUCTION_CHANNEL`], [`RECONSTRUCTION_TARGET`]),
//! because it affects codegen and not semantics.
//!
//! The neighbouring question — **which `soroban-sdk` version does *this contract*
//! need?** — used to be answered here too, and is not. It is a recovered fact that
//! genuinely does change semantics (host functions, error codes, event layout and
//! Val marshalling all moved between protocols 21 and 23), and its one real
//! consumer is the emitter, which writes the reconstruction's `Cargo.toml`. It
//! therefore lives in `sordec-backend`'s `scaffold::sdk_requirement`. Keeping a
//! second copy here — a copy nothing called — was an invitation for the two to
//! drift, and the emitter's is the one that ships.
//!
//! Conflating the two questions is tempting because the wasm carries *both* an
//! `rsver` and an `rssdkver`. Neither is a rustup channel — see
//! [`RECONSTRUCTION_CHANNEL`].
//!
//! Nothing here runs `rustup`. `rustup target list --toolchain X` *installs* X
//! when it is absent, so a routine "is this present?" check would mutate the
//! machine and reach the network. Detection reads `~/.rustup/toolchains/`
//! directly and, where it needs a version, executes a toolchain's own `rustc`
//! by absolute path so the shim is never involved.

use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The rustc channel our reconstruction is compiled with.
///
/// Fixed and global, deliberately *not* derived from the contract's recovered
/// `rsver`. Two reasons, both load-bearing:
///
/// 1. **`rsver` is not a rustup channel name.** It is three-component
///    (`"1.89.0"`); rustup channels here are two (`1.89`). Those are *different
///    toolchains with different install directories* — on this machine
///    `1.89.0-…` exists and has no wasm target at all, while `1.89-…` has
///    `wasm32v1-none`. Pinning from `rsver` would silently select the
///    target-less one and then reach the network mid-build to fetch a std for
///    it.
/// 2. **The toolchain does not affect observable behaviour.** It affects
///    codegen. Both sides of the comparison are read *after* the module loads,
///    so any module that loads is comparable regardless of which rustc built
///    it. The SDK version is the axis that changes semantics, and that one
///    *is* per-contract — recovered and pinned by the emitter, in
///    `sordec-backend`'s `scaffold::sdk_requirement`.
///
/// `1.89` also clears every soroban-sdk MSRV in our corpus (21.7.7 wants
/// 1.74; 22.x and 23.x want 1.84), and already carries the target.
pub const RECONSTRUCTION_CHANNEL: &str = "1.89";

/// The wasm target our reconstruction is compiled for.
///
/// `wasm32v1-none` restricts codegen to WebAssembly 1.0, which *cannot* encode
/// `reference-types` or `multi-value` — precisely the two proposals the Soroban
/// host disables when it configures wasmi. So "the module was rejected at load"
/// stops being a failure mode we have to defend against.
///
/// The alternative — mirroring each contract's original target — would mean
/// reproducing `wasm32-unknown-unknown` on a modern rustc for the older
/// fixtures, a pairing soroban-sdk's own build script calls unsupported. The
/// existing fixtures survive it only because `lto = true` devirtualised every
/// indirect call and so no function table was ever emitted. That is an accident
/// worth not depending on.
pub const RECONSTRUCTION_TARGET: &str = "wasm32v1-none";

/// A resolved, ready-to-use toolchain for recompiling a reconstruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolchainPlan {
    /// The rustup channel, as it must be passed via `RUSTUP_TOOLCHAIN`.
    pub channel: String,
    /// The wasm target triple to pass via `--target`.
    pub target: String,
    /// Absolute path to the toolchain's install directory.
    pub toolchain_dir: PathBuf,
    /// `rustc --version` output, for the record in reports.
    pub rustc_version: String,
}

/// Why the harness cannot run on this machine.
///
/// Always a degradation, never a verdict on the reconstruction. Callers map
/// this to an *unchecked* category — a behaviour score that could not be
/// attempted must not pose as a behaviour score of zero.
///
/// [`Unavailable::reason`] is written to be actionable: it names what is
/// missing and the command that fixes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unavailable {
    /// Human-readable explanation, surfaced in the report's notes.
    pub reason: String,
}

impl fmt::Display for Unavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.reason)
    }
}

impl std::error::Error for Unavailable {}

/// Resolve the toolchain and target the harness will recompile with.
///
/// # Errors
///
/// [`Unavailable`] when rustup's toolchain root cannot be located, the pinned
/// channel is not installed, or it is installed without the wasm target. Each
/// reason names the command that fixes it.
pub fn detect() -> Result<ToolchainPlan, Unavailable> {
    detect_in(&rustup_toolchains_dir()?, RECONSTRUCTION_CHANNEL, RECONSTRUCTION_TARGET)
}

/// [`detect`] against an explicit toolchains root, so tests can drive it
/// against a fixture directory instead of the developer's real rustup install.
///
/// # Errors
///
/// As [`detect`].
pub fn detect_in(
    toolchains_dir: &Path,
    channel: &str,
    target: &str,
) -> Result<ToolchainPlan, Unavailable> {
    let toolchain_dir = resolve_channel(toolchains_dir, channel).ok_or_else(|| Unavailable {
        reason: format!(
            "rustc {channel} is not installed (looked in {}); \
             install it with `rustup toolchain install {channel}`",
            toolchains_dir.display()
        ),
    })?;

    if !has_target(&toolchain_dir, target) {
        return Err(Unavailable {
            reason: format!(
                "rustc {channel} is installed but lacks the {target} target; \
                 add it with `rustup target add {target} --toolchain {channel}`"
            ),
        });
    }

    let rustc_version = rustc_version(&toolchain_dir).ok_or_else(|| Unavailable {
        reason: format!(
            "could not run rustc from {}; the toolchain looks incomplete",
            toolchain_dir.display()
        ),
    })?;

    Ok(ToolchainPlan {
        channel: channel.to_owned(),
        target: target.to_owned(),
        toolchain_dir,
        rustc_version,
    })
}

/// Rustup's toolchain root, honoring `RUSTUP_HOME` before falling back to
/// `$HOME/.rustup`.
fn rustup_toolchains_dir() -> Result<PathBuf, Unavailable> {
    if let Some(home) = std::env::var_os("RUSTUP_HOME") {
        return Ok(PathBuf::from(home).join("toolchains"));
    }
    let home = std::env::var_os("HOME").ok_or_else(|| Unavailable {
        reason: "neither RUSTUP_HOME nor HOME is set; cannot locate rustup".to_owned(),
    })?;
    Ok(PathBuf::from(home).join(".rustup").join("toolchains"))
}

/// Find the install directory for `channel`.
///
/// Toolchain directories are named `<channel>-<host-triple>`. The host triple
/// is discovered by matching the prefix rather than hardcoded, so this works on
/// any platform — and so a channel that is a *prefix* of another (`1.9` vs
/// `1.91`) cannot match the wrong one: the separator is required.
fn resolve_channel(toolchains_dir: &Path, channel: &str) -> Option<PathBuf> {
    let wanted_prefix = format!("{channel}-");
    let entries = std::fs::read_dir(toolchains_dir).ok()?;
    entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .find(|path| {
            path.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|name| name.starts_with(&wanted_prefix))
        })
}

/// Whether a toolchain carries the std for `target`.
///
/// Presence of `lib/rustlib/<target>/` is how rustup itself records an
/// installed target, and reading it avoids `rustup target list`, which would
/// install the toolchain being asked about.
fn has_target(toolchain_dir: &Path, target: &str) -> bool {
    toolchain_dir.join("lib").join("rustlib").join(target).is_dir()
}

/// `rustc --version` for a toolchain, invoked by absolute path.
///
/// The absolute path matters: going through the `rustc` on `PATH` would hit the
/// rustup shim, which resolves the toolchain from the working directory and can
/// trigger an install.
fn rustc_version(toolchain_dir: &Path) -> Option<String> {
    let rustc = toolchain_dir.join("bin").join("rustc");
    let output = Command::new(rustc).arg("--version").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let version = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    (!version.is_empty()).then_some(version)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- toolchain detection: filesystem-only, no rustup, no network ----

    /// A fake rustup toolchains root. `target` is created only when named.
    fn fake_toolchains(dir: &Path, name: &str, target: Option<&str>) {
        let toolchain = dir.join(name);
        std::fs::create_dir_all(toolchain.join("bin")).unwrap();
        if let Some(target) = target {
            std::fs::create_dir_all(toolchain.join("lib").join("rustlib").join(target)).unwrap();
        }
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sordec-preflight-{tag}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_missing_channel_names_the_install_command() {
        let root = temp_dir("no-channel");
        let err = detect_in(&root, "1.89", "wasm32v1-none").unwrap_err();
        assert!(err.reason.contains("not installed"), "{}", err.reason);
        assert!(
            err.reason.contains("rustup toolchain install 1.89"),
            "the reason must be actionable: {}",
            err.reason
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn an_installed_channel_missing_the_target_names_the_target_command() {
        let root = temp_dir("no-target");
        fake_toolchains(&root, "1.89-aarch64-apple-darwin", None);
        let err = detect_in(&root, "1.89", "wasm32v1-none").unwrap_err();
        assert!(err.reason.contains("lacks the wasm32v1-none target"), "{}", err.reason);
        assert!(
            err.reason.contains("rustup target add wasm32v1-none --toolchain 1.89"),
            "{}",
            err.reason
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn channel_matching_requires_the_separator() {
        // `1.9-…` must not satisfy a request for `1.91`, nor the reverse. Without
        // the trailing `-` in the prefix, `starts_with` would match both ways.
        let root = temp_dir("prefix");
        fake_toolchains(&root, "1.9-aarch64-apple-darwin", Some("wasm32v1-none"));
        let err = detect_in(&root, "1.91", "wasm32v1-none").unwrap_err();
        assert!(err.reason.contains("not installed"), "{}", err.reason);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn an_incomplete_toolchain_reports_rather_than_panicking() {
        // Target dir present but no usable rustc — the shape a partially
        // removed toolchain leaves behind.
        let root = temp_dir("no-rustc");
        fake_toolchains(&root, "1.89-aarch64-apple-darwin", Some("wasm32v1-none"));
        let err = detect_in(&root, "1.89", "wasm32v1-none").unwrap_err();
        assert!(err.reason.contains("could not run rustc"), "{}", err.reason);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn detect_returns_a_structured_result_on_this_machine() {
        // Environment-dependent, so it asserts the *shape* rather than success:
        // either a plan for the pinned pair, or an actionable reason. What it
        // must never do is panic — B23 maps this straight to `unchecked`.
        match detect() {
            Ok(plan) => {
                assert_eq!(plan.channel, RECONSTRUCTION_CHANNEL);
                assert_eq!(plan.target, RECONSTRUCTION_TARGET);
                assert!(plan.rustc_version.starts_with("rustc "), "{}", plan.rustc_version);
                assert!(plan.toolchain_dir.is_dir());
            }
            Err(unavailable) => assert!(
                !unavailable.reason.is_empty(),
                "an unavailable reason must say something"
            ),
        }
    }
}
