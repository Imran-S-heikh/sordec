//! Guards the one dependency constraint that lives in `Cargo.lock` rather than
//! in a manifest.
//!
//! `soroban-env-host` declares `ed25519-dalek = ">=2.0.0"`, unbounded across
//! majors. The resolver therefore prefers 3.0.0, whose reworked `CryptoRng`
//! bound does not compile against the host's own
//! `builtin_contracts/testutils.rs`. Because the requirement spans majors, a
//! manifest bound in *our* crate cannot constrain the host's node — cargo simply
//! keeps two. The committed lockfile is the only mechanism that does.
//!
//! Constraints that live in a lockfile are invisible: `cargo update` undoes this
//! one silently, and the symptom arrives later as an unexplained trait-bound
//! error deep inside a third-party crate. This test converts that into an
//! immediate, named failure carrying the fix.
//!
//! It reads the lockfile as text rather than parsing TOML — the shape is stable,
//! and the alternative is a dependency for one assertion.

use std::path::PathBuf;

/// Workspace root, two levels up from this crate's manifest.
fn workspace_lockfile() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.lock")
}

/// The version recorded for `name` in the lockfile, if it appears exactly once.
///
/// Returns every match so the test can distinguish "wrong version" from "two
/// majors in the graph", which are different problems with different fixes.
fn locked_versions(lock: &str, name: &str) -> Vec<String> {
    let needle = format!("name = \"{name}\"");
    lock.lines()
        .zip(lock.lines().skip(1))
        .filter(|(line, _)| line.trim() == needle)
        .filter_map(|(_, next)| {
            next.trim()
                .strip_prefix("version = \"")
                .and_then(|rest| rest.strip_suffix('"'))
                .map(str::to_owned)
        })
        .collect()
}

#[test]
fn ed25519_dalek_is_held_at_2_x() {
    let lock = std::fs::read_to_string(workspace_lockfile()).expect("read workspace Cargo.lock");
    let versions = locked_versions(&lock, "ed25519-dalek");

    assert_eq!(
        versions.len(),
        1,
        "expected exactly one ed25519-dalek in the graph, found {versions:?}. \
         Two majors means the pin was partially undone; restore it with \
         `cargo update -p ed25519-dalek@3.0.0 --precise 2.2.0`"
    );
    assert!(
        versions[0].starts_with("2."),
        "ed25519-dalek is locked at {}, but soroban-env-host only compiles against 2.x. \
         A `cargo update` has undone the pin. Restore it with \
         `cargo update -p ed25519-dalek@3.0.0 --precise 2.2.0`",
        versions[0]
    );
}

#[test]
fn curve25519_dalek_follows_from_the_ed25519_bound() {
    // Not pinned directly: ed25519-dalek 2.2 requires curve25519-dalek ^4, which
    // is enough. Asserted so that if that transitive bound ever loosens, we find
    // out here rather than in the host graph.
    let lock = std::fs::read_to_string(workspace_lockfile()).expect("read workspace Cargo.lock");
    let versions = locked_versions(&lock, "curve25519-dalek");

    assert_eq!(
        versions.len(),
        1,
        "expected exactly one curve25519-dalek in the graph, found {versions:?}"
    );
    assert!(
        versions[0].starts_with("4."),
        "curve25519-dalek is locked at {}; soroban-env-host needs 4.x. Its own \
         requirement is `>=4.1.3` (unbounded), so this normally follows from the \
         ed25519-dalek 2.x pin — check that pin first.",
        versions[0]
    );
}
