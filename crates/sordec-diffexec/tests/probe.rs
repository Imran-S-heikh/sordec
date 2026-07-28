//! Proves the recompile-and-load path works, for every soroban-sdk version in
//! the corpus.
//!
//! B1's acceptance criterion is deliberately *build **and** load*, not build.
//! Those are different claims, and the gap between them is where this problem
//! hides: the Soroban host disables the `reference-types` and `multi-value` wasm
//! proposals, so a module that compiles perfectly can still be rejected at
//! registration. Asserting only `cargo build` would declare victory over the
//! half of the pipeline that never fails.
//!
//! Each probe assembles a crate shaped like the emitter's real output, builds it
//! for [`RECONSTRUCTION_TARGET`] under [`RECONSTRUCTION_CHANNEL`], and registers
//! the bytes in an in-process host. The SDK version varies; the toolchain does
//! not — see `preflight` for why that split is the right one.
//!
//! These shell out to cargo and are therefore `#[ignore]`d, per the house
//! convention (`tools/gate.sh` runs a plain `cargo test --workspace`, which
//! skips them, and the gate stays fast). The fast counterparts live in
//! `preflight`'s and `wasm`'s unit tests, `tests/lockfile.rs`, and
//! `tests/observe.rs` — the last of which runs contracts in a host without
//! touching cargo, so it needs no `#[ignore]` at all.
//!
//! Run: `cargo test -p sordec-diffexec --test probe -- --ignored --nocapture`

// Probes report what they observe; that is the point of running them with
// `--nocapture`. The workspace lints `print_stdout` at warn and the gate runs
// clippy with `-D warnings`, so the allowance is explicit.
#![allow(clippy::print_stdout)]

use std::path::PathBuf;
use std::process::Command;

use sordec_diffexec::preflight::{self, RECONSTRUCTION_CHANNEL, RECONSTRUCTION_TARGET};
use soroban_sdk::Env;

/// The package name of the probe crate. The wasm cargo emits substitutes
/// underscores, so the two spellings are kept adjacent to stay in step.
const PROBE_PACKAGE: &str = "probe-contract";
/// Basename of the wasm cargo produces for [`PROBE_PACKAGE`].
const PROBE_WASM_STEM: &str = "probe_contract";

/// Environment that must not leak from the outer cargo process into the probe
/// build.
///
/// This is `sordec-score`'s `expand::INHERITED_ENV_TO_CLEAR` minus
/// `RUSTUP_TOOLCHAIN`, and the omission is the point. `expand` *clears* it so
/// that a fixture's own `rust-toolchain.toml` decides; we *set* it (see
/// [`build_probe_wasm`]) because for the reconstruction the toolchain is our
/// decision, not the artifact's. `CARGO_BUILD_TARGET` stays on the list either
/// way — inherited, it would fight our `--target`.
const INHERITED_ENV_TO_CLEAR: [&str; 6] = [
    "RUSTC",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "RUSTFLAGS",
    "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_BUILD_TARGET",
];

/// A contract shaped like what the emitter actually produces: `#![no_std]`, a
/// `#[contract]` unit struct, and one `#[contractimpl]` method taking `Env`
/// first.
///
/// Kept trivial on purpose. The probe is testing the build-and-load path, not
/// recovery quality, so anything beyond the minimum would only add ways for it
/// to fail for reasons that are not B1's.
const PROBE_CONTRACT: &str = r#"#![no_std]
use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn add(_env: Env, a: u64, b: u64) -> u64 {
        a + b
    }
}
"#;

/// The manifest for the probe crate.
///
/// Carries the full `[profile.release]` the corpus contracts were built with.
/// That block is not cosmetic here: `overflow-checks = true` is what makes
/// arithmetic trap rather than wrap (so a recompiled contract matches the
/// original on boundary inputs), and `lto` + `codegen-units = 1` are what keep
/// LLVM from emitting an indirect-call table. The trailing `[workspace]` opts
/// out of any parent workspace, without which cargo refuses to build a crate
/// that sits inside one.
fn probe_manifest(sdk_requirement: &str) -> String {
    format!(
        "[package]\n\
         name = \"{PROBE_PACKAGE}\"\n\
         version = \"0.0.0\"\n\
         edition = \"2021\"\n\
         \n\
         [lib]\n\
         crate-type = [\"cdylib\"]\n\
         \n\
         [dependencies]\n\
         soroban-sdk = \"{sdk_requirement}\"\n\
         \n\
         [profile.release]\n\
         opt-level = \"z\"\n\
         overflow-checks = true\n\
         debug = 0\n\
         strip = \"symbols\"\n\
         debug-assertions = false\n\
         panic = \"abort\"\n\
         codegen-units = 1\n\
         lto = true\n\
         \n\
         [workspace]\n"
    )
}

/// A unique scratch directory under the system temp dir.
///
/// pid + clock + counter, mirroring `sordec-score`'s `scratch::unique_scratch_dir`.
/// The counter is load-bearing rather than defensive: macOS clock resolution is
/// coarse enough that two directories created in quick succession — which is
/// exactly what four probes running in parallel do — would otherwise collide and
/// delete each other's build mid-run.
fn unique_dir(prefix: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("{prefix}-{}-{nanos}-{seq}", std::process::id()))
}

/// Persistent build directory, one per SDK major.
///
/// Persistent because a cold wasm build of soroban-sdk costs ~30s and a warm one
/// is near-instant; per-major because the three SDK majors are three distinct
/// dependency graphs, and sharing one directory makes them evict each other's
/// fingerprints on every alternating run.
fn target_dir(sdk_version: &str) -> PathBuf {
    let major = sdk_version.split('.').next().unwrap_or("unknown");
    std::env::temp_dir().join(format!("sordec-diffexec-probe-target-{major}"))
}

/// Build the probe crate against `sdk_version` and return the wasm bytes.
///
/// # Panics
///
/// With cargo's stderr attached when the build fails — these are diagnostic
/// probes, so the output matters more than a tidy error type.
fn build_probe_wasm(sdk_version: &str) -> Vec<u8> {
    let plan = preflight::detect().unwrap_or_else(|unavailable| {
        panic!("toolchain preflight failed: {unavailable}");
    });

    let dir = unique_dir("sordec-diffexec-probe");
    std::fs::create_dir_all(dir.join("src")).expect("create probe crate");
    std::fs::write(dir.join("src/lib.rs"), PROBE_CONTRACT).expect("write lib.rs");
    std::fs::write(dir.join("Cargo.toml"), probe_manifest(&format!("={sdk_version}")))
        .expect("write manifest");

    let manifest = std::fs::canonicalize(dir.join("Cargo.toml")).expect("canonicalize manifest");
    let out_dir = target_dir(sdk_version);

    // The bare `cargo` on PATH is the rustup shim, which resolves cargo and
    // rustc together. `$CARGO` — what `sordec-score::compile` uses — is bound to
    // the outer toolchain and would pair a newer cargo with 1.89's rustc, which
    // dies on unrecognised flags.
    let mut command = Command::new("cargo");
    command
        .args(["build", "--release", "--offline", "--target", RECONSTRUCTION_TARGET])
        .arg("--manifest-path")
        .arg(&manifest)
        .env("RUSTUP_TOOLCHAIN", RECONSTRUCTION_CHANNEL)
        .env("CARGO_TARGET_DIR", &out_dir)
        .current_dir(&dir);
    for key in INHERITED_ENV_TO_CLEAR {
        command.env_remove(key);
    }

    let output = command.output().expect("launch cargo");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "cargo build failed for soroban-sdk {sdk_version} \
         (rustc {}, target {RECONSTRUCTION_TARGET}):\n{stderr}",
        plan.rustc_version
    );

    let wasm_path = out_dir
        .join(RECONSTRUCTION_TARGET)
        .join("release")
        .join(format!("{PROBE_WASM_STEM}.wasm"));
    let bytes = std::fs::read(&wasm_path)
        .unwrap_or_else(|e| panic!("read {}: {e}\ncargo stderr:\n{stderr}", wasm_path.display()));

    // Only the source tree is cleaned up; `out_dir` is deliberately kept warm.
    let _ = std::fs::remove_dir_all(&dir);
    bytes
}

/// Build for `sdk_version`, register the result in a host, and invoke it.
///
/// Registration is the assertion that matters — it is where a module carrying
/// wasm features the host disables would be rejected. Invoking afterwards
/// confirms the export survived, which is the smallest end-to-end statement
/// worth making.
fn assert_builds_and_loads(sdk_version: &str) {
    let wasm = build_probe_wasm(sdk_version);
    println!("soroban-sdk {sdk_version}: built {} bytes", wasm.len());

    assert!(
        sordec_diffexec::wasm::is_loadable(&wasm),
        "soroban-sdk {sdk_version}: no {} section — the host rejects modules \
         without one, so such a build could never be executed",
        sordec_diffexec::wasm::ENV_META_SECTION
    );

    let env = Env::default();
    let address = env.register(wasm.as_slice(), ());
    println!("soroban-sdk {sdk_version}: registered at {address:?}");
}

/// Run: `cargo test -p sordec-diffexec --test probe -- --ignored --nocapture`
#[ignore = "shells out to cargo build --target wasm32v1-none (slow, toolchain-dependent)"]
#[test]
fn sdk_21_7_7_builds_and_loads() {
    // The oldest SDK in the corpus (hello-add), and the one whose support for
    // `wasm32v1-none` was least certain: the target postdates the release. It
    // gates on `target_family = "wasm"` rather than `target_os = "unknown"`
    // though, so it should select the guest env correctly. This settles it.
    assert_builds_and_loads("21.7.7");
}

/// Run: `cargo test -p sordec-diffexec --test probe -- --ignored --nocapture`
#[ignore = "shells out to cargo build --target wasm32v1-none (slow, toolchain-dependent)"]
#[test]
fn sdk_22_0_11_builds_and_loads() {
    assert_builds_and_loads("22.0.11");
}

/// Run: `cargo test -p sordec-diffexec --test probe -- --ignored --nocapture`
#[ignore = "shells out to cargo build --target wasm32v1-none (slow, toolchain-dependent)"]
#[test]
fn sdk_23_0_1_builds_and_loads() {
    // The acceptance contract's SDK — token-v23, timelock and dex all report
    // this via `rssdkver`.
    assert_builds_and_loads("23.0.1");
}

/// Run: `cargo test -p sordec-diffexec --test probe -- --ignored --nocapture`
#[ignore = "shells out to cargo build --target wasm32v1-none (slow, toolchain-dependent)"]
#[test]
fn sdk_23_5_3_builds_and_loads() {
    assert_builds_and_loads("23.5.3");
}
