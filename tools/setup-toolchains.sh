#!/usr/bin/env bash
# setup-toolchains.sh — provision the two harnesses that shell out to cargo,
# and prefetch the corpus so both can build offline.
#
# There are two of them, and they are needed at different times:
#
#   scoring   `cargo expand`, for the macro-expanded basis the RFP mandates.
#             The corpus accuracy bands are derived on that basis, so a machine
#             without it scores a *different* metric — three of seven fixtures
#             breach their band. Needed by `tools/gate.sh`, hence by CI.
#
#   behavior  rustc ${CHANNEL} + the ${TARGET} target, to recompile a
#             reconstruction into wasm and run it against the original. Needed
#             only by the `#[ignore]`d differential-execution tests and by the
#             benchmark report, both run by hand on a provisioned machine.
#
# `--scoring-only` provisions the first group alone. That is what CI asks for:
# it must run the gate, and it must not pay a cold soroban-sdk wasm build on
# every push for tests it never runs.
#
# This script MUTATES: it installs a rustup toolchain, adds a target, installs
# a cargo subcommand, and downloads crates. The read-only counterpart lives in
# code — `sordec_diffexec::preflight::detect()` — because the harness has to
# answer "can I run?" programmatically and report an actionable reason when it
# cannot.
#
# Deliberately NOT part of `tools/gate.sh`. Machine state is not repo content,
# and a gate that fails because a colleague hasn't installed a target teaches
# people to skip the gate. CI calls it as a *provisioning* step, alongside its
# toolchain install — not as a gate step, so `gate.sh` needs no counterpart.
#
# Why this toolchain/target pair, and why it is not derived from the contract:
# see the doc comments on `RECONSTRUCTION_CHANNEL` / `RECONSTRUCTION_TARGET` in
# `crates/sordec-diffexec/src/preflight.rs`. In short — the SDK version is a
# recovered fact that changes behavior and varies per contract; the rustc
# channel and wasm target only affect codegen, so they are one fixed choice.
#
# Exit codes:
#   0 — everything the selected harness needs is present (installing as required)
#   1 — a step failed
#   2 — usage / environment error (rustup not found, corpus missing)

set -euo pipefail

# Resolve repo root from this script's location, regardless of CWD.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." &>/dev/null && pwd)"
CORPUS_ROOT="${REPO_ROOT}/samples/contracts"

# Keep these in step with `preflight.rs`. Two constants in two languages is a
# duplication we accept: the alternative is this script shelling out to a cargo
# build in order to ask a question, which is slower than the work it precedes.
CHANNEL="1.89"
TARGET="wasm32v1-none"

usage() {
    cat <<'EOF'
Usage: setup-toolchains.sh [--scoring-only]

  (no argument)    provision both harnesses: cargo-expand, rustc 1.89 +
                   wasm32v1-none, and the corpus prefetch.
  --scoring-only   provision only what `tools/gate.sh` needs: cargo-expand
                   and the corpus prefetch. Skips the wasm toolchain.
EOF
}

WANT_BEHAVIOR=1
while [[ $# -gt 0 ]]; do
    case "$1" in
        --scoring-only)
            WANT_BEHAVIOR=0
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            echo "setup-toolchains.sh: unknown option '$1'" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ ! -d "${CORPUS_ROOT}" ]]; then
    echo "setup-toolchains.sh: corpus directory not found at ${CORPUS_ROOT}" >&2
    exit 2
fi

if ! command -v cargo >/dev/null 2>&1; then
    echo "setup-toolchains.sh: cargo not found in PATH" >&2
    exit 2
fi

if ((WANT_BEHAVIOR)) && ! command -v rustup >/dev/null 2>&1; then
    echo "setup-toolchains.sh: rustup not found in PATH" >&2
    exit 2
fi

# Announce steps with a running count, so the output says how much is left.
TOTAL=$((WANT_BEHAVIOR ? 4 : 2))
STEP=0
step() {
    STEP=$((STEP + 1))
    ((STEP > 1)) && echo
    echo "== ${STEP}/${TOTAL} $1 =="
}

step "cargo-expand (macro-expanded scoring basis)"
# Ask the subcommand itself rather than looking for a binary on PATH: cargo
# resolves subcommands from `$CARGO_HOME/bin` as well, so a `command -v` here
# reports "missing" on a machine where `cargo expand` works perfectly.
if cargo expand --version >/dev/null 2>&1; then
    echo "OK:      cargo-expand already installed"
else
    echo "install: cargo-expand"
    # `--locked` so the build uses the versions cargo-expand was released
    # against, rather than whatever resolves today.
    cargo install cargo-expand --locked
fi

if ((WANT_BEHAVIOR)); then
    step "toolchain ${CHANNEL}"
    # `rustup toolchain list` is local-only. We check before installing so a
    # provisioned machine stays silent and idempotent, rather than re-resolving
    # the channel over the network on every run.
    if rustup toolchain list | grep -q "^${CHANNEL}-"; then
        echo "OK:      ${CHANNEL} already installed"
    else
        echo "install: ${CHANNEL}"
        rustup toolchain install "${CHANNEL}" --profile minimal
    fi

    step "target ${TARGET} for ${CHANNEL}"
    # Read the filesystem rather than `rustup target list --toolchain ${CHANNEL}`,
    # which INSTALLS the toolchain it is asked about — a surprising side effect for
    # a query, and one that reaches the network.
    RUSTUP_HOME_DIR="${RUSTUP_HOME:-${HOME}/.rustup}"
    TOOLCHAIN_DIR="$(find "${RUSTUP_HOME_DIR}/toolchains" -maxdepth 1 -name "${CHANNEL}-*" -type d 2>/dev/null | head -n 1)"
    if [[ -n "${TOOLCHAIN_DIR}" && -d "${TOOLCHAIN_DIR}/lib/rustlib/${TARGET}" ]]; then
        echo "OK:      ${TARGET} already present"
    else
        echo "install: ${TARGET} for ${CHANNEL}"
        rustup target add "${TARGET}" --toolchain "${CHANNEL}"
    fi
fi

step "prefetch fixture dependencies (for --offline builds)"
# Every fixture `source/` is a self-contained crate with its own Cargo.lock.
# Both harnesses build with `--offline` — `cargo expand` and the recompile
# step alike — so the registry has to be warm first. Measured: token-v22 pins
# `proc-macro2 v1.0.87`, which the workspace build never pulls in, so scoring
# fell back to the pre-expansion basis until it was fetched.
prefetched=0
skipped=0
while IFS= read -r -d '' manifest; do
    fixture_dir="$(dirname "${manifest}")"
    fixture_name="$(basename "$(dirname "${fixture_dir}")")"
    if (cd "${fixture_dir}" && cargo fetch --quiet 2>/dev/null); then
        echo "OK:      ${fixture_name}"
        prefetched=$((prefetched + 1))
    else
        echo "SKIP:    ${fixture_name} (fetch failed; offline builds may be incomplete)" >&2
        skipped=$((skipped + 1))
    fi
done < <(find "${CORPUS_ROOT}" -mindepth 3 -maxdepth 3 -path '*/source/Cargo.toml' -print0)

echo
echo "----"
if ((WANT_BEHAVIOR)); then
    echo "cargo-expand: ok, toolchain: ${CHANNEL}, target: ${TARGET}, prefetched: ${prefetched}, skipped: ${skipped}"
    echo
    echo "Verify with:"
    echo "  cargo test -p sordec --test benchmark accuracy_regression"
    echo "  cargo test -p sordec-diffexec --test probe -- --ignored --nocapture"
else
    echo "cargo-expand: ok, prefetched: ${prefetched}, skipped: ${skipped} (scoring only)"
    echo
    echo "Verify with:"
    echo "  cargo test -p sordec --test benchmark accuracy_regression"
fi

exit 0
