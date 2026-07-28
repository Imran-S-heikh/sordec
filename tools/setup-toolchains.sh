#!/usr/bin/env bash
# setup-toolchains.sh — provision what the behavior harness needs to recompile
# a reconstruction into wasm, and prefetch the corpus for offline builds.
#
# This script MUTATES: it installs a rustup toolchain, adds a target, and
# downloads crates. It is opt-in and run by a human. The read-only counterpart
# lives in code — `sordec_diffexec::preflight::detect()` — because the harness
# has to answer "can I run?" programmatically and report an actionable reason
# when it cannot.
#
# Deliberately NOT part of `tools/gate.sh`. Machine state is not repo content,
# and a gate that fails because a colleague hasn't installed a target teaches
# people to skip the gate.
#
# Why this toolchain/target pair, and why it is not derived from the contract:
# see the doc comments on `RECONSTRUCTION_CHANNEL` / `RECONSTRUCTION_TARGET` in
# `crates/sordec-diffexec/src/preflight.rs`. In short — the SDK version is a
# recovered fact that changes behavior and varies per contract; the rustc
# channel and wasm target only affect codegen, so they are one fixed choice.
#
# Exit codes:
#   0 — everything the harness needs is present (installing as required)
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

if ! command -v rustup >/dev/null 2>&1; then
    echo "setup-toolchains.sh: rustup not found in PATH" >&2
    exit 2
fi

if [[ ! -d "${CORPUS_ROOT}" ]]; then
    echo "setup-toolchains.sh: corpus directory not found at ${CORPUS_ROOT}" >&2
    exit 2
fi

echo "== 1/3 toolchain ${CHANNEL} =="
# `rustup toolchain list` is local-only. We check before installing so a
# provisioned machine stays silent and idempotent, rather than re-resolving the
# channel over the network on every run.
if rustup toolchain list | grep -q "^${CHANNEL}-"; then
    echo "OK:      ${CHANNEL} already installed"
else
    echo "install: ${CHANNEL}"
    rustup toolchain install "${CHANNEL}" --profile minimal
fi

echo
echo "== 2/3 target ${TARGET} for ${CHANNEL} =="
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

echo
echo "== 3/3 prefetch fixture dependencies (for --offline builds) =="
# Every fixture `source/` is a self-contained crate with its own Cargo.lock.
# The probes and the eventual recompile step build with `--offline`, so the
# registry has to be warm first.
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
echo "toolchain: ${CHANNEL}, target: ${TARGET}, prefetched: ${prefetched}, skipped: ${skipped}"
echo
echo "Verify with:"
echo "  cargo test -p sordec-diffexec --test probe -- --ignored --nocapture"

exit 0
