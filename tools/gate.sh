#!/usr/bin/env bash
# gate.sh — the full local acceptance gate for a change.
#
# Runs, in order, every check a commit must pass. Stops on the first
# failure. Run from anywhere; it resolves the repo root itself.
#
# The release-build step is load-bearing and easy to miss: `cargo clippy`
# runs in the *dev* profile, so it never sees warnings that only exist in a
# release build or under `#[cfg(not(debug_assertions))]`. A plain
# warnings-as-errors release build is the only step that catches that class
# (surfaced by the Phase 3 closeout audit — an unused import that was live
# in dev but dead in release).
#
# Exit codes:
#   0 — every step passed
#   non-zero — the first failing step's exit code

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." &>/dev/null && pwd)"
cd "${REPO_ROOT}"

echo "== 1/6 build (workspace) =="
cargo build --workspace

echo "== 2/6 build (release, warnings-as-errors) — the dev-profile blind spot =="
RUSTFLAGS="-D warnings" cargo build --release --workspace

echo "== 3/6 test (workspace) =="
cargo test --workspace

echo "== 4/6 clippy (all features, all targets, warnings-as-errors) =="
cargo clippy --workspace --all-features --all-targets -- -D warnings

echo "== 5/6 doc (no deps, must be warning-free) =="
cargo doc --workspace --no-deps

echo "== 6/6 fixtures =="
bash "${SCRIPT_DIR}/verify-fixtures.sh"

echo "== OK: all gate steps passed =="
