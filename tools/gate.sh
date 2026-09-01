#!/usr/bin/env bash
# gate.sh — the full local acceptance gate for a change.
#
# Runs, in order, every check a commit must pass. Stops on the first
# failure. Run from anywhere; it resolves the repo root itself.
#
# The release step is load-bearing and easy to miss: `cargo clippy` runs in
# the *dev* profile, so it never sees warnings that only exist under
# `#[cfg(not(debug_assertions))]` (surfaced by the Phase 3 closeout audit —
# an unused import that was live in dev but dead in release). It is a
# `check`, not a `build`: warnings come out of the frontend, so checking
# raises exactly the same ones, and `[profile.release]` here is
# `lto = true, codegen-units = 1, opt-level = 3` — the full optimising build
# cost 124 s against 25 s for the check, on a one-file change, and produced
# nothing the gate reads. Verified rather than assumed: with the
# release-side use of `debug_validate`'s arguments removed, the check reports
# both unused variables as errors while dev clippy reports nothing.
#
# What that trades away: `check` does not run codegen, so a
# post-monomorphisation or link failure that only appears in a real release
# build would slip past. This crate has no `unsafe` and no const-generic
# machinery, which is why the trade is worth 100 s a run — but a release
# build belongs in CI, or before a tagged release, where its cost is paid
# once rather than per commit.
#
# Exit codes:
#   0 — every step passed
#   non-zero — the first failing step's exit code

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." &>/dev/null && pwd)"
cd "${REPO_ROOT}"

GATE_START=${SECONDS}

# Announce a step and time the previous one, so a slow gate says *which*
# part is slow instead of leaving it to be re-measured by hand.
STEP_START=${SECONDS}
step() {
    if [[ -n "${STEP_NAME:-}" ]]; then
        printf '   ↳ %s: %ds\n' "${STEP_NAME}" "$((SECONDS - STEP_START))"
    fi
    STEP_NAME="$1"
    STEP_START=${SECONDS}
    echo "== $1 =="
}

step "1/6 build (workspace)"
cargo build --workspace

step "2/6 check (release, warnings-as-errors) — the dev-profile blind spot"
# `--all-targets` so test code is checked under release cfg too, which the
# old `build --release` never covered.
RUSTFLAGS="-D warnings" cargo check --release --workspace --all-targets

step "3/6 test (workspace)"
cargo test --workspace

step "4/6 clippy (all features, all targets, warnings-as-errors)"
cargo clippy --workspace --all-features --all-targets -- -D warnings

step "5/6 doc (no deps, must be warning-free)"
# The step said "must be warning-free" for months while enforcing nothing —
# `cargo doc` exits 0 on broken intra-doc links, so the gate passed while
# emitting 26 warnings. A gate that reports clean while it is not will not
# catch the one warning that matters.
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps

step "6/6 fixtures"
bash "${SCRIPT_DIR}/verify-fixtures.sh"

step "done"
echo "== OK: all gate steps passed in $((SECONDS - GATE_START))s =="
