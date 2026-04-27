#!/usr/bin/env bash
# verify-fixtures.sh — verify committed WASM bytes match their sha256 sidecars.
#
# This script does NOT rebuild from source. Rebuilding produces non-bit-stable
# bytes across machines (cargo + rustc embed build paths, parallelism is
# non-deterministic, etc.). The committed WASM is the source of truth; this
# script catches accidental corruption / tampering.
#
# Per-fixture rebuild lives in `samples/contracts/<name>/build.sh`.
#
# Exit codes:
#   0 — every fixture's WASM matches its sha256 sidecar
#   1 — at least one mismatch, or a sidecar is missing
#   2 — usage / environment error (sha256sum not found, etc.)

set -euo pipefail

# Resolve repo root from this script's location, regardless of CWD.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." &>/dev/null && pwd)"
CORPUS_ROOT="${REPO_ROOT}/samples/contracts"

if ! command -v sha256sum >/dev/null 2>&1; then
    echo "verify-fixtures.sh: sha256sum not found in PATH" >&2
    exit 2
fi

if [[ ! -d "${CORPUS_ROOT}" ]]; then
    echo "verify-fixtures.sh: corpus directory not found at ${CORPUS_ROOT}" >&2
    exit 2
fi

# Find every <name>.wasm.sha256 — for each, recompute sha256 of the sibling
# .wasm and compare against the committed sidecar. Find -print0 + read -d ''
# is paranoia for paths with spaces (the corpus shouldn't have any, but cheap
# to be correct).
checked=0
failed=0
missing=0

while IFS= read -r -d '' sidecar; do
    wasm="${sidecar%.sha256}"
    fixture_name="$(basename "$(dirname "${wasm}")")"
    if [[ ! -f "${wasm}" ]]; then
        echo "MISSING: ${fixture_name}: ${wasm} not found (sidecar exists)" >&2
        missing=$((missing + 1))
        continue
    fi

    expected="$(awk '{print $1}' "${sidecar}")"
    actual="$(sha256sum "${wasm}" | awk '{print $1}')"

    if [[ "${expected}" == "${actual}" ]]; then
        echo "OK:      ${fixture_name}"
    else
        echo "FAIL:    ${fixture_name}: expected ${expected}, got ${actual}" >&2
        failed=$((failed + 1))
    fi
    checked=$((checked + 1))
done < <(find "${CORPUS_ROOT}" -mindepth 2 -maxdepth 3 -name '*.wasm.sha256' -print0)

echo "----"
echo "verified: ${checked}, failed: ${failed}, missing: ${missing}"

if (( failed > 0 || missing > 0 )); then
    exit 1
fi

# Empty corpus is fine — early in Task 1.6 there are no fixtures yet.
exit 0
