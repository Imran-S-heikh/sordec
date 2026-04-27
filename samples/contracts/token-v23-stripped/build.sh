#!/usr/bin/env bash
# build.sh — rebuild token-v23-stripped.wasm from vendored source.
#
# Same build recipe as token-v23/, plus a final `wasm-tools strip --all`
# pass that removes every custom section (including the Soroban-specific
# `contractmetav0` and `contractspecv0` sections, plus `name`, `producers`,
# etc). This simulates a mainnet-deployed contract that has been through
# `stellar contract optimize` — the shape of WASM the decompiler will
# encounter on production contracts where developers chose to drop metadata.

set -euo pipefail

FIXTURE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
SRC_DIR="${FIXTURE_DIR}/source"
WASM_NAME="token-v23-stripped.wasm"
TARGET="wasm32v1-none"

if ! command -v wasm-tools >/dev/null 2>&1; then
    echo "build.sh: wasm-tools not found in PATH (install via 'cargo install wasm-tools')" >&2
    exit 1
fi

cd "${SRC_DIR}"
cargo build --release --target "${TARGET}"

BUILT_WASM="target/${TARGET}/release/soroban_token_contract.wasm"
if [[ ! -f "${BUILT_WASM}" ]]; then
    echo "build.sh: expected output not found at ${BUILT_WASM}" >&2
    exit 1
fi

# Strip all custom sections. `--all` is more aggressive than the default
# (which preserves `name`/`component-type`/`dylink.0`); we want a fully
# stripped contract to mirror what gets deployed.
wasm-tools strip --all "${BUILT_WASM}" -o "${FIXTURE_DIR}/${WASM_NAME}"

sha256sum "${FIXTURE_DIR}/${WASM_NAME}" | awk '{print $1}' > "${FIXTURE_DIR}/${WASM_NAME}.sha256"

echo "built: ${FIXTURE_DIR}/${WASM_NAME}"
echo "sha256: $(cat "${FIXTURE_DIR}/${WASM_NAME}.sha256")"
echo "size:   $(wc -c < "${FIXTURE_DIR}/${WASM_NAME}") bytes"
