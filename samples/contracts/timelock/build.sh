#!/usr/bin/env bash
# build.sh — rebuild timelock.wasm from vendored source.

set -euo pipefail

FIXTURE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
SRC_DIR="${FIXTURE_DIR}/source"
WASM_NAME="timelock.wasm"
TARGET="wasm32v1-none"

cd "${SRC_DIR}"
cargo build --release --target "${TARGET}"

BUILT_WASM="target/${TARGET}/release/soroban_timelock_contract.wasm"
if [[ ! -f "${BUILT_WASM}" ]]; then
    echo "build.sh: expected output not found at ${BUILT_WASM}" >&2
    exit 1
fi

cp "${BUILT_WASM}" "${FIXTURE_DIR}/${WASM_NAME}"
sha256sum "${FIXTURE_DIR}/${WASM_NAME}" | awk '{print $1}' > "${FIXTURE_DIR}/${WASM_NAME}.sha256"

echo "built: ${FIXTURE_DIR}/${WASM_NAME}"
echo "sha256: $(cat "${FIXTURE_DIR}/${WASM_NAME}.sha256")"
echo "size:   $(wc -c < "${FIXTURE_DIR}/${WASM_NAME}") bytes"
