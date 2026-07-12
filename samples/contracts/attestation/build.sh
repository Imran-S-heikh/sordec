#!/usr/bin/env bash
# build.sh — rebuild attestation.wasm from vendored source.
#
# Targets wasm32-unknown-unknown (matching the token fixtures). The
# source is original, purpose-built for the sordec corpus; see
# source/VENDORED_FROM.

set -euo pipefail

FIXTURE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
SRC_DIR="${FIXTURE_DIR}/source"
WASM_NAME="attestation.wasm"
TARGET="wasm32-unknown-unknown"

cd "${SRC_DIR}"
cargo build --release --target "${TARGET}"

BUILT_WASM="target/${TARGET}/release/attestation.wasm"
if [[ ! -f "${BUILT_WASM}" ]]; then
    echo "build.sh: expected output not found at ${BUILT_WASM}" >&2
    exit 1
fi

cp "${BUILT_WASM}" "${FIXTURE_DIR}/${WASM_NAME}"
sha256sum "${FIXTURE_DIR}/${WASM_NAME}" | awk '{print $1}' > "${FIXTURE_DIR}/${WASM_NAME}.sha256"

echo "built: ${FIXTURE_DIR}/${WASM_NAME}"
echo "sha256: $(cat "${FIXTURE_DIR}/${WASM_NAME}.sha256")"
echo "size:   $(wc -c < "${FIXTURE_DIR}/${WASM_NAME}") bytes"
