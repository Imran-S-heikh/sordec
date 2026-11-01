#!/usr/bin/env bash
# build.sh — rebuild treasury.wasm from its source.
#
# Targets wasm32v1-none with the soroban-examples release profile; the
# toolchain is pinned by source/rust-toolchain.toml.

set -euo pipefail

FIXTURE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
SRC_DIR="${FIXTURE_DIR}/source"
WASM_NAME="treasury.wasm"
TARGET="wasm32v1-none"
TARGET_DIR="${CARGO_TARGET_DIR:-${SRC_DIR}/target}"

cd "${SRC_DIR}"
cargo build --release --target "${TARGET}"

BUILT_WASM="${TARGET_DIR}/${TARGET}/release/treasury.wasm"
if [[ ! -f "${BUILT_WASM}" ]]; then
    echo "build.sh: expected output not found at ${BUILT_WASM}" >&2
    exit 1
fi

cp "${BUILT_WASM}" "${FIXTURE_DIR}/${WASM_NAME}"
sha256sum "${FIXTURE_DIR}/${WASM_NAME}" | awk '{print $1}' > "${FIXTURE_DIR}/${WASM_NAME}.sha256"

echo "built: ${FIXTURE_DIR}/${WASM_NAME}"
echo "sha256: $(cat "${FIXTURE_DIR}/${WASM_NAME}.sha256")"
echo "size:   $(wc -c < "${FIXTURE_DIR}/${WASM_NAME}") bytes"
