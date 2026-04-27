#!/usr/bin/env bash
# build.sh — rebuild token-v23.wasm from vendored source.
#
# Reproducibility caveat: cargo + rustc embed build paths and other
# environmental bits into the WASM. A locally-rebuilt WASM may differ
# byte-for-byte from the committed sample; that's expected. The committed
# WASM is the source of truth, sha256-verified by tools/verify-fixtures.sh.
# This script's job is to prove the recipe still works, not to produce
# bit-identical output across machines.

set -euo pipefail

FIXTURE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
SRC_DIR="${FIXTURE_DIR}/source"
WASM_NAME="token-v23.wasm"
TARGET="wasm32v1-none"

# rustup will honor source/rust-toolchain.toml automatically and install
# rustc 1.89 + the wasm32v1-none target on demand.
cd "${SRC_DIR}"
cargo build --release --target "${TARGET}"

# Cargo emits the WASM under target/<triple>/release/<crate-name>.wasm
# where <crate-name> uses underscores not hyphens.
BUILT_WASM="target/${TARGET}/release/soroban_token_contract.wasm"
if [[ ! -f "${BUILT_WASM}" ]]; then
    echo "build.sh: expected output not found at ${BUILT_WASM}" >&2
    exit 1
fi

cp "${BUILT_WASM}" "${FIXTURE_DIR}/${WASM_NAME}"
sha256sum "${FIXTURE_DIR}/${WASM_NAME}" | awk '{print $1}' > "${FIXTURE_DIR}/${WASM_NAME}.sha256"

echo "built: ${FIXTURE_DIR}/${WASM_NAME}"
echo "sha256: $(cat "${FIXTURE_DIR}/${WASM_NAME}.sha256")"
echo "size:   $(wc -c < "${FIXTURE_DIR}/${WASM_NAME}") bytes"
