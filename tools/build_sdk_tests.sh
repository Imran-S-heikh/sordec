#!/usr/bin/env bash
# Build the Stellar SDK's own test contracts (soroban-sdk 26.0.1) as a
# measurement set shaped like the one tools/build_heldout.sh produces.
#
# Compiles every contract crate under tests/ in a checkout of
# stellar/rs-soroban-sdk and lays each out as
#   <out>/<name>/<name>.wasm
#   <out>/<name>/source/{Cargo.toml,src}
# <name> is the test crate's directory name (udt, errors, ...).
#
# Pinned so the set is reproducible:
#   SDK commit  f52b6aad85f18c5e312ff3f60e57cb613274e6bb  (soroban-sdk 26.0.1)
#   rustc       1.95.0 (what these contracts' metadata records)
#   target      wasm32v1-none
# Builds run inside the SDK workspace so the workspace's release profile and
# locked dependency versions apply, one crate at a time, sharing one target dir.
#
# Skipped: crates that are not cdylib contracts (libraries), and anything whose
# wasm has no contractspecv0 section. Each skip is reported. A test.rs next to
# lib.rs is dropped from the copied source, as in build_heldout.sh.
#
# Usage: tools/build_sdk_tests.sh [sdk checkout] [out dir] [target dir]
#   defaults: ~/.cache/rs-soroban-sdk  ~/.cache/sordec-sdk26
#             ~/.cache/sordec-targets/sdk26-build
# (spec_shaking_v1/src/lib.rs is a symlink to v2's; it is copied as a real file.)
# Heavy: wrap in systemd-run / nice on a small machine.
set -u
SDK=${1:-$HOME/.cache/rs-soroban-sdk}
OUT=${2:-$HOME/.cache/sordec-sdk26}
export CARGO_TARGET_DIR=${3:-$HOME/.cache/sordec-targets/sdk26-build}
export RUSTUP_TOOLCHAIN=1.95.0
# The workspace turns on soroban-sdk's spec-shaking-v2 feature, whose build script
# insists on `stellar contract build`; that tool just sets this variable.
export SOROBAN_SDK_BUILD_SYSTEM_SUPPORTS_SPEC_SHAKING_V2=1
COMMIT=f52b6aad85f18c5e312ff3f60e57cb613274e6bb

if [ ! -d "$SDK/.git" ]; then
  git clone -q --filter=blob:none https://github.com/stellar/rs-soroban-sdk "$SDK" || exit 1
fi
git -C "$SDK" checkout -q "$COMMIT" || exit 1
rustup toolchain list | grep -q '^1\.95\.0' || rustup toolchain install 1.95.0 --profile minimal
rustup target add wasm32v1-none --toolchain 1.95.0 >/dev/null 2>&1
# import_contract and spec_shaking_* contractimport! sibling wasms from <sdk>/target.
mkdir -p "$OUT" "$CARGO_TARGET_DIR"
[ -e "$SDK/target" ] || ln -s "$CARGO_TARGET_DIR" "$SDK/target"

for dir in "$SDK"/tests/*/; do
  name=$(basename "$dir")
  [ -f "$dir/Cargo.toml" ] && [ -d "$dir/src" ] || continue
  if ! grep -q 'crate-type.*cdylib' "$dir/Cargo.toml"; then echo "skip $name (not a cdylib contract)"; continue; fi
  pkg=$(grep -m1 '^name' "$dir/Cargo.toml" | sed 's/.*"\(.*\)".*/\1/')
  wasm="$CARGO_TARGET_DIR/wasm32v1-none/release/$(echo "$pkg" | tr - _).wasm"
  log=$(mktemp)
  if (cd "$SDK" && cargo build -q --release --target wasm32v1-none -p "$pkg" >"$log" 2>&1) && [ -f "$wasm" ]; then
    if ! grep -aq contractspecv0 "$wasm"; then echo "skip $name (no contractspecv0 section)"
    else
      rm -rf "${OUT:?}/$name"; mkdir -p "$OUT/$name/source"
      cp "$wasm" "$OUT/$name/$name.wasm"
      cp "$dir/Cargo.toml" "$OUT/$name/source/"
      cp -rL "$dir/src" "$OUT/$name/source/"
      rm -f "$OUT/$name/source/src/test.rs"
      echo "ok   $name"
    fi
  else
    echo "FAIL $name: $(grep -m1 '^error' "$log")"
  fi
  rm -f "$log"
done
