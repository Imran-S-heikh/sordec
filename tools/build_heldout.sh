#!/usr/bin/env bash
# Build a held-out corpus for crates/sordec/tests/heldout_bench.rs.
#
# Compiles every single-crate contract in a checkout of Stellar's
# soroban-examples to wasm and lays each out as
#   <out>/<name>/<name>.wasm
#   <out>/<name>/source/{Cargo.toml,src}
# The three examples the vendored corpus already contains (liquidity_pool,
# timelock, token) are left out: they are what the pipeline was tuned on.
# Workspace examples are skipped.
#
# Usage: tools/build_heldout.sh <soroban-examples checkout> <out dir> [target dir]
set -u
EX=${1:?soroban-examples checkout}
OUT=${2:?output dir}
export CARGO_TARGET_DIR=${3:-$OUT/../heldout-target}
mkdir -p "$OUT"
SKIP=" liquidity_pool timelock token "
for dir in "$EX"/*/; do
  name=$(basename "$dir")
  case "$SKIP" in *" $name "*) continue;; esac
  [ -f "$dir/Cargo.toml" ] && [ -d "$dir/src" ] || continue
  if grep -q '^\[workspace\]' "$dir/Cargo.toml"; then echo "skip $name (workspace)"; continue; fi
  pkg=$(grep -m1 '^name' "$dir/Cargo.toml" | sed 's/.*"\(.*\)".*/\1/' | tr - _)
  log=$(mktemp)
  if (cd "$dir" && cargo build -q --release --target wasm32v1-none >"$log" 2>&1) \
      && [ -f "$CARGO_TARGET_DIR/wasm32v1-none/release/$pkg.wasm" ]; then
    mkdir -p "$OUT/$name/source"
    cp "$CARGO_TARGET_DIR/wasm32v1-none/release/$pkg.wasm" "$OUT/$name/$name.wasm"
    cp "$dir/Cargo.toml" "$OUT/$name/source/"
    cp -r "$dir/src" "$OUT/$name/source/"
    # The contract, not its tests, is what the reconstruction is scored against.
    rm -f "$OUT/$name/source/src/test.rs"
    echo "ok   $name"
  else
    echo "FAIL $name: $(grep -m1 '^error' "$log")"
  fi
  rm -f "$log"
done
