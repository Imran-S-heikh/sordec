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
# Two inputs are pinned, because each moves the scores on its own:
#
#   soroban-examples 1f5aeb5 (2026-09-10), the last SDK 27 revision. From
#   01a9a33 on, the examples are on soroban-sdk 28, whose build script
#   refuses to build outside `stellar contract build`, so every example fails.
#
#   rustc 1.97. Codegen differs between releases; built with 1.99, `pause`
#   falls from 1.0000 to 0.7059 and the mean from 0.7620 to 0.7525.
#
#   git clone https://github.com/stellar/soroban-examples ~/.cache/soroban-examples
#   git -C ~/.cache/soroban-examples checkout 1f5aeb5
#   RUSTUP_TOOLCHAIN=1.97 tools/build_heldout.sh ~/.cache/soroban-examples ~/.cache/sordec-heldout
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
    # The contract, not its tests, is what the reconstruction is scored
    # against. Emptied rather than deleted: every example declares a bare
    # `mod test;`, and without the file `cargo expand` fails with E0583, so
    # the scorer silently falls back to the pre-expansion basis (mean 0.7407
    # against 0.7620 on the expanded one).
    [ -f "$OUT/$name/source/src/test.rs" ] && : > "$OUT/$name/source/src/test.rs"
    echo "ok   $name"
  else
    echo "FAIL $name: $(grep -m1 '^error' "$log")"
  fi
  rm -f "$log"
done
