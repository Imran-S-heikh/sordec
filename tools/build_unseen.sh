#!/usr/bin/env bash
# Build the *unseen* corpus: third-party contracts from real projects, held to
# the same layout as the held-out set so `heldout_bench.rs` can score either.
#
#   SORDEC_HELDOUT_DIR=~/.cache/sordec-unseen \
#     cargo test --release -p sordec --test heldout_bench -- --ignored --nocapture
#
# Why a third set. `samples/contracts` is what every recognizer was built
# against. The held-out set is Stellar's own `soroban-examples` — never tuned
# on, but written by one author in one house style, each contract a single
# self-contained crate. Neither resembles what people actually deploy: a
# contract built on somebody else's library, where much of the binary is code
# the contract's own source never contains. That gap is what this set measures,
# and the two members were picked to bracket it:
#
#   merkle-voting   90 lines over OpenZeppelin's stellar-contracts. Nearly all
#                   of the binary is library. Scores 0.3595 — and the loss is
#                   mostly the scorer's basis, not the reconstruction (recall
#                   is 1.0000 on types and 0.8000 on semantic facts; it is
#                   precision that collapses, against a basis that cannot see
#                   the dependency).
#   phoenix-vesting 1263 lines of mainnet DeFi. Mostly self-contained. Scores
#                   0.6054 — and here the loss is ours: semantic precision is
#                   0.9375 but recall is 0.4545, because enum-key naming lands
#                   0/7 and every missed fact is a storage op we could not name
#                   the key of.
#
# Layout, per contract:
#   <out>/<name>/<name>.wasm
#   <out>/<name>/source -> the crate dir inside its checkout
#
# `source` is a symlink, not a copy, and that is deliberate. The scorer's
# macro-expanded basis shells out to `cargo expand`, which needs a manifest
# that resolves — and both crates inherit from a workspace and use path
# dependencies. A copied `source/` would silently fail to expand and degrade to
# the pre-expansion basis, which is a different (and much worse) measurement
# wearing the same number. Keep the checkouts.
#
# Usage: tools/build_unseen.sh [out dir] [target dir]
set -eu
OUT=${1:-$HOME/.cache/sordec-unseen}
export CARGO_TARGET_DIR=${2:-$HOME/.cache/sordec-heldout-target}
CHECKOUTS=${SORDEC_CHECKOUT_DIR:-$HOME/.cache}

# Pinned: these scores are only comparable against the same source.
OZ_REPO=https://github.com/OpenZeppelin/stellar-contracts
OZ_REF=a5bd8cbd3d0bb8efbd5cf5e2edf9734f87e47640   # 2026-09-18
PX_REPO=https://github.com/Phoenix-Protocol-Group/phoenix-contracts
PX_REF=aa9bfc000166e3ccdc30281b5181bbd8046fd35d   # 2026-07-04

clone_at() { # repo ref dest
  [ -d "$3/.git" ] && return 0
  git clone --quiet "$1" "$3"
  git -C "$3" checkout --quiet "$2"
}

place() { # name wasm-path crate-dir
  mkdir -p "$OUT/$1"
  cp "$2" "$OUT/$1/$1.wasm"
  ln -sfn "$3" "$OUT/$1/source"
  echo "ok   $1  ($(stat -c%s "$OUT/$1/$1.wasm") bytes)"
}

mkdir -p "$OUT"

# ---------------------------------------------------------------- OpenZeppelin
OZ=$CHECKOUTS/oz-stellar
clone_at "$OZ_REPO" "$OZ_REF" "$OZ"
# soroban-sdk's `experimental_spec_shaking_v2` refuses to build outside
# `stellar contract build` from stellar-cli 25.2.0+. Dropping it keeps the
# FULL contract spec, which flatters interface recovery: a shaken spec carries
# fewer dependency types, so the precision penalty would be smaller than what
# we report. Noted so the number is read with that thumb on the scale.
sed -i 's/^soroban-sdk = { version = "27.0.2", features = \[$/soroban-sdk = { version = "27.0.2" }/' "$OZ/Cargo.toml"
sed -i '/^    "experimental_spec_shaking_v2",$/d; /^\] }$/d' "$OZ/Cargo.toml"
# The contract is what a reconstruction is scored against, not its tests.
rm -f "$OZ/examples/merkle-voting/src/test.rs"
(cd "$OZ" && cargo build -q --release --target wasm32v1-none -p merkle-voting-example)
place merkle-voting \
  "$CARGO_TARGET_DIR/wasm32v1-none/release/merkle_voting_example.wasm" \
  "$OZ/examples/merkle-voting"

# --------------------------------------------------------------------- Phoenix
PX=$CHECKOUTS/phoenix
clone_at "$PX_REPO" "$PX_REF" "$PX"
# Phoenix pins 1.81, which we do not carry; `ethnum` then fails to compile on
# current stable (E0512, a 0-bit -> 8-bit transmute std tightened). 1.87 is the
# newest installed toolchain that builds the workspace. Note the reconstruction
# itself needs *stable* to check — its dependency floor outranks 1.87 — so the
# two sides of this measurement do not share a toolchain.
printf '[toolchain]\nchannel = "1.87"\ntargets = ["wasm32-unknown-unknown"]\ncomponents = ["rustfmt", "clippy"]\nprofile = "minimal"\n' \
  > "$PX/rust-toolchain.toml"
rustup target add wasm32-unknown-unknown --toolchain 1.87 >/dev/null 2>&1 || true
# vesting/src/lib.rs `contractimport!`s the token wasm from a path relative to
# the workspace, which CARGO_TARGET_DIR moves out from under it. Build the
# token first and put it back where the macro looks.
(cd "$PX" && cargo +1.87 build -q --release --target wasm32-unknown-unknown -p soroban-token-contract)
mkdir -p "$PX/target/wasm32-unknown-unknown/release"
cp "$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/soroban_token_contract.wasm" \
   "$PX/target/wasm32-unknown-unknown/release/"
rm -rf "$PX/contracts/vesting/src/tests.rs" "$PX/contracts/vesting/src/tests"
(cd "$PX" && cargo +1.87 build -q --release --target wasm32-unknown-unknown -p phoenix-vesting)
place phoenix-vesting \
  "$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/phoenix_vesting.wasm" \
  "$PX/contracts/vesting"

echo
echo "unseen corpus at $OUT — score it with:"
echo "  SORDEC_HELDOUT_DIR=$OUT cargo test --release -p sordec --test heldout_bench -- --ignored --nocapture"
