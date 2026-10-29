#!/usr/bin/env bash
# Build the soroban-examples contracts that tools/build_heldout.sh skips:
# multi-contract folders (one level deeper), contracts that import another
# contract's wasm, and the three the vendored corpus was tuned on (current
# SDK 27 build, not the 22/23 builds in samples/contracts).
#
# Same layout as the held-out set: <out>/<name>/<name>.wasm + source/{Cargo.toml,src}
set -u
EX=$HOME/.cache/soroban-examples
EXTRA=$HOME/.cache/sordec-examples-extra
TUNED=$HOME/.cache/sordec-examples-tuned
LOG=$HOME/.cache/sordec-build-logs/examples-extra
mkdir -p "$EXTRA" "$TUNED" "$LOG"
export CARGO_TARGET_DIR=$HOME/.cache/sordec-heldout-target
REL=$CARGO_TARGET_DIR/wasm32v1-none/release

# build <out root> <name> <crate dir under EX> <wasm stem>
build() {
  local out=$1 name=$2 crate=$EX/$3 stem=$4
  if (cd "$crate" && CARGO_BUILD_JOBS=6 nice -n 19 ionice -c3 \
        cargo build -q --release --target wasm32v1-none) >"$LOG/$name.log" 2>&1 \
      && [ -f "$REL/$stem.wasm" ]; then
    mkdir -p "$out/$name/source"
    cp "$REL/$stem.wasm" "$out/$name/$name.wasm"
    cp "$crate/Cargo.toml" "$out/$name/source/"
    rm -rf "$out/$name/source/src"
    cp -r "$crate/src" "$out/$name/source/"
    rm -f "$out/$name/source/src/test.rs"
    echo "ok   $name ($(stat -c %s "$out/$name/$name.wasm") bytes)"
  else
    echo "FAIL $name: $(grep -m1 '^error' "$LOG/$name.log")"
  fi
}

# stage <wasm stem> <path>: put a built wasm where a contractimport! expects it
stage() { mkdir -p "$(dirname "$2")"; cp "$REL/$1.wasm" "$2"; }

# --- dependencies first, staged where the importers look for them
build "$EXTRA" cross_contract_a cross_contract/contract_a soroban_cross_contract_a_contract
stage soroban_cross_contract_a_contract "$EX/cross_contract/contract_a/target/wasm32v1-none/release/soroban_cross_contract_a_contract.wasm"
stage soroban_atomic_swap_contract "$EX/atomic_swap/target/wasm32v1-none/release/soroban_atomic_swap_contract.wasm"
build "$EXTRA" groth16_bls12_381_verifier groth16_verifier/contracts/bls12_381_verifier bls12_381_verifier
stage bls12_381_verifier "$EX/groth16_verifier/target/wasm32v1-none/release/bls12_381_verifier.wasm"

# --- the rest
build "$EXTRA" cross_contract_b cross_contract/contract_b soroban_cross_contract_b_contract
build "$EXTRA" atomic_multiswap atomic_multiswap soroban_atomic_multiswap_contract
build "$EXTRA" groth16_bn254_verifier groth16_verifier/contracts/bn254_verifier bn254_verifier
build "$EXTRA" deployer deployer/deployer soroban_deployer_contract
build "$EXTRA" deployer_contract deployer/contract soroban_deployer_test_contract
build "$EXTRA" multisig_1_of_n_account multisig_1_of_n_account/contract soroban_multisig_1_of_n_account_contract
build "$EXTRA" privacy_pools privacy-pools/contract privacy_pools
build "$EXTRA" upgradeable_old_contract upgradeable_contract/old_contract soroban_upgradeable_contract_old_contract
build "$EXTRA" upgradeable_new_contract upgradeable_contract/new_contract soroban_upgradeable_contract_new_contract
build "$EXTRA" workspace_contract_a workspace/contract_a soroban_workspace_contract_a
build "$EXTRA" workspace_contract_b workspace/contract_b soroban_workspace_contract_b

build "$TUNED" liquidity_pool liquidity_pool soroban_liquidity_pool_contract
build "$TUNED" timelock timelock soroban_timelock_contract
build "$TUNED" token token soroban_token_contract
