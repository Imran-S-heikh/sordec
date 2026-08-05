#!/usr/bin/env bash
# build-corpus.sh — rebuild contracts *with their symbol names intact*, so the
# signature catalogue has ground truth to be generated from.
#
# ## Why this exists
#
# A deployed Soroban contract is name-stripped: of 43 mainnet modules sampled,
# exactly one carried a `name` section. But rebuilding a contract with
# `profile.release.strip=false` reproduces its code section **byte-for-byte**
# while adding the names back — verified on token-v23, 46 bodies, identical
# SHA-256 over the concatenated bodies. Same code, with the answers attached.
#
# `siggen` fingerprints those labelled bodies to build the catalogue that the
# decompiler then uses on contracts it has never seen. Nothing produced here
# ships; it is a development instrument.
#
# ## Why the corpus is deliberately multi-author
#
# Matching measured 45-70% of library bytes between contracts by the same
# author, but only 6-29% between genuinely unrelated ones. Training on one
# organisation's contracts therefore produces a catalogue that looks far better
# than it is. The third-party set below spans five organisations on purpose,
# and `siggen validate` should always hold out a different author's contract
# than it trained on.
#
# ## Output
#
# One labelled `.wasm` per contract under $OUT/wasm/, flat, named for its
# origin. Build trees are deleted as we go: a full corpus is ~15 GB of
# `target/` and this machine runs at 96%.
#
# Exit codes:
#   0 — every requested contract built
#   1 — at least one contract failed to build (others still produced)
#   2 — usage / environment error

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." &>/dev/null && pwd)"

# Default outside the repo and outside /tmp. /tmp is swept by systemd-tmpfiles
# and a swept corpus silently becomes an empty catalogue.
OUT="${SORDEC_ORACLE_DIR:-${HOME}/.cache/sordec/oracle}"
LOCAL_ONLY=0
KEEP_TREES=0

usage() {
    cat <<'EOF'
usage: build-corpus.sh [--out DIR] [--local-only] [--keep-trees]

  --out DIR      where to write labelled wasm (default: ~/.cache/sordec/oracle,
                 or $SORDEC_ORACLE_DIR)
  --local-only   build only the in-repo fixtures; skip cloning third parties
  --keep-trees   do not delete each contract's target/ after extracting its
                 wasm (needs ~15 GB; the default reclaims as it goes)
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --out)         OUT="${2:?--out needs a directory}"; shift 2 ;;
        --local-only)  LOCAL_ONLY=1; shift ;;
        --keep-trees)  KEEP_TREES=1; shift ;;
        -h|--help)     usage; exit 0 ;;
        *)             echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

command -v cargo >/dev/null || { echo "cargo not found" >&2; exit 2; }
command -v git   >/dev/null || { echo "git not found" >&2; exit 2; }

SRC="${OUT}/src"
WASM="${OUT}/wasm"
mkdir -p "${SRC}" "${WASM}" || exit 2

FAILURES=0

# Build one crate tree with names retained.
#
# $1 label   output prefix
# $2 dir     crate/workspace root
# $3 target  wasm target triple
# $4.. pkgs  packages to build; empty means the whole workspace
#
# `--config` rather than editing the manifest: fixtures are pinned artefacts and
# third-party checkouts are not ours to modify.
build_one() {
    local label="$1" dir="$2" target="$3"; shift 3
    local pkgs=("$@")
    local target_dir="${SRC}/.target-${label}"
    local -a args=(build --release --target "${target}"
                   --config 'profile.release.strip=false'
                   --config 'profile.release.debug=1'
                   --target-dir "${target_dir}")
    local p
    for p in "${pkgs[@]}"; do args+=(-p "${p}"); done

    echo "==> ${label}"
    if ! (cd "${dir}" && cargo "${args[@]}" >/dev/null 2>&1); then
        echo "    BUILD FAILED (${label})" >&2
        FAILURES=$((FAILURES + 1))
    fi

    # Collect whatever did build — a partial workspace build is still useful
    # corpus, and several third-party workspaces have one crate that fails.
    local found=0 w base
    while IFS= read -r w; do
        base="$(basename "${w}")"
        cp -f "${w}" "${WASM}/${label}__${base}" && found=$((found + 1))
    done < <(find "${target_dir}/${target}/release" -maxdepth 1 -name '*.wasm' 2>/dev/null)
    echo "    ${found} wasm"

    [[ ${KEEP_TREES} -eq 1 ]] || rm -rf "${target_dir}"
}

# --- in-repo fixtures -------------------------------------------------------
# Always available and always same-author, which is why they are never a
# sufficient corpus on their own.
#
# The target is read from each fixture's own `build.sh` rather than assumed:
# the corpus spans SDK 22 and 23, and those use different wasm targets
# (`wasm32-unknown-unknown` before `wasm32v1-none`). Guessing one silently
# drops every fixture on the other.
for src in "${REPO_ROOT}"/samples/contracts/*/source; do
    [[ -d "${src}" ]] || continue
    fixture_dir="$(dirname "${src}")"
    name="$(basename "${fixture_dir}")"
    target="$(grep -ohE 'wasm32[a-z0-9-]*' "${fixture_dir}/build.sh" 2>/dev/null | head -1)"
    build_one "fixture-${name}" "${src}" "${target:-wasm32v1-none}"
done

if [[ ${LOCAL_ONLY} -eq 1 ]]; then
    echo
    echo "wrote $(find "${WASM}" -name '*.wasm' | wc -l) labelled modules to ${WASM}"
    [[ ${FAILURES} -eq 0 ]] || exit 1
    exit 0
fi

# --- third-party contracts --------------------------------------------------
# repo|target|packages(space-separated, empty = whole workspace)
#
# Packages are listed explicitly because a workspace's test crate enables
# soroban-sdk's `testutils` feature, which is `compile_error!` on a wasm
# target — building the workspace fails on crates we do not want anyway.
THIRD_PARTY=(
    "blend-capital/blend-contracts|wasm32-unknown-unknown|pool emitter pool-factory"
    "script3/soroban-governor|wasm32-unknown-unknown|soroban-votes"
    "CometDEX/comet-contracts-v1|wasm32-unknown-unknown|"
    "reflector-network/reflector-contract|wasm32v1-none|"
    "Consulting-Manao/tansu|wasm32v1-none|"
)

for spec in "${THIRD_PARTY[@]}"; do
    IFS='|' read -r repo target pkgs <<<"${spec}"
    name="$(basename "${repo}")"
    dir="${SRC}/${name}"
    if [[ ! -d "${dir}" ]]; then
        echo "==> cloning ${repo}"
        if ! git clone --depth 1 -q "https://github.com/${repo}" "${dir}" 2>/dev/null; then
            echo "    CLONE FAILED (${repo})" >&2
            FAILURES=$((FAILURES + 1))
            continue
        fi
    fi
    # shellcheck disable=SC2086  # deliberate word-splitting: pkgs is a list
    build_one "${name}" "${dir}" "${target}" ${pkgs}
done

echo
echo "wrote $(find "${WASM}" -name '*.wasm' | wc -l) labelled modules to ${WASM}"
[[ ${FAILURES} -eq 0 ]] || { echo "${FAILURES} target(s) failed" >&2; exit 1; }
