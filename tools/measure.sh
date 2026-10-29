#!/usr/bin/env bash
# measure.sh — decompile every contract in the measurement sets, cargo-check
# each reconstruction, and report compile/errors/holes per set, optionally
# against a baseline run of the same script.
#
# This is the change gate for the decompiler's output: the unit tests say a
# pass does what its tests describe, this says what it did to every contract
# we measure on. Run it on `main` once to make a baseline, then on a branch
# with `--baseline` to see exactly which reconstructions moved.
#
# Sets. Each root holds `<root>/<name>/<name>.wasm` (the layout
# tools/build_heldout.sh produces; samples/contracts is the same shape).
# A root that does not exist is skipped with a note, never an error.
#
#   corpus   samples/contracts
#   heldout  $SORDEC_HELDOUT_DIR  (default ~/.cache/sordec-heldout)
#   extra    $SORDEC_EXTRA_DIR    (default ~/.cache/sordec-examples-extra)
#   unseen   $SORDEC_UNSEEN_DIR   (default ~/.cache/sordec-unseen)
#   sdk26    $SORDEC_SDK26_DIR    (default ~/.cache/sordec-sdk26)
#
# Usage:
#   tools/measure.sh [--sets a,b,..] [--out DIR] [--baseline DIR] [--no-build] [--no-check] [--table]
#
#   --out DIR       where reconstructions and logs go (default ~/.cache/sordec-measure/<short commit>)
#   --baseline DIR  an earlier --out directory; prints what differs from it
#   --no-build      use $SORDEC_BIN (or target/release/sordec) as is
#   --no-check      skip cargo check (holes and lines only)
#   --table         also print the per-contract table
#
# Env: SORDEC_BIN (the decompiler; built with `cargo build --release -p sordec`
# when unset or when --no-build is absent), CARGO_TARGET_DIR (respected for
# that build), SORDEC_CHECK_TARGET (the shared target dir for the cargo checks,
# default ~/.cache/sordec-check-target; sharing it keeps each run to seconds
# per crate once soroban-sdk is built), CARGO_BUILD_JOBS (default 4).
#
# Run the whole script inside the capped scope on this machine:
#   systemd-run --user --scope --quiet -p MemoryHigh=8G -p MemoryMax=12G \
#     -p CPUQuota=1000% nice -n 19 ionice -c3 tools/measure.sh --baseline ...
#
# Output: $OUT/<set>/<name>/{Cargo.toml,src/lib.rs,<name>.wat}, logs under
# $OUT/logs/<set>/<name>.{decompile,check}.log, and $OUT/summary.tsv with one
# row per contract: set  name  compiles  errors  holes  lines.
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." &>/dev/null && pwd)"

SETS=corpus,heldout,extra,unseen,sdk26
OUT=""
BASELINE=""
BUILD=1
CHECK=1
TABLE=0
while [ $# -gt 0 ]; do
  case $1 in
    --sets) SETS=$2; shift 2 ;;
    --out) OUT=$2; shift 2 ;;
    --baseline) BASELINE=$2; shift 2 ;;
    --no-build) BUILD=0; shift ;;
    --no-check) CHECK=0; shift ;;
    --table) TABLE=1; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-4}
COMMIT=$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo nogit)
OUT=${OUT:-$HOME/.cache/sordec-measure/$COMMIT}
CHECK_TARGET=${SORDEC_CHECK_TARGET:-$HOME/.cache/sordec-check-target}

root_of() {
  case $1 in
    corpus) echo "$REPO_ROOT/samples/contracts" ;;
    heldout) echo "${SORDEC_HELDOUT_DIR:-$HOME/.cache/sordec-heldout}" ;;
    extra) echo "${SORDEC_EXTRA_DIR:-$HOME/.cache/sordec-examples-extra}" ;;
    unseen) echo "${SORDEC_UNSEEN_DIR:-$HOME/.cache/sordec-unseen}" ;;
    sdk26) echo "${SORDEC_SDK26_DIR:-$HOME/.cache/sordec-sdk26}" ;;
    *) echo "unknown set: $1" >&2; exit 2 ;;
  esac
}

# The decompiler: this tree's release build unless told otherwise.
if [ $BUILD -eq 1 ]; then
  echo "== building sordec ($COMMIT)"
  (cd "$REPO_ROOT" && cargo build --release -p sordec -q) || { echo "build failed" >&2; exit 1; }
  SORDEC_BIN=${CARGO_TARGET_DIR:-$REPO_ROOT/target}/release/sordec
else
  SORDEC_BIN=${SORDEC_BIN:-${CARGO_TARGET_DIR:-$REPO_ROOT/target}/release/sordec}
fi
[ -x "$SORDEC_BIN" ] || { echo "no decompiler at $SORDEC_BIN" >&2; exit 1; }

mkdir -p "$OUT/logs"
# A shared CARGO_TARGET_DIR means another checkout's build can overwrite
# `release/sordec` between our build and our run; measure the copy, so
# every reconstruction in this run comes from one binary.
cp "$SORDEC_BIN" "$OUT/sordec" && SORDEC_BIN=$OUT/sordec
IFS=, read -r -a set_list <<< "$SETS"
# A re-run of some sets replaces only their rows, so a set measured later
# (one that did not exist yet) joins an earlier run's summary.
if [ -f "$OUT/summary.tsv" ]; then
  keep=$(printf '%s\n' "${set_list[@]}" | paste -sd'|')
  grep -vE "^($keep)	" "$OUT/summary.tsv" > "$OUT/summary.tsv.new" || true
  mv "$OUT/summary.tsv.new" "$OUT/summary.tsv"
else
  : > "$OUT/summary.tsv"
fi
echo "== measuring $COMMIT with $SORDEC_BIN -> $OUT"

count_errors() { grep -E '^error(\[E[0-9]+\])?:' "$1" | grep -vcE 'could not compile|aborting due to'; }
for set in "${set_list[@]}"; do
  root=$(root_of "$set")
  if [ ! -d "$root" ]; then echo "-- $set: no root at $root, skipped"; continue; fi
  mkdir -p "$OUT/$set" "$OUT/logs/$set"
  for d in "$root"/*/; do
    n=$(basename "$d")
    [ -f "$d/$n.wasm" ] || continue
    dlog=$OUT/logs/$set/$n.decompile.log
    if ! "$SORDEC_BIN" decompile --force --quiet --out-dir "$OUT/$set" "$d/$n.wasm" >"$dlog" 2>&1; then
      printf '%s\t%s\tDECOMPILE-FAILED\t-\t-\t-\n' "$set" "$n" >> "$OUT/summary.tsv"; continue
    fi
    crate=$OUT/$set/$n
    holes=$(grep -c 'todo!(' "$crate/src/lib.rs")
    lines=$(wc -l < "$crate/src/lib.rs")
    if [ $CHECK -eq 1 ]; then
      clog=$OUT/logs/$set/$n.check.log
      touch "$crate/src/lib.rs"
      (cd "$crate" && CARGO_TARGET_DIR=$CHECK_TARGET cargo check -q) >"$clog" 2>&1
      if [ $? -eq 0 ]; then ok=yes; else ok=no; fi
      errs=$(count_errors "$clog")
    else
      ok=-; errs=-
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$set" "$n" "$ok" "$errs" "$holes" "$lines" >> "$OUT/summary.tsv"
  done
done

# Per-set summary, with the baseline's numbers beside it when given.
summarize() { # file set -> "a/b errors holes lines"
  awk -F'\t' -v s="$2" '$1==s { n++; if ($3=="yes") ok++; if ($4!="-") e+=$4; if ($5!="-") h+=$5; if ($6!="-") l+=$6 }
    END { if (n) printf "%d/%d\t%d\t%d\t%d", ok, n, e, h, l }' "$1"
}
echo
printf '%-8s %-9s %-7s %-7s %-7s' set compile errors holes lines
[ -n "$BASELINE" ] && printf '   | baseline: %-9s %-7s %-7s' compile errors holes
echo
for set in "${set_list[@]}"; do
  cur=$(summarize "$OUT/summary.tsv" "$set"); [ -z "$cur" ] && continue
  IFS=$'\t' read -r c e h l <<< "$cur"
  printf '%-8s %-9s %-7s %-7s %-7s' "$set" "$c" "$e" "$h" "$l"
  if [ -n "$BASELINE" ] && [ -f "$BASELINE/summary.tsv" ]; then
    base=$(summarize "$BASELINE/summary.tsv" "$set")
    if [ -n "$base" ]; then IFS=$'\t' read -r bc be bh bl <<< "$base"; printf '   | %-19s %-7s %-7s' "$bc" "$be" "$bh"; fi
  fi
  echo
done

if [ $TABLE -eq 1 ]; then
  echo; printf '%-8s %-30s %-5s %-6s %-6s %-6s\n' set contract ok errs holes lines
  awk -F'\t' '{ printf "%-8s %-30s %-5s %-6s %-6s %-6s\n", $1, $2, $3, $4, $5, $6 }' "$OUT/summary.tsv"
fi

if [ -n "$BASELINE" ]; then
  echo; echo "== reconstructions that differ from $BASELINE"
  changed=0
  for set in "${set_list[@]}"; do
    [ -d "$OUT/$set" ] || continue
    for crate in "$OUT/$set"/*/; do
      n=$(basename "$crate")
      b=$BASELINE/$set/$n/src/lib.rs
      if [ ! -f "$b" ]; then echo "  $set/$n: not in baseline"; changed=$((changed+1)); continue; fi
      if ! cmp -s "$crate/src/lib.rs" "$b"; then
        cur=$(awk -F'\t' -v s="$set" -v n="$n" '$1==s && $2==n {print $4"/"$5}' "$OUT/summary.tsv")
        was=$(awk -F'\t' -v s="$set" -v n="$n" '$1==s && $2==n {print $4"/"$5}' "$BASELINE/summary.tsv")
        echo "  $set/$n: errors/holes $was -> $cur  ($(diff "$b" "$crate/src/lib.rs" | grep -c '^[<>]') lines differ)"
        changed=$((changed+1))
      fi
    done
  done
  [ $changed -eq 0 ] && echo "  none — output byte-identical to the baseline"
fi
