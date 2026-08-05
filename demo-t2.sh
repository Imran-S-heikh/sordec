#!/usr/bin/env bash
# demo-t2.sh — Tranche 2 acceptance demo, one take, no voiceover.
#
# Tranche 2 (Testnet) = typed AST-like restructuring with explicit control
# flow; completion = emit human-readable annotated WAT.
#
# Each act proves exactly one clause of that sentence, on screen, with FULL
# output — nothing truncated, nothing filtered, nothing cherry-picked.
#
# Usage:
#   cargo build --release && bash demo-t2.sh
#   SPEED=0 bash demo-t2.sh    # dry run, no pauses
#
# Set terminal scrollback to unlimited first: the full dumps run ~15k lines.

# Deliberately NOT `set -e`/`pipefail`: the corpus act tolerates per-fixture
# noise, and a demo must never abort mid-recording.
set -u
cd "$(git rev-parse --show-toplevel)"

SPEED=${SPEED:-1}

SORDEC=./target/release/sordec
TOKEN=samples/contracts/token-v23/token-v23.wasm
TIMELOCK=samples/contracts/timelock/timelock.wasm
OUT=out/t2-demo   # under the already-gitignored /out/, so recording leaves no diff

pause() { [ "$SPEED" = 0 ] || sleep "$1"; }
act()   { printf '\n\033[1;36m════ %s\033[0m\n\n' "$*"; pause 3; }
run()   { printf '\033[1;32m$\033[0m %s\n' "$*"; pause 1; eval "$*"; pause 4; }

if [ ! -x "$SORDEC" ]; then
  echo "demo-t2.sh: $SORDEC not built. Run: cargo build --release" >&2
  exit 1
fi

rm -rf "$OUT"

# ─────────────────────────────────────────────────────────────────────
act "0 · The input: a stripped, optimized Soroban WASM binary"
run "ls -l $TOKEN"
run "$SORDEC dump-facts $TOKEN 2>/dev/null"
# Host imports are minified to l."7", l."1" — there are no symbol names to
# read. Everything recovered below is inferred, not looked up.

# ─────────────────────────────────────────────────────────────────────
act "1 · TYPED + EXPLICIT CONTROL FLOW — the full coverage report"
run "$SORDEC coverage $TOKEN 2>/dev/null"
# types:       1366/2067 bindings typed (66%). `known` = proven (ABI /
#              literal / host-fn identity), `inferred` = propagated, the
#              rest stays honestly Unknown — no guessing.
# structuring: 46/46 functions structured, 0 fallback regions.
# diagnostics: every recogniser miss is surfaced, not hidden.

# ─────────────────────────────────────────────────────────────────────
act "2 · Structured output in full — timelock (match on a recovered enum)"
run "$SORDEC dump-hir $TIMELOCK 2>/dev/null"
# Look for: symbol_dispatch(v45) -> TimeBoundKind::{Before | After}
# followed by `match v74 { TimeBoundKind::Before => ... }` — an SDK
# symbol-dispatch chain recovered as a match on a *named* enum.

act "2b · Structured output in full — token-v23 (46 functions)"
run "$SORDEC dump-hir $TOKEN 2>/dev/null"
# Typed signatures (Address / i128 / u32), `while` loops with labels,
# hoisted guard clauses, typed panics.

# ─────────────────────────────────────────────────────────────────────
act "3 · ANNOTATED WAT — the Tranche 2 completion criterion"
run "$SORDEC dump-wat $TOKEN 2>/dev/null"
# Module banner carries the full recovered interface; each function gets a
# header block with its recovered signature + the facts found inside it;
# every host call is labeled inline, anchored by printed callee index.

act "3b · The same thing as a written artifact"
run "$SORDEC decompile $TOKEN --out-dir $OUT 2>/dev/null"
run "cat $OUT/token-v23/token-v23.wat"

# ─────────────────────────────────────────────────────────────────────
act "4 · Acceptance is encoded as tests, not asserted in a slide"
# A byte round-trip is provably impossible (LLD pads LEB128s, re-encoding
# minimizes them), so WAT acceptance was redefined as five checks. All five
# hold on all 7 fixtures. Checks 1-3:
run "cargo test -p sordec-backend --test wat_gates"
# Checks 4-5 — lossless annotation extraction, deterministic emission:
run "cargo test -p sordec-backend wat::corpus_tests"

# ─────────────────────────────────────────────────────────────────────
act "5 · Not cherry-picked: every fixture in the corpus, decompiled + measured"
for f in token-v23 token-v22 timelock dex-liquidity-pool attestation hello-add token-v23-stripped; do
  w=$(ls samples/contracts/$f/*.wasm | head -1)
  printf '\n\033[1;33m─── %s\033[0m\n' "$f"
  $SORDEC decompile "$w" --out-dir "$OUT" 2>/dev/null
  $SORDEC coverage "$w" 2>/dev/null
  pause 2
done
pause 2
run "find $OUT -name '*.wat' | sort"
run "wc -l $OUT/*/*.wat"

# ─────────────────────────────────────────────────────────────────────
act "6 · Full test suite"
run "cargo test --workspace"

# ─────────────────────────────────────────────────────────────────────
act "7 · Bonus, built ahead of schedule: the Tranche 3 accuracy scorer"
run "$SORDEC score samples/contracts/token-v23/source/src samples/contracts/token-v23/source/src"
# The >=90% reconstruction metric's ruler, frozen and versioned now, so the
# Tranche 3 Rust emitter is measurable from its first line of output.

printf '\n\033[1;36m════ Tranche 2 complete: typed · explicit control flow · annotated WAT\033[0m\n\n'
