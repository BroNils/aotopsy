#!/usr/bin/env bash
# Decompile every function in a libapp.so via aotopsy's decompile-native
# --all, in SEPARATE SHARDS (one fresh OS process per shard) instead of one
# long-running process. Built after repeated whole-VM crashes (WSL2) trying
# to run --all --max 0 as a single process against a real ~7800-function
# Flutter app build -- the exact root cause was never conclusively pinned
# down (heap stayed flat every time, ruling out a memory leak in the Go
# program itself), but splitting into independent process invocations
# means: (a) each run's resource/time footprint is bounded and predictable,
# (b) if one shard is ever killed for any reason, only that shard needs
# re-running, not the whole batch, and (c) progress survives incrementally
# on disk shard-by-shard rather than all-or-nothing.
#
# Usage:
#   tools/decompile_all_sharded.sh <aotopsy-binary> <libapp.so> <out-dir> [shard-size]
#
# Example:
#   tools/decompile_all_sharded.sh /tmp/aotopsy path/to/libapp.so /tmp/out 500

set -euo pipefail

AOTOPSY="${1:?usage: decompile_all_sharded.sh <aotopsy-binary> <libapp.so> <out-dir> [shard-size]}"
LIBAPP="${2:?missing libapp.so path}"
OUTDIR="${3:?missing output directory}"
SHARD_SIZE="${4:-500}"

mkdir -p "$OUTDIR/shards"
COMBINED="$OUTDIR/combined_all.dart"
: > "$COMBINED"

skip=0
shard_num=0
while true; do
  shard_num=$((shard_num + 1))
  shard_out="$OUTDIR/shards/shard_${shard_num}"
  echo "=== shard $shard_num: --skip $skip --max $SHARD_SIZE ==="

  # Each shard is its own process invocation -- a crash/kill here only
  # loses this one shard's progress, not everything before it.
  if ! "$AOTOPSY" _debug decompile-native \
        --lib "$LIBAPP" --all --skip "$skip" --max "$SHARD_SIZE" \
        --out "$shard_out" 2>&1 | tee "$OUTDIR/shard_${shard_num}.log"; then
    echo "shard $shard_num FAILED (see $OUTDIR/shard_${shard_num}.log) -- rerun just this shard with --skip $skip --max $SHARD_SIZE once fixed" >&2
    exit 1
  fi

  # "nothing to do" / 0 emitted means we've reached the end.
  if grep -q "nothing to do, this shard is past the end" "$OUTDIR/shard_${shard_num}.log"; then
    echo "reached the end of the binary's function list."
    break
  fi

  cat "$shard_out/combined.dart" >> "$COMBINED"
  skip=$((skip + SHARD_SIZE))
done

echo "=== done: combined output at $COMBINED ==="
wc -l "$COMBINED"
grep -c "^// === " "$COMBINED" || true
