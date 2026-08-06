#!/bin/bash
# Test matrix: compare baseline (825e2f6) vs current (828eb5f) across all samples
# Avoids --all decompile (OOM). Uses timeout for each command.
set -u
BASELINE=/tmp/aotopsy_baseline
CURRENT=/tmp/aotopsy_current
OUTDIR="$(dirname "$0")/out/test_matrix"
mkdir -p "$OUTDIR"

# H-7 fix: Always build CURRENT from source before testing.
# The pre-built binary may be stale (predating commits being tested).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "Building current binary from source..."
( cd "$SCRIPT_DIR" && go build -o "$CURRENT" ./cmd/aotopsy/ ) || {
  echo "ERROR: build failed, cannot run test matrix"
  exit 1
}

# Samples: name|path
SAMPLES=(
  "compare_arm64|/home/user/samples/compare_sample/build/app/intermediates/stripped_native_libs/release/stripReleaseDebugSymbols/out/lib/arm64-v8a/libapp.so"
  "compare_x64|/home/user/samples/compare_sample/build/app/intermediates/stripped_native_libs/release/stripReleaseDebugSymbols/out/lib/x86_64/libapp.so"
  "apk_fresh_x64|/home/user/samples/dart_apk_fresh/split_x86_64/lib/x86_64/libapp.so"
  "apk_212_arm64|/home/user/samples/dart_apk_2.12.1/arm64/lib/arm64-v8a/libapp.so"
  "apk_212_x64|/home/user/samples/dart_apk_2.12.1/x86_64/lib/x86_64/libapp.so"
  "native_arm64|/home/user/samples/dart_native_extract/arm64/libapp.so"
)

# Commands: name|full_invocation (uses {LIB} placeholder)
# _debug prefix needed for subcommands not in top-level main.go
# Skip: decompile --all (OOM), ghidra/ida (need external tools), cmd_run (heavy)
COMMANDS=(
  # Top-level commands
  "fingerprint|_debug fingerprint --lib {LIB}"
  "find-libapp|find-libapp --apk {LIB}"
  "scan|scan --lib {LIB} --max-steps 1000"
  "dump|dump --lib {LIB} --max-steps 1000"
  "objects|objects --lib {LIB} --max-steps 1000"
  "strings|strings --lib {LIB} --max-steps 1000 --max-len 100"
  "strings_names|strings --lib {LIB} --max-steps 1000 --names --max-len 100"
  "clusters|clusters --lib {LIB} --max-steps 1000"
  "graph|graph --lib {LIB} --max-steps 1000"
  "thr-audit|thr-audit --lib {LIB} --max-steps 1000"
  # _debug subcommands
  "refinfo_list|_debug refinfo --lib {LIB} --list-toplevel"
  "refinfo_find|_debug refinfo --lib {LIB} --find-owner-of-code-ref 1"
  "decomp_native_find|_debug decompile-native --lib {LIB} --find factorial"
  "decomp_native_find2|_debug decompile-native --lib {LIB} --find main"
  "x64refs_find|_debug x64refs --lib {LIB} --find factorial"
  "dispatch_table|_debug dispatch-table --lib {LIB}"
  "ffi_trace|_debug ffi-trace --lib {LIB} --max-scan 100"
  "funcdiff|_debug funcdiff --old {LIB} --new {LIB} --top 10"
  # Lightweight commands
  "fingerprint_only|_debug fingerprint --lib {LIB}"
)

PASS=0
FAIL=0
DIFF=0
BOTH_ERROR=0
FIXED=0

for entry in "${SAMPLES[@]}"; do
  sample_name="${entry%%|*}"
  sample_path="${entry##*|}"
  if [ ! -f "$sample_path" ]; then
    echo "SKIP $sample_name (file not found)"
    continue
  fi
  sample_dir="$OUTDIR/$sample_name"
  mkdir -p "$sample_dir"
  echo "========== SAMPLE: $sample_name =========="

  for cmd_entry in "${COMMANDS[@]}"; do
    cmd_name="${cmd_entry%%|*}"
    cmd_template="${cmd_entry##*|}"
    logbase="$sample_dir/$cmd_name"
    base_log="$logbase.baseline"
    curr_log="$logbase.current"

    # Substitute {LIB}
    base_args="${cmd_template//\{LIB\}/$sample_path}"
    curr_args="${cmd_template//\{LIB\}/$sample_path}"

    # Run baseline
    timeout 120 $BASELINE $base_args > "$base_log.out" 2> "$base_log.err"
    rc_base=$?
    # Run current
    timeout 120 $CURRENT $curr_args > "$curr_log.out" 2> "$curr_log.err"
    rc_curr=$?

    # Compare
    status="OK"
    detail=""
    if [ "$rc_base" -ne 0 ] && [ "$rc_curr" -ne 0 ]; then
      status="BOTH_ERROR"
      BOTH_ERROR=$((BOTH_ERROR+1))
    elif [ "$rc_base" -ne 0 ] && [ "$rc_curr" -eq 0 ]; then
      status="FIXED"
      detail="(baseline rc=$rc_base, current rc=$rc_curr)"
      FIXED=$((FIXED+1))
    elif [ "$rc_base" -eq 0 ] && [ "$rc_curr" -ne 0 ]; then
      status="REGRESSION!"
      detail="(baseline rc=$rc_base, current rc=$rc_curr)"
      FAIL=$((FAIL+1))
    else
      # Both succeeded - compare output
      if diff -q "$base_log.out" "$curr_log.out" > /dev/null 2>&1 && \
         diff -q "$base_log.err" "$curr_log.err" > /dev/null 2>&1; then
        status="IDENTICAL"
        PASS=$((PASS+1))
      else
        status="DIFF"
        diffcount_out=$(diff "$base_log.out" "$curr_log.out" 2>/dev/null | grep -c '^[<>]')
        diffcount_err=$(diff "$base_log.err" "$curr_log.err" 2>/dev/null | grep -c '^[<>]')
        detail="(stdout:$diffcount_out stderr:$diffcount_err lines differ)"
        DIFF=$((DIFF+1))
      fi
    fi

    echo "  [$status] $cmd_name $detail"
    echo "$status rc_base=$rc_base rc_curr=$rc_curr $detail" > "$logbase.status"
  done
  echo ""
done

echo ""
echo "========== SUMMARY =========="
echo "IDENTICAL: $PASS"
echo "FIXED (baseline error, current ok): $FIXED"
echo "DIFF (both ok, output differs): $DIFF"
echo "REGRESSION (baseline ok, current fails): $FAIL"
echo "BOTH_ERROR: $BOTH_ERROR"
echo ""
echo "Detailed logs saved in: $OUTDIR"
