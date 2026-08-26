#!/usr/bin/env bash
# Cross-check export-dart output against the REAL Dart analyzer.
# Usage: SAMPLE=<libapp.so> [DART=<path to dart>] make analyze
# Requires a local sample and a Dart SDK (not redistributable / not in CI).
set -euo pipefail
SAMPLE="${SAMPLE:-samples/dart-3.13.0-arm64.so}"
DART="${DART:-}"
if [ -z "$DART" ]; then
  for d in "$(command -v dart 2>/dev/null || true)" \
           "$HOME/dev/flutter/bin/dart" "$HOME/flutter/bin/dart"; do
    [ -n "$d" ] && [ -x "$d" ] && DART="$d" && break
  done
fi
[ -z "$DART" ] && { echo "no dart SDK found (set DART=/path/to/dart)"; exit 2; }
[ -e "$SAMPLE" ] || { echo "sample not found: $SAMPLE (set SAMPLE=...)"; exit 2; }

OUT="$(mktemp -d)"; trap 'rm -rf "$OUT"' EXIT
echo "export-dart $SAMPLE -> $OUT ..." >&2
go run ./cmd/aotopsy export-dart --lib "$SAMPLE" --out "$OUT" --app-only --max 500 >&2

REPORT="$(mktemp)"; trap 'rm -f "$REPORT"' EXIT
"$DART" analyze "$OUT" > "$REPORT" 2>&1 || true

syntax=$(grep -cE 'expected_token|missing_identifier|expected_identifier_but_got_keyword|unterminated' "$REPORT" || true)
errors=$(grep -cE '^  error ' "$REPORT" || true)
total=$(grep -E 'issues? found|No issues' "$REPORT" | tail -1)
echo "== dart analyze cross-check ($DART) =="
echo "  syntax errors (parse-breaking): $syntax"
echo "  total analyzer errors:          $errors"
echo "  $total"
echo "  (undefined_identifier/method dominate the rest: the honest floor of"
echo "   abstracted reconstruction -- bodies reference sub_/registers we don't fabricate)"
