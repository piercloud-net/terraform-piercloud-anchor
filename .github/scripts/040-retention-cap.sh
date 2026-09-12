#!/usr/bin/env bash
# 040-retention-cap.sh — mode=check assertion (H1): every workflow artifact
# upload must stay within the public-repo retention cap.
#
# GitHub caps artifact retention on PUBLIC repos at 90 days ("must be
# between 1 and 90 inclusive"); a larger retention-days is silently clamped
# at upload time, so an over-cap value is false durability. The run artifact
# is a 90-day convenience copy; the durable thumbprint legs are the committed
# break-glass file and the platform registry (both pending) — never logs or
# artifacts alone (H1).
#
# Scans the workflow directory (default .github/workflows) for YAML keys of
# the shape `retention-days: <value>` and fails closed on:
#   - zero matches anywhere (a broken scan must never pass green),
#   - a value that is not a literal integer (expression, quoted, missing),
#   - a literal outside the 1..90 band.
#
# Usage: 040-retention-cap.sh [workflow-dir]
set -euo pipefail

CAP=90
DIR="${1:-.github/workflows}"

if [ ! -d "$DIR" ]; then
  echo "::error::retention-cap: workflow directory '$DIR' not found — cannot scan (fail closed)."
  exit 1
fi

# Sanitize an untrusted (file-derived) token for terminal output.
# Keep the LAST $2 chars so long absolute fixture paths still carry the
# basename+line (file:line contract). `tail -c` clamps cleanly on short
# inputs; a negative-offset bash substring (${v: -n}) returns EMPTY on some
# bash builds when n exceeds the length (CI-caught 2026-09-12) — do not
# reintroduce it.
sanitize() { # $1 value, $2 max chars (default 32)
  printf '%s' "$1" | tr -cd 'A-Za-z0-9_./-' | tail -c "${2:-32}"
}

COUNT=0
FAIL=0
while IFS= read -r match; do
  COUNT=$((COUNT + 1))
  FILE="${match%%:*}"
  REST="${match#*:}"
  LINE="${REST%%:*}"
  KV="${REST#*:}"
  VALUE="${KV#*:}"
  VALUE="${VALUE%%#*}"                        # strip a trailing comment
  VALUE="$(printf '%s' "$VALUE" | tr -d '[:space:]')"  # whitespace incl. CR
  case "$VALUE" in
    ''|*[!0-9]*)
      echo "::error::$(sanitize "$FILE" 80):${LINE} retention-days is not a literal integer ('$(sanitize "$VALUE")') — cannot prove it stays within the public-repo band (1-${CAP}). Use a literal 1-${CAP}."
      FAIL=$((FAIL + 1))
      ;;
    *)
      if [ "$VALUE" -lt 1 ] || [ "$VALUE" -gt "$CAP" ]; then
        echo "::error::$(sanitize "$FILE" 80):${LINE} retention-days: $(sanitize "$VALUE") is outside the public-repo band (1-${CAP}) — GitHub clamps it at upload, so the value is false durability. Keep it 1-${CAP}; the durable thumbprint legs are the committed break-glass file and the platform registry (H1)."
        FAIL=$((FAIL + 1))
      fi
      ;;
  esac
done < <(grep -rnHE '^[[:space:]]*retention-days[[:space:]]*:' --include='*.yml' --include='*.yaml' "$DIR" || true)

if [ "$COUNT" -eq 0 ]; then
  echo "::error::retention-cap: no retention-days keys found under '$DIR' — the scan proved nothing (wrong directory or broken pattern); refusing to pass green (fail closed)."
  exit 1
fi

if [ "$FAIL" -ne 0 ]; then
  echo "::error::retention-cap: ${FAIL} violation(s) — fix the workflow before dispatching (H1: artifacts are a convenience copy, never the durable record)."
  exit 1
fi

echo "retention-days literals checked: ${COUNT} (all within 1-${CAP}); artifact = 90-day convenience copy — the durable thumbprint legs stay the committed break-glass file and the platform registry (H1)."
exit 0
