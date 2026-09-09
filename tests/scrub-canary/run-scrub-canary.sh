#!/usr/bin/env bash
# run-scrub-canary.sh — redactor proof for the 020 poll_task failure dumps.
#
# Sources TASK_DUMP_BYTES + scrub_task_body from
# .github/scripts/020-provision-anchor.sh at runtime (never a copy), pipes
# the synthetic fixture (fixture.txt: task-name echo, structured password
# echo, JWK d, PEM armor, free-form secret — all canary values, no live
# material) through the merged function, and fails loudly on any leak.
# Secrets are read out of the fixture with jq at runtime; this file holds
# no secret literal. Cred-free, no cloud.
set -euo pipefail

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HARNESS_DIR}/../.." && pwd)"
SRC="${REPO_ROOT}/.github/scripts/020-provision-anchor.sh"
FIX="${HARNESS_DIR}/fixture.txt"

eval "$(sed -n '/^TASK_DUMP_BYTES/,/^}/p' "$SRC")"
eval "$(sed -n '/^scrub_task_body/,/^}/p' "$SRC")"

RAW="$(cat "$FIX")"
OUT="$(scrub_task_body "$RAW")"
fails=0

pass() { printf 'canary PASS: %s\n' "$1"; }
fail() { printf 'canary FAIL: %s\n' "$1" >&2; fails=$((fails + 1)); }

# Values below are fixture canaries read at runtime (never literals here).
FREE="$(printf '%s' "$RAW" | jq -r '.message | capture("password (?<v>[^ ]+)").v')"
STRUCT="$(printf '%s' "$RAW" | jq -r '.rootPassword')"
JWKD="$(printf '%s' "$RAW" | jq -r '.jwk.d')"
PEMBODY="$(printf '%s' "$RAW" | jq -r '.note | split("\n")[1]')"
UUID="$(printf '%s' "$RAW" | jq -r '.uuid')"

check_gone() { # $1 = desc, $2 = value: the value must NOT appear in scrubbed output
  if [ -z "${2:-}" ] || [ "$2" = "null" ]; then fail "$1 (fixture unreadable)"; return; fi
  if printf '%s' "$OUT" | grep -qF "$2"; then fail "$1 leaked"; else pass "$1 redacted"; fi
}

check_kept() { # $1 = desc, $2 = text: metadata must survive scrubbing
  if printf '%s' "$OUT" | grep -qF "$2"; then pass "$1 kept"; else fail "$1 mangled"; fi
}

check_gone "structured password echo" "$STRUCT"
check_gone "JWK d scalar" "$JWKD"
check_gone "PEM body" "$PEMBODY"
check_gone "free-form password" "$FREE"
check_kept "task uuid (correlation)" "$UUID"
check_kept "task name" "SetRootPasswordTask"
check_kept "failure word" "failed"
if printf '%s' "$OUT" | grep -q "REDACTED-PEM"; then pass "PEM armor marker"; else fail "PEM armor marker missing"; fi
if printf '%s' "$OUT" | grep -q "REDACTED"; then pass "redaction marker present"; else fail "no redaction at all"; fi

# Bound proof: 5KB of padding must come back capped at TASK_DUMP_BYTES.
BIG="$(python3 -c 'print("{\"uuid\":\"b\",\"state\":\"ERROR\",\"pad\":\"" + "A"*5000 + "\"}")')"
BIGOUT="$(scrub_task_body "$BIG")"
if [ "${#BIGOUT}" -le "$TASK_DUMP_BYTES" ]; then pass "bound (${#BIGOUT} <= $TASK_DUMP_BYTES)"; else fail "bound exceeded (${#BIGOUT})"; fi

if [ "$fails" -ne 0 ]; then printf 'canary RESULT: %s failure(s)\n' "$fails" >&2; exit 1; fi
printf 'canary RESULT: all green\n'
