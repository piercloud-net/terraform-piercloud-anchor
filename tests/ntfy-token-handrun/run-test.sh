#!/usr/bin/env bash
# tests/ntfy-token-handrun/run-test.sh — issue #137 regression tooth.
#
# scripts/010-provision.sh runs under `set -euo pipefail` (line 20) and
# validates NTFY_TOKEN before rendering the Gatus config. The validation
# must be UNSET-SAFE: a hand run with NTFY_TOPIC set and NTFY_TOKEN absent
# from the environment must not die `NTFY_TOKEN: unbound variable` (the
# dispatch path always exports it — empty when the secret is missing — but
# the documented console-fallback hand run does not).
#
# This extracts the REAL validation line from the script (never a copy) and
# drives it under `set -u` with the variable absent / empty / valid /
# whitespace / control-char. Offline, cred-free, no network.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROV="$ROOT/scripts/010-provision.sh"
[ -f "$PROV" ] || { printf 'FAIL provision script not found: %s\n' "$PROV"; exit 1; }

pass=0
fail=0
ok()  { pass=$((pass + 1)); printf 'ok   %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL %s\n' "$1"; }

# Anchored on the guarded form: the unguarded `case "$NTFY_TOKEN"` is the
# pre-#137 bug (dies under `set -u` when the variable is absent). `|| true`
# keeps the not-found case on the loud path below (pipefail would otherwise
# exit before the failure message).
LINE="$(grep -nF 'case "${NTFY_TOKEN:-}" in' "$PROV" | head -1 | cut -d: -f1 || true)"
if [ -z "$LINE" ]; then
  bad "guarded NTFY_TOKEN case not found — unset-unsafe guard regression (#137)"
  printf '\n%s passed, %s failed\n' "$pass" "$fail"
  exit 1
fi
SNIPPET="$(sed -n "${LINE}p" "$PROV")"

run_case() { # $1 = unset|empty|valid|ws|ctrl -> prints ok|die (or the error)
  (
    set -euo pipefail
    case "$1" in
      unset) unset NTFY_TOKEN ;;
      empty) NTFY_TOKEN="" ;;
      valid) NTFY_TOKEN="tk_valid" ;;
      ws)    NTFY_TOKEN="$(printf 'tk\tbad')" ;;
      ctrl)  NTFY_TOKEN="$(printf 'tk\001bad')" ;;
    esac
    die() { printf 'die\n'; exit 1; }
    eval "$SNIPPET"
    printf 'ok\n'
  ) 2>&1 || true
}

expect() { # $1 mode, $2 expected ok|die, $3 label
  local out
  out="$(run_case "$1")"
  case "$out" in
    "$2") ok "$3" ;;
    *) bad "$3 (got: $out)" ;;
  esac
}

expect unset ok  "NTFY_TOKEN unset is unset-safe (no 'unbound variable')"
expect empty ok  "NTFY_TOKEN empty is accepted"
expect valid ok  "NTFY_TOKEN valid is accepted"
expect ws    die "NTFY_TOKEN with whitespace is rejected"
expect ctrl  die "NTFY_TOKEN with a control character is rejected"

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
