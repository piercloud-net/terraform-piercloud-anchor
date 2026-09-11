#!/usr/bin/env bash
# Unit test for the SCP access-token refresh path in
# .github/scripts/020-provision-anchor.sh (scp_token_refresh + api_call).
#
# Context (live 2026-09-11): the netcup/SCP access token lives ~5 minutes
# while a real run takes longer (async apply), so every tail step 401'd and
# leaked the A1 window policy. The fix re-mints the access token from the
# device grant's own offline_access refresh token on the first 401 and
# replays the request once. This harness proves the three behaviours with a
# stubbed `curl` — no network, no credentials:
#   1. 401 → refresh → retry once → 2xx, and the retry carries the NEW token
#   2. no refresh token → 401 stays 401, exactly one request (fail loud)
#   3. refresh refused / unusable → 401 stays 401, exactly one request
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$ROOT/.github/scripts/020-provision-anchor.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0
ok()  { pass=$((pass + 1)); printf 'ok   %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL %s\n' "$1"; }
is()  { # $1 label, $2 expected, $3 actual
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi
}

# ---- stubbed curl -----------------------------------------------------------
mkdir -p "$WORK/bin"
cat > "$WORK/bin/curl" <<'STUB'
#!/usr/bin/env bash
# Minimal curl stand-in: understands -sS --max-time N -X M -o FILE -w '%{http_code}'
# -H 'Header: v' -d body --data-urlencode k v and one URL. Driven by $STUB_MODE.
set -euo pipefail
out=""; url=""; body=""; declare -a headers=()
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    -w) shift 2 ;;                                   # only '%{http_code}' is used
    -X) shift 2 ;;
    -H) headers+=("$2"); shift 2 ;;
    -d) body="$2"; shift 2 ;;
    --data-urlencode) body="$body&$2"; shift 2 ;;
    --max-time) shift 2 ;;
    -sS) shift ;;
    *) url="$1"; shift ;;
  esac
done

if [ "$url" = "https://token.example/token" ]; then
  echo refresh >> "$STUB_REFRESHED"
  case "$STUB_MODE" in
    refresh-bad) printf 'this is not json' ;;
    *)           printf '{"access_token":"AT2","refresh_token":"RT2"}' ;;
  esac
  exit 0
fi

# API call: record the bearer token actually sent, then answer by mode.
n="$(cat "$STUB_CALLS" 2>/dev/null || echo 0)"
n=$((n + 1)); echo "$n" > "$STUB_CALLS"
for h in "${headers[@]}"; do
  case "$h" in
    Authorization:*)
      token="${h#Authorization: Bearer }"
      printf '%s\n' "$token" >> "$STUB_SEEN"
      ;;
  esac
done
if [ "$STUB_MODE" = "401-then-200" ] && [ "$n" -ge 2 ]; then
  if [ -n "$out" ]; then printf '{"ok":true}' > "$out"; fi
  printf 200
  exit 0
fi
if [ -n "$out" ]; then printf '{"message":"Invalid token."}' > "$out"; fi
printf 401
STUB
chmod +x "$WORK/bin/curl"

# ---- extract the functions under test (sourcing the CLI would dispatch) ----
extract() { awk "/^$1\\(\\) \\{/,/^\\}/" "$SCRIPT"; }
{
  # Real log shape (stdout): with a stubbed log() the captured-stdout regression
  # below cannot see the bug at all — that is exactly why the refresh banner
  # slipped through review. Keep this faithful to the script.
  echo 'log() { printf "A1: %s\n" "$*"; }'
  extract scp_token_refresh
  extract _api_curl
  extract api_call
} > "$WORK/functions.sh"
for fn in scp_token_refresh _api_curl api_call; do
  grep -q "^$fn() {" "$WORK/functions.sh" || { echo "FAIL could not extract $fn"; exit 1; }
done

run_case() { # $1 mode, $2 refresh token ("" = unset) -> sets HTTP_STATUS/OUT/CALLS/REFRESHED/SEEN
  STUB_MODE="$1" \
  STUB_CALLS="$WORK/calls.$1" STUB_SEEN="$WORK/seen.$1" \
  STUB_REFRESHED="$WORK/refreshed.$1" \
  PATH="$WORK/bin:$PATH" \
  NETCUP_API_BASE="https://scp.example" \
  NETCUP_SCP_ACCESS_TOKEN="AT1" \
  NETCUP_SCP_REFRESH_TOKEN="$2" \
  NETCUP_SCP_TOKEN_ENDPOINT="https://token.example/token" \
  bash -c '
    set -euo pipefail
    source "$1"
    out=""
    api_call GET "/api/v1/test" "" out
    printf "HTTP_STATUS=%s\nOUT=%s\n" "$HTTP_STATUS" "$out"
  ' _ "$WORK/functions.sh" > "$WORK/result.$1" 2>&1 || true
  HTTP_STATUS="$(sed -n 's/^HTTP_STATUS=//p' "$WORK/result.$1")"
  OUT="$(sed -n 's/^OUT=//p' "$WORK/result.$1")"
  CALLS=0; REFRESHED=0; SEEN=""
  if [ -f "$WORK/calls.$1" ]; then CALLS="$(cat "$WORK/calls.$1")"; fi
  if [ -f "$WORK/refreshed.$1" ]; then REFRESHED="$(wc -l < "$WORK/refreshed.$1" | tr -d ' ')"; fi
  if [ -f "$WORK/seen.$1" ]; then SEEN="$(paste -sd, "$WORK/seen.$1")"; fi
}

# ---- case 1: 401 → refresh → retry once → 200 (and the NEW token is used) ---
run_case 401-then-200 "RT1"
is "case1 status"        "200"         "$HTTP_STATUS"
is "case1 body"          '{"ok":true}' "$OUT"
is "case1 api calls"     "2"           "$CALLS"
is "case1 refresh calls" "1"           "$REFRESHED"
is "case1 tokens seen"   "AT1,AT2"     "$SEEN"

# ---- case 2: no refresh token → 401 stays 401, single request --------------
run_case always-401 ""
is "case2 status"        "401"         "$HTTP_STATUS"
is "case2 api calls"     "1"           "$CALLS"
is "case2 refresh calls" "0"           "$REFRESHED"

# ---- case 3: refresh refused (non-JSON) → 401 stays 401, no replay ---------
run_case refresh-bad "RT1"
is "case3 status"        "401"         "$HTTP_STATUS"
is "case3 api calls"     "1"           "$CALLS"
is "case3 refresh calls" "1"           "$REFRESHED"

# ---- case 4: a refresh must not corrupt a captured stdout ------------------
# The live failure (review SECURITY, reproduced): pid="$(own_policy_id)" — a
# captured call site — got the refresh success line on stdout PREPENDED to the
# JSON, so jq died with "parse error: Invalid numeric literal", cmd_close read
# rc 5 with an empty pid, and the A1 window policy leaked. The capture below is
# the faithful shape: api_call's body goes to the outvar and the wrapper prints
# the outvar INSIDE the command substitution (a bare `$(api_call ...)` would
# lose HTTP_STATUS — see api_call's subshell warning).
run_capture() { # $1 label, $2 mode -> CAP_RC/CAPTURED/CAP_STDOUT/CAP_STDERR/CAP_REFRESHED
  local rc=0
  STUB_MODE="$2" \
  STUB_CALLS="$WORK/calls.cap.$1" STUB_SEEN="$WORK/seen.cap.$1" \
  STUB_REFRESHED="$WORK/refreshed.cap.$1" \
  PATH="$WORK/bin:$PATH" \
  NETCUP_API_BASE="https://scp.example" \
  NETCUP_SCP_ACCESS_TOKEN="AT1" \
  NETCUP_SCP_REFRESH_TOKEN="RT1" \
  NETCUP_SCP_TOKEN_ENDPOINT="https://token.example/token" \
  bash -c '
    set -euo pipefail
    source "$1"
    json_call() { local o=""; api_call GET "/api/v1/test" "" o; printf "%s" "$o"; }
    captured="$(json_call)"
    printf "CAPTURED=%s\n" "$captured"
  ' _ "$WORK/functions.sh" > "$WORK/cap.out.$1" 2> "$WORK/cap.err.$1" || rc=$?
  CAP_RC="$rc"
  CAPTURED="$(sed -n 's/^CAPTURED=//p' "$WORK/cap.out.$1")"
  # Anything else the wrapper wrote to stdout (the bug: the refresh banner).
  CAP_STDOUT="$(grep -v '^CAPTURED=' "$WORK/cap.out.$1" || true)"
  CAP_STDERR="$(cat "$WORK/cap.err.$1")"
  CAP_REFRESHED=0
  if [ -f "$WORK/refreshed.cap.$1" ]; then CAP_REFRESHED="$(wc -l < "$WORK/refreshed.cap.$1" | tr -d ' ')"; fi
}

run_capture c4 401-then-200
is "case4 rc"                    "0"           "$CAP_RC"
is "case4 captured body"         '{"ok":true}' "$CAPTURED"
is "case4 captured parses (jq)"  "1"           "$(printf '%s' "$CAPTURED" | jq -e '.ok == true' >/dev/null 2>&1 && echo 1 || echo 0)"
is "case4 no stray stdout"       ""            "$CAP_STDOUT"
is "case4 refresh banner stderr" "1"           "$(grep -c 'scp token refreshed' "$WORK/cap.err.c4" || true)"
is "case4 refresh calls"         "1"           "$CAP_REFRESHED"

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
