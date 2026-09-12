#!/usr/bin/env bash
# Approve a netcup device-flow run from the automation browser.
#
# S1: every netcup use is human-approved per run — no stored tokens, no CI
# automation. Sequence proven live 2026-09-10/11 (see the repo's
# docs/verification.md and tools/verification-browser/README.md).
#
# Usage:
#   approve-device.sh <run-id> [owner/repo]   approve a dispatched provision run
#   approve-device.sh --preflight [owner/repo]  session check only (no run, no click)
#
# What it does (full mode):
#   1. waits (bounded) for the run's "Device code request" job to complete;
#   2. reads the device URL from that job's log;
#   3. pre-flights the automation profile's netcup SCP session (URL-only);
#   4. navigates to the device URL and confirms the Keycloak Grant Access page;
#   5. clicks #kc-login once (one retry allowed), then polls for
#      /realms/scp/device/status + "Device Login Successful" within the
#      approval window;
#   6. prints DEVICE_LOGIN_SUCCESSFUL, or fails closed with NOT_CONFIRMED and
#      recovery instructions.
#
# The device user_code is NEVER printed: every URL this script prints is passed
# through redact(). The job log is never dumped.
#
# Requirements: gh (logged in), python3 + websocket-client, and a running
# verification browser (launch.sh) whose profile is signed in to netcup SCP.
#
# Env knobs: CDP_PORT (default 9333); PROFILE / BROWSER_HOME are reported only.
set -euo pipefail

PREFLIGHT_ONLY=0
if [ "${1:-}" = "--preflight" ]; then
  PREFLIGHT_ONLY=1
  shift
fi
RUN_ID="${1:-}"
REPO="${2:-${GITHUB_REPOSITORY:-}}"
if [ "$PREFLIGHT_ONLY" -eq 1 ]; then
  # --preflight [owner/repo]: the optional repo arrives as $1, not $2.
  case "${RUN_ID:-}" in */*) REPO="${RUN_ID}"; RUN_ID="" ;; esac
fi
CDP_PORT="${CDP_PORT:-9333}"
BROWSER_HOME="${BROWSER_HOME:-$HOME/.piercloud/test-browser}"
PROFILE="${PROFILE:-$BROWSER_HOME/cft-profile}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CDP="$SCRIPT_DIR/cdp.py"
PY="${PYTHON:-python3}"

JOB_PREFIX="Device code request"        # job name prefix (the live name has a suffix)
JOB_WAIT_ATTEMPTS=60                    # x 3s = 180s bound for job completion
LOG_WAIT_ATTEMPTS=20                    # x 3s = 60s bound for log availability
APPROVAL_WINDOW_SECONDS=570             # live netcup device window is ~570s
POLL_SECONDS=3

SCP_UI_URL="https://www.servercontrolpanel.de/scp-ui/"

die() { echo "error: $*" >&2; exit 1; }

redact() { sed -E 's/user_code=[^&[:space:]]+/user_code=<redacted>/g'; }

not_confirmed() {
  echo "NOT_CONFIRMED: $1" >&2
  cat >&2 <<'MSG'
The device code may still be live for a few minutes. Recovery:
  1. Open the verification browser window and sign in to netcup SCP IN THAT WINDOW (the automation profile is what approves — a personal browser does not help).
  2. Re-run this script with the same run id.
  3. If the run already failed its poll, re-dispatch provision.yml and approve the new code the same way.
Note: a warm scp-ui session does not guarantee the Grant Access page — the device-flow client may still ask for a fresh sign-in; complete it in that window when prompted.
MSG
  exit 1
}

page_url() { "$PY" "$CDP" url 2>/dev/null || true; }

preflight_session() {
  echo "pre-flight: checking the automation profile's netcup SCP session ..."
  "$PY" "$CDP" nav "$SCP_UI_URL" >/dev/null
  # A signed-out profile shows scp-ui FIRST and only then bounces to the
  # Keycloak login form (observed 4-6 s later), so the requested URL lying for
  # one poll is not proof of a session. Classify only after the navigation
  # settles: wait PREFLIGHT_SETTLE_SECS, then require the URL to hold for
  # PREFLIGHT_SETTLE_POLLS consecutive polls. Detection stays URL-only (no
  # account names, no DOM text).
  local settle_secs="${PREFLIGHT_SETTLE_SECS:-6}"
  local settle_polls="${PREFLIGHT_SETTLE_POLLS:-3}"
  sleep "$settle_secs"
  local ui_url="" prev="" stable=0
  for _ in $(seq 1 30); do
    ui_url="$(page_url)"
    if [ -n "$ui_url" ] && [ "$ui_url" = "$prev" ]; then
      stable=$((stable + 1))
    else
      stable=0
    fi
    prev="$ui_url"
    [ "$stable" -ge "$settle_polls" ] && break
    sleep 1
  done
  case "$ui_url" in
    *login-actions/authenticate*|*protocol/openid-connect/auth*)
      not_confirmed "the automation profile's netcup SCP session is gone (pre-flight landed on the sign-in page: $(printf '%s' "$ui_url" | redact))" ;;
    https://www.servercontrolpanel.de/scp-ui*)
      if [ "$stable" -ge "$settle_polls" ]; then
        echo "pre-flight OK: netcup SCP session present in the automation profile"
      else
        not_confirmed "pre-flight could not observe a stable page within the poll bound (last URL: $(printf '%s' "$ui_url" | redact)) — refusing to report a session; re-run, or sign in if the sign-in form appears"
      fi ;;
    *)
      not_confirmed "pre-flight landed on an unexpected page: $(printf '%s' "$ui_url" | redact)" ;;
  esac
}

if [ "$PREFLIGHT_ONLY" -eq 0 ] && [ -z "$RUN_ID" ]; then
  die "usage: approve-device.sh <run-id> [owner/repo]  (or --preflight [owner/repo])"
fi
command -v gh >/dev/null 2>&1 || die "gh CLI not found — install it and log in"
command -v "$PY" >/dev/null 2>&1 || die "python3 not found"
[ -x "$CDP" ] || die "cdp.py missing at $CDP"

if [ -z "$REPO" ] && [ "$PREFLIGHT_ONLY" -eq 0 ]; then
  REPO="$(gh repo view --json nameWithOwner --jq .nameWithOwner 2>/dev/null)" \
    || die "cannot determine the repo — pass owner/repo or run from inside the clone"
fi

echo "repo=${REPO:-<unused in --preflight>}"
[ -n "$RUN_ID" ] && echo "run=$RUN_ID"
echo "BROWSER_HOME=$BROWSER_HOME"
echo "CDP_PORT=$CDP_PORT"
echo "PROFILE=$PROFILE"

curl -fsS --max-time 2 "http://127.0.0.1:$CDP_PORT/json/version" >/dev/null 2>&1 \
  || die "verification browser not reachable on CDP :$CDP_PORT — run launch.sh first"

preflight_session
if [ "$PREFLIGHT_ONLY" -eq 1 ]; then
  exit 0
fi

echo "waiting for the '$JOB_PREFIX' job (bound: $((JOB_WAIT_ATTEMPTS * 3))s) ..."
job_id=""; job_status=""; job_conclusion=""
for _ in $(seq 1 "$JOB_WAIT_ATTEMPTS"); do
  jobs_json="$(gh run view "$RUN_ID" --repo "$REPO" --json jobs 2>/dev/null)" \
    || die "cannot read run $RUN_ID in $REPO — check the id and that gh is logged in"
  job_line="$(printf '%s' "$jobs_json" | "$PY" -c '
import json, sys
for job in json.load(sys.stdin).get("jobs", []):
    if job.get("name", "").startswith(sys.argv[1]):
        print(job["databaseId"], job.get("status", ""), job.get("conclusion") or "none")
        break
' "$JOB_PREFIX")"
  if [ -n "$job_line" ]; then
    read -r job_id job_status job_conclusion <<<"$job_line"
    if [ "$job_status" = "completed" ]; then
      [ "$job_conclusion" = "success" ] || die "the '$JOB_PREFIX' job ended $job_status/$job_conclusion — read the run log; there is no device code to approve"
      break
    fi
  fi
  sleep 3
done
if [ -z "$job_id" ] || [ "$job_status" != "completed" ]; then
  die "the '$JOB_PREFIX' job did not complete within the wait bound — check the run page"
fi

echo "reading the device URL from the job log (the code itself is never printed) ..."
device_url=""
for _ in $(seq 1 "$LOG_WAIT_ATTEMPTS"); do
  log_text="$(gh api "repos/$REPO/actions/jobs/$job_id/logs" 2>/dev/null)" || { sleep 3; continue; }
  device_url="$(printf '%s\n' "$log_text" | tr -d '\r' | grep -oE 'https://[^[:space:]"]+' | grep -m1 'user_code=' || true)"
  [ -n "$device_url" ] && break
  sleep 3
done
[ -n "$device_url" ] || die "no device URL found in the job log — check that gh is logged in and the device request succeeded"
case "$device_url" in
  https://www.servercontrolpanel.de/realms/scp/*) ;;
  *) die "device URL is not on the expected netcup host — refusing to navigate" ;;
esac
echo "device URL: $(printf '%s' "$device_url" | redact)"

"$PY" "$CDP" nav "$device_url" >/dev/null
grant_url=""
for _ in $(seq 1 30); do
  grant_url="$(page_url)"
  case "$grant_url" in
    *login-actions/authenticate*|*protocol/openid-connect/auth*)
      not_confirmed "the device page asked for a fresh sign-in instead of showing Grant Access (a warm scp-ui session does not guarantee the device-flow grant)" ;;
    *login-actions/required-action*) break ;;
  esac
  sleep 1
done
case "$grant_url" in
  *login-actions/required-action*) ;;
  *) not_confirmed "the Grant Access page did not appear (last page: $(printf '%s' "$grant_url" | redact))" ;;
esac

if ! "$PY" "$CDP" eval "document.querySelector('#kc-login') !== null" 2>/dev/null | grep -q '"value": true'; then
  not_confirmed "the Grant Access command button did not render (#kc-login missing)"
fi

echo "clicking Grant Access (bare .click(), at most one retry) ..."
click_js="document.querySelector('#kc-login').click()"
"$PY" "$CDP" eval "$click_js" >/dev/null
clicks=1
deadline=$(( $(date +%s) + APPROVAL_WINDOW_SECONDS ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  current_url="$(page_url)"
  case "$current_url" in
    */realms/scp/device/status*)
      if "$PY" "$CDP" eval "document.body.innerText.includes('Device Login Successful')" 2>/dev/null | grep -q '"value": true'; then
        echo "DEVICE_LOGIN_SUCCESSFUL"
        exit 0
      fi
      ;;
    *login-actions/required-action*)
      if [ "$clicks" -eq 1 ]; then
        sleep 5
        "$PY" "$CDP" eval "$click_js" >/dev/null
        clicks=2
      fi
      ;;
  esac
  sleep "$POLL_SECONDS"
done
not_confirmed "no approval confirmation within the ${APPROVAL_WINDOW_SECONDS}s window"
