#!/usr/bin/env bash
# Approve a netcup device-flow run from the automation browser.
#
# S1: every netcup use is human-approved per run — no stored tokens, no CI
# automation. Sequence proven live 2026-09-10/11 (see the repo's
# docs/verification.md and tools/verification-browser/README.md).
#
# Usage:
#   approve-device.sh <run-id> [owner/repo]            resolve the device URL, then approve
#   approve-device.sh --device-url <url> [owner/repo]  explicit device URL (run id optional)
#   approve-device.sh --ntfy-topic <topic> [owner/repo]  read the card from an ntfy topic
#   approve-device.sh --preflight [owner/repo]         session check only (no run, no click)
#
# What it does (full mode):
#   1. resolves the device URL from the first available source: --device-url /
#      DEVICE_URL, then the ntfy topic (--ntfy-topic / NTFY_TOPIC, optional
#      --ntfy-token / NTFY_TOKEN; bounded JSON-API polling), then the
#      check-run notice annotation titled "PierCloud device approval"
#      (bounded), else it stops with instructions. The device flow is now a
#      single long step whose log is NOT readable through the API until the
#      job completes (i.e. after approval) — with no source, open the LIVE
#      run page and pass --device-url;
#   2. pre-flights the automation profile's netcup SCP session (URL-only);
#   3. navigates to the device URL and confirms the Keycloak Grant Access page;
#   4. clicks #kc-login once (one retry allowed), then polls for
#      /realms/scp/device/status + "Device Login Successful" within the
#      approval window;
#   5. prints DEVICE_LOGIN_SUCCESSFUL, or fails closed with NOT_CONFIRMED and
#      recovery instructions.
#
# The device user_code is NEVER printed: every URL this script prints is passed
# through redact(). Job logs are never dumped.
#
# Requirements: gh (logged in) for the run/annotation lookups — not needed
# with --device-url — plus python3 + websocket-client, and a running
# verification browser (launch.sh) whose profile is signed in to netcup SCP.
#
# Env knobs: CDP_PORT (default 9333); PROFILE / BROWSER_HOME are reported only.
#            DEVICE_URL / NTFY_TOPIC / NTFY_TOKEN are the env forms of
#            --device-url / --ntfy-topic / --ntfy-token.
set -euo pipefail

APPROVAL_WINDOW_SECONDS=570      # live netcup device window is ~570s
POLL_SECONDS=3
NTFY_LOOKUP_ATTEMPTS=20          # x (request + 3s) bound for the ntfy card
NOTICE_LOOKUP_ATTEMPTS=40        # x (request + 3s) bound for the notice annotation
JOB_PREFIX="S1 device-flow"      # job name prefix (the live name has a suffix; used to pick the check run)

die() { echo "error: $*" >&2; exit 1; }

usage() {
  cat <<'MSG'
usage: approve-device.sh [--device-url <url>] [--ntfy-topic <topic> [--ntfy-token <token>]] <run-id> [owner/repo]
       approve-device.sh --preflight [owner/repo]

  --device-url <url>    explicit device approval URL (run id optional; skips lookups)
  --ntfy-topic <topic>  ntfy topic carrying the approval card (or NTFY_TOPIC env)
  --ntfy-token <token>  ntfy token for protected topics (or NTFY_TOKEN env)
  --preflight           check the profile's netcup SCP session only
MSG
}

PREFLIGHT_ONLY=0
DEVICE_URL_IN="${DEVICE_URL:-}"
NTFY_TOPIC_IN="${NTFY_TOPIC:-}"
NTFY_TOKEN_IN="${NTFY_TOKEN:-}"

# Flags may appear in any order; positionals are <run-id> [owner/repo].
POSITIONAL=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --preflight) PREFLIGHT_ONLY=1; shift ;;
    --device-url) [ "$#" -ge 2 ] || { usage >&2; die "--device-url needs a value"; }; DEVICE_URL_IN="$2"; shift 2 ;;
    --device-url=*) DEVICE_URL_IN="${1#*=}"; shift ;;
    --ntfy-topic) [ "$#" -ge 2 ] || { usage >&2; die "--ntfy-topic needs a value"; }; NTFY_TOPIC_IN="$2"; shift 2 ;;
    --ntfy-topic=*) NTFY_TOPIC_IN="${1#*=}"; shift ;;
    --ntfy-token) [ "$#" -ge 2 ] || { usage >&2; die "--ntfy-token needs a value"; }; NTFY_TOKEN_IN="$2"; shift 2 ;;
    --ntfy-token=*) NTFY_TOKEN_IN="${1#*=}"; shift ;;
    -h|--help) usage; exit 0 ;;
    --) shift; while [ "$#" -gt 0 ]; do POSITIONAL+=("$1"); shift; done ;;
    -*) usage >&2; die "unknown option '$1'" ;;
    *) POSITIONAL+=("$1"); shift ;;
  esac
done
RUN_ID="${POSITIONAL[0]:-}"
REPO="${POSITIONAL[1]:-${GITHUB_REPOSITORY:-}}"
if [ "$PREFLIGHT_ONLY" -eq 1 ]; then
  # --preflight [owner/repo]: the optional repo arrives as the first positional.
  case "${RUN_ID:-}" in */*) REPO="$RUN_ID"; RUN_ID="" ;; esac
fi
if [ "$PREFLIGHT_ONLY" -eq 0 ] && [ -z "$RUN_ID" ] && [ -z "$DEVICE_URL_IN" ]; then
  usage >&2
  die "a run id is required unless --device-url is given"
fi

CDP_PORT="${CDP_PORT:-9333}"
BROWSER_HOME="${BROWSER_HOME:-$HOME/.piercloud/test-browser}"
PROFILE="${PROFILE:-$BROWSER_HOME/cft-profile}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CDP="$SCRIPT_DIR/cdp.py"
PY="${PYTHON:-python3}"

SCP_UI_URL="https://www.servercontrolpanel.de/scp-ui/"

redact() { sed -E 's/user_code=[^&[:space:]]+/user_code=<redacted>/g'; }

not_confirmed() {
  echo "NOT_CONFIRMED: $1" >&2
  cat >&2 <<'MSG'
The device code may still be live for a few minutes. Recovery:
  1. Open the verification browser window and sign in to netcup SCP IN THAT WINDOW (the automation profile is what approves — a personal browser does not help).
  2. Re-run this script with the same run id (or pass the device URL with --device-url).
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

# The device-flow step is ONE long step: its job log does not exist through
# the API until the job completes (and the job completes only after the
# approval). The live channels are the run page's streaming log, the ntfy
# push, and the check-run notice annotation. Every lookup below is bounded
# numerically and never dumps the message body.
ntfy_get() { # $1 = URL
  if [ -n "$NTFY_TOKEN_IN" ]; then
    curl -fsS --max-time 10 -u ":$NTFY_TOKEN_IN" "$1"
  else
    curl -fsS --max-time 10 "$1"
  fi
}

extract_scp_device_url() { # stdin: newline-delimited JSON records (ntfy) or one annotation array
  "$PY" -c '
import json, re, sys
pattern = re.compile(r"https://www\.servercontrolpanel\.de/realms/scp/\S+")
raw = sys.stdin.read()
try:
    parsed = json.loads(raw)
    records = parsed if isinstance(parsed, list) else [parsed]
except ValueError:
    records = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except ValueError:
            continue
for record in records:
    if not isinstance(record, dict):
        continue
    text = " ".join(str(record.get(key, "")) for key in ("message", "title"))
    match = pattern.search(text)
    if match:
        print(match.group(0))
        break
'
}

fetch_device_url_via_ntfy() {
  [ -n "$NTFY_TOPIC_IN" ] || return 1
  echo "polling ntfy topic '$NTFY_TOPIC_IN' for the approval card (bound: $((NTFY_LOOKUP_ATTEMPTS * 3))s) ..." >&2
  local attempt url
  for ((attempt = 1; attempt <= NTFY_LOOKUP_ATTEMPTS; attempt++)); do
    url="$(ntfy_get "https://ntfy.sh/$NTFY_TOPIC_IN/json?poll=1&since=10m" 2>/dev/null | extract_scp_device_url || true)"
    if [ -n "$url" ]; then
      printf '%s' "$url"
      return 0
    fi
    sleep 3
  done
  echo "no device URL found on the ntfy topic within the bound — trying the next source" >&2
  return 1
}

fetch_device_url_via_notice() {
  command -v gh >/dev/null 2>&1 || { echo "gh CLI not found — cannot look up the notice annotation" >&2; return 1; }
  if [ -z "$REPO" ]; then
    REPO="$(gh repo view --json nameWithOwner --jq .nameWithOwner 2>/dev/null || true)"
    [ -n "$REPO" ] || { echo "cannot determine the repo — pass owner/repo or run from inside the clone" >&2; return 1; }
  fi
  echo "looking up the '$JOB_PREFIX' check-run notice annotation (bound: $((NOTICE_LOOKUP_ATTEMPTS * 3))s) ..." >&2
  local attempt sha ids id url
  for ((attempt = 1; attempt <= NOTICE_LOOKUP_ATTEMPTS; attempt++)); do
    sha="$(gh run view "$RUN_ID" --repo "$REPO" --json headSha --jq '.headSha' 2>/dev/null || true)"
    if [ -n "$sha" ]; then
      ids="$("$PY" -c '
import json, sys
prefix = sys.argv[1]
try:
    data = json.load(sys.stdin)
except ValueError:
    sys.exit(0)
for check in data.get("check_runs", []):
    if check.get("name", "").startswith(prefix) and (check.get("output") or {}).get("annotations_count", 0) > 0:
        print(check["id"])
' "$JOB_PREFIX" <<<"$(gh api "repos/$REPO/commits/$sha/check-runs" 2>/dev/null || true)" || true)"
      # Newline-separated numeric check-run ids (word splitting intended).
      # shellcheck disable=SC2086
      for id in $ids; do
        url="$("$PY" -c '
import json, re, sys
pattern = re.compile(r"https://www\.servercontrolpanel\.de/realms/scp/\S+")
try:
    data = json.load(sys.stdin)
except ValueError:
    sys.exit(0)
for annotation in data:
    if annotation.get("annotation_level") == "notice" and annotation.get("title") == "PierCloud device approval":
        match = pattern.search(str(annotation.get("message", "")))
        if match:
            print(match.group(0))
            break
' <<<"$(gh api "repos/$REPO/check-runs/$id/annotations" 2>/dev/null || true)" || true)"
        if [ -n "$url" ]; then
          printf '%s' "$url"
          return 0
        fi
      done
    fi
    sleep 3
  done
  echo "no 'PierCloud device approval' notice annotation found within the bound — trying the next source" >&2
  return 1
}

command -v "$PY" >/dev/null 2>&1 || die "python3 not found"
[ -x "$CDP" ] || die "cdp.py missing at $CDP"

echo "repo=${REPO:-<unresolved — resolved lazily only for the annotation lookup>}"
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

device_url=""
device_url_source=""
if [ -n "$DEVICE_URL_IN" ]; then
  device_url="$DEVICE_URL_IN"
  device_url_source="--device-url"
else
  if [ -n "$NTFY_TOPIC_IN" ]; then
    device_url="$(fetch_device_url_via_ntfy || true)"
    [ -n "$device_url" ] && device_url_source="ntfy topic '$NTFY_TOPIC_IN'"
  fi
  if [ -z "$device_url" ] && [ -n "$RUN_ID" ]; then
    device_url="$(fetch_device_url_via_notice || true)"
    [ -n "$device_url" ] && device_url_source="check-run notice annotation"
  fi
fi
if [ -z "$device_url" ]; then
  cat >&2 <<'MSG'
error: no device URL could be resolved from the available sources.

The device flow is a single long step, so its log is not readable through the
API while the run waits for approval. To finish the approval:
  1. Open the LIVE run page in the GitHub web UI — the step log streams the
     approval card while the code is still valid.
  2. Copy the "Open this URL on your phone to approve" link.
  3. Re-run this script with --device-url <url> (the run id is optional on
     that path), or set an ntfy topic so the card is pushed to ntfy.
The card is also exposed as a check-run notice annotation titled
"PierCloud device approval" once the step has minted the code.
MSG
  exit 1
fi
echo "device URL source: $device_url_source"
case "$device_url" in
  https://www.servercontrolpanel.de/realms/scp/*) ;;
  *) die "device URL is not on the expected netcup host — refusing to navigate (copy it from the live run page and pass --device-url)" ;;
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
