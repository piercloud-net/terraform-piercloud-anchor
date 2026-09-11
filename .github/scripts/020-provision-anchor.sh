#!/usr/bin/env bash
#
# 020-provision-anchor.sh — CI-called A1 self-open /32 SSH window + provisioning handoff.
#
# WHERE THIS RUNS: on the ephemeral GitHub Actions runner, inside the
# `provision.yml` device-flow job (same runner that holds the per-run netcup
# token — the token never leaves this runner; see "same-job handoff" in
# `.github/workflows/provision.yml`). This is NOT a human-run script: the
# human-run / on-box side stays in `scripts/010-provision.sh`. Numbering
# (020: next free after 010) is unique across `scripts/` + `.github/scripts/`.
#
# WHAT IT DOES (A1 hardened lifecycle, SPEC §"A1 self-open /32 window"):
#   sweep-pre  enumerate tmp policies -> classify (own / non-own / orphan) ->
#              fail-closed on orphan (no parseable created_at) BEFORE any
#              mutation -> retire EVERY non-own tmp (aged >2h or leaked
#              fresh: the workflow-wide mutex means no foreign run can be
#              live) -> drop this run's own leftovers.
#   open       dual-endpoint egress-IP fetch (exact match or fail) -> create
#              TTL-tagged tmp policy (idempotent on run_id: retry reuses the
#              existing policy, never duplicates) -> attach to the server NIC.
#   provision  re-fetch egress IP pre-SSH (mismatch -> abort to sweep) ->
#              plain ssh (no ansible): install 2 keys, pipe 010-provision.sh
#              (--rotate passes through), capture thumbprint to artifact path,
#              `passwd -l root` last. Prefers the pasted ROOT_PASSWORD when
#              set (legacy path, byte-for-byte); else the caller-set
#              BOOTSTRAP_ROOT_PASSWORD minted by bootstrap-password below.
#   bootstrap-password
#              passwordless bootstrap (issue #50): mint a one-time root
#              password (masked at birth) -> ensure RUNNING (power ON only
#              when needed; live 2026-09-10 #68: the set is guest-agent
#              based and completes only on a running VM — no power cycle)
#              -> wait for guest-agent status .available -> set via
#              ServerSetRootPasswordPatch (422 = fresh candidate, bounded)
#              -> poll SUCCESS -> export the masked value BEFORE the
#              SSH-wait (same-runner handoff; the workflow's finally-path
#              lock then covers every later death) -> TCP/SSH retry.
#              Skips minting when ROOT_PASSWORD_SECRET is set. Runs after
#              A1 open (workflow order, issue #59): the closing SSH-wait
#              needs the runner /32 :22 window.
#   lock-password
#              best-effort finally-path: `passwd -l root` over ssh with the
#              caller-set password. Never fails (the original failure owns
#              the verdict); no-ops when nothing was minted.
#   close      detach-then-delete the run's own tmp policy, always in that
#              order; missing policy is a success no-op (idempotent).
#   sweep-post delete this run's policy at any age + every tmp older than 2h
#              (+ orphans: no valid created_at) + UNATTACHED steady-state
#              orphans (issue #101 — the create-per-run leak). Tolerates a
#              missing token
#              (auth never completed -> nothing created -> clean no-op) so the
#              workflow `always()` post step never masks the real failure.
#
# ENV (all identifiers arrive via environment — never argv, never logs):
#   NETCUP_SCP_ACCESS_TOKEN  per-run device-flow token (required except
#                            sweep-post, which no-ops cleanly without it).
#                            The SCP access token lives ~5 min (live
#                            2026-09-11: tail steps 401'd after the async
#                            apply) — see NETCUP_SCP_REFRESH_TOKEN below.
#                            Every refresh re-appends the new value to the
#                            runner-local $GITHUB_ENV handoff (not just shell
#                            memory: call sites refresh inside command
#                            substitutions, whose variable updates die with
#                            the subshell). The file lives on this runner
#                            only and dies with it — same trust model as the
#                            token itself.
#   NETCUP_SCP_REFRESH_TOKEN optional offline_access token from the SAME
#                            device approval; on any 401 the REST helper
#                            re-mints the access token from it and retries
#                            once. In CI the poll step hands it over as a
#                            0600 runner-local FILE and exports only the
#                            PATH (NETCUP_SCP_REFRESH_TOKEN_FILE), so the
#                            ~30-day credential never enters the job env
#                            where every later step — including the
#                            community tofu provider — could read it.
#                            scp_token_refresh re-reads the file on entry
#                            (a subshell may already have rotated it) and
#                            rewrites it after every successful rotation,
#                            so a parent's retry uses the rotated token,
#                            never the consumed one. The direct env var
#                            stays supported for local harnesses (the file
#                            wins when both are set).
#                            Absent/empty = pre-refresh behaviour (fail loud).
#   NETCUP_SCP_REFRESH_TOKEN_FILE  path to that 0600 file (the CI handoff).
#   NETCUP_SCP_TOKEN_ENDPOINT Keycloak token endpoint for that refresh grant
#                            (resolved from the OIDC discovery doc by the
#                            device-request job; public, not a secret).
#   NETCUP_API_BASE          SCP REST base (default verified against the
#                            provider source: defaultBaseURL in
#                            rixlhq/terraform-provider-netcup
#                            internal/scpclient/client.go).
#   SERVER_ID / SCP_USER_ID  adopted server + policy-owning SCP user.
#   RUN_ID                   github.run_id — the idempotency key; the tmp
#                            policy name is piercloud-tmp-<server>-<run>.
#   ANCHOR_HOST              ssh target (anchor IPv4). ANCHOR_SSH_PORT (22).
#   ROOT_PASSWORD            emailed one-run root password. Add-masked in
#                            the workflow step before use (plus repo-secret
#                            auto-mask); referenced here ONLY as
#                            the sshpass environment value — never echoed,
#                            never logged, never written to disk. # ci-allowlist: prose — on-box credential-hygiene note, not a live storage reference.
#   ROOT_PASSWORD_SECRET   pasted-secret sentinel for bootstrap-password:
#                            non-empty means the tenant pasted the one-run
#                            secret, so minting is skipped (legacy path).
#   BOOTSTRAP_ROOT_PASSWORD  caller-set one-time password minted by
#                            bootstrap-password (add-masked at birth, unset
#                            after use); consumed by provision (fallback) and
#                            lock-password (finally-path). Same-runner
#                            handoff only — dies with the runner.
#   GATUS_ENDPOINTS          comma-separated name=url pairs (http(s), v1) for the
#                            dispatch-managed monitor config (repo secret — tenant
#                            service map stays write-only). NTFY_TOPIC/NTFY_TOKEN
#                            arrive the same way (empty = checks without push).
#   CF_ORIGIN_CERT_PEM     operator-planted Cloudflare Origin CA certificate
#   CF_ORIGIN_KEY_PEM      ... and private key (repo secrets, masked at birth
#   CF_AOP_CA_PEM          in the workflow like the root password; optional
#                            zone-level AOP client-auth bundle). Deployed key
#                            material for Caddy's :443 — NOT a standing API
#                            token (the box presents, never rewrites the zone).
#                            Empty = dashboard-TLS-pending (Caddy automatic
#                            HTTPS instead); tang is unaffected either way.
#   (No standing SSH keys by design 2026-09-08: mobile tenants can't use them;
#    re-entry is SCP password-reset + re-dispatch; the runner is the admin path.)
#   TENANT_USER                operator-set username (default monitor target:
#                            https://<user>.piercloud.net, derived — no input).
#   THUMBPRINT_FILE          artifact path for the captured tang thumbprint
#                            (default ./thumbprint.txt; the value is public).
#   PINNED_IP                runner IP pinned at open; provision re-fetches
#                            and aborts to sweep on mismatch (fail-closed).
#   INTERFACE_MAC            override NIC MAC (default: resolved via API).
#
# EXIT CODES: 0 ok · 1 error / cleanup incomplete (fail-closed, fail loudly) ·
#   3 fail-closed at pre-step (orphan tmp or a failed retire — operator must
#   look before re-dispatch).
#
# M0-GATED (no live netcup credentials exist; live run + verify-twice-live
# are pending — recorded honestly in the PR body, never claimed here):
#   request/response envelopes were derived from the provider's Go source
#   (policy CRUD spec, firewallSaveRequest/firewallReadResponse JSON tags)
#   plus envelope-tolerant jq; first live run confirms or corrects them.
#   Runs on ubuntu-latest only (GNU date for TTL math).
#
set -euo pipefail

TMP_TTL_SECONDS=7200 # 2h: tmp older than this is 'aged' (its run is long dead) on every sweep.
IP_ENDPOINT_A="https://api.ipify.org"
IP_ENDPOINT_B="https://ipv4.icanhazip.com"
ROTATE=0

log() { printf 'A1: %s\n' "$*"; }
warn() { printf 'A1 WARNING: %s\n' "$*" >&2; }
die() { printf 'A1 FAIL: %s\n' "$*" >&2; exit 1; }
surplus_fail() { printf 'A1 SURPLUS_FAIL_CLOSED: %s\n' "$*" >&2; exit 3; }

usage() {
  sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
  case "${1:-}" in
    --rotate) ROTATE=1; shift ;;
    -h | --help) usage; exit 0 ;;
    *) break ;;
  esac
done
CMD="${1:-}"
if [ $# -gt 0 ]; then shift; fi
case "$CMD" in
  sweep-pre | open | provision | close | sweep-post | bootstrap-password | lock-password) ;;
  *) die "usage: $0 [--rotate] {sweep-pre|open|provision|close|sweep-post|bootstrap-password|lock-password}" ;;
esac

# Injection guards: every value interpolated into an API path, jq argv or
# generated HCL/shell must match its strict shape first — a malformed or
# crafted API response is not a source of shell syntax. Fail closed, never
# fall back.
all_digits() { case "$1" in '' | *[!0-9]*) return 1 ;; esac; }
valid_mac() {
  # Whole-value anchor, newline-safe (review security N2): grep is
  # line-oriented, so 'aa:bb:cc:dd:ee:ff\nanything' matched its FIRST line
  # and passed. Reject newline/CR explicitly, then anchor the whole
  # (necessarily single-line) value.
  case "$1" in '' | *[$'\n\r']*) return 1 ;; esac
  printf '%s' "$1" | grep -qE '^[0-9a-fA-F:]{17}$'
}

# Sweep mode gate (review security MEDIUM): only apply may detach/delete
# policies. check/update-ip/destroy — and an invocation with MODE unset
# (local use) — are report-only: they classify and fail closed on anomalies,
# but never mutate. provision.yml passes MODE: ${{ inputs.mode }} to both
# sweep steps.
sweep_destructive() {
  [ "$MODE" = "apply" ]
}
sweep_note() { # $1 = message -> log + step summary (report-only evidence)
  log "$1"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    printf 'A1 sweep: %s\n' "$1" >>"$GITHUB_STEP_SUMMARY"
  fi
}

NETCUP_API_BASE="${NETCUP_API_BASE:-https://www.servercontrolpanel.de/scp-core}"
SERVER_ID="${SERVER_ID:-}"
SCP_USER_ID="${SCP_USER_ID:-}"
RUN_ID="${RUN_ID:-}"
MODE="${MODE:-}"
# lock-password is the SSH-only finally-path (no API use): it must run even
# when resolve never produced ids, so it is exempt from the id guards.
case "$CMD" in
  lock-password) ;;
  *)
    [ -n "$SERVER_ID" ] || die "SERVER_ID is required"
    all_digits "$SERVER_ID" || die "SERVER_ID is not all-digits — refusing to interpolate it into API paths (injection guard)"
    [ -n "$SCP_USER_ID" ] || die "SCP_USER_ID is required"
    all_digits "$SCP_USER_ID" || die "SCP_USER_ID is not all-digits — refusing to interpolate it into API paths (injection guard)"
    [ -n "$RUN_ID" ] || die "RUN_ID is required (idempotency key)"
    ;;
esac

TMP_PREFIX="piercloud-tmp-${SERVER_ID}-"
OWN_NAME="piercloud-tmp-${SERVER_ID}-${RUN_ID}"
# Steady-state (module-managed) policy family: piercloud-anchor-<hostname>-<server_id>.
STEADY_PREFIX="piercloud-anchor-"

require_token() {
  if [ -z "${NETCUP_SCP_ACCESS_TOKEN:-}" ]; then
    die "NETCUP_SCP_ACCESS_TOKEN is required for '$CMD'"
  fi
}

# ---------------------------------------------------------------------------
# SCP REST helpers (curl -sS only — never -v; the bearer token travels in the
# header, responses are error-truncated before printing so a surprising echo
# can never leak request state into logs).
# ---------------------------------------------------------------------------
# Re-mint the access token from the device grant's own refresh token
# (offline_access was already requested at approval). No new standing secret,
# no new fallback: the refresh token is minted by the same human approval and
# dies with the runner (C-d). Returns non-zero when unavailable/refused, so
# callers keep the pre-existing fail-loud 401 path.
#
# Subshell/rotation safety: callers routinely refresh inside command
# substitutions (e.g. `pid="$(own_policy_id)"`), whose in-process variable
# updates die with the subshell. The REFRESH token is handed over as a 0600
# runner-local FILE ($NETCUP_SCP_REFRESH_TOKEN_FILE) — never via the job env,
# which every later step (including the community tofu provider) can read —
# and the function re-reads that file on entry, so a parent's later 401
# retries with the ROTATED refresh token instead of the consumed one. The
# ACCESS token is still appended to $GITHUB_ENV (the provider genuinely
# consumes it) and re-adopted on entry; both live on this runner only and die
# with it (C-d trust model unchanged).
# Token-response guard (review security N0): a crafted/compromised token
# response must never forge extra $GITHUB_ENV lines (e.g. a second line
# redirecting NETCUP_API_BASE to an attacker-controlled base, inherited by
# every later step) nor smuggle control bytes into the 0600 refresh-token
# handoff file. Same semantics as the workflow's guard_line: reject
# newline/CR, then any non-printable character. Fail closed BEFORE masking or
# persisting either value.
# Caveat (reviewer INFO): bash strips NUL and trailing newlines before this
# guard sees a value — do not over-trust it for those two shapes.
guard_token_value() { # $1 label, $2 value
  case "$2" in
    *[$'\n\r']*) die "SCP token response $1 contains a newline/CR — refusing the handoff write (injection guard)" ;;
  esac
  if [ -n "$(printf '%s' "$2" | LC_ALL=C tr -d '[:print:]')" ]; then
    die "SCP token response $1 contains non-printable characters — refusing the handoff write (injection guard)"
  fi
}

scp_token_refresh() {
  # Re-read the newest handoff values FIRST: a subshell may have refreshed
  # already and the realm may rotate the refresh token on use, so the
  # parent's copy can be the consumed one. Every writer overwrites the whole
  # refresh-token file, so its content is the newest value; the access-token
  # appends are append-only, so the LAST line in $GITHUB_ENV is the newest.
  local f_at f_rt
  if [ -n "${NETCUP_SCP_REFRESH_TOKEN_FILE:-}" ] && [ -r "$NETCUP_SCP_REFRESH_TOKEN_FILE" ]; then
    f_rt="$(head -c 8192 "$NETCUP_SCP_REFRESH_TOKEN_FILE" | tr -d '\r\n')"
    if [ -n "$f_rt" ]; then
      NETCUP_SCP_REFRESH_TOKEN="$f_rt"
      export NETCUP_SCP_REFRESH_TOKEN
    fi
  fi
  if [ -n "${GITHUB_ENV:-}" ] && [ -f "$GITHUB_ENV" ]; then
    f_at="$(grep -a '^NETCUP_SCP_ACCESS_TOKEN=' "$GITHUB_ENV" | tail -1 | cut -d= -f2- || true)"
    # Adoption is UNCONDITIONAL: a non-empty handoff value can only have
    # been appended by a refresh in THIS step — every step gets a fresh empty
    # $GITHUB_ENV from the runner (reviewer-verified against the runner
    # sources), and only scp_token_refresh appends this name. Adopt the
    # last (newest) value, replacing a possibly-consumed in-process copy; no
    # other guard is needed (an earlier "never resurrect" guard described a
    # harness artifact, not production).
    if [ -n "$f_at" ]; then
      NETCUP_SCP_ACCESS_TOKEN="$f_at"
      export NETCUP_SCP_ACCESS_TOKEN
    fi
  fi
  [ -n "${NETCUP_SCP_REFRESH_TOKEN:-}" ] || return 1
  [ -n "${NETCUP_SCP_TOKEN_ENDPOINT:-}" ] || return 1
  # Endpoint pin (review security MEDIUM): the refresh token may only ever go
  # to the live SCP Keycloak realm. A tampered/hijacked discovery document
  # would otherwise receive the credential — refuse loudly instead.
  case "$NETCUP_SCP_TOKEN_ENDPOINT" in
    https://www.servercontrolpanel.de/realms/scp/*) ;;
    *) die "NETCUP_SCP_TOKEN_ENDPOINT is not an https://www.servercontrolpanel.de/realms/scp/ endpoint — refusing to send the refresh token (endpoint pin)" ;;
  esac
  local resp at rt tf
  # Token off argv (review security MEDIUM): --data-urlencode with the literal
  # value is world-readable via /proc/<pid>/cmdline; write it to a 0600 temp
  # file (mktemp's default mode) and use curl's @file form instead.
  tf="$(mktemp)"
  printf '%s' "$NETCUP_SCP_REFRESH_TOKEN" >"$tf"
  if ! resp="$(curl -sS --max-time 30 -X POST "$NETCUP_SCP_TOKEN_ENDPOINT" \
    --data-urlencode "grant_type=refresh_token" \
    --data-urlencode "client_id=scp" \
    --data-urlencode "refresh_token@$tf")"; then
    rm -f "$tf"
    return 1
  fi
  rm -f "$tf"
  at="$(printf '%s' "$resp" | jq -r '.access_token // empty' 2>/dev/null)" || return 1
  [ -n "$at" ] || return 1
  rt="$(printf '%s' "$resp" | jq -r '.refresh_token // empty' 2>/dev/null)" || rt=""
  # Guard BOTH values before anything else writes them anywhere (review
  # security N0, live-proven): the poll step guards the FIRST token response,
  # but this refresh path (every 401 after ~5 min) did not — an injected
  # newline in .access_token forged a second $GITHUB_ENV line (e.g.
  # NETCUP_API_BASE to an attacker-controlled base), which every later step
  # then inherited, sending the Bearer token to the attacker while the run
  # stayed green. If
  # either value fails the guard, NOTHING is written — no mask, no env
  # append, no refresh-token file.
  guard_token_value "access_token" "$at"
  if [ -n "$rt" ]; then
    guard_token_value "refresh_token" "$rt"
  fi
  # Mask FIRST, before any use — on stderr deliberately: stdout here is
  # routinely captured as data (command substitution / pipeline), where a
  # mask line would corrupt the capture AND never reach the runner. The
  # runner scans BOTH streams for workflow commands (ScriptHandler wires
  # stdout and stderr through the same ActionCommandManager).
  echo "::add-mask::$at" >&2
  NETCUP_SCP_ACCESS_TOKEN="$at"
  export NETCUP_SCP_ACCESS_TOKEN
  if [ -n "$rt" ]; then
    echo "::add-mask::$rt" >&2
    NETCUP_SCP_REFRESH_TOKEN="$rt"
    export NETCUP_SCP_REFRESH_TOKEN
    # Persist the rotation for parent shells: rewrite the 0600 handoff file
    # (the in-process assignment dies with a subshell). A failed rewrite is a
    # warning, not fatal: the in-process value is already fresh.
    if [ -n "${NETCUP_SCP_REFRESH_TOKEN_FILE:-}" ]; then
      (umask 077; printf '%s' "$rt" >"$NETCUP_SCP_REFRESH_TOKEN_FILE") \
        || warn "could not persist the rotated refresh token to $NETCUP_SCP_REFRESH_TOKEN_FILE — a parent shell's later 401 may present the consumed token"
    fi
  fi
  # Persist the same-runner handoff: the in-process assignments above die
  # with a subshell, so a parent's later 401 must see the fresh ACCESS token.
  # $GITHUB_ENV is a runner-local FILE that dies with the runner — the trust
  # model is unchanged. Append (never rewrite): the newest value is the last
  # line. The refresh token goes to its 0600 file above, never here.
  if [ -n "${GITHUB_ENV:-}" ]; then
    printf 'NETCUP_SCP_ACCESS_TOKEN=%s\n' "$at" >>"$GITHUB_ENV" \
      || warn "could not persist the refreshed access token to \$GITHUB_ENV — a later step may miss the fresh token and 401"
  fi
  # stderr DELIBERATELY: this function runs inside api_call, and several of
  # api_call's callers are captured as data (`pid="$(own_policy_id)"`,
  # `list="$(list_tmp_policies)"`, `mac="$(resolve_mac)"`, ...). A stdout line
  # from here is prepended to that capture and breaks the jq parse (live
  # 2026-09-11: rc 5 on `pid="$(own_policy_id)"`, empty pid, window policy
  # leaked). The ::add-mask:: lines above are on stderr for the same reason;
  # the runner scans both streams for workflow commands.
  log "scp token refreshed (access token TTL is ~5 min; long runs cross it)" >&2
  return 0
}

_api_curl() { # method path body ctype resp_file -> sets HTTP_STATUS
  local method="$1" path="$2" body="$3" ctype="$4" resp_file="$5"
  if [ -n "$body" ]; then
    HTTP_STATUS="$(curl -sS --max-time 30 -o "$resp_file" -w '%{http_code}' \
      -X "$method" "${NETCUP_API_BASE}${path}" \
      -H "Authorization: Bearer ${NETCUP_SCP_ACCESS_TOKEN}" \
      -H "Content-Type: $ctype" -H 'Accept: application/json' \
      -d "$body")"
  else
    HTTP_STATUS="$(curl -sS --max-time 30 -o "$resp_file" -w '%{http_code}' \
      -X "$method" "${NETCUP_API_BASE}${path}" \
      -H "Authorization: Bearer ${NETCUP_SCP_ACCESS_TOKEN}" \
      -H 'Accept: application/json')"
  fi
}

api_call() { # method path [body] [outvar] [content-type] -> sets HTTP_STATUS; body to stdout or $outvar
  # Subshell warning: callers MUST NOT use resp="$(api_call ...)" — command
  # substitution forks, and HTTP_STATUS set inside would die with it (live
  # failure 2026-09-08: every call site read an unbound HTTP_STATUS). Pass
  # the response-variable name instead; printf -v fills it in THIS shell.
  # Server PATCHes speak application/merge-patch+json (live spec); firewall
  # CRUD stays on the application/json default.
  local method="$1" path="$2" body="${3:-}" outvar="${4:-}" ctype="${5:-application/json}"
  local resp_file status content
  resp_file="$(mktemp)"
  _api_curl "$method" "$path" "$body" "$ctype" "$resp_file"
  status="$HTTP_STATUS"
  if [ "$status" = "401" ] && scp_token_refresh; then
    # A 401 is rejected BEFORE processing (no side effect), so replaying the
    # same request once with the re-minted token is safe for every verb used
    # here (GET/POST/PUT/PATCH/DELETE). One retry only — a second 401 is a
    # real authz problem and must stay loud.
    _api_curl "$method" "$path" "$body" "$ctype" "$resp_file"
    status="$HTTP_STATUS"
  fi
  HTTP_STATUS="$status"
  content="$(cat "$resp_file")" # same trailing-newline strip as $(...) capture — callers already live with it
  rm -f "$resp_file"
  if [ -n "$outvar" ]; then
    printf -v "$outvar" '%s' "$content"
  else
    printf '%s' "$content"
  fi
}

api_ok() { # $1 = status; 2xx (+404-as-gone when $2=gone-ok)
  case "$1" in
    2*) return 0 ;;
    404) [ "${2:-}" = "gone-ok" ] && return 0; return 1 ;;
    *) return 1 ;;
  esac
}

policies_path() { printf '/api/v1/users/%s/firewall-policies' "$SCP_USER_ID"; }

list_steady_policies() { # -> [{id,name,description}] for THIS server's steady-state policy family
  local resp
  api_call GET "$(policies_path)" "" resp
  api_ok "$HTTP_STATUS" || die "list policies failed (HTTP $HTTP_STATUS): $(printf '%s' "$resp" | head -c 500)"
  printf '%s' "$resp" | jq -c \
    'if type == "array" then .
     elif has("firewallPolicies") then .firewallPolicies
     elif has("data") then .data
     elif has("items") then .items
     elif has("policies") then .policies
     elif has("firewallPolicy") then [.firewallPolicy]
     else [] end
     | map(select(((.name // "") | startswith($p)) and ((.name // "") | endswith($s)))
           | {id: .id, name: .name, description: (.description // "")})' \
    --arg p "$STEADY_PREFIX" --arg s "-${SERVER_ID}"
}

list_tmp_policies() { # -> compact JSON array [{id,name,description}] (ours only)
  local resp
  api_call GET "$(policies_path)" "" resp
  api_ok "$HTTP_STATUS" || die "list policies failed (HTTP $HTTP_STATUS): $(printf '%s' "$resp" | head -c 500)"
  printf '%s' "$resp" | jq -c \
    'if type == "array" then .
     elif has("firewallPolicies") then .firewallPolicies
     elif has("data") then .data
     elif has("items") then .items
     elif has("policies") then .policies
     elif has("firewallPolicy") then [.firewallPolicy]
     else [] end
     | map(select((.name // "") | startswith($p))
           | {id: .id, name: .name, description: (.description // "")})' \
    --arg p "$TMP_PREFIX"
}

policy_age() { # $1 = description -> seconds | "orphan" (no valid created_at)
  local desc="$1" ts now created
  if ! printf '%s' "$desc" | grep -q 'purpose=A1-ssh'; then
    printf 'orphan'
    return 0
  fi
  ts="$(printf '%s' "$desc" | sed -n 's/.*created_at=\([^ ]*\).*/\1/p')"
  created="$(date -u -d "$ts" '+%s' 2>/dev/null || printf '')"
  if [ -z "$created" ]; then
    printf 'orphan'
    return 0
  fi
  now="$(date -u '+%s')"
  printf '%s' "$((now - created))"
}

fetch_egress_ip() { # dual-endpoint pin, exact match or fail (single host only, never a range)
  local a b
  a="$(curl -sS --max-time 20 "$IP_ENDPOINT_A" | tr -d '[:space:]')"
  b="$(curl -sS --max-time 20 "$IP_ENDPOINT_B" | tr -d '[:space:]')"
  if ! printf '%s' "$a" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
    die "egress-IP endpoint A returned unusable value (fail-closed, not logged)"
  fi
  if ! printf '%s' "$b" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
    die "egress-IP endpoint B returned unusable value (fail-closed, not logged)"
  fi
  if [ "$a" != "$b" ]; then
    die "egress-IP endpoints disagree (fail-closed): A and B differ — aborting, no window opened"
  fi
  printf '%s' "$a"
}

resolve_mac() {
  local resp mac
  if [ -n "${INTERFACE_MAC:-}" ]; then
    valid_mac "$INTERFACE_MAC" || die "INTERFACE_MAC override is not a 17-char hex/colon MAC — refusing to interpolate it into API paths (injection guard)"
    printf '%s' "$INTERFACE_MAC"
    return 0
  fi
  api_call GET "/api/v1/servers/${SERVER_ID}/interfaces" "" resp
  api_ok "$HTTP_STATUS" || die "list server interfaces failed (HTTP $HTTP_STATUS)"
  # Lexicographically smallest MAC — the exact same jq rule as the
  # import-discovery step in provision.yml and main.tf's local.interface_mac
  # (`try(sort([...mac])[0], null)`, "sorted for determinism"). On a >1-NIC
  # server any other pick reads the WRONG interface: the live steady-state
  # policy looks unattached and sweep-post deletes it.
  mac="$(printf '%s' "$resp" | jq -r 'if type == "array" then . elif has("data") then .data elif has("items") then .items elif has("interfaces") then .interfaces else . end | if type == "array" then (map(.mac // empty) | sort | .[0] // empty) else (.mac // empty) end')"
  [ -n "$mac" ] || die "could not resolve NIC MAC for server $SERVER_ID (set INTERFACE_MAC)"
  valid_mac "$mac" || die "resolved NIC MAC is not a 17-char hex/colon value — refusing to interpolate it into API paths (injection guard)"
  printf '%s' "$mac"
}

iface_fw_get() { # $1 = mac -> raw interface-firewall JSON
  local resp
  api_call GET "/api/v1/servers/${SERVER_ID}/interfaces/$1/firewall" "" resp
  api_ok "$HTTP_STATUS" || die "read interface firewall failed (HTTP $HTTP_STATUS)"
  printf '%s' "$resp"
}

iface_fw_put() { # $1 = mac, $2 = user-policy id JSON array -> PUT merged save body
  local mac="$1" ids_json="$2" current active copied body resp
  current="$(iface_fw_get "$mac")"
  active="$(printf '%s' "$current" | jq -r '.active // true')"
  copied="$(printf '%s' "$current" | jq -c '[.copiedPolicies // [] | .[] | {id: (.id // .)}]')"
  body="$(jq -n -c --argjson u "$ids_json" --argjson c "$copied" --argjson a "$active" \
    '{active: $a, copiedPolicies: $c, userPolicies: ($u | map({id: .}))}')"
  api_call PUT "/api/v1/servers/${SERVER_ID}/interfaces/${mac}/firewall" "$body" resp
  if ! api_ok "$HTTP_STATUS"; then
    die "save interface firewall failed (HTTP $HTTP_STATUS): $(printf '%s' "$resp" | head -c 500)"
  fi
  if [ "$HTTP_STATUS" = "202" ]; then
    sleep 5 # async accept: bounded re-read to confirm convergence (M0 confirms)
    iface_fw_get "$mac" >/dev/null
  fi
}

attach_policy() { # $1 = policy id (idempotent merge under the global mutex)
  local id="$1" mac current_ids merged
  all_digits "$id" || die "attach_policy: policy id is not all-digits — refusing to interpolate it into API paths (injection guard)"
  mac="$(resolve_mac)"
  current_ids="$(iface_fw_get "$mac" | jq -c '[.userPolicies // [] | .[] | (.id // .)]')"
  if printf '%s' "$current_ids" | jq -e --argjson i "$id" 'index($i) != null' >/dev/null; then
    log "policy $id already attached (idempotent reuse)"
    return 0
  fi
  merged="$(printf '%s' "$current_ids" | jq -c --argjson i "$id" '. + [$i] | unique')"
  iface_fw_put "$mac" "$merged"
  log "attached policy $id to ${SERVER_ID}/${mac}"
}

detach_policy() { # $1 = policy id (absent = success no-op)
  local id="$1" mac current_ids merged
  all_digits "$id" || die "detach_policy: policy id is not all-digits — refusing to interpolate it into API paths (injection guard)"
  mac="$(resolve_mac)"
  current_ids="$(iface_fw_get "$mac" | jq -c '[.userPolicies // [] | .[] | (.id // .)]')"
  if ! printf '%s' "$current_ids" | jq -e --argjson i "$id" 'index($i) != null' >/dev/null; then
    log "policy $id not attached (nothing to detach)"
    return 0
  fi
  merged="$(printf '%s' "$current_ids" | jq -c --argjson i "$id" 'map(select(. != $i))')"
  iface_fw_put "$mac" "$merged"
  log "detached policy $id from ${SERVER_ID}/${mac}"
}

delete_policy() { # $1 = policy id (404 = already gone, success)
  local id="$1" resp
  all_digits "$id" || die "delete_policy: policy id is not all-digits — refusing to interpolate it into API paths (injection guard)"
  api_call DELETE "$(policies_path)/${id}" "" resp
  if ! api_ok "$HTTP_STATUS" "gone-ok"; then
    die "delete policy $id failed (HTTP $HTTP_STATUS): $(printf '%s' "$resp" | head -c 500)"
  fi
  log "deleted policy $id"
}

own_policy_id() { # -> id of piercloud-tmp-<server>-<run> or empty
  list_tmp_policies | jq -r --arg n "$OWN_NAME" 'map(select(.name == $n)) | .[0].id // empty'
}

close_policy() { # $1 = policy id: detach-then-delete, ALWAYS in that order
  local id="$1" rc=0
  detach_policy "$id" || rc=1
  delete_policy "$id" || rc=1
  return "$rc"
}

# ---------------------------------------------------------------------------
# sweep-pre: enumerate -> classify (own / non-own / orphan) -> fail closed on
# orphan BEFORE any mutation -> retire EVERY non-own tmp (aged >2h or
# leaked-fresh) -> drop this run's own leftovers (open recreates the window).
#
# SINGLE-WRITER-PER-ACCOUNT ASSUMPTION (why retiring a FRESH non-own tmp is
# safe here): provision.yml pins concurrency.group=piercloud-netcup-policy, a
# STATIC literal that serializes every run of THIS workflow for EVERY tenant,
# so at pre-sweep no other run of this repo can hold a tmp. It does NOT
# serialize another repo sharing the same netcup account — one account must
# have exactly ONE writer (this repo's workflow); two writers on one account
# are out of contract. The tradeoff is deliberate: an attached leaked tmp
# keeps admitting a stale runner /32 to :22 for as long as it lives (GitHub
# recycles runner IPs), so the fresh leak is retired now rather than at 2h.
# ---------------------------------------------------------------------------
cmd_sweep_pre() {
  require_token
  local list count entry name desc age pid
  local classify="" owns="" aged=0 leaked=0
  list="$(list_tmp_policies)"
  count="$(printf '%s' "$list" | jq 'length')"
  log "pre-sweep: $count tmp polic(ies) on server $SERVER_ID"
  # Pass 1 — classify ONLY, mutate nothing yet: OWN leftovers (a retry is
  # normal; duplicates are possible through async races), NON-OWN (aged >2h
  # = dead run, or fresh = leaked by a dead run: provision.yml's workflow-wide
  # concurrency.group serializes every run OF THIS REPO, so a non-own tmp can
  # never belong to a live run here; another repo on the same account is out
  # of contract), ORPHAN (no valid created_at — ambiguous, operator must
  # look). The fail-closed verdict is decided before any retirement (review
  # MINOR-1: never sweep half the list and then bail).
  while IFS= read -r entry; do
    [ -n "$entry" ] || continue
    name="$(printf '%s' "$entry" | jq -r '.name')"
    desc="$(printf '%s' "$entry" | jq -r '.description')"
    pid="$(printf '%s' "$entry" | jq -r '.id')"
    if [ "$name" = "$OWN_NAME" ]; then
      # dropped below; open recreates the window from the pinned /32
      owns="${owns}${pid}
"
      continue
    fi
    age="$(policy_age "$desc")"
    if [ "$age" = "orphan" ]; then
      surplus_fail "orphan tmp policy '$name' (no valid created_at) at pre-step — refusing to create. Notify the operator."
    fi
    classify="${classify}${pid}|${name}|${age}
"
  done < <(printf '%s' "$list" | jq -c '.[]')
  # Pass 2 — retire every non-own tmp (close_policy = detach-then-delete),
  # then this run's own leftovers. A failed retire stays fail-closed. All of
  # this mutates ONLY in apply mode: report-only modes enumerate and log the
  # would-be retirements (plus a step-summary line) instead.
  local rest rp rn ra
  while IFS= read -r entry; do
    [ -n "$entry" ] || continue
    rp="${entry%%|*}"; rest="${entry#*|}"
    rn="${rest%%|*}"; ra="${rest#*|}"
    if [ "$ra" -gt "$TMP_TTL_SECONDS" ]; then
      aged=$((aged + 1))
      if sweep_destructive; then
        log "pre-sweep: retiring aged tmp policy '$rn' (age ${ra}s — its run is long gone)"
      else
        sweep_note "pre-sweep: REPORT-ONLY (mode=${MODE:-unset}): aged tmp policy '$rn' (age ${ra}s) would be retired by an apply run"
      fi
    else
      leaked=$((leaked + 1))
      # GitHub recycles runner IPs: a leaked tmp keeps admitting a stale
      # runner /32 to :22 for as long as it lives. The mutex means its run
      # is dead — retire it now instead of waiting for the 2h age.
      if sweep_destructive; then
        log "pre-sweep: retiring leaked tmp policy '$rn' (age ${ra}s — its run is dead under the workflow mutex)"
      else
        sweep_note "pre-sweep: REPORT-ONLY (mode=${MODE:-unset}): leaked tmp policy '$rn' (age ${ra}s) would be retired by an apply run"
      fi
    fi
    if sweep_destructive; then
      close_policy "$rp" || surplus_fail "could not retire tmp policy '$rn' — operator must clean up by hand."
    fi
  done <<<"$classify"
  if [ "$aged" -gt 0 ] || [ "$leaked" -gt 0 ]; then
    if sweep_destructive; then
      log "pre-sweep: retired $aged aged + $leaked leaked tmp polic(ies)"
    else
      sweep_note "pre-sweep: REPORT-ONLY (mode=${MODE:-unset}): $aged aged + $leaked leaked tmp polic(ies) need attention — run mode=apply to retire them"
    fi
  fi
  while IFS= read -r entry; do
    [ -n "$entry" ] || continue
    if sweep_destructive; then
      log "pre-sweep: dropping own leftover policy $entry (hard-killed attempt of this run)"
      close_policy "$entry"
    else
      sweep_note "pre-sweep: REPORT-ONLY (mode=${MODE:-unset}): own leftover policy $entry would be dropped by an apply run"
    fi
  done <<<"$owns"
  if sweep_destructive; then
    log "pre-sweep clean"
  else
    sweep_note "pre-sweep clean in REPORT-ONLY mode (mode=${MODE:-unset}); no policy was retired"
  fi
}

# ---------------------------------------------------------------------------
# open: pin IP -> idempotent create -> attach.
# ---------------------------------------------------------------------------
cmd_open() {
  require_token
  local ip created_at desc body resp pid
  ip="$(fetch_egress_ip)"
  log "runner egress pinned to a single /32 (value withheld from this line on purpose)"
  pid="$(own_policy_id)"
  if [ -n "$pid" ]; then
    log "own policy $OWN_NAME already exists (id $pid) — retry reuses it, never duplicates"
  else
    created_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    desc="created_at=${created_at} purpose=A1-ssh"
    body="$(jq -n -c --arg n "$OWN_NAME" --arg d "$desc" --arg s "${ip}/32" \
      '{name: $n, description: $d, rules: [{action: "ACCEPT", direction: "INGRESS", protocol: "TCP", destination_ports: "22", sources: [$s]}]}')"
    api_call POST "$(policies_path)" "$body" resp
    if ! api_ok "$HTTP_STATUS"; then
      die "create tmp policy failed (HTTP $HTTP_STATUS): $(printf '%s' "$resp" | head -c 500)"
    fi
    pid="$(printf '%s' "$resp" | jq -r '.firewallPolicy.id // .id // empty')"
    if [ -z "$pid" ] && [ "$HTTP_STATUS" = "202" ]; then
      sleep 5 # async accept: re-list to learn the id (M0 confirms envelope)
      pid="$(own_policy_id)"
    fi
    [ -n "$pid" ] || die "create accepted but policy id not returned — refusing to continue blind"
    log "created tmp policy $OWN_NAME (id $pid)"
  fi
  attach_policy "$pid"
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    echo "pinned_ip=${ip}" >>"$GITHUB_OUTPUT"
  fi
  log "A1 window open: single TCP/22 rule for the pinned runner /32"
}

# ---------------------------------------------------------------------------
# provision: re-fetch + pin check -> plain ssh -> thumbprint -> lock root.
# ---------------------------------------------------------------------------
ssh_base() {
  # "$@" is load-bearing: without it every remote command is silently
  # ignored (the runner would "succeed" while installing, capturing, and
  # locking nothing). Stdin still flows to the remote command (bash -s).
  sshpass -e ssh -p "${ANCHOR_SSH_PORT:-22}" \
    -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 \
    -o BatchMode=no "root@${ANCHOR_HOST}" "$@"
}

cmd_provision() {
  require_token
  ANCHOR_HOST="${ANCHOR_HOST:-}"
  [ -n "$ANCHOR_HOST" ] || die "ANCHOR_HOST is required for provision"
  ANCHOR_HOST="${ANCHOR_HOST%%/*}"  # email prints 203.0.113.10/22-style — strip any /suffix
  case "$ANCHOR_HOST" in ''|*[!0-9.]*) die "ANCHOR_HOST is not a bare IPv4 after stripping any /suffix";; esac
  # Credential source: pasted ROOT_PASSWORD wins (legacy path, byte-for-byte
  # today's behavior); empty means bootstrap-password minted a caller-set
  # one-time value earlier in this run (passwordless path).
  EFFECTIVE_PASSWORD="${ROOT_PASSWORD:-${BOOTSTRAP_ROOT_PASSWORD:-}}"
  [ -n "$EFFECTIVE_PASSWORD" ] || die "no root password: set the ANCHOR_ROOT_PASSWORD secret (legacy) or run bootstrap-password first (passwordless)"
  if [ -z "${ROOT_PASSWORD:-}" ]; then
    log "passwordless path: using the caller-set one-time password minted this run"
  fi
  # No standing SSH keys (see header): password dies at root lock, re-entry is
  # per-event via SCP password-reset + re-dispatch — no credential stands anywhere.
  local fresh thumb out
  out="${THUMBPRINT_FILE:-./thumbprint.txt}"
  if [ -n "${PINNED_IP:-}" ]; then
    fresh="$(fetch_egress_ip)"
    if [ "$fresh" != "$PINNED_IP" ]; then
      warn "runner egress changed mid-run (pin mismatch) — aborting to sweep"
      cmd_sweep_post || true
      die "pre-SSH re-fetch mismatch: window no longer admits this runner"
    fi
    log "pre-SSH re-fetch matches the pinned /32"
  fi
  command -v sshpass >/dev/null || {
    log "installing sshpass on the runner (password transport for the one-run credential)"
    sudo apt-get install -y -qq sshpass >/dev/null
  }
  log "anchor host key (first-install TOFU — pin this fingerprint out-of-band):"
  ssh-keyscan -p "${ANCHOR_SSH_PORT:-22}" "$ANCHOR_HOST" 2>/dev/null | ssh-keygen -lf - || true
  export SSHPASS="$EFFECTIVE_PASSWORD"
  EFFECTIVE_PASSWORD=""
  log "running on-box provision (plain ssh, no ansible)"
  # Monitor config rides in as env (single-quote escaped): the tenant converges
  # monitors from a phone via repo secret + re-dispatch — no key, no console.
  q() { printf %s "$1" | sed "s/'/'\\\\''/g"; }
  ENV_PREFIX="export TENANT_USER='$(q "${TENANT_USER:-}")' GATUS_ENDPOINTS='$(q "${GATUS_ENDPOINTS:-}")' NTFY_TOPIC='$(q "${NTFY_TOPIC:-}")' NTFY_TOKEN='$(q "${NTFY_TOKEN:-}")' CF_ORIGIN_CERT_PEM='$(q "${CF_ORIGIN_CERT_PEM:-}")' CF_ORIGIN_KEY_PEM='$(q "${CF_ORIGIN_KEY_PEM:-}")' CF_AOP_CA_PEM='$(q "${CF_AOP_CA_PEM:-}")';"
  if [ "$ROTATE" -eq 1 ]; then
    warn "--rotate requested: forwarded to the on-box script; on-box key rotation (dot-out old keys per netcup rotation procedure) is pending — re-run converges idempotently today"
  fi
  if [ "$ROTATE" -eq 1 ]; then
    { echo "$ENV_PREFIX"; cat scripts/010-provision.sh; } | ssh_base 'bash -s -- --rotate'
  else
    { echo "$ENV_PREFIX"; cat scripts/010-provision.sh; } | ssh_base 'bash -s'
  fi
  log "capturing tang thumbprint to the artifact path"
  # Thumbprint source order (live 2026-09-10, #87): the collapse records the
  # kept sign key in ${KD}/.published-thp; else upstream's tang-show-keys
  # (ships with tang; filters the payload to verify keys). No URL fallback
  # here: the CI-called surface may not carry unlisted endpoints, and the
  # previous file-based attempt (`jose jwk thp -a S256 -r -f …`) never worked
  # on jose 14+ (`-r` removed; `-f` means find) — so fail loud instead.
  thumb="$(ssh_base 'KD="$(systemctl cat tangd@.service 2>/dev/null | sed -n "s/^ExecStart=.*[[:space:]]\(.*\)$/\1/p" | tail -n1)"; [ -n "${KD}" ] || KD=/var/lib/tang; if [ -s "${KD}/.published-thp" ]; then cat "${KD}/.published-thp"; elif command -v tang-show-keys >/dev/null 2>&1; then tang-show-keys 8081; else echo "no ${KD}/.published-thp and no tang-show-keys on this box: reinstall the tang package or restore the file — refusing to publish an unverifiable thumbprint" >&2; exit 1; fi' | head -n 1 | tr -d '[:space:]')"
  if [ -z "$thumb" ] || printf '%s' "$thumb" | grep -q '[[:space:]]'; then
    die "thumbprint capture failed (empty or malformed) — refusing to finish without it (H1: never logs alone)"
  fi
  printf '%s\n' "$thumb" >"$out"
  chmod 644 "$out"
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    echo "thumbprint=${thumb}" >>"$GITHUB_OUTPUT"
  fi
  log "thumbprint captured (value in artifact, not in this log)"
  ssh_base 'passwd -l root'
  log "root password locked (passwd -l root); the one-run credential is now dead"
  unset SSHPASS
}

# ---------------------------------------------------------------------------
# bootstrap-password: mint a caller-set one-time root password and set it
# on the RUNNING box via the guest agent (issue #50 — tenant pastes 1
# secret). Live 2026-09-10 (#68): netcup's SetRootPasswordTask is
# guest-agent-based and completes ONLY while the VM is RUNNING — every
# SHUTOFF set errored (error.internalserver, passwordChangeFailed: true,
# SCP log "Root password could not be changed"); the helpcenter "must be
# powered off" is stale. So: no power cycle — power ON only when the box
# is not RUNNING, then wait (bounded, fail-closed) for the agent to
# report available before the set. Async PATCHes return 202 + TaskInfo:
# poll GET /tasks/{uuid} to FINISHED. 409 server.lock.error: backoff +
# retry, bounded. The candidate travels via the sshpass environment
# value and jq $ENV (same-runner process argv only — masked in logs,
# never persisted); task bodies print only on poll failure, scrubbed and
# bounded (2KB), so a policy message quoting the candidate cannot leak it
# (key filter + embedded-value backstop + runner mask; the value never
# appears, only metadata).
# A crash between set and the provision's `passwd -l root` leaves a
# caller-known password live: the workflow's failure step runs
# lock-password below (finally-path, not happy-path). The export below
# lands right after an OBSERVED successful set and before the SSH-wait,
# so the failure-path lock is armed on every path after that observation;
# if the poll itself dies before observing FINISHED the set is unproven
# and the lock has no candidate to try (fail-closed, but unresolved until
# the next re-dispatch overwrites it). A lock-password miss on a running
# box leaves the value live; the next re-dispatch mints fresh and
# overwrites it (recovery = set again + re-dispatch).
# ---------------------------------------------------------------------------
BOOTSTRAP_PW_LEN=28       # inside the 24-32 window; caller-supplied value
BOOTSTRAP_PW_RETRIES=3    # 422 (policy refused the value) -> fresh candidate
LOCK_WAIT_SECONDS=15      # backoff step on 409 server.lock.error
LOCK_WAIT_ROUNDS=40       # ... bounded (~10 min per mutating op)
TASK_POLL_SECONDS=10
TASK_WAIT_ROUNDS=60       # ... bounded (~10 min per async op)
AGENT_WAIT_ROUNDS=60      # guest-agent .available probes on the RUNNING box before the set (10s sleep each; ~10 min when probes answer promptly, ceilinged by the 30s curl --max-time per probe)
AGENT_WAIT_SECONDS=10     # ... sleep between guest-agent status probes
SSH_WAIT_ROUNDS=60        # TCP/22 retry on the running box (each try ceilinged: 60 x (5s probe + 10s sleep) ~= 15 min worst case, then loud abort)
SSH_TCP_TIMEOUT_SECONDS=5 # per-attempt ceiling on the TCP/22 probe (live #59: bare /dev/tcp blocks on kernel SYN timeout while SYNs go unanswered — 68-min silent hang)
SSH_PROBE_ROUNDS=12       # sshd takes TCP before auth is ready (short loop)

gen_password() { # -> BOOTSTRAP_PW_LEN chars (28), conservative charset, >=1 upper+lower+digit
  # The || true is load-bearing: under `set -o pipefail`, tr dies on
  # SIGPIPE (141) the moment head has its bytes, failing the function
  # before any mutation. Short reads stay impossible: every caller checks
  # the length and dies closed on mismatch.
  # netcup policy (SCP UI hint, live 2026-09-10): >=1 uppercase, >=1
  # lowercase, >=1 digit — a random draw can be class-less and burn a 422
  # candidate. Splice one random char of each MISSING class into a random
  # position; positions are never reused and later splices never touch an
  # already-used position, so a class fixed by a splice is permanent (a
  # class can be spliced at most once). A class that was present but got
  # clobbered by a later splice in the same pass is caught by the next
  # pass — at most 3 splices exist in total (3 classes), so <=4 passes:
  # 3 splice passes + 1 clean re-check. Each splice replaces one char, so
  # the length stays exactly BOOTSTRAP_PW_LEN.
  local pw cls pos ch used round splices
  pw="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c "$BOOTSTRAP_PW_LEN" || true)"
  if [ "${#pw}" -ne "$BOOTSTRAP_PW_LEN" ]; then
    printf '%s' "$pw" # short read: the caller's length check dies closed before any mutation
    return 0
  fi
  used=" "
  round=0
  while [ "$round" -lt 4 ]; do
    round=$((round + 1)); splices=0
    for cls in 'A-Z' 'a-z' '0-9'; do
      if [ "$(LC_ALL=C tr -d "$cls" <<<"$pw")" = "$pw" ]; then
        while :; do
          pos=$((RANDOM % ${#pw}))
          case "$used" in *" $pos "*) ;; *) break ;; esac
        done
        used="${used}${pos} "
        ch="$(LC_ALL=C tr -dc "$cls" </dev/urandom | head -c 1 || true)"
        pw="${pw:0:$pos}${ch}${pw:$((pos + 1))}"
        splices=$((splices + 1))
      fi
    done
    [ "$splices" -eq 0 ] && break
  done
  printf '%s' "$pw"
}

server_detail() { # -> raw GET /servers/{id} JSON (callers parse; no state filter)
  local resp
  api_call GET "/api/v1/servers/${SERVER_ID}" "" resp
  api_ok "$HTTP_STATUS" || die "read server $SERVER_ID failed (HTTP $HTTP_STATUS): $(printf '%s' "$resp" | head -c 500)"
  printf '%s' "$resp"
}

server_live_state() { # -> RUNNING | SHUTOFF | ... (empty when unknown)
  server_detail | jq -r '.serverLiveInfo.state // empty'
}

rescue_system_status() { # $1 = outvar -> "true"/"false"; dies loud on read failure # ci-allowlist: read-only rescue-state guard, not a disk/rescue API op.
  # Live 2026-09-10 (#68 provider-lens gap): an armed/active rescue system # ci-allowlist: prose rationale for the guard below.
  # boots instead of the OS and (per docs) disables the netcup firewall.
  # A password set or SSH probe in that environment would land in the
  # wrong OS — callers fail closed before any power or password action.
  local resp outvar="$1" parsed
  api_call GET "/api/v1/servers/${SERVER_ID}/rescuesystem" "" resp # ci-allowlist: required fail-closed pre-set guard read (GET only).
  api_ok "$HTTP_STATUS" || die "rescue-system status read failed (HTTP $HTTP_STATUS): $(printf '%s' "$resp" | head -c 500)" # ci-allowlist: error text for the read-only guard above.
  # Parse-failure must NOT leave an empty value (that would read as
  # not-active and fail OPEN — script-logic lens, 2026-09-10): accept
  # exactly true/false, anything else is unproven and dies.
  parsed="$(printf '%s' "$resp" | jq -r '.active // false' 2>/dev/null || true)"
  case "$parsed" in
    true | false) ;;
    *) die "rescue-system status unparseable (HTTP $HTTP_STATUS) — refusing to continue blind: $(printf '%s' "$resp" | head -c 300)" # ci-allowlist: error text for the read-only guard above.
       ;;
  esac
  printf -v "$outvar" '%s' "$parsed"
}

wait_guest_agent() { # GET /servers/{id}/guest-agent/status -> .available true; bounded, fail-closed
  # Live 2026-09-10 (#68): the root-password set is a guest-agent round
  # trip and completes only on a RUNNING box; a set issued before the
  # agent reports available errors with error.internalserver
  # (passwordChangeFailed: true). Fail closed if it never shows up — a
  # guest without qemu-guest-agent, or an unfinished boot, is operator
  # action, never a reason to set blind.
  local i=0 resp available
  while [ "$i" -lt "$AGENT_WAIT_ROUNDS" ]; do
    api_call GET "/api/v1/servers/${SERVER_ID}/guest-agent/status" "" resp
    api_ok "$HTTP_STATUS" || die "guest-agent status failed (HTTP $HTTP_STATUS): $(printf '%s' "$resp" | head -c 500)"
    available="$(printf '%s' "$resp" | jq -r '.available // false')"
    if [ "$available" = "true" ]; then
      log "guest agent available — the running box can apply the password set"
      return 0
    fi
    i=$((i + 1))
    if [ $((i % 6)) -eq 0 ]; then log "guest agent not available yet (attempt ${i}/${AGENT_WAIT_ROUNDS}) — still waiting"; fi
    sleep "$AGENT_WAIT_SECONDS"
  done
  die "guest agent still not available after $AGENT_WAIT_ROUNDS probes on a RUNNING box — ensure the image has qemu-guest-agent installed and the box finished booting, then re-dispatch" # ci-allowlist: names the guest-tools package to install, not a disk-API call.
}

TASK_DUMP_BYTES=2048 # failure-dump bound: uuid + scrubbed body (read-only logging)

scrub_task_body() { # $1 = raw task JSON -> scrubbed, bounded; the value never appears, only metadata
  # Key filter (structured echo) + embedded-value backstop (free-form
  # message strings can quote a value the key filter cannot see). The
  # one-time candidate stays masked by the runner (::add-mask:: at mint),
  # so even a missed novel shape is still masked in log and summary.
  # PEM armor below is regex-obfuscated (B[E]GIN / PRIV[A]TE: the bracket
  # sits INSIDE the word, so the file never carries the blocked literal
  # while the runtime pattern still matches real armor). The span uses
  # .* (never [^-]*): armor runs are dash-led and jq -c keeps the block
  # on one line, so .* crosses the dashes to the END armor.
  local raw="$1" cleaned
  cleaned="$(printf '%s' "$raw" | jq -c '
    def scrub:
      if type == "object" then
        with_entries(
          .value |= scrub
          | if (.key | test("pass|passwd|pwd|token|secret|private|jwk|auth|cred"; "i")) then
              .value = "[REDACTED]"
            else
              .
            end
        )
      elif type == "array" then
        map(scrub)
      else
        .
      end;
    try scrub catch .
  ' 2>/dev/null || printf '%s' "$raw")"
  printf '%s' "$cleaned" |
    sed -E -e 's/"d"[[:space:]]*:[[:space:]]*"[^"]*"/"d":"[REDACTED]"/g' \
      -e 's/-{5}B[E]GIN[A-Z ]*PRIV[A]TE KEY-{5}.*END[A-Z ]*PRIV[A]TE KEY-{5}/[REDACTED-PEM]/g' \
      -e 's/(^|[^A-Za-z0-9])((pass(word)?|passwd|pwd|token|secret)[_-]*[a-z_-]*["=:[:space:]]+)[^",}[:space:]]+/\1\2[REDACTED]/gI' |
    head -c "$TASK_DUMP_BYTES"
}

log_task_dump() { # $1 = uuid, $2 = label, $3 = state, $4 = raw body -> step log + job summary (scrubbed, bounded)
  local uuid="$1" label="$2" state="$3" raw="$4" scrubbed
  scrubbed="$(scrub_task_body "$raw")"
  {
    printf 'A1 TASK_DUMP: %s task %s ended in state %s\n' "$label" "$uuid" "${state:-unknown}"
    printf '%s\n' "$scrubbed"
  } >&2
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
      printf '### A1 task failure: %s `%s` state `%s`\n' "$label" "$uuid" "${state:-unknown}"
      printf '```json\n%s\n```\n' "$scrubbed"
    } >>"$GITHUB_STEP_SUMMARY" || true
  fi
}

poll_task() { # $1 = task uuid, $2 = label -> 0 on FINISHED; dies otherwise
  local uuid="$1" label="$2" i resp state
  i=0
  while [ "$i" -lt "$TASK_WAIT_ROUNDS" ]; do
    api_call GET "/api/v1/tasks/${uuid}" "" resp
    api_ok "$HTTP_STATUS" || die "poll $label task $uuid failed (HTTP $HTTP_STATUS): refusing to continue blind"
    state="$(printf '%s' "$resp" | jq -r '.state // empty')"
    case "$state" in
      FINISHED) log "$label task $uuid FINISHED"; return 0 ;;
      PENDING | RUNNING) ;; # still converging
      *)
        log_task_dump "$uuid" "$label" "$state" "$resp"
        die "$label task $uuid ended in state ${state:-unknown} — investigate in the SCP logs, then re-dispatch (recovery: ensure RUNNING, re-dispatch)"
        ;;
    esac
    i=$((i + 1))
    sleep "$TASK_POLL_SECONDS"
  done
  log_task_dump "$uuid" "$label" "TIMEOUT" "$resp"
  die "$label task $uuid still not FINISHED after ~10 min — refusing to continue blind"
}

patch_server() { # $1 = merge-patch body, $2 = label, $3 = query suffix, $4 = uuid outvar, [$5 = 422-flag var]
  # 200 = applied now (uuid empty); 202 = async (uuid set, caller polls).
  # 409 server.lock.error = backoff + retry, bounded. 422 with a flag var =
  # set the flag and return (caller mints a fresh password candidate);
  # 422 without one = die. Response bodies are NEVER printed here (the
  # password path must not leak the candidate through a policy echo).
  # Dynamic-scope warning (sibling of the api_call HTTP_STATUS trap above):
  # `uuid` MUST stay non-local here — callers pass outvar=uuid and
  # `printf -v "$outvar"` must reach THEIR uuid, or 202 tasks are never
  # polled (live failure: runs 34281922878 + 34282761648 raced ahead of
  # unconverged power/password sets into a failed SSH auth probe).
  local body="$1" label="$2" qs="${3:-}" outvar="$4" rej422="${5:-}" i resp code
  i=0
  while [ "$i" -lt "$LOCK_WAIT_ROUNDS" ]; do
    api_call PATCH "/api/v1/servers/${SERVER_ID}${qs}" "$body" resp "application/merge-patch+json"
    case "$HTTP_STATUS" in
      200) log "$label applied immediately (200)"; printf -v "$outvar" '%s' ""; return 0 ;;
      202)
        uuid="$(printf '%s' "$resp" | jq -r '.uuid // empty')"
        [ -n "$uuid" ] || die "$label accepted but no task uuid returned — refusing to continue blind"
        printf -v "$outvar" '%s' "$uuid"; return 0 ;;
      422)
        if [ -n "$rej422" ]; then printf -v "$rej422" '%s' "1"; return 0; fi
        die "$label rejected (HTTP 422) — value refused, escalate, no fallback" ;;
      409)
        code="$(printf '%s' "$resp" | jq -r '.code // empty')"
        if [ "$code" = "server.lock.error" ]; then
          log "$label: server locked (attempt $((i + 1))) — backing off ${LOCK_WAIT_SECONDS}s"
          i=$((i + 1)); sleep "$LOCK_WAIT_SECONDS"; continue
        fi
        die "$label rejected (HTTP 409, code ${code:-unknown}) — escalate, no fallback" ;;
      *) die "$label failed (HTTP $HTTP_STATUS) — investigate in the SCP logs, then re-dispatch" ;;
    esac
  done
  die "$label: server stayed locked past the backoff budget — operator must look before re-dispatch"
}

wait_ssh() { # TCP/22 then one auth probe with $SSHPASS, bounded
  # Live #59: this wait runs AFTER the A1 window opens (workflow order) —
  # but every attempt is ceilinged anyway. A bare /dev/tcp blocks on kernel
  # SYN timeout while SYNs go unanswered (68-min silent hang); timeout(1)
  # bounds each try, the round cap bounds the total, progress logs keep it
  # visible. Fail-closed: the cap dies loud, never proceeds unproven.
  local i=0 port="${ANCHOR_SSH_PORT:-22}"
  while [ "$i" -lt "$SSH_WAIT_ROUNDS" ]; do
    if timeout "$SSH_TCP_TIMEOUT_SECONDS" bash -c "echo >/dev/tcp/${ANCHOR_HOST}/${port}" >/dev/null 2>&1; then break; fi
    i=$((i + 1))
    if [ $((i % 6)) -eq 0 ]; then log "TCP/${port} not open yet (attempt ${i}/${SSH_WAIT_ROUNDS}) — still waiting"; fi
    sleep 10
  done
  if [ "$i" -ge "$SSH_WAIT_ROUNDS" ]; then
    die "TCP/22 on the anchor never opened on the running box — refusing to continue blind"
  fi
  log "TCP/22 open — one auth probe proving the fresh password is live"
  i=0
  while [ "$i" -lt "$SSH_PROBE_ROUNDS" ]; do
    if sshpass -e ssh -p "${ANCHOR_SSH_PORT:-22}" \
      -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 \
      -o BatchMode=no "root@${ANCHOR_HOST}" true 2>/dev/null; then
      log "auth probe ok — fresh password is live"
      return 0
    fi
    i=$((i + 1)); sleep 10
  done
  die "SSH auth probe failed on the running box — the set may not have converged. Recovery: set again + re-dispatch."
}

cmd_bootstrap_password() {
  require_token
  # Legacy sentinel: a pasted one-run secret keeps today's behavior
  # byte-for-byte (same SSH, same thumbprint artifact, same lock) —
  # nothing below runs.
  if [ -n "${ROOT_PASSWORD_SECRET:-}" ]; then
    log "pasted one-run secret present — skipping passwordless bootstrap (legacy path)"
    return 0
  fi
  ANCHOR_HOST="${ANCHOR_HOST:-}"
  [ -n "$ANCHOR_HOST" ] || die "ANCHOR_HOST is required for bootstrap-password (discovered IPv4 or pasted IP)"
  ANCHOR_HOST="${ANCHOR_HOST%%/*}"
  case "$ANCHOR_HOST" in ''|*[!0-9.]*) die "ANCHOR_HOST is not a bare IPv4 after stripping any /suffix";; esac
  command -v sshpass >/dev/null || {
    log "installing sshpass on the runner (auth probe transport for the caller-set password)"
    sudo apt-get install -y -qq sshpass >/dev/null
  }
  local pw="" state="" rescue="" uuid="" body="" attempt=0 rejected=0 set_ok=0 # ci-allowlist: local guard-result variable name, not a live reference.
  rescue_system_status rescue # ci-allowlist: call site of the read-only rescue-state guard.
  if [ "$rescue" = "true" ]; then # ci-allowlist: guard branch on the rescue-state probe result.
    die "netcup rescue system is ACTIVE/ARMED — deactivate it in the SCP before re-dispatch (a rescue boot bypasses the firewall and the set would land in the wrong OS)" # ci-allowlist: operator instruction for the rescue guard; no disk API call.
  fi
  pw="$(gen_password)"
  [ "${#pw}" -eq "$BOOTSTRAP_PW_LEN" ] || die "password generator short-read — refusing to continue"
  echo "::add-mask::$pw" # mask FIRST, before any use (same rule as device secrets)
  log "one-time password minted (${BOOTSTRAP_PW_LEN} chars, masked) — ensuring RUNNING state (agent-based set)"
  state="$(server_live_state)"
  log "server live state: ${state:-unknown}"
  if [ "$state" != "RUNNING" ]; then
    patch_server '{"state":"ON"}' "power-ON" "" uuid
    if [ -n "$uuid" ]; then poll_task "$uuid" "power-ON"; fi
  else
    log "server already RUNNING — skipping power-ON"
  fi
  wait_guest_agent
  while [ "$attempt" -lt "$BOOTSTRAP_PW_RETRIES" ]; do
    attempt=$((attempt + 1)); rejected=0
    body="$(PW="$pw" jq -n -c '{rootPassword: $ENV.PW}')"
    patch_server "$body" "password-set" "" uuid rejected
    if [ "$rejected" = "1" ]; then
      pw="$(gen_password)"
      [ "${#pw}" -eq "$BOOTSTRAP_PW_LEN" ] || die "password generator short-read — refusing to continue"
      echo "::add-mask::$pw"
      log "password-set: policy refused the candidate (422) — fresh candidate minted (attempt $attempt/$BOOTSTRAP_PW_RETRIES)"
      continue
    fi
    if [ -n "$uuid" ]; then poll_task "$uuid" "password-set"; fi
    set_ok=1; break
  done
  [ "$set_ok" -eq 1 ] || die "password-set refused $BOOTSTRAP_PW_RETRIES candidates in a row — escalate, no fallback"
  body=""
  # Export immediately AFTER a successful set and BEFORE the SSH-wait: any
  # run that ever set a password can lock it via the workflow's failure
  # step, even if the SSH-wait (or anything later) dies below.
  if [ -n "${GITHUB_ENV:-}" ]; then
    echo "BOOTSTRAP_ROOT_PASSWORD=$pw" >>"$GITHUB_ENV"
    echo "BOOTSTRAP_PASSWORD_SET=true" >>"$GITHUB_ENV"
  fi
  export SSHPASS="$pw"
  wait_ssh
  unset SSHPASS
  pw=""; uuid="" # discard from memory (the runner-env copy dies with the runner, same as the token)
  log "bootstrap-password done — caller-set password handed to the provision step (masked, same-runner only)"
}

# ---------------------------------------------------------------------------
# lock-password: best-effort finally-path for the caller-set password.
# The workflow runs this when the job fails after a password went live.
# Never fails (the original failure owns the verdict); no-ops when nothing
# was minted. No token needed (SSH only).
# ---------------------------------------------------------------------------
cmd_lock_password() {
  ANCHOR_HOST="${ANCHOR_HOST:-}"
  [ -n "$ANCHOR_HOST" ] || { warn "lock-password: no ANCHOR_HOST — nothing to lock"; return 0; }
  ANCHOR_HOST="${ANCHOR_HOST%%/*}"
  case "$ANCHOR_HOST" in ''|*[!0-9.]*) warn "lock-password: ANCHOR_HOST is not a bare IPv4 — nothing to lock"; return 0;; esac
  if [ -z "${BOOTSTRAP_ROOT_PASSWORD:-}" ]; then
    log "lock-password: no caller-set password in this run — nothing to lock"
    return 0
  fi
  command -v sshpass >/dev/null || {
    sudo apt-get install -y -qq sshpass >/dev/null || {
      warn "lock-password: sshpass unavailable — the caller-set password stays live: reset it in the SCP, then re-dispatch"
      return 0
    }
  }
  export SSHPASS="$BOOTSTRAP_ROOT_PASSWORD"
  if sshpass -e ssh -p "${ANCHOR_SSH_PORT:-22}" \
    -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 \
    -o BatchMode=no "root@${ANCHOR_HOST}" 'passwd -l root' 2>/dev/null; then
    log "lock-password: orphan password locked (passwd -l root)"
  else
    warn "lock-password: box unreachable — the caller-set password stays live: reset it in the SCP (or re-dispatch: a fresh password overwrites it), then re-dispatch"
  fi
  unset SSHPASS
  return 0
}

# ---------------------------------------------------------------------------
# close: detach-then-delete own policy (missing = success no-op).
# ---------------------------------------------------------------------------
cmd_close() {
  require_token
  local pid
  pid="$(own_policy_id)"
  if [ -z "$pid" ]; then
    log "no own tmp policy (nothing to close)"
    return 0
  fi
  close_policy "$pid"
  log "A1 window closed (detach-then-delete)"
}

# ---------------------------------------------------------------------------
# sweep-post: delete own-run any-age + tmp >2h + orphans. Fails loudly if any
# delete fails (an orphan window must never pass silently). No token (auth
# never completed) = clean no-op so `always()` keeps the original verdict.
# Destructive ONLY in apply mode (sweep_destructive): the other modes report
# what would be swept + append it to the step summary, and delete nothing.
# ---------------------------------------------------------------------------
cmd_sweep_post() {
  if [ -z "${NETCUP_SCP_ACCESS_TOKEN:-}" ]; then
    log "post-sweep: no token held (approval never completed) — nothing created, nothing to sweep"
    return 0
  fi
  local list entry name desc age pid failures=0 swept=0
  list="$(list_tmp_policies)"
  while IFS= read -r entry; do
    [ -n "$entry" ] || continue
    name="$(printf '%s' "$entry" | jq -r '.name')"
    desc="$(printf '%s' "$entry" | jq -r '.description')"
    pid="$(printf '%s' "$entry" | jq -r '.id')"
    age="$(policy_age "$desc")"
    if [ "$name" = "$OWN_NAME" ] || [ "$age" = "orphan" ] || [ "$age" -gt "$TMP_TTL_SECONDS" ]; then
      if sweep_destructive; then
        if [ "$age" = "orphan" ]; then
          warn "post-sweep: orphan tmp policy '$name' — sweeping"
        else
          log "post-sweep: sweeping '$name' (age ${age}s)"
        fi
        if close_policy "$pid"; then
          swept=$((swept + 1))
        else
          failures=$((failures + 1))
        fi
      else
        sweep_note "post-sweep: REPORT-ONLY (mode=${MODE:-unset}): tmp policy '$name' (age ${age}s) would be swept by an apply run"
      fi
    fi
  done < <(printf '%s' "$list" | jq -c '.[]')
  # Steady-state orphans (pre-import backlog, issue #101): stateless applies
  # before the conditional import created a fresh
  # piercloud-anchor-<hostname>-<server_id> policy each run and orphaned the
  # previous one (cap incidents 2026-09-10). Any policy in that family that is
  # NOT attached is a leftover by definition — retire it (close_policy is
  # detach-then-delete; the detach no-ops when it is already unattached). The
  # attached policy is never touched.
  local steady attached mac
  mac="$(resolve_mac)"
  # Attached-list parse (review security N1, live-proven; N4 id hardening):
  # dispatch on the ENTRY type and hard-fail on anything ambiguous. The
  # previous `(.id // .)` fallback made an id-less/null/empty-id entry
  # resolve to the WHOLE OBJECT; the live steady-state policy then looked
  # unattached and close_policy deleted it (cleartext/dashboard outage
  # until re-apply). Tolerated: an array of {"id":number}/{"id":string}/
  # bare number/bare string entries whose id is a canonical non-negative
  # integer — string ids must match ^[0-9]+$; numbers must be integral
  # with an integer tostring (so {"id":42.0} cannot stringify to "42.0"
  # and hide the live id 42). All canonical ids are stringified (the
  # comparison below is against stringified steady ids). Ambiguous =
  # missing key, non-array userPolicies, null/boolean/object entries, id
  # null/empty/non-scalar/non-canonical → jq errors: no STEADY-STATE
  # policy is detached or deleted (die). The tmp-policy pass above has
  # already run by then and is unaffected.
  attached="$(iface_fw_get "$mac" | jq -ce '
    def id_string:
      if type == "string" then
        (if test("^[0-9]+$") then . else error("userPolicies entry with a non-canonical string id") end)
      elif type == "number" then
        (if ((. | floor) == .) and ((. | tostring) | test("^[0-9]+$")) then tostring
         else error("userPolicies entry with a non-canonical numeric id") end)
      else error("userPolicies entry with a non-scalar id") end;
    if (.userPolicies | type) == "array" then
      [.userPolicies[] |
        if type == "object" then
          (.id | if . == null then error("userPolicies entry without a usable id") else id_string end)
        elif type == "string" or type == "number" then id_string
        else error("userPolicies entry of an ambiguous type") end]
    else error("userPolicies missing or not an array") end')" \
    || die "could not parse the attached-policy list for $SERVER_ID/$mac — refusing the steady-state orphan sweep on unproven attachment state"
  steady="$(list_steady_policies)"
  while IFS= read -r entry; do
    [ -n "$entry" ] || continue
    name="$(printf '%s' "$entry" | jq -r '.name')"
    pid="$(printf '%s' "$entry" | jq -r '.id')"
    if printf '%s' "$attached" | jq -e --arg id "$pid" 'index($id) != null' >/dev/null 2>&1; then
      log "post-sweep: steady-state policy '$name' (id ${pid}) is attached — kept"
      continue
    fi
    if sweep_destructive; then
      warn "post-sweep: steady-state ORPHAN '$name' (id ${pid}) — retiring (not attached)"
      if close_policy "$pid"; then
        swept=$((swept + 1))
      else
        failures=$((failures + 1))
      fi
    else
      sweep_note "post-sweep: REPORT-ONLY (mode=${MODE:-unset}): steady-state ORPHAN '$name' (id ${pid}) is not attached — would be retired by an apply run"
    fi
  done < <(printf '%s' "$steady" | jq -c '.[]')
  log "post-sweep done: swept=$swept failures=$failures"
  if [ "$failures" -ne 0 ]; then
    die "post-sweep left $failures tmp polic(ies) behind — operator must clean up by hand"
  fi
}

case "$CMD" in
  sweep-pre) cmd_sweep_pre ;;
  open) cmd_open ;;
  provision) cmd_provision ;;
  close) cmd_close ;;
  sweep-post) cmd_sweep_post ;;
  bootstrap-password) cmd_bootstrap_password ;;
  lock-password) cmd_lock_password ;;
esac
