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
#   sweep-pre  enumerate tmp policies -> surplus fail-closed (>1 tmp on this
#              server, or any tmp older than 2h / orphan at pre-step, exits 3
#              BEFORE creating anything) -> drop this run's own leftover.
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
#              password (masked at birth) -> PATCH state OFF (mandatory per
#              vendor docs) -> poll task SUCCESS -> set via
#              ServerSetRootPasswordPatch (422 = fresh candidate, bounded)
#              -> poll SUCCESS -> PATCH state ON -> poll + TCP/SSH retry ->
#              export the masked value for the provision step (same-runner
#              handoff). Skips minting when ROOT_PASSWORD_SECRET is set.
#   lock-password
#              best-effort finally-path: `passwd -l root` over ssh with the
#              caller-set password. Never fails (the original failure owns
#              the verdict); no-ops when nothing was minted.
#   close      detach-then-delete the run's own tmp policy, always in that
#              order; missing policy is a success no-op (idempotent).
#   sweep-post delete this run's policy at any age + every tmp older than 2h
#              (+ orphans: no valid created_at). Tolerates a missing token
#              (auth never completed -> nothing created -> clean no-op) so the
#              workflow `always()` post step never masks the real failure.
#
# ENV (all identifiers arrive via environment — never argv, never logs):
#   NETCUP_SCP_ACCESS_TOKEN  per-run device-flow token (required except
#                            sweep-post, which no-ops cleanly without it).
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
#   3 surplus fail-closed at pre-step (operator must look before re-dispatch).
#
# M0-GATED (no live netcup credentials exist; live run + verify-twice-live
# are pending — recorded honestly in the PR body, never claimed here):
#   request/response envelopes were derived from the provider's Go source
#   (policy CRUD spec, firewallSaveRequest/firewallReadResponse JSON tags)
#   plus envelope-tolerant jq; first live run confirms or corrects them.
#   Runs on ubuntu-latest only (GNU date for TTL math).
#
set -euo pipefail

TMP_TTL_SECONDS=7200 # 2h: tmp older than this is swept, and fails pre-step.
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

NETCUP_API_BASE="${NETCUP_API_BASE:-https://www.servercontrolpanel.de/scp-core}"
SERVER_ID="${SERVER_ID:-}"
SCP_USER_ID="${SCP_USER_ID:-}"
RUN_ID="${RUN_ID:-}"
# lock-password is the SSH-only finally-path (no API use): it must run even
# when resolve never produced ids, so it is exempt from the id guards.
case "$CMD" in
  lock-password) ;;
  *)
    [ -n "$SERVER_ID" ] || die "SERVER_ID is required"
    [ -n "$SCP_USER_ID" ] || die "SCP_USER_ID is required"
    [ -n "$RUN_ID" ] || die "RUN_ID is required (idempotency key)"
    ;;
esac

TMP_PREFIX="piercloud-tmp-${SERVER_ID}-"
OWN_NAME="piercloud-tmp-${SERVER_ID}-${RUN_ID}"

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
  if [ -n "$body" ]; then
    status="$(curl -sS --max-time 30 -o "$resp_file" -w '%{http_code}' \
      -X "$method" "${NETCUP_API_BASE}${path}" \
      -H "Authorization: Bearer ${NETCUP_SCP_ACCESS_TOKEN}" \
      -H "Content-Type: $ctype" -H 'Accept: application/json' \
      -d "$body")"
  else
    status="$(curl -sS --max-time 30 -o "$resp_file" -w '%{http_code}' \
      -X "$method" "${NETCUP_API_BASE}${path}" \
      -H "Authorization: Bearer ${NETCUP_SCP_ACCESS_TOKEN}" \
      -H 'Accept: application/json')"
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
    printf '%s' "$INTERFACE_MAC"
    return 0
  fi
  api_call GET "/api/v1/servers/${SERVER_ID}/interfaces" "" resp
  api_ok "$HTTP_STATUS" || die "list server interfaces failed (HTTP $HTTP_STATUS)"
  mac="$(printf '%s' "$resp" | jq -r \
    'if type == "array" then .[0]
     elif has("data") then .data[0]
     elif has("items") then .items[0]
     elif has("interfaces") then .interfaces[0]
     else . end
     | .mac // empty')"
  [ -n "$mac" ] || die "could not resolve NIC MAC for server $SERVER_ID (set INTERFACE_MAC)"
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
# sweep-pre: enumerate -> surplus fail-closed -> drop own leftover.
# ---------------------------------------------------------------------------
cmd_sweep_pre() {
  require_token
  local list count entry name desc age
  list="$(list_tmp_policies)"
  count="$(printf '%s' "$list" | jq 'length')"
  log "pre-sweep: $count tmp polic(ies) on server $SERVER_ID"
  if [ "$count" -gt 1 ]; then
    surplus_fail "$count tmp policies on server $SERVER_ID (>1) — refusing to create. Notify the operator; clean up by hand, then re-dispatch."
  fi
  while IFS= read -r entry; do
    [ -n "$entry" ] || continue
    name="$(printf '%s' "$entry" | jq -r '.name')"
    desc="$(printf '%s' "$entry" | jq -r '.description')"
    if [ "$name" = "$OWN_NAME" ]; then
      continue # own leftover handled below (retry of this run reuses it)
    fi
    age="$(policy_age "$desc")"
    if [ "$age" = "orphan" ]; then
      surplus_fail "orphan tmp policy '$name' (no valid created_at) at pre-step — refusing to create. Notify the operator."
    fi
    if [ "$age" -gt "$TMP_TTL_SECONDS" ]; then
      surplus_fail "tmp policy '$name' is ${age}s old (>2h) at pre-step — refusing to create. Notify the operator."
    fi
    # A fresh single tmp that is not ours: leave it alone (only >1 or
    # stale/orphan fail-closed per SPEC; the mutex rules out a racing run).
  done < <(printf '%s' "$list" | jq -c '.[]')
  local own
  own="$(printf '%s' "$list" | jq -r --arg n "$OWN_NAME" 'map(select(.name == $n)) | .[0].id // empty')"
  if [ -n "$own" ]; then
    log "pre-sweep: dropping own leftover policy $own (hard-killed attempt of this run)"
    close_policy "$own"
  fi
  log "pre-sweep clean"
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
  ENV_PREFIX="export TENANT_USER='$(q "${TENANT_USER:-}")' GATUS_ENDPOINTS='$(q "${GATUS_ENDPOINTS:-}")' NTFY_TOPIC='$(q "${NTFY_TOPIC:-}")' NTFY_TOKEN='$(q "${NTFY_TOKEN:-}")';"
  if [ "$ROTATE" -eq 1 ]; then
    warn "--rotate requested: forwarded to the on-box script; on-box key rotation (dot-out old keys per netcup rotation procedure) is pending — re-run converges idempotently today"
  fi
  if [ "$ROTATE" -eq 1 ]; then
    { echo "$ENV_PREFIX"; cat scripts/010-provision.sh; } | ssh_base 'bash -s -- --rotate'
  else
    { echo "$ENV_PREFIX"; cat scripts/010-provision.sh; } | ssh_base 'bash -s'
  fi
  log "capturing tang thumbprint to the artifact path"
  thumb="$(ssh_base 'command -v tang-show-keys >/dev/null && tang-show-keys 80 || jose jwk thp -a S256 -r -f /var/db/tang/*.jwk' | head -n 1 | tr -d '[:space:]')"
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
# bootstrap-password: mint a caller-set one-time root password, power-cycle
# the server around the set (issue #50 — tenant pastes 1 secret).
#
# Power-OFF is mandatory per vendor docs (offline shadow surgery; absolute
# — no guest-agent write path, guest-agent is GET-only telemetry), so the
# flow converges to OFF first. Fresh boxes: harmless machine-wait.
# Re-provisions: note the brief downtime. Async PATCHes return 202 +
# TaskInfo: poll GET /tasks/{uuid} to FINISHED. 409 server.lock.error:
# backoff + retry, bounded. The candidate travels only via the sshpass
# environment value and jq --arg (never argv, never logs); task bodies are
# never printed on this path (policy messages could quote the candidate).
# A crash between set and the provision's `passwd -l root` leaves a
# caller-known password live: the workflow's failure step runs
# lock-password below (finally-path, not happy-path). An orphan on a
# powered-OFF box is unreachable — the next re-dispatch mints fresh and
# overwrites it (recovery = set again + power on + re-dispatch).
# ---------------------------------------------------------------------------
BOOTSTRAP_PW_LEN=28       # inside the 24-32 window; caller-supplied value
BOOTSTRAP_PW_RETRIES=3    # 422 (policy refused the value) -> fresh candidate
LOCK_WAIT_SECONDS=15      # backoff step on 409 server.lock.error
LOCK_WAIT_ROUNDS=40       # ... bounded (~10 min per mutating op)
TASK_POLL_SECONDS=10
TASK_WAIT_ROUNDS=60       # ... bounded (~10 min per async op)
SSH_WAIT_ROUNDS=60        # TCP/SSH retry after power-ON (~10 min)
SSH_PROBE_ROUNDS=12       # sshd takes TCP before auth is ready (short loop)

gen_password() { # -> 28 chars, conservative charset (no shell/JSON specials)
  LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c "$BOOTSTRAP_PW_LEN"
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

server_primary_ipv4() { # -> first IPv4 from the server detail (empty when none)
  server_detail | jq -r '.ipv4Addresses[0].ip // empty'
}

poll_task() { # $1 = task uuid, $2 = label -> 0 on FINISHED; dies otherwise
  local uuid="$1" label="$2" i resp state
  i=0
  while [ "$i" -lt "$TASK_WAIT_ROUNDS" ]; do
    api_call GET "/api/v1/tasks/${uuid}" "" resp
    api_ok "$HTTP_STATUS" || die "poll $label task failed (HTTP $HTTP_STATUS): refusing to continue blind"
    state="$(printf '%s' "$resp" | jq -r '.state // empty')"
    case "$state" in
      FINISHED) log "$label task FINISHED"; return 0 ;;
      PENDING | RUNNING) ;; # still converging
      *) die "$label task ended in state ${state:-unknown} — investigate in the SCP logs, then re-dispatch (recovery = set again + power on)" ;;
    esac
    i=$((i + 1))
    sleep "$TASK_POLL_SECONDS"
  done
  die "$label task still not FINISHED after ~10 min — refusing to continue blind"
}

patch_server() { # $1 = merge-patch body, $2 = label, $3 = query suffix, $4 = uuid outvar, [$5 = 422-flag var]
  # 200 = applied now (uuid empty); 202 = async (uuid set, caller polls).
  # 409 server.lock.error = backoff + retry, bounded. 422 with a flag var =
  # set the flag and return (caller mints a fresh password candidate);
  # 422 without one = die. Response bodies are NEVER printed here (the
  # password path must not leak the candidate through a policy echo).
  local body="$1" label="$2" qs="${3:-}" outvar="$4" rej422="${5:-}" i resp code uuid
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
  local i=0
  while [ "$i" -lt "$SSH_WAIT_ROUNDS" ]; do
    if (echo >/dev/tcp/"$ANCHOR_HOST"/22) >/dev/null 2>&1; then break; fi
    i=$((i + 1)); sleep 10
  done
  if [ "$i" -ge "$SSH_WAIT_ROUNDS" ]; then
    die "TCP/22 on the anchor never opened after power-ON — refusing to continue blind"
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
  die "SSH auth probe failed after power-ON — the set may not have converged. Recovery: set again + power on + re-dispatch."
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
  local pw="" state="" uuid="" body="" attempt=0 rejected=0 set_ok=0
  pw="$(gen_password)"
  [ "${#pw}" -eq "$BOOTSTRAP_PW_LEN" ] || die "password generator short-read — refusing to continue"
  echo "::add-mask::$pw" # mask FIRST, before any use (same rule as device secrets)
  log "one-time password minted (${BOOTSTRAP_PW_LEN} chars, masked) — converging power state"
  state="$(server_live_state)"
  log "server live state: ${state:-unknown}"
  if [ "$state" != "SHUTOFF" ]; then
    patch_server '{"state":"OFF"}' "power-OFF" "?stateOption=POWEROFF" uuid
    if [ -n "$uuid" ]; then poll_task "$uuid" "power-OFF"; fi
  else
    log "server already OFF — skipping power-OFF"
  fi
  while [ "$attempt" -lt "$BOOTSTRAP_PW_RETRIES" ]; do
    attempt=$((attempt + 1)); rejected=0
    body="$(jq -n -c --arg p "$pw" '{rootPassword: $p}')"
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
  state="$(server_live_state)"
  if [ "$state" != "RUNNING" ]; then
    patch_server '{"state":"ON"}' "power-ON" "" uuid
    if [ -n "$uuid" ]; then poll_task "$uuid" "power-ON"; fi
  else
    log "server already RUNNING — skipping power-ON"
  fi
  export SSHPASS="$pw"
  wait_ssh
  unset SSHPASS
  if [ -n "${GITHUB_ENV:-}" ]; then
    echo "BOOTSTRAP_ROOT_PASSWORD=$pw" >>"$GITHUB_ENV"
    echo "BOOTSTRAP_PASSWORD_SET=true" >>"$GITHUB_ENV"
  fi
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
    fi
  done < <(printf '%s' "$list" | jq -c '.[]')
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
