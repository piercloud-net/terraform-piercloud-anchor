#!/usr/bin/env bash
#
# 010-provision.sh — provision the tang/clevis NBDE anchor + uptime monitor.
#
# WHERE THIS RUNS: ON the anchor box itself, as root, normally via the A1
# dispatch (the runner SSHes in under a per-run device-flow approval and pipes
# this script over stdin with GATUS_*/NTFY_* env prefixed). Fallback: paste it
# into the netcup SCP remote console by hand — env unset means a self-check-only
# monitor. Either way the tang keypair is generated ON THIS BOX and never leaves.
#
#   curl -fsSL https://raw.githubusercontent.com/piercloud-net/terraform-piercloud-anchor/main/scripts/010-provision.sh | bash
#
# Properties (see scripts/README.md): idempotent, human-run, no secrets.
# The tang keypair is generated ON THIS BOX and never leaves it. This script
# never sends key material anywhere; it only prints a public thumbprint.
#
set -euo pipefail

TANG_KEYS_DIR="/var/db/tang"
# renovate: depName=twinproduction/gatus datasource=docker
GATUS_IMAGE="twinproduction/gatus:v5.36.0"
GATUS_PORT="8080"
GATUS_CONFIG="/etc/gatus/config.yaml"

log()  { printf '\n\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mWARNING:\033[0m %s\n' "$*"; }
die()  { printf '\n\033[1;31mFAIL:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root (netcup SCP remote console, root login)"

ROTATE=0
case "${1:-}" in
  "") ;; # normal provision
  --rotate) ROTATE=1 ;;
  *) die "usage: $0 [--rotate]" ;;
esac

gen_keys() { # append a fresh key set on this box (never deletes)
  # Live 2026-09-08: tangd-keygen requires the dir to exist (usage error
  # otherwise) — some base images lack /var/db/tang entirely. # ci-allowlist: prose — base-image note, not a live image reference.
  mkdir -p "${TANG_KEYS_DIR}"
  if [ -x /usr/libexec/tangd-keygen ]; then
    /usr/libexec/tangd-keygen "${TANG_KEYS_DIR}"
  elif [ -x /usr/lib/tang/tangd-keygen ]; then
    /usr/lib/tang/tangd-keygen "${TANG_KEYS_DIR}"
  else
    die "tangd-keygen not found; reinstall the 'tang' package"
  fi
  systemctl restart tangd.socket 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# a) tang + tangd.socket (idempotent)
# ---------------------------------------------------------------------------
log "Installing tang (NBDE key server)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq tang jq >/dev/null

log "Enabling tangd.socket (port 80)"
systemctl enable --now tangd.socket >/dev/null 2>&1 || true

# Defensive key generation: some base images ship tang without keys on disk. # ci-allowlist: prose — on-box keygen note, not a live reference.
if ! compgen -G "${TANG_KEYS_DIR}/*.jwk" >/dev/null; then
  log "No tang keys found — generating keypair on this box"
  gen_keys
fi

# Rotation (--rotate): append a FRESH key set next to the old one, so already-
# bound clients keep booting while you re-bind to the new thumbprint below.
# AFTER every client has rotated and reboot-verified, delete the OLD .jwk
# files by hand. Deleting before that locks out unattended boot (passphrase
# prompt at 3am). Live proof (two consecutive runs) is M0-gated.
if [ "$ROTATE" = "1" ]; then
  log "Rotating: generating a fresh key set alongside the old one"
  gen_keys
  warn "Re-bind every client to the NEW thumbprint below and reboot-verify each BEFORE deleting old keys."
fi

# ---------------------------------------------------------------------------
# b) thumbprint — the ONE value you must save
# ---------------------------------------------------------------------------
log "tang is running. Your thumbprint (SAVE THIS NOW):"
echo
if command -v tang-show-keys >/dev/null 2>&1; then
  echo "    $(tang-show-keys 80)"
else
  echo "    $(jose jwk thp -a S256 -r -f "${TANG_KEYS_DIR}"/*.jwk | head -n1)"
fi
echo

# ---------------------------------------------------------------------------
# f) key-leak assertion (module invariant #1: tang keys never enter tf state —
#    this script prints no secrets, but if you happen to run it from a
#    directory holding OpenTofu/Terraform state, scan that state for key
#    material and fail loudly on a match)
# ---------------------------------------------------------------------------
assert_no_key_leak() {
  local leaked=0 states secret
  states=$(find . -maxdepth 3 \( -name '*.tfstate' -o -name '*.tfstate.*' -o -name '*.tfplan' \) -type f 2>/dev/null || true)
  if [ -z "${states}" ]; then
    log "Key-leak assertion: no terraform state files in $(pwd) — nothing to scan (OK)"
    return 0
  fi
  while IFS= read -r jwk; do
    [ -n "${jwk}" ] || continue
    # the private field "d" of each JWK, and every thumbprint algorithm
    secret=$(jq -r '.d // empty' "${jwk}" 2>/dev/null || true)
    if [ -n "${secret}" ] && grep -qF -- "${secret}" ${states}; then leaked=1; fi
    for alg in S1 S256 S512; do
      for secret in $(jose jwk thp -a "${alg}" -r -f "${jwk}" 2>/dev/null || true); do
        if grep -qF -- "${secret}" ${states}; then leaked=1; fi
      done
    done
  done < <(compgen -G "${TANG_KEYS_DIR}/*.jwk" || true)
  if [ "${leaked}" -eq 1 ]; then
    die "tang key material matched a terraform state/plan file in $(pwd). \
This violates the module's hard invariant #1 (tang keys never enter tf state). \
Do NOT apply that configuration; investigate before proceeding."
  fi
  log "Key-leak assertion: tang key material NOT present in terraform state files (OK)"
}
assert_no_key_leak

# ---------------------------------------------------------------------------
# c) Gatus config — DISPATCH-MANAGED (2026-09-08: no standing SSH keys, no
#    console edits; a phone tenant converges monitors via the GATUS_ENDPOINTS
#    repo secret + re-dispatch). Rendered on EVERY run; hand edits die
#    (one-time backup below). Env in: GATUS_ENDPOINTS (comma-separated
#    name=url pairs, http(s) only, v1), NTFY_TOPIC / NTFY_TOKEN (empty =
#    checks without push + warn).
# ---------------------------------------------------------------------------
log "Rendering dispatch-managed Gatus config (${GATUS_CONFIG})"
mkdir -p "$(dirname "${GATUS_CONFIG}")"
# One-time backup of any pre-managed hand config (never overwritten twice).
if [ -f "${GATUS_CONFIG}" ] && [ ! -f "${GATUS_CONFIG}.pre-managed.bak" ] && ! grep -q "DISPATCH-MANAGED" "${GATUS_CONFIG}" 2>/dev/null; then
  cp -p "${GATUS_CONFIG}" "${GATUS_CONFIG}.pre-managed.bak"
  log "Backed up pre-managed config to ${GATUS_CONFIG}.pre-managed.bak (one-time)"
fi
# Tenant endpoints. Bad pairs fail closed: a typo'd monitor you'd trust is
# worse than none.
ENDPOINTS_YAML=""
# Default target: the tenant homepage derives from TENANT_USER — no input
# needed (pier → https://pier.piercloud.net). Skipped only for hand runs
# without env (console fallback = self-check only, as documented).
if [ -n "${TENANT_USER:-}" ]; then
  case "$TENANT_USER" in ''|*[!a-zA-Z0-9_-]*) die "bad TENANT_USER for homepage URL (chars [a-zA-Z0-9_-] only)";; esac
  ENDPOINTS_YAML="  - name: main
    url: https://${TENANT_USER}.piercloud.net
    interval: 60s
    conditions:
      - \"[STATUS] == 200\"
"
  if [ -n "${NTFY_TOPIC:-}" ]; then
    ENDPOINTS_YAML="${ENDPOINTS_YAML}    alerts:
      - type: ntfy
        failure-threshold: 3
"
  fi
fi
if [ -n "${GATUS_ENDPOINTS:-}" ]; then
  set -f
  OLD_IFS="$IFS"; IFS=","
  # shellcheck disable=SC2086
  for pair in ${GATUS_ENDPOINTS}; do
    [ -z "$pair" ] && continue  # tolerate ,, / trailing comma (commas are illegal inside URLs — split there)
    name="$(printf '%s' "$pair" | cut -d= -f1 | tr -d '[:space:]')"
    url="$(printf '%s' "$pair" | cut -d= -f2- | tr -d '[:space:]')"
    case "$name" in ''|*[!a-zA-Z0-9_-]*) die "bad GATUS_ENDPOINTS pair (want name=url, name chars [a-zA-Z0-9_-]): $pair";; esac
    case "$url" in http://*|https://*) ;; *) die "bad GATUS_ENDPOINTS pair (v1 supports http(s) URLs only): $pair";; esac
    ENDPOINTS_YAML="${ENDPOINTS_YAML}  - name: ${name}
    url: ${url}
    interval: 60s
    conditions:
      - \"[STATUS] == 200\"
"
    if [ -n "${NTFY_TOPIC:-}" ]; then
      ENDPOINTS_YAML="${ENDPOINTS_YAML}    alerts:
      - type: ntfy
        failure-threshold: 3
"
    fi
  done
  IFS="$OLD_IFS"
  set +f
fi
if [ -n "${NTFY_TOPIC:-}" ]; then
  # Fail fast on YAML injection: topic/token interpolate into config-as-data.
  case "$NTFY_TOPIC" in ''|*[!a-zA-Z0-9_-]*) die "bad NTFY_TOPIC (chars [a-zA-Z0-9_-] only): ${NTFY_TOPIC}";; esac
  case "$NTFY_TOKEN" in *[[:space:]]*|*[![:print:]]*) die "bad NTFY_TOKEN (no whitespace/control characters)";; esac
  ALERTING_YAML="  ntfy:
    url: https://ntfy.sh
    topic: ${NTFY_TOPIC}"
  if [ -n "${NTFY_TOKEN:-}" ]; then
    ALERTING_YAML="${ALERTING_YAML}
    token: ${NTFY_TOKEN}"
  fi
else
  ALERTING_YAML="  # No push channel: NTFY_TOPIC unset, so failures are checked
  # but never pushed. Set the NTFY_TOPIC secret + re-dispatch for alerts."
  warn "NTFY_TOPIC unset — Gatus checks endpoints but cannot push failures anywhere."
fi
TMP_CFG="${GATUS_CONFIG}.new"
{
  printf '%s\n' "# DISPATCH-MANAGED by terraform-piercloud-anchor (scripts/010-provision.sh)."
  printf '%s\n' "# DO NOT EDIT BY HAND — re-rendered on every provision run. Change monitors"
  printf '%s\n' "# via the GATUS_ENDPOINTS repo secret (+ NTFY_TOPIC secret for push) and"
  printf '%s\n' "# re-dispatch mode=apply. Docs: https://gatus.io/docs"
  printf '%s\n' "#"
  printf '%s\n' "# Probe targets by DNS NAME, not IP: Gatus never caches DNS, so when you"
  printf '%s\n' "# migrate and flip the record, the monitor follows automatically and the"
  printf '%s\n' "# availability history stays continuous across the cutover."
  printf '%s\n' ""
  printf '%s\n' "storage:"
  printf '%s\n' "  type: sqlite" # explicit: Gatus defaults to memory and panics if a path is set (live 2026-09-08)
  printf '%s\n' "  path: /data/gatus.db   # sqlite in the gatus-data volume: history survives restarts"
  printf '%s\n' ""
  printf '%s\n' "alerting:"
  printf '%s\n' "$ALERTING_YAML"
  printf '%s\n' ""
  printf '%s\n' "metrics: false"
  printf '%s\n' ""
  printf '%s\n' "endpoints:"
  printf '%s\n' "  # The anchor itself - local only, never firewalled, always accurate."
  printf '%s\n' "  - name: tang (local)"
  printf '%s\n' "    url: http://127.0.0.1/adv"
  printf '%s\n' "    interval: 60s"
  printf '%s\n' "    conditions:"
  printf '%s\n' "      - \"[STATUS] == 200\""
  printf '%s' "$ENDPOINTS_YAML"
} >"$TMP_CFG"
if [ -f "${GATUS_CONFIG}" ] && cmp -s "${GATUS_CONFIG}" "$TMP_CFG"; then
  log "Gatus config unchanged — no restart"
  rm -f "$TMP_CFG"
  GATUS_RESTART=0
else
  mv "$TMP_CFG" "${GATUS_CONFIG}"
  log "Gatus config installed (rendered from dispatch env)"
  GATUS_RESTART=1
fi

# ---------------------------------------------------------------------------
# d) Run Gatus (container recreated when the pinned image changed - so an # ci-allowlist: prose — container-tag wording, not a live reference.
#    auto-bumped pin actually REACHES deployed anchors on script re-run;
#    config and the sqlite history volume survive the recreation)
# ---------------------------------------------------------------------------
log "Running Gatus monitor (bound to 127.0.0.1:${GATUS_PORT})"
if docker ps --format '{{.Names}}' | grep -qx "gatus"; then
  RUNNING_IMAGE=$(docker inspect --format '{{.Config.Image}}' gatus) # ci-allowlist: code — docker inspect field name, not a live reference.
  if [ "${RUNNING_IMAGE}" = "${GATUS_IMAGE}" ]; then
    log "Gatus already running on ${GATUS_IMAGE}"
  else
    log "Gatus image changed (${RUNNING_IMAGE} -> ${GATUS_IMAGE}) - recreating container" # ci-allowlist: prose — container-tag change note, not a live reference.
    docker rm -f gatus >/dev/null
  fi
elif docker ps -a --format '{{.Names}}' | grep -qx "gatus"; then
  docker rm -f gatus >/dev/null   # stale stopped container; recreated below
fi
if ! docker ps --format '{{.Names}}' | grep -qx "gatus"; then
  docker run -d --name gatus --restart unless-stopped \
    -p 127.0.0.1:${GATUS_PORT}:8080 \
    -v "${GATUS_CONFIG}:/config/config.yaml:ro" \
    --mount type=volume,source=gatus-data,target=/data \
    "${GATUS_IMAGE}" >/dev/null
fi
if [ "${GATUS_RESTART:-0}" = "1" ]; then
  docker restart gatus >/dev/null
  log "Gatus restarted on new config"
fi
# Prove the monitor from the tenant's chair: endpoint statuses print into the
# run log (the tenant has no shell — this output IS their dashboard check).
# Path confirmed against the pinned source (TwiN/gatus v5.36.0 api/api.go:
# GET /v1/endpoints/statuses); unprotected here because our config ships no
# security: section (nil Security = middleware never applied).
ok=0
for i in 1 2 3 4 5 6; do
  if curl -sf -o /tmp/gatus-status.json "http://127.0.0.1:${GATUS_PORT}/api/v1/endpoints/statuses"; then head -c 2000 /tmp/gatus-status.json; echo; ok=1; break; fi
  sleep 10
done
if [ "$ok" != "1" ]; then
  docker logs gatus 2>&1 | tail -20 || true
  die "Gatus did not answer /api/v1/endpoints/statuses after restart — refusing to finish blind"
fi

log "Done. tang is up, the thumbprint is above, Gatus is dispatch-managed (statuses printed above)."
