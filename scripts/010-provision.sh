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

# Legacy/upstream-default keydir. The authoritative dir is resolved after the
# tang install below, from the INSTALLED unit: Debian/Ubuntu patch upstream's
# jwkdir default to /var/lib/tang, so keys generated only here are read by
# nobody (tangd answers HTTP 500) while the on-box thumbprint, computed from
# these files, still looks fine — live 2026-09-10 (#78).
TANG_KEYS_DIR="/var/db/tang"
LEGACY_TANG_KEYS_DIR="/var/db/tang"
TANG_PORT="8081"
# renovate: depName=twinproduction/gatus datasource=docker
GATUS_IMAGE="twinproduction/gatus:v5.36.0"
GATUS_PORT="8080"
GATUS_CONFIG="/etc/gatus/config.yaml"
# renovate: depName=caddy datasource=docker
CADDY_IMAGE="caddy:2.11.4-alpine"
CADDY_CONFIG="/etc/caddy/Caddyfile"
CADDY_ORIGIN_CRT="/etc/caddy/origin.crt"
CADDY_ORIGIN_KEY="/etc/caddy/origin.key"
CADDY_AOP_CA="/etc/caddy/aop-ca.pem"
CADDY_CHALLENGE_DIR="/var/lib/caddy/acme-challenge"
# Cloudflare edge ranges for trusted_proxies (public constants — keep in
# sync with local.cf_edge_cidrs in main.tf; stale ranges read as edge 403s).
CF_EDGE_CIDRS="173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22 2400:cb00::/32 2606:4700::/32 2803:f800::/32 2405:b500::/32 2405:8100::/32 2a06:98c0::/29 2c0f:f248::/32"

log()  { printf '\n\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mWARNING:\033[0m %s\n' "$*"; }
die()  { printf '\n\033[1;31mFAIL:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root (netcup SCP remote console, root login)"

# --- BEGIN CADDY RENDER (tests/bind-e2e/run-bind-e2e.sh extracts this span; keep markers) ---
caddy_status_names() { # STATUS_HOST/STATUS_MATCH from TENANT_USER
# Dispatch-managed hostnames (same sanitize one-liner as the workflow
# resolve step and .github/scripts/030-anchor-dns.sh — keep the three in
# sync). Empty on hand runs without env (console fallback): the :80 tang
# proxy still renders below, but the :443 dashboard block and the TLS-expiry
# probe wait for a re-dispatch with TENANT_USER.
SAN="$(printf '%s' "${TENANT_USER:-}" | tr '[:upper:]' '[:lower:]' | sed -e 's/[^a-z0-9-]/-/g' -e 's/-\{2,\}/-/g' -e 's/^-//' -e 's/-$//')"
if [ -n "$SAN" ]; then
  STATUS_HOST="status.${SAN}.piercloud.net"
else
  STATUS_HOST=""
  warn "TENANT_USER unset — dashboard TLS block and TLS-expiry probe skipped (re-dispatch with TENANT_USER to converge them)"
fi
# Exact Host value for the :80 dashboard matcher (review: a wildcard span was
# never verified — render the exact name; hand runs get a never-matching
# sentinel so the :80 block still validates).
STATUS_MATCH="${STATUS_HOST:-status.invalid}"
}

render_caddyfile() { # print the Caddyfile to stdout
  printf '%s\n' "# DISPATCH-MANAGED by terraform-piercloud-anchor (scripts/010-provision.sh)."
  printf '%s\n' "# DO NOT EDIT BY HAND — re-rendered on every provision run. Dashboard TLS"
  printf '%s\n' "# converges from TENANT_USER + the CF_ORIGIN_* / CF_AOP_CA_* repo secrets;"
  printf '%s\n' "# re-dispatch mode=apply to converge. Future tenant domains get their own"
  printf '%s\n' "# explicit site blocks here — NEVER on_demand TLS."
  printf '%s\n' ""
  printf '%s\n' "{"
  printf '%s\n' "	# Loopback admin: \`docker exec caddy caddy reload\` keeps working;"
  printf '%s\n' "	# admin.disabled:true would refuse the reload, and publishing :2019"
  printf '%s\n' "	# would expose control — loopback is neither."
  printf '%s\n' "	admin 127.0.0.1:2019"
  printf '%s\n' "	servers {"
  printf '%s\n' "		# Real client IP behind the orange cloud. CF-Connecting-IP only —"
  printf '%s\n' "		# never X-Forwarded-For (spoofable through the edge)."
  printf '%s\n' "		trusted_proxies static ${CF_EDGE_CIDRS}"
  printf '%s\n' "		client_ip_headers CF-Connecting-IP"
  printf '%s\n' "	}"
  printf '%s\n' "}"
  printf '%s\n' ""
  printf '%s\n' "# Tang front (:80, plain HTTP, NO redirect): ONLY /adv*|/rec* reach"
  printf '%s\n' "# tangd. ACME HTTP-01 answers here (zone-side cache bypass + no WAF"
  printf '%s\n' "# block on that path are operator steps, see docs/dr.md). The status"
  printf '%s\n' "# host on :80 proxies the dashboard plain (no redirect by design);"
  printf '%s\n' "# TLS lives on :443 below. Everything else aborts."
  printf '%s\n' "${CADDY_HTTP_ADDR:-:80} {"
  printf '%s\n' "	log_skip"
  printf '%s\n' "	header -Server"
  printf '%s\n' "	handle /.well-known/acme-challenge/* {"
  printf '%s\n' "		root * ${CADDY_CHALLENGE_DIR}"
  printf '%s\n' "		file_server"
  printf '%s\n' "	}"
  printf '%s\n' "	handle /adv* {"
  printf '%s\n' "		reverse_proxy 127.0.0.1:${TANG_PORT}"
  printf '%s\n' "	}"
  printf '%s\n' "	handle /rec* {"
  printf '%s\n' "		# No in-Caddy rate limit by decision: the pinned official build"
  printf '%s\n' "		# (caddy:2.11.4-alpine) ships no rate_limit directive — verified via"
  printf '%s\n' "		# list-modules on the v2.11.4 binary; it lives in a third-party xcaddy"
  printf '%s\n' "		# plugin, which would break the pinned-build call (queued: issue #56)."
  printf '%s\n' "		# Flood protection"
  printf '%s\n' "		# rests on the firewall allowlist (main /32 + edge ranges) plus AOP"
  printf '%s\n' "		# handshake enforcement when the bundle is deployed (see docs/dr.md)."
  printf '%s\n' "		reverse_proxy 127.0.0.1:${TANG_PORT}"
  printf '%s\n' "	}"
  printf '%s\n' "	# Named matcher keeps the dashboard off tang paths (disjoint by"
  printf '%s\n' "	# construction, so handle order cannot misroute)."
  printf '%s\n' "	@status {"
  printf '%s\n' "		host ${STATUS_MATCH}"
  printf '%s\n' "		not path /adv* /rec* /.well-known/acme-challenge/*"
  printf '%s\n' "	}"
  printf '%s\n' "	handle @status {"
  printf '%s\n' "		reverse_proxy 127.0.0.1:${GATUS_PORT}"
  printf '%s\n' "	}"
  printf '%s\n' "	handle {"
  printf '%s\n' "		abort"
  printf '%s\n' "	}"
  printf '%s\n' "}"
  if [ -n "${STATUS_HOST:-}" ] && [ -z "${CADDY_SKIP_HTTPS:-}" ]; then
    printf '%s\n' ""
    printf '%s\n' "# Dashboard (explicit per-tenant block — this name only, never on_demand)."
    printf '%s\n' "https://${STATUS_HOST} {"
    printf '%s\n' "	header -Server"
    printf '%s\n' "${DASH_TLS_STANZA}"
    printf '%s\n' "	# Tang paths are never served on the dashboard vhost."
    printf '%s\n' "	@dashtang path /adv* /rec*"
    printf '%s\n' "	handle @dashtang {"
    printf '%s\n' "		abort"
    printf '%s\n' "	}"
    printf '%s\n' "	handle {"
    printf '%s\n' "		# No rate_limit directive in the pinned official build (see the"
    printf '%s\n' "		# /rec* note above) — dashboard flood protection is the firewall"
    printf '%s\n' "		# allowlist plus AOP handshake enforcement when deployed (the"
    printf '%s\n' "		# rate_limit directive itself is queued: issue #56)."
    printf '%s\n' "		reverse_proxy 127.0.0.1:${GATUS_PORT}"
    printf '%s\n' "	}"
    printf '%s\n' "}"
  elif [ -z "${STATUS_HOST:-}" ]; then
    printf '%s\n' ""
    printf '%s\n' "# No TENANT_USER: :443 dashboard block skipped (re-dispatch converges it)."
  else
    printf '%s\n' ""
    printf '%s\n' "# :443 dashboard block skipped by harness (CADDY_SKIP_HTTPS)."
  fi
}
# --- END CADDY RENDER ---

ROTATE=0
case "${1:-}" in
  "") ;; # normal provision
  --rotate) ROTATE=1 ;;
  *) die "usage: $0 [--rotate]" ;;
esac

# --- keys must live where the INSTALLED unit reads them -------------------
# The unit pins both the keydir (ExecStart's last argument) and the user that
# runs tangd; ask the unit itself instead of assuming a distro layout.
unit_keydir() {
  systemctl cat 'tangd@.service' 2>/dev/null \
    | sed -n 's/^ExecStart=[^[:space:]]*[[:space:]]\{1,\}\(\/[^[:space:]]*\)[[:space:]]*$/\1/p' \
    | tail -n1
}
unit_user() {
  systemctl cat 'tangd@.service' 2>/dev/null \
    | sed -n 's/^User=\([^[:space:]]*\)[[:space:]]*$/\1/p' | tail -n1
}
# Keys are private material: owned by the unit's user (Debian: _tang:_tang)
# with dir 0750 / files 0640. If that user is absent, fall back to root plus
# world-readable so tangd can still read (the unit runs as a fixed user).
own_keys() {
  local u="${TANG_UNIT_USER:-_tang}"
  getent passwd "${u}" >/dev/null 2>&1 || u="root"
  chown -R "${u}:${u}" "${TANG_KEYS_DIR}" 2>/dev/null || true
  chmod 0750 "${TANG_KEYS_DIR}" 2>/dev/null || true
  chmod 0640 "${TANG_KEYS_DIR}"/*.jwk 2>/dev/null || true
  [ "${u}" = "root" ] && chmod 0644 "${TANG_KEYS_DIR}"/*.jwk 2>/dev/null || true
  return 0
}

# --- collapse:start --- (CI extracts this span verbatim; tests/bind-e2e)
# One bindable key set, deterministically (live 2026-09-10, #87): two
# historical keygen rounds left two sign keys, so /adv used the JWS GENERAL
# serialization (signatures[]) and the published thumbprint depended on
# readdir order. clevis verifies with `jose jws ver -a` (every verify key
# must validate a signature) and pins `thp=` to a SIGNING key, so the anchor
# must serve exactly one sign key (ES512) + one exchange key (ECMR).
# Detection is by JWK `alg`, never mtime (a keygen pair can straddle a
# second, two runs can share one). Extras are QUARANTINED to a sibling dir,
# never deleted (restore: move back, clear .published-thp if needed, re-run).
# `--rotate` is the only flow that may keep several sets: it drops
# .rotation-pending and normal runs leave the directory alone until the
# operator has re-bound every client and removed the marker.
key_alg() { jq -r '.alg // empty' "$1" 2>/dev/null || true; }
key_thp() { jose jwk thp -a S256 -i "$1" 2>/dev/null || true; }
key_inventory() {
  local f
  for f in "$@"; do [ -e "$f" ] || continue; printf '%s(%s,%s) ' "$(basename "$f")" "$(key_alg "$f")" "$(key_thp "$f")"; done
}
collapse_keys() {
  local signs=() excs=() f alg keep_thp keep_sign="" keep_exc="" best="" best_d="" d qdir keep_name
  for f in "${TANG_KEYS_DIR}"/*.jwk; do
    [ -e "$f" ] || continue
    case "$(basename "$f")" in .*) continue ;; esac
    alg="$(key_alg "$f")"
    case "$alg" in
      ES512) signs+=("$f") ;;
      ECMR)  excs+=("$f") ;;
      *) warn "keydir: $(basename "$f") has alg='${alg}' (want ES512/ECMR) — leaving it untouched" ;;
    esac
  done
  if [ "${#signs[@]}" -eq 0 ] || [ "${#excs[@]}" -eq 0 ]; then
    die "keydir ${TANG_KEYS_DIR} lacks a sign (ES512) or exchange (ECMR) key — an unbindable anchor is worse than a failed run (inventory: $(key_inventory "${TANG_KEYS_DIR}"/*.jwk))"
  fi
  if [ -e "${TANG_KEYS_DIR}/.rotation-pending" ]; then
    warn "rotation pending (.rotation-pending): keeping ${#signs[@]} sign key(s); dot out or quarantine the old set and remove the marker once every client re-bound (docs/dr.md)"
    return 0
  fi
  if [ "${#signs[@]}" -eq 1 ] && [ "${#excs[@]}" -eq 1 ]; then
    printf '%s\n' "$(key_thp "${signs[0]}")" > "${TANG_KEYS_DIR}/.published-thp"
    log "keydir: exactly one key set (sign $(basename "${signs[0]}"), exchange $(basename "${excs[0]}"))"
    return 0
  fi
  # Keep the sign key the world already knows, never guess between two:
  # TANG_KEEP_THP (operator override) -> .published-thp (recorded here) ->
  # the first verify key tang-show-keys reports (what the artifact used) ->
  # deterministic basename order.
  keep_thp="${TANG_KEEP_THP:-}"
  [ -n "${keep_thp}" ] || keep_thp="$(cat "${TANG_KEYS_DIR}/.published-thp" 2>/dev/null || true)"
  [ -n "${keep_thp}" ] || keep_thp="$(tang-show-keys "${TANG_PORT}" 2>/dev/null | tr -s '[:space:]' '\n' | grep -m1 . || true)"
  if [ -n "${keep_thp}" ]; then
    # `if` not `&&`: a trailing failing test would leave the loop status 1, and
    # a pipeline whose FIRST element exits 1 is fatal under set -e + pipefail
    # (silent death — hit in CI, order-dependent).
    for f in "${signs[@]}"; do if [ "$(key_thp "$f")" = "${keep_thp}" ]; then keep_sign="$f"; fi; done
  fi
  if [ -z "${keep_sign}" ]; then
    keep_sign="$(printf '%s\n' "${signs[@]}" | LC_ALL=C sort | head -n1 || true)"
    [ -n "${keep_sign}" ] || die "could not choose a sign key among ${#signs[@]} candidates (inventory: $(key_inventory "${TANG_KEYS_DIR}"/*.jwk))"
    keep_name="$(basename "${keep_sign}")"
    warn "no sign key matches the published thumbprint '${keep_thp:-none}' — keeping ${keep_name} deterministically and re-publishing (inventory: $(key_inventory "${TANG_KEYS_DIR}"/*.jwk))"
  fi
  for f in "${excs[@]}"; do
    d="$(( $(date -r "$f" +%s) - $(date -r "${keep_sign}" +%s) ))"; d="${d#-}"
    if [ -z "${best_d}" ] || [ "$d" -lt "${best_d}" ]; then best="$f"; best_d="$d"; fi
  done
  keep_exc="${best}"
  qdir="${TANG_KEYS_DIR}.orphaned-$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -p "${qdir}"
  for f in "${signs[@]}" "${excs[@]}"; do
    if [ "$f" != "${keep_sign}" ] && [ "$f" != "${keep_exc}" ]; then
      mv -f -- "$f" "${qdir}/"
      log "quarantined $(basename "$f") [$(key_alg "${qdir}/$(basename "$f")"), thp $(key_thp "${qdir}/$(basename "$f")")] -> ${qdir} (restore: mv it back and re-run)"
    fi
  done
  printf '%s\n' "$(key_thp "${keep_sign}")" > "${TANG_KEYS_DIR}/.published-thp"
  chmod 0700 "${qdir}" 2>/dev/null || true
  chown -R "${TANG_UNIT_USER:-_tang}:${TANG_UNIT_USER:-_tang}" "${qdir}" 2>/dev/null || true
  own_keys
  log "keydir collapsed: serving sign $(basename "${keep_sign}") + exchange $(basename "${keep_exc}"); re-published thumbprint $(key_thp "${keep_sign}")"
}
# --- collapse:end ---

gen_keys() { # append a fresh key set on this box (never deletes)
  # Live 2026-09-08: tangd-keygen requires the dir to exist (usage error
  # otherwise) — some base images lack it entirely. # ci-allowlist: prose — base-image note, not a live image reference.
  mkdir -p "${TANG_KEYS_DIR}"
  if [ -x /usr/libexec/tangd-keygen ]; then
    /usr/libexec/tangd-keygen "${TANG_KEYS_DIR}"
  elif [ -x /usr/lib/tang/tangd-keygen ]; then
    /usr/lib/tang/tangd-keygen "${TANG_KEYS_DIR}"
  else
    die "tangd-keygen not found; reinstall the 'tang' package"
  fi
  own_keys
  systemctl restart tangd.socket 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# a) tang + tangd.socket (idempotent)
# ---------------------------------------------------------------------------
log "Installing tang (NBDE key server)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq tang jq jose >/dev/null

# Resolve the keydir/user from the installed unit and migrate keys written by
# earlier runs, so the published thumbprint survives (never regenerate over
# live keys). See the TANG_KEYS_DIR note at the top for why this matters.
TANG_UNIT_USER="$(unit_user || true)"
UNIT_KEYDIR="$(unit_keydir || true)"
# Accept only an absolute path — own_keys() chown/chmod -R's this directory.
case "${UNIT_KEYDIR}" in
  /?*) TANG_KEYS_DIR="${UNIT_KEYDIR}" ;;
  *) [ -d /var/lib/tang ] && TANG_KEYS_DIR="/var/lib/tang" ;;
esac
log "tang keydir: ${TANG_KEYS_DIR} (unit user: ${TANG_UNIT_USER:-unknown})"
if [ "${TANG_KEYS_DIR}" != "${LEGACY_TANG_KEYS_DIR}" ] \
   && ! compgen -G "${TANG_KEYS_DIR}/*.jwk" >/dev/null \
   && compgen -G "${LEGACY_TANG_KEYS_DIR}/*.jwk" >/dev/null; then
  mkdir -p "${TANG_KEYS_DIR}"
  for f in "${LEGACY_TANG_KEYS_DIR}"/*.jwk; do
    cp -p "$f" "${TANG_KEYS_DIR}/"
  done
  log "Migrated existing tang keys ${LEGACY_TANG_KEYS_DIR} -> ${TANG_KEYS_DIR} (thumbprint preserved)"
fi
# One-shot by design: only migrate into an EMPTY keydir. Copying per-file
# would resurrect keys quarantined by collapse_keys() below (same basename
# absent from the keydir) and re-create a multi-set anchor on every run.
own_keys

log "Moving tangd.socket to 127.0.0.1:${TANG_PORT} (Caddy owns :80 from here on)"
mkdir -p /etc/systemd/system/tangd.socket.d
printf '[Socket]\nListenStream=\nListenStream=127.0.0.1:%s\n' "${TANG_PORT}" > /etc/systemd/system/tangd.socket.d/listen.conf
systemctl daemon-reload
systemctl enable --now tangd.socket >/dev/null 2>&1 || true
systemctl restart tangd.socket 2>/dev/null || true
# Serve model on Debian/Ubuntu (verified live 2026-09-10, #75): the tang
# package ships tangd.socket + tangd@.service with Accept=yes — there is NO
# plain tangd.service, and a connection spawns a per-connection instance.
# So the socket cycle above is the whole restart; the instances are spawned
# on demand and must be diagnosed through the socket unit.
# Prove no double-bind: tangd must listen ONLY on loopback (Caddy owns :80).
# Exact match is deliberate: any extra listener (including a lingering :80)
# fails closed instead of half-covering the proxy cutover. Live 2026-09-10
# (#71): `systemctl show -p Listen` appends the socket type on this systemd
# version ('127.0.0.1:8081(Stream)'), so exactly two raw forms are accepted —
# the bare address and the one-listener form with the (Stream) suffix. Any
# other shape (multiple listeners, another type, :80) dies with the raw value.
RAW_LISTEN="$(systemctl show tangd.socket -p Listen --value 2>/dev/null | tr -d '[:space:]' || true)"
log "tangd.socket listens: ${RAW_LISTEN}"
case "${RAW_LISTEN}" in
  "127.0.0.1:${TANG_PORT}" | "127.0.0.1:${TANG_PORT}(Stream)") ;;
  *) die "tangd.socket listens on '${RAW_LISTEN}', want exactly one listener '127.0.0.1:${TANG_PORT}' (a (Stream) suffix is tolerated) — refusing to continue with an unexpected listener (tang and Caddy must never both bind :80)" ;;
esac

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
  touch "${TANG_KEYS_DIR}/.rotation-pending"
  gen_keys
  warn "Re-bind every client to the NEW thumbprint below and reboot-verify each BEFORE dotting out or removing the old keys; then remove ${TANG_KEYS_DIR}/.rotation-pending (the single-set collapse stays paused while it exists)."
fi

# Normal runs converge to exactly one bindable key set; --rotate pauses this
# via the .rotation-pending marker it drops above (see the block comment).
collapse_keys

# ---------------------------------------------------------------------------
# b) thumbprint — the ONE value you must save
# ---------------------------------------------------------------------------
log "tang is running. Your thumbprint (SAVE THIS NOW):"
echo
if command -v tang-show-keys >/dev/null 2>&1; then
  echo "    $(tang-show-keys "${TANG_PORT}")"
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
caddy_status_names
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
  printf '%s\n' "  # The anchor through Caddy's :80 (proves the proxy path clevis"
  printf '%s\n' "  # traffic takes). Probes reach the host via the hostanchor mapping on \`docker run\` below;"
  printf '%s\n' "  # never firewalled, always accurate. There is deliberately NO direct endpoint"
  printf '%s\n' "  # here: tangd binds 127.0.0.1 only, which a bridge-network container can never"
  printf '%s\n' "  # dial; instead every run proves tang direct with a host-level curl to :8081/adv"
  printf '%s\n' "  # (see the proxy proofs at the end)."
  printf '%s\n' "  - name: tang (via Caddy)"
  printf '%s\n' "    url: http://hostanchor/adv"
  printf '%s\n' "    interval: 60s"
  printf '%s\n' "    conditions:"
  printf '%s\n' "      - \"[STATUS] == 200\""
  printf '%s\n' "      - \"[RESPONSE_TIME] < 500\"  # Caddy p95>500ms alert, per-probe form (docs: https://gatus.io/docs)"
  printf '%s' "$ENDPOINTS_YAML"
  if [ -n "${STATUS_HOST:-}" ]; then
    printf '%s\n' "  # Dashboard through the orange cloud: proves edge -> origin TLS and"
    printf '%s\n' "  # warns while the cert is still fresh (stale-cert failure is"
    printf '%s\n' "  # dashboard-only — tang answers plain HTTP on its own port)."
    printf '%s\n' "  - name: dashboard TLS (via edge)"
    printf '%s\n' "    url: https://${STATUS_HOST}"
    printf '%s\n' "    interval: 300s"
    printf '%s\n' "    conditions:"
    printf '%s\n' "      - \"[STATUS] == 200\""
    printf '%s\n' "      - \"[CERTIFICATE_EXPIRATION] > 720h\"  # fail (and ALERT via ntfy) inside the ~30d stale-cert window"
  fi
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
# c2) Docker runtime (idempotent; distro package, no third-party script)
# ---------------------------------------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
  log "Installing Docker (docker.io distro package)"
  export DEBIAN_FRONTEND=noninteractive
  apt-get install -y -qq docker.io >/dev/null
fi
systemctl enable --now docker >/dev/null 2>&1 || true
# The runner-facing `docker` CLI is the daemon on the same box (root) — the
# provision runs as root over the A1 window, so no sudo/group gymnastics.

# ---------------------------------------------------------------------------
# d) Run Gatus (container recreated when the pinned image changed - so an # ci-allowlist: prose — container-tag wording, not a live reference.
#    auto-bumped pin actually REACHES deployed anchors on script re-run;
#    config and the sqlite history volume survive the recreation)
# ---------------------------------------------------------------------------
log "Running Gatus monitor (bound to 127.0.0.1:${GATUS_PORT})"
if docker ps --format '{{.Names}}' | grep -qx "gatus"; then
  RUNNING_IMAGE=$(docker inspect --format '{{.Config.Image}}' gatus) # ci-allowlist: code — docker inspect field name, not a live reference.
  if [ "${RUNNING_IMAGE}" = "${GATUS_IMAGE}" ]; then
    if docker inspect --format '{{json .HostConfig.ExtraHosts}}' gatus 2>/dev/null | grep -q hostanchor; then
      log "Gatus already running on ${GATUS_IMAGE}"
    else
      log "Gatus container predates the hostanchor mapping (dual probes need it) - recreating" # ci-allowlist: prose — container-flag change note, not a live reference.
      docker rm -f gatus >/dev/null
    fi
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
    --add-host=hostanchor:host-gateway \
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

# ---------------------------------------------------------------------------
# e) Caddy — dashboard TLS + tang proxy (DISPATCH-MANAGED Caddyfile, same
#    render pattern as the Gatus config above). Caddy owns :80; tangd.socket
#    moved to 127.0.0.1:${TANG_PORT} in section (a); Gatus stays loopback-only
#    (127.0.0.1:8080, Caddy proxies the status host to it).
#
#    Shape (issue #49, decided): explicit per-tenant site blocks, NEVER
#    on_demand TLS. :80 serves tang paths plain (NO redirect), the ACME
#    HTTP-01 path, and the status host plain; everything else aborts.
#    :443 serves the dashboard for the one explicit status hostname below.
#
#    Env in (operator-plane repo secrets — the tenant pastes nothing, so
#    tenant bootstrap stays 1 secret): CF_ORIGIN_CERT_PEM / CF_ORIGIN_KEY_PEM
#    (Cloudflare Origin CA pair, deployed key material — the box can present
#    its origin cert but cannot rewrite the zone, unlike a standing API
#    token. Absent = Caddy automatic HTTPS via HTTP-01 instead:
#    dashboard-only degradation, tang unaffected), CF_AOP_CA_PEM (optional
#    zone-level Authenticated Origin Pulls bundle for our own cert; absent =
#    edge auth stays firewall-allowlist + Host binding until the operator
#    finishes the AOP ceremony in docs/dr.md + re-dispatches).
# ---------------------------------------------------------------------------
log "Rendering dispatch-managed Caddyfile (${CADDY_CONFIG})"
mkdir -p "$(dirname "${CADDY_CONFIG}")" "${CADDY_CHALLENGE_DIR}"
# One-time backup of any pre-managed hand config (never overwritten twice).
if [ -f "${CADDY_CONFIG}" ] && [ ! -f "${CADDY_CONFIG}.pre-managed.bak" ] && ! grep -q "DISPATCH-MANAGED" "${CADDY_CONFIG}" 2>/dev/null; then
  cp -p "${CADDY_CONFIG}" "${CADDY_CONFIG}.pre-managed.bak"
  log "Backed up pre-managed Caddyfile to ${CADDY_CONFIG}.pre-managed.bak (one-time)"
fi
# Origin pair: garbage fails closed (half-TLS is worse than dashboard-pending).
ORIGIN_TLS=0
if [ -n "${CF_ORIGIN_CERT_PEM:-}" ] || [ -n "${CF_ORIGIN_KEY_PEM:-}" ]; then
  case "${CF_ORIGIN_CERT_PEM:-}" in *"BEGIN CERTIFICATE"*) ;; *) die "CF_ORIGIN_CERT_PEM does not look like a PEM certificate — refusing to render half-TLS";; esac
  case "${CF_ORIGIN_KEY_PEM:-}" in *"PRIVATE KEY"*) ;; *) die "CF_ORIGIN_KEY_PEM does not look like a PEM private key — refusing to render half-TLS";; esac
  printf '%s\n' "${CF_ORIGIN_CERT_PEM}" > "${CADDY_ORIGIN_CRT}"
  printf '%s\n' "${CF_ORIGIN_KEY_PEM}" > "${CADDY_ORIGIN_KEY}"
  chmod 600 "${CADDY_ORIGIN_CRT}" "${CADDY_ORIGIN_KEY}"
  ORIGIN_TLS=1
  log "Origin CA pair deployed (cert $(wc -c <"${CADDY_ORIGIN_CRT}") bytes; key material never logged)"
else
  warn "CF_ORIGIN_CERT_PEM/CF_ORIGIN_KEY_PEM unset — :443 uses Caddy automatic HTTPS (HTTP-01 via :80 below). Set the operator pair + re-dispatch for Origin-CA Full (Strict)."
fi
# AOP bundle (public cert material — world-readable is fine).
AOP_TLS=""
if [ -n "${CF_AOP_CA_PEM:-}" ]; then
  case "${CF_AOP_CA_PEM}" in *"BEGIN CERTIFICATE"*) ;; *) die "CF_AOP_CA_PEM does not look like a PEM certificate bundle";; esac
  printf '%s\n' "${CF_AOP_CA_PEM}" > "${CADDY_AOP_CA}"
  chmod 644 "${CADDY_AOP_CA}"
  AOP_TLS="yes"
  log "AOP client-auth bundle deployed — origin pulls must present a client cert signed by this CA (require_and_verify)"
else
  warn "CF_AOP_CA_PEM unset — edge authentication is firewall-allowlist + Host binding until the operator finishes the AOP ceremony (docs/dr.md) + re-dispatches"
fi
CF_AOP_CA_PEM=""; CF_ORIGIN_KEY_PEM=""; CF_ORIGIN_CERT_PEM=""  # discard from memory (files above are 600/644 on this box only)
if [ "${ORIGIN_TLS}" = "1" ]; then
  if [ -n "${AOP_TLS}" ]; then
    DASH_TLS_STANZA="	tls ${CADDY_ORIGIN_CRT} ${CADDY_ORIGIN_KEY} {
		client_auth {
			mode require_and_verify
			trust_pool file ${CADDY_AOP_CA}
		}
	}"
  else
    DASH_TLS_STANZA="	tls ${CADDY_ORIGIN_CRT} ${CADDY_ORIGIN_KEY}"
  fi
else
  DASH_TLS_STANZA="	# No origin pair deployed: Caddy automatic HTTPS (HTTP-01 via :80 below)."
fi
TMP_CADDY="${CADDY_CONFIG}.new"
render_caddyfile >"$TMP_CADDY"
CADDY_RESTART=0
if [ -f "${CADDY_CONFIG}" ] && cmp -s "${CADDY_CONFIG}" "$TMP_CADDY"; then
  log "Caddyfile unchanged"
  rm -f "$TMP_CADDY"
else
  # Pre-validate the RENDERED file in an ephemeral container before it goes
  # live (mounts mirror the run below; the file mounts at a scratch path so
  # a rejection never touches the serving config).
  log "Validating rendered Caddyfile in an ephemeral container"
  CADDY_VAL_ARGS="-v ${TMP_CADDY}:/tmp/Caddyfile.new:ro"
  if [ "${ORIGIN_TLS}" = "1" ]; then
    CADDY_VAL_ARGS="${CADDY_VAL_ARGS} -v ${CADDY_ORIGIN_CRT}:/etc/caddy/origin.crt:ro -v ${CADDY_ORIGIN_KEY}:/etc/caddy/origin.key:ro"
  fi
  if [ -n "${AOP_TLS}" ]; then
    CADDY_VAL_ARGS="${CADDY_VAL_ARGS} -v ${CADDY_AOP_CA}:/etc/caddy/aop-ca.pem:ro"
  fi
  # shellcheck disable=SC2086: mount args are flag-or-path pairs built above, no spaces by construction.
  docker run --rm $CADDY_VAL_ARGS "${CADDY_IMAGE}" caddy validate --config /tmp/Caddyfile.new --adapter caddyfile || die "rendered Caddyfile failed validate — refusing to install it (serving config untouched)"
  mv "$TMP_CADDY" "${CADDY_CONFIG}"
  log "Caddyfile installed (rendered from dispatch env)"
  CADDY_RESTART=1
fi
# ---------------------------------------------------------------------------
# e2) Run Caddy (container recreated when the pinned tag changed — so a
#    Renovate bump REACHES deployed anchors on re-run — or when the deployed
#    PEM set changed (new mounts); the Caddyfile + history volumes survive.
#    256M cap + GOMEMLIMIT + GOMAXPROCS=1: the piko box is small and Caddy
#    must never starve tangd.
# ---------------------------------------------------------------------------
log "Running Caddy edge proxy (:80+:443, 256M cap)"
CADDY_WANT_MOUNTS="caddyfile"
[ "${ORIGIN_TLS}" = "1" ] && CADDY_WANT_MOUNTS="${CADDY_WANT_MOUNTS} origin"
[ -n "${AOP_TLS}" ] && CADDY_WANT_MOUNTS="${CADDY_WANT_MOUNTS} aop"
CADDY_HAVE_MOUNTS="$(cat /etc/caddy/.deployed-mounts 2>/dev/null || true)"
if docker ps --format '{{.Names}}' | grep -qx "caddy"; then
  CADDY_RUNNING_IMAGE=$(docker inspect --format '{{.Config.Image}}' caddy) # ci-allowlist: code — docker inspect field name, not a live reference.
  if [ "${CADDY_RUNNING_IMAGE}" = "${CADDY_IMAGE}" ] && [ "${CADDY_HAVE_MOUNTS}" = "${CADDY_WANT_MOUNTS}" ]; then
    log "Caddy already running on ${CADDY_IMAGE}"
  else
    log "Caddy image or deployed-PEM set changed - recreating container" # ci-allowlist: prose — container-tag change note, not a live reference.
    docker rm -f caddy >/dev/null
  fi
elif docker ps -a --format '{{.Names}}' | grep -qx "caddy"; then
  docker rm -f caddy >/dev/null   # stale stopped container; recreated below
fi
CADDY_MOUNT_ARGS="-v ${CADDY_CONFIG}:/etc/caddy/Caddyfile:ro"
if [ "${ORIGIN_TLS}" = "1" ]; then
  CADDY_MOUNT_ARGS="${CADDY_MOUNT_ARGS} -v ${CADDY_ORIGIN_CRT}:/etc/caddy/origin.crt:ro -v ${CADDY_ORIGIN_KEY}:/etc/caddy/origin.key:ro"
fi
if [ -n "${AOP_TLS}" ]; then
  CADDY_MOUNT_ARGS="${CADDY_MOUNT_ARGS} -v ${CADDY_AOP_CA}:/etc/caddy/aop-ca.pem:ro"
fi
if ! docker ps --format '{{.Names}}' | grep -qx "caddy"; then
  # shellcheck disable=SC2086: mount args are flag-or-path pairs built above, no spaces by construction.
  # --network host (NOT -p publishing): Caddy dials 127.0.0.1:8081/:8080 for
  # tangd/Gatus on the HOST loopback — in the default bridge netns those dials
  # would hit the container's own loopback (502 everywhere, tang dead). Host
  # networking keeps the loopback dials valid; the netcup firewall policy
  # (main /32 + edge ranges) stays the ingress gate. Loopback admin :2019
  # likewise binds host loopback: `docker exec` reload works, outside cannot reach.
  docker run -d --name caddy --restart unless-stopped \
    --network host \
    --memory 256m \
    -e GOMEMLIMIT=230MiB -e GOMAXPROCS=1 \
    $CADDY_MOUNT_ARGS \
    --mount type=volume,source=caddy-data,target=/data \
    --mount type=volume,source=caddy-config,target=/config \
    -v "${CADDY_CHALLENGE_DIR}:/var/lib/caddy/acme-challenge" \
    "${CADDY_IMAGE}" >/dev/null
  printf '%s' "${CADDY_WANT_MOUNTS}" > /etc/caddy/.deployed-mounts
  sleep 3
  if ! docker ps --format '{{.Names}}' | grep -qx "caddy"; then
    docker logs caddy 2>&1 | tail -20 || true
    die "Caddy exited on boot with the new config — tang stays up on loopback but the :80 proxy is down; reversibility: docs/dr.md"
  fi
fi
if [ "${CADDY_RESTART:-0}" = "1" ]; then
  # Mounts already converged above (recreate path); reload = zero-downtime.
  docker exec caddy caddy reload --config /etc/caddy/Caddyfile
  log "Caddy reloaded on new config"
fi
# Prove tang DIRECT on loopback first (this host curl is the direct proof that
# replaces a Gatus direct endpoint — see the render comment above), then tang
# through Caddy's :80, dashboard by Host.
# The /adv body is a flattened JWS: upstream tang (v11..v15, src/keys.c
# jwk_sign) packs {"payload": b64u({"keys":[...]}), "protected": ...,
# "signature": ...} — the literal string "kty" exists ONLY inside the
# base64url payload, so a raw grep can never match a serving tang. Live
# 2026-09-10 (#77): that grep failed every run while the real fault was the
# key directory above.
# A tang with MORE THAN ONE key set installed signs with every sign key and
# jose then emits the JWS GENERAL serialization — {"payload": ...,
# "signatures": [{"protected": ..., "signature": ...}, ...]} — with no
# top-level protected/signature. Live 2026-09-10 (#79, reproduced locally
# with Debian trixie tang 15-2 + jose 14-2 and two keygen rounds): the box
# answered in that shape while CI's single-key mock stays flattened, so the
# probe must accept BOTH.
# The shape check is mandatory; the deeper jose parse is best-effort and
# fails loud-but-non-fatal, because the `tang` package does not depend on
# jose (the cryptographic proof lives in the thumbprint step and the
# operator's bind). Every branch logs WHY it rejected, so a live run is
# diagnosable without another dispatch.
adv_ok() {
  adv_file="$1"
  if [ ! -s "${adv_file}" ]; then
    log "adv check: empty /adv response"
    return 1
  fi
  if command -v jq >/dev/null 2>&1; then
    if ! jq -e 'has("payload") and ((has("protected") and has("signature")) or (has("signatures") and (.signatures | type == "array") and (.signatures | length > 0)))' "${adv_file}" >/dev/null 2>&1; then
      log "adv check: not a JWS advertisement (flattened or general) — body starts (160 bytes):"
      head -c 160 "${adv_file}" || true; echo
      jq -r 'keys | join(",")' "${adv_file}" 2>&1 | head -2 || true
      return 1
    fi
  else
    log "adv check: jq missing — falling back to an envelope substring check"
    has_payload=0; has_flat=0; has_general=0
    grep -q '"payload"' "${adv_file}" && has_payload=1
    { grep -q '"protected"' "${adv_file}" && grep -q '"signature"' "${adv_file}"; } && has_flat=1
    grep -q '"signatures"' "${adv_file}" && has_general=1
    if [ "${has_payload}" != "1" ] || { [ "${has_flat}" != "1" ] && [ "${has_general}" != "1" ]; }; then
      log "adv check: body lacks JWS fields — body starts (160 bytes):"
      head -c 160 "${adv_file}" || true; echo
      return 1
    fi
  fi
  if command -v jose >/dev/null 2>&1; then
    if ! jose fmt --json="$(cat "${adv_file}")" -g payload -y -o- 2>/dev/null \
      | jose jwk use -i- -r -u verify -o- >/dev/null 2>&1; then
      log "adv check: envelope ok but jose found no verify-usable key in the payload (non-fatal; payload starts below)"
      jose fmt --json="$(cat "${adv_file}")" -g payload -y -o- 2>&1 | head -c 200 || true; echo
    fi
  else
    log "adv check: jose missing — envelope shape only (jose is installed with the tang package above)"
  fi
  return 0
}
probe_tang_direct() {
  curl -sf --max-time 5 "http://127.0.0.1:${TANG_PORT}/adv" -o /tmp/tang-direct.json \
    && adv_ok /tmp/tang-direct.json
}
ok=0
for i in 1 2 3 4 5 6; do
  probe_tang_direct && { ok=1; break; }
  sleep 10
done
if [ "$ok" != "1" ]; then
  # Live 2026-09-10 (#75): a socket that was reconfigured in place can be left
  # "not functional until restarted"; a full stop/start is the documented cure.
  log "Direct probe failed — cycling the socket once and re-probing"
  systemctl stop tangd.socket 2>/dev/null || true
  systemctl start tangd.socket 2>/dev/null || true
  sleep 2
  for i in 1 2 3; do
    probe_tang_direct && { ok=1; break; }
    sleep 5
  done
fi
if [ "$ok" != "1" ]; then
  # The socket is Accept=yes on this distro (tangd@.service, instance per
  # connection), so the failure lives in the instance path: dump everything
  # (verbose curl, unit files, instance journal, package, keys, manual spawn)
  # so the next run's log is enough to write the real fix. # ci-allowlist: prose — on-box instance note, not a live image reference.
  log "tangd direct-probe failed — capturing listener, instance and package state"
  curl -sv --max-time 5 "http://127.0.0.1:${TANG_PORT}/adv" 2>&1 | tail -25 || true
  systemctl --no-pager -l status tangd.socket 2>&1 | tail -18 || true
  systemctl list-units 'tangd*' --all --no-pager 2>&1 | tail -12 || true
  log "unit file tangd.socket:"; systemctl cat tangd.socket 2>&1 | tail -25 || true
  log "unit file tangd@.service:"; systemctl cat 'tangd@.service' 2>&1 | tail -25 || true
  log "instance journal:"; journalctl -u 'tangd@*' -n 60 --no-pager 2>&1 | tail -60 || true
  log "advertisement body (first 200 bytes):"; head -c 200 /tmp/tang-direct.json 2>/dev/null || true; echo
  log "adv tooling:"; command -v jq || echo "jq MISSING"; command -v jose || echo "jose MISSING"
  jq --version 2>/dev/null || true; dpkg -l jq jose 2>&1 | tail -3 || true
  jq -e 'has("payload") and has("protected") and has("signature")' /tmp/tang-direct.json >/dev/null 2>&1 && log "manual jq shape check: OK" || log "manual jq shape check: FAILED"
  jose fmt --json="$(cat /tmp/tang-direct.json 2>/dev/null)" -g payload -y -o- 2>/dev/null | jose jwk use -i- -r -u verify -o- >/dev/null 2>&1 && log "manual jose payload parse: OK" || log "manual jose payload parse: FAILED"
  log "package:"; dpkg -l tang 2>&1 | tail -3 || true
  dpkg -L tang 2>&1 | grep -E 'systemd|libexec|lib/tang|/s?bin/' | head -12 || true
  log "keydir + user (${TANG_KEYS_DIR} / ${TANG_UNIT_USER:-unknown}):"
  ls -la "${TANG_KEYS_DIR}" 2>&1 | head -8 || true; ls -la "${LEGACY_TANG_KEYS_DIR}" 2>&1 | head -4 || true
  getent passwd "${TANG_UNIT_USER:-_tang}" 2>&1 || true
  TBIN=/usr/libexec/tangd; [ -x "$TBIN" ] || TBIN=/usr/lib/tang/tangd
  log "manual spawn ($TBIN):"
  "$TBIN" --help >/tmp/tangd-help.txt 2>&1; log "help exit=$?"; head -c 400 /tmp/tangd-help.txt || true; echo
  timeout 5 "$TBIN" "${TANG_KEYS_DIR}" </dev/null >/tmp/tangd-try.txt 2>&1; log "manual exit=$?"; head -c 300 /tmp/tangd-try.txt || true; echo
  die "tangd does not answer direct on 127.0.0.1:${TANG_PORT} (/adv) — refusing to finish blind"
fi
log "tangd answers direct on loopback (OK)"
ok=0
for i in 1 2 3 4 5 6; do
  if curl -sf --max-time 5 http://127.0.0.1/adv -o /tmp/caddy-adv.json && adv_ok /tmp/caddy-adv.json; then ok=1; break; fi
  sleep 10
done
if [ "$ok" != "1" ]; then
  docker logs caddy 2>&1 | tail -20 || true
  die "Caddy :80 does not proxy tang (/adv) after converge — refusing to finish blind"
fi
log "Caddy :80 proxies tang (OK)"
if [ -n "${STATUS_HOST:-}" ]; then
  # Dashboard proof goes through the Host matcher to Gatus's own statuses API
  # (deterministic body: our rendered endpoint name, not UI branding bytes).
  # Two legitimate states (live 2026-09-10, #83): under CADDY_SKIP_HTTPS the
  # :80 vhost proxies straight to Gatus; with automatic HTTPS (no operator
  # origin pair yet) Caddy answers :80 with the HTTP->HTTPS redirect for that
  # name. Both prove the Host matched the dashboard vhost; an unmatched host
  # hits the render's `handle { abort }` (empty reply, code 000) instead.
  if curl -sf -H "Host: ${STATUS_HOST}" http://127.0.0.1/api/v1/endpoints/statuses -o /tmp/caddy-dash.json && grep -q 'tang (via Caddy)' /tmp/caddy-dash.json; then
    log "Caddy :80 serves the dashboard vhost for ${STATUS_HOST} (OK)"
  else
    dash_code="$(curl -s -o /dev/null -w '%{http_code}' -H "Host: ${STATUS_HOST}" http://127.0.0.1/api/v1/endpoints/statuses 2>/dev/null || true)"
    case "${dash_code}" in
      301|302|307|308)
        log "Caddy :80 matches the dashboard vhost for ${STATUS_HOST} (HTTP ${dash_code} -> HTTPS; auto-TLS stopgap — the proxied edge record is upserted by the DNS stage after close)" ;;
      *)
        docker logs caddy 2>&1 | tail -20 || true
        die "Caddy :80 does not serve the dashboard vhost for ${STATUS_HOST} (HTTP ${dash_code:-000}) — refusing to finish blind" ;;
    esac
  fi
  # SNI must be the real hostname: curl sends no SNI for an IP-literal URL
  # and Caddy selects the origin cert by SNI, so a Host header alone fails a
  # healthy box once the operator origin pair is deployed (live 2026-09-10,
  # issue #92). --resolve keeps the TCP connect on loopback.
  #
  # AOP (issue #97): when the client-auth bundle is deployed the origin must
  # REJECT a cert-less probe (that is the point), while the edge pull — which
  # carries Cloudflare's client cert — must still serve. Both halves are
  # asserted; a wrong trust bundle black-holes every edge pull, so this is
  # fail-closed.
  if [ -n "${AOP_TLS}" ]; then
    # curl exit codes decisively separate "the origin rejected the cert-less
    # handshake" (35/56 = TLS layer, the point of AOP) from "nothing answered"
    # (7 refused / 28 timeout) or a DNS problem (6): only a TLS-layer rejection
    # proves client_auth is enforcing — a dead :443 must not pass this probe.
    neg_rc=0
    curl -sk --max-time 10 --resolve "${STATUS_HOST}:443:127.0.0.1" "https://${STATUS_HOST}/" -o /dev/null 2>/dev/null || neg_rc=$?
    case "${neg_rc}" in
      0)
        die "Caddy :443 answered a cert-less probe while AOP is deployed — client_auth is not enforcing; roll back with: gh secret delete CF_AOP_CA_PEM --repo ${GITHUB_REPOSITORY:-piercloud-net/terraform-piercloud-anchor} && gh workflow run provision.yml -f mode=apply" ;;
      35|56)
        log "Caddy :443 rejected the cert-less probe at the TLS layer (curl exit ${neg_rc}; OK under require_and_verify)" ;;
      7|28)
        die "Caddy :443 did not answer the cert-less probe (curl exit ${neg_rc}: refused/timeout) — cannot prove client_auth is enforcing; refusing to finish blind" ;;
      *)
        die "Caddy :443 cert-less probe failed with curl exit ${neg_rc} (not a TLS-layer rejection) — cannot prove client_auth is enforcing; refusing to finish blind" ;;
    esac
    edge_ok=0
    edge_rc=0
    for attempt in 1 2 3; do
      edge_rc=0
      curl -sSf --max-time 20 "https://${STATUS_HOST}/" -o /dev/null || edge_rc=$?
      if [ "${edge_rc}" -eq 0 ]; then edge_ok=1; break; fi
      if [ "${attempt}" -lt 3 ]; then
        log "edge pull attempt ${attempt}/3 failed (curl exit ${edge_rc}); retrying in 5s"
        sleep 5
      fi
    done
    if [ "$edge_ok" -ne 1 ]; then
      if [ "${edge_rc}" -eq 6 ]; then
        die "edge pull failed: https://${STATUS_HOST}/ does not resolve yet (curl exit 6). The proxied edge record is upserted by the DNS stage AFTER this job, so on a first-time/DR dispatch this probe cannot pass. Temporarily: gh secret delete CF_AOP_CA_PEM --repo ${GITHUB_REPOSITORY:-piercloud-net/terraform-piercloud-anchor} && re-dispatch; once DNS converges re-enable AOP (docs/dr.md)"
      fi
      die "edge pull through Cloudflare failed while AOP is deployed (curl exit ${edge_rc}) — the origin trust bundle does not match Cloudflare's client cert; roll back with: gh secret delete CF_AOP_CA_PEM --repo ${GITHUB_REPOSITORY:-piercloud-net/terraform-piercloud-anchor} && gh workflow run provision.yml -f mode=apply (or rotate the leaf with 102 --force-aop, then re-dispatch)"
    fi
    log "edge pull through Cloudflare serves with AOP enforced (OK)"
  elif curl -skf --max-time 10 --resolve "${STATUS_HOST}:443:127.0.0.1" "https://${STATUS_HOST}/" -o /dev/null; then
    log "Caddy :443 handshakes for ${STATUS_HOST} (OK; edge trust is zone-side, see docs/dr.md)"
  elif [ ! -s "${CADDY_ORIGIN_CRT}" ]; then
    # No operator origin pair: auto-TLS cannot issue for a name whose public
    # record is only upserted by the DNS stage after this job. Origin TLS is
    # proven there (verify-after-write + orange-cloud) and by the edge, so
    # this is loud, not fatal; with the pair deployed it stays fail-closed.
    log "WARNING: Caddy :443 has no certificate for ${STATUS_HOST} yet — auto-TLS stopgap, no operator origin pair; the proxied edge record is upserted after close (docs/dr.md)"
  else
    docker logs caddy 2>&1 | tail -20 || true
    die "Caddy :443 does not handshake for ${STATUS_HOST} — refusing to finish blind"
  fi
fi

log "Done. tang is up (loopback, via Caddy :80), the thumbprint is above, Gatus is dispatch-managed (statuses printed above), dashboard at https://${STATUS_HOST:-status.<alias>.piercloud.net} (TLS on the box)."
