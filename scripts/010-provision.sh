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
# Per-anchor Cloudflare Origin CA material (issue #123) follows the same rule:
# the key is generated ON THIS BOX and never leaves; the CSR is public; the
# signed cert arrives via ORIGIN_CA_CERT_PEM (cert-only material).
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
# Tenant naming is canonical in scripts/lib/naming.sh (the workflow resolve
# step and .github/scripts/030-anchor-dns.sh source it). Inside the nested
# NAMING markers below sits the embedded fallback for console hand runs
# (dispatched runs receive STATUS_HOST as the dashboard FQDN via 020's
# ENV_PREFIX; ANCHOR_HOSTNAME stays the zone-less SCP hostname);
# tests/naming-scheme/run-test.sh diffs the block against the lib — edit the
# lib and copy the block, never fork it.
# --- BEGIN NAMING ---
validate_tenant_username() { # $1 = lowercased RAW tenant username; 0 ok, 1 fail (message names the value)
  case "$1" in
    *[!a-z0-9]* | '')
      printf 'invalid TENANT_USER "%s": must match ^[a-z0-9]{1,20}$ before normalization (letters/digits only, 1-20 chars).\n' "$1" >&2
      return 1 ;;
  esac
  if [ "${#1}" -gt 20 ]; then
    printf 'invalid TENANT_USER "%s": must match ^[a-z0-9]{1,20}$ before normalization (letters/digits only, 1-20 chars).\n' "$1" >&2
    return 1
  fi
  case "$1" in
    anchor* | status* | pcu* | platform*)
      printf 'invalid TENANT_USER "%s": reserved prefix — names starting with anchor/status/pcu/platform are platform labels, not tenants.\n' "$1" >&2
      return 1 ;;
  esac
  return 0
}

sanitize_tenant() { # $1 = raw tenant username -> lowercase [a-z0-9-], hyphen runs collapsed, edges trimmed
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | sed -e 's/[^a-z0-9-]/-/g' -e 's/-\{2,\}/-/g' -e 's/^-//' -e 's/-$//'
}

derive_anchor_hostname() { # $1 = sanitized tenant -> anchor-<NN>-<tenant> (NN=01; -02+ is future)
  printf 'anchor-01-%s\n' "$1"
}

derive_status_host() { # $1 = sanitized tenant -> status-<tenant> (dashboard singleton, one label)
  printf 'status-%s\n' "$1"
}
# --- END NAMING ---
caddy_status_names() { # STATUS_HOST/ANCHOR_HOSTNAME from dispatch env, else derived from TENANT_USER
# Empty on hand runs without env (console fallback): the :80 tang proxy
# still renders below, but the :443 dashboard block and the TLS-expiry
# probe wait for a re-dispatch with TENANT_USER.
local raw san
if [ -z "${STATUS_HOST:-}" ] || [ -z "${ANCHOR_HOSTNAME:-}" ]; then
  raw="$(printf '%s' "${TENANT_USER:-}" | tr '[:upper:]' '[:lower:]')"
  if [ -n "$raw" ]; then
    san="$(sanitize_tenant "$raw")"
    if [ -n "$san" ]; then
      [ -n "${STATUS_HOST:-}" ] || STATUS_HOST="$(derive_status_host "$san").piercloud.net"
      [ -n "${ANCHOR_HOSTNAME:-}" ] || ANCHOR_HOSTNAME="$(derive_anchor_hostname "$san")"
    fi
  fi
fi
if [ -z "${STATUS_HOST:-}" ]; then
  STATUS_HOST=""
  warn "TENANT_USER unset — dashboard TLS block and TLS-expiry probe skipped (re-dispatch with TENANT_USER to converge them)"
fi
# Exact Host value for the :80 dashboard matcher (review: a wildcard span was
# never verified — render the exact name; hand runs get a never-matching
# sentinel so the :80 block still validates).
STATUS_MATCH="${STATUS_HOST:-status-invalid.invalid}"
}

render_caddyfile() { # print the Caddyfile to stdout
  printf '%s\n' "# DISPATCH-MANAGED by terraform-piercloud-anchor (scripts/010-provision.sh)."
  printf '%s\n' "# DO NOT EDIT BY HAND — re-rendered on every provision run. Dashboard TLS"
  printf '%s\n' "# converges from TENANT_USER + the installed origin pair / CF_AOP_CA_* secret;"
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

# --- origin-ca:start --- (tests/origin-ca extracts this span; keep markers)
# Per-anchor Cloudflare Origin CA material (issue #123): the private key is
# generated ON this box and never leaves it; the CSR is public material
# published in the run artifact for operator-side signing; the signed cert
# returns via the ORIGIN_CA_CERT_PEM env (cert-only repo variable) and is
# validated fail-closed before Caddy may serve it. Paths are overridable so
# the harness can run this span off-box (same pattern as the bind-e2e
# render span).
ORIGIN_CA_DIR="${ORIGIN_CA_DIR:-/etc/caddy}"
ORIGIN_CA_KEY="${ORIGIN_CA_KEY:-${ORIGIN_CA_DIR}/origin-ca.key}"
ORIGIN_CA_CSR="${ORIGIN_CA_CSR:-${ORIGIN_CA_DIR}/origin-ca.csr}"
ORIGIN_CA_CRT="${ORIGIN_CA_CRT:-${ORIGIN_CA_DIR}/origin-ca.crt}"
ORIGIN_CA_HASH="${ORIGIN_CA_HASH:-${ORIGIN_CA_DIR}/.origin-ca.crt.sha256}"
ORIGIN_CA_ACTIVE="${ORIGIN_CA_ACTIVE:-${ORIGIN_CA_DIR}/.origin-ca-active}"
# :443 target for the served-leaf probe (test override keeps the harness able
# to drive it against a local s_server).
ORIGIN_CA_PROBE_ADDR="${ORIGIN_CA_PROBE_ADDR:-127.0.0.1:443}"
ORIGIN_CA_SUPPLIED=0

# SHA-256 fingerprint (lowercase hex) of a PEM cert's DER form — different
# PEM encodings of the same certificate hash the same.
origin_ca_cert_hash() { # $1 = cert file
  openssl x509 -in "$1" -noout -fingerprint -sha256 2>/dev/null \
    | sed -e 's/^.*=//' -e 's/://g' | tr 'A-F' 'a-f'
}

origin_ca_key_pub()  { openssl pkey -in "$1" -pubout 2>/dev/null || true; }
origin_ca_csr_pub()  { openssl req -in "$1" -pubkey -noout 2>/dev/null || true; }
origin_ca_cert_pub() { openssl x509 -in "$1" -pubkey -noout 2>/dev/null || true; }

origin_ca_csr_cn() { # $1 = CSR file -> CN value (empty when absent)
  openssl req -in "$1" -noout -subject -nameopt RFC2253 2>/dev/null \
    | sed -n 's/^subject=//p' | tr ',' '\n' | sed -n 's/^CN=//p' | head -n1
}

origin_ca_csr_sans() { # $1 = CSR file -> DNS SANs, one per line
  openssl req -in "$1" -noout -text 2>/dev/null \
    | sed -n '/X509v3 Subject Alternative Name/{n;p;}' \
    | tr ',' '\n' | sed -n 's/^[[:space:]]*DNS:\([^[:space:]]*\)[[:space:]]*$/\1/p'
}

origin_ca_cert_sans() { # $1 = cert file -> DNS SANs, one per line
  openssl x509 -in "$1" -noout -text 2>/dev/null \
    | sed -n '/X509v3 Subject Alternative Name/{n;p;}' \
    | tr ',' '\n' | sed -n 's/^[[:space:]]*DNS:\([^[:space:]]*\)[[:space:]]*$/\1/p'
}

origin_ca_dns_san_count() { # $1 = newline-separated SANs -> count
  printf '%s\n' "$1" | grep -c . || true
}

origin_ca_csr_selfcheck() { # $1 = CSR, $2 = key, $3 = expected host; reason on stderr
  local csr="$1" key="$2" host="$3" sans text ext
  [ -s "$csr" ] || { printf 'CSR %s missing or empty' "$csr" >&2; return 1; }
  openssl req -in "$csr" -noout -verify >/dev/null 2>&1 \
    || { printf 'CSR %s fails self-signature verification' "$csr" >&2; return 1; }
  [ "$(origin_ca_csr_cn "$csr")" = "$host" ] \
    || { printf 'CSR CN %s differs from %s' "$(origin_ca_csr_cn "$csr")" "$host" >&2; return 1; }
  sans="$(origin_ca_csr_sans "$csr")"
  [ "$(origin_ca_dns_san_count "$sans")" = "1" ] \
    || { printf 'CSR carries %s DNS SAN(s), want exactly one (%s)' "$(origin_ca_dns_san_count "$sans")" "$host" >&2; return 1; }
  [ "$sans" = "$host" ] || { printf 'CSR SAN %s differs from %s' "$sans" "$host" >&2; return 1; }
  [ -n "$(origin_ca_key_pub "$key")" ] && [ "$(origin_ca_key_pub "$key")" = "$(origin_ca_csr_pub "$csr")" ] \
    || { printf 'CSR public key does not match %s' "$key" >&2; return 1; }
  # Extensions are load-bearing (the operator/broker signs the CSR as-is): a
  # pre-existing CSR must ask for serverAuth + the critical digitalSignature
  # keyUsage, exactly like a generated one. Only the Requested Extensions
  # region counts: the -text subject dump must never satisfy the check (a
  # crafted DN can imitate both strings), and a missing/empty region fails
  # closed (review N3).
  text="$(openssl req -in "$csr" -noout -text 2>/dev/null || true)"
  ext="$(printf '%s\n' "$text" | awk '
    /^[[:space:]]*(Requested Extensions:|X509v3 extensions:)[[:space:]]*$/ { seen = 1; next }
    seen && /^[[:space:]]*Signature Algorithm/ { done = 1; exit }
    seen { print }
    END { if (!seen || !done) exit 1 }
  ')" || ext=""
  case "$ext" in *"TLS Web Server Authentication"*) ;; *) printf 'CSR %s lacks the serverAuth EKU' "$csr" >&2; return 1 ;; esac
  case "$ext" in *"Digital Signature"*) ;; *) printf 'CSR %s lacks the digitalSignature keyUsage' "$csr" >&2; return 1 ;; esac
  return 0
}

origin_ca_generate() { # ensure key+CSR; the key is never regenerated while a cert exists
  local reason
  [ -n "${STATUS_HOST:-}" ] || die "STATUS_HOST unset — cannot derive the per-anchor Origin CA CSR SAN"
  if [ ! -s "${ORIGIN_CA_KEY}" ] && [ -s "${ORIGIN_CA_CRT}" ]; then
    die "orphaned ${ORIGIN_CA_CRT}: ${ORIGIN_CA_KEY} is missing — restore the key or remove the cert; never regenerating a key a cert was minted for"
  fi
  if [ ! -s "${ORIGIN_CA_KEY}" ]; then
    log "generating the per-anchor Origin CA key (ECDSA P-256, never leaves this box)"
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "${ORIGIN_CA_KEY}" \
      || die "openssl genpkey failed for ${ORIGIN_CA_KEY}"
  else
    openssl pkey -in "${ORIGIN_CA_KEY}" -noout >/dev/null 2>&1 \
      || die "existing ${ORIGIN_CA_KEY} is not a parseable private key — restore or remove it (it is never silently replaced)"
  fi
  chmod 0600 "${ORIGIN_CA_KEY}"
  if reason="$(origin_ca_csr_selfcheck "${ORIGIN_CA_CSR}" "${ORIGIN_CA_KEY}" "${STATUS_HOST}" 2>&1)"; then
    log "per-anchor Origin CA key + CSR present and consistent (no-op)"
    return 0
  fi
  log "building the per-anchor Origin CA CSR for ${STATUS_HOST} (${reason}; the key is kept)"
  rm -f -- "${ORIGIN_CA_CSR}"
  openssl req -new -key "${ORIGIN_CA_KEY}" \
    -subj "/CN=${STATUS_HOST}" \
    -addext "subjectAltName=DNS:${STATUS_HOST}" \
    -addext "keyUsage=critical,digitalSignature" \
    -addext "extendedKeyUsage=serverAuth" \
    -out "${ORIGIN_CA_CSR}" \
    || die "openssl req failed to build ${ORIGIN_CA_CSR}"
  chmod 0644 "${ORIGIN_CA_CSR}"
  origin_ca_csr_selfcheck "${ORIGIN_CA_CSR}" "${ORIGIN_CA_KEY}" "${STATUS_HOST}" \
    || die "generated CSR failed its self-check — refusing to continue"
  log "per-anchor Origin CA CSR ready (publish it for signing; the key stays on this box)"
}

origin_ca_cert_pem_ok() { # $1 = PEM text -> exactly one bounded certificate, no leading/trailing junk
  local pem="$1" bytes begins ends junk
  begins="$(printf '%s\n' "$pem" | grep -c -- '-----BEGIN CERTIFICATE-----' || true)"
  ends="$(printf '%s\n' "$pem" | grep -c -- '-----END CERTIFICATE-----' || true)"
  # Multi-cert blobs must be rejected: only the first block would be
  # validated/hashed while the whole blob got installed.
  [ "$begins" = "1" ] && [ "$ends" = "1" ] || return 1
  junk="$(printf '%s\n' "$pem" | awk '/-----BEGIN CERTIFICATE-----/{exit} {print}' | tr -d '[:space:]')"
  [ -z "$junk" ] || return 1
  junk="$(printf '%s\n' "$pem" | awk '/-----END CERTIFICATE-----/{f=1; next} f{print}' | tr -d '[:space:]')"
  [ -z "$junk" ] || return 1
  bytes="$(printf '%s' "$pem" | wc -c | tr -d ' ')"
  [ "${bytes:-0}" -gt 0 ] && [ "${bytes:-0}" -le 16384 ]
}

origin_ca_validate_cert() { # $1 = cert, $2 = key, $3 = expected host; reason on stderr
  local cert="$1" key="$2" host="$3" sans start start_epoch now_epoch
  [ -s "$cert" ] || { printf 'cert %s missing or empty' "$cert" >&2; return 1; }
  [ -n "$(origin_ca_cert_hash "$cert")" ] \
    || { printf '%s is not a parseable X.509 certificate' "$cert" >&2; return 1; }
  openssl x509 -in "$cert" -noout -checkend 0 >/dev/null 2>&1 \
    || { printf '%s is expired' "$cert" >&2; return 1; }
  start="$(openssl x509 -in "$cert" -noout -startdate 2>/dev/null | cut -d= -f2)"
  start_epoch="$(date -d "$start" +%s 2>/dev/null || true)"
  now_epoch="$(date +%s)"
  [ -n "$start_epoch" ] || { printf 'cannot parse notBefore %s' "${start:-unknown}" >&2; return 1; }
  [ "$start_epoch" -le "$now_epoch" ] \
    || { printf '%s is not yet valid (notBefore %s)' "$cert" "$start" >&2; return 1; }
  sans="$(origin_ca_cert_sans "$cert")"
  [ "$(origin_ca_dns_san_count "$sans")" = "1" ] \
    || { printf '%s carries %s DNS SAN(s), want exactly one (%s)' "$cert" "$(origin_ca_dns_san_count "$sans")" "$host" >&2; return 1; }
  [ "$sans" = "$host" ] || { printf 'cert SAN %s differs from %s' "$sans" "$host" >&2; return 1; }
  [ -n "$(origin_ca_key_pub "$key")" ] && [ "$(origin_ca_key_pub "$key")" = "$(origin_ca_cert_pub "$cert")" ] \
    || { printf 'certificate public key does not match %s' "$key" >&2; return 1; }
  return 0
}

origin_ca_install_from_env() { # install ORIGIN_CA_CERT_PEM (cert-only public material), fail-closed
  local pem="${ORIGIN_CA_CERT_PEM:-}" tmp reason
  [ -n "$pem" ] || return 0
  ORIGIN_CA_SUPPLIED=1
  [ -n "${STATUS_HOST:-}" ] \
    || die "ORIGIN_CA_CERT_PEM is set but STATUS_HOST is unset — cannot verify the cert SAN; refusing to install"
  [ -s "${ORIGIN_CA_KEY}" ] \
    || die "ORIGIN_CA_CERT_PEM is set but ${ORIGIN_CA_KEY} is missing — restore the key first (the cert must match it)"
  origin_ca_cert_pem_ok "$pem" \
    || die "ORIGIN_CA_CERT_PEM is not a bounded PEM certificate — refusing to install it"
  tmp="$(mktemp)"
  printf '%s\n' "$pem" >"$tmp"
  if ! reason="$(origin_ca_validate_cert "$tmp" "${ORIGIN_CA_KEY}" "${STATUS_HOST}" 2>&1)"; then
    rm -f "$tmp"
    die "ORIGIN_CA_CERT_PEM rejected: ${reason} — keeping the currently served pair untouched"
  fi
  # In-place write, NEVER install/mv: the Caddy container bind-mounts the
  # FILE, and a rename would leave Caddy reading the old inode forever.
  cat "$tmp" >"${ORIGIN_CA_CRT}" \
    || { rm -f "$tmp"; die "in-place write to ${ORIGIN_CA_CRT} failed"; }
  rm -f "$tmp"
  chmod 0644 "${ORIGIN_CA_CRT}"
  ORIGIN_CA_CERT_PEM=""
  log "per-anchor Origin CA certificate installed for ${STATUS_HOST} (sha256 $(origin_ca_cert_hash "${ORIGIN_CA_CRT}"))"
}

origin_ca_write_hash() { # $1 = cert file -> record the deployed cert hash (after a successful reload)
  local h
  h="$(origin_ca_cert_hash "$1")"
  [ -n "$h" ] || die "cannot hash ${1} — refusing to record the deployed-cert marker"
  printf '%s\n' "$h" >"${ORIGIN_CA_HASH}"
  chmod 0644 "${ORIGIN_CA_HASH}"
}

origin_ca_mark_active() { # one-way: the per-anchor pair has served on :443
  if [ -e "${ORIGIN_CA_ACTIVE}" ]; then return 0; fi
  printf '%s\n' "per-anchor origin-ca pair has served on :443" >"${ORIGIN_CA_ACTIVE}"
  chmod 0644 "${ORIGIN_CA_ACTIVE}"
  log "one-way marker set (${ORIGIN_CA_ACTIVE}): the legacy shared pair can never be selected again on this box"
}

origin_ca_select_pair() { # choose the served pair; a per-anchor pair is VALIDATED before it may be selected
  local reason
  ORIGIN_TLS=0
  ORIGIN_CA_PAIR=0
  ORIGIN_CERT_CHANGED=0
  ORIGIN_CA_HASH_WANT=""
  if [ -s "${ORIGIN_CA_CRT}" ] && [ -s "${ORIGIN_CA_KEY}" ]; then
    # Fail-closed selection (review F1): a key-matching but wrong-SAN (or
    # expired/not-yet-valid) on-box pair would otherwise be selected and
    # could satisfy the fingerprint-only probe while the edge→origin Full
    # (Strict) leg breaks. Validate against the on-box key + STATUS_HOST
    # first; never select (and never mark) an invalid pair.
    if [ -n "${STATUS_HOST:-}" ]; then
      if ! reason="$(origin_ca_validate_cert "${ORIGIN_CA_CRT}" "${ORIGIN_CA_KEY}" "${STATUS_HOST}" 2>&1)"; then
        die "on-box per-anchor Origin CA pair rejected for ${STATUS_HOST}: ${reason} — refusing to select or serve it (fix the cert, or remove origin-ca.{crt,key} to fall back/pending)"
      fi
    else
      warn "STATUS_HOST unset — per-anchor pair validation skipped (no :443 vhost is rendered; re-dispatch with TENANT_USER)"
    fi
    CADDY_ORIGIN_CRT="${ORIGIN_CA_CRT}"
    CADDY_ORIGIN_KEY="${ORIGIN_CA_KEY}"
    ORIGIN_TLS=1
    ORIGIN_CA_PAIR=1
    ORIGIN_CA_HASH_WANT="$(origin_ca_cert_hash "${ORIGIN_CA_CRT}")"
    [ -n "${ORIGIN_CA_HASH_WANT}" ] || die "cannot hash ${ORIGIN_CA_CRT} — refusing to render TLS against an unreadable per-anchor cert"
    if [ "$(cat "${ORIGIN_CA_HASH}" 2>/dev/null || true)" != "${ORIGIN_CA_HASH_WANT}" ]; then
      ORIGIN_CERT_CHANGED=1
    fi
  elif [ "${ORIGIN_CA_SUPPLIED}" = "1" ]; then
    die "ORIGIN_CA_CERT_PEM was supplied this run but the per-anchor pair is not present on the box — refusing to select any fallback"
  elif [ -s "${CADDY_ORIGIN_CRT}" ] && [ -s "${CADDY_ORIGIN_KEY}" ]; then
    if [ -e "${ORIGIN_CA_ACTIVE}" ]; then
      warn "per-anchor pair absent but ${ORIGIN_CA_ACTIVE} is set (one-way marker): the legacy shared pair is NOT resurrected — dashboard TLS pending until the per-anchor pair returns"
    else
      ORIGIN_TLS=1
      warn "per-anchor pair absent — serving the legacy shared origin pair (transition fallback; suppressed forever once the per-anchor pair serves)"
    fi
  else
    warn "no origin pair on this box — :443 uses Caddy automatic HTTPS (HTTP-01 via :80 below); re-dispatch with a signed per-anchor cert (ORIGIN_CA_CERT_PEM variable) for Origin-CA Full (Strict)"
  fi
  return 0
}

origin_ca_assert_served_pair() { # $1 = host -> 0 when the served :443 leaf IS the installed pair AND covers the host
  local host="$1" want_fp served_pem served_fp checkhost_out
  want_fp="$(origin_ca_cert_hash "${ORIGIN_CA_CRT}")"
  [ -n "${want_fp}" ] || { printf 'cannot hash %s' "${ORIGIN_CA_CRT}" >&2; return 1; }
  served_pem="$(openssl s_client -connect "${ORIGIN_CA_PROBE_ADDR}" -servername "${host}" </dev/null 2>/dev/null | openssl x509 2>/dev/null || true)"
  [ -n "${served_pem}" ] || { printf 'no certificate retrievable from %s for SNI %s' "${ORIGIN_CA_PROBE_ADDR}" "${host}" >&2; return 1; }
  served_fp="$(printf '%s\n' "${served_pem}" | openssl x509 -noout -fingerprint -sha256 2>/dev/null \
    | sed -e 's/^.*=//' -e 's/://g' | tr 'A-F' 'a-f')"
  [ -n "${served_fp}" ] || { printf 'cannot fingerprint the certificate served on %s' "${ORIGIN_CA_PROBE_ADDR}" >&2; return 1; }
  [ "${served_fp}" = "${want_fp}" ] \
    || { printf 'served certificate fingerprint %s differs from the installed pair %s' "${served_fp}" "${want_fp}" >&2; return 1; }
  # Coverage, not just identity (review F1): a selected/installed cert that
  # does not actually cover the site host must never satisfy the probe.
  # Output is parsed, not the exit code: OpenSSL < 3.2 exits 0 even on a
  # mismatch (it only prints "does NOT match"), so the exit status alone is
  # not a proof (found on CI, OpenSSL 3.0.13).
  checkhost_out="$(printf '%s\n' "${served_pem}" | openssl x509 -noout -checkhost "${host}" 2>/dev/null || true)"
  case "$checkhost_out" in
    *"does NOT match"*) printf 'served certificate does not cover %s' "${host}" >&2; return 1 ;;
    *"does match certificate"*) ;;
    *) printf 'served certificate host-coverage check was inconclusive for %s' "${host}" >&2; return 1 ;;
  esac
  return 0
}

origin_ca_probe_and_mark() { # $1 = host; asserts the served pair FIRST, then sets the one-way marker
  local host="$1" reason
  [ "${ORIGIN_CA_PAIR}" = "1" ] || return 0
  if ! reason="$(origin_ca_assert_served_pair "${host}" 2>&1)"; then
    printf '%s' "${reason}" >&2
    return 1
  fi
  origin_ca_mark_active
  return 0
}
# --- origin-ca:end ---

# ---------------------------------------------------------------------------
# a) tang + tangd.socket (idempotent)
# ---------------------------------------------------------------------------
log "Installing tang (NBDE key server)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq tang jq jose openssl >/dev/null

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
#    checks without push + warn), ANCHOR_ROLE (empty/tenant = the platform
#    row is monitor-only; operator = it alerts).
# ---------------------------------------------------------------------------
# --- gatus-render:start ---
# Operator-role gate (issue #134, call C1): unset/tenant = the platform row
# is monitor-only; operator = the platform row alerts (with a push topic).
# Fail closed on anything else — an unknown role must not silently alert.
case "${ANCHOR_ROLE:-}" in
  ''|tenant) PLATFORM_ALERTS=0 ;;
  operator)  PLATFORM_ALERTS=1 ;;
  *) die "bad ANCHOR_ROLE (want empty/tenant/operator): ${ANCHOR_ROLE}" ;;
esac
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
# Alert-intent ledger (issue #134, call C4): every alert stanza appended
# below records its endpoint name; the render-time assertion after the
# config write checks each named endpoint's block carries the stanza and
# that the total matches — a count-only check would pass a stanza moved
# to the wrong endpoint (#136 review).
ALERTS_EXPECTED=0
ALERTS_EXPECTED_NAMES=""
alert_intent() { # $1 = endpoint name (one call per appended alert stanza)
  ALERTS_EXPECTED=$((ALERTS_EXPECTED + 1))
  ALERTS_EXPECTED_NAMES="${ALERTS_EXPECTED_NAMES}${1}"$'\n'
}
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
      - type: custom
        failure-threshold: 3
        send-on-resolved: true
        provider-override:
          placeholders:
            ALERT_TRIGGERED_OR_RESOLVED:
              TRIGGERED: \"5\"
              RESOLVED: \"3\"
"
    alert_intent main
  fi
fi
# Built-in endpoint names actually rendered this run (issue #134, call C6):
# a GATUS_ENDPOINTS pair may not shadow one — the render has no dedupe, so a
# collision would silently render two rows under one name. `platform` is
# unconditional; `main` exists only when TENANT_USER is set (console
# fallback runs don't render it, so a `main=` pair is accepted there — the
# next dispatch fails loud, which is when the duplicate would appear).
BUILTIN_NAMES="platform"
[ -n "${TENANT_USER:-}" ] && BUILTIN_NAMES="main ${BUILTIN_NAMES}"
# Platform row (issue #134, calls C2/C3): the shared host's health as a
# platform-level fact, built into the render (not a per-anchor secret). The
# durable name is created S1-era on the control plane; tenant pages show it
# monitor-only (host-down already reds `main`), the operator anchor alerts.
ENDPOINTS_YAML="${ENDPOINTS_YAML}  - name: platform
    url: https://platform.piercloud.net/healthz
    interval: 60s
    conditions:
      - \"[STATUS] == 200\"
"
if [ "$PLATFORM_ALERTS" -eq 1 ] && [ -n "${NTFY_TOPIC:-}" ]; then
  ENDPOINTS_YAML="${ENDPOINTS_YAML}    alerts:
      - type: custom
        failure-threshold: 3
        send-on-resolved: true
        provider-override:
          placeholders:
            ALERT_TRIGGERED_OR_RESOLVED:
              TRIGGERED: \"5\"
              RESOLVED: \"3\"
"
  alert_intent platform
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
    case " ${BUILTIN_NAMES} " in *" ${name} "*) die "GATUS_ENDPOINTS pair name '${name}' collides with a built-in endpoint (${BUILTIN_NAMES// /, }) — pick another name";; esac
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
        provider-override:
          priority: 4  # alert class 4 (time-sensitive; never a night emergency)
"
      alert_intent "$name"
    fi
  done
  IFS="$OLD_IFS"
  set +f
fi
if [ -n "${NTFY_TOPIC:-}" ]; then
  # Fail fast on YAML injection: topic/token interpolate into config-as-data.
  case "$NTFY_TOPIC" in ''|*[!a-zA-Z0-9_-]*) die "bad NTFY_TOPIC (chars [a-zA-Z0-9_-] only): ${NTFY_TOPIC}";; esac
  case "${NTFY_TOKEN:-}" in *[[:space:]]*|*[![:print:]]*) die "bad NTFY_TOKEN (no whitespace/control characters)";; esac
  ALERTING_YAML="  ntfy:
    url: https://ntfy.sh
    topic: ${NTFY_TOPIC}"
  if [ -n "${NTFY_TOKEN:-}" ]; then
    ALERTING_YAML="${ALERTING_YAML}
    token: ${NTFY_TOKEN}"
  fi
  # ntfy-JSON bridge (issue #134, call C9): the native ntfy provider repeats
  # its single priority on resolve, so class-5 rows (main/platform) publish
  # through ntfy's JSON API instead — [ALERT_TRIGGERED_OR_RESOLVED] maps to
  # 5 (triggered) / 3 (resolved), and per-alert provider-override.placeholders
  # carries the class.
  ALERTING_YAML="${ALERTING_YAML}
  custom:
    url: \"https://ntfy.sh/\"
    method: POST
    headers:
      Content-Type: \"application/json\""
  if [ -n "${NTFY_TOKEN:-}" ]; then
    ALERTING_YAML="${ALERTING_YAML}
      Authorization: \"Bearer ${NTFY_TOKEN}\""
  fi
  ALERTING_YAML="${ALERTING_YAML}
    body: '{\"topic\":\"${NTFY_TOPIC}\",\"title\":\"Gatus: [ENDPOINT_NAME]\",\"message\":\"[ENDPOINT_NAME]: [RESULT_CONDITIONS][RESULT_ERRORS]\",\"priority\":[ALERT_TRIGGERED_OR_RESOLVED]}'
    placeholders:
      ALERT_TRIGGERED_OR_RESOLVED:
        TRIGGERED: \"5\"
        RESOLVED: \"3\""
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
    printf '%s\n' "      - \"[CERTIFICATE_EXPIRATION] > 720h\"  # fail inside the ~30d stale-cert window (ntfy ALERT when a topic is set)"
    if [ -n "${NTFY_TOPIC:-}" ]; then
      printf '%s\n' "    alerts:"
      printf '%s\n' "      - type: ntfy"
      printf '%s\n' "        failure-threshold: 3"
      printf '%s\n' "        provider-override:"
      printf '%s\n' "          priority: 4  # alert class 4 (time-sensitive; never a night emergency)"
      alert_intent "dashboard TLS (via edge)"
    fi
  fi
} >"$TMP_CFG"
# Render-time assertion (issue #134, call C4): the rendered alert stanzas
# must equal the intent ledger recorded while rendering — the #118 class of
# gap (condition rendered, stanza forgotten) is otherwise invisible. Total
# equality plus a per-name presence check is exact: every intended name
# present with equal totals leaves no room for an extra stanza, and a
# stanza moved to the wrong endpoint keeps the total and still fails
# (#136 review, finding 2).
ALERTS_RENDERED="$(grep -c '^    alerts:$' "$TMP_CFG" || true)"
[ "$ALERTS_RENDERED" -eq "$ALERTS_EXPECTED" ] \
  || die "Gatus render assertion failed: ${ALERTS_RENDERED} alerts stanza(s) rendered, expected ${ALERTS_EXPECTED} — refusing to install"
while IFS= read -r _alert_ep; do
  [ -n "$_alert_ep" ] || continue
  awk -v want="  - name: ${_alert_ep}" '
    $0 == want { inb = 1; next }
    inb && /^  - name: / { inb = 0 }
    inb && $0 == "    alerts:" { found = 1 }
    END { exit found ? 0 : 1 }
  ' "$TMP_CFG" \
    || die "Gatus render assertion failed: '${_alert_ep}' is missing its alerts stanza — refusing to install"
done <<EOF
${ALERTS_EXPECTED_NAMES}
EOF
# Silent-downgrade check (issue #134, call C7): the run log names the
# endpoints that will alert — `platform` missing means the role/topic is
# not active (names only; never the topic).
if [ "$ALERTS_EXPECTED" -gt 0 ]; then
  log "Gatus alert stanzas: ${ALERTS_EXPECTED} — $(printf '%s' "${ALERTS_EXPECTED_NAMES}" | tr '\n' ',' | sed 's/,$//')"
elif [ -n "${NTFY_TOPIC:-}" ]; then
  log "Gatus alert stanzas: 0 (push channel configured; no alerting rows in this shape)"
else
  log "Gatus alert stanzas: 0 (no push channel configured)"
fi
if [ -f "${GATUS_CONFIG}" ] && cmp -s "${GATUS_CONFIG}" "$TMP_CFG"; then
  log "Gatus config unchanged — no restart"
  rm -f "$TMP_CFG"
  GATUS_RESTART=0
else
  mv "$TMP_CFG" "${GATUS_CONFIG}"
  log "Gatus config installed (rendered from dispatch env)"
  GATUS_RESTART=1
fi
# --- gatus-render:end ---

# ---------------------------------------------------------------------------
# c1) Per-anchor Origin CA key + CSR + cert install (issue #123, M2)
#    Key/CSR are generated ON this box (openssl, installed above) with the
#    STATUS_HOST the Gatus section just resolved; the CSR is public material
#    published for operator-side signing; a signed cert returns via the
#    cert-only ORIGIN_CA_CERT_PEM variable and is validated fail-closed
#    against the on-box key before it is installed in place. The legacy
#    shared pair (if present) keeps serving until the per-anchor pair does
#    (see the pair-selection block in the Caddy section).
# ---------------------------------------------------------------------------
if [ -n "${STATUS_HOST:-}" ]; then
  origin_ca_generate
  origin_ca_install_from_env
else
  [ -z "${ORIGIN_CA_CERT_PEM:-}" ] \
    || die "ORIGIN_CA_CERT_PEM is set but TENANT_USER/STATUS_HOST is unset — refusing to install an unverifiable cert (re-dispatch with TENANT_USER)"
  warn "per-anchor Origin CA key/CSR skipped (TENANT_USER unset — console fallback run; re-dispatch converges it)"
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
#    Env in (operator-plane — the tenant pastes nothing, so tenant bootstrap
#    stays 1 secret): ORIGIN_CA_CERT_PEM (the per-anchor Origin CA cert,
#    cert-only PUBLIC material installed from the repo VARIABLE; key material
#    never travels — the key is generated on this box in section (c1)),
#    CF_AOP_CA_PEM (optional zone-level Authenticated Origin Pulls bundle for
#    our own cert; absent = edge auth stays firewall-allowlist + Host binding
#    until the operator finishes the AOP ceremony in docs/dr.md +
#    re-dispatches).
# ---------------------------------------------------------------------------
log "Rendering dispatch-managed Caddyfile (${CADDY_CONFIG})"
mkdir -p "$(dirname "${CADDY_CONFIG}")" "${CADDY_CHALLENGE_DIR}"
# One-time backup of any pre-managed hand config (never overwritten twice).
if [ -f "${CADDY_CONFIG}" ] && [ ! -f "${CADDY_CONFIG}.pre-managed.bak" ] && ! grep -q "DISPATCH-MANAGED" "${CADDY_CONFIG}" 2>/dev/null; then
  cp -p "${CADDY_CONFIG}" "${CADDY_CONFIG}.pre-managed.bak"
  log "Backed up pre-managed Caddyfile to ${CADDY_CONFIG}.pre-managed.bak (one-time)"
fi
# Origin pair selection (issue #123): per-anchor first, VALIDATED against the
# on-box key + STATUS_HOST before selection (review F1); the legacy shared
# pair is a ONE-WAY transition fallback — once the per-anchor pair has served
# (the :443 probe below), .origin-ca-active exists and the legacy pair is
# never selected again. The selection function lives in the origin-ca span
# above (tests/origin-ca drives the real one).
origin_ca_select_pair
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
CF_AOP_CA_PEM=""  # discard from memory (the file above is 644 on this box only)
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
    CADDY_VAL_ARGS="${CADDY_VAL_ARGS} -v ${CADDY_ORIGIN_CRT}:${CADDY_ORIGIN_CRT}:ro -v ${CADDY_ORIGIN_KEY}:${CADDY_ORIGIN_KEY}:ro"
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
if [ "${ORIGIN_TLS}" = "1" ]; then
  if [ "${ORIGIN_CA_PAIR}" = "1" ]; then
    CADDY_WANT_MOUNTS="${CADDY_WANT_MOUNTS} origin-ca"
  else
    CADDY_WANT_MOUNTS="${CADDY_WANT_MOUNTS} origin"
  fi
fi
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
  CADDY_MOUNT_ARGS="${CADDY_MOUNT_ARGS} -v ${CADDY_ORIGIN_CRT}:${CADDY_ORIGIN_CRT}:ro -v ${CADDY_ORIGIN_KEY}:${CADDY_ORIGIN_KEY}:ro"
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
if [ "${CADDY_RESTART:-0}" = "1" ] || [ "${ORIGIN_CERT_CHANGED:-0}" = "1" ]; then
  # Mounts already converged above (recreate path); reload = zero-downtime.
  # ORIGIN_CERT_CHANGED covers the in-place cert swap: the bind-mounted FILE
  # kept its inode (in-place write), so only a reload makes Caddy re-read it.
  docker exec caddy caddy reload --config /etc/caddy/Caddyfile
  log "Caddy reloaded on new config"
  if [ "${ORIGIN_CERT_CHANGED:-0}" = "1" ]; then
    # Recorded ONLY after the successful reload (a failed run must re-reload
    # on the next dispatch, never claim the cert is live).
    origin_ca_write_hash "${ORIGIN_CA_CRT}"
    log "deployed origin-ca cert hash recorded after the successful reload"
  fi
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
  # healthy box once an origin pair is deployed (live 2026-09-10,
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
    neg_err=""
    neg_err="$(curl -sk --max-time 10 --resolve "${STATUS_HOST}:443:127.0.0.1" "https://${STATUS_HOST}/" -o /dev/null 2>&1)" || neg_rc=$?
    case "${neg_rc}" in
      0)
        die "Caddy :443 answered a cert-less probe while AOP is deployed — client_auth is not enforcing; roll back with: gh secret delete CF_AOP_CA_PEM --repo ${GITHUB_REPOSITORY:-piercloud-net/terraform-piercloud-anchor} && gh workflow run provision.yml -f mode=apply" ;;
      35|55|56)
        # 35 = TLS connect error (handshake stage); 55/56 = send/recv failure —
        # these are how curl surfaces a client-auth rejection (measured on curl
        # 7.88/8.5/8.11/8.14/8.19/8.20 across TLS 1.2/1.3; 55 is real on the
        # newer OpenSSL 3.5 builds). The OpenSSL 'alert' line is extra evidence
        # when present, but a rejection must not fail on its absence.
        neg_hint="$(printf '%s' "${neg_err}" | tr '\n' ' ' | cut -c1-160)"
        if printf '%s' "${neg_err}" | grep -qi 'alert'; then
          log "Caddy :443 rejected the cert-less probe at the TLS layer (curl exit ${neg_rc}, alert confirmed; OK under require_and_verify)"
        else
          log "Caddy :443 rejected the cert-less probe at the TLS layer (curl exit ${neg_rc}; OK under require_and_verify)"
          warn "no OpenSSL 'alert' text in curl stderr (${neg_hint:-no stderr}) — confirm the rejection manually if this box was expected to serve cert-less"
        fi ;;
      7|28)
        die "Caddy :443 did not answer the cert-less probe (curl exit ${neg_rc}: refused/timeout) — cannot prove client_auth is enforcing; check 'docker logs caddy' and that :443 is listening BEFORE touching AOP secrets; refusing to finish blind" ;;
      *)
        die "Caddy :443 cert-less probe failed with curl exit ${neg_rc} (not a TLS-layer rejection) — cannot prove client_auth is enforcing; stderr: $(printf '%s' "${neg_err}" | tr '\n' ' ' | cut -c1-160); refusing to finish blind" ;;
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
      die "edge pull through Cloudflare failed while AOP is deployed (curl exit ${edge_rc}) — the origin trust bundle does not match Cloudflare's client cert; roll back with: gh secret delete CF_AOP_CA_PEM --repo ${GITHUB_REPOSITORY:-piercloud-net/terraform-piercloud-anchor} && gh workflow run provision.yml -f mode=apply (or rotate the leaf with 102 --force-aop, then re-dispatch). If this is a first-time/DR dispatch, the proxied record may still point at the old box (edge 521/522) — the DNS stage converges only AFTER this job, see docs/dr.md"
    fi
    if [ "${ORIGIN_CA_PAIR}" = "1" ]; then
      # Under require_and_verify a cert-less s_client cannot retrieve the
      # served cert (the AOP client leaf key is operator-side): the
      # structural proof is Caddyfile references + hash marker after reload +
      # this edge pull 200 under Full (Strict) — enough to declare the pair
      # has SERVED, which is the one-way marker's precondition.
      origin_ca_mark_active
    fi
    log "edge pull through Cloudflare serves with AOP enforced (OK)"
  elif curl -skf --max-time 10 --resolve "${STATUS_HOST}:443:127.0.0.1" "https://${STATUS_HOST}/" -o /dev/null; then
    if [ "${ORIGIN_CA_PAIR}" = "1" ]; then
      # Prove the SERVED leaf is the installed per-anchor cert (guards a stale
      # Caddy still serving the legacy pair) AND that it covers the site host
      # (guards a key-matching wrong-SAN pair). Only then may the one-way
      # marker suppress the legacy fallback forever — the probe function
      # writes the marker only after every check passes (review F1).
      if ! origin_ca_probe_and_mark "${STATUS_HOST}"; then
        die "Caddy :443 does not serve the installed per-anchor pair for ${STATUS_HOST} (reason above) — refusing to mark the per-anchor pair active"
      fi
    fi
    log "Caddy :443 handshakes for ${STATUS_HOST} (OK; edge trust is zone-side, see docs/dr.md)"
  elif [ "${ORIGIN_TLS}" != "1" ]; then
    # No origin pair selected (absent, or the one-way marker suppressed the
    # legacy fallback): auto-TLS cannot reliably issue for a name whose public
    # record is only upserted by the DNS stage after this job. Origin TLS is
    # proven there (verify-after-write + orange-cloud) and by the edge, so
    # this is loud, not fatal; with a pair selected it stays fail-closed.
    log "WARNING: Caddy :443 has no certificate for ${STATUS_HOST} yet — no origin pair selected this run; the proxied edge record is upserted after close (docs/dr.md)"
  else
    docker logs caddy 2>&1 | tail -20 || true
    die "Caddy :443 does not handshake for ${STATUS_HOST} — refusing to finish blind"
  fi
fi

log "Done. tang is up (loopback, via Caddy :80), the thumbprint is above, Gatus is dispatch-managed (statuses printed above), dashboard at https://${STATUS_HOST:-status-<alias>.piercloud.net} (TLS on the box), bind URL http://${ANCHOR_HOSTNAME:-anchor-01-<alias>}.piercloud.net (record verified by the DNS stage)."
