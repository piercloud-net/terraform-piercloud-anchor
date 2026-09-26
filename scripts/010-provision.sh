#!/usr/bin/env bash
#
# 010-provision.sh — provision the tang/clevis NBDE anchor + uptime monitor.
#
# WHERE THIS RUNS: ON the anchor box itself, as root, normally via the A1
# dispatch (the runner SSHes in under a per-run device-flow approval and pipes
# this script over stdin with GATUS_*/NTFY_*/RECORDING_WITNESS_* env prefixed).
# Fallback: paste it
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
    anchor* | status* | pcu*)
      printf 'invalid TENANT_USER "%s": reserved prefix — names starting with anchor/status/pcu are platform labels, not tenants.\n' "$1" >&2
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
  case "${NTFY_TOKEN:-}" in *[[:space:]]*|*[![:print:]]*) die "bad NTFY_TOKEN (no whitespace/control characters)";; esac
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
    printf '%s\n' "      - \"[CERTIFICATE_EXPIRATION] > 720h\"  # fail inside the ~30d stale-cert window (ntfy ALERT when a topic is set)"
    if [ -n "${NTFY_TOPIC:-}" ]; then
      printf '%s\n' "    alerts:"
      printf '%s\n' "      - type: ntfy"
      printf '%s\n' "        failure-threshold: 3"
      printf '%s\n' "        provider-override:"
      printf '%s\n' "          priority: 4  # alert class 4 (time-sensitive; never a night emergency)"
    fi
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

# --- BEGIN RECORDING WITNESS (tests/recording-witness extracts this span; keep markers) ---
# Recording-completeness witness — optional component, dormant without env.
# Renders /usr/local/sbin/pc-recording-witness.sh + its 0600 env file + a
# 5-minute systemd timer. The witness is STRICTLY list-only (ListObjectsV2 +
# ListMultipartUploads with a listFiles-only B2 application key: no readFiles,
# no HEAD, no ListParts) and fail-closed (an un-runnable witness reports
# `error`; the last baseline is held). Design, key contract and checks:
# docs/recording-witness.md.
#
# Paths are overridable so the committed test harness can render and install
# into throwaway paths; the dispatch env never exports these names, so on-box
# runs always get the canonical defaults.
RECORDING_WITNESS_SBIN="${RECORDING_WITNESS_SBIN:-/usr/local/sbin/pc-recording-witness.sh}"
RECORDING_WITNESS_ENV_FILE="${RECORDING_WITNESS_ENV_FILE:-/etc/piercloud/recording-witness.env}"
RECORDING_WITNESS_STATE_DIR="${RECORDING_WITNESS_STATE_DIR:-/var/lib/piercloud/recording-witness}"
RECORDING_WITNESS_SERVICE="${RECORDING_WITNESS_SERVICE:-/etc/systemd/system/pc-recording-witness.service}"
RECORDING_WITNESS_TIMER="${RECORDING_WITNESS_TIMER:-/etc/systemd/system/pc-recording-witness.timer}"

recording_witness_config_problem() { # print the first config problem; empty = ok
  if [ -z "${RECORDING_WITNESS_ENDPOINT:-}" ]; then printf '%s' 'RECORDING_WITNESS_ENDPOINT is empty'; return 0; fi
  case "${RECORDING_WITNESS_ENDPOINT}" in
    http://*|https://*) ;;
    *) printf '%s' 'RECORDING_WITNESS_ENDPOINT must start with http:// or https://'; return 0 ;;
  esac
  case "${RECORDING_WITNESS_ENDPOINT}" in *[[:space:]]*) printf '%s' 'RECORDING_WITNESS_ENDPOINT has whitespace'; return 0;; esac
  if [ -z "${RECORDING_WITNESS_BUCKET:-}" ]; then printf '%s' 'RECORDING_WITNESS_BUCKET is empty'; return 0; fi
  case "${RECORDING_WITNESS_BUCKET}" in *[!a-z0-9.-]*) printf '%s' 'RECORDING_WITNESS_BUCKET must match [a-z0-9.-]'; return 0;; esac
  if [ -z "${RECORDING_WITNESS_AUDIT_PREFIX:-}" ]; then printf '%s' 'RECORDING_WITNESS_AUDIT_PREFIX is empty'; return 0; fi
  case "${RECORDING_WITNESS_AUDIT_PREFIX}" in */) ;; *) printf '%s' 'RECORDING_WITNESS_AUDIT_PREFIX must end with /'; return 0;; esac
  case "${RECORDING_WITNESS_AUDIT_PREFIX}" in *[!A-Za-z0-9._/-]*) printf '%s' 'RECORDING_WITNESS_AUDIT_PREFIX has unsupported characters'; return 0;; esac
  if [ -z "${RECORDING_WITNESS_RECORDINGS_PREFIX:-}" ]; then printf '%s' 'RECORDING_WITNESS_RECORDINGS_PREFIX is empty'; return 0; fi
  case "${RECORDING_WITNESS_RECORDINGS_PREFIX}" in */) ;; *) printf '%s' 'RECORDING_WITNESS_RECORDINGS_PREFIX must end with /'; return 0;; esac
  case "${RECORDING_WITNESS_RECORDINGS_PREFIX}" in *[!A-Za-z0-9._/-]*) printf '%s' 'RECORDING_WITNESS_RECORDINGS_PREFIX has unsupported characters'; return 0;; esac
  if [ "${RECORDING_WITNESS_AUDIT_PREFIX}" = "${RECORDING_WITNESS_RECORDINGS_PREFIX}" ]; then printf '%s' 'audit and recordings prefixes must differ'; return 0; fi
  if [ -z "${RECORDING_WITNESS_KEY_ID:-}" ]; then printf '%s' 'RECORDING_WITNESS_KEY_ID is empty'; return 0; fi
  case "${RECORDING_WITNESS_KEY_ID}" in *[!A-Za-z0-9_-]*) printf '%s' 'RECORDING_WITNESS_KEY_ID has unsupported characters'; return 0;; esac
  if [ -z "${RECORDING_WITNESS_KEY:-}" ]; then printf '%s' 'RECORDING_WITNESS_KEY is empty'; return 0; fi
  case "${RECORDING_WITNESS_KEY}" in *[[:space:]]*|*[![:print:]]*) printf '%s' 'RECORDING_WITNESS_KEY has whitespace or control characters'; return 0;; esac
  return 0
}

recording_witness_state() { # off | partial | on
  local present=0 total=0 name
  for name in RECORDING_WITNESS_ENDPOINT RECORDING_WITNESS_BUCKET RECORDING_WITNESS_AUDIT_PREFIX RECORDING_WITNESS_RECORDINGS_PREFIX RECORDING_WITNESS_KEY_ID RECORDING_WITNESS_KEY; do
    total=$((total + 1))
    if [ -n "${!name:-}" ]; then present=$((present + 1)); fi
  done
  if [ "$present" -eq 0 ]; then printf 'off'; return 0; fi
  if [ "$present" -ne "$total" ]; then printf 'partial'; return 0; fi
  if [ -n "$(recording_witness_config_problem)" ]; then printf 'partial'; return 0; fi
  printf 'on'
}

render_recording_witness() { # print the on-box witness script to stdout
  cat <<'RECORDING_WITNESS_FILE_EOF'
#!/usr/bin/env bash
# pc-recording-witness.sh — list-only recording-completeness witness.
# RENDERED by terraform-piercloud-anchor scripts/010-provision.sh; DO NOT EDIT.
# Contract + checks: docs/recording-witness.md (repo).
#
# Strictly list-only: reads /etc/piercloud/recording-witness.env (0600) and
# makes only ListObjectsV2 / ListMultipartUploads calls. Never fetches object
# content (no GET/HEAD) and never calls ListParts (writeFiles).
set -euo pipefail

ENV_FILE="${RECORDING_WITNESS_ENV_FILE:-/etc/piercloud/recording-witness.env}"
if [ ! -r "$ENV_FILE" ]; then
  printf '[witness] FAIL: witness env file not readable: %s\n' "$ENV_FILE" >&2
  exit 2
fi
set -a
# shellcheck disable=SC1090,SC1091  # operator-controlled dispatched env file
. "$ENV_FILE"
set +a

if ! command -v python3 >/dev/null 2>&1; then
  printf '[witness] FAIL: python3 is not installed\n' >&2
  exit 2
fi

exec python3 - <<'RECORDING_WITNESS_PY_EOF'
"""List-only recording-completeness witness (B2 S3 metadata).

Strictly list-only: ListObjectsV2 + ListMultipartUploads with a listFiles-only
application key. Never reads an object (no GET/HEAD) and never calls the
writeFiles-gated ListParts. Fail-closed: any failure to run reports state
`error`, exits 2, and never advances the last good baseline (an unreadable or
oversized state file is preserved as `state.json.corrupt` - or a timestamped
`.corrupt.<stamp>` sibling when that name is taken - and the repaired record
reports `baseline: null` - it could not be read and is never fabricated);
alerts exit 1; green exits 0.
"""
import collections
import hashlib
import hmac
import http.client
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

STATE_VERSION = 2
# A state record is a few KB; an oversized file is invalid input, never a reason
# to allocate it. The bounded read keeps a planted huge state.json from raising
# an uncaught MemoryError before any verdict (round-7 R2).
STATE_MAX_BYTES = 1 << 20
VERDICT_LOG_MAX_BYTES = 1 << 20  # verdict.log rotates once at 1 MiB (previous kept as .1)
UUID_PATTERN = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
# The shipper's list-parseable UTC timestamp (pc-admin audit_ts: %Y%m%dT%H%M%SZ).
# Classification is shape-strict so a malformed session key cannot be re-parsed
# as a non-session event (or vice versa).
TS_PATTERN = r"[0-9]{8}T[0-9]{6}Z"
# Session-scoped keys: <ts>-session.<type>.<sid>.<seq>[.<mode>].json. The
# optional mode marker (.shell/.exec) is contract-defined for session.start
# and session.end only (pc-admin D1); other session events keep the old shape.
SESSION_KEY_RE = re.compile(
    r"^(?P<ts>" + TS_PATTERN + r")-(?P<etype>session\.[A-Za-z0-9_]+)\."
    r"(?P<sid>" + UUID_PATTERN + r")\.(?P<seq>[0-9]{1,18})"
    r"(?:\.(?P<mode>shell|exec))?\.json$"
)
# Documented non-session audit event: <ts>-<event-type>.<seq>.json (no sid).
NON_SESSION_KEY_RE = re.compile(
    r"^(?P<ts>" + TS_PATTERN + r")-(?P<etype>[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*)\.(?P<seq>[0-9]{1,18})\.json$"
)
HEARTBEAT_KEY_RE = re.compile(r"^(?P<ts>" + TS_PATTERN + r")\.json$")
UUID_RE = re.compile(UUID_PATTERN)
RECORDING_KEY_RE = re.compile(r"^(?P<sid>" + UUID_PATTERN + r")\.tar$")
# Sid-less session.* event types documented by the shipper contract (Teleport
# v18 emits session.rejected without a session id): they ship on the
# non-session shape and are not naming drift.
SID_LESS_SESSION_EVENTS = frozenset({"session.rejected"})
# Replay-conflict variants (pc-admin `disambiguate_audit_key`): when a rebuilt
# audit file replays an event under a key that already exists with DIFFERENT
# bytes, the shipper appends `_<sha256[:16]>` to the event type (a session
# lifecycle variant drops its mode marker) instead of silently skipping the
# line. The witness is list-only and cannot see bytes, so a variant is the
# SAME event identity as its base key, re-shipped under a disambiguated name:
# canonicalize the type and count the (ts, type, seq) identity once per session.
CONFLICT_SUFFIX_RE = re.compile(r"_[0-9a-f]{16}$")


def canonical_conflict_type(event_type):
    """Strip a replay-conflict `_<hash16>` suffix; return (base, is_variant)."""
    match = CONFLICT_SUFFIX_RE.search(event_type)
    if not match:
        return event_type, False
    return event_type[: match.start()], True


class WitnessError(Exception):
    """Any condition that makes the witness un-runnable (fail-closed)."""


def env(name, default=""):
    value = os.environ.get(name, "")
    return value if value else default


def env_int(name, default):
    raw = env(name, str(default))
    try:
        return int(raw)
    except ValueError:
        raise WitnessError("%s must be an integer, got %r" % (name, raw))


def log(message):
    print("[witness] " + message, flush=True)


def clip(text, limit=300):
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[:limit] + "..."


def utc_stamp(instant):
    return instant.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def age_seconds(now, moment, label, skew_tolerance):
    """Signed age in seconds; a future timestamp beyond tolerance is an error."""
    age = int((now - moment).total_seconds())
    if age < -skew_tolerance:
        raise WitnessError(
            "%s timestamp %s is %ds in the future (clock skew beyond %ds)"
            % (label, utc_stamp(moment), -age, skew_tolerance)
        )
    return age


def parse_timestamp(text):
    value = (text or "").strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    instant = datetime.fromisoformat(value)
    if instant.tzinfo is None:
        instant = instant.replace(tzinfo=timezone.utc)
    return instant.astimezone(timezone.utc)


def quote(value, keep_slash=False):
    safe = "-_.~"
    if keep_slash:
        safe += "/"
    return urllib.parse.quote(value, safe=safe)


def local_name(tag):
    return tag.rsplit("}", 1)[-1]


def sign(key, message):
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()


class Config(object):
    def __init__(self):
        self.endpoint = env("RECORDING_WITNESS_ENDPOINT").rstrip("/")
        self.bucket = env("RECORDING_WITNESS_BUCKET")
        self.audit_prefix = env("RECORDING_WITNESS_AUDIT_PREFIX")
        self.recordings_prefix = env("RECORDING_WITNESS_RECORDINGS_PREFIX")
        self.key_id = env("RECORDING_WITNESS_KEY_ID")
        self.key = env("RECORDING_WITNESS_KEY")
        self.region = env("RECORDING_WITNESS_REGION")
        self.state_dir = env("RECORDING_WITNESS_STATE_DIR", "/var/lib/piercloud/recording-witness")
        self.heartbeat_max_age = env_int("RECORDING_WITNESS_HEARTBEAT_MAX_AGE_SECONDS", 900)
        self.session_grace = env_int("RECORDING_WITNESS_SESSION_GRACE_SECONDS", 600)
        self.completer_lag = env_int("RECORDING_WITNESS_COMPLETER_LAG_SECONDS", 900)
        self.open_upload_max_age = env_int("RECORDING_WITNESS_OPEN_UPLOAD_MAX_AGE_SECONDS", 43200)
        self.clock_skew_tolerance = env_int("RECORDING_WITNESS_CLOCK_SKEW_TOLERANCE_SECONDS", 300)
        self.renotify = env_int("RECORDING_WITNESS_RENOTIFY_SECONDS", 1800)
        self.ntfy_topic = env("NTFY_TOPIC")
        self.ntfy_token = env("NTFY_TOKEN")
        self.heartbeat_prefix = self.audit_prefix + "heartbeat/"
        self.validate()

    def validate(self):
        required = [
            ("RECORDING_WITNESS_ENDPOINT", self.endpoint),
            ("RECORDING_WITNESS_BUCKET", self.bucket),
            ("RECORDING_WITNESS_AUDIT_PREFIX", self.audit_prefix),
            ("RECORDING_WITNESS_RECORDINGS_PREFIX", self.recordings_prefix),
            ("RECORDING_WITNESS_KEY_ID", self.key_id),
            ("RECORDING_WITNESS_KEY", self.key),
        ]
        for name, value in required:
            if not value:
                raise WitnessError("%s is empty - witness env incomplete" % name)
        if not self.endpoint.startswith(("http://", "https://")):
            raise WitnessError("RECORDING_WITNESS_ENDPOINT must be an http(s) URL")
        if urllib.parse.urlsplit(self.endpoint).path not in ("", "/"):
            raise WitnessError("RECORDING_WITNESS_ENDPOINT must not carry a path")
        for name, value in (("AUDIT_PREFIX", self.audit_prefix), ("RECORDINGS_PREFIX", self.recordings_prefix)):
            if not value.endswith("/"):
                raise WitnessError("RECORDING_WITNESS_%s must end with /" % name)

    def signing_region(self):
        if self.region:
            return self.region
        match = re.match(r"^https?://s3\.([a-z0-9-]+)\.backblazeb2\.com$", self.endpoint)
        return match.group(1) if match else "us-east-1"


def signed_get(config, params):
    """SigV4-signed path-style GET against the S3 endpoint (list calls only)."""
    now = datetime.now(timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")
    host = urllib.parse.urlsplit(config.endpoint).netloc
    canonical_uri = "/" + quote(config.bucket, keep_slash=True)
    pairs = sorted((quote(str(name)), quote(str(value))) for name, value in params.items())
    canonical_query = "&".join("%s=%s" % (name, value) for name, value in pairs)
    payload_hash = hashlib.sha256(b"").hexdigest()
    headers = {
        "host": host,
        "x-amz-content-sha256": payload_hash,
        "x-amz-date": amz_date,
    }
    signed_headers = ";".join(sorted(headers))
    canonical_headers = "".join("%s:%s\n" % (name, headers[name]) for name in sorted(headers))
    canonical_request = "\n".join(
        ["GET", canonical_uri, canonical_query, canonical_headers, signed_headers, payload_hash]
    )
    scope = "%s/%s/s3/aws4_request" % (datestamp, config.signing_region())
    string_to_sign = "\n".join(
        ["AWS4-HMAC-SHA256", amz_date, scope,
         hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()]
    )
    signing_key = sign(("AWS4" + config.key).encode("utf-8"), datestamp)
    signing_key = sign(signing_key, config.signing_region())
    signing_key = sign(signing_key, "s3")
    signing_key = sign(signing_key, "aws4_request")
    signature = hmac.new(signing_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    authorization = "AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s" % (
        config.key_id, scope, signed_headers, signature)
    url = config.endpoint + canonical_uri + (("?" + canonical_query) if canonical_query else "")
    request = urllib.request.Request(url, method="GET")
    request.add_header("Authorization", authorization)
    request.add_header("x-amz-content-sha256", payload_hash)
    request.add_header("x-amz-date", amz_date)
    try:
        with open_signed(request, timeout=30) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def list_objects(config, prefix):
    """ListObjectsV2 -> {key: last_modified}. List-only; never fetches content."""
    objects = {}
    token = ""
    for _ in range(1000):
        params = {"list-type": "2", "prefix": prefix}
        if token:
            params["continuation-token"] = token
        status, body = signed_get(config, params)
        if status != 200:
            raise WitnessError("ListObjectsV2 %s failed: HTTP %s %s" % (prefix, status, clip(body, 200)))
        try:
            root = ET.fromstring(body)
        except ET.ParseError as exc:
            raise WitnessError("ListObjectsV2 %s returned unparseable XML: %s" % (prefix, exc))
        truncated = False
        next_token = ""
        for child in root:
            name = local_name(child.tag)
            if name == "Contents":
                key = ""
                last_modified = ""
                for field in child:
                    field_name = local_name(field.tag)
                    if field_name == "Key":
                        key = field.text or ""
                    elif field_name == "LastModified":
                        last_modified = field.text or ""
                if key:
                    try:
                        objects[key] = parse_timestamp(last_modified)
                    except ValueError:
                        raise WitnessError("object %s has unparseable LastModified %r" % (key, last_modified))
            elif name == "IsTruncated":
                truncated = (child.text or "").strip().lower() == "true"
            elif name == "NextContinuationToken":
                next_token = child.text or ""
        if not truncated:
            return objects
        if not next_token:
            raise WitnessError("ListObjectsV2 %s truncated without a continuation token" % prefix)
        token = next_token
    raise WitnessError("ListObjectsV2 %s exceeded 1000 pages" % prefix)


def list_uploads(config, prefix):
    """ListMultipartUploads -> [{key, upload_id, initiated}]. List-only."""
    uploads = []
    key_marker = ""
    upload_marker = ""
    for _ in range(1000):
        params = {"uploads": ""}
        if prefix:
            params["prefix"] = prefix
        if key_marker:
            params["key-marker"] = key_marker
        if upload_marker:
            params["upload-id-marker"] = upload_marker
        status, body = signed_get(config, params)
        if status != 200:
            raise WitnessError("ListMultipartUploads %s failed: HTTP %s %s" % (prefix, status, clip(body, 200)))
        try:
            root = ET.fromstring(body)
        except ET.ParseError as exc:
            raise WitnessError("ListMultipartUploads %s returned unparseable XML: %s" % (prefix, exc))
        truncated = False
        next_key = ""
        next_upload = ""
        for child in root:
            name = local_name(child.tag)
            if name == "Upload":
                entry = {"key": "", "upload_id": "", "initiated": None}
                for field in child:
                    field_name = local_name(field.tag)
                    if field_name == "Key":
                        entry["key"] = field.text or ""
                    elif field_name == "UploadId":
                        entry["upload_id"] = field.text or ""
                    elif field_name == "Initiated":
                        entry["initiated"] = parse_timestamp(field.text or "")
                if entry["key"]:
                    uploads.append(entry)
            elif name == "IsTruncated":
                truncated = (child.text or "").strip().lower() == "true"
            elif name == "NextKeyMarker":
                next_key = child.text or ""
            elif name == "NextUploadIdMarker":
                next_upload = child.text or ""
        if not truncated:
            return uploads
        if not next_key:
            raise WitnessError("ListMultipartUploads %s truncated without a key marker" % prefix)
        key_marker = next_key
        upload_marker = next_upload
    raise WitnessError("ListMultipartUploads %s exceeded 1000 pages" % prefix)


def resolve_lifecycle_marker(current_time, current_mode, candidate_time, candidate_mode):
    """Resolve duplicate session.start/session.end markers.

    The strictly-newest LastModified wins with its mode. An exact tie is
    ambiguous (nothing is "newest"): when the declared modes conflict, fail
    closed to the conservative `shell` marker (a tar is expected), so neither
    listing order can silently exempt the session; an identical-mode tie
    keeps the marker as-is.
    """
    if current_time is None or candidate_time > current_time:
        return candidate_time, candidate_mode
    if candidate_time < current_time:
        return current_time, current_mode
    if (candidate_mode == "exec") != (current_mode == "exec"):
        return current_time, "shell"
    return current_time, current_mode


def run_checks(config, now):
    audit_objects = list_objects(config, config.audit_prefix)
    recording_objects = list_objects(config, config.recordings_prefix)
    uploads = list_uploads(config, config.recordings_prefix)
    alerts = []
    # Enforce the clock-skew contract at collection time: every S3 timestamp
    # the checks can read (object LastModified, multipart Initiated) is
    # validated once here, so "any S3 timestamp more than 5 min in the future
    # -> error" holds for every key - including exec sessions that are later
    # exempt from the gap clock and completed tars whose session.end is
    # present, which never reach a per-session age check otherwise.
    for key, last_modified in audit_objects.items():
        age_seconds(now, last_modified, "object %s" % key, config.clock_skew_tolerance)
    for key, last_modified in recording_objects.items():
        age_seconds(now, last_modified, "recording %s" % key, config.clock_skew_tolerance)
    for upload in uploads:
        age_seconds(now, upload["initiated"], "upload %s initiated" % upload["key"], config.clock_skew_tolerance)

    heartbeat_times = []
    unrecognized = []
    for key, last_modified in audit_objects.items():
        if not key.startswith(config.heartbeat_prefix):
            continue
        if HEARTBEAT_KEY_RE.match(key[len(config.heartbeat_prefix):]):
            heartbeat_times.append(last_modified)
        else:
            unrecognized.append(key)

    heartbeat_age = None
    if not heartbeat_times:
        alerts.append("heartbeat-missing: no objects under %s" % config.heartbeat_prefix)
    else:
        heartbeat_age = age_seconds(
            now, max(heartbeat_times), "newest heartbeat", config.clock_skew_tolerance)
        if heartbeat_age > config.heartbeat_max_age:
            alerts.append(
                "heartbeat-stale: newest heartbeat is %ds old (limit %ds)"
                % (heartbeat_age, config.heartbeat_max_age)
            )

    sessions = {}
    contract_bad = 0
    for key, last_modified in audit_objects.items():
        if key.startswith(config.heartbeat_prefix):
            continue
        relative = key[len(config.audit_prefix):] if key.startswith(config.audit_prefix) else key
        match = SESSION_KEY_RE.match(relative)
        if match:
            event_type, is_variant = canonical_conflict_type(match.group("etype"))
            sid = match.group("sid").lower()
            state = sessions.setdefault(
                sid, {"seqs": [], "start": None, "end": None, "start_mode": None,
                      "end_mode": None, "identities": set()})
            seq = int(match.group("seq"))
            # A base key and its replay-conflict variant share one identity
            # (ts, canonical type, seq): count the seq once so a legitimate
            # variant cannot read as a `sequence-duplicate`, while a genuine
            # duplicate from a different timestamp still does. The identity is
            # for sequence counting ONLY - it must not skip lifecycle
            # resolution: a same-ts `.exec`/`.shell` marker pair also shares
            # the identity (the mode is not part of it), so forcing the second
            # key to skip would let whichever key the listing returns first
            # win regardless of LastModified (a stale/equal-LM `.exec` silently
            # exempting a shell session). Only a key whose type
            # `canonical_conflict_type` actually flags as a replay-conflict
            # variant skips resolution; every canonical key reaches
            # `resolve_lifecycle_marker` and the newest marker (or the
            # conservative conflicting tie) wins in either listing order.
            identity = (match.group("ts"), event_type, seq)
            if identity not in state["identities"]:
                state["identities"].add(identity)
                state["seqs"].append(seq)
            mode = match.group("mode")
            if is_variant:
                # Variants drop the mode marker by contract and must not
                # re-resolve the lifecycle marker: the base key (which the
                # producer only variants because it exists) is authoritative.
                # A mode marker on a variant is naming drift exactly like a
                # mode marker on any non-lifecycle base shape.
                if mode:
                    contract_bad += 1
                continue
            # Duplicate starts and ends resolve by the newest LastModified,
            # exactly like each other: a re-PUT / replayed marker must not win
            # just because its key sorts first, or a stale `.exec` start could
            # silently exempt a session whose newest marker says shell. An
            # exact tie with conflicting declared modes fails closed to the
            # conservative `shell` (see resolve_lifecycle_marker).
            if event_type == "session.start":
                state["start"], state["start_mode"] = resolve_lifecycle_marker(
                    state["start"], state["start_mode"], last_modified, mode)
            elif event_type == "session.end":
                state["end"], state["end_mode"] = resolve_lifecycle_marker(
                    state["end"], state["end_mode"], last_modified, mode)
            elif mode:
                # The mode marker is contract-defined on start/end only; a
                # marker anywhere else is naming drift.
                contract_bad += 1
            continue
        generic = NON_SESSION_KEY_RE.match(relative)
        if generic:
            # A replay-conflict variant (`session.rejected_<hash16>`) is the
            # same documented event as its base type, never naming drift.
            event_type, _ = canonical_conflict_type(generic.group("etype"))
            if not event_type.startswith("session.") or event_type in SID_LESS_SESSION_EVENTS:
                continue  # documented non-session (or known sid-less session) event
        # Drift is judged by shape (a UUID-shaped sid or a session.* event
        # type), not by one literal substring: a rename that drops
        # "-session." but keeps the sid still fails closed.
        if UUID_RE.search(relative) or re.search(r"(?:^|[-.])session[.]", relative):
            contract_bad += 1
        else:
            unrecognized.append(key)

    if contract_bad:
        alerts.append(
            "naming-contract: %d audit key(s) look like session events but do not match the shipper naming contract"
            % contract_bad
        )
    if unrecognized:
        alerts.append(
            "contract-mismatch: %d audit object(s) match no documented shipper key shape"
            % len(unrecognized)
        )

    # Completed recordings and in-progress uploads keyed by lowercased sid:
    # sessions are grouped case-insensitively, so an uppercase-sid tar or
    # upload must satisfy the gap check for the lowercased session id instead
    # of false-alerting (round-6 F5). The newest LastModified wins a case
    # collision for the tar clock.
    recordings_by_sid = {}
    for key, last_modified in recording_objects.items():
        if not key.startswith(config.recordings_prefix):
            continue
        match = RECORDING_KEY_RE.match(key[len(config.recordings_prefix):])
        if not match:
            continue
        sid = match.group("sid").lower()
        current = recordings_by_sid.get(sid)
        if current is None or last_modified > current:
            recordings_by_sid[sid] = last_modified
    upload_sids = set()
    for upload in uploads:
        key = upload["key"]
        if not key.startswith(config.recordings_prefix):
            continue
        match = RECORDING_KEY_RE.match(key[len(config.recordings_prefix):])
        if match:
            upload_sids.add(match.group("sid").lower())
    for sid in sorted(sessions):
        state = sessions[sid]
        if state["start"] is None:
            # Stream closure: session events with no session.start can never
            # be gap-checked, so they must alert on their own.
            alerts.append(
                "session-start-missing: session %s has %d audit event(s) but no session.start"
                % (sid, len(state["seqs"]))
            )
            continue
        # session.end is authoritative for the exec/shell split: live Teleport
        # v18 emits `interactive` on the end event only (the start key reads
        # `.shell` for exec sessions too). With no end yet, the start marker
        # governs; a missing/legacy marker is shell (conservative: a tar is
        # expected).
        if state["end"] is not None:
            session_mode = "exec" if state["end_mode"] == "exec" else "shell"
        else:
            session_mode = "exec" if state["start_mode"] == "exec" else "shell"
        if session_mode == "exec":
            continue  # non-interactive exec sessions ship no recording (documented)
        age = age_seconds(now, state["start"], "session.start", config.clock_skew_tolerance)
        recording_key = config.recordings_prefix + sid + ".tar"
        completed_at = recordings_by_sid.get(sid)
        if completed_at is not None:
            # The tar satisfies the gap check by itself, so a completed
            # recording whose session.end never shipped would stay green
            # forever; anchor the end grace on the tar's own LastModified
            # (the completer-lag window: > shipper backoff, 15 min default).
            if state["end"] is None:
                completed_age = age_seconds(
                    now, completed_at, "recording %s" % recording_key, config.clock_skew_tolerance)
                if completed_age > config.completer_lag:
                    alerts.append(
                        "session-end-missing: %s completed %ds ago but session %s has no session.end (grace %ds)"
                        % (recording_key, completed_age, sid, config.completer_lag)
                    )
            continue
        if sid in upload_sids:
            continue
        if age <= config.session_grace:
            continue
        if state["end"] is None:
            # No end yet: live v18 marks only the end event, so a `.shell`
            # start cannot be told apart from an in-flight exec session
            # (which ships no tar and clears this alert when its `.exec` end
            # lands). Alert anyway - conservative, never silenced - with
            # wording that names the ambiguity so triage does not read it as
            # a confirmed loss. An interactive session whose recording never
            # started has the same shape and is exactly what must not be
            # suppressed, which is why a longer bound is not used here (it
            # would only delay both the false positive and the real gap).
            alerts.append(
                "recording-gap: shell session %s started %ds ago with no %s object and no in-progress upload "
                "(no session.end yet - an in-flight exec session also reads `.shell` until its end ships; "
                "may clear when the end or tar lands)"
                % (sid, age, recording_key)
            )
        else:
            alerts.append(
                "recording-gap: %s session %s started %ds ago with no %s object and no in-progress upload"
                % (session_mode, sid, age, recording_key)
            )

    # Orphan completed recordings: a tar whose sid has no audit events at all
    # is the extreme tail of stream closure (no start -> no gap clock at all).
    # The session loop above cannot see it because it only visits observed
    # sessions, so it is checked here against the same completer-lag grace.
    for key, completed in recording_objects.items():
        if not key.startswith(config.recordings_prefix):
            continue
        match = RECORDING_KEY_RE.match(key[len(config.recordings_prefix):])
        if not match:
            continue
        sid = match.group("sid").lower()
        if sid in sessions:
            continue
        completed_age = age_seconds(
            now, completed, "recording %s" % key, config.clock_skew_tolerance)
        if completed_age > config.completer_lag:
            alerts.append(
                "session-start-missing: %s completed %ds ago but session %s has no audit events at all "
                "(no session.start; grace %ds)" % (key, completed_age, sid, config.completer_lag)
            )

    for sid in sorted(sessions):
        seqs = sessions[sid]["seqs"]
        counts = collections.Counter(seqs)
        duplicates = sorted(seq for seq, count in counts.items() if count > 1)
        if duplicates:
            alerts.append(
                "sequence-duplicate: session %s repeats <seq> %s"
                % (sid, ",".join(str(number) for number in duplicates))
            )
            continue
        unique = sorted(counts)
        if unique[0] > 1:
            alerts.append(
                "sequence-origin: session %s starts at <seq> %d (the first seq must be 0 or 1)"
                % (sid, unique[0])
            )
        if unique[-1] - unique[0] + 1 != len(unique):
            # Bounded missing-set: render gap ranges from the observed values
            # (never range(low, high+1), which crafted seq values could hang).
            missing_ranges = [
                (before + 1, after - 1)
                for before, after in zip(unique, unique[1:]) if after > before + 1
            ]
            rendered = [
                str(start) if start == stop else "%d-%d" % (start, stop)
                for start, stop in missing_ranges[:20]
            ]
            if len(missing_ranges) > 20:
                rendered.append("...")
            alerts.append(
                "sequence-gap: session %s missing <seq> %s"
                % (sid, ",".join(rendered))
            )

    for upload in uploads:
        key = upload["key"]
        if not key.startswith(config.recordings_prefix):
            continue
        match = RECORDING_KEY_RE.match(key[len(config.recordings_prefix):])
        if not match:
            continue
        sid = match.group("sid").lower()
        initiated_age = age_seconds(
            now, upload["initiated"], "upload %s initiated" % key, config.clock_skew_tolerance)
        ended = sessions.get(sid, {}).get("end")
        if ended is not None:
            ended_age = age_seconds(now, ended, "session.end for %s" % sid, config.clock_skew_tolerance)
            if ended_age > config.completer_lag:
                alerts.append(
                    "completer-lag: %s still in progress %ds after session.end (started at %s)"
                    % (key, ended_age, utc_stamp(upload["initiated"]))
                )
        elif initiated_age > config.open_upload_max_age:
            # Distinct from completer-lag (session.end seen) and from the
            # bare-old-multipart rule: an upload with no session.end has no
            # end-anchored clock, so it gets its own age bound.
            alerts.append(
                "open-upload-stale: %s has been open %ds with no session.end (bound %ds)"
                % (key, initiated_age, config.open_upload_max_age)
            )

    if alerts:
        return "alert", "; ".join(alerts)
    detail = "sessions=%d uploads=%d audit_objects=%d recordings_objects=%d heartbeat_age=%s" % (
        len(sessions), len(uploads), len(audit_objects), len(recording_objects),
        ("%ds" % heartbeat_age) if heartbeat_age is not None else "none")
    return "ok", detail


def corrupt_state_destination(path, now):
    """Pick a never-overwriting destination for an unreadable state file.

    `<state>.corrupt` when free; when that name is already taken (an earlier
    preservation, or a planted entry such as a directory) a timestamped
    `<state>.corrupt.<UTCstamp>` name is used, so earlier forensics are never
    overwritten (round-7 R3).
    """
    base = path + ".corrupt"
    if not os.path.lexists(base):
        return base
    stamp = now.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    candidate = "%s.%s" % (base, stamp)
    suffix = 0
    while os.path.lexists(candidate):
        suffix += 1
        candidate = "%s.%s-%d" % (base, stamp, suffix)
    return candidate


def read_state(path):
    try:
        # Read raw BYTES: the cap below is a byte bound (a worst-case
        # 4-byte-per-char UTF-8 file must not slip past a character count).
        with open(path, "rb") as handle:
            raw_bytes = handle.read(STATE_MAX_BYTES + 1)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError, RecursionError) as exc:
        raise WitnessError("state file unreadable: %s" % exc)
    if len(raw_bytes) > STATE_MAX_BYTES:
        # An oversized state is invalid input, not a reason to read it whole
        # (round-7 R2: the unbounded read raised an uncaught MemoryError).
        raise WitnessError("state file exceeds %d bytes" % STATE_MAX_BYTES)
    try:
        raw = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise WitnessError("state file is not valid UTF-8: %s" % exc)
    try:
        data = json.loads(raw)
    except (ValueError, RecursionError) as exc:
        # RecursionError: a pathologically nested JSON document must take the
        # invalid-state path (preserve + repair), never abort before the
        # verdict with no files (round-6 F4).
        raise WitnessError("state file unreadable: %s" % exc)
    if not isinstance(data, dict):
        raise WitnessError("state file is not a JSON object")
    return data


def _open_state_file(path, mode):
    """Open a state/verdict file without following or reusing a planted entry.

    A symlink at `state.json.tmp` or `verdict.log` used to redirect the write
    (truncate + chmod) at whatever it pointed to, before the tmp was renamed
    into place (round-6 F3). O_NOFOLLOW refuses a symlink at the final
    component and O_EXCL refuses to reuse an existing tmp; a stale regular tmp
    is unlinked first (unlinking a name never touches what it points at).
    """
    if mode == "w":
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise OSError("cannot clear stale %s: %s" % (path, clip(exc, 120)))
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    else:
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    return os.fdopen(fd, mode, encoding="utf-8")


def write_state(path, record):
    tmp = path + ".tmp"
    with _open_state_file(tmp, "w") as handle:
        json.dump(record, handle, indent=1, sort_keys=True)
        handle.write("\n")
        os.fchmod(handle.fileno(), 0o600)
    os.replace(tmp, path)


def append_verdict(path, state, detail):
    try:
        if os.path.getsize(path) >= VERDICT_LOG_MAX_BYTES:
            os.replace(path, path + ".1")
    except FileNotFoundError:
        pass
    with _open_state_file(path, "a") as handle:
        handle.write("%s %s %s\n" % (utc_stamp(datetime.now(timezone.utc)), state, detail))


def ntfy_token_problem(token):
    """Why a publish token cannot be an HTTP header value (empty string = ok).

    Header values are latin-1 bytes: a control character (especially CR/LF)
    makes http.client.putheader raise ValueError and a non-ASCII token raises
    UnicodeEncodeError. Both used to escape notify()'s transport except-clause,
    aborting the run before state/verdict with no files (and the ValueError
    text echoed the token bytes into the traceback). Validate first so a bad
    token becomes a skipped push, never a crash. The length cap also keeps a
    pathological token from building a giant header (round-6 F1).
    """
    if len(token) > 4096:
        return "token is longer than 4096 characters"
    for char in token:
        if not ("!" <= char <= "~"):
            return "token is not printable ASCII without spaces"
    return ""


class RefuseRedirects(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect (ntfy POST and signed S3 list GETs).

    urllib's default redirect handler copies the request headers onto the
    redirect target, so a 301/302/303 to another host or scheme re-sent the
    `Authorization` header cross-origin: `Bearer <publish token>` for the ntfy
    POST (round-6 F2, mirror of pc-admin's R3 fix) and the SigV4
    `AWS4-HMAC-SHA256 Credential=...` header for the witness S3 client
    (round-7 R1). Neither call needs a redirect hop, so a 3xx becomes a failed
    call (logged, retried) with nothing sent to the redirect target.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url, code, "refusing redirect to %r" % (newurl,), headers, fp
        )


# One redirect-refusing opener serves every client call. The module-level
# _NTFY_OPENER name is patchable for the offline harness; the signed S3 list
# client always uses the real opener (round-7 R1).
_REDIRECT_REFUSING_OPENER = urllib.request.build_opener(RefuseRedirects())
_NTFY_OPENER = _REDIRECT_REFUSING_OPENER


def open_ntfy(request, timeout=15):
    """Open the ntfy POST through the redirect-refusing opener."""
    return _NTFY_OPENER.open(request, timeout=timeout)


def open_signed(request, timeout=30):
    """Open a SigV4-signed S3 list GET through the redirect-refusing opener."""
    return _REDIRECT_REFUSING_OPENER.open(request, timeout=timeout)


def notify(config, state, detail):
    """Push the verdict through ntfy when a topic is configured. Best-effort."""
    if not config.ntfy_topic:
        return False
    token = config.ntfy_token
    problem = ntfy_token_problem(token) if token else ""
    if problem:
        # The reason names the class of problem only - never the token bytes;
        # a bad token must fail the push, not the run (round-6 F1).
        log("WARNING: ntfy push skipped: %s" % problem)
        return False
    headers = {
        "Title": "recording witness: %s" % state,
        "Tags": "white_check_mark" if state == "ok" else "warning",
    }
    if token:
        headers["Authorization"] = "Bearer " + token
    try:
        request = urllib.request.Request(
            "https://ntfy.sh/" + urllib.parse.quote(config.ntfy_topic, safe=""),
            data=clip(detail, 800).encode("utf-8"),
            method="POST",
        )
        for name, value in headers.items():
            request.add_header(name, value)
        with open_ntfy(request, timeout=15):
            return True
    except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
        # HTTPException covers BadStatusLine / IncompleteRead (not OSError
        # subclasses); URLError covers the refused-redirect HTTPError. A
        # transport failure must be logged and retried, never abort the run
        # before state/verdict.
        log("WARNING: ntfy push failed: %s" % clip(exc, 200))
        return False
    except (ValueError, UnicodeError) as exc:
        # A late header-validation failure can embed the header value (the
        # token); log the exception class only, never its message, and keep
        # the push non-fatal (round-6 F1).
        log("WARNING: ntfy push failed: %s" % type(exc).__name__)
        return False


def should_notify(previous_state, last_epoch, state, now_epoch, renotify, state_since_run=0, last_notify_run=0):
    """Notification bookkeeping.

    Non-green states push on transition and re-notify every renotify window.
    Green pushes on the non-green -> ok recovery; a recovery push that failed
    is retried while the current ok state began after the last successful
    notify (state_since_run > last_notify_run), so a green state never
    re-pushes once its recovery has landed. The retry boundary is the per-run
    identity, not the second-resolution epoch: a recovery transition in the
    same second as the last non-green push still retries, and a landing in
    that same second still stops (run ids are unique per run).
    """
    if state == "ok":
        if previous_state not in (None, "ok"):
            return True
        if previous_state == "ok":
            return int(state_since_run) > int(last_notify_run)
        return False  # a first-ever green run has nothing to recover from
    if state != previous_state:
        return True
    last_epoch = int(last_epoch)
    if last_epoch > now_epoch:
        # A stored last-push epoch in the future (the anchor clock stepped
        # ahead, then was corrected) would otherwise suppress renotify until
        # wall clock catches up; an impossible value is not a reason to stay
        # silent.
        return True
    return now_epoch - last_epoch >= int(renotify)


def main():
    now = datetime.now(timezone.utc)
    now_epoch = int(now.timestamp())
    config = None
    try:
        config = Config()
        state, detail = run_checks(config, now)
    except Exception as exc:  # fail-closed by design: any failure => error
        state = "error"
        detail = "error: %s: %s" % (type(exc).__name__, exc)
    detail = clip(detail, 1000)

    state_dir = env("RECORDING_WITNESS_STATE_DIR", "/var/lib/piercloud/recording-witness")
    state_path = os.path.join(state_dir, "state.json")
    verdict_path = os.path.join(state_dir, "verdict.log")
    try:
        os.makedirs(state_dir, mode=0o700, exist_ok=True)
    except OSError as exc:
        log("FAIL: cannot create state directory: %s" % clip(exc, 200))
        log("%s: %s" % (state, detail))
        return 2

    previous = {}
    state_bad_reason = ""
    try:
        previous = read_state(state_path)
    except WitnessError as exc:
        state_bad_reason = str(exc)
        previous = {}
        # Keep the unreadable record for forensics instead of overwriting it
        # outright; the repaired record cannot carry a baseline it could not
        # read.
        corrupt_path = None
        try:
            corrupt_path = corrupt_state_destination(state_path, now)
            os.replace(state_path, corrupt_path)
            log("WARNING: unreadable state file preserved as %s" % corrupt_path)
        except OSError as exc:
            # An unwritable state dir disables the preservation; say so
            # instead of silently dropping forensics (round-6 F8). A name
            # collision is not a failure: the destination is unique (R3).
            log("WARNING: cannot preserve unreadable state as %s: %s"
                % (corrupt_path or (state_path + ".corrupt"), clip(exc, 200)))

    renotify = config.renotify if config is not None else 1800
    baseline = previous.get("baseline") if isinstance(previous.get("baseline"), dict) else None
    # Defensive numeric parsing: a type-valid state.json with a corrupted
    # counter (e.g. "run_seq": "not-a-number") must never crash the run
    # before the verdict/push. A bad value is treated like any other invalid
    # state: error verdict + repair, while the readable baseline is held.
    numerics = {}
    for name in ("last_notify_epoch", "last_notify_run", "run_seq", "state_since_run", "state_since_epoch"):
        value = previous.get(name)
        if value is None:
            numerics[name] = 0
        elif isinstance(value, bool) or not isinstance(value, int) or value < 0:
            state_bad_reason = state_bad_reason or "state field %s is invalid: %r" % (name, value)
            numerics[name] = 0
        else:
            numerics[name] = value
    if state_bad_reason:
        if state != "error":
            state = "error"
            detail = clip("error: %s" % state_bad_reason, 1000)
        else:
            detail = clip("%s (state record also invalid: %s)" % (detail, state_bad_reason), 1000)
        # An invalid record is not a trustworthy previous state: the error
        # verdict must push instead of comparing against it.
        previous = {}
    last_notify_epoch = numerics["last_notify_epoch"]
    last_notify_run = numerics["last_notify_run"]
    # Per-run identity: a monotonic counter written into state.json, never a
    # second-resolution timestamp, so a genuine same-second run still advances
    # it while a run that failed to persist state still repeats it.
    run_seq = numerics["run_seq"] + 1
    state_since_run = numerics["state_since_run"]
    state_since_epoch = numerics["state_since_epoch"]
    previous_state = previous.get("state")
    # Arm the transition marker only when a PERSISTED previous state changed:
    # a first-ever run (previous_state None) must not arm it, or the next
    # green run looks like an un-landed recovery and pushes a spurious ok.
    if previous_state is not None and previous_state != state:
        state_since_run = run_seq
        state_since_epoch = now_epoch
    if should_notify(previous_state, last_notify_epoch, state, now_epoch, renotify, state_since_run, last_notify_run):
        if config is not None and notify(config, state, detail):
            last_notify_epoch = now_epoch
            last_notify_run = run_seq
    record = {
        "version": STATE_VERSION,
        "state": state,
        "detail": detail,
        "updated_at": utc_stamp(now),
        "run_seq": run_seq,
        "state_since_run": state_since_run,
        "state_since_epoch": state_since_epoch,
        "last_notify_run": last_notify_run,
        "last_notify_epoch": last_notify_epoch,
    }
    if state_bad_reason:
        # Explicit repair evidence: an unreadable/invalid record has no
        # readable baseline, so the counter restarts at 1 above. The run-once
        # acceptance cannot tell that reset from a stale record by `run_seq`
        # alone, so mark the repair here and name the systemd invocation that
        # wrote it below; the acceptance only counts a repair written by the
        # invocation that just ran.
        record["repaired"] = True
    invocation = env("INVOCATION_ID", "")
    if invocation:
        # systemd's per-runtime-cycle ID (unique 32-hex, the same value
        # `systemctl show -p InvocationID` reports). A failed state write
        # leaves the previous record - and its previous invocation - in
        # place, so this is what lets the acceptance tell "this invocation
        # repaired the record" from "this invocation never persisted state".
        record["invocation"] = invocation
    if state == "error":
        # Held when it could be read: an un-runnable run never advances the
        # last good baseline. An unreadable state file has no readable
        # baseline (the file is kept as state.json.corrupt); the repaired
        # record says null rather than fabricating one.
        record["baseline"] = baseline
    else:
        record["baseline"] = {"state": state, "detail": detail, "updated_at": utc_stamp(now)}
    try:
        write_state(state_path, record)
    except OSError as exc:
        log("WARNING: cannot write state file: %s" % clip(exc, 200))
    try:
        append_verdict(verdict_path, state, detail)
    except OSError as exc:
        log("WARNING: cannot append verdict log: %s" % clip(exc, 200))
    log("%s: %s" % (state, detail))
    return {"ok": 0, "alert": 1, "error": 2}[state]


if __name__ == "__main__":
    sys.exit(main())
RECORDING_WITNESS_PY_EOF
RECORDING_WITNESS_FILE_EOF
}

render_recording_witness_service() { # print the systemd service unit to stdout
  cat <<RECORDING_WITNESS_UNIT_EOF
[Unit]
Description=pc-admin recording-completeness witness (list-only B2 metadata)
Documentation=https://github.com/piercloud-net/terraform-piercloud-anchor/blob/main/docs/recording-witness.md
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${RECORDING_WITNESS_SBIN}
User=root
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=${RECORDING_WITNESS_STATE_DIR}
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
LockPersonality=yes
CapabilityBoundingSet=
AmbientCapabilities=
RECORDING_WITNESS_UNIT_EOF
}

render_recording_witness_timer() { # print the systemd timer unit to stdout
  cat <<'RECORDING_WITNESS_TIMER_EOF'
[Unit]
Description=Run the pc-admin recording-completeness witness every 5 minutes

[Timer]
OnBootSec=2min
OnUnitInactiveSec=5min
AccuracySec=30s

[Install]
WantedBy=timers.target
RECORDING_WITNESS_TIMER_EOF
}

recording_witness_install() { # render + install the component (idempotent)
  local tmp
  if ! command -v python3 >/dev/null 2>&1; then
    log "Installing python3 (witness runtime)"
    export DEBIAN_FRONTEND=noninteractive
    apt-get install -y -qq python3-minimal >/dev/null
  fi
  mkdir -p "$(dirname "$RECORDING_WITNESS_SBIN")" "$(dirname "$RECORDING_WITNESS_ENV_FILE")" "$RECORDING_WITNESS_STATE_DIR" \
    "$(dirname "$RECORDING_WITNESS_SERVICE")" "$(dirname "$RECORDING_WITNESS_TIMER")"
  chmod 700 "$RECORDING_WITNESS_STATE_DIR"
  tmp="$(mktemp)"
  render_recording_witness >"$tmp"
  bash -n "$tmp" || die "rendered witness script failed bash -n - refusing to install"
  chmod 0755 "$tmp"
  if [ "$(id -u)" -eq 0 ]; then chown root:root "$tmp"; fi
  mv "$tmp" "$RECORDING_WITNESS_SBIN"
  tmp="$(mktemp)"
  {
    printf '%s\n' "# DISPATCH-MANAGED by terraform-piercloud-anchor (scripts/010-provision.sh)."
    printf '%s\n' "# DO NOT EDIT BY HAND - re-rendered on every provision run. Holds the"
    printf '%s\n' "# list-only witness key: mode 0600, root-only, never printed to logs."
    printf 'RECORDING_WITNESS_ENDPOINT=%q\n' "$RECORDING_WITNESS_ENDPOINT"
    printf 'RECORDING_WITNESS_BUCKET=%q\n' "$RECORDING_WITNESS_BUCKET"
    printf 'RECORDING_WITNESS_AUDIT_PREFIX=%q\n' "$RECORDING_WITNESS_AUDIT_PREFIX"
    printf 'RECORDING_WITNESS_RECORDINGS_PREFIX=%q\n' "$RECORDING_WITNESS_RECORDINGS_PREFIX"
    printf 'RECORDING_WITNESS_KEY_ID=%q\n' "$RECORDING_WITNESS_KEY_ID"
    printf 'RECORDING_WITNESS_KEY=%q\n' "$RECORDING_WITNESS_KEY"
    printf 'RECORDING_WITNESS_STATE_DIR=%q\n' "$RECORDING_WITNESS_STATE_DIR"
    if [ -n "${RECORDING_WITNESS_REGION:-}" ]; then printf 'RECORDING_WITNESS_REGION=%q\n' "$RECORDING_WITNESS_REGION"; fi
    if [ -n "${NTFY_TOPIC:-}" ]; then printf 'NTFY_TOPIC=%q\n' "$NTFY_TOPIC"; fi
    if [ -n "${NTFY_TOKEN:-}" ]; then printf 'NTFY_TOKEN=%q\n' "$NTFY_TOKEN"; fi
  } >"$tmp"
  chmod 0600 "$tmp"
  if [ "$(id -u)" -eq 0 ]; then chown root:root "$tmp"; fi
  mv "$tmp" "$RECORDING_WITNESS_ENV_FILE"
  render_recording_witness_service >"$RECORDING_WITNESS_SERVICE.tmp.$$"
  chmod 0644 "$RECORDING_WITNESS_SERVICE.tmp.$$"
  mv "$RECORDING_WITNESS_SERVICE.tmp.$$" "$RECORDING_WITNESS_SERVICE"
  render_recording_witness_timer >"$RECORDING_WITNESS_TIMER.tmp.$$"
  chmod 0644 "$RECORDING_WITNESS_TIMER.tmp.$$"
  mv "$RECORDING_WITNESS_TIMER.tmp.$$" "$RECORDING_WITNESS_TIMER"
  systemctl daemon-reload
  systemctl enable --now pc-recording-witness.timer >/dev/null
  log "recording witness installed (5 min timer; env file 0600, key never printed)"
}

recording_witness_redact() { # redact session ids / recording keys from a verdict line
  python3 - "$1" <<'RECORDING_WITNESS_REDACT_PY'
import hashlib
import re
import sys


def _scrub(match):
    token = match.group(0)
    return "<redacted:%s:%d>" % (hashlib.sha256(token.encode("utf-8")).hexdigest()[:12], len(token))


sys.stdout.write(re.sub(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    _scrub,
    sys.argv[1],
))
RECORDING_WITNESS_REDACT_PY
}

recording_witness_run_once() { # run one check now and surface the verdict
  local rc=0 state exec_status detail updated_at before_run_seq run_seq before_invocation after_invocation repaired state_invocation state_advanced
  # Anchor freshness to THIS invocation, not to wall-clock recency: a run
  # that genuinely took longer than the old +/-300 s window must not be
  # rejected, and a wedged `systemctl start` that never executed ExecStart
  # (or a failed state write) must not let the previous verdict read as
  # current. InvocationID changes on every real systemd invocation (skipped
  # only if the property is unavailable); state.json's per-run identity
  # (run_seq) must also advance so a run that could not persist state.json
  # never counts, while two runs in the same wall-clock second still count
  # (updated_at is second-resolution and may legitimately repeat). The one
  # exception is an explicit repair written by THIS invocation (`repaired`,
  # a matching `invocation`, and the `error` verdict a repair always
  # carries): only an unreadable `run_seq` restarts the counter at 1 (a
  # valid `run_seq` with another invalid field is kept and still advances),
  # and that `error` verdict still fails the acceptance closed below.
  before_run_seq="$(jq -r '.run_seq // ""' "${RECORDING_WITNESS_STATE_DIR}/state.json" 2>/dev/null || true)"
  before_invocation="$(systemctl show pc-recording-witness.service -p InvocationID --value 2>/dev/null || true)"
  systemctl start pc-recording-witness.service >/dev/null 2>&1 || rc=$?
  exec_status="$(systemctl show pc-recording-witness.service -p ExecMainStatus --value 2>/dev/null || true)"
  after_invocation="$(systemctl show pc-recording-witness.service -p InvocationID --value 2>/dev/null || true)"
  # Type=oneshot: the witness alert (exit 1) also makes `systemctl start`
  # non-zero. A witness run is exactly rc=0+ExecMainStatus=0 (ok),
  # rc=1+ExecMainStatus=1 (alert) or rc=1+ExecMainStatus=2 (error); anything
  # else (unset status, exec error 203, a failed start that never executed the
  # main process) is not a verdict.
  case "${rc}:${exec_status}" in
    0:0|1:1|1:2) ;;
    *) die "witness produced no trustworthy verdict (systemctl rc=${rc} ExecMainStatus=${exec_status:-unset}) — the unit demonstrably did not run; refusing to read a possibly stale state.json" ;;
  esac
  state="$(jq -r '.state // "unknown"' "${RECORDING_WITNESS_STATE_DIR}/state.json" 2>/dev/null || true)"
  detail="$(jq -r '.detail // ""' "${RECORDING_WITNESS_STATE_DIR}/state.json" 2>/dev/null | cut -c1-300 || true)"
  updated_at="$(jq -r '.updated_at // ""' "${RECORDING_WITNESS_STATE_DIR}/state.json" 2>/dev/null || true)"
  run_seq="$(jq -r '.run_seq // ""' "${RECORDING_WITNESS_STATE_DIR}/state.json" 2>/dev/null || true)"
  repaired="$(jq -r '.repaired // false' "${RECORDING_WITNESS_STATE_DIR}/state.json" 2>/dev/null || true)"
  state_invocation="$(jq -r '.invocation // ""' "${RECORDING_WITNESS_STATE_DIR}/state.json" 2>/dev/null || true)"
  if [ -n "${after_invocation}" ] && [ "${after_invocation}" = "${before_invocation}" ]; then
    die "witness unit did not start a new invocation (InvocationID ${after_invocation} unchanged, systemctl rc=${rc} ExecMainStatus=${exec_status}) — refusing to read a possibly stale state.json"
  fi
  state_advanced=yes
  if [ -z "${run_seq}" ] || [ "${run_seq}" = "${before_run_seq}" ]; then
    state_advanced=no
    if [ -n "${run_seq}" ] && [ "${repaired}" = "true" ] && [ "${state}" = "error" ] && [ -n "${state_invocation}" ] && [ "${state_invocation}" = "${after_invocation}" ]; then
      state_advanced=yes
      log "witness state was repaired by this invocation (run_seq reset to ${run_seq}); reading the explicit repair verdict"
    fi
  fi
  if [ "${state_advanced}" != "yes" ]; then
    die "witness state did not advance (run_seq=${run_seq:-none}, before=${before_run_seq:-none}, updated_at=${updated_at:-none}, systemctl rc=${rc} ExecMainStatus=${exec_status}) — refusing to read a possibly stale verdict"
  fi
  # A `repaired` record is only trustworthy as the `error` verdict the shipped
  # writer always forces. Enforce that AFTER advancement is granted, not only
  # in the collision branch above: when the prior run_seq does not render as
  # the same non-empty string (unreadable state -> ""; a missing run_seq;
  # "01"; 1.0; -1; true) or is simply advanced (5 -> 6), the outer check
  # passes. The invocation field is only evidence for the collision-branch
  # exception (run_seq did not move); a fresh run_seq already authenticates
  # the record as THIS run's write, so every repaired non-error record dies
  # here however it names its invocation.
  if [ "${repaired}" = "true" ] && [ "${state}" != "error" ]; then
    die "witness state carries repaired=true but state=${state} (a repaired record must be error) — no trustworthy verdict; refusing to finish blind"
  fi
  detail="$(recording_witness_redact "${detail}")"
  case "${state}:${exec_status}" in
    ok:0) log "witness verdict: OK - ${detail}" ;;
    alert:1) warn "witness verdict: ALERT - ${detail} (the witness works; the recording pipeline has an open alert)" ;;
    error:2) die "witness verdict: ERROR - ${detail} (an un-runnable witness fails the run closed; fix the config and re-dispatch)" ;;
    *) die "witness produced no trustworthy verdict (state=${state:-missing} ExecMainStatus=${exec_status} rc=${rc}) - refusing to finish blind" ;;
  esac
}

recording_witness_disable() { # remove a previously installed component
  if [ ! -e "$RECORDING_WITNESS_SERVICE" ] && [ ! -e "$RECORDING_WITNESS_TIMER" ] && [ ! -e "$RECORDING_WITNESS_SBIN" ] && [ ! -e "$RECORDING_WITNESS_ENV_FILE" ]; then
    return 0
  fi
  log "recording witness disabled (no RECORDING_WITNESS_* env) - removing the timer and rendered artifacts"
  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now pc-recording-witness.timer >/dev/null 2>&1 || true
    systemctl stop pc-recording-witness.service >/dev/null 2>&1 || true
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi
  rm -f "$RECORDING_WITNESS_SERVICE" "$RECORDING_WITNESS_TIMER" "$RECORDING_WITNESS_SBIN" "$RECORDING_WITNESS_ENV_FILE"
  log "witness state + verdict log kept at ${RECORDING_WITNESS_STATE_DIR} (evidence; remove by hand to reset)"
}
# --- END RECORDING WITNESS ---

# ---------------------------------------------------------------------------
# g) Recording-completeness witness (list-only; optional)
#    Renders + enables the 5-minute witness timer when the RECORDING_WITNESS_*
#    env is fully set. Missing env = the component stays dormant (tenants
#    unaffected) and a previously installed copy is removed, so a retire never
#    leaves a stale timer. A partial env is a config error (fail closed).
#    Env in: RECORDING_WITNESS_ENDPOINT / _BUCKET / _AUDIT_PREFIX /
#    _RECORDINGS_PREFIX / _KEY_ID / _KEY (list-only), plus the existing
#    NTFY_TOPIC / NTFY_TOKEN for alert pushes. Docs: docs/recording-witness.md.
# ---------------------------------------------------------------------------
case "$(recording_witness_state)" in
  on)
    log "Installing the list-only recording-completeness witness (B2 metadata checks)"
    recording_witness_install
    recording_witness_run_once
    ;;
  partial)
    witness_problem="$(recording_witness_config_problem)"
    die "recording-witness env is partial: ${witness_problem:-unknown problem}. Set every RECORDING_WITNESS_* repo secret or none at all (docs/recording-witness.md)."
    ;;
  off)
    recording_witness_disable
    ;;
esac

log "Done. tang is up (loopback, via Caddy :80), the thumbprint is above, Gatus is dispatch-managed (statuses printed above), dashboard at https://${STATUS_HOST:-status-<alias>.piercloud.net} (TLS on the box), bind URL http://${ANCHOR_HOSTNAME:-anchor-01-<alias>}.piercloud.net (record verified by the DNS stage)."
