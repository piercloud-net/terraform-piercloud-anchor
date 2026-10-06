#!/usr/bin/env bash
# tests/edge-origin-auth/run-test.sh — CloudFront origin-auth proofs (call D).
#
# The :443 origin leg has two independent controls: the firewall admits only
# the CloudFront origin-facing ranges + the main box (main.tf), and Caddy
# requires the X-Piercloud-Origin secret header from those peers
# (scripts/010-provision.sh). This harness drives the REAL render span
# (extracted, never a copy) and asserts:
#   - fail-closed: missing/ill-formed CLOUDFRONT_ORIGIN_SECRET or
#     MAIN_BOX_IPV4 refuses to render the :443 dashboard block;
#   - gate content: both CEL matchers + aborts, the secret, the main-box
#     bypass, the CloudFront trusted_proxies list, client_ip_headers;
#   - sync tooth: the 010 constant == cloudfront_ranges.tf (same set, 81);
#   - firewall wiring: :443 loops the CloudFront ranges + the main-box rule,
#     :80 still loops cf_edge_cidrs;
#   - pipeline wiring: provision.yml passes + masks both secrets, 020
#     exports both, ci.yml runs this harness with its path gate intact.
# Cred-free, offline (no caddy, no network).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
PROVISION_SH="scripts/010-provision.sh"
RANGES_TF="cloudfront_ranges.tf"
MAIN_TF="main.tf"
PROV=".github/workflows/provision.yml"
ANCHOR_020=".github/scripts/020-provision-anchor.sh"
CI=".github/workflows/ci.yml"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0
ok()  { pass=$((pass + 1)); printf 'ok   %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL %s\n' "$1"; }
is()  { # $1 label, $2 expected, $3 actual
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi
}
has() { # $1 file, $2 literal, $3 label
  if grep -Fq -- "$2" "$1"; then ok "$3"; else bad "$3 (missing '$2' in $1)"; fi
}

# ---- real render span (extracted, never a copy) ---------------------------
die()  { printf '\nFAIL: %s\n' "$*" >&2; exit 1; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
b="$(grep -n -m1 'BEGIN CADDY RENDER' "${PROVISION_SH}" | cut -d: -f1)"
e="$(grep -n -m1 'END CADDY RENDER' "${PROVISION_SH}" | cut -d: -f1)"
[ -n "$b" ] && [ -n "$e" ] && [ "$b" -lt "$e" ] || die "Caddy render markers missing/ambiguous in ${PROVISION_SH}"
sed -n "$((b + 1)),$((e - 1))p" "${PROVISION_SH}" > "${WORK}/render.src"
# shellcheck disable=SC1090
source "${WORK}/render.src"
command -v render_caddyfile >/dev/null || die "extraction did not yield render_caddyfile"
command -v caddy_status_names >/dev/null || die "extraction did not yield caddy_status_names"
# Production origin-range constant, extracted — never retyped, cannot drift.
eval "$(grep '^CLOUDFRONT_ORIGIN_CIDRS=' "${PROVISION_SH}")"
[ -n "${CLOUDFRONT_ORIGIN_CIDRS:-}" ] || die "CLOUDFRONT_ORIGIN_CIDRS extraction failed"

MAIN_BOX="192.0.2.99"
SECRET="harness-origin-secret"
cf_cel="$(printf "'%s'," ${CLOUDFRONT_ORIGIN_CIDRS})"
cf_cel="${cf_cel%,}"

render_443() { # print the :443 dashboard shape (fail-closed on bad env)
  export CADDY_HTTP_ADDR=":80" CADDY_SKIP_HTTPS="" TANG_PORT="8081" GATUS_PORT="8080"
  export CADDY_CHALLENGE_DIR="${WORK}/acme-challenge"
  export TENANT_USER=prodprobe STATUS_HOST="" STATUS_MATCH=""
  export DASH_TLS_STANZA="	# harness: no origin pair; auto-HTTPS stub."
  caddy_status_names
  render_caddyfile
}
expect_fail() { # $1 label, $2 expected message substring; caller sets the env
  local out rc
  set +e
  out="$(render_443 2>&1)"
  rc=$?
  set -e
  if [ "$rc" -eq 0 ]; then bad "$1 (render succeeded; expected refusal)"; return 0; fi
  ok "$1 (refused, rc=$rc)"
  case "$out" in
    *"$2"*) ok "$1 message" ;;
    *) bad "$1 message (missing '$2' in: $(printf '%s' "$out" | tail -c 300))" ;;
  esac
}

# ---- fail-closed ----------------------------------------------------------
export MAIN_BOX_IPV4="${MAIN_BOX}"
unset CLOUDFRONT_ORIGIN_SECRET
expect_fail "missing CLOUDFRONT_ORIGIN_SECRET refuses" "CLOUDFRONT_ORIGIN_SECRET is not set"

export CLOUDFRONT_ORIGIN_SECRET="${SECRET}"
unset MAIN_BOX_IPV4
expect_fail "missing MAIN_BOX_IPV4 refuses" "MAIN_BOX_IPV4 is not set"

export CLOUDFRONT_ORIGIN_SECRET='sec ret' MAIN_BOX_IPV4="${MAIN_BOX}"
expect_fail "secret outside [A-Za-z0-9._-] refuses" "must match [A-Za-z0-9._-]+"

export CLOUDFRONT_ORIGIN_SECRET="${SECRET}" MAIN_BOX_IPV4="1.2.3"
expect_fail "short MAIN_BOX_IPV4 refuses" "not a bare IPv4"

export MAIN_BOX_IPV4="999.999.999.999"
expect_fail "out-of-range MAIN_BOX_IPV4 refuses" "not a bare IPv4"

export MAIN_BOX_IPV4="1.2.3.4.5"
expect_fail "five-octet MAIN_BOX_IPV4 refuses" "not a bare IPv4"

export CLOUDFRONT_ORIGIN_SECRET="${SECRET}" MAIN_BOX_IPV4="${MAIN_BOX}"
saved_cidrs="${CLOUDFRONT_ORIGIN_CIDRS}"
CLOUDFRONT_ORIGIN_CIDRS=""
expect_fail "empty CLOUDFRONT_ORIGIN_CIDRS refuses" "CLOUDFRONT_ORIGIN_CIDRS is empty"
CLOUDFRONT_ORIGIN_CIDRS="${saved_cidrs}"

# ---- happy-path render + gate content -------------------------------------
export CLOUDFRONT_ORIGIN_SECRET="${SECRET}" MAIN_BOX_IPV4="${MAIN_BOX}"
( render_443 ) > "${WORK}/Caddyfile.443" || die "happy-path render failed"
has "${WORK}/Caddyfile.443" 'abort @not_edge_peer' "gate aborts non-CloudFront peers"
has "${WORK}/Caddyfile.443" 'abort @unauthorized' "gate aborts peers without the secret"
has "${WORK}/Caddyfile.443" "${SECRET}" "gate carries the origin secret"
has "${WORK}/Caddyfile.443" "trusted_proxies static ${CLOUDFRONT_ORIGIN_CIDRS}" "trusted_proxies = the CloudFront origin ranges"
has "${WORK}/Caddyfile.443" 'client_ip_headers CloudFront-Viewer-Address' "client_ip_headers = CloudFront-Viewer-Address"

not_edge_line="$(grep -m1 '@not_edge_peer' "${WORK}/Caddyfile.443" || true)"
case "${not_edge_line}" in
  *"!(remote_ip(${cf_cel}, '127.0.0.1/32', '${MAIN_BOX}/32'))"*) ok "not_edge_peer matcher lists all 81 ranges + loopback + the main box" ;;
  *) bad "not_edge_peer matcher shape (got: $(printf '%s' "${not_edge_line}" | tail -c 200))" ;;
esac
unauth_line="$(grep -m1 '@unauthorized' "${WORK}/Caddyfile.443" || true)"
case "${unauth_line}" in
  *"!(remote_ip('127.0.0.1/32', '${MAIN_BOX}/32') || header({'X-Piercloud-Origin':'${SECRET}'}))"*) ok "unauthorized matcher = loopback/main-box bypass OR the secret header" ;;
  *) bad "unauthorized matcher shape (got: $(printf '%s' "${unauth_line}" | tail -c 200))" ;;
esac

# The gate must sit INSIDE the catch-all handle: Caddy adapts `abort` after
# `handle`, so a site-level gate is dead code (tests/bind-e2e pins the
# adapted route order; this pins the text-level placement everywhere else).
awk '/^https:\/\//{f=1} f{print}' "${WORK}/Caddyfile.443" > "${WORK}/dash.block"
catchall_line="$(grep -n -m1 '^	handle {$' "${WORK}/dash.block" | cut -d: -f1 || true)"
gate_line="$(grep -n -m1 '@not_edge_peer' "${WORK}/dash.block" | cut -d: -f1 || true)"
proxy_line="$(grep -n -m1 'reverse_proxy 127.0.0.1:' "${WORK}/dash.block" | cut -d: -f1 || true)"
if [ -n "${catchall_line}" ] && [ -n "${gate_line}" ] && [ -n "${proxy_line}" ] && [ "${catchall_line}" -lt "${gate_line}" ] && [ "${gate_line}" -lt "${proxy_line}" ]; then
  ok "gate sits inside the catch-all handle, before the proxy"
else
  bad "gate placement (catch-all=${catchall_line} gate=${gate_line} proxy=${proxy_line})"
fi

# ---- sync tooth: 010 constant == cloudfront_ranges.tf ---------------------
tf_list="$(awk '/cloudfront_origin_facing_cidrs = \[/{f=1;next} f&&/^ *\]/{f=0} f' "${RANGES_TF}" \
  | grep -oE '"[^"]+"' | tr -d '"' | LC_ALL=C sort)"
sh_list="$(printf '%s\n' ${CLOUDFRONT_ORIGIN_CIDRS} | LC_ALL=C sort)"
is "cloudfront_ranges.tf entry count" "81" "$(printf '%s\n' "${tf_list}" | wc -l | tr -d ' ')"
is "010 range count" "81" "$(printf '%s\n' ${CLOUDFRONT_ORIGIN_CIDRS} | wc -w | tr -d ' ')"
is "010 == cloudfront_ranges.tf (sorted set)" "${sh_list}" "${tf_list}"

# ---- firewall wiring ------------------------------------------------------
has "${MAIN_TF}" 'for cidr in local.cloudfront_origin_facing_cidrs' "main.tf :443 loop = CloudFront origin ranges"
has "${MAIN_TF}" 'for cidr in local.cf_edge_cidrs' "main.tf :80 loop still = Cloudflare edge ranges"
if grep -A8 'for cidr in local.cloudfront_origin_facing_cidrs' "${MAIN_TF}" | grep -Fq 'destination_ports = "443"'; then
  ok "CloudFront loop is the :443 rule"
else
  bad "CloudFront loop is not a :443 rule"
fi
if grep -A8 'for cidr in local.cf_edge_cidrs' "${MAIN_TF}" | grep -Fq 'destination_ports = "80"'; then
  ok "Cloudflare loop is the :80 rule"
else
  bad "Cloudflare loop is not a :80 rule"
fi
if grep -A2 'destination_ports = "443"' "${MAIN_TF}" | grep -Fq 'allow_main_box_ipv4}/32"]'; then
  ok "main-box :443 bypass rule present"
else
  bad "main-box :443 bypass rule missing"
fi
if grep -A2 'destination_ports = "443"' "${MAIN_TF}" | grep -Fq 'allow_main_box_ipv6'; then
  bad "main.tf admits a main-box IPv6 peer on :443 with no Caddy counterpart"
else
  ok "no main-box IPv6 :443 rule (the Caddy bypass is v4-only)"
fi

# ---- render custody -------------------------------------------------------
has "${PROVISION_SH}" 'install -m 0600 /dev/null "$TMP_CADDY"' "rendered Caddyfile pre-created root-only"
has "${PROVISION_SH}" 'rm -f "$TMP_CADDY"; die "rendered Caddyfile failed validate' "validate failure removes the rendered file"

# ---- pipeline wiring ------------------------------------------------------
has "${PROV}" 'CLOUDFRONT_ORIGIN_SECRET: ${{ secrets.CLOUDFRONT_ORIGIN_SECRET }}' "provision.yml passes CLOUDFRONT_ORIGIN_SECRET"
has "${PROV}" 'MAIN_BOX_IPV4: ${{ secrets.MAIN_BOX_IPV4 }}' "provision.yml passes MAIN_BOX_IPV4"
has "${PROV}" '::add-mask::${{ secrets.CLOUDFRONT_ORIGIN_SECRET }}' "provision.yml masks the origin secret"
has "${PROV}" '::add-mask::${{ secrets.MAIN_BOX_IPV4 }}' "provision.yml masks the main-box address"
has "${ANCHOR_020}" "CLOUDFRONT_ORIGIN_SECRET='\$(q \"\${CLOUDFRONT_ORIGIN_SECRET:-}\")'" "020 exports CLOUDFRONT_ORIGIN_SECRET"
has "${ANCHOR_020}" "MAIN_BOX_IPV4='\$(q \"\${MAIN_BOX_IPV4:-}\")'" "020 exports MAIN_BOX_IPV4"
has "${CI}" 'tests/edge-origin-auth/run-test.sh' "ci.yml runs this harness"
has "${CI}" 'edge-origin-auth|origin-ca|recording-witness)/' "ci.yml path gate includes edge-origin-auth (witness pin intact)"
gate_line_ci="$(grep -m1 'tests/(anchor-ip-selection' "${CI}" || true)"
case "${gate_line_ci}" in
  *'.*\.tf$'*) ok "ci.yml unit-tests gate runs on .tf-only changes" ;;
  *) bad "ci.yml unit-tests gate skips .tf-only changes (the sync tooth would not run)" ;;
esac

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
