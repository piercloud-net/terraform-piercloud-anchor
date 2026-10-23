#!/usr/bin/env bash
# tests/origin-mtls/run-test.sh — origin-mTLS trust-anchor proofs (issue #202).
#
# CloudFront presents a client certificate signed by the self-held origin CA;
# the anchor's Caddy verifies it against that CA in the same
# `client_auth require_and_verify` pool the retired Cloudflare AOP bundle uses.
# This harness pins:
#   - the committed `scripts/origin-mtls-ca.pem`: one X.509 CA cert, the exact
#     fingerprint (a silent CA swap must red), self-signed, CA:TRUE, ~10 years;
#   - the wiring: 020 reads the committed PUBLIC file and exports
#     ORIGIN_MTLS_CA_PEM into the piped on-box script; 010 validates it and
#     discards it after writing the 0644 pool;
#   - the REAL pool-construction span (extracted, never a copy): mTLS-only,
#     AOP-only, both (ordered), key-bearing, garbage, and the empty state;
#   - the render: client_auth + a single trust_pool file when a pool exists.
# Cred-free, offline (no caddy, no network, no docker).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
PROVISION_SH="scripts/010-provision.sh"
ANCHOR_020=".github/scripts/020-provision-anchor.sh"
CA_FILE="scripts/origin-mtls-ca.pem"
CI=".github/workflows/ci.yml"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0
ok()  { pass=$((pass + 1)); printf 'ok   %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL %s\n' "$1"; }
is()  { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi; }
has() { if grep -Fq -- "$2" "$1"; then ok "$3"; else bad "$3 (missing '$2' in $1)"; fi; }
hasnt() { if grep -Fq -- "$2" "$1"; then bad "$3 (unexpected '$2' in $1)"; else ok "$3"; fi; }

# ---- the committed trust anchor -------------------------------------------
[ -s "$CA_FILE" ] || { bad "the committed CA ${CA_FILE} is missing"; printf '\n%s passed, %s failed\n' "$pass" "$fail"; exit 1; }
is "the committed CA file holds exactly one certificate" "1" "$(grep -cE '^-----BEGIN CERTIFICATE-----[[:space:]]*$' "$CA_FILE")"
hasnt "$CA_FILE" "PRIVATE KEY" "the committed CA file carries no private key"
is "the committed CA fingerprint is pinned (a silent CA swap reds)" \
  "2a1bda4712df8f904088274752592b8c44a143f4287e82543bc38cf718c5a6b6" \
  "$(openssl x509 -in "$CA_FILE" -noout -fingerprint -sha256 2>/dev/null | sed -e 's/^.*=//' -e 's/://g' | tr 'A-F' 'a-f')"
openssl x509 -in "$CA_FILE" -noout -ext basicConstraints 2>/dev/null | grep -q 'CA:TRUE' \
  && ok "the committed CA has basicConstraints CA:TRUE" || bad "the committed CA lacks CA:TRUE"
is "the committed CA subject equals its issuer (self-signed root)" \
  "$(openssl x509 -in "$CA_FILE" -noout -subject 2>/dev/null | sed 's/^subject=//')" \
  "$(openssl x509 -in "$CA_FILE" -noout -issuer 2>/dev/null | sed 's/^issuer=//')"
openssl verify -CAfile "$CA_FILE" "$CA_FILE" >/dev/null 2>&1 \
  && ok "the committed CA verifies as its own trust anchor" || bad "the committed CA does not self-verify"
days="$(( ($(date -d "$(openssl x509 -in "$CA_FILE" -noout -enddate 2>/dev/null | cut -d= -f2)" +%s) - $(date -d "$(openssl x509 -in "$CA_FILE" -noout -startdate 2>/dev/null | cut -d= -f2)" +%s)) / 86400 ))"
[ "${days:-0}" -ge 3400 ] && [ "${days:-0}" -le 3700 ] \
  && ok "the committed CA lifetime is ~10 years (${days} days)" || bad "the committed CA lifetime is not ~10 years (${days} days)"

# ---- wiring: 020 reads the file and exports it -----------------------------
has "$ANCHOR_020" 'if [ -s scripts/origin-mtls-ca.pem ]; then' "020 reads the committed CA file"
has "$ANCHOR_020" 'ORIGIN_MTLS_CA_PEM="$(cat scripts/origin-mtls-ca.pem)"' "020 loads the CA from the committed file"
has "$ANCHOR_020" "ORIGIN_MTLS_CA_PEM='\$(q \"\${ORIGIN_MTLS_CA_PEM:-}\")'" "020 exports ORIGIN_MTLS_CA_PEM into the on-box env"
has "$PROVISION_SH" 'ORIGIN_MTLS_CA_PEM=""  # same' "010 discards the CA from memory after writing the pool"
has "$PROVISION_SH" 'must be certificate-only (public trust anchor)' "010 refuses a key-bearing ORIGIN_MTLS_CA_PEM"
has "$PROVISION_SH" 'client-auth pool is not a bounded PEM certificate bundle' "010 validates the combined pool"

# ---- real functions + the real pool span ----------------------------------
extract_fn() { # $1 = function name; prints the function body from 010
  awk -v name="$1" '$0 ~ ("^" name "\\(\\) \\{") { p = 1 } p { print } p && /^}/ { exit }' "$PROVISION_SH"
}
for fn in origin_ca_cert_pem_ok origin_ca_chain_blocks origin_ca_block_der_exact origin_ca_blocks_parse origin_ca_aop_deployed; do
  extract_fn "$fn" > "${WORK}/${fn}.src"
  [ -s "${WORK}/${fn}.src" ] || { bad "could not extract ${fn} from ${PROVISION_SH}"; printf '\n%s passed, %s failed\n' "$pass" "$fail"; exit 1; }
  # shellcheck disable=SC1090
  source "${WORK}/${fn}.src"
done
b="$(grep -n -m1 '^AOP_TLS=""$' "$PROVISION_SH" | cut -d: -f1)"
e="$(grep -n -m1 '^ORIGIN_MTLS_CA_PEM=""  # same$' "$PROVISION_SH" | cut -d: -f1)"
[ -n "$b" ] && [ -n "$e" ] && [ "$b" -lt "$e" ] || { bad "the client-auth pool span markers are missing/ambiguous"; printf '\n%s passed, %s failed\n' "$pass" "$fail"; exit 1; }
sed -n "${b},${e}p" "$PROVISION_SH" > "${WORK}/pool.src"
grep -Fq 'client-auth pool deployed' "${WORK}/pool.src" || bad "the extracted span is not the pool construction"

# Run the real span in a subshell: $1 = CF_AOP value, $2 = mTLS value; prints
# the resulting flags, or DIE:<message> when the span refuses.
run_pool() (
  CADDY_AOP_CA="${WORK}/pool.pem"
  CF_AOP_CA_PEM="${1:-}"
  ORIGIN_MTLS_CA_PEM="${2:-}"
  AOP_TLS=""
  MTLS_TLS=""
  CLIENT_CA_POOL=""
  log()  { :; }
  warn() { printf 'WARN:%s\n' "$*"; }
  die()  { printf 'DIE:%s\n' "$*"; exit 9; }
  # shellcheck disable=SC1090
  source "${WORK}/pool.src"
  printf 'AOP_TLS=%s MTLS_TLS=%s POOL=%s\n' "${AOP_TLS}" "${MTLS_TLS}" "$(grep -cE '^-----BEGIN CERTIFICATE-----[[:space:]]*$' "${CADDY_AOP_CA}" 2>/dev/null || true)"
)

# Real CA + a synthetic AOP CA (openssl, offline).
mtls_pem="$(cat "$CA_FILE")"
aop_key="${WORK}/aop.key"
aop_pem="$(openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$aop_key" -out /dev/stdout -days 1 -subj '/CN=harness-aop' 2>/dev/null)"
[ -n "$aop_pem" ] || { bad "openssl could not mint the harness AOP CA"; printf '\n%s passed, %s failed\n' "$pass" "$fail"; exit 1; }

out="$(run_pool "" "$mtls_pem")"
is "pool: mTLS only enables client auth" "AOP_TLS=yes MTLS_TLS=yes POOL=1" "$out"
out="$(run_pool "$aop_pem" "")"
is "pool: AOP only keeps the legacy behaviour (no mTLS flag)" "AOP_TLS=yes MTLS_TLS= POOL=1" "$out"
out="$(run_pool "$aop_pem" "$mtls_pem")"
is "pool: both sources land in one ordered pool" "AOP_TLS=yes MTLS_TLS=yes POOL=2" "$out"
out="$(run_pool "" "")"
case "$out" in
  *WARN:*'pre-#202 state'*'AOP_TLS= MTLS_TLS='*) ok "pool: empty state warns and enforces nothing" ;;
  *) bad "pool: empty state did not warn as expected (got '$out')" ;;
esac
out="$(run_pool "" "${mtls_pem}
AAABgarbage-after-the-certificate")" || true
case "$out" in
  DIE:*) ok "pool: trailing DER after a certificate is refused" ;;
  *) bad "pool: trailing DER after a certificate was accepted (got '$out')" ;;
esac
out="$(run_pool "" '-----BEGIN CERTIFICATE-----
not-base64!!!
-----END CERTIFICATE-----')" || true
case "$out" in
  DIE:*) ok "pool: a non-certificate PEM body is refused" ;;
  *) bad "pool: a non-certificate PEM body was accepted (got '$out')" ;;
esac
out="$(run_pool "" "${mtls_pem}
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIPqykxYO1HEjq8lTO8Gj58MMFhV2CAheP05wnl9Wr1rhoAoGCCqGSM49
-----END EC PRIVATE KEY-----")" || true
case "$out" in
  DIE:*'certificate-only'*) ok "pool: a key-bearing mTLS value is refused" ;;
  *) bad "pool: a key-bearing mTLS value was not refused (got '$out')" ;;
esac

# ---- render stanza (real span) --------------------------------------------
render_b="$(grep -n -m1 'BEGIN CADDY RENDER' "$PROVISION_SH" | cut -d: -f1)"
render_e="$(grep -n -m1 'END CADDY RENDER' "$PROVISION_SH" | cut -d: -f1)"
sed -n "$((render_b + 1)),$((render_e - 1))p" "$PROVISION_SH" > "${WORK}/render.src"
(
  # shellcheck disable=SC1090
  source "${WORK}/render.src"
  CADDY_AOP_CA="/etc/caddy/aop-ca.pem"
  CADDY_HTTP_ADDR=":80"
  CADDY_CHALLENGE_DIR="${WORK}/acme"
  TANG_PORT="8081"
  GATUS_PORT="8080"
  CADDY_SKIP_HTTPS=""
  DASH_TLS_STANZA="	tls /etc/caddy/origin.crt /etc/caddy/origin.key {
		client_auth {
			mode require_and_verify
			trust_pool file ${CADDY_AOP_CA}
		}
	}"
  STATUS_HOST="status.example.test"
  CLOUDFRONT_ORIGIN_SECRET="harness-secret"
  MAIN_BOX_IPV4="192.0.2.10"
  CLOUDFRONT_ORIGIN_CIDRS="192.0.2.0/24"
  render_caddyfile
) > "${WORK}/Caddyfile"
has "${WORK}/Caddyfile" "client_auth" "render: the dashboard site asks for a client certificate"
is "render: exactly one trust_pool file backs the pool" "1" "$(grep -c 'trust_pool file' "${WORK}/Caddyfile")"
is "render: the client-auth mode is require_and_verify" "1" "$(grep -c 'mode require_and_verify' "${WORK}/Caddyfile")"

# ---- pipeline wiring ------------------------------------------------------
has "$CI" "bash tests/origin-mtls/run-test.sh" "ci.yml runs this harness"
has "$CI" "origin-mtls" "ci.yml path gate includes tests/origin-mtls"
hasnt "$PROVISION_SH" 'CF_AOP_CA_PEM="$(q' "010 does not source the mTLS CA from a secret var"

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
