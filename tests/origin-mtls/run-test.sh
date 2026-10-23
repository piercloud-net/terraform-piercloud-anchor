#!/usr/bin/env bash
# tests/origin-mtls/run-test.sh — origin-mTLS trust-anchor proofs (issue #202).
#
# CloudFront presents a client certificate signed by the self-held origin CA;
# the anchor's Caddy verifies it against that CA in the same
# `client_auth require_and_verify` pool the retired Cloudflare AOP bundle uses.
# This harness pins:
#   - the committed `scripts/origin-mtls-ca.pem`: one X.509 CA cert, the exact
#     fingerprint (a silent CA swap must red), self-signed, CA:TRUE, ~10 years;
#   - the wiring: 020 reads the committed PUBLIC file (missing or empty is fatal)
#     and exports ORIGIN_MTLS_CA_PEM into the piped on-box script; 010 accepts
#     exactly one self-signed CA:TRUE root, then discards the CA and the
#     assembled pool once the 0644 pool is written;
#   - the ci.yml path gate: a CA-only change must run this harness;
#   - the REAL pool-construction span (extracted, never a copy): mTLS-only,
#     AOP-only, both (ordered), key-bearing, two roots, a non-CA leaf, trailing
#     DER, garbage, STATUS_HOST without a CA, and the empty state;
#   - the REAL origin stanza builder (extracted, never hand-written): the
#     client_auth block is `require_and_verify` over one `trust_pool file`, and
#     the render embeds that stanza;
#   - the live-probe contract text: the cert-less probe accepts only a
#     client-auth TLS alert; the edge pull requires HTTP 200.
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
has "$ANCHOR_020" 'refusing to provision an anchor without the origin-mTLS trust anchor' "020 dies when the committed CA is missing or empty"
hasnt "$ANCHOR_020" 'origin-mTLS will not be enforced' "020 no longer downgrades a missing CA to a warning"
has "$PROVISION_SH" 'ORIGIN_MTLS_CA_PEM=""  # same' "010 discards the CA from memory after writing the pool"
if grep -qE '^CLIENT_CA_POOL="" +# same' "$PROVISION_SH"; then ok "010 discards the assembled client-auth pool too (F4)"; else bad "010 does not discard CLIENT_CA_POOL after writing the pool (F4)"; fi
has "$PROVISION_SH" 'must be certificate-only (public trust anchor)' "010 refuses a key-bearing ORIGIN_MTLS_CA_PEM"
has "$PROVISION_SH" 'client-auth pool is not a bounded PEM certificate bundle' "010 validates the combined pool"
has "$PROVISION_SH" 'exactly one self-signed X.509 certificate with CA:TRUE' "010 states the one-root contract in its refusal (F2)"

# ---- ci.yml path gate (F1): a CA-only change must run this harness ---------
gate_line="$(grep -m1 -F "grep -qE '^(\\.github/scripts/" "$CI" || true)"
is "the ci.yml path-gate line is unique" "1" "$(grep -cF "grep -qE '^(\\.github/scripts/" "$CI" || true)"
gate="$(printf '%s\n' "$gate_line" | sed -e "s/^.*grep -qE '//" -e "s/' <<<.*//")"
gate_hits() { printf '%s\n' "$1" | grep -qE "$gate"; }
if gate_hits "scripts/origin-mtls-ca.pem"; then ok "the path gate runs the harness for a CA-only change (scripts/origin-mtls-ca.pem)"; else bad "the path gate SKIPs a CA-only change (scripts/origin-mtls-ca.pem)"; fi
if gate_hits "scripts/010-provision.sh" && gate_hits "tests/origin-mtls/run-test.sh"; then ok "the path gate runs the harness for the provisioner and the harness itself"; else bad "the path gate misses the provisioner or this harness"; fi
if gate_hits "docs/usage.md" || gate_hits "README.md"; then bad "the path gate matches docs-only changes"; else ok "the path gate still skips docs-only changes"; fi

# ---- real functions + the real pool span ----------------------------------
extract_fn() { # $1 = function name; prints the function body from 010
  awk -v name="$1" '$0 ~ ("^" name "\\(\\) \\{") { p = 1 } p { print } p && /^}/ { exit }' "$PROVISION_SH"
}
for fn in origin_ca_cert_pem_ok origin_ca_chain_blocks origin_ca_block_der_exact origin_ca_blocks_parse origin_ca_aop_deployed origin_mtls_ca_single_root; do
  extract_fn "$fn" > "${WORK}/${fn}.src"
  [ -s "${WORK}/${fn}.src" ] || { bad "could not extract ${fn} from ${PROVISION_SH}"; printf '\n%s passed, %s failed\n' "$pass" "$fail"; exit 1; }
  # shellcheck disable=SC1090
  source "${WORK}/${fn}.src"
done
b="$(grep -n -m1 '^AOP_TLS=""$' "$PROVISION_SH" | cut -d: -f1)"
e="$(grep -nE -m1 '^CLIENT_CA_POOL="" +# same' "$PROVISION_SH" | cut -d: -f1)"
[ -n "$b" ] && [ -n "$e" ] && [ "$b" -lt "$e" ] || { bad "the client-auth pool span markers are missing/ambiguous"; printf '\n%s passed, %s failed\n' "$pass" "$fail"; exit 1; }
sed -n "${b},${e}p" "$PROVISION_SH" > "${WORK}/pool.src"
grep -Fq 'client-auth pool deployed' "${WORK}/pool.src" || bad "the extracted span is not the pool construction"

# Run the real span in a subshell: $1 = CF_AOP value, $2 = mTLS value; prints
# the resulting flags and the residual CLIENT_CA_POOL length, or DIE:<message>
# when the span refuses. STATUS_HOST may be passed in the environment.
# shellcheck disable=SC2034  # CADDY_AOP_CA / CF_AOP_CA_PEM / ORIGIN_MTLS_CA_PEM are read by the sourced pool span
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
  printf 'AOP_TLS=%s MTLS_TLS=%s POOL=%s CLIENT_POOL_LEN=%s\n' "${AOP_TLS}" "${MTLS_TLS}" "$(grep -cE '^-----BEGIN CERTIFICATE-----[[:space:]]*$' "${CADDY_AOP_CA}" 2>/dev/null || true)" "${#CLIENT_CA_POOL}"
)

# Real CA + synthetic roots/leaves (openssl, offline).
mtls_pem="$(cat "$CA_FILE")"
aop_key="${WORK}/aop.key"
aop_pem="$(openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$aop_key" -out /dev/stdout -days 1 -subj '/CN=harness-aop' 2>/dev/null)"
second_pem="$(openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "${WORK}/second.key" -out /dev/stdout -days 1 -subj '/CN=harness-second-root' -addext 'basicConstraints=critical,CA:TRUE' 2>/dev/null)"
leaf_pem="$(openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "${WORK}/leaf.key" -out /dev/stdout -days 1 -subj '/CN=harness-leaf' -addext 'basicConstraints=critical,CA:FALSE' -addext 'extendedKeyUsage=clientAuth' 2>/dev/null)"
[ -n "$aop_pem" ] && [ -n "$second_pem" ] && [ -n "$leaf_pem" ] || { bad "openssl could not mint the harness roots/leaf"; printf '\n%s passed, %s failed\n' "$pass" "$fail"; exit 1; }

out="$(run_pool "" "$mtls_pem")" || true
is "pool: mTLS only enables client auth and leaves no residual pool" "AOP_TLS=yes MTLS_TLS=yes POOL=1 CLIENT_POOL_LEN=0" "$out"
out="$(run_pool "$aop_pem" "")" || true
is "pool: AOP only keeps the legacy behaviour (no mTLS flag)" "AOP_TLS=yes MTLS_TLS= POOL=1 CLIENT_POOL_LEN=0" "$out"
out="$(run_pool "$aop_pem" "$mtls_pem")" || true
is "pool: both sources land in one ordered pool" "AOP_TLS=yes MTLS_TLS=yes POOL=2 CLIENT_POOL_LEN=0" "$out"
out="$(run_pool "" "")" || true
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
priv_pem="$(printf -- '-----BEGIN EC %s KEY-----\nMHcCAQEEIPqykxYO1HEjq8lTO8Gj58MMFhV2CAheP05wnl9Wr1rhoAoGCCqGSM49\n-----END EC %s KEY-----' PRIVATE PRIVATE)"
out="$(run_pool "" "${mtls_pem}
${priv_pem}")" || true
case "$out" in
  DIE:*'certificate-only'*) ok "pool: a key-bearing mTLS value is refused" ;;
  *) bad "pool: a key-bearing mTLS value was not refused (got '$out')" ;;
esac

# ---- one bounded CA:TRUE root (F2) ----------------------------------------
if origin_mtls_ca_single_root "$CA_FILE"; then ok "origin_mtls_ca_single_root accepts the committed CA"; else bad "origin_mtls_ca_single_root refused the committed CA"; fi
printf '%s\n%s\n' "$mtls_pem" "$second_pem" > "${WORK}/two-roots.pem"
printf '%s\n' "$leaf_pem" > "${WORK}/leaf.pem"
if origin_mtls_ca_single_root "${WORK}/two-roots.pem"; then bad "two concatenated CA:TRUE roots pass origin_mtls_ca_single_root"; else ok "two concatenated CA:TRUE roots are refused by origin_mtls_ca_single_root"; fi
if origin_mtls_ca_single_root "${WORK}/leaf.pem"; then bad "a non-CA leaf passes origin_mtls_ca_single_root"; else ok "a non-CA leaf is refused by origin_mtls_ca_single_root"; fi
out="$(run_pool "" "$(cat "${WORK}/two-roots.pem")")" || true
case "$out" in
  DIE:*'exactly one self-signed'*) ok "pool: two concatenated roots die (one bounded root for ORIGIN_MTLS_CA_PEM)" ;;
  *) bad "pool: two concatenated roots were not refused (got '$out')" ;;
esac
out="$(run_pool "" "$(cat "${WORK}/leaf.pem")")" || true
case "$out" in
  DIE:*'exactly one self-signed'*) ok "pool: a non-CA leaf dies (no CA:TRUE)" ;;
  *) bad "pool: a non-CA leaf was not refused (got '$out')" ;;
esac
# The combined AOP+mTLS pool may legitimately hold two CAs: the one-root rule
# is for the mTLS value only, so the ordered two-source pool still assembles.
out="$(run_pool "$aop_pem" "$mtls_pem")" || true
is "pool: AOP plus the one mTLS root still assembles two CAs" "AOP_TLS=yes MTLS_TLS=yes POOL=2 CLIENT_POOL_LEN=0" "$out"

# ---- STATUS_HOST without any client-auth CA (review finding) ---------------
out="$(STATUS_HOST=status.example.test run_pool "" "")" || true
case "$out" in
  DIE:*'STATUS_HOST is set'*) ok "pool: STATUS_HOST without any client-auth CA refuses to serve the edge" ;;
  *) bad "pool: STATUS_HOST without a client-auth CA was not refused (got '$out')" ;;
esac

# ---- the REAL origin stanza builder (F3): extracted, compiled, never copied --
stanza_b="$e"
[ "$(sed -n "$((stanza_b + 1))p" "$PROVISION_SH")" = 'if [ "${ORIGIN_TLS}" = "1" ]; then' ] \
  || { bad "the origin stanza builder is not where the harness expects it"; printf '\n%s passed, %s failed\n' "$pass" "$fail"; exit 1; }
stanza_e="$(awk -v s="$stanza_b" 'NR > s && /^fi$/ { print NR; exit }' "$PROVISION_SH")"
sed -n "$((stanza_b + 1)),${stanza_e}p" "$PROVISION_SH" > "${WORK}/stanza.src"
# shellcheck disable=SC2034  # ORIGIN_TLS / AOP_TLS are read by the sourced stanza builder
stanza_out="$(
  ORIGIN_TLS=1
  AOP_TLS=yes
  eval "$(grep -E '^CADDY_(ORIGIN_CRT|ORIGIN_KEY|AOP_CA)=' "$PROVISION_SH")"
  # shellcheck disable=SC1090
  source "${WORK}/stanza.src"
  printf '%s\n' "${DASH_TLS_STANZA}"
)"
printf '%s\n' "$stanza_out" > "${WORK}/stanza.out"
has "${WORK}/stanza.out" "mode require_and_verify" "F3: the compiled origin builder requires and verifies the client certificate"
has "${WORK}/stanza.out" "trust_pool file /etc/caddy/aop-ca.pem" "F3: the compiled origin builder trusts the single pool file"
has "${WORK}/stanza.out" "tls /etc/caddy/origin.crt /etc/caddy/origin.key {" "F3: the compiled builder keeps the origin certificate pair"
is "F3: exactly one client_auth block is compiled" "1" "$(grep -c 'client_auth {' "${WORK}/stanza.out")"
# F1 (#236 verify): with NO origin pair on the box the dashboard still gets
# automatic HTTPS — the client-auth stanza must be emitted there too, or the
# edge is admitted on the shared header alone.
auto_out="$(
  ORIGIN_TLS=0
  AOP_TLS=yes
  eval "$(grep -E '^CADDY_(ORIGIN_CRT|ORIGIN_KEY|AOP_CA)=' "$PROVISION_SH")"
  # shellcheck disable=SC1090
  source "${WORK}/stanza.src"
  printf '%s\n' "${DASH_TLS_STANZA}"
)"
printf '%s\n' "$auto_out" > "${WORK}/stanza-auto.out"
is "F1: the automatic-HTTPS branch still compiles one client_auth block" "1" \
  "$(grep -c 'client_auth {' "${WORK}/stanza-auto.out")"
has "${WORK}/stanza-auto.out" "mode require_and_verify" \
  "F1: the automatic-HTTPS branch requires and verifies the client certificate"
has "${WORK}/stanza-auto.out" "trust_pool file /etc/caddy/aop-ca.pem" \
  "F1: the automatic-HTTPS branch trusts the same single pool file"
hasnt "${WORK}/stanza-auto.out" "tls /etc/caddy/origin.crt" \
  "F1: the automatic-HTTPS branch does not claim a pair it does not have"

# ---- render stanza (real render span, real builder output) ----------------
render_b="$(grep -n -m1 'BEGIN CADDY RENDER' "$PROVISION_SH" | cut -d: -f1)"
render_e="$(grep -n -m1 'END CADDY RENDER' "$PROVISION_SH" | cut -d: -f1)"
sed -n "$((render_b + 1)),$((render_e - 1))p" "$PROVISION_SH" > "${WORK}/render.src"
# shellcheck disable=SC2034  # the render inputs are read by the sourced render span
(
  # shellcheck disable=SC1090
  source "${WORK}/render.src"
  ORIGIN_TLS=1
  AOP_TLS=yes
  eval "$(grep -E '^CADDY_(ORIGIN_CRT|ORIGIN_KEY|AOP_CA)=' "$PROVISION_SH")"
  # shellcheck disable=SC1090
  source "${WORK}/stanza.src"
  CADDY_HTTP_ADDR=":80"
  CADDY_CHALLENGE_DIR="${WORK}/acme"
  TANG_PORT="8081"
  GATUS_PORT="8080"
  CADDY_SKIP_HTTPS=""
  STATUS_HOST="status.example.test"
  CLOUDFRONT_ORIGIN_SECRET="harness-secret"
  MAIN_BOX_IPV4="192.0.2.10"
  CLOUDFRONT_ORIGIN_CIDRS="192.0.2.0/24"
  render_caddyfile
) > "${WORK}/Caddyfile"
has "${WORK}/Caddyfile" "client_auth" "render: the dashboard site asks for a client certificate"
is "render: exactly one trust_pool file backs the pool" "1" "$(grep -c 'trust_pool file' "${WORK}/Caddyfile")"
is "render: the client-auth mode is require_and_verify" "1" "$(grep -c 'mode require_and_verify' "${WORK}/Caddyfile")"

# ---- live-probe contract (F5, F12): pinned text of the edge checks --------
has "$PROVISION_SH" 'curl -sSk --max-time 10 --resolve' "the cert-less probe reports curl errors (-S) and stays -k"
has "$PROVISION_SH" "alert (certificate required|bad certificate)" "the cert-less probe accepts only a client-auth TLS alert"
has "$PROVISION_SH" "-w '%{http_code}'" "the edge pull captures the HTTP status code"
has "$PROVISION_SH" '[ "${edge_code}" = "200" ]' "the edge pull requires HTTP 200 (not exit 0)"
hasnt "$PROVISION_SH" 'curl -sSf --max-time 20' "the edge pull no longer treats any exit-0 response as success"
has "$PROVISION_SH" 'redeploy the previous release (the committed origin-mTLS CA ships in the release' "the mTLS rollback names the release redeploy, not the AOP secret (F5)"
has "$PROVISION_SH" 're-add the repository secret and the distribution origin header FIRST, then revert the anchor, never the anchor alone' "the post-cutover rollback keeps the docs/dr.md ordering (header and secret first, anchor last)"
has "$ROOT/docs/dr.md" 'never revert the anchor alone' "docs/dr.md states the same post-cutover ordering the runbook text cites"

# ---- pipeline wiring ------------------------------------------------------
has "$CI" "bash tests/origin-mtls/run-test.sh" "ci.yml runs this harness"
has "$CI" "origin-mtls" "ci.yml path gate includes tests/origin-mtls"
hasnt "$PROVISION_SH" 'CF_AOP_CA_PEM="$(q' "010 does not source the mTLS CA from a secret var"

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
