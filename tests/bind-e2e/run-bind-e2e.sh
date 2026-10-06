#!/usr/bin/env bash
# run-bind-e2e.sh — CI bind-proof: the Caddy→tang path, proven with clevis.
#
# Topology (mirrors production, loopback edition): mock tang on
# 127.0.0.1:$MOCK_PORT (behind), real `caddy` on :$CADDY_PORT
# (front, running the repo's REAL rendered Caddyfile — extracted from
# scripts/010-provision.sh at runtime, never a copy), stub backend for
# the dashboard vhost. Then, all THROUGH Caddy:
#   clevis luks bind  +  clevis luks list  +  clevis encrypt/decrypt  +
#   clevis luks unlock -n (real dm-crypt open) on loopback LUKS volumes.
# Negatives: unknown Host is aborted by Caddy; wrong thumbprint bind
# is refused by clevis.
#
# Cred-free, no secrets, no cloud. Must run as root (loop setup,
# cryptsetup); CI calls it via sudo. Time-boxed for a <10 min job.
set -euo pipefail

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HARNESS_DIR}/../.." && pwd)"
PROVISION_SH="${REPO_ROOT}/scripts/010-provision.sh"

CADDY_PORT="${CADDY_PORT:-18080}"
MOCK_PORT="${MOCK_PORT:-18081}"
STUB_PORT="${STUB_PORT:-18082}"
# Gate-proof ports (call D): a dedicated dashboard render + stub, served
# before the main .ci serve so no other Caddy holds the admin endpoint.
GATE_TLS_PORT="${GATE_TLS_PORT:-18443}"
GATE_HTTP_PORT="${GATE_HTTP_PORT:-18084}"
GATE_STUB_PORT="${GATE_STUB_PORT:-18085}"
AOP_SNI="prodprobe.status.piercloud.net"
TENANT_USER="${TENANT_USER:-citest}"
CADDY_VERSION="2.11.4"
CADDY_TGZ="caddy_${CADDY_VERSION}_linux_amd64.tar.gz"
CADDY_URL="https://github.com/caddyserver/caddy/releases/download/v${CADDY_VERSION}/${CADDY_TGZ}"
# Pinned SHA-512 of the upstream release asset (caddy ships SHA512 checksums).
CADDY_SHA512="8220d1f013b6f27510247b2360c9e0ca9f018feebd82515f07635318b34ff9777ccc8fd0b6e6f2486ce3a33fe389fbb7db12d05baa474f4587509fb4f5ebf1c9"

WORK="$(mktemp -d /tmp/bind-e2e.XXXXXX)"
START="$(date +%s)"
log() { printf '\n==> %s\n' "$*"; }
die() { printf '\nFAIL: %s\n' "$*" >&2; exit 1; }

cleanup() {
  # Best-effort teardown in reverse bring-up order; never masks the failure.
  [ -n "${RT_PID:-}" ] && kill "${RT_PID}" 2>/dev/null || true
  [ -n "${GATE_PID:-}" ] && kill "${GATE_PID}" 2>/dev/null || true
  [ -n "${GATE_STUB_PID:-}" ] && kill "${GATE_STUB_PID}" 2>/dev/null || true
  cryptsetup close real-tang 2>/dev/null || true
  [ -n "${CADDY_PID:-}" ] && kill "${CADDY_PID}" 2>/dev/null || true
  [ -n "${AOP_CADDY_PID:-}" ] && kill "${AOP_CADDY_PID}" 2>/dev/null || true
  [ -n "${MOCK_PID:-}" ] && kill "${MOCK_PID}" 2>/dev/null || true
  [ -n "${STUB_PID:-}" ] && kill "${STUB_PID}" 2>/dev/null || true
  cryptsetup close e2e-slot 2>/dev/null || true
  [ -n "${DEV1:-}" ] && losetup -d "${DEV1}" 2>/dev/null || true
  [ -n "${DEV2:-}" ] && losetup -d "${DEV2}" 2>/dev/null || true
  rm -rf "${WORK}"
}
trap cleanup EXIT

[ "$(id -u)" -eq 0 ] || die "run as root (CI calls this via sudo: loop setup + cryptsetup need it)"
[ -f "${PROVISION_SH}" ] || die "provision script not found at ${PROVISION_SH}"

# ---------------------------------------------------------------- 1. deps
log "Installing harness deps (apt)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq clevis clevis-luks cryptsetup jose curl jq python3 python3-cryptography tang >/dev/null
command -v clevis >/dev/null || die "clevis missing after apt"
command -v jq >/dev/null || die "jq missing after apt (the collapse proof and the provision probe need it)"
command -v cryptsetup >/dev/null || die "cryptsetup missing after apt"
python3 -c "import cryptography" 2>/dev/null || die "python3-cryptography missing after apt"
# Drift canary: the runner's jose must still speak the mock's curve. If a
# future jose changes ECMR generation, this fails LOUDLY here instead of
# mid-bind with a cryptic clevis error.
jose jwk gen -i '{"alg":"ECMR","crv":"P-521"}' >/dev/null || die "runner jose cannot generate ECMR/P-521 keys — mock curve drift, see tests/bind-e2e/README"
modprobe loop 2>/dev/null || true
modprobe dm-crypt 2>/dev/null || true
losetup -f >/dev/null 2>&1 || die "no loop device available (need loop + dm-crypt on the runner)"

# ---------------------------------------------------------------- 2. caddy
log "Fetching real caddy ${CADDY_VERSION} (SHA-pinned)"
curl -fsSL --max-time 120 -o "${WORK}/${CADDY_TGZ}" "${CADDY_URL}"
echo "${CADDY_SHA512}  ${WORK}/${CADDY_TGZ}" > "${WORK}/caddy.sha512"
sha512sum -c "${WORK}/caddy.sha512" || die "caddy tarball SHA mismatch — refusing to run it"
tar -xzf "${WORK}/${CADDY_TGZ}" -C "${WORK}"
CADDY_BIN="${WORK}/caddy"
[ -x "${CADDY_BIN}" ] || die "caddy binary missing from release asset"
"${CADDY_BIN}" version

# ---------------------------------------------------------------- 3. render
log "Rendering the REAL Caddyfile (extracted from scripts/010-provision.sh)"
BEGIN_N=$(grep -c 'BEGIN CADDY RENDER' "${PROVISION_SH}" || true)
END_N=$(grep -c 'END CADDY RENDER' "${PROVISION_SH}" || true)
[ "${BEGIN_N}" = "1" ] && [ "${END_N}" = "1" ] || die "Caddy render markers missing/ambiguous in ${PROVISION_SH} — refusing a copy"
b=$(grep -n 'BEGIN CADDY RENDER' "${PROVISION_SH}" | cut -d: -f1)
e=$(grep -n 'END CADDY RENDER' "${PROVISION_SH}" | cut -d: -f1)
sed -n "$((b+1)),$((e-1))p" "${PROVISION_SH}" > "${WORK}/render.src"
# shellcheck disable=SC1090
source "${WORK}/render.src"
command -v caddy_status_names >/dev/null || die "extraction did not yield caddy_status_names"
command -v render_caddyfile >/dev/null || die "extraction did not yield render_caddyfile"
# Production origin-range constant, extracted — never retyped, cannot drift.
eval "$(grep '^CLOUDFRONT_ORIGIN_CIDRS=' "${PROVISION_SH}")"
[ -n "${CLOUDFRONT_ORIGIN_CIDRS:-}" ] || die "CLOUDFRONT_ORIGIN_CIDRS extraction failed"
export TENANT_USER TANG_PORT="${MOCK_PORT}" GATUS_PORT="${STUB_PORT}"
export CADDY_CHALLENGE_DIR="${WORK}/acme-challenge"
# Bare :port (like production :80): matches ANY Host with plain HTTP, so the
# exact-Host @status matcher and the abort catch-all are exercised exactly
# like prod. (http://127.0.0.1:port would pin Host matching to loopback and
# bypass the matchers; bare IP:port makes Caddy serve internal-CA HTTPS.)
export CADDY_HTTP_ADDR=":${CADDY_PORT}" CADDY_SKIP_HTTPS=1
export DASH_TLS_STANZA="	# harness: no :443 block (CADDY_SKIP_HTTPS); tang never touches :443."
export STATUS_HOST="" STATUS_MATCH=""
caddy_status_names
render_caddyfile > "${WORK}/Caddyfile.ci"
[ "${STATUS_HOST}" = "citest.status.piercloud.net" ] || die "sanitize drift: STATUS_HOST=${STATUS_HOST}"
grep -q "reverse_proxy 127.0.0.1:${MOCK_PORT}" "${WORK}/Caddyfile.ci" || die "render does not point /adv|/rec at the mock"
grep -q "reverse_proxy 127.0.0.1:${STUB_PORT}" "${WORK}/Caddyfile.ci" || die "render does not point the status host at the stub"
grep -q "host ${STATUS_HOST}" "${WORK}/Caddyfile.ci" || die "render lacks the exact-Host status matcher"
log "CI Caddyfile rendered (status host: ${STATUS_HOST})"
# The shipped shape must still parse after the refactor: render it with
# production addressing and validate (never served here).
( export CADDY_HTTP_ADDR=":80" CADDY_SKIP_HTTPS="" TANG_PORT="8081" GATUS_PORT="8080"
export TENANT_USER=prodprobe STATUS_HOST="" STATUS_MATCH=""
export CLOUDFRONT_ORIGIN_SECRET=harness-origin-secret MAIN_BOX_IPV4=192.0.2.99
export DASH_TLS_STANZA="	# No origin pair deployed: Caddy automatic HTTPS (HTTP-01 via :80 below)."
caddy_status_names
render_caddyfile > "${WORK}/Caddyfile.prodshape" )
HOME="${WORK}" "${CADDY_BIN}" validate --config "${WORK}/Caddyfile.prodshape" --adapter caddyfile
grep -q "@unauthorized" "${WORK}/Caddyfile.prodshape" || die "prodshape render lacks the CloudFront origin gate"
grep -q "harness-origin-secret" "${WORK}/Caddyfile.prodshape" || die "prodshape render lacks the origin secret in the gate"
grep -q "192.0.2.99/32" "${WORK}/Caddyfile.prodshape" || die "prodshape render lacks the main-box bypass"
HOME="${WORK}" "${CADDY_BIN}" validate --config "${WORK}/Caddyfile.ci" --adapter caddyfile
log "Both renders validate (CI shape + shipped shape)"

# AOP shape: compile the REAL stanza builder (extracted from its first
# column-0 guard line up to the column-0 closing `fi`; later indented guards
# belong to the probe section) with a CA bundle + origin pair present, so a
# directive rename (require_and_verify / trust_pool file) fails HERE and not
# only on the next live dispatch (review lens LENS1-7).
aop_b=$(grep -n -m1 '^if \[ "${ORIGIN_TLS}" = "1" \]; then$' "${PROVISION_SH}" | cut -d: -f1)
[ -n "${aop_b}" ] || die "AOP stanza builder not found in ${PROVISION_SH}"
aop_e=$(awk -v s="${aop_b}" 'NR>s && /^fi$/{print NR; exit}' "${PROVISION_SH}")
[ -n "${aop_e}" ] || die "AOP stanza builder end (column-0 fi) not found"
sed -n "${aop_b},${aop_e}p" "${PROVISION_SH}" > "${WORK}/aop-stanza.src"
openssl req -x509 -newkey rsa:2048 -keyout "${WORK}/aop-ca.key" -out "${WORK}/aop-ca.pem" \
  -days 1 -nodes -subj "/CN=harness-aop-ca" >/dev/null 2>&1 || die "openssl could not mint the harness AOP CA"
openssl req -x509 -newkey rsa:2048 -keyout "${WORK}/origin.key" -out "${WORK}/origin.crt" \
  -days 1 -nodes -subj "/CN=harness-origin" >/dev/null 2>&1 || die "openssl could not mint the harness origin pair"
( export CADDY_HTTP_ADDR=":443" CADDY_SKIP_HTTPS="" TANG_PORT="8081" GATUS_PORT="8080"
  export TENANT_USER=prodprobe STATUS_HOST="" STATUS_MATCH=""
  export CLOUDFRONT_ORIGIN_SECRET=harness-origin-secret MAIN_BOX_IPV4=192.0.2.99
  export ORIGIN_TLS="1" AOP_TLS="yes"
  export CADDY_ORIGIN_CRT="${WORK}/origin.crt" CADDY_ORIGIN_KEY="${WORK}/origin.key" CADDY_AOP_CA="${WORK}/aop-ca.pem"
  # shellcheck disable=SC1090
  source "${WORK}/aop-stanza.src"
  caddy_status_names
  render_caddyfile > "${WORK}/Caddyfile.aop" )
grep -q "client_auth" "${WORK}/Caddyfile.aop" || die "AOP render lacks the client_auth block"
HOME="${WORK}" "${CADDY_BIN}" validate --config "${WORK}/Caddyfile.aop" --adapter caddyfile
log "AOP render validates (real client_auth stanza compiled)"

# Per-anchor Origin CA render (issue #123, G1 render half): the PRODUCTION
# shape — ORIGIN_TLS=1 with the origin-ca pair paths + AOP — goes through the
# real render_caddyfile and caddy must compile it. A path/semantics drift in
# the pair selection or the stanza builder fails here, not on a live dispatch.
openssl req -x509 -newkey rsa:2048 -keyout "${WORK}/origin-ca.key" -out "${WORK}/origin-ca.crt" \
  -days 1 -nodes -subj "/CN=harness-origin-ca" >/dev/null 2>&1 || die "openssl could not mint the harness origin-ca pair"
( export CADDY_HTTP_ADDR=":443" CADDY_SKIP_HTTPS="" TANG_PORT="8081" GATUS_PORT="8080"
  export TENANT_USER=prodprobe STATUS_HOST="" STATUS_MATCH=""
  export CLOUDFRONT_ORIGIN_SECRET=harness-origin-secret MAIN_BOX_IPV4=192.0.2.99
  export ORIGIN_TLS="1" ORIGIN_CA_PAIR="1" AOP_TLS="yes"
  export CADDY_ORIGIN_CRT="${WORK}/origin-ca.crt" CADDY_ORIGIN_KEY="${WORK}/origin-ca.key" CADDY_AOP_CA="${WORK}/aop-ca.pem"
  # The REAL stanza builder (extracted above) must pick up the per-anchor
  # paths — never a hand-built copy of the stanza.
  # shellcheck disable=SC1090
  source "${WORK}/aop-stanza.src"
  caddy_status_names
  render_caddyfile > "${WORK}/Caddyfile.origin-ca" )
grep -q "tls ${WORK}/origin-ca.crt ${WORK}/origin-ca.key" "${WORK}/Caddyfile.origin-ca" \
  || die "origin-ca render does not reference the per-anchor pair paths"
grep -q "client_auth" "${WORK}/Caddyfile.origin-ca" || die "origin-ca render lacks the client_auth block"
grep -q "trust_pool file ${WORK}/aop-ca.pem" "${WORK}/Caddyfile.origin-ca" || die "origin-ca render lost the AOP trust pool"
if grep -vE '^[[:space:]]*#' "${WORK}/Caddyfile.origin-ca" | grep -q "on_demand"; then
  die "origin-ca render uses on_demand TLS — explicit per-site blocks only"
fi
HOME="${WORK}" "${CADDY_BIN}" validate --config "${WORK}/Caddyfile.origin-ca" --adapter caddyfile
log "Per-anchor origin-ca render validates (real pair + AOP stanza compiled)"

# ---------------------------------------------------------------- 3e. gate
# CloudFront origin gate (call D) — request-level proof. Caddy 2.11.4 adapts
# `abort` AFTER `handle`, so a site-level gate would sit behind the dashboard
# catch-all handle and never execute; the gate lives INSIDE that handle
# (scripts/010-provision.sh) and this section proves it BOTH ways: the
# adapted route order (test-scoped AND production-shape), then a served
# peer/header matrix. Loopback is exempt (the on-box probes connect from
# it), so the matrix uses MAIN_BOX_IPV4=127.0.0.2 and a test-scoped admitted
# range 127.0.0.3/32 (production carries the 81 public AWS prefixes; the
# render reads CLOUDFRONT_ORIGIN_CIDRS). The matrix includes a forged
# client-IP header from an admitted peer: the gate must match the DIRECT
# peer (remote_ip), never the trusted-proxy-resolved client, or a
# viewer-supplied header would be spoofable through the edge.
log "Gate: adapted route order + served peer/header matrix"
GATE_HOST="gateprobe.status.piercloud.net:${GATE_TLS_PORT}"
# The cert SAN must cover the site host or Caddy falls back to ACME (which
# would hang/fail here): mint it for the exact host.
openssl req -x509 -newkey rsa:2048 -keyout "${WORK}/gate.key" -out "${WORK}/gate.crt" \
  -days 1 -nodes -subj "/CN=${GATE_HOST%:*}" -addext "subjectAltName=DNS:${GATE_HOST%:*}" >/dev/null 2>&1 \
  || die "openssl could not mint the gate pair"
( export CADDY_HTTP_ADDR=":${GATE_HTTP_PORT}" CADDY_SKIP_HTTPS="" TANG_PORT="${MOCK_PORT}" GATUS_PORT="${GATE_STUB_PORT}"
  export TENANT_USER=gateprobe STATUS_HOST="${GATE_HOST}" STATUS_MATCH=""
  export CLOUDFRONT_ORIGIN_CIDRS="127.0.0.3/32" CLOUDFRONT_ORIGIN_SECRET="harness-origin-secret" MAIN_BOX_IPV4="127.0.0.2"
  export DASH_TLS_STANZA="	tls ${WORK}/gate.crt ${WORK}/gate.key"
  caddy_status_names
  render_caddyfile > "${WORK}/Caddyfile.gate" )
# Serve copy: one global option added so the test binds no privileged :80
# (Caddy's auto HTTP->HTTPS redirect listener); the dashboard block under
# test is byte-identical to the render.
awk 'NR == 1 { print; next } /^\{$/ { print; print "\tauto_https disable_redirects"; next } { print }' \
  "${WORK}/Caddyfile.gate" > "${WORK}/Caddyfile.gate.serve"
HOME="${WORK}" "${CADDY_BIN}" adapt --config "${WORK}/Caddyfile.gate" --adapter caddyfile --pretty > "${WORK}/Caddyfile.gate.json" \
  || die "gate render does not adapt"
assert_gate_order() { # $1 = adapted config json, $2 = site host
python3 - "$1" "$2" <<'PY' || die "adapted route order puts the origin gate behind the catch-all handle (dead code)"
import json, sys
cfg = json.load(open(sys.argv[1]))
host = sys.argv[2]
site = None
for srv in cfg["apps"]["http"]["servers"].values():
    for rt in srv.get("routes", []):
        for m in rt.get("match", []):
            if host in m.get("host", []):
                site = rt
if site is None:
    print(f"dashboard route for {host} not found")
    sys.exit(1)
catchall = None
for grp in site["handle"][0]["routes"]:
    h0 = grp["handle"][0]
    if "match" not in grp and h0.get("handler") == "subroute":
        catchall = grp
if catchall is None:
    print("catch-all handle group not found")
    sys.exit(1)
inner = [r["handle"][0] for r in catchall["handle"][0]["routes"]]
kinds = ["abort" if h.get("handler") == "static_response" and h.get("abort") else h.get("handler") for h in inner]
if kinds.count("abort") < 2 or "reverse_proxy" not in kinds:
    print(f"gate handlers missing from the catch-all handle: {kinds}")
    sys.exit(1)
if kinds.index("reverse_proxy") < max(i for i, k in enumerate(kinds) if k == "abort"):
    print(f"gate aborts after the reverse_proxy: {kinds}")
    sys.exit(1)
print(f"adapted gate order OK: {kinds}")
PY
}
assert_gate_order "${WORK}/Caddyfile.gate.json" "${GATE_HOST%:*}"
# Production-shape render: the real 81-prefix CLOUDFRONT_ORIGIN_CIDRS (the
# value extracted from 010 above, no test override) must adapt to the same
# gate order AND actually carry the production prefixes — the served matrix
# below uses a test-scoped range, and `caddy adapt` is CEL-blind, so the
# presence tooth below is what keeps a leaked override from passing.
( export CADDY_HTTP_ADDR=":${GATE_HTTP_PORT}" CADDY_SKIP_HTTPS="" TANG_PORT="${MOCK_PORT}" GATUS_PORT="${GATE_STUB_PORT}"
  export TENANT_USER=gateprobe STATUS_HOST="${GATE_HOST}" STATUS_MATCH=""
  export CLOUDFRONT_ORIGIN_SECRET="harness-origin-secret" MAIN_BOX_IPV4="127.0.0.2"
  export DASH_TLS_STANZA="	tls ${WORK}/gate.crt ${WORK}/gate.key"
  caddy_status_names
  render_caddyfile > "${WORK}/Caddyfile.gate.prod" )
HOME="${WORK}" "${CADDY_BIN}" adapt --config "${WORK}/Caddyfile.gate.prod" --adapter caddyfile --pretty > "${WORK}/Caddyfile.gate.prod.json" \
  || die "production-shape gate render does not adapt"
assert_gate_order "${WORK}/Caddyfile.gate.prod.json" "${GATE_HOST%:*}"
grep -q '130.176.88.0/21' "${WORK}/Caddyfile.gate.prod" || die "production-shape gate render does not carry the production ranges"
if grep -q '127.0.0.3/32' "${WORK}/Caddyfile.gate.prod"; then die "production-shape gate render carries the test range"; fi
mkdir -p "${WORK}/gate-stub" && printf 'STUBOK' > "${WORK}/gate-stub/index.html"
python3 -m http.server "${GATE_STUB_PORT}" --bind 127.0.0.1 --directory "${WORK}/gate-stub" >"${WORK}/gate-stub.log" 2>&1 &
GATE_STUB_PID=$!
HOME="${WORK}" "${CADDY_BIN}" run --config "${WORK}/Caddyfile.gate.serve" --adapter caddyfile >"${WORK}/caddy-gate.log" 2>&1 &
GATE_PID=$!
ok=0
for i in $(seq 1 30); do
  if curl -skf --max-time 3 --interface 127.0.0.2 --resolve "${GATE_HOST}:127.0.0.1" "https://${GATE_HOST}/" -o /dev/null; then ok=1; break; fi
  sleep 1
done
[ "${ok}" = "1" ] || { tail -20 "${WORK}/caddy-gate.log"; kill "${GATE_PID}" "${GATE_STUB_PID}" 2>/dev/null || true; die "gate test Caddy did not serve the dashboard"; }
gate_expect() { # $1 label, $2 source interface, $3 want (ok|abort); rest = extra curl args
  local label="$1" iface="$2" want="$3"; shift 3
  local code rc
  # An abort gives curl a non-zero rc (empty reply / stream error) — capture
  # it instead of letting `set -e` kill the harness before the assertion.
  set +e
  code="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 --interface "${iface}" --resolve "${GATE_HOST}:127.0.0.1" "$@" "https://${GATE_HOST}/" 2>/dev/null)"
  rc=$?
  set -e
  case "${want}" in
    ok)    [ "${code}" = "200" ] && log "gate OK: ${label}" || die "gate: ${label} expected 200, got ${code} (curl rc ${rc})" ;;
    abort) { [ "${code}" != "200" ] || [ "${rc}" -ne 0 ]; } && log "gate OK: ${label} (aborted, http ${code}, curl rc ${rc})" || die "gate: ${label} expected an abort, got 200" ;;
  esac
}
gate_expect "main box, no header passes"          127.0.0.2 ok
gate_expect "admitted peer, no header aborts"     127.0.0.3 abort
gate_expect "admitted peer, wrong header aborts"  127.0.0.3 abort -H 'X-Piercloud-Origin: wrong'
gate_expect "admitted peer, secret passes"        127.0.0.3 ok    -H 'X-Piercloud-Origin: harness-origin-secret'
gate_expect "outside peer, secret aborts"         127.0.0.4 abort -H 'X-Piercloud-Origin: harness-origin-secret'
gate_expect "outside peer, no header aborts"      127.0.0.4 abort
gate_expect "loopback, no header passes"          127.0.0.1 ok
gate_expect "admitted peer, forged viewer-IP header aborts" 127.0.0.3 abort -H 'CloudFront-Viewer-Address: 127.0.0.1'
kill "${GATE_PID}" "${GATE_STUB_PID}" 2>/dev/null || true
wait "${GATE_PID}" 2>/dev/null || true
log "Gate matrix passed (adapted order + 8 request cases)"

# ---------------------------------------------------------------- 4. serve
log "Starting mock tang + stub + caddy"
export TENANT_USER=citest TANG_PORT="${MOCK_PORT}" GATUS_PORT="${STUB_PORT}"
python3 "${HARNESS_DIR}/mock-tang.py" --port "${MOCK_PORT}" --thp-file "${WORK}/thp.txt" >"${WORK}/mock.log" 2>&1 &
MOCK_PID=$!
python3 "${HARNESS_DIR}/mock-tang.py" --stub --port "${STUB_PORT}" --stub-body "gatus-stub-ok" >"${WORK}/stub.log" 2>&1 &
STUB_PID=$!
for i in $(seq 1 30); do [ -f "${WORK}/thp.txt" ] && break; sleep 1; done
THP="$(cat "${WORK}/thp.txt" 2>/dev/null || true)"
[ -n "${THP}" ] || { cat "${WORK}/mock.log"; die "mock tang did not start"; }
ok=0
for i in $(seq 1 30); do
  if curl -sf "http://127.0.0.1:${STUB_PORT}/" -o /dev/null; then ok=1; break; fi
  sleep 1
done
[ "${ok}" = "1" ] || { cat "${WORK}/stub.log"; die "stub backend did not start"; }
log "Mock thumbprint: ${THP}"
HOME="${WORK}" "${CADDY_BIN}" run --config "${WORK}/Caddyfile.ci" --adapter caddyfile >"${WORK}/caddy.log" 2>&1 &
CADDY_PID=$!
ok=0
for i in $(seq 1 30); do
  if curl -sf "http://127.0.0.1:${CADDY_PORT}/adv" -o "${WORK}/via-caddy.json"; then ok=1; break; fi
  sleep 1
done
[ "${ok}" = "1" ] || { tail -30 "${WORK}/caddy.log"; die "caddy did not serve /adv"; }

# --- AOP handshake split, served for real (not just validated): a cert-less
# client must be rejected at the TLS layer, a client leaf signed by the
# trust-pool CA must be accepted. The vhost is minimal ON PURPOSE — built from
# the REAL stanza builder (extracted above), `respond` instead of the full
# render: the full render is validated twice already, and serving it here would
# drag in the tang site + admin endpoint + :80 redirects, none of which this
# assertion is about. CI runs as root, so :443 binds. (review lens LENS1R2-5)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${WORK}/aop-leaf.key" >/dev/null 2>&1 || die "openssl could not mint the harness client key"
chmod 600 "${WORK}/aop-leaf.key"
openssl req -new -key "${WORK}/aop-leaf.key" -subj "/CN=aop-client" \
  -out "${WORK}/aop-leaf.csr" >/dev/null 2>&1 || die "openssl could not build the harness client CSR"
printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n' > "${WORK}/aop-leaf.ext"
openssl x509 -req -in "${WORK}/aop-leaf.csr" -CA "${WORK}/aop-ca.pem" -CAkey "${WORK}/aop-ca.key" \
  -CAcreateserial -CAserial "${WORK}/aop-ca.srl" -days 1 -sha256 -extfile "${WORK}/aop-leaf.ext" \
  -out "${WORK}/aop-leaf.crt" >/dev/null 2>&1 || die "openssl could not sign the harness client leaf"
( export ORIGIN_TLS="1" AOP_TLS="yes"
  export CADDY_ORIGIN_CRT="${WORK}/origin.crt" CADDY_ORIGIN_KEY="${WORK}/origin.key" CADDY_AOP_CA="${WORK}/aop-ca.pem"
  # shellcheck disable=SC1090
  source "${WORK}/aop-stanza.src"
  {
    printf '{\n\tadmin off\n\tauto_https disable_redirects\n}\n\n'
    printf 'https://%s {\n' "${AOP_SNI}"
    printf '%s\n' "${DASH_TLS_STANZA}"
    printf '\trespond "gatus-stub-ok" 200\n}\n'
  } > "${WORK}/Caddyfile.aopsrv" )
HOME="${WORK}" "${CADDY_BIN}" run --config "${WORK}/Caddyfile.aopsrv" --adapter caddyfile >"${WORK}/caddy-aop.log" 2>&1 &
AOP_CADDY_PID=$!
ok=0
for i in $(seq 1 30); do
  # cert-less must NOT connect, so "ready" is :443 accepting TCP.
  if (: >"/dev/tcp/127.0.0.1/443") 2>/dev/null; then ok=1; break; fi
  sleep 1
done
[ "${ok}" = "1" ] || { tail -30 "${WORK}/caddy-aop.log"; die "AOP caddy did not open :443"; }
aop_neg_rc=0
curl -sk --max-time 10 --resolve "${AOP_SNI}:443:127.0.0.1" "https://${AOP_SNI}/" -o /dev/null 2>"${WORK}/aop-neg.err" || aop_neg_rc=$?
[ "${aop_neg_rc}" -ne 0 ] || die "AOP vhost answered a cert-less request — client_auth is not enforcing"
log "PASS: cert-less request rejected (curl exit ${aop_neg_rc}; $(head -1 "${WORK}/aop-neg.err" | cut -c1-90))"
curl -skf --max-time 10 --cert "${WORK}/aop-leaf.crt" --key "${WORK}/aop-leaf.key" \
  --resolve "${AOP_SNI}:443:127.0.0.1" "https://${AOP_SNI}/" -o "${WORK}/aop-pos.body" \
  || die "leaf-signed client was rejected by the AOP vhost"
grep -q "gatus-stub-ok" "${WORK}/aop-pos.body" || die "leaf-signed client did not reach the stub backend (got: $(head -c 120 "${WORK}/aop-pos.body"))"
log "PASS: leaf-signed client accepted end-to-end through the AOP vhost"

# ---------------------------------------------------------------- 5. proxy
log "Proxy assertions (content-identical + signature-verified)"
curl -sf "http://127.0.0.1:${MOCK_PORT}/adv" -o "${WORK}/direct.jws"
# Raw-byte compare is impossible by design (fresh ECDSA nonce per adv —
# real tangd re-signs per request too), so compare the deterministic
# payload plus verify the PROXIED envelope signature instead: any proxy
# mutation breaks the signature, which is the stronger assertion.
jose fmt --json="$(cat "${WORK}/direct.jws")" -Og payload -o "${WORK}/direct.payload"
jose fmt --json="$(cat "${WORK}/via-caddy.json")" -Og payload -o "${WORK}/via.payload"
cmp "${WORK}/direct.payload" "${WORK}/via.payload" || die "Caddy altered /adv content (direct vs proxied payload differ)"
log "PASS: /adv payload identical direct vs through Caddy"
jose fmt --json="$(cat "${WORK}/via-caddy.json")" -Og payload -SyOg keys -AUo- | jose jwk use -i- -r -u verify -o- > "${WORK}/sigkey.json"
jose jws ver -i "${WORK}/via-caddy.json" -k "${WORK}/sigkey.json" >/dev/null || die "proxied /adv signature does not verify"
log "PASS: proxied envelope signature verifies (proxy transparent for this response)"
# The provision script's own /adv assertion, extracted and executed here (never
# a copy) so a wire-shape regression fails CI instead of a live run. Live
# 2026-09-10 (#77): a raw '\"kty\"' grep shipped unverified and killed runs
# while tang was healthy; the advertisement is a flattened JWS.
eval "$(sed -n '/^adv_ok() {$/,/^}$/p' "${PROVISION_SH}")"
declare -f adv_ok >/dev/null || die "adv_ok() not found in ${PROVISION_SH} — update this harness"
adv_ok "${WORK}/direct.jws" || die "provision /adv assertion rejects the mock's direct advertisement"
adv_ok "${WORK}/via-caddy.json" || die "provision /adv assertion rejects the Caddy-proxied advertisement"
# A tang with more than one key set installed signs with every sign key, and
# jose then emits JWS GENERAL serialization (live 2026-09-10, #79: the real
# box had four .jwk files and answered that way while this single-key mock
# stays flattened). Both shapes must pass the probe.
jq -c '{payload: .payload, signatures: [{protected: .protected, signature: .signature}]}' \
  "${WORK}/direct.jws" > "${WORK}/direct-general.jws"
adv_ok "${WORK}/direct-general.jws" || die "provision /adv assertion rejects JWS general serialization (multi-key tang)"
# Adversarial: the assertion must NOT accept a raw JWK set (the shape the old
# unverified '"kty"' grep was written against) — the signed envelope is the wire format.
printf '%s' '{"keys":[{"kty":"EC"}]}' > "${WORK}/not-an-adv.json"
adv_ok "${WORK}/not-an-adv.json" && die "provision /adv assertion accepts a raw JWK set — wire-shape guard broken"
log "PASS: provision /adv assertion accepts flattened + general advertisements and rejects raw JWK sets"
# Regression guard: the prodshape render above runs in a subshell precisely
# so this still names the CI tenant (a clobbered name aborts here, by design).
[ "${STATUS_HOST}" = "citest.status.piercloud.net" ] || die "harness tenant clobbered (got ${STATUS_HOST})"
STUB_GOT="$(curl -sf -H "Host: ${STATUS_HOST}" "http://127.0.0.1:${CADDY_PORT}/api/v1/endpoints/statuses")" || die "status-host request failed"
[ "${STUB_GOT}" = "gatus-stub-ok" ] || die "status-host routing broken (got: ${STUB_GOT})"
log "PASS: exact-Host dashboard routing reaches the stub"
rc=0
curl -s -H "Host: evil.invalid" "http://127.0.0.1:${CADDY_PORT}/" -o /dev/null 2>/dev/null || rc=$?
[ "${rc}" = "52" ] || die "unknown Host: want curl 52 (abort/empty-reply), got ${rc}"
log "PASS: unknown Host aborted (deputy-closed in miniature)"
rc=0
curl -s "http://127.0.0.1:${CADDY_PORT}/" -o /dev/null 2>/dev/null || rc=$?
[ "${rc}" = "52" ] || die "bare /: want curl 52 (abort/empty-reply), got ${rc}"
log "PASS: catch-all abort on /"

# ---------------------------------------------------------------- 6. volumes
log "Preparing loopback LUKS volumes"
# pipefail is off for this one line: the trailing head closes early by
# design (SIGPIPE toward tr is success, not failure); the -s check below
# keeps it fail-closed.
set +o pipefail
head -c 64 /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 32 > "${WORK}/passphrase"
set -o pipefail
[ -s "${WORK}/passphrase" ] || die "passphrase generation failed"
for n in 1 2; do
  dd if=/dev/zero of="${WORK}/vol${n}.img" bs=1M count=64 status=none
done
DEV1="$(losetup -f --show "${WORK}/vol1.img")"
DEV2="$(losetup -f --show "${WORK}/vol2.img")"
cryptsetup luksFormat --type luks2 --batch-mode --key-file "${WORK}/passphrase" "${DEV1}"
cryptsetup luksFormat --type luks2 --batch-mode --key-file "${WORK}/passphrase" "${DEV2}"
log "Volumes: ${DEV1} ${DEV2}"

# ---------------------------------------------------------------- 7-10. bind
log "Binding ${DEV1} through Caddy"
clevis luks bind -f -d "${DEV1}" -k "${WORK}/passphrase" tang "{\"url\":\"http://127.0.0.1:${CADDY_PORT}\",\"thp\":\"${THP}\"}"
# NOTE: `clevis luks list` prints tokens as `ID: pin 'config'` (not JSON),
# e.g. `1: tang '{"url":"http://127.0.0.1:18080"}'` — match pin+endpoint.
clevis luks list -d "${DEV1}" | grep "tang.*${CADDY_PORT}" >/dev/null || { clevis luks list -d "${DEV1}"; die "bind token missing from luks list"; }
log "PASS: bind + pin listed"
echo -n "bind-proof-secret" | clevis encrypt tang "{\"url\":\"http://127.0.0.1:${CADDY_PORT}\",\"thp\":\"${THP}\"}" > "${WORK}/s.jwe"
[ "$(clevis decrypt < "${WORK}/s.jwe")" = "bind-proof-secret" ] || die "JWE roundtrip through Caddy failed"
log "PASS: encrypt/decrypt roundtrip through Caddy (real /rec exchange)"
clevis luks unlock -d "${DEV1}" -n e2e-slot
[ -e /dev/mapper/e2e-slot ] || die "unlock did not open the mapper device"
log "PASS: clevis luks unlock opened /dev/mapper/e2e-slot (full bind-proof)"

# ---------------------------------------------------------------- 11. negatives
log "Negative: wrong thumbprint must refuse bind"
if clevis luks bind -f -d "${DEV2}" -k "${WORK}/passphrase" tang "{\"url\":\"http://127.0.0.1:${CADDY_PORT}\",\"thp\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}" 2>"${WORK}/neg.err"; then
  die "bind with a wrong thumbprint SUCCEEDED — pin check broken"
fi
log "PASS: tampered thumbprint refused"
grep -qiE 'thumbprint|thp|advertisement|trust|verify|adv' "${WORK}/neg.err" || { cat "${WORK}/neg.err"; die "wrong-thp refusal message unrecognized (pin check may have moved)"; }
if clevis luks list -d "${DEV2}" 2>/dev/null | grep "tang.*${CADDY_PORT}" >/dev/null; then
  die "refused bind left a tang token behind"
fi
log "PASS: refused bind left no token"

# ------------------------------------------- 12. real-tang key collapse (#87)
# Two historical keygen rounds left the live anchor advertising a JWS GENERAL
# advertisement and an ambiguous thumbprint. The provision script's collapse
# span is executed here VERBATIM (extracted, never a copy) against real tang:
# two keygen rounds -> one sign + one exchange key, extras quarantined,
# strict-flattened /adv, exactly one thumbprint, and a real clevis bind/unlock.
log "Real tangd: two keygen rounds must collapse to one bindable set"
RT_DIR="${WORK}/real-tang"
RT_PORT=18083
mkdir -p "${RT_DIR}"
[ -x /usr/libexec/tangd-keygen ] || die "real tang not installed (no /usr/libexec/tangd-keygen)"
/usr/libexec/tangd -h >"${WORK}/tangd-help.txt" 2>&1 || true
grep -q -- --listen "${WORK}/tangd-help.txt" || { sed -n '1,12p' "${WORK}/tangd-help.txt"; die "this runner's tangd has no --listen mode (need tang >= 14)"; }
for round in 1 2; do
  if ! /usr/libexec/tangd-keygen "${RT_DIR}" >"${WORK}/keygen${round}.log" 2>&1; then
    sed -n '1,20p' "${WORK}/keygen${round}.log"
    die "tangd-keygen round ${round} failed (log above; check the tang package's key user)"
  fi
done
[ "$(find "${RT_DIR}" -maxdepth 1 -name '*.jwk' | wc -l | tr -d ' ')" = "4" ] || { ls -la "${RT_DIR}"; die "expected two keygen rounds to leave four .jwk files"; }
eval "$(sed -n '/# --- collapse:start ---/,/# --- collapse:end ---/p' "${PROVISION_SH}")"
declare -f collapse_keys >/dev/null || die "collapse_keys() not found in ${PROVISION_SH} — update this harness"
warn() { printf '\n==> WARN: %s\n' "$*"; }
own_keys() { :; } # the real one chowns to the unit user; this proof is root-only
TANG_KEYS_DIR="${RT_DIR}"
TANG_PORT="${RT_PORT}"
TANG_UNIT_USER="$(id -un)"
TANG_KEEP_THP="$(for f in "${RT_DIR}"/*.jwk; do if [ "$(jq -r '.alg // empty' "$f")" = ES512 ]; then printf '%s\n' "$(jose jwk thp -a S256 -i "$f")"; fi; done | LC_ALL=C sort | head -n1 || true)"
[ -n "${TANG_KEEP_THP}" ] || die "could not compute a signing-key thumbprint from the generated keys"
collapse_keys
[ "$(find "${RT_DIR}" -maxdepth 1 -name '*.jwk' | wc -l | tr -d ' ')" = "2" ] || die "collapse did not leave exactly two keys"
[ "$(find "${RT_DIR}" -maxdepth 1 -name '*.jwk' -exec jq -r '.alg' {} \; | LC_ALL=C sort | tr '\n' ' ')" = "ECMR ES512 " ] || die "collapse left the wrong key roles"
[ "$(ls -d "${RT_DIR}".orphaned-* 2>/dev/null | wc -l | tr -d ' ')" = "1" ] || die "collapse did not quarantine the extras"
[ "$(cat "${RT_DIR}/.published-thp")" = "${TANG_KEEP_THP}" ] || die "collapse changed the published thumbprint"
# Fallback path: a third keygen round + no recorded/kept thumbprint must be
# collapsed deterministically and re-published loudly. This is where the
# pipeline that silently died under set -e + pipefail lived (its first element
# was a loop that could exit 1 — order-dependent, hence the CI flake).
/usr/libexec/tangd-keygen "${RT_DIR}" >"${WORK}/keygen3.log" 2>&1 || { sed -n '1,20p' "${WORK}/keygen3.log"; die "tangd-keygen round 3 failed"; }
rm -f "${RT_DIR}/.published-thp"
if ! ( TANG_KEEP_THP="" collapse_keys ) >"${WORK}/collapse-fallback.log" 2>&1; then cat "${WORK}/collapse-fallback.log"; die "fallback collapse failed"; fi
grep -q 'no sign key matches the published thumbprint' "${WORK}/collapse-fallback.log" || { cat "${WORK}/collapse-fallback.log"; die "fallback path did not warn about the re-publish"; }
[ "$(find "${RT_DIR}" -maxdepth 1 -name '*.jwk' | wc -l | tr -d ' ')" = "2" ] || die "fallback collapse did not leave exactly two keys"
TANG_KEEP_THP="$(cat "${RT_DIR}/.published-thp")"
[ "$(for f in "${RT_DIR}"/*.jwk; do if [ "$(jq -r '.alg' "$f")" = ES512 ]; then printf '%s\n' "$(jose jwk thp -a S256 -i "$f")"; fi; done | LC_ALL=C sort)" = "${TANG_KEEP_THP}" ] || die "re-published thumbprint is not the surviving sign key"
/usr/libexec/tangd -l -p "${RT_PORT}" "${RT_DIR}" & RT_PID=$!
ok=0
for i in $(seq 1 20); do
  if curl -sf -m 3 "http://127.0.0.1:${RT_PORT}/adv" -o "${WORK}/real-adv.json"; then ok=1; break; fi
  sleep 0.5
done
[ "${ok}" = "1" ] || { cat "${WORK}/caddy.log" 2>/dev/null || true; die "real tangd did not serve /adv on ${RT_PORT}"; }
jq -e 'has("payload") and has("protected") and has("signature") and (has("signatures") | not)' "${WORK}/real-adv.json" >/dev/null \
  || die "collapsed tang still advertises JWS general serialization (signatures[])"
[ "$(tang-show-keys "${RT_PORT}" | tr -s '[:space:]' '\n' | grep -c .)" = "1" ] || die "tang-show-keys reports more than one thumbprint after collapse"
[ "$(tang-show-keys "${RT_PORT}")" = "${TANG_KEEP_THP}" ] || die "tang-show-keys thumbprint differs from the collapse's published value"
clevis luks bind -f -d "${DEV2}" -k "${WORK}/passphrase" tang "{\"url\":\"http://127.0.0.1:${RT_PORT}\",\"thp\":\"${TANG_KEEP_THP}\"}" >/dev/null \
  || die "real-tang bind failed after the collapse"
clevis luks unlock -d "${DEV2}" -n real-tang || die "real-tang unlock failed after the collapse"
[ -e /dev/mapper/real-tang ] || die "real-tang unlock did not open the mapper device"
cryptsetup close real-tang 2>/dev/null || true
kill "${RT_PID}" 2>/dev/null || true
log "PASS: real tang collapsed two keygen rounds to one flattened, bindable key set (bind + unlock round-trip)"

ELAPSED=$(( $(date +%s) - START ))
log "BIND-E2E GREEN in ${ELAPSED}s: bind + unlock + roundtrip through the real Caddyfile; negatives hold."
