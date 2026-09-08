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
TENANT_USER="${TENANT_USER:-citest}"
CADDY_VERSION="2.11.2"
CADDY_TGZ="caddy_${CADDY_VERSION}_linux_amd64.tar.gz"
CADDY_URL="https://github.com/caddyserver/caddy/releases/download/v${CADDY_VERSION}/${CADDY_TGZ}"
# Pinned SHA-512 of the upstream release asset (caddy ships SHA512 checksums).
CADDY_SHA512="2513b289054386b76642a9e8bfc10d217df2b5361e4cdd0c72672b0eeab57ae737d57466eb70f1a44233cbcc697ecf21de88137ca45ef4b64f150a32b58f5f14"

WORK="$(mktemp -d /tmp/bind-e2e.XXXXXX)"
START="$(date +%s)"
log() { printf '\n==> %s\n' "$*"; }
die() { printf '\nFAIL: %s\n' "$*" >&2; exit 1; }

cleanup() {
  # Best-effort teardown in reverse bring-up order; never masks the failure.
  [ -n "${CADDY_PID:-}" ] && kill "${CADDY_PID}" 2>/dev/null || true
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
apt-get install -y -qq clevis clevis-luks cryptsetup jose curl python3 python3-cryptography >/dev/null
command -v clevis >/dev/null || die "clevis missing after apt"
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
# Production firewall constant, extracted — never retyped, cannot drift.
eval "$(grep '^CF_EDGE_CIDRS=' "${PROVISION_SH}")"
[ -n "${CF_EDGE_CIDRS:-}" ] || die "CF_EDGE_CIDRS extraction failed"
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
[ "${STATUS_HOST}" = "status.citest.piercloud.net" ] || die "sanitize drift: STATUS_HOST=${STATUS_HOST}"
grep -q "reverse_proxy 127.0.0.1:${MOCK_PORT}" "${WORK}/Caddyfile.ci" || die "render does not point /adv|/rec at the mock"
grep -q "reverse_proxy 127.0.0.1:${STUB_PORT}" "${WORK}/Caddyfile.ci" || die "render does not point the status host at the stub"
grep -q "host ${STATUS_HOST}" "${WORK}/Caddyfile.ci" || die "render lacks the exact-Host status matcher"
log "CI Caddyfile rendered (status host: ${STATUS_HOST})"
# The shipped shape must still parse after the refactor: render it with
# production addressing and validate (never served here).
export CADDY_HTTP_ADDR=":80" CADDY_SKIP_HTTPS="" TANG_PORT="8081" GATUS_PORT="8080"
export TENANT_USER=prodprobe STATUS_HOST="" STATUS_MATCH=""
export DASH_TLS_STANZA="	# No origin pair deployed: Caddy automatic HTTPS (HTTP-01 via :80 below)."
caddy_status_names
render_caddyfile > "${WORK}/Caddyfile.prodshape"
HOME="${WORK}" "${CADDY_BIN}" validate --config "${WORK}/Caddyfile.prodshape" --adapter caddyfile
HOME="${WORK}" "${CADDY_BIN}" validate --config "${WORK}/Caddyfile.ci" --adapter caddyfile
log "Both renders validate (CI shape + shipped shape)"

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
log "PASS: proxied /adv signature verifies (envelope byte-exact)"
STUB_GOT="$(curl -sf -H "Host: ${STATUS_HOST}" "http://127.0.0.1:${CADDY_PORT}/api/v1/endpoints/statuses")" || die "status-host request failed"
[ "${STUB_GOT}" = "gatus-stub-ok" ] || die "status-host routing broken (got: ${STUB_GOT})"
log "PASS: exact-Host dashboard routing reaches the stub"
if curl -sf -H "Host: evil.invalid" "http://127.0.0.1:${CADDY_PORT}/" -o /dev/null 2>/dev/null; then
  die "Caddy answered an unknown Host — deputy not closed"
fi
log "PASS: unknown Host aborted (deputy-closed in miniature)"
if curl -sf "http://127.0.0.1:${CADDY_PORT}/" -o /dev/null 2>/dev/null; then
  die "Caddy answered / on the bare address — catch-all abort broken"
fi
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
clevis luks list -d "${DEV1}" | grep '"pin": "tang"' >/dev/null || { clevis luks list -d "${DEV1}"; die "bind token missing from luks list"; }
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
if clevis luks list -d "${DEV2}" 2>/dev/null | grep '"pin": "tang"' >/dev/null; then
  die "refused bind left a tang token behind"
fi
log "PASS: refused bind left no token"

ELAPSED=$(( $(date +%s) - START ))
log "BIND-E2E GREEN in ${ELAPSED}s: bind + unlock + roundtrip through the real Caddyfile; negatives hold."
