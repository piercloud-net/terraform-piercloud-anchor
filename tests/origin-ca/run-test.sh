#!/usr/bin/env bash
# tests/origin-ca/run-test.sh — per-anchor Origin CA state machine + install
# validation (issue #123, M2).
#
# Offline, cred-free: extracts the REAL origin-ca span from
# scripts/010-provision.sh (never a copy) and drives it against throwaway
# paths. What it proves:
#   (a) key + CSR generation: ECDSA P-256, key 0600, single SAN + matching
#       CN, serverAuth EKU, CSR self-signature;
#   (b) idempotency: a second run reuses the same key and CSR (the key is
#       never regenerated);
#   (c) corrupt / mismatched-CSR recovery: the CSR is rebuilt, the key kept;
#   (d) orphaned cert (cert without key) fails closed;
#   (e) CSR self-check rejections: wrong CN, wrong SAN, extra SAN, foreign key,
#       missing/partial extensions (serverAuth EKU + digitalSignature keyUsage),
#       and a crafted DN that only imitates the extension strings (review N3);
#   (f) install validation: a test-CA-signed cert for the exact SAN + key is
#       accepted; wrong SAN, wrong public key, expired, not-yet-valid, non-PEM,
#       oversized and multi-cert/junk-framed material are rejected fail-closed;
#   (g) the install is an IN-PLACE write: the destination inode survives
#       (the Caddy container bind-mounts the file — a rename would leave
#       Caddy reading the old inode forever);
#   (h) the deployed-cert sha256 marker; the one-way .origin-ca-active marker
#       is never removed by the script;
#   (i) the bind-e2e extraction contract: the exact column-0 ORIGIN_TLS guard
#       line and the CADDY_ORIGIN_CRT/KEY stanza semantics are preserved.
#   (j) pair selection validates the on-box pair against the key + STATUS_HOST
#       before selection (stale SAN / mismatched key / supplied-without-pair
#       die; the one-way marker is never written);
#   (k) the served-leaf probe asserts BOTH identity (fingerprint) and coverage
#       (`-checkhost`) against a real local `openssl s_server`, and marks the
#       pair active only after both hold (review F1);
#   (l) 020's CSR capture runs on a FAILING 010 too and preserves the original
#       status (review F2); a framed-but-corrupt CSR never replaces the
#       published artifact — verification precedes the atomic publish (NIT).
#
# No root, no network, no cloud. macOS needs GNU-ish openssl on PATH (the
# Homebrew one); a `date` shim below covers BSD date for the GNU `date -d`
# the on-box validator uses.
# shellcheck disable=SC2034  # globals consumed by the extracted 010/020 functions below (fired via source)
set -euo pipefail

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HARNESS_DIR}/../.." && pwd)"
PROVISION="${ROOT}/scripts/010-provision.sh"

WORK="$(mktemp -d /tmp/origin-ca.XXXXXX)"
cleanup() {
  [ -n "${S_SERVER_PID:-}" ] && kill "${S_SERVER_PID}" 2>/dev/null || true
  rm -rf "${WORK}"
}
trap cleanup EXIT

pass=0
fail=0
ok()  { pass=$((pass + 1)); printf 'ok   %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL %s\n' "$1"; }
is()  { # $1 label, $2 expected, $3 actual
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi
}

# BSD/macOS `stat` has no -c; GNU has no -f. Try GNU first (CI), BSD second.
inode_of() { stat -c %i "$1" 2>/dev/null || stat -f %i "$1" 2>/dev/null || echo "?"; }
mode_of()  { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1" 2>/dev/null || echo "?"; }
file_sha() { printf '%s' "$(openssl dgst -sha256 <"$1" | awk '{print $NF}')"; }

# The on-box validator compares notBefore with GNU `date -d`; BSD date has no
# -d, so shim it (GNU first — CI runs the real thing). Passthrough otherwise.
date() {
  if [ "${1:-}" = "-d" ]; then
    command date -d "${2:-}" "${3:-+%s}" 2>/dev/null && return 0
    command date -j -f '%b %e %T %Y %Z' "$(printf '%s' "${2:-}" | tr -s ' ')" "${3:-+%s}" 2>/dev/null && return 0
    return 1
  fi
  command date "$@"
}
stamp() { # $1 = GNU date offset ('-1 hour'), $2 = BSD date flags ('-v-1H')
  command date -u -d "$1" +%y%m%d%H%M%SZ 2>/dev/null || command date -u "$2" +%y%m%d%H%M%SZ
}

[ -f "$PROVISION" ] || { printf 'FAIL provision script not found: %s\n' "$PROVISION"; exit 1; }
command -v openssl >/dev/null || { printf 'FAIL openssl is required\n'; exit 1; }

# ---- extract the real span (markers must be unique) ----------------------
BEGIN='# --- origin-ca:start ---'
END='# --- origin-ca:end ---'
for m in "$BEGIN" "$END"; do
  n="$(grep -cF -- "$m" "$PROVISION" || true)"
  [ "$n" = "1" ] || { printf 'FAIL marker %s found %s times in %s\n' "$m" "${n:-0}" "$PROVISION"; exit 1; }
done
b="$(grep -nF -- "$BEGIN" "$PROVISION" | cut -d: -f1)"
e="$(grep -nF -- "$END" "$PROVISION" | cut -d: -f1)"
sed -n "$((b + 1)),$((e - 1))p" "$PROVISION" >"${WORK}/span.src"
[ -s "${WORK}/span.src" ] || { printf 'FAIL extracted origin-ca span is empty\n'; exit 1; }

# Harness overrides + the same helpers the on-box script defines earlier.
log()  { printf 'harness: %s\n' "$*" >&2; }
warn() { printf 'harness WARNING: %s\n' "$*" >&2; }
die()  { printf 'FAIL(die): %s\n' "$*" >&2; exit 1; }
export ORIGIN_CA_DIR="${WORK}/caddy"
export ORIGIN_CA_KEY="${ORIGIN_CA_DIR}/origin-ca.key"
export ORIGIN_CA_CSR="${ORIGIN_CA_DIR}/origin-ca.csr"
export ORIGIN_CA_CRT="${ORIGIN_CA_DIR}/origin-ca.crt"
export ORIGIN_CA_HASH="${ORIGIN_CA_DIR}/.origin-ca.crt.sha256"
export ORIGIN_CA_ACTIVE="${ORIGIN_CA_DIR}/.origin-ca-active"
mkdir -p "${ORIGIN_CA_DIR}"
# shellcheck disable=SC1090
source "${WORK}/span.src"
for fn in origin_ca_generate origin_ca_cert_hash origin_ca_csr_selfcheck origin_ca_validate_cert origin_ca_install_from_env origin_ca_write_hash origin_ca_mark_active; do
  declare -f "$fn" >/dev/null || { printf 'FAIL extraction did not yield %s\n' "$fn"; exit 1; }
done

STATUS_HOST="status-citest.piercloud.net"
OTHER_HOST="status-other.piercloud.net"

# ---- (a) generation ------------------------------------------------------
origin_ca_generate
[ -s "${ORIGIN_CA_KEY}" ] && ok "key generated" || bad "key missing after origin_ca_generate"
[ -s "${ORIGIN_CA_CSR}" ] && ok "CSR generated" || bad "CSR missing after origin_ca_generate"
is "key mode is 0600" "600" "$(mode_of "${ORIGIN_CA_KEY}")"
is "CSR mode is 0644" "644" "$(mode_of "${ORIGIN_CA_CSR}")"
if openssl ec -in "${ORIGIN_CA_KEY}" -text -noout 2>/dev/null | grep -q 'prime256v1'; then
  ok "key is ECDSA P-256"
else
  bad "key is not ECDSA P-256"
fi
is "CSR single DNS SAN equals the status host" "$STATUS_HOST" "$(origin_ca_csr_sans "${ORIGIN_CA_CSR}")"
is "CSR CN equals the status host" "$STATUS_HOST" "$(origin_ca_csr_cn "${ORIGIN_CA_CSR}")"
if openssl req -in "${ORIGIN_CA_CSR}" -noout -verify >/dev/null 2>&1; then
  ok "CSR self-signature verifies"
else
  bad "CSR self-signature does not verify"
fi
csr_text="$(openssl req -in "${ORIGIN_CA_CSR}" -noout -text 2>/dev/null)"
case "$csr_text" in *"TLS Web Server Authentication"*) ok "CSR carries the serverAuth EKU" ;; *) bad "CSR lacks the serverAuth EKU" ;; esac
case "$csr_text" in *"Digital Signature"*) ok "CSR carries digitalSignature keyUsage" ;; *) bad "CSR lacks digitalSignature keyUsage" ;; esac
origin_ca_csr_selfcheck "${ORIGIN_CA_CSR}" "${ORIGIN_CA_KEY}" "$STATUS_HOST" && ok "generated CSR passes the self-check" || bad "generated CSR fails the self-check"

# ---- (b) idempotency -----------------------------------------------------
key_hash_1="$(file_sha "${ORIGIN_CA_KEY}")"
csr_hash_1="$(file_sha "${ORIGIN_CA_CSR}")"
key_inode_1="$(inode_of "${ORIGIN_CA_KEY}")"
origin_ca_generate
is "second run keeps the key byte-identical" "$key_hash_1" "$(file_sha "${ORIGIN_CA_KEY}")"
is "second run keeps the CSR byte-identical" "$csr_hash_1" "$(file_sha "${ORIGIN_CA_CSR}")"
is "second run keeps the key inode" "$key_inode_1" "$(inode_of "${ORIGIN_CA_KEY}")"

# ---- (c) corrupt / mismatched CSR recovery (key kept) --------------------
printf 'not a csr\n' >"${ORIGIN_CA_CSR}"
origin_ca_generate
is "corrupt CSR: key byte-identical" "$key_hash_1" "$(file_sha "${ORIGIN_CA_KEY}")"
origin_ca_csr_selfcheck "${ORIGIN_CA_CSR}" "${ORIGIN_CA_KEY}" "$STATUS_HOST" && ok "corrupt CSR regenerated" || bad "corrupt CSR not regenerated"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "${WORK}/foreign.key" >/dev/null 2>&1
openssl req -new -key "${WORK}/foreign.key" -subj "/CN=${STATUS_HOST}" \
  -addext "subjectAltName=DNS:${STATUS_HOST}" -addext "keyUsage=critical,digitalSignature" \
  -addext "extendedKeyUsage=serverAuth" -out "${ORIGIN_CA_CSR}" >/dev/null 2>&1
origin_ca_generate
is "mismatched CSR: key byte-identical" "$key_hash_1" "$(file_sha "${ORIGIN_CA_KEY}")"
origin_ca_csr_selfcheck "${ORIGIN_CA_CSR}" "${ORIGIN_CA_KEY}" "$STATUS_HOST" && ok "mismatched-key CSR regenerated" || bad "mismatched-key CSR not regenerated"

# ---- (d) orphaned cert (cert without key) fails closed -------------------
openssl req -x509 -new -key "${ORIGIN_CA_KEY}" -subj "/CN=${STATUS_HOST}" \
  -addext "subjectAltName=DNS:${STATUS_HOST}" -days 1 -out "${ORIGIN_CA_CRT}" >/dev/null 2>&1
mv "${ORIGIN_CA_KEY}" "${WORK}/key.saved"
rc=0
err="$(origin_ca_generate 2>&1)" || rc=$?
mv "${WORK}/key.saved" "${ORIGIN_CA_KEY}"
if [ "$rc" -ne 0 ]; then ok "orphaned cert without key fails closed (rc=$rc)"; else bad "orphaned cert without key did NOT fail"; fi
case "$err" in *orphaned*) ok "orphan failure names the condition" ;; *) bad "orphan failure message lacks 'orphaned': $err" ;; esac
rm -f "${ORIGIN_CA_CRT}" # back to a clean state for later cases

# ---- (e) CSR self-check rejections ---------------------------------------
expect_csr_fail() { # $1 label, $2 csr, $3 key
  local rc=0
  origin_ca_csr_selfcheck "$2" "$3" "$STATUS_HOST" >/dev/null 2>&1 || rc=$?
  if [ "$rc" -ne 0 ]; then ok "$1"; else bad "$1 (self-check accepted it)"; fi
}
openssl req -new -key "${ORIGIN_CA_KEY}" -subj "/CN=${OTHER_HOST}" \
  -addext "subjectAltName=DNS:${STATUS_HOST}" -out "${WORK}/csr-badcn.pem" >/dev/null 2>&1
expect_csr_fail "self-check rejects a wrong CN" "${WORK}/csr-badcn.pem" "${ORIGIN_CA_KEY}"
openssl req -new -key "${ORIGIN_CA_KEY}" -subj "/CN=${STATUS_HOST}" \
  -addext "subjectAltName=DNS:${OTHER_HOST}" -out "${WORK}/csr-badsan.pem" >/dev/null 2>&1
expect_csr_fail "self-check rejects a wrong SAN" "${WORK}/csr-badsan.pem" "${ORIGIN_CA_KEY}"
openssl req -new -key "${ORIGIN_CA_KEY}" -subj "/CN=${STATUS_HOST}" \
  -addext "subjectAltName=DNS:${STATUS_HOST},DNS:${OTHER_HOST}" -out "${WORK}/csr-extrasan.pem" >/dev/null 2>&1
expect_csr_fail "self-check rejects an extra SAN" "${WORK}/csr-extrasan.pem" "${ORIGIN_CA_KEY}"
openssl req -new -key "${WORK}/foreign.key" -subj "/CN=${STATUS_HOST}" \
  -addext "subjectAltName=DNS:${STATUS_HOST}" -out "${WORK}/csr-foreign.pem" >/dev/null 2>&1
expect_csr_fail "self-check rejects a foreign public key" "${WORK}/csr-foreign.pem" "${ORIGIN_CA_KEY}"
openssl req -new -key "${ORIGIN_CA_KEY}" -subj "/CN=${STATUS_HOST}" \
  -addext "subjectAltName=DNS:${STATUS_HOST}" -out "${WORK}/csr-noext.pem" >/dev/null 2>&1
expect_csr_fail "self-check rejects a CSR without any extensions" "${WORK}/csr-noext.pem" "${ORIGIN_CA_KEY}"
# A crafted DN carrying the extension wording must not satisfy the check
# (review N3: the check is scoped to the Requested Extensions region).
openssl req -new -key "${ORIGIN_CA_KEY}" -subj "/CN=${STATUS_HOST}/O=TLS Web Server Authentication/OU=Digital Signature" \
  -addext "subjectAltName=DNS:${STATUS_HOST}" -out "${WORK}/csr-crafted-dn.pem" >/dev/null 2>&1
expect_csr_fail "self-check rejects a crafted DN that imitates the extensions" "${WORK}/csr-crafted-dn.pem" "${ORIGIN_CA_KEY}"
openssl req -new -key "${ORIGIN_CA_KEY}" -subj "/CN=${STATUS_HOST}" \
  -addext "subjectAltName=DNS:${STATUS_HOST}" \
  -addext "keyUsage=critical,digitalSignature" -out "${WORK}/csr-ku-only.pem" >/dev/null 2>&1
expect_csr_fail "self-check rejects a CSR without the serverAuth EKU" "${WORK}/csr-ku-only.pem" "${ORIGIN_CA_KEY}"
openssl req -new -key "${ORIGIN_CA_KEY}" -subj "/CN=${STATUS_HOST}" \
  -addext "subjectAltName=DNS:${STATUS_HOST}" \
  -addext "extendedKeyUsage=serverAuth" -out "${WORK}/csr-eku-only.pem" >/dev/null 2>&1
expect_csr_fail "self-check rejects a CSR without the digitalSignature keyUsage" "${WORK}/csr-eku-only.pem" "${ORIGIN_CA_KEY}"

# ---- test CA (signed certs for the install validation) -------------------
CA_DIR="${WORK}/ca"
mkdir -p "${CA_DIR}/newcerts"
: >"${CA_DIR}/index.txt"
CA_SERIAL=9000
cat >"${CA_DIR}/ca.cnf" <<EOF
[ ca ]
default_ca = CA_default
[ CA_default ]
dir = ${CA_DIR}
database = \$dir/index.txt
new_certs_dir = \$dir/newcerts
serial = \$dir/serial
certificate = \$dir/ca.pem
private_key = \$dir/ca.key
default_md = sha256
policy = policy_any
x509_extensions = server_ext
unique_subject = no
[ policy_any ]
commonName = supplied
[ server_ext ]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:${STATUS_HOST}
[ wrong_san_ext ]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:${OTHER_HOST}
EOF
openssl req -x509 -newkey rsa:2048 -keyout "${CA_DIR}/ca.key" -out "${CA_DIR}/ca.pem" \
  -days 2 -nodes -subj "/CN=origin-ca-harness-ca" >/dev/null 2>&1 || { printf 'FAIL could not mint the test CA\n'; exit 1; }
sign_cert() { # $1 = csr, $2 = out, $3 = startdate, $4 = enddate, $5 = ext section
  CA_SERIAL=$((CA_SERIAL + 1))
  printf '%04X\n' "$CA_SERIAL" >"${CA_DIR}/serial"
  : >"${CA_DIR}/index.txt"
  rm -f "${CA_DIR}/index.txt.attr"
  openssl ca -batch -notext -config "${CA_DIR}/ca.cnf" -extensions "${5:-server_ext}" \
    -startdate "$3" -enddate "$4" -in "$1" -out "$2" >/dev/null 2>&1
}
NOW_RECENT="$(stamp '-1 hour' '-v-1H')"
NOW_FUTURE="$(stamp '+1 day' '-v+1d')"
NOW_FUTURE2="$(stamp '+2 day' '-v+2d')"
NOW_PAST="$(stamp '-2 day' '-v-2d')"
sign_cert "${ORIGIN_CA_CSR}" "${WORK}/cert-valid.pem" "$NOW_RECENT" "$NOW_FUTURE" \
  || { printf 'FAIL could not sign the valid test cert\n'; exit 1; }
sign_cert "${ORIGIN_CA_CSR}" "${WORK}/cert-wrongsan.pem" "$NOW_RECENT" "$NOW_FUTURE" wrong_san_ext \
  || { printf 'FAIL could not sign the wrong-SAN test cert\n'; exit 1; }
sign_cert "${ORIGIN_CA_CSR}" "${WORK}/cert-expired.pem" "$NOW_PAST" "$NOW_RECENT" \
  || { printf 'FAIL could not sign the expired test cert\n'; exit 1; }
sign_cert "${ORIGIN_CA_CSR}" "${WORK}/cert-notyet.pem" "$NOW_FUTURE" "$NOW_FUTURE2" \
  || { printf 'FAIL could not sign the not-yet-valid test cert\n'; exit 1; }
openssl req -new -key "${WORK}/foreign.key" -subj "/CN=${STATUS_HOST}" \
  -addext "subjectAltName=DNS:${STATUS_HOST}" -out "${WORK}/csr-foreign2.pem" >/dev/null 2>&1
sign_cert "${WORK}/csr-foreign2.pem" "${WORK}/cert-foreignkey.pem" "$NOW_RECENT" "$NOW_FUTURE" \
  || { printf 'FAIL could not sign the foreign-key test cert\n'; exit 1; }
# Confirm the fixtures are what the labels claim (a broken CA setup must not
# silently turn "rejects" assertions into passes).
if openssl verify -CAfile "${CA_DIR}/ca.pem" "${WORK}/cert-valid.pem" >/dev/null 2>&1; then
  ok "fixture: valid cert verifies against the test CA"
else
  bad "fixture: valid cert does not verify against the test CA"
fi

# ---- (f) install validation ----------------------------------------------
expect_cert_fail() { # $1 label, $2 cert, $3 expected reason fragment
  local rc=0 reason
  reason="$(origin_ca_validate_cert "$2" "${ORIGIN_CA_KEY}" "$STATUS_HOST" 2>&1)" || rc=$?
  if [ "$rc" -eq 0 ]; then
    bad "$1 (validation accepted it)"
    return
  fi
  case "$reason" in
    *"$3"*) ok "$1" ;;
    *) bad "$1 (rejected, but reason '$reason' lacks '$3')" ;;
  esac
}
origin_ca_validate_cert "${WORK}/cert-valid.pem" "${ORIGIN_CA_KEY}" "$STATUS_HOST" \
  && ok "validation accepts the exact-SAN key-matching cert" \
  || bad "validation rejected the exact-SAN key-matching cert"
expect_cert_fail "validation rejects a wrong SAN" "${WORK}/cert-wrongsan.pem" "differs from"
expect_cert_fail "validation rejects a foreign public key" "${WORK}/cert-foreignkey.pem" "does not match"
expect_cert_fail "validation rejects an expired cert" "${WORK}/cert-expired.pem" "expired"
expect_cert_fail "validation rejects a not-yet-valid cert" "${WORK}/cert-notyet.pem" "not yet valid"
if origin_ca_cert_pem_ok $'not a pem at all\n'; then bad "bounded-PEM shape accepts non-PEM junk"; else ok "bounded-PEM shape rejects non-PEM junk"; fi
if origin_ca_cert_pem_ok "$(printf -- '-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----' "$(head -c 17000 /dev/zero | tr '\0' 'A')")"; then
  bad "bounded-PEM shape accepts oversized material"
else
  ok "bounded-PEM shape rejects oversized material"
fi
valid_pem="$(cat "${WORK}/cert-valid.pem")"
if origin_ca_cert_pem_ok "$(printf '%s\n%s\n' "$valid_pem" "$valid_pem")"; then
  bad "bounded-PEM shape accepts a multi-cert blob"
else
  ok "bounded-PEM shape rejects a multi-cert blob (no first-block-only validation)"
fi
if origin_ca_cert_pem_ok "$(printf 'leading junk line\n%s\n' "$valid_pem")"; then
  bad "bounded-PEM shape accepts leading junk"
else
  ok "bounded-PEM shape rejects leading junk before the certificate"
fi
if origin_ca_cert_pem_ok "$(printf '%s\ntrailing junk line\n' "$valid_pem")"; then
  bad "bounded-PEM shape accepts trailing junk"
else
  ok "bounded-PEM shape rejects trailing junk after the certificate"
fi

# ---- (g) install is an in-place write (inode survives) -------------------
# Pre-create the destination like a previously served cert file, with a
# stale placeholder; the install must preserve the inode (bind-mount rule).
printf 'stale placeholder\n' >"${ORIGIN_CA_CRT}"
chmod 644 "${ORIGIN_CA_CRT}"
crt_inode_before="$(inode_of "${ORIGIN_CA_CRT}")"
valid_pem="$(cat "${WORK}/cert-valid.pem")"
ORIGIN_CA_CERT_PEM="$valid_pem" origin_ca_install_from_env
is "install keeps the destination inode" "$crt_inode_before" "$(inode_of "${ORIGIN_CA_CRT}")"
is "install writes the validated cert content" "$(origin_ca_cert_hash "${WORK}/cert-valid.pem")" "$(origin_ca_cert_hash "${ORIGIN_CA_CRT}")"
is "installed cert mode is 0644" "644" "$(mode_of "${ORIGIN_CA_CRT}")"

# A FAILED install leaves the served file untouched (same inode + content).
crt_hash_before_fail="$(origin_ca_cert_hash "${ORIGIN_CA_CRT}")"
wrong_pem="$(cat "${WORK}/cert-wrongsan.pem")"
rc=0
err="$(ORIGIN_CA_CERT_PEM="$wrong_pem" origin_ca_install_from_env 2>&1)" || rc=$?
if [ "$rc" -ne 0 ]; then ok "install rejects a wrong-SAN cert (rc=$rc)"; else bad "install accepted a wrong-SAN cert"; fi
case "$err" in *"differs from"*) ok "failed install names the SAN mismatch" ;; *) bad "failed install message lacks the SAN reason: $err" ;; esac
is "failed install keeps the destination inode" "$crt_inode_before" "$(inode_of "${ORIGIN_CA_CRT}")"
is "failed install keeps the served cert content" "$crt_hash_before_fail" "$(origin_ca_cert_hash "${ORIGIN_CA_CRT}")"
rc=0
err="$(ORIGIN_CA_CERT_PEM='not a pem' origin_ca_install_from_env 2>&1)" || rc=$?
if [ "$rc" -ne 0 ]; then ok "install rejects non-PEM material fail-closed"; else bad "install accepted non-PEM material"; fi
is "non-PEM install keeps the served cert content" "$crt_hash_before_fail" "$(origin_ca_cert_hash "${ORIGIN_CA_CRT}")"

# ---- (h) deployed-cert hash marker + one-way active marker ---------------
origin_ca_write_hash "${ORIGIN_CA_CRT}"
is "hash marker carries the deployed cert hash" "$(origin_ca_cert_hash "${ORIGIN_CA_CRT}")" "$(cat "${ORIGIN_CA_HASH}")"
is "hash marker mode is 0644" "644" "$(mode_of "${ORIGIN_CA_HASH}")"
is "hash marker is a bare 64-char sha256 hex" "64" "$(tr -d '\n' <"${ORIGIN_CA_HASH}" | wc -c | tr -d ' ')"
origin_ca_mark_active
[ -e "${ORIGIN_CA_ACTIVE}" ] && ok "one-way active marker created" || bad "one-way active marker missing"
origin_ca_mark_active
[ -e "${ORIGIN_CA_ACTIVE}" ] && ok "active marker is idempotent" || bad "active marker idempotency broken"
if grep -qE 'rm .*ORIGIN_CA_ACTIVE' "$PROVISION"; then
  bad "010 removes the one-way marker anywhere (must be one-way)"
else
  ok "010 never removes the one-way marker"
fi

# ---- (i) bind-e2e extraction contract ------------------------------------
if grep -qxF 'if [ "${ORIGIN_TLS}" = "1" ]; then' "$PROVISION"; then
  ok "010 keeps the exact column-0 ORIGIN_TLS stanza guard (bind-e2e)"
else
  bad "010 lost the column-0 ORIGIN_TLS stanza guard (bind-e2e extraction breaks)"
fi
if grep -qF 'tls ${CADDY_ORIGIN_CRT} ${CADDY_ORIGIN_KEY}' "$PROVISION"; then
  ok "010 keeps the CADDY_ORIGIN_CRT/KEY stanza semantics"
else
  bad "010 dropped the CADDY_ORIGIN_CRT/KEY stanza shape"
fi
if grep -qF 'origin_ca_select_pair() {' "$PROVISION" && grep -qxF 'origin_ca_select_pair' "$PROVISION"; then
  ok "010 defines and calls the extracted pair-selection function"
else
  bad "010 pair-selection function missing or never called"
fi
if grep -qF 'origin_ca_assert_served_pair() {' "$PROVISION" && grep -qF 'origin_ca_probe_and_mark "${STATUS_HOST}"' "$PROVISION"; then
  ok "010 defines and calls the served-pair probe (identity + coverage)"
else
  bad "010 served-pair probe missing or never called"
fi

# ---- (j) pair selection validates before selecting (review F1) -----------
# Drives the REAL extracted origin_ca_select_pair against throwaway paths.
SEL_DIR="${WORK}/select"
SEL_KEY="${SEL_DIR}/origin-ca.key"
SEL_CSR="${SEL_DIR}/origin-ca.csr"
SEL_CRT="${SEL_DIR}/origin-ca.crt"
SEL_HASH="${SEL_DIR}/.origin-ca.crt.sha256"
SEL_ACTIVE="${SEL_DIR}/.origin-ca-active"
LEGACY_DIR="${WORK}/legacy"
mkdir -p "$SEL_DIR" "$LEGACY_DIR"
LEGACY_KEY="${LEGACY_DIR}/origin.key"
LEGACY_CRT="${LEGACY_DIR}/origin.crt"
printf 'legacy cert placeholder\n' >"$LEGACY_CRT"
printf 'legacy key placeholder\n' >"$LEGACY_KEY"
cp -p "${ORIGIN_CA_KEY}" "$SEL_KEY"
cp -p "${ORIGIN_CA_CSR}" "$SEL_CSR"
cp -p "${WORK}/cert-valid.pem" "$SEL_CRT"
ORIGIN_CA_DIR="$SEL_DIR"; ORIGIN_CA_KEY="$SEL_KEY"; ORIGIN_CA_CSR="$SEL_CSR"
ORIGIN_CA_CRT="$SEL_CRT"; ORIGIN_CA_HASH="$SEL_HASH"; ORIGIN_CA_ACTIVE="$SEL_ACTIVE"

# j1: a valid pair is selected (and the missing hash marker reads as change).
rm -f "$SEL_ACTIVE" "$SEL_HASH"
CADDY_ORIGIN_CRT="$LEGACY_CRT"; CADDY_ORIGIN_KEY="$LEGACY_KEY"; ORIGIN_CA_SUPPLIED=0
origin_ca_select_pair
is "valid pair: selected" "1" "$ORIGIN_CA_PAIR"
is "valid pair: TLS on" "1" "$ORIGIN_TLS"
is "valid pair: CRT points at the per-anchor cert" "$SEL_CRT" "$CADDY_ORIGIN_CRT"
is "valid pair: cert change detected (no hash marker yet)" "1" "$ORIGIN_CERT_CHANGED"

# j2: key-matching but stale-SAN pair must die; marker untouched.
openssl req -x509 -new -key "$SEL_KEY" -subj "/CN=${OTHER_HOST}" \
  -addext "subjectAltName=DNS:${OTHER_HOST}" -days 1 -out "$SEL_CRT" >/dev/null 2>&1
rm -f "$SEL_ACTIVE"
rc=0
err="$(origin_ca_select_pair 2>&1)" || rc=$?
if [ "$rc" -ne 0 ]; then ok "stale-SAN pair: selection dies (rc=$rc)"; else bad "stale-SAN pair was selected"; fi
case "$err" in *"differs from"*) ok "stale-SAN rejection names the SAN mismatch" ;; *) bad "stale-SAN rejection message lacks the reason: $err" ;; esac
if [ -e "$SEL_ACTIVE" ]; then bad "stale-SAN selection wrote the one-way marker"; else ok "stale-SAN selection leaves the marker untouched"; fi

# j3: key-mismatched pair must die; marker untouched.
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "${SEL_DIR}/other.key" >/dev/null 2>&1
openssl req -x509 -new -key "${SEL_DIR}/other.key" -subj "/CN=${STATUS_HOST}" \
  -addext "subjectAltName=DNS:${STATUS_HOST}" -days 1 -out "$SEL_CRT" >/dev/null 2>&1
rm -f "$SEL_ACTIVE"
rc=0
err="$(origin_ca_select_pair 2>&1)" || rc=$?
if [ "$rc" -ne 0 ]; then ok "key-mismatched pair: selection dies (rc=$rc)"; else bad "key-mismatched pair was selected"; fi
case "$err" in *"does not match"*) ok "key-mismatch rejection names the key mismatch" ;; *) bad "key-mismatch rejection message lacks the reason: $err" ;; esac
if [ -e "$SEL_ACTIVE" ]; then bad "key-mismatched selection wrote the one-way marker"; else ok "key-mismatched selection leaves the marker untouched"; fi

# j4: with the one-way marker set and the pair absent, the legacy pair is not
# resurrected (transition contract).
rm -f "$SEL_CRT" "$SEL_ACTIVE"
printf 'marker\n' >"$SEL_ACTIVE"
CADDY_ORIGIN_CRT="$LEGACY_CRT"; CADDY_ORIGIN_KEY="$LEGACY_KEY"; ORIGIN_CA_SUPPLIED=0
origin_ca_select_pair
is "marker set + pair absent: TLS off" "0" "$ORIGIN_TLS"
is "marker set + pair absent: no pair selected" "0" "$ORIGIN_CA_PAIR"
is "marker set + pair absent: legacy path left untouched" "$LEGACY_CRT" "$CADDY_ORIGIN_CRT"

# j5: a certificate supplied this run with no on-box pair dies (no fallback).
rm -f "$SEL_CRT" "$SEL_ACTIVE"
CADDY_ORIGIN_CRT="$LEGACY_CRT"; CADDY_ORIGIN_KEY="$LEGACY_KEY"; ORIGIN_CA_SUPPLIED=1
rc=0
err="$(origin_ca_select_pair 2>&1)" || rc=$?
ORIGIN_CA_SUPPLIED=0
if [ "$rc" -ne 0 ]; then ok "supplied cert without an on-box pair: selection dies (rc=$rc)"; else bad "supplied-without-pair run selected a fallback"; fi
case "$err" in *"not present on the box"*) ok "supplied-without-pair rejection names the missing pair" ;; *) bad "supplied-without-pair message lacks the reason: $err" ;; esac

# ---- (k) served-leaf probe: identity AND coverage (review F1) ------------
# Real origin_ca_probe_and_mark against a real local TLS server, with the
# extracted pair as the installed file. The stale case IS the reviewer's
# reproduction: fingerprint matches (same file served), SAN does not cover
# STATUS_HOST — the marker must stay absent.
start_probe_server() { # $1 = cert, $2 = key; retries a fresh port a few times
  local attempt i
  for attempt in 1 2 3; do
    PROBE_PORT=$((20000 + RANDOM % 20000))
    ORIGIN_CA_PROBE_ADDR="127.0.0.1:${PROBE_PORT}"
    openssl s_server -accept "${PROBE_PORT}" -cert "$1" -key "$2" -www >"${WORK}/s_server.log" 2>&1 &
    S_SERVER_PID=$!
    for i in $(seq 1 40); do
      if openssl s_client -connect "127.0.0.1:${PROBE_PORT}" -servername "$STATUS_HOST" </dev/null >/dev/null 2>&1; then return 0; fi
      sleep 0.25
    done
    kill "${S_SERVER_PID}" 2>/dev/null || true
    S_SERVER_PID=""
    sleep 0.2
  done
  return 1
}
stop_probe_server() { kill "${S_SERVER_PID}" 2>/dev/null || true; S_SERVER_PID=""; }

cp -p "${WORK}/cert-valid.pem" "$SEL_CRT"
rm -f "$SEL_ACTIVE"
ORIGIN_CA_PAIR=1
if start_probe_server "$SEL_CRT" "$SEL_KEY"; then
  rc=0
  err="$(origin_ca_probe_and_mark "$STATUS_HOST" 2>&1)" || rc=$?
  if [ "$rc" -eq 0 ]; then ok "probe accepts the installed pair when it is served and covers the host"; else bad "probe rejected a valid served pair: $err"; fi
  if [ -e "$SEL_ACTIVE" ]; then ok "probe sets the one-way marker only after both checks pass"; else bad "probe did not set the marker after a valid proof"; fi
else
  bad "openssl s_server did not start on ${PROBE_PORT} (see ${WORK}/s_server.log)"
fi
stop_probe_server

openssl req -x509 -new -key "$SEL_KEY" -subj "/CN=${OTHER_HOST}" \
  -addext "subjectAltName=DNS:${OTHER_HOST}" -days 1 -out "$SEL_CRT" >/dev/null 2>&1
rm -f "$SEL_ACTIVE"
if start_probe_server "$SEL_CRT" "$SEL_KEY"; then
  rc=0
  err="$(origin_ca_probe_and_mark "$STATUS_HOST" 2>&1)" || rc=$?
  if [ "$rc" -ne 0 ]; then ok "probe rejects a served cert that does not cover the host (rc=$rc)"; else bad "probe accepted a served cert without host coverage"; fi
  case "$err" in *"does not cover"*) ok "coverage rejection names the missing host coverage" ;; *) bad "coverage rejection message lacks the reason: $err" ;; esac
  if [ -e "$SEL_ACTIVE" ]; then bad "failed coverage probe wrote the one-way marker"; else ok "failed coverage probe leaves the marker untouched"; fi
else
  bad "openssl s_server did not start on ${PROBE_PORT} (stale cert)"
fi
stop_probe_server

if start_probe_server "${WORK}/cert-valid.pem" "$SEL_KEY"; then
  rc=0
  err="$(origin_ca_probe_and_mark "$STATUS_HOST" 2>&1)" || rc=$?
  if [ "$rc" -ne 0 ]; then ok "probe rejects a served cert that is not the installed pair (rc=$rc)"; else bad "probe accepted a fingerprint mismatch"; fi
  case "$err" in *"fingerprint"*) ok "identity rejection names the fingerprint mismatch" ;; *) bad "identity rejection message lacks the reason: $err" ;; esac
else
  bad "openssl s_server did not start on ${PROBE_PORT} (identity case)"
fi
stop_probe_server

# ---- (l) 020 captures the CSR on a FAILING 010 (review F2) ---------------
PROVISION_020="${ROOT}/.github/scripts/020-provision-anchor.sh"
c0="$(grep -nF -- '# --- csr-capture:start ---' "$PROVISION_020" | cut -d: -f1)"
c1="$(grep -nF -- '# --- csr-capture:end ---' "$PROVISION_020" | cut -d: -f1)"
if [ -n "$c0" ] && [ -n "$c1" ] && [ "$c0" -lt "$c1" ]; then
  sed -n "$((c0 + 1)),$((c1 - 1))p" "$PROVISION_020" >"${WORK}/csr-capture.src"
  ok "020 keeps the csr-capture extraction markers"
else
  bad "020 csr-capture markers missing/ambiguous"
fi
FAKE_CSR="$(cat "${WORK}/csr-capture-valid.pem" 2>/dev/null || true)"
if [ -z "$FAKE_CSR" ]; then
  openssl req -new -key "${WORK}/foreign.key" -subj "/CN=${STATUS_HOST}" \
    -addext "subjectAltName=DNS:${STATUS_HOST}" -addext "keyUsage=critical,digitalSignature" \
    -addext "extendedKeyUsage=serverAuth" -out "${WORK}/csr-capture-valid.pem" >/dev/null 2>&1
  FAKE_CSR="$(cat "${WORK}/csr-capture-valid.pem")"
fi
# PEM framing + a body openssl cannot parse/verify (framed-but-corrupt).
FRAMED_CORRUPT_CSR="$(printf '%s\n%s\n%s\n' '-----BEGIN CERTIFICATE REQUEST-----' 'bm90IGEgY3Ny' '-----END CERTIFICATE REQUEST-----')"
# Stubbed ssh_base: the 010 pipe fails with rc 7 and the CSR fetch returns
# the fixture (mode controls which). All other ssh calls die loud.
run_capture_case() { # $1 = out path, $2 = rc file, $3 = stderr file; $4 = 'direct' calls capture only
  ( set +e
    cd "$ROOT" || exit 90
    # shellcheck disable=SC1090
    source "${WORK}/csr-capture.src"
    MODE_FILE="${WORK}/capture-mode"
    # shellcheck disable=SC2317
    ssh_base() {
      case "$*" in
        *'bash -s'*)
          cat >/dev/null
          case "$(cat "$MODE_FILE" 2>/dev/null)" in fail*) return 7 ;; *) return 0 ;; esac ;;
        *'cat /etc/caddy/origin-ca.csr'*)
          case "$(cat "$MODE_FILE" 2>/dev/null)" in *no-csr*) : ;; *corrupt*) printf '%s\n' "$FRAMED_CORRUPT_CSR" ;; *) printf '%s\n' "$FAKE_CSR" ;; esac ;;
        *) return 1 ;;
      esac
    }
    ROTATE=0
    ENV_PREFIX="export FOO='bar'"
    STATUS_HOST="$STATUS_HOST"
    ORIGIN_CA_CSR_OUT="$1"
    if [ "${4:-}" = "direct" ]; then capture_origin_ca_csr; else run_onbox_provision; fi
    printf '%s' "$?" >"$2"
  ) 2>"$3"
}
printf 'fail-with-csr' >"${WORK}/capture-mode"
rm -f "${WORK}/cap-a.csr"
run_capture_case "${WORK}/cap-a.csr" "${WORK}/rc-a" "${WORK}/err-a"
is "020 capture-on-failure: the original 010 status is preserved" "7" "$(cat "${WORK}/rc-a" 2>/dev/null || echo missing)"
if [ -s "${WORK}/cap-a.csr" ]; then ok "020 capture-on-failure: CSR artifact written"; else bad "020 capture-on-failure: CSR artifact missing"; fi
if cmp -s "${WORK}/csr-capture-valid.pem" "${WORK}/cap-a.csr"; then ok "020 capture-on-failure: artifact matches the on-box CSR"; else bad "020 capture-on-failure: artifact differs from the on-box CSR"; fi

printf 'ok' >"${WORK}/capture-mode"
rm -f "${WORK}/cap-b.csr"
run_capture_case "${WORK}/cap-b.csr" "${WORK}/rc-b" "${WORK}/err-b"
is "020 capture on success: rc 0" "0" "$(cat "${WORK}/rc-b" 2>/dev/null || echo missing)"
if [ -s "${WORK}/cap-b.csr" ]; then ok "020 capture on success: CSR artifact written"; else bad "020 capture on success: CSR artifact missing"; fi

printf 'fail-no-csr' >"${WORK}/capture-mode"
rm -f "${WORK}/cap-c.csr"
run_capture_case "${WORK}/cap-c.csr" "${WORK}/rc-c" "${WORK}/err-c"
is "020 capture without a CSR on failure: the 010 status still wins" "7" "$(cat "${WORK}/rc-c" 2>/dev/null || echo missing)"
if [ -e "${WORK}/cap-c.csr" ]; then bad "020 capture without a CSR wrote an artifact"; else ok "020 capture without a CSR: no artifact written"; fi
if grep -q 'not captured' "${WORK}/err-c" 2>/dev/null; then ok "020 capture without a CSR warns without masking the failure"; else bad "020 capture without a CSR did not warn: $(cat "${WORK}/err-c" 2>/dev/null)"; fi

printf 'no-csr' >"${WORK}/capture-mode"
rm -f "${WORK}/cap-d.csr"
rc=0
run_capture_case "${WORK}/cap-d.csr" "${WORK}/rc-d" "${WORK}/err-d" || rc=$?
if [ "$rc" -ne 0 ]; then ok "020 capture missing on SUCCESS fails the run closed (rc=$rc)"; else bad "020 capture missing on success did not fail"; fi
if grep -q 'capture failed' "${WORK}/err-d" 2>/dev/null; then ok "020 strict capture failure names the refusal"; else bad "020 strict capture failure message missing: $(cat "${WORK}/err-d" 2>/dev/null)"; fi

# A framed-but-corrupt CSR: the previous artifact survives and the run fails
# (verification runs on a temp sibling before the atomic publish).
printf 'fail-corrupt-csr' >"${WORK}/capture-mode"
printf 'sentinel\n' >"${WORK}/cap-e.csr"
run_capture_case "${WORK}/cap-e.csr" "${WORK}/rc-e" "${WORK}/err-e"
is "020 corrupt-CSR capture: the original 010 status is preserved" "7" "$(cat "${WORK}/rc-e" 2>/dev/null || echo missing)"
is "020 corrupt-CSR capture: the previous artifact is untouched" "sentinel" "$(cat "${WORK}/cap-e.csr" 2>/dev/null)"
if grep -q 'self-signature verification' "${WORK}/err-e" 2>/dev/null; then ok "020 corrupt-CSR capture: refusal names the verification failure"; else bad "020 corrupt-CSR capture: refusal message missing: $(cat "${WORK}/err-e" 2>/dev/null)"; fi
if ls "${WORK}"/cap-e.csr.tmp.* >/dev/null 2>&1; then bad "020 corrupt-CSR capture: temp artifact left behind"; else ok "020 corrupt-CSR capture: temp artifact cleaned up"; fi

printf 'fail-corrupt-csr' >"${WORK}/capture-mode"
rm -f "${WORK}/cap-f.csr"
run_capture_case "${WORK}/cap-f.csr" "${WORK}/rc-f" "${WORK}/err-f"
if [ -e "${WORK}/cap-f.csr" ]; then bad "020 corrupt-CSR capture without a previous artifact published one"; else ok "020 corrupt-CSR capture without a previous artifact: destination untouched"; fi

# Direct capture call: the capture function itself must fail closed and
# publish nothing (the previous artifact survives).
printf 'corrupt-csr' >"${WORK}/capture-mode"
printf 'sentinel\n' >"${WORK}/cap-g.csr"
run_capture_case "${WORK}/cap-g.csr" "${WORK}/rc-g" "${WORK}/err-g" direct
if [ "$(cat "${WORK}/rc-g" 2>/dev/null)" = "1" ]; then ok "020 corrupt-CSR capture (direct): capture returns non-zero"; else bad "020 corrupt-CSR capture (direct): rc=$(cat "${WORK}/rc-g" 2>/dev/null || echo missing)"; fi
is "020 corrupt-CSR capture (direct): the previous artifact is untouched" "sentinel" "$(cat "${WORK}/cap-g.csr" 2>/dev/null)"

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
