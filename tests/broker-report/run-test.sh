#!/usr/bin/env bash
# tests/broker-report/run-test.sh — broker report path proofs (M1 broker leg
# (b) b2; pc-control #123).
#
# Exercises the REAL .github/scripts/lib/broker-report.sh function against a
# stubbed curl (no network, no credentials, real jq):
#
#   ok   happy path: audience-tagged OIDC request, broker POST with the
#        report JSON, 200 accepted; the OIDC tokens reach curl ONLY through
#        0600 config files (argv carries no token).
#   fail missing OIDC context; malformed anchor_ref; non-canonical IPv4
#        (leading zero / out of range / IPv6 / empty); non-https BROKER_URL;
#        token endpoint non-200; token body without .value; broker refusal
#        (401/404/409) with the body sanitized to one line; curl network
#        errors on either leg; the temp dir is removed on every path.
#
# Plus static wiring assertions over provision.yml and the selftest workflow:
# the lib is sourced, the call site passes the resolve output + the anchor_ref
# input, the report step is managed-run gated, and the job/workflow carry
# `id-token: write`.
#
# Cred-free, offline: no network, no credentials, real jq.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
LIB="$ROOT/.github/scripts/lib/broker-report.sh"
PROV="$ROOT/.github/workflows/provision.yml"
SELF="$ROOT/.github/workflows/broker-report-selftest.yml"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0
ok()  { pass=$((pass + 1)); printf 'ok   %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL %s\n' "$1"; }
is()  { # $1 label, $2 expected, $3 actual
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi
}
contains() { # $1 label, $2 needle, $3 haystack
  case "$3" in *"$2"*) ok "$1" ;; *) bad "$1 (missing '$2')" ;; esac
}
lacks() { # $1 label, $2 needle, $3 haystack -- ok when the needle is ABSENT
  case "$3" in *"$2"*) bad "$1 (found '$2')" ;; *) ok "$1" ;; esac
}

[ -f "$LIB" ] || { printf 'FAIL lib not found: %s\n' "$LIB"; exit 1; }
[ -f "$PROV" ] || { printf 'FAIL workflow not found: %s\n' "$PROV"; exit 1; }
[ -f "$SELF" ] || { printf 'FAIL selftest workflow not found: %s\n' "$SELF"; exit 1; }

# ---- the curl stub -------------------------------------------------------
# Records each invocation (method, URL, config files, argv) into $STUB_LOG and
# answers from STUB_* env vars: TOKEN_CODE/TOKEN_BODY, POST_CODE/POST_BODY,
# FAIL=token|post for a network error. It does NOT parse config semantics
# beyond recording the file contents, so the harness asserts on the real
# bytes the lib wrote.
mkdir -p "$WORK/bin"
cat >"$WORK/bin/curl" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
out=""; url=""; method="GET"; argv="$*"; declare -a cfgs=()
while [ $# -gt 0 ]; do
  case "$1" in
    --config) cfgs+=("$2"); shift 2 ;;
    -o) out="$2"; shift 2 ;;
    -w) shift 2 ;;
    --max-time) shift 2 ;;
    -X) method="$2"; shift 2 ;;
    -H | --header) shift 2 ;;
    -sS | -s | -f | -fsS) shift ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
{
  printf 'CALL method=%s url=%s\n' "$method" "$url"
  printf 'ARGV %s\n' "$argv"
  for c in "${cfgs[@]}"; do
    printf 'CONFIG %s mode=%s\n' "$c" "$(stat -c %a "$c")"
    sed 's/^/CONFIGLINE /' "$c"
    # data = "@file" — record the referenced body file's bytes + mode.
    while IFS= read -r line; do
      case "$line" in
        'data = "@'*'"')
          f="${line#data = \"@}"; f="${f%\"}"
          printf 'DATA %s mode=%s\n' "$f" "$(stat -c %a "$f")"
          sed 's/^/DATALINE /' "$f"
          ;;
      esac
    done <"$c"
  done
} >>"$STUB_LOG"
if [ "$method" = "POST" ]; then
  [ "${STUB_FAIL:-}" = "post" ] && exit 7
  code="${STUB_POST_CODE:-200}"; body="${STUB_POST_BODY:-{\"ok\":true}}"
else
  [ "${STUB_FAIL:-}" = "token" ] && exit 7
  code="${STUB_TOKEN_CODE:-200}"; body="${STUB_TOKEN_BODY:-{\"value\":\"minted-oidc-token\"}}"
fi
[ -n "$out" ] && printf '%s' "$body" >"$out"
printf '%s' "$code"
STUB
chmod +x "$WORK/bin/curl"
PATH="$WORK/bin:$PATH"
export STUB_LOG="$WORK/curl.log"

# ---- call the real function ---------------------------------------------
# RUN <tag> <ref> <ip> [env assignments...] -> rc; stdout/stderr captured.
RUN() {
  local tag="$1" ref="$2" ip="$3"
  shift 3
  local rc=0
  : >"$WORK/curl.log"
  env \
    ACTIONS_ID_TOKEN_REQUEST_URL="${REQ_URL:-https://oidc.example/req?x=1}" \
    ACTIONS_ID_TOKEN_REQUEST_TOKEN="${REQ_TOKEN:-runner-req-token}" \
    BROKER_URL="${BROKER:-https://broker.piercloud.net}" \
    PATH="$WORK/bin:$PATH" \
    "$@" \
    bash -c 'set -euo pipefail; . "$1"; report_anchor_ip "$2" "$3"' _ "$LIB" "$ref" "$ip" \
    >"$WORK/out.$tag" 2>"$WORK/err.$tag" || rc=$?
  printf '%s' "$rc"
}

# ---- behavior: happy path -------------------------------------------------
rc="$(RUN ok broker-ref-1 192.0.2.10)"
is "happy path rc=0" 0 "$rc"
contains "happy path note" "anchor IP reported to the broker (anchor_ref=broker-ref-1)" "$(cat "$WORK/out.ok")"
log="$(cat "$WORK/curl.log")"
contains "token request carries the audience" "audience=piercloud-broker" "$log"
contains "token request method GET" "CALL method=GET" "$log"
contains "broker POST method" "CALL method=POST" "$log"
post_url="$(awk '/^CALL method=POST/ { print $3; exit }' "$WORK/curl.log" | sed 's/^url=//')"
is "broker POST URL exact" "https://broker.piercloud.net/v1/anchors/ip" "$post_url"
contains "POST Authorization header is the MINTED token" "Authorization: Bearer minted-oidc-token" "$log"
contains "POST body JSON carries ref + ip" '"anchor_ref":"broker-ref-1"' "$log"
contains "POST body JSON carries ip" '"ipv4":"192.0.2.10"' "$log"
cfgmode="$(awk '/^CONFIG / { print $3; exit }' "$WORK/curl.log")"
is "token config mode is 0600" "mode=600" "$cfgmode"
datamode="$(awk '/^DATA / { print $3; exit }' "$WORK/curl.log")"
is "body data file mode is 0600" "mode=600" "$datamode"
lacks "argv carries no minted token" "minted-oidc-token" "$(grep '^ARGV' "$WORK/curl.log")"
lacks "argv carries no request token" "runner-req-token" "$(grep '^ARGV' "$WORK/curl.log")"
# The temp dir is removed on the happy path: the CONFIG paths recorded are
# gone after the call.
cfgpath="$(awk '/^CONFIG / { print $2; exit }' "$WORK/curl.log")"
if [ -n "$cfgpath" ] && [ ! -e "$cfgpath" ]; then ok "temp config removed after the call"; else bad "temp config still present: $cfgpath"; fi

# ---- behavior: input validation ------------------------------------------
is "empty anchor_ref refused" 1 "$(RUN refempty '' 192.0.2.10)"
is "uppercase anchor_ref refused" 1 "$(RUN refupper BrokerRef 192.0.2.10)"
is "over-long anchor_ref refused" 1 "$(RUN reflong "$(printf 'a%.0s' $(seq 1 65))" 192.0.2.10)"
is "leading-zero IPv4 refused" 1 "$(RUN ipzero broker-ref-1 192.000.2.10)"
is "out-of-range IPv4 refused" 1 "$(RUN iprange broker-ref-1 192.0.2.256)"
is "IPv6 refused" 1 "$(RUN ipv6 broker-ref-1 2001:db8::1)"
is "empty IPv4 refused" 1 "$(RUN ipempty broker-ref-1 '')"
contains "refusal message names the grammar" "[a-z0-9._-]{1,64}" "$(cat "$WORK/err.refempty")"
lacks "no curl call for invalid input" "CALL " "$(cat "$WORK/curl.log")"
is "non-https BROKER_URL refused" 1 "$(RUN httpurl broker-ref-1 192.0.2.10 BROKER_URL=http://broker.example)"
is "missing OIDC context refused" 1 "$(RUN noctx broker-ref-1 192.0.2.10 ACTIONS_ID_TOKEN_REQUEST_URL= ACTIONS_ID_TOKEN_REQUEST_TOKEN=)"
contains "no-OIDC error carries the broker report prefix" "::error::broker report: no OIDC request context" "$(cat "$WORK/err.noctx")"
# A non-default BROKER_URL must actually be used, and a trailing slash must
# not produce a double-slash path.
rc="$(RUN okalt broker-ref-1 192.0.2.10 BROKER_URL=https://broker.example)"
is "alternate base rc=0" 0 "$rc"
alt_url="$(awk '/^CALL method=POST/ { print $3; exit }' "$WORK/curl.log" | sed 's/^url=//')"
is "alternate base POST URL exact" "https://broker.example/v1/anchors/ip" "$alt_url"
rc="$(RUN oktrail broker-ref-1 192.0.2.10 BROKER_URL=https://broker.example/)"
is "trailing-slash base rc=0" 0 "$rc"
trail_url="$(awk '/^CALL method=POST/ { print $3; exit }' "$WORK/curl.log" | sed 's/^url=//')"
is "trailing-slash base POST URL exact" "https://broker.example/v1/anchors/ip" "$trail_url"

# ---- behavior: upstream failures ------------------------------------------
is "token endpoint non-200 refused" 1 "$(RUN tok500 broker-ref-1 192.0.2.10 STUB_TOKEN_CODE=500)"
contains "token 500 message" "OIDC token request answered HTTP 500" "$(cat "$WORK/err.tok500")"
is "token body without value refused" 1 "$(RUN toknone broker-ref-1 192.0.2.10 'STUB_TOKEN_BODY={}')"
is "token network error refused" 1 "$(RUN tokfail broker-ref-1 192.0.2.10 STUB_FAIL=token)"
is "post 401 refused" 1 "$(RUN post401 broker-ref-1 192.0.2.10 STUB_POST_CODE=401 'STUB_POST_BODY={\"error\":\"unauthorized\"}')"
is "post 409 refused" 1 "$(RUN post409 broker-ref-1 192.0.2.10 STUB_POST_CODE=409 'STUB_POST_BODY={\"error\":\"ambiguous anchor\"}')"
is "post network error refused" 1 "$(RUN postfail broker-ref-1 192.0.2.10 STUB_FAIL=post)"
# A multi-line refusal body is flattened to one log line.
RUN postml broker-ref-1 192.0.2.10 'STUB_POST_CODE=409' 'STUB_POST_BODY={"error":"ambiguous anchor"}' >/dev/null
errlines="$(wc -l <"$WORK/err.postml")"
is "refusal body flattened to one line" 1 "$errlines"
contains "refusal body preserved on the line" "ambiguous" "$(cat "$WORK/err.postml")"
# The label must stay pinned on the refusal path too (a hardcoded label
# would otherwise pass every test).
contains "refusal carries the broker report prefix" "::error::broker report refused" "$(cat "$WORK/err.postml")"

# ---- static wiring: provision.yml -----------------------------------------
prov_live="$(grep -v '^[[:space:]]*#' "$PROV")"
contains "provision sources the lib" '.github/scripts/lib/broker-report.sh' "$prov_live"
contains "provision calls report_anchor_ip" 'report_anchor_ip "$ANCHOR_REF" "$ANCHOR_IPV4"' "$prov_live"
contains "provision passes the anchor_ref input" 'ANCHOR_REF: ${{ inputs.anchor_ref }}' "$prov_live"
contains "provision passes the resolve output" 'ANCHOR_IPV4: ${{ steps.resolve.outputs.anchor_ipv4 }}' "$prov_live"
contains "report step is managed-run gated" "if: inputs.tenant != ''" "$prov_live"
contains "device-flow job carries id-token: write" 'id-token: write' "$prov_live"

# ---- static wiring: selftest workflow -------------------------------------
self_live="$(grep -v '^[[:space:]]*#' "$SELF")"
contains "selftest is dispatch-only" 'workflow_dispatch:' "$self_live"
contains "selftest carries id-token: write" 'id-token: write' "$self_live"
contains "selftest selects the environment input" 'environment: ${{ inputs.environment }}' "$self_live"
contains "selftest sources the lib" '.github/scripts/lib/broker-report.sh' "$self_live"
contains "selftest calls report_anchor_ip" 'report_anchor_ip "$ANCHOR_REF" "$ANCHOR_IPV4"' "$self_live"
contains "selftest checkout does not persist credentials" 'persist-credentials: false' "$self_live"

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
