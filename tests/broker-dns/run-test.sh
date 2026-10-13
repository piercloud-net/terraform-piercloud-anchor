#!/usr/bin/env bash
# tests/broker-dns/run-test.sh — broker DNS write path proofs (M1 broker leg
# (b) b3a; pc-control #131; anchor companion #185).
#
# Exercises the REAL .github/scripts/lib/broker-dns.sh functions against a
# stubbed curl (no network, no credentials, real jq):
#
#   ok   write_anchor_dns happy path: audience-tagged OIDC request, POST
#        {"anchor_ref","ipv4"} to /v1/anchors/dns, 200 accepted.
#   ok   write_challenge present + cleanup: POST {"name","value","action"}
#        to /v1/dns/challenges for both actions.
#   ok   the OIDC tokens reach curl ONLY through 0600 config files (argv
#        carries no token); the body goes through a 0600 data file; the temp
#        dir is removed on every path.
#   fail missing OIDC context; malformed ref/ipv4/challenge name/value/action;
#        non-https BROKER_URL; token endpoint non-200; broker refusal
#        (401/404/409/502) with the body sanitized to one line; curl network
#        errors.
#
# Plus static wiring assertions over broker-report-selftest.yml: both libs are
# sourced, the DNS steps run in the SAME job as the report (the run-id
# cross-check requires it), the challenge and negative inputs exist, and the
# job carries `id-token: write`.
#
# Cred-free, offline: no network, no credentials, real jq.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
LIB="$ROOT/.github/scripts/lib/broker-dns.sh"
REPORT_LIB="$ROOT/.github/scripts/lib/broker-report.sh"
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
[ -f "$REPORT_LIB" ] || { printf 'FAIL report lib not found: %s\n' "$REPORT_LIB"; exit 1; }
[ -f "$SELF" ] || { printf 'FAIL selftest workflow not found: %s\n' "$SELF"; exit 1; }

# ---- the curl stub (same shape as tests/broker-report) --------------------
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

# ---- call the real functions ---------------------------------------------
# RUN <tag> <fn> <args...> [KEY=VALUE env assignments...] -> rc; stdout/stderr
# captured. An argument containing `=` is an env assignment (no function
# argument in this lib contains one: the challenge value grammar forbids it).
RUN() {
  local tag="$1" fn="$2"
  shift 2
  local rc=0 a
  local -a fargs=() envs=()
  for a in "$@"; do
    case "$a" in
      *=*) envs+=("$a") ;;
      *) fargs+=("$a") ;;
    esac
  done
  : >"$WORK/curl.log"
  env \
    ACTIONS_ID_TOKEN_REQUEST_URL="${REQ_URL:-https://oidc.example/req?x=1}" \
    ACTIONS_ID_TOKEN_REQUEST_TOKEN="${REQ_TOKEN:-runner-req-token}" \
    BROKER_URL="${BROKER:-https://broker.piercloud.net}" \
    PATH="$WORK/bin:$PATH" \
    ${envs[@]+"${envs[@]}"} \
    bash -c 'set -euo pipefail; . "$1"; shift; "$@"' _ "$LIB" "$fn" ${fargs[@]+"${fargs[@]}"} \
    >"$WORK/out.$tag" 2>"$WORK/err.$tag" || rc=$?
  printf '%s' "$rc"
}

# ---- behavior: write_anchor_dns happy path -------------------------------
rc="$(RUN okdns write_anchor_dns broker-ref-1 192.0.2.10)"
is "anchor dns happy path rc=0" 0 "$rc"
log="$(cat "$WORK/curl.log")"
contains "anchor dns note" "anchor DNS records written through the broker (anchor_ref=broker-ref-1)" "$(cat "$WORK/out.okdns")"
contains "token request carries the audience" "audience=piercloud-broker" "$log"
contains "anchor dns POST method" "CALL method=POST" "$log"
post_url="$(awk '/^CALL method=POST/ { print $3; exit }' "$WORK/curl.log" | sed 's/^url=//')"
is "anchor dns POST URL exact" "https://broker.piercloud.net/v1/anchors/dns" "$post_url"
contains "anchor dns POST Authorization is the MINTED token" "Authorization: Bearer minted-oidc-token" "$log"
contains "anchor dns body carries ref" '"anchor_ref":"broker-ref-1"' "$log"
contains "anchor dns body carries ip" '"ipv4":"192.0.2.10"' "$log"
cfgmode="$(awk '/^CONFIG / { print $3; exit }' "$WORK/curl.log")"
is "token config mode is 0600" "mode=600" "$cfgmode"
datamode="$(awk '/^DATA / { print $3; exit }' "$WORK/curl.log")"
is "body data file mode is 0600" "mode=600" "$datamode"
lacks "argv carries no minted token" "minted-oidc-token" "$(grep '^ARGV' "$WORK/curl.log")"
lacks "argv carries no request token" "runner-req-token" "$(grep '^ARGV' "$WORK/curl.log")"
lacks "minted token not on stdout" "minted-oidc-token" "$(cat "$WORK/out.okdns")"
lacks "minted token not on stderr" "minted-oidc-token" "$(cat "$WORK/err.okdns")"
lacks "request token not on stdout" "runner-req-token" "$(cat "$WORK/out.okdns")"
cfgpath="$(awk '/^CONFIG / { print $2; exit }' "$WORK/curl.log")"
if [ -n "$cfgpath" ] && [ ! -e "$cfgpath" ]; then ok "temp config removed after the call"; else bad "temp config still present: $cfgpath"; fi

# ---- behavior: write_challenge present + cleanup -------------------------
rc="$(RUN chpresent write_challenge _acme-challenge.anchor-01-envproof.piercloud.net abc_DEF-123 present)"
is "challenge present rc=0" 0 "$rc"
log="$(cat "$WORK/curl.log")"
contains "challenge POST method" "CALL method=POST" "$log"
ch_url="$(awk '/^CALL method=POST/ { print $3; exit }' "$WORK/curl.log" | sed 's/^url=//')"
is "challenge POST URL exact" "https://broker.piercloud.net/v1/dns/challenges" "$ch_url"
contains "challenge body carries name" '"name":"_acme-challenge.anchor-01-envproof.piercloud.net"' "$log"
contains "challenge body carries value" '"value":"abc_DEF-123"' "$log"
contains "challenge body carries action present" '"action":"present"' "$log"

rc="$(RUN chcleanup write_challenge _acme-challenge.anchor-01-envproof.piercloud.net abc_DEF-123 cleanup)"
is "challenge cleanup rc=0" 0 "$rc"
log="$(cat "$WORK/curl.log")"
contains "cleanup body carries action cleanup" '"action":"cleanup"' "$log"
contains "cleanup note" "challenge cleanup accepted by the broker" "$(cat "$WORK/out.chcleanup")"

# ---- behavior: input validation (no curl call) ---------------------------
is "empty anchor_ref refused" 1 "$(RUN refempty write_anchor_dns '' 192.0.2.10)"
is "uppercase anchor_ref refused" 1 "$(RUN refupper write_anchor_dns BrokerRef 192.0.2.10)"
is "over-long anchor_ref refused" 1 "$(RUN reflong write_anchor_dns "$(printf 'a%.0s' $(seq 1 65))" 192.0.2.10)"
is "leading-zero IPv4 refused" 1 "$(RUN ipzero write_anchor_dns broker-ref-1 192.000.2.10)"
is "out-of-range IPv4 refused" 1 "$(RUN iprange write_anchor_dns broker-ref-1 192.0.2.256)"
is "IPv6 refused" 1 "$(RUN ipv6 write_anchor_dns broker-ref-1 2001:db8::1)"
is "empty challenge name refused" 1 "$(RUN chname write_challenge '' abc present)"
is "wildcard challenge name refused" 1 "$(RUN chwild write_challenge '_acme-challenge.*.envproof.piercloud.net' abc present)"
is "non-challenge name refused" 1 "$(RUN chplain write_challenge envproof.piercloud.net abc present)"
is "uppercase challenge name refused" 1 "$(RUN chupper write_challenge _acme-challenge.EnvProof.piercloud.net abc present)"
is "empty challenge value refused" 1 "$(RUN chval write_challenge _acme-challenge.anchor-01-envproof.piercloud.net '' present)"
is "non-base64url challenge value refused" 1 "$(RUN chvalbad write_challenge _acme-challenge.anchor-01-envproof.piercloud.net 'bad value!' present)"
is "over-long challenge value refused" 1 "$(RUN chvallen write_challenge _acme-challenge.anchor-01-envproof.piercloud.net "$(printf 'a%.0s' $(seq 1 129))" present)"
is "bad action refused" 1 "$(RUN chaction write_challenge _acme-challenge.anchor-01-envproof.piercloud.net abc delete)"
is "trailing-dot IPv4 refused" 1 "$(RUN ipdot write_anchor_dns broker-ref-1 192.0.2.10.)"
is "double-dot challenge name refused" 1 "$(RUN chddot write_challenge '_acme-challenge.a..b.piercloud.net' abc present)"
is "trailing-dot challenge name refused" 1 "$(RUN chtdot write_challenge '_acme-challenge.anchor-01-envproof.piercloud.net.' abc present)"
contains "challenge name refusal names the shape" "_acme-challenge." "$(cat "$WORK/err.chwild")"
lacks "no curl call for invalid input" "CALL " "$(cat "$WORK/curl.log")"

# ---- behavior: environment and upstream failures -------------------------
is "non-https BROKER_URL refused" 1 "$(RUN httpurl write_anchor_dns broker-ref-1 192.0.2.10 BROKER_URL=http://broker.example)"
is "missing OIDC context refused" 1 "$(RUN noctx write_anchor_dns broker-ref-1 192.0.2.10 ACTIONS_ID_TOKEN_REQUEST_URL= ACTIONS_ID_TOKEN_REQUEST_TOKEN=)"
is "token endpoint non-200 refused" 1 "$(RUN tok500 write_anchor_dns broker-ref-1 192.0.2.10 STUB_TOKEN_CODE=500)"
contains "token 500 message" "OIDC token request answered HTTP 500" "$(cat "$WORK/err.tok500")"
is "token network error refused" 1 "$(RUN tokfail write_anchor_dns broker-ref-1 192.0.2.10 STUB_FAIL=token)"
is "anchor dns post 409 refused" 1 "$(RUN post409 write_anchor_dns broker-ref-1 192.0.2.10 STUB_POST_CODE=409 'STUB_POST_BODY={"error":"A value does not match the registry anchor IP reported by this run"}')"
is "anchor dns post 502 refused" 1 "$(RUN post502 write_anchor_dns broker-ref-1 192.0.2.10 STUB_POST_CODE=502)"
is "challenge post 404 refused" 1 "$(RUN ch404 write_challenge _acme-challenge.anchor-01-envproof.piercloud.net abc present STUB_POST_CODE=404)"
is "post network error refused" 1 "$(RUN postfail write_anchor_dns broker-ref-1 192.0.2.10 STUB_FAIL=post)"
RUN postml write_anchor_dns broker-ref-1 192.0.2.10 STUB_POST_CODE=409 'STUB_POST_BODY={"error":"ambiguous anchor"}' >/dev/null
errlines="$(wc -l <"$WORK/err.postml")"
is "refusal body flattened to one line" 1 "$errlines"
contains "refusal body preserved on the line" "ambiguous" "$(cat "$WORK/err.postml")"

# ---- static wiring: broker-report-selftest.yml ---------------------------
self_live="$(grep -v '^[[:space:]]*#' "$SELF")"
contains "selftest sources the report lib" '.github/scripts/lib/broker-report.sh' "$self_live"
contains "selftest sources the dns lib" '.github/scripts/lib/broker-dns.sh' "$self_live"
contains "selftest calls write_anchor_dns" 'write_anchor_dns "$ANCHOR_REF" "$ANCHOR_IPV4"' "$self_live"
contains "selftest presents the challenge" 'write_challenge "$CHALLENGE_NAME" "$CHALLENGE_VALUE" present' "$self_live"
contains "selftest cleans the challenge" 'write_challenge "$CHALLENGE_NAME" "$CHALLENGE_VALUE" cleanup' "$self_live"
contains "selftest negative requires refusal" 'if out="$(write_anchor_dns "$ANCHOR_REF" "$NEGATIVE_IPV4" 2>&1)"; then' "$self_live"
contains "selftest carries id-token: write" 'id-token: write' "$self_live"
contains "selftest selects the environment input" 'environment: ${{ inputs.environment }}' "$self_live"
contains "selftest checkout does not persist credentials" 'persist-credentials: false' "$self_live"
# The report and the DNS writes must live in the SAME job: the broker's
# A-write cross-check compares the stored report run id with the write's run
# id, so splitting them across jobs breaks the proof by construction.
# Count the job keys under `jobs:` (2-space keys), not the `on:` keys above it.
job_count="$(printf '%s\n' "$self_live" | awk '/^jobs:/{inj=1; next} inj && /^  [a-z0-9_-]+:$/{n++} END{print n+0}')"
is "selftest has exactly one job" 1 "$job_count"

# Extract one step block (from its `      - name:` line to the next one) so
# assertions bind to the step that actually runs, not to any occurrence.
step_block() { # $1 = exact step name
  printf '%s\n' "$self_live" | awk -v want="      - name: $1" '
    $0 == want { inblock = 1 }
    inblock && $0 != want && $0 ~ /^      - name: / { exit }
    inblock { print }
  '
}
report_block="$(step_block 'Report the anchor IPv4')"
dns_block="$(step_block 'Write the anchor DNS records through the broker')"
challenge_block="$(step_block 'Present and clean up a DNS-01 challenge TXT')"
negative_block="$(step_block 'Mismatched A value is refused with 409 (negative)')"
[ -n "$report_block" ] || bad "report step block not found"
[ -n "$dns_block" ] || bad "dns step block not found"
[ -n "$challenge_block" ] || bad "challenge step block not found"
[ -n "$negative_block" ] || bad "negative step block not found"
contains "dns step binds the anchor_ref input" 'ANCHOR_REF: ${{ inputs.anchor_ref }}' "$dns_block"
contains "dns step binds the ipv4 input" 'ANCHOR_IPV4: ${{ inputs.ipv4 }}' "$dns_block"
contains "challenge step binds the name input" 'CHALLENGE_NAME: ${{ inputs.challenge_name }}' "$challenge_block"
contains "challenge step binds the value input" 'CHALLENGE_VALUE: ${{ inputs.challenge_value }}' "$challenge_block"
contains "negative step gated on the input" "if: inputs.negative_ipv4 != ''" "$negative_block"
contains "negative step requires a 409" '*"HTTP 409"*' "$negative_block"
contains "negative step refuses any other failure" 'expected a 409 cross-check refusal' "$negative_block"

dns_step_line="$(printf '%s\n' "$self_live" | grep -n '^      - name: Write the anchor DNS records through the broker$' | cut -d: -f1)"
report_step_line="$(printf '%s\n' "$self_live" | grep -n '^      - name: Report the anchor IPv4$' | cut -d: -f1)"
if [ -n "$dns_step_line" ] && [ -n "$report_step_line" ] && [ "$dns_step_line" -gt "$report_step_line" ]; then
  ok "DNS write step follows the report step in the same job"
else
  bad "DNS write step ordering/report step missing (report=$report_step_line dns=$dns_step_line)"
fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
