#!/usr/bin/env bash
# tests/anchor-dns/run-test.sh — A2 writer proofs for .github/scripts/030-anchor-dns.sh.
#
# Drives the REAL writer script (never a copy) with a PATH-stubbed curl; no
# network, no credentials, real jq. Green paths: Cloudflare create/overwrite,
# Gcore create/overwrite (404 -> POST, 200 -> PUT), zone override, provider
# switch. Red paths: verify-after-write mismatch (both providers), Gcore GET
# non-200, missing token per provider (fail-closed, names the org secret),
# bad provider, bad zone. Static wiring: no status-record write survives,
# provision.yml passes the provider switch + both tokens, and the Gcore
# boolean read uses tostring (the repo's jq-boolean-guard shape).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
SCRIPT=".github/scripts/030-anchor-dns.sh"
PROV=".github/workflows/provision.yml"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin"

pass=0
fail=0
ok()  { pass=$((pass + 1)); printf 'ok   %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL %s\n' "$1"; }
is()  { # $1 label, $2 expected, $3 actual
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi
}
contains() { case "$3" in *"$2"*) ok "$1" ;; *) bad "$1 (missing '$2' in: $(printf '%s' "$3" | tail -c 400))" ;; esac; }
lacks()    { case "$3" in *"$2"*) bad "$1 (found '$2')" ;; *) ok "$1" ;; esac; }

# ---- stubbed curl ----------------------------------------------------------
# Handles exactly the shapes 030-anchor-dns.sh uses: -sS, -H <h>, -X <M>,
# --data <json>, -o <file>, -w '%{http_code}'. State lives in JSON files under
# $STUB_DIR; $STUB_CF_MISMATCH / $STUB_GCORE_MISMATCH force a verify read to
# answer a different address; $STUB_GCORE_HTTP forces the initial GET status.
cat > "$WORK/bin/curl" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
DIR="${STUB_DIR:?}"
method="GET"; url=""; out=""; wfmt=""; data=""
args=("$@")
i=0
while [ "$i" -lt "${#args[@]}" ]; do
  a="${args[$i]}"
  case "$a" in
    -X) i=$((i + 1)); method="${args[$i]}" ;;
    --data) i=$((i + 1)); data="${args[$i]}" ;;
    -o) i=$((i + 1)); out="${args[$i]}" ;;
    -w) i=$((i + 1)); wfmt="${args[$i]}" ;;
    -H) i=$((i + 1)); hv="${args[$i]}"
        case "$hv" in
          @*) [ -f "${hv#@}" ] && sed 's/^/hdr /' "${hv#@}" >> "$DIR/headers.log" ;;
          *) printf 'hdr %s\n' "$hv" >> "$DIR/headers.log" ;;
        esac ;;
    -sS | -s | -S | -f | -k | --fail) ;;
    http://* | https://*) url="$a" ;;
  esac
  i=$((i + 1))
done
[ -n "$url" ] || { echo "stub-curl: no URL" >&2; exit 2; }
printf '%s %s\n' "$method" "$url" >> "$DIR/curl.log"
[ -n "$data" ] && printf '%s\n' "$data" >> "$DIR/curl-data.log"
emit() { # $1 = code, $2 = body
  if [ -n "$out" ]; then
    printf '%s' "$2" > "$out"
    if [ -n "$wfmt" ]; then printf '%s' "${wfmt//\%\{http_code\}/$1}"; fi
  else
    printf '%s' "$2"
    if [ -n "$wfmt" ]; then printf '%s' "${wfmt//\%\{http_code\}/$1}"; fi
  fi
}

# ---- Cloudflare ----
if [[ "$url" == *"api.cloudflare.com"* ]]; then
  CF="$DIR/cf-records.json"
  [ -f "$CF" ] || printf '{}' > "$CF"
  case "$url" in
    *"/zones?name="*)
      zone="${url#*name=}"
      printf '%s\n' "$zone" >> "$DIR/zones.log"
      emit 200 '{"result":[{"id":"zone-cf"}]}'
      exit 0 ;;
  esac
  if [[ "$url" == *"/zones/zone-cf/dns_records"* ]]; then
    if [[ "$url" == *"?"* ]]; then
      name="${url#*name=}"
      rec="$(jq -c --arg n "$name" '.[$n] // empty' "$CF")"
      if [ -n "$rec" ]; then
        if [ -n "${STUB_CF_MISMATCH:-}" ]; then
          rec="$(printf '%s' "$rec" | jq -c '.content = "203.0.113.99"')"
        fi
        if [ -n "${STUB_CF_DUPLICATE:-}" ]; then
          emit 200 "{\"result\":[$rec,$rec]}"
        else
          emit 200 "{\"result\":[$rec]}"
        fi
      else
        emit 200 '{"result":[]}'
      fi
    else
      if [ -n "${STUB_CF_WRITE_HTTP:-}" ]; then emit "$STUB_CF_WRITE_HTTP" '{"success":false}'; exit 0; fi
      jq -c --argjson d "$data" '.[$d.name] = {id: "rec1", name: $d.name, type: $d.type, content: $d.content, ttl: $d.ttl, proxied: $d.proxied}' "$CF" > "$CF.tmp" && mv "$CF.tmp" "$CF"
      emit 200 '{"success":true}'
    fi
    exit 0
  fi
  emit 500 '{"error":"stub-curl: unhandled Cloudflare URL"}'
  exit 0
fi

# ---- Gcore ----
if [[ "$url" == *"api.gcore.com"* ]]; then
  GC="$DIR/gcore-rrsets.json"
  [ -f "$GC" ] || printf '{}' > "$GC"
  case "$url" in
    *"/dns/v2/zones/"*"/A")
      path="${url#*"/dns/v2/zones/"}" # <zone>/<fqdn>/A
      zone="${path%%/*}"
      rest="${path#*/}" # <fqdn>/A
      fqdn="${rest%/A}"
      printf '%s\n' "$zone" >> "$DIR/zones.log"
      case "$method" in
        GET)
          if [ -n "${STUB_GCORE_HTTP:-}" ]; then emit "$STUB_GCORE_HTTP" '{"error":"stub"}'; exit 0; fi
          rr="$(jq -c --arg n "$fqdn" '.[$n] // empty' "$GC")"
          if [ -n "$rr" ]; then
            if [ -n "${STUB_GCORE_MISMATCH:-}" ]; then
              rr="$(printf '%s' "$rr" | jq -c '.resource_records[0].content = ["203.0.113.99"]')"
            fi
            if [ -n "${STUB_GCORE_DUPLICATE:-}" ]; then
              rr="$(printf '%s' "$rr" | jq -c '.resource_records += [.resource_records[0]]')"
            fi
            if [ -n "${STUB_GCORE_BUNDLED:-}" ]; then
              rr="$(printf '%s' "$rr" | jq -c '.resource_records[0].content += ["203.0.113.99"]')"
            fi
            emit 200 "$rr"
          else
            emit 404 '{"error":"not found"}'
          fi ;;
        PUT | POST)
          if [ -n "${STUB_GCORE_WRITE_HTTP:-}" ]; then emit "$STUB_GCORE_WRITE_HTTP" '{"error":"stub"}'; exit 0; fi
          jq -c --argjson d "$data" --arg n "$fqdn" '.[$n] = {name: $n, type: "A", ttl: $d.ttl, resource_records: $d.resource_records}' "$GC" > "$GC.tmp" && mv "$GC.tmp" "$GC"
          emit 200 '{"ok":true}' ;;
        *) emit 500 '{"error":"stub-curl: unhandled method"}' ;;
      esac
      exit 0 ;;
  esac
  emit 500 '{"error":"stub-curl: unhandled Gcore URL"}'
  exit 0
fi

emit 500 '{"error":"stub-curl: unhandled URL"}'
STUB
chmod +x "$WORK/bin/curl"
export PATH="$WORK/bin:$PATH"
export STUB_DIR="$WORK"

# ---- helpers ---------------------------------------------------------------
reset_state() {
  printf '{}' > "$WORK/cf-records.json"
  printf '{}' > "$WORK/gcore-rrsets.json"
  : > "$WORK/curl.log"
  : > "$WORK/curl-data.log"
  : > "$WORK/zones.log"
  : > "$WORK/headers.log"
}
run_writer() { # $@ = env assignments for the writer; rc echoed; log in $WORK/last.log
  local rc=0
  (
    unset NET_DNS_PROVIDER NET_DNS_ZONE ANCHOR_TTL CLOUDFLARE_DNS_TOKEN GCORE_DNS_TOKEN
    unset STUB_CF_MISMATCH STUB_GCORE_MISMATCH STUB_GCORE_HTTP STUB_CF_WRITE_HTTP STUB_GCORE_WRITE_HTTP STUB_CF_DUPLICATE STUB_GCORE_DUPLICATE STUB_GCORE_BUNDLED
    env "$@" bash "$SCRIPT"
  ) >"$WORK/last.log" 2>&1 || rc=$?
  printf '%s' "$rc"
}
LOG() { cat "$WORK/last.log"; }
CF_KEYS() { jq -r 'keys | join(",")' "$WORK/cf-records.json"; }
GC_KEYS() { jq -r 'keys | join(",")' "$WORK/gcore-rrsets.json"; }

T_USER="pier"
T_IP="203.0.113.10"
T_HOST="anchor-01-pier.piercloud.net"

[ -f "$SCRIPT" ] || { printf 'FAIL writer not found: %s\n' "$SCRIPT"; exit 1; }
[ -f "$PROV" ] || { printf 'FAIL workflow not found: %s\n' "$PROV"; exit 1; }

# ---- green: Cloudflare create ---------------------------------------------
reset_state
rc="$(run_writer TENANT_USER="$T_USER" ANCHOR_IPV4="$T_IP" CLOUDFLARE_DNS_TOKEN="cf-token")"
is "cloudflare create rc" "0" "$rc"
contains "cloudflare create verifies" "verified: $T_HOST -> $T_IP (proxied=false, ttl=300)" "$(LOG)"
is "cloudflare create writes exactly the anchor record" "$T_HOST" "$(CF_KEYS)"
lacks "cloudflare create wrote no status record" "status" "$(CF_KEYS)"
contains "cloudflare create used POST (no record existed)" "POST" "$(cat "$WORK/curl.log")"
lacks "cloudflare create did not PUT" "PUT" "$(cat "$WORK/curl.log")"
is "cloudflare create zone resolved" "piercloud.net" "$(cat "$WORK/zones.log")"

# ---- green: Cloudflare overwrite ------------------------------------------
reset_state
jq -n --arg n "$T_HOST" '{($n): {id:"rec1",name:$n,type:"A",content:"198.51.100.7",ttl:300,proxied:false}}' > "$WORK/cf-records.json"
rc="$(run_writer TENANT_USER="$T_USER" ANCHOR_IPV4="$T_IP" CLOUDFLARE_DNS_TOKEN="cf-token")"
is "cloudflare overwrite rc" "0" "$rc"
contains "cloudflare overwrite PUT" "PUT" "$(cat "$WORK/curl.log")"
is "cloudflare overwrite final address" "$T_IP" "$(jq -r --arg n "$T_HOST" '.[$n].content' "$WORK/cf-records.json")"
contains "cloudflare overwrite logs the old address" "record exists (198.51.100.7)" "$(LOG)"

# ---- red: Cloudflare verify mismatch --------------------------------------
reset_state
rc="$(run_writer TENANT_USER="$T_USER" ANCHOR_IPV4="$T_IP" CLOUDFLARE_DNS_TOKEN="cf-token" STUB_CF_MISMATCH=1)"
[ "$rc" != "0" ] && ok "cloudflare verify mismatch fails the run (rc=$rc)" || bad "cloudflare verify mismatch did not fail"
contains "cloudflare verify mismatch message" "verify-after-write mismatch" "$(LOG)"

# ---- green: Gcore create (404 -> POST) ------------------------------------
reset_state
rc="$(run_writer TENANT_USER="$T_USER" ANCHOR_IPV4="$T_IP" NET_DNS_PROVIDER=gcore GCORE_DNS_TOKEN="gc-token")"
is "gcore create rc" "0" "$rc"
contains "gcore create verifies" "verified: $T_HOST -> $T_IP (ttl=300, enabled=true)" "$(LOG)"
is "gcore create writes exactly the anchor record" "$T_HOST" "$(GC_KEYS)"
lacks "no status record was written on the Gcore path" "status" "$(GC_KEYS)"
contains "gcore create used POST (404 first)" "POST" "$(cat "$WORK/curl.log")"
is "gcore create body shape (A content single-element array)" "[\"$T_IP\"]" "$(jq -c --arg n "$T_HOST" '.[$n].resource_records[0].content' "$WORK/gcore-rrsets.json")"
is "gcore create enabled flag" "true" "$(jq -r --arg n "$T_HOST" '.[$n].resource_records[0].enabled' "$WORK/gcore-rrsets.json")"

# ---- green: Gcore overwrite (200 -> PUT) ----------------------------------
reset_state
jq -n --arg n "$T_HOST" '{($n): {name:$n,type:"A",ttl:300,resource_records:[{content:["198.51.100.7"],enabled:true}]}}' > "$WORK/gcore-rrsets.json"
rc="$(run_writer TENANT_USER="$T_USER" ANCHOR_IPV4="$T_IP" NET_DNS_PROVIDER=gcore GCORE_DNS_TOKEN="gc-token")"
is "gcore overwrite rc" "0" "$rc"
contains "gcore overwrite PUT" "PUT" "$(cat "$WORK/curl.log")"
is "gcore overwrite final address" "$T_IP" "$(jq -r --arg n "$T_HOST" '.[$n].resource_records[0].content[0]' "$WORK/gcore-rrsets.json")"

# ---- red: Gcore verify mismatch -------------------------------------------
reset_state
rc="$(run_writer TENANT_USER="$T_USER" ANCHOR_IPV4="$T_IP" NET_DNS_PROVIDER=gcore GCORE_DNS_TOKEN="gc-token" STUB_GCORE_MISMATCH=1)"
[ "$rc" != "0" ] && ok "gcore verify mismatch fails the run (rc=$rc)" || bad "gcore verify mismatch did not fail"
contains "gcore verify mismatch message" "verify-after-write mismatch" "$(LOG)"

# ---- red: Gcore initial GET non-200 ---------------------------------------
reset_state
rc="$(run_writer TENANT_USER="$T_USER" ANCHOR_IPV4="$T_IP" NET_DNS_PROVIDER=gcore GCORE_DNS_TOKEN="gc-token" STUB_GCORE_HTTP=500)"
[ "$rc" != "0" ] && ok "gcore GET 500 fails the run (rc=$rc)" || bad "gcore GET 500 did not fail"
contains "gcore GET 500 message" "returned HTTP 500" "$(LOG)"
is "gcore GET 500 wrote nothing" "" "$(GC_KEYS)"

# ---- red: missing token per provider (fail-closed, names the secret) ------
reset_state
rc="$(run_writer TENANT_USER="$T_USER" ANCHOR_IPV4="$T_IP")"
[ "$rc" != "0" ] && ok "missing CLOUDFLARE_DNS_TOKEN fails closed (rc=$rc)" || bad "missing CLOUDFLARE_DNS_TOKEN did not fail"
contains "missing token names CLOUDFLARE_DNS_TOKEN" "CLOUDFLARE_DNS_TOKEN is not set" "$(LOG)"
is "missing token wrote nothing" "" "$(CF_KEYS)"
rc="$(run_writer TENANT_USER="$T_USER" ANCHOR_IPV4="$T_IP" NET_DNS_PROVIDER=gcore)"
[ "$rc" != "0" ] && ok "missing GCORE_DNS_TOKEN fails closed (rc=$rc)" || bad "missing GCORE_DNS_TOKEN did not fail"
contains "missing token names GCORE_DNS_TOKEN" "GCORE_DNS_TOKEN is not set" "$(LOG)"

# ---- red: a control byte in the token is refused before any curl ----------
reset_state
rc="$(run_writer TENANT_USER="$T_USER" ANCHOR_IPV4="$T_IP" CLOUDFLARE_DNS_TOKEN=$'cf\x01-token')"
[ "$rc" != "0" ] && ok "control-byte token fails the run (rc=$rc)" || bad "control-byte token did not fail"
contains "control-byte token message" "whitespace or a control character" "$(LOG)"
lacks "control-byte token never reaches curl" "hdr " "$(cat "$WORK/headers.log" 2>/dev/null || true)"

# ---- red: bad provider / bad zone ------------------------------------------
reset_state
rc="$(run_writer TENANT_USER="$T_USER" ANCHOR_IPV4="$T_IP" NET_DNS_PROVIDER=bogus CLOUDFLARE_DNS_TOKEN="cf-token")"
[ "$rc" != "0" ] && ok "unknown provider fails closed (rc=$rc)" || bad "unknown provider did not fail"
contains "unknown provider message" "is not one of cloudflare|gcore" "$(LOG)"
rc="$(run_writer TENANT_USER="$T_USER" ANCHOR_IPV4="$T_IP" NET_DNS_ZONE="bad zone" CLOUDFLARE_DNS_TOKEN="cf-token")"
[ "$rc" != "0" ] && ok "invalid zone fails closed (rc=$rc)" || bad "invalid zone did not fail"
contains "invalid zone message" "is not a valid zone name" "$(LOG)"

# ---- green: zone override (canary-proof path) ------------------------------
reset_state
rc="$(run_writer TENANT_USER="$T_USER" ANCHOR_IPV4="$T_IP" NET_DNS_PROVIDER=gcore GCORE_DNS_TOKEN="gc-token" NET_DNS_ZONE=pc-canary.com)"
is "canary zone override rc" "0" "$rc"
contains "canary zone resolved on Gcore" "pc-canary.com" "$(cat "$WORK/zones.log")"
is "canary zone record key" "anchor-01-pier.pc-canary.com" "$(GC_KEYS)"

# ---- auth header shape + mask-first ordering -------------------------------
reset_state
rc="$(run_writer TENANT_USER="$T_USER" ANCHOR_IPV4="$T_IP" CLOUDFLARE_DNS_TOKEN="cf-token")"
is "cloudflare auth run rc" "0" "$rc"
contains "cloudflare sends Authorization: Bearer" "hdr Authorization: Bearer cf-token" "$(cat "$WORK/headers.log")"
contains "cloudflare sends the JSON content type" "hdr Content-Type: application/json" "$(cat "$WORK/headers.log")"
head -n1 "$WORK/last.log" | grep -q '::add-mask::' && ok "mask line precedes every curl" || bad "mask line is not first (token could reach logs/curl before masking)"
reset_state
rc="$(run_writer TENANT_USER="$T_USER" ANCHOR_IPV4="$T_IP" NET_DNS_PROVIDER=gcore GCORE_DNS_TOKEN="gc-token")"
is "gcore auth run rc" "0" "$rc"
contains "gcore sends Authorization: APIKey" "hdr Authorization: APIKey gc-token" "$(cat "$WORK/headers.log")"

# ---- red: rejected write (HTTP 500) must not reach verify ------------------
reset_state
rc="$(run_writer TENANT_USER="$T_USER" ANCHOR_IPV4="$T_IP" CLOUDFLARE_DNS_TOKEN="cf-token" STUB_CF_WRITE_HTTP=500)"
[ "$rc" != "0" ] && ok "cloudflare write 500 fails the run (rc=$rc)" || bad "cloudflare write 500 did not fail"
contains "cloudflare write 500 message" "cloudflare write (POST) returned HTTP 500" "$(LOG)"
lacks "cloudflare write 500 never reaches verify" "verified:" "$(LOG)"
reset_state
rc="$(run_writer TENANT_USER="$T_USER" ANCHOR_IPV4="$T_IP" NET_DNS_PROVIDER=gcore GCORE_DNS_TOKEN="gc-token" STUB_GCORE_WRITE_HTTP=500)"
[ "$rc" != "0" ] && ok "gcore write 500 fails the run (rc=$rc)" || bad "gcore write 500 did not fail"
contains "gcore write 500 message" "gcore write (POST) returned HTTP 500" "$(LOG)"
lacks "gcore write 500 never reaches verify" "verified:" "$(LOG)"

# ---- red: a stale duplicate record in the rrset ---------------------------
reset_state
rc="$(run_writer TENANT_USER="$T_USER" ANCHOR_IPV4="$T_IP" CLOUDFLARE_DNS_TOKEN="cf-token" STUB_CF_DUPLICATE=1)"
[ "$rc" != "0" ] && ok "cloudflare duplicate-record rrset fails the run (rc=$rc)" || bad "cloudflare duplicate-record rrset did not fail"
contains "cloudflare duplicate message names the count" "2 record(s)" "$(LOG)"
reset_state
rc="$(run_writer TENANT_USER="$T_USER" ANCHOR_IPV4="$T_IP" NET_DNS_PROVIDER=gcore GCORE_DNS_TOKEN="gc-token" STUB_GCORE_DUPLICATE=1)"
[ "$rc" != "0" ] && ok "gcore duplicate-record rrset fails the run (rc=$rc)" || bad "gcore duplicate-record rrset did not fail"
contains "gcore duplicate message names the count" "2 record(s)" "$(LOG)"
# Bundled content: ONE rrset entry holding [want, stale] — counting entries
# alone would pass it; the flattened address count must fail it.
reset_state
rc="$(run_writer TENANT_USER="$T_USER" ANCHOR_IPV4="$T_IP" NET_DNS_PROVIDER=gcore GCORE_DNS_TOKEN="gc-token" STUB_GCORE_BUNDLED=1)"
[ "$rc" != "0" ] && ok "gcore bundled-content rrset fails the run (rc=$rc)" || bad "gcore bundled-content rrset did not fail"
contains "gcore bundled-content message names both addresses" "2 record(s)" "$(LOG)"
contains "gcore bundled-content message shows the stale address" "203.0.113.99" "$(LOG)"

# ---- red: Gcore TTL floor is exercised ------------------------------------
reset_state
rc="$(run_writer TENANT_USER="$T_USER" ANCHOR_IPV4="$T_IP" NET_DNS_PROVIDER=gcore GCORE_DNS_TOKEN="gc-token" ANCHOR_TTL=60)"
[ "$rc" != "0" ] && ok "gcore TTL floor fails the run (rc=$rc)" || bad "gcore TTL floor did not fail"
contains "gcore TTL floor message" "below the Gcore Free floor of 120s" "$(LOG)"
is "gcore TTL floor wrote nothing" "" "$(GC_KEYS)"

# ---- no per-tenant status record survives ----------------------------------
contains "writer still derives the anchor name" "derive_anchor_hostname" "$(cat "$SCRIPT")"
lacks "writer no longer derives a status host" "derive_status_host" "$(cat "$SCRIPT")"

# ---- static wiring ---------------------------------------------------------
contains "provision.yml passes GCORE_DNS_TOKEN" 'GCORE_DNS_TOKEN: ${{ secrets.GCORE_DNS_TOKEN }}' "$(cat "$PROV")"
contains "provision.yml passes the provider switch" 'NET_DNS_PROVIDER: ${{ vars.NET_DNS_PROVIDER }}' "$(cat "$PROV")"
lacks "gcore boolean read never uses the jq alternative on enabled" ".enabled //" "$(cat "$SCRIPT")"
contains "gcore boolean read uses tostring" ".enabled | tostring" "$(cat "$SCRIPT")"
contains "anchor TTL constant documented" 'ANCHOR_TTL="${ANCHOR_TTL:-300}"' "$(cat "$SCRIPT")"
# The line that emits the credential must land in the 0600 header file — a
# future edit redirecting it to stdout would otherwise be invisible to the
# contract secret-print grep (which only sees print-builtin+scheme lines).
auth_print_line="$(grep -F "printf 'Authorization:" "$SCRIPT" || true)"
contains "auth header printf redirects into the token file" '> "$AUTH_FILE"' "$auth_print_line"
contains "auth header printf passes the token, never a literal" '"$token"' "$auth_print_line"

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
