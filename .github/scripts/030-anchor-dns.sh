#!/usr/bin/env bash
#
# 030-anchor-dns.sh — operator-zone DNS upsert for provisioned anchors.
#
# WHERE THIS RUNS: on the ephemeral GitHub Actions runner, in the
# `provision.yml` `anchor-dns` job (needs device-flow, so the A1 window is
# already closed and swept; the thumbprint job needs this job, so a DNS
# failure fails the run before any thumbprint goes out — we never bind
# by name against a record we didn't just verify). CI-called, never `scripts/`.
#
# WHAT IT DOES: derives the flat anchor name from TENANT_USER (D5:
# `anchor-01-<sanitized>.piercloud.net`; NN=01 — a second operator anchor
# for one alias (-02+) is a future multi-anchor case, not handled here),
# resolves the zone, creates or overwrites the anchor A record to the exact
# anchor IPv4 (TTL 300, DNS-only), then re-reads the record and fails unless
# the rrset is EXACTLY one record with the wanted name + address (+ ttl;
# + the enabled flag on Gcore) — a stale extra record fails closed. A2
# (2026-09-30): the per-tenant dashboard record is GONE — the nested
# `<tenant>.status.piercloud.net` dashboard is covered by the platform
# `*.status.piercloud.net` wildcard (one platform record for the whole
# fleet, never one per tenant).
#
# PROVIDER SWITCH (A2): NET_DNS_PROVIDER=cloudflare|gcore (default
# cloudflare). `piercloud.net` moves from Cloudflare to Gcore at the B
# session; the switch writes either zone with the same guarantees, flipped
# by a repo variable — no code change. NET_DNS_ZONE overrides the zone
# (canary-proof target `pc-canary.com`; production default `piercloud.net`);
# ANCHOR_TTL overrides the record TTL (test seam; default 300).
#
# SCOPE (D8): the operator zone mints names only for operator-provisioned
# netcup anchors. A BYO twin anchor keeps its tenant-owned URL via the
# module's extra_tang_urls input — no record is minted here for twins.
#
# ENV (identifiers arrive via environment — never argv, never logs; the
# token reaches curl through a 0600 header FILE (`-H @file`), never argv):
#   TENANT_USER            repo tenant username, e.g. "pier" -> anchor-01-pier.
#   ANCHOR_IPV4            exact anchor IPv4 the A record must carry.
#   NET_DNS_PROVIDER       cloudflare (default) | gcore.
#   NET_DNS_ZONE           zone name; default piercloud.net.
#   ANCHOR_TTL             record TTL; default 300 (Gcore Free floor 120).
#   CLOUDFLARE_DNS_TOKEN   DNS-edit token for the zone (provider=cloudflare).
#   GCORE_DNS_TOKEN        Gcore API token (provider=gcore).
#                          Absent + this job running (mode=apply) = explicit
#                          error naming the org secret, then re-dispatch
#                          (C-A fail-closed — no fallback, none permitted).
#                          mode=check never runs this job and never requires
#                          a token.
#
# `proxied:false` on the anchor record is load-bearing: plain-HTTP tang
# must not sit behind the orange cloud. Gcore is authoritative-only (no
# proxy concept) — the same DNS-only invariant. `curl -sS` only, no `-v`,
# no TF_LOG; logs carry jq-selected public fields only (name/type/address/
# ttl) — never the token and never whole API responses.
#
# No new GitHub Actions needed: curl + jq (preinstalled on runners) suffice.

set -euo pipefail

# D8: naming comes from the one canonical lib (single source — the workflow
# resolve step and the on-box 010 fallback consume the same functions).
. scripts/lib/naming.sh

ZONE="${NET_DNS_ZONE:-piercloud.net}" # public DNS info, not a secret.
# A real zone: >=2 labels, lowercase alnum/hyphen, no leading/trailing
# hyphen or dot (`.`/`..`/`-x`/`x.` all fail closed — no curl path tricks).
if ! [[ "$ZONE" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]]; then
  echo "::error::NET_DNS_ZONE='$ZONE' is not a valid zone name — refusing to touch an unverified zone."
  exit 1
fi
PROVIDER="${NET_DNS_PROVIDER:-cloudflare}"
case "$PROVIDER" in
  cloudflare | gcore) ;;
  *) echo "::error::NET_DNS_PROVIDER='$PROVIDER' is not one of cloudflare|gcore — refusing to guess a provider."; exit 1 ;;
esac

ANCHOR_TTL="${ANCHOR_TTL:-300}" # DNS-only record TTL; Gcore Free rejects TTL < 120 s at the API.
case "$ANCHOR_TTL" in '' | *[!0-9]*) echo "::error::ANCHOR_TTL='$ANCHOR_TTL' is not an integer."; exit 1 ;; esac

CF_API="https://api.cloudflare.com/client/v4"
GCORE_API="https://api.gcore.com"

alias="${TENANT_USER:?TENANT_USER is required}"
want_ip="${ANCHOR_IPV4:?ANCHOR_IPV4 is required}"
want_ip="${want_ip%%/*}"  # email prints 203.0.113.10/22-style — strip any /suffix
case "$want_ip" in '' | *[!0-9.]*) echo "::error::ANCHOR_IPV4 is not a bare IPv4 after stripping any /suffix."; exit 1 ;; esac

# Fail closed (C-A): without the provider's token this job cannot prove the
# record, and the ordering is load-bearing — error out with the fix, never
# skip. Mask FIRST, before any use below (repo-secret values are auto-masked,
# this covers every expansion path).
case "$PROVIDER" in
  cloudflare) token="${CLOUDFLARE_DNS_TOKEN:-}"; secret_name="CLOUDFLARE_DNS_TOKEN" ;;
  gcore) token="${GCORE_DNS_TOKEN:-}"; secret_name="GCORE_DNS_TOKEN" ;;
esac
if [ -z "$token" ]; then
  echo "::error::${secret_name} is not set — DNS upsert is required on mode=apply (provider=${PROVIDER}). Set the ${secret_name} org secret, then re-dispatch. Refusing to publish a thumbprint against an unverified name."
  exit 1
fi
# Header-injection guard: the token lands in an HTTP header FILE, so a
# whitespace/control character would forge a second header. Tokens never
# contain one; refuse rather than trust.
case "$token" in *[[:space:]]*) echo "::error::${secret_name} contains whitespace — refusing to build the auth header."; exit 1 ;; esac
echo "::add-mask::$token"
# Token transport: curl reads the header from a 0600 file (`-H @file`) so the
# near-account-wide Gcore token never appears in curl's argv (/proc/*/cmdline,
# core dumps) — the "never argv" invariant holds end to end.
AUTH_FILE="$(mktemp)"
chmod 0600 "$AUTH_FILE"
trap 'rm -f "$AUTH_FILE"' EXIT
case "$PROVIDER" in
  cloudflare) printf 'Authorization: Bearer %s\nContent-Type: application/json\n' "$token" > "$AUTH_FILE" ;;
  gcore) printf 'Authorization: APIKey %s\nContent-Type: application/json\n' "$token" > "$AUTH_FILE" ;;
esac
auth=(-sS -H "@$AUTH_FILE")

# D5: lowercase, alnum + hyphen only; anything else becomes a hyphen, runs
# collapse, edges trim. Empty after cleaning = refuse.
san="$(sanitize_tenant "$alias")"
if [ -z "$san" ]; then
  echo "::error::TENANT_USER sanitizes to empty — set a username with letters/digits."
  exit 1
fi
record="$(derive_anchor_hostname "$san")" # NN=01; -02+ is a future multi-anchor case.

# Write helper: fail on any non-2xx write response (a rejected PUT/POST must
# never reach the verify step as a silent success).
assert_write_ok() { # $1 = provider label, $2 = method, $3 = url, $4 = body
  local code
  code="$(curl "${auth[@]}" -o /dev/null -w '%{http_code}' -X "$2" --data "$4" "$3")"
  case "$code" in
    2*) return 0 ;;
    *) echo "::error::$1 write ($2) returned HTTP ${code} — the record was NOT written; STOP before any bind-by-name."; exit 1 ;;
  esac
}

# ---------------------------------------------------------------------------
# Cloudflare driver (provider=cloudflare; today's production path).
# ---------------------------------------------------------------------------
cf_upsert_anchor() {
  local fqdn existing rec_id rec_ip body verify zone_id
  local got_name got_ip got_proxied got_ttl count
  fqdn="${record}.${ZONE}"
  zone_id="$(curl "${auth[@]}" "$CF_API/zones?name=$ZONE" | jq -r '.result[0].id // empty')"
  if [ -z "$zone_id" ]; then
    echo "::error::could not resolve zone id for $ZONE — check the token scope and try again."
    exit 1
  fi
  echo "record: $fqdn -> $want_ip (provider=cloudflare, proxied=false, ttl=${ANCHOR_TTL})"
  existing="$(curl "${auth[@]}" "$CF_API/zones/$zone_id/dns_records?type=A&name=$fqdn")"
  rec_id="$(printf '%s' "$existing" | jq -r '.result[0].id // empty')"
  rec_ip="$(printf '%s' "$existing" | jq -r '.result[0].content // empty')"
  # List-then-write IS the create-or-overwrite: PUT when the name exists,
  # POST when it doesn't.
  body="$(jq -n --arg name "$fqdn" --arg ip "$want_ip" --argjson ttl "$ANCHOR_TTL" '{type:"A", name:$name, content:$ip, ttl:$ttl, proxied:false, comment:"operator anchor; DNS-only (proxied off)"}')"
  if [ -n "$rec_id" ]; then
    echo "record exists ($rec_ip) — overwriting to the exact anchor address."
    assert_write_ok cloudflare PUT "$CF_API/zones/$zone_id/dns_records/$rec_id" "$body"
  else
    echo "no record yet — creating."
    assert_write_ok cloudflare POST "$CF_API/zones/$zone_id/dns_records" "$body"
  fi
  # Verify-after-write: re-read and exact-match the rrset (exactly one A
  # record) name + address + proxied + ttl, else fail.
  verify="$(curl "${auth[@]}" "$CF_API/zones/$zone_id/dns_records?type=A&name=$fqdn")"
  count="$(printf '%s' "$verify" | jq -r '(.result // []) | length')"
  got_name="$(printf '%s' "$verify" | jq -r '.result[0].name // empty')"
  got_ip="$(printf '%s' "$verify" | jq -r '.result[0].content // empty')"
  # NOT `.proxied // empty`: jq's alternative operator treats false as empty,
  # so a DNS-only record (proxied=false) read as "" and this check aborted a
  # fully provisioned run (live 2026-09-10, #85). tostring keeps false.
  got_proxied="$(printf '%s' "$verify" | jq -r '(.result[0] // {}) | .proxied | tostring')"
  got_ttl="$(printf '%s' "$verify" | jq -r '(.result[0] // {}) | .ttl | tostring')"
  printf '%s' "$verify" | jq '{name: .result[0].name, type: .result[0].type, content: .result[0].content, ttl: .result[0].ttl, proxied: .result[0].proxied}'
  if [ "$count" != "1" ] || [ "$got_name" != "$fqdn" ] || [ "$got_ip" != "$want_ip" ] || [ "$got_proxied" != "false" ] || [ "$got_ttl" != "$ANCHOR_TTL" ]; then
    echo "::error::verify-after-write mismatch: want exactly one $fqdn -> $want_ip (proxied=false, ttl=${ANCHOR_TTL}), zone answers ${count} record(s): $got_name -> $got_ip (proxied=$got_proxied, ttl=${got_ttl:-unknown}). STOP — investigate before any bind-by-name."
    exit 1
  fi
  echo "verified: $fqdn -> $want_ip (proxied=false, ttl=${ANCHOR_TTL})."
}

# ---------------------------------------------------------------------------
# Gcore driver (provider=gcore; the `.net` provider post-B).
# API (C8-verified 2026-09-29): `Authorization: APIKey <token>`, rrset CRUD
# by name/type path `/dns/v2/zones/{zone}/{fqdn}/{type}`, body
# `{ttl, resource_records:[{content:[...], enabled:true}]}` (A content is a
# single string in the array), GET returns 404 for a missing rrset.
# ---------------------------------------------------------------------------
gcore_upsert_anchor() {
  local fqdn body tmp code
  local got_name got_ip got_ttl got_enabled count
  fqdn="${record}.${ZONE}"
  if [ "$ANCHOR_TTL" -lt 120 ]; then
    echo "::error::TTL ${ANCHOR_TTL}s is below the Gcore Free floor of 120s — fix ANCHOR_TTL before writing."
    exit 1
  fi
  echo "record: $fqdn -> $want_ip (provider=gcore, ttl=${ANCHOR_TTL})"
  body="$(jq -n --arg ip "$want_ip" --argjson ttl "$ANCHOR_TTL" '{ttl:$ttl, resource_records:[{content:[$ip], enabled:true}]}')"
  tmp="$(mktemp)"
  code="$(curl "${auth[@]}" -o "$tmp" -w '%{http_code}' "$GCORE_API/dns/v2/zones/$ZONE/$fqdn/A")"
  case "$code" in
    200)
      echo "record exists — overwriting to the exact anchor address."
      assert_write_ok gcore PUT "$GCORE_API/dns/v2/zones/$ZONE/$fqdn/A" "$body"
      ;;
    404)
      echo "no record yet — creating."
      assert_write_ok gcore POST "$GCORE_API/dns/v2/zones/$ZONE/$fqdn/A" "$body"
      ;;
    *)
      rm -f "$tmp"
      echo "::error::Gcore GET $fqdn/A returned HTTP ${code} — check the token scope and the zone name, then re-dispatch."
      exit 1
      ;;
  esac
  # Verify-after-write: re-read and exact-match the rrset (exactly one
  # record) name + address + ttl + enabled.
  code="$(curl "${auth[@]}" -o "$tmp" -w '%{http_code}' "$GCORE_API/dns/v2/zones/$ZONE/$fqdn/A")"
  if [ "$code" != "200" ]; then
    rm -f "$tmp"
    echo "::error::verify-after-write GET $fqdn/A returned HTTP ${code} — cannot prove the record. STOP — investigate before any bind-by-name."
    exit 1
  fi
  count="$(jq -r '(.resource_records // []) | length' "$tmp")"
  got_name="$(jq -r '.name // empty' "$tmp" | sed 's/\.$//')"
  got_ip="$(jq -r '(.resource_records[0] // {}) | .content | if type == "array" then (.[0] // "") else (. // "") end' "$tmp")"
  got_ttl="$(jq -r '.ttl // empty' "$tmp")"
  # Boolean read via tostring (never `// empty` — false is empty to jq; CI's
  # jq-boolean-guard enforces this shape).
  got_enabled="$(jq -r '(.resource_records[0] // {}) | .enabled | tostring' "$tmp")"
  jq '{name: .name, type: .type, ttl: .ttl, resource_records: .resource_records}' "$tmp"
  rm -f "$tmp"
  if [ "$count" != "1" ] || [ "$got_name" != "$fqdn" ] || [ "$got_ip" != "$want_ip" ] || [ "$got_ttl" != "$ANCHOR_TTL" ] || [ "$got_enabled" != "true" ]; then
    echo "::error::verify-after-write mismatch: want exactly one $fqdn -> $want_ip (ttl=${ANCHOR_TTL}, enabled=true), zone answers ${count} record(s): $got_name -> $got_ip (ttl=${got_ttl:-unknown}, enabled=${got_enabled:-unknown}). STOP — investigate before any bind-by-name."
    exit 1
  fi
  echo "verified: $fqdn -> $want_ip (ttl=${ANCHOR_TTL}, enabled=true)."
}

case "$PROVIDER" in
  cloudflare) cf_upsert_anchor ;;
  gcore) gcore_upsert_anchor ;;
esac
