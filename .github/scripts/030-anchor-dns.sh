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
# for one alias (-02+) is a future multi-anchor case, not handled here) and
# the nested dashboard name (`<sanitized>.status.piercloud.net`), resolves
# the zone, then upserts BOTH records (TTL 300, DNS-only):
#   1. the anchor A record -> the exact anchor IPv4 (clevis bind-by-name);
#   2. the dashboard CNAME -> STATUS_EDGE_DOMAIN (the CloudFront distribution).
# After each write it re-reads the rrset and fails unless it is EXACTLY one
# record with the wanted name + content (+ ttl; + the enabled flag on Gcore)
# — a stale extra record fails closed.
#
# WHY THE DASHBOARD CNAME EXISTS (2026-10-07): the `*.status.piercloud.net`
# wildcard alone is not enough on an RFC 4592-strict provider. During every
# ACME DNS-01 issuance/renewal the challenge node
# `_acme-challenge.<tenant>.status.piercloud.net` exists, which makes
# `<tenant>.status.piercloud.net` an empty non-terminal — wildcard synthesis
# stops (NODATA) and the dashboard goes dark for the node's lifetime.
# Cloudflare masked this (its wildcard synthesizes at any depth and ignores
# ENTs); Gcore, the post-B `.net` provider, is strict (live: the carried
# placeholder node darkened pier.status.piercloud.net until deleted). An
# explicit CNAME answers the name directly, so a challenge node can never
# block it. Cost = one record per tenant (Gcore is uncapped; "zero per-tenant
# dashboard records" was an artifact of the Cloudflare 200-record cap).
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
#   STATUS_EDGE_DOMAIN     CloudFront distribution hostname the dashboard
#                          CNAME must carry (e.g. d123.cloudfront.net);
#                          absent = explicit error (fail closed: a run that
#                          cannot write the dashboard name leaves it
#                          wildcard-only, i.e. dark at every renewal).
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
# `proxied:false` on both records is load-bearing: plain-HTTP tang
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
# Header-injection guard: the token lands in an HTTP header FILE, so a CR/LF
# (the only bytes that can forge a second header) would break it. Refuse any
# whitespace or control byte rather than trust.
case "$token" in *[[:space:][:cntrl:]]*) echo "::error::${secret_name} contains whitespace or a control character — refusing to build the auth header."; exit 1 ;; esac
echo "::add-mask::$token"
# Token transport: curl reads the header from a 0600 file (`-H @file`) so the
# near-account-wide Gcore token never appears in curl's argv (/proc/*/cmdline,
# core dumps) — the "never argv" invariant holds end to end.
AUTH_FILE="$(mktemp)"
chmod 0600 "$AUTH_FILE"
# EXIT covers normal paths; the signal traps also remove the file when a job
# is cancelled (SIGKILL cannot be trapped — the runner VM teardown is the
# backstop there).
cleanup_auth_file() { rm -f "$AUTH_FILE"; }
trap cleanup_auth_file EXIT
trap 'cleanup_auth_file; exit 130' INT
trap 'cleanup_auth_file; exit 143' TERM
trap 'cleanup_auth_file; exit 129' HUP
# The auth scheme is a separate constant so no shell print builtin ever
# carries the scheme literal on its own line (C-A secret-print contract).
case "$PROVIDER" in
  cloudflare) auth_scheme="Bearer" ;;
  gcore) auth_scheme="APIKey" ;;
esac
printf 'Authorization: %s %s\nContent-Type: application/json\n' "$auth_scheme" "$token" > "$AUTH_FILE"
auth=(-sS -H "@$AUTH_FILE")

# Dashboard CNAME target (the platform status edge). Fail closed when absent:
# without it the dashboard name stays wildcard-only and goes dark at every
# renewal (the challenge node makes it an ENT — see the header). Validated as
# a hostname (lowercase, no trailing dot) so it cannot smuggle a path/space
# into the curl URL. Checked after the credential gate on purpose: a run with
# no token reports the missing secret first (the actionable error), never the
# config one.
status_edge_domain="${STATUS_EDGE_DOMAIN:-}"
if [ -z "$status_edge_domain" ]; then
  echo "::error::STATUS_EDGE_DOMAIN is not set — the dashboard CNAME target is required (the CloudFront distribution hostname, e.g. d123.cloudfront.net). Set the repo variable, then re-dispatch."
  exit 1
fi
if ! [[ "$status_edge_domain" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]]; then
  echo "::error::STATUS_EDGE_DOMAIN='$status_edge_domain' is not a valid hostname (lowercase alnum/hyphen labels, no trailing dot) — refusing to write it."
  exit 1
fi

# D5: lowercase, alnum + hyphen only; anything else becomes a hyphen, runs
# collapse, edges trim. Empty after cleaning = refuse.
san="$(sanitize_tenant "$alias")"
if [ -z "$san" ]; then
  echo "::error::TENANT_USER sanitizes to empty — set a username with letters/digits."
  exit 1
fi
record="$(derive_anchor_hostname "$san")" # NN=01; -02+ is a future multi-anchor case.
status_record="$(derive_status_host "$san")" # <tenant>.status — the dashboard name (explicit CNAME, see header).

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
cf_upsert_record() { # $1 = rr_type (A|CNAME), $2 = fqdn, $3 = wanted content, $4 = record comment
  local rr_type="$1" fqdn="$2" want_content="$3" comment="$4"
  local existing rec_id rec_content body verify zone_id
  local got_name got_content got_proxied got_ttl count
  zone_id="$(curl "${auth[@]}" "$CF_API/zones?name=$ZONE" | jq -r '.result[0].id // empty')"
  if [ -z "$zone_id" ]; then
    echo "::error::could not resolve zone id for $ZONE — check the token scope and try again."
    exit 1
  fi
  echo "record: $fqdn $rr_type -> $want_content (provider=cloudflare, proxied=false, ttl=${ANCHOR_TTL})"
  existing="$(curl "${auth[@]}" "$CF_API/zones/$zone_id/dns_records?type=$rr_type&name=$fqdn")"
  rec_id="$(printf '%s' "$existing" | jq -r '.result[0].id // empty')"
  rec_content="$(printf '%s' "$existing" | jq -r '.result[0].content // empty')"
  # List-then-write IS the create-or-overwrite: PUT when the name exists,
  # POST when it doesn't.
  body="$(jq -n --arg type "$rr_type" --arg name "$fqdn" --arg content "$want_content" --arg comment "$comment" --argjson ttl "$ANCHOR_TTL" '{type:$type, name:$name, content:$content, ttl:$ttl, proxied:false, comment:$comment}')"
  if [ -n "$rec_id" ]; then
    echo "record exists ($rec_content) — overwriting to the exact wanted content."
    assert_write_ok cloudflare PUT "$CF_API/zones/$zone_id/dns_records/$rec_id" "$body"
  else
    echo "no record yet — creating."
    assert_write_ok cloudflare POST "$CF_API/zones/$zone_id/dns_records" "$body"
  fi
  # Verify-after-write: re-read and exact-match the rrset (exactly one
  # record) name + content + proxied + ttl, else fail.
  verify="$(curl "${auth[@]}" "$CF_API/zones/$zone_id/dns_records?type=$rr_type&name=$fqdn")"
  count="$(printf '%s' "$verify" | jq -r '(.result // []) | length')"
  got_name="$(printf '%s' "$verify" | jq -r '.result[0].name // empty')"
  got_content="$(printf '%s' "$verify" | jq -r '.result[0].content // empty')"
  got_content="${got_content%.}" # DNS names compare equal with/without the root dot
  # NOT `.proxied // empty`: jq's alternative operator treats false as empty,
  # so a DNS-only record (proxied=false) read as "" and this check aborted a
  # fully provisioned run (live 2026-09-10, #85). tostring keeps false.
  got_proxied="$(printf '%s' "$verify" | jq -r '(.result[0] // {}) | .proxied | tostring')"
  got_ttl="$(printf '%s' "$verify" | jq -r '(.result[0] // {}) | .ttl | tostring')"
  printf '%s' "$verify" | jq '{name: .result[0].name, type: .result[0].type, content: .result[0].content, ttl: .result[0].ttl, proxied: .result[0].proxied}'
  if [ "$count" != "1" ] || [ "$got_name" != "$fqdn" ] || [ "$got_content" != "$want_content" ] || [ "$got_proxied" != "false" ] || [ "$got_ttl" != "$ANCHOR_TTL" ]; then
    echo "::error::verify-after-write mismatch: want exactly one $fqdn $rr_type -> $want_content (proxied=false, ttl=${ANCHOR_TTL}), zone answers ${count} record(s): $got_name -> $got_content (proxied=$got_proxied, ttl=${got_ttl:-unknown}). STOP — investigate before any bind-by-name."
    exit 1
  fi
  echo "verified: $fqdn $rr_type -> $want_content (proxied=false, ttl=${ANCHOR_TTL})."
}

# ---------------------------------------------------------------------------
# Gcore driver (provider=gcore; the `.net` provider post-B).
# API (C8-verified 2026-09-29): `Authorization: APIKey <token>`, rrset CRUD
# by name/type path `/dns/v2/zones/{zone}/{fqdn}/{type}`, body
# `{ttl, resource_records:[{content:[...], enabled:true}]}` (A/CNAME content is
# a single string in the array), GET returns 404 for a missing rrset.
# ---------------------------------------------------------------------------
gcore_upsert_record() { # $1 = rr_type (A|CNAME), $2 = fqdn, $3 = wanted content
  local rr_type="$1" fqdn="$2" want_content="$3"
  local body tmp code
  local got_name got_content got_ttl got_enabled count
  if [ "$ANCHOR_TTL" -lt 120 ]; then
    echo "::error::TTL ${ANCHOR_TTL}s is below the Gcore Free floor of 120s — fix ANCHOR_TTL before writing."
    exit 1
  fi
  echo "record: $fqdn $rr_type -> $want_content (provider=gcore, ttl=${ANCHOR_TTL})"
  body="$(jq -n --arg content "$want_content" --argjson ttl "$ANCHOR_TTL" '{ttl:$ttl, resource_records:[{content:[$content], enabled:true}]}')"
  tmp="$(mktemp)"
  code="$(curl "${auth[@]}" -o "$tmp" -w '%{http_code}' "$GCORE_API/dns/v2/zones/$ZONE/$fqdn/$rr_type")"
  case "$code" in
    200)
      echo "record exists — overwriting to the exact wanted content."
      assert_write_ok gcore PUT "$GCORE_API/dns/v2/zones/$ZONE/$fqdn/$rr_type" "$body"
      ;;
    404)
      echo "no record yet — creating."
      assert_write_ok gcore POST "$GCORE_API/dns/v2/zones/$ZONE/$fqdn/$rr_type" "$body"
      ;;
    *)
      rm -f "$tmp"
      echo "::error::Gcore GET $fqdn/$rr_type returned HTTP ${code} — check the token scope and the zone name, then re-dispatch."
      exit 1
      ;;
  esac
  # Verify-after-write: re-read and exact-match the rrset (exactly one
  # record) name + content + ttl + enabled. The content count flattens
  # every resource_records[].content value: Gcore models an A address as
  # an array inside ONE rrset entry, so counting entries alone would pass
  # a bundled [want, stale] content (count=1).
  code="$(curl "${auth[@]}" -o "$tmp" -w '%{http_code}' "$GCORE_API/dns/v2/zones/$ZONE/$fqdn/$rr_type")"
  if [ "$code" != "200" ]; then
    rm -f "$tmp"
    echo "::error::verify-after-write GET $fqdn/$rr_type returned HTTP ${code} — cannot prove the record. STOP — investigate before any bind-by-name."
    exit 1
  fi
  count="$(jq -r '[(.resource_records // [])[] | (.content // empty) | if type == "array" then .[] else . end] | length' "$tmp")"
  got_name="$(jq -r '.name // empty' "$tmp" | sed 's/\.$//')"
  got_content="$(jq -r '[(.resource_records // [])[] | (.content // empty) | if type == "array" then .[] else . end] | join(",")' "$tmp")"
  got_content="${got_content%.}" # DNS names compare equal with/without the root dot
  got_ttl="$(jq -r '.ttl // empty' "$tmp")"
  # Boolean read via tostring (never `// empty` — false is empty to jq; CI's
  # jq-boolean-guard enforces this shape). Read EVERY entry: a single disabled
  # junk entry alongside the real one must fail the exact-one proof.
  got_enabled="$(jq -r '[(.resource_records // [])[] | .enabled | tostring] | unique | join(",")' "$tmp")"
  jq '{name: .name, type: .type, ttl: .ttl, resource_records: .resource_records}' "$tmp"
  rm -f "$tmp"
  if [ "$count" != "1" ] || [ "$got_name" != "$fqdn" ] || [ "$got_content" != "$want_content" ] || [ "$got_ttl" != "$ANCHOR_TTL" ] || [ "$got_enabled" != "true" ]; then
    echo "::error::verify-after-write mismatch: want exactly one $fqdn $rr_type -> $want_content (ttl=${ANCHOR_TTL}, enabled=true), zone answers ${count} record(s): $got_name -> $got_content (ttl=${got_ttl:-unknown}, enabled=${got_enabled:-unknown}). STOP — investigate before any bind-by-name."
    exit 1
  fi
  echo "verified: $fqdn $rr_type -> $want_content (ttl=${ANCHOR_TTL}, enabled=true)."
}

# Both records, always, in order: the anchor A first (clevis bind-by-name is
# the load-bearing one), then the dashboard CNAME (renewal-proofing; the
# wildcard covers it between renewals, but an explicit record is immune to
# the ACME challenge-node ENT — see the header).
case "$PROVIDER" in
  cloudflare)
    cf_upsert_record A "${record}.${ZONE}" "$want_ip" "operator anchor; DNS-only (proxied off)"
    cf_upsert_record CNAME "${status_record}.${ZONE}" "$status_edge_domain" "per-tenant status dashboard; DNS-only (proxied off)"
    ;;
  gcore)
    gcore_upsert_record A "${record}.${ZONE}" "$want_ip"
    gcore_upsert_record CNAME "${status_record}.${ZONE}" "$status_edge_domain"
    ;;
esac
