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
# `anchor-<sanitized>-01.piercloud.net`; NN=01 — a second operator anchor
# for one alias (-02+) is a future multi-anchor case, not handled here),
# resolves the zone id at runtime (one fewer stored secret), creates or
# overwrites the A record to the exact anchor IPv4 (TTL 300, DNS-only),
# then re-reads the record and fails unless name + address match exactly.
#
# SCOPE (D8): the operator zone mints names only for operator-provisioned
# netcup anchors. A BYO twin anchor keeps its tenant-owned URL via the
# module's extra_tang_urls input — no record is minted here for twins.
#
# ENV (identifiers arrive via environment — never argv, never logs):
#   TENANT_USER            repo tenant username, e.g. "pier" -> anchor-pier-01.
#   ANCHOR_IPV4            exact anchor IPv4 the A record must carry.
#   CLOUDFLARE_DNS_TOKEN   API token with DNS-edit on piercloud.net.
#                          Absent + this job running (mode=apply) = explicit
#                          error: set the CLOUDFLARE_DNS_TOKEN org secret,
#                          then re-dispatch (C-A fail-closed — no fallback,
#                          none permitted). mode=check never runs this job
#                          and never requires the token.
#
# Zone `piercloud.net` is hardcoded below: public DNS info, not a secret.
# `proxied:false` is load-bearing: plain-HTTP tang must not sit behind the
# orange cloud. `curl -sS` only, no `-v`, no TF_LOG; logs carry jq-selected
# public fields only (name/type/address/ttl/proxied) — never the token and
# never whole API responses.
#
# No new GitHub Actions needed: curl + jq (preinstalled on runners) suffice.

set -euo pipefail

CF_ZONE="piercloud.net" # public DNS info, not a secret.
CF_API="https://api.cloudflare.com/client/v4"

alias="${TENANT_USER:?TENANT_USER is required}"
want_ip="${ANCHOR_IPV4:?ANCHOR_IPV4 is required}"
want_ip="${want_ip%%/*}"  # email prints 203.0.113.10/22-style — strip any /suffix
case "$want_ip" in ''|*[!0-9.]*) echo "::error::ANCHOR_IPV4 is not a bare IPv4 after stripping any /suffix."; exit 1;; esac

# Fail closed (C-A): without the token this job cannot prove the record,
# and the ordering is load-bearing — error out with the fix, never skip.
if [ -z "${CLOUDFLARE_DNS_TOKEN:-}" ]; then
  echo "::error::CLOUDFLARE_DNS_TOKEN is not set — DNS upsert is required on mode=apply. Set the CLOUDFLARE_DNS_TOKEN org secret (DNS-edit on piercloud.net), then re-dispatch. Refusing to publish a thumbprint against an unverified name."
  exit 1
fi
# Mask FIRST, before any use below (same ordering rule as the device-secret
# masks in provision.yml; repo-secret values are auto-masked, this covers
# every expansion path).
echo "::add-mask::$CLOUDFLARE_DNS_TOKEN"

# D5: lowercase, alnum + hyphen only; anything else becomes a hyphen, runs
# collapse, edges trim. Empty after cleaning = refuse.
san="$(printf '%s' "$alias" | tr '[:upper:]' '[:lower:]' | sed -e 's/[^a-z0-9-]/-/g' -e 's/-\{2,\}/-/g' -e 's/^-//' -e 's/-$//')"
if [ -z "$san" ]; then
  echo "::error::TENANT_USER sanitizes to empty — set a username with letters/digits/hyphens."
  exit 1
fi
record="anchor-${san}-01" # NN=01; -02+ is a future multi-anchor case.
fqdn="${record}.${CF_ZONE}"
echo "record: $fqdn -> $want_ip"

auth=(-sS -H "Authorization: Bearer $CLOUDFLARE_DNS_TOKEN" -H "Content-Type: application/json")

zone_id="$(curl "${auth[@]}" "$CF_API/zones?name=$CF_ZONE" | jq -r '.result[0].id // empty')"
if [ -z "$zone_id" ]; then
  echo "::error::could not resolve zone id for $CF_ZONE — check the token scope and try again."
  exit 1
fi

existing="$(curl "${auth[@]}" "$CF_API/zones/$zone_id/dns_records?type=A&name=$fqdn")"
rec_id="$(printf '%s' "$existing" | jq -r '.result[0].id // empty')"
rec_ip="$(printf '%s' "$existing" | jq -r '.result[0].content // empty')"

# List-then-write IS the create-or-overwrite: PUT when the name exists,
# POST when it doesn't. TTL 300; proxied:false keeps tang DNS-only.
body="$(jq -n --arg name "$fqdn" --arg ip "$want_ip" '{type:"A", name:$name, content:$ip, ttl:300, proxied:false, comment:"operator anchor; DNS-only (proxied off)"}')"
if [ -n "$rec_id" ]; then
  echo "record exists ($rec_ip) — overwriting to the exact anchor address."
  curl "${auth[@]}" -X PUT --data "$body" "$CF_API/zones/$zone_id/dns_records/$rec_id" > /dev/null
else
  echo "no record yet — creating."
  curl "${auth[@]}" -X POST --data "$body" "$CF_API/zones/$zone_id/dns_records" > /dev/null
fi

# Verify-after-write: re-read and exact-match name + address, else fail.
verify="$(curl "${auth[@]}" "$CF_API/zones/$zone_id/dns_records?type=A&name=$fqdn")"
got_name="$(printf '%s' "$verify" | jq -r '.result[0].name // empty')"
got_ip="$(printf '%s' "$verify" | jq -r '.result[0].content // empty')"
printf '%s' "$verify" | jq '{name: .result[0].name, type: .result[0].type, content: .result[0].content, ttl: .result[0].ttl, proxied: .result[0].proxied}'
if [ "$got_name" != "$fqdn" ] || [ "$got_ip" != "$want_ip" ]; then
  echo "::error::verify-after-write mismatch: want $fqdn -> $want_ip, zone answers $got_name -> $got_ip. STOP — investigate before any bind-by-name."
  exit 1
fi
echo "verified: $fqdn -> $want_ip (DNS-only, ttl 300)."
