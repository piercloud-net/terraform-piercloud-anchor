#!/usr/bin/env bash
# .github/scripts/lib/broker-dns.sh — write anchor records and DNS-01
# challenge TXT through the pc-control broker (M1 broker leg (b) b3a;
# pc-control #131).
#
# Why the broker: the anchor runner must not hold a DNS provider token (the
# near-account-wide Gcore token is the broker's custody, not the runner's).
# Authentication is the job's GitHub OIDC token (audience `piercloud-broker`);
# the broker derives the tenant from the environment `sub`, re-checks the
# repository binding, looks the record names up in the registry's dns_name
# authority (never from this request), and — for the A record — requires the
# value to equal the anchor IP the SAME RUN reported (`report_anchor_ip` in
# broker-report.sh). A mismatch is refused 409 and nothing is written.
#
# Contract (bash 3.2 compatible; stdout carries notes, stderr carries errors):
#   write_anchor_dns <anchor_ref> <ipv4>
#     0        the broker wrote the A + dashboard CNAME (HTTP 200)
#     non-zero fail closed — missing OIDC context, malformed inputs, a
#              non-https broker URL, a network error, or a non-200 answer.
#   write_challenge <name> <value> <present|cleanup>
#     0        the broker presented/cleaned the TXT (HTTP 200)
#     non-zero fail closed (same rules; `cleanup` is 409 when the zone does
#              not hold exactly the presented value).
#   Neither ever prints the OIDC token: curl reads the Authorization header
#   and the JSON body from 0600 config files inside a 0700 temp dir, and only
#   the inputs and the HTTP status (plus a sanitized one-line body on refusal)
#   are printed.
#
# Environment:
#   ACTIONS_ID_TOKEN_REQUEST_URL / ACTIONS_ID_TOKEN_REQUEST_TOKEN — set by the
#     runner when the job carries `id-token: write`.
#   BROKER_URL — https base URL (default host broker.piercloud.net).

# The lib reuses broker-report.sh's validators and mint/post helpers so the
# token/argv discipline has one implementation (the report path is unchanged).
# shellcheck source=broker-report.sh
. "$(dirname -- "${BASH_SOURCE[0]}")/broker-report.sh"

# is_broker_challenge_name <s> — 0 iff s is `_acme-challenge.<name>` with a
# lowercase DNS name and no wildcard. The broker re-validates against the
# registry; this is the fail-early copy (no network call for junk).
is_broker_challenge_name() { # $1 = candidate
  local s="${1:-}" rest
  case "$s" in
    _acme-challenge.*) rest="${s#_acme-challenge.}" ;;
    *) return 1 ;;
  esac
  case "$rest" in
    '' | .* | *. | *..* | *'*'* | *[!a-z0-9.-]*) return 1 ;;
  esac
  [ "${#s}" -le 253 ]
}

# is_broker_challenge_value <s> — 0 iff s is a bounded base64url token (the
# broker pins ^[A-Za-z0-9_-]{1,128}$).
is_broker_challenge_value() { # $1 = candidate
  local s="${1:-}"
  case "$s" in
    '' | *[!A-Za-z0-9_-]*) return 1 ;;
  esac
  [ "${#s}" -le 128 ]
}

# _broker_dns_base — echo the validated https broker base (or fail).
_broker_dns_base() {
  local base="${BROKER_URL:-https://broker.piercloud.net}"
  # Strip every trailing slash: a single `${base%/}` leaves one trailing
  # slash and the join then doubles the separator (`//v1/...`).
  while [ "$base" != "${base%/}" ]; do base="${base%/}"; done
  _broker_validate_base "$base" || return 1
  printf '%s' "$base"
}

# write_anchor_dns <anchor_ref> <ipv4> — publish the tenant's anchor A record
# and dashboard CNAME through the broker. The broker refuses (409) when the
# IP does not equal the one this run reported.
write_anchor_dns() { # $1 = anchor_ref, $2 = ipv4
  local ref="${1:-}" ip="${2:-}" base body work rc=0

  if ! is_broker_anchor_ref "$ref"; then
    echo "::error::broker dns: anchor_ref must match [a-z0-9._-]{1,64} — refusing." >&2
    return 1
  fi
  if ! is_broker_ipv4 "$ip"; then
    echo "::error::broker dns: ipv4 is not a canonical dotted-quad — refusing." >&2
    return 1
  fi
  base="$(_broker_dns_base)" || {
    echo "::error::broker dns: BROKER_URL must be a plain https URL (no userinfo/query/fragment) — refusing." >&2
    return 1
  }
  body="$(jq -cn --arg ref "$ref" --arg ip "$ip" '{anchor_ref:$ref,ipv4:$ip}')" || {
    echo "::error::broker dns: cannot encode the request body — refusing." >&2
    return 1
  }
  work="$(mktemp -d "${TMPDIR:-/tmp}/broker-dns.XXXXXX")" || {
    echo "::error::broker dns: cannot create a temp dir — refusing." >&2
    return 1
  }
  _broker_post_json "broker dns" "$base" "/v1/anchors/dns" "$body" "$work" || rc=$?
  rm -rf "$work"
  [ "$rc" -eq 0 ] || return "$rc"
  echo "anchor DNS records written through the broker (anchor_ref=${ref})."
  return 0
}

# write_challenge <name> <value> <present|cleanup> — present or clean up one
# DNS-01 TXT through the broker. The broker authorizes the name against the
# caller tenant's registered dns_name rows and refuses wildcards.
write_challenge() { # $1 = name, $2 = value, $3 = action
  local name="${1:-}" value="${2:-}" action="${3:-}" base body work rc=0

  if ! is_broker_challenge_name "$name"; then
    echo "::error::broker dns: challenge name must be _acme-challenge.<lowercase dns name> with no wildcard — refusing." >&2
    return 1
  fi
  if ! is_broker_challenge_value "$value"; then
    echo "::error::broker dns: challenge value must be a bounded base64url token — refusing." >&2
    return 1
  fi
  case "$action" in
    present | cleanup) ;;
    *)
      echo "::error::broker dns: action must be present|cleanup — refusing." >&2
      return 1
      ;;
  esac
  base="$(_broker_dns_base)" || {
    echo "::error::broker dns: BROKER_URL must be a plain https URL (no userinfo/query/fragment) — refusing." >&2
    return 1
  }
  body="$(jq -cn --arg n "$name" --arg v "$value" --arg a "$action" '{name:$n,value:$v,action:$a}')" || {
    echo "::error::broker dns: cannot encode the request body — refusing." >&2
    return 1
  }
  work="$(mktemp -d "${TMPDIR:-/tmp}/broker-dns.XXXXXX")" || {
    echo "::error::broker dns: cannot create a temp dir — refusing." >&2
    return 1
  }
  _broker_post_json "broker dns" "$base" "/v1/dns/challenges" "$body" "$work" || rc=$?
  rm -rf "$work"
  [ "$rc" -eq 0 ] || return "$rc"
  echo "challenge ${action} accepted by the broker (name=${name})."
  return 0
}
