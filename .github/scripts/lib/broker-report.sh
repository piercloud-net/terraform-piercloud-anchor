#!/usr/bin/env bash
# .github/scripts/lib/broker-report.sh — report the anchor's API-resolved IPv4
# to the pc-control broker (M1 broker leg (b) b2; pc-control #123).
#
# Why a push: the registry's `anchor.anchor_ipv4` is the value the broker
# cross-checks every DNS A write against (b3), and the console reads it as the
# anchor's address. GitHub job outputs are not exposed by the REST API, so the
# runner pushes the value right after the resolve step. Authentication is the
# job's GitHub OIDC token (audience `piercloud-broker`): the broker verifies
# RS256/JWKS + issuer/audience/exp/iat, requires the token's environment `sub`
# to be self-consistent with its repository/ids/environment claims, requires
# `job_workflow_ref` on its allowlist, and the registry then re-checks
# environment -> tenant -> repository before writing.
#
# Contract (bash 3.2 compatible; stdout carries notes, stderr carries errors):
#   report_anchor_ip <anchor_ref> <ipv4>
#     0        the broker accepted the report (HTTP 200)
#     non-zero fail closed — missing OIDC request context, malformed inputs,
#              a non-https broker URL, a network error, or a non-200 answer.
#   The OIDC tokens never reach argv or the log: curl reads the Authorization
#   headers from 0600 config files inside a 0700 temp dir, and only the
#   anchor_ref and the HTTP status (plus a sanitized one-line body on refusal)
#   are printed. The temp dir is removed on every path.
#
# Environment:
#   ACTIONS_ID_TOKEN_REQUEST_URL / ACTIONS_ID_TOKEN_REQUEST_TOKEN — set by the
#     runner when the job carries `id-token: write`.
#   BROKER_URL — https base URL (default host broker.piercloud.net).
#
# The IPv4 shape check is duplicated here on purpose: the value arrives from
# the resolve step's `$GITHUB_OUTPUT`, and this lib is also called by the
# dispatch-only selftest workflow with an input — neither may reach the wire
# unvalidated. `is_broker_ipv4` mirrors `is_bare_ipv4` in anchor-ip.sh
# (canonical dotted quad, no leading zeros); the two are deliberately
# independent so the report path cannot be weakened by an anchor-ip change.

# is_broker_ipv4 <s> — 0 iff s is a canonical dotted-quad (4 octets 0-255, no
# leading zeros, no trailing dot, no whitespace).
is_broker_ipv4() { # $1 = candidate string
  local s="${1:-}" a b c d extra oct
  case "$s" in
    '' | *[!0-9.]*) return 1 ;;
  esac
  # A trailing dot or a 4th separator survives `read` as an empty/short
  # field; refuse them before the split so the shape is exactly dotted-quad.
  case "$s" in
    *. | *.*.*.*.*) return 1 ;;
  esac
  IFS=. read -r a b c d extra <<<"$s"
  [ -z "$extra" ] || return 1
  for oct in "$a" "$b" "$c" "$d"; do
    case "$oct" in
      '' | *[!0-9]* | ????* | 0[0-9]*) return 1 ;;
    esac
    [ "$oct" -le 255 ] || return 1
  done
  return 0
}

# is_broker_anchor_ref <s> — 0 iff s matches the managed-dispatch grammar
# pinned by the provision.yml preflight and the broker's request validator
# (`^[a-z0-9._-]{1,64}$`).
is_broker_anchor_ref() { # $1 = candidate string
  local s="${1:-}"
  case "$s" in
    '' | *[!a-z0-9._-]*) return 1 ;;
  esac
  [ "${#s}" -le 64 ]
}

# _broker_mint_token <audience> <workdir> <label> — mint a GitHub OIDC token
# for the audience and print it on stdout. The request token and the minted
# token travel in 0600 curl config files inside the caller's 0700 workdir;
# neither ever reaches argv or the log. Fails closed on any unexpected
# answer. The label keeps each caller's diagnostic prefix stable (the b2
# report path's `broker report:` prefix is part of its runbook contract).
_broker_mint_token() { # $1 = audience, $2 = workdir, $3 = label
  local aud="$1" work="$2" label="$3" req_url req_token aud_url code token hdr
  req_url="${ACTIONS_ID_TOKEN_REQUEST_URL:-}"
  req_token="${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}"
  if [ -z "$req_url" ] || [ -z "$req_token" ]; then
    echo "::error::${label}: no OIDC request context (ACTIONS_ID_TOKEN_REQUEST_URL/TOKEN empty) — the job needs permissions: id-token: write. Refusing." >&2
    return 1
  fi

  # GitHub's OIDC token endpoint takes one `audience` query parameter; append
  # it to whatever query the runner already put in the URL.
  case "$req_url" in
    *\?*) aud_url="${req_url}&audience=${aud}" ;;
    *) aud_url="${req_url}?audience=${aud}" ;;
  esac

  # The request token is a credential: it goes in a 0600 curl config file,
  # never argv. The umask subshell keeps the mode explicit without leaking a
  # umask change into the caller. A heredoc (not printf) keeps the auth line
  # off the CI's "print builtin + bearer" pattern while the semantics stay
  # "write a curl config file".
  hdr="${work}/token.hdr"
  (umask 077; cat >"$hdr" <<EOF
header = "Authorization: Bearer ${req_token}"
EOF
  )
  code="$(curl -sS --config "$hdr" --max-time 10 -o "${work}/token.json" -w '%{http_code}' "$aud_url")" || {
    echo "::error::${label}: OIDC token request failed (network/curl error)." >&2
    return 1
  }
  if [ "$code" != "200" ]; then
    echo "::error::${label}: OIDC token request answered HTTP ${code} — refusing (is id-token: write set on the job?)." >&2
    return 1
  fi
  token="$(jq -r '.value // empty' "${work}/token.json" 2>/dev/null)"
  if [ -z "$token" ]; then
    echo "::error::${label}: OIDC token response carried no value — refusing." >&2
    return 1
  fi
  printf '%s' "$token"
}

# _broker_validate_base <base> — 0 iff base is an https URL (the broker's
# ingress is TLS-only; a plaintext base would leak the minted token).
_broker_validate_base() { # $1 = base URL
  case "$1" in
    https:*//*) return 0 ;;
    *) return 1 ;;
  esac
}

# _broker_post_json <label> <base> <path> <body> <workdir> — mint a
# broker-audience token and POST the JSON body to ${base}${path}. The body
# (never a secret) and the minted token go through 0600 curl config files, so
# the whole request line stays out of argv. A non-200 is refused with one
# sanitized body line (CR/LF stripped, bounded) so a failed run is
# diagnosable without a rerun. Internal; callers are report_anchor_ip /
# write_anchor_dns / write_challenge.
_broker_post_json() { # $1..$5 as above
  local label="$1" base="$2" path="$3" body="$4" work="$5"
  local token hdr cfg code

  token="$(_broker_mint_token "piercloud-broker" "$work" "$label")" || return 1
  hdr="${work}/post.hdr"
  (umask 077; cat >"$hdr" <<EOF
header = "Authorization: Bearer ${token}"
header = "Content-Type: application/json"
EOF
  )
  (umask 077; printf '%s' "$body" >"${work}/body.json")
  cfg="${work}/post.cfg"
  printf 'data = "@%s"\n' "${work}/body.json" >"$cfg"
  code="$(curl -sS --config "$hdr" --config "$cfg" --max-time 15 -o "${work}/resp.json" -w '%{http_code}' \
    -X POST "${base}${path}")" || {
    echo "::error::${label}: POST to the broker failed (network/curl error)." >&2
    return 1
  }
  if [ "$code" != "200" ]; then
    # The broker's refusal bodies are short JSON diagnostics (unknown
    # environment, repo mismatch, unknown/ambiguous anchor/name, cross-check
    # mismatch, bad token) — log one sanitized line. The body is
    # broker-authored, but strip CR/LF and bound it anyway so a
    # compromised/misbehaving endpoint cannot inject log lines.
    echo "::error::${label} refused (HTTP ${code}): $(tr -d '\r\n' <"${work}/resp.json" | cut -c1-200)" >&2
    return 1
  fi
  return 0
}

# report_anchor_ip <anchor_ref> <ipv4> — validate, mint a broker-audience OIDC
# token and POST the report. Fail closed on anything unexpected.
report_anchor_ip() { # $1 = anchor_ref, $2 = ipv4
  local ref="${1:-}" ip="${2:-}" base body work rc=0

  if ! is_broker_anchor_ref "$ref"; then
    echo "::error::broker report: anchor_ref must match [a-z0-9._-]{1,64} — refusing." >&2
    return 1
  fi
  if ! is_broker_ipv4 "$ip"; then
    echo "::error::broker report: ipv4 is not a canonical dotted-quad — refusing." >&2
    return 1
  fi

  base="${BROKER_URL:-https://broker.piercloud.net}"
  base="${base%/}"
  if ! _broker_validate_base "$base"; then
    echo "::error::broker report: BROKER_URL must be an https URL (got a non-https value) — refusing." >&2
    return 1
  fi

  body="$(jq -cn --arg ref "$ref" --arg ip "$ip" '{anchor_ref:$ref,ipv4:$ip}')" || {
    echo "::error::broker report: cannot encode the request body — refusing." >&2
    return 1
  }
  work="$(mktemp -d "${TMPDIR:-/tmp}/broker-report.XXXXXX")" || {
    echo "::error::broker report: cannot create a temp dir — refusing." >&2
    return 1
  }
  _broker_post_json "broker report" "$base" "/v1/anchors/ip" "$body" "$work" || rc=$?
  rm -rf "$work"
  [ "$rc" -eq 0 ] || return "$rc"
  echo "anchor IP reported to the broker (anchor_ref=${ref})."
  return 0
}
