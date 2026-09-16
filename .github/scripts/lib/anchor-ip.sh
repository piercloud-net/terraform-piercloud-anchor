#!/usr/bin/env bash
# .github/scripts/lib/anchor-ip.sh — canonical anchor address selection (issue #124).
#
# ONE source for "which IPv4 is the SSH/DNS target": the workflow resolve
# step sources this file next to scripts/lib/naming.sh and feeds it the
# netcup `GET /servers/{id}` detail JSON. Pure functions only — no network,
# no credentials, no state outside the function bodies.
#
# Security property (F2): the target can only ever be an IPv4 the resolved
# server itself reports. An explicit value (ANCHOR_IPV4) may SELECT among
# those addresses, never override them; a mismatch fails closed. A server
# reporting several IPv4s with no explicit pick fails loud with the
# address count and an operator action (P4) — never a silent first-index
# pick, and never the address values in the public log (2026-09-12
# exposure audit §4.3/§5).
#
# Contract (bash 3.2 compatible; stdout carries data, stderr carries notes):
#   is_bare_ipv4 <s>                      0 iff s is a canonical dotted-quad
#                                         (4 octets 0-255, no leading zeros,
#                                         no trailing dot).
#   anchor_ipv4_candidates <detail-json>  stdout: validated candidates, one
#                                         per line, deduped, order preserved.
#                                         Any unexpected shape fails closed
#                                         with nothing on stdout.
#   resolve_anchor_ipv4 <detail-json> <explicit|""> <label>
#                                         stdout: ONLY the chosen IPv4.
#                                         stderr: one-line note on success,
#                                         ::error:: + count/action on
#                                         failure; candidate values are
#                                         NEVER written to stderr (public
#                                         log). Non-zero = fail closed.
# The lib expects a bare IPv4 (or empty) as <explicit>: /suffix stripping
# is the caller's single validated entry point, never done here.

# Canonical dotted-quad only: reject leading zeros (01), out-of-range octets,
# wrong arity, trailing dots, whitespace and any non-digit/dot byte. The
# reconstruction equality catches arity/trailing-dot shapes; the per-octet
# case rejects leading zeros and >3-digit runs before `-le` can overflow.
is_bare_ipv4() { # $1 = candidate string
  local s="${1:-}" a b c d extra oct
  case "$s" in
    '' | *[!0-9.]*) return 1 ;;
  esac
  IFS=. read -r a b c d extra <<<"$s"
  [ -z "$extra" ] || return 1
  for oct in "$a" "$b" "$c" "$d"; do
    case "$oct" in
      '' | *[!0-9]* | ????* | 0[0-9]*) return 1 ;;
    esac
    [ "$oct" -le 255 ] || return 1
  done
  [ "$s" = "$a.$b.$c.$d" ]
}

anchor_ipv4_candidates() { # $1 = netcup server detail JSON
  local detail="${1:-}" list="" validated="" ip
  # Strict shape guard: an object root, an array ipv4Addresses, and every
  # element an object with a non-empty string .ip whose bytes are only
  # digits and dots. A non-object element, a missing/null/empty .ip, a .ip
  # carrying whitespace/NUL/letters, a non-array ipv4Addresses or invalid
  # JSON are ALL the same unexpected-shape failure — never a silent drop.
  # `\z` (not `$`) is load-bearing: Oniguruma's `$` matches before a
  # trailing newline.
  if ! printf '%s' "$detail" | jq -e 'type == "object" and (.ipv4Addresses | type == "array") and ([.ipv4Addresses[] | (type == "object" and (.ip | type == "string" and length > 0 and test("^[0-9.]+\\z")))] | all)' >/dev/null 2>&1; then
    printf '::error::server detail ipv4Addresses is not an array of {ip} objects — unexpected shape, escalate (fail closed).\n' >&2
    return 1
  fi
  list="$(printf '%s' "$detail" | jq -r '[.ipv4Addresses[] | .ip] | .[]')" || return 1
  # Zero addresses is not a shape failure: the caller decides (an IPv6-only
  # server fails closed there, with the attach-an-IPv4 fix).
  [ -n "$list" ] || return 0
  # Validate EVERY entry BEFORE emitting any stdout line: a partially
  # validated list must never stream (the first good address must not reach
  # the caller when a later entry is bad). The offending entry is never
  # printed (it is external data; errors carry no values).
  while IFS= read -r ip; do
    [ -n "$ip" ] || continue
    if ! is_bare_ipv4 "$ip"; then
      printf '::error::server detail carries an address entry that is not a bare IPv4 — unexpected shape, escalate (fail closed).\n' >&2
      return 1
    fi
    validated="${validated}${ip}"$'\n'
  done <<<"$list"
  # Dedupe preserving first-seen order (a repeated address is one candidate,
  # not an ambiguity).
  printf '%s' "$validated" | awk '!seen[$0]++'
}

resolve_anchor_ipv4() { # $1 = server detail JSON, $2 = explicit bare IPv4 or "", $3 = label (public hostname)
  local detail="${1:-}" explicit="${2:-}" label="${3:-anchor}"
  local candidates="" count=0
  candidates="$(anchor_ipv4_candidates "$detail")" || return 1
  if [ -n "$candidates" ]; then
    count="$(printf '%s\n' "$candidates" | awk 'END { print NR }')"
  fi
  if [ -n "$explicit" ]; then
    # The explicit value may SELECT among the resolved server's own
    # addresses, never override them (F2). Herestring, never a pipe: under
    # pipefail grep's early exit can SIGPIPE the writer.
    if grep -Fqx -- "$explicit" <<<"$candidates"; then
      printf "Discovery: %s: using the explicit ANCHOR_IPV4 value (it matches one of the resolved server's own addresses).\n" "$label" >&2
      printf '%s\n' "$explicit"
      return 0
    fi
    printf "::error::%s: the explicit ANCHOR_IPV4 value is not one of the resolved server's own addresses — refusing it (fail closed).\n" "$label" >&2
    if [ "$count" -gt 0 ]; then
      printf 'The resolved server reports %s IPv4 address(es); the explicit value matches none of them. Read the addresses in the netcup SCP (server detail), set ANCHOR_IPV4 to one of them (or delete the secret), then re-dispatch. Address values are never printed to this public log.\n' "$count" >&2
    else
      printf 'The resolved server reports no IPv4 address at all — attach the intended IPv4 to it, then re-dispatch.\n' >&2
    fi
    return 1
  fi
  if [ "$count" -eq 0 ]; then
    printf '::error::%s: the resolved server reports no IPv4 address (IPv6-only is unsupported — runners have no IPv6). Attach an IPv4 to the server, then re-dispatch.\n' "$label" >&2
    return 1
  fi
  if [ "$count" -eq 1 ]; then
    printf 'Discovery: %s: anchor IPv4 from server detail, no pasted IP needed.\n' "$label" >&2
    printf '%s\n' "$candidates"
    return 0
  fi
  printf '::error::%s: the resolved server reports %s IPv4 addresses — refusing to pick one (fail loud).\n' "$label" "$count" >&2
  printf 'Read the addresses in the netcup SCP (server detail), set ANCHOR_IPV4 to the intended one (or attach exactly one IPv4 to the server), then re-dispatch. Address values are never printed to this public log.\n' >&2
  return 1
}
