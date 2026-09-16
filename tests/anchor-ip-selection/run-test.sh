#!/usr/bin/env bash
# tests/anchor-ip-selection/run-test.sh — issue #124 anchor-IP selection proofs.
#
# Exercises the REAL .github/scripts/lib/anchor-ip.sh functions (sourced, not
# re-implemented) against fixtures of the netcup `GET /servers/{id}` detail:
#
#   ok   single candidate; explicit == the server's own address (selects);
#        multi + explicit in list; duplicate candidates deduped.
#   fail F2 poison — explicit != the resolved server's address (the SSH/DNS
#        target can never come from the secret alone);
#        P4 — multi-IPv4 with no explicit fails loud with the candidate list;
#        zero candidates (IPv6-only) fails closed;
#        malformed detail shapes / malformed explicit values fail closed.
#
# Plus static wiring assertions over provision.yml: the lib is sourced, the
# call site uses resolve_anchor_ipv4, the secret is normalized once before
# any use, and the old direct-override / silent-first-index shapes are gone.
# The wiring checks are structural (non-comment lines; the HOST4 assignment
# pinned to the exact guarded call), so a partial revert cannot satisfy them
# by leaving the old code text in a comment.
#
# Cred-free, offline: no network, no credentials, real jq.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
LIB="$ROOT/.github/scripts/lib/anchor-ip.sh"
PROV="$ROOT/.github/workflows/provision.yml"
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

[ -f "$LIB" ] || { printf 'FAIL lib not found: %s\n' "$LIB"; exit 1; }
[ -f "$PROV" ] || { printf 'FAIL workflow not found: %s\n' "$PROV"; exit 1; }
. .github/scripts/lib/anchor-ip.sh

# ---- helpers: call the real functions, capture rc + stdout + stderr ------
RUN() { # $1 tag, $2 detail, $3 explicit, $4 label -> rc; out/err in files
  local rc=0
  resolve_anchor_ipv4 "$2" "$3" "$4" > "$WORK/out.$1" 2> "$WORK/err.$1" || rc=$?
  printf '%s' "$rc"
}
CANDS() { # $1 tag, $2 detail -> rc; stdout in file
  local rc=0
  anchor_ipv4_candidates "$2" > "$WORK/cands.$1" 2> "$WORK/cerr.$1" || rc=$?
  printf '%s' "$rc"
}
IPV4() { # $1 value -> rc of is_bare_ipv4
  local rc=0
  is_bare_ipv4 "$1" >/dev/null 2>&1 || rc=$?
  printf '%s' "$rc"
}
OUT() { cat "$WORK/out.$1"; }
ERR() { cat "$WORK/err.$1"; }

# Fixtures (RFC 5737 documentation addresses only).
ONE='{"ipv4Addresses":[{"ip":"203.0.113.10"}]}'
TWO='{"ipv4Addresses":[{"ip":"203.0.113.10"},{"ip":"198.51.100.7"}]}'
DUP='{"ipv4Addresses":[{"ip":"203.0.113.10"},{"ip":"203.0.113.10"}]}'
LABEL="anchor-01-pier"

# ---- ok paths ------------------------------------------------------------
rc="$(RUN t1 "$ONE" "" "$LABEL")"
is "t1 single candidate rc" "0" "$rc"
is "t1 chosen IP (stdout is only the IP)" "203.0.113.10" "$(OUT t1)"
contains "t1 success note on stderr" "no pasted IP needed" "$(ERR t1)"

rc="$(RUN t2 "$ONE" "203.0.113.10" "$LABEL")"
is "t2 explicit == server's own address rc" "0" "$rc"
is "t2 chosen IP" "203.0.113.10" "$(OUT t2)"
contains "t2 selection note on stderr" "explicit ANCHOR_IPV4 value" "$(ERR t2)"

rc="$(RUN t3 "$TWO" "198.51.100.7" "$LABEL")"
is "t3 multi + explicit in list rc" "0" "$rc"
is "t3 chosen IP" "198.51.100.7" "$(OUT t3)"

rc="$(RUN t4 "$DUP" "" "$LABEL")"
is "t4 duplicate candidates deduped rc" "0" "$rc"
is "t4 chosen IP" "203.0.113.10" "$(OUT t4)"

rc="$(CANDS c1 '{"ipv4Addresses":[{"ip":"9.9.9.9"},{"ip":"1.2.3.4"},{"ip":"9.9.9.9"}]}')"
is "c1 candidates rc" "0" "$rc"
is "c1 candidate count (deduped)" "2" "$(wc -l < "$WORK/cands.c1" | tr -d ' ')"
is "c1 first candidate (order preserved)" "9.9.9.9" "$(sed -n 1p "$WORK/cands.c1")"
is "c1 second candidate" "1.2.3.4" "$(sed -n 2p "$WORK/cands.c1")"

# ---- F2: the explicit value can select, never override -------------------
rc="$(RUN f1 "$ONE" "198.51.100.7" "$LABEL")"
is "f1 F2 poison rc (fail closed)" "1" "$rc"
is "f1 F2 poison stdout empty" "" "$(OUT f1)"
contains "f1 F2 poison names the refusal" "not one of the resolved server's own addresses" "$(ERR f1)"
contains "f1 F2 poison lists the server's own address" "203.0.113.10" "$(ERR f1)"

# The workflow strips /suffix before the lib; a raw suffix at the lib
# boundary is not a member and must fail closed (single validated entry
# point — the lib never strips).
rc="$(RUN f2 "$ONE" "203.0.113.10/24" "$LABEL")"
is "f2 raw /suffix at the lib boundary rc" "1" "$rc"
is "f2 raw /suffix stdout empty" "" "$(OUT f2)"

# ---- P4: multi-IPv4 fails loud with the candidate list -------------------
rc="$(RUN f3 "$TWO" "" "$LABEL")"
is "f3 multi, no explicit rc (fail loud)" "1" "$rc"
is "f3 multi, no explicit stdout empty" "" "$(OUT f3)"
contains "f3 lists candidate 1" "203.0.113.10" "$(ERR f3)"
contains "f3 lists candidate 2" "198.51.100.7" "$(ERR f3)"
contains "f3 names the ambiguity" "IPv4 addresses" "$(ERR f3)"

rc="$(RUN f4 "$TWO" "192.0.2.99" "$LABEL")"
is "f4 multi + explicit not in list rc" "1" "$rc"
is "f4 multi + explicit not in list stdout empty" "" "$(OUT f4)"
contains "f4 lists candidates" "198.51.100.7" "$(ERR f4)"

# ---- zero candidates: IPv6-only is unsupported ---------------------------
rc="$(RUN f5 '{"ipv4Addresses":[]}' "" "$LABEL")"
is "f5 zero candidates rc (fail closed)" "1" "$rc"
is "f5 zero candidates stdout empty" "" "$(OUT f5)"
contains "f5 names the IPv6-only case" "IPv6-only is unsupported" "$(ERR f5)"

rc="$(RUN f5b '{"ipv4Addresses":[]}' "203.0.113.10" "$LABEL")"
is "f5b zero candidates + explicit rc" "1" "$rc"
contains "f5b zero candidates + explicit names the missing address" "no IPv4 address at all" "$(ERR f5b)"

# ---- strict shape guard: no silent drops, no partial stdout --------------
for pair in \
  "f6|{\"name\":\"anchor-01-pier\"}" \
  "f7|{\"ipv4Addresses\":\"203.0.113.10\"}" \
  "f8|{\"ipv4Addresses\":[\"203.0.113.10\"]}" \
  "f9|{\"ipv4Addresses\":[{\"address\":\"203.0.113.10\"}]}" \
  "f10|{\"ipv4Addresses\":[{\"ip\":null}]}" \
  "f11|{\"ipv4Addresses\":[{\"ip\":\"\"}]}" \
  "f13|[]" \
  "f14|not-json"; do
  tag="${pair%%|*}"; detail="${pair#*|}"
  rc="$(RUN "$tag" "$detail" "" "$LABEL")"
  is "$tag unexpected shape rc" "1" "$rc"
  is "$tag unexpected shape stdout empty" "" "$(OUT "$tag")"
  contains "$tag unexpected shape message" "unexpected shape, escalate (fail closed)" "$(ERR "$tag")"
done

# Non-dotted-quad bytes fail the shape guard (the literal "never a silent
# drop" contract): whitespace/NUL/newline/letters all fail closed with no
# stdout. Canonical-octet failures (range, leading zeros) fall through to
# is_bare_ipv4 and are reported as "not a bare IPv4".
rc="$(RUN f12 '{"ipv4Addresses":[{"ip":"not-an-ip"}]}' "" "$LABEL")"
is "f12 non-dotted-quad entry rc" "1" "$rc"
is "f12 non-dotted-quad entry no stdout" "" "$(OUT f12)"
contains "f12 non-dotted-quad entry fails closed" "unexpected shape, escalate (fail closed)" "$(ERR f12)"

rc="$(RUN f12c '{"ipv4Addresses":[{"ip":"999.1.1.1"}]}' "" "$LABEL")"
is "f12c non-canonical octet rc" "1" "$rc"
contains "f12c non-canonical octet fails is_bare_ipv4" "not a bare IPv4" "$(ERR f12c)"

rc="$(RUN f12d '{"ipv4Addresses":[{"ip":"203.0.113.10\n"}]}' "" "$LABEL")"
is "f12d trailing-newline entry rc" "1" "$rc"
is "f12d trailing-newline entry no stdout" "" "$(OUT f12d)"
contains "f12d trailing-newline is a shape failure" "unexpected shape, escalate (fail closed)" "$(ERR f12d)"

rc="$(RUN f12e '{"ipv4Addresses":[{"ip":"\n"}]}' "" "$LABEL")"
is "f12e whitespace-only entry rc" "1" "$rc"
is "f12e whitespace-only entry no stdout" "" "$(OUT f12e)"

rc="$(RUN f12f '{"ipv4Addresses":[{"ip":"\u0000198.51.100.7"}]}' "" "$LABEL")"
is "f12f NUL-prefixed entry rc" "1" "$rc"
is "f12f NUL-prefixed entry no stdout" "" "$(OUT f12f)"

# A valid first entry must NOT be emitted when a later entry is bad
# (validate-before-emit, no streaming).

rc="$(RUN f12b '{"ipv4Addresses":[{"ip":"203.0.113.10"},{"ip":"not-an-ip"}]}' "" "$LABEL")"
is "f12b partial list rc" "1" "$rc"
is "f12b no partial stdout" "" "$(OUT f12b)"

rc="$(CANDS c2 '{"ipv4Addresses":[{"ip":"9.9.9.9"},{"ip":"bogus"}]}')"
is "c2 candidates partial list rc" "1" "$rc"
is "c2 candidates no partial stdout" "0" "$(wc -c < "$WORK/cands.c2" | tr -d ' ')"

# ---- is_bare_ipv4: canonical dotted-quad only ----------------------------
for good in 203.0.113.10 0.0.0.0 255.255.255.255; do
  is "is_bare_ipv4 accepts $good" "0" "$(IPV4 "$good")"
done
for bad in 256.1.1.1 01.2.3.4 1.2.3.4. 1.2.3 1.2.3.4/24 not-an-ip 999.1.1.1 1.2.3.04 "" " 203.0.113.10" "203.0.113.10 "; do
  is "is_bare_ipv4 rejects '$bad'" "1" "$(IPV4 "$bad")"
done

# ---- static wiring over provision.yml ------------------------------------
# Asserted structurally, not by substring alone: every required pattern must
# sit on a NON-COMMENT line, and the HOST4 assignment must be exactly the
# guarded resolve_anchor_ipv4 call — a same-line fallback that leaves the
# call text in a trailing comment (or wraps it in a substitution) fails.
active_line() { # $1 needle, $2 file -> first non-comment line number containing it
  awk -v n="$1" 'index($0, n) && $0 !~ /^[[:space:]]*#/ { print NR; exit }' "$2"
}
active() { # $1 label, $2 needle, $3 file
  if [ -n "$(active_line "$2" "$3")" ]; then ok "$1"; else bad "$1 (no non-comment line with: $2)"; fi
}
lack() { if grep -qF -- "$2" "$1"; then bad "$3 (found: $2)"; else ok "$3"; fi; }
before() { # $1 label, $2 earlier line, $3 later line
  if [ -n "$2" ] && [ -n "$3" ] && [ "$2" -lt "$3" ] 2>/dev/null; then ok "$1"; else bad "$1 (line order: $2 then $3)"; fi
}
active "workflow sources .github/scripts/lib/anchor-ip.sh" '. .github/scripts/lib/anchor-ip.sh' "$PROV"
active "workflow strips any /suffix once into EXPLICIT" 'EXPLICIT="${ANCHOR_IPV4%%/*}"' "$PROV"
active "workflow validates the explicit value with is_bare_ipv4" 'is_bare_ipv4 "$EXPLICIT"' "$PROV"
# Exactly one HOST4 assignment anywhere (start of line, after whitespace, or
# after `!`); the resolved-output write `ANCHOR_HOST=$HOST4` is not one.
is "exactly one HOST4 assignment (the resolve_anchor_ipv4 call site)" "1" "$(grep -cE '(^|[[:space:]!])HOST4=' "$PROV")"
host4_line="$(grep -nE '(^|[[:space:]!])HOST4=' "$PROV" | head -n1 | cut -d: -f1)"
expected4='if ! HOST4="$(resolve_anchor_ipv4 "$DETAIL" "$EXPLICIT" "$HOSTNAME")"; then'
got4="$(sed -n "${host4_line:-99999}p" "$PROV" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
is "HOST4 assignment is exactly the guarded lib call" "$expected4" "$got4"
before "lib sourced before the explicit validation" \
  "$(active_line '. .github/scripts/lib/anchor-ip.sh' "$PROV")" \
  "$(active_line 'is_bare_ipv4 "$EXPLICIT"' "$PROV")"
before "explicit normalized before the resolve call" \
  "$(active_line 'EXPLICIT="${ANCHOR_IPV4%%/*}"' "$PROV")" \
  "${host4_line:-}"
lack "$PROV" 'ipv4Addresses[0]' "no silent first-index pick remains in provision.yml"
lack "$PROV" 'HOST4="${ANCHOR_IPV4' "no direct HOST4 override from the secret remains"

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
