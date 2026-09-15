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

# A non-IPv4 entry fails is_bare_ipv4; a valid first entry must NOT be
# emitted when a later entry is bad (validate-before-emit, no streaming).
rc="$(RUN f12 '{"ipv4Addresses":[{"ip":"not-an-ip"}]}' "" "$LABEL")"
is "f12 non-IPv4 entry rc" "1" "$rc"
contains "f12 non-IPv4 entry fails closed" "not a bare IPv4" "$(ERR f12)"

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
has()  { if grep -qF -- "$2" "$1"; then ok "$3"; else bad "$3 (missing: $2)"; fi; }
lack() { if grep -qF -- "$2" "$1"; then bad "$3 (found: $2)"; else ok "$3"; fi; }
first_line() { grep -nF -- "$1" "$2" 2>/dev/null | head -n1 | cut -d: -f1 || true; }
before() { # $1 label, $2 earlier line, $3 later line
  if [ -n "$2" ] && [ -n "$3" ] && [ "$2" -lt "$3" ]; then ok "$1"; else bad "$1 (line order: $2 then $3)"; fi
}
has "$PROV" '. .github/scripts/lib/anchor-ip.sh' "workflow sources .github/scripts/lib/anchor-ip.sh"
has "$PROV" 'resolve_anchor_ipv4 "$DETAIL" "$EXPLICIT" "$HOSTNAME"' "workflow resolves HOST4 via resolve_anchor_ipv4"
has "$PROV" 'EXPLICIT="${ANCHOR_IPV4%%/*}"' "workflow strips any /suffix once into EXPLICIT"
has "$PROV" 'is_bare_ipv4 "$EXPLICIT"' "workflow validates the explicit value with is_bare_ipv4"
before "lib sourced before the explicit validation" \
  "$(first_line '. .github/scripts/lib/anchor-ip.sh' "$PROV")" \
  "$(first_line 'is_bare_ipv4 "$EXPLICIT"' "$PROV")"
before "explicit normalized before the resolve call" \
  "$(first_line 'EXPLICIT="${ANCHOR_IPV4%%/*}"' "$PROV")" \
  "$(first_line 'resolve_anchor_ipv4 "$DETAIL"' "$PROV")"
lack "$PROV" 'ipv4Addresses[0]' "no silent first-index pick remains in provision.yml"
lack "$PROV" 'HOST4="${ANCHOR_IPV4' "no direct HOST4 override from the secret remains"

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
