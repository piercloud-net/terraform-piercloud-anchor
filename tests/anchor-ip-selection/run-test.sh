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
# by leaving the old code text in a comment — and a BEHAVIORAL section runs
# the real resolve-step body against a stubbed netcup API, asserting the
# emitted ANCHOR_HOST/anchor_ipv4: that binding survives control-flow
# rewrites the static greps cannot bound (e.g. a `read -r HOST4` bypass).
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

# ---- behavioral binding: run the REAL resolve-step body against a stubbed
# netcup API ---------------------------------------------------------------
# The static assertions stop shape-level reverts, but a control-flow rewrite
# can keep them all green while the emitted target comes from the secret
# (e.g. `read -r HOST4 <<<"$EXPLICIT"` on the secret path). This section
# binds the CONTRACT behaviorally: whatever the step does, the emitted
# ANCHOR_HOST / anchor_ipv4 must be an address the resolved server itself
# reports, and a non-matching explicit value must exit non-zero with
# nothing emitted.
RESOLVE_BODY="$WORK/resolve-body.sh"
awk '
  index($0, "- name: Resolve server + approver guard + zero-IP discovery") { inblock=1; next }
  inblock && $0 == "        run: |" { inrun=1; next }
  inrun && /^      - name: / { exit }
  inrun { line=$0; sub(/^          /, "", line); print line }
' "$PROV" > "$RESOLVE_BODY"
[ -s "$RESOLVE_BODY" ] || { printf 'FAIL could not extract the resolve step body from provision.yml\n'; exit 1; }
grep -qF 'resolve_anchor_ipv4' "$RESOLVE_BODY" || { printf 'FAIL extracted body has no resolve_anchor_ipv4 call\n'; exit 1; }

mkdir -p "$WORK/bin"
cat > "$WORK/bin/curl" <<'STUB'
#!/usr/bin/env bash
# Stub netcup SCP API: fixtures via STUB_LIST / STUB_DETAIL / STUB_BY_IP.
args="$*"
case "$args" in
  *protocol/openid-connect/userinfo*) printf '%s' '{"id":"123"}'; exit 0 ;;
  *"/api/v1/users/123"*) printf '%s' '{"username":"999999"}'; exit 0 ;;
  *"--data-urlencode ip="*) printf '%s' "${STUB_BY_IP:-[]}"; exit 0 ;;
esac
case "$args" in
  *"/api/v1/servers/42"*) printf '%s' "${STUB_DETAIL:?STUB_DETAIL unset}"; exit 0 ;;
  *"/api/v1/servers"*) printf '%s' "${STUB_LIST:?STUB_LIST unset}"; exit 0 ;;
  *) printf 'stub curl: unexpected args: %s\n' "$args" >&2; exit 1 ;;
esac
STUB
chmod +x "$WORK/bin/curl"

DETAIL_ONE='{"name":"order","hostname":"anchor-01-test","ipv4Addresses":[{"ip":"203.0.113.10"}]}'
DETAIL_TWO='{"name":"order","hostname":"anchor-01-test","ipv4Addresses":[{"ip":"203.0.113.10"},{"ip":"198.51.100.7"}]}'
LIST_ONE='[{"id":"42","hostname":"anchor-01-test"}]'
LIST_TWO='[{"id":"1","hostname":"other-a"},{"id":"2","hostname":"other-b"}]'
BY_IP_42='[{"id":"42","hostname":"anchor-01-test"}]'

RESOLVE_RUN() { # $1 tag; remaining: VAR=value pairs -> rc; files in $WORK/res.<tag>.*
  local tag="$1"; shift
  local genv="$WORK/res.$tag.genv" gout="$WORK/res.$tag.gout" rc=0
  : > "$genv"; : > "$gout"
  env -i PATH="$WORK/bin:$PATH" HOME="$WORK" \
    GITHUB_ENV="$genv" GITHUB_OUTPUT="$gout" \
    TENANT_USER=test CUSTOMER_NUMBER=999999 SCP_USER_ID_IN= \
    NETCUP_SCP_ACCESS_TOKEN=stub-token \
    "$@" \
    bash "$RESOLVE_BODY" > "$WORK/res.$tag.out" 2> "$WORK/res.$tag.err" || rc=$?
  printf '%s' "$rc"
}
emitted() { # $1 tag, $2 file suffix (genv|gout) -> matching lines or empty
  grep -E '^(ANCHOR_HOST|anchor_ipv4)=' "$WORK/res.$1.$2" || true
}

# b1: F2 poison — server reports 203.0.113.10, the secret says 198.51.100.99.
rc="$(RESOLVE_RUN b1 STUB_LIST="$LIST_ONE" STUB_DETAIL="$DETAIL_ONE" ANCHOR_IPV4=198.51.100.99)"
is "b1 poisoned explicit rc (fail closed)" "1" "$rc"
is "b1 nothing emitted to GITHUB_ENV" "" "$(emitted b1 genv)"
is "b1 nothing emitted to GITHUB_OUTPUT" "" "$(emitted b1 gout)"
contains "b1 fail-closed message" "not one of the resolved server's own addresses" "$(cat "$WORK/res.b1.err")"

# b2: no explicit — target is the server detail's own address.
rc="$(RESOLVE_RUN b2 STUB_LIST="$LIST_ONE" STUB_DETAIL="$DETAIL_ONE" ANCHOR_IPV4=)"
is "b2 discovery rc" "0" "$rc"
is "b2 ANCHOR_HOST is the API address" "ANCHOR_HOST=203.0.113.10" "$(emitted b2 genv)"
is "b2 anchor_ipv4 is the API address" "anchor_ipv4=203.0.113.10" "$(emitted b2 gout)"

# b3: explicit matching the server's own address — selected and emitted.
rc="$(RESOLVE_RUN b3 STUB_LIST="$LIST_ONE" STUB_DETAIL="$DETAIL_ONE" ANCHOR_IPV4=203.0.113.10)"
is "b3 matching explicit rc" "0" "$rc"
is "b3 ANCHOR_HOST is the API address" "ANCHOR_HOST=203.0.113.10" "$(emitted b3 genv)"

# b4/b5: multi-IPv4 — no explicit fails loud; explicit selects a member.
rc="$(RESOLVE_RUN b4 STUB_LIST="$LIST_ONE" STUB_DETAIL="$DETAIL_TWO" ANCHOR_IPV4=)"
is "b4 multi no explicit rc (fail loud)" "1" "$rc"
is "b4 nothing emitted" "" "$(emitted b4 genv)"
contains "b4 lists candidate 198.51.100.7" "198.51.100.7" "$(cat "$WORK/res.b4.err")"
rc="$(RESOLVE_RUN b5 STUB_LIST="$LIST_ONE" STUB_DETAIL="$DETAIL_TWO" ANCHOR_IPV4=198.51.100.7)"
is "b5 multi explicit member rc" "0" "$rc"
is "b5 ANCHOR_HOST is the selected member" "ANCHOR_HOST=198.51.100.7" "$(emitted b5 genv)"

# b6/b7: explicit resolves the server via ?ip= (ambiguous account) — the
# emitted target is still that server's own address, never the secret.
rc="$(RESOLVE_RUN b6 STUB_LIST="$LIST_TWO" STUB_BY_IP="$BY_IP_42" STUB_DETAIL="$DETAIL_ONE" ANCHOR_IPV4=198.51.100.7)"
is "b6 ?ip= resolved + non-member explicit rc" "1" "$rc"
is "b6 nothing emitted on ?ip= mismatch" "" "$(emitted b6 genv)"
rc="$(RESOLVE_RUN b7 STUB_LIST="$LIST_TWO" STUB_BY_IP="$BY_IP_42" STUB_DETAIL="$DETAIL_ONE" ANCHOR_IPV4=203.0.113.10)"
is "b7 ?ip= resolved + member explicit rc" "0" "$rc"
is "b7 ANCHOR_HOST is the API address" "ANCHOR_HOST=203.0.113.10" "$(emitted b7 genv)"

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
