#!/usr/bin/env bash
# Unit test for cmd_sweep_post's attached-policy parsing in
# .github/scripts/020-provision-anchor.sh (the steady-state orphan sweep).
#
# Contract under test (review SECURITY N1, 2026-09-11): the sweep must NEVER
# delete the LIVE attached policy. The old parse applied `(.id // .)` to every
# userPolicies entry, so an entry whose id was missing/null/empty fell back to
# the WHOLE OBJECT: the live policy then looked unattached and close_policy
# deleted it (real repro: STUB_IFACE '{"userPolicies":[{"name":"x"}]}', steady
# id 42, MODE=apply -> rc 0, actions `close 42`; cleartext/dashboard outage
# until a re-apply). The fix dispatches on the entry type: {"id":number},
# {"id":string}, bare number and bare string entries are tolerated and
# stringified; anything ambiguous (missing key, non-array userPolicies,
# null/boolean/object entries, id null/empty/non-scalar) hard-fails with NO
# detach and NO delete.
#
# N4 id hardening (same day): tolerated ids must be canonical non-negative
# integers — string ids must match ^[0-9]+$, and numbers must be integral
# with an integer tostring. In particular {"id":42.0} must hard-fail on
# jq >= 1.7 (decNumber preserves the literal; tostring gives "42.0", which
# would read as unattached against live id 42) and {"id":"42 "},
# {"id":"   "}, {"id":"42.0"}, {"id":"0x2a"}, {"id":"+42"} must all
# hard-fail instead of stringifying through to a non-matching id.
#
# F1/F2 id hardening (security delta review, 2026-09-11): the N4 string
# guard was ^[0-9]+$ — but in jq/Oniguruma `$` also matches immediately
# BEFORE a trailing newline, so {"id":"42\n"} passed, missed the live-id
# index() and the sweep deleted the attached policy 42; {"id":"0042"}
# (leading zero) reached the delete the same way. The guard now anchors
# with \z and requires canonical digits. Independently, the STEADY-state
# pid (from the steady list) was never validated: steady {"id":"0042"} +
# attached numeric 42 made close_policy PUT merged=[] (live attachment
# removed) + DELETE /firewall-policies/0042. Both sides now use one
# canonical rule (strings ^(0|[1-9][0-9]*)\z; numbers integral,
# non-negative, canonical after tostring, so 42.0/1e2/-3 fail; the
# literal 0 is allowed uniformly).
#
# Issue #121 (policy naming): steady-state names are
# piercloud-anchor-<hostname> — the server id left the name. This harness
# feeds cmd_sweep_post the names the real list_steady_policies returns
# (new shape + pre-change id-suffixed migration shape) and asserts the
# attachment compare still protects the live policy in both; the filter
# itself is covered by tests/policy-naming.
#
# Real cmd_sweep_post / policy_age / close_policy / sweep_* are exercised;
# only the API boundary (list/detach/delete) and logging are stubbed — no
# network, no credentials.
#
# Issue #196 (entrypoint cases e1-e8, at the end): these run the WHOLE
# script as a subprocess (`env -i`, nothing stubbed) so the ordering of the
# no-token sweep-post short-circuit against the global id guards is pinned.
# They never reach an API helper: a `curl` tripwire on PATH records every
# PATH-resolved curl call in a hit file (so redirected stderr cannot hide it)
# and any hit fails the case; curl is the only API transport (_api_curl +
# token endpoint). A PATH shim does not catch an absolute-path binary or ssh.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$ROOT/.github/scripts/020-provision-anchor.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0
ok()  { pass=$((pass + 1)); printf 'ok   %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL %s\n' "$1"; }
is()  { # $1 label, $2 expected, $3 actual
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi
}

extract() { awk "/^$1\\(\\) \\{/,/^\\}/" "$SCRIPT"; }
{
  cat <<'PRELUDE'
log()  { printf 'A1: %s\n' "$*"; }
warn() { printf 'A1 WARNING: %s\n' "$*" >&2; }
die()  { printf 'A1 FAIL: %s\n' "$*" >&2; exit 1; }
list_tmp_policies()    { printf '%s' "$STUB_LIST_TMP"; }
list_steady_policies() { printf '%s' "$STUB_STEADY"; }
resolve_mac()          { printf '%s' "${STUB_MAC:-aa:bb:cc:dd:ee:ff}"; }
iface_fw_get()         { printf '%s' "$STUB_IFACE"; }
detach_policy() { printf 'detach %s\n' "$1" >> "$STUB_ACTIONS"; }
delete_policy() { printf 'delete %s\n' "$1" >> "$STUB_ACTIONS"; }
PRELUDE
  extract sweep_destructive
  extract sweep_note
  extract policy_age
  extract close_policy
  extract cmd_sweep_post
} > "$WORK/functions.sh"
for fn in sweep_destructive sweep_note policy_age close_policy cmd_sweep_post; do
  grep -q "^$fn() {" "$WORK/functions.sh" || { echo "FAIL could not extract $fn"; exit 1; }
done

# GNU-compatible `date -d <RFC 3339 timestamp>` shim: the script runs on Ubuntu
# runners (GNU date) while a dev laptop may be BSD/macOS — the shim keeps the
# REAL policy_age exercised on both. Everything else delegates to the real date.
mkdir -p "$WORK/bin"
cat > "$WORK/bin/date" <<'SHIM'
#!/usr/bin/env bash
if [ "${1:-}" = "-u" ] && [ "${2:-}" = "-d" ]; then
  shift 2 # drop -u -d; next arg is the timestamp, then the format (+%s)
  python3 -c 'import datetime,sys;print(int(datetime.datetime.strptime(sys.argv[1],"%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc).timestamp()))' "$1"
  exit $?
fi
exec /bin/date "$@"
SHIM
chmod +x "$WORK/bin/date"

stamp() { # $1 = seconds ago -> RFC 3339 UTC timestamp (same shape the workflow writes)
  python3 -c "import datetime,sys;print((datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(seconds=int(sys.argv[1]))).strftime('%Y-%m-%dT%H:%M:%SZ'))" "$1"
}
tmp_entry() { # $1 id, $2 run-id suffix, $3 age-seconds ("orphan" = unstamped description)
  if [ "$3" = "orphan" ]; then
    printf '{"id":"%s","name":"piercloud-tmp-%s","description":"hand-made policy"}' "$1" "$2"
  else
    printf '{"id":"%s","name":"piercloud-tmp-%s","description":"created_at=%s purpose=A1-ssh"}' "$1" "$2" "$(stamp "$3")"
  fi
}

# One steady-state policy (id 42) — the live attachment under test. New
# (#121) piercloud-anchor-<hostname> shape.
STEADY_LIVE='[{"id":42,"name":"piercloud-anchor-anchor-01-pier","description":""}]'
# Pre-change (#121) id-suffixed shape — kept only as the migration clause's
# input; the real filter recognizes it once (tests/policy-naming).
STEADY_LEGACY='[{"id":43,"name":"piercloud-anchor-anchor-01-pier-933556","description":""}]'

RC_OF() { # $1 label, $2 STUB_LIST_TMP, $3 STUB_IFACE, [$4 STUB_STEADY]; RC_TOKEN overrides the token (default AT)
  local l="$1" rc=0
  : > "$WORK/actions.$l"
  STUB_LIST_TMP="$2" STUB_IFACE="$3" STUB_STEADY="${4:-[]}" \
  PATH="$WORK/bin:$PATH" STUB_ACTIONS="$WORK/actions.$l" \
  GITHUB_STEP_SUMMARY="$WORK/summary.$l" MODE=apply \
  SERVER_ID=933556 SCP_USER_ID=1 RUN_ID=999 ANCHOR_HOSTNAME=anchor-01-pier \
  OWN_NAME="piercloud-tmp-999" NETCUP_SCP_ACCESS_TOKEN="${RC_TOKEN-AT}" TMP_TTL_SECONDS=7200 \
  bash -c 'set -euo pipefail; source "$1"; cmd_sweep_post' _ "$WORK/functions.sh" \
    > "$WORK/out.$l" 2>&1 || rc=$?
  printf '%s' "$rc"
}
ACTIONS() { [ -f "$WORK/actions.$1" ] && paste -sd' ' "$WORK/actions.$1" || echo ""; }

# ---- cases 1-4: tolerant attached shapes -> live policy KEPT, no mutation ---
rc="$(RC_OF c1 "[]" '{"userPolicies":[{"id":42,"name":"piercloud-anchor-anchor-01-pier"}]}' "$STEADY_LIVE")"
is "c1 rc" "0" "$rc"
is "c1 actions (live kept)" "" "$(ACTIONS c1)"
is "c1 kept log" "1" "$(grep -c 'is attached — kept' "$WORK/out.c1" || true)"
rc="$(RC_OF c2 "[]" '{"userPolicies":[{"id":"42","name":"piercloud-anchor-anchor-01-pier"}]}' "$STEADY_LIVE")"
is "c2 rc" "0" "$rc"
is "c2 actions (live kept)" "" "$(ACTIONS c2)"
rc="$(RC_OF c3 "[]" '{"userPolicies":["42"]}' "$STEADY_LIVE")"
is "c3 rc" "0" "$rc"
is "c3 actions (bare string id kept)" "" "$(ACTIONS c3)"
rc="$(RC_OF c4 "[]" '{"userPolicies":[42]}' "$STEADY_LIVE")"
is "c4 rc" "0" "$rc"
is "c4 actions (bare number id kept)" "" "$(ACTIONS c4)"

# ---- case 5: genuinely unattached steady policy -> apply still retires it ---
rc="$(RC_OF c5 "[]" '{"userPolicies":[]}' "$STEADY_LIVE")"
is "c5 rc" "0" "$rc"
is "c5 actions (orphan retired)" "detach 42 delete 42" "$(ACTIONS c5)"

# ---- case 5b: pre-change id-suffixed name, unattached -> retired (migration) -
rc="$(RC_OF c5b "[]" '{"userPolicies":[]}' "$STEADY_LEGACY")"
is "c5b rc" "0" "$rc"
is "c5b actions (legacy orphan retired)" "detach 43 delete 43" "$(ACTIONS c5b)"

# ---- case 5c: pre-change id-suffixed name, ATTACHED -> kept (migration) -----
rc="$(RC_OF c5c "[]" '{"userPolicies":[43]}' "$STEADY_LEGACY")"
is "c5c rc" "0" "$rc"
is "c5c actions (legacy live kept)" "" "$(ACTIONS c5c)"
is "c5c kept log" "1" "$(grep -c 'is attached — kept' "$WORK/out.c5c" || true)"

# ---- case 6: tmp orphan (no parseable created_at) still retired in apply ----
rc="$(RC_OF c6 "[$(tmp_entry 7 other orphan)]" '{"userPolicies":[]}' "[]")"
is "c6 rc" "0" "$rc"
is "c6 actions (tmp orphan retired)" "detach 7 delete 7" "$(ACTIONS c6)"

# ---- case 7: own-run tmp at any age still dropped --------------------------
rc="$(RC_OF c7 "[$(tmp_entry 99 999 99999)]" '{"userPolicies":[]}' "[]")"
is "c7 rc" "0" "$rc"
is "c7 actions (own tmp retired)" "detach 99 delete 99" "$(ACTIONS c7)"

# ---- cases 8+: ambiguous attached lists hard-fail BEFORE any detach/delete --
# Every case seeds the live steady id 42: before the fix several of these read
# as unattached and produced `detach 42 delete 42` (the live policy gone).
ambiguous_case() { # $1 label, $2 STUB_IFACE
  local rc
  rc="$(RC_OF "$1" "[]" "$2" "$STEADY_LIVE")"
  is "$1 rc != 0 (fail-closed)" "1" "$([ "$rc" -ne 0 ] && echo 1 || echo 0)"
  is "$1 actions (live untouched)" "" "$(ACTIONS "$1")"
  is "$1 refusal logged" "1" "$(grep -c 'refusing the steady-state orphan sweep' "$WORK/out.$1" || true)"
}
ambiguous_case c8a '{"active":true}'                                                            # missing userPolicies key
ambiguous_case c8b '{"userPolicies":5}'                                                        # userPolicies not an array
ambiguous_case c8c '{"userPolicies":null}'                                                     # userPolicies null
ambiguous_case c8d '{"userPolicies":[null]}'                                                   # null entry
ambiguous_case c8e '{"userPolicies":[{"id":null}]}'                                            # id null
ambiguous_case c8f '{"userPolicies":[{"id":""}]}'                                              # id empty
ambiguous_case c8g '{"userPolicies":[{"name":"piercloud-anchor-anchor-01-pier"}]}'             # THE live-policy repro: object without id
ambiguous_case c8h '{"userPolicies":[42,{"name":"x"}]}'                                        # mixed usable + ambiguous
ambiguous_case c8i '{"userPolicies":[""]}'                                                     # bare empty string
ambiguous_case c8j '{"userPolicies":[true]}'                                                   # boolean entry
ambiguous_case c8k '{"userPolicies":[{"id":true}]}'                                            # boolean id
ambiguous_case c8l '{"userPolicies":[{"id":[42]}]}'                                            # array id

# ---- N4: non-canonical ids hard-fail like the ambiguous shapes -----------
# (other tolerated shapes: 42, "42", 42, "42" bare — covered by cases 1-4.)
# {"id":42.0} needs jq >= 1.7 (decNumber): 1.6 stores doubles and collapses
# the literal to 42, where accepting it as the live id is the only possible
# behaviour — gate the single case instead of failing on old jq.
if [ "$(jq -rn '42.0 | tostring')" = "42.0" ]; then
  ambiguous_case c8m '{"userPolicies":[{"id":42.0}]}'                                          # 42.0 -> "42.0"
else
  printf 'SKIP c8m ({"id":42.0}: jq < 1.7 collapses the literal to 42)\n'
fi
ambiguous_case c8n '{"userPolicies":[{"id":"42 "}]}'                                         # trailing space
ambiguous_case c8o '{"userPolicies":[{"id":"   "}]}'                                         # whitespace only
ambiguous_case c8p '{"userPolicies":[{"id":"42.0"}]}'                                        # stringified float
ambiguous_case c8q '{"userPolicies":[{"id":"0x2a"}]}'                                        # hex string
ambiguous_case c8r '{"userPolicies":[{"id":"+42"}]}'                                         # signed string

# ---- F1 (security delta): $ matches before a trailing LF; \z does not ----
# {"id":"42\n"} and {"id":"0042"} are the two proven holes: both passed
# the old ^[0-9]+$ guard, failed index() against the live id "42", and the
# steady policy read as unattached -> close_policy deleted it. Both must
# now hard-fail with the live policy untouched (the N4 cases above kept
# their meaning; these two are the teeth of the F1 fix).
ambiguous_case c8s '{"userPolicies":[{"id":"42\n"}]}'                                        # trailing LF (F1 proof)
ambiguous_case c8t '{"userPolicies":[{"id":"0042"}]}'                                        # leading zero (F1 proof)
ambiguous_case c8u '{"userPolicies":[{"id":"42\r"}]}'                                        # trailing CR
ambiguous_case c8v '{"userPolicies":[{"id":"\n42"}]}'                                        # leading LF
# 1e2 keeps its literal only on jq >= 1.7 (like c8m): 1.6 collapses it to
# 100, where accepting it as the live id is the only possible behaviour.
if [ "$(jq -rn '1e2 | tostring')" = "1E+2" ]; then
  ambiguous_case c8w '{"userPolicies":[{"id":1e2}]}'                                          # exponent form
else
  printf 'SKIP c8w ({"id":1e2}: jq < 1.7 collapses the literal to 100)\n'
fi

# ---- canonical 0 stays accepted on both sides (uniform rule) -------------
# netcup policy ids are >= 1 in practice; allowing the literal 0 uniformly
# keeps one rule for both sides. Attached bare 0 and "0" must read as
# attached to steady id 0 and mutate nothing.
rc="$(RC_OF c8x "[]" '{"userPolicies":[0]}' '[{"id":0,"name":"piercloud-anchor-anchor-01-pier","description":""}]')"
is "c8x rc" "0" "$rc"
is "c8x actions (id 0 kept)" "" "$(ACTIONS c8x)"
rc="$(RC_OF c8y "[]" '{"userPolicies":["0"]}' '[{"id":0,"name":"piercloud-anchor-anchor-01-pier","description":""}]')"
is "c8y rc" "0" "$rc"
is "c8y actions (string 0 kept)" "" "$(ACTIONS c8y)"

# ---- F2 (security delta): the STEADY-state pid is canonicalized too ------
# steady {"id":"0042"} + attached numeric 42 used to miss the index()
# match; close_policy then PUT merged=[] (live attachment removed) and
# DELETEd /firewall-policies/0042. Raw "42\n" was newline-stripped by the
# shell into "42" (accepted by luck) and an empty id ran close_policy("").
# All three must fail closed with the live policy untouched, and a
# canonical string steady id must still match the numeric attachment.
steady_case() { # $1 label, $2 STUB_STEADY (attached stays numeric 42)
  local rc
  rc="$(RC_OF "$1" "[]" '{"userPolicies":[{"id":42}]}' "$2")"
  is "$1 rc != 0 (fail-closed)" "1" "$([ "$rc" -ne 0 ] && echo 1 || echo 0)"
  is "$1 actions (live untouched)" "" "$(ACTIONS "$1")"
  is "$1 refusal logged" "1" "$(grep -c 'refusing the steady-state orphan sweep' "$WORK/out.$1" || true)"
}
steady_case c9a '[{"id":"0042","name":"piercloud-anchor-anchor-01-pier","description":""}]'  # leading zero (F2 proof)
steady_case c9b '[{"id":"42\n","name":"piercloud-anchor-anchor-01-pier","description":""}]' # trailing LF (F2 proof)
steady_case c9c '[{"id":"","name":"piercloud-anchor-anchor-01-pier","description":""}]'     # empty id (F2 proof)
# positive control: a canonical STRING steady id still matches live id 42
rc="$(RC_OF c9d "[]" '{"userPolicies":[42]}' '[{"id":"42","name":"piercloud-anchor-anchor-01-pier","description":""}]')"
is "c9d rc" "0" "$rc"
is "c9d actions (live kept)" "" "$(ACTIONS c9d)"

# ---- #196 defense in depth: cmd_sweep_post's own no-token branch ---------
# Called directly (bypassing the entrypoint short-circuit): with no token it
# must not touch the API even when an orphan tmp and a live steady policy are
# listed — rc 0, zero actions, the no-op line.
rc="$(RC_TOKEN='' RC_OF c0n "[$(tmp_entry 7 1 orphan)]" '' "$STEADY_LIVE")"
is "c0n no-token rc" "0" "$rc"
is "c0n no-token actions (none)" "" "$(ACTIONS c0n)"
is "c0n no-token no-op logged" "1" "$(grep -c '^A1: post-sweep: no token held' "$WORK/out.c0n" || true)"

# ---- #196: the no-token no-op holds through the REAL entrypoint ----------
# The always() post-sweep usually runs on a run that failed before resolve
# (binding refusal, approval timeout): no token AND no ids. The global id
# guards used to run first and fail `SERVER_ID is required`, so every early
# failure grew a second red step. Drive the whole script (not the extracted
# function) so the guard ordering itself is pinned. No network: every case
# exits before any API helper.
mkdir -p "$WORK/tripwire"
cat > "$WORK/tripwire/curl" <<TRIP
#!/usr/bin/env bash
echo "curl \$*" >> "$WORK/tripwire.hits"
exit 97
TRIP
chmod +x "$WORK/tripwire/curl"
# E2E sets the global rc (not printed): it is called in the main shell so
# the tripwire assertion's pass/fail counters are not lost in a subshell.
E2E() { # $1 label, $2 command, then VAR=value env assignments
  local l="$1" cmd="$2"
  shift 2
  rc=0
  rm -f "$WORK/tripwire.hits"
  local want_net="${E2E_NET:-absent}"
  env -i PATH="$WORK/tripwire:$PATH" HOME="$WORK" RUN_ID=999 MODE=check "$@" \
    bash "$SCRIPT" "$cmd" > "$WORK/e2e.$l" 2>&1 || rc=$?
  is "$l network tripwire $want_net" "$want_net" "$([ -e "$WORK/tripwire.hits" ] && echo present || echo absent)"
}
noop_case() { # $1 label, then env assignments: must be the clean no-op
  local l="$1"
  shift
  E2E "$l" sweep-post "$@"
  is "$l rc 0 (clean no-op)" "0" "$rc"
  is "$l no-op logged" "1" "$(grep -c '^A1: post-sweep: no token held' "$WORK/e2e.$l" || true)"
  is "$l no FAIL line" "0" "$(grep -c 'A1 FAIL' "$WORK/e2e.$l" || true)"
}
noop_case e1 NETCUP_SCP_ACCESS_TOKEN= SERVER_ID= SCP_USER_ID=   # the run-38823575615 shape
noop_case e2                                                   # token + ids unset entirely
noop_case e3 NETCUP_SCP_ACCESS_TOKEN= SERVER_ID='1;x' SCP_USER_ID=  # malformed id never interpolated
noop_case e3b NETCUP_SCP_ACCESS_TOKEN= SERVER_ID= SCP_USER_ID='1;x' # malformed user id too
# With a token held the guards are unchanged: empty / non-digit ids still fail closed.
E2E e4 sweep-post NETCUP_SCP_ACCESS_TOKEN=AT SERVER_ID= SCP_USER_ID=1
is "e4 token + empty SERVER_ID rc 1" "1" "$rc"
is "e4 guard message" "1" "$(grep -c 'A1 FAIL: SERVER_ID is required' "$WORK/e2e.e4" || true)"
E2E e5 sweep-post NETCUP_SCP_ACCESS_TOKEN=AT SERVER_ID='1;x' SCP_USER_ID=1
is "e5 token + non-digit SERVER_ID rc 1" "1" "$rc"
is "e5 injection guard" "1" "$(grep -c 'SERVER_ID is not all-digits' "$WORK/e2e.e5" || true)"
# A token-bearing sweep-post with valid ids is NOT short-circuited: it reaches
# the API boundary (the tripwire curl fails it -> rc != 0). Pins that the
# no-op is gated on the token, not on the command alone (r2 red-team).
E2E_NET=present E2E e7 sweep-post NETCUP_SCP_ACCESS_TOKEN=AT ANCHOR_HOSTNAME=anchor.example.net SERVER_ID=1 SCP_USER_ID=1
is "e7 token + valid ids reaches the API (rc != 0)" "nonzero" "$([ "$rc" -ne 0 ] && echo nonzero || echo zero)"
is "e7 no no-op line" "0" "$(grep -c 'no token held' "$WORK/e2e.e7" || true)"
# A token only in a $GITHUB_ENV handoff line is still "held": no short-circuit,
# the id guards apply (fail closed).
printf 'NETCUP_SCP_ACCESS_TOKEN=AT\n' > "$WORK/github_env.e8"
E2E e8 sweep-post GITHUB_ENV="$WORK/github_env.e8" NETCUP_SCP_ACCESS_TOKEN= SERVER_ID= SCP_USER_ID=
is "e8 handoff token + empty SERVER_ID rc 1" "1" "$rc"
is "e8 guard message" "1" "$(grep -c 'A1 FAIL: SERVER_ID is required' "$WORK/e2e.e8" || true)"
# Other commands with no token are unchanged (the short-circuit is sweep-post only).
E2E e6 sweep-pre NETCUP_SCP_ACCESS_TOKEN= SERVER_ID= SCP_USER_ID=
is "e6 sweep-pre no token + no ids rc 1" "1" "$rc"
is "e6 guard message" "1" "$(grep -c 'A1 FAIL: SERVER_ID is required' "$WORK/e2e.e6" || true)"

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
