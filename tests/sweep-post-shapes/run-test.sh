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
# Real cmd_sweep_post / policy_age / close_policy / sweep_* are exercised;
# only the API boundary (list/detach/delete) and logging are stubbed — no
# network, no credentials.
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
    printf '{"id":"%s","name":"piercloud-tmp-933556-%s","description":"hand-made policy"}' "$1" "$2"
  else
    printf '{"id":"%s","name":"piercloud-tmp-933556-%s","description":"created_at=%s purpose=A1-ssh"}' "$1" "$2" "$(stamp "$3")"
  fi
}

# One steady-state policy (id 42) — the live attachment under test.
STEADY_LIVE='[{"id":42,"name":"piercloud-anchor-anchor-pier-01-933556","description":""}]'

RC_OF() { # $1 label, $2 STUB_LIST_TMP, $3 STUB_IFACE, [$4 STUB_STEADY]
  local l="$1" rc=0
  : > "$WORK/actions.$l"
  STUB_LIST_TMP="$2" STUB_IFACE="$3" STUB_STEADY="${4:-[]}" \
  PATH="$WORK/bin:$PATH" STUB_ACTIONS="$WORK/actions.$l" \
  GITHUB_STEP_SUMMARY="$WORK/summary.$l" MODE=apply \
  SERVER_ID=933556 SCP_USER_ID=1 RUN_ID=999 \
  OWN_NAME="piercloud-tmp-933556-999" NETCUP_SCP_ACCESS_TOKEN=AT TMP_TTL_SECONDS=7200 \
  bash -c 'set -euo pipefail; source "$1"; cmd_sweep_post' _ "$WORK/functions.sh" \
    > "$WORK/out.$l" 2>&1 || rc=$?
  printf '%s' "$rc"
}
ACTIONS() { [ -f "$WORK/actions.$1" ] && paste -sd' ' "$WORK/actions.$1" || echo ""; }

# ---- cases 1-4: tolerant attached shapes -> live policy KEPT, no mutation ---
rc="$(RC_OF c1 "[]" '{"userPolicies":[{"id":42,"name":"piercloud-anchor-anchor-pier-01-933556"}]}' "$STEADY_LIVE")"
is "c1 rc" "0" "$rc"
is "c1 actions (live kept)" "" "$(ACTIONS c1)"
is "c1 kept log" "1" "$(grep -c 'is attached — kept' "$WORK/out.c1" || true)"
rc="$(RC_OF c2 "[]" '{"userPolicies":[{"id":"42","name":"piercloud-anchor-anchor-pier-01-933556"}]}' "$STEADY_LIVE")"
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
ambiguous_case c8g '{"userPolicies":[{"name":"piercloud-anchor-anchor-pier-01-933556"}]}'      # THE live-policy repro: object without id
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

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
