#!/usr/bin/env bash
# Unit test for cmd_sweep_pre's classification matrix in
# .github/scripts/020-provision-anchor.sh.
#
# Context (live 2026-09-11): the pre-sweep step used to check "more than one
# tmp policy" BEFORE looking at their age, so two tmps leaked by the ~5 min
# access-token TTL blocked every later run at this step (SURPLUS_FAIL_CLOSED)
# until they aged past 2h. The fixed order classifies first:
#   own leftover        -> tolerated, dropped (retry of this run)
#   aged (>2h)          -> retired here (its run is long dead)
#   orphan (no stamp)   -> still fail-closed (ambiguous)
#   fresh foreign       -> 1 tolerated (mutex rules out a racer), >1 fails
# Real cmd_sweep_pre/policy_age/close_policy are exercised; only the API
# boundary (list/detach/delete) and logging are stubbed — no network.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$ROOT/.github/scripts/020-provision-anchor.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0
ok()  { pass=$((pass + 1)); printf 'ok   %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL %s\n' "$1"; }
is()  { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi; }

extract() { awk "/^$1\\(\\) \\{/,/^\\}/" "$SCRIPT"; }
{
  cat <<'PRELUDE'
require_token() { :; }
log()  { printf 'A1: %s\n' "$*"; }
warn() { printf 'A1 WARNING: %s\n' "$*"; }
die()  { printf 'A1 FAIL: %s\n' "$*" >&2; exit 1; }
surplus_fail() { printf 'A1 SURPLUS_FAIL_CLOSED: %s\n' "$*" >&2; exit 3; }
list_tmp_policies() { printf '%s' "$STUB_LIST"; }
detach_policy() { printf 'detach %s\n' "$1" >> "$STUB_ACTIONS"; }
delete_policy() { printf 'delete %s\n' "$1" >> "$STUB_ACTIONS"; }
PRELUDE
  extract policy_age
  extract close_policy
  extract cmd_sweep_pre
} > "$WORK/functions.sh"
for fn in policy_age close_policy cmd_sweep_pre; do
  grep -q "^$fn() {" "$WORK/functions.sh" || { echo "FAIL could not extract $fn"; exit 1; }
done

# GNU-compatible `date -d <RFC 3339 timestamp>` shim: the script runs on Ubuntu runners
# (GNU date) while a dev laptop may be BSD/macOS — the shim keeps the REAL
# policy_age exercised on both. Everything else delegates to the real date.
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
entry() { # $1 id, $2 name, $3 age-seconds ("orphan" = unstamped description)
  if [ "$3" = "orphan" ]; then
    printf '{"id":"%s","name":"%s","description":"hand-made policy"}' "$1" "$2"
  else
    printf '{"id":"%s","name":"%s","description":"created_at=%s purpose=A1-ssh"}' "$1" "$2" "$(stamp "$3")"
  fi
}

RC_OF() { local l="$1"; STUB_LIST="$2" PATH="$WORK/bin:$PATH" STUB_ACTIONS="$WORK/actions.$l" SERVER_ID=933556 OWN_NAME="piercloud-tmp-933556-999" TMP_TTL_SECONDS=7200 \
  bash -c 'set -euo pipefail; source "$1"; cmd_sweep_pre' _ "$WORK/functions.sh" > "$WORK/out.$l" 2>&1 && echo 0 || echo $?; }
ACTIONS() { [ -f "$WORK/actions.$1" ] && paste -sd' ' "$WORK/actions.$1" || echo ""; }
OUT() { cat "$WORK/out.$1" 2>/dev/null || echo ""; }

# ---- case 1: nothing to sweep ----------------------------------------------
rc=$(RC_OF c1 "[]"); is "c1 rc" "0" "$rc"
is "c1 clean" "$(grep -c 'pre-sweep clean' "$WORK/out.c1" || true)" "1"
is "c1 actions" "" "$(ACTIONS c1)"

# ---- case 2: one fresh foreign tmp is tolerated -----------------------------
rc=$(RC_OF c2 "[$(entry 11 piercloud-tmp-933556-1 60)]")
is "c2 rc" "0" "$rc"; is "c2 actions" "" "$(ACTIONS c2)"

# ---- case 3: two fresh foreign tmps fail closed -----------------------------
rc=$(RC_OF c3 "[$(entry 11 piercloud-tmp-933556-1 60),$(entry 12 piercloud-tmp-933556-2 120)]")
is "c3 rc" "3" "$rc"; is "c3 surplus msg" "$(grep -c 'SURPLUS_FAIL_CLOSED: 2 fresh tmp' "$WORK/out.c3" || true)" "1"
is "c3 actions" "" "$(ACTIONS c3)"

# ---- case 4: two AGED tmps are retired, run proceeds ------------------------
rc=$(RC_OF c4 "[$(entry 11 piercloud-tmp-933556-1 10800),$(entry 12 piercloud-tmp-933556-2 9000)]")
is "c4 rc" "0" "$rc"
is "c4 actions" "detach 11 delete 11 detach 12 delete 12" "$(ACTIONS c4)"
is "c4 retired count" "$(grep -c 'retired 2 aged' "$WORK/out.c4" || true)" "1"

# ---- case 5: one aged + one fresh -> aged retired, fresh tolerated ----------
rc=$(RC_OF c5 "[$(entry 11 piercloud-tmp-933556-1 10800),$(entry 12 piercloud-tmp-933556-2 60)]")
is "c5 rc" "0" "$rc"; is "c5 actions" "detach 11 delete 11" "$(ACTIONS c5)"

# ---- case 6: orphan stays fail-closed --------------------------------------
rc=$(RC_OF c6 "[$(entry 11 piercloud-tmp-933556-1 orphan)]")
is "c6 rc" "3" "$rc"; is "c6 orphan msg" "$(grep -c 'orphan tmp policy' "$WORK/out.c6" || true)" "1"
is "c6 actions" "" "$(ACTIONS c6)"

# ---- case 7: own leftover + one fresh foreign -> own dropped, no surplus ----
rc=$(RC_OF c7 "[$(entry 99 piercloud-tmp-933556-999 30),$(entry 12 piercloud-tmp-933556-2 60)]")
is "c7 rc" "0" "$rc"; is "c7 actions" "detach 99 delete 99" "$(ACTIONS c7)"

# ---- case 8: own leftover alone -> dropped ---------------------------------
rc=$(RC_OF c8 "[$(entry 99 piercloud-tmp-933556-999 30)]")
is "c8 rc" "0" "$rc"; is "c8 actions" "detach 99 delete 99" "$(ACTIONS c8)"

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
