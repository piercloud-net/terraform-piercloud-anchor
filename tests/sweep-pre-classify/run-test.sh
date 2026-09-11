#!/usr/bin/env bash
# Unit test for cmd_sweep_pre's classification/retirement matrix in
# .github/scripts/020-provision-anchor.sh.
#
# Contract under test (review MAJOR-2/MINOR-1/MINOR-2, 2026-09-11):
#   - The workflow-wide concurrency.group in provision.yml (~line 53)
#     serializes EVERY run of this workflow, so any non-own tmp found at
#     pre-sweep belongs to a dead run — including a FRESH one (leaked by an
#     earlier run's tail failure). A leaked tmp keeps admitting a stale
#     runner /32 to :22 (GitHub recycles runner IPs), so it is retired NOW
#     instead of waiting for the 2h age.
#   - Two passes: classify first (own / non-own / orphan), fail closed on
#     orphan BEFORE any mutation, then retire non-own tmps and drop own
#     leftovers. [aged, orphan] therefore leaves the aged tmp untouched.
#   - Fail closed (exit 3) ONLY on an orphan (no parseable created_at) or a
#     close_policy failure; anything else proceeds.
#   - Own leftovers (duplicates included) are dropped — open recreates the
#     window from its pinned /32.
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
# detach can be told to fail for ONE policy id (STUB_FAIL_DETACH_PID) so the
# close_policy-failure path is reachable without touching the real function.
detach_policy() {
  printf 'detach %s\n' "$1" >> "$STUB_ACTIONS"
  [ "${STUB_FAIL_DETACH_PID:-}" != "$1" ]
}
delete_policy() { printf 'delete %s\n' "$1" >> "$STUB_ACTIONS"; }
PRELUDE
  extract sweep_destructive
  extract sweep_note
  extract policy_age
  extract close_policy
  extract cmd_sweep_pre
} > "$WORK/functions.sh"
for fn in sweep_destructive sweep_note policy_age close_policy cmd_sweep_pre; do
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

RC_OF() { local l="$1" mode="${3-apply}"; STUB_LIST="$2" STUB_FAIL_DETACH_PID="${STUB_FAIL_DETACH_PID:-}" PATH="$WORK/bin:$PATH" STUB_ACTIONS="$WORK/actions.$l" GITHUB_STEP_SUMMARY="$WORK/summary.$l" MODE="$mode" SERVER_ID=933556 OWN_NAME="piercloud-tmp-933556-999" TMP_TTL_SECONDS=7200 \
  bash -c 'set -euo pipefail; source "$1"; cmd_sweep_pre' _ "$WORK/functions.sh" > "$WORK/out.$l" 2>&1 && echo 0 || echo $?; }
ACTIONS() { [ -f "$WORK/actions.$1" ] && paste -sd' ' "$WORK/actions.$1" || echo ""; }
OUT() { cat "$WORK/out.$1" 2>/dev/null || echo ""; }
SUMMARY() { [ -f "$WORK/summary.$1" ] && cat "$WORK/summary.$1" || echo ""; }

# ---- case 1: nothing to sweep ----------------------------------------------
rc=$(RC_OF c1 "[]"); is "c1 rc" "0" "$rc"
is "c1 clean" "$(grep -c 'pre-sweep clean' "$WORK/out.c1" || true)" "1"
is "c1 actions" "" "$(ACTIONS c1)"

# ---- case 2: one FRESH foreign tmp is a dead run's leak -> retired ----------
rc=$(RC_OF c2 "[$(entry 11 piercloud-tmp-933556-1 60)]")
is "c2 rc" "0" "$rc"
is "c2 actions" "detach 11 delete 11" "$(ACTIONS c2)"
is "c2 leaked log" "$(grep -c "retiring leaked tmp policy 'piercloud-tmp-933556-1'" "$WORK/out.c2" || true)" "1"

# ---- case 3: two fresh foreign tmps -> BOTH retired, run proceeds -----------
rc=$(RC_OF c3 "[$(entry 11 piercloud-tmp-933556-1 60),$(entry 12 piercloud-tmp-933556-2 120)]")
is "c3 rc" "0" "$rc"
is "c3 actions" "detach 11 delete 11 detach 12 delete 12" "$(ACTIONS c3)"
is "c3 no surplus" "$(grep -c 'SURPLUS_FAIL_CLOSED' "$WORK/out.c3" || true)" "0"

# ---- case 4: two AGED tmps are retired, run proceeds ------------------------
rc=$(RC_OF c4 "[$(entry 11 piercloud-tmp-933556-1 10800),$(entry 12 piercloud-tmp-933556-2 9000)]")
is "c4 rc" "0" "$rc"
is "c4 actions" "detach 11 delete 11 detach 12 delete 12" "$(ACTIONS c4)"
is "c4 summary" "$(grep -c 'retired 2 aged + 0 leaked' "$WORK/out.c4" || true)" "1"

# ---- case 5: one aged + one fresh -> both retired ---------------------------
rc=$(RC_OF c5 "[$(entry 11 piercloud-tmp-933556-1 10800),$(entry 12 piercloud-tmp-933556-2 60)]")
is "c5 rc" "0" "$rc"
is "c5 actions" "detach 11 delete 11 detach 12 delete 12" "$(ACTIONS c5)"
is "c5 summary" "$(grep -c 'retired 1 aged + 1 leaked' "$WORK/out.c5" || true)" "1"

# ---- case 6: orphan stays fail-closed, nothing mutated ----------------------
rc=$(RC_OF c6 "[$(entry 11 piercloud-tmp-933556-1 orphan)]")
is "c6 rc" "3" "$rc"
is "c6 orphan msg" "$(grep -c 'orphan tmp policy' "$WORK/out.c6" || true)" "1"
is "c6 actions" "" "$(ACTIONS c6)"

# ---- case 7: own leftover + one fresh foreign -> foreign retired FIRST, -----
# ----         then the own leftover is dropped -------------------------------
rc=$(RC_OF c7 "[$(entry 99 piercloud-tmp-933556-999 30),$(entry 12 piercloud-tmp-933556-2 60)]")
is "c7 rc" "0" "$rc"
is "c7 actions" "detach 12 delete 12 detach 99 delete 99" "$(ACTIONS c7)"

# ---- case 8: own leftover alone -> dropped ---------------------------------
rc=$(RC_OF c8 "[$(entry 99 piercloud-tmp-933556-999 30)]")
is "c8 rc" "0" "$rc"
is "c8 actions" "detach 99 delete 99" "$(ACTIONS c8)"

# ---- case 9: [aged, orphan] -> orphan verdict BEFORE any mutation: exit 3, --
# ----         the aged tmp is NOT retired (two-pass ordering contract) -------
rc=$(RC_OF c9 "[$(entry 11 piercloud-tmp-933556-1 10800),$(entry 12 piercloud-tmp-933556-2 orphan)]")
is "c9 rc" "3" "$rc"
is "c9 orphan msg" "$(grep -c 'orphan tmp policy' "$WORK/out.c9" || true)" "1"
is "c9 actions" "" "$(ACTIONS c9)"
is "c9 aged untouched" "$(grep -c 'retiring' "$WORK/out.c9" || true)" "0"

# ---- case 10: [fresh, fresh, aged] -> all three retired, run proceeds -------
rc=$(RC_OF c10 "[$(entry 11 piercloud-tmp-933556-1 60),$(entry 12 piercloud-tmp-933556-2 120),$(entry 13 piercloud-tmp-933556-3 10800)]")
is "c10 rc" "0" "$rc"
is "c10 actions" "detach 11 delete 11 detach 12 delete 12 detach 13 delete 13" "$(ACTIONS c10)"
is "c10 summary" "$(grep -c 'retired 1 aged + 2 leaked' "$WORK/out.c10" || true)" "1"

# ---- case 11: close_policy failure on a non-own tmp -> exit 3, fail-closed --
STUB_FAIL_DETACH_PID=11
rc=$(RC_OF c11 "[$(entry 11 piercloud-tmp-933556-1 60)]")
unset STUB_FAIL_DETACH_PID
is "c11 rc" "3" "$rc"
is "c11 actions" "detach 11 delete 11" "$(ACTIONS c11)"
is "c11 message" "$(grep -c 'could not retire tmp policy' "$WORK/out.c11" || true)" "1"

# ---- case 12: duplicate own leftovers -> BOTH dropped, run proceeds ---------
rc=$(RC_OF c12 "[$(entry 99 piercloud-tmp-933556-999 30),$(entry 98 piercloud-tmp-933556-999 45)]")
is "c12 rc" "0" "$rc"
is "c12 actions" "detach 99 delete 99 detach 98 delete 98" "$(ACTIONS c12)"
is "c12 drop count" "$(grep -c 'dropping own leftover' "$WORK/out.c12" || true)" "2"

# ---- case 13: mode=check is REPORT-ONLY: nothing is detached/deleted, the
# ----          would-be retirements land in the log + step summary ----------
rc=$(RC_OF c13 "[$(entry 11 piercloud-tmp-933556-1 60),$(entry 99 piercloud-tmp-933556-999 30)]" check)
is "c13 rc" "0" "$rc"
is "c13 actions (none)" "" "$(ACTIONS c13)"
is "c13 no destructive line" "$(grep -c 'retiring leaked tmp policy' "$WORK/out.c13" || true)" "0"
is "c13 report-only leaked" "$(grep -c 'REPORT-ONLY (mode=check): leaked tmp policy' "$WORK/out.c13" || true)" "1"
is "c13 report-only own" "$(grep -c 'REPORT-ONLY (mode=check): own leftover policy' "$WORK/out.c13" || true)" "1"
is "c13 summary line" "3" "$(grep -c 'A1 sweep: pre-sweep: REPORT-ONLY' "$WORK/summary.c13" || true)"
is "c13 clean report" "$(grep -c 'pre-sweep clean in REPORT-ONLY mode' "$WORK/out.c13" || true)" "1"

# ---- case 14: mode=check still fails closed on an orphan (anomaly stays
# ----          visible) but mutates nothing ---------------------------------
rc=$(RC_OF c14 "[$(entry 11 piercloud-tmp-933556-1 orphan)]" check)
is "c14 rc" "3" "$rc"
is "c14 orphan msg" "$(grep -c 'orphan tmp policy' "$WORK/out.c14" || true)" "1"
is "c14 actions (none)" "" "$(ACTIONS c14)"

# ---- case 15: MODE unset (local invocation) is report-only too (fail-safe) --
rc=$(RC_OF c15 "[$(entry 11 piercloud-tmp-933556-1 60)]" "")
is "c15 rc" "0" "$rc"
is "c15 actions (none)" "" "$(ACTIONS c15)"
is "c15 report-only" "1" "$(grep -c 'REPORT-ONLY (mode=unset): leaked tmp policy' "$WORK/out.c15" || true)"

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
