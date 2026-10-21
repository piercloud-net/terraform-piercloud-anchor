#!/usr/bin/env bash
# tests/policy-naming/run-test.sh — issue #121 policy-name scope proofs.
#
# Exercises the REAL list_tmp_policies / list_steady_policies filters from
# .github/scripts/020-provision-anchor.sh with a stubbed API boundary (the
# fixture replaces the HTTP response). The filters decide what a sweep may
# ever see, so their scope is security-relevant:
#
#   tmp, new shape      piercloud-tmp-<run_id>, matched by an ANCHORED
#                       digits-only suffix ^piercloud-tmp-[0-9]+\z — the
#                       \z is load-bearing (Oniguruma's $ also matches
#                       immediately before a trailing newline).
#   tmp, legacy shape   piercloud-tmp-<server_id>-<run_id> — matched ONLY
#                       for THIS server (startswith the id prefix).
#   tmp, other server   never matched: never swept, never logged.
#   steady, family      piercloud-anchor- prefix AND (endswith the new
#                       -<hostname> anchor OR the pre-change -<server_id>
#                       migration anchor). Another hostname or another
#                       server's legacy name is out of scope.
#   names               OWN_NAME carries no server id; TMP_PREFIX is gone
#                       (it would be an unused variable after the rename).
#
# Cred-free, offline: no network, no credentials, real jq.
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
log() { printf 'A1: %s\n' "$*"; }
die() { printf 'A1 FAIL: %s\n' "$*" >&2; exit 1; }
policies_path() { printf '/api/v1/users/%s/firewall-policies' "$SCP_USER_ID"; }
api_call() { # method path body outvar -> fixture into the outvar (bash dynamic scope)
  HTTP_STATUS=200
  printf -v "${4:-resp}" '%s' "$STUB_POLICIES"
}
api_ok() { return 0; }
PRELUDE
  extract list_tmp_policies
  extract list_steady_policies
} > "$WORK/functions.sh"
for fn in list_tmp_policies list_steady_policies; do
  grep -q "^$fn() {" "$WORK/functions.sh" || { echo "FAIL could not extract $fn"; exit 1; }
done

RC_OF() { # $1 label, $2 fixture, $3 real function
  local rc=0
  STUB_POLICIES="$2" ANCHOR_HOSTNAME=anchor-01-pier SERVER_ID=424242 SCP_USER_ID=1 \
  STEADY_PREFIX="$STEADY_PREFIX" OWN_NAME="$OWN_NAME" \
  bash -c 'set -euo pipefail; source "$1"; "$2"' _ "$WORK/functions.sh" "$3" \
    > "$WORK/out.$1" 2>&1 || rc=$?
  printf '%s' "$rc"
}
IDS() { jq -c '[.[].id] | sort' "$WORK/out.$1"; }

# Name construction: eval the REAL assignments from the script (so the
# tests track the shipped values, not a copy).
RUN_ID=999
eval "$(grep -E '^OWN_NAME=' "$SCRIPT")"
eval "$(grep -E '^STEADY_PREFIX=' "$SCRIPT")"

# ---- tmp scope (the sweep may NEVER see an id-bearing name outside this
# ---- server's legacy prefix; see plan R1/B1) ------------------------------
TMP_FIXTURE='[
 {"id":"1","name":"piercloud-tmp-12345","description":""},
 {"id":"2","name":"piercloud-tmp-424242-legacy","description":""},
 {"id":"3","name":"piercloud-tmp-777-old","description":""},
 {"id":"4","name":"piercloud-anchor-anchor-01-pier","description":""},
 {"id":"5","name":"unrelated-policy","description":""},
 {"id":"6","name":"piercloud-tmp-","description":""},
 {"id":"7","name":"piercloud-tmp-12x","description":""},
 {"id":"8","name":"piercloud-tmp-12345-extra","description":""},
 {"id":"9","name":"piercloud-tmp-9\n","description":""},
 {"id":"10","name":"piercloud-tmp-10\r","description":""}
]'
rc="$(RC_OF t1 "$TMP_FIXTURE" list_tmp_policies)"
is "t1 rc" "0" "$rc"
is "t1 tmp scope (new + legacy this-server only)" '["1","2"]' "$(IDS t1)"

# ---- steady scope: new name + legacy migration name, nothing else --------
STEADY_FIXTURE='[
 {"id":"11","name":"piercloud-anchor-anchor-01-pier","description":""},
 {"id":"12","name":"piercloud-anchor-anchor-01-pier-424242","description":""},
 {"id":"13","name":"piercloud-anchor-anchor-02-pier","description":""},
 {"id":"14","name":"piercloud-anchor-other-01-777","description":""},
 {"id":"15","name":"piercloud-anchor-anchor-01-pier-777","description":""},
 {"id":"16","name":"piercloud-tmp-12345","description":""},
 {"id":"17","name":"piercloud-anchor-","description":""}
]'
rc="$(RC_OF s1 "$STEADY_FIXTURE" list_steady_policies)"
is "s1 rc" "0" "$rc"
is "s1 steady scope (new + migration only)" '["11","12"]' "$(IDS s1)"

# ---- envelope tolerance survives the filter rewrite ----------------------
rc="$(RC_OF s2 '{"firewallPolicies":[{"id":"21","name":"piercloud-anchor-anchor-01-pier","description":""},{"id":"22","name":"piercloud-anchor-someone-else","description":""}]}' list_steady_policies)"
is "s2 rc" "0" "$rc"
is "s2 envelope dispatch" '["21"]' "$(IDS s2)"

# ---- name construction: no server id in OWN_NAME, TMP_PREFIX gone --------
is "own name shape" "piercloud-tmp-999" "$OWN_NAME"
if printf '%s' "$OWN_NAME" | grep -q '424242'; then
  bad "OWN_NAME must not carry the server id"
else
  ok "OWN_NAME carries no server id"
fi
if grep -qE '^TMP_PREFIX=' "$SCRIPT"; then
  bad "TMP_PREFIX should be removed (unused after the rename)"
else
  ok "TMP_PREFIX is gone"
fi

# ---- the interfaces read asks the API for no reverse DNS (#216) ----------
# The SCP API's rdns assembly broke upstream on 2026-10-21: with the parameter
# omitted the same endpoint answered `rdns` as a list (failing the provider's
# map-typed schema, which kills every plan) and HTTP 500 here. Both raw call
# sites must therefore carry `loadRdns=false`; a dropped parameter is a silent
# return of a provisioning-wide outage, so pin it behaviourally.
{
  cat <<'PRELUDE'
log() { printf 'A1: %s\n' "$*" >&2; }
die() { printf 'A1 FAIL: %s\n' "$*" >&2; exit 1; }
api_ok() { [ "$1" = "200" ]; }
api_call() { # record method + path, then answer per STUB_STATUS (bash dynamic scope)
  printf '%s %s\n' "$1" "$2" >"$STUB_PATH_OUT"
  HTTP_STATUS="${STUB_STATUS:-200}"
  printf -v "${4:-resp}" '%s' '[{"mac":"00:11:22:33:44:55"}]'
}
PRELUDE
  # The real valid_mac (whole-value anchored, newline-safe), not a weaker copy.
  extract valid_mac
  extract resolve_mac
} > "$WORK/resolve_mac.sh"
for fn in valid_mac resolve_mac; do
  grep -q "^$fn() {" "$WORK/resolve_mac.sh" || { echo "FAIL could not extract $fn"; exit 1; }
done
RUN_RESOLVE() { # $1 label, $2 stub status -> rc; side files per label
  local rc=0
  STUB_STATUS="$2" STUB_PATH_OUT="$WORK/interfaces-path.$1" INTERFACE_MAC='' SERVER_ID=424242 \
    bash -c 'set -euo pipefail; source "$1"; resolve_mac' _ "$WORK/resolve_mac.sh" \
    > "$WORK/out.resolve_mac.$1" 2> "$WORK/err.resolve_mac.$1" || rc=$?
  printf '%s' "$rc"
}
rc="$(RUN_RESOLVE ok 200)"
is "resolve_mac rc on 200" "0" "$rc"
is "resolve_mac asks for no rdns (method + path)" \
  "GET /api/v1/servers/424242/interfaces?loadRdns=false" \
  "$(cat "$WORK/interfaces-path.ok" 2>/dev/null)"
is "resolve_mac still resolves the MAC" "00:11:22:33:44:55" "$(cat "$WORK/out.resolve_mac.ok")"
rc="$(RUN_RESOLVE fail 500)"
if [ "$rc" -ne 0 ] && grep -q 'list server interfaces failed (HTTP 500)' "$WORK/err.resolve_mac.fail"; then
  ok "resolve_mac fails closed on a non-200 interfaces read"
else
  bad "resolve_mac must die on a non-200 interfaces read (rc=$rc)"
fi
# Real YAML parse, not a text grep (docs/verification.md §1: no hand-rolled
# parsers in verification artifacts). A comment quoting the parameter must not
# satisfy this; only an executed `run:` script can.
if WORK="$WORK" ROOT="$ROOT" python3 - <<'PYEOF'
import os, sys, yaml
doc = yaml.safe_load(open(os.path.join(os.environ["ROOT"], ".github/workflows/provision.yml")))
runs = []
for job in (doc.get("jobs") or {}).values():
    for step in (job.get("steps") or []):
        if isinstance(step, dict) and isinstance(step.get("run"), str):
            runs.append(step["run"])
want = "/interfaces?loadRdns=false"
sys.exit(0 if any(want in r for r in runs) else 1)
PYEOF
then
  ok "import-discovery read carries loadRdns=false (parsed from the run script)"
else
  bad "import-discovery read in provision.yml must carry ?loadRdns=false (#216)"
fi
# The data source half: the argument must sit inside the interfaces data source.
if awk '/^data "netcup_scp_server_interfaces" "anchor" \{/{f=1} f&&/load_rdns[[:space:]]*=[[:space:]]*false/{print "yes"; exit} f&&/^\}/{f=0}' \
     "$ROOT/main.tf" | grep -q yes; then
  ok "interfaces data source carries load_rdns = false"
else
  bad "main.tf: the interfaces data source must set load_rdns = false (#216)"
fi

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
