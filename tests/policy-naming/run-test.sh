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
  STUB_POLICIES="$2" ANCHOR_HOSTNAME=anchor-01-pier SERVER_ID=933556 SCP_USER_ID=1 \
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
 {"id":"2","name":"piercloud-tmp-933556-legacy","description":""},
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
 {"id":"12","name":"piercloud-anchor-anchor-01-pier-933556","description":""},
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
if printf '%s' "$OWN_NAME" | grep -q '933556'; then
  bad "OWN_NAME must not carry the server id"
else
  ok "OWN_NAME carries no server id"
fi
if grep -qE '^TMP_PREFIX=' "$SCRIPT"; then
  bad "TMP_PREFIX should be removed (unused after the rename)"
else
  ok "TMP_PREFIX is gone"
fi

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
