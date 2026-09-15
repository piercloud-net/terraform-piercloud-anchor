#!/usr/bin/env bash
# tests/public-log-safety/run-test.sh — issue #121 public-run hygiene proofs.
#
# Static, cred-free, offline assertions over the shipped artifacts:
#   (a) every identifier is masked at first receipt and never echoes raw
#       (SCP_EFF, RESOLVED_ID at all three assignment sites via
#       mask_server_id, API_USER, ORDER_NAME, OLD_HOSTNAME, MAC; the
#       server id at the top of 020-provision-anchor.sh);
#   (b) the wrong-account error carries no approver value;
#   (c) the discovery-failure path prints no server list (no nickname dump);
#   (d) the SSH host-key fingerprint print is gone from 020;
#   (e) the published artifacts (head-sha, thumbprint) reference no netcup
#       account identifiers;
#   (f) the 020 tmp/steady filter shapes + the sweep-post hostname guard +
#       the fail-closed order-name guard;
#   (g) the module identifier inputs and id outputs are sensitive.
#
# These are the regression teeth for the exposure sweep: they fail on the
# exact pre-#121 shapes (echoed ids, `'$API_USER'` in the error, the
# nickname dump, the keyscan pipe, the id-suffixed policy name).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROV="$ROOT/.github/workflows/provision.yml"
SCRIPT="$ROOT/.github/scripts/020-provision-anchor.sh"
VARS="$ROOT/variables.tf"
OUTS="$ROOT/outputs.tf"

pass=0
fail=0
ok()  { pass=$((pass + 1)); printf 'ok   %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL %s\n' "$1"; }
is()  { # $1 label, $2 expected, $3 actual
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi
}
has()  { if grep -qF -- "$2" "$1"; then ok "$3"; else bad "$3 (missing: $2)"; fi; }
lack() { if grep -qF -- "$2" "$1"; then bad "$3 (found: $2)"; else ok "$3"; fi; }

first_line() { # $1 fixed string, $2 file -> first matching line number or empty
  grep -nF -- "$1" "$2" 2>/dev/null | head -n1 | cut -d: -f1 || true
}
before() { # $1 label, $2 earlier, $3 later
  if [ -n "$2" ] && [ -n "$3" ] && [ "$2" -lt "$3" ]; then ok "$1"; else bad "$1 (line order: $2 then $3)"; fi
}

# Leaky print lines for a variable: shell print builtins (echo/printf) that
# reference it, excluding the mask itself and the $GITHUB_ENV/$GITHUB_OUTPUT
# handoff writes. printf is covered on purpose (review finding on SHA
# 2b422f8: echo-only matching passed while a printf leak was inserted).
# A printf feeding another command through a pipe (`printf '%s' "$V" |
# grep ...`) is a data feeder, not a log print — excluded; the self-test
# below proves the matcher still catches a real printf print.
print_refs() { # $1 file, $2 variable name (no $)
  awk -v v="$2" '
    /::add-mask::/ { next }
    /\$GITHUB_ENV/ { next }
    /\$GITHUB_OUTPUT/ { next }
    $0 ~ ("(^|[^A-Za-z0-9_])(echo|printf) .*\\$" v "([^A-Za-z0-9_]|$)") \
      && $0 !~ ("printf [^|]*\\$" v "([^A-Za-z0-9_]|$)[^|]*\\|") { print FILENAME":"FNR": "$0 }
  ' "$1" || true
}
no_raw_print() { # $1 label, $2 file, $3 variable name (no $)
  local hits
  hits="$(print_refs "$2" "$3")"
  if [ -z "$hits" ]; then ok "$1"; else bad "$1 — raw print found:"; printf '%s\n' "$hits"; fi
}

# Self-test: the matcher must catch a printf leak, not just echo (the
# reverted-fix shape the review used against the pre-fix harness).
selftest="$(mktemp)"
cat > "$selftest" <<'EOF'
printf 'DEBUG raw id=%s\n' "$RESOLVED_ID"
EOF
if [ -n "$(print_refs "$selftest" RESOLVED_ID)" ]; then
  ok "matcher catches a printf leak (self-test)"
else
  bad "matcher misses a printf leak (self-test)"
fi
rm -f "$selftest"

# ---- (a) masks exist and are ordered at each assignment site -------------
has "$PROV" 'echo "::add-mask::$SCP_EFF"' "SCP id mask present"
before "SCP id: digits guard before mask" \
  "$(first_line 'resolved SCP user id is not all-digits' "$PROV")" \
  "$(first_line 'echo "::add-mask::$SCP_EFF"' "$PROV")"
has "$PROV" 'echo "::add-mask::$API_USER"' "approver mask present"
before "approver: non-empty guard before mask" \
  "$(first_line 'could not read the approver' "$PROV")" \
  "$(first_line 'echo "::add-mask::$API_USER"' "$PROV")"
has "$PROV" 'mask_escaped "$ORDER_NAME"' "order-name mask present (runner-escaped)"
has "$PROV" 'mask_escaped "$OLD_HOSTNAME"' "old-hostname mask present (runner-escaped)"
has "$PROV" 'mask_escaped()' "mask_escaped helper defined"
has "$PROV" "%25" "mask_escaped escapes '%' per workflow-command data rules"
before "order name: fail-closed guard before mask" \
  "$(first_line 'without masking the order name' "$PROV")" \
  "$(first_line 'mask_escaped "$ORDER_NAME"' "$PROV")"
has "$PROV" 'echo "::add-mask::$MAC"' "MAC mask present"
before "MAC: shape validation before mask" \
  "$(first_line 'resolved interface MAC is not a 17-char' "$PROV")" \
  "$(first_line 'echo "::add-mask::$MAC"' "$PROV")"
has "$PROV" 'mask_server_id() {' "mask_server_id helper defined"
if grep -A4 -F 'mask_server_id() {' "$PROV" | grep -qF '::add-mask::'; then
  ok "mask_server_id masks inside the helper"
else
  bad "mask_server_id helper does not mask"
fi
is "mask_server_id called at all three sites" "3" "$(grep -cF 'mask_server_id "$RESOLVED_ID"' "$PROV" || true)"
before "mask_server_id defined before first call" \
  "$(first_line 'mask_server_id() {' "$PROV")" \
  "$(first_line 'mask_server_id "$RESOLVED_ID"' "$PROV")"
before "020: server-id digits guard before mask" \
  "$(first_line 'all_digits "$SERVER_ID"' "$SCRIPT")" \
  "$(first_line 'echo "::add-mask::$SERVER_ID" >&2' "$SCRIPT")"
has "$SCRIPT" 'echo "::add-mask::$mac" >&2' "020 resolved MAC masked on stderr"
has "$SCRIPT" 'echo "::add-mask::$INTERFACE_MAC" >&2' "020 override MAC masked on stderr"

# No identifier is ever printed raw (mask/env/output lines excluded) ------
no_raw_print "SCP id never printed raw" "$PROV" SCP_EFF
no_raw_print "server id never printed raw" "$PROV" RESOLVED_ID
no_raw_print "approver username never printed raw" "$PROV" API_USER
no_raw_print "order name never printed raw" "$PROV" ORDER_NAME
no_raw_print "old hostname never printed raw" "$PROV" OLD_HOSTNAME
no_raw_print "MAC never printed raw" "$PROV" MAC

# ---- (b) wrong-account error carries no value ----------------------------
wa="$(grep -nF 'WRONG-ACCOUNT APPROVAL' "$PROV" | head -n1 | cut -d: -f1 || true)"
is "wrong-account error is a single line" "1" "$(grep -cF 'WRONG-ACCOUNT APPROVAL' "$PROV" || true)"
if [ -n "$wa" ] && sed -n "${wa}p" "$PROV" | grep -qF '$API_USER'; then
  bad "wrong-account error still prints the approver value"
else
  ok "wrong-account error carries no approver value"
fi

# ---- (c) discovery failure prints count + action, never a server list ----
lack "$PROV" 'nickname' "no server-list dump (nickname) in provision.yml"
lack "$PROV" "Your account's servers" "old discovery-failure dump text gone"
has "$PROV" 'none is named $HOSTNAME. Rename the anchor to $HOSTNAME' "discovery failure carries count + action"

# ---- (d) no host-key fingerprint pipe in 020 -----------------------------
is "no ssh-keyscan/ssh-keygen in 020" "0" "$(grep -cE 'ssh-keyscan|ssh-keygen' "$SCRIPT" || true)"

# ---- (e) artifacts carry no netcup account identifiers -------------------
span() { # $1 file, $2 begin marker, $3 end marker
  awk -v a="$2" -v b="$3" '$0 ~ a {f=1} f && $0 ~ b {exit} f {print}' "$1"
}
artifact_ids='(^|[^A-Za-z0-9_])(SERVER_ID|ANCHOR_HOST|MAC|SCP_USER_ID|ORDER_NAME|API_USER|CUSTOMER_NUMBER)([^A-Za-z0-9_]|$)'
for pair in "head-sha|Record head SHA for the backend approval pin|Upload head-SHA artifact" \
  "thumbprint|Write thumbprint captured by the A1 provision step|Upload thumbprint artifact" \
  "origin-ca-csr|Upload per-anchor CSR artifact|Best-effort root lock"; do
  label="${pair%%|*}"; rest="${pair#*|}"; begin="${rest%%|*}"; end="${rest#*|}"
  body="$(span "$PROV" "$begin" "$end")"
  if [ -z "$body" ]; then
    bad "$label artifact span not found"
    continue
  fi
  if printf '%s\n' "$body" | grep -qE "$artifact_ids"; then
    bad "$label artifact references a netcup account identifier"
    printf '%s\n' "$body" | grep -nE "$artifact_ids" || true
  else
    ok "$label artifact has no netcup account identifiers"
  fi
done

# ---- (f) 020 filter shapes, guards, and gone fingerprint/test bits -------
has "$SCRIPT" '^piercloud-tmp-[0-9]+\z' "tmp filter uses the anchored new shape"
has "$SCRIPT" 'startswith($legacy)' "tmp filter keeps the legacy this-server shape"
has "$SCRIPT" '--arg legacy "piercloud-tmp-${SERVER_ID}-"' "tmp legacy prefix is the server id prefix"
has "$SCRIPT" 'endswith($h)' "steady filter uses the hostname anchor"
has "$SCRIPT" 'endswith($s)' "steady filter uses the migration id anchor"
has "$SCRIPT" '--arg h "-${ANCHOR_HOSTNAME}"' "steady hostname anchor wired"
before "sweep-post: hostname guard after the no-token no-op" \
  "$(first_line 'no token held (approval never completed)' "$SCRIPT")" \
  "$(first_line 'ANCHOR_HOSTNAME is required to scope' "$SCRIPT")"

# ---- (g) module sensitivity marks ----------------------------------------
block_of() { # $1 file, $2 kind (variable|output), $3 name
  sed -n "/^$2 \"$3\" {/,/^}/p" "$1"
}
sensitive() { # $1 label, $2 block text
  if printf '%s\n' "$2" | grep -qE '^[[:space:]]*sensitive[[:space:]]*=[[:space:]]*true'; then
    ok "$1"
  else
    bad "$1 (missing sensitive = true)"
  fi
}
for v in server_id scp_user_id customer_number; do
  sensitive "variable $v is sensitive" "$(block_of "$VARS" variable "$v")"
done
for o in server_id firewall_policy_id; do
  sensitive "output $o is sensitive" "$(block_of "$OUTS" output "$o")"
done

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
