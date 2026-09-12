#!/usr/bin/env bash
# tests/naming-scheme/run-test.sh — naming derivation + drift + legacy-shape guard.
#
# Guards issue #105 (flat tenant-suffix names: anchor-01-<tenant>):
#   (a) scripts/lib/naming.sh derivations + the D2 fail-closed username policy;
#   (b) the console-fallback copy embedded in scripts/010-provision.sh between
#       the BEGIN/END NAMING markers must stay byte-identical to the lib;
#   (c) no tracked .sh/.tf/.md/.yml may still carry the legacy
#       anchor-<tenant>-01 shape (ordinal-boundary regex: the new shape and
#       the firewall policy name piercloud-anchor-anchor-01-pier-<id> must
#       NOT match).
# Cred-free, offline, read-only: sources the lib and reads tracked files.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
LIB="scripts/lib/naming.sh"
PROVISION="scripts/010-provision.sh"
SELF_REL="tests/naming-scheme/run-test.sh"

pass=0
fail=0
ok()  { pass=$((pass + 1)); printf 'ok   %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL %s\n' "$1"; }
is()  { # $1 label, $2 expected, $3 actual
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi
}

[ -f "$LIB" ] || { printf 'FAIL lib not found: %s\n' "$LIB"; exit 1; }
[ -f "$PROVISION" ] || { printf 'FAIL provision script not found: %s\n' "$PROVISION"; exit 1; }
. scripts/lib/naming.sh

# ---- (a) canonical derivations -------------------------------------------
is "sanitize pier" "pier" "$(sanitize_tenant pier)"
is "anchor host for pier" "anchor-01-pier" "$(derive_anchor_hostname "$(sanitize_tenant pier)")"
is "status host for pier" "status-pier" "$(derive_status_host "$(sanitize_tenant pier)")"
is "status FQDN for pier" "status-pier.piercloud.net" "$(derive_status_host "$(sanitize_tenant pier)").piercloud.net"
is "anchor FQDN for pier" "anchor-01-pier.piercloud.net" "$(derive_anchor_hostname "$(sanitize_tenant pier)").piercloud.net"
# The tenants the CI proofs rely on stay derivable unchanged.
is "status host for citest" "status-citest" "$(derive_status_host "$(sanitize_tenant citest)")"
is "anchor host for prodprobe" "anchor-01-prodprobe" "$(derive_anchor_hostname "$(sanitize_tenant prodprobe)")"
# The old sanitizer semantics survive (non-destructive: strip/normalize).
is "sanitize .pier" "pier" "$(sanitize_tenant .pier)"
is "sanitize pier--carlo" "pier-carlo" "$(sanitize_tenant pier--carlo)"

# ---- (a2) D2 policy: fail closed on the LOWERCASED RAW value -------------
expect_fail() { # $1 = lowercased raw value that must be rejected
  local raw="$1" rc=0 err
  err="$(validate_tenant_username "$raw" 2>&1)" || rc=$?
  if [ "$rc" -eq 0 ]; then
    bad "validate rejects '$raw' (returned 0)"; return
  fi
  case "$err" in
    *"$raw"*) ok "validate rejects '$raw' and names the raw value" ;;
    *) bad "validate rejects '$raw' but message lacks the raw value: $err" ;;
  esac
}
expect_pass() { # $1 = lowercased raw value that must be accepted
  local raw="$1" rc=0 err
  err="$(validate_tenant_username "$raw" 2>&1)" || rc=$?
  if [ "$rc" -eq 0 ]; then ok "validate accepts '$raw'"; else bad "validate rejects '$raw': $err"; fi
}
expect_fail 'pier-'
expect_fail '.pier'
expect_fail 'pier--carlo'
expect_fail 'anchorfan'
expect_fail 'statuspage'
expect_fail 'pcu123'
expect_fail 'abcdefghijklmnopqrstu' # 21 chars
expect_fail ''                      # empty
expect_pass 'pier'
expect_pass 'citest'
expect_pass 'prodprobe'
# Uppercase is normalised by the caller's tr before validation (Pier -> pier).
pier_lower="$(printf '%s' Pier | tr '[:upper:]' '[:lower:]')"
expect_pass "$pier_lower"
is "Pier normalises to pier" "pier" "$pier_lower"

# ---- (b) the 010 embedded fallback must not drift from the lib -----------
span() { sed -n '/^# --- BEGIN NAMING ---$/,/^# --- END NAMING ---$/p' "$1"; }
lib_span="$(span "$LIB")"
prov_span="$(span "$PROVISION")"
[ -n "$lib_span" ] || bad "lib carries the BEGIN/END NAMING markers"
[ -n "$prov_span" ] || bad "010 carries the nested BEGIN/END NAMING markers"
if [ "$lib_span" = "$prov_span" ]; then
  ok "010 embedded naming block matches scripts/lib/naming.sh"
else
  bad "010 embedded naming block drifted from scripts/lib/naming.sh"
  diff <(printf '%s\n' "$lib_span") <(printf '%s\n' "$prov_span") || true
fi
# The fallback must stay inside the CADDY RENDER span (bind-e2e extracts it).
if grep -q 'BEGIN CADDY RENDER' "$PROVISION" && grep -q 'END CADDY RENDER' "$PROVISION"; then
  ok "010 keeps the Caddy render markers"
else
  bad "010 lost a Caddy render marker"
fi

# ---- (c) legacy anchor-<tenant>-01 shape must be gone --------------------
# Ordinal boundary: the OLD shape ends in -01 and is followed by a non-hyphen
# boundary. The NEW shape (anchor-01-<tenant>) and the policy name
# piercloud-anchor-anchor-01-pier-933556 sit on the correct side of it.
legacy_re='anchor-[A-Za-z0-9${}<>._-]+-01([^A-Za-z0-9-]|$)'
matches() { printf '%s' "$1" | grep -qE "$legacy_re"; }
mismatches() { ! printf '%s' "$1" | grep -qE "$legacy_re"; }
# Self-test the guard: legacy shapes match, new shapes do not.
matches 'anchor-pier-01' && ok "guard matches legacy anchor-pier-01" || bad "guard misses legacy anchor-pier-01"
matches 'anchor-${SAN}-01' && ok "guard matches legacy anchor-\${SAN}-01" || bad "guard misses legacy anchor-\${SAN}-01"
matches 'anchor-USER-01.piercloud.net' && ok "guard matches legacy anchor-USER-01.piercloud.net" || bad "guard misses legacy anchor-USER-01.piercloud.net"
if mismatches 'piercloud-anchor-anchor-01-pier-933556'; then ok "guard ignores new policy name"; else bad "guard hits new policy name"; fi
if mismatches 'anchor-01-${SAN}'; then ok "guard ignores new anchor-01-\${SAN}"; else bad "guard hits new anchor-01-\${SAN}"; fi
# Sweep tracked files; exclude this harness (it carries the pattern by design).
hits=""
while IFS= read -r f; do
  [ -n "$f" ] || continue
  out="$(grep -nHE "$legacy_re" "$f" 2>/dev/null || true)"
  if [ -n "$out" ]; then hits="${hits}${out}"$'\n'; fi
done < <(git ls-files '*.sh' '*.tf' '*.md' '*.yml' | grep -v "^${SELF_REL}$")
if [ -z "$hits" ]; then
  ok "no tracked file carries the legacy anchor-<tenant>-01 shape"
else
  bad "legacy anchor-<tenant>-01 shape still present:"
  printf '%s' "$hits"
fi

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
