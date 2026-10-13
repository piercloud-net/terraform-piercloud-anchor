#!/usr/bin/env bash
# tests/broker-provision-dns/run-test.sh — b3b (#189): the provision DNS
# stage writes through the pc-control broker, and the direct provider-token
# writer is retired.
#
# Static, offline harness (no network, no credentials): pins the shape of the
# provision.yml `anchor-dns` job (broker lib call over OIDC, managed-lane
# guard, tenant environment, resolved IPv4, fail-before-thumbprint ordering)
# and proves the retired provider surface (script, harness, variable and
# secret names) is gone from every production surface.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
PROV=".github/workflows/provision.yml"
CI=".github/workflows/ci.yml"
LIB=".github/scripts/lib/broker-dns.sh"
REPORT_LIB=".github/scripts/lib/broker-report.sh"

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
lacks() { # $1 label, $2 needle, $3 haystack -- ok when the needle is ABSENT
  case "$3" in *"$2"*) bad "$1 (found '$2')" ;; *) ok "$1" ;; esac
}
lacks_word() { # $1 label, $2 word, $3 haystack -- word-boundary absence
  if printf '%s\n' "$3" | grep -qwE -- "$2"; then bad "$1 (found '$2')"; else ok "$1"; fi
}

[ -f "$PROV" ] || { printf 'FAIL provision.yml not found: %s\n' "$PROV"; exit 1; }
[ -f "$CI" ] || { printf 'FAIL ci.yml not found: %s\n' "$CI"; exit 1; }
[ -f "$LIB" ] || { printf 'FAIL broker-dns lib not found: %s\n' "$LIB"; exit 1; }
[ -f "$REPORT_LIB" ] || { printf 'FAIL broker-report lib not found: %s\n' "$REPORT_LIB"; exit 1; }

# The anchor-dns job text, comments stripped: a stray comment must not fake a
# wiring assertion (the lib call, guard message and env are live YAML). The
# job sits between `anchor-dns:` and the next top-level job key.
JOB="$(awk '/^  anchor-dns:/{f=1} /^  apply-placeholder:/{f=0} f' "$PROV" | grep -v '^[[:space:]]*#')"
[ -n "$JOB" ] || { printf 'FAIL anchor-dns job not found in %s\n' "$PROV"; exit 1; }

# ---- the broker-dns lib is the one writer --------------------------------
contains "broker-dns lib defines write_anchor_dns" 'write_anchor_dns()' "$(cat "$LIB")"
contains "dns lib reuses the shared broker helpers" 'broker-report.sh' "$(cat "$LIB")"
contains "broker mint pins the broker audience" '"piercloud-broker"' "$(cat "$REPORT_LIB")"

# ---- job shape: broker call, managed lane, OIDC ---------------------------
contains "job routes through the broker" 'Anchor DNS upsert + verify through the pc-control broker (fail-closed)' "$JOB"
contains "job needs device-flow (same-run report)" 'needs: [device-flow]' "$JOB"
contains "job is apply-gated" "if: inputs.mode == 'apply'" "$JOB"
contains "job selects the tenant environment" "environment: \${{ inputs.tenant != '' && inputs.tenant || 'anchor' }}" "$JOB"
contains "job requests the OIDC token" 'id-token: write' "$JOB"
contains "job keeps contents read" 'contents: read' "$JOB"
contains "job sets the broker base" 'BROKER_URL: https://broker.piercloud.net' "$JOB"
contains "job passes the anchor_ref input" 'ANCHOR_REF: ${{ inputs.anchor_ref }}' "$JOB"
contains "job passes the device-flow resolved IPv4" 'ANCHOR_IPV4: ${{ needs.device-flow.outputs.anchor_ipv4 }}' "$JOB"
contains "job checks out without persisted credentials" 'persist-credentials: false' "$JOB"

# The security-relevant lines are pinned as WHOLE lines at the exact YAML
# body indentation (10 spaces), and ordered: a substring pin survives
# comment decoys, `: '...'` no-ops, deeper indentation (wrapping in a dead
# `if`) and step reorder.
JOB_LINES="$(printf '%s\n' "$JOB")"
src_line="$(printf '%s\n' "$JOB_LINES" | grep -nE '^          \. \.github/scripts/lib/broker-dns\.sh$' | cut -d: -f1)"
call_line="$(printf '%s\n' "$JOB_LINES" | grep -nE '^          write_anchor_dns "\$ANCHOR_REF" "\$ANCHOR_IPV4"$' | cut -d: -f1)"
guard_line="$(printf '%s\n' "$JOB_LINES" | grep -nE '^          if \[ -z "\$ANCHOR_REF" \]; then$' | cut -d: -f1)"
guard_exit="$(printf '%s\n' "$JOB_LINES" | grep -cE '^            exit 1$')"
[ -n "$src_line" ] && ok "job sources the broker-dns lib (exact line)" || bad "broker-dns source line not found at the expected indentation"
[ -n "$call_line" ] && ok "job calls write_anchor_dns with ref + ipv4 (exact line)" || bad "write_anchor_dns call line not found at the expected indentation"
[ -n "$guard_line" ] && ok "guard is a live if (exact line)" || bad "guard if line not found at the expected indentation"
is "guard exits non-zero" "1" "$guard_exit"
if [ -n "$guard_line" ] && [ -n "$call_line" ] && [ "$guard_line" -lt "$call_line" ]; then ok "guard runs before the write"; else bad "guard line ($guard_line) must precede the write line ($call_line)"; fi
if [ -n "$src_line" ] && [ -n "$call_line" ] && [ "$src_line" -lt "$call_line" ]; then ok "lib sourced before the write"; else bad "source line ($src_line) must precede the write line ($call_line)"; fi
# A dead step or a shadowed function defeats the line pins above: no
# step-level `if:`/`continue-on-error` may appear (the job's own apply gate
# is the only `if:` at 4-space indent), and the call/source may appear once.
is "no step-level if in the job" "0" "$(printf '%s\n' "$JOB_LINES" | grep -cE '^        if:')"
is "no continue-on-error in the job" "0" "$(printf '%s\n' "$JOB_LINES" | grep -cE '^        continue-on-error')"
is "job-level if is exactly the apply gate" "1" "$(printf '%s\n' "$JOB_LINES" | grep -cE '^    if: inputs\.mode == .apply.$')"
is "exactly one write_anchor_dns source line" "1" "$(printf '%s\n' "$JOB_LINES" | grep -cE '^          \. \.github/scripts/lib/broker-dns\.sh$')"
is "exactly one write_anchor_dns call line" "1" "$(printf '%s\n' "$JOB_LINES" | grep -cE '^          write_anchor_dns "\$ANCHOR_REF" "\$ANCHOR_IPV4"$')"
is "no shadowing write_anchor_dns definition in the job" "0" "$(printf '%s\n' "$JOB_LINES" | grep -cE '^          write_anchor_dns\(\)')"

# ---- the managed-lane guard fails closed ----------------------------------
contains "guard names the b3b broker path" 'anchor DNS now goes through the pc-control broker (b3b, #189)' "$JOB"

# ---- the retired provider surface is absent from the job ------------------
for v in NET_DNS_PROVIDER STATUS_EDGE_DOMAIN CLOUDFLARE_DNS_TOKEN GCORE_DNS_TOKEN; do
  lacks_word "job does not consume $v" "$v" "$JOB"
done
lacks "job does not call the retired writer" '030-anchor-dns.sh' "$JOB"
lacks "job does not name a provider zone override" 'NET_DNS_ZONE' "$JOB"

# ---- workflow wiring: fail before any thumbprint --------------------------
prov_live="$(grep -v '^[[:space:]]*#' "$PROV")"
contains "thumbprint waits for the DNS job" 'needs: [device-flow, anchor-dns]' "$prov_live"
lacks "provision no longer references the retired writer" '030-anchor-dns.sh' "$prov_live"
for v in NET_DNS_PROVIDER STATUS_EDGE_DOMAIN CLOUDFLARE_DNS_TOKEN GCORE_DNS_TOKEN; do
  lacks_word "provision does not use $v anywhere" "$v" "$prov_live"
done

# ---- the retired surface is gone from the tree ----------------------------
if [ -e .github/scripts/030-anchor-dns.sh ]; then bad "retired writer still present"; else ok "retired writer deleted"; fi
if [ -e tests/anchor-dns ]; then bad "retired harness still present"; else ok "retired harness deleted"; fi

# ---- CI: the new harness is wired, the old one is not ---------------------
ci_live="$(grep -v '^[[:space:]]*#' "$CI")"
contains "ci path gate triggers this harness" 'broker-provision-dns' "$ci_live"
contains "ci runs this harness" 'bash tests/broker-provision-dns/run-test.sh' "$ci_live"
lacks "ci no longer runs the retired harness" 'tests/anchor-dns/run-test.sh' "$ci_live"
lacks "ci path gate no longer names the retired harness" 'anchor-dns' "$ci_live"

# ---- production surfaces carry no retired name ----------------------------
# Every workflow + every shell script in the run's code surface. Word
# boundaries keep the live broker config name (`PC_BROKER_STATUS_EDGE_DOMAIN`)
# legal while the retired repo variable is caught. Comments are INCLUDED: a
# stale comment is drift too. Each group must be non-empty and every surface
# must exist, so a renamed/moved file cannot silently drop out of the scan; a
# grep error (rc>1) is a failure, not a pass.
shopt -s nullglob
for pat in '.github/workflows/*.yml' '.github/scripts/*.sh' '.github/scripts/lib/*.sh' 'scripts/*.sh' 'scripts/lib/*.sh'; do
  compgen -G "$pat" >/dev/null || bad "surface group matched nothing: $pat"
done
surfaces=(.github/workflows/*.yml .github/scripts/*.sh .github/scripts/lib/*.sh scripts/*.sh scripts/lib/*.sh)
[ "${#surfaces[@]}" -gt 0 ] || bad "no production surfaces matched"
for f in "${surfaces[@]}"; do
  [ -f "$f" ] || bad "scanned surface missing: $f"
done
for v in NET_DNS_PROVIDER STATUS_EDGE_DOMAIN CLOUDFLARE_DNS_TOKEN GCORE_DNS_TOKEN; do
  rc=0
  hits="$(grep -lnwE -- "$v" "${surfaces[@]}")" || rc=$?
  case "$rc" in
    0) bad "production surface uses $v: $hits" ;;
    1) ok "no production surface uses $v" ;;
    *) bad "grep failed scanning for $v (rc=$rc)" ;;
  esac
done
rc=0
hits="$(grep -lnE '030-anchor-dns|tests/anchor-dns' "${surfaces[@]}")" || rc=$?
case "$rc" in
  0) bad "production surface references the retired writer/harness: $hits" ;;
  1) ok "no production surface references the retired writer/harness" ;;
  *) bad "grep failed scanning for the retired writer/harness (rc=$rc)" ;;
esac

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
