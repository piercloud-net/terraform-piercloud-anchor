#!/usr/bin/env bash
# tests/managed-inputs/run-test.sh — issue #132 managed-dispatch inputs.
#
# The workflow carries two operator/dispatcher inputs (a′ migration):
#
#   tenant      — the job environment selector (`environment: <tenant>`;
#                 empty = the shared `anchor` env).
#   anchor_ref  — the account-lane key (`anchor-<ref>` concurrency group;
#                 empty = the static fallback lane).
#
# This harness binds both halves:
#   - STATIC wiring over provision.yml: the lane group is pinned as a stable
#     function of `anchor_ref` only; exactly the two environment-gated jobs
#     carry the dynamic `environment:` expression (per-job extraction, so a
#     quoted literal or a decoy binding elsewhere is caught); the preflight
#     step lives in the UNGATED banner job, has no `if:` and precedes the
#     device-flow job; the device-flow job depends on the banner job; the
#     environment binding check uses the MANAGED_TENANT marker.
#   - BEHAVIORAL: the REAL preflight and binding step bodies (extracted,
#     never copies) run under `env -i`; refusals must fail closed and valid
#     shapes must pass (incl. the ref-less mutating-run warning).
#
# Cred-free, offline: no network, no credentials.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
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

[ -f "$PROV" ] || { printf 'FAIL workflow not found: %s\n' "$PROV"; exit 1; }

DYN_ENV="\${{ inputs.tenant != '' && inputs.tenant || 'anchor' }}"

# ---- static wiring over provision.yml ------------------------------------
# The lane must be a STABLE function of anchor_ref alone: pin the exact
# group value (a run-id suffix or any other variable would split the lane).
LANE="$(awk '/^concurrency:/{f=1; next} f && /^[^ ]/{exit} f{print}' "$PROV" | sed -n 's/^  group: //p')"
is "lane group is the pinned anchor_ref expression" \
  "\${{ inputs.anchor_ref != '' && format('anchor-{0}', inputs.anchor_ref) || 'piercloud-netcup-policy' }}" \
  "$LANE"
case "$LANE" in *github.*|*needs.*|*strategy.*|*matrix.*) bad "lane references a non-input context";; *) ok "lane references no non-input context";; esac

# Per-job environment extraction: every job's own `environment:` line.
ENV_LINES="$(awk '
  /^  [A-Za-z0-9_.-]+:$/ { job=$1; sub(/:$/, "", job) }
  /^    environment:/ { line=$0; sub(/^    environment: /, "", line); gsub(/^['"'"'"]|['"'"'"]$/, "", line); print job "|" line }
' "$PROV")"
is "exactly two jobs carry an environment" "2" "$(printf '%s\n' "$ENV_LINES" | grep -c '|')"
is "device-flow binds the dynamic environment" "device-flow|$DYN_ENV" "$(printf '%s\n' "$ENV_LINES" | grep '^device-flow|')"
is "anchor-dns binds the dynamic environment" "anchor-dns|$DYN_ENV" "$(printf '%s\n' "$ENV_LINES" | grep '^anchor-dns|')"

# Inputs declared.
is "tenant input declared" "1" "$(grep -c '^      tenant:$' "$PROV")"
is "anchor_ref input declared" "1" "$(grep -c '^      anchor_ref:$' "$PROV")"

# Preflight placement: in the ungated banner job, before device-flow, no `if:`.
PREFLIGHT_LINE="$(grep -n '^      - name: Managed-input preflight' "$PROV" | head -1 | cut -d: -f1)"
BANNER_LINE="$(grep -n '^  visibility-banner:' "$PROV" | cut -d: -f1)"
DEVFLOW_LINE="$(grep -n '^  device-flow:' "$PROV" | cut -d: -f1)"
[ -n "$PREFLIGHT_LINE" ] && ok "preflight step present" || bad "preflight step missing"
if [ -n "$PREFLIGHT_LINE" ] && [ -n "$BANNER_LINE" ] && [ -n "$DEVFLOW_LINE" ] \
   && [ "$PREFLIGHT_LINE" -gt "$BANNER_LINE" ] && [ "$PREFLIGHT_LINE" -lt "$DEVFLOW_LINE" ]; then
  ok "preflight sits in the ungated banner job, before device-flow"
else
  bad "preflight is not in the banner job before device-flow ($PREFLIGHT_LINE / $BANNER_LINE / $DEVFLOW_LINE)"
fi
# Step header (name .. run:) must carry no `if:` — a disabled preflight is a
# silent bypass.
awk -v n="$PREFLIGHT_LINE" 'NR>=n && /^      - name:/ && NR>n { exit } NR>=n { print }' "$PROV" > "$WORK/preflight-header.txt"
is "preflight step has no if: guard" "0" "$(grep -c '^        if:' "$WORK/preflight-header.txt")"
# device-flow must depend on the banner job so a preflight failure gates it.
contains "device-flow needs the banner job" "needs: [visibility-banner]" "$(cat "$PROV")"

# Environment binding check.
contains "binding check uses MANAGED_TENANT" 'MANAGED_TENANT: ${{ vars.MANAGED_TENANT }}' "$(cat "$PROV")"
contains "binding check compares marker to input" 'if [ -n "$TENANT_INPUT" ] && [ "$MANAGED_TENANT" != "$TENANT_INPUT" ]' "$(cat "$PROV")"

# ---- behavior helpers ------------------------------------------------------
extract_step() { # $1 = step name needle, $2 = out file
  awk -v needle="$1" '
    index($0, "- name: " needle) { inblock=1; next }
    inblock && $0 == "        run: |" { inrun=1; next }
    inrun && /^      - name: / { exit }
    inrun { line=$0; sub(/^          /, "", line); print line }
  ' "$PROV" > "$2"
}
PREFLIGHT_BODY="$WORK/preflight-body.sh"
BINDING_BODY="$WORK/binding-body.sh"
extract_step "Managed-input preflight" "$PREFLIGHT_BODY"
extract_step "Tenant-environment binding check" "$BINDING_BODY"
[ -s "$PREFLIGHT_BODY" ] || { printf 'FAIL could not extract the preflight body\n'; exit 1; }
[ -s "$BINDING_BODY" ] || { printf 'FAIL could not extract the binding-check body\n'; exit 1; }
grep -qF 'must carry anchor_ref' "$PREFLIGHT_BODY" || { printf 'FAIL extracted body is not the preflight\n'; exit 1; }
grep -qF 'MANAGED_TENANT' "$BINDING_BODY" || { printf 'FAIL extracted body is not the binding check\n'; exit 1; }

RUN_BODY() { # $1 tag, $2 body, remaining: VAR=value -> rc; stdout in $WORK/<tag>.out
  local tag="$1" body="$2"; shift 2
  local rc=0
  env -i PATH="$PATH" HOME="$WORK" "$@" \
    bash "$body" > "$WORK/$tag.out" 2> "$WORK/$tag.err" || rc=$?
  printf '%s' "$rc"
}
OUT() { cat "$WORK/$1.out"; }

LONG41="$(printf 'a%.0s' {1..41})"
LONG65="$(printf 'a%.0s' {1..65})"

# ---- preflight behavior ----------------------------------------------------
rc="$(RUN_BODY p0 "$PREFLIGHT_BODY" MODE=check)"
is "p0 empty inputs rc" "0" "$rc"
contains "p0 preflight ok" "Managed-input preflight ok." "$(OUT p0)"

rc="$(RUN_BODY p0b "$PREFLIGHT_BODY" MODE=apply)"
is "p0b ref-less apply rc" "0" "$rc"
contains "p0b ref-less apply warns" "::warning::no anchor_ref" "$(OUT p0b)"

rc="$(RUN_BODY p0c "$PREFLIGHT_BODY" MODE=check)"
case "$(OUT p0c)" in *"::warning::"*) bad "p0c check mode must not warn";; *) ok "p0c check mode emits no warning";; esac

rc="$(RUN_BODY p1 "$PREFLIGHT_BODY" TENANT_INPUT=foo MODE=apply)"
is "p1 tenant without anchor_ref rc" "1" "$rc"
contains "p1 names the lane requirement" "must carry anchor_ref" "$(OUT p1)"

rc="$(RUN_BODY p1b "$PREFLIGHT_BODY" ANCHOR_REF=ok MODE=check)"
is "p1b ref without tenant rc" "0" "$rc"

rc="$(RUN_BODY p2 "$PREFLIGHT_BODY" TENANT_INPUT=Foo ANCHOR_REF=ok MODE=check)"
is "p2 bad tenant charset rc" "1" "$rc"
contains "p2 names the tenant shape" "tenant input must match" "$(OUT p2)"

rc="$(RUN_BODY p2b "$PREFLIGHT_BODY" TENANT_INPUT=_foo ANCHOR_REF=ok MODE=check)"
is "p2b leading underscore rc" "1" "$rc"
rc="$(RUN_BODY p2c "$PREFLIGHT_BODY" TENANT_INPUT=_ ANCHOR_REF=ok MODE=check)"
is "p2c lone underscore rc" "1" "$rc"

rc="$(RUN_BODY p3 "$PREFLIGHT_BODY" TENANT_INPUT=-foo ANCHOR_REF=ok MODE=check)"
is "p3 leading hyphen rc" "1" "$rc"
rc="$(RUN_BODY p3b "$PREFLIGHT_BODY" TENANT_INPUT=foo- ANCHOR_REF=ok MODE=check)"
is "p3b trailing hyphen rc" "1" "$rc"

rc="$(RUN_BODY p4 "$PREFLIGHT_BODY" "TENANT_INPUT=$LONG41" ANCHOR_REF=ok MODE=check)"
is "p4 long tenant rc" "1" "$rc"
contains "p4 names the tenant length" "tenant input exceeds 40 characters" "$(OUT p4)"

rc="$(RUN_BODY p5 "$PREFLIGHT_BODY" TENANT_INPUT=foo "ANCHOR_REF=bad ref" MODE=check)"
is "p5 bad anchor_ref charset rc" "1" "$rc"
contains "p5 names the anchor_ref shape" "anchor_ref input must match" "$(OUT p5)"

rc="$(RUN_BODY p5b "$PREFLIGHT_BODY" TENANT_INPUT=foo ANCHOR_REF=ABC MODE=check)"
is "p5b uppercase anchor_ref rc" "1" "$rc"

rc="$(RUN_BODY p6 "$PREFLIGHT_BODY" "ANCHOR_REF=$LONG65" MODE=check)"
is "p6 long anchor_ref rc" "1" "$rc"
contains "p6 names the anchor_ref length" "anchor_ref input exceeds 64 characters" "$(OUT p6)"

rc="$(RUN_BODY p7 "$PREFLIGHT_BODY" TENANT_INPUT=foo ANCHOR_REF=ok-ref.1 MODE=apply)"
is "p7 valid managed dispatch rc" "0" "$rc"
contains "p7 preflight ok" "Managed-input preflight ok." "$(OUT p7)"

# ---- binding-check behavior -------------------------------------------------
rc="$(RUN_BODY b0 "$BINDING_BODY")"
is "b0 no tenant rc" "0" "$rc"

rc="$(RUN_BODY b1 "$BINDING_BODY" TENANT_INPUT=foo)"
is "b1 tenant without marker rc" "1" "$rc"
contains "b1 names the marker" "does not carry MANAGED_TENANT" "$(OUT b1)"

rc="$(RUN_BODY b2 "$BINDING_BODY" TENANT_INPUT=foo MANAGED_TENANT=foo)"
is "b2 matching marker rc" "0" "$rc"

rc="$(RUN_BODY b3 "$BINDING_BODY" TENANT_INPUT=foo MANAGED_TENANT=bar)"
is "b3 mismatching marker rc" "1" "$rc"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
