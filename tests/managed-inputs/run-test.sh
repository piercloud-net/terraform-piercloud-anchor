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
#     step lives in the UNGATED job that owns it, is that job's FIRST step,
#     has no `if:`, and the device-flow job `needs:` that same job
#     (dependency-checked, not line proximity); the environment binding check
#     uses the MANAGED_TENANT marker.
#   - BEHAVIORAL: the REAL preflight and binding step bodies (extracted,
#     never copies) run under `env -i`; refusals must fail closed and valid
#     shapes must pass (incl. the b3b managed-apply refusal and the
#     ref-less update-ip/destroy warning — those modes do not touch DNS).
#   - WIRING COMPLETENESS: every committed `tests/*/run-test.sh` is named in
#     the ci.yml run list and its directory is in the unit-tests path gate;
#     a dropped line would silently skip that harness (no harness can catch
#     its own absence — broker-provision-dns carries the same cross-check).
#
# Cred-free, offline: no network, no credentials.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
PROV="$ROOT/.github/workflows/provision.yml"
CI="$ROOT/.github/workflows/ci.yml"
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

# Block-scalar-stripped structural view (NR + text): every extraction below
# reads THIS, so a decoy `|`/`>` scalar quoting the job (a `run-name: |2`
# copy, anchors/tags/quoted keys included) can never satisfy a pin meant for
# the real job; the raw exactly-one job-key count backstops a form the
# stripper does not recognise.
PROV_STRUCT="$(awk '
function indent(s,   m) { match(s, /^ */); return RLENGTH }
function qprefix(s,   i, c, q) {
  q = 0
  for (i = 1; i <= length(s); i++) {
    c = substr(s, i, 1)
    if (c == "\"") { q = 1 - q }
    else if (c == "#" && q == 0) { return substr(s, 1, i - 1) }
  }
  return s
}
{
  if (skip) {
    if ($0 ~ /^[[:space:]]*$/) next
    i = indent($0)
    if (sind < 0) {
      if (i <= ihdr) { skip = 0 } else { sind = i; next }
    } else if (i >= sind) { next } else { skip = 0 }
  }
  printf "%d\t%s\n", NR, $0
  if (($0 ~ /^[[:space:]]*[^#[:space:]].*:[[:space:]]*((&[^[:space:]#]+|![^[:space:]#]+)[[:space:]]+)*[|>]([0-9][-+]?|[-+][0-9]?)?[[:space:]]*(#.*)?$/ || $0 ~ /^[[:space:]]*\?[[:space:]]*((&[^[:space:]#]+|![^[:space:]#]+)[[:space:]]+)*[|>]([0-9][-+]?|[-+][0-9]?)?[[:space:]]*(#.*)?$/) && qprefix($0) ~ /[|>]([0-9][-+]?|[-+][0-9]?)?[[:space:]]*$/) {
    ihdr = indent($0)
    if (match($0, /[|>][-+]?[0-9]/)) { sind = ihdr + substr($0, RSTART + RLENGTH - 1, 1) + 0 }
    else { sind = -1 }
    skip = 1
  }
}'  "$PROV")"
[ -n "$PROV_STRUCT" ] || { printf 'FAIL structural view of %s is empty\n' "$PROV"; exit 1; }

# ---- static wiring over provision.yml ------------------------------------
# The lane must be a STABLE function of anchor_ref alone: pin the exact
# group value (a run-id suffix or any other variable would split the lane).
LANE="$(awk '/^concurrency:/{f=1; next} f && /^[^ ]/{exit} f{print}' "$PROV" | sed -n 's/^  group: //p')"
is "lane group is the pinned anchor_ref expression" \
  "\${{ inputs.anchor_ref != '' && format('anchor-{0}', inputs.anchor_ref) || 'piercloud-netcup-policy' }}" \
  "$LANE"
case "$LANE" in *github.*|*needs.*|*strategy.*|*matrix.*) bad "lane references a non-input context";; *) ok "lane references no non-input context";; esac

# Per-job environment extraction: every job's own `environment:` line.
ENV_LINES="$(printf '%s\n' "$PROV_STRUCT" | awk -F'\t' '
  $2 ~ /^  [A-Za-z0-9_.-]+:[[:space:]]*(#.*)?$/ { job=$2; sub(/:[[:space:]]*(#.*)?$/, "", job); sub(/^  /, "", job) }
  $2 ~ /^    environment:/ { line=$2; sub(/^    environment: /, "", line); gsub(/^['"'"'"]|['"'"'"]$/, "", line); print job "|" line }
')"
is "exactly two jobs carry an environment" "2" "$(printf '%s\n' "$ENV_LINES" | grep -c '|')"
is "device-flow binds the dynamic environment" "device-flow|$DYN_ENV" "$(printf '%s\n' "$ENV_LINES" | grep '^device-flow|')"
is "anchor-dns binds the dynamic environment" "anchor-dns|$DYN_ENV" "$(printf '%s\n' "$ENV_LINES" | grep '^anchor-dns|')"

# Inputs declared.
is "tenant input declared" "1" "$(grep -c '^      tenant:$' "$PROV")"
is "anchor_ref input declared" "1" "$(grep -c '^      anchor_ref:$' "$PROV")"

# Preflight placement: the preflight must be the FIRST step of the ungated job
# that owns it, and device-flow must `needs:` that job — a new ungated job
# owning the preflight between banner and device-flow must not stay green.
PREFLIGHT_LINE="$(awk -F'\t' '$2 ~ /^      - name: Managed-input preflight/ {print $1; exit}' <<<"$PROV_STRUCT")"
DEVFLOW_LINE="$(awk -F'\t' '$2 ~ /^  device-flow:[[:space:]]*(#.*)?$/ {print $1; exit}' <<<"$PROV_STRUCT")"
[ -n "$PREFLIGHT_LINE" ] && ok "preflight step present" || bad "preflight step missing"
# The owning job = nearest 2-space job header at/before the preflight line.
OWNER_JOB="$(printf '%s\n' "$PROV_STRUCT" | awk -F'\t' -v n="$PREFLIGHT_LINE" '$1<=n && $2 ~ /^  [A-Za-z0-9_.-]+:[[:space:]]*(#.*)?$/ { job=$2; sub(/:[[:space:]]*(#.*)?$/, "", job); sub(/^  /, "", job) } END { print job }')"
OWNER_HEADER_LINE=""
[ -n "$OWNER_JOB" ] && OWNER_JOB_RE="${OWNER_JOB//./[.]}" && OWNER_HEADER_LINE="$(awk -F'\t' -v j="$OWNER_JOB_RE" '$2 ~ ("^  " j ":[[:space:]]*(#.*)?$") {print $1; exit}' <<<"$PROV_STRUCT")"
FIRST_STEP_LINE=""
[ -n "$OWNER_HEADER_LINE" ] && FIRST_STEP_LINE="$(awk -F'\t' -v n="$OWNER_HEADER_LINE" '$1>n && $2 ~ /^      - name: / {print $1; exit}' <<<"$PROV_STRUCT")"
is "preflight is the first step of its own job" "$PREFLIGHT_LINE" "$FIRST_STEP_LINE"
# …and it must still precede the device-flow job in the file (the banner job
# is scheduled before device-flow).
if [ -n "$PREFLIGHT_LINE" ] && [ -n "$DEVFLOW_LINE" ] && [ "$PREFLIGHT_LINE" -lt "$DEVFLOW_LINE" ]; then
  ok "preflight precedes the device-flow job"
else
  bad "preflight does not precede device-flow ($PREFLIGHT_LINE / $DEVFLOW_LINE)"
fi
# device-flow must `needs:` the owning job (dependency, not line proximity).
DEVFLOW_NEEDS="$(awk -F'\t' '
  $2 ~ /^  device-flow:[[:space:]]*(#.*)?$/ {f=1; next}
  f && $2 ~ /^  [A-Za-z0-9_.-]+:$/ {exit}
  f && $2 ~ /^    needs:/ {line=$2; sub(/^    needs: */, "", line); print line; exit}
' <<<"$PROV_STRUCT")"
case "$DEVFLOW_NEEDS" in *"$OWNER_JOB"*) ok "device-flow needs the preflight's job ($OWNER_JOB)";; *) bad "device-flow does not need $OWNER_JOB (needs: $DEVFLOW_NEEDS)";; esac
# Step header (name .. run:) must carry no `if:` — a disabled preflight is a
# silent bypass (quoted keys and space-before-colon included).
awk -v n="$PREFLIGHT_LINE" 'NR>=n && /^      - name:/ && NR>n { exit } NR>=n { print }' "$PROV" > "$WORK/preflight-header.txt"
is "preflight step has no if: guard" "0" "$(grep -cE "^        [\"']?if[\"']?[[:space:]]*:" "$WORK/preflight-header.txt")"
# The owning job must be ungated (no `environment:` for it in the per-job extraction).
OWNER_ENV="$(printf '%s\n' "$ENV_LINES" | grep "^${OWNER_JOB}|" || true)"
is "preflight's job is ungated" "" "$OWNER_ENV"

# Environment binding check.
contains "binding check uses MANAGED_TENANT" 'MANAGED_TENANT: ${{ vars.MANAGED_TENANT }}' "$(cat "$PROV")"
contains "binding check compares marker to input" 'if [ -n "$TENANT_INPUT" ] && [ "$MANAGED_TENANT" != "$TENANT_INPUT" ]' "$(cat "$PROV")"

# ---- behavior helpers ------------------------------------------------------
extract_step() { # $1 = step name needle, $2 = out file
  local start end
  start="$(awk -F'\t' -v needle="$1" 'index($2, "- name: " needle) {print $1; exit}' <<<"$PROV_STRUCT")"
  [ -n "$start" ] || return 1
  end="$(awk -F'\t' -v s="$start" '$1 > s && $2 ~ /^      - name: / {print $1; exit}' <<<"$PROV_STRUCT")"
  [ -n "$end" ] || end=$(( $(wc -l < "$PROV") + 1 ))
  awk -v s="$start" -v e="$end" 'NR>s && NR<e' "$PROV" | awk '
    /^        run: \|$/ { inrun=1; next }
    inrun && /^      - name: / { exit }
    inrun { line=$0; sub(/^          /, "", line); print line }
  ' > "$2"
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
is "p0b ref-less apply rc" "1" "$rc"
contains "p0b ref-less apply names the managed requirement" "apply now requires a managed dispatch" "$(OUT p0b)"
contains "p0b ref-less apply names the broker" "anchor DNS writes through the pc-control broker (b3b, #189)" "$(OUT p0b)"
contains "p0b ref-less apply names the early refusal" "Refusing before any provisioning" "$(OUT p0b)"

rc="$(RUN_BODY p0d "$PREFLIGHT_BODY" MODE=update-ip)"
is "p0d ref-less update-ip rc" "0" "$rc"
contains "p0d ref-less update-ip warns" "::warning::no anchor_ref" "$(OUT p0d)"

rc="$(RUN_BODY p0c "$PREFLIGHT_BODY" MODE=check)"
case "$(OUT p0c)" in *"::warning::"*) bad "p0c check mode must not warn";; *) ok "p0c check mode emits no warning";; esac

rc="$(RUN_BODY p1 "$PREFLIGHT_BODY" TENANT_INPUT=foo MODE=apply)"
is "p1 tenant without anchor_ref rc" "1" "$rc"
contains "p1 names the lane requirement" "must carry anchor_ref" "$(OUT p1)"

rc="$(RUN_BODY p1b "$PREFLIGHT_BODY" ANCHOR_REF=ok MODE=check)"
is "p1b ref without tenant rc" "0" "$rc"

rc="$(RUN_BODY p1c "$PREFLIGHT_BODY" ANCHOR_REF=ok MODE=apply)"
is "p1c tenant-less apply rc" "1" "$rc"
contains "p1c names the managed-apply requirement" "apply now requires a managed dispatch" "$(OUT p1c)"

rc="$(RUN_BODY p1d "$PREFLIGHT_BODY" TENANT_INPUT=foo MODE=update-ip)"
is "p1d ref-less managed update-ip rc" "1" "$rc"
contains "p1d names the lane requirement" "must carry anchor_ref" "$(OUT p1d)"

rc="$(RUN_BODY p2 "$PREFLIGHT_BODY" TENANT_INPUT=Foo ANCHOR_REF=ok MODE=check)"
is "p2 bad tenant charset rc" "1" "$rc"
contains "p2 names the tenant shape" "tenant input must match" "$(OUT p2)"

rc="$(RUN_BODY p2b "$PREFLIGHT_BODY" TENANT_INPUT=_foo ANCHOR_REF=ok MODE=check)"
is "p2b leading underscore rc" "1" "$rc"
rc="$(RUN_BODY p2c "$PREFLIGHT_BODY" TENANT_INPUT=_ ANCHOR_REF=ok MODE=check)"
is "p2c lone underscore rc" "1" "$rc"
# #198: the tenant input is the managed alias, so the preflight enforces the
# pc-control environment/alias grammar ^[a-z0-9]{3,15}$ plus the anchor's
# reserved prefixes (underscores and hyphens are refused now).
rc="$(RUN_BODY p2d "$PREFLIGHT_BODY" TENANT_INPUT=foo_ ANCHOR_REF=ok MODE=check)"
is "p2d trailing underscore refused rc" "1" "$rc"

rc="$(RUN_BODY p3 "$PREFLIGHT_BODY" TENANT_INPUT=-foo ANCHOR_REF=ok MODE=check)"
is "p3 leading hyphen rc" "1" "$rc"
rc="$(RUN_BODY p3b "$PREFLIGHT_BODY" TENANT_INPUT=foo- ANCHOR_REF=ok MODE=check)"
is "p3b trailing hyphen rc" "1" "$rc"

rc="$(RUN_BODY p4 "$PREFLIGHT_BODY" "TENANT_INPUT=$LONG41" ANCHOR_REF=ok MODE=check)"
is "p4 long tenant rc" "1" "$rc"
contains "p4 names the tenant length" "tenant input must be 3-15 characters" "$(OUT p4)"

# p8 (#198 differential): the preflight must never admit a name the canonical
# validator (scripts/lib/naming.sh validate_tenant_username) refuses, or the
# refusal would land after the device card. Accepted names must also fit the
# pc-control environment grammar ^[a-z0-9]{3,15}$.
LONG16="$(printf 'a%.0s' {1..16})"
LONG21="$(printf 'a%.0s' {1..21})"
. "$ROOT/scripts/lib/naming.sh"
for name in envproof foo abc 123 abc123def456ghi pier-2 my_tenant ab a \
    "$LONG16" "$LONG21" status1 statusx anchor1 pcuabc12345 pcu platform1 \
    Pier pier. "pier x" envtagproof mail www edge broker mailbox; do
  rc="$(RUN_BODY p8 "$PREFLIGHT_BODY" "TENANT_INPUT=$name" ANCHOR_REF=ok MODE=check)"
  if [ "$rc" = 0 ]; then
    if validate_tenant_username "$name" 2>/dev/null && [[ "$name" =~ ^[a-z0-9]{3,15}$ ]]; then
      ok "p8 preflight-accepted '$name' passes the canonical validator and the env grammar"
    else
      bad "p8 preflight accepts '$name' but the canonical validator / env grammar refuses it"
    fi
  else
    ok "p8 preflight refuses '$name' before any gate"
  fi
done
for name in pier-2 my_tenant ab "$LONG16" status1 anchor1 pcuabc12345 platform1 edge console ops keys unlock bounce mail broker www; do
  rc="$(RUN_BODY p8r "$PREFLIGHT_BODY" "TENANT_INPUT=$name" ANCHOR_REF=ok MODE=check)"
  is "p8 '$name' refused by the preflight rc" "1" "$rc"
done

# b4 (#198): the binding step runs the canonical validator before the device
# card (defense in depth behind the preflight).
rc="$( cd "$ROOT" && RUN_BODY b4 "$BINDING_BODY" TENANT_INPUT=pier-2 MANAGED_TENANT=pier-2 CUSTOMER_NUMBER=123456)"
is "b4 binding step refuses an invalid tenant name rc" "1" "$rc"
contains "b4 names the refusal before the device card" "not a valid tenant name" "$(OUT b4)"

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

# #198: a managed run also needs its tenant-only customer number (the job
# env resolves TENANT_CUSTOMER_NUMBER into CUSTOMER_NUMBER on a managed run).
rc="$(RUN_BODY b2 "$BINDING_BODY" TENANT_INPUT=foo MANAGED_TENANT=foo CUSTOMER_NUMBER=123456)"
is "b2 matching marker rc" "0" "$rc"

rc="$(RUN_BODY b2n "$BINDING_BODY" TENANT_INPUT=foo MANAGED_TENANT=foo)"
is "b2n matching marker, no tenant customer number rc" "1" "$rc"
contains "b2n names the tenant-only secret" "TENANT_CUSTOMER_NUMBER" "$(OUT b2n)"

rc="$(RUN_BODY b3 "$BINDING_BODY" TENANT_INPUT=foo MANAGED_TENANT=bar)"
is "b3 mismatching marker rc" "1" "$rc"

# ---- wiring completeness: no harness can be silently un-wired ------------
# The unit-tests gate line (anchored on its own prefix) must name every
# committed harness directory, and the run list must name every harness
# script. Removing a single token or line then fails HERE — broker-provision-dns
# and edge-origin-auth carry the same cross-check, so dropping one checker's
# own line still leaves two failing. (Removing all three checkers is a
# three-line, review-visible edit and remains the disclosed drift-guard
# residual.) The gate and run-list assertions are scoped to the
# unit-tests-scripts job block of a block-scalar-stripped structural view: a
# mention in another job's run line, a decoy `echo skipped # bash ...`, a
# commented-out line or a decoy scalar cannot satisfy them.
CI_STRUCT="$(awk '
function indent(s,   m) { match(s, /^ */); return RLENGTH }
function qprefix(s,   i, c, q) {
  q = 0
  for (i = 1; i <= length(s); i++) {
    c = substr(s, i, 1)
    if (c == "\"") { q = 1 - q }
    else if (c == "#" && q == 0) { return substr(s, 1, i - 1) }
  }
  return s
}
{
  if (skip) {
    if ($0 ~ /^[[:space:]]*$/) next
    i = indent($0)
    if (sind < 0) {
      if (i <= ihdr) { skip = 0 } else { sind = i; next }
    } else if (i >= sind) { next } else { skip = 0 }
  }
  printf "%d\t%s\n", NR, $0
  if (($0 ~ /^[[:space:]]*[^#[:space:]].*:[[:space:]]*((&[^[:space:]#]+|![^[:space:]#]+)[[:space:]]+)*[|>]([0-9][-+]?|[-+][0-9]?)?[[:space:]]*(#.*)?$/ || $0 ~ /^[[:space:]]*\?[[:space:]]*((&[^[:space:]#]+|![^[:space:]#]+)[[:space:]]+)*[|>]([0-9][-+]?|[-+][0-9]?)?[[:space:]]*(#.*)?$/) && qprefix($0) ~ /[|>]([0-9][-+]?|[-+][0-9]?)?[[:space:]]*$/) {
    ihdr = indent($0)
    if (match($0, /[|>][-+]?[0-9]/)) { sind = ihdr + substr($0, RSTART + RLENGTH - 1, 1) + 0 }
    else { sind = -1 }
    skip = 1
  }
}'  "$CI")"
ci_unit_START="$(awk -F'\t' '$2 ~ /^  unit-tests-scripts:[[:space:]]*(#.*)?$/ {print $1; exit}' <<<"$CI_STRUCT")"
ci_unit_END="$(awk -F'\t' -v s="$ci_unit_START" '$1 > s && $2 ~ /^  [^ #].*:[[:space:]]*(#.*)?$/ {print $1; exit}' <<<"$CI_STRUCT")"
ci_unit=""
[ -n "$ci_unit_START" ] && [ -n "$ci_unit_END" ] && ci_unit="$(sed -n "$((ci_unit_START + 1)),$((ci_unit_END - 1))p" "$CI" | grep -v '^[[:space:]]*#' || true)"
[ -n "$ci_unit" ] || bad "ci.yml unit-tests-scripts job not found"
is "exactly one unit-tests-scripts job key line in ci.yml" "1" "$(grep -cE "^  (\\?[[:space:]]*)?((&[^[:space:]]+|![^[:space:]]+)[[:space:]]+)*(\"unit-tests-scripts\"|'unit-tests-scripts'|unit-tests-scripts)[[:space:]]*:?[[:space:]]*(#.*)?$" "$CI")"
# Spelling-agnostic census for ci.yml (same doctrine as provision.yml):
# every indent-2 non-space/non-comment line of the stripped view is a
# structural line of the top level (on/env/permissions children plus the job
# keys). A
# duplicate or decoy job key in ANY spelling adds one.
is "ci.yml structural indent-2 line count (pin: update for a new top-level line)" "15" "$(printf '%s\n' "$CI_STRUCT" | cut -f2- | grep -cE '^  [^[:space:]#]')"
gate_line="$(grep -m1 -F "elif grep -qE '^(\.github/scripts/" <<<"$ci_unit" || true)"
[ -n "$gate_line" ] || bad "ci.yml unit-tests gate line not found"
is "exactly one gate elif in the unit-tests job" "1" "$(printf '%s\n' "$ci_unit" | grep -cE 'elif grep -qE')"
# Extract the regex from the gate LINE itself, exactly one match: a decoy
# `grep -qE` elsewhere in the job cannot satisfy the functional check.
gate_raw="$(printf '%s\n' "$gate_line" | grep -oE "grep -qE '[^']*'" || true)"
is "exactly one gate regex on the gate line" "1" "$(printf '%s\n' "$gate_raw" | grep -c . || true)"
gate_pattern="$(head -n1 <<<"$gate_raw" | sed -e "s/^grep -qE '//" -e "s/'$//")"
[ -n "$gate_pattern" ] || bad "could not extract the unit-tests gate regex"
gate_ln="$(printf '%s\n' "$ci_unit" | grep -nE 'elif grep -qE' | head -n1 | cut -d: -f1 || true)"
if [ -n "$gate_ln" ]; then
  gate_next="$(printf '%s\n' "$ci_unit" | sed -n "$((gate_ln + 1)),\$p" | awk '/^[[:space:]]*(elif|else|fi)([[:space:]]|$)/ {exit} {print}' | grep -vE '^[[:space:]]*(#|$)' | head -n1 || true)"
  is "gate branch sets run=yes" '              echo "run=yes" >> "$GITHUB_OUTPUT"' "$gate_next"
else
  bad "gate elif line not found in the unit-tests job"
fi
shopt -s nullglob
harnesses=(tests/*/run-test.sh)
[ ${#harnesses[@]} -gt 0 ] || bad "no tests/*/run-test.sh harnesses found"
for t in "${harnesses[@]}"; do
  dir="$(basename "$(dirname "$t")")"
  contains "unit-tests gate covers tests/$dir" "$dir" "$gate_line"
  if [ -n "$gate_pattern" ] && grep -qE "$gate_pattern" <<<"$t"; then
    ok "unit-tests gate regex matches $t"
  else
    bad "unit-tests gate regex does not match $t"
  fi
  if grep -qE "^[[:space:]]+bash ${t//./\\.}[[:space:]]*$" <<<"$ci_unit"; then
    ok "ci.yml run list includes $t"
  else
    bad "ci.yml run list includes $t"
  fi
done

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
