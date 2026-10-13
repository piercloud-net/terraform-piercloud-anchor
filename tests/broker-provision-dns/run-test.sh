#!/usr/bin/env bash
# tests/broker-provision-dns/run-test.sh — b3b (#189): the provision DNS
# stage writes through the pc-control broker, and the direct provider-token
# writer is retired.
#
# Static, offline harness (no network, no credentials): pins the shape of the
# provision.yml `anchor-dns` job (broker lib call over OIDC, managed-lane
# guard, tenant environment, resolved IPv4, fail-before-thumbprint ordering),
# proves the retired provider surface (script, harness, variable and secret
# names) is gone from every production surface, and cross-checks that the
# committed CI wiring still names every harness (a dropped run-list line
# cannot silently skip one). All extractions are block-scalar-aware: a decoy
# `|`/`>` scalar (anchors/tags/quoted keys included) that quotes the job or
# the CI run step cannot stand in for the real one, and the raw
# exactly-one-job-key counts catch a form the stripper does not recognise.
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
  if grep -qwE -- "$2" <<<"$3"; then bad "$1 (found '$2')"; else ok "$1"; fi
}

[ -f "$PROV" ] || { printf 'FAIL provision.yml not found: %s\n' "$PROV"; exit 1; }
[ -f "$CI" ] || { printf 'FAIL ci.yml not found: %s\n' "$CI"; exit 1; }
[ -f "$LIB" ] || { printf 'FAIL broker-dns lib not found: %s\n' "$LIB"; exit 1; }
[ -f "$REPORT_LIB" ] || { printf 'FAIL broker-report lib not found: %s\n' "$REPORT_LIB"; exit 1; }

# A line-based extraction cannot tell a real job from a block scalar that
# quotes one (`run-name: |2` + a byte-copy of the job satisfies every text
# pin while the real job is gutted). Build a block-scalar-stripped structural
# view (NR + text) and locate the job THERE, then extract its lines from the
# original file: content lines of `key: |`/`>` scalars (any indicator form)
# are dropped, the header line stays. Anchors/tags (`&a |`, `!tag |`) and
# quoted keys are recognised; an explicit indentation indicator is header
# indent + N; a scalar whose first content line is not deeper than the header
# is empty and does not swallow the next line. A form the stripper does not
# recognise leaves its content in the structural view, where the raw
# exactly-one job-key count catches the duplicate.
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
prov_raw_live="$(grep -v '^[[:space:]]*#' "$PROV")"
JOB_START="$(awk -F'\t' '$2 ~ /^  anchor-dns:[[:space:]]*(#.*)?$/ {print $1; exit}' <<<"$PROV_STRUCT")"
[ -n "$JOB_START" ] || { printf 'FAIL anchor-dns job key not found in %s\n' "$PROV"; exit 1; }
JOB_END="$(awk -F'\t' -v s="$JOB_START" '$1 > s && $2 ~ /^  [^ #].*:[[:space:]]*(#.*)?$/ {print $1; exit}' <<<"$PROV_STRUCT")"
[ -n "$JOB_END" ] || { printf 'FAIL anchor-dns job end not found in %s\n' "$PROV"; exit 1; }
JOB_RAW="$(sed -n "$((JOB_START + 1)),$((JOB_END - 1))p" "$PROV")"
JOB="$(printf '%s\n' "$JOB_RAW" | grep -v '^[[:space:]]*#' || true)"
[ -n "$JOB" ] || { printf 'FAIL anchor-dns job body not found in %s\n' "$PROV"; exit 1; }
# Exactly one job key at top level: a decoy scalar the stripper does not
# recognise would add a second (and the structural view would pick it first).
is "exactly one anchor-dns job key line in provision.yml" "1" "$(grep -cE "^  (\\?[[:space:]]*)?(\"anchor-dns\"|'anchor-dns'|anchor-dns)[[:space:]]*:?[[:space:]]*(#.*)?$" "$PROV")"
# Spelling-agnostic structural census: every raw line that starts at indent 2
# with a non-space, non-comment character is a structural line of the
# workflow top level (on/concurrency/permissions children plus the eight job
# keys). A duplicate or decoy job key in ANY spelling (tags, quotes, hex
# escapes, explicit keys) adds one, so it fails until the pin is deliberately
# updated.
is "provision.yml structural indent-2 line count (pin: update for a new top-level line)" "12" "$(printf '%s\n' "$PROV_STRUCT" | cut -f2- | grep -cE '^  [^[:space:]#]')"

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
# `|| true` keeps the diagnostics: under `set -e` + pipefail a missing line
# would abort the harness before the intended `bad` message prints.
src_line="$(printf '%s\n' "$JOB_LINES" | grep -nE '^          \. \.github/scripts/lib/broker-dns\.sh$' | cut -d: -f1 || true)"
call_line="$(printf '%s\n' "$JOB_LINES" | grep -nE '^          write_anchor_dns "\$ANCHOR_REF" "\$ANCHOR_IPV4"$' | cut -d: -f1 || true)"
guard_line="$(printf '%s\n' "$JOB_LINES" | grep -nE '^          if \[ -z "\$ANCHOR_REF" \]; then$' | cut -d: -f1 || true)"
guard_exit="$(printf '%s\n' "$JOB_LINES" | grep -cE '^            exit 1$' || true)"
[ -n "$src_line" ] && ok "job sources the broker-dns lib (exact line)" || bad "broker-dns source line not found at the expected indentation"
[ -n "$call_line" ] && ok "job calls write_anchor_dns with ref + ipv4 (exact line)" || bad "write_anchor_dns call line not found at the expected indentation"
[ -n "$guard_line" ] && ok "guard is a live if (exact line)" || bad "guard if line not found at the expected indentation"
is "guard exits non-zero" "1" "$guard_exit"
if [ -n "$guard_line" ] && [ -n "$call_line" ] && [ "$guard_line" -lt "$call_line" ]; then ok "guard runs before the write"; else bad "guard line ($guard_line) must precede the write line ($call_line)"; fi
if [ -n "$src_line" ] && [ -n "$call_line" ] && [ "$src_line" -lt "$call_line" ]; then ok "lib sourced before the write"; else bad "source line ($src_line) must precede the write line ($call_line)"; fi
# A dead step or a shadowed function defeats the line pins above: no
# step-level `if:`/`continue-on-error` may appear (the job's own apply gate
# is the only `if:` at 4-space indent), and the call/source may appear once.
is "no step-level if in the job" "0" "$(printf '%s\n' "$JOB_LINES" | grep -cE "^(      - |        )(&[^[:space:]]+[[:space:]]+|![^[:space:]]+[[:space:]]+)*[\"']?if[\"']?[[:space:]]*:")"
is "no continue-on-error in the job" "0" "$(printf '%s\n' "$JOB_LINES" | grep -cE "^(      - |        )(&[^[:space:]]+[[:space:]]+|![^[:space:]]+[[:space:]]+)*[\"']?continue-on-error[\"']?[[:space:]]*:")"
is "job-level if is exactly the apply gate" "1" "$(printf '%s\n' "$JOB_LINES" | grep -cE '^    if: inputs\.mode == .apply.$')"
is "exactly one write_anchor_dns source line" "1" "$(printf '%s\n' "$JOB_LINES" | grep -cE '^          \. \.github/scripts/lib/broker-dns\.sh$')"
# The step set is pinned: an extra unpinned step (e.g. a direct provider
# fallback with a split URL) changes the count/order and must update the pin.
is "exactly three steps in the anchor-dns job" "3" "$(printf '%s\n' "$JOB_LINES" | grep -cE '^      - name: ')"
# A step item need not carry a name (`- uses:` / `- run:`): count the
# sequence items too, so a nameless extra step is caught.
is "exactly three step items in the anchor-dns job" "3" "$(printf '%s\n' "$JOB_LINES" | grep -cE '^      -($|[[:space:]])')"
expected_step_names='Checkout (no credentials persisted)
Managed-lane guard (b3b #189 retired the direct-token writer)
Upsert anchor A + dashboard CNAME through the broker'
actual_step_names="$(printf '%s\n' "$JOB_LINES" | grep -E '^      - name: ' | sed -e 's/^      - name: //')"
is "anchor-dns step names in order" "$expected_step_names" "$actual_step_names"
is "exactly one write_anchor_dns call line" "1" "$(printf '%s\n' "$JOB_LINES" | grep -cE '^          write_anchor_dns "\$ANCHOR_REF" "\$ANCHOR_IPV4"$')"
is "no shadowing write_anchor_dns definition in the job" "0" "$(printf '%s\n' "$JOB_LINES" | grep -cE '^[[:space:]]*(function[[:space:]]+)?write_anchor_dns[[:space:]]*(\(\))?[[:space:]]*(\{|$)')"
# Job-level switches change how every step runs without touching the pinned
# step text: `continue-on-error` swallows a guard/write failure, `defaults`
# can replace the shell with a no-op. Both are banned, as are the bash
# startup-file variables that can neuter the job's `set -euo pipefail`.
is "no job-level continue-on-error" "0" "$(printf '%s\n' "$JOB_LINES" | grep -cE "^    (&[^[:space:]]+[[:space:]]+|![^[:space:]]+[[:space:]]+)*[\"']?continue-on-error[\"']?[[:space:]]*:")"
is "no job-level defaults" "0" "$(printf '%s\n' "$JOB_LINES" | grep -cE "^    (&[^[:space:]]+[[:space:]]+|![^[:space:]]+[[:space:]]+)*[\"']?defaults[\"']?[[:space:]]*:")"
is "exactly one job-level if in the anchor-dns job" "1" "$(printf '%s\n' "$JOB_LINES" | grep -cE "^    (&[^[:space:]]+[[:space:]]+|![^[:space:]]+[[:space:]]+)*[\"']?if[\"']?[[:space:]]*:")"
is "exactly one strict apply-gate if" "1" "$(printf '%s\n' "$JOB_LINES" | grep -cE '^    if: inputs\.mode == .apply.$')" 
for k in if strategy defaults continue-on-error; do
  is "no job-level explicit-key $k in the anchor-dns job" "0" "$(printf '%s\n' "$JOB_LINES" | grep -cE "^    \\?[[:space:]]*((&[^[:space:]]+|![^[:space:]]+)[[:space:]]+)*[\"']?${k}[\"']?[[:space:]]*(#.*)?$")"
  is "no step-level explicit-key $k in the anchor-dns job" "0" "$(printf '%s\n' "$JOB_LINES" | grep -cE "^        \\?[[:space:]]*((&[^[:space:]]+|![^[:space:]]+)[[:space:]]+)*[\"']?${k}[\"']?[[:space:]]*(#.*)?$")"
done
is "no workflow-level defaults" "0" "$(grep -cE "^(&[^[:space:]]+[[:space:]]+|![^[:space:]]+[[:space:]]+)*[\"']?defaults[\"']?[[:space:]]*:" "$PROV")"
for v in BASH_ENV ENV SHELLOPTS BASHOPTS; do
  lacks_word "job does not set $v" "$v" "$JOB"
done

# Byte-exact pin of the write step: the line pins above cannot see a
# same-indent `exit 0`/`if false` wrap, a `function` keyword shadow or an
# injected step-level `env:`, because YAML strips the body indent and bash
# does not care about the residual indentation. The whole step (comments
# included) is hashed, so any content edit must update the pin (a trailing
# blank line is stripped by $( ) and cannot change the executed script).
# Extraction is job-scoped: the step must live inside the anchor-dns job,
# so a decoy step in a workflow-level block scalar / another job cannot
# satisfy the pin, and the same `_`/uppercase job boundary applies.
STEP_BLOB="$(awk '
  /^      - name: Upsert anchor A \+ dashboard CNAME through the broker$/ {f=1}
  f && /^      - name: / && $0 !~ /Upsert anchor A \+ dashboard CNAME through the broker$/ {exit}
  f && /^  [A-Za-z_][A-Za-z0-9_-]*:$/ {exit}
  f {print}
' <<<"$JOB_RAW")"
is "write step blob hash" "5293b16c734b119a757a0653e8824f44b224910d9909bc5f18f4b8bef9c5f806" "$(printf '%s\n' "$STEP_BLOB" | sha256sum | cut -d' ' -f1)"
# The guard step is byte-pinned too: its body decides whether a ref-less
# apply can reach the write (a prefix such as
# `ANCHOR_REF="${ANCHOR_REF:-anchor-01}"` inside the run block would neuter
# it without touching any pinned line).
GUARD_BLOB="$(awk '
  /^      - name: Managed-lane guard \(b3b #189 retired the direct-token writer\)$/ {f=1}
  f && /^      - name: / && $0 !~ /Managed-lane guard/ {exit}
  f && /^  [A-Za-z_][A-Za-z0-9_-]*:$/ {exit}
  f {print}
' <<<"$JOB_RAW")"
is "guard step blob hash" "ef59e00c3696d06e3b3c2ed4fe2e9d20ab317fa110a619613fd13b1c86a46fe7" "$(printf '%s\n' "$GUARD_BLOB" | sha256sum | cut -d' ' -f1)"
# Exactly one guard step and one write step anywhere in the workflow, and
# exactly one write_anchor_dns token in the job: a second (unpinned) writer
# step that runs `... || true`, or a relocated copy, is caught here.
is "exactly one guard-step header in the workflow" "1" "$(grep -cE '^      - name: Managed-lane guard \(b3b #189 retired the direct-token writer\)$' "$PROV")"
is "exactly one write-step header in the workflow" "1" "$(grep -cE '^      - name: Upsert anchor A \+ dashboard CNAME through the broker$' "$PROV")"
is "exactly one write_anchor_dns token in the job" "1" "$(printf '%s\n' "$JOB_LINES" | grep -c 'write_anchor_dns')"
# The writer may live only here: a second call in another job, or an
# obfuscated same-job call (`write_anchor_""dns`), adds a token.
is "exactly one write_anchor mention in the job" "1" "$(printf '%s\n' "$JOB_LINES" | grep -c 'write_anchor')"
is "exactly one write_anchor_dns token in provision.yml" "1" "$(grep -c 'write_anchor_dns' "$PROV")"

# ---- the managed-lane guard fails closed ----------------------------------
contains "guard names the b3b broker path" 'anchor DNS now goes through the pc-control broker (b3b, #189)' "$JOB"

# ---- the retired provider surface is absent from the job ------------------
for v in NET_DNS_PROVIDER STATUS_EDGE_DOMAIN CLOUDFLARE_DNS_TOKEN GCORE_DNS_TOKEN; do
  lacks_word "job does not consume $v" "$v" "$JOB"
done
lacks "job does not call the retired writer" '030-anchor-dns.sh' "$JOB"
lacks "job does not name a provider zone override" 'NET_DNS_ZONE' "$JOB"

# ---- workflow wiring: fail before any thumbprint --------------------------
prov_live="$(printf '%s\n' "$PROV_STRUCT" | cut -f2- | grep -v '^[[:space:]]*#')"
# Workflow-level env can set the startup variables too: ban them provision-wide.
for v in BASH_ENV ENV SHELLOPTS BASHOPTS; do
  lacks_word "provision does not set $v" "$v" "$prov_raw_live"
done
contains "thumbprint waits for the DNS job" 'needs: [device-flow, anchor-dns]' "$prov_live"
lacks "provision no longer references the retired writer" '030-anchor-dns.sh' "$prov_raw_live"
for v in NET_DNS_PROVIDER STATUS_EDGE_DOMAIN CLOUDFLARE_DNS_TOKEN GCORE_DNS_TOKEN; do
  lacks_word "provision does not use $v anywhere" "$v" "$prov_raw_live"
done

# ---- the retired surface is gone from the tree ----------------------------
if [ -e .github/scripts/030-anchor-dns.sh ]; then bad "retired writer still present"; else ok "retired writer deleted"; fi
if [ -e tests/anchor-dns ]; then bad "retired harness still present"; else ok "retired harness deleted"; fi

# ---- CI: the new harness is wired, the old one is not ---------------------
ci_live="$(grep -v '^[[:space:]]*#' "$CI")"
# ci.yml gets the same block-scalar-aware structural view: the unit-tests
# job and its run step are located structurally, so a decoy scalar cannot
# spoof either.
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
# The gate and run-list assertions are scoped to the unit-tests-scripts job
# block: a mention in another job's run line or a commented-out line cannot
# satisfy them.
ci_gate="$(grep -m1 -F "elif grep -qE '^(\.github/scripts/" <<<"$ci_unit" || true)"
[ -n "$ci_gate" ] || bad "ci.yml unit-tests gate line not found"
contains "ci runs this harness" 'bash tests/broker-provision-dns/run-test.sh' "$ci_unit"
lacks "ci no longer runs the retired harness" 'tests/anchor-dns/run-test.sh' "$ci_live"
lacks "ci path gate no longer names the retired harness" 'anchor-dns' "$ci_live"
# The gate is checked FUNCTIONALLY: extract the regex literal from the gate
# LINE itself (not from anywhere in the job) and prove it matches this
# harness's path. A decoy `grep -qE` elsewhere, or a token parked in an
# inline comment, cannot satisfy it.
gate_raw="$(printf '%s\n' "$ci_gate" | grep -oE "grep -qE '[^']*'" || true)"
is "exactly one gate regex on the gate line" "1" "$(printf '%s\n' "$gate_raw" | grep -c . || true)"
gate_pattern="$(head -n1 <<<"$gate_raw" | sed -e "s/^grep -qE '//" -e "s/'$//")"
[ -n "$gate_pattern" ] || bad "could not extract the unit-tests gate regex"
if [ -n "$gate_pattern" ]; then
  if grep -qE "$gate_pattern" <<<"tests/broker-provision-dns/run-test.sh"; then
    ok "unit-tests gate regex matches this harness path"
  else
    bad "unit-tests gate regex does not match this harness path"
  fi
fi
# The harness-run step is byte-pinned and located structurally: an
# `if: false` rewrite, an early `exit 0`, or a `set +e` inside it must
# update the pin.
RUN_START="$(awk -F'\t' '$2 == "      - name: Run the committed script harnesses (cheap first)" {print $1; exit}' <<<"$CI_STRUCT")"
RUN_END="$(awk -F'\t' -v s="$RUN_START" '$1 > s && $2 ~ /^      - name: / {print $1; exit}' <<<"$CI_STRUCT")"
if [ -n "$RUN_START" ] && [ -n "$RUN_END" ]; then
  RUN_STEP_BLOB="$(sed -n "${RUN_START},$((RUN_END - 1))p" "$CI")"
  is "harness-run step blob hash" "286baff6b596031b9d0faaa716dac758b1515251ee3fafa2454d639184991182" "$(printf '%s\n' "$RUN_STEP_BLOB" | sha256sum | cut -d' ' -f1)"
  is "harness-run step keeps the gate expression" "1" "$(printf '%s\n' "$RUN_STEP_BLOB" | grep -cE '^        if: steps\.gate\.outputs\.run == .yes.$')"
else
  bad "harness-run step span not found in ci.yml"
fi
is "exactly one harness-run step header" "1" "$(grep -cE '^      - name: Run the committed script harnesses \(cheap first\)$' "$CI")"
is "exactly one unit-tests-scripts job key line in ci.yml" "1" "$(grep -cE "^  (\\?[[:space:]]*)?((&[^[:space:]]+|![^[:space:]]+)[[:space:]]+)*(\"unit-tests-scripts\"|'unit-tests-scripts'|unit-tests-scripts)[[:space:]]*:?[[:space:]]*(#.*)?$" "$CI")"
# Spelling-agnostic census for ci.yml (same doctrine as provision.yml):
# every indent-2 non-space/non-comment line of the stripped view is a
# structural line of the top level (on/env/permissions children plus the job
# keys). A
# duplicate or decoy job key in ANY spelling adds one.
is "ci.yml structural indent-2 line count (pin: update for a new top-level line)" "15" "$(printf '%s\n' "$CI_STRUCT" | cut -f2- | grep -cE '^  [^[:space:]#]')"
# The unit-tests job itself must stay live and shell-predictable: no
# job-level if/defaults/strategy, no workflow defaults, no bash startup-file
# variables anywhere in ci.yml, and the allowlist must no longer name the
# retired direct provider APIs.
is "no job-level if on the unit-tests job" "0" "$(printf '%s\n' "$ci_unit" | grep -cE "^    (&[^[:space:]]+[[:space:]]+|![^[:space:]]+[[:space:]]+)*[\"']?if[\"']?[[:space:]]*:")"
is "no job-level defaults on the unit-tests job" "0" "$(printf '%s\n' "$ci_unit" | grep -cE "^    (&[^[:space:]]+[[:space:]]+|![^[:space:]]+[[:space:]]+)*[\"']?defaults[\"']?[[:space:]]*:")"
is "no job-level strategy on the unit-tests job" "0" "$(printf '%s\n' "$ci_unit" | grep -cE "^    (&[^[:space:]]+[[:space:]]+|![^[:space:]]+[[:space:]]+)*[\"']?strategy[\"']?[[:space:]]*:")"
is "no workflow-level defaults in ci.yml" "0" "$(grep -cE "^(&[^[:space:]]+[[:space:]]+|![^[:space:]]+[[:space:]]+)*[\"']?defaults[\"']?[[:space:]]*:" "$CI")"
for v in BASH_ENV ENV SHELLOPTS BASHOPTS; do
  lacks_word "ci.yml does not set $v" "$v" "$ci_live"
done
lacks "ci allowlist no longer names the Cloudflare DNS API" 'api.cloudflare.com' "$(cat "$CI")"
lacks "ci allowlist no longer names the Gcore DNS API" 'api.gcore.com' "$(cat "$CI")"
# ci.yml liveness: a disabled or empty unit-tests job, a job-level shell
# override, or a workflow-level shell default would make every harness
# assertion moot.
is "exactly one gate elif in the unit-tests job" "1" "$(printf '%s\n' "$ci_unit" | grep -cE 'elif grep -qE')"
gate_ln="$(printf '%s\n' "$ci_unit" | grep -nE 'elif grep -qE' | head -n1 | cut -d: -f1 || true)"
if [ -n "$gate_ln" ]; then
  gate_next="$(printf '%s\n' "$ci_unit" | sed -n "$((gate_ln + 1)),\$p" | awk '/^[[:space:]]*(elif|else|fi)([[:space:]]|$)/ {exit} {print}' | grep -vE '^[[:space:]]*(#|$)' | head -n1 || true)"
  is "gate branch sets run=yes" '              echo "run=yes" >> "$GITHUB_OUTPUT"' "$gate_next"
else
  bad "gate elif line not found in the unit-tests job"
fi
# The whole gate step is byte-pinned: a later run=no write, a redefined
# GITHUB_OUTPUT, a shadowed grep, or any other subversion inside it must
# update the pin.
GATE_START="$(awk -F'\t' '$2 == "      - name: Gate on changed paths (CI scripts or harnesses)" {print $1; exit}' <<<"$CI_STRUCT")"
GATE_END="$(awk -F'\t' -v s="$GATE_START" '$1 > s && $2 ~ /^      - name: / {print $1; exit}' <<<"$CI_STRUCT")"
if [ -n "$GATE_START" ] && [ -n "$GATE_END" ]; then
  GATE_STEP_BLOB="$(sed -n "${GATE_START},$((GATE_END - 1))p" "$CI")"
  is "gate step blob hash" "0f85dbbe46c2abad81a846cc32397163ec1a3cb9a50afe5c674849b1ebcd18e9" "$(printf '%s\n' "$GATE_STEP_BLOB" | sha256sum | cut -d' ' -f1)"
else
  bad "gate step span not found in ci.yml"
fi
is "exactly one gate-step header" "1" "$(grep -cE '^      - name: Gate on changed paths \(CI scripts or harnesses\)$' "$CI")"
is "unit-tests job has no if" "0" "$(printf '%s\n' "$ci_unit" | grep -cE "^    (&[^[:space:]]+[[:space:]]+|![^[:space:]]+[[:space:]]+)*[\"']?if[\"']?[[:space:]]*:")"
is "unit-tests job has no strategy" "0" "$(printf '%s\n' "$ci_unit" | grep -cE "^    (&[^[:space:]]+[[:space:]]+|![^[:space:]]+[[:space:]]+)*[\"']?strategy[\"']?[[:space:]]*:")"
is "unit-tests job has no continue-on-error" "0" "$(printf '%s\n' "$ci_unit" | grep -cE "^    (&[^[:space:]]+[[:space:]]+|![^[:space:]]+[[:space:]]+)*[\"']?continue-on-error[\"']?[[:space:]]*:")"
is "unit-tests job has no defaults" "0" "$(printf '%s\n' "$ci_unit" | grep -cE "^    (&[^[:space:]]+[[:space:]]+|![^[:space:]]+[[:space:]]+)*[\"']?defaults[\"']?[[:space:]]*:")"
for k in if strategy defaults continue-on-error; do
  is "unit-tests job has no explicit-key $k" "0" "$(printf '%s\n' "$ci_unit" | grep -cE "^    \\?[[:space:]]*((&[^[:space:]]+|![^[:space:]]+)[[:space:]]+)*[\"']?${k}[\"']?[[:space:]]*(#.*)?$")"
done
# An explicit mapping key can carry its name across lines (`? "i\` + `f"`),
# which no single-line regex sees. Neither workflow has a legitimate explicit
# key at any mapping level (indent 0-8), so the form is banned blanket; the
# per-key checks above stay as diagnostics.
is "ci.yml has no explicit mapping keys" "0" "$(grep -cE '^ {0,8}\?([[:space:]]|$)' "$CI")"
is "provision.yml has no explicit mapping keys" "0" "$(grep -cE '^ {0,8}\?([[:space:]]|$)' "$PROV")"
# A YAML merge key (`<<: *anchor`) can inject a mapping — including
# `if: false` / `continue-on-error: true` — from an anchor defined elsewhere,
# invisible to every key regex. Neither workflow uses merge keys, so they are
# banned blanket.
is "ci.yml has no YAML merge keys" "0" "$(grep -cE '^ {0,8}((&|!)[^[:space:]]+[[:space:]]+)*<<[[:space:]]*:' "$CI")"
is "provision.yml has no YAML merge keys" "0" "$(grep -cE '^ {0,8}((&|!)[^[:space:]]+[[:space:]]+)*<<[[:space:]]*:' "$PROV")"
is "ci.yml has no workflow defaults" "0" "$(grep -cE "^(&[^[:space:]]+[[:space:]]+|![^[:space:]]+[[:space:]]+)*[\"']?defaults[\"']?[[:space:]]*:" "$CI")"
lacks_word "unit-tests job does not set BASH_ENV" BASH_ENV "$ci_unit"
lacks_word "ci.yml does not set BASH_ENV" BASH_ENV "$ci_live"
for f in "$CI" "$PROV"; do
  if grep -qE '\\[uUxX][0-9a-fA-F]|\\[0-7]' <<<"$(grep -v '^[[:space:]]*#' "$f")"; then
    bad "$(basename "$f") contains a hex/octal escape (name-assembly route, banned blanket)"
  else
    ok "$(basename "$f") has no hex/octal escape"
  fi
done
# The in-tree allowlist default must not admit the retired provider APIs
# (PR runs use origin/main's fetched pattern; this pins the post-merge state).
allowed_default="$(grep -E '^[[:space:]]*allowed_url=' "$CI" || true)"
[ -n "$allowed_default" ] || bad "ci.yml allowed_url default not found"
is "exactly one line-leading allowed_url assignment" "1" "$(grep -cE '^[[:space:]]*allowed_url=' "$CI")"
is "ci.yml allowed_url default blob hash" "2995ad1ff3581328f07a567d6ffa840d3dad8cc14627869d8dc2288ff7b57617" "$(printf '%s' "$allowed_default" | sha256sum | cut -d' ' -f1)"
lacks "ci.yml does not append to allowed_url" 'allowed_url+=' "$(cat "$CI")"
lacks "ci.yml allowlist default does not name cloudflare" 'cloudflare' "$allowed_default"
lacks "ci.yml allowlist default does not name gcore" 'gcore' "$allowed_default"

# ---- production surfaces carry no retired name ----------------------------
# Every file in the repo outside tests/, .git/ and the gitignored .local/
# proof config is a production surface (extensionless and Markdown included),
# except the two records that name the retired identifiers by design:
# docs/security-posture.md (the retirement record) and docs/verification.md
# (the b3b verification row naming the retired harness). A new
# `tools/evil.sh`, `tools/dns-fallback.env`, `evil.bash`,
# `.github/workflows/evil.yaml`, `scripts/lib/helper` or sourced
# `docs/evil.md` must not sit outside the scan. Word
# boundaries keep the live broker config name (`PC_BROKER_STATUS_EDGE_DOMAIN`)
# legal while the retired repo variable is caught. Comments are INCLUDED: a
# stale comment is drift too. The named groups are still checked explicitly
# so a renamed/moved directory cannot silently empty the scan; a grep error
# (rc>1) is a failure, not a pass.
shopt -s nullglob
for d in .github/workflows .github/scripts scripts; do
  [ -d "$d" ] || bad "surface directory missing: $d"
done
for pat in '.github/workflows/*.yml' '.github/scripts/*.sh' 'scripts/*.sh'; do
  compgen -G "$pat" >/dev/null || bad "surface group matched nothing: $pat"
done
surface_files=()
while IFS= read -r f; do surface_files+=("$f"); done < <(find . \( -path ./.git -o -path ./tests -o -path ./.local \) -prune -o -type f ! -path './docs/security-posture.md' ! -path './docs/verification.md' -print | sort)
[ "${#surface_files[@]}" -gt 0 ] || bad "no production surfaces matched"
# A symlink in the production surface would dodge the scan entirely: fail
# closed instead (the tree has none).
symlinks="$(find . \( -path ./.git -o -path ./tests -o -path ./.local \) -prune -o -type l -print | sort)"
if [ -z "$symlinks" ]; then ok "no symlinks in the production surface"; else bad "symlink in the production surface: $symlinks"; fi
for f in "${surface_files[@]}"; do
  [ -f "$f" ] || bad "scanned surface missing: $f"
done
for v in NET_DNS_PROVIDER STATUS_EDGE_DOMAIN CLOUDFLARE_DNS_TOKEN GCORE_DNS_TOKEN; do
  rc=0
  hits="$(grep -lnwE -- "$v" "${surface_files[@]}")" || rc=$?
  case "$rc" in
    0) bad "production surface uses $v: $hits" ;;
    1) ok "no production surface uses $v" ;;
    *) bad "grep failed scanning for $v (rc=$rc)" ;;
  esac
done
rc=0
hits="$(grep -lnE '030-anchor-dns|tests/anchor-dns' "${surface_files[@]}")" || rc=$?
case "$rc" in
  0) bad "production surface references the retired writer/harness: $hits" ;;
  1) ok "no production surface references the retired writer/harness" ;;
  *) bad "grep failed scanning for the retired writer/harness (rc=$rc)" ;;
esac

# Composite and local actions execute in the same context: every action
# manifest anywhere outside tests/ (a `uses: ./actions/foo` local action
# included) and every file under an actions/ or .github/actions/ directory
# joins the scan. Retired names must not appear in any of them.
action_files=()
while IFS= read -r f; do action_files+=("$f"); done < <(find . \( -path ./.git -o -path ./tests \) -prune -o -type f \( -name 'action.yml' -o -name 'action.yaml' \) -print | sort)
for d in .github/actions actions; do
  if [ -d "$d" ]; then
    while IFS= read -r f; do action_files+=("$f"); done < <(find "$d" -type f | sort)
  fi
done
if [ "${#action_files[@]}" -gt 0 ]; then
  for v in NET_DNS_PROVIDER STATUS_EDGE_DOMAIN CLOUDFLARE_DNS_TOKEN GCORE_DNS_TOKEN; do
    rc=0
    hits="$(grep -lnwE -- "$v" "${action_files[@]}")" || rc=$?
    case "$rc" in
      0) bad "action manifest/script uses $v: $hits" ;;
      1) ok "no action manifest/script uses $v" ;;
      *) bad "grep failed scanning action files for $v (rc=$rc)" ;;
    esac
  done
  rc=0
  hits="$(grep -lnE '030-anchor-dns|tests/anchor-dns' "${action_files[@]}")" || rc=$?
  case "$rc" in
    0) bad "action manifest/script references the retired writer/harness: $hits" ;;
    1) ok "no action manifest/script references the retired writer/harness" ;;
    *) bad "grep failed scanning action files for the retired writer/harness (rc=$rc)" ;;
  esac
fi

# Dynamic secret/variable indexing can reconstruct any banned name from split
# literals (`secrets[format('{0}{1}', 'CLOUDFLARE', '_DNS_TOKEN')]`), which no
# word-boundary grep can see — ban the bracket form across the whole
# executable .github surface. Literal `secrets.NAME` / `vars.NAME` stays the
# only admitted spelling.
gh_files="$(find .github -type f \( -name '*.yml' -o -name '*.yaml' -o -name '*.sh' \) | sort)"
[ -n "$gh_files" ] || bad "no .github files found for the dynamic-index scan"
for pat in 'secrets[[:space:]]*\[' 'vars[[:space:]]*\['; do
  rc=0
  hits="$(grep -lnE -- "$pat" $gh_files)" || rc=$?
  case "$rc" in
    0) bad "dynamic indexing matching '$pat' in .github: $hits" ;;
    1) ok "no dynamic indexing matching '$pat' in .github" ;;
    *) bad "grep failed scanning for '$pat' (rc=$rc)" ;;
  esac
done

# A dropped run-list line silently skips a harness and no harness can catch
# its own absence — the cross-check lives here, in managed-inputs and in
# edge-origin-auth, so removing one checker's line still leaves two failing.
shopt -s nullglob
harnesses=(tests/*/run-test.sh)
[ ${#harnesses[@]} -gt 0 ] || bad "no tests/*/run-test.sh harnesses found"
for t in "${harnesses[@]}"; do
  # Whole-line, indentation-tolerant match inside the unit-tests-scripts job:
  # an `echo skipped # bash ...` decoy, a commented-out line, or a run line
  # in any other job does not satisfy it.
  if grep -qE "^[[:space:]]+bash ${t//./\\.}[[:space:]]*$" <<<"$ci_unit"; then
    ok "ci.yml run list includes $t"
  else
    bad "ci.yml run list includes $t"
  fi
done

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
