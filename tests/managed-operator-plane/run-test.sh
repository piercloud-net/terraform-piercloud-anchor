#!/usr/bin/env bash
# tests/managed-operator-plane/run-test.sh — issues #198 + #204 operator-plane pin.
#
# A managed tenant run selects its own environment, and GitHub falls back to
# repository-level values for every name that environment does not define.
# A managed run reads its operator-plane values (ANCHOR_ROLE, NTFY_*, the B2
# witness key, the TLS chain, ...) from its own environment (#204): bare reads
# are allowed only inside tenant-environment jobs, and the ungated banner
# job's repo-scope step probes every such name and refuses a managed dispatch
# while a repository- or organization-level copy exists. The operator-only
# values (TENANT_USER, CUSTOMER_NUMBER) stay gated on `inputs.tenant`.
#
# Structural pins (#204 round 1): workflow/banner job/banner step keys are
# allowlisted (no `defaults:`, `shell:`, BASH_ENV-style env), the preflight
# and repo-scope steps are banner steps 1-2 pinned by digest, and any status
# function in a tenant-environment job's needs closure is refused.
#
# This harness binds:
#   - the PIN (check.py, PyYAML node walk, exact-literal allowlist, default
#     deny) is green on the committed workflows;
#   - MUTANTS: each ungating shape a later edit could introduce is red
#     (bare reference, other case, index syntax, whole-context toJSON, a
#     wrong-polarity gate, a duplicate key, an alias, an `environment:` added
#     to an operator-only workflow);
#   - BEHAVIOR: the real binding step body (extracted with PyYAML, never a
#     copy) refuses a managed run with no TENANT_CUSTOMER_NUMBER before the
#     device card, and leaves the operator run and a provisioned managed run
#     alone.
#
# Cred-free, offline: no network, no credentials.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
HARNESS_DIR="$ROOT/tests/managed-operator-plane"
CHECK="$HARNESS_DIR/check.py"
WFDIR="$ROOT/.github/workflows"
PROV="$WFDIR/provision.yml"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export PYTHONDONTWRITEBYTECODE=1

pass=0
fail=0
ok()  { pass=$((pass + 1)); printf 'ok   %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL %s\n' "$1"; }
contains() { # $1 label, $2 needle, $3 haystack
  case "$3" in *"$2"*) ok "$1" ;; *) bad "$1 (missing '$2')" ;; esac
}

python3 -I -B -c 'import yaml' 2>/dev/null || { printf 'FAIL PyYAML is required (python3-yaml)\n'; exit 1; }

# --- pin on the committed tree -------------------------------------------
if out="$(python3 -I -B "$CHECK" "$WFDIR" 2>&1)"; then
  ok "pin holds on the committed workflows"
else
  bad "pin holds on the committed workflows: $out"
fi

# --- mutants ---------------------------------------------------------------
# mutant LABEL FILE PYTHON-EXPR: copy the workflow dir, rewrite FILE with the
# expression (s = file text), expect the pin to go red.
mutant() {
  local label="$1" file="$2" expr="$3" dir="$WORK/m$((pass + fail))"
  mkdir -p "$dir"
  cp "$WFDIR"/*.yml "$dir"/
  python3 -I -B - "$dir/$file" "$expr" <<'PY'
import sys
p, expr = sys.argv[1], sys.argv[2]
s = open(p).read()
t = eval(expr, {"s": s})
assert t != s, "mutation did not change the file"
open(p, "w").write(t)
PY
  if python3 -I -B "$CHECK" "$dir" >/dev/null 2>&1; then
    bad "mutant stays green: $label"
  else
    ok "mutant red: $label"
  fi
}

G="\${{ inputs.tenant == '' && secrets.NTFY_TOPIC || '' }}"
mutant "bare operator secret" provision.yml "s.replace(\"$G\", '\${{ secrets.NTFY_TOPIC }}', 1)"
mutant "upper-case context" provision.yml "s.replace(\"$G\", '\${{ SECRETS.NTFY_TOPIC }}', 1)"
mutant "index syntax" provision.yml "s.replace(\"$G\", \"\${{ secrets['NTFY_TOPIC'] }}\", 1)"
mutant "whole-context toJSON" provision.yml "s.replace(\"$G\", '\${{ toJSON(secrets) }}', 1)"
mutant "wrong-polarity gate" provision.yml "s.replace(\"$G\", \"\${{ inputs.tenant != '' && secrets.NTFY_TOPIC || '' }}\", 1)"
mutant "fallback to the operator value" provision.yml "s.replace(\"$G\", \"\${{ inputs.tenant == '' && secrets.NTFY_TOPIC || secrets.NTFY_TOPIC }}\", 1)"
mutant "bare TENANT_USER" provision.yml "s.replace(\"\${{ inputs.tenant != '' && inputs.tenant || vars.TENANT_USER }}\", '\${{ vars.TENANT_USER }}', 1)"
mutant "bare CUSTOMER_NUMBER" provision.yml "s.replace(\"\${{ inputs.tenant != '' && secrets.TENANT_CUSTOMER_NUMBER || inputs.tenant == '' && secrets.CUSTOMER_NUMBER || '' }}\", '\${{ secrets.CUSTOMER_NUMBER }}', 1)"
mutant "new ungated name" provision.yml "s.replace('          MODE: \${{ inputs.mode }}\n', '          MODE: \${{ inputs.mode }}\n          EXTRA: \${{ vars.SOMETHING_NEW }}\n', 1)"
mutant "duplicate env key" provision.yml "s.replace('      - name: Tenant-environment binding check (environment marker == tenant input)\n        env:\n', '      - name: Tenant-environment binding check (environment marker == tenant input)\n        env:\n          NTFY_TOPIC: \${{ secrets.NTFY_TOPIC }}\n        env:\n', 1)"
mutant "aliased scalar" provision.yml "s.replace('          MODE: \${{ inputs.mode }}\n', '          MODE: \${{ inputs.mode }}\n          A: &leak \"\${{ secrets.RECORDING_WITNESS_KEY }}\"\n          B: *leak\n', 1)"
mutant "environment added to an operator-only workflow" external-watch.yml "s.replace('    runs-on: ubuntu-latest\n', '    runs-on: ubuntu-latest\n    environment: \${{ inputs.probe_url }}\n', 1)"
mutant "environment added to visibility-banner" provision.yml "s.replace('  visibility-banner:\n', '  visibility-banner:\n    environment: anchor\n', 1)"
mutant "local reusable-workflow call" provision.yml "s.replace('  visibility-banner:\n', '  callee:\n    needs: [visibility-banner]\n    uses: ./.github/workflows/release.yml\n  visibility-banner:\n', 1)"
mutant "binary-tagged expression" provision.yml "s.replace('          MODE: \${{ inputs.mode }}\n', '          MODE: \${{ inputs.mode }}\n          X: !!binary JHt7IHNlY3JldHMuTlRGWV9UT1BJQyB9fQ==\n', 1)"
mutant "remote self-reference composite" provision.yml "s.replace('      - name: Checkout (no credentials persisted)\n', '      - uses: PIERCLOUD-NET/Terraform-Piercloud-Anchor/.github/actions/x@main\n      - name: Checkout (no credentials persisted)\n', 1)"
mutant "unpinned third-party action" provision.yml "s.replace('actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1', 'actions/checkout@v4', 1)"
mutant "renamed banner job" provision.yml "s.replace('  visibility-banner:\n', '  banner:\n', 1).replace('needs: visibility-banner', 'needs: banner').replace('needs: [visibility-banner', 'needs: [banner').replace('needs.visibility-banner.', 'needs.banner.')"
mutant "duplicate banner job with an environment" provision.yml "s.replace('\njobs:\n', '\njobs:\n  visibility-banner:\n    runs-on: ubuntu-latest\n    environment: anchor\n    steps:\n      - run: echo hi\n', 1)"
mutant "duplicate banner job without an environment" provision.yml "s.replace('\njobs:\n', '\njobs:\n  visibility-banner:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n', 1)"
mutant "release-only tag action added to provision.yml" provision.yml "s.replace('      - name: Checkout (no credentials persisted)\n', '      - uses: cad0p/semver-calver-release/release@v1\n      - name: Checkout (no credentials persisted)\n', 1)"
mutant "local composite action" provision.yml "s.replace('      - name: Checkout (no credentials persisted)\n', '      - uses: ./.github/actions/leak\n      - name: Checkout (no credentials persisted)\n', 1)"
mutant "repository_dispatch trigger on a checked file" release.yml "s.replace('on:\n', 'on:\n  repository_dispatch:\n', 1)"
mutant "workflow_call trigger on a checked file" release.yml "s.replace('on:\n', 'on:\n  workflow_call:\n', 1)"

# --- issue #204: bare reads only in environment jobs, probes only in the
# repo-scope step, the step is unconditional, every environment job is
# reached through the banner ------------------------------------------------
SCOPE="      - name: Repo-scope check (managed runs read operator-plane values from their environment only)\n        env:\n"
LASTP="          REPO_SCOPE_MANAGED_TENANT: \${{ vars.MANAGED_TENANT != '' }}\n"
mutant "bare read in the banner job" provision.yml "s.replace(\"$LASTP\", \"$LASTP          LEAK: \${{ secrets.NTFY_TOPIC }}\\n\", 1)"
mutant "bare read in a job with no environment" provision.yml "s.replace('  apply-placeholder:\n', '  apply-placeholder:\n    env:\n      LEAK: \${{ secrets.NTFY_TOPIC }}\n', 1)"
mutant "missing probe" provision.yml "s.replace(\"          REPO_SCOPE_STATUS_PULLER: \${{ vars.STATUS_PULLER != '' }}\\n\", '', 1)"
mutant "extra probe" provision.yml "s.replace(\"$LASTP\", \"$LASTP          REPO_SCOPE_FOO: \${{ vars.FOO != '' }}\\n\", 1)"
mutant "probe on the wrong context" provision.yml "s.replace(\"\${{ vars.STATUS_PULLER != '' }}\", \"\${{ secrets.STATUS_PULLER != '' }}\", 1)"
mutant "probe outside the repo-scope step" provision.yml "s.replace('          MANAGED_TENANT: \${{ vars.MANAGED_TENANT }}\n', \"          MANAGED_TENANT: \${{ vars.MANAGED_TENANT }}\\n          P: \${{ vars.ANCHOR_ROLE != '' }}\\n\", 1)"
mutant "repo-scope step renamed" provision.yml "s.replace('Repo-scope check (managed runs', 'Repo scope check (managed runs', 1)"
mutant "repo-scope step if:" provision.yml "s.replace(\"$SCOPE\", \"$SCOPE\".replace('        env:', \"        if: inputs.tenant == 'x'\\n        env:\"), 1)"
mutant "repo-scope step continue-on-error" provision.yml "s.replace(\"$SCOPE\", \"$SCOPE\".replace('        env:', '        continue-on-error: true\\n        env:'), 1)"
mutant "banner job continue-on-error" provision.yml "s.replace('  visibility-banner:\n', '  visibility-banner:\n    continue-on-error: true\n', 1)"
mutant "device-flow needs removed" provision.yml "s.replace('    needs: [visibility-banner]\n', '', 1)"
mutant "device-flow if: always()" provision.yml "s.replace('    needs: [visibility-banner]\n', '    needs: [visibility-banner]\n    if: always()\n', 1)"
mutant "device-flow if: !success()" provision.yml "s.replace('    needs: [visibility-banner]\n', \"    needs: [visibility-banner]\\n    if: \${{ !success() }}\\n\", 1)"
mutant "anchor-dns if: always()" provision.yml "s.replace(\"    if: inputs.mode == 'apply'\\n    # Same gate as device-flow\", \"    if: always() && inputs.mode == 'apply'\\n    # Same gate as device-flow\", 1)"
mutant "anchor on a scope-step node" provision.yml "s.replace('          TENANT_INPUT: \${{ inputs.tenant }}\n          REPO_SCOPE_', '          TENANT_INPUT: &t \${{ inputs.tenant }}\n          REPO_SCOPE_', 1)"

# --- PR #205 round 1 (red-team F1-F5, functional F3): each mutant must be red
# for its own rule, not incidentally. mutant_why LABEL FILE EXPR NEEDLE.
mutant_why() {
  local label="$1" file="$2" expr="$3" needle="$4" dir="$WORK/m$((pass + fail))" out
  mkdir -p "$dir"
  cp "$WFDIR"/*.yml "$dir"/
  python3 -I -B - "$dir/$file" "$expr" <<'PY'
import sys
p, expr = sys.argv[1], sys.argv[2]
s = open(p).read()
t = eval(expr, {"s": s})
assert t != s, "mutation did not change the file"
open(p, "w").write(t)
PY
  if out="$(python3 -I -B "$CHECK" "$dir" 2>&1)"; then
    bad "mutant stays green: $label"
  elif printf '%s' "$out" | grep -qF -- "$needle"; then
    ok "mutant red for its rule: $label"
  else
    bad "mutant red for another reason: $label (want '$needle'; got: $(printf '%s' "$out" | head -n1))"
  fi
}
mutant_why "device-flow if: success() || ..." provision.yml 's.replace("    needs: [visibility-banner]\n", "    needs: [visibility-banner]\n    if: ${{ success() || needs.visibility-banner.result == \"failure\" }}\n", 1)' "status-function"
mutant_why "repo-scope body: TENANT_INPUT blanked" provision.yml 's.replace("TENANT_INPUT=\"${TENANT_INPUT:-}\"\n          if [ -z \"$TENANT_INPUT\" ]; then\n            echo \"Operator run", "TENANT_INPUT=\"${TENANT_INPUT:-}\"\n          TENANT_INPUT=\"\"\n          if [ -z \"$TENANT_INPUT\" ]; then\n            echo \"Operator run", 1)' "step 2"
mutant_why "repo-scope body: comment-spoofed loop" provision.yml 's.replace("          for v in ${!REPO_SCOPE_@}; do\n", "          # for v in ${!REPO_SCOPE_@}; do\n          for v in ${!NOPE_@}; do\n", 1)' "step 2"
mutant_why "repo-scope step shell: override" provision.yml 's.replace("      - name: Repo-scope check (managed runs read operator-plane values from their environment only)\n", "      - name: Repo-scope check (managed runs read operator-plane values from their environment only)\n        shell: \"true {0}\"\n", 1)' "step 2 keys must be within"
mutant_why "banner job defaults: shell" provision.yml 's.replace("  visibility-banner:\n", "  visibility-banner:\n    defaults:\n      run:\n        shell: \"true {0}\"\n", 1)' "visibility-banner keys must be within"
mutant_why "banner job env: BASH_ENV" provision.yml 's.replace("  visibility-banner:\n", "  visibility-banner:\n    env:\n      BASH_ENV: /tmp/x\n", 1)' "visibility-banner keys must be within"
mutant_why "workflow-level defaults: shell" provision.yml 's.replace("\njobs:\n", "\ndefaults:\n  run:\n    shell: \"true {0}\"\njobs:\n", 1)' "workflow top-level keys must be within"
mutant_why "workflow-level env: BASH_ENV" provision.yml 's.replace("\njobs:\n", "\nenv:\n  BASH_ENV: /tmp/x\njobs:\n", 1)' "workflow top-level keys must be within"
mutant_why "preflight step if: false" provision.yml 's.replace("      - name: Managed-input preflight", "      - if: false\n        name: Managed-input preflight", 1)' "step 1 keys must be within"
mutant_why "preflight body edited" provision.yml 's.replace("          MODE: ${{ inputs.mode }}\n        run: |\n          set -euo pipefail\n", "          MODE: ${{ inputs.mode }}\n        run: |\n          set -euo pipefail\n          exit 0\n", 1)' "step 1"
mutant_why "step inserted before the preflight" provision.yml 's.replace("      - name: Managed-input preflight", "      - name: Early\n        run: echo BASH_ENV=/tmp/x >> \"$GITHUB_ENV\"\n      - name: Managed-input preflight", 1)' "step 1 must be"
mutant_why "later banner step shell: override" provision.yml 's.replace("      - name: Record head SHA for the backend approval pin\n", "      - name: Record head SHA for the backend approval pin\n        shell: sh\n", 1)' "keys must be within"
mutant_why "bare MANAGED_TENANT in a job with no environment" provision.yml 's.replace("  apply-placeholder:\n", "  apply-placeholder:\n    env:\n      M: ${{ vars.MANAGED_TENANT }}\n", 1)' "ungated 'vars' reference"

# --- operator-only is an explicit named list, checked structurally too ----
# r1 red-team F1: a structural guess exempted a reusable callee with no
# environment/tenant text. Only OPERATOR_ONLY files may read operator values
# bare; any new file is checked in full.
mkdir -p "$WORK/op"
cat > "$WORK/op/callee.yml" <<'YML'
on: workflow_dispatch
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ vars.ANCHOR_ROLE }}"
YML
if python3 -I -B "$CHECK" "$WORK/op" >/dev/null 2>&1; then bad "an unlisted workflow reads operator values bare"; else ok "an unlisted workflow is checked in full"; fi
mkdir -p "$WORK/op2"
cp "$WORK/op/callee.yml" "$WORK/op2/external-watch.yml"
if python3 -I -B "$CHECK" "$WORK/op2" >/dev/null 2>&1; then ok "a listed operator-only workflow may read operator values"; else bad "listed operator-only workflow wrongly red"; fi
sed 's/on: workflow_dispatch/on:\n  workflow_dispatch:\n    inputs:\n      tenant:\n        type: string/' "$WORK/op/callee.yml" > "$WORK/op2/external-watch.yml"
if python3 -I -B "$CHECK" "$WORK/op2" >/dev/null 2>&1; then bad "a listed file naming a tenant stays exempt"; else ok "a listed file naming a tenant loses the exemption"; fi
sed 's/on: workflow_dispatch/on: workflow_run/' "$WORK/op/callee.yml" > "$WORK/op2/external-watch.yml"
if python3 -I -B "$CHECK" "$WORK/op2" >/dev/null 2>&1; then bad "workflow_run on a listed file stays green"; else ok "workflow_run fails closed even on a listed file"; fi
sed 's/run: echo/run: echo "${{ github.event.client_payload.tenant }}" \&\& echo/' "$WORK/op/callee.yml" > "$WORK/op2/external-watch.yml"
if python3 -I -B "$CHECK" "$WORK/op2" >/dev/null 2>&1; then bad "a listed file reading client_payload stays exempt"; else ok "a listed file reading client_payload loses the exemption"; fi
# r1 red-team F2: the extension match is case-insensitive.
mkdir -p "$WORK/op3"
cp "$WFDIR/release.yml" "$WORK/op3/release.yml"
cp "$WORK/op/callee.yml" "$WORK/op3/PROVISION.YML"
if python3 -I -B "$CHECK" "$WORK/op3" >/dev/null 2>&1; then bad "upper-case extension skipped"; else ok "upper-case extension is checked"; fi

# --- behavior: the real binding step -------------------------------------
python3 -I -B - "$PROV" "$WORK/binding.sh" <<'PY'
import sys, yaml
wf = yaml.safe_load(open(sys.argv[1]))
steps = [s for s in wf["jobs"]["device-flow"]["steps"]
         if s.get("name") == "Tenant-environment binding check (environment marker == tenant input)"]
assert len(steps) == 1, len(steps)
open(sys.argv[2], "w").write(steps[0]["run"])
PY
job_cn="$(python3 -I -B -c 'import sys,yaml; print(yaml.safe_load(open(sys.argv[1]))["jobs"]["device-flow"]["env"]["CUSTOMER_NUMBER"])' "$PROV")"
contains "device-flow job reads the tenant-only customer number on a managed run" "secrets.TENANT_CUSTOMER_NUMBER" "$job_cn"

run_binding() { env -i PATH="$PATH" TENANT_INPUT="$1" MANAGED_TENANT="$2" CUSTOMER_NUMBER="$3" bash "$WORK/binding.sh" 2>&1; }
if out="$(run_binding envproof envproof '')"; then
  bad "managed run without TENANT_CUSTOMER_NUMBER passes the binding step"
else
  ok "managed run without TENANT_CUSTOMER_NUMBER refused"
  contains "refusal names the tenant-only secret" "TENANT_CUSTOMER_NUMBER" "$out"
  contains "refusal happens before the device card" "before the device card" "$out"
fi
if out="$(run_binding envproof envproof 123456)"; then ok "provisioned managed run passes"; else bad "provisioned managed run refused: $out"; fi
if out="$(run_binding '' '' '')"; then ok "operator run unaffected by the managed check"; else bad "operator run refused: $out"; fi
if out="$(run_binding envproof other 123456)"; then bad "marker mismatch passes"; else ok "marker mismatch still refused"; fi

# --- behavior: the real repo-scope step (issue #204) ----------------------
python3 -I -B - "$PROV" "$WORK/scope.sh" "$WORK/probes.txt" <<'PY'
import sys, yaml
wf = yaml.safe_load(open(sys.argv[1]))
steps = [s for s in wf["jobs"]["visibility-banner"]["steps"]
         if s.get("name") == "Repo-scope check (managed runs read operator-plane values from their environment only)"]
assert len(steps) == 1, len(steps)
open(sys.argv[2], "w").write(steps[0]["run"])
open(sys.argv[3], "w").write("\n".join(k for k in steps[0]["env"] if k.startswith("REPO_SCOPE_")) + "\n")
PY
mapfile -t PROBES < "$WORK/probes.txt"
# run_scope TENANT [NAME=VALUE ...]: every probe false unless overridden.
run_scope() {
  local t="$1"; shift
  local args=() p
  for p in "${PROBES[@]}"; do args+=("$p=false"); done
  env -i PATH="$PATH" TENANT_INPUT="$t" "${args[@]}" "$@" bash "$WORK/scope.sh" 2>&1
}
if [ "${#PROBES[@]}" -ge 20 ]; then ok "repo-scope step carries ${#PROBES[@]} probes"; else bad "repo-scope step carries only ${#PROBES[@]} probes"; fi
if out="$(run_scope envproof REPO_SCOPE_NTFY_TOPIC=true)"; then
  bad "managed run with a repo-level NTFY_TOPIC passes"
else
  ok "managed run with a repo-level copy refused"
  contains "refusal names the repo-level name" "NTFY_TOPIC" "$out"
  contains "refusal happens before any gate" "before any gate or device card" "$out"
fi
if out="$(run_scope envproof REPO_SCOPE_MANAGED_TENANT=true)"; then bad "repo-level MANAGED_TENANT passes"; else ok "repo-level MANAGED_TENANT refused"; fi
if out="$(run_scope envproof)"; then ok "managed run with no repo-level copies passes"; else bad "clean managed run refused: $out"; fi
if out="$(run_scope '' REPO_SCOPE_NTFY_TOPIC=true REPO_SCOPE_ANCHOR_ROLE=true)"; then ok "operator run keeps its repo-level values"; else bad "operator run refused: $out"; fi
if out="$(env -i PATH="$PATH" TENANT_INPUT=envproof bash "$WORK/scope.sh" 2>&1)"; then
  bad "managed run with no probes passes"
else
  contains "no probes fails closed" "fail closed" "$out"
fi
if out="$(run_scope envproof REPO_SCOPE_NTFY_TOPIC=)"; then bad "empty probe value passes"; else ok "empty probe value refused"; fi
if out="$(run_scope envproof REPO_SCOPE_NTFY_TOPIC=TRUE)"; then bad "non-boolean probe value passes"; else ok "non-boolean probe value refused"; fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
