#!/usr/bin/env bash
# tests/managed-operator-plane/run-test.sh — issue #198 operator-plane pin.
#
# A managed tenant run selects its own environment, and GitHub falls back to
# repository-level values for every name that environment does not define.
# The operator's values (ANCHOR_ROLE, TENANT_USER, NTFY_*, the B2 witness key,
# CUSTOMER_NUMBER, the pier.status chain) live at repository level, so every
# reference a managed run can reach must be gated on `inputs.tenant`.
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
mutant "local composite action" provision.yml "s.replace('      - name: Checkout (no credentials persisted)\n', '      - uses: ./.github/actions/leak\n      - name: Checkout (no credentials persisted)\n', 1)"
mutant "repository_dispatch trigger on a checked file" release.yml "s.replace('on:\n', 'on:\n  repository_dispatch:\n', 1)"
mutant "workflow_call trigger on a checked file" release.yml "s.replace('on:\n', 'on:\n  workflow_call:\n', 1)"

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

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
