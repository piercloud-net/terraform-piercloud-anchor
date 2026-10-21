#!/usr/bin/env bash
# tests/provider-stopgap/run-test.sh — the temporary patched-provider step
# (issue #218, upstream rixlhq/terraform-provider-netcup PR #47).
#
# The step downloads a checksummed build of the community provider with the
# empty-array-as-map tolerance and installs it through `dev_overrides` for
# plan/apply only. Three properties are load-bearing and each is pinned here,
# because a silent regression in any of them is a security or correctness bug:
#
#   1. `tofu init` must run WITHOUT the override, so the committed lock file
#      still verifies the registry build (review security N3). The step must
#      therefore come AFTER init and must export TF_CLI_CONFIG_FILE only for
#      later steps.
#   2. The downloaded binary is hash-pinned: a 64-hex digest is checked with
#      `sha256sum -c` before anything uses it.
#   3. The step is scoped to `mode == 'apply'` and names the stopgap, so it is
#      deleted (not forgotten) when upstream ships the fix.
#
# Cred-free, offline: static assertions over the workflow file only.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WF="$ROOT/.github/workflows/provision.yml"

pass=0
fail=0
ok()  { pass=$((pass + 1)); printf 'ok   %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL %s\n' "$1"; }

[ -f "$WF" ] || { echo "FAIL provision.yml not found at $WF"; exit 1; }

# Line numbers of the anchors we order against.
step_line="$(grep -n 'Patched netcup provider (TEMPORARY' "$WF" | head -1 | cut -d: -f1 || true)"
init_line="$(grep -n 'tofu init -input=false -lockfile=readonly' "$WF" | head -1 | cut -d: -f1 || true)"
plan_line="$(grep -n 'name: tofu plan (ephemeral token, never state)' "$WF" | head -1 | cut -d: -f1 || true)"

if [ -n "$step_line" ] && [ -n "$init_line" ] && [ -n "$plan_line" ]; then
  ok "the stopgap step exists alongside init and plan"
else
  bad "the stopgap step (or init/plan) is missing — expected all three"
fi

if [ -n "$step_line" ] && [ -n "$init_line" ] && [ "$step_line" -gt "$init_line" ]; then
  ok "the stopgap step runs AFTER tofu init (lock-file verification unchanged)"
else
  bad "the stopgap step must run after tofu init, else init sees dev_overrides and the lock check is bypassed"
fi

if [ -n "$step_line" ] && [ -n "$plan_line" ] && [ "$step_line" -lt "$plan_line" ]; then
  ok "the stopgap step runs BEFORE tofu plan (the override is in effect for the read)"
else
  bad "the stopgap step must run before tofu plan, else the registry build reads the broken shape"
fi

# The step block: from its name line to the next `      - name:` at the same depth.
block="$(awk -v s="$step_line" 'NR>=s { if (NR>s && /^      - name:/) exit; print }' "$WF")"

case "$block" in
  *"if: inputs.mode == 'apply'"*) ok "scoped to mode=apply" ;;
  *) bad "the stopgap must be scoped to mode=apply (it is a plan/apply-only stopgap)" ;;
esac

if printf '%s\n' "$block" | grep -q 'PROVIDER_SHA256: [0-9a-f]\{64\}$'; then
  ok "the binary digest is pinned (64 hex)"
else
  bad "PROVIDER_SHA256 must be a pinned 64-hex digest"
fi

if printf '%s\n' "$block" | grep -q 'sha256sum -c'; then
  ok "the digest is verified before use"
else
  bad "the step must verify the digest with sha256sum -c before using the binary"
fi

if printf '%s\n' "$block" | grep -q 'dev_overrides'; then
  ok "the override is a dev_override (not a provider source change)"
else
  bad "the step must install through dev_overrides, not by changing the provider source"
fi

if printf '%s\n' "$block" | grep -q 'TF_CLI_CONFIG_FILE=\$rc" >> "\$GITHUB_ENV"'; then
  ok "the override is exported through \$GITHUB_ENV (later steps only)"
else
  bad "the override must be exported through \$GITHUB_ENV so tofu init never sees it"
fi

if printf '%s\n' "$block" | grep -q 'ci-allowlist:'; then
  ok "the pinned download URL carries the allowlist exemption reason"
else
  bad "the pinned download URL needs a 'ci-allowlist: <reason>' marker (the URL is outside the API allowlist)"
fi

# The step must not run with a credential it could print: no token in its env.
if printf '%s\n' "$block" | grep -qE 'NETCUP_SCP_ACCESS_TOKEN|NTFY_TOKEN|RECORDING_WITNESS_KEY'; then
  bad "the stopgap step must not carry a credential in its env"
else
  ok "no credential in the stopgap step's env"
fi

# versions.tf must still point at the community provider (no fork in the source).
if grep -q 'source *= *"rixlhq/netcup"' "$ROOT/versions.tf"; then
  ok "required_providers still points at the community provider"
else
  bad "versions.tf must keep source = rixlhq/netcup (the stopgap is not a supply-chain change)"
fi

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
