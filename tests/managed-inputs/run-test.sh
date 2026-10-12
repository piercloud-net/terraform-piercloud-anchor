#!/usr/bin/env bash
# tests/managed-inputs/run-test.sh — issue #132 managed-dispatch input preflight.
#
# The device-flow job's preflight (first step, before the banner gate and the
# device card) validates the two (a′) inputs:
#
#   tenant      — the job environment selector (`environment: <tenant>`;
#                 empty = the shared `anchor` env).
#   anchor_ref  — the account-lane key (`anchor-<ref>` concurrency group;
#                 empty = the static fallback lane).
#
# This harness binds both halves:
#   - STATIC wiring over provision.yml: the lane expression uses the input
#     and keeps the static fallback, both gated jobs carry the same dynamic
#     `environment:` expression, and the inputs are declared.
#   - BEHAVIORAL: the REAL preflight body (extracted, never a copy) runs
#     under `env -i`; a managed (tenant) dispatch without anchor_ref, bad
#     shapes and over-length values fail closed BEFORE any netcup use; a
#     well-formed managed dispatch and the empty manual/template dispatch
#     pass.
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

# ---- static wiring over provision.yml ------------------------------------
# Lane expression: input-derived, anchor-prefixed, static fallback intact.
CONC="$(awk '/^concurrency:/{f=1; next} f && /^[^ ]/{exit} f{print}' "$PROV")"
contains "lane uses the anchor_ref input" "inputs.anchor_ref" "$CONC"
contains "lane prefixes the group with anchor-" "anchor-" "$CONC"
contains "lane keeps the static fallback" "piercloud-netcup-policy" "$CONC"
is "literal static group is gone" "0" "$(grep -cE '^  group: piercloud-netcup-policy$' "$PROV")"
is "lane evaluates cancel-in-progress false" "1" "$(printf '%s' "$CONC" | grep -c 'cancel-in-progress: false')"

# Both gated jobs (device-flow, anchor-dns) carry the SAME dynamic expression;
# no literal `environment: anchor` line may remain.
is "two dynamic environment bindings" "2" "$(grep -c 'environment: \${{ inputs.tenant' "$PROV")"
is "no literal 'environment: anchor' remains" "0" "$(grep -c 'environment: anchor' "$PROV")"

# Inputs declared; the preflight validates and normalizes both.
is "tenant input declared" "1" "$(grep -c '^      tenant:$' "$PROV")"
is "anchor_ref input declared" "1" "$(grep -c '^      anchor_ref:$' "$PROV")"
contains "preflight normalizes TENANT_INPUT" 'TENANT_INPUT="${TENANT_INPUT:-}"' "$(cat "$PROV")"
contains "preflight normalizes ANCHOR_REF" 'ANCHOR_REF="${ANCHOR_REF:-}"' "$(cat "$PROV")"
contains "managed dispatch must carry the lane" "must carry anchor_ref" "$(cat "$PROV")"

# ---- behavioral binding: run the REAL preflight body ----------------------
PREFLIGHT_BODY="$WORK/preflight-body.sh"
awk '
  index($0, "- name: Managed-input preflight") { inblock=1; next }
  inblock && $0 == "        run: |" { inrun=1; next }
  inrun && /^      - name: / { exit }
  inrun { line=$0; sub(/^          /, "", line); print line }
' "$PROV" > "$PREFLIGHT_BODY"
[ -s "$PREFLIGHT_BODY" ] || { printf 'FAIL could not extract the preflight body from provision.yml\n'; exit 1; }
grep -qF 'must carry anchor_ref' "$PREFLIGHT_BODY" || { printf 'FAIL extracted body is not the managed-input preflight\n'; exit 1; }

PREFLIGHT_RUN() { # $1 tag; remaining: VAR=value pairs -> rc; stdout file
  local tag="$1"; shift
  local rc=0
  env -i PATH="$PATH" HOME="$WORK" "$@" \
    bash "$PREFLIGHT_BODY" > "$WORK/pre.$tag.out" 2> "$WORK/pre.$tag.err" || rc=$?
  printf '%s' "$rc"
}
OUT() { cat "$WORK/pre.$1.out"; }

LONG41="$(printf 'a%.0s' {1..41})"
LONG65="$(printf 'a%.0s' {1..65})"

# v0: manual/template dispatch (both empty) passes — the shared anchor env.
rc="$(PREFLIGHT_RUN v0)"
is "v0 empty inputs rc" "0" "$rc"
contains "v0 preflight ok" "Managed-input preflight ok." "$(OUT v0)"

# v1: managed (tenant) dispatch without the lane key -> fail closed.
rc="$(PREFLIGHT_RUN v1 TENANT_INPUT=foo)"
is "v1 tenant without anchor_ref rc" "1" "$rc"
contains "v1 names the lane requirement" "must carry anchor_ref" "$(OUT v1)"

# v1b: a lane key without tenant is a manual run on a managed account -> ok.
rc="$(PREFLIGHT_RUN v1b ANCHOR_REF=ok)"
is "v1b ref without tenant rc" "0" "$rc"

# v2: tenant charset (uppercase refused).
rc="$(PREFLIGHT_RUN v2 TENANT_INPUT=Foo ANCHOR_REF=ok)"
is "v2 bad tenant charset rc" "1" "$rc"
contains "v2 names the tenant shape" "tenant input must match" "$(OUT v2)"

# v3: tenant leading/trailing hyphen refused.
rc="$(PREFLIGHT_RUN v3 TENANT_INPUT=-foo ANCHOR_REF=ok)"
is "v3 leading hyphen rc" "1" "$rc"
rc="$(PREFLIGHT_RUN v3b TENANT_INPUT=foo- ANCHOR_REF=ok)"
is "v3b trailing hyphen rc" "1" "$rc"

# v4: tenant over-length refused.
rc="$(PREFLIGHT_RUN v4 "TENANT_INPUT=$LONG41" ANCHOR_REF=ok)"
is "v4 long tenant rc" "1" "$rc"
contains "v4 names the tenant length" "tenant input exceeds 40 characters" "$(OUT v4)"

# v5: anchor_ref charset refused (space).
rc="$(PREFLIGHT_RUN v5 TENANT_INPUT=foo "ANCHOR_REF=bad ref")"
is "v5 bad anchor_ref charset rc" "1" "$rc"
contains "v5 names the anchor_ref shape" "anchor_ref input must match" "$(OUT v5)"

# v6: anchor_ref over-length refused (independent of tenant).
rc="$(PREFLIGHT_RUN v6 "ANCHOR_REF=$LONG65")"
is "v6 long anchor_ref rc" "1" "$rc"
contains "v6 names the anchor_ref length" "anchor_ref input exceeds 64 characters" "$(OUT v6)"

# v7: well-formed managed dispatch passes.
rc="$(PREFLIGHT_RUN v7 TENANT_INPUT=foo ANCHOR_REF=ok-ref.1)"
is "v7 valid managed dispatch rc" "0" "$rc"
contains "v7 preflight ok" "Managed-input preflight ok." "$(OUT v7)"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
