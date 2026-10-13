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
# cannot silently skip one).
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
# job sits between `anchor-dns:` and the next top-level job key — the
# boundary regex admits `_` and uppercase (a renamed `anchor_dns_helper:`
# job or a capitalised decoy key must still END the extraction, not sit
# inside it).
JOB_RAW="$(awk '/^  anchor-dns:/{f=1;next} f && /^  [A-Za-z_][A-Za-z0-9_-]*:$/{exit} f' "$PROV")"
JOB="$(printf '%s\n' "$JOB_RAW" | grep -v '^[[:space:]]*#')"
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
is "no step-level if in the job" "0" "$(printf '%s\n' "$JOB_LINES" | grep -cE '^        if:')"
is "no continue-on-error in the job" "0" "$(printf '%s\n' "$JOB_LINES" | grep -cE '^        continue-on-error')"
is "job-level if is exactly the apply gate" "1" "$(printf '%s\n' "$JOB_LINES" | grep -cE '^    if: inputs\.mode == .apply.$')"
is "exactly one write_anchor_dns source line" "1" "$(printf '%s\n' "$JOB_LINES" | grep -cE '^          \. \.github/scripts/lib/broker-dns\.sh$')"
is "exactly one write_anchor_dns call line" "1" "$(printf '%s\n' "$JOB_LINES" | grep -cE '^          write_anchor_dns "\$ANCHOR_REF" "\$ANCHOR_IPV4"$')"
is "no shadowing write_anchor_dns definition in the job" "0" "$(printf '%s\n' "$JOB_LINES" | grep -cE '^[[:space:]]*(function[[:space:]]+)?write_anchor_dns[[:space:]]*(\(\))?[[:space:]]*(\{|$)')"

# Byte-exact pin of the write step: the line pins above cannot see a
# same-indent `exit 0`/`if false` wrap, a `function` keyword shadow or an
# injected step-level `env:`, because YAML strips the body indent and bash
# does not care about the residual indentation. The whole step (comments
# included) is hashed, so any edit — however indented — must update the pin.
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
# Exactly one write step anywhere in the workflow and exactly one
# write_anchor_dns token in the job: a second (unpinned) writer step that
# runs `... || true`, or a relocated copy, is caught here.
is "exactly one write-step header in the workflow" "1" "$(grep -cE '^      - name: Upsert anchor A \+ dashboard CNAME through the broker$' "$PROV")"
is "exactly one write_anchor_dns token in the job" "1" "$(printf '%s\n' "$JOB_LINES" | grep -c 'write_anchor_dns')"

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
# The gate assertion is scoped to the unit-tests gate LINE (extracted from
# comment-stripped text): a commented-out or unrelated mention of the
# harness elsewhere in ci.yml must not satisfy it.
ci_gate="$(printf '%s\n' "$ci_live" | grep -m1 -F "elif grep -qE '^(\.github/scripts/" || true)"
[ -n "$ci_gate" ] || bad "ci.yml unit-tests gate line not found"
contains "ci path gate triggers this harness" 'broker-provision-dns' "$ci_gate"
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
# its own absence — the cross-check lives here and in managed-inputs, so
# removing either checker's line still leaves the other one to fail.
shopt -s nullglob
harnesses=(tests/*/run-test.sh)
[ ${#harnesses[@]} -gt 0 ] || bad "no tests/*/run-test.sh harnesses found"
for t in "${harnesses[@]}"; do
  # Whole-line, indentation-tolerant match: an `echo skipped # bash ...`
  # decoy or a removed line does not satisfy it (the line must be the run).
  if grep -qE "^[[:space:]]+bash ${t//./\\.}[[:space:]]*$" "$CI"; then
    ok "ci.yml run list includes $t"
  else
    bad "ci.yml run list includes $t"
  fi
done

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
