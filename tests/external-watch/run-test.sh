#!/usr/bin/env bash
# tests/external-watch/run-test.sh — D6 "who watches the puller" (issue #186).
#
# Offline, cred-free: extracts the REAL manifest-watch block from
# .github/workflows/external-watch.yml (markers `# --- manifest-watch:start/end
# ---`; never a copy) and drives it with a PATH-stubbed curl + fixture files.
# Proves:
#   - the block is valid shell and only runs when STATUS_PULLER is enabled;
#   - the fetch discipline is the puller's (HTTPS only, no redirects, bounded
#     time/size);
#   - a fresh tenant + platform manifest whose rows all appear in the
#     dashboard's public statuses API is green;
#   - a manifest row missing from the dashboard fails (puller-timer death /
#     frozen fragment), including the seeded platform / gate / slice rows and
#     the D13-derived `shared (gate)` / `public edge` rows;
#   - a dashboard row in a parsed channel's group that the manifest does not
#     justify fails too (removal drift: a stale derived or removed site row
#     means the puller never applied the change);
#   - a manifest 5xx or an aged generated_at fails (producer staleness); a
#     404/410 is not-published (no page; the puller keeps last-known-good);
#   - TENANT_USER unset degrades to the platform channel only;
#   - #207: the per-tenant target parser (legacy fallback, flags, refusals,
#     the probe_url override rule) and the matrix/incident/ntfy wiring.
#   - #209: the LIVE env maps bind the WATCH_ names to the EXTERNAL_WATCH_*
#     secrets (duplicate keys rejected, not literal lines), and the run blocks
#     assign the channel pair only in the two pairing branches; the
#     permissions pins survive a quoted key (canonical key line) and a blank
#     line inside the block; the incident env declares exactly its five keys;
#     the targets block runs with WATCH_TENANTS unset; the docs name
#     EXTERNAL_WATCH_TENANTS in the amendment's own paragraph, list the five
#     other repo-level names it does not cover, and qualify every `v*` claim
#     in its own sentence.
set -euo pipefail

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HARNESS_DIR}/../.." && pwd)"
WATCH="${ROOT}/.github/workflows/external-watch.yml"
CI="${ROOT}/.github/workflows/ci.yml"
WORK="$(mktemp -d /tmp/external-watch.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# ---- tooling for the round-6 pin folds -------------------------------------
# PyYAML is a test dependency (tests/provider-stopgap does the same): the
# env-map pin below loads the REAL workflow, so a missing parser must fail
# loudly instead of silently skipping the pin.
python3 -I -B -c 'import yaml' 2>/dev/null || { printf 'FAIL PyYAML is required (python3-yaml)\n'; exit 1; }

# Loads the workflow with a duplicate-key-REJECTING loader (PyYAML's
# safe_load is last-wins and silently keeps a second `WATCH_NTFY_TOKEN:`) and
# reports every env map that binds a WATCH_ channel name to anything but its
# own secret, or binds one more than twice, or binds it without the repo
# fallback quintet that travels with it. Empty output = pass.
cat >"${WORK}/env-map.py" <<'PY'
import sys

import yaml

WANT = {
    "WATCH_NTFY_TOPIC": "${{ secrets.EXTERNAL_WATCH_NTFY_TOPIC }}",
    "WATCH_NTFY_TOKEN": "${{ secrets.EXTERNAL_WATCH_NTFY_TOKEN }}",
}


class StrictLoader(yaml.SafeLoader):
    """SafeLoader that refuses a duplicate mapping key instead of last-wins."""


def _strict_mapping(loader, node, deep=False):
    seen = set()
    for key_node, _value in node.value:
        if isinstance(key_node, yaml.ScalarNode):
            if key_node.value in seen:
                raise yaml.constructor.ConstructorError(
                    None, None,
                    "duplicate key %r" % key_node.value,
                    key_node.start_mark,
                )
            seen.add(key_node.value)
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _strict_mapping
)

with open(sys.argv[1], encoding="utf-8") as handle:
    document = yaml.load(handle, Loader=StrictLoader)

found = {name: [] for name in WANT}
quartet_envs = []
QUARTET = (
    "WATCH_NTFY_TOPIC",
    "WATCH_NTFY_TOKEN",
    "REPO_NTFY_TOPIC",
    "REPO_NTFY_TOKEN",
)


def walk(node, where):
    if isinstance(node, dict):
        env = node.get("env")
        if isinstance(env, dict):
            for name in WANT:
                if name in env:
                    found[name].append((where, str(env[name]).strip()))
            if any(name in env for name in WANT):
                quartet_envs.append((where, env))
        for key, child in node.items():
            walk(child, "%s.%s" % (where, key) if where else str(key))
    elif isinstance(node, list):
        for child in node:
            walk(child, where)


walk(document, "")

problems = []
for name, expected in WANT.items():
    binds = found[name]
    if len(binds) != 2:
        problems.append("%s is bound %d time(s), want 2: %r" % (name, len(binds), binds))
    for where, value in binds:
        if value != expected:
            problems.append("%s binds %r at %s, want %r" % (name, value, where, expected))
# The channel pair travels with its repo fallback, in the two steps that push:
# a binding parked in any other step's env (a decoy the count alone accepts)
# is missing the quartet.
if len(quartet_envs) != 2:
    problems.append(
        "%d env map(s) bind a WATCH_ channel name, want 2: %r"
        % (len(quartet_envs), [where for where, _env in quartet_envs])
    )
for where, env in quartet_envs:
    missing = [name for name in QUARTET if name not in env]
    if missing:
        problems.append("%s binds the watch channel without the quartet, missing %s" % (where, missing))
if problems:
    print("\n".join(problems))
    sys.exit(1)
PY

# Reports every `v*` deployment-policy claim (backticked or bare) whose OWN
# CLAIM UNIT lacks the "not verified in this repo/here" qualifier. A claim unit
# is a paragraph (wrapped lines join), a markdown list item, a table row or a
# heading, so a qualifier in the next item or row does not qualify this one.
# A decoy qualifier in another sentence does not count either. The branch glob
# `release/from-v*` is a ref pattern, not a claim.
cat >"${WORK}/vstar.py" <<'PY'
import re
import sys

CLAIM = re.compile(r"(?<![A-Za-z0-9_])v\*")
QUALIFIER = re.compile(r"not verified (in this repo|here)")
LIST_ITEM = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s")
TABLE_ROW = re.compile(r"^\s*\|")
HEADING = re.compile(r"^\s*#{1,6}\s")
BRANCH_GLOB = re.compile(r"release/from-v\*")


def clauses(unit):
    """Split a claim unit into sentences, without cutting inside a code span
    or a parenthesised aside (a `;` there is punctuation, not a new claim)."""
    out, buf, ticks, depth = [], [], 0, 0
    index = 0
    while index < len(unit):
        char = unit[index]
        if char == "`":
            ticks ^= 1
        elif not ticks and char == "(":
            depth += 1
        elif not ticks and char == ")" and depth:
            depth -= 1
        buf.append(char)
        if not ticks and not depth and char in ".!?;":
            after = index + 1
            if after >= len(unit) or unit[after].isspace():
                out.append("".join(buf))
                buf = []
                while after < len(unit) and unit[after].isspace():
                    after += 1
                index = after - 1
        index += 1
    if buf:
        out.append("".join(buf))
    return out


def units(path, text):
    markdown = path.endswith(".md")
    current = []
    for raw in text.splitlines():
        if not raw.strip():
            if current:
                yield " ".join(current)
                current = []
            continue
        starts = LIST_ITEM.match(raw) or TABLE_ROW.match(raw) or (markdown and HEADING.match(raw))
        if starts and current:
            yield " ".join(current)
            current = []
        current.append(raw.strip())
    if current:
        yield " ".join(current)


problems = []
for path in sys.argv[1:]:
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    for unit in units(path, text):
        for sentence in clauses(BRANCH_GLOB.sub("release/from-vX", unit)):
            if CLAIM.search(sentence) and not QUALIFIER.search(sentence):
                problems.append("%s: %s" % (path, sentence.strip()[:200]))
if problems:
    print("\n".join(problems))
    sys.exit(1)
PY

pass=0
fail=0
MIN_CHECKS=290
ok()  { pass=$((pass + 1)); printf 'ok   %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL %s\n' "$1"; }
is()  { # $1 label, $2 expected, $3 actual
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi
}
has() { case "$2" in *"$3"*) ok "$1" ;; *) bad "$1 (missing: $3)" ;; esac; }
lacks() { case "$2" in *"$3"*) bad "$1 (unexpected: $3)" ;; *) ok "$1" ;; esac; }

# ---- extract the real block ------------------------------------------------
start="$(grep -n 'manifest-watch:start' "$WATCH" | cut -d: -f1)"
end="$(grep -n 'manifest-watch:end' "$WATCH" | cut -d: -f1)"
[ -n "$start" ] && [ -n "$end" ] || { printf 'FAIL markers not found\n'; exit 1; }
sed -n "$((start + 1)),$((end - 1))p" "$WATCH" | sed 's/^            //' >"${WORK}/block.sh"
[ -s "${WORK}/block.sh" ] || { printf 'FAIL extracted block is empty\n'; exit 1; }
if bash -n "${WORK}/block.sh"; then ok "extracted block parses (bash -n)"; else bad "extracted block fails bash -n"; fi
has "block gates on STATUS_PULLER" "$(cat "${WORK}/block.sh")" 'case "${STATUS_PULLER:-}" in'
has "block pins =https" "$(cat "${WORK}/block.sh")" "--proto '=https'"
has "block forbids redirects" "$(cat "${WORK}/block.sh")" "--max-redirs 0"
has "block caps time" "$(cat "${WORK}/block.sh")" "--max-time 20"
has "block caps size" "$(cat "${WORK}/block.sh")" "--max-filesize 65536"
has "block checks freshness" "$(cat "${WORK}/block.sh")" "generated_at"
has "block diffs the dashboard keys" "$(cat "${WORK}/block.sh")" "missing from the dashboard"
has "block flags stale dashboard rows" "$(cat "${WORK}/block.sh")" "stale dashboard rows not in the manifest"
has "block counts the seeded rows" "$(cat "${WORK}/block.sh")" 'name:"your piercloud"'
has "block counts the gate row" "$(cat "${WORK}/block.sh")" 'name:"private (gate)"'
has "block expects the derived shared gate row" "$(cat "${WORK}/block.sh")" 'shared (gate)'
has "block expects the derived public edge row" "$(cat "${WORK}/block.sh")" 'public edge'
lacks "block never uses the jq // empty boolean shape" "$(cat "${WORK}/block.sh")" "// empty"

# ---- stub curl -------------------------------------------------------------
mkdir -p "${WORK}/bin"
cat >"${WORK}/bin/curl" <<'STUB'
#!/usr/bin/env bash
set -u
dir="${STUB_CURL_DIR:?}"
body=""; writefmt=""; url=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) body="$2"; shift 2 ;;
    -w) writefmt="$2"; shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
key="$(printf '%s' "$url" | tr -c 'A-Za-z0-9' '_')"
printf '%s\n' "$url" >>"${dir}/calls.txt"
code="$(cat "${dir}/${key}.code" 2>/dev/null || printf 200)"
[ -n "$body" ] && cp "${dir}/${key}.body" "$body" 2>/dev/null || true
[ -n "$writefmt" ] && printf '%s' "$code"
exit 0
STUB
chmod +x "${WORK}/bin/curl"
export PATH="${WORK}/bin:${PATH}"

TENANT_URL="https://meta-pier.piercloud.site/.well-known/pc-status.json"
PLATFORM_URL="https://platform.piercloud.net/.well-known/pc-status.json"
tenant_key="$(printf '%s' "$TENANT_URL" | tr -c 'A-Za-z0-9' '_')"
platform_key="$(printf '%s' "$PLATFORM_URL" | tr -c 'A-Za-z0-9' '_')"

write_fixtures() { # $1 case dir
  mkdir -p "$1"
  python3 - "$1" <<'PY'
import datetime
import json
import sys
case = sys.argv[1]
now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
tenant = {
    "version": 1, "generated_at": now, "tenant": "pier",
    "endpoints": [
        {"name": "blog", "url": "https://blog-pier.piercloud.site", "alerts": True, "type": "public"},
        {"name": "gone", "url": "https://gone-pier.piercloud.site", "disabled": True, "type": "public"},
    ],
}
platform = {
    "version": 1, "generated_at": now,
    "platform": [{"name": "platform", "url": "https://platform.piercloud.net/healthz"}],
    "hosts": [{"name": "host-01", "url": "https://host-01.piercloud.net/healthz"}],
}
open(case + "/tenant.json", "w").write(json.dumps(tenant))
open(case + "/platform.json", "w").write(json.dumps(platform))
PY
}

run_block() { # $1 case dir; env: STATUS_PULLER, TENANT_USER, plus optional api override
  local dir="$1"
  rm -f "$dir/calls.txt"
  ( cd "$dir" && work="$dir" fail="" STUB_CURL_DIR="$dir" \
      STATUS_PULLER="${STATUS_PULLER-on}" TENANT_USER="${TENANT_USER-pier}" \
      bash -c 'set -uo pipefail; source "$0"; printf "%s" "${fail:-}"' "${WORK}/block.sh" )
}

new_case() { # $1 name
  CASE="${WORK}/case-$1"
  rm -rf "$CASE"
  write_fixtures "$CASE"
  cp "$CASE/tenant.json" "$CASE/${tenant_key}.body"
  cp "$CASE/platform.json" "$CASE/${platform_key}.body"
  printf '200' >"$CASE/${tenant_key}.code"
  printf '200' >"$CASE/${platform_key}.code"
}

api_json() { # stdin = rows array, writes $CASE/api
  cat >"$CASE/api"
}

# ---- green: all manifest rows + seeded rows present ------------------------
new_case green
printf '[{"name":"platform","group":"platform"},{"name":"your piercloud","group":"pier"},{"name":"private (gate)","group":"pier"},{"name":"host-01","group":"platform"},{"name":"blog","group":"pier"}]' | api_json
out="$(run_block "$CASE")"
is "green: no manifest failure" "" "$out"
has "green: both manifests fetched" "$(cat "$CASE/calls.txt")" "$TENANT_URL"
has "green: platform manifest fetched" "$(cat "$CASE/calls.txt")" "$PLATFORM_URL"

# ---- a missing manifest row fails (puller death / frozen fragment) ---------
new_case missing
printf '[{"name":"platform","group":"platform"},{"name":"your piercloud","group":"pier"},{"name":"private (gate)","group":"pier"},{"name":"host-01","group":"platform"}]' | api_json
out="$(run_block "$CASE")"
has "missing: names the missing row" "$out" "pier/blog"
has "missing: reports a manifest watch failure" "$out" "missing from the dashboard"

new_case missing-seed
printf '[{"name":"platform","group":"platform"},{"name":"your piercloud","group":"pier"},{"name":"host-01","group":"platform"},{"name":"blog","group":"pier"}]' | api_json
out="$(run_block "$CASE")"
has "missing seed: names the gate row" "$out" "pier/private (gate)"

# ---- disabled entries are not expected -------------------------------------
new_case disabled
printf '[{"name":"platform","group":"platform"},{"name":"your piercloud","group":"pier"},{"name":"private (gate)","group":"pier"},{"name":"host-01","group":"platform"},{"name":"blog","group":"pier"}]' | api_json
out="$(run_block "$CASE")"
lacks "disabled entries are not required" "$out" "gone"

# ---- D13: a shared entry makes the derived gate row expected ---------------
add_shared() {
  python3 - "$CASE/tenant.json" <<'PY'
import json
import sys
doc = json.load(open(sys.argv[1]))
doc["endpoints"].append({"name": "fantasy", "url": "https://fantasy.pier.piercloud.net",
                         "alerts": True, "type": "shared"})
open(sys.argv[1], "w").write(json.dumps(doc))
PY
  cp "$CASE/tenant.json" "$CASE/${tenant_key}.body"
}

new_case shared
add_shared
printf '[{"name":"platform","group":"platform"},{"name":"your piercloud","group":"pier"},{"name":"private (gate)","group":"pier"},{"name":"shared (gate)","group":"pier"},{"name":"host-01","group":"platform"},{"name":"blog","group":"pier"}]' | api_json
out="$(run_block "$CASE")"
is "shared: derived gate row satisfies the check" "" "$out"
lacks "shared: the shared entry is not expected as a row" "$(cat "$CASE/manifest-expected.json")" '"fantasy"'

new_case shared-missing
add_shared
printf '[{"name":"platform","group":"platform"},{"name":"your piercloud","group":"pier"},{"name":"private (gate)","group":"pier"},{"name":"host-01","group":"platform"},{"name":"blog","group":"pier"}]' | api_json
out="$(run_block "$CASE")"
has "shared missing: names the derived row" "$out" "pier/shared (gate)"

# ---- D13 removal drift: a stale row the manifest does not justify fails ----
new_case stale-derived
printf '[{"name":"platform","group":"platform"},{"name":"your piercloud","group":"pier"},{"name":"private (gate)","group":"pier"},{"name":"shared (gate)","group":"pier"},{"name":"host-01","group":"platform"},{"name":"blog","group":"pier"}]' | api_json
out="$(run_block "$CASE")"
has "stale derived: names the stale row" "$out" "pier/shared (gate)"
has "stale derived: reports the removal drift" "$out" "stale dashboard rows not in the manifest"

new_case stale-site
printf '[{"name":"platform","group":"platform"},{"name":"your piercloud","group":"pier"},{"name":"private (gate)","group":"pier"},{"name":"host-01","group":"platform"},{"name":"blog","group":"pier"},{"name":"old-site","group":"pier"}]' | api_json
out="$(run_block "$CASE")"
has "stale site: names the removed row" "$out" "pier/old-site"

# ---- D13: platform `edge: true` makes the public edge row expected ---------
add_edge() {
  python3 - "$CASE/platform.json" <<'PY'
import json
import sys
doc = json.load(open(sys.argv[1]))
doc["edge"] = True
open(sys.argv[1], "w").write(json.dumps(doc))
PY
  cp "$CASE/platform.json" "$CASE/${platform_key}.body"
}

new_case edge
add_edge
printf '[{"name":"platform","group":"platform"},{"name":"your piercloud","group":"pier"},{"name":"private (gate)","group":"pier"},{"name":"host-01","group":"platform"},{"name":"blog","group":"pier"},{"name":"public edge","group":"platform"}]' | api_json
out="$(run_block "$CASE")"
is "edge: derived row satisfies the check" "" "$out"

new_case edge-missing
add_edge
printf '[{"name":"platform","group":"platform"},{"name":"your piercloud","group":"pier"},{"name":"private (gate)","group":"pier"},{"name":"host-01","group":"platform"},{"name":"blog","group":"pier"}]' | api_json
out="$(run_block "$CASE")"
has "edge missing: names the derived row" "$out" "platform/public edge"

# ---- 404/410 is not-published: no page (puller keeps last-known-good) ------
new_case notfound
printf '[{"name":"platform","group":"platform"},{"name":"your piercloud","group":"pier"},{"name":"private (gate)","group":"pier"},{"name":"blog","group":"pier"}]' | api_json
printf '404' >"$CASE/${platform_key}.code"
out="$(run_block "$CASE")"
has "404/410: not published is logged, not failed" "$out" "not published (HTTP 404)"
lacks "404/410: no HTTP-failure verdict" "$out" "manifest HTTP 404"

# ---- a 5xx fetch failure still fails ---------------------------------------
new_case server-error
printf '[{"name":"platform","group":"platform"}]' | api_json
printf '500' >"$CASE/${platform_key}.code"
out="$(run_block "$CASE")"
has "5xx: reported as an HTTP failure" "$out" "platform manifest HTTP 500"

# ---- stale generated_at fails ----------------------------------------------
new_case stale
python3 - "$CASE/tenant.json" <<'PY'
import json
import sys
doc = json.load(open(sys.argv[1]))
doc["generated_at"] = "2000-01-01T00:00:00Z"
open(sys.argv[1], "w").write(json.dumps(doc))
PY
cp "$CASE/tenant.json" "$CASE/${tenant_key}.body"
printf '[{"name":"platform","group":"platform"},{"name":"your piercloud","group":"pier"},{"name":"private (gate)","group":"pier"},{"name":"host-01","group":"platform"},{"name":"blog","group":"pier"}]' | api_json
out="$(run_block "$CASE")"
has "stale: reported as stale" "$out" "tenant manifest stale"

# ---- switch off: no fetch at all -------------------------------------------
new_case off
printf '[]' | api_json
out="$(STATUS_PULLER="" run_block "$CASE")"
is "switch off: block is a no-op" "" "$out"
[ ! -e "$CASE/calls.txt" ] && ok "switch off: no manifest fetch" || bad "switch off: no manifest fetch"

# ---- TENANT_USER unset: platform channel only ------------------------------
new_case noalias
printf '[{"name":"platform","group":"platform"},{"name":"host-01","group":"platform"}]' | api_json
out="$(TENANT_USER="" run_block "$CASE")"
lacks "no alias: no manifest failure" "$out" "missing from the dashboard"
has "no alias: platform-only notice" "$out" "TENANT_USER unset"
lacks "no alias: tenant manifest not fetched" "$(cat "$CASE/calls.txt")" "$TENANT_URL"

# ---- #207: watch targets (per-tenant matrix) ------------------------------
tstart="$(grep -n 'watch-targets:start' "$WATCH" | cut -d: -f1)"
tend="$(grep -n 'watch-targets:end' "$WATCH" | cut -d: -f1)"
if [ -n "$tstart" ] && [ -n "$tend" ]; then ok "targets markers present"; else bad "targets markers present"; fi
sed -n "$((tstart + 1)),$((tend - 1))p" "$WATCH" | sed 's/^          //' >"${WORK}/targets.sh"
if bash -n "${WORK}/targets.sh"; then ok "targets block parses (bash -n)"; else bad "targets block fails bash -n"; fi

targets() { # env: WATCH_TENANTS [WATCH_TENANTS_UNSET=1] PROBE_OVERRIDE LEGACY_*; prints "0|matrix", "refused|reason|matrix" or "rc|output"
  local out rc refused tenv
  # WATCH_TENANTS_UNSET drives the block's own unset default
  # (`WATCH_TENANTS="${WATCH_TENANTS-}"`, red-team r5 F2): Actions always sets
  # the variable, so only `env -u` reaches that line.
  if [ "${WATCH_TENANTS_UNSET:-}" = 1 ]; then
    tenv=(-u WATCH_TENANTS)
  else
    tenv=("WATCH_TENANTS=${WATCH_TENANTS-}")
  fi
  out="$( ( cd "$WORK" && env -u GITHUB_OUTPUT "${tenv[@]}" \
      PROBE_OVERRIDE="${PROBE_OVERRIDE-}" \
      LEGACY_PROBE_URL="${LEGACY_PROBE_URL-}" LEGACY_STATUS_PULLER="${LEGACY_STATUS_PULLER-}" \
      LEGACY_TENANT_USER="${LEGACY_TENANT_USER-}" GITHUB_OUTPUT="$WORK/gh_out" \
      LC_ALL="${TARGETS_LC_ALL-en_US.UTF-8}" \
      bash "${WORK}/targets.sh" ) 2>&1 )" && rc=0 || rc=$?
  if [ "$rc" -eq 0 ]; then
    refused="$(sed -n 's/^refused=//p' "$WORK/gh_out" | tail -n1)"
    if [ -n "$refused" ]; then
      printf 'refused|%s|%s' "$refused" "$(sed -n 's/^matrix=//p' "$WORK/gh_out" | tail -n1)"
    else
      printf '0|%s' "$(sed -n 's/^matrix=//p' "$WORK/gh_out" | tail -n1)"
    fi
    printf '\n%s' "$out" >"$WORK/last_out"
  else
    printf '%s|%s' "$rc" "$out"
  fi
  rm -f "$WORK/gh_out"
}

r="$(WATCH_TENANTS="" LEGACY_TENANT_USER=pier LEGACY_STATUS_PULLER=on LEGACY_PROBE_URL=https://pier.status.piercloud.net/ targets)"
is "legacy: unset list = one legacy target" '0|[{"alias":"pier","label":"","puller":"on","probe_url":"https://pier.status.piercloud.net/","legacy":true}]' "$r"
r="$(WATCH_TENANTS=" , " LEGACY_TENANT_USER=pier LEGACY_STATUS_PULLER=no targets)"
is "legacy: blank list + puller off" '0|[{"alias":"pier","label":"","puller":"","probe_url":"","legacy":true}]' "$r"
# Functional r5 F2 (#209): the unset-safe default is only reachable with the
# variable absent; under the block's own `set -u` a bare `${WATCH_TENANTS}`
# aborts the targets job (no matrix, every leg skipped).
r="$(WATCH_TENANTS_UNSET=1 LEGACY_TENANT_USER=pier LEGACY_STATUS_PULLER=on LEGACY_PROBE_URL=https://pier.status.piercloud.net/ targets)"
is "unset WATCH_TENANTS: the - default keeps the legacy target" '0|[{"alias":"pier","label":"","puller":"on","probe_url":"https://pier.status.piercloud.net/","legacy":true}]' "$r"
r="$(WATCH_TENANTS_UNSET=1 LEGACY_TENANT_USER=zed PROBE_OVERRIDE=https://b.example/ targets)"
has "unset WATCH_TENANTS: the override still applies" "$r" '"probe_url":"https://b.example/"'
# Functional r3 F2: the legacy puller mapping (same accepted set as the puller).
for pv in 1 true yes on; do
  r="$(WATCH_TENANTS="" LEGACY_TENANT_USER=pier LEGACY_STATUS_PULLER="$pv" targets)"
  has "legacy: puller '${pv}' maps to on" "$r" '"puller":"on"'
done
for pv in 0 false no off ON True; do
  r="$(WATCH_TENANTS="" LEGACY_TENANT_USER=pier LEGACY_STATUS_PULLER="$pv" targets)"
  has "legacy: puller '${pv}' maps to off" "$r" '"puller":""'
done
r="$(WATCH_TENANTS="" LEGACY_PROBE_URL=https://a.example/ PROBE_OVERRIDE=https://b.example/ targets)"
has "legacy: probe_url override wins" "$r" '"probe_url":"https://b.example/"'

r="$(WATCH_TENANTS="pier:puller, alice bob:puller" LEGACY_STATUS_PULLER=on LEGACY_TENANT_USER=zed targets)"
is "list: three legs, flags, nested URLs, legacy values ignored" \
  '0|[{"alias":"pier","label":"pier","puller":"on","probe_url":"https://pier.status.piercloud.net/","legacy":false},{"alias":"alice","label":"alice","puller":"","probe_url":"https://alice.status.piercloud.net/","legacy":false},{"alias":"bob","label":"bob","puller":"on","probe_url":"https://bob.status.piercloud.net/","legacy":false}]' "$r"
r="$(WATCH_TENANTS="pier:puller" PROBE_OVERRIDE=https://x.example/ targets)"
has "list: single target takes the override" "$r" '"probe_url":"https://x.example/"'

refuses() { # $1 label, $2 list, $3 expected message fragment, [$4 override]
  local r legacy
  r="$(WATCH_TENANTS="$2" PROBE_OVERRIDE="${4-}" LEGACY_TENANT_USER=zed LEGACY_PROBE_URL=https://zed.example/ targets)"
  legacy='[{"alias":"zed","label":"","puller":"","probe_url":"'"${4:-https://zed.example/}"'","legacy":true}]'
  case "$r" in
    refused\|*)
      has "$1" "$r" "$3"
      is "$1: falls back to the legacy target" "$legacy" "${r##*|}" ;;
    *) bad "$1 (not refused: $r)" ;;
  esac
}
refuses "refuse: override with two targets" "pier alice" "overrides exactly one target" "https://x.example/"
refuses "refuse: duplicate alias" "pier pier:puller" "entry 2: duplicate alias"
refuses "refuse: unknown flag" "pier:loud" "entry 1: unknown flag"
refuses "refuse: empty flag" "pier:" "entry 1: empty flag"
refuses "refuse: double flag" "pier:puller:x" "entry 1: unknown flag"
refuses "refuse: uppercase alias" "Pier" "entry 1: bad alias"
refuses "refuse: hyphen" "pier-2" "entry 1: bad alias"
refuses "refuse: underscore" "pier_2" "entry 1: bad alias"
refuses "refuse: host injection" "pier.evil.example" "entry 1: bad alias"
refuses "refuse: path injection" "pier/x" "entry 1: bad alias"
refuses "refuse: 2 chars" "ab" "entry 1: bad alias"
refuses "refuse: 16 chars" "$(printf 'a%.0s' $(seq 1 16))" "bad alias"
refuses "refuse: glob stays a word" "*" "entry 1: bad alias"
# Trust r2 F1: a refused entry's text reaches the public log, the config
# incident and ntfy, so the reason names the position and rule, never the value.
for sv in 'trust-sentinel-xyz' 'pier trust-sentinel-xyz' 'pier:trust-sentinel-xyz' 'Trust-Sentinel'; do
  r="$(WATCH_TENANTS="$sv" LEGACY_TENANT_USER=zed targets 2>&1)"
  case "$r" in
    refused\|*) case "$r" in *[Ss]entinel*) bad "refusal never echoes the entry ('${sv}')" ;; *) ok "refusal never echoes the entry ('${sv}')" ;; esac ;;
    *) bad "sentinel list refused ('${sv}'): $r" ;;
  esac
done
refuses "refuse: reserved prefix status" "statusx" "reserved prefix"
refuses "refuse: reserved prefix pcu" "pcu12345" "reserved prefix"
refuses "refuse: reserved prefix anchor" "anchor01" "reserved prefix"
refuses "refuse: reserved prefix platform" "platformx" "reserved prefix"
for rn in edge console ops keys unlock bounce mail broker www; do
  refuses "refuse: reserved name ${rn}" "$rn" "reserved platform name"
done
# Locale (#208 round 1): the caller's UTF-8 locale must not widen [a-z].
for na in 'pièr' 'aéb' 'ßab' 'ａｂｃ'; do refuses "refuse: non-ASCII '${na}' under a UTF-8 locale" "$na" "bad alias"; done
refuses "refuse: fullwidth digit 'pier２'" 'pier２' "bad alias"
# Unicode-space-only list: never the silent legacy path (C locale: not [[:space:]]).
refuses "refuse: U+2003-only list" $'\u2003' "bad alias"
refuses "refuse: U+3000-only list" $'\u3000' "bad alias"
# Functional r3 F1: ASCII control whitespace the gate saw as blank but the
# parser (IFS split) sees as a word.
refuses "refuse: CR-only list" $'\r' "bad alias"
refuses "refuse: VT-only list" $'\v' "bad alias"
refuses "refuse: FF-only list" $'\f' "bad alias"
# Functional r4 F2: the gate strips the separator BYTES, never the letters t/n
# or a backslash (an over-wide bracket would turn these into the legacy path).
r="$(WATCH_TENANTS="tnt" targets)"
is "accept: alias of only t/n letters is one tenant leg" '0|[{"alias":"tnt","label":"tnt","puller":"","probe_url":"https://tnt.status.piercloud.net/","legacy":false}]' "$r"
refuses "refuse: backslash-only list" '\\' "bad alias"
refuses "refuse: t/n-only short list" "tn" "bad alias"
r="$(WATCH_TENANTS=$' \t\n, ' LEGACY_TENANT_USER=pier targets)"
case "$r" in 0\|*'"legacy":true'*) ok "legacy: space/tab/newline/comma-only list" ;; *) bad "legacy: space/tab/newline/comma-only list ($r)" ;; esac
refuses "refuse: 257 tenants (matrix cap)" "$(for i in $(seq 100 356); do printf 'abc%s ' "$i"; done)" "exceed the 256-leg matrix cap"
r="$(WATCH_TENANTS="$(for i in $(seq 100 355); do printf 'abc%s ' "$i"; done)" targets)"
case "$r" in 0\|*) ok "accept: 256 tenants" ;; *) bad "accept: 256 tenants (${r:0:120})" ;; esac
r="$(TARGETS_LC_ALL=C.UTF-8 WATCH_TENANTS='pièr' LEGACY_TENANT_USER=zed LEGACY_PROBE_URL=https://zed.example/ targets)"
case "$r" in refused\|*) ok "refuse: non-ASCII under C.UTF-8" ;; *) bad "refuse: non-ASCII under C.UTF-8 ($r)" ;; esac
r="$(WATCH_TENANTS="$(printf 'a%.0s' $(seq 1 15))" targets)"
case "$r" in 0\|*) ok "accept: 15-char alias" ;; *) bad "accept: 15-char alias ($r)" ;; esac
r="$(WATCH_TENANTS="p1x" targets)"
case "$r" in 0\|*) ok "accept: 3-char digit alias" ;; *) bad "accept: 3-char digit alias ($r)" ;; esac
# The refusal is loud in the log and the targets line prints a count, never the aliases.
r="$(WATCH_TENANTS="pier Pier" LEGACY_TENANT_USER=zed targets)"
has "refusal: ::error:: line names the fallback" "$(cat "$WORK/last_out")" "falling back to the legacy single target"
r="$(WATCH_TENANTS="alice bob" targets)"
is "targets line: count only" "watch targets: 2 (per-tenant)" "$(grep '^watch targets:' "$WORK/last_out")"
lacks "targets line: no alias list" "$(grep '^watch targets:' "$WORK/last_out")" "alice"

# Wiring: the legs read the matrix, never the repo-level switch / target.
wf="$(cat "$WATCH")"
has "watch job is a matrix over the targets output" "$wf" 'target: ${{ fromJSON(needs.targets.outputs.matrix) }}'
has "probe reads the leg URL" "$wf" 'PROBE_URL: ${{ matrix.target.probe_url }}'
has "probe reads the leg puller flag" "$wf" 'STATUS_PULLER: ${{ matrix.target.puller }}'
has "probe reads the leg alias" "$wf" 'TENANT_USER: ${{ matrix.target.alias }}'
is "probe never reads repo-level STATUS_PULLER/TENANT_USER directly" "0" \
  "$(grep -cE '^[[:space:]]+(STATUS_PULLER|TENANT_USER|PROBE_URL): \$\{\{ (vars|inputs)\.' "$WATCH" || true)"
has "incident title is per tenant" "$wf" 'prefix="[external-watch] ${WATCH_ALIAS:+${WATCH_ALIAS}: }dashboard probe failing:"'
has "incident lookup filters by the tenant prefix" "$wf" 'select(.title | startswith($p))'
is "incident + ntfy read the leg label (blank on the legacy leg)" "2" "$(grep -c 'WATCH_ALIAS: ${{ matrix.target.label }}' "$WATCH")"
has "watch ntfy topic is read" "$wf" 'WATCH_NTFY_TOPIC: ${{ secrets.EXTERNAL_WATCH_NTFY_TOPIC }}'
has "topic/token pair never crosses channels" "$wf" 'NTFY_TOPIC="$WATCH_NTFY_TOPIC"; NTFY_TOKEN="${WATCH_NTFY_TOKEN:-}"'
is "fail-fast stays off (a failed leg never cancels the other tenants)" "1" "$(grep -c '^      fail-fast: false$' "$WATCH")"
is "incident lookups read up to 100 open issues (leg + config)" "2" "$(grep -c 'gh issue list --label "$label" --state open --limit 100 --json number,title' "$WATCH")"
is "repo fallback pairs the repo topic with the repo token (leg + config)" "2" "$(grep -c 'NTFY_TOPIC="${REPO_NTFY_TOPIC:-}"; NTFY_TOKEN="${REPO_NTFY_TOKEN:-}"' "$WATCH")"
is "watch-channel pair (leg + config)" "2" "$(grep -c 'NTFY_TOPIC="$WATCH_NTFY_TOPIC"; NTFY_TOKEN="${WATCH_NTFY_TOKEN:-}"' "$WATCH")"
# Trust r5 F2 + r6 F2 (#209 fold): the amendment's own PARAGRAPH — the
# blockquote under its heading, not the section (a Rationale mention must not
# satisfy the pin) — must name the repository variable the same PR ships, and
# must not claim the repository-level surface is complete: the watch reads
# five more repo-level names (trust r6 F1).
inv_file="${ROOT}/docs/invariants.md"
amend="$(awk '
  /^### Scoped amendment/ && /push channel/ { f = 1; print; next }
  f && /^>/ { started = 1; print; next }
  f && !started && /^[[:space:]]*$/ { next }
  f { exit }
' "$inv_file")"
has "invariant 4 amendment names the repo variable EXTERNAL_WATCH_TENANTS" "$amend" 'EXTERNAL_WATCH_TENANTS'
has "invariant 4 amendment names its own topic secret" "$amend" 'EXTERNAL_WATCH_NTFY_TOPIC'
has "invariant 4 amendment names its own token secret" "$amend" 'EXTERNAL_WATCH_NTFY_TOKEN'
lacks "amendment extraction stops at the paragraph (not the Rationale)" "$amend" '**Rationale.**'
lacks "amendment does not claim the repository-level surface is complete" "$amend" 'surface is complete'
bt='`'
for rn in vars.STATUS_PROBE_URL vars.STATUS_PULLER vars.TENANT_USER secrets.NTFY_TOPIC secrets.NTFY_TOKEN; do
  has "amendment names ${bt}${rn#*.}${bt} as outside the carve-out" "$amend" "${bt}${rn#*.}${bt}"
done
is "each of those five names is really read by external-watch.yml" "0" \
  "$(for rn in vars.STATUS_PROBE_URL vars.STATUS_PULLER vars.TENANT_USER secrets.NTFY_TOPIC secrets.NTFY_TOKEN; do
       grep -qE -- "(^|[^A-Za-z0-9_])${rn//./[.]}([^A-Za-z0-9_]|$)" "$WATCH" || printf '%s\n' "$rn"
     done | grep -c . || true)"
# Trust r5 F4 + r6 F4 (#209 fold): every `v*` deployment-policy claim carries
# the same "not verified in this repo" qualifier as docs/invariants.md.
# Discover the claim files from the repo (a hardcoded list would miss a new
# doc) and require the qualifier in the CLAIM'S OWN SENTENCE (a decoy
# elsewhere on the line does not count). The reviewed set below is a gate: a
# new file holding the claim must be reviewed and added here, qualified or
# not.
vstar_rc=0
vstar_files="$(cd "$ROOT" && git grep -l -E '(^|[^A-Za-z0-9_])v[*]' -- '*.md' .github/workflows)" || vstar_rc=$?
is "v* claim pin: the discovery grep ran (a git work tree is present)" "0" "$vstar_rc"
is "v* claim files are the reviewed set (discovered, not hardcoded)" ".github/workflows/external-watch.yml
docs/conventions.md
docs/dr.md
docs/invariants.md
docs/usage.md" "$vstar_files"
# shellcheck disable=SC2086  # repo paths, never whitespace
unq="$(cd "$ROOT" && python3 -I -B "${WORK}/vstar.py" $vstar_files 2>&1)" || true
is "every v* claim carries the qualifier in its own sentence" "" "$unq"
cfg="$(awk '/^  config:$/{f=1} /^  watch:$/{f=0} f' "$WATCH")"
has "config job waits on targets" "$cfg" "needs: targets"
is "config job always runs (exact line, no extra condition)" "1" "$(printf '%s\n' "$cfg" | grep -cx '    if: always()' || true)"
has "config job reads the targets result" "$cfg" 'TARGETS_RESULT: ${{ needs.targets.result }}'
has "config job reads the refusal" "$cfg" 'REFUSED: ${{ needs.targets.outputs.refused }}'
has "config job fails the run while refused" "$cfg" 'exit 1'
has "targets job exports the refusal" "$wf" 'refused: ${{ steps.targets.outputs.refused }}'
has "job name uses the label (legacy name unchanged)" "$wf" "name: probe \${{ matrix.target.label || 'the dashboard' }} from GitHub's network"
# Invariant 4 carve-out (#208 round 1): the watch channel names are read by
# external-watch.yml only, never by a managed run. The amendment's "Enforced
# by" line covers the repository variable too (#209).
# Trust r3 F1: never vacuous — outside a git work tree the pin fails loudly.
ewn_only() { # $1 grep pattern, $2 label
  local ewn_rc=0 ewn
  ewn="$(cd "$ROOT" && git grep -l "$1" -- .github scripts ':!.github/workflows/external-watch.yml')" || ewn_rc=$?
  # git grep: 0 = matches, 1 = none, anything else = error.
  case "$ewn_rc" in
    1) ok "$2 read only by external-watch.yml" ;;
    0) bad "$2 read only by external-watch.yml (also in: ${ewn})" ;;
    *) bad "$2 pin: git grep failed (rc ${ewn_rc})" ;;
  esac
}
if (cd "$ROOT" && git rev-parse --is-inside-work-tree >/dev/null 2>&1); then
  ewn_only 'EXTERNAL_WATCH_NTFY_' 'EXTERNAL_WATCH_NTFY_*'
  ewn_only 'EXTERNAL_WATCH_TENANTS' 'EXTERNAL_WATCH_TENANTS'
  is "external-watch.yml itself is tracked (the pin scope is real)" "1" \
    "$(cd "$ROOT" && git ls-files -- .github/workflows/external-watch.yml | wc -l | tr -d ' ')"
else
  bad "EXTERNAL_WATCH_NTFY_* pin needs a git work tree (refusing to pass vacuously)"
fi
has "invariant 4 carries the scoped watch-channel amendment" "$(cat "${ROOT}/docs/invariants.md")" "Scoped amendment — the external watch's own push channel"
lacks "watch names are not in the managed repo-scope list" "$(cat "${ROOT}/.github/workflows/provision.yml")" 'EXTERNAL_WATCH_'
# Red-team r6 F3 (#209 fold): the literal greps above cannot see a
# split-literal or a dynamic index — `vars[format('{0}{1}', 'EXTERNAL',
# '_WATCH_TENANTS')]` contains both halves. Scan the FRAGMENTS any such
# spelling must contain, so no name can be assembled outside the watch file.
ewn_frag() { # $1 fragment, $2 label
  local frc=0 fhits
  fhits="$(cd "$ROOT" && git grep -l -F -- "$1" -- .github scripts ':!.github/workflows/external-watch.yml')" || frc=$?
  case "$frc" in
    1) ok "$2: no fragment '$1' outside external-watch.yml" ;;
    0) bad "$2: fragment '$1' also in: ${fhits}" ;;
    *) bad "$2: git grep failed (rc ${frc})" ;;
  esac
}
ewn_frag 'EXTERNAL' 'the external-watch carve-out names'
ewn_frag 'WATCH_NTFY' 'the watch push-channel names'
ewn_frag 'WATCH_TENANTS' 'the watched-tenant variable'
# The repo-scope refusal step is the control that keeps a repository-level
# copy out of a managed run, so a computed probe name (which no name grep can
# see) has to red: every REPO_SCOPE_ probe must be a literal secret/var read.
PROV="${ROOT}/.github/workflows/provision.yml"
scopestep="$(awk '/^      - name: Repo-scope check/{f=1;next} f&&/^      - name:/{exit} f' "$PROV")"
ro_keys="$(printf '%s\n' "$scopestep" | grep -cE '^[[:space:]]*REPO_SCOPE_[A-Z0-9_]+:' || true)"
ro_lit="$(printf '%s\n' "$scopestep" | grep -cE '^[[:space:]]*REPO_SCOPE_[A-Z0-9_]+: [$][{][{] (secrets|vars)[.][A-Za-z0-9_]+ !=' || true)"
is "repo-scope probe list is non-empty (the pin is not vacuous)" "1" "$([ "$ro_keys" -gt 0 ] && printf 1 || printf 0)"
is "repo-scope probes are literal secret/var reads" "$ro_keys" "$ro_lit"
is "repo-scope step has no dynamic vars[]/secrets[] indexing" "0" \
  "$(printf '%s\n' "$scopestep" | grep -cE '(vars|secrets)\[' || true)"

# Red-team r7 F2 (#232 fold): the Repo-scope pins look at ONE step, so a dynamic
# read of a watch name in any other step passed (`vars[format(...)]` split into
# fragments). Scan every tracked workflow and script: a `vars` or `secrets`
# context inside `${{ }}` or an `if:` may only be a literal `.NAME` read.
cat >"${WORK}/dynread.py" <<'PY'
import re
import sys

EXPR = re.compile(r"\$\{\{(.*?)\}\}", re.S)
IF_KEY = re.compile(r"""^([ \t-]*)(?:"if"|'if'|if)[ \t]*:[ \t]*(.*)$""")
BLOCK = re.compile(r"^[|>](?:[1-9][+-]?|[+-][1-9]?)?$")
QUOTED = re.compile(r"'(?:[^']|'')*'")
CONTEXT = re.compile(r"(?<![A-Za-z0-9_.])(vars|secrets)\b")
LITERAL = re.compile(r"\s*\.\s*[A-Za-z_]")

def if_values(text):
    """Every `if:` value, including a folded block scalar whose condition
    lives on the following, more-indented lines."""
    values = []
    lines = text.splitlines()
    for index, line in enumerate(lines):
        match = IF_KEY.match(line)
        if not match:
            continue
        indent, rest = len(match.group(1)), match.group(2).strip()
        block = []
        for later in lines[index + 1:]:
            if later.strip() and (len(later) - len(later.lstrip())) <= indent:
                break
            if later.strip():
                block.append(later.strip())
        if BLOCK.match(rest):
            values.append(" ".join(block))
        elif rest:
            # a plain scalar may continue on the following, more-indented lines
            values.append(" ".join([rest] + block))
        else:
            values.append(" ".join(block))
    return values


legal = 0
offenders = []
for path in sys.argv[1:]:
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    exprs = [m.group(1) for m in EXPR.finditer(text)]
    exprs += if_values(text)
    for expr in exprs:
        flat = QUOTED.sub("''", expr)
        for m in CONTEXT.finditer(flat):
            if LITERAL.match(flat, m.end()):
                legal += 1
            else:
                offenders.append("%s: %s" % (path, expr.strip()[:200]))
if offenders:
    print("\n".join(offenders))
print("files=%d legal=%d" % (len(sys.argv) - 1, legal), file=sys.stderr)
sys.exit(1 if offenders else 0)
PY
dr_files="$(cd "$ROOT" && git ls-files -- .github scripts)"
dr_rc=0
# shellcheck disable=SC2086  # repo paths, never whitespace
dr_out="$(cd "$ROOT" && python3 -I -B "${WORK}/dynread.py" $dr_files 2>"${WORK}/dr.err")" || dr_rc=$?
is "every vars/secrets read in .github and scripts is a literal .NAME" "" "$dr_out"
is "dynamic-read scan exits clean on the tracked tree" "0" "$dr_rc"
is "dynamic-read scan covers every tracked .github/scripts file" "$(printf '%s\n' "$dr_files" | grep -c .)" "$(sed -n 's/^files=\([0-9]*\) .*/\1/p' "${WORK}/dr.err")"
dr_legal="$(sed -n 's/.* legal=\([0-9]*\)$/\1/p' "${WORK}/dr.err")"
is "the scan counts legal literal reads (not vacuous)" "1" "$([ "${dr_legal:-0}" -gt 0 ] && printf 1 || printf 0)"
cat >"${WORK}/dr-split.yml" <<'YML'
      - name: split read
        run: echo "${{ vars[format('{0}{1}{2}', 'EXTER', 'NAL_WA', 'TCH_TENANTS')] }}"
YML
cat >"${WORK}/dr-dump.yml" <<'YML'
        run: echo "${{ toJSON(vars) }}"
YML
cat >"${WORK}/dr-legal.yml" <<'YML'
        if: vars.STATUS_PULLER != '' && secrets.NTFY_TOPIC != ''
        run: echo "${{ format('{0}', github.sha) }}"
YML
dr_split_rc=0
dr_split="$(python3 -I -B "${WORK}/dynread.py" "${WORK}/dr-split.yml" 2>/dev/null)" || dr_split_rc=$?
is "a split-fragment dynamic read is refused" "1" "$dr_split_rc"
has "the split-fragment read is named" "$dr_split" 'vars[format('
dr_dump_rc=0
python3 -I -B "${WORK}/dynread.py" "${WORK}/dr-dump.yml" >/dev/null 2>&1 || dr_dump_rc=$?
is "a whole-context dump (toJSON(vars)) is refused" "1" "$dr_dump_rc"
cat >"${WORK}/dr-folded.yml" <<'YML'
        if: >-
          vars[format('{0}', 'X')] == 'x'
        run: echo hi
YML
dr_folded_rc=0
dr_folded="$(python3 -I -B "${WORK}/dynread.py" "${WORK}/dr-folded.yml" 2>/dev/null)" || dr_folded_rc=$?
is "a folded if: block scalar is judged, not just its first line" "1" "$dr_folded_rc"
has "the folded-if read is named" "$dr_folded" "vars[format("
cat >"${WORK}/dr-multi.yml" <<'YML'
        if: github.event_name == 'push' &&
          vars[format('{0}', 'X')] == 'x'
        run: echo hi
YML
dr_multi_rc=0
dr_multi="$(python3 -I -B "${WORK}/dynread.py" "${WORK}/dr-multi.yml" 2>/dev/null)" || dr_multi_rc=$?
is "a plain multi-line if: continuation is judged" "1" "$dr_multi_rc"
cat >"${WORK}/dr-quoted.yml" <<'YML'
        "if": vars[format('{0}', 'X')] == 'x'
        run: echo hi
YML
dr_quoted_rc=0
python3 -I -B "${WORK}/dynread.py" "${WORK}/dr-quoted.yml" >/dev/null 2>&1 || dr_quoted_rc=$?
is "a quoted if: key is judged" "1" "$dr_quoted_rc"
cat >"${WORK}/dr-space.yml" <<'YML'
        if : vars[format('{0}', 'X')] == 'x'
        run: echo hi
YML
dr_space_rc=0
python3 -I -B "${WORK}/dynread.py" "${WORK}/dr-space.yml" >/dev/null 2>&1 || dr_space_rc=$?
is "an if key with a space before the colon is judged" "1" "$dr_space_rc"
cat >"${WORK}/dr-indent.yml" <<'YML'
        if: >2-
          vars[format('{0}', 'X')] == 'x'
        run: echo hi
YML
dr_indent_rc=0
python3 -I -B "${WORK}/dynread.py" "${WORK}/dr-indent.yml" >/dev/null 2>&1 || dr_indent_rc=$?
is "a block scalar with an indentation indicator is judged" "1" "$dr_indent_rc"
dr_legal_rc=0
python3 -I -B "${WORK}/dynread.py" "${WORK}/dr-legal.yml" >/dev/null 2>&1 || dr_legal_rc=$?
is "literal vars/secrets reads stay green" "0" "$dr_legal_rc"
# Red-team r7 F3 (#232 fold): a list item or table row is its own claim unit,
# so a qualifier in the NEXT item does not qualify this one, and a bare `v*`
# (no backticks) is still a claim. The wrapped-prose case stays green.
printf '%s\n' '- tenant tags carry `v*` tags' '- not verified in this repo' >"${WORK}/vstar-list.md"
printf '%s\n' 'Tenant tags carry v* tags.' >"${WORK}/vstar-bare.md"
printf '%s\n' 'Tenant tags carry `v*` tags, which' 'are not verified in this repo.' >"${WORK}/vstar-wrap.md"
vs_list_rc=0
python3 -I -B "${WORK}/vstar.py" "${WORK}/vstar-list.md" >/dev/null 2>&1 || vs_list_rc=$?
is "list items are separate claim units (a qualifier in the next item does not count)" "1" "$vs_list_rc"
vs_bare_rc=0
python3 -I -B "${WORK}/vstar.py" "${WORK}/vstar-bare.md" >/dev/null 2>&1 || vs_bare_rc=$?
is "a bare v* (no backticks) is a claim" "1" "$vs_bare_rc"
vs_wrap_rc=0
python3 -I -B "${WORK}/vstar.py" "${WORK}/vstar-wrap.md" >/dev/null 2>&1 || vs_wrap_rc=$?
is "a wrapped qualified sentence stays green" "0" "$vs_wrap_rc"
printf '%s\n' 'Tenant tags carry `v*` tags; not verified in this repo.' >"${WORK}/vstar-semi.md"
vs_semi_rc=0
python3 -I -B "${WORK}/vstar.py" "${WORK}/vstar-semi.md" >/dev/null 2>&1 || vs_semi_rc=$?
is "a semicolon starts a new claim unit (the qualifier cannot be borrowed)" "1" "$vs_semi_rc"
printf '%s\n' 'The gate (`ref; see docs`) is expected by the platform, not verified in this repo.' >"${WORK}/vstar-code.md"
vs_code_rc=0
python3 -I -B "${WORK}/vstar.py" "${WORK}/vstar-code.md" >/dev/null 2>&1 || vs_code_rc=$?
is "a semicolon inside a code span does not split the claim unit" "0" "$vs_code_rc"
printf '%s\n' 'The gate (ref; see docs) is expected by the platform, not verified in this repo.' >"${WORK}/vstar-paren.md"
vs_paren_rc=0
python3 -I -B "${WORK}/vstar.py" "${WORK}/vstar-paren.md" >/dev/null 2>&1 || vs_paren_rc=$?
is "a semicolon inside a parenthesised aside does not split the claim unit" "0" "$vs_paren_rc"

# ---- #208 round 2: behavioural drivers for the config + incident steps -----
# Both steps run against stub gh/curl on PATH; every call is logged, so the
# assertions are on what the step DOES (create/comment/close/push, exit code),
# not on substrings of the workflow.
mkdir -p "$WORK/stubs"
cat >"$WORK/stubs/gh" <<'STUB'
#!/usr/bin/env bash
printf 'gh %s\n' "$*" >>"$STUB_LOG"
# Like the real gh: with no GH_REPO and no git work tree it cannot resolve the
# repo (#211 — the config job has no checkout).
if [ -z "${GH_REPO:-}" ] && [ -z "${STUB_GIT_TREE:-}" ]; then
  echo "failed to run git: fatal: not a git repository" >&2
  exit 1
fi
case "$1 $2" in
  "issue list") printf '%s\n' "${GH_LIST_JSON:-[]}" ;;
  "issue view") printf '%s\n' "${GH_VIEW_LAST:-}" ;;
  "issue create") [ -n "${GH_CREATE_FAIL_LABEL:-}" ] && case "$*" in *--label*) exit 1 ;; esac; exit 0 ;;
esac
exit 0
STUB
cat >"$WORK/stubs/curl" <<'STUB'
#!/usr/bin/env bash
printf 'curl %s\n' "$*" >>"$STUB_LOG"
exit "${CURL_RC:-0}"
STUB
chmod +x "$WORK/stubs/gh" "$WORK/stubs/curl"

span() { # $1 marker name -> extracted, dedented step body
  local a b
  a="$(grep -n "# --- $1:start ---" "$WATCH" | cut -d: -f1)"
  b="$(grep -n "# --- $1:end ---" "$WATCH" | cut -d: -f1)"
  [ -n "$a" ] && [ -n "$b" ] || return 1
  sed -n "$((a + 1)),$((b - 1))p" "$WATCH" | sed 's/^          //'
}
if span watch-config >"$WORK/config.sh" && bash -n "$WORK/config.sh"; then ok "config step extracted + parses"; else bad "config step extracted + parses"; fi
if span watch-incident >"$WORK/incident.sh" && bash -n "$WORK/incident.sh"; then ok "incident step extracted + parses"; else bad "incident step extracted + parses"; fi

drive() { # $1 script; env passes through; sets D_RC, D_LOG
  : >"$WORK/stub.log"
  D_RC=0
  ( cd "$WORK" && PATH="$WORK/stubs:$PATH" STUB_LOG="$WORK/stub.log" GH_TOKEN=x \
      RUN_URL=https://example.invalid/run bash "$1" ) >"$WORK/drive.out" 2>&1 || D_RC=$?
  D_LOG="$(cat "$WORK/stub.log")"
  # A repo-resolution failure also exits 1, which the "run fails" cases
  # would otherwise accept as the intended failure (#211).
  if grep -q 'not a git repository' "$WORK/drive.out"; then REPO_MISSES=$((REPO_MISSES + 1)); fi
}
REPO_MISSES=0
# Repo context comes from the workflow, not the driver: the config job gets
# GH_REPO only if its step env sets it; the watch job has a git work tree only
# if it checks the repo out (#211).
job_span() { awk -v j="  $1:" '$0==j{f=1;next} f&&/^  [a-z][a-z-]*:$/{exit} f' "$WATCH"; }
CFG_GH_REPO=""
grep -qxF '          GH_REPO: ${{ github.repository }}' <(job_span config) && CFG_GH_REPO="owner/repo"
WATCH_GIT_TREE=""
# The work tree must exist before the incident step's gh calls, not just
# somewhere in the job.
co_line="$(job_span watch | grep -n '^      - uses: actions/checkout@' | head -n1 | cut -d: -f1 || true)"
inc_line="$(job_span watch | grep -n '^      - name: Incident state' | head -n1 | cut -d: -f1 || true)"
[ -n "$co_line" ] && [ -n "$inc_line" ] && [ "$co_line" -lt "$inc_line" ] && WATCH_GIT_TREE=1
cdrive() { GH_REPO="$CFG_GH_REPO" STUB_GIT_TREE="" drive "$@"; }
idrive() { GH_REPO="" STUB_GIT_TREE="$WATCH_GIT_TREE" drive "$@"; }
calls() { printf '%s\n' "$D_LOG" | grep -c "$1" || true; }
CFG_OPEN='[{"number":7,"title":"[external-watch] watch config refused: x"},{"number":3,"title":"[external-watch] pier: dashboard probe failing: y"}]'

is "config job names the repo for gh (#211)" "owner/repo" "$CFG_GH_REPO"
is "watch job checks the repo out (gh resolves it from the work tree)" "1" "$WATCH_GIT_TREE"
# config: refused, no incident yet -> create once, push once, run fails
TARGETS_RESULT=success REFUSED="bad alias 'X'" WATCH_NTFY_TOPIC=t1 cdrive "$WORK/config.sh"
is "config refused: run fails" "1" "$D_RC"
is "config refused: one incident created" "1" "$(calls '^gh issue create')"
has "config refused: incident title carries the prefix" "$D_LOG" '--title [external-watch] watch config refused: bad alias'
is "config refused: one ntfy push" "1" "$(calls '^curl ')"
has "config refused: push goes to the watch topic" "$D_LOG" 'https://ntfy.sh/t1'
# config: refused, incident already open -> no duplicate, no re-push, still fails
TARGETS_RESULT=success REFUSED="bad alias 'X'" WATCH_NTFY_TOPIC=t1 GH_LIST_JSON="$CFG_OPEN" cdrive "$WORK/config.sh"
is "config refused + open: run fails" "1" "$D_RC"
is "config refused + open: no duplicate incident" "0" "$(calls '^gh issue create')"
is "config refused + open: no re-push" "0" "$(calls '^curl ')"
# config: targets job broken -> alert
TARGETS_RESULT=failure REFUSED="" cdrive "$WORK/config.sh"
is "config targets failed: run fails" "1" "$D_RC"
has "config targets failed: incident names the result" "$D_LOG" "the targets job ended 'failure'"
# config: refused, push fails -> incident still filed, run still fails
TARGETS_RESULT=success REFUSED="bad" REPO_NTFY_TOPIC=t2 CURL_RC=22 cdrive "$WORK/config.sh"
is "config push failure: run still fails" "1" "$D_RC"
is "config push failure: incident still created" "1" "$(calls '^gh issue create')"
has "config push failure: repo topic used when no watch topic" "$D_LOG" 'https://ntfy.sh/t2'
# config: valid list, open config incident -> closed, run green; the tenant incident is untouched
TARGETS_RESULT=success REFUSED="" GH_LIST_JSON="$CFG_OPEN" cdrive "$WORK/config.sh"
is "config valid: run green" "0" "$D_RC"
is "config valid: closes the config incident only" "gh issue close 7" "$(printf '%s\n' "$D_LOG" | grep '^gh issue close')"
is "config valid: no create, no push" "0" "$(( $(calls '^gh issue create') + $(calls '^curl ') ))"
# config: valid/unset, nothing open -> silent green
TARGETS_RESULT=success REFUSED="" cdrive "$WORK/config.sh"
is "config valid + nothing open: run green" "0" "$D_RC"
is "config valid + nothing open: no issue writes" "0" "$(printf '%s\n' "$D_LOG" | grep -cE '^gh issue (create|comment|close)' || true)"

# incident: tenant leg failing, none open -> per-tenant incident created
OK=false DETAIL=boom WATCH_ALIAS=pier idrive "$WORK/incident.sh"
is "incident fail: step exits 0 (the Fail step fails the run)" "0" "$D_RC"
has "incident fail: per-tenant title" "$D_LOG" '--title [external-watch] pier: dashboard probe failing: boom'
# incident: tenant leg failing, its incident open with a fresh comment -> no spam
OK=false DETAIL=boom WATCH_ALIAS=pier GH_LIST_JSON="$CFG_OPEN" GH_VIEW_LAST="$(date -u +%FT%TZ)" idrive "$WORK/incident.sh"
is "incident fail + open (<6h): no create, no comment" "0" "$(printf '%s\n' "$D_LOG" | grep -cE '^gh issue (create|comment)' || true)"
# incident: tenant leg green -> closes ITS incident, never the config one
OK=true WATCH_ALIAS=pier GH_LIST_JSON="$CFG_OPEN" idrive "$WORK/incident.sh"
is "incident recovered: closes the tenant incident only" "gh issue close 3" "$(printf '%s\n' "$D_LOG" | grep '^gh issue close')"
# incident: legacy leg (blank label) never matches a tenant-titled incident
OK=true WATCH_ALIAS="" GH_LIST_JSON="$CFG_OPEN" idrive "$WORK/incident.sh"
is "incident legacy leg: tenant incident untouched" "0" "$(calls '^gh issue close')"
OK=false DETAIL=boom WATCH_ALIAS="" idrive "$WORK/incident.sh"
has "incident legacy leg: legacy title kept" "$D_LOG" '--title [external-watch] dashboard probe failing: boom'
# incident: label attach fails -> created without it
OK=false DETAIL=boom WATCH_ALIAS=pier GH_CREATE_FAIL_LABEL=1 idrive "$WORK/incident.sh"
is "incident label failure: retried without the label" "2" "$(calls '^gh issue create')"

# Fail step: the run goes red on a failed probe (exact condition).
failstep="$(awk '/- name: Fail the run on probe failure/{f=1;next} f&&n<2{print;n++}' "$WATCH")"
is "Fail step condition + body are exact" "        if: steps.probe.outcome == 'failure'
        run: exit 1" "$failstep"
pushstep="$(awk '/- name: ntfy push \(no-op until a topic is set\)/{f=1;next} f&&n<1{print;n++}' "$WATCH")"
is "leg ntfy step fires on a failed probe (exact condition)" "        if: steps.probe.outcome == 'failure'" "$pushstep"
# A failed leg push must not skip the incident step (the step has no if:).
pushbody="$(awk '/- name: ntfy push \(no-op until a topic is set\)/{f=1;next} f&&/^      - name:/{exit} f' "$WATCH")"
has "leg ntfy push is guarded by if (a curl failure never fails the step)" "$pushbody" '          if curl -sS --fail "${NTFY_AUTH[@]}" \'
has "leg ntfy failure is a warning, not a step failure" "$pushbody" $'          else\n            echo "::warning::ntfy push failed - the incident step still runs"\n          fi'
# Red-team r5 F1 + r6 F1 (#209 fold): pin the EFFECTIVE mapping, not literal
# lines. Two evasions the exact-line pins missed: a third binding after the
# pairing `fi` (the run block would then send the repo token to the watch
# topic) and a duplicate env key (YAML last-wins silently keeps the second).
# So: load the workflow with a duplicate-key-rejecting loader and check every
# env map, then require each run block to assign each channel name exactly
# twice — once per branch, nothing after the guard.
envmap="$(python3 -I -B "${WORK}/env-map.py" "$WATCH" 2>&1)" || true
is "env maps bind the WATCH_ names to their own secrets once, with the repo pair (dup key rejects)" "" "$envmap"
ntfy_sets() { # $1 body, $2 name -> assignment count
  printf '%s\n' "$1" | grep -cE "(^|[^[:alnum:]_])${2}=" || true
}
is "config step assigns NTFY_TOPIC only in the two pairing branches" "2" "$(ntfy_sets "$(cat "${WORK}/config.sh")" NTFY_TOPIC)"
is "config step assigns NTFY_TOKEN only in the two pairing branches" "2" "$(ntfy_sets "$(cat "${WORK}/config.sh")" NTFY_TOKEN)"
is "watch leg assigns NTFY_TOPIC only in the two pairing branches" "2" "$(ntfy_sets "$pushbody" NTFY_TOPIC)"
is "watch leg assigns NTFY_TOKEN only in the two pairing branches" "2" "$(ntfy_sets "$pushbody" NTFY_TOKEN)"
# Red-team r7 F1 (#232 fold): the count above sees only the textual `NAME=`,
# so a rebind through `printf -v`, `read`, `export`, `declare`, `local`, `eval`
# or `+=` after the pairing passes it. Layer 2 (textual): no such rebind of a
# channel name in either body. Layer 1 (behavioural, below): drive both bodies
# with the watch pair AND the repo pair set; the post must use the watch values.
ntfy_rebinds() { # $1 body -> rebind count (comments dropped, continuations joined)
  printf '%s\n' "$1" | grep -vE '^[[:space:]]*#' \
    | sed -e ':a' -e '/\\[[:space:]]*$/{N; s/\\[[:space:]]*\n/ /; ta}' \
    | grep -cE '(^|[^[:alnum:]_])(printf[[:space:]]+-v|read|readarray|mapfile|export|declare|typeset|local|readonly|eval|unset)([^[:alnum:]_]|$).*NTFY_(TOPIC|TOKEN)|(^|[^[:alnum:]_])NTFY_(TOPIC|TOKEN)(\+|:)=' || true
}
is "rebind detector flags printf -v on a channel name" "1" "$(ntfy_rebinds 'printf -v NTFY_TOPIC "%s" "$x"')"
is "rebind detector flags a += on a channel name" "1" "$(ntfy_rebinds 'NTFY_TOKEN+=x')"
is "rebind detector flags a := on a channel name" "1" "$(ntfy_rebinds 'NTFY_TOKEN:=x')"
is "rebind detector joins a line continuation" "1" \
  "$(ntfy_rebinds "$(printf 'printf -v \\\nNTFY_TOPIC "%s" x')")"
is "rebind detector ignores a comment that names a channel" "0" "$(ntfy_rebinds '# read NTFY_TOPIC here')"
is "config step has no rebind verb on a channel name" "0" "$(ntfy_rebinds "$(cat "${WORK}/config.sh")")"
is "watch leg has no rebind verb on a channel name" "0" "$(ntfy_rebinds "$pushbody")"
hits() { printf '%s\n' "$D_LOG" | grep -cF -- "$1" || true; }
ldrive() { WATCH_ALIAS=pier DETAIL=boom drive "$@"; }
legrun="$(awk '/- name: ntfy push \(no-op until a topic is set\)/{f=1;next} f&&/^      - name:/{exit} f&&r{print} f&&/^        run: [|]$/{r=1}' "$WATCH" | sed 's/^          //')"
printf '%s\n' "$legrun" >"${WORK}/leg.sh"
if bash -n "${WORK}/leg.sh" && [ -s "${WORK}/leg.sh" ]; then ok "leg push body extracted + parses"; else bad "leg push body extracted + parses"; fi
# (a) both pairs set: the watch pair wins; the repo pair never reaches a post.
WATCH_NTFY_TOPIC=wt WATCH_NTFY_TOKEN=wk REPO_NTFY_TOPIC=rt REPO_NTFY_TOKEN=rk TARGETS_RESULT=success REFUSED=bad cdrive "$WORK/config.sh"
is "config, both pairs set: watch topic+token only" "1:0:1:0" "$(hits 'https://ntfy.sh/wt'):$(hits 'https://ntfy.sh/rt'):$(hits 'Bearer wk'):$(hits 'Bearer rk')"
WATCH_NTFY_TOPIC=wt WATCH_NTFY_TOKEN=wk REPO_NTFY_TOPIC=rt REPO_NTFY_TOKEN=rk ldrive "${WORK}/leg.sh"
is "leg, both pairs set: exits 0" "0" "$D_RC"
is "leg, both pairs set: watch topic+token only" "1:0:1:0" "$(hits 'https://ntfy.sh/wt'):$(hits 'https://ntfy.sh/rt'):$(hits 'Bearer wk'):$(hits 'Bearer rk')"
# (b) watch topic with an empty watch token: no auth header, no repo values.
WATCH_NTFY_TOPIC=wt WATCH_NTFY_TOKEN= REPO_NTFY_TOPIC=rt REPO_NTFY_TOKEN=rk TARGETS_RESULT=success REFUSED=bad cdrive "$WORK/config.sh"
is "config, empty watch token: watch topic, no auth, no repo values" "1:0:0" "$(hits 'https://ntfy.sh/wt'):$(hits 'https://ntfy.sh/rt'):$(hits 'Bearer')"
WATCH_NTFY_TOPIC=wt WATCH_NTFY_TOKEN= REPO_NTFY_TOPIC=rt REPO_NTFY_TOKEN=rk ldrive "${WORK}/leg.sh"
is "leg, empty watch token: watch topic, no auth, no repo values" "1:0:0" "$(hits 'https://ntfy.sh/wt'):$(hits 'https://ntfy.sh/rt'):$(hits 'Bearer')"
# (c) the documented fallback: watch pair unset, repo pair used (pinned above too).
WATCH_NTFY_TOPIC= WATCH_NTFY_TOKEN= REPO_NTFY_TOPIC=rt REPO_NTFY_TOKEN=rk TARGETS_RESULT=success REFUSED=bad cdrive "$WORK/config.sh"
is "config, watch pair unset: documented repo fallback" "1:1" "$(hits 'https://ntfy.sh/rt'):$(hits 'Bearer rk')"
WATCH_NTFY_TOPIC= WATCH_NTFY_TOKEN= REPO_NTFY_TOPIC=rt REPO_NTFY_TOKEN=rk ldrive "${WORK}/leg.sh"
is "leg, watch pair unset: documented repo fallback" "1:1" "$(hits 'https://ntfy.sh/rt'):$(hits 'Bearer rk')"
# (d) no topic at all: no push.
WATCH_NTFY_TOPIC= REPO_NTFY_TOPIC= ldrive "${WORK}/leg.sh"
is "leg, no topic at all: no curl" "0" "$(calls '^curl ')"

# #208 round 3 (red-team F1): the step headers that decide whether the
# incident path runs at all. A probe without continue-on-error stops the job
# before the incident step; an incident step with an `if:` stops filing on a
# failure or stops closing on recovery.
probehdr="$(awk '/- name: "Probe: HTTP 200 \+ Gatus data \+ edge cert >= 14d"/{f=1;next} f&&n<3{print;n++}' "$WATCH")"
is "probe step header is exact (id + continue-on-error + env)" "        id: probe
        continue-on-error: true
        env:" "$probehdr"
incstep="$(awk '/- name: Incident state \(issue = open while failing; auto-close on recovery\)/{f=1;next} f&&/^      - name:/{exit} f' "$WATCH")"
is "incident step: env: follows the name directly" "        env:" "$(printf '%s\n' "$incstep" | head -n1)"
is "incident step carries no if: (runs on failure AND recovery)" "0" "$(printf '%s\n' "$incstep" | grep -cE '^        if:' || true)"
# Red-team r4 F1: the incident step's env bindings (the drivers stub these
# values, so pin the YAML lines themselves, inside the step).
for bl in '          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}' '          OK: ${{ steps.probe.outputs.ok }}' '          DETAIL: ${{ steps.probe.outputs.detail }}' '          WATCH_ALIAS: ${{ matrix.target.label }}'; do
  is "incident step binds: ${bl#"${bl%%[! ]*}"}" "1" "$(printf '%s\n' "$incstep" | grep -cxF -- "$bl" || true)"
done
is "incident step has no continue-on-error" "0" "$(printf '%s\n' "$incstep" | grep -c 'continue-on-error' || true)"
# Red-team r5 F3 (#209): the exact-line pins above cannot see a duplicate key
# written differently (quoted, re-spaced). Count the env block's keys: a
# duplicate makes it 6 and this reds, whatever its spelling.
incenv="$(printf '%s\n' "$incstep" | awk 'NR > 1 && /^        run:/{exit} NR > 1{print}')"
env_key='^[[:space:]]*["'"'"']?[A-Za-z_][A-Za-z0-9_]*["'"'"']?[[:space:]]*:'
is "incident step env declares exactly 5 keys (a duplicate cannot pass)" "5" \
  "$(printf '%s\n' "$incenv" | grep -cE "$env_key" || true)"
is "watch concurrency never cancels a running watcher" "  group: external-watch
  cancel-in-progress: false" "$(grep -A1 '^  group: external-watch$' "$WATCH")"
is "legs run one at a time (ordered incident calls)" "1" "$(grep -cx '      max-parallel: 1' "$WATCH")"
is "incident step exists exactly once" "1" "$(grep -c '^      - name: Incident state (issue = open while failing; auto-close on recovery)$' "$WATCH")"
# Red-team r5 F2 (#209): YAML allows a quoted key, so the uniqueness pin
# matches an optional quote and whitespace around the colon.
perm_key='^[[:space:]]*["'"'"']?permissions["'"'"']?[[:space:]]*:'
# Functional r5 F1 (#209): the extract ends at the first line that is neither
# indented nor blank — a blank line does not close the top-level block (a
# blank line followed by `  actions: write` is valid YAML and grants the scope).
perm_block() { # $1 workflow file (default: the real one)
  awk -v k="$perm_key" '
    $0 ~ k && !f { print "permissions:"; f=1; next }
    f {
      if ($0 !~ /^[[:space:]]/ && $0 !~ /^[[:space:]]*$/) exit
      if ($0 ~ /^[[:space:]]*$/) { blank = blank "\n"; next }
      if (blank != "") { printf "%s", blank; blank = "" }
      print
    }
  ' "${1:-$WATCH}"
}
is "permissions block is exact (whole block, to the first non-indented line)" "permissions:
  contents: read
  issues: write" "$(perm_block)"
is "permissions block is unique (quoted key included, no job-level override)" "1" "$(grep -cE "$perm_key" "$WATCH" || true)"
# Functional r5 F1 + r6 F2 (#209 fold): a legal re-spelling of the key must not
# fail CI, so the extract prints a canonical `permissions:` key line; the
# block BELOW it is still exact, so a scope added after a quoted key reds.
perm_case() { # $1 replacement key line, $2=1 to append an extra scope, $3 tag
  local f="${WORK}/perm-$3.yml"
  awk -v k="$perm_key" -v key="$1" -v extra="$2" '
    $0 ~ k { print key; if (extra == "1") print "  actions: write"; next }
    { print }
  ' "$WATCH" >"$f"
  perm_block "$f"
}
is "permissions block survives a quoted key (a legal re-spelling stays green)" "permissions:
  contents: read
  issues: write" "$(perm_case '"permissions":' 0 quoted)"
is "permissions block cannot hide a scope added after a quoted key" "permissions:
  actions: write
  contents: read
  issues: write" "$(perm_case '"permissions":' 1 quoted-extra)"
is "cron cadence is exact" '    - cron: "*/15 * * * *"' "$(grep -E '^[[:space:]]*- cron:' "$WATCH")"
# Config incident label fallback: a missing/unattachable label still files it.
TARGETS_RESULT=success REFUSED="bad" GH_CREATE_FAIL_LABEL=1 cdrive "$WORK/config.sh"
is "config label failure: retried without the label" "2" "$(calls '^gh issue create')"
is "config label failure: run still fails" "1" "$D_RC"
is "no driver run failed on repo resolution (#211)" "0" "$REPO_MISSES"

# ---- CI wiring -------------------------------------------------------------
has "CI runs this harness" "$(cat "$CI")" "tests/external-watch/run-test.sh"
has "CI path gate covers this harness" "$(cat "$CI")" "external-watch"

printf '\n%s passed, %s failed\n' "$pass" "$fail"
if [ "$pass" -lt "$MIN_CHECKS" ]; then
  printf 'FAIL check-count floor: %s < %s\n' "$pass" "$MIN_CHECKS"
  fail=$((fail + 1))
fi
[ "$fail" -eq 0 ]
