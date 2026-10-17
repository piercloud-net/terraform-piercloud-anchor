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
set -euo pipefail

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HARNESS_DIR}/../.." && pwd)"
WATCH="${ROOT}/.github/workflows/external-watch.yml"
CI="${ROOT}/.github/workflows/ci.yml"
WORK="$(mktemp -d /tmp/external-watch.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0
MIN_CHECKS=181
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

targets() { # env: WATCH_TENANTS PROBE_OVERRIDE LEGACY_*; prints "0|matrix", "refused|reason|matrix" or "rc|output"
  local out rc refused
  out="$( ( cd "$WORK" && env -u GITHUB_OUTPUT \
      WATCH_TENANTS="${WATCH_TENANTS-}" PROBE_OVERRIDE="${PROBE_OVERRIDE-}" \
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
cfg="$(awk '/^  config:$/{f=1} /^  watch:$/{f=0} f' "$WATCH")"
has "config job waits on targets" "$cfg" "needs: targets"
is "config job always runs (exact line, no extra condition)" "1" "$(printf '%s\n' "$cfg" | grep -cx '    if: always()' || true)"
has "config job reads the targets result" "$cfg" 'TARGETS_RESULT: ${{ needs.targets.result }}'
has "config job reads the refusal" "$cfg" 'REFUSED: ${{ needs.targets.outputs.refused }}'
has "config job fails the run while refused" "$cfg" 'exit 1'
has "targets job exports the refusal" "$wf" 'refused: ${{ steps.targets.outputs.refused }}'
has "job name uses the label (legacy name unchanged)" "$wf" "name: probe \${{ matrix.target.label || 'the dashboard' }} from GitHub's network"
# Invariant 4 carve-out (#208 round 1): the watch channel names are read by
# external-watch.yml only, never by a managed run.
is "EXTERNAL_WATCH_NTFY_* read only by external-watch.yml" "" \
  "$(cd "$ROOT" && git grep -l 'EXTERNAL_WATCH_NTFY_' -- .github scripts ':!.github/workflows/external-watch.yml' || true)"
has "invariant 4 carries the scoped watch-channel amendment" "$(cat "${ROOT}/docs/invariants.md")" "Scoped amendment — the external watch's own push channel"
lacks "watch names are not in the managed repo-scope list" "$(cat "${ROOT}/.github/workflows/provision.yml")" 'EXTERNAL_WATCH_'

# ---- #208 round 2: behavioural drivers for the config + incident steps -----
# Both steps run against stub gh/curl on PATH; every call is logged, so the
# assertions are on what the step DOES (create/comment/close/push, exit code),
# not on substrings of the workflow.
mkdir -p "$WORK/stubs"
cat >"$WORK/stubs/gh" <<'STUB'
#!/usr/bin/env bash
printf 'gh %s\n' "$*" >>"$STUB_LOG"
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
}
calls() { printf '%s\n' "$D_LOG" | grep -c "$1" || true; }
CFG_OPEN='[{"number":7,"title":"[external-watch] watch config refused: x"},{"number":3,"title":"[external-watch] pier: dashboard probe failing: y"}]'

# config: refused, no incident yet -> create once, push once, run fails
TARGETS_RESULT=success REFUSED="bad alias 'X'" WATCH_NTFY_TOPIC=t1 drive "$WORK/config.sh"
is "config refused: run fails" "1" "$D_RC"
is "config refused: one incident created" "1" "$(calls '^gh issue create')"
has "config refused: incident title carries the prefix" "$D_LOG" '--title [external-watch] watch config refused: bad alias'
is "config refused: one ntfy push" "1" "$(calls '^curl ')"
has "config refused: push goes to the watch topic" "$D_LOG" 'https://ntfy.sh/t1'
# config: refused, incident already open -> no duplicate, no re-push, still fails
TARGETS_RESULT=success REFUSED="bad alias 'X'" WATCH_NTFY_TOPIC=t1 GH_LIST_JSON="$CFG_OPEN" drive "$WORK/config.sh"
is "config refused + open: run fails" "1" "$D_RC"
is "config refused + open: no duplicate incident" "0" "$(calls '^gh issue create')"
is "config refused + open: no re-push" "0" "$(calls '^curl ')"
# config: targets job broken -> alert
TARGETS_RESULT=failure REFUSED="" drive "$WORK/config.sh"
is "config targets failed: run fails" "1" "$D_RC"
has "config targets failed: incident names the result" "$D_LOG" "the targets job ended 'failure'"
# config: refused, push fails -> incident still filed, run still fails
TARGETS_RESULT=success REFUSED="bad" REPO_NTFY_TOPIC=t2 CURL_RC=22 drive "$WORK/config.sh"
is "config push failure: run still fails" "1" "$D_RC"
is "config push failure: incident still created" "1" "$(calls '^gh issue create')"
has "config push failure: repo topic used when no watch topic" "$D_LOG" 'https://ntfy.sh/t2'
# config: valid list, open config incident -> closed, run green; the tenant incident is untouched
TARGETS_RESULT=success REFUSED="" GH_LIST_JSON="$CFG_OPEN" drive "$WORK/config.sh"
is "config valid: run green" "0" "$D_RC"
is "config valid: closes the config incident only" "gh issue close 7" "$(printf '%s\n' "$D_LOG" | grep '^gh issue close')"
is "config valid: no create, no push" "0" "$(( $(calls '^gh issue create') + $(calls '^curl ') ))"
# config: valid/unset, nothing open -> silent green
TARGETS_RESULT=success REFUSED="" drive "$WORK/config.sh"
is "config valid + nothing open: run green" "0" "$D_RC"
is "config valid + nothing open: no issue writes" "0" "$(printf '%s\n' "$D_LOG" | grep -cE '^gh issue (create|comment|close)' || true)"

# incident: tenant leg failing, none open -> per-tenant incident created
OK=false DETAIL=boom WATCH_ALIAS=pier drive "$WORK/incident.sh"
is "incident fail: step exits 0 (the Fail step fails the run)" "0" "$D_RC"
has "incident fail: per-tenant title" "$D_LOG" '--title [external-watch] pier: dashboard probe failing: boom'
# incident: tenant leg failing, its incident open with a fresh comment -> no spam
OK=false DETAIL=boom WATCH_ALIAS=pier GH_LIST_JSON="$CFG_OPEN" GH_VIEW_LAST="$(date -u +%FT%TZ)" drive "$WORK/incident.sh"
is "incident fail + open (<6h): no create, no comment" "0" "$(printf '%s\n' "$D_LOG" | grep -cE '^gh issue (create|comment)' || true)"
# incident: tenant leg green -> closes ITS incident, never the config one
OK=true WATCH_ALIAS=pier GH_LIST_JSON="$CFG_OPEN" drive "$WORK/incident.sh"
is "incident recovered: closes the tenant incident only" "gh issue close 3" "$(printf '%s\n' "$D_LOG" | grep '^gh issue close')"
# incident: legacy leg (blank label) never matches a tenant-titled incident
OK=true WATCH_ALIAS="" GH_LIST_JSON="$CFG_OPEN" drive "$WORK/incident.sh"
is "incident legacy leg: tenant incident untouched" "0" "$(calls '^gh issue close')"
OK=false DETAIL=boom WATCH_ALIAS="" drive "$WORK/incident.sh"
has "incident legacy leg: legacy title kept" "$D_LOG" '--title [external-watch] dashboard probe failing: boom'
# incident: label attach fails -> created without it
OK=false DETAIL=boom WATCH_ALIAS=pier GH_CREATE_FAIL_LABEL=1 drive "$WORK/incident.sh"
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

# ---- CI wiring -------------------------------------------------------------
has "CI runs this harness" "$(cat "$CI")" "tests/external-watch/run-test.sh"
has "CI path gate covers this harness" "$(cat "$CI")" "external-watch"

printf '\n%s passed, %s failed\n' "$pass" "$fail"
if [ "$pass" -lt "$MIN_CHECKS" ]; then
  printf 'FAIL check-count floor: %s < %s\n' "$pass" "$MIN_CHECKS"
  fail=$((fail + 1))
fi
[ "$fail" -eq 0 ]
