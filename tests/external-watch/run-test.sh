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
#   - TENANT_USER unset degrades to the platform channel only.
set -euo pipefail

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HARNESS_DIR}/../.." && pwd)"
WATCH="${ROOT}/.github/workflows/external-watch.yml"
CI="${ROOT}/.github/workflows/ci.yml"
WORK="$(mktemp -d /tmp/external-watch.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0
MIN_CHECKS=40
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

# ---- CI wiring -------------------------------------------------------------
has "CI runs this harness" "$(cat "$CI")" "tests/external-watch/run-test.sh"
has "CI path gate covers this harness" "$(cat "$CI")" "external-watch"

printf '\n%s passed, %s failed\n' "$pass" "$fail"
if [ "$pass" -lt "$MIN_CHECKS" ]; then
  printf 'FAIL check-count floor: %s < %s\n' "$pass" "$MIN_CHECKS"
  fail=$((fail + 1))
fi
[ "$fail" -eq 0 ]
