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
#   - #209: the backstop push channel binds the WATCH_ names to the
#     EXTERNAL_WATCH_* secrets as exact lines in both steps; the permissions
#     pins survive a quoted key and a blank line inside the block; the
#     incident env declares exactly its five keys; the targets block runs with
#     WATCH_TENANTS unset; the docs name EXTERNAL_WATCH_TENANTS and qualify
#     every `v*` claim.
set -euo pipefail

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HARNESS_DIR}/../.." && pwd)"
WATCH="${ROOT}/.github/workflows/external-watch.yml"
CI="${ROOT}/.github/workflows/ci.yml"
WORK="$(mktemp -d /tmp/external-watch.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0
MIN_CHECKS=236
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
# Trust r5 F2 (#209): the amendment must also name the repository variable the
# same PR ships; it is repository-level data feeding the watch, outside
# invariant 4's secret scope but part of the same surface.
amend="$(awk '/Scoped amendment/ && /push channel/{f=1} f && /^## /{exit} f' "${ROOT}/docs/invariants.md")"
has "invariant 4 amendment names the repo variable EXTERNAL_WATCH_TENANTS" "$amend" 'EXTERNAL_WATCH_TENANTS'
# Trust r5 F4 (#209): every `v*` deployment-policy claim carries the same
# "not verified in this repo" qualifier as docs/invariants.md.
for vf in .github/workflows/external-watch.yml docs/dr.md docs/invariants.md docs/usage.md; do
  unq="$(grep -n '`v\*`' "${ROOT}/${vf}" | grep -vE 'not verified (in this repo|here)' || true)"
  is "every v* claim in ${vf} is qualified" "" "$unq"
done
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
# Red-team r5 F1 (#209): the backstop push channel must bind the WATCH_ names
# to the EXTERNAL_WATCH_* secrets, in BOTH steps, as exact lines — rebinding
# either to `secrets.NTFY_TOKEN` (or to the other channel's secret) has to red.
for bl in 'WATCH_NTFY_TOPIC: ${{ secrets.EXTERNAL_WATCH_NTFY_TOPIC }}' 'WATCH_NTFY_TOKEN: ${{ secrets.EXTERNAL_WATCH_NTFY_TOKEN }}'; do
  is "config step binds ${bl%%:*} to its own secret (exact line)" "1" \
    "$(job_span config | grep -cxF -- "          ${bl}" || true)"
  is "watch leg binds ${bl%%:*} to its own secret (exact line)" "1" \
    "$(printf '%s\n' "$pushbody" | grep -cxF -- "          ${bl}" || true)"
done

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
perm_block() {
  awk -v k="$perm_key" '
    $0 ~ k && !f { print; f=1; next }
    f {
      if ($0 !~ /^[[:space:]]/ && $0 !~ /^[[:space:]]*$/) exit
      if ($0 ~ /^[[:space:]]*$/) { blank = blank "\n"; next }
      if (blank != "") { printf "%s", blank; blank = "" }
      print
    }
  ' "$WATCH"
}
is "permissions block is exact (whole block, to the first non-indented line)" "permissions:
  contents: read
  issues: write" "$(perm_block)"
is "permissions block is unique (quoted key included, no job-level override)" "1" "$(grep -cE "$perm_key" "$WATCH" || true)"
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
