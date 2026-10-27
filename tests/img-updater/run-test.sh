#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2154 # subshell assignments feed the sourced 010 span (read there, not here)
# tests/img-updater/run-test.sh - offline, cred-free harness for the A-IMG
# on-box container updater (issue #51, Lane A).
#
# Extracts the REAL spans from scripts/010-provision.sh (never a copy): the
# IMG UPDATER span, the HARDENING CHECK span and
# the adv_ok/probe_tang_direct probes the updater embeds. docker, curl,
# systemctl and sleep are PATH stubs; the registry answers come from the
# recorded Docker Hub tag-list fixtures in fixtures/ (no network). Proves:
#   precedence  max(repo pin, recorded) inside the pin's track, no downgrade,
#               another track resets, a bad digest is never selected, the
#               off switch returns to the pin;
#   track       only same-major, same-suffix x.y.z tags (3.x, plain, builder,
#               windows and two-part tags are refused);
#   soak        a build younger than IMG_UPDATE_SOAK_HOURS is not taken;
#   swap        pull by digest, caddy validate before the swap, the shared
#               docker run args, state recorded, success pushed, no alert;
#   ladder      a failing candidate restores the previous exact digest, else
#               the provisioned pin digest (each verified tang-first); when
#               every rung fails: direct ntfy NOW + disarm until a dispatch;
#   live        every push is derived from checks run at push time (a
#               broken Caddy never reports green; an unproven box never swaps);
#   binding     validate and the self-checks are bound to the candidate digest;
#   registry    the tag list is complete (every page) or the round fails closed;
#   freeze      a box trailing the newest in-track build past soak + one cycle
#               is red (behind:<tag> reason:<class>);
#   pin         the repo pin runs by a recorded digest (never tag-only);
#   validate    a candidate the live Caddyfile rejects never runs (and a
#               Caddyfile the running build rejects too holds nothing);
#   drill       IMG_DRILL=<name> (root on the box) yields a clean rollback;
#   token       the push token reaches curl on stdin only, never argv/output;
#   off         IMG_AUTO_UPDATES=off renders no rows and removes the updater;
#   install     modes (0700 state, 0600 env/token), the 6 h jittered timer.
# Every suite also runs against mutants of the span (teeth): each mutant must
# turn at least one assertion red.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HARNESS_DIR="$ROOT/tests/img-updater"
PROVISION="$ROOT/scripts/010-provision.sh"
SUITE_ONLY=""
if [ "${1:-}" = "--suite" ]; then SUITE_ONLY="$2"; fi

pass=0
fail=0
ok()  { pass=$((pass + 1)); [ -n "$SUITE_ONLY" ] || printf 'ok   %s\n' "$1"; }
bad() { fail=$((fail + 1)); [ -n "$SUITE_ONLY" ] || printf 'FAIL %s\n' "$1"; }
is()  { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi; }
has() { case "$2" in *"$3"*) ok "$1" ;; *) bad "$1 (missing: $3)" ;; esac; }
lacks() { case "$2" in *"$3"*) bad "$1 (unexpected: $3)" ;; *) ok "$1" ;; esac; }

WORK="$(mktemp -d)"
trap '[ -n "${KEEP_WORK:-}" ] || rm -rf "$WORK"' EXIT

# ---- extract the real spans ----------------------------------------------
span() { # $1 begin marker (prefix), $2 end marker -> body between them (markers unique)
  local nb ne b e
  nb="$(grep -c -- "^$1" "$PROVISION" || true)"
  ne="$(grep -c -- "^$2" "$PROVISION" || true)"
  [ "$nb" = "1" ] && [ "$ne" = "1" ] || { printf 'FAIL markers %s / %s found %s / %s times\n' "$1" "$2" "$nb" "$ne"; exit 1; }
  b="$(grep -n -- "^$1" "$PROVISION" | cut -d: -f1)"
  e="$(grep -n -- "^$2" "$PROVISION" | cut -d: -f1)"
  sed -n "$((b + 1)),$((e - 1))p" "$PROVISION"
}
fn_src() { # $1 function name -> its top-level definition from 010
  awk -v hdr="$1() {" 'index($0, hdr) == 1 { on = 1 } on { print } on && /^}$/ { exit }' "$PROVISION"
}
if [ -z "${IMG_HARNESS_SPAN:-}" ]; then
  span '# --- BEGIN IMG UPDATER' '# --- END IMG UPDATER ---' >"$WORK/img.src"
else
  cp "$IMG_HARNESS_SPAN" "$WORK/img.src"
fi
span '# --- BEGIN HARDENING CHECK' '# --- END HARDENING CHECK ---' >"$WORK/hard.src"
# The 010 tang probe writes a fixed /tmp path (PrivateTmp on the box); the
# harness points it at its own work dir so a concurrent run cannot collide.
mkdir -p "$WORK/tmp"
{ fn_src adv_ok; fn_src probe_tang_direct; } | sed "s#/tmp/tang-direct.json#$WORK/tmp/tang-direct.json#g" >"$WORK/probes.src"
[ -s "$WORK/img.src" ] && [ -s "$WORK/hard.src" ] || { printf 'FAIL a span extracted empty\n'; exit 1; }
grep -q '^probe_tang_direct() {' "$WORK/probes.src" && grep -q '^adv_ok() {' "$WORK/probes.src" \
  || { printf 'FAIL adv_ok/probe_tang_direct not found in 010\n'; exit 1; }
PIN_LINES="$(grep -E '^(GATUS|CADDY)_IMAGE="' "$PROVISION")"
eval "$PIN_LINES"
GATUS_PIN="$GATUS_IMAGE"
CADDY_PIN="$CADDY_IMAGE"

cat >"$WORK/prelude.src" <<'EOF'
set -euo pipefail
log()  { printf 'log: %s\n' "$*"; }
warn() { printf 'warn: %s\n' "$*" >&2; }
die()  { printf 'FAIL(die): %s\n' "$*" >&2; exit 1; }
alert_intent() { :; }
gatus_ext_items=()
TANG_PORT="8081"
GATUS_PORT="8080"
CADDY_ORIGIN_CRT="/etc/caddy/origin.crt"
CADDY_ORIGIN_KEY="/etc/caddy/origin.key"
CADDY_AOP_CA="/etc/caddy/aop-ca.pem"
CADDY_CHALLENGE_DIR="/var/lib/caddy/acme-challenge"
EOF
{ cat "$WORK/prelude.src"; printf '%s\n' "$PIN_LINES"; cat "$WORK/hard.src" "$WORK/probes.src" "$WORK/img.src"; } >"$WORK/lib.sh"

# ---- PATH stubs ------------------------------------------------------------
BIN="$WORK/bin"
mkdir -p "$BIN"
cat >"$BIN/docker" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$STUB/docker.log"
last="${*: -1}"
listed() { # $1 = stub list file, $2 = text -> 0 when a listed digest occurs in the text
  local l
  [ -f "$1" ] || return 1
  while IFS= read -r l; do [ -n "$l" ] && case "$2" in *"$l"*) return 0 ;; esac; done <"$1"
  return 1
}
case "$1" in
  inspect)
    case "$*" in
      *' id:'*) # inspect of a container's object id: the RepoDigests it was created from
        ref="${last#id:}"; d="${ref#*@}"; r="${ref%%@*}"
        if listed "$STUB/lie_for" "$d"; then d="sha256:$(printf 'f%.0s' $(seq 1 64))"; fi
        printf '%s@%s\n' "${r%:*}" "$d"; exit 0 ;;
      *'{{.Image}}'*) [ -f "$STUB/running.$last" ] || exit 1; printf 'id:%s\n' "$(cat "$STUB/running.$last")"; exit 0 ;; # ci-allowlist: code — docker inspect field name stub, not a live reference.
    esac
    cat "$STUB/repodigests" 2>/dev/null; exit 0 ;;
  pull) printf '%s\n' "$last" >>"$STUB/pulls"; exit "$(cat "$STUB/pull_rc" 2>/dev/null || echo 0)" ;;
  run)
    case " $* " in
      *" --rm "*) printf '%s\n' "$*" >>"$STUB/validate.log"
        listed "$STUB/validate_bad" "$*" && exit 1
        exit "$(cat "$STUB/validate_rc" 2>/dev/null || echo 0)" ;;
    esac
    name=""; prev=""
    for a in "$@"; do [ "$prev" = "--name" ] && name="$a"; prev="$a"; done
    [ -n "$name" ] || exit 1
    listed "$STUB/run_fail" "$last" && exit 1
    printf '%s\n' "$last" >"$STUB/running.$name"
    exit 0 ;;
  rm) rm -f "$STUB/running.$last"; exit 0 ;;
  ps) for f in "$STUB"/running.*; do [ -e "$f" ] && printf '%s\n' "${f##*/running.}"; done; exit 0 ;;
esac
exit 0
EOF
cat >"$BIN/curl" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$STUB/curl.log"
out=""; url=""; wfmt=""; prev=""
for a in "$@"; do
  case "$prev" in
    -o) out="$a" ;;
    -w) wfmt="$a" ;;
    -K) if [ "$a" = "-" ]; then
          cfg="$(cat)"; printf '%s\n' "$cfg" >>"$STUB/curl.stdin"
          u="$(printf '%s\n' "$cfg" | sed -n 's/^url = "\(.*\)"$/\1/p')"; [ -z "$u" ] || url="$u"
        fi ;;
  esac
  case "$prev:$a" in -K:*) ;; *:http://*|*:https://*) url="$a" ;; esac
  prev="$a"
done
emit() { if [ -n "$out" ] && [ "$out" != "/dev/null" ]; then printf '%s' "$1" >"$out"; elif [ -z "$out" ]; then printf '%s' "$1"; fi; }
broken() { # $1 container name -> 0 when it runs a digest the case marked broken
  [ -e "$STUB/fail_all" ] && return 0
  [ -f "$STUB/broken" ] && [ -f "$STUB/running.$1" ] || return 1
  while IFS= read -r d; do [ -n "$d" ] && grep -qF -- "$d" "$STUB/running.$1" && return 0; done <"$STUB/broken"
  return 1
}
ADV='{"payload":"eyJrZXlzIjpbXX0","protected":"e30","signature":"c2ln"}'
hubpage() { # $1 = repo label -> the paged / endless / single-file registry answer
  local pg
  pg="$(printf '%s' "$url" | sed -n 's/.*[?&]page=\([0-9]*\).*/\1/p')"; pg="${pg:-1}"
  printf '%s %s\n' "$1" "$pg" >>"$STUB/hub.log"
  if [ -e "$STUB/hub-endless" ]; then
    printf '{"next":"https://hub.docker.com/v2/repositories/library/caddy/tags?page=%s&page_size=100&name=2.","results":[]}' "$((pg + 1))"
  elif [ -d "$STUB/hub-$1-pages" ]; then
    [ -f "$STUB/hub-$1-pages/$pg.json" ] || exit 22
    cat "$STUB/hub-$1-pages/$pg.json"
  else
    cat "$STUB/hub-$1.json"
  fi
}
case "$url" in
  https://hub.docker.com/v2/repositories/library/caddy/tags*) hubpage caddy ;;
  https://hub.docker.com/v2/repositories/twinproduction/gatus/tags*) hubpage gatus ;;
  http://127.0.0.1:8080/api/v1/endpoints/statuses) broken gatus && exit 22; emit '[]' ;;
  http://127.0.0.1:8080/api/v1/endpoints/*/external*) printf '%s\n' "$url" >>"$STUB/push.log"; exit "$(cat "$STUB/push_rc" 2>/dev/null || echo 0)" ;;
  http://127.0.0.1:8081/adv) [ -e "$STUB/tang_down" ] && exit 7; emit "$ADV" ;;
  http://127.0.0.1/adv) broken caddy && exit 22; emit "$ADV" ;;
  https://ntfy.sh/*) printf '%s\n' "$url" >>"$STUB/ntfy.log" ;;
  *) exit 7 ;;
esac
[ -z "$wfmt" ] || printf '200'
exit 0
EOF
for t in systemctl sleep; do
  printf '#!/usr/bin/env bash\nprintf "%%s\\n" "%s $*" >>"${STUB:-/dev/null}/sys.log" 2>/dev/null || true\nexit 0\n' "$t" >"$BIN/$t"
done
chmod +x "$BIN"/*

TOKEN="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
epoch() { date -u -d "$1" +%s; }
NOW_LATE="$(epoch 2026-10-27T12:00:00Z)"     # every recorded build soaked
NOW_FRESH="$(epoch 2026-10-22T20:00:00Z)"    # caddy 2.11.7-alpine pushed ~2 h earlier
GATUS_NEW="sha256:094eb186e55235db367e90e9d56140e5897b7044c41de23cde4cc18e6da1242e"   # v5.37.0 (recorded)
GATUS_OLD="sha256:c5f210d095fa78e6efaa20ffeb14803f2ba4f10615e16a6d12087697149617f0"   # v5.36.0 (recorded)
CADDY_NEW="sha256:eb4d35b7452d1ab6171fbdbe8d9275b2301dad6dad92115d91e19fb9b24d510f"   # 2.11.7-alpine (recorded)
CADDY_OLD="sha256:6aeddd44c3078b0f9a35206472a11420648a79c184603ef95957d0a20044cb2b"   # 2.11.4-alpine (recorded)
FAKE="sha256:$(printf 'a%.0s' $(seq 1 64))"
REBUILD="sha256:$(printf 'b%.0s' $(seq 1 64))"   # a same-version rebuild the updater recorded
GATUS_PIN_REF="$GATUS_PIN@$GATUS_OLD"
CADDY_PIN_REF="$CADDY_PIN@$CADDY_OLD"
NOW_INFLIGHT="$(epoch 2026-10-23T01:53:00Z)" # caddy 2.11.7-alpine ~8 h old: soaked, inside soak + one cycle
STATUS_TEST_HOST="status.example.test"

# Fixture variant: the recorded caddy list plus synthetic out-of-track tags
# pushed long ago (a 3.x major, a plain and a builder 2.99.0, a two-part tag).
jq --arg d "$FAKE" '.results += [
  {name: "3.0.0-alpine", digest: $d, tag_last_pushed: "2026-01-01T00:00:00Z"},
  {name: "2.99.0", digest: $d, tag_last_pushed: "2026-01-01T00:00:00Z"},
  {name: "2.99.0-builder-alpine", digest: $d, tag_last_pushed: "2026-01-01T00:00:00Z"},
  {name: "2.99-alpine", digest: $d, tag_last_pushed: "2026-01-01T00:00:00Z"}]' \
  "$HARNESS_DIR/fixtures/hub-caddy-tags.json" >"$WORK/hub-caddy-plus.json"

new_case() { # $1 case label; env: MODE (IMG_AUTO_UPDATES), SOAK -> sets C (case dir) and renders the updater
  C="$WORK/cases/$1"
  mkdir -p "$C/stub" "$C/state" "$C/etc/gatus"
  cp "$WORK/hub-caddy-plus.json" "$C/stub/hub-caddy.json"
  cp "$HARNESS_DIR/fixtures/hub-gatus-tags.json" "$C/stub/hub-gatus.json"
  printf '%s\n' "$TOKEN" >"$C/etc/token"
  printf 'NTFY_TOPIC=%q\nNTFY_TOKEN=%q\n' "pc-test-topic" "ntfy-test-credential" >"$C/etc/env"
  printf 'ref=%s\n' "$GATUS_PIN_REF" >"$C/state/gatus.pin"
  printf 'ref=%s\n' "$CADDY_PIN_REF" >"$C/state/caddy.pin"
  printf '%s\n' "$GATUS_PIN_REF" >"$C/stub/running.gatus"
  printf '%s\n' "$CADDY_PIN_REF" >"$C/stub/running.caddy"
  printf 'twinproduction/gatus@%s\ncaddy@%s\n' "$GATUS_OLD" "$CADDY_OLD" >"$C/stub/repodigests"
  : >"$C/stub/docker.log"; : >"$C/stub/curl.log"; : >"$C/stub/curl.stdin"; : >"$C/stub/push.log"; : >"$C/stub/ntfy.log"
  (
    IMG_STATE_DIR="$C/state" IMG_ENV_FILE="$C/etc/env" IMG_TOKEN_FILE="$C/etc/token" \
    CADDY_CONFIG="$C/etc/Caddyfile" GATUS_CONFIG="$C/etc/gatus/config.yaml" \
    IMG_AUTO_UPDATES="${MODE-}" IMG_UPDATE_SOAK_HOURS="${SOAK-}"
    # shellcheck source=/dev/null
    . "$WORK/lib.sh"
    STATUS_HOST="${SH-$STATUS_TEST_HOST}" ORIGIN_TLS=0 AOP_TLS=""
    # The hardening check has its own harness (tests/edge-origin-auth); here a
    # stub stands in so the case controls it (hard_fail in the stub dir).
    assert_caddyfile_hardened() { [ ! -e "$STUB/hard_fail" ]; }
    render_img_updater
  ) >"$C/updater" 2>"$C/render.err" || bad "$1: updater renders"
}
run_updater() { # $1 = IMG_NOW epoch, $2.. = extra env -> runs the rendered updater in the current case
  local rc=0 now="$1"
  shift
  env "$@" PATH="$BIN:$PATH" TMPDIR="$WORK/tmp" STUB="$C/stub" IMG_NOW="$now" IMG_CHECK_TRIES=1 IMG_CHECK_SLEEP=0 IMG_START_SLEEP=0 \
    EDGE_PULL_RETRY_SLEEP=0 bash "$C/updater" >"$C/out.log" 2>&1 || rc=$?
  return "$rc"
}
fn() { # run lib functions in a subshell: fn <state dir> <code...>
  local st="$1"; shift
  ( IMG_STATE_DIR="$st"; export PATH="$BIN:$PATH" STUB="$WORK/fnstub"
    # shellcheck source=/dev/null
    . "$WORK/lib.sh"; eval "$*" ) 2>/dev/null
}
mkdir -p "$WORK/fnstub"
printf 'caddy@%s\ntwinproduction/gatus@%s\n' "$CADDY_OLD" "$GATUS_OLD" >"$WORK/fnstub/repodigests"
push_of() { grep "$1-updates" "$C/stub/push.log" || true; }

# ---- suites ----------------------------------------------------------------
suite_precedence() {
  local st="$WORK/prec" rec
  rm -rf "$st"; mkdir -p "$st"
  is "precedence: no record -> the repo pin BY DIGEST" "$CADDY_PIN_REF" "$(fn "$st" img_effective_ref caddy "$CADDY_PIN_REF")"
  is "precedence: off -> the repo pin BY DIGEST" "$CADDY_PIN_REF" "$(fn "$st" IMG_AUTO_UPDATES=off img_effective_ref caddy "$CADDY_PIN_REF")"
  printf 'ref=caddy:2.11.7-alpine@%s\n' "$CADDY_NEW" >"$st/caddy.state"
  is "precedence: newer record in the track wins (no downgrade)" "caddy:2.11.7-alpine@$CADDY_NEW" "$(fn "$st" img_effective_ref caddy caddy:2.11.4-alpine)"
  is "precedence: equal-version record (rebuild digest) is kept" "caddy:2.11.7-alpine@$CADDY_NEW" "$(fn "$st" img_effective_ref caddy caddy:2.11.7-alpine)"
  is "precedence: a newer pin in the track wins" "caddy:2.11.9-alpine" "$(fn "$st" img_effective_ref caddy caddy:2.11.9-alpine)"
  is "precedence: a pin in another major resets the track" "caddy:3.0.0-alpine" "$(fn "$st" img_effective_ref caddy caddy:3.0.0-alpine)"
  is "precedence: a pin with another suffix resets the track" "caddy:2.11.4" "$(fn "$st" img_effective_ref caddy caddy:2.11.4)"
  is "precedence: a record for another repository is ignored" "other/caddy:2.11.4-alpine" "$(fn "$st" img_effective_ref caddy other/caddy:2.11.4-alpine)"
  is "precedence: IMG_AUTO_UPDATES=off returns to the pin" "caddy:2.11.4-alpine" "$(fn "$st" IMG_AUTO_UPDATES=off img_effective_ref caddy caddy:2.11.4-alpine)"
  printf '%s\n' "$CADDY_NEW" >"$st/caddy.bad"
  is "precedence: a recorded bad digest is never selected" "caddy:2.11.4-alpine" "$(fn "$st" img_effective_ref caddy caddy:2.11.4-alpine)"
  rm -f "$st/caddy.bad"
  printf 'ref=caddy:2.11.7-alpine\n' >"$st/caddy.state"
  is "precedence: a digest-less (malformed) record is ignored" "caddy:2.11.4-alpine" "$(fn "$st" img_effective_ref caddy caddy:2.11.4-alpine)"
  printf 'ref=caddy:2.11.7-alpine@%s\n' "$CADDY_NEW" >"$st/caddy.state"
  fn "$st" img_reconcile_state caddy caddy:2.11.4-alpine >/dev/null
  [ -f "$st/caddy.state" ] && ok "reconcile: an honoured record is kept" || bad "reconcile: an honoured record is kept"
  fn "$st" img_reconcile_state caddy caddy:3.0.0-alpine >/dev/null
  [ -f "$st/caddy.state" ] && bad "reconcile: a Lane B major pin drops the old-track record" || ok "reconcile: a Lane B major pin drops the old-track record"
  printf 'ref=caddy:2.11.7-alpine@%s\n' "$CADDY_NEW" >"$st/caddy.state"
  fn "$st" IMG_AUTO_UPDATES=off img_reconcile_state caddy caddy:2.11.4-alpine >/dev/null
  [ -f "$st/caddy.state" ] && bad "reconcile: the off switch drops the record" || ok "reconcile: the off switch drops the record"
  rec="$(fn "$st" 'img_state_put gatus "twinproduction/gatus:v5.37.0@'"$GATUS_NEW"'"; img_state_get gatus')"
  is "state: put/get round-trips a ref" "twinproduction/gatus:v5.37.0@$GATUS_NEW" "$rec"
  is "state: the state dir is 0700" "700" "$(stat -c %a "$st")"
  is "state: the state file is 0600" "600" "$(stat -c %a "$st/gatus.state")"
}

suite_track() {
  local t tags pick
  is "track: caddy 2.x.y-alpine accepted" "2.11.7" "$(fn "$WORK" img_ver_key 2.11.7-alpine 2.11.4-alpine)"
  is "track: gatus v5.x.y accepted" "5.37.0" "$(fn "$WORK" img_ver_key v5.37.0 v5.36.0)"
  for t in 3.0.0-alpine 2.11.7 2.11.7-builder-alpine 2.11-alpine 2.11.7-windowsservercore-ltsc2022 1.9.9-alpine 2.11.05-alpine 2.011.5-alpine 02.11.5-alpine; do
    is "track: caddy tag $t refused" "" "$(fn "$WORK" img_ver_key "$t" 2.11.4-alpine || true)"
  done
  for t in v6.0.0 5.37.0 v5.37 v5.37.0-rc1; do
    is "track: gatus tag $t refused" "" "$(fn "$WORK" img_ver_key "$t" v5.36.0 || true)"
  done
  cp "$WORK/hub-caddy-plus.json" "$WORK/fnstub/hub-caddy.json"
  tags="$(fn "$WORK" img_hub_tags caddy 2.11.4-alpine)"
  is "track: the tag list carries the synthetic 3.x row (fixture sanity)" "1" "$(jq '[.[] | select(.name == "3.0.0-alpine")] | length' <<<"$tags")"
  printf '%s' "$tags" >"$WORK/tags.json"
  pick="$(IMG_NOW="$NOW_LATE" fn "$WORK/none" img_pick_candidate caddy caddy:2.11.4-alpine 2.11.4-alpine "$CADDY_OLD" '<"$WORK/tags.json"')"
  is "track: newest in-track build is picked over 3.x/plain/builder rows" "2.11.7-alpine $CADDY_NEW" "$pick"
}

suite_soak() {
  local pick
  jq -c '[.results[] | {name, digest, pushed: .tag_last_pushed}]' "$WORK/hub-caddy-plus.json" >"$WORK/tags.json"
  pick="$(IMG_NOW="$NOW_FRESH" fn "$WORK/none" img_pick_candidate caddy caddy:2.11.4-alpine 2.11.4-alpine "$CADDY_OLD" '<"$WORK/tags.json"')"
  is "soak: a build pushed 2 h ago is not taken at the 6 h default (previous patch is)" "2.11.6-alpine" "${pick%% *}"
  pick="$(IMG_NOW="$NOW_FRESH" IMG_UPDATE_SOAK_HOURS=0 fn "$WORK/none" img_pick_candidate caddy caddy:2.11.4-alpine 2.11.4-alpine "$CADDY_OLD" '<"$WORK/tags.json"')"
  is "soak: soak 0 takes the newest" "2.11.7-alpine" "${pick%% *}"
  is "soak: a bad soak value is refused" "1" "$(fn "$WORK" 'IMG_UPDATE_SOAK_HOURS=6h; img_soak_hours >/dev/null && echo 0 || echo 1')"
  is "soak: default is 6" "6" "$(fn "$WORK" img_soak_hours)"
  MODE="" SOAK="" new_case soak_e2e
  run_updater "$NOW_FRESH" || bad "soak e2e: updater exits 0"
  has "soak e2e: caddy moves only to the soaked 2.11.6-alpine" "$(cat "$C/stub/running.caddy")" "caddy:2.11.6-alpine@"
}

suite_swap() {
  local vline rline
  MODE="" SOAK="" new_case swap
  if run_updater "$NOW_LATE"; then ok "swap: updater exits 0"; else bad "swap: updater exits 0 ($(tail -3 "$C/out.log"))"; fi
  is "swap: gatus runs v5.37.0 by digest" "twinproduction/gatus:v5.37.0@$GATUS_NEW" "$(cat "$C/stub/running.gatus")"
  is "swap: caddy runs 2.11.7-alpine by digest" "caddy:2.11.7-alpine@$CADDY_NEW" "$(cat "$C/stub/running.caddy")"
  has "swap: pulled by digest" "$(cat "$C/stub/docker.log")" "pull -q caddy@$CADDY_NEW"
  has "swap: caddy validate of the LIVE Caddyfile with the candidate" "$(cat "$C/stub/validate.log" 2>/dev/null)" \
    "run --rm --network none --cap-drop ALL --read-only --tmpfs /config --tmpfs /data -v $C/etc/Caddyfile:/tmp/Caddyfile.new:ro caddy@$CADDY_NEW caddy validate --config /tmp/Caddyfile.new --adapter caddyfile"
  vline="$(grep -n 'run --rm' "$C/stub/docker.log" | head -n1 | cut -d: -f1)"
  rline="$(grep -n 'run -d --name caddy' "$C/stub/docker.log" | head -n1 | cut -d: -f1)"
  if [ -n "$vline" ] && [ -n "$rline" ] && [ "$vline" -lt "$rline" ]; then ok "swap: validate runs before the caddy recreate"; else bad "swap: validate runs before the caddy recreate"; fi
  has "swap: caddy recreated with the shared 010 run args" "$(cat "$C/stub/docker.log")" \
    "run -d --name caddy --restart unless-stopped --network host --memory 256m -e GOMEMLIMIT=230MiB -e GOMAXPROCS=1 -v $C/etc/Caddyfile:/etc/caddy/Caddyfile:ro"
  has "swap: gatus recreated with the shared 010 run args" "$(cat "$C/stub/docker.log")" \
    "run -d --name gatus --restart unless-stopped -p 127.0.0.1:8080:8080 --add-host=hostanchor:host-gateway -e GATUS_CONFIG_PATH=/config -v $C/etc/gatus:/config:ro"
  is "swap: caddy state recorded" "ref=caddy:2.11.7-alpine@$CADDY_NEW" "$(cat "$C/state/caddy.state" 2>/dev/null)"
  is "swap: gatus state recorded" "ref=twinproduction/gatus:v5.37.0@$GATUS_NEW" "$(cat "$C/state/gatus.state" 2>/dev/null)"
  is "swap: two success pushes" "2" "$(grep -c 'external?success=true' "$C/stub/push.log" || true)"
  has "swap: push key for caddy" "$(cat "$C/stub/push.log")" "/api/v1/endpoints/anchor_caddy-updates/external?success=true"
  has "swap: push key for gatus" "$(cat "$C/stub/push.log")" "/api/v1/endpoints/anchor_gatus-updates/external?success=true"
  is "swap: no alert on success" "" "$(cat "$C/stub/ntfy.log")"
  : >"$C/stub/docker.log"; : >"$C/stub/push.log"
  printf 'twinproduction/gatus@%s\ncaddy@%s\n' "$GATUS_NEW" "$CADDY_NEW" >"$C/stub/repodigests"
  run_updater "$NOW_LATE" || bad "swap rerun: exits 0"
  lacks "swap rerun: nothing recreated once current" "$(cat "$C/stub/docker.log")" "run -d"
  is "swap rerun: two success pushes (heartbeat)" "2" "$(grep -c 'success=true' "$C/stub/push.log" || true)"
  # A same-tag rebuild (new digest under the current tag) flows.
  jq --arg d "$FAKE" '(.results[] | select(.name == "v5.37.0")) |= (.digest = $d)' "$HARNESS_DIR/fixtures/hub-gatus-tags.json" >"$C/stub/hub-gatus.json"
  run_updater "$NOW_LATE" || bad "rebuild: exits 0"
  is "rebuild: a same-tag rebuild is taken by digest" "twinproduction/gatus:v5.37.0@$FAKE" "$(cat "$C/stub/running.gatus")"
}

suite_rollback() {
  MODE="" SOAK="" new_case rollback
  printf '%s\n' "$GATUS_NEW" >"$C/stub/broken"
  run_updater "$NOW_LATE" || bad "rollback: exits 0"
  is "rollback: gatus restored to the previous exact digest" "$GATUS_PIN_REF" "$(cat "$C/stub/running.gatus")"
  has "rollback: the candidate is held as bad" "$(cat "$C/state/gatus.bad" 2>/dev/null)" "$GATUS_NEW"
  if [ -f "$C/state/gatus.state" ]; then bad "rollback: no state recorded for the failed candidate"; else ok "rollback: no state recorded for the failed candidate"; fi
  has "rollback: one failure push" "$(cat "$C/stub/push.log")" "anchor_gatus-updates/external?success=false&duration="
  has "rollback: error string carries version/digest prefix/reason class only" "$(grep 'gatus-updates' "$C/stub/push.log")" "error=rolled-back%20ver%3Dv5.37.0%20dig%3D094eb186e552%20reason%3Dgatus"
  is "rollback: gatus pushed exactly once (failure)" "1" "$(grep -c 'gatus-updates' "$C/stub/push.log" || true)"
  is "rollback: caddy unaffected (still swapped)" "caddy:2.11.7-alpine@$CADDY_NEW" "$(cat "$C/stub/running.caddy")"
  is "rollback: no direct alert while Gatus takes the push" "" "$(cat "$C/stub/ntfy.log")"
  : >"$C/stub/docker.log"; : >"$C/stub/push.log"
  # Past the soak from the hold: only the per-digest hold keeps it out now.
  run_updater "$((NOW_LATE + 8 * 3600))" || bad "rollback rerun: exits 0"
  lacks "rollback rerun: the bad digest is never retried" "$(cat "$C/stub/docker.log")" "$GATUS_NEW"
  has "rollback rerun: a box held behind the newest build stays red (no silent freeze)" "$(push_of gatus)" "success=false"
  has "rollback rerun: behind:<tag> reason:<hold class>" "$(push_of gatus)" "error=behind%3Av5.37.0%20reason%3Abad-gatus"
  has "rollback: the hold carries version, reason and time" "$(cat "$C/state/gatus.bad")" "$GATUS_NEW 5.37.0 gatus $NOW_LATE"
}

suite_ladder() {
  # Rung 2: the previous (recorded) digest cannot start again -> the pin.
  MODE="" SOAK="" new_case ladder_pin
  printf 'ref=twinproduction/gatus:v5.36.0@%s\n' "$REBUILD" >"$C/state/gatus.state"
  printf 'twinproduction/gatus:v5.36.0@%s\n' "$REBUILD" >"$C/stub/running.gatus"
  printf '%s\n' "$GATUS_NEW" >"$C/stub/broken"
  printf '%s\n' "$REBUILD" >"$C/stub/run_fail"
  run_updater "$NOW_LATE" || bad "ladder pin: exits 0"
  is "ladder pin: restore failed -> the provisioned pin digest runs" "$GATUS_PIN_REF" "$(cat "$C/stub/running.gatus")"
  has "ladder pin: outcome class" "$(push_of gatus)" "error=fell-back-to-pin%20ver%3Dv5.37.0%20dig%3D094eb186e552%20reason%3Dgatus%20restore%3Dstart"
  if [ -f "$C/state/gatus.state" ]; then bad "ladder pin: the record is dropped (back on the pin)"; else ok "ladder pin: the record is dropped (back on the pin)"; fi
  if [ -f "$C/state/disarmed" ]; then bad "ladder pin: a rung that held does not disarm"; else ok "ladder pin: a rung that held does not disarm"; fi
  is "ladder pin: no direct alert while Gatus takes the push" "" "$(cat "$C/stub/ntfy.log")"
  # Every rung fails: alert NOW (direct, even with Gatus up), disarm, keep the box.
  MODE="" SOAK="" new_case ladder_all
  printf 'ref=twinproduction/gatus:v5.36.0@%s\n' "$REBUILD" >"$C/state/gatus.state"
  printf 'twinproduction/gatus:v5.36.0@%s\n' "$REBUILD" >"$C/stub/running.gatus"
  printf '%s\n' "$GATUS_NEW" >"$C/stub/broken"
  printf '%s\n%s\n' "$REBUILD" "$GATUS_OLD" >"$C/stub/run_fail"
  run_updater "$NOW_LATE" || bad "ladder all: exits 0"
  has "ladder all: direct ntfy fires immediately (Gatus took the push too)" "$(cat "$C/stub/ntfy.log")" "https://ntfy.sh/pc-test-topic"
  has "ladder all: the red push still lands" "$(push_of gatus)" "error=all-rungs-failed%20ver%3Dv5.37.0"
  has "ladder all: the updater disarms" "$(cat "$C/state/disarmed" 2>/dev/null)" "reason=all-rungs-failed"
  is "ladder all: caddy is not touched once disarmed" "$CADDY_PIN_REF" "$(cat "$C/stub/running.caddy")"
  has "ladder all: caddy row red (disarmed)" "$(push_of caddy)" "error=disarmed%3Aall-rungs-failed"
  has "ladder all: the ntfy credential rides stdin" "$(cat "$C/stub/curl.stdin")" "Bearer ntfy-test-credential"
  has "ladder all: the ntfy topic rides stdin" "$(cat "$C/stub/curl.stdin")" 'url = "https://ntfy.sh/pc-test-topic"'
  lacks "ladder all: the ntfy credential never in argv" "$(cat "$C/stub/curl.log")" "ntfy-test-credential"
  lacks "ladder all: the ntfy topic never in argv" "$(cat "$C/stub/curl.log")" "pc-test-topic"
  : >"$C/stub/docker.log"; : >"$C/stub/push.log"; : >"$C/stub/ntfy.log"
  run_updater "$NOW_LATE" || bad "ladder all rerun: exits 0"
  lacks "ladder all rerun: a disarmed updater swaps nothing" "$(cat "$C/stub/docker.log")" "run -d"
  lacks "ladder all rerun: never green while disarmed" "$(cat "$C/stub/push.log")" "success=true"
  # Gatus is what broke and every rung fails: the direct alert still fires.
  MODE="" SOAK="" new_case ladder_nogatus
  printf '%s\n' "$GATUS_NEW" >"$C/stub/broken"
  printf '%s\n' "$GATUS_OLD" >"$C/stub/run_fail"
  printf '22' >"$C/stub/push_rc"
  run_updater "$NOW_LATE" || bad "ladder no-gatus: exits 0"
  has "ladder no-gatus: direct ntfy fires" "$(cat "$C/stub/ntfy.log")" "https://ntfy.sh/pc-test-topic"
  has "ladder no-gatus: message class" "$(cat "$C/out.log")" "all-rungs-failed ver=v5.37.0"
}

suite_live() {
  # Repro D: Caddy is down and there is nothing to update -> red, never green.
  MODE="" SOAK="" new_case live_down
  printf 'ref=caddy:2.11.7-alpine@%s\n' "$CADDY_NEW" >"$C/state/caddy.state"
  rm -f "$C/stub/running.caddy"
  run_updater "$NOW_LATE" || bad "live down: exits 0"
  has "live down: caddy row red from the live check" "$(push_of caddy)" "error=unhealthy%3Anot-running"
  lacks "live down: no green while Caddy is down" "$(push_of caddy)" "success=true"
  # Repro C: Caddy up but :80 does not proxy tang -> red, and no swap.
  MODE="" SOAK="" new_case live_80
  printf '%s\n' "$CADDY_OLD" >"$C/stub/broken"
  run_updater "$NOW_LATE" || bad "live 80: exits 0"
  has "live 80: red with the failing class" "$(push_of caddy)" "error=unhealthy%3Acaddy-80"
  lacks "live 80: an unhealthy box never swaps" "$(cat "$C/stub/docker.log")" "run -d --name caddy"
  # Tang path first: with tang down AND Gatus down, the class is tang.
  MODE="" SOAK="" new_case live_tang
  : >"$C/stub/fail_all"; : >"$C/stub/tang_down"
  run_updater "$NOW_LATE" || bad "live tang: exits 0"
  has "live tang: the tang path is checked first" "$(push_of gatus)" "error=unhealthy%3Atang-direct"
  # No status host: the TLS/hardening half fails the check, never a silent pass.
  MODE="" SOAK="" SH="" new_case live_nohost
  run_updater "$NOW_LATE" || bad "live no-host: exits 0"
  has "live no-host: red no-status-host" "$(push_of caddy)" "error=unhealthy%3Ano-status-host"
  lacks "live no-host: nothing swapped" "$(cat "$C/stub/docker.log")" "run -d"
  # Hardening fails -> red, no swap.
  MODE="" SOAK="" new_case live_hard
  : >"$C/stub/hard_fail"
  run_updater "$NOW_LATE" || bad "live hard: exits 0"
  has "live hard: red hardening" "$(push_of caddy)" "error=unhealthy%3Ahardening"
  # The running container is not the recorded digest -> red digest.
  MODE="" SOAK="" new_case live_drift
  printf 'caddy:2.11.4-alpine@%s\n' "$FAKE" >"$C/stub/running.caddy"
  run_updater "$NOW_LATE" || bad "live drift: exits 0"
  has "live drift: red digest" "$(push_of caddy)" "error=unhealthy%3Adigest"
}

suite_binding() {
  # The candidate tag resolves to another build at run time -> never verified as the candidate.
  MODE="" SOAK="" new_case binding
  printf '%s\n' "$CADDY_NEW" >"$C/stub/lie_for"
  run_updater "$NOW_LATE" || bad "binding: exits 0"
  has "binding: a running digest != candidate fails before the self-checks" "$(push_of caddy)" "error=rolled-back%20ver%3D2.11.7-alpine%20dig%3Deb4d35b7452d%20reason%3Ddigest"
  is "binding: restored to the pin digest" "$CADDY_PIN_REF" "$(cat "$C/stub/running.caddy")"
  has "binding: validate runs the candidate BY DIGEST" "$(cat "$C/stub/validate.log")" " caddy@$CADDY_NEW caddy validate"
  has "binding: validate is confined (no network, no caps, read-only)" "$(cat "$C/stub/validate.log")" "run --rm --network none --cap-drop ALL --read-only "
}

suite_registry() {
  local k n
  MODE="" SOAK="" new_case pages
  mkdir -p "$C/stub/hub-caddy-pages"
  n="$(jq '.results | length' "$C/stub/hub-caddy.json")"
  for k in 1 2 3 4; do
    jq --argjson k "$k" --argjson n "$n" '(.results | sort_by(.name == "2.11.7-alpine")) as $r | (($n + 3) / 4 | floor) as $c
      | {count: $n, next: (if $k < 4 then "https://hub.docker.com/v2/repositories/library/caddy/tags?page=\($k + 1)&page_size=100&name=2." else null end),
         previous: null, results: $r[(($k - 1) * $c):($k * $c)]}' "$C/stub/hub-caddy.json" >"$C/stub/hub-caddy-pages/$k.json"
  done
  is "registry: the 4-page stub carries the newest build on page 4 only" "1" "$(jq '[.results[] | select(.name == "2.11.7-alpine")] | length' "$C/stub/hub-caddy-pages/4.json")"
  run_updater "$NOW_LATE" || bad "registry pages: exits 0"
  is "registry: every page read (4)" "4" "$(grep -c '^caddy ' "$C/stub/hub.log")"
  is "registry: the newest build from page 4 is taken" "caddy:2.11.7-alpine@$CADDY_NEW" "$(cat "$C/stub/running.caddy")"
  MODE="" SOAK="" new_case page_err
  mkdir -p "$C/stub/hub-caddy-pages"
  cp "$WORK/cases/pages/stub/hub-caddy-pages/1.json" "$WORK/cases/pages/stub/hub-caddy-pages/2.json" "$C/stub/hub-caddy-pages/"
  cp "$WORK/cases/pages/stub/hub-caddy-pages/4.json" "$C/stub/hub-caddy-pages/"
  run_updater "$NOW_LATE" || bad "registry page error: exits 0"
  has "registry: a page error fails the whole check closed" "$(push_of caddy)" "error=registry-listing-incomplete"
  is "registry: no update on a partial list" "$CADDY_PIN_REF" "$(cat "$C/stub/running.caddy")"
  MODE="" SOAK="" new_case page_cap
  : >"$C/stub/hub-endless"
  run_updater "$NOW_LATE" || bad "registry cap: exits 0"
  has "registry: the page cap fails closed" "$(push_of caddy)" "error=registry-listing-incomplete"
  is "registry: the cap is 20 pages" "20" "$(grep -c '^caddy ' "$C/stub/hub.log")"
}

suite_freeze() {
  # A soaked candidate whose pull fails: green inside soak + one cycle ...
  MODE="" SOAK="" new_case freeze_inflight
  printf '1' >"$C/stub/pull_rc"
  run_updater "$NOW_INFLIGHT" || bad "freeze in-flight: exits 0"
  has "freeze: within soak + one cycle stays green" "$(push_of caddy)" "success=true"
  # ... red once the gap outlives it.
  MODE="" SOAK="" new_case freeze_late
  printf '1' >"$C/stub/pull_rc"
  run_updater "$NOW_LATE" || bad "freeze late: exits 0"
  has "freeze: behind past soak + one cycle is red" "$(push_of caddy)" "error=behind%3A2.11.7-alpine%20reason%3Apull"
}

suite_marks() {
  local st="$WORK/marks" pick
  rm -rf "$st"; mkdir -p "$st"
  jq -c '[.results[] | {name, digest, pushed: .tag_last_pushed}]' "$HARNESS_DIR/fixtures/hub-gatus-tags.json" >"$WORK/gtags.json"
  printf '%s 5.37.0 gatus %s\n' "$FAKE" "$((NOW_LATE - 3600))" >"$st/gatus.bad"
  pick="$(IMG_NOW="$NOW_LATE" fn "$st" img_pick_candidate gatus "$GATUS_PIN" v5.36.0 "$GATUS_OLD" '<"$WORK/gtags.json"')"
  is "marks: a re-pushed digest of a held version soaks again from the hold" "" "$pick"
  printf '%s 5.37.0 gatus %s\n' "$FAKE" "$((NOW_LATE - 7 * 3600))" >"$st/gatus.bad"
  pick="$(IMG_NOW="$NOW_LATE" fn "$st" img_pick_candidate gatus "$GATUS_PIN" v5.36.0 "$GATUS_OLD" '<"$WORK/gtags.json"')"
  is "marks: ... and is taken once soaked past the hold" "v5.37.0 $GATUS_NEW" "$pick"
  # Validate: the running build rejects the live Caddyfile too -> config, nothing held.
  MODE="" SOAK="" new_case validate_config
  printf '1' >"$C/stub/validate_rc"
  run_updater "$NOW_LATE" || bad "validate-config: exits 0"
  has "marks: a Caddyfile the running build rejects too is a config problem" "$(push_of caddy)" "error=validate-config"
  if [ -s "$C/state/caddy.bad" ]; then bad "marks: a config problem holds no candidate"; else ok "marks: a config problem holds no candidate"; fi
  # A pin change clears the holds at or below the new pin (the manual clear).
  rm -rf "$st"; mkdir -p "$st"
  printf '%s 2.11.5 validate 1\n%s 2.11.9 caddy-80 2\n' "$FAKE" "$REBUILD" >"$st/caddy.bad"
  : >"$WORK/fnstub/pulls"
  is "pin: resolved to the registry digest" "caddy:2.11.6-alpine@$CADDY_OLD" "$(fn "$st" img_pin_resolve caddy caddy:2.11.6-alpine)"
  is "pin: recorded" "ref=caddy:2.11.6-alpine@$CADDY_OLD" "$(cat "$st/caddy.pin" 2>/dev/null)"
  is "pin: holds at/below the new pin cleared, above kept" "$REBUILD 2.11.9 caddy-80 2" "$(cat "$st/caddy.bad")"
  is "pin: one pull" "1" "$(grep -c . "$WORK/fnstub/pulls")"
  fn "$st" img_pin_resolve caddy caddy:2.11.6-alpine >/dev/null
  is "pin: resolved once per pin tag (no second pull)" "1" "$(grep -c . "$WORK/fnstub/pulls")"
  printf '1' >"$WORK/fnstub/pull_rc"
  is "pin: an unresolvable pin fails (never a tag-only ref)" "rc=1" "$(fn "$st" 'img_pin_resolve caddy caddy:2.11.8-alpine && echo rc=0 || echo rc=1')"
  rm -f "$WORK/fnstub/pull_rc"
  # No pin record on the box -> red, nothing runs.
  MODE="" SOAK="" new_case nopin
  rm -f "$C/state/caddy.pin"
  run_updater "$NOW_LATE" || bad "no pin: exits 0"
  has "pin: no pin record -> red" "$(push_of caddy)" "error=no-pin-record"
}

suite_drill() {
  MODE="" SOAK="" new_case drill
  printf 'ref=caddy:2.11.7-alpine@%s\n' "$CADDY_NEW" >"$C/state/caddy.state"
  printf 'caddy:2.11.7-alpine@%s\n' "$CADDY_NEW" >"$C/stub/running.caddy"
  run_updater "$NOW_LATE" IMG_DRILL=caddy || bad "drill: exits 0"
  has "drill: a candidate-scoped fault yields a clean rollback" "$(push_of caddy)" "error=rolled-back%20drill%20ver%3D2.11.7-alpine%20dig%3Deb4d35b7452d%20reason%3Ddrill"
  is "drill: the same digest runs afterwards" "caddy:2.11.7-alpine@$CADDY_NEW" "$(cat "$C/stub/running.caddy")"
  if [ -e "$C/state/caddy.bad" ] || [ -e "$C/state/disarmed" ]; then bad "drill: no hold, no disarm"; else ok "drill: no hold, no disarm"; fi
  is "drill: caddy recreated twice (fault + restore)" "2" "$(grep -c 'run -d --name caddy' "$C/stub/docker.log")"
  : >"$C/stub/push.log"
  run_updater "$NOW_LATE" || bad "drill rerun: exits 0"
  has "drill: the next round is green again" "$(push_of caddy)" "success=true"
}

suite_validate() {
  MODE="" SOAK="" new_case validate
  printf '%s\n' "$CADDY_NEW" >"$C/stub/validate_bad"
  run_updater "$NOW_LATE" || bad "validate: exits 0"
  is "validate: caddy never recreated on a rejected candidate" "$CADDY_PIN_REF" "$(cat "$C/stub/running.caddy")"
  lacks "validate: no caddy docker run" "$(cat "$C/stub/docker.log")" "run -d --name caddy"
  has "validate: rejected candidate held as bad (reason validate)" "$(cat "$C/state/caddy.bad" 2>/dev/null)" "$CADDY_NEW 2.11.7 validate "
  has "validate: failure pushed" "$(grep caddy-updates "$C/stub/push.log")" "reason%3Dvalidate"
}

suite_token() {
  local d="$WORK/tok" out first second
  MODE="" SOAK="" new_case token
  printf '%s\n' "$GATUS_NEW" >"$C/stub/broken"
  run_updater "$NOW_LATE" || true
  has "token: the push header rides curl stdin" "$(cat "$C/stub/curl.stdin")" "Authorization: Bearer $TOKEN"
  lacks "token: never in curl argv" "$(cat "$C/stub/curl.log")" "$TOKEN"
  lacks "token: never in the updater output" "$(cat "$C/out.log")" "$TOKEN"
  lacks "token: never in the push URL" "$(cat "$C/stub/push.log")" "$TOKEN"
  lacks "token: never in the rendered updater" "$(cat "$C/updater")" "$TOKEN"
  rm -rf "$d"; mkdir -p "$d"
  out="$( ( IMG_TOKEN_FILE="$d/sub/token"; NTFY_TOPIC=t; . "$WORK/lib.sh"; img_status_items_add; printf '%s\n' "${gatus_ext_items[@]}" ) 2>&1 )"
  is "token: token file is 0600" "600" "$(stat -c %a "$d/sub/token" 2>/dev/null)"
  is "token: token dir is 0700" "700" "$(stat -c %a "$d/sub" 2>/dev/null)"
  has "token: external rows rendered with the 24 h heartbeat" "$out" "      interval: 24h"
  has "token: caddy row rendered" "$out" "  - name: caddy updates"
  has "token: gatus row rendered" "$out" "  - name: gatus updates"
  has "token: rows carry the box token" "$out" "    token: \"$(cat "$d/sub/token" 2>/dev/null)\""
  lacks "token: the add call prints nothing" "$( ( IMG_TOKEN_FILE="$d/sub/t2"; . "$WORK/lib.sh"; img_status_items_add ) 2>&1 )" "token"
  has "token: alert once per failure, no resolve push" "$out" "        send-on-resolved: false"
  first="$(cat "$d/sub/token")"
  ( IMG_TOKEN_FILE="$d/sub/token"; . "$WORK/lib.sh"; img_status_items_add ) >/dev/null 2>&1
  second="$(cat "$d/sub/token")"
  if [ -n "$first" ] && [ "$first" != "$second" ]; then ok "token: regenerated on every provision run"; else bad "token: regenerated on every provision run"; fi
  if [[ "$second" =~ ^[0-9a-f]{64}$ ]]; then ok "token: 256-bit lowercase hex"; else bad "token: 256-bit lowercase hex"; fi
}

suite_off() {
  local d="$WORK/off" out
  rm -rf "$d"; mkdir -p "$d"
  : >"$d/token"
  out="$( ( IMG_AUTO_UPDATES=off IMG_TOKEN_FILE="$d/token"; . "$WORK/lib.sh"; img_status_items_add; printf '%s' "${#gatus_ext_items[@]}" ) 2>&1 )"
  is "off: no external rows rendered" "0" "$out"
  if [ -e "$d/token" ]; then bad "off: the push token is removed"; else ok "off: the push token is removed"; fi
  out="$( ( IMG_AUTO_UPDATES="" IMG_TOKEN_FILE="$d/token"; . "$WORK/lib.sh"; img_status_items_add; printf '%s' "${#gatus_ext_items[@]}" ) 2>&1 )"
  is "off: unset = on (two rows)" "2" "$out"
  if ( IMG_AUTO_UPDATES=yes IMG_TOKEN_FILE="$d/token"; . "$WORK/lib.sh"; img_status_items_add ) >/dev/null 2>&1; then bad "off: any other value is refused"; else ok "off: any other value is refused"; fi
  is "off: mode off" "off" "$(fn "$d" IMG_AUTO_UPDATES=off img_updater_mode)"
  is "off: mode bad" "bad" "$(fn "$d" IMG_AUTO_UPDATES=true img_updater_mode)"
  MODE="off" SOAK="" new_case off_run
  run_updater "$NOW_LATE" || bad "off: updater exits 0"
  is "off: an off-rendered updater swaps nothing" "$GATUS_PIN_REF" "$(cat "$C/stub/running.gatus")"
  is "off: and pushes nothing" "" "$(cat "$C/stub/push.log")"
}

suite_install() {
  local d="$WORK/inst" out
  rm -rf "$d"; mkdir -p "$d/state"
  printf 'ref=caddy:2.11.7-alpine@%s\n' "$CADDY_NEW" >"$d/state/caddy.state"
  printf '%s\n' "$CADDY_NEW" >"$d/state/caddy.bad"
  printf 'ref=%s\n' "$CADDY_PIN_REF" >"$d/state/caddy.pin"
  printf 'reason=all-rungs-failed\n' >"$d/state/disarmed"
  out="$( ( export PATH="$BIN:$PATH" STUB="$d"
    IMG_STATE_DIR="$d/state" IMG_ENV_FILE="$d/etc/img.env" IMG_SBIN="$d/sbin/upd" IMG_SERVICE="$d/units/u.service" \
    IMG_TIMER="$d/units/u.timer" NTFY_TOPIC=pc-test-topic NTFY_TOKEN=ntfy-test-credential CADDY_CONFIG="$d/Caddyfile" \
    GATUS_CONFIG="$d/gatus/config.yaml" IMG_TOKEN_FILE="$d/token"
    . "$WORK/lib.sh"; ORIGIN_TLS=0; AOP_TLS=""; STATUS_HOST=""
    img_updater_install ) 2>&1 )" || bad "install: completes ($out)"
  if [ -e "$d/state/disarmed" ]; then bad "install: a dispatch re-arms a disarmed updater"; else ok "install: a dispatch re-arms a disarmed updater"; fi
  is "install: env file 0600" "600" "$(stat -c %a "$d/etc/img.env" 2>/dev/null)"
  is "install: env dir 0700" "700" "$(stat -c %a "$d/etc" 2>/dev/null)"
  is "install: state dir 0700" "700" "$(stat -c %a "$d/state" 2>/dev/null)"
  if bash -n "$d/sbin/upd" 2>/dev/null; then ok "install: rendered updater parses"; else bad "install: rendered updater parses"; fi
  lacks "install: the ntfy credential is not in the script" "$(cat "$d/sbin/upd" 2>/dev/null)" "ntfy-test-credential"
  lacks "install: the ntfy credential is not printed" "$out" "ntfy-test-credential"
  has "install: timer every 6 h" "$(cat "$d/units/u.timer" 2>/dev/null)" "OnUnitInactiveSec=6h"
  has "install: timer jitter" "$(cat "$d/units/u.timer" 2>/dev/null)" "RandomizedDelaySec=30min"
  has "install: service serialized by flock" "$(cat "$d/units/u.service" 2>/dev/null)" "ExecStart=/usr/bin/flock -n -E 0 "
  has "install: timer enabled" "$(cat "$d/sys.log" 2>/dev/null)" "systemctl enable piercloud-img-update.timer"
  out="$( ( export PATH="$BIN:$PATH" STUB="$d"
    IMG_STATE_DIR="$d/state" IMG_ENV_FILE="$d/etc/img.env" IMG_SBIN="$d/sbin/upd" IMG_SERVICE="$d/units/u.service" IMG_TIMER="$d/units/u.timer"
    . "$WORK/lib.sh"; img_updater_disable ) 2>&1 )" || bad "disable: completes"
  if [ ! -e "$d/sbin/upd" ] && [ ! -e "$d/units/u.timer" ] && [ ! -e "$d/etc/img.env" ]; then ok "disable: updater removed"; else bad "disable: updater removed"; fi
  if [ ! -e "$d/state/caddy.state" ]; then ok "disable: current record removed (back on the pin)"; else bad "disable: current record removed (back on the pin)"; fi
  if [ -e "$d/state/caddy.bad" ]; then ok "disable: bad-digest holds kept"; else bad "disable: bad-digest holds kept"; fi
  if [ -e "$d/state/caddy.pin" ]; then ok "disable: the by-digest pin record kept (off runs it)"; else bad "disable: the by-digest pin record kept (off runs it)"; fi
  if ( . "$WORK/lib.sh"; unset -f adv_ok; render_img_updater ) >/dev/null 2>&1; then bad "render: a missing reused function fails the render"; else ok "render: a missing reused function fails the render"; fi
}

SUITES="precedence track soak swap rollback ladder live binding registry freeze marks drill validate token off install"
if [ -n "$SUITE_ONLY" ]; then
  "suite_$SUITE_ONLY"
  [ "$fail" -eq 0 ]
  exit $?
fi
for s in $SUITES; do "suite_$s"; done

# ---- 010 wiring (static) ---------------------------------------------------
PROV_TXT="$(cat "$PROVISION")"
has "010: gatus recreate goes through the shared run function" "$PROV_TXT" 'img_run_gatus "${GATUS_RUN_IMAGE}"'
has "010: caddy recreate goes through the shared run function" "$PROV_TXT" 'img_run_caddy "${CADDY_RUN_IMAGE}"'
has "010: provision validates with the shared validate function" "$PROV_TXT" 'img_caddy_validate "${CADDY_RUN_IMAGE}" "$TMP_CADDY"'
has "010: provision applies the precedence for gatus (on the pin BY DIGEST)" "$PROV_TXT" 'GATUS_RUN_IMAGE="$(img_effective_ref gatus "${GATUS_PIN_REF}")"'
has "010: provision applies the precedence for caddy (on the pin BY DIGEST)" "$PROV_TXT" 'CADDY_RUN_IMAGE="$(img_effective_ref caddy "${CADDY_PIN_REF}")"'
has "010: gatus pin resolved to a digest" "$PROV_TXT" 'GATUS_PIN_REF="$(img_pin_resolve gatus "${GATUS_IMAGE}")"'
has "010: caddy pin resolved to a digest" "$PROV_TXT" 'CADDY_PIN_REF="$(img_pin_resolve caddy "${CADDY_IMAGE}")"'
is "010: no tag-only effective ref (img_effective_ref never takes the bare pin)" "0" "$(grep -cE 'img_(effective_ref|reconcile_state) (gatus|caddy) "\$\{(GATUS|CADDY)_IMAGE\}"' "$PROVISION" || true)"
is "updater span: no early-exit grep -q on a docker listing (pipefail SIGPIPE flake)" "0" "$(grep -cE 'docker (ps|inspect|[i]mage).*\| *grep -q' "$WORK/img.src" || true)"
is "010: exactly one gatus docker run" "1" "$(grep -c 'docker run -d --name gatus' "$PROVISION")"
is "010: exactly one caddy docker run" "1" "$(grep -c 'docker run -d --name caddy' "$PROVISION")"
is "010: exactly one caddy validate" "1" "$(grep -c 'caddy validate --config' "$PROVISION")"
add_line="$(grep -nx 'img_status_items_add' "$PROVISION" | head -n1 | cut -d: -f1)"
reset_line="$(grep -nx 'gatus_ext_items=()' "$PROVISION" | head -n1 | cut -d: -f1)"
ext_line="$(grep -n '^# --- BEGIN GATUS EXTERNAL' "$PROVISION" | head -n1 | cut -d: -f1)"
if [ -n "$add_line" ] && [ -n "$reset_line" ] && [ -n "$ext_line" ] && [ "$reset_line" -lt "$add_line" ] && [ "$add_line" -lt "$ext_line" ]; then
  ok "010: the rows join gatus_ext_items after the reset and before the shared GATUS EXTERNAL render"
else
  bad "010: the rows join gatus_ext_items after the reset and before the shared GATUS EXTERNAL render"
fi

# ---- mutation teeth ---------------------------------------------------------
# Each mutant is a literal (old, new) pair over the extracted span; the
# harness re-runs itself on the mutated span with one suite, which must fail.
mutant() { # $1 label, $2 suite, $3 old text, $4 new text
  local m="$WORK/mut.src"
  if ! python3 -c 'import sys
s = open(sys.argv[1]).read()
if sys.argv[2] not in s:
    sys.exit(3)
open(sys.argv[4], "w").write(s.replace(sys.argv[2], sys.argv[3], 1))' "$WORK/img.src" "$3" "$4" "$m"; then
    bad "mutant $1: the mutation applies"
    return
  fi
  if IMG_HARNESS_SPAN="$m" bash "$HARNESS_DIR/run-test.sh" --suite "$2" >/dev/null 2>&1; then
    bad "mutant $1: caught by suite $2"
  else
    ok "mutant $1: caught by suite $2"
  fi
}
NL=$'\n'
mutant "downgrade below the record" precedence 'img_ver_gt "$pk" "$rk"' 'img_ver_gt "$rk" "$pk"'
mutant "bad digest re-selected by provision" precedence '|| img_is_bad "$1" "$rdig" ' ''
mutant "reconcile keeps a stale record" precedence "    rm -f \"\${IMG_STATE_DIR}/\$1.state\"${NL}    log" '    log'
mutant "major not checked" track '[ "${BASH_REMATCH[2]}" = "$maj" ] && ' ''
mutant "suffix not checked" track ' && [ "${BASH_REMATCH[5]}" = "$sfx" ]' ''
mutant "soak skipped" soak "    [ \"\$at\" -le \"\$cutoff\" ] || continue${NL}" ''
mutant "bad digest retried by the updater" rollback "    img_is_bad \"\$1\" \"\$digest\" && continue${NL}" ''
mutant "rollback skips the bad hold" rollback "        img_mark_bad \"\$1\" \"\$cnew\" \"\$ckey\" \"\$r\"${NL}" ''
mutant "no restore on failure" rollback 'if img_swap "$1" "$2" && r1=' 'if r1='
mutant "validate skipped" validate 'elif [ "$1" = "caddy" ] && ! img_caddy_validate "$newref"' 'elif false && ! img_caddy_validate "$newref"'
mutant "no pin rung" ladder 'if img_swap "$1" "$3" && r2=' 'if false && r2='
mutant "no direct alert when every rung fails" ladder '  img_alert_direct "$1: ${msg}"' '  :'
mutant "no disarm when every rung fails" ladder '  img_disarm "all-rungs-failed"' '  :'
mutant "disarm ignored" ladder 'if r="$(img_disarmed)"; then' 'if false; then'
mutant "ntfy topic in argv" ladder '--data-binary "$1" <<IMG_NTFY_EOF || true' '--data-binary "$1" "https://ntfy.sh/${NTFY_TOPIC}" <<IMG_NTFY_EOF || true'
mutant "no live check before a report" live '  if ! r="$(img_verify "$1" "$cur")"; then' '  if false; then'
mutant "gatus checked before tang" live "  img_try img_probe_tang_direct || { printf 'tang-direct'; return 1; }${NL}" ''
mutant "status host empty passes silently" live "  [ -n \"\${STATUS_HOST:-}\" ] || { printf 'no-status-host'; return 1; }" "  [ -n \"\${STATUS_HOST:-}\" ] || return 0"
mutant "running digest not asserted" binding "  img_running_digest_is \"\$1\" \"\$repo\" \"\$dig\" || { printf 'digest'; return 1; }${NL}" ''
mutant "validate by tag" binding '  [ -z "$dig" ] || ref="${repo}@${dig}"' '  :'
mutant "validate unconfined" binding 'docker run --rm --network none --cap-drop ALL --read-only' 'docker run --rm'
mutant "partial tag list at a page cap" registry '    [ "$page" -le 20 ] || return 1' '    [ "$page" -le 3 ] || break'
mutant "page error returns a partial list" registry '--max-time 30 "$url")" || return 1' '--max-time 30 "$url")" || break'
mutant "behind never red" freeze '  [ -n "$nk" ] || return 1' '  return 1'
mutant "held version re-push not re-soaked" marks '    if mat="$(img_version_mark_at "$1" "$key")" && [ "$mat" -gt "$cutoff" ]; then continue; fi' ''
mutant "config problem held as bad" marks '      if img_caddy_validate "$cur" "${CADDY_CONFIG}" >/dev/null 2>&1; then' '      if true; then'
mutant "pin holds never expire" marks '  if pk="$(img_ver_key "$tag" "$tag")"; then img_marks_expire "$1" "$pk"; fi' '  :'
mutant "pin recorded tag-only" marks "  printf '%s@%s' \"\$base\" \"\$dig\"" "  printf '%s' \"\$base\""
mutant "leading zeros accepted" track '(0|[1-9][0-9]{0,8})\\.(0|[1-9][0-9]{0,8})\\.(0|[1-9][0-9]{0,8})' '([0-9]+)\\.([0-9]+)\\.([0-9]+)'
mutant "drill marks the candidate bad" drill '    img_after_failure "$1" "$cur" "$pin" "drill' '    img_mark_bad "$1" "$cdig" 0.0.0 drill; img_after_failure "$1" "$cur" "$pin" "drill'
mutant "token in argv" token '-X POST -K -' '-X POST -H "X-Push: ${tok}" -K -'
mutant "off switch ignored" off "off) printf 'off' ;;" "off) printf 'on' ;;"
mutant "state record skipped" swap "    img_state_put \"\$1\" \"\$newref\"${NL}" ''
mutant "push token world-readable" token '  chmod 600 "$tmp"
  mv "$tmp" "$IMG_TOKEN_FILE"' '  chmod 644 "$tmp"
  mv "$tmp" "$IMG_TOKEN_FILE"'
mutant "env file world-readable" install "  chmod 0600 \"\$tmp\"${NL}" "  chmod 0644 \"\$tmp\"${NL}"

# ---- dispatch plumbing: provision.yml A1 env -> 020 ENV_PREFIX -> 010 -----
PROV_YML="$ROOT/.github/workflows/provision.yml"
for v in IMG_AUTO_UPDATES IMG_UPDATE_SOAK_HOURS; do
  # shellcheck disable=SC2016 # literal workflow expression
  if grep -qxF "          ${v}: \${{ vars.${v} }}" "$PROV_YML"; then ok "plumbing: provision.yml A1 env reads vars.${v}"; else bad "plumbing: provision.yml lost vars.${v}"; fi
  # shellcheck disable=SC2016 # literal workflow expression
  if grep -qxF "          REPO_SCOPE_${v}: \${{ vars.${v} != '' }}" "$PROV_YML"; then ok "plumbing: banner probes ${v} at repo scope"; else bad "plumbing: banner lost the ${v} repo-scope probe"; fi
done
( q() { printf %s "$1" | sed "s/'/'\\\\''/g"; }
  export IMG_AUTO_UPDATES="off" IMG_UPDATE_SOAK_HOURS="12"
  eval "$(sed -n 's/^  \(ENV_PREFIX=.*\)$/\1/p' "$ROOT/.github/scripts/020-provision-anchor.sh")"
  unset IMG_AUTO_UPDATES IMG_UPDATE_SOAK_HOURS
  eval "$ENV_PREFIX"
  printf '%s|%s\n' "${IMG_AUTO_UPDATES:-}" "${IMG_UPDATE_SOAK_HOURS:-}" ) >"$WORK/prefix.out" 2>/dev/null || true
is "plumbing: 020 ENV_PREFIX passes IMG_AUTO_UPDATES / IMG_UPDATE_SOAK_HOURS through" "off|12" "$(cat "$WORK/prefix.out")"

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
