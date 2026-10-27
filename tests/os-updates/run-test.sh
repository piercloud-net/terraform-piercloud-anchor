#!/usr/bin/env bash
# tests/os-updates/run-test.sh - offline, cred-free harness for Lane A slice
# A-OS (#51): unattended OS security updates + kernel reboot window.
#
# Extracts the REAL span from scripts/010-provision.sh (# --- BEGIN/END OS
# UPDATES ---; never a copy) plus the gatus-render span, and drives them with
# stubbed apt-get/apt-config/systemctl/unattended-upgrade/curl. Proves:
#   (a) the origin pattern per distro: Debian -> codename=<c>-security +
#       label=Debian-Security, Ubuntu -> archive=<c>-security, exactly one
#       pattern, the distro defaults cleared (#clear);
#   (b) any other /etc/os-release ID (or none) is refused before a write;
#   (c) OS_AUTO_UPDATES=off renders Unattended-Upgrade "0", no origin, no
#       status row, no token/report/drop-in; any value but unset/on/off dies;
#   (d) OS_AUTO_REBOOT_TIME accepts 00:00-04:59 HH:MM only (default 03:30);
#   (e) the bearer token is 0600, regenerated per run, reaches curl on stdin
#       only and is never printed (apply + report output scanned);
#   (f) staleness: success iff newest(stamp, marker) < 48 h; the error field
#       carries counts only (pending security, reboot-required, age);
#   (g) the converge self-checks die on an overriding origin, a failing
#       --dry-run, a disabled tangd.socket, a timer without its drop-in;
#   (h) the shared GATUS EXTERNAL sub-span renders external-endpoints: only
#       with an item, records the alert intent, and the YAML parses;
#   (i) MUTANTS of the span (dropped -security, -updates pocket, removed
#       refusal, off -> "1", widened window, token on argv, 72 h staleness,
#       removed #clear) each turn the matching check red.
# No network, no root.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROVISION="$ROOT/scripts/010-provision.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0
MIN_CHECKS=79
ok()  { pass=$((pass + 1)); printf 'ok   %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL %s\n' "$1"; }
has()   { case "$2" in *"$3"*) ok "$1" ;; *) bad "$1 (missing: $3)" ;; esac; }
lacks() { case "$2" in *"$3"*) bad "$1 (unexpected: $3)" ;; *) ok "$1" ;; esac; }
is()    { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi; }

extract() { # $1 begin marker, $2 end marker, $3 out
  local m n b e
  for m in "$1" "$2"; do
    n="$(grep -cF -- "$m" "$PROVISION" || true)"
    [ "$n" = "1" ] || { printf 'FAIL marker %s found %s times\n' "$m" "${n:-0}"; exit 1; }
  done
  b="$(grep -nF -- "$1" "$PROVISION" | cut -d: -f1)"
  e="$(grep -nF -- "$2" "$PROVISION" | cut -d: -f1)"
  sed -n "$((b + 1)),$((e - 1))p" "$PROVISION" >"$3"
  [ -s "$3" ] || { printf 'FAIL empty span %s\n' "$1"; exit 1; }
}
extract '# --- BEGIN OS UPDATES' '# --- END OS UPDATES ---' "$WORK/os.src"
extract '# --- gatus-render:start ---' '# --- gatus-render:end ---' "$WORK/gatus.src"
has "gatus span carries the GATUS EXTERNAL sub-span" "$(cat "$WORK/gatus.src")" "# --- BEGIN GATUS EXTERNAL"

# ---- stubs on PATH ---------------------------------------------------------
BIN="$WORK/bin"
mkdir -p "$BIN"
cat >"$BIN/apt-get" <<'EOF'
#!/usr/bin/env bash
case " $* " in *" -s "*) [ -n "${FAKE_SIM_RC:-}" ] && exit "$FAKE_SIM_RC"; cat "${FAKE_SIM:-/dev/null}" ;; esac
exit 0
EOF
# apt-config dump: models apt's list merge - distro defaults survive unless the
# rendered file clears them; FAKE_APT_EXTRA models another apt.conf.d file.
cat >"$BIN/apt-config" <<'EOF'
#!/usr/bin/env bash
conf="$OS_UPD_APT_CONF"
if ! grep -qxF '#clear Unattended-Upgrade::Origins-Pattern;' "$conf" 2>/dev/null; then
  printf '%s\n' 'Unattended-Upgrade::Origins-Pattern::=origin=Debian,codename=${distro_codename},label=Debian'
fi
sed -n 's/^Unattended-Upgrade::Origins-Pattern { "\(.*\)"; };$/Unattended-Upgrade::Origins-Pattern::=\1/p' "$conf" 2>/dev/null
[ -n "${FAKE_APT_EXTRA:-}" ] && printf '%s\n' "$FAKE_APT_EXTRA"
exit 0
EOF
cat >"$BIN/unattended-upgrade" <<'EOF'
#!/usr/bin/env bash
exit "${FAKE_UU_RC:-0}"
EOF
cat >"$BIN/systemctl" <<'EOF'
#!/usr/bin/env bash
case "$1" in
  is-enabled) [ "$2" = "${FAKE_DISABLED:-}" ] && { echo disabled; exit 1; }; echo enabled ;;
  show) u="${!#}"; [ "$u" = "${FAKE_NO_DROPIN:-}" ] && exit 0
        ls -1 "$OS_UPD_UNIT_DIR/$u.d/"*.conf 2>/dev/null | tr '\n' ' ' ;;
esac
exit 0
EOF
cat >"$BIN/curl" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$@" >"$FAKE_CURL_ARGV"
cat >"$FAKE_CURL_STDIN"
printf '%s' "${FAKE_HTTP:-200}"
EOF
chmod +x "$BIN"/*

cat >"$WORK/stubs.src" <<'EOF'
set -euo pipefail
log()  { printf 'harness: %s\n' "$*"; }
warn() { printf 'harness WARNING: %s\n' "$*"; }
die()  { printf 'FAIL(die): %s\n' "$*" >&2; exit 1; }
GATUS_PORT=8080
gatus_ext_items=()
EOF

newcase() { # $1 label -> sets D (case dir) and exports the fixture env
  D="$WORK/c-$1"
  rm -rf "$D"; mkdir -p "$D/etc" "$D/units" "$D/state" "$D/sbin"
  export PATH="$BIN:$PATH" TZ=UTC \
    OS_UPD_APT_CONF="$D/etc/52piercloud-unattended-upgrades" OS_UPD_OS_RELEASE="$D/etc/os-release" \
    OS_UPD_UNIT_DIR="$D/units" OS_UPD_SBIN="$D/sbin/report.sh" OS_UPD_TOKEN_FILE="$D/etc/os-updates.token" \
    OS_UPD_STATE_DIR="$D/state" OS_UPD_MARKER="$D/state/os-updates.installed" \
    FAKE_CURL_ARGV="$D/curl.argv" FAKE_CURL_STDIN="$D/curl.stdin"
  unset OS_AUTO_UPDATES OS_AUTO_REBOOT_TIME NTFY_TOPIC FAKE_APT_EXTRA FAKE_UU_RC FAKE_DISABLED FAKE_NO_DROPIN FAKE_HTTP FAKE_SIM FAKE_SIM_RC
  printf 'PRETTY_NAME="Debian GNU/Linux 13 (trixie)"\nID=debian\nVERSION_CODENAME=trixie\n' >"$OS_UPD_OS_RELEASE"
}

apply() { # $1 span file; runs os_updates_apply and dumps the status items
  { cat "$WORK/stubs.src" "$1"
    printf '%s\n' 'os_updates_apply' 'for i in "${gatus_ext_items[@]}"; do printf "%s\n" "$i"; done >"$OS_UPD_STATE_DIR/items"'
  } >"$D/run.sh"
  bash "$D/run.sh" >"$D/out.log" 2>"$D/err.log"
}

S="$WORK/os.src"
deb_pat='Unattended-Upgrade::Origins-Pattern { "origin=Debian,codename=${distro_codename}-security,label=Debian-Security"; };'
ubu_pat='Unattended-Upgrade::Origins-Pattern { "origin=Ubuntu,archive=${distro_codename}-security"; };'

# ---- checks (each returns 0 = green; reused by the mutants) ----------------
chk_debian() {
  newcase deb; apply "$1" || return 1
  grep -qxF "$deb_pat" "$OS_UPD_APT_CONF" || return 1
  [ "$(grep -c 'Origins-Pattern {' "$OS_UPD_APT_CONF")" = 1 ] || return 1
  ! grep -qE -- '-updates|backports|proposed' "$OS_UPD_APT_CONF"
}
chk_ubuntu() {
  newcase ubu; printf 'ID=ubuntu\nVERSION_CODENAME=noble\n' >"$OS_UPD_OS_RELEASE"
  apply "$1" || return 1
  grep -qxF "$ubu_pat" "$OS_UPD_APT_CONF" || return 1
  ! grep -qE -- '-updates|backports|proposed' "$OS_UPD_APT_CONF"
}
chk_refuse() { # every unsupported os-release dies before writing the policy
  local rel
  for rel in 'ID=fedora' 'ID=raspbian\nID_LIKE=debian' 'NAME=nothing' 'ID=debian-ish'; do
    newcase refuse; printf "$rel\n" >"$OS_UPD_OS_RELEASE"
    if apply "$1"; then return 1; fi
    [ ! -e "$OS_UPD_APT_CONF" ] || return 1
    grep -q 'unsupported distribution' "$D/err.log" || return 1
  done
}
chk_clear() { newcase clr; apply "$1" || return 1; grep -qxF '#clear Unattended-Upgrade::Allowed-Origins;' "$OS_UPD_APT_CONF"; }
chk_off() {
  newcase off; export OS_AUTO_UPDATES=off
  printf 'ID=fedora\n' >"$OS_UPD_OS_RELEASE"   # off needs no origin, so no refusal
  mkdir -p "$D/units/apt-daily-upgrade.service.d"; : >"$D/units/apt-daily-upgrade.service.d/piercloud-os-updates.conf"
  : >"$OS_UPD_TOKEN_FILE"
  apply "$1" || return 1
  grep -qxF 'APT::Periodic::Unattended-Upgrade "0";' "$OS_UPD_APT_CONF" || return 1
  ! grep -q 'Origins-Pattern {' "$OS_UPD_APT_CONF" || return 1
  ! grep -q 'Unattended-Upgrade "1"' "$OS_UPD_APT_CONF" || return 1
  [ ! -s "$OS_UPD_STATE_DIR/items" ] && [ ! -e "$OS_UPD_TOKEN_FILE" ] && [ ! -e "$OS_UPD_SBIN" ] \
    && [ ! -e "$D/units/apt-daily-upgrade.service.d/piercloud-os-updates.conf" ]
}
chk_window() { # valid edges render; everything else dies
  local t
  for t in 00:00 04:59 01:15; do
    newcase win; export OS_AUTO_REBOOT_TIME="$t"; apply "$1" || return 1
    grep -qxF "Unattended-Upgrade::Automatic-Reboot-Time \"$t\";" "$OS_UPD_APT_CONF" || return 1
  done
  for t in 05:00 3:30 24:00 03:60 '03:30 ' 0330 12:00 23:59 -1:00; do
    newcase win; export OS_AUTO_REBOOT_TIME="$t"
    if apply "$1"; then return 1; fi
  done
}
chk_token() { # 0600, per-run, stdin-only, never printed
  local tok tok2 out
  newcase tok; apply "$1" || return 1
  tok="$(cat "$OS_UPD_TOKEN_FILE")"
  [[ "$tok" =~ ^[0-9a-f]{64}$ ]] || return 1
  [ "$(stat -c %a "$OS_UPD_TOKEN_FILE")" = 600 ] || return 1
  grep -qF "token: \"$tok\"" "$OS_UPD_STATE_DIR/items" || return 1
  ! grep -qF "$tok" "$D/out.log" "$D/err.log" || return 1
  out="$(bash "$OS_UPD_SBIN" 2>&1)" || return 1
  case "$out" in *"$tok"*) return 1 ;; esac
  ! grep -qF "$tok" "$FAKE_CURL_ARGV" || return 1
  grep -qxF "header = \"Authorization: Bearer $tok\"" "$FAKE_CURL_STDIN" || return 1
  grep -qxF -- '-K' "$FAKE_CURL_ARGV" || return 1
  apply "$1" || return 1
  tok2="$(cat "$OS_UPD_TOKEN_FILE")"
  [ "$tok" != "$tok2" ]
}
report() { # $1 stamp age seconds (or -), $2 marker age (or -) -> report stdout; sets RC
  local now=1800000000
  rm -f "$D/stamp" "$OS_UPD_MARKER"
  [ "$1" = - ] || touch -d "@$((now - $1))" "$D/stamp"
  [ "$2" = - ] || touch -d "@$((now - $2))" "$OS_UPD_MARKER"
  RC=0
  OS_UPD_NOW="$now" OS_UPD_STAMP="$D/stamp" OS_UPD_REBOOT_FLAG="$D/reboot-required" bash "$OS_UPD_SBIN" || RC=$?
}
chk_stale() {
  newcase stale; apply "$1" || return 1
  report $((47 * 3600)) - >/dev/null; grep -q 'success=true&' "$FAKE_CURL_ARGV" || return 1
  report $((49 * 3600)) - >/dev/null; grep -q 'success=false&error=stale-over-48h,' "$FAKE_CURL_ARGV" || return 1
  report $((49 * 3600)) $((3600)) >/dev/null; grep -q 'success=true&' "$FAKE_CURL_ARGV" || return 1
  report - - >/dev/null; grep -q 'success=false&.*last-ok-age-h:never' "$FAKE_CURL_ARGV" || return 1
  report $((48 * 3600)) - >/dev/null; grep -q 'success=false&' "$FAKE_CURL_ARGV"
}

# ---- (a)-(f) on the real span ---------------------------------------------
if chk_debian "$S"; then ok "(a) Debian: only origin=Debian,codename=<c>-security,label=Debian-Security"; else bad "(a) Debian origin pattern"; sed -n 1,5p "$D/err.log"; fi
if chk_ubuntu "$S"; then ok "(a) Ubuntu: only origin=Ubuntu,archive=<c>-security"; else bad "(a) Ubuntu origin pattern"; fi
if chk_clear "$S"; then ok "(a) distro default origin lists are cleared"; else bad "(a) #clear lines"; fi
newcase deb2; apply "$S"
CONF="$(cat "$OS_UPD_APT_CONF")"
has "(a) periodic unattended upgrade on" "$CONF" 'APT::Periodic::Unattended-Upgrade "1";'
has "(a) package lists refreshed" "$CONF" 'APT::Periodic::Update-Package-Lists "1";'
has "(a) unused kernels removed" "$CONF" 'Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";'
has "(a) automatic reboot on" "$CONF" 'Unattended-Upgrade::Automatic-Reboot "true";'
has "(a) default reboot window 03:30" "$CONF" 'Unattended-Upgrade::Automatic-Reboot-Time "03:30";'
has "(a) apt-daily timer at 01:30 UTC" "$(cat "$D/units/apt-daily.timer.d/piercloud-os-updates.conf")" 'OnCalendar=*-*-* 01:30:00 UTC'
has "(a) apt-daily-upgrade timer at 02:30 UTC" "$(cat "$D/units/apt-daily-upgrade.timer.d/piercloud-os-updates.conf")" 'OnCalendar=*-*-* 02:30:00 UTC'
has "(a) upgrade timer jitter 15m" "$(cat "$D/units/apt-daily-upgrade.timer.d/piercloud-os-updates.conf")" 'RandomizedDelaySec=15m'
has "(a) the timer drop-in resets the distro OnCalendar" "$(cat "$D/units/apt-daily-upgrade.timer.d/piercloud-os-updates.conf")" $'OnCalendar=\nOnCalendar='
has "(a) report runs after each apt-daily-upgrade" "$(cat "$D/units/apt-daily-upgrade.service.d/piercloud-os-updates.conf")" "ExecStartPost=-$OS_UPD_SBIN"
[ -e "$OS_UPD_MARKER" ] && ok "(a) install marker starts the 48 h clock" || bad "(a) install marker missing"
OUT="$(cat "$D/out.log")"
has "(g) converge line: origin policy" "$OUT" "apt origin policy is exactly the rendered one (OK)"
has "(g) converge line: dry-run" "$OUT" "unattended-upgrade --dry-run accepts the rendered config (OK)"
has "(g) converge line: tangd.socket" "$OUT" "tangd.socket enabled"
has "(g) converge line: timers" "$OUT" "timers enabled with their drop-ins (OK)"
ITEM="$(cat "$OS_UPD_STATE_DIR/items")"
has "(h) item: name" "$ITEM" "  - name: os-security-updates"
has "(h) item: group anchor" "$ITEM" "    group: anchor"
has "(h) item: heartbeat 26h" "$ITEM" "      interval: 26h"
lacks "(h) item without push channel has no alerts" "$ITEM" "alerts:"

if chk_refuse "$S"; then ok "(b) fedora / raspbian / no ID / debian-ish refused before any write"; else bad "(b) unsupported distro refusal"; fi
if chk_off "$S"; then ok "(c) off renders Unattended-Upgrade \"0\", no origin, no row/token/report/drop-in"; else bad "(c) off switch"; fi
for v in yes ON true 1 'off ' disabled; do
  newcase badmode; export OS_AUTO_UPDATES="$v"
  if apply "$S"; then bad "(c) OS_AUTO_UPDATES='$v' refused"; else ok "(c) OS_AUTO_UPDATES='$v' refused"; fi
done
newcase on; export OS_AUTO_UPDATES=on
if apply "$S" && grep -q 'Unattended-Upgrade "1"' "$OS_UPD_APT_CONF"; then ok "(c) explicit on accepted"; else bad "(c) explicit on"; fi
if chk_window "$S"; then ok "(d) reboot window: 00:00/04:59/01:15 render; 05:00, 3:30, 24:00, 03:60, padded, 0330, 12:00, 23:59 refused"; else bad "(d) reboot window validation"; fi
if chk_token "$S"; then ok "(e) token: 64 hex, 0600, per run, stdin only, never printed"; else bad "(e) token handling"; fi
if chk_stale "$S"; then ok "(f) staleness: 47h ok, 48h/49h stale, fresh marker rescues, none = never"; else bad "(f) staleness logic"; fi

newcase counts; apply "$S"
printf '%s\n' 'Inst libssl3t64 [3.5.1-1] (3.5.1-1+deb13u1 Debian-Security:13/stable-security [amd64])' \
  'Inst linux-image-amd64 [6.12.1-1] (6.12.2-1 Debian-Security:13/stable-security [amd64])' \
  'Inst tzdata [2025a-1] (2025b-0+deb13u1 Debian:13.1/stable [all])' 'Conf libssl3t64 (x)' >"$D/sim"
export FAKE_SIM="$D/sim"; : >"$D/reboot-required"
OUTR="$(report 3600 - )"
ARGV="$(cat "$FAKE_CURL_ARGV")"
has "(f) pending security count (2 of 3 Inst lines)" "$ARGV" "pending-security:2,"
has "(f) reboot-required flag" "$ARGV" "reboot-required:yes"
has "(f) last-ok age in hours" "$ARGV" "last-ok-age-h:1&"
has "(f) push targets the external endpoint key" "$ARGV" "http://127.0.0.1:8080/api/v1/endpoints/anchor_os-security-updates/external?success=true&error="
has "(f) report line is counts only" "$OUTR" "success=true pending-security=2 reboot-required=yes last-ok-age-h=1 push=HTTP 200"
is "(f) push 200 exits 0" 0 "$RC"
export FAKE_SIM_RC=100
report 3600 - >/dev/null; has "(f) apt simulation failure -> pending unknown" "$(cat "$FAKE_CURL_ARGV")" "pending-security:unknown"
unset FAKE_SIM_RC
export FAKE_HTTP=401
report 3600 - >"$D/r.out"; is "(f) rejected push exits 3" 3 "$RC"; has "(f) rejected push logged by code" "$(cat "$D/r.out")" "push=HTTP 401"
unset FAKE_HTTP
rm -f "$OS_UPD_TOKEN_FILE"; report 3600 - >"$D/r.out"; is "(f) missing token exits 3" 3 "$RC"

# ---- (g) converge self-checks fail closed ----------------------------------
newcase g1; export FAKE_APT_EXTRA='Unattended-Upgrade::Origins-Pattern::=origin=Debian,codename=${distro_codename}-updates'
if apply "$S"; then bad "(g) overriding origin dies"; else ok "(g) overriding origin dies"; fi
newcase g1b; export FAKE_APT_EXTRA='Unattended-Upgrade::Allowed-Origins::=${distro_id}:${distro_codename}-updates'
if apply "$S"; then bad "(g) leftover Allowed-Origins dies"; else ok "(g) leftover Allowed-Origins dies"; fi
newcase g2; export FAKE_UU_RC=1
if apply "$S"; then bad "(g) failing --dry-run dies"; else ok "(g) failing --dry-run dies"; fi
newcase g3; export FAKE_DISABLED=tangd.socket
if apply "$S"; then bad "(g) disabled tangd.socket dies"; else ok "(g) disabled tangd.socket dies"; fi
for u in apt-daily.timer apt-daily-upgrade.timer apt-daily-upgrade.service; do
  newcase g4; export FAKE_NO_DROPIN="$u"
  if apply "$S"; then bad "(g) $u without its drop-in dies"; else ok "(g) $u without its drop-in dies"; fi
done
newcase g5; export FAKE_DISABLED=apt-daily-upgrade.timer
if apply "$S"; then bad "(g) disabled apt-daily-upgrade.timer dies"; else ok "(g) disabled apt-daily-upgrade.timer dies"; fi
newcase g6; export OS_AUTO_UPDATES=off FAKE_APT_EXTRA='Unattended-Upgrade::Origins-Pattern::=origin=Debian'
if apply "$S"; then bad "(g) off with a leftover origin dies"; else ok "(g) off with a leftover origin dies"; fi

# ---- (h) shared GATUS EXTERNAL sub-span in the real gatus render ----------
gatus_render() { # $1 label, $2 items file (one item) or '' -> sets G (config path); rc of the render
  G="$WORK/g-$1/config.yaml"; mkdir -p "$WORK/g-$1"
  { cat "$WORK/stubs.src"
    printf '%s\n' 'caddy_status_names() { :; }'
    printf 'GATUS_CONFIG=%q\n' "$G"
    [ -n "$2" ] && printf 'gatus_ext_items+=("$(cat %q)")\n' "$2"
    cat "$WORK/gatus.src"; } >"$WORK/g-$1/run.sh"
  ( export TENANT_USER=pier STATUS_HOST=pier.status.piercloud.net ANCHOR_HOSTNAME=anchor-01-pier
    bash "$WORK/g-$1/run.sh" >"$WORK/g-$1/out.log" 2>&1 )
}
yaml_ok() {
  if ! command -v ruby >/dev/null 2>&1; then bad "$1 (ruby unavailable - YAML NOT verified)"; return; fi
  if ruby -ryaml -e 'c = YAML.load_file(ARGV[0]); e = c["external-endpoints"]; exit(e.is_a?(Array) && e.size == 1 && e[0]["token"].to_s.size == 64 && e[0]["heartbeat"]["interval"] == "26h" ? 0 : 1)' "$2" 2>/dev/null; then ok "$1"; else bad "$1"; fi
}
newcase gi; export NTFY_TOPIC=pc-test-topic; apply "$S"
cp "$OS_UPD_STATE_DIR/items" "$WORK/item-alert"
has "(h) item with push channel carries an alerts stanza" "$(cat "$WORK/item-alert")" "    alerts:"
if gatus_render alert "$WORK/item-alert"; then ok "(h) render with an alerting item passes the C4 ledger"; else bad "(h) render with an alerting item"; sed -n '1,5p' "$WORK/g-alert/out.log"; fi
GC="$(cat "$G")"
has "(h) external-endpoints rendered" "$GC" $'\nexternal-endpoints:\n  - name: os-security-updates\n    group: anchor\n'
has "(h) ledger names the external row" "$(cat "$WORK/g-alert/out.log")" "os-security-updates"
yaml_ok "(h) YAML parses with one external endpoint (token, 26h heartbeat)" "$G"
unset NTFY_TOPIC
if gatus_render none ""; then ok "(h) render without items"; else bad "(h) render without items"; fi
lacks "(h) no item -> no external-endpoints key" "$(cat "$G")" "external-endpoints:"
# a bad item fails closed
printf '%s\n' '    group: anchor' >"$WORK/item-bad"
if gatus_render badi "$WORK/item-bad"; then bad "(h) malformed item refused"; else ok "(h) malformed item refused"; fi
# tooth: an alerts stanza without its intent must trip the existing ledger
sed 's/alert_intent "\$_ext_name"/:/' "$WORK/gatus.src" >"$WORK/gatus.mut"
cp "$WORK/gatus.src" "$WORK/gatus.orig"; cp "$WORK/gatus.mut" "$WORK/gatus.src"
export NTFY_TOPIC=pc-test-topic
if gatus_render mut "$WORK/item-alert"; then bad "mutant red: external alert intent dropped"; else ok "mutant red: external alert intent dropped"; fi
unset NTFY_TOPIC
cp "$WORK/gatus.orig" "$WORK/gatus.src"

# ---- (i) mutants of the OS span -------------------------------------------
mutant() { # $1 label, $2 check fn, $3 python expr over s
  local m="$WORK/mut-$((pass + fail)).src"
  python3 - "$S" "$m" "$3" <<'PY'
import sys
s = open(sys.argv[1]).read()
t = eval(sys.argv[3], {"s": s})
assert t != s, "mutation did not change the span"
open(sys.argv[2], "w").write(t)
PY
  if "$2" "$m" >/dev/null 2>&1; then bad "mutant stays green: $1"; else ok "mutant red: $1"; fi
}
mutant "Debian pattern without -security" chk_debian "s.replace('codename=\${distro_codename}-security,label=Debian-Security', 'codename=\${distro_codename},label=Debian', 1)"
mutant "Ubuntu pattern on the -updates pocket" chk_ubuntu "s.replace('archive=\${distro_codename}-security', 'archive=\${distro_codename}-updates', 1)"
mutant "unknown distro falls back to Debian" chk_refuse "s.replace('    *) die \"OS updates: unsupported distribution', '    *) printf \"%s\\\\n\" x; return 0; die \"OS updates: unsupported distribution', 1)"
mutant "off renders Unattended-Upgrade 1" chk_off "s.replace('APT::Periodic::Unattended-Upgrade \"0\";', 'APT::Periodic::Unattended-Upgrade \"1\";', 1)"
mutant "off keeps the status row" chk_off "s.replace('    rm -f \"\$svc_dropin\" \"\$OS_UPD_SBIN\" \"\$OS_UPD_TOKEN_FILE\"', '    :', 1)"
mutant "reboot window widened to 0-9" chk_window "s.replace('^0[0-4]:[0-5][0-9]\$', '^[0-2][0-9]:[0-5][0-9]\$', 1)"
mutant "token on curl argv" chk_token "s.replace('-m 10 -X POST -K - ', '-m 10 -X POST -H \"Authorization: Bearer \$token\" -K - ', 1)"
mutant "token echoed in the report line" chk_token "s.replace('  \"\$success\" \"\$pending\"', '  \"\$success \$token\" \"\$pending\"', 1)"
mutant "token file world-readable" chk_token "s.replace('os_updates_install_file \"\$OS_UPD_TOKEN_FILE\" 0600', 'os_updates_install_file \"\$OS_UPD_TOKEN_FILE\" 0644', 1)"
mutant "staleness 72 h" chk_stale "s.replace('MAX_AGE=172800', 'MAX_AGE=259200', 1)"
mutant "staleness ignores the stamp age" chk_stale "s.replace('[ \"\$age\" -lt \"\$MAX_AGE\" ]', 'true', 1)"
mutant "#clear Origins-Pattern removed" chk_debian "s.replace('printf \'%s\\\\n\' \"#clear Unattended-Upgrade::Origins-Pattern;\"', ':', 1)"
mutant "#clear Allowed-Origins removed" chk_clear "s.replace('printf \'%s\\\\n\' \"#clear Unattended-Upgrade::Allowed-Origins;\"', ':', 1)"

# ---- (j) dispatch plumbing: provision.yml A1 env -> 020 ENV_PREFIX -> 010 --
PROV_YML="$ROOT/.github/workflows/provision.yml"
for v in OS_AUTO_UPDATES OS_AUTO_REBOOT_TIME; do
  # shellcheck disable=SC2016 # literal workflow expression
  if grep -qxF "          ${v}: \${{ vars.${v} }}" "$PROV_YML"; then ok "(j) provision.yml A1 env reads vars.${v}"; else bad "(j) provision.yml lost vars.${v}"; fi
done
( q() { printf %s "$1" | sed "s/'/'\\\\''/g"; }
  export OS_AUTO_UPDATES="off" OS_AUTO_REBOOT_TIME="04:15"
  eval "$(sed -n 's/^  \(ENV_PREFIX=.*\)$/\1/p' "$ROOT/.github/scripts/020-provision-anchor.sh")"
  unset OS_AUTO_UPDATES OS_AUTO_REBOOT_TIME
  eval "$ENV_PREFIX"
  printf '%s|%s\n' "${OS_AUTO_UPDATES:-}" "${OS_AUTO_REBOOT_TIME:-}" ) >"$WORK/prefix.out" 2>/dev/null || true
is "(j) 020 ENV_PREFIX passes OS_AUTO_UPDATES / OS_AUTO_REBOOT_TIME through" "off|04:15" "$(cat "$WORK/prefix.out")"

total=$((pass + fail))
printf '\n%d passed, %d failed (%d checks)\n' "$pass" "$fail" "$total"
[ "$total" -ge "$MIN_CHECKS" ] || { printf 'FAIL check-count floor: %d < %d\n' "$total" "$MIN_CHECKS"; exit 1; }
[ "$fail" -eq 0 ]
