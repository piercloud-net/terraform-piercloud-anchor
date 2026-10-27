#!/usr/bin/env bash
# tests/os-updates/run-test.sh - offline, cred-free harness for Lane A slice
# A-OS (#51): unattended OS security updates + kernel reboot window.
#
# Extracts the REAL span from scripts/010-provision.sh (# --- BEGIN/END OS
# UPDATES ---; never a copy) plus the gatus-render span, and drives them with
# stubbed apt-get/apt-config/systemctl/timedatectl/unattended-upgrade/curl. Proves:
#   (a) the origin pattern per distro (Debian -> codename=<c>-security +
#       label=Debian-Security, Ubuntu -> archive=<c>-security), exactly one
#       pattern, the distro defaults cleared (#clear); unattended-upgrade's
#       own reboot stays "false" (no WithUsers line); the gated reboot timer
#       carries the window in UTC; the box is put on UTC (set-timezone) and a
#       box that stays non-UTC is refused;
#   (b) any other /etc/os-release ID (or none) is refused, and the refusal
#       leaves the box DISARMED (Unattended-Upgrade "0", no drop-ins/timer);
#   (c) OS_AUTO_UPDATES=off disarms and logs it; any value but unset/on/off dies;
#   (d) OS_AUTO_REBOOT_TIME accepts 00:00-04:59 HH:MM only (default 03:30) and
#       maps 1:1 onto the reboot timer even when the harness runs in Europe/Rome;
#   (e) the bearer token is 0600, regenerated per run, written only by
#       os_updates_commit_token (after the Gatus config), reaches curl on
#       stdin only and is never printed;
#   (f) green = pending known AND (grace OR real run < 48 h AND security lists
#       < 48 h AND 0 pending); grace ends at the first real run or 26 h; only
#       --after-run (SERVICE_RESULT=success + fresh upgrade-stamp) writes the
#       run marker; env overrides of paths/thresholds are ignored; a live
#       token swap makes the report wait;
#   (g) the converge self-checks die on an overriding origin, a failing
#       --dry-run, a disabled tangd.socket, a timer without its drop-in - and
#       every such refusal disarms a previously armed box;
#   (k) the reboot gate: no flag / live provision / rotation pending /
#       upgrade running hold it; a stale pidfile does not;
#   (l) run-once + first report: warn-only, cause class named;
#   (h) the shared GATUS EXTERNAL sub-span renders external-endpoints: only
#       with an item, records the alert intent, the YAML parses, the config
#       is written 0600 (also over a pre-existing 0644 file);
#   (i) MUTANTS of the span each turn the matching check red.
# No network, no root, no real ntfy topic.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROVISION="$ROOT/scripts/010-provision.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0
MIN_CHECKS=143
ok()  { pass=$((pass + 1)); printf 'ok   %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL %s\n' "$1"; }
has()   { case "$2" in *"$3"*) ok "$1" ;; *) bad "$1 (missing: $3)" ;; esac; }
lacks() { case "$2" in *"$3"*) bad "$1 (unexpected: $3)" ;; *) ok "$1" ;; esac; }
is()    { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi; }
t() { if ( "$@" ) >/dev/null 2>&1; then ok "$label"; else bad "$label"; fi; } # uses $label

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

# ---- stubs (baked by absolute path into the on-box scripts, or on PATH) ----
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
printf '%s\n' "$*" >>"${FAKE_SYSTEMCTL_LOG:-/dev/null}"
case "$1" in
  is-enabled) [ "$2" = "${FAKE_DISABLED:-}" ] && { echo disabled; exit 1; }; echo enabled ;;
  is-active) [ -n "${FAKE_UPGRADE_ACTIVE:-}" ] && exit 0; exit 3 ;;
  show) u="${!#}"; [ "$u" = "${FAKE_NO_DROPIN:-}" ] && exit 0
        ls -1 "$OS_UPD_UNIT_DIR/$u.d/"*.conf 2>/dev/null | tr '\n' ' ' ;;
  start) exit "${FAKE_START_RC:-0}" ;;
esac
exit 0
EOF
cat >"$BIN/timedatectl" <<'EOF'
#!/usr/bin/env bash
case "$1" in
  show) cat "$FAKE_TZ_FILE" ;;
  set-timezone) printf '%s\n' "set-timezone $2" >>"$FAKE_TZ_FILE.log"; [ -n "${FAKE_TZ_STUCK:-}" ] || printf '%s\n' "$2" >"$FAKE_TZ_FILE" ;;
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
  rm -rf "$D"; mkdir -p "$D/etc" "$D/units" "$D/state" "$D/sbin" "$D/lists" "$D/run"
  export PATH="$BIN:$PATH" TZ=Europe/Rome \
    OS_UPD_APT_CONF="$D/etc/52piercloud-unattended-upgrades" OS_UPD_OS_RELEASE="$D/etc/os-release" \
    OS_UPD_UNIT_DIR="$D/units" OS_UPD_SBIN="$D/sbin/report.sh" OS_UPD_GATE="$D/sbin/gate.sh" \
    OS_UPD_TOKEN_FILE="$D/etc/os-updates.token" OS_UPD_STATE_DIR="$D/state" \
    OS_UPD_MARKER="$D/state/os-updates.installed" OS_UPD_RUN_MARKER="$D/state/os-updates.last-run" \
    OS_UPD_UPGRADE_STAMP="$D/state/upgrade-stamp" OS_UPD_LISTS_DIR="$D/lists" \
    OS_UPD_REBOOT_FLAG="$D/run/reboot-required" OS_UPD_ROTATION_MARKER="$D/state/.rotation-pending" \
    OS_UPD_PROVISION_PIDFILE="$D/run/provision.pid" OS_UPD_SWAP_MARK="$D/run/swap" \
    OS_UPD_APT_GET_BIN="$BIN/apt-get" OS_UPD_CURL_BIN="$BIN/curl" OS_UPD_SYSTEMCTL_BIN="$BIN/systemctl" \
    OS_UPD_RETRY_SLEEP=0 FAKE_TZ_FILE="$D/tz" FAKE_SYSTEMCTL_LOG="$D/systemctl.log" \
    FAKE_CURL_ARGV="$D/curl.argv" FAKE_CURL_STDIN="$D/curl.stdin"
  unset OS_AUTO_UPDATES OS_AUTO_REBOOT_TIME NTFY_TOPIC FAKE_APT_EXTRA FAKE_UU_RC FAKE_DISABLED FAKE_NO_DROPIN FAKE_HTTP FAKE_SIM FAKE_SIM_RC FAKE_TZ_STUCK FAKE_START_RC FAKE_UPGRADE_ACTIVE
  printf 'UTC\n' >"$FAKE_TZ_FILE"
  printf 'PRETTY_NAME="Debian GNU/Linux 13 (trixie)"\nID=debian\nVERSION_CODENAME=trixie\n' >"$OS_UPD_OS_RELEASE"
}

run_span() { # $1 span file, rest = commands to run after sourcing the span
  local s="$1"; shift
  { cat "$WORK/stubs.src" "$s"; printf '%s\n' "$@"; } >"$D/run.sh"
  bash "$D/run.sh" >"$D/out.log" 2>"$D/err.log"
}
apply() { # $1 span: apply + commit (the Gatus render commits the token) + dump the items
  run_span "$1" 'os_updates_apply' 'os_updates_commit_token' 'for i in "${gatus_ext_items[@]}"; do printf "%s\n" "$i"; done >"$OS_UPD_STATE_DIR/items"'
}
apply_only() { run_span "$1" 'os_updates_apply'; }

S="$WORK/os.src"
deb_pat='Unattended-Upgrade::Origins-Pattern { "origin=Debian,codename=${distro_codename}-security,label=Debian-Security"; };'
ubu_pat='Unattended-Upgrade::Origins-Pattern { "origin=Ubuntu,archive=${distro_codename}-security"; };'
DROPINS="apt-daily.timer.d apt-daily-upgrade.timer.d apt-daily-upgrade.service.d"

disarmed() { # the safe state after a refusal / off
  local d
  grep -qxF 'APT::Periodic::Unattended-Upgrade "0";' "$OS_UPD_APT_CONF" || return 1
  grep -qxF 'Unattended-Upgrade::Automatic-Reboot "false";' "$OS_UPD_APT_CONF" || return 1
  ! grep -q 'Origins-Pattern {' "$OS_UPD_APT_CONF" || return 1
  ! grep -q 'Unattended-Upgrade "1"' "$OS_UPD_APT_CONF" || return 1
  for d in $DROPINS; do [ ! -e "$D/units/$d/piercloud-os-updates.conf" ] || return 1; done
  [ ! -e "$D/units/piercloud-os-reboot.timer" ] && [ ! -e "$D/units/piercloud-os-reboot.service" ] || return 1
  [ ! -e "$OS_UPD_SBIN" ] && [ ! -e "$OS_UPD_GATE" ] && [ ! -e "$OS_UPD_TOKEN_FILE" ] || return 1
  grep -qx 'disable --now piercloud-os-reboot.timer' "$FAKE_SYSTEMCTL_LOG"
}
arm_first() { apply "$1" || return 1; [ -e "$D/units/piercloud-os-reboot.timer" ] && [ -s "$OS_UPD_TOKEN_FILE" ]; }

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
chk_refuse() { # every unsupported os-release dies and leaves the (armed) box disarmed
  local rel
  for rel in 'ID=fedora' 'ID=raspbian\nID_LIKE=debian' 'NAME=nothing' 'ID=debian-ish'; do
    newcase refuse; arm_first "$1" || return 1; : >"$FAKE_SYSTEMCTL_LOG"
    printf "$rel\n" >"$OS_UPD_OS_RELEASE"
    if apply "$1"; then return 1; fi
    grep -q 'unsupported distribution' "$D/err.log" || return 1
    disarmed || return 1
  done
}
chk_clear() { newcase clr; apply "$1" || return 1; grep -qxF '#clear Unattended-Upgrade::Allowed-Origins;' "$OS_UPD_APT_CONF"; }
chk_noreboot_uu() { # u-u never reboots by itself: the gated timer does
  newcase uur; apply "$1" || return 1
  grep -qxF 'Unattended-Upgrade::Automatic-Reboot "false";' "$OS_UPD_APT_CONF" || return 1
  ! grep -q 'Automatic-Reboot "true"\|Automatic-Reboot-WithUsers\|Automatic-Reboot-Time' "$OS_UPD_APT_CONF"
}
chk_off() {
  newcase off; arm_first "$1" || return 1; : >"$FAKE_SYSTEMCTL_LOG"
  export OS_AUTO_UPDATES=off
  printf 'ID=fedora\n' >"$OS_UPD_OS_RELEASE"   # off needs no origin, so no refusal
  apply "$1" || return 1
  disarmed || return 1
  [ ! -s "$OS_UPD_STATE_DIR/items" ] || return 1
  grep -q 'DISABLED by the approval-gated variable OS_AUTO_UPDATES=off' "$D/out.log"
}
chk_window() { # valid edges render 1:1 onto the UTC reboot timer (harness TZ=Europe/Rome); the rest die
  local tm
  for tm in 00:00 04:59 01:15 03:30; do
    newcase win; export OS_AUTO_REBOOT_TIME="$tm"; apply "$1" || return 1
    grep -qxF "OnCalendar=*-*-* ${tm}:00 UTC" "$D/units/piercloud-os-reboot.timer" || return 1
    [ "$(grep -c '^OnCalendar=' "$D/units/piercloud-os-reboot.timer")" = 1 ] || return 1
  done
  for tm in 05:00 3:30 24:00 03:60 '03:30 ' 0330 12:00 23:59 -1:00; do
    newcase win; export OS_AUTO_REBOOT_TIME="$tm"
    if apply "$1"; then return 1; fi
    disarmed || return 1
  done
}
chk_utc() { # a non-UTC box is set to UTC; one that stays non-UTC is refused + disarmed
  newcase utc; printf 'Europe/Rome\n' >"$FAKE_TZ_FILE"; apply "$1" || return 1
  grep -qx 'set-timezone UTC' "$FAKE_TZ_FILE.log" || return 1
  grep -q 'box timezone is UTC (OK)' "$D/out.log" || return 1
  newcase utc2; arm_first "$1" || return 1; : >"$FAKE_SYSTEMCTL_LOG"
  printf 'Europe/Rome\n' >"$FAKE_TZ_FILE"; export FAKE_TZ_STUCK=1
  if apply "$1"; then return 1; fi
  disarmed
}
chk_token() { # 0600, per-run, committed only after the Gatus config, stdin-only, never printed
  local tok tok2 out
  newcase tok; apply_only "$1" || return 1
  [ ! -e "$OS_UPD_TOKEN_FILE" ] || return 1          # apply alone never writes the token file
  apply "$1" || return 1
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
  apply_only "$1" || return 1
  [ "$(cat "$OS_UPD_TOKEN_FILE")" = "$tok" ] || return 1  # a run that dies before the Gatus write keeps the old pair
  apply "$1" || return 1
  tok2="$(cat "$OS_UPD_TOKEN_FILE")"
  [ "$tok" != "$tok2" ]
}
age() { # $1 file, $2 age in hours or - (absent)
  rm -f "$1"
  [ "$2" = - ] || touch -d "@$(( $(date +%s) - $2 * 3600 ))" "$1"
}
LISTF="deb.debian.org_debian-security_dists_trixie-security_InRelease"
report() { # $1 run-marker age h, $2 install-marker age h, $3 security lists age h ('-' = absent) [env...]
  age "$OS_UPD_RUN_MARKER" "$1"; age "$OS_UPD_MARKER" "$2"; age "$D/lists/$LISTF" "$3"
  rm -f "$FAKE_CURL_ARGV"; RC=0
  shift 3
  env "$@" bash "$OS_UPD_SBIN" >"$D/r.out" 2>&1 || RC=$?
  ARGV="$(cat "$FAKE_CURL_ARGV" 2>/dev/null || true)"
}
green() { report "$@"; case "$ARGV" in *'external?success=true&'*) return 0 ;; esac; return 1; }
red() { report "$@"; case "$ARGV" in *'external?success=false&'*) return 0 ;; esac; return 1; }
PEND2="$WORK/sim-pend2"
printf '%s\n' 'Inst libssl3t64 [3.5.1-1] (3.5.1-1+deb13u1 Debian-Security:13/stable-security [amd64])' \
  'Inst libc6 [2.41-11] (2.41-12+deb13u1 Debian-Security:13/stable-security [amd64])' \
  'Inst tzdata [2025a-1] (2025b-0+deb13u1 Debian:13.1/stable [all])' 'Conf libssl3t64 (x)' >"$PEND2"
PEND0="$WORK/sim-pend0"
printf '%s\n' 'Inst tzdata [2025a-1] (2025b-0+deb13u1 Debian:13.1/stable [all])' >"$PEND0"
chk_stale() { # the green/red matrix
  newcase stale; apply "$1" || return 1
  export FAKE_SIM="$PEND0"
  green 1 30 1 || return 1                        # real run 1h, lists 1h, 0 pending
  green 47 60 47 || return 1
  red 49 60 1 || return 1; case "$ARGV" in *run-stale-over-48h*) ;; *) return 1 ;; esac
  red 1 60 49 || return 1; case "$ARGV" in *lists-stale-over-48h*) ;; *) return 1 ;; esac
  red - 27 1 || return 1                          # no real run, grace (26h) over
  red 1 60 - || return 1                          # no security lists at all
  export FAKE_SIM="$PEND2"
  red 1 60 1 || return 1; case "$ARGV" in *security-pending,pending-security:2,*) ;; *) return 1 ;; esac
  green - 1 - || return 1; case "$ARGV" in *grace:yes*) ;; *) return 1 ;; esac   # fresh install: grace
  green 30 1 - || return 1                        # re-enabled: install marker newer than the old run
  red 1 25 - || return 1                          # the first real run ends the grace at once
  export FAKE_SIM_RC=100
  red - 1 - || return 1; case "$ARGV" in *pending-unknown,pending-security:unknown*) ;; *) return 1 ;; esac
  red 1 60 1 || return 1
  unset FAKE_SIM_RC
}
chk_afterrun() { # only a successful real run with a fresh upgrade-stamp writes the run marker
  newcase ar; apply "$1" || return 1
  [ ! -e "$OS_UPD_RUN_MARKER" ] || return 1          # the converge (incl. its --dry-run) never writes it
  age "$OS_UPD_UPGRADE_STAMP" 1
  SERVICE_RESULT=success bash "$OS_UPD_SBIN" --after-run >/dev/null 2>&1 || true
  [ -e "$OS_UPD_RUN_MARKER" ] || return 1
  rm -f "$OS_UPD_RUN_MARKER"
  SERVICE_RESULT=exit-code bash "$OS_UPD_SBIN" --after-run >"$D/ar.out" 2>&1 || true
  [ ! -e "$OS_UPD_RUN_MARKER" ] || return 1
  grep -q 'run marker NOT refreshed' "$D/ar.out" || return 1
  bash "$OS_UPD_SBIN" >/dev/null 2>&1 || true
  [ ! -e "$OS_UPD_RUN_MARKER" ] || return 1          # a plain (converge) report never writes it
  age "$OS_UPD_UPGRADE_STAMP" 30
  SERVICE_RESULT=success bash "$OS_UPD_SBIN" --after-run >/dev/null 2>&1 || true
  [ ! -e "$OS_UPD_RUN_MARKER" ]                      # skipped run with an old stamp: not a real run
}
chk_envproof() { # paths, thresholds and PATH from the environment are ignored
  local evil="$WORK/evil"; mkdir -p "$evil"
  printf '#!/bin/sh\necho 0\n' >"$evil/stat"; printf '#!/bin/sh\necho 1\n' >"$evil/date"; chmod +x "$evil"/*
  newcase env; apply "$1" || return 1
  export FAKE_SIM="$PEND0"
  red 49 60 1 MAX_AGE=999999999 GRACE=999999999 OS_UPD_NOW=1 OS_UPD_STAMP=/dev/null RUN_MARKER=/dev/null \
    MARKER=/dev/null LISTS_DIR=/ PATH="$evil:$PATH" || return 1
  grep -q '^PATH=/usr/sbin:/usr/bin:/sbin:/bin$' "$OS_UPD_SBIN" || return 1
  ! grep -qE '\${OS_UPD_|:-[0-9]' "$OS_UPD_SBIN" || return 1
  grep -qF "APT_GET=$BIN/apt-get" "$OS_UPD_SBIN"
}
pidmark() { printf '%s %s\n' "$1" "$(sed 's/^.*) //' "/proc/$1/stat" | cut -d' ' -f20)"; }
chk_swapwait() { # a live token swap holds the push; a dead one does not
  local sp
  newcase sw; apply "$1" || return 1
  sleep 30 & sp=$!
  pidmark "$sp" >"$OS_UPD_SWAP_MARK"
  rm -f "$FAKE_CURL_ARGV"; timeout 3 bash "$OS_UPD_SBIN" >/dev/null 2>&1 || true
  kill "$sp" 2>/dev/null || true; wait "$sp" 2>/dev/null || true
  [ ! -e "$FAKE_CURL_ARGV" ] || return 1
  printf '%s 1\n' "$sp" >"$OS_UPD_SWAP_MARK"   # dead pid / wrong start time
  bash "$OS_UPD_SBIN" >/dev/null 2>&1 || true
  [ -e "$FAKE_CURL_ARGV" ]
}
gate() { RC=0; bash "$OS_UPD_GATE" >"$D/gate.out" 2>&1 || RC=$?; }
chk_gate() { # exit 0 = reboot; 1 = held
  local sp held
  newcase gate; apply "$1" || return 1
  gate; [ "$RC" = 1 ] || return 1                                  # no reboot-required
  : >"$OS_UPD_REBOOT_FLAG"
  gate; [ "$RC" = 0 ] || return 1
  sleep 30 & sp=$!
  pidmark "$sp" >"$OS_UPD_PROVISION_PIDFILE"
  gate; held=$RC
  kill "$sp" 2>/dev/null || true; wait "$sp" 2>/dev/null || true
  [ "$held" = 1 ] || return 1
  grep -q 'provision run is in progress' "$D/gate.out" || return 1
  gate; [ "$RC" = 0 ] || return 1                                  # stale pidfile (dead run) ignored
  printf '%s 1\n' "$$" >"$OS_UPD_PROVISION_PIDFILE"
  gate; [ "$RC" = 0 ] || return 1                                  # reused pid (wrong start time) ignored
  : >"$OS_UPD_ROTATION_MARKER"
  gate; [ "$RC" = 1 ] || return 1
  grep -q 'tang key rotation pending' "$D/gate.out" || return 1
  rm -f "$OS_UPD_ROTATION_MARKER"; export FAKE_UPGRADE_ACTIVE=1
  gate; [ "$RC" = 1 ] || return 1
  unset FAKE_UPGRADE_ACTIVE
  grep -qxF "ExecCondition=$OS_UPD_GATE" "$D/units/piercloud-os-reboot.service" || return 1
  grep -qxF "ExecStart=$BIN/systemctl reboot" "$D/units/piercloud-os-reboot.service"
}
chk_disarm_g() { # $1 span; rest = env assignments that make the converge refuse -> the armed box ends disarmed
  local span="$1"; shift
  newcase gd; arm_first "$span" || return 1; : >"$FAKE_SYSTEMCTL_LOG"
  # shellcheck disable=SC2163 # each argument is a NAME=value assignment
  export "$@"
  if apply "$span"; then return 1; fi
  disarmed
}
chk_disarm_origin() { chk_disarm_g "$1" FAKE_APT_EXTRA='Unattended-Upgrade::Origins-Pattern::=origin=Debian,codename=${distro_codename}-updates'; }

# ---- (a)-(f) on the real span ---------------------------------------------
if chk_debian "$S"; then ok "(a) Debian: only origin=Debian,codename=<c>-security,label=Debian-Security"; else bad "(a) Debian origin pattern"; sed -n 1,5p "$D/err.log"; fi
if chk_ubuntu "$S"; then ok "(a) Ubuntu: only origin=Ubuntu,archive=<c>-security"; else bad "(a) Ubuntu origin pattern"; fi
if chk_clear "$S"; then ok "(a) distro default origin lists are cleared"; else bad "(a) #clear lines"; fi
if chk_noreboot_uu "$S"; then ok "(a) unattended-upgrade's own reboot is \"false\" (no WithUsers / Reboot-Time line)"; else bad "(a) u-u Automatic-Reboot"; fi
if chk_utc "$S"; then ok "(a) non-UTC box set to UTC; a box that stays non-UTC is refused + disarmed"; else bad "(a) UTC enforcement"; fi
newcase deb2; apply "$S"
CONF="$(cat "$OS_UPD_APT_CONF")"
has "(a) periodic unattended upgrade on" "$CONF" 'APT::Periodic::Unattended-Upgrade "1";'
has "(a) package lists refreshed" "$CONF" 'APT::Periodic::Update-Package-Lists "1";'
has "(a) unused kernels removed" "$CONF" 'Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";'
RT="$(cat "$D/units/piercloud-os-reboot.timer")"
has "(a) reboot timer: default window 03:30 UTC" "$RT" 'OnCalendar=*-*-* 03:30:00 UTC'
has "(a) reboot timer: no catch-up reboot after a missed window" "$RT" 'Persistent=false'
has "(a) reboot timer: wanted by timers.target" "$RT" 'WantedBy=timers.target'
lacks "(a) reboot timer: no jitter" "$RT" 'RandomizedDelaySec'
has "(a) reboot timer enabled + started" "$(cat "$FAKE_SYSTEMCTL_LOG")" 'enable apt-daily.timer apt-daily-upgrade.timer piercloud-os-reboot.timer'
has "(a) apt-daily timer at 01:30 UTC" "$(cat "$D/units/apt-daily.timer.d/piercloud-os-updates.conf")" 'OnCalendar=*-*-* 01:30:00 UTC'
has "(a) apt-daily-upgrade timer at 02:30 UTC" "$(cat "$D/units/apt-daily-upgrade.timer.d/piercloud-os-updates.conf")" 'OnCalendar=*-*-* 02:30:00 UTC'
has "(a) upgrade timer jitter 15m" "$(cat "$D/units/apt-daily-upgrade.timer.d/piercloud-os-updates.conf")" 'RandomizedDelaySec=15m'
has "(a) the timer drop-in resets the distro OnCalendar" "$(cat "$D/units/apt-daily-upgrade.timer.d/piercloud-os-updates.conf")" $'OnCalendar=\nOnCalendar='
has "(a) report runs after each apt-daily-upgrade, success or failure (ExecStopPost --after-run)" "$(cat "$D/units/apt-daily-upgrade.service.d/piercloud-os-updates.conf")" "ExecStopPost=-$OS_UPD_SBIN --after-run"
lacks "(a) no ExecStartPost (it skips failed runs)" "$(cat "$D/units/apt-daily-upgrade.service.d/piercloud-os-updates.conf")" "ExecStartPost"
is "(a) report script 0700" 700 "$(stat -c %a "$OS_UPD_SBIN")"
is "(a) reboot gate 0700" 700 "$(stat -c %a "$OS_UPD_GATE")"
[ -e "$OS_UPD_MARKER" ] && ok "(a) install marker starts the grace" || bad "(a) install marker missing"
OUT="$(cat "$D/out.log")"
has "(g) converge line: origin policy" "$OUT" "apt origin policy is exactly the rendered one (OK)"
has "(g) converge line: dry-run" "$OUT" "unattended-upgrade --dry-run accepts the rendered config (OK)"
has "(g) converge line: tangd.socket" "$OUT" "tangd.socket enabled"
has "(g) converge line: timers" "$OUT" "timers enabled with their drop-ins, report hook loaded (OK)"
has "(g) converge line: gated reboot timer" "$OUT" "piercloud-os-reboot.timer at 03:30 UTC, gated on reboot-required / no provision run / no tang rotation (OK)"
has "(g) converge line: UTC" "$OUT" "box timezone is UTC (OK)"
ITEM="$(cat "$OS_UPD_STATE_DIR/items")"
has "(h) item: name" "$ITEM" "  - name: os-security-updates"
has "(h) item: group anchor" "$ITEM" "    group: anchor"
has "(h) item: heartbeat 26h" "$ITEM" "      interval: 26h"
lacks "(h) item without push channel has no alerts" "$ITEM" "alerts:"
pre="$(awk '/^os_updates_apply\(\)/{on=1} on&&/^  os_updates_utc$/{print NR; exit}' "$S")"
arm="$(awk '/^os_updates_apply\(\)/{on=1} on&&/render_os_updates_apt_conf on/{print NR; exit}' "$S")"
if [ -n "$pre" ] && [ -n "$arm" ] && [ "$pre" -lt "$arm" ]; then ok "(g) UTC + tangd.socket checks run before the policy is armed"; else bad "(g) pre-arm order"; fi

if chk_refuse "$S"; then ok "(b) fedora / raspbian / no ID / debian-ish refused and the (armed) box disarmed"; else bad "(b) unsupported distro refusal"; fi
if chk_off "$S"; then ok "(c) off disarms (Unattended-Upgrade \"0\", no row/token/report/drop-ins/reboot timer) and logs DISABLED"; else bad "(c) off switch"; fi
for v in yes ON true 1 'off ' disabled; do
  newcase badmode; arm_first "$S"; : >"$FAKE_SYSTEMCTL_LOG"; export OS_AUTO_UPDATES="$v"
  if apply "$S"; then bad "(c) OS_AUTO_UPDATES='$v' refused"; elif disarmed; then ok "(c) OS_AUTO_UPDATES='$v' refused + disarmed"; else bad "(c) OS_AUTO_UPDATES='$v' refused but not disarmed"; fi
done
newcase on; export OS_AUTO_UPDATES=on
if apply "$S" && grep -q 'Unattended-Upgrade "1"' "$OS_UPD_APT_CONF"; then ok "(c) explicit on accepted"; else bad "(c) explicit on"; fi
if chk_window "$S"; then ok "(d) reboot window maps 1:1 to the UTC timer under TZ=Europe/Rome (00:00/04:59/01:15/03:30); 05:00, 3:30, 24:00, 03:60, padded, 0330, 12:00, 23:59 refused + disarmed"; else bad "(d) reboot window"; fi
if chk_token "$S"; then ok "(e) token: 64 hex, 0600, per run, written only by the commit after the Gatus config, stdin only, never printed"; else bad "(e) token handling"; fi
if chk_stale "$S"; then ok "(f) green matrix: run/lists < 48 h + 0 pending; grace to first run or 26 h; pending unknown red"; else bad "(f) green matrix"; tail -n 2 "$D/r.out" 2>/dev/null || true; fi
if chk_afterrun "$S"; then ok "(f) only --after-run (SERVICE_RESULT=success, upgrade-stamp < 26 h) writes the run marker"; else bad "(f) run marker"; fi
if chk_envproof "$S"; then ok "(f) env overrides (paths, thresholds, PATH) ignored; absolute command paths baked"; else bad "(f) env proof"; fi
if chk_swapwait "$S"; then ok "(f) a live token swap holds the push; a dead swap marker does not"; else bad "(f) swap wait"; fi
if chk_gate "$S"; then ok "(k) reboot gate: no flag / live provision / rotation / upgrade running hold; stale or reused pid does not"; else bad "(k) reboot gate"; cat "$D/gate.out" 2>/dev/null || true; fi

newcase counts; apply "$S"
export FAKE_SIM="$PEND2"; : >"$OS_UPD_REBOOT_FLAG"
report 1 60 1
has "(f) pending security count (2 of 3 Inst lines)" "$ARGV" "pending-security:2,"
has "(f) reboot-required flag" "$ARGV" "reboot-required:yes"
has "(f) last-run age in hours" "$ARGV" "last-run-age-h:1,"
has "(f) lists age in hours" "$ARGV" "lists-age-h:1,"
has "(f) push targets the external endpoint key" "$ARGV" "http://127.0.0.1:8080/api/v1/endpoints/anchor_os-security-updates/external?success=false&error=security-pending,"
has "(f) report line is reasons + counts only" "$(cat "$D/r.out")" "success=false reasons=security-pending pending-security=2 reboot-required=yes last-run-age-h=1 lists-age-h=1 grace=no push=HTTP 200"
is "(f) push 200 exits 0" 0 "$RC"
: >"$OS_UPD_ROTATION_MARKER"; report 1 60 1
has "(f) reboot held by a pending rotation is visible" "$ARGV" "reboot-required:held-rotation"
rm -f "$OS_UPD_ROTATION_MARKER"
export FAKE_HTTP=401
report 1 60 1; is "(f) rejected push exits 3" 3 "$RC"; has "(f) rejected push logged by code" "$(cat "$D/r.out")" "push=HTTP 401"
unset FAKE_HTTP
rm -f "$OS_UPD_TOKEN_FILE"; report 1 60 1; is "(f) missing token exits 3" 3 "$RC"; has "(f) missing token names its cause" "$(cat "$D/r.out")" "cause: token-missing"

# ---- (g) converge self-checks fail closed AND disarm ----------------------
label="(g) overriding origin dies + disarms"; t chk_disarm_origin "$S"
label="(g) leftover Allowed-Origins dies + disarms"; t chk_disarm_g "$S" FAKE_APT_EXTRA='Unattended-Upgrade::Allowed-Origins::=${distro_id}:${distro_codename}-updates'
label="(g) failing --dry-run dies + disarms"; t chk_disarm_g "$S" FAKE_UU_RC=1
label="(g) disabled tangd.socket dies + disarms"; t chk_disarm_g "$S" FAKE_DISABLED=tangd.socket
for u in apt-daily.timer apt-daily-upgrade.timer apt-daily-upgrade.service; do
  label="(g) $u without its drop-in dies + disarms"; t chk_disarm_g "$S" FAKE_NO_DROPIN="$u"
done
label="(g) disabled apt-daily-upgrade.timer dies + disarms"; t chk_disarm_g "$S" FAKE_DISABLED=apt-daily-upgrade.timer
label="(g) disabled reboot timer dies + disarms"; t chk_disarm_g "$S" FAKE_DISABLED=piercloud-os-reboot.timer
newcase g6; export OS_AUTO_UPDATES=off FAKE_APT_EXTRA='Unattended-Upgrade::Origins-Pattern::=origin=Debian'
if apply "$S"; then bad "(g) off with a leftover origin dies"; else ok "(g) off with a leftover origin dies"; fi

# ---- (l) run-once + first report (warn-only, cause named) -----------------
runonce() { run_span "$S" 'os_updates_apply' 'os_updates_commit_token' 'os_updates_run_once' 'os_updates_first_report'; }
newcase ro; age "$OS_UPD_UPGRADE_STAMP" 1; export FAKE_SIM="$PEND0"
if runonce; then ok "(l) run-once + report succeed"; else bad "(l) run-once"; fi
RO="$(cat "$D/out.log")"
has "(l) run-once starts apt-daily-upgrade synchronously" "$(cat "$FAKE_SYSTEMCTL_LOG")" "start apt-daily-upgrade.service"
[ ! -e "$OS_UPD_UPGRADE_STAMP" ] && ok "(l) run-once clears apt's day stamp so the run is real" || bad "(l) upgrade-stamp not cleared"
has "(l) run-once converge line" "$RO" "run-once: apt-daily-upgrade.service completed (OK)"
has "(l) row state logged with counts" "$RO" "status push landed"
newcase ro2; export FAKE_START_RC=1
if runonce; then ok "(l) failed run-once is warn-only"; else bad "(l) failed run-once failed the run"; fi
has "(l) failed run-once names its cause" "$(cat "$D/out.log")" "WARNING: OS updates: run-once failed (cause: service-failed, rc=1)"
newcase ro3; export FAKE_START_RC=124
runonce || true; has "(l) timed-out run-once names its cause" "$(cat "$D/out.log")" "WARNING: OS updates: run-once did not finish within 900 s (cause: timeout)"
newcase ro4; export FAKE_HTTP=401
if runonce; then ok "(l) rejected first push is warn-only"; else bad "(l) rejected first push failed the run"; fi
has "(l) rejected first push names its cause" "$(cat "$D/out.log")" "WARNING: OS updates: the first status push did not land (cause: token-rejected-401;"
newcase ro5; export FAKE_HTTP=000
runonce || true; has "(l) unreachable Gatus names its cause" "$(cat "$D/out.log")" "(cause: gatus-unreachable;"
newcase ro6; export FAKE_HTTP=500
runonce || true; has "(l) other HTTP code names its cause" "$(cat "$D/out.log")" "(cause: gatus-http-500;"
newcase ro7; export FAKE_SIM_RC=100   # pending unknown: red even inside the grace
runonce || true; has "(l) a red row after the dispatch is a WARNING line" "$(cat "$D/out.log")" "WARNING: OS updates: status push landed but the row is RED"
newcase ro8; export OS_AUTO_UPDATES=off
runonce || true; has "(l) off skips the run-once" "$(cat "$D/out.log")" "run-once skipped (OS_AUTO_UPDATES=off)"
lacks "(l) off never starts apt-daily-upgrade" "$(cat "$FAKE_SYSTEMCTL_LOG")" "start apt-daily-upgrade.service"
newcase clean

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


# ---- (h2) Gatus config mode + the token commit order in the real gatus span
G2="$WORK/g-mode/config.yaml"; mkdir -p "$WORK/g-mode"; printf 'old: 1\n' >"$G2"; chmod 0644 "$G2"
{ cat "$WORK/stubs.src"; printf '%s\n' 'caddy_status_names() { :; }'; printf 'GATUS_CONFIG=%q\n' "$G2"; cat "$WORK/gatus.src"; } >"$WORK/g-mode/run.sh"
if ( export TENANT_USER=pier STATUS_HOST=pier.status.piercloud.net ANCHOR_HOSTNAME=anchor-01-pier; umask 022
  bash "$WORK/g-mode/run.sh" >"$WORK/g-mode/out.log" 2>&1 ); then ok "(h) render over a pre-existing 0644 config"; else bad "(h) render over a 0644 config"; fi
is "(h) Gatus config tightened to 0600 (it holds bearer tokens)" 600 "$(stat -c %a "$G2")"
has "(h) converge line: Gatus config mode" "$(cat "$WORK/g-mode/out.log")" "Gatus config is mode 0600 (root-only; it holds bearer tokens) (OK)"
cmpl="$(grep -n 'cmp -s "\$TMP_CFG" "\${GATUS_CONFIG}" || die' "$WORK/gatus.src" | cut -d: -f1)"
coml="$(grep -n 'os_updates_commit_token; fi' "$WORK/gatus.src" | cut -d: -f1)"
swpl="$(grep -n 'os_updates_swap_begin; fi' "$WORK/gatus.src" | cut -d: -f1)"
wrl="$(grep -nF '(umask 077; cat "$TMP_CFG" >"${GATUS_CONFIG}")' "$WORK/gatus.src" | cut -d: -f1)"
if [ -n "$cmpl" ] && [ -n "$coml" ] && [ -n "$swpl" ] && [ -n "$wrl" ] && [ "$swpl" -lt "$wrl" ] && [ "$wrl" -lt "$cmpl" ] && [ "$cmpl" -lt "$coml" ]; then
  ok "(h) order: swap marker -> config write -> byte check -> token commit"
else bad "(h) token commit order (swap=$swpl write=$wrl cmp=$cmpl commit=$coml)"; fi
swend="$(grep -n 'os_updates_swap_end; fi' "$PROVISION" | cut -d: -f1)"
rst="$(grep -n '^docker restart gatus >/dev/null$' "$PROVISION" | cut -d: -f1)"
if [ -n "$swend" ] && [ -n "$rst" ] && [ "$swend" -gt "$rst" ]; then ok "(h) the swap marker clears only after Gatus restarted"; else bad "(h) swap end order"; fi
pidl="$(grep -n '^PROVISION_PIDFILE="/run/piercloud-provision.pid"$' "$PROVISION" | cut -d: -f1)"
tangl="$(grep -n 'rotation-pending"$' "$PROVISION" | head -n 1 | cut -d: -f1)"
if [ -n "$pidl" ] && [ -n "$tangl" ] && [ "$pidl" -lt "$tangl" ]; then ok "(k) provision pidfile written before any tang key work"; else bad "(k) provision pidfile placement"; fi
rol="$(grep -n '^os_updates_run_once$' "$PROVISION" | cut -d: -f1)"
frl="$(grep -n '^os_updates_first_report$' "$PROVISION" | cut -d: -f1)"
if [ -n "$rol" ] && [ -n "$frl" ] && [ -n "$rst" ] && [ "$rst" -lt "$rol" ] && [ "$rol" -lt "$frl" ]; then ok "(l) run-once after Gatus restarted, then the first report"; else bad "(l) run-once placement"; fi

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
  [ -s "$m" ] || { bad "mutant did not apply: $1"; return 0; }
  if ( "$2" "$m" ) >/dev/null 2>&1; then bad "mutant stays green: $1"; else ok "mutant red: $1"; fi
}
mutant "Debian pattern without -security" chk_debian "s.replace('codename=\${distro_codename}-security,label=Debian-Security', 'codename=\${distro_codename},label=Debian', 1)"
mutant "Ubuntu pattern on the -updates pocket" chk_ubuntu "s.replace('archive=\${distro_codename}-security', 'archive=\${distro_codename}-updates', 1)"
mutant "unknown distro falls back to Debian" chk_refuse "s.replace('    *) os_updates_refuse \"OS updates: unsupported distribution', '    *) OSU_PATTERN=x; return 0; os_updates_refuse \"OS updates: unsupported distribution', 1)"
mutant "off renders Unattended-Upgrade 1" chk_off "s.replace('APT::Periodic::Unattended-Upgrade \"0\";', 'APT::Periodic::Unattended-Upgrade \"1\";', 1)"
mutant "off does not disarm (row/hook kept)" chk_off "s.replace('    os_updates_disarm\n    got=', '    :\n    got=', 1)"
mutant "off is silent" chk_off "s.replace('DISABLED by the approval-gated variable', 'off', 1)"
mutant "reboot window widened to 0-9" chk_window "s.replace('^0[0-4]:[0-5][0-9]\$', '^[0-2][0-9]:[0-5][0-9]\$', 1)"
mutant "render-time local conversion re-added (lens no-tz-conversion class)" chk_window "s.replace('render_os_updates_reboot_timer \"\$OSU_REBOOT\"', 'render_os_updates_reboot_timer \"\$(date -d \"today \${OSU_REBOOT} UTC\" +%H:%M)\"', 1)"
mutant "set-timezone UTC dropped" chk_utc "s.replace('timedatectl set-timezone UTC >/dev/null 2>&1 || true', ':', 1)"
mutant "non-UTC accepted" chk_utc "s.replace('    *) os_updates_refuse \"OS updates: box timezone', '    *) return 0; os_updates_refuse \"OS updates: box timezone', 1)"
mutant "u-u Automatic-Reboot true (lens withusers-false class)" chk_noreboot_uu "s.replace('Unattended-Upgrade::Automatic-Reboot \"false\";', 'Unattended-Upgrade::Automatic-Reboot \"true\";', 1)"
mutant "u-u WithUsers line re-added" chk_noreboot_uu "s.replace('  printf \'%s\\\\n\' \'Unattended-Upgrade::Automatic-Reboot \"false\";\'', '  printf \'%s\\\\n\' \'Unattended-Upgrade::Automatic-Reboot \"false\";\' \'Unattended-Upgrade::Automatic-Reboot-WithUsers \"true\";\'', 1)"
mutant "refusal does not disarm" chk_disarm_origin "s.replace('  os_updates_disarm\n  die ', '  die ', 1)"
mutant "disarm keeps the timer drop-ins" chk_disarm_origin "s.replace('    rm -f \"\${OS_UPD_UNIT_DIR}/\${d}/\${OS_UPD_DROPIN_NAME}\"', '    :', 1)"
mutant "disarm keeps the reboot timer" chk_disarm_origin "s.replace('  systemctl disable --now \"\${OS_UPD_REBOOT_UNIT}.timer\"', '  : \"\${OS_UPD_REBOOT_UNIT}.timer\"', 1)"
mutant "token written at apply (before the Gatus config)" chk_token "s.replace('  OS_UPD_NEW_TOKEN=\"\$(openssl rand -hex 32)\"\n', '  OS_UPD_NEW_TOKEN=\"\$(openssl rand -hex 32)\"\n  os_updates_commit_token\n', 1)"
mutant "token on curl argv" chk_token "s.replace('-m 10 -X POST -K - ', '-m 10 -X POST -H \"Authorization: Bearer \$token\" -K - ', 1)"
mutant "token echoed in the report line" chk_token "s.replace('push=HTTP %s\\\\n\' \"\$line\"', 'push=HTTP %s\\\\n\' \"\$line \$token\"', 1)"
mutant "token file world-readable" chk_token "s.replace('os_updates_install_file \"\$OS_UPD_TOKEN_FILE\" 0600', 'os_updates_install_file \"\$OS_UPD_TOKEN_FILE\" 0644', 1)"
mutant "staleness 72 h" chk_stale "s.replace('MAX_AGE=172800', 'MAX_AGE=259200', 1)"
mutant "run age ignored" chk_stale "s.replace('[ \$((now - run_m)) -lt \"\$MAX_AGE\" ]', 'true', 1)"
mutant "security lists freshness ignored" chk_stale "s.replace('[ \$((now - lists_m)) -lt \"\$MAX_AGE\" ]', 'true', 1)"
mutant "pending security ignored" chk_stale "s.replace('[ \"\$pending\" -eq 0 ] || reasons=', 'true || reasons=', 1)"
mutant "pending unknown reads green" chk_stale "s.replace('  reasons=\"pending-unknown\"', '  reasons=\"\"', 1)"
mutant "grace 72 h" chk_stale "s.replace('GRACE=93600', 'GRACE=259200', 1)"
mutant "grace survives the first real run" chk_stale "s.replace('[ \"\$run_m\" -le \"\$inst_m\" ] && ', '', 1)"
mutant "run marker on any service result" chk_afterrun "s.replace('[ \"\${SERVICE_RESULT:-}\" = success ] && ', '', 1)"
mutant "run marker without a fresh upgrade-stamp" chk_afterrun "s.replace('[ \"\$up\" -gt 0 ] && [ \$((now - up)) -lt \"\$GRACE\" ]', 'true', 1)"
mutant "env overrides honoured (MAX_AGE)" chk_envproof "s.replace('MAX_AGE=172800', 'MAX_AGE=\"\${MAX_AGE:-172800}\"', 1)"
mutant "report trusts the caller PATH" chk_envproof "s.replace(\"'PATH=/usr/sbin:/usr/bin:/sbin:/bin' \", '', 1)"
mutant "report ignores a live token swap" chk_swapwait "s.replace('while live \"\$SWAP_MARK\"', 'while false', 1)"
mutant "gate ignores a live provision" chk_gate "s.replace('live \"\$PROVISION_PIDFILE\" && {', 'false && {', 1)"
mutant "gate ignores a pending tang rotation" chk_gate "s.replace('[ -e \"\$ROTATION\" ] && { say', 'false && { say', 1)"
mutant "gate ignores a running upgrade" chk_gate "s.replace('\"\$SYSTEMCTL\" is-active --quiet apt-daily-upgrade.service && {', 'false && {', 1)"
mutant "gate trusts a reused pid" chk_gate "s.replace('[ -n \"\$now_st\" ] && [ \"\$now_st\" = \"\$st\" ]', '[ -d /proc/\$pid ]', 1)"
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
