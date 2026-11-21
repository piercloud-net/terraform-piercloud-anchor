#!/usr/bin/env bash
# tests/time-sync/run-test.sh — anchor clock discipline (#281).
#
# Extracts the REAL CLOCK DISCIPLINE span from scripts/010-provision.sh (never
# a copy; same pattern as tests/os-updates) and proves:
#   (a) the rendered chrony config authenticates EVERY source (NTS, several
#       of them) and renders no plaintext NTP server or pool at all; the
#       first-boot certificate-time problem is solved by nocerttimecheck, not
#       by an unauthenticated source (chrony >= 4.0, refused otherwise);
#   (b) provisioning refuses when the clock does not synchronize within
#       TIME_SYNC_WAIT_SECONDS (300 s), and says why;
#   (c) the wait is bounded by that constant (the loop never spins past it);
#   (d) a synchronized clock passes and the measured offset is logged;
#   (e) chrony is enabled and the unauthenticated systemd-timesyncd is masked,
#       so a later package action cannot put it back in charge;
#   (f) the witness's runtime posture is unchanged: a clock problem is a
#       verdict (cause clock-skew), never a stopped witness (pinned by the
#       recording-witness harness; the marker here keeps the split honest).
set -euo pipefail

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HARNESS_DIR}/../.." && pwd)"
PROVISION="${ROOT}/scripts/010-provision.sh"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/time-sync.XXXXXX")"
cleanup() { rm -rf "${WORK}"; }
trap cleanup EXIT

pass=0
fail=0
ok()  { pass=$((pass + 1)); printf 'ok   %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL %s\n' "$1"; }
is()  { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi; }
has() { case "$3" in *"$2"*) ok "$1" ;; *) bad "$1 (missing '$2' in: ${3})" ;; esac; }

BEGIN='# --- BEGIN CLOCK DISCIPLINE (tests/time-sync extracts this span; keep markers) ---'
END='# --- END CLOCK DISCIPLINE ---'
begin_line="$(grep -nF -- "${BEGIN}" "${PROVISION}" | cut -d: -f1)"
end_line="$(grep -nF -- "${END}" "${PROVISION}" | cut -d: -f1)"
[ -n "${begin_line}" ] && [ -n "${end_line}" ] || { printf 'FAIL clock-discipline markers missing\n'; exit 1; }
sed -n "$((begin_line + 1)),$((end_line - 1))p" "${PROVISION}" >"${WORK}/span.src"
[ -s "${WORK}/span.src" ] || { printf 'FAIL extracted clock span is empty\n'; exit 1; }

# The span calls provision's log/die; stub them so a refusal is observable.
log() { printf '[time-sync] %s\n' "$*"; }
die() { printf 'REFUSED: %s\n' "$*"; exit 1; }
source "${WORK}/span.src"

# -- (a) the rendered config ------------------------------------------------
conf="$(time_sync_render_conf)"
has "chrony config pins a drift file" "driftfile /var/lib/chrony/chrony.drift" "${conf}"
has "chrony config steps a large first-boot offset" "makestep 1.0 3" "${conf}"
has "chrony config keeps the RTC in sync" "rtcsync" "${conf}"
has "chrony config authenticates NLnet Labs over NTS" "server nts.time.nl iburst nts" "${conf}"
has "chrony config authenticates Netnod over NTS" "server nts.netnod.se iburst nts" "${conf}"
has "chrony config authenticates PTB over NTS" "server ptbtime1.ptb.de iburst nts" "${conf}"
has "chrony config relaxes the certificate time check for the first updates only" "nocerttimecheck 1" "${conf}"
# TM-1/RT-3: a plaintext NTP source left in the config is a PERMANENT
# unauthenticated clock (nothing retires it), so no pool or server line may
# exist without nts. This fails at 941a4ec (the pool line is unconditional).
plain_sources="$(printf '%s\n' "${conf}" | grep -E '^(pool|server|peer)[[:space:]]' | grep -v '[[:space:]]nts$' || true)"
is "chrony config renders no plaintext NTP server or pool" "" "${plain_sources}"
if printf '%s\n' "${conf}" | grep -qE '^pool[[:space:]]'; then
  bad "chrony config still carries a plain NTP pool (a permanent unauthenticated source)"
else
  ok "chrony config carries no plain NTP pool"
fi
nts_count="$(printf '%s\n' "${conf}" | grep -c '^server .* nts$' || true)"
is "the config uses several authenticated sources (outlier rejection)" "3" "${nts_count}"
# The first-boot relaxation is chrony 4.0+ only: an older box must be REFUSED
# rather than rendered a directive its chrony silently ignores.
is "the nocerttimecheck floor is the chrony version that documents it" "4" "${TIME_SYNC_NOCERTTIMECHECK_MIN_MAJOR}"
is "the provisioning wait is the decided 300 s" "300" "${TIME_SYNC_WAIT_SECONDS}"

# -- (b)/(c) the refusal and its bound -------------------------------------
# chronyc reports an unsynchronized clock: the converge must refuse after
# exactly TIME_SYNC_WAIT_SECONDS sleeps, not spin forever.
chronyc() {
  case "$*" in
    *tracking*)
      printf 'Reference ID    : 00000000 ()\nLeap status     : Not synchronised\nSystem time     : 0.000000000 seconds slow of NTP time\n'
      ;;
  esac
}
apt-get() { return 0; }
systemctl() { return 0; }
chronyd() { printf 'chronyd (chrony) version 4.6.1 (+CMDMON +NTP +NTS)\n'; }
CHRONY_CONF="${WORK}/chrony.conf"
# The span waits with the absolute `/usr/bin/env sleep 1`, so the wait is
# measured, not stubbed: it must be bounded by the constant and never spin.
TIME_SYNC_WAIT_SECONDS=3
rc=0
SECONDS=0
converge_out="$(time_sync_converge 2>&1)" || rc=$?
waited=${SECONDS}
is "an unsynchronized clock refuses the provision" "1" "${rc}"
has "the refusal names the wait bound" "did not synchronize within 3s" "${converge_out}"
has "the refusal names the NTS egress paths" "TCP/4460" "${converge_out}"
if [ "${waited}" -ge 2 ] && [ "${waited}" -le 6 ]; then
  ok "the wait is bounded by TIME_SYNC_WAIT_SECONDS (waited ${waited}s of 3s)"
else
  bad "the wait was not bounded by TIME_SYNC_WAIT_SECONDS (waited ${waited}s of 3s)"
fi
is "the config was rendered to the pinned path" "yes" \
  "$([ -s "${CHRONY_CONF}" ] && echo yes || echo no)"

# -- (a2) an older chrony is refused, never rendered a directive it lacks ---
chronyd() { printf 'chronyd (chrony) version 3.4 (+CMDMON +NTP +RTC)\n'; }
TIME_SYNC_WAIT_SECONDS=0
rc=0
old_out="$(time_sync_converge 2>&1)" || rc=$?
is "a chrony older than nocerttimecheck refuses the provision" "1" "${rc}"
has "the refusal names the installed chrony version" "version 3.4" "${old_out}"
has "the refusal names the required directive" "nocerttimecheck" "${old_out}"
chronyd() { printf 'chronyd (chrony) version 4.6.1 (+CMDMON +NTP +NTS)\n'; }

# -- (e) install/enable posture --------------------------------------------
# A file, not a variable: the converge runs in a subshell (its die exits).
SYSTEMCTL_CALLS="${WORK}/systemctl.calls"
: >"${SYSTEMCTL_CALLS}"
systemctl() { printf '%s;' "$*" >>"${SYSTEMCTL_CALLS}"; return 0; }
systemctl_calls() { cat "${SYSTEMCTL_CALLS}" 2>/dev/null || true; }
# WAIT=0 keeps this leg instant: the posture assertions do not need a wait.
TIME_SYNC_WAIT_SECONDS=0
rc=0
# A subshell: the span's die is an exit, and a refusal must not end the test.
( time_sync_converge ) >/dev/null 2>&1 || rc=$?
is "an unsynchronized clock still refuses after the install" "1" "${rc}"
has "systemd-timesyncd is disabled (never two clock owners)" "disable --now systemd-timesyncd" "$(systemctl_calls)"
has "systemd-timesyncd is masked (a package action cannot restore it)" "mask systemd-timesyncd" "$(systemctl_calls)"
has "chrony is enabled" "enable chrony" "$(systemctl_calls)"
has "chrony is (re)started" "restart chrony" "$(systemctl_calls)"

# -- (d) a synchronized clock passes and logs the offset --------------------
chronyc() {
  case "$*" in
    *tracking*)
      printf 'Reference ID    : C0A8C8C8 (nts.time.nl)\nLeap status     : Normal\nSystem time     : 0.000123456 seconds slow of NTP time\n'
      ;;
  esac
}
TIME_SYNC_WAIT_SECONDS=3
rc=0
SECONDS=0
converge_out="$(time_sync_converge 2>&1)" || rc=$?
is "a synchronized clock passes provisioning" "0" "${rc}"
has "the pass logs the measured offset" "offset: 0.000123456 seconds slow of NTP time" "${converge_out}"
is "a synchronized clock does not wait" "0" "${SECONDS}"

# -- time_sync_synchronized: the accept/reject matrix ----------------------
for shape in \
  "Normal|C0A8C8C8 (nts.time.nl)|accept" \
  "Not synchronised|00000000 ()|reject" \
  "Normal|00000000 ()|reject" \
  "Normal||reject" \
  "|C0A8C8C8 (nts.time.nl)|reject"; do
  # NOT leap/reference: those are local inside time_sync_synchronized, so a
  # same-named global would be shadowed to empty inside the stub.
  ts_leap="${shape%%|*}"
  rest="${shape#*|}"
  ts_ref="${rest%|*}"
  want="${rest##*|}"
  chronyc() {
    printf 'Reference ID    : %s\nLeap status     : %s\n' "${ts_ref}" "${ts_leap}"
  }
  rc=0
  time_sync_synchronized || rc=$?
  if [ "${want}" = "accept" ]; then want_rc=0; else want_rc=1; fi
  is "tracking '${ts_leap}' / '${ts_ref}' -> ${want}" "${want_rc}" "${rc}"
done

# -- (f) the runtime posture is the witness's, not the provisioner's ------
if grep -q 'clock-skew' "${ROOT}/scripts/010-provision.sh"; then
  ok "the witness reports clock trouble as a verdict cause (never stops)"
else
  bad "the witness lost the clock-skew cause class"
fi

printf '\n%s passed, %s failed\n' "${pass}" "${fail}"
[ "${fail}" -eq 0 ]
