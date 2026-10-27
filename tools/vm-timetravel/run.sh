#!/usr/bin/env bash
# tools/vm-timetravel/run.sh - MANUAL time-travel proof for the A-OS slice (#51).
# NOT in CI (needs /dev/kvm, a network fetch and ~10-20 min). See docs/verification.md.
#
# Renders ONLY the OS-updates artifacts from the real scripts/010-provision.sh
# span (os_updates_render_tree; no full provision), boots the Debian trixie
# genericcloud qcow2 for the host arch under qemu + KVM INSIDE a docker
# container (the host needs docker and /dev/kvm, no qemu, no sudo), applies the
# artifacts, disables NTP and moves the clock:
#   1. 02:29:30 UTC -> apt-daily-upgrade fires (journal), the report hook runs;
#   2. /run/reboot-required + 03:29:30 UTC -> the gated reboot timer reboots;
#   3. after the boot the three timers are still enabled.
# Summary log: $VMTT_LOG (default /tmp/vm-timetravel.log). Throwaway SSH key, no secrets.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOG="${VMTT_LOG:-/tmp/vm-timetravel.log}"
CACHE="${VMTT_CACHE:-/tmp/vm-timetravel-cache}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
case "$(uname -m)" in
  aarch64|arm64) ARCH=arm64 ;;
  x86_64) ARCH=amd64 ;;
  *) echo "unsupported host arch $(uname -m)" >&2; exit 1 ;;
esac
[ -c /dev/kvm ] || { echo "no /dev/kvm" >&2; exit 1; }
mkdir -p "$CACHE" "$WORK/tree"

# 1. render the artifacts from the real span (stubbed log/die, Debian origin)
P="$ROOT/scripts/010-provision.sh"
b="$(grep -nF '# --- BEGIN OS UPDATES' "$P" | cut -d: -f1)"
e="$(grep -nF '# --- END OS UPDATES ---' "$P" | cut -d: -f1)"
printf 'ID=debian\nVERSION_CODENAME=trixie\n' >"$WORK/os-release"
( log() { :; }; warn() { :; }; die() { echo "render: $*" >&2; exit 1; }
  # shellcheck disable=SC2034 # read by the sourced span
  GATUS_PORT=8080
  # shellcheck disable=SC2034 # read by the sourced span
  gatus_ext_items=()
  # shellcheck disable=SC1090 # the span is extracted at run time
  source <(sed -n "$((b + 1)),$((e - 1))p" "$P")
  OS_UPD_OS_RELEASE="$WORK/os-release" os_updates_render_tree "$WORK/tree" )
tar -C "$WORK/tree" -cf "$WORK/tree.tar" .
cp "$ROOT/tools/vm-timetravel/base-image.sh" "$WORK/base-image.sh" # ci-allowlist: helper file name, not an image reference.

# 2. the in-container driver
cat >"$WORK/inner.sh" <<'INNER'
#!/usr/bin/env bash
set -euo pipefail
ARCH="$1"
say() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a /w/summary.log; }
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
if [ "$ARCH" = arm64 ]; then pk="qemu-system-arm qemu-efi-aarch64"; else pk="qemu-system-x86"; fi
# shellcheck disable=SC2086
apt-get install -y -qq --no-install-recommends $pk qemu-utils dosfstools mtools openssh-client curl ca-certificates >/dev/null
source /w/base-image.sh # ci-allowlist: helper file name, not an image reference.
BASE="$(vmtt_stage_base "$ARCH" /cache /w/base.qcow2 2>/w/base.err)" || { cat /w/base.err | tee -a /w/summary.log; say "FAIL: base qcow2 refused, VM not booted"; exit 1; }
qemu-img create -q -f qcow2 -F qcow2 -b "$BASE" /w/vm.qcow2 8G
ssh-keygen -q -t ed25519 -N '' -f /w/key
printf 'instance-id: vmtt-1\nlocal-hostname: vmtt\n' >/w/meta-data
printf '#cloud-config\nssh_authorized_keys:\n  - %s\n' "$(cat /w/key.pub)" >/w/user-data
truncate -s 2M /w/seed.raw; mkfs.vfat -n CIDATA /w/seed.raw >/dev/null; mcopy -i /w/seed.raw /w/user-data /w/meta-data ::
if [ "$ARCH" = arm64 ]; then
  Q=(qemu-system-aarch64 -M virt -cpu host -bios /usr/share/qemu-efi-aarch64/QEMU_EFI.fd)
else
  Q=(qemu-system-x86_64 -M q35 -cpu host)
fi
"${Q[@]}" -accel kvm -smp 2 -m 2048 -drive if=virtio,file=/w/vm.qcow2,format=qcow2 \
  -drive if=virtio,file=/w/seed.raw,format=raw -netdev user,id=n0,hostfwd=tcp:127.0.0.1:2222-:22 \
  -device virtio-net-pci,netdev=n0,romfile= -display none -serial file:/w/console.log -monitor none &
QPID=$!
S=(ssh -q -i /w/key -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 debian@127.0.0.1)
vm() { "${S[@]}" "sudo bash -c $(printf '%q' "$1")"; }
wait_ssh() { local i; for i in $(seq 1 90); do kill -0 "$QPID" 2>/dev/null || return 1; "${S[@]}" true 2>/dev/null && return 0; sleep 4; done; return 1; }
finish() { kill "$QPID" 2>/dev/null || true; [ -z "${VMTT_TMP:-}" ] || rm -f -- "$VMTT_TMP"; } # ci-allowlist: cleanup of the pinned base download's temp file, not a live reference.
trap finish EXIT
wait_ssh || { say "FAIL: VM never answered ssh"; tail -n 20 /w/console.log; exit 1; }
say "booted: $(vm 'grep PRETTY /etc/os-release; uname -m')"
# apply ONLY the rendered artifacts (+ the package they configure)
"${S[@]}" "sudo tar -C / --no-same-owner --no-overwrite-dir -xf -" </w/tree.tar
vm 'apt-get update -qq; apt-get install -y -qq unattended-upgrades >/dev/null; timedatectl set-timezone UTC; systemctl daemon-reload;
    systemctl enable apt-daily.timer apt-daily-upgrade.timer piercloud-os-reboot.timer >/dev/null 2>&1;
    systemctl restart apt-daily.timer apt-daily-upgrade.timer piercloud-os-reboot.timer; timedatectl set-ntp false'
say "applied: $(vm 'ls /etc/apt/apt.conf.d/52piercloud-unattended-upgrades /usr/local/sbin/piercloud-os-*; timedatectl show -p Timezone -p NTP')"
day="$(vm 'date -u +%F')"; now_hm="$(vm 'date -u +%H%M')"
[ "$now_hm" -lt 0229 ] || day="$(vm "date -u -d '$day + 1 day' +%F")"
boot1="$(vm 'cat /proc/sys/kernel/random/boot_id')"
# step 1: 02:29:30 -> apt-daily-upgrade
vm "timedatectl set-time '$day 02:29:30'"
say "clock set to $day 02:29:30 UTC; next upgrade elapse: $(vm 'systemctl show -p NextElapseUSecRealtime --value apt-daily-upgrade.timer')"
sleep 40
if ! vm 'journalctl -u apt-daily-upgrade.service --since "'"$day"' 02:29:00" | grep -q Start'; then
  say "not fired in the first 40 s (RandomizedDelaySec=15m); jumping to $day 02:45:05 (past the latest elapse)"
  vm "timedatectl set-time '$day 02:45:05'"
fi
for _ in $(seq 1 150); do
  vm 'journalctl -u apt-daily-upgrade.service | grep -q "os-updates report:"' && break; sleep 6
done
say "apt-daily-upgrade journal: $(vm 'journalctl -u apt-daily-upgrade.service --no-pager -o short | grep -E "Start|Finished|os-updates report|Deactivated" | tail -n 6' | tr '\n' '|')"
say "run marker: $(vm 'ls -l --time-style=+%FT%T /var/lib/piercloud/os-updates.last-run 2>&1')"
# step 2: reboot-required + 03:29:30 -> gated reboot
vm 'until ! systemctl is-active --quiet apt-daily-upgrade.service; do sleep 2; done; touch /run/reboot-required'
vm "timedatectl set-time '$day 03:29:30'"
say "reboot-required set, clock $day 03:29:30 UTC; next reboot elapse: $(vm 'systemctl show -p NextElapseUSecRealtime --value piercloud-os-reboot.timer')"
for _ in $(seq 1 60); do
  b2="$(vm 'cat /proc/sys/kernel/random/boot_id' 2>/dev/null || true)"
  [ -n "$b2" ] && [ "$b2" != "$boot1" ] && break; sleep 4
done
wait_ssh || { say "FAIL: no ssh after the reboot"; exit 1; }
b2="$(vm 'cat /proc/sys/kernel/random/boot_id')"
if [ "$b2" != "$boot1" ]; then say "REBOOTED by the window (boot_id changed)"; else say "FAIL: no reboot"; exit 1; fi
say "previous boot gate: $(vm 'journalctl -b -1 -u piercloud-os-reboot.service --no-pager -o cat 2>&1 | tail -n 3' | tr '\n' '|')"
# step 3: timers survive the boot
say "after boot: $(vm 'systemctl is-enabled apt-daily.timer apt-daily-upgrade.timer piercloud-os-reboot.timer | tr "\n" " "; systemctl is-active apt-daily.timer apt-daily-upgrade.timer piercloud-os-reboot.timer | tr "\n" " "')"
say "timers: $(vm 'systemctl list-timers --all --no-pager apt-daily.timer apt-daily-upgrade.timer piercloud-os-reboot.timer | head -n 4' | tr '\n' '|')"
st="$(vm 'systemctl is-enabled apt-daily.timer apt-daily-upgrade.timer piercloud-os-reboot.timer' | sort -u)"
if [ "$st" = enabled ]; then say "RESULT: PASS"; else say "RESULT: FAIL (timers: $st)"; exit 1; fi
INNER

rc=0
docker run --rm --device /dev/kvm -v "$WORK:/w" -v "$CACHE:/cache" debian:trixie-slim bash /w/inner.sh "$ARCH" || rc=$?
{ printf 'vm-timetravel %s arch=%s rc=%s\n' "$(date -u +%FT%TZ)" "$ARCH" "$rc"; cat "$WORK/summary.log" 2>/dev/null || true; } | tee "$LOG"
exit "$rc"
