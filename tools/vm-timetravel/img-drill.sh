#!/usr/bin/env bash
# tools/vm-timetravel/img-drill.sh - MANUAL live proof of the container-updater
# rollback drill (#253, docs/updaters.md "Drill (rollback ladder, live proof)").
# NOT in CI (needs /dev/kvm, Docker Hub and ~10-15 min). See docs/verification.md.
#
# Boots the Debian trixie genericcloud qcow2 under qemu + KVM INSIDE a docker
# container (same pattern as run.sh: the host needs docker and /dev/kvm, no
# qemu, no sudo), installs docker.io + tang + the updater's tools in the VM and
# stands up the minimum real box from the REAL scripts/010-provision.sh spans,
# extracted at run time (never copied): the CADDY RENDER, HARDENING CHECK, IMG
# UPDATER and GATUS EXTERNAL spans, the scalars (pins, ports, paths), log/warn/
# die, adv_ok and probe_tang_direct. Caddy and Gatus run on the repo-pinned
# builds resolved BY DIGEST by img_pin_resolve, through img_run_caddy /
# img_run_gatus; the updater is installed by img_updater_install (no ntfy).
# Then, capturing evidence:
#   a) a non-root drill is refused (exit 1, nothing touched, nothing pushed);
#   b) a drill while flock holds the updater lock is refused (same);
#   c) IMG_DRILL=caddy as root; d) IMG_DRILL=gatus as root: rung 0 drill-fault,
#      re-check fails, rung 1 restores the SAME digest; two creates on the
#      same digest (container id/StartedAt change); state files unchanged (no
#      hold, no record change, no disarm); the row read back from the VM's
#      Gatus API is red "rolled-back drill ver=<v> dig=<12 hex> reason=drill-fault";
#      tang answers through Caddy :80 afterwards;
#   e) one normal round: green, running:<tag>@sha256:<12 hex>.
#
# Deviations from production (harness only; the updater code is unchanged):
#   - tang is installed and moved to 127.0.0.1:${TANG_PORT} with a socket
#     drop-in replicated from 010's tang block (that block is not a span);
#   - the Gatus config is minimal (sqlite storage + web port + one tang (via
#     Caddy) endpoint, as Gatus refuses a config without one, + the rendered
#     external-endpoints rows), not 010's full inline render;
#   - the origin pair is a throwaway self-signed P-256 pair minted in the VM
#     (ORIGIN_TLS=1); no client-auth CA (AOP_TLS empty), so the mTLS/edge
#     probes are not exercised; DASH_TLS_STANZA is 010's no-client-auth form;
#   - STATUS_HOST/ANCHOR_HOSTNAME are RFC 2606 example names, MAIN_BOX_IPV4 is
#     a TEST-NET-2 address; the 6 h timer is stopped after install so only the
#     rounds this script runs touch the containers;
#   - IMG_UPDATE_SOAK_HOURS=720 (the maximum) so the non-drilled leg and the
#     normal round do not swap to a newer build; a swap is logged if it happens.
# Summary: $VMIMG_LOG (default /tmp/vm-img-drill.log), full guest transcript:
# $VMIMG_FULL_LOG (default /tmp/vm-img-drill.full.log). Throwaway SSH key, no
# secrets, every key is generated at run time.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOG="${VMIMG_LOG:-/tmp/vm-img-drill.log}"
FULL="${VMIMG_FULL_LOG:-/tmp/vm-img-drill.full.log}"
CACHE="${VMTT_CACHE:-/tmp/vm-timetravel-cache}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
case "$(uname -m)" in
  aarch64|arm64) ARCH=arm64 ;;
  x86_64) ARCH=amd64 ;;
  *) echo "unsupported host arch $(uname -m)" >&2; exit 1 ;;
esac
[ -c /dev/kvm ] || { echo "no /dev/kvm" >&2; exit 1; }
mkdir -p "$CACHE" "$WORK/payload"

# 1. extract the real spans + scalars from 010 (never a hand copy)
P="$ROOT/scripts/010-provision.sh"
span() { # $1 = marker name -> the span, markers included
  local b e
  b="$(grep -nF "# --- BEGIN $1" "$P" | head -n 1 | cut -d: -f1)"
  e="$(grep -nF "# --- END $1 ---" "$P" | head -n 1 | cut -d: -f1)"
  [ -n "$b" ] && [ -n "$e" ] && [ "$b" -lt "$e" ] || { echo "span $1 not found" >&2; exit 1; }
  sed -n "${b},${e}p" "$P"
}
fn() { # $1 = top-level function name -> its definition (to the first column-0 brace)
  local out
  out="$(awk -v f="$1() {" 'index($0, f) == 1 { on = 1 } on { print } on && /^}/ { exit }' "$P")"
  [ -n "$out" ] || { echo "function $1 not found" >&2; exit 1; }
  printf '%s\n' "$out"
}
{
  printf '%s\n' '# extracted at run time from scripts/010-provision.sh by tools/vm-timetravel/img-drill.sh'
  for v in TANG_PORT GATUS_IMAGE GATUS_PORT GATUS_CONFIG CADDY_IMAGE CADDY_CONFIG CADDY_ORIGIN_CRT \
    CADDY_ORIGIN_KEY CADDY_AOP_CA CADDY_CHALLENGE_DIR CLOUDFRONT_ORIGIN_CIDRS; do
    grep -m 1 -E "^${v}=" "$P" || { echo "scalar $v not found" >&2; exit 1; }
  done
  grep -E '^(log|warn|die)\(\)' "$P" | head -n 3
  span 'CADDY RENDER'
  span 'HARDENING CHECK'
  span 'IMG UPDATER'
  fn adv_ok
  fn probe_tang_direct
} >"$WORK/payload/lib.sh"
span 'GATUS EXTERNAL' >"$WORK/payload/gatus-ext.sh"
bash -n "$WORK/payload/lib.sh"

# 2. the in-VM driver (root): stand the box up, run a-e, print PASS/FAIL lines
cat >"$WORK/payload/guest.sh" <<'GUEST'
#!/usr/bin/env bash
set -euo pipefail
cd /opt/imgdrill
SUM=/opt/imgdrill/summary.log
: >"$SUM"
res() { printf '%-4s %s\n' "$1" "$2" | tee -a "$SUM"; [ "$1" = PASS ] || FAILS=$((FAILS + 1)); }
ev() { printf '       %s\n' "$*" | tee -a "$SUM"; }
chk() { if eval "$2"; then res PASS "$1"; else res FAIL "$1"; fi; }
FAILS=0
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq --no-install-recommends docker.io docker-cli tang jq jose openssl curl util-linux ca-certificates >/dev/null
systemctl enable --now docker >/dev/null 2>&1
command -v docker >/dev/null || die "docker CLI missing after install"
# shellcheck source=/dev/null
. ./lib.sh
# box identity (example names only) and the TLS shape
STATUS_HOST=vmdrill.status.example.net
ANCHOR_HOSTNAME=anchor-01-vmdrill
MAIN_BOX_IPV4=198.51.100.7
ORIGIN_TLS=1
AOP_TLS=""
IMG_UPDATE_SOAK_HOURS=720
unset IMG_AUTO_UPDATES NTFY_TOPIC NTFY_TOKEN
printf -v DASH_TLS_STANZA '\ttls %s %s' "$CADDY_ORIGIN_CRT" "$CADDY_ORIGIN_KEY"
# tang on loopback (replicated from 010's tang block: socket drop-in)
mkdir -p /etc/systemd/system/tangd.socket.d
printf '[Socket]\nListenStream=\nListenStream=127.0.0.1:%s\n' "$TANG_PORT" >/etc/systemd/system/tangd.socket.d/listen.conf
systemctl daemon-reload
systemctl enable tangd.socket >/dev/null 2>&1
systemctl restart tangd.socket
if ! img_try img_probe_tang_direct; then
  kd="$(systemctl cat tangd@.service 2>/dev/null | sed -n 's#^ExecStart=.*tangd \(/[^ ]*\).*#\1#p' | head -n 1)"
  kd="${kd:-/var/db/tang}"; kg="$(find /usr -name tangd-keygen -type f 2>/dev/null | head -n 1)"
  mkdir -p "$kd"; [ -z "$kg" ] || "$kg" "$kd"; chown -R "$(stat -c %U "$(dirname "$kd")")" "$kd" 2>/dev/null || true
  systemctl restart tangd.socket
  img_try img_probe_tang_direct || die "tang does not answer on 127.0.0.1:${TANG_PORT}"
fi
log "tang answers on 127.0.0.1:${TANG_PORT}"
# pins by digest (the provision path)
mkdir -p "$IMG_STATE_DIR"; chmod 700 "$IMG_STATE_DIR"
for ref in "$CADDY_IMAGE" "$GATUS_IMAGE"; do # harness pre-pull (retried, visible); img_pin_resolve pulls again itself
  for i in 1 2 3; do docker pull -q "$ref" && break; [ "$i" -lt 3 ] || die "docker pull $ref failed"; sleep 10; done
  log "pulled ${ref}: $(docker inspect --format '{{json .RepoDigests}}' "$ref")"
done
CADDY_PIN="$(img_pin_resolve caddy "$CADDY_IMAGE")" || die "caddy pin resolve failed"
GATUS_PIN="$(img_pin_resolve gatus "$GATUS_IMAGE")" || die "gatus pin resolve failed"
log "pins: ${CADDY_PIN} ${GATUS_PIN}"
# throwaway origin pair (CN/SAN = STATUS_HOST), Caddyfile render + hardening + validate
mkdir -p /etc/caddy "$CADDY_CHALLENGE_DIR" "$(dirname "$CADDY_ORIGIN_CRT")"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 7 -subj "/CN=${STATUS_HOST}" \
  -addext "subjectAltName=DNS:${STATUS_HOST}" -keyout "$CADDY_ORIGIN_KEY" -out "$CADDY_ORIGIN_CRT" 2>/dev/null
chmod 600 "$CADDY_ORIGIN_KEY"
render_caddyfile >"$CADDY_CONFIG"
assert_caddyfile_hardened
img_caddy_validate "$CADDY_PIN" "$CADDY_CONFIG" >/dev/null || die "caddy validate of the rendered Caddyfile failed"
# Gatus: the push rows through img_status_items_add + the GATUS EXTERNAL span
declare -a gatus_ext_items=()
img_status_items_add
# shellcheck source=/dev/null
. ./gatus-ext.sh
mkdir -p "$(dirname "$GATUS_CONFIG")"
{ # Gatus refuses a config with no endpoint: one row mirrors 010's tang (via Caddy) probe
  printf 'storage:\n  type: sqlite\n  path: /data/gatus.db\nweb:\n  port: 8080\nendpoints:\n'
  printf '  - name: tang (via Caddy)\n    group: anchor\n    url: http://hostanchor/adv\n    interval: 60s\n    conditions:\n      - "[STATUS] == 200"\n'
  printf 'external-endpoints:\n%s' "$GATUS_EXT_YAML"; } >"$GATUS_CONFIG"
chmod 600 "$GATUS_CONFIG"
img_run_gatus "$GATUS_PIN"
img_run_caddy "$CADDY_PIN"
for _ in $(seq 1 30); do r="$(IMG_CHECK_TRIES=1 img_selfcheck)" && break; sleep 4; done
if ! r="$(img_selfcheck)"; then docker ps -a; docker logs --tail 20 gatus 2>&1; docker logs --tail 20 caddy 2>&1; die "box never became healthy: ${r}"; fi
log "box healthy (img_selfcheck passed)"
IMG_SOAK="$(img_soak_hours)"; export IMG_SOAK
img_updater_install
systemctl stop piercloud-img-update.timer
U="$IMG_SBIN"
grep -q '^IMG_UPDATE_SOAK_HOURS=720$' "$U" || die "rendered updater does not carry the 720 h soak"
log "updater installed at ${U} (soak 720 h, ntfy unset, timer stopped)"

# evidence helpers
cinfo() { docker inspect --format '{{.Id}} {{.State.StartedAt}}' "$1"; }
cdig() { local id; id="$(docker inspect --format '{{.Image}}' "$1")"; docker inspect --format '{{join .RepoDigests " "}}' "$id"; } # ci-allowlist: code - docker inspect field name, not a live reference.
statehash() { (cd "$IMG_STATE_DIR" && ls -A && find . -type f -print0 | sort -z | xargs -0 sha256sum); }
rowjson() { curl -fsS "http://127.0.0.1:${GATUS_PORT}/api/v1/endpoints/$(img_gatus_key "$1 updates")/statuses?pageSize=100"; } # ci-allowlist: on-VM loopback Gatus read-back of the push row, not a provider endpoint.
rowlast() { rowjson "$1" | jq -c '.results | sort_by(.timestamp) | last | {success, errors}'; }
rowcount() { rowjson "$1" | jq '.results | length'; }
creates() { docker events --since "$1" --until "$2" --filter type=container --filter event=create --format '{{.Actor.Attributes.name}} {{index .Actor.Attributes "image"}}'; } # ci-allowlist: code - docker events attribute name, not a live reference.
capture_all() { printf '%s|%s|%s|%s|%s|%s\n' "$(cinfo caddy)" "$(cinfo gatus)" "$(statehash | sha256sum)" "$(rowcount caddy)" "$(rowcount gatus)" "$(img_probe_caddy80 && echo tang80-ok)"; }

# a) non-root refusal
before="$(capture_all)"
rc=0; runuser -u debian -- env IMG_DRILL=caddy "$U" >a.out 2>&1 || rc=$?
after="$(capture_all)"
ev "a) rc=${rc}: $(grep -o 'IMG_DRILL is honoured only for root.*' a.out | head -n 1)"
chk "a) non-root drill refused, exit 1 - docs: 'refuses for a non-root caller'" \
  '[ "$rc" = 1 ] && grep -q "honoured only for root on the box - drill refused" a.out && [ "$before" = "$after" ]'
# b) lock held -> refusal, nothing touched, nothing pushed
flock "$IMG_LOCK_FILE" sleep 20 & hp=$!
sleep 2
before="$(capture_all)"
rc=0; IMG_DRILL=caddy "$U" >b.out 2>&1 || rc=$?
after="$(capture_all)"
wait "$hp" || true
ev "b) rc=${rc}: $(grep -o '/run/piercloud-img-update.lock is held.*' b.out | head -n 1)"
ev "b) containers/state/row counts unchanged: $([ "$before" = "$after" ] && echo yes || echo NO)"
chk "b) drill under a held lock refused, exit 1 - docs: 'refuses (exit 1, nothing touched, nothing pushed) while a provision run or a timer round holds it'" \
  '[ "$rc" = 1 ] && grep -q "is held (a provision run or an update round is live) - drill refused" b.out && [ "$before" = "$after" ]'

drill() { # $1 = name, $2 = step letter
  local n="$1" s="$2" other pin tag dig d12 bi ai bd ad bs as t0 t1 ev_c nc no rc=0 want row
  case "$n" in caddy) other=gatus ;; *) other=caddy ;; esac
  pin="$(img_pin_get "$n")"; read -r _ tag dig <<<"$(img_split_ref "$(img_effective_ref "$n" "$pin")")"; d12="${dig:7:12}"
  bi="$(cinfo "$n")"; bd="$(cdig "$n")"; bs="$(statehash)"
  t0="$(date +%s)"
  IMG_DRILL="$n" "$U" >"$s.out" 2>&1 || rc=$?
  t1="$(( $(date +%s) + 1 ))"
  ai="$(cinfo "$n")"; ad="$(cdig "$n")"; as="$(statehash)"
  ev_c="$(creates "$t0" "$t1")"; nc="$(printf '%s\n' "$ev_c" | grep -c "^${n} " || true)"; no="$(printf '%s\n' "$ev_c" | grep -c "^${other} " || true)"
  want="rolled-back drill ver=${tag} dig=${d12} reason=drill-fault"
  row="$(rowlast "$n")"
  ev "${s}) IMG_DRILL=${n} rc=${rc}; current ${tag} dig=${d12}"
  while IFS= read -r l; do ev "${s}) log: ${l}"; done < <(grep -E "${n}: (DRILL|candidate|ladder|restore|rolled-back|fell-back|all-rungs|drill-fault)|${other}: (green|swapping|now on)" "$s.out" | sed 's/\x1b\[[0-9;]*m//g')
  ev "${s}) creates: $(printf '%s' "$ev_c" | tr '\n' ';')"
  ev "${s}) digest before: ${bd}"
  ev "${s}) digest after:  ${ad}"
  ev "${s}) id/StartedAt before: ${bi:0:12} ${bi#* }; after: ${ai:0:12} ${ai#* }"
  ev "${s}) state before==after: $([ "$bs" = "$as" ] && echo yes || echo NO); files: $(ls -A "$IMG_STATE_DIR" | tr '\n' ' ')"
  ev "${s}) Gatus row $(img_gatus_key "$n updates"): ${row}"
  chk "${s}) rung 0 drill-fault - docs: 'rung 0 re-creates the current digest ... its self-check is forced to fail (drill-fault)'" \
    "grep -q '${n}: DRILL rung 0 - candidate ${tag} (${d12}) re-created' '$s.out' && grep -q 'the candidate failed as injected (drill-fault)' '$s.out' && ! grep -q drill-fault-not-injected '$s.out'"
  chk "${s}) re-check fails - docs: 'the re-check fails the same way'" \
    "grep -q '${n}: candidate check failed (drill-fault) - one re-check' '$s.out' && ! grep -q 'passed its re-check' '$s.out'"
  chk "${s}) rung 1 restores the same digest, verified - docs: 'rung 1 restores the previous exact digest (the same one) and verifies it for real (digest assert + every self-check, tang first)'" \
    "grep -q '${n}: ladder rung 1 - restoring the previous digest ${tag} (${d12})' '$s.out' && grep -q '${n}: ladder rung 1 green - back on ${tag} (${d12})' '$s.out' && ! grep -q 'ladder rung 2' '$s.out'"
  chk "${s}) recreated twice on the same digest - docs: 'the container is recreated twice on the same digest'" \
    "[ '$nc' = 2 ] && [ '$no' = 0 ] && [ -n '$bd' ] && [ '$bd' = '$ad' ] && [ '${bi%% *}' != '${ai%% *}' ] && [ '${bi#* }' != '${ai#* }' ]"
  chk "${s}) no hold, no record change, no disarm - docs: 'no hold is written ..., no record changes, no disarm'" \
    "[ '$bs' = '$as' ] && ! ls '$IMG_STATE_DIR' | grep -qE '\\.bad\$|^disarmed\$'"
  chk "${s}) red row - docs: 'the row turns red rolled-back drill ver=<current> dig=<12 hex> reason=drill-fault'" \
    "[ \"\$(jq -r .success <<<'$row')\" = false ] && [ \"\$(jq -r '.errors[0]' <<<'$row')\" = '$want' ]"
  chk "${s}) tang answers through Caddy :80 afterwards (img_probe_caddy80)" 'img_probe_caddy80'
}
drill caddy c
drill gatus d

# e) one normal round
rc=0; "$U" >e.out 2>&1 || rc=$?
ev "e) normal round rc=${rc}"
while IFS= read -r l; do ev "e) log: ${l}"; done < <(grep -E '(caddy|gatus): ' e.out | sed 's/\x1b\[[0-9;]*m//g')
if grep -q 'swapping' e.out; then ev "e) a swap happened in the normal round (recorded, allowed)"; else ev "e) no swap (soak 720 h): both stay on the pin digests"; fi
for n in caddy gatus; do ev "e) Gatus row $(img_gatus_key "$n updates"): $(rowlast "$n")"; done
chk "e) next round green - docs: 'the next round is green' + 'Every green push carries what runs, running:<tag>@sha256:<12 hex>'" \
  'grep -qE "caddy: green running:[^ @]+@sha256:[0-9a-f]{12}$" <(sed "s/\x1b\[[0-9;]*m//g" e.out) && grep -qE "gatus: green running:[^ @]+@sha256:[0-9a-f]{12}$" <(sed "s/\x1b\[[0-9;]*m//g" e.out) && [ "$(rowlast caddy | jq -r .success)" = true ] && [ "$(rowlast gatus | jq -r .success)" = true ]'
ev "final state files: $(ls -A "$IMG_STATE_DIR" | tr '\n' ' ')"
if [ "$FAILS" -eq 0 ]; then res PASS "RESULT: all expectations hold"; else res FAIL "RESULT: ${FAILS} expectation(s) failed"; exit 1; fi
GUEST
tar -C "$WORK/payload" -cf "$WORK/payload.tar" .

# 3. the in-container VM driver (same boot pattern as run.sh)
cat >"$WORK/inner.sh" <<'INNER'
#!/usr/bin/env bash
set -euo pipefail
ARCH="$1"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
if [ "$ARCH" = arm64 ]; then pk="qemu-system-arm qemu-efi-aarch64"; else pk="qemu-system-x86"; fi
# shellcheck disable=SC2086
apt-get install -y -qq --no-install-recommends $pk qemu-utils dosfstools mtools openssh-client curl ca-certificates >/dev/null
BASE="/cache/debian-13-genericcloud-$ARCH.qcow2"
URL="https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-$ARCH.qcow2" # ci-allowlist: Debian cloud qcow2 URL for the manual VM proof, not an SCP reference
[ -s "$BASE" ] || curl -fsSL -o "$BASE" "$URL"
qemu-img create -q -f qcow2 -F qcow2 -b "$BASE" /w/vm.qcow2 10G
ssh-keygen -q -t ed25519 -N '' -f /w/key
printf 'instance-id: vmimg-1\nlocal-hostname: vmimg\n' >/w/meta-data
printf '#cloud-config\nssh_authorized_keys:\n  - %s\n' "$(cat /w/key.pub)" >/w/user-data
truncate -s 2M /w/seed.raw; mkfs.vfat -n CIDATA /w/seed.raw >/dev/null; mcopy -i /w/seed.raw /w/user-data /w/meta-data ::
if [ "$ARCH" = arm64 ]; then
  Q=(qemu-system-aarch64 -M virt -cpu host -bios /usr/share/qemu-efi-aarch64/QEMU_EFI.fd)
else
  Q=(qemu-system-x86_64 -M q35 -cpu host)
fi
"${Q[@]}" -accel kvm -smp 2 -m 3072 -drive if=virtio,file=/w/vm.qcow2,format=qcow2 \
  -drive if=virtio,file=/w/seed.raw,format=raw -netdev user,id=n0,hostfwd=tcp:127.0.0.1:2222-:22 \
  -device virtio-net-pci,netdev=n0,romfile= -display none -serial file:/w/console.log -monitor none &
QPID=$!
S=(ssh -q -i /w/key -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o ServerAliveInterval=30 debian@127.0.0.1)
wait_ssh() { local i; for i in $(seq 1 90); do kill -0 "$QPID" 2>/dev/null || return 1; "${S[@]}" true 2>/dev/null && return 0; sleep 4; done; return 1; }
finish() { kill "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; }
trap finish EXIT
wait_ssh || { echo "FAIL: VM never answered ssh" | tee /w/summary.log; tail -n 20 /w/console.log; exit 1; }
"${S[@]}" "sudo mkdir -p /opt/imgdrill && sudo tar -C /opt/imgdrill --no-same-owner -xf -" </w/payload.tar
rc=0
"${S[@]}" "sudo bash /opt/imgdrill/guest.sh" </dev/null >/w/full.log 2>&1 || rc=$?
"${S[@]}" "sudo cat /opt/imgdrill/summary.log" >/w/summary.log 2>/dev/null || true
"${S[@]}" 'sudo bash -c "cd /opt/imgdrill && tail -n +1 a.out b.out c.out d.out e.out"' >>/w/full.log 2>&1 || true
[ "$rc" -eq 0 ] || tail -n 30 /w/full.log
exit "$rc"
INNER

rc=0
docker run --rm --device /dev/kvm -v "$WORK:/w" -v "$CACHE:/cache" debian:trixie-slim bash /w/inner.sh "$ARCH" || rc=$?
cp "$WORK/full.log" "$FULL" 2>/dev/null || true
{ printf 'vm-img-drill %s arch=%s rc=%s head=%s\n' "$(date -u +%FT%TZ)" "$ARCH" "$rc" "$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
  printf 'docs/updaters.md "Drill (rollback ladder, live proof)"; full transcript: %s\n' "$FULL"
  cat "$WORK/summary.log" 2>/dev/null || true; } | tee "$LOG"
exit "$rc"
