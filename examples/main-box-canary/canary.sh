#!/usr/bin/env bash
#
# piercloud anchor canary — runs ON the main box (the LUKS-encrypted machine
# the anchor unlocks), on a systemd timer. The anchor-side Gatus sees the
# main box, but Gatus probes never traverse the anchor's ingress firewall —
# so firewall drift, policy deletion, and stale bindings are invisible to it.
# This canary closes that blind spot from the other direction (mutual-silence
# coverage: each monitor covers the other's blind spot).
#
# On ANY failure it pushes ntfy carrying the main box's CURRENT public IP
# (discovered here — the anchor cannot see it through its own firewall) plus
# a pre-written mode=apply snippet, so recovery is one dispatch away.
#
# Install: see README.md in this directory. Configure ANCHOR_URL + NTFY_* below.
#
set -euo pipefail

ANCHOR_URL="http://anchor-01-USER.piercloud.net"  # tenant anchor, DNS name (same-URL rebuilds need no change here)
NTFY_BASE="https://ntfy.sh"                       # or your own ntfy server
NTFY_TOPIC="piercloud-anchor"                     # publish-scoped token below
NTFY_TOKEN=""                                     # empty = log locally only

fail() {
  local reason="$1"
  local now_ip
  now_ip="$(curl -sS -m 10 https://api.ipify.org || echo UNKNOWN)"
  local msg="piercloud canary FAIL (main box): $reason. anchor=$ANCHOR_URL main-ip-now=$now_ip. If drift/deleted policy: dispatch provision.yml mode=apply (add-first, confirm boot). If anchor dead: unlock via passphrase, rebuild, regen same URL."
  logger -t piercloud-canary "$msg"
  echo "$msg" >&2
  if [ -n "$NTFY_TOKEN" ]; then
    curl -sS -u ":$NTFY_TOKEN" -d "$msg" "$NTFY_BASE/$NTFY_TOPIC" >/dev/null || true
  fi
  exit 1
}

# 1. Anchor answers its advertise endpoint.
curl -sS -m 15 -o /dev/null -w "%{http_code}" "$ANCHOR_URL/adv" | grep -q "^200$" \
  || fail "anchor /adv unreachable (anchor down? firewall drift? policy deleted?)"

# 2. Our clevis binding still reports healthy.
# Default device path is prose (main-box label), not a live SCP disk reference. # ci-allowlist: prose default path, exempt this line and the next.
LUKS_DEV="${LUKS_DEVICE:-/dev/disk/by-label/cryptroot}" # ci-allowlist: prose — main-box device-path default, not a live SCP disk reference.
clevis luks report -d "$LUKS_DEV" >/dev/null 2>&1 \
  || fail "clevis luks report unhealthy (stale binding? rotated anchor keys?)"

echo "canary OK: anchor reachable, binding healthy."
