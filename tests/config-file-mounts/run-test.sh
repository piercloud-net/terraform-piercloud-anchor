#!/usr/bin/env bash
# tests/config-file-mounts/run-test.sh — bind-mounted config installs.
#
# The caddy and gatus containers bind-mount their config as FILES
# (/etc/caddy/Caddyfile, /config/config.yaml). A file bind mount pins the
# inode: an `mv` install swaps the inode and the container keeps reading the
# OLD bytes forever — the live A2 cutover (2026-10-07) rendered the nested
# dashboard, "installed" it, and `caddy reload` reported "config is
# unchanged" while the running container served the flat config. This
# harness pins:
#   - behavioral: an open reader sees new bytes only on an in-place write;
#   - install shape: 010 writes both configs in place (no mv onto the path);
#   - stale-mount guard: 010 compares the container's /proc/<pid>/root view
#     to the rendered path and recreates on divergence (caddy + gatus);
#   - CI wiring: this harness is listed + path-gated.
# Cred-free, offline (no docker, no caddy, no network).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
PROVISION_SH="scripts/010-provision.sh"
CI=".github/workflows/ci.yml"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0
ok()  { pass=$((pass + 1)); printf 'ok   %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL %s\n' "$1"; }
is()  { # $1 label, $2 expected, $3 actual
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi
}
has() { # $1 file, $2 literal, $3 label
  if grep -Fq -- "$2" "$1"; then ok "$3"; else bad "$3 (missing '$2' in $1)"; fi
}
hasnt() { # $1 file, $2 literal, $3 label
  if grep -Fq -- "$2" "$1"; then bad "$3 (found '$2' in $1)"; else ok "$3"; fi
}

# ---- behavioral tooth: file bind-mount semantics --------------------------
# A reader holding the old inode must see the new bytes ONLY when the writer
# rewrites the file in place; `mv` leaves the reader on the old inode (this
# is the mechanism the fix exists for).
printf 'old\n' >"${WORK}/f"
exec 9<"${WORK}/f"
printf 'new\n' >"${WORK}/t"
mv "${WORK}/t" "${WORK}/f"
IFS= read -r -u9 seen_mv || seen_mv=""
exec 9<&-
is "mv install leaves an open reader on the old inode" "old" "$seen_mv"

printf 'old\n' >"${WORK}/f2"
exec 9<"${WORK}/f2"
printf 'new\n' >"${WORK}/t2"
cat "${WORK}/t2" >"${WORK}/f2"
IFS= read -r -u9 seen_cat || seen_cat=""
exec 9<&-
is "in-place install reaches an open reader" "new" "$seen_cat"

# ---- install shape: both configs are written in place ---------------------
has "${PROVISION_SH}" 'cat "$TMP_CADDY" >"${CADDY_CONFIG}"' "Caddyfile installs in place"
has "${PROVISION_SH}" 'cat "$TMP_CFG" >"${GATUS_CONFIG}"' "Gatus config installs in place"
hasnt "${PROVISION_SH}" 'mv "$TMP_CADDY" "${CADDY_CONFIG}"' "no mv install for the Caddyfile"
hasnt "${PROVISION_SH}" 'mv "$TMP_CFG" "${GATUS_CONFIG}"' "no mv install for the Gatus config"

# ---- stale-mount guard: container view vs rendered path -------------------
has "${PROVISION_SH}" 'cmp -s "/proc/${caddy_pid}/root/etc/caddy/Caddyfile" "${CADDY_CONFIG}"' "Caddy guard compares the container view"
has "${PROVISION_SH}" 'cmp -s "/proc/${gatus_pid}/root/config/config.yaml" "${GATUS_CONFIG}"' "Gatus guard compares the container view"
has "${PROVISION_SH}" '&& [ "${CADDY_MOUNT_STALE}" = "0" ]' "Caddy recreate condition includes the stale flag"
has "${PROVISION_SH}" '&& [ "${GATUS_MOUNT_STALE}" = "0" ]' "Gatus recreate condition includes the stale flag"

# ---- CI wiring -------------------------------------------------------------
has "$CI" 'tests/config-file-mounts/run-test.sh' "CI runs this harness"
has "$CI" 'config-file-mounts' "CI path gate covers this harness"

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
