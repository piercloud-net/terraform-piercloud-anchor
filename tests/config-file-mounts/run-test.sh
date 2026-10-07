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
#     to the rendered path and recreates on divergence (caddy + gatus, plus
#     the bind-mounted cert/key/AOP PEMs — the live run-E class where the
#     chain landed on the host while the container served the old inode);
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

# ---- stale-mount guard: the deployed PEM files (same class) ----------------
# The cert/key/AOP PEMs are bind-mounted FILES too. A container created before
# a PEM's inode last changed keeps reading the OLD bytes; `caddy reload`
# reports success and re-reads the stale mount. Live 2026-10-07: the 4-block
# chain landed on the host while the container still served the leaf-only
# inode (CloudFront 502 with a green run). The guard must compare the PEMs
# through the container's root too, and recreate on divergence.
has "${PROVISION_SH}" 'cmp -s "/proc/${caddy_pid}/root${CADDY_ORIGIN_CRT}" "${CADDY_ORIGIN_CRT}"' "Caddy guard compares the mounted cert view"
has "${PROVISION_SH}" 'cmp -s "/proc/${caddy_pid}/root${CADDY_ORIGIN_KEY}" "${CADDY_ORIGIN_KEY}"' "Caddy guard compares the mounted key view"
has "${PROVISION_SH}" 'cmp -s "/proc/${caddy_pid}/root/etc/caddy/aop-ca.pem" "${CADDY_AOP_CA}"' "Caddy guard compares the mounted AOP CA view"
has "${PROVISION_SH}" '[ "${CADDY_MOUNT_STALE}" = "0" ] && [ -n "${caddy_pid}" ] && [ "${ORIGIN_TLS}" = "1" ]' "PEM guard is scoped to a selected origin pair"
has "${PROVISION_SH}" '[ "${CADDY_MOUNT_STALE}" = "0" ] && [ -n "${caddy_pid}" ] && [ -n "${AOP_TLS}" ]' "AOP guard is scoped to a deployed AOP bundle"
has "${PROVISION_SH}" 'CADDY_MOUNT_STALE_REASON="origin-ca cert"' "stale-reason names the diverging PEM"
has "${PROVISION_SH}" 'stale bind-mount: ${CADDY_MOUNT_STALE_REASON:-' "recreate log carries the stale reason"

# ---- unconditional reload/restart (red-team re-verify F4) ------------------
# The guard proves the MOUNT, not what the running process loaded; the reload
# and restart must stay unconditional (a CADDY_RESTART/GATUS_RESTART gate
# would re-open the aborted-reload class: a next dispatch sees identical
# bytes and reports green while the old config serves).
has "${PROVISION_SH}" 'docker exec caddy caddy reload --config /etc/caddy/Caddyfile' "Caddy reload stays unconditional"
has "${PROVISION_SH}" 'caddy reload failed' "a failed Caddy reload dies (no silent green)"
has "${PROVISION_SH}" 'docker restart gatus' "Gatus restart stays unconditional"
hasnt "${PROVISION_SH}" 'CADDY_RESTART' "no CADDY_RESTART gate (reload is unconditional)"
hasnt "${PROVISION_SH}" 'GATUS_RESTART' "no GATUS_RESTART gate (restart is unconditional)"

# ---- CI wiring -------------------------------------------------------------
has "$CI" 'tests/config-file-mounts/run-test.sh' "CI runs this harness"
has "$CI" 'config-file-mounts' "CI path gate covers this harness"

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
