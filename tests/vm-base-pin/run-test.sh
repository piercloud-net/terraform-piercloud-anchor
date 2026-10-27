#!/usr/bin/env bash
# run-test.sh — cred-free, offline harness for the pinned Debian base qcow2
# helper (tools/vm-timetravel/base-image.sh, issue #268). # ci-allowlist: the helper file name in this header, not a live image reference.
# curl is stubbed on
# PATH and the pin is overridden per case with a known digest; the arch and
# shape cases run against the real pin table. Every case must hold: a matching
# cache hit passes with no download; a corrupted cache hit refuses non-zero
# with the mismatch line and keeps the file; a bad or failed download caches
# nothing; a good download is cached under the build-qualified name; an
# unknown arch refuses before any download; the real pins are well formed.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
HELPER="$REPO_ROOT/tools/vm-timetravel/base-image.sh" # ci-allowlist: helper path in this harness, not a live image reference.

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); echo "  ok   $1"; }
bad() { FAIL=$((FAIL + 1)); echo "  FAIL $1"; }
is() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want '$2', got '$3')"; fi; }

# shellcheck source=/dev/null
BUILD="$(. "$HELPER"; echo "$VMTT_BUILD")"
NAME="debian-13-genericcloud-amd64-${BUILD}.qcow2"

# stub curl: logs the URL, fails on demand, else copies FAKE_BODY to the -o target
mkdir -p "$TMP/bin"
cat >"$TMP/bin/curl" <<'STUB'
#!/usr/bin/env bash
out=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    http*) echo "$1" >>"$CURL_LOG"; shift ;;
    *) shift ;;
  esac
done
[ -z "${FAKE_FAIL:-}" ] || exit 22
cp "$FAKE_BODY" "$out"
STUB
chmod +x "$TMP/bin/curl"

BODY="$TMP/body.bin"; printf 'pinned base bytes\n' >"$BODY"
BAD="$TMP/bad.bin"; printf 'tampered base bytes\n' >"$BAD"
GOOD="$(sha512sum "$BODY" | cut -d' ' -f1)"

# helper_run ARCH CACHE BODY SHA: vmtt_base_image with the amd64 pin set to SHA
helper_run() {
  local expected="$4"
  : >"$TMP/curl.log"
  (
    export PATH="$TMP/bin:$PATH" CURL_LOG="$TMP/curl.log" FAKE_BODY="$3"
    # shellcheck source=/dev/null
    . "$HELPER"
    vmtt_pin_sha512() { if [ "$1" = amd64 ]; then echo "$expected"; else echo "no pinned qcow2 for arch '$1': refusing" >&2; return 1; fi; }
    vmtt_base_image "$1" "$2"
  ) >"$TMP/out" 2>"$TMP/err"
}

echo "vm-base-pin:"

# (a) matching cache hit: verified, printed, no download
C="$TMP/cache-a"; mkdir -p "$C"; cp "$BODY" "$C/$NAME"
rc=0; helper_run amd64 "$C" "$BODY" "$GOOD" || rc=$?
is "matching cache hit exits 0" "0" "$rc"
is "matching cache hit prints the cached path" "$C/$NAME" "$(cat "$TMP/out")"
is "matching cache hit does not download" "" "$(cat "$TMP/curl.log")"

# (b) corrupted cache hit: refuses before use, names the path, keeps the file
C="$TMP/cache-b"; mkdir -p "$C"; cp "$BAD" "$C/$NAME"
rc=0; helper_run amd64 "$C" "$BODY" "$GOOD" || rc=$?
is "corrupted cache hit exits non-zero" "1" "$rc"
if grep -qF "base image checksum mismatch: $C/$NAME" "$TMP/err"; then ok "corrupted cache hit prints the mismatch line"; else bad "corrupted cache hit prints the mismatch line"; fi # ci-allowlist: the fixed refusal line is asserted, not a live reference.
is "corrupted cache hit prints no path on stdout" "" "$(cat "$TMP/out")"
is "corrupted cache hit does not download" "" "$(cat "$TMP/curl.log")"
if [ -f "$C/$NAME" ]; then ok "corrupted cache hit keeps the file (no auto-delete)"; else bad "corrupted cache hit keeps the file (no auto-delete)"; fi

# (c) bad download: refused, nothing left in the cache
C="$TMP/cache-c"; mkdir -p "$C"
rc=0; helper_run amd64 "$C" "$BAD" "$GOOD" || rc=$?
is "bad download exits non-zero" "1" "$rc"
is "bad download leaves nothing in the cache" "" "$(ls -A "$C")"

# (d) failed download: refused, nothing left in the cache
C="$TMP/cache-d"; mkdir -p "$C"
export FAKE_FAIL=1; rc=0; helper_run amd64 "$C" "$BODY" "$GOOD" || rc=$?; unset FAKE_FAIL
is "failed download exits non-zero" "1" "$rc"
is "failed download leaves nothing in the cache" "" "$(ls -A "$C")"

# (e) good download: verified, renamed into the cache under the build name
C="$TMP/cache-e"; mkdir -p "$C"
rc=0; helper_run amd64 "$C" "$BODY" "$GOOD" || rc=$?
is "good download exits 0" "0" "$rc"
is "good download prints the cached path" "$C/$NAME" "$(cat "$TMP/out")"
is "good download leaves only the named file" "$NAME" "$(ls -A "$C")"
if grep -qF "/${BUILD}/${NAME}" "$TMP/curl.log"; then ok "good download fetches the dated build directory"; else bad "good download fetches the dated build directory"; fi

# (f) unknown arch: refused before any download, nothing cached
C="$TMP/cache-f"; mkdir -p "$C"
rc=0
(
  export PATH="$TMP/bin:$PATH" CURL_LOG="$TMP/curl.log" FAKE_BODY="$BODY"
  : >"$TMP/curl.log"
  # shellcheck source=/dev/null
  . "$HELPER"
  vmtt_base_image riscv64 "$C"
) >"$TMP/out" 2>"$TMP/err" || rc=$?
is "unknown arch exits non-zero" "1" "$rc"
if grep -qF "no pinned qcow2 for arch 'riscv64'" "$TMP/err"; then ok "unknown arch prints the refusal"; else bad "unknown arch prints the refusal"; fi
is "unknown arch does not download" "" "$(cat "$TMP/curl.log")"
is "unknown arch leaves nothing in the cache" "" "$(ls -A "$C")"

# (g) the real pin table is well formed and the build is a dated directory
for arch in amd64 arm64; do
  # shellcheck source=/dev/null
  sum="$( . "$HELPER"; vmtt_pin_sha512 "$arch" )"
  if [[ "$sum" =~ ^[0-9a-f]{128}$ ]]; then ok "pin $arch is a 128-hex SHA512"; else bad "pin $arch is a 128-hex SHA512"; fi
done
if [[ "$BUILD" =~ ^[0-9]{8}-[0-9]{4}$ ]]; then ok "build is a dated directory name"; else bad "build is a dated directory name"; fi

# qemu-img stub: prints QEMU_INFO_JSON, or fails on QEMU_INFO_FAIL
cat >"$TMP/bin/qemu-img" <<'STUB'
#!/usr/bin/env bash
[ -z "${QEMU_INFO_FAIL:-}" ] || exit 1
printf '%s\n' "$QEMU_INFO_JSON"
STUB
chmod +x "$TMP/bin/qemu-img"
QCOW2='{"virtual-size": 100, "filename": "x", "format": "qcow2"}'

# stage_run CACHE DEST JSON: vmtt_stage_base for amd64 with the stub qemu-img
stage_run() {
  (
    export PATH="$TMP/bin:$PATH" CURL_LOG="$TMP/curl.log" FAKE_BODY="$BODY" QEMU_INFO_JSON="$3"
    # shellcheck source=/dev/null
    . "$HELPER"
    vmtt_pin_sha512() { if [ "$1" = amd64 ]; then echo "$GOOD"; else echo "no pinned qcow2 for arch '$1': refusing" >&2; return 1; fi; }
    vmtt_stage_base amd64 "$1" "$2"
  ) >"$TMP/out" 2>"$TMP/err"
}

# (h) staging: a verified private copy is made and printed
C="$TMP/cache-h"; mkdir -p "$C"; cp "$BODY" "$C/$NAME"
D="$TMP/staged-h.qcow2"
rc=0; stage_run "$C" "$D" "$QCOW2" || rc=$?
is "staging exits 0" "0" "$rc"
is "staging prints the private copy" "$D" "$(cat "$TMP/out")"
if cmp -s "$BODY" "$D"; then ok "staged copy carries the pinned bytes"; else bad "staged copy carries the pinned bytes"; fi

# (i) staging verifies the COPY: a swap between copy and check is caught
# (the copy is made from a cache file that is corrupted after the cache check)
C="$TMP/cache-i"; mkdir -p "$C"; cp "$BODY" "$C/$NAME"
D="$TMP/staged-i.qcow2"
(
  # a cp stub that writes the tampered body: the cache check passed, the copy is wrong
  cat >"$TMP/bin/cp" <<'CP'
#!/usr/bin/env bash
for last; do :; done
/bin/cp "$FAKE_BODY" "$last"
CP
  chmod +x "$TMP/bin/cp"
  export PATH="$TMP/bin:$PATH" CURL_LOG="$TMP/curl.log" FAKE_BODY="$BAD" QEMU_INFO_JSON="$QCOW2"
  # shellcheck source=/dev/null
  . "$HELPER"
  vmtt_pin_sha512() { if [ "$1" = amd64 ]; then echo "$GOOD"; else return 1; fi; }
  vmtt_stage_base amd64 "$C" "$D"
) >"$TMP/out" 2>"$TMP/err" || rc=$?
if [ "$rc" != "0" ]; then ok "a copy that does not match the pin is refused"; else bad "a copy that does not match the pin is refused"; fi
if grep -qF "checksum mismatch after staging: $D" "$TMP/err"; then ok "the staged-copy mismatch names the file"; else bad "the staged-copy mismatch names the file"; fi
if [ ! -e "$D" ]; then ok "a refused staged copy is removed"; else bad "a refused staged copy is removed"; fi
rm -f "$TMP/bin/cp"

# (j) staging refuses a copy qemu-img cannot read
C="$TMP/cache-j"; mkdir -p "$C"; cp "$BODY" "$C/$NAME"
D="$TMP/staged-j.qcow2"
rc=0
( export PATH="$TMP/bin:$PATH" QEMU_INFO_FAIL=1; stage_run "$C" "$D" "$QCOW2" ) || rc=$?
if [ "$rc" != "0" ] && [ ! -e "$D" ]; then ok "an unreadable staged copy is refused and removed"; else bad "an unreadable staged copy is refused and removed"; fi

# (k) staging refuses a non-qcow2 and a qcow2 with a backing file
for json in '{"format": "raw"}' '{"format": "qcow2", "backing-filename": "base.qcow2"}'; do
  C="$TMP/cache-k"; mkdir -p "$C"; cp "$BODY" "$C/$NAME"
  D="$TMP/staged-k.qcow2"
  rc=0; stage_run "$C" "$D" "$json" || rc=$?
  if [ "$rc" != "0" ] && [ ! -e "$D" ]; then ok "staged copy refused: $json"; else bad "staged copy refused: $json"; fi
done
if grep -qF "carries a backing file" "$TMP/err"; then ok "the backing-file refusal says why"; else bad "the backing-file refusal says why"; fi

# (l) chmod or rename failing after a good download is reported, and the temp is removed
mkdir -p "$TMP/binl" "$TMP/binc"
printf '#!/usr/bin/env bash\nexit 1\n' >"$TMP/binl/mv"; chmod +x "$TMP/binl/mv"
printf '#!/usr/bin/env bash\nexit 1\n' >"$TMP/binc/chmod"; chmod +x "$TMP/binc/chmod"
for case in mv chmod; do
  C="$TMP/cache-l-$case"; mkdir -p "$C"
  rc=0
  (
    export PATH="$TMP/binl:$TMP/binc:$TMP/bin:$PATH" CURL_LOG="$TMP/curl.log" FAKE_BODY="$BODY"
    # shellcheck source=/dev/null
    . "$HELPER"
    vmtt_pin_sha512() { if [ "$1" = amd64 ]; then echo "$GOOD"; else return 1; fi; }
    vmtt_base_image amd64 "$C"
  ) >"$TMP/out" 2>"$TMP/err" || rc=$?
  if [ "$rc" != "0" ]; then ok "a failing $case after the download exits non-zero"; else bad "a failing $case after the download exits non-zero"; fi
  if grep -qE "could not be (stored as|made readable)" "$TMP/err"; then ok "a failing $case says what failed"; else bad "a failing $case says what failed"; fi
  if [ -z "$(ls -A "$C")" ]; then ok "a failing $case leaves no temp file in the cache"; else bad "a failing $case leaves no temp file in the cache"; fi
  rm -rf "$C"
done

# (m) the call sites: both VM proofs stage a verified copy before they boot
for script in run.sh img-drill.sh; do
  f="$REPO_ROOT/tools/vm-timetravel/$script"
  if grep -qF 'cp "$ROOT/tools/vm-timetravel/base-image.sh" "$WORK/base-image.sh"' "$f" && grep -qF 'source /w/base-image.sh' "$f"; then ok "$script ships and sources the pinned helper"; else bad "$script ships and sources the pinned helper"; fi
  if grep -qF 'vmtt_stage_base "$ARCH" /cache /w/base.qcow2' "$f"; then ok "$script stages a private verified copy"; else bad "$script stages a private verified copy"; fi
  if grep -qF -- '-b "$BASE" /w/vm.qcow2' "$f"; then ok "$script boots from the staged copy"; else bad "$script boots from the staged copy"; fi
  if ! grep -qE 'cloud/trixie/latest|\[ -s "\$BASE" \]' "$f"; then ok "$script trusts no unpinned download"; else bad "$script trusts no unpinned download"; fi
done

echo "vm-base-pin: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
