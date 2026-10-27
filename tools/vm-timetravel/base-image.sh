#!/usr/bin/env bash
# tools/vm-timetravel/base-image.sh - the pinned, SHA512-verified Debian base qcow2 for the manual VM proofs (run.sh, img-drill.sh). # ci-allowlist: this header names the file and its subject, not a live reference.
# Both copy this file into their work dir and source it INSIDE the
# debian:trixie-slim container. It runs nothing at source time and sets no
# shell options.
#
# The pin is the trust anchor. VMTT_BUILD and the SHA512 per arch are copied
# from that dated directory's SHA512SUMS and are never fetched or trusted at
# run time. Every use of a cached file re-verifies it; a mismatch refuses and
# the file is NOT deleted. An unknown arch refuses.
#
# TOFU, stated plainly: Debian publishes NO detached signature for these
# files (SHA512SUMS[.sign] is absent from the build directory), so the pin is
# trust-on-first-use over HTTPS against the Debian publisher. What a bump can
# still do is a consistency check: fetch SHA512SUMS TWICE, from the same
# build directory on two hostnames, cloud.debian.org and cdimage.debian.org
# (same path below the host), confirm the two files are byte-identical
# (sha256sum of the file matches), and only then copy the per-arch lines.
# Record both hostnames, the sha256 of SHA512SUMS and the exact lines in the
# commit message. LIMIT: both names are served by the same Debian mirror
# network today (both names resolve to the same addresses), so the two fetches
# are NOT independent: the check catches a truncated or transient bad
# response, not a substituted mirror or CDN, and not a compromise of Debian
# itself. A fetch from an independent vantage (another network, or the
# reviewer's own) is what would catch a substituted mirror.
#
# To bump the pin: list the release directory on cloud.debian.org, take the
# newest dated build, run the two-source check above, then set VMTT_BUILD and
# the SHA512 values in vmtt_pin_sha512. The next cache miss fetches the new
# build (the cache name carries the build id, so an old file is never reused).

VMTT_BUILD=20261026-2643
VMTT_BASE_DIR="https://cloud.debian.org/images/cloud/trixie/${VMTT_BUILD}" # ci-allowlist: pinned Debian cloud build directory for the manual VM proof, not an SCP reference.

vmtt_pin_sha512() { # $1 arch -> the pinned SHA512 of its qcow2; an unknown arch refuses
  case "$1" in
    amd64) echo "3ace18e33bdd036edb49d1f79342bd01d2ab980e35194edb0b410435cd543538d286a0bd13bbb0835f7862306e3d385ce2f6a70d8ecf0bd961111166adbc1b8e" ;;
    arm64) echo "71aa5d5dbcb3d9ecfe96bc3f6dd41b6805a0a41c852204a32747d230b64b95912297fb453b11a6031fd54d84a0a0a430e137d07e6986dc9ebc9d41483be003c4" ;;
    *) echo "no pinned qcow2 for arch '$1': refusing" >&2; return 1 ;;
  esac
}

vmtt_verify() { # $1 expected SHA512, $2 file -> 0 only on an exact match
  printf '%s  %s\n' "$1" "$2" | sha512sum -c --status
}

vmtt_base_image() { # $1 arch, $2 cache dir -> prints the verified cached path, or refuses
  local arch="$1" cache="$2" sum name path tmp
  sum="$(vmtt_pin_sha512 "$arch")" || return 1
  name="debian-13-genericcloud-${arch}-${VMTT_BUILD}.qcow2"
  path="${cache}/${name}"
  if [ -e "$path" ]; then
    if ! vmtt_verify "$sum" "$path"; then
      echo "base image checksum mismatch: $path" >&2 # ci-allowlist: the refusal line is fixed by the #268 design, a message not a live reference.
      echo "refusing to boot; the file is kept: remove it by hand, then re-run to fetch the pinned build" >&2
      return 1
    fi
    printf '%s\n' "$path"
    return 0
  fi
  tmp="$(mktemp "${cache}/.${name}.XXXXXX")" || return 1
  # The download runs in its own subshell with its own EXIT trap, so the temp
  # file is removed on a failure, SIGINT, SIGTERM or SIGHUP, whatever the
  # caller does with traps (callers invoke this helper inside $(...), where a
  # caller's EXIT trap never sees a variable set here). SIGKILL runs no trap
  # and leaves the .XXXXXX temp behind; it is never used as a cached image
  # (the cache name differs) and can be removed by hand. After the mv the temp
  # name no longer exists, so the EXIT trap is a no-op on success.
  (
    trap 'rm -f -- "$tmp"' EXIT
    if ! curl --proto '=https' --proto-redir '=https' -fsSL -o "$tmp" "${VMTT_BASE_DIR}/${name}"; then
      echo "base qcow2 download failed: ${name}" >&2
      exit 1
    fi
    if ! vmtt_verify "$sum" "$tmp"; then
      echo "base qcow2 checksum mismatch on download, nothing cached: ${name}" >&2
      exit 1
    fi
    if ! chmod 0644 "$tmp"; then
      echo "base qcow2 could not be made readable: ${tmp}" >&2
      exit 1
    fi
    if ! mv -f -- "$tmp" "$path"; then
      echo "base qcow2 could not be stored as ${path}" >&2
      exit 1
    fi
  ) || return 1
  printf '%s\n' "$path"
}

vmtt_stage_base() { # $1 arch, $2 cache dir, $3 destination -> prints $3, a verified private copy the caller boots from
  # Verify the CACHE file, copy it to a path only this run writes, verify the
  # COPY and only then hand it to qemu. A swap or an in-place edit of the
  # shared cache after the check cannot reach the guest, and qemu's lazy read
  # reads a file nobody else owns.
  local arch="$1" cache="$2" dest="$3" src sum info
  sum="$(vmtt_pin_sha512 "$arch")" || return 1
  src="$(vmtt_base_image "$arch" "$cache")" || return 1
  if ! cp -- "$src" "$dest"; then
    echo "base copy failed: ${src} -> ${dest}" >&2
    return 1
  fi
  if ! vmtt_verify "$sum" "$dest"; then
    rm -f -- "$dest"
    echo "base qcow2 checksum mismatch after staging: ${dest}" >&2
    return 1
  fi
  if ! info="$(qemu-img info --output=json "$dest" 2>/dev/null)"; then
    rm -f -- "$dest"
    echo "staged base is not readable by qemu-img: ${dest}" >&2
    return 1
  fi
  case "$info" in
    *'"format": "qcow2"'*|*'"format":"qcow2"'*) ;;
    *) rm -f -- "$dest"; echo "staged base is not a qcow2: ${dest}" >&2; return 1 ;;
  esac
  case "$info" in
    *'"backing-filename"'*)
      rm -f -- "$dest"
      echo "staged base carries a backing file: ${dest}" >&2
      return 1 ;;
  esac
  printf '%s\n' "$dest"
}
