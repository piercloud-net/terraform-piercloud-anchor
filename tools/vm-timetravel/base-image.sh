#!/usr/bin/env bash
# tools/vm-timetravel/base-image.sh - the pinned, SHA512-verified Debian base # ci-allowlist: the file name in this header, not a live image reference.
# qcow2 for the manual VM proofs (run.sh and img-drill.sh). Both copy this file
# into their work dir and source it INSIDE the debian:trixie-slim container. It
# runs nothing at source time and sets no shell options.
#
# The pin is the trust anchor. VMTT_BUILD and the SHA512 per arch are copied from
# that dated directory's SHA512SUMS and are never fetched or trusted at run time
# (Debian publishes no detached signature for the cloud qcow2 files). Every use
# of a cached file re-verifies it; a mismatch refuses and the file is NOT
# deleted. An unknown arch refuses.
#
# To bump the pin: list the trixie/ directory on cloud.debian.org, take the
# newest dated build, copy its SHA512SUMS lines for
# debian-13-genericcloud-<arch>-<build>.qcow2 into vmtt_pin_sha512 and set
# VMTT_BUILD. The next cache miss then fetches the new build.

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
  if ! curl -fsSL -o "$tmp" "${VMTT_BASE_DIR}/${name}"; then
    rm -f "$tmp"
    echo "base qcow2 download failed: ${name}" >&2
    return 1
  fi
  if ! vmtt_verify "$sum" "$tmp"; then
    rm -f "$tmp"
    echo "base qcow2 checksum mismatch on download, nothing cached: ${name}" >&2
    return 1
  fi
  chmod 0644 "$tmp"
  mv -f "$tmp" "$path"
  printf '%s\n' "$path"
}
