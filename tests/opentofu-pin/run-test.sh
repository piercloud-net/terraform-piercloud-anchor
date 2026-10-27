#!/usr/bin/env bash
# run-test.sh — cred-free, offline harness for the OpenTofu pin (issue #248).
# .opentofu-version must be a bare N.N.N equal to both provision.yml tofu_version
# pins (leading v optional on the workflow side); ci.yml must read
# .opentofu-version via tofu_version_file and carry no literal tofu_version.
# Mutants run on temp copies and must each be caught.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0
FAIL=0

# check_pins ROOT: 0 when the pins agree; prints the first disagreement otherwise.
check_pins() {
  local root="$1" ver value line count=0 ci="$1/.github/workflows/ci.yml"
  ver="$(cat "$root/.opentofu-version")"
  if [[ ! "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "  .opentofu-version is not a bare N.N.N: '$ver'"
    return 1
  fi
  while IFS= read -r line; do
    count=$((count + 1))
    value="${line#*tofu_version: }"
    value="${value//\"/}"
    value="${value#v}"
    if [[ "$value" != "$ver" ]]; then
      echo "  provision.yml pin '$value' does not match .opentofu-version '$ver'"
      return 1
    fi
  done < <(grep -E '^[[:space:]]*tofu_version: "v?[0-9]' "$root/.github/workflows/provision.yml" || true)
  if [[ "$count" -ne 2 ]]; then
    echo "  expected 2 provision.yml tofu_version pins, found $count"
    return 1
  fi
  if grep -q 'tofu_version:' "$ci"; then
    echo "  ci.yml carries a literal tofu_version: pin"
    return 1
  fi
  if [[ "$(grep -c 'tofu_version_file: .opentofu-version' "$ci" || true)" -lt 2 ]]; then
    echo "  ci.yml does not read .opentofu-version via tofu_version_file in both setup-opentofu steps"
    return 1
  fi
  return 0
}

expect_pass() { # $1 label, $2 root
  local out
  if out="$(check_pins "$2" 2>&1)"; then
    PASS=$((PASS + 1)); echo "ok   $1"
  else
    FAIL=$((FAIL + 1)); echo "FAIL $1"; echo "$out"
  fi
}

expect_caught() { # $1 label, $2 root
  local out
  if out="$(check_pins "$2" 2>&1)"; then
    FAIL=$((FAIL + 1)); echo "FAIL $1: mutant not caught"
  else
    PASS=$((PASS + 1)); echo "ok   $1 (caught:$out)"
  fi
}

copy_tree() { # $1 name -> prints the copy dir
  local d="$TMP/$1"
  mkdir -p "$d/.github/workflows"
  cp "$REPO_ROOT/.opentofu-version" "$d/"
  cp "$REPO_ROOT/.github/workflows/provision.yml" "$REPO_ROOT/.github/workflows/ci.yml" "$d/.github/workflows/"
  printf '%s\n' "$d"
}

expect_pass "pins agree in the repo tree" "$REPO_ROOT"

d="$(copy_tree m1)"
printf '1.13.1\n' > "$d/.opentofu-version"
expect_caught "mutant: .opentofu-version drifts from provision.yml" "$d"

d="$(copy_tree m2)"
content="$(cat "$d/.github/workflows/provision.yml")"
content="${content/v1.13.2/v1.13.1}"
printf '%s\n' "$content" > "$d/.github/workflows/provision.yml"
expect_caught "mutant: one provision.yml tofu_version drifts" "$d"

d="$(copy_tree m3)"
content="$(cat "$d/.github/workflows/ci.yml")"
content="${content/tofu_version_file: .opentofu-version/tofu_version: \"v1.13.2\"}"
printf '%s\n' "$content" > "$d/.github/workflows/ci.yml"
expect_caught "mutant: ci.yml reintroduces a literal tofu_version" "$d"

echo "opentofu-pin: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
