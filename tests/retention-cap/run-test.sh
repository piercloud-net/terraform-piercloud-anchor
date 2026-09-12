#!/usr/bin/env bash
# run-test.sh — cred-free, offline harness for the retention-cap assertion
# `.github/scripts/040-retention-cap.sh` (issue #119). No network, no cloud:
# writes YAML fixtures under a temp dir and asserts exit codes + messages.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
SCRIPT="$REPO_ROOT/.github/scripts/040-retention-cap.sh"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0
FAIL=0
LAST_OUT=""

check() { # $1 label, $2 expected exit, $3 workflow dir
  set +e
  LAST_OUT="$(bash "$SCRIPT" "$3" 2>&1)"
  local rc=$?
  set -e
  if [ "$rc" -ne "$2" ]; then
    echo "FAIL $1: expected exit $2, got $rc"
    printf '%s\n' "$LAST_OUT" | head -5
    FAIL=$((FAIL + 1))
    return
  fi
  PASS=$((PASS + 1))
  echo "ok   $1 (exit $rc)"
}

expect_out() { # $1 label, $2 substring
  case "$LAST_OUT" in
    *"$2"*) PASS=$((PASS + 1)); echo "ok   $1" ;;
    *) echo "FAIL $1: missing substring '$2'"; printf '%s\n' "$LAST_OUT" | head -5; FAIL=$((FAIL + 1)) ;;
  esac
}

# 1. Literal at the cap passes.
mkdir -p "$TMP/at-cap"
cat > "$TMP/at-cap/provision.yml" <<'YML'
      - name: Upload artifact
        with:
          retention-days: 90
YML
check "at-cap passes" 0 "$TMP/at-cap"
expect_out "at-cap summary counts the key" "retention-days literals checked: 1"

# 2. Literal above the public cap fails loudly with file:line.
mkdir -p "$TMP/over-cap"
printf '          retention-days: 400\n' > "$TMP/over-cap/provision.yml"
check "over-cap fails" 1 "$TMP/over-cap"
expect_out "over-cap error names the band" "outside the public-repo band"
expect_out "over-cap error carries file:line" "provision.yml:1"

# 3. Expression value is not provably in band -> fail closed.
mkdir -p "$TMP/expr"
printf '          retention-days: ${{ inputs.days }}\n' > "$TMP/expr/provision.yml"
check "expression fails closed" 1 "$TMP/expr"

# 4. Quoted value parses as non-integer -> fail closed.
mkdir -p "$TMP/quoted"
printf '          retention-days: "90"\n' > "$TMP/quoted/provision.yml"
check "quoted fails closed" 1 "$TMP/quoted"

# 5. Zero is outside the platform band (1..90) -> fail.
mkdir -p "$TMP/zero"
printf '          retention-days: 0\n' > "$TMP/zero/provision.yml"
check "zero fails" 1 "$TMP/zero"

# 6. A trailing comment is stripped; 95 is a violation, 89 passes.
mkdir -p "$TMP/comment"
printf '          retention-days: 95 # temporary bump\n' > "$TMP/comment/provision.yml"
check "commented over-cap fails" 1 "$TMP/comment"
printf '          retention-days: 89 # fine\n' > "$TMP/comment/provision.yml"
check "commented in-band passes" 0 "$TMP/comment"

# 7. A silent no-op must never be green: an empty scan fails.
mkdir -p "$TMP/empty"
check "empty dir fails closed" 1 "$TMP/empty"
expect_out "empty dir says the scan proved nothing" "proved nothing"

# 8. The real tree passes and proves both uploads.
check "real tree passes" 0 "$REPO_ROOT/.github/workflows"
expect_out "real tree counts both literals" "retention-days literals checked: 2"

echo "harness summary: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
