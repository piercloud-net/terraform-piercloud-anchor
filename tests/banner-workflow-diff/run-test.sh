#!/usr/bin/env bash
# tests/banner-workflow-diff/run-test.sh — regression harness for #130: the
# C-E approval-card workflow diff must survive a dispatched branch that is
# behind the base branch, and an undeterminable diff must fail closed.
#
# Runs the REAL shipped script (.github/scripts/banner-workflow-diff.sh)
# against synthetic repositories (tmp clones; no network, no credentials):
#   (a) behind-main branch with one workflow change on the branch -> count 1,
#       rc 0 (the #130 regression: the pre-fix shallow fetch + three-dot diff
#       died with exit 128 on exactly this shape);
#   (b) the pre-fix form reproduces the exit-128 failure (the tooth that
#       motivates the fix — a re-introduced `--depth=1` fetch reddens (a));
#   (c) an unrelated-history branch (no merge base) -> rc non-zero, an
#       ::error:: on stderr, and NO count on stdout (a silent "0" would be a
#       false UNCHANGED verdict);
#   (d) a branch at the base tip -> count 0;
#   (e) wiring: provision.yml calls the script and no longer carries the
#       inline shallow fetch; ci.yml gates and runs this harness.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$REPO_ROOT/.github/scripts/banner-workflow-diff.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0
ok()  { pass=$((pass + 1)); printf 'ok   %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL %s\n' "$1"; }
is() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi; }

git_c() { git -c user.email=harness@example.invalid -c user.name=harness -c commit.gpgsign=false "$@"; }

# --- synthetic origin: main (base + a later move) + a behind-main branch ----
ORIGIN="$WORK/origin.git"
git_c init -q --bare "$ORIGIN"
git_c -C "$ORIGIN" symbolic-ref HEAD refs/heads/main
SEED="$WORK/seed"
git_c init -q "$SEED"
cd "$SEED"
git_c remote add origin "$ORIGIN"
mkdir -p .github/workflows
printf 'name: base\n' > .github/workflows/base.yml
git_c add -A
git_c commit -qm "base"
git_c branch -M main
git_c push -q origin main

git_c checkout -qb behind
printf 'name: branch\n' > .github/workflows/branch.yml
git_c add -A
git_c commit -qm "branch workflow change"
git_c push -q origin behind

git_c checkout -q main
printf 'name: moved\n' > .github/workflows/moved.yml
git_c add -A
git_c commit -qm "main moves ahead of the branch"
git_c push -q origin main

# --- (a) the #130 shape: a behind-main branch --------------------------------
CLONE="$WORK/clone"
git clone -q "$ORIGIN" "$CLONE"
cd "$CLONE"
git_c checkout -q behind
rc=0
count="$(bash "$SCRIPT" main)" || rc=$?
is "behind-main: the count is the branch's own change" "1" "$count"
is "behind-main: rc" "0" "$rc"

# --- (b) the pre-fix form reproduces the exit-128 failure -------------------
OLD="$WORK/old"
git clone -q "$ORIGIN" "$OLD"
cd "$OLD"
git_c checkout -q behind
git fetch origin main --depth=1 >/dev/null 2>&1 || true
old_rc=0
old_out="$(git diff --name-only "origin/main...HEAD" -- .github/workflows 2>/dev/null)" || old_rc=$?
is "pre-fix form: exit 128 reproduced" "128" "$old_rc"
is "pre-fix form: no count" "" "$old_out"
# An externally grafted ref still fails LOUD (never a silent 0): the caller's
# full history is the script's contract.
grafted_rc=0
grafted_out="$(bash "$SCRIPT" main 2>/dev/null)" || grafted_rc=$?
if [ "$grafted_rc" -ne 0 ]; then ok "grafted ref: the script fails loud"; else bad "grafted ref: the script returned rc=$grafted_rc"; fi
is "grafted ref: no silent 0" "" "$grafted_out"

# --- (c) unrelated history: no merge base -> loud refusal, no count ---------
cd "$CLONE"
git_c checkout -q --orphan orphan
git_c rm -rq --cached . 2>/dev/null || true
printf 'name: orphan\n' > .github/workflows/orphan.yml
git_c add -A
git_c commit -qm "unrelated history"
orphan_rc=0
orphan_out="$(bash "$SCRIPT" main 2>"$WORK/orphan.err")" || orphan_rc=$?
if [ "$orphan_rc" -ne 0 ]; then ok "unrelated history: rc non-zero"; else bad "unrelated history: rc=$orphan_rc"; fi
is "unrelated history: no count on stdout" "" "$orphan_out"
if grep -q '::error::' "$WORK/orphan.err"; then ok "unrelated history: ::error:: annotation"; else bad "unrelated history: no ::error:: annotation"; fi

# --- (d) at the base tip: count 0 -------------------------------------------
git_c checkout -q main
rc=0
count="$(bash "$SCRIPT" main)" || rc=$?
is "at tip: rc" "0" "$rc"
is "at tip: count 0" "0" "$count"

# --- (e) wiring --------------------------------------------------------------
PROV="$REPO_ROOT/.github/workflows/provision.yml"
CI="$REPO_ROOT/.github/workflows/ci.yml"
if grep -q 'banner-workflow-diff.sh' "$PROV"; then ok "provision.yml calls the diff script"; else bad "provision.yml does not call the diff script"; fi
if grep -q 'depth=1' "$PROV"; then bad "provision.yml still carries a shallow fetch"; else ok "provision.yml carries no shallow fetch"; fi
if grep -q 'banner-workflow-diff' "$CI"; then ok "ci.yml gates and runs this harness"; else bad "ci.yml does not gate/run this harness"; fi

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
