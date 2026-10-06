#!/usr/bin/env bash
# tests/banner-workflow-diff/run-test.sh — regression harness for #130: the
# C-E approval-card workflow diff must survive a dispatched branch that is
# behind the base branch, and an undeterminable diff must fail closed.
#
# Runs the REAL shipped script (.github/scripts/banner-workflow-diff.sh)
# against synthetic repositories (tmp clones; no network, no credentials):
#   (a) behind-main branch with one workflow change + one CI-script change on
#       the branch -> count 2, rc 0 (the #130 regression: the pre-fix shallow
#       fetch + three-dot diff died with exit 128 on exactly this shape);
#   (f) tag shadowing: a tag literally named origin/<base> must not win over
#       refs/remotes/origin/<base> — the pre-fix unqualified form collapses to
#       a false UNCHANGED (red-team r1 HIGH);
#   (b) the pre-fix form reproduces the exit-128 failure (the tooth that
#       motivates the fix — a re-introduced shallow fetch reddens (a)); an
#       externally grafted ref fails loud, never a silent 0;
#   (c) an unrelated-history branch (no merge base) -> rc non-zero, an
#       ::error:: on stderr, and NO count on stdout (a silent "0" would be a
#       false UNCHANGED verdict);
#   (d) a branch at the base tip -> count 0;
#   (g) a scripts/lib (sourced provisioning) change is counted (red-team r2);
#   (h) a non-root cwd must not narrow the diff (:(top) pathspecs);
#   (i) a missing remote-tracking ref refuses instead of dwim-resolving a tag
#       literally named refs/remotes/origin/<base> (red-team r2);
#   (j) a symlink in the counted set refuses (a target-only change would not
#       appear in the diff) (red-team r2);
#   (e) wiring: comment-proof pins for the exact call line, the sole COUNT
#       assignment, the exact `-eq 0` comparison, a whitespace-tolerant
#       no-fetch, and fetch-depth: 0; ci.yml gates AND runs this harness.
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

git_c() { git -c user.email=harness@example.invalid -c user.name=harness -c commit.gpgsign=false -c tag.gpgsign=false -c tag.forceSignAnnotated=false "$@"; }

# --- synthetic origin: main (base + a later move) + a behind-main branch ----
ORIGIN="$WORK/origin.git"
git_c init -q --bare "$ORIGIN"
git_c -C "$ORIGIN" symbolic-ref HEAD refs/heads/main
SEED="$WORK/seed"
git_c init -q "$SEED"
cd "$SEED"
git_c remote add origin "$ORIGIN"
mkdir -p .github/workflows .github/scripts
printf 'name: base\n' > .github/workflows/base.yml
printf '#!/usr/bin/env bash\necho base\n' > .github/scripts/base.sh
git_c add -A
git_c commit -qm "base"
git_c branch -M main
git_c push -q origin main

git_c checkout -qb behind
printf 'name: branch\n' > .github/workflows/branch.yml
printf '#!/usr/bin/env bash\necho branch\n' > .github/scripts/branch.sh
git_c add -A
git_c commit -qm "branch workflow + CI-script change"
git_c push -q origin behind

# A scripts/lib (sourced by provision.yml) change and a symlink-in-the-set
# branch: both are counted-set teeth (red-team r2).
git_c checkout -qb sourced main
mkdir -p scripts/lib
printf '#!/usr/bin/env bash\necho sourced\n' > scripts/lib/naming.sh
git_c add -A
git_c commit -qm "sourced provisioning script change"
git_c push -q origin sourced

git_c checkout -qb symlink main
mkdir -p scripts/lib .github/scripts
printf '#!/usr/bin/env bash\necho target\n' > scripts/lib/naming.sh
ln -s ../../scripts/lib/naming.sh .github/scripts/link.sh
git_c add -A
git_c commit -qm "symlink in the counted set"
git_c push -q origin symlink

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
is "behind-main: the count is the branch's own workflow + CI-script change" "2" "$count"
is "behind-main: rc" "0" "$rc"

# --- (f) tag shadowing: a tag named origin/main must not win -----------------
git_c tag origin/main
old_base="$(git merge-base "origin/main" HEAD 2>/dev/null || true)"
old_count="$(git diff --name-only "$old_base" HEAD -- .github/workflows .github/scripts 2>/dev/null | grep -c . || true)"
is "tag shadow (pre-fix form): collapses to a false 0" "0" "$old_count"
rc=0
count="$(bash "$SCRIPT" main)" || rc=$?
is "tag shadow: the remote-tracking ref still wins" "2" "$count"
is "tag shadow: rc" "0" "$rc"

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

# --- (g) the sourced provisioning script is part of the counted set ---------
# provision.yml sources scripts/lib/naming.sh (line 527): a change there must
# move the verdict (red-team r2 MEDIUM).
cd "$CLONE"
git_c checkout -q sourced
rc=0
count="$(bash "$SCRIPT" main)" || rc=$?
is "sourced script: a scripts/lib change is counted" "1" "$count"
is "sourced script: rc" "0" "$rc"

# --- (h) cwd independence: a non-root cwd must not narrow the diff ----------
# The wired caller runs at the workspace root; the pathspecs are :(top)-
# anchored so any cwd sees the same set (functional r2 / red-team r2 LOW).
git_c checkout -q behind
rc=0
count="$(cd "$CLONE/.github" && bash "$SCRIPT" main)" || rc=$?
is "non-root cwd: count unchanged" "2" "$count"
is "non-root cwd: rc" "0" "$rc"

# --- (i) the exact remote-tracking ref is required (no tag dwim) ------------
# With refs/remotes/origin/main deleted and a tag literally named
# refs/remotes/origin/main present, merge-base dwim-resolves the tag; the
# script must refuse loud instead (red-team r2 LOW).
git_c update-ref -d refs/remotes/origin/main
git_c tag refs/remotes/origin/main
rc=0
out="$(bash "$SCRIPT" main 2>"$WORK/dwim.err")" || rc=$?
if [ "$rc" -ne 0 ]; then ok "missing remote-tracking ref: rc non-zero"; else bad "missing remote-tracking ref: rc=$rc"; fi
is "missing remote-tracking ref: no count on stdout" "" "$out"
if grep -q '::error::' "$WORK/dwim.err"; then ok "missing remote-tracking ref: ::error:: annotation"; else bad "missing remote-tracking ref: no ::error::"; fi
git_c tag -d refs/remotes/origin/main >/dev/null
git_c fetch -q origin main

# --- (j) a symlink in the counted set refuses -------------------------------
# A symlink can point outside the counted set, so a target-only change would
# not appear in the diff; refusing is the fail-closed answer (red-team r2).
git_c checkout -q symlink
rc=0
out="$(bash "$SCRIPT" main 2>"$WORK/symlink.err")" || rc=$?
if [ "$rc" -ne 0 ]; then ok "symlink in the counted set: rc non-zero"; else bad "symlink in the counted set: rc=$rc"; fi
is "symlink in the counted set: no count on stdout" "" "$out"
if grep -q '::error::' "$WORK/symlink.err"; then ok "symlink in the counted set: ::error:: annotation"; else bad "symlink in the counted set: no ::error::"; fi
git_c checkout -q behind

# --- (e) wiring --------------------------------------------------------------
# Comment-proof pins: a commented-out call line, a second `COUNT=` assignment,
# a `-ge 0` comparison, a whitespace-variant `git  fetch`, or a shallow
# checkout must redden (functional r1/r2, red-team r1/r2). Full-line and
# inline comments are stripped first, so only ACTIVE code satisfies a pin.
# The pins below are deliberately exact: a comment mentioning the script, the
# `--depth 1` spelling, or one half of the ci.yml wiring must not satisfy them
# (functional r1 LOWs / red-team r1 MEDIUM-LOW).
PROV="$REPO_ROOT/.github/workflows/provision.yml"
CI="$REPO_ROOT/.github/workflows/ci.yml"
prov_active="$(sed -E 's/^[[:space:]]*#.*$//; s/[[:space:]]+#.*$//' "$PROV")"
# The verdict pins are scoped to the banner step, so a `COUNT=` assignment in
# another job (e.g. the DNS job's list_count) is neither counted nor
# satisfying (red-team r2 MEDIUM).
banner_step="$(awk '/- name: Approval card/{f=1} /- name: Record head SHA/{f=0} f' "$PROV")"
banner_active="$(sed -E 's/^[[:space:]]*#.*$//; s/[[:space:]]+#.*$//' <<<"$banner_step")"
if [ -n "$banner_step" ]; then ok "the banner step was located for the scoped pins"; else bad "the banner step was not located (pin scope lost)"; fi
call_line='COUNT="$(bash .github/scripts/banner-workflow-diff.sh "$BASE_REF")"'
if [ "$(grep -cF "$call_line" <<<"$banner_active")" = "1" ]; then ok "the banner step calls the diff script (exact active call line)"; else bad "the banner step call line is missing, duplicated, or only commented"; fi
if [ "$(grep -cE '^[[:space:]]*COUNT=' <<<"$banner_active")" = "1" ]; then ok "the script call is the only COUNT assignment in the banner step"; else bad "the banner step has extra or missing COUNT assignments"; fi
if grep -qF '[ "$COUNT" -eq 0 ]' <<<"$banner_active"; then ok "the UNCHANGED branch compares COUNT exactly to 0"; else bad "the COUNT comparison is missing or widened"; fi
if grep -qE 'git[[:space:]]+fetch' <<<"$prov_active"; then bad "provision.yml still carries a fetch"; else ok "provision.yml carries no fetch (whitespace-tolerant)"; fi
if printf 'git  fetch origin main --depth=1\n' | grep -qE 'git[[:space:]]+fetch'; then ok "the no-fetch pin matches whitespace variants"; else bad "the no-fetch pin misses whitespace variants"; fi
if grep -qF 'fetch-depth: 0' <<<"$prov_active"; then ok "provision.yml keeps the full-history checkout"; else bad "provision.yml lost fetch-depth: 0"; fi
if grep -qF 'tests/(banner-workflow-diff|' "$CI"; then ok "ci.yml path gate includes the harness"; else bad "ci.yml path gate does not include the harness"; fi
if grep -qF 'bash tests/banner-workflow-diff/run-test.sh' "$CI"; then ok "ci.yml run list includes the harness"; else bad "ci.yml run list does not include the harness"; fi

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
