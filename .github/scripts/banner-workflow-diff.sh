#!/usr/bin/env bash
# banner-workflow-diff.sh — count the run's executed code surface changed on
# the dispatched head relative to its merge base with the base branch (#130).
#
# Called by provision.yml's `visibility-banner` job (the C-E approval card).
# The job's actions/checkout carries full history (fetch-depth: 0), so the
# count is taken straight against the checked-out remote-tracking ref:
#
#   * No fetch happens here. A `git fetch --depth=1` replaces the
#     remote-tracking ref with a grafted shallow one; when the dispatched
#     branch is behind the base the merge base becomes unreachable and the
#     diff dies with exit 128 before the approval card renders (#130; live
#     on runs 34734083690/34734109911).
#   * The ref is FULLY QUALIFIED (`refs/remotes/origin/<base>`) and must
#     exist: git's shorthand resolution prefers `refs/tags/<name>` over
#     `refs/remotes/<name>`, and `rev-parse`/`merge-base` would dwim-resolve a
#     tag literally named `refs/remotes/origin/<base>` when the exact ref is
#     absent (red-team r1 HIGH / r2 LOW).
#   * The counted set is the run's executed code surface: `.github/workflows`,
#     `.github/scripts`, the provisioning scripts the workflow runs or sources
#     (`scripts/lib/*` is sourced by the provision job; `scripts/010-provision.sh`
#     runs on the host), and the root HCL the run applies (`*.tf`, `*.tfvars`,
#     `.terraform.lock.hcl`; `:(glob)` keeps it top-level-only — the examples
#     are not executed) (red-team r1/r2/r3 MEDIUM/HIGH, functional r3 MEDIUM).
#   * Pathspecs are `:(top)`-anchored: a non-root cwd must not silently narrow
#     the diff to zero (functional r2 / red-team r2 LOW).
#   * A symlink anywhere in the counted set's closure (at, above, or inside a
#     counted path) can resolve an executed file outside the diff; the script
#     refuses rather than certify (red-team r2/r3 MEDIUM). The scan is a
#     while-read loop, never `... | grep -q`: under `pipefail` an early
#     `grep -q` exit SIGPIPEs the producer and the pipeline's rc 141 silently
#     skips the guard at listing scale (functional r3 LOW).
#   * A diff that cannot be computed is a loud error, never a silent
#     "0 files changed": the card's UNCHANGED verdict is a security signal
#     and an undeterminable count must fail closed.
#
# Prints the changed-file count (one line, digits) to stdout on success.
set -euo pipefail

base_ref="${1:?usage: banner-workflow-diff.sh <base-ref>}"
remote_ref="refs/remotes/origin/${base_ref}"
if ! git show-ref --verify --quiet "$remote_ref"; then
  echo "::error::no $remote_ref in this checkout — refusing a banner verdict; re-dispatch from a branch that shares history with ${base_ref}" >&2
  exit 1
fi
if ! base="$(git merge-base "$remote_ref" HEAD)"; then
  echo "::error::cannot find a merge base with $remote_ref — refusing a banner verdict; re-dispatch from a branch that shares history with ${base_ref}" >&2
  exit 1
fi
pathspecs=(
  ':(top).github/workflows'
  ':(top).github/scripts'
  ':(top)scripts/lib'
  ':(top)scripts/010-provision.sh'
  ':(top,glob)*.tf'
  ':(top,glob)*.tfvars'
  ':(top).terraform.lock.hcl'
)
# A path in the counted closure: the path itself, an ancestor, or a child.
counted_closure() {
  case "$1" in
    .github|.github/workflows|.github/workflows/*|.github/scripts|.github/scripts/*) return 0 ;;
    scripts|scripts/lib|scripts/lib/*|scripts/010-provision.sh) return 0 ;;
  esac
  case "$1" in
    *.tf|*.tfvars|.terraform.lock.hcl)
      [ "${1%/*}" = "$1" ] && return 0 ;;
  esac
  return 1
}
symlink_hit=""
top="$(git rev-parse --show-toplevel)"
while IFS= read -r link; do
  [ -n "$link" ] || continue
  if counted_closure "$link"; then
    symlink_hit="$link"
    break
  fi
done < <(git -C "$top" ls-files -s | awk '$1 == "120000" { print $4 }')
if [ -n "$symlink_hit" ]; then
  echo "::error::symlink '$symlink_hit' is in the run's code surface — refusing a banner verdict" >&2
  exit 1
fi
if ! changed="$(git diff --name-only "$base" HEAD -- "${pathspecs[@]}")"; then
  echo "::error::cannot diff the run's code surface against the merge base — refusing a banner verdict" >&2
  exit 1
fi
printf '%s\n' "$changed" | grep -c . || true
