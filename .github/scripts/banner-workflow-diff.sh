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
#   * The ref is FULLY QUALIFIED (`refs/remotes/origin/<base>`): git's
#     shorthand resolution prefers `refs/tags/<name>` over
#     `refs/remotes/<name>`, and the pinned checkout fetches every tag, so a
#     pushed tag literally named `origin/<base>` could otherwise shadow the
#     remote-tracking ref and collapse the count to a false UNCHANGED
#     (red-team r1 HIGH). `show-ref --verify` additionally refuses when the
#     exact ref is absent, because `git rev-parse`/`merge-base` would still
#     dwim-resolve a tag literally named `refs/remotes/origin/<base>`
#     (red-team r2 LOW).
#   * The counted set is the run's executed code surface — `.github/workflows`,
#     `.github/scripts`, and the provisioning scripts the workflow runs or
#     sources (`scripts/lib/*` is sourced at provision.yml:527;
#     `scripts/010-provision.sh` runs on the host) — mirroring ci.yml's
#     change-relevant classification (`scripts/(lib/|010-provision\.sh)`).
#     The workflow executes the checked-out scripts, so a script-only change
#     must move the verdict too (red-team r1 MEDIUM / r2 MEDIUM).
#   * Pathspecs are `:(top)`-anchored: a non-root cwd must not silently narrow
#     the diff to zero (functional r2 / red-team r2 LOW).
#   * A symlink in the counted set can point outside it, so a target-only
#     change would not appear in the diff; the script refuses rather than
#     certify (red-team r2 MEDIUM variant).
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
)
if git ls-files -s -- "${pathspecs[@]}" | awk '$1 == "120000" { print $4 }' | grep -q .; then
  echo "::error::a symlink exists in the run's code surface — refusing a banner verdict" >&2
  exit 1
fi
if ! changed="$(git diff --name-only "$base" HEAD -- "${pathspecs[@]}")"; then
  echo "::error::cannot diff the run's code surface against the merge base — refusing a banner verdict" >&2
  exit 1
fi
printf '%s\n' "$changed" | grep -c . || true
