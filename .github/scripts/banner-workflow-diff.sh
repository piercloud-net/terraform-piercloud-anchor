#!/usr/bin/env bash
# banner-workflow-diff.sh — count the .github workflow/CI-script files changed
# on the dispatched head relative to its merge base with the base branch
# (#130).
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
#     (red-team r1 HIGH).
#   * The counted set is the run's CI-called code surface — `.github/workflows`
#     and `.github/scripts` — not just the workflow files: the workflow
#     executes the checked-out scripts, so a script-only change must move the
#     verdict too (red-team r1 MEDIUM).
#   * A diff that cannot be computed is a loud error, never a silent
#     "0 files changed": the card's UNCHANGED verdict is a security signal
#     and an undeterminable count must fail closed.
#
# Prints the changed-file count (one line, digits) to stdout on success.
set -euo pipefail

base_ref="${1:?usage: banner-workflow-diff.sh <base-ref>}"
remote_ref="refs/remotes/origin/${base_ref}"
if ! base="$(git merge-base "$remote_ref" HEAD)"; then
  echo "::error::cannot find a merge base with $remote_ref — refusing a banner verdict; re-dispatch from a branch that shares history with ${base_ref}" >&2
  exit 1
fi
if ! changed="$(git diff --name-only "$base" HEAD -- .github/workflows .github/scripts)"; then
  echo "::error::cannot diff the workflow/CI-script surface against the merge base — refusing a banner verdict" >&2
  exit 1
fi
printf '%s\n' "$changed" | grep -c . || true
