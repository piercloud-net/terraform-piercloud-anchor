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
#     runs on the host), and the root HCL the run applies (`*.tf`, `*.tf.json`,
#     `*.tofu`, `*.tofu.json`, `*.tfvars`, `*.tfvars.json`,
#     `.terraform.lock.hcl`; `:(glob)` keeps it top-level-only — the examples
#     are not executed). JSON-syntax HCL is a full member of the root module to
#     OpenTofu, and the `.tofu`/`.tofu.json` extensions are loaded by the
#     pinned 1.12.2 runtime (functional r5b HIGH), so all are counted like
#     native HCL (red-team r1/r2/r3/r4 HIGH/MEDIUM, functional r3/r4 MEDIUM).
#   * Pathspecs are `:(top)`-anchored: a non-root cwd must not silently narrow
#     the diff to zero (functional r2 / red-team r2 LOW).
#   * A symlink anywhere in the counted set's closure (at, above, or inside a
#     counted path) can resolve an executed file outside the diff; the script
#     refuses rather than certify (red-team r2/r3/r4 MEDIUM, functional r4 LOW).
#     The scan is a while-read loop over NUL-delimited `ls-files -s -z` output,
#     never `... | grep -q`: under `pipefail` an early `grep -q` exit SIGPIPEs
#     the producer and the pipeline's rc 141 silently skips the guard at
#     listing scale, and whitespace/C-quoted path rendering (`x main.tf`)
#     defeats an awk `$4` field split (functional r3 LOW, red-team r4 MEDIUM).
#   * A module block in the counted root HCL refuses: its source tree may be
#     local/executed code the diff cannot see, and source-value matching is
#     evadable (attached `=`, comments, `\uNNNN` escapes, absolute paths), so
#     the gate is the block statement itself — a native line whose first
#     non-comment token is `module` (`module/*c*/"m"`, `module"m"`, a leading
#     block comment `/*c*/ module "m"`, an indented line), any line where a
#     comment close (`*/`, incl. a `*` run like `/***/` and a multi-line
#     comment whose text precedes the close) directly precedes the `module`
#     token, a BOM-prefixed `module` token, or the `"module"` key (JSON HCL,
#     incl. a key split from its colon) — never the bare word in prose (a
#     description/comment containing "module" must not refuse; functional
#     r5c/r5c-delta/r5f HIGH/MEDIUM, red-team r5c/r5c-delta/r5f MEDIUM, trust
#     r5f MEDIUM). Registry-only modules refuse too (fail-closed): extend the
#     pathspecs and relax this gate deliberately.
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
  ':(top,glob)*.tf.json'
  ':(top,glob)*.tofu'
  ':(top,glob)*.tofu.json'
  ':(top,glob)*.tfvars'
  ':(top,glob)*.tfvars.json'
  ':(top).terraform.lock.hcl'
)
# A path in the counted closure: the path itself, an ancestor, or a child.
counted_closure() {
  case "$1" in
    .github|.github/workflows|.github/workflows/*|.github/scripts|.github/scripts/*) return 0 ;;
    scripts|scripts/lib|scripts/lib/*|scripts/010-provision.sh) return 0 ;;
  esac
  case "$1" in
    *.tf|*.tf.json|*.tofu|*.tofu.json|*.tfvars|*.tfvars.json|.terraform.lock.hcl)
      [ "${1%/*}" = "$1" ] && return 0 ;;
  esac
  return 1
}
symlink_hit=""
top="$(git rev-parse --show-toplevel)"
while IFS= read -r -d '' entry; do
  case "$entry" in
    120000\ *) ;;
    *) continue ;;
  esac
  link="${entry#*$'\t'}"
  [ -n "$link" ] || continue
  if counted_closure "$link"; then
    symlink_hit="$link"
    break
  fi
done < <(git -C "$top" ls-files -s -z)
if [ -n "$symlink_hit" ]; then
  echo "::error::symlink '$symlink_hit' is in the run's code surface — refusing a banner verdict" >&2
  exit 1
fi
# A module block in the counted root HCL refuses: its source tree may be
# local/executed code the diff cannot see, and source-value matching is
# evadable (attached `=`, comments, `\uNNNN` escapes, absolute paths), so the
# gate is the block statement itself — a line whose first non-comment token is
# `module` (native HCL: `module "m" {`, `module/*c*/"m" {`, `module"m" {`, a
# leading block comment `/*c*/ module "m"`, a BOM prefix) or the `"module"` key
# (JSON HCL, including a key split from its colon) — never the bare word in
# prose (a description/comment containing "module" must not refuse; functional
# r5c/r5c-delta HIGH/MEDIUM, red-team r5c/r5c-delta MEDIUM). Registry-only
# modules refuse too (fail-closed): extend the pathspecs with the module tree
# and relax this gate deliberately.
# Residual: an escaped JSON KEY (`"\u006dodule"`; a source-VALUE escape like
# `source = "\u002e/x"` is covered because the block itself is seen) is out of
# a textual scan's reach; the gate over-refuses (fail-closed) any line whose
# first token is `module` even when it is not a block (e.g. a `module = 3`
# local), any line where a `*/` precedes a `module` token (incl. heredoc/string
# text like `*/ module …`), and a line ending in the literal string `"module"`
# — the review is the backstop (trust r5f LOW, red-team r5f LOW).
if git grep -qE '^[[:space:]]*module([^[:alnum:]_]|$)|\*+/[[:space:]]*module([^[:alnum:]_]|$)|"module"[[:space:]]*:|"module"[[:space:]]*$' -- ':(top,glob)*.tf' ':(top,glob)*.tf.json' ':(top,glob)*.tofu' ':(top,glob)*.tofu.json' \
   || git grep -qE $'^\xef\xbb\xbf[[:space:]]*module([^[:alnum:]_]|$)' -- ':(top,glob)*.tf' ':(top,glob)*.tf.json' ':(top,glob)*.tofu' ':(top,glob)*.tofu.json'; then
  echo "::error::a module block exists in the counted root HCL — its source tree is executed code outside the counted set; add it to the pathspecs and relax this gate deliberately" >&2
  exit 1
fi
if ! changed="$(git diff --name-only "$base" HEAD -- "${pathspecs[@]}")"; then
  echo "::error::cannot diff the run's code surface against the merge base — refusing a banner verdict" >&2
  exit 1
fi
printf '%s\n' "$changed" | grep -c . || true
