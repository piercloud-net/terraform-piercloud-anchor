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
#   (k) a root-HCL change (main.tf / .terraform.lock.hcl) is counted, while an
#       example-tree .tf change is not — the run applies only the root module
#       (red-team r3 HIGH / functional r3 MEDIUM);
#   (m) a symlink at or above a counted path (`scripts -> real`) refuses, and a
#       2000-symlink farm still refuses (the while-read scan is not defeated by
#       listing size) (red-team r3 MEDIUM / functional r3 LOW);
#   (n) a scripts/010-provision.sh change is counted (functional r3 LOW);
#   (p) JSON-syntax and `.tofu` root HCL (main.tf.json / *.auto.tfvars.json /
#       main.tofu / main.tofu.json) is counted, as are plain `*.tfvars` and
#       `.terraform.lock.hcl`, while an example-tree `.tofu` change is not —
#       OpenTofu loads all of the root-module ones (red-team r4 HIGH /
#       functional r4 MEDIUM / functional r5b HIGH / red-team r5c LOW);
#   (q) a symlink whose name carries whitespace still refuses — the
#       NUL-delimited scan must not truncate at the field split, and
#       JSON-/`.tofu`-/tfvars-named symlinks refuse too (the closure mirrors
#       the pathspecs) (red-team r4 MEDIUM / trust r4 MEDIUM / functional r4
#       LOW / red-team r5c LOW);
#   (r) a module block in the counted root HCL refuses — its source tree is
#       executed by the run but may be outside the counted set; the gate is the
#       block statement itself (line-anchored `module` token: attached `=`,
#       attached label, leading inline/multi-line block comments incl. `*` runs
#       and text before the close, indentation, a BOM prefix, a comment close
#       directly before the token, JSON split keys and spaced colons,
#       source-value escapes covered; `.tf`/`.tf.json`/`.tofu`/`.tofu.json`
#       included), while a non-module `source` (attribute, comment or heredoc
#       text) and the bare word "module" in prose do not refuse (red-team
#       r5/r5b/r5c/r5c-delta/r5f MEDIUM, trust r5b/r5c-delta/r5f MEDIUM/LOW,
#       functional r5b/r5c/r5c-delta/r5f HIGH/MEDIUM/LOW; latent — no module
#       blocks in the counted root HCL today; the example tree has one,
#       unexecuted; fail-closed over-refusals: a non-block first-token
#       `module` (e.g. `module = 3`), any `*/`-before-`module` line incl.
#       heredoc/string text, a line ending in the literal `"module"`);
#   (e) wiring: comment- and continuation-proof pins — the exact active call,
#       exactly one COUNT= token (space/compound-tolerant), no COUNT override
#       form (arithmetic/export/read/declare/let/unset/readonly/typeset/
#       readarray/mapfile/eval/source, incl. quoted/escaped `printf -v`),
#       every non-call COUNT mention is a read, no double-quote-spliced
#       identifier, exactly one `-eq 0` with no widened/decoy comparison, an
#       option/continuation/quote/newline/backslash-splice-tolerant
#       no-fetch-or-pull with no git alias and no fetch/pull assignment, and
#       the banner job's single fetch-depth: 0; ci.yml gates AND runs this
#       harness. Residual: single-quote splicing (`COU'NT=0`), deep variable
#       indirection (`cmd=git; $cmd fetch`, `git${IFS}fetch`) and an escaped
#       JSON module key (`"\u006dodule"`) are out of a textual pin's reach —
#       the pin is a regression tripwire, the review is the backstop.
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

# A root-HCL change, a JSON-syntax root-HCL change, an example-tree .tf change,
# an ancestor symlink, the 010 provisioning script, a large symlink farm, and
# a spaced-name symlink: counted-set / closure teeth (red-team r3/r4,
# functional r3/r4, trust r4).
git_c checkout -qb hcl main
printf '# root hcl\n' > main.tf
git_c add -A
git_c commit -qm "root HCL change"
git_c push -q origin hcl

git_c checkout -qb hcljson main
printf '{"resource":{}}\n' > main.tf.json
git_c add -A
git_c commit -qm "JSON-syntax root HCL change"
git_c push -q origin hcljson

git_c checkout -qb varsjson main
printf '{"tenant":"x"}\n' > prod.auto.tfvars.json
git_c add -A
git_c commit -qm "JSON-syntax auto tfvars change"
git_c push -q origin varsjson

git_c checkout -qb example main
mkdir -p examples/quickstart
printf '# example hcl\n' > examples/quickstart/main.tf
git_c add -A
git_c commit -qm "example-tree HCL change"
git_c push -q origin example

git_c checkout -qb ancestor main
mkdir -p real
printf '#!/usr/bin/env bash\necho real\n' > real/010-provision.sh
ln -s real scripts
git_c add -A
git_c commit -qm "ancestor symlink over the counted set"
git_c push -q origin ancestor

git_c checkout -qb prov main
mkdir -p scripts
printf '#!/usr/bin/env bash\necho prov\n' > scripts/010-provision.sh
git_c add -A
git_c commit -qm "010-provision.sh change"
git_c push -q origin prov

git_c checkout -qb farm main
mkdir -p payload .github/scripts
printf '#!/usr/bin/env bash\necho payload\n' > payload/run.sh
for i in $(seq 1 2000); do ln -s ../../payload/run.sh ".github/scripts/farm-$i.sh"; done
git_c add -A
git_c commit -qm "symlink farm"
git_c push -q origin farm

git_c checkout -qb spaced main
mkdir -p payload
printf '#!/usr/bin/env bash\necho payload\n' > payload/evil.sh
ln -s payload/evil.sh "evil .tf"
git_c add -A
git_c commit -qm "symlink with whitespace in a counted path"
git_c push -q origin spaced

git_c checkout -qb jsonsymlink main
mkdir -p payload
printf '#!/usr/bin/env bash\necho payload\n' > payload/evil.sh
ln -s payload/evil.sh main.tf.json
git_c add -A
git_c commit -qm "JSON-named symlink in a counted path"
git_c push -q origin jsonsymlink

git_c checkout -qb dottofusymlink main
mkdir -p payload
printf '#!/usr/bin/env bash\necho payload\n' > payload/evil.sh
ln -s payload/evil.sh main.tofu
git_c add -A
git_c commit -qm ".tofu-named symlink in a counted path"
git_c push -q origin dottofusymlink

git_c checkout -qb modulesrc main
mkdir -p modules/m
printf 'module "m" {\n  source = "./modules/m"\n}\n' > main.tf
printf '# module\n' > modules/m/main.tf
git_c add -A
git_c commit -qm "local module source"
git_c push -q origin modulesrc

git_c checkout -qb modulesrcjson main
mkdir -p modules/m
printf '{"module":{"m":{"source":"./modules/m"}}}\n' > main.tf.json
printf '{}\n' > modules/m/main.tf.json
git_c add -A
git_c commit -qm "JSON local module source"
git_c push -q origin modulesrcjson

git_c checkout -qb modulesrcattached main
mkdir -p modules/m
printf 'module "m" {source="./modules/m"}\n' > main.tf
printf '# module\n' > modules/m/main.tf
git_c add -A
git_c commit -qm "attached-equals module source"
git_c push -q origin modulesrcattached

git_c checkout -qb modulesrccomment main
mkdir -p modules/m
printf 'module "m" {\n  source = /* bypass */ "./modules/m"\n}\n' > main.tf
printf '# module\n' > modules/m/main.tf
git_c add -A
git_c commit -qm "comment-bypassed module source"
git_c push -q origin modulesrccomment

git_c checkout -qb modulesrcesc main
mkdir -p modules/m
printf 'module "m" {\n  source = "\\u002e/modules/m"\n}\n' > main.tf
printf '# module\n' > modules/m/main.tf
git_c add -A
git_c commit -qm "escaped module source"
git_c push -q origin modulesrcesc

git_c checkout -qb ressrc main
printf 'resource "x" "y" {\n  source = "./file.txt"\n}\n' > main.tf
git_c add -A
git_c commit -qm "non-module source attribute"
git_c push -q origin ressrc

git_c checkout -qb rescomment main
printf '# source = "./modules/m"\n' > main.tf
git_c add -A
git_c commit -qm "comment-only source text"
git_c push -q origin rescomment

git_c checkout -qb resheredoc main
printf 'resource "x" "y" {\n  description = <<EOT\nsource = "./modules/m"\nEOT\n}\n' > main.tf
git_c add -A
git_c commit -qm "heredoc source text"
git_c push -q origin resheredoc

git_c checkout -qb dottofu main
printf 'output "x" { value = "tofu-ext" }\n' > main.tofu
git_c add -A
git_c commit -qm ".tofu root HCL change"
git_c push -q origin dottofu

git_c checkout -qb dottofujson main
printf '{"output":{"x":{"value":"json-ext"}}}\n' > main.tofu.json
git_c add -A
git_c commit -qm ".tofu.json root HCL change"
git_c push -q origin dottofujson

git_c checkout -qb dottofumodule main
mkdir -p modules/m
printf 'module "m" {\n  source = "./modules/m"\n}\n' > main.tofu
printf '# module\n' > modules/m/main.tofu
git_c add -A
git_c commit -qm ".tofu module source"
git_c push -q origin dottofumodule

git_c checkout -qb modprose main
printf '# blocks are root-only, and this module is consumed as a CHILD module\nresource "x" "y" {\n  description = "Required for the module to manage the firewall policy"\n}\n' > main.tf
git_c add -A
git_c commit -qm "module prose in the root HCL"
git_c push -q origin modprose

git_c checkout -qb modulecblock main
mkdir -p modules/m
printf 'module/*c*/"m" {\n  source = "./modules/m"\n}\n' > main.tf
printf '# module\n' > modules/m/main.tf
git_c add -A
git_c commit -qm "inline-block-comment module block"
git_c push -q origin modulecblock

git_c checkout -qb moduleattachedlabel main
mkdir -p modules/m
printf 'module"m" {\n  source = "./modules/m"\n}\n' > main.tf
printf '# module\n' > modules/m/main.tf
git_c add -A
git_c commit -qm "attached-label module block"
git_c push -q origin moduleattachedlabel

git_c checkout -qb modulebom main
mkdir -p modules/m
printf '\xef\xbb\xbfmodule "m" {\n  source = "./modules/m"\n}\n' > main.tf
printf '# module\n' > modules/m/main.tf
git_c add -A
git_c commit -qm "BOM-prefixed module block"
git_c push -q origin modulebom

git_c checkout -qb moduleleadcomment main
mkdir -p modules/m
printf '/*c*/ module "m" {\n  source = "./modules/m"\n}\n' > main.tf
printf '# module\n' > modules/m/main.tf
git_c add -A
git_c commit -qm "leading block-comment module block"
git_c push -q origin moduleleadcomment

git_c checkout -qb moduleleadcommentnl main
mkdir -p modules/m
printf '/* c\n*/ module "m" {\n  source = "./modules/m"\n}\n' > main.tf
printf '# module\n' > modules/m/main.tf
git_c add -A
git_c commit -qm "multi-line leading block-comment module block"
git_c push -q origin moduleleadcommentnl

git_c checkout -qb moduleclosecomment main
mkdir -p modules/m
printf '/* c\ncontinued text */ module "m" {\n  source = "./modules/m"\n}\n' > main.tf
printf '# module\n' > modules/m/main.tf
git_c add -A
git_c commit -qm "multi-line comment close before the module token"
git_c push -q origin moduleclosecomment

git_c checkout -qb modulestars main
mkdir -p modules/m
printf '/***/ module "m" {\n  source = "./modules/m"\n}\n' > main.tf
printf '# module\n' > modules/m/main.tf
git_c add -A
git_c commit -qm "comment close with a star run before the module token"
git_c push -q origin modulestars

git_c checkout -qb modulestarspace main
mkdir -p modules/m
printf '/* **/ module "m" {\n  source = "./modules/m"\n}\n' > main.tf
printf '# module\n' > modules/m/main.tf
git_c add -A
git_c commit -qm "comment close with a spaced star run before the module token"
git_c push -q origin modulestarspace

git_c checkout -qb modulebomcomment main
mkdir -p modules/m
printf '\xef\xbb\xbf/*c*/ module "m" {\n  source = "./modules/m"\n}\n' > main.tf
printf '# module\n' > modules/m/main.tf
git_c add -A
git_c commit -qm "BOM before a comment-prefixed module block"
git_c push -q origin modulebomcomment

git_c checkout -qb moduleattr main
printf 'locals {\n  module = 3\n}\n' > main.tf
git_c add -A
git_c commit -qm "non-block first-token module attribute (fail-closed refusal)"
git_c push -q origin moduleattr

git_c checkout -qb moduleheredocclose main
printf 'locals {\n  description = <<EOT\n*/ module is mentioned in this heredoc line\nEOT\n}\n' > main.tf
git_c add -A
git_c commit -qm "heredoc line with a comment close before a module token (fail-closed refusal)"
git_c push -q origin moduleheredocclose

git_c checkout -qb moduleindented main
mkdir -p modules/m
printf '  module "m" {\n    source = "./modules/m"\n  }\n' > main.tf
printf '# module\n' > modules/m/main.tf
git_c add -A
git_c commit -qm "indented module block"
git_c push -q origin moduleindented

git_c checkout -qb modulejsonspaced main
mkdir -p modules/m
printf '{"module" : {"m":{"source":"./modules/m"}}}\n' > main.tf.json
printf '{}\n' > modules/m/main.tf.json
git_c add -A
git_c commit -qm "JSON spaced-colon module block"
git_c push -q origin modulejsonspaced

git_c checkout -qb modulecount main
printf 'locals {\n  module_count = 3\n}\n' > main.tf
git_c add -A
git_c commit -qm "module_count local (prose-like identifier)"
git_c push -q origin modulecount

git_c checkout -qb modulejsonsplit main
mkdir -p modules/m
printf '{"module"\n:{"m":{"source":"./modules/m"}}}\n' > main.tf.json
printf '{}\n' > modules/m/main.tf.json
git_c add -A
git_c commit -qm "JSON split-key module block"
git_c push -q origin modulejsonsplit

git_c checkout -qb dottofujsonmodule main
mkdir -p modules/m
printf '{"module":{"m":{"source":"./modules/m"}}}\n' > main.tofu.json
printf '{}\n' > modules/m/main.tofu.json
git_c add -A
git_c commit -qm ".tofu.json module block"
git_c push -q origin dottofujsonmodule

git_c checkout -qb vars main
printf 'tenant = "x"\n' > prod.tfvars
git_c add -A
git_c commit -qm "plain tfvars change"
git_c push -q origin vars

git_c checkout -qb lockfile main
printf '# lock\n' > .terraform.lock.hcl
git_c add -A
git_c commit -qm "lockfile change"
git_c push -q origin lockfile

git_c checkout -qb exampletofu main
mkdir -p examples/quickstart
printf 'output "x" { value = "example" }\n' > examples/quickstart/main.tofu
git_c add -A
git_c commit -qm "example-tree .tofu change"
git_c push -q origin exampletofu

git_c checkout -qb tfvarssymlink main
mkdir -p payload
printf '#!/usr/bin/env bash\necho payload\n' > payload/evil.sh
ln -s payload/evil.sh prod.auto.tfvars.json
git_c add -A
git_c commit -qm "tfvars-named symlink in a counted path"
git_c push -q origin tfvarssymlink

git_c checkout -qb tfsymlink main
mkdir -p payload
printf '#!/usr/bin/env bash\necho payload\n' > payload/evil.sh
ln -s payload/evil.sh prod.tfvars
git_c add -A
git_c commit -qm "plain-tfvars-named symlink in a counted path"
git_c push -q origin tfsymlink

git_c checkout -qb lockfilesymlink main
mkdir -p payload
printf '#!/usr/bin/env bash\necho payload\n' > payload/evil.sh
ln -s payload/evil.sh .terraform.lock.hcl
git_c add -A
git_c commit -qm "lockfile-named symlink in a counted path"
git_c push -q origin lockfilesymlink

git_c checkout -qb dottofujsonsymlink main
mkdir -p payload
printf '#!/usr/bin/env bash\necho payload\n' > payload/evil.sh
ln -s payload/evil.sh main.tofu.json
git_c add -A
git_c commit -qm ".tofu.json-named symlink in a counted path"
git_c push -q origin dottofujsonsymlink

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
# provision.yml sources scripts/lib/naming.sh: a change there must move the
# verdict (red-team r2 MEDIUM).
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

# --- (k) the root HCL the run applies is counted ----------------------------
# `tofu init/plan/apply` execute the committed root module (provision.yml
# tofu steps); a branch changing only main.tf must move the verdict
# (red-team r3 HIGH / functional r3 MEDIUM).
git_c checkout -q hcl
rc=0
count="$(bash "$SCRIPT" main)" || rc=$?
is "root HCL: a main.tf change is counted" "1" "$count"
is "root HCL: rc" "0" "$rc"

# --- (l) an example-tree .tf change is not counted --------------------------
# The `:(glob)` pathspec keeps the counted HCL top-level-only: the examples
# are not executed by the run (red-team r3 HIGH — precision tooth).
git_c checkout -q example
rc=0
count="$(bash "$SCRIPT" main)" || rc=$?
is "example HCL: not counted" "0" "$count"
is "example HCL: rc" "0" "$rc"

# --- (m) an ancestor symlink refuses ----------------------------------------
# A mode-120000 entry at `scripts` (an ancestor of two counted roots) resolves
# the executed file outside the diff; the closure check refuses (red-team r3
# MEDIUM).
git_c checkout -q ancestor
rc=0
out="$(bash "$SCRIPT" main 2>"$WORK/ancestor.err")" || rc=$?
if [ "$rc" -ne 0 ]; then ok "ancestor symlink: rc non-zero"; else bad "ancestor symlink: rc=$rc"; fi
is "ancestor symlink: no count on stdout" "" "$out"
if grep -q '::error::' "$WORK/ancestor.err"; then ok "ancestor symlink: ::error:: annotation"; else bad "ancestor symlink: no ::error::"; fi

# --- (n) the 010 provisioning script is part of the counted set -------------
# 020-provision-anchor.sh pipes scripts/010-provision.sh to the host (executed
# code); a 010-only change must move the verdict (functional r3 LOW).
git_c checkout -q prov
rc=0
count="$(bash "$SCRIPT" main)" || rc=$?
is "010-provision.sh: a change is counted" "1" "$count"
is "010-provision.sh: rc" "0" "$rc"

# --- (o) a large symlink farm still refuses ---------------------------------
# A `git ls-files ... | awk ... | grep -q .` guard is defeated by listing size
# (grep -q exits early -> awk SIGPIPE -> pipeline rc 141 under pipefail -> the
# guard is skipped); the while-read loop must refuse 2000 symlinks
# (functional r3 LOW).
git_c checkout -q farm
rc=0
out="$(bash "$SCRIPT" main 2>"$WORK/farm.err")" || rc=$?
if [ "$rc" -ne 0 ]; then ok "symlink farm: rc non-zero"; else bad "symlink farm: rc=$rc"; fi
is "symlink farm: no count on stdout" "" "$out"
if grep -q '::error::' "$WORK/farm.err"; then ok "symlink farm: ::error:: annotation"; else bad "symlink farm: no ::error::"; fi

# --- (p) JSON-syntax HCL is part of the executed root module ----------------
# OpenTofu loads main.tf.json and *.auto.tfvars.json exactly like native HCL;
# a JSON-only change must move the verdict (red-team r4 HIGH / functional r4
# MEDIUM).
git_c checkout -q hcljson
rc=0
count="$(bash "$SCRIPT" main)" || rc=$?
is "JSON HCL: a main.tf.json change is counted" "1" "$count"
is "JSON HCL: rc" "0" "$rc"
git_c checkout -q varsjson
rc=0
count="$(bash "$SCRIPT" main)" || rc=$?
is "JSON tfvars: a prod.auto.tfvars.json change is counted" "1" "$count"
is "JSON tfvars: rc" "0" "$rc"
git_c checkout -q dottofu
rc=0
count="$(bash "$SCRIPT" main)" || rc=$?
is "tofu HCL: a main.tofu change is counted" "1" "$count"
is "tofu HCL: rc" "0" "$rc"
git_c checkout -q dottofujson
rc=0
count="$(bash "$SCRIPT" main)" || rc=$?
is "tofu JSON HCL: a main.tofu.json change is counted" "1" "$count"
is "tofu JSON HCL: rc" "0" "$rc"
git_c checkout -q vars
rc=0
count="$(bash "$SCRIPT" main)" || rc=$?
is "plain tfvars: a prod.tfvars change is counted" "1" "$count"
is "plain tfvars: rc" "0" "$rc"
git_c checkout -q lockfile
rc=0
count="$(bash "$SCRIPT" main)" || rc=$?
is "lockfile: a .terraform.lock.hcl change is counted" "1" "$count"
is "lockfile: rc" "0" "$rc"
git_c checkout -q exampletofu
rc=0
count="$(bash "$SCRIPT" main)" || rc=$?
is "example .tofu: not counted" "0" "$count"
is "example .tofu: rc" "0" "$rc"

# --- (q) a whitespace-bearing symlink name still refuses --------------------
# `git ls-files -s` renders `120000 … 0\tevil .tf`; an awk `$4` split yields
# `evil` and the closure misses it, while the target-only change stays
# invisible to the diff -> false UNCHANGED. The NUL-delimited scan must
# refuse (red-team r4 MEDIUM / trust r4 MEDIUM / functional r4 LOW).
git_c checkout -q spaced
rc=0
out="$(bash "$SCRIPT" main 2>"$WORK/spaced.err")" || rc=$?
if [ "$rc" -ne 0 ]; then ok "spaced symlink: rc non-zero"; else bad "spaced symlink: rc=$rc"; fi
is "spaced symlink: no count on stdout" "" "$out"
if grep -q '::error::' "$WORK/spaced.err"; then ok "spaced symlink: ::error:: annotation"; else bad "spaced symlink: no ::error::"; fi
git_c checkout -q jsonsymlink
rc=0
out="$(bash "$SCRIPT" main 2>"$WORK/jsonsymlink.err")" || rc=$?
if [ "$rc" -ne 0 ]; then ok "JSON-named symlink: rc non-zero"; else bad "JSON-named symlink: rc=$rc"; fi
is "JSON-named symlink: no count on stdout" "" "$out"
if grep -q '::error::' "$WORK/jsonsymlink.err"; then ok "JSON-named symlink: ::error:: annotation"; else bad "JSON-named symlink: no ::error::"; fi
git_c checkout -q dottofusymlink
rc=0
out="$(bash "$SCRIPT" main 2>"$WORK/dottofusymlink.err")" || rc=$?
if [ "$rc" -ne 0 ]; then ok ".tofu-named symlink: rc non-zero"; else bad ".tofu-named symlink: rc=$rc"; fi
is ".tofu-named symlink: no count on stdout" "" "$out"
if grep -q '::error::' "$WORK/dottofusymlink.err"; then ok ".tofu-named symlink: ::error:: annotation"; else bad ".tofu-named symlink: no ::error::"; fi
git_c checkout -q tfvarssymlink
rc=0
out="$(bash "$SCRIPT" main 2>"$WORK/tfvarssymlink.err")" || rc=$?
if [ "$rc" -ne 0 ]; then ok "tfvars-named symlink: rc non-zero"; else bad "tfvars-named symlink: rc=$rc"; fi
is "tfvars-named symlink: no count on stdout" "" "$out"
if grep -q '::error::' "$WORK/tfvarssymlink.err"; then ok "tfvars-named symlink: ::error:: annotation"; else bad "tfvars-named symlink: no ::error::"; fi
for variant in tfsymlink lockfilesymlink dottofujsonsymlink; do
  git_c checkout -q "$variant"
  rc=0
  out="$(bash "$SCRIPT" main 2>"$WORK/$variant.err")" || rc=$?
  if [ "$rc" -ne 0 ]; then ok "$variant: rc non-zero"; else bad "$variant: rc=$rc"; fi
  is "$variant: no count on stdout" "" "$out"
  if grep -q '::error::' "$WORK/$variant.err"; then ok "$variant: ::error:: annotation"; else bad "$variant: no ::error::"; fi
done

# --- (r) a module block in the counted root HCL refuses ----------------------
# A referenced module tree is executed by `tofu` but may be outside the
# counted set; certifying it would be a false UNCHANGED (red-team r5/r5b
# MEDIUM, trust r5b MEDIUM, functional r5b MEDIUM; latent — no module blocks
# in the counted root HCL today). The gate is the block itself, so attached
# `=`, comment-bypassed and `\uNNNN`-escaped sources all refuse; native, JSON
# and `.tofu` HCL are covered, and a non-module `source` does not refuse.
git_c checkout -q modulesrc
rc=0
out="$(bash "$SCRIPT" main 2>"$WORK/modulesrc.err")" || rc=$?
if [ "$rc" -ne 0 ]; then ok "local module source: rc non-zero"; else bad "local module source: rc=$rc"; fi
is "local module source: no count on stdout" "" "$out"
if grep -q '::error::' "$WORK/modulesrc.err"; then ok "local module source: ::error:: annotation"; else bad "local module source: no ::error::"; fi
git_c checkout -q modulesrcjson
rc=0
out="$(bash "$SCRIPT" main 2>"$WORK/modulesrcjson.err")" || rc=$?
if [ "$rc" -ne 0 ]; then ok "JSON local module source: rc non-zero"; else bad "JSON local module source: rc=$rc"; fi
is "JSON local module source: no count on stdout" "" "$out"
if grep -q '::error::' "$WORK/modulesrcjson.err"; then ok "JSON local module source: ::error:: annotation"; else bad "JSON local module source: no ::error::"; fi
for variant in modulesrcattached modulesrccomment modulesrcesc dottofumodule modulecblock moduleattachedlabel modulebom modulejsonsplit dottofujsonmodule moduleleadcomment moduleleadcommentnl moduleclosecomment modulestars modulestarspace modulebomcomment moduleindented modulejsonspaced moduleattr moduleheredocclose; do
  git_c checkout -q "$variant"
  rc=0
  out="$(bash "$SCRIPT" main 2>"$WORK/$variant.err")" || rc=$?
  if [ "$rc" -ne 0 ]; then ok "$variant: rc non-zero"; else bad "$variant: rc=$rc"; fi
  is "$variant: no count on stdout" "" "$out"
  if grep -q '::error::' "$WORK/$variant.err"; then ok "$variant: ::error:: annotation"; else bad "$variant: no ::error::"; fi
done
git_c checkout -q modprose
rc=0
count="$(bash "$SCRIPT" main)" || rc=$?
is "module prose: counted (not refused)" "1" "$count"
is "module prose: rc" "0" "$rc"
git_c checkout -q modulecount
rc=0
count="$(bash "$SCRIPT" main)" || rc=$?
is "module_count local: counted (not refused)" "1" "$count"
is "module_count local: rc" "0" "$rc"
git_c checkout -q ressrc
rc=0
count="$(bash "$SCRIPT" main)" || rc=$?
is "non-module source: counted (not refused)" "1" "$count"
is "non-module source: rc" "0" "$rc"
git_c checkout -q rescomment
rc=0
count="$(bash "$SCRIPT" main)" || rc=$?
is "comment-only source text: counted (not refused)" "1" "$count"
is "comment-only source text: rc" "0" "$rc"
git_c checkout -q resheredoc
rc=0
count="$(bash "$SCRIPT" main)" || rc=$?
is "heredoc source text: counted (not refused)" "1" "$count"
is "heredoc source text: rc" "0" "$rc"
git_c checkout -q behind

# --- (e) wiring --------------------------------------------------------------
# Comment- and continuation-proof pins: a commented-out call line, a second
# `COUNT=` assignment (incl. `export`/`declare`/same-line/`if`), a widened or
# decoy comparison, a `git \`-continued, option-bearing, quoted, aliased or
# multi-line-command-substitution `fetch`, or a shallow checkout with a decoy
# `fetch-depth: 0` must redden (functional r1/r2/r3/r4, red-team
# r1/r2/r3/r4). Backslash continuations are joined and full-line comments
# stripped first, so only ACTIVE code satisfies a pin — an in-string `#` must
# not hide a fetch from the scan (functional r4 LOW).
# The pins below are deliberately exact: a comment mentioning the script, the
# `--depth 1` spelling, or one half of the ci.yml wiring must not satisfy them
# (functional r1 LOWs / red-team r1 MEDIUM-LOW).
PROV="$REPO_ROOT/.github/workflows/provision.yml"
CI="$REPO_ROOT/.github/workflows/ci.yml"
join_continuations() { awk '{ if (sub(/\\$/, "")) printf "%s ", $0; else print }'; }
strip_comments() { sed -E 's/^[[:space:]]*#.*$//'; }
prov_active="$(join_continuations < "$PROV" | strip_comments)"
prov_flat="$(tr '\n' ' ' <<<"$prov_active")"
# Backslash-escaped letters are a bash no-op (`g\it fetch` runs `git fetch`);
# unescape so the pins see through that spelling too (red-team r5c LOW). The
# helper and the scan are functions so the wiring itself is pin-able (trust
# r5c-delta LOW).
unslash() { sed -E 's/\\(.)/\1/g'; }
prov_unslashed="$(unslash <<<"$prov_flat")"
no_fetch_scan() {
  grep -qE "$no_fetch_re" <<<"$prov_active" \
    || grep -qE "$no_fetch_re" <<<"$prov_flat" \
    || grep -qE "$no_fetch_re" <<<"$prov_unslashed"
}
# The verdict pins are scoped to the banner job/step, so a `COUNT=` assignment
# in another job (e.g. the DNS job's list_count) is neither counted nor
# satisfying (red-team r2/r3 MEDIUM).
banner_job="$(awk '/^  visibility-banner:/{f=1; next} f && /^  [a-zA-Z0-9_-]+:$/{f=0} f' "$PROV")"
banner_step="$(awk '/- name: Approval card/{f=1} /- name: Record head SHA/{f=0} f' "$PROV")"
banner_active="$(join_continuations <<<"$banner_step" | strip_comments)"
if [ -n "$banner_job" ] && [ -n "$banner_step" ]; then ok "the banner job and step were located for the scoped pins"; else bad "the banner job/step was not located (pin scope lost)"; fi
call_line='COUNT="$(bash .github/scripts/banner-workflow-diff.sh "$BASE_REF")"'
if [ "$(grep -cF "$call_line" <<<"$banner_active")" = "1" ]; then ok "the banner step calls the diff script (exact active call line)"; else bad "the banner step call line is missing, duplicated, or only commented"; fi
if [ "$(grep -oF 'COUNT=' <<<"$banner_active" | grep -c .)" = "1" ]; then ok "COUNT is assigned exactly once in the banner step"; else bad "the banner step has extra COUNT assignments or aliases"; fi
if [ "$(grep -cE 'COUNT[[:space:]]*[+*/%^-]?=' <<<"$banner_active")" = "1" ]; then ok "COUNT is assigned exactly once (space/compound-tolerant spelling)"; else bad "the banner step carries a COUNT assignment beyond the single call line"; fi
override_re="\(\(|(^|[^[:alnum:]_])(export|read|declare|let|unset|readonly|typeset|readarray|mapfile|eval|source)([[:space:]]|$)|(^|[^[:alnum:]_])printf[[:space:]]+[\\]?[\"']?-v|^[[:space:]]*\.[[:space:]]"
if grep -qE "$override_re" <<<"$banner_active"; then bad "the banner step carries a COUNT override form (arithmetic/export/read/declare/let/unset/readonly/typeset/readarray/mapfile/eval/source/printf -v)"; else ok "no COUNT override form in the banner step"; fi
# The shipped check must consume the shared `override_re` (the probes below
# pin its content; this pins the call site — red-team r5f LOW: an inline
# literal minus `[\\]?` at the call site stayed 159/0).
if [ "$(grep -cE '^if grep -qE "[$]override_re" <<<"\$banner_active"; then bad' "$REPO_ROOT/tests/banner-workflow-diff/run-test.sh")" = "1" ]; then
  ok "the shipped override check consumes override_re (the call site is pinned)"
else
  bad "the shipped override check does not consume the shared override_re"
fi
stray_count="$(awk -v call="$call_line" 'index($0, call) { next } /\$\{?COUNT/ { next } /(^|[^[:alnum:]_])COUNT([^[:alnum:]_]|$)/ { print }' <<<"$banner_active")"
if [ -z "$stray_count" ]; then ok "every COUNT mention outside the call line is a read"; else bad "a COUNT mention outside the call line is not a read: $stray_count"; fi
if [ "$(grep -oE '\-eq[[:space:]]+0' <<<"$banner_active" | grep -c .)" = "1" ] && ! grep -qE '\-(ge|gt|le|lt|ne)[[:space:]]' <<<"$banner_active"; then ok "the UNCHANGED branch compares COUNT exactly to 0 (no widened/decoy comparison)"; else bad "the COUNT comparison is missing, widened, or decoyed"; fi
no_fetch_re="(^|[^[:alnum:]_])[\"']?git[\"']?([[:space:]]+[^[:space:];&|]+)*[[:space:]]+[\"']?(fetch|pull)[\"']?"
if no_fetch_scan; then bad "provision.yml still carries a fetch/pull"; else ok "provision.yml carries no fetch/pull (continuation-, option-, quote-, newline-, backslash-splice- and whitespace-tolerant)"; fi
if printf 'git -c protocol.version=2 fetch origin main --depth=1\n' | grep -qE "$no_fetch_re"; then ok "the no-fetch pin matches global-option variants"; else bad "the no-fetch pin misses global-option variants"; fi
if printf 'git \\\nfetch origin main --depth=1\n' | join_continuations | grep -qE "$no_fetch_re"; then ok "the no-fetch pin matches continuation variants"; else bad "the no-fetch pin misses continuation variants"; fi
if printf 'g\\it fetch origin main --depth=1\n' | unslash | grep -qE "$no_fetch_re"; then ok "the no-fetch pin matches backslash-spliced variants"; else bad "the no-fetch pin misses backslash-spliced variants"; fi
no_fetch_saved_active="$prov_active"; no_fetch_saved_flat="$prov_flat"; no_fetch_saved_unslashed="$prov_unslashed"
prov_active=""; prov_flat=""; prov_unslashed='git fetch origin main --depth=1'
if no_fetch_scan; then ok "the no-fetch scan consumes prov_unslashed (the backslash-splice wiring is pinned)"; else bad "the no-fetch scan ignores prov_unslashed"; fi
prov_active="$no_fetch_saved_active"; prov_flat="$no_fetch_saved_flat"; prov_unslashed="$no_fetch_saved_unslashed"
if printf '"git" fetch origin main --depth=1\n' | grep -qE "$no_fetch_re"; then ok "the no-fetch pin matches quoted git"; else bad "the no-fetch pin misses quoted git"; fi
if printf 'git "fetch" origin main --depth=1\n' | grep -qE "$no_fetch_re"; then ok "the no-fetch pin matches quoted fetch"; else bad "the no-fetch pin misses quoted fetch"; fi
if printf 'git pull origin main --depth=1\n' | grep -qE "$no_fetch_re"; then ok "the no-fetch pin matches pull"; else bad "the no-fetch pin misses pull"; fi
if printf 'DECOY="$(git\nfetch origin main --depth=1)"\n' | tr '\n' ' ' | grep -qE "$no_fetch_re"; then ok "the no-fetch pin matches multi-line command substitutions"; else bad "the no-fetch pin misses multi-line command substitutions"; fi
if grep -qE 'alias\.' <<<"$prov_active"; then bad "provision.yml carries a git alias (a fetch can hide behind one)"; else ok "provision.yml carries no git alias"; fi
alias_probe='git -c alias.f=fetch f'
if grep -qE "$no_fetch_re" <<<"$alias_probe" || ! grep -qE 'alias\.' <<<"$alias_probe"; then bad "an alias-spelled fetch would evade the no-fetch pins"; else ok "an alias-spelled fetch is refused by the alias pin"; fi
splice_re='[[:alnum:]_]"{1,2}[[:alnum:]_]'
if grep -qE "$splice_re" <<<"$banner_active"; then bad "the banner step carries a double-quote-spliced identifier (a COUNT override can hide behind one)"; else ok "no double-quote-spliced identifier in the banner step"; fi
if grep -qE "$splice_re" <<<"$prov_active"; then bad "provision.yml carries a double-quote-spliced identifier (a fetch can hide behind one)"; else ok "no double-quote-spliced identifier in provision.yml"; fi
assign_re="=[[:space:]]*[\"']?(fetch|pull)([^[:alnum:]_]|$)"
if grep -qE "$assign_re" <<<"$prov_active"; then bad "provision.yml assigns fetch/pull to a variable (an indirect fetch)"; else ok "provision.yml does not assign fetch/pull to a variable"; fi
if grep -qE "$override_re" <<< 'printf -vCOUNT "%s" 0'; then ok "the override pin matches an attached printf -v target"; else bad "the override pin misses an attached printf -v target"; fi
if grep -qE "$override_re" <<< "printf '-v' COUNT 0"; then ok "the override pin matches a quoted printf -v"; else bad "the override pin misses a quoted printf -v"; fi
if grep -qE "$override_re" <<< 'printf \-v COUNT 0'; then ok "the override pin matches an escaped printf -v"; else bad "the override pin misses an escaped printf -v"; fi
if grep -qE "$override_re" <<< 'export "COU""NT=0"'; then ok "the override pin matches a spliced export"; else bad "the override pin misses a spliced export"; fi
if grep -qE "$override_re" <<< "readonly COU'NT'=0"; then ok "the override pin matches a single-quote-spliced readonly"; else bad "the override pin misses a single-quote-spliced readonly"; fi
if grep -qE "$override_re" <<< 'typeset -n r=COUNT'; then ok "the override pin matches a typeset nameref"; else bad "the override pin misses a typeset nameref"; fi
if grep -qE "$override_re" <<< 'readarray -t COUNT'; then ok "the override pin matches readarray"; else bad "the override pin misses readarray"; fi
if grep -qE "$splice_re" <<< 'COU""NT=0'; then ok "the splice pin matches a spliced identifier"; else bad "the splice pin misses a spliced identifier"; fi
if grep -qE "$assign_re" <<< 'f=fetch; git $f'; then ok "the assignment pin matches a fetch alias"; else bad "the assignment pin misses a fetch alias"; fi
if [ "$(grep -c 'fetch-depth:' <<<"$banner_job")" = "1" ] && grep -q 'fetch-depth: 0' <<<"$banner_job"; then ok "the banner job keeps the single full-history checkout"; else bad "the banner job lost fetch-depth: 0 or gained a decoy"; fi
if grep -qF 'tests/(banner-workflow-diff|' "$CI"; then ok "ci.yml path gate includes the harness"; else bad "ci.yml path gate does not include the harness"; fi
if grep -qF 'bash tests/banner-workflow-diff/run-test.sh' "$CI"; then ok "ci.yml run list includes the harness"; else bad "ci.yml run list does not include the harness"; fi

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
