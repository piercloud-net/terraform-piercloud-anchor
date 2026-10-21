#!/usr/bin/env bash
# tests/provider-stopgap/run-test.sh — the temporary patched-provider step
# (issue #218, upstream rixlhq/terraform-provider-netcup PR #47).
#
# The step downloads a checksummed build of the community provider with the
# empty-array-as-map tolerance and installs it through `dev_overrides` for
# plan/apply only. The properties below are load-bearing; a silent regression in
# any of them is a security or correctness bug, so each is pinned here.
#
# Assertions read the workflow through a YAML parser, never through greps over
# raw text: a comment can satisfy a grep (review red-team m7/m9), it cannot
# satisfy a parsed key. The one property a static check cannot prove — that the
# digest mismatch really aborts — is proven by EXECUTING the step's run block
# against a stub `curl` (a `|| true` on the digest line then turns the harness
# red; that mutant stayed green under the old grep tooth).
#
# The tag + commit + digest triple is pinned as ONE record: the URL tag must
# match the tag named in the step comment, and both must match the pinned
# commit/digest. Provenance can therefore not be half-updated, and a stale pair
# fails here instead of in production.
#
# Cred-free, offline: YAML parsing + a stub curl, no network.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WF="$ROOT/.github/workflows/provision.yml"
VERSIONS="$ROOT/versions.tf"

pass=0
fail=0
ok()  { pass=$((pass + 1)); printf 'ok   %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL %s\n' "$1"; }
is()  { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi; }

[ -f "$WF" ] || { echo "FAIL provision.yml not found at $WF"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "FAIL python3 is required"; exit 1; }
python3 -I -B -c 'import yaml' 2>/dev/null || { echo "FAIL PyYAML is required (python3-yaml)"; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# --- pinned provenance record (tag / commit / digest) --------------------------
# Deliberate pin: bumping any one of these without the other two reds this
# harness, and the release's own tag must sit on PATCH_COMMIT (verify with the
# `gh api .../compare/v1.2.1...<tag>` command in the step comment).
PATCH_TAG='v1.2.1-patch.2'
PATCH_COMMIT='2254e9bea19e52ed114e0c2c814767c669d93307'
PATCH_SHA256='b8d3e7ffff2ed01a27ddf9dcc141ca6641e0d79615527dd0aa0977668085bb19'

# --- extract facts from the YAML (no grep: comments cannot satisfy these) -----
python3 - "$WF" "$WORK" <<'PY'
import json, os, re, sys
wf, work = sys.argv[1], sys.argv[2]
raw = open(wf).read()
doc = json.loads(json.dumps(__import__('yaml').safe_load(raw), default=str))

step = None
siblings = []
for job in doc.get('jobs', {}).values():
    steps = job.get('steps') or []
    for i, s in enumerate(steps):
        name = str(s.get('name', ''))
        if name.startswith('Patched netcup provider'):
            step = dict(s)
            step['_index'] = i
            siblings = steps
            break
    if step:
        break

INIT_RE = re.compile(r'(?:^|[;&|]\s*|\s)(tofu|terraform)(\s+-[^\s]+)*\s+init(?:\s|$)')
def inits(steps):
    out = []
    for i, s in enumerate(steps):
        run = str(s.get('run') or '')
        if INIT_RE.search(run):
            out.append({'index': i, 'name': str(s.get('name', ''))})
    return out

facts = {'found': bool(step)}
if step:
    facts.update({
        'name': str(step.get('name', '')),
        'if': str(step.get('if', '')),
        'has_coe': 'continue-on-error' in step,
        'env_keys': sorted((step.get('env') or {}).keys()),
        'url': str((step.get('env') or {}).get('PROVIDER_URL', '')),
        'sha': str((step.get('env') or {}).get('PROVIDER_SHA256', '')),
        'run': str(step.get('run') or ''),
        'index': step['_index'],
        'inits': inits(siblings),
        'plan_index': next((i for i, s in enumerate(siblings)
                            if i > step['_index'] and 'tofu plan' in str(s.get('run') or '')), -1),
        'other_mentions': [str(s.get('name', '')) for i, s in enumerate(siblings)
                           if i != step['_index'] and re.search(
                               r'pc-provider|dev_overrides|TF_CLI_CONFIG_FILE',
                               str(s.get('run') or '') + ' ' + json.dumps(s.get('env') or {}))],
        'same_name_count': sum(1 for s in siblings
                               if str(s.get('name', '')).startswith('Patched netcup provider')),
    })
    # The step's raw comment text (everything between its header and `run: |`),
    # so provenance wording can be checked without trusting the parsed keys.
    start = raw.index('- name: ' + facts['name'])
    end = raw.index('run: |', start)
    facts['comment'] = raw[start:end]

scripts = []
import glob
root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(wf))))
for p in glob.glob(root + '/.github/scripts/*.sh'):
    if INIT_RE.search(open(p).read()):
        scripts.append(p)
facts['script_inits'] = scripts
json.dump(facts, open(work + '/facts.json', 'w'))
PY

f() { python3 -c "import json;d=json.load(open('$WORK/facts.json'));v=d$1;print(json.dumps(v) if isinstance(v,(list,dict)) else v)"; }

if [ "$(f "['found']")" = "True" ]; then
  ok "the stopgap step exists"
else
  bad "the stopgap step is missing — expected a step named 'Patched netcup provider …'"
  printf '\n%s passed, %s failed\n' "$pass" "$fail"
  exit 1
fi

# --- structure ---------------------------------------------------------------
is "exactly one stopgap step (no second step may re-stage the provider)" "1" "$(f "['same_name_count']")"
is "the step is gated to mode=apply (parsed key, not a comment)" "inputs.mode == 'apply'" "$(f "['if']")"
is "the step has no continue-on-error (a refused download must fail the job)" "False" "$(f "['has_coe']")"
is "the step's env carries exactly the two pins (no credential can be added)" \
   '["PROVIDER_SHA256", "PROVIDER_URL"]' "$(f "['env_keys']")"
is "no other step touches pc-provider/dev_overrides/TF_CLI_CONFIG_FILE" "[]" "$(f "['other_mentions']")"

# --- ordering ----------------------------------------------------------------
inits="$(f "['inits']")"
init_count="$(INITS="$inits" python3 -c 'import json,os;print(len(json.loads(os.environ["INITS"])))')"
is "exactly one tofu/terraform init step in the workflow" "1" "$init_count"
init_idx="$(INITS="$inits" python3 -c 'import json,os;d=json.loads(os.environ["INITS"]);print(d[0]["index"] if d else -1)')"
step_idx="$(f "['index']")"
plan_idx="$(f "['plan_index']")"
if [ "$step_idx" -gt "$init_idx" ] && [ "$init_idx" -ge 0 ]; then
  ok "the stopgap step runs AFTER tofu init"
else
  bad "the stopgap step must run after tofu init (init=$init_idx, step=$step_idx)"
fi
if [ "$plan_idx" -gt "$step_idx" ]; then
  ok "the stopgap step runs BEFORE tofu plan (the override is in effect for the read)"
else
  bad "the stopgap step must run before tofu plan (step=$step_idx, plan=$plan_idx)"
fi
is "no CI-called script invokes tofu/terraform init" "[]" "$(f "['script_inits']")"

# --- the pins ----------------------------------------------------------------
url="$(f "['url']")"
sha="$(f "['sha']")"
comment_file="$WORK/comment.txt"
f "['comment']" > "$comment_file"

if printf '%s' "$sha" | grep -qE '^[0-9a-f]{64}$'; then
  ok "the binary digest is pinned (64 hex)"
else
  bad "PROVIDER_SHA256 must be a pinned 64-hex digest"
fi
case "$url" in
  https://github.com/*/releases/download/"$PATCH_TAG"/terraform-provider-netcup_"$PATCH_TAG"_linux_amd64)
    ok "the download URL is https, on the pinned release tag, with a matching filename" ;;
  *) bad "the download URL must be https://github.com/…/releases/download/$PATCH_TAG/terraform-provider-netcup_${PATCH_TAG}_linux_amd64 (got: $url)" ;;
esac
is "the pinned digest is the one recorded for this tag" "$PATCH_SHA256" "$sha"

# Provenance triple: the comment must name the same tag and commit the URL pins.
if grep -qF "$PATCH_TAG" "$comment_file"; then
  ok "the step comment names the release tag it downloads"
else
  bad "the step comment must name $PATCH_TAG (the tag the URL downloads)"
fi
if grep -qF "$PATCH_COMMIT" "$comment_file"; then
  ok "the step comment names the build commit (40-hex) that the binary stamps"
else
  bad "the step comment must name the build commit $PATCH_COMMIT"
fi
if grep -qF 'vcs.revision' "$comment_file" && grep -qF "compare/v1.2.1...$PATCH_TAG" "$comment_file"; then
  ok "the step comment carries both provenance verification commands"
else
  bad "the step comment must carry the two verification commands (compare/v1.2.1...<tag>, go version -m | grep vcs.revision)"
fi
if grep -q 'BYPASSES the' "$comment_file" && grep -q 'NETCUP_SCP_ACCESS_TOKEN' "$comment_file"; then
  ok "the step discloses the lock-file bypass and the inherited plan/apply token"
else
  bad "the step must disclose that dev_overrides bypasses the lock file and that the binary inherits NETCUP_SCP_ACCESS_TOKEN"
fi

# --- the run block, line by line ---------------------------------------------
f "['run']" > "$WORK/block.sh"
block="$WORK/block.sh"

line_of() { grep -nF -- "$1" "$block" | head -1 | cut -d: -f1 || true; }
digest_line="$(grep -nE 'sha256sum -c' "$block" | head -1 | cut -d: -f1 || true)"
digest_text="$(sed -n "${digest_line}p" "$block" 2>/dev/null || true)"

if [ "$digest_text" = 'printf '"'"'%s  %s\n'"'"' "$PROVIDER_SHA256" "$out" | sha256sum -c - >/dev/null' ]; then
  ok "the digest check is the exact pinned line"
else
  bad "the digest check line changed (got: ${digest_text:-<none>}) — a pin bump must update this tooth"
fi
case "$digest_text" in
  *'||'*|*'&&'*|*';'*) bad "the digest check must not be short-circuited (||, && or ;)" ;;
  *) ok "the digest check has no short-circuit (|| / && / ;)" ;;
esac
if grep -qE '\|\|[[:space:]]*(true|:)[[:space:]]*$|set \+e' "$block"; then
  bad "the run block must not swallow failures (|| true / || : / set +e)"
else
  ok "the run block swallows no failure (|| true / || : / set +e)"
fi

rm_line="$(line_of 'rm -rf "$bin_dir"')"
mkdir_line="$(line_of 'mkdir -p "$bin_dir"')"
if [ -n "$rm_line" ] && [ -n "$mkdir_line" ] && [ "$rm_line" -lt "$mkdir_line" ]; then
  ok "the override directory is emptied before it is populated"
else
  bad "the run block must 'rm -rf \"\$bin_dir\"' before 'mkdir -p' (plan executes whatever sits there)"
fi
if grep -qF 'bin_dir="$RUNNER_TEMP/pc-provider"' "$block"; then
  ok "the override directory lives under \$RUNNER_TEMP (not a shared /tmp path)"
else
  bad "bin_dir must be \"\$RUNNER_TEMP/pc-provider\""
fi
if grep -qE 'curl -fsSL .*--max-time [0-9]+' "$block" && grep -qF -- "--proto '=https'" "$block"; then
  ok "the download fails on HTTP errors, is time-bounded, and is https-only"
else
  bad "curl must use -fsSL, --max-time and --proto '=https'"
fi
if grep -qF 'chmod 0755 "$out"' "$block"; then
  ok "the verified binary is made executable explicitly"
else
  bad "the run block must 'chmod 0755 \"\$out\"'"
fi
if grep -qF 'chmod 0600 "$rc"' "$block"; then
  ok "the CLI config is mode 0600"
else
  bad "the run block must 'chmod 0600 \"\$rc\"' (the config names the override path)"
fi
if grep -qF 'echo "TF_CLI_CONFIG_FILE=$rc" >> "$GITHUB_ENV"' "$block"; then
  ok "the override is exported through \$GITHUB_ENV (later steps only)"
else
  bad "the override must be exported through \$GITHUB_ENV so tofu init never sees it"
fi

# --- the override key must be the provider this module requires --------------
src="$(sed -n 's/.*source[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$VERSIONS" | head -1)"
if [ "$src" = "rixlhq/netcup" ]; then
  ok "required_providers still points at the community provider"
else
  bad "versions.tf must keep source = rixlhq/netcup (the stopgap is not a supply-chain change)"
fi
if grep -qF 'dev_overrides {' "$block"; then
  ok "the CLI config uses dev_overrides (not a filesystem mirror)"
else
  bad "the run block must write a dev_overrides block"
fi
if grep -qF "\"registry.opentofu.org/$src\"" "$block"; then
  ok "the dev_overrides key is the registry address of that exact source"
else
  bad "the dev_overrides key must be \"registry.opentofu.org/$src\" (a mismatch silently does nothing)"
fi

# --- behavioural: run the real block against a stub curl ---------------------
# A static grep cannot tell a verified download from an advisory one; executing
# the block can. Mutating the digest line to `|| true` reds the mismatch case.
run_case() { # $1=name $2=digest-to-present
  local case_dir="$WORK/case-$1"
  mkdir -p "$case_dir/bin" "$case_dir/rt"
  cat > "$case_dir/bin/curl" <<'STUB'
#!/usr/bin/env bash
out=""
while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2 ;; *) shift ;; esac; done
[ -n "$out" ] || exit 2
printf 'stub-provider-bytes' > "$out"
STUB
  chmod +x "$case_dir/bin/curl"
  : > "$case_dir/env"
  env PATH="$case_dir/bin:$PATH" RUNNER_TEMP="$case_dir/rt" GITHUB_ENV="$case_dir/env" \
      PROVIDER_URL="$url" PROVIDER_SHA256="$2" bash "$block" >"$case_dir/out" 2>&1
}
stub_sha="$(printf 'stub-provider-bytes' | sha256sum | cut -d' ' -f1)"
if run_case good "$stub_sha"; then
  ok "the step succeeds on a digest match"
else
  bad "the step failed on a matching digest: $(tail -2 "$WORK/case-good/out")"
fi
case_dir="$WORK/case-good"
bin="$case_dir/rt/pc-provider/terraform-provider-netcup_${PATCH_TAG}"
[ -f "$bin" ] && ok "the verified binary lands at the expected filename" || bad "the binary is not at $bin"
[ "$(stat -c '%a' "$bin" 2>/dev/null)" = "755" ] && ok "the binary is 0755" || bad "the binary mode must be 755"
[ "$(stat -c '%a' "$case_dir/rt/tofurc" 2>/dev/null)" = "600" ] && ok "the CLI config is 0600 in the filesystem" || bad "the CLI config mode must be 600"
grep -qF "TF_CLI_CONFIG_FILE=$case_dir/rt/tofurc" "$case_dir/env" && ok "the export lands in \$GITHUB_ENV" || bad "TF_CLI_CONFIG_FILE was not exported to \$GITHUB_ENV"
grep -qF "registry.opentofu.org/$src" "$case_dir/rt/tofurc" && ok "the written CLI config points the override at that provider" || bad "the written CLI config lacks the dev_overrides entry"

if run_case bad "$(printf '0%.0s' {1..64})"; then
  bad "the step SUCCEEDED on a digest mismatch — the integrity check is advisory"
else
  ok "the step fails closed on a digest mismatch"
fi
if [ -s "$WORK/case-bad/env" ]; then
  bad "a failed download must not export TF_CLI_CONFIG_FILE"
else
  ok "a failed download exports nothing"
fi

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
