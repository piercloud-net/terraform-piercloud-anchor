"""tests/managed-operator-plane/check.py: issues #198 + #204 operator-plane pin.

A managed tenant run selects its own environment, but GitHub falls back to
repository-level values for every name the environment does not define. So
every `secrets` / `vars` reference in a workflow that a managed run can reach
must be one of the exact allowed forms below: a shared platform-plane name, a
gated form that resolves empty whenever `inputs.tenant` is set (operator-only
names), the TENANT_USER form (the tenant input for a managed run), or (#204,
below) inside a tenant-environment job only, a bare read of a name the banner
proves absent at repository level, `vars.MANAGED_TENANT`, or the
customer-number form.

Default-deny, no hand-rolled parsing: PyYAML composes the node graph (every
key and value scalar, duplicate keys and alias targets included), the allowed
expressions are removed as exact literals, and any remaining mention of the
`secrets` or `vars` context (any case, any syntax: dot, index, toJSON) fails.

A workflow may read the operator's values bare only if it is NAMED in
OPERATOR_ONLY and its node graph names no managed reach at all, in any case:
no `environment` key, no `tenant` key, and none of the markers `inputs.tenant`,
`inputs[`, `client_payload`, `outputs.tenant`. Any other file is checked in
full. Every `uses:` value must be one of the exact USES_ALLOWED strings for
its own file (a per-file map, so a mutable-tag action allowed in a release
workflow cannot be added to provision.yml): a
composite action or reusable workflow runs with the calling job's `vars` and
this pin never scans its file, so a new one is a deliberate pin update. Any
local `uses: ./...` also fails, and a `workflow_call` / `workflow_run` /
`repository_dispatch` trigger fail closed anywhere: they let a managed run
execute, or feed, a file the environment checks never see.
Every node must carry a core YAML tag; an unquoted date composes as the core
`timestamp` tag and is accepted (its text is scanned like any other scalar),
while a `!!binary` or custom tag fails closed (it would hide expression text
from the scan). A file must compose to exactly ONE document: GitHub reads one
and other parsers disagree on the rest, so a second document is reported by
name instead of being scanned silently. provision.yml must define the
`visibility-banner` job exactly once, and no `visibility-banner` key in any
workflow may carry an `environment` key (the approval card is reviewed before
the environment gate; a renamed or duplicated banner job fails too).

PR #201 round 4 (red-team F-1/F-2/R-1/R-3): every `environment:` (job level and
the workflow's own) is a per-file exact allowlist (ENVIRONMENT_ALLOWED), so a
new job cannot name a static environment such as `anchor` (the broker refuses
it, but the pin now refuses the class in-repo); device-flow's gate order is
pinned whole (PINNED_JOBS: `needs:` exactly the banner job, no `if:` at all);
and no job (or workflow) may grant the `actions` scope, whose API reads would
reach a repository-level value a managed run must never see.

Issue #204 (environment-scoped operator values): inside a job whose
`environment:` is exactly the tenant expression (TENANT_ENV), the DIRECT_NAMES
may be read bare (`${{ secrets.X }}` / `${{ vars.X }}`): GitHub resolves the
environment's value first. The #198 leak (a repo-level value falling through
to a tenant) is closed by refusal instead: provision.yml's ungated
`visibility-banner` job carries exactly one step named SCOPE_STEP whose env
holds exactly one presence probe `REPO_SCOPE_<N>: ${{ ctx.N != '' }}` per name
in DIRECT_NAMES plus ENV_ONLY_NAMES (that job selects no environment, so the
probe sees repository/organization scope only), and its body refuses a
managed dispatch on any `true`. The step may carry no `if:` and no
`continue-on-error`; every job that selects TENANT_ENV must reach
`visibility-banner` through its `needs:` closure, and no job in that closure
may carry a status-function `if:` (always/failure/cancelled/success in any
form: an explicit `success() || x` replaces the implicit one) that would run
it after the banner refused. Probe forms are allowed only inside that step;
bare forms, `vars.MANAGED_TENANT` and the customer-number form (which reads
TENANT_CUSTOMER_NUMBER for a managed run) only inside a TENANT_ENV job. YAML
anchors and aliases are refused (a node shared across jobs would carry one
job's allowance into another).

The banner's execution context is pinned too (PR #205 round 1): the
workflow's top-level keys, the banner job's keys and every banner step's
keys are exact allowlists (no `defaults:`, `env:`, `shell:`, `if:`,
`continue-on-error:`, `working-directory:`), and the first two banner steps
are the preflight and the repo-scope check, each pinned whole by a sha256
over [name, sorted env pairs, run] (PINNED_STEPS). A deliberate edit to
either step updates its digest in the same reviewed change.

This is a drift guard over the committed workflow text, not a boundary: the
isolation is GitHub's environment / secret scoping plus the workflow text on
the executed ref. A change that edits both the workflow and this pin passes
it, and so does one that drops the ci.yml run step and updates the
broker-provision-dns blob-hash pins in the same PR (a review control).
The `secrets` / `vars` context scan is expression-scoped: the whole value of
every `if:` key (GitHub evaluates it as an expression, bare or wrapped) and the
text inside a `${{ ... }}` expression are judged; a `run:` line, a shell variable
spelled `vars`, an unquoted date or `run: ./script` is not a false red. A bare
`if:` value is judged as `${{ value }}`, so `if: secrets.X != ''` reds exactly
like `if: ${{ secrets.X != '' }}`; a quoted string such as
`contains('secrets.foo', x)` is not a read (quoted literal bodies are stripped
before the context word is searched). The slice
follows the runner's lexer (actions/runner `TemplateReader.cs`: `'` toggles
in-string, `''` is an escaped quote inside a string, and `}}` closes an
expression only OUTSIDE a string), so a `}}` inside a quoted literal does not
end the expression and hide the rest: `${{ '}}' == 'x' && 1 ||
secrets.NTFY_TOKEN }}` is judged whole. Anything where this scan and GitHub's
parser would diverge fails closed — an opener whose `}}` is not found outside a
string, a string left open to the end of the value (an odd quote count), and a
second `${{` inside a running expression.

The `environment:`, `permissions:` and `if:` pins match their KEY
case-insensitively (`mget_ci`: GitHub's own schema is case-sensitive, so a
`Environment:`/`Permissions:`/`If:` spelling cannot execute — judging it is
consistency with this file's own assumption that case variants are reachable,
never an allowance. A case variant gains no allowance: the tenant-environment
read allowance stays exact, so a case-variant environment job reds on its bare
reads). The pinned VALUES stay exact literals.

Every workflow file must declare exactly one workflow-level `permissions:`
mapping: `permission_findings` can only refuse the `actions` scope in a block
that exists, so an undeclared workflow would inherit the repository/org
default token scopes without any pin edit. All seven workflows declare one
(the pin fails closed if a new file does not).

Residuals: the allowed forms are a set of literals, not bound per name (a
gated name may use another name's gated form; a managed run still resolves
empty) — the per-name binding is disclosed, not closed; scripts are not
scanned — reading repo variables through the API needs `actions: read`, no
declared `permissions:` block at job or workflow level may grant it, and every
workflow must declare one, so the route needs a reviewed pin edit (both the
scope refusal and the declaration);
repository-level `MANAGED_TENANT` / `TENANT_CUSTOMER_NUMBER` are refused by
the banner's repo-scope step, not by a repo-level name check (that check lives
in the pc-lifecycle verify run and needs API credentials, so it is disclosed
here rather than duplicated); a job outside TENANT_ENV may use only the global
forms: the shared names, the run-scoped GITHUB_TOKEN, the gated forms (empty
for a managed run) and the TENANT_USER form (the tenant input for a managed
run). PyYAML (YAML 1.1) is not GitHub's parser; a parse
difference that splits an expression leaves the context word in place and
fails closed.

Usage: check.py WORKFLOW_DIR   (exit 0 = pin holds; findings on stdout)
"""

import hashlib
import json
import os
import re
import sys

try:
    import yaml
except ImportError:  # fail closed: the pin must never skip silently
    print("FAIL PyYAML is required (python3-yaml)")
    sys.exit(2)

# Platform-plane values every anchor legitimately shares: the pc-host address
# (tang firewall source). Tenants hold it by design. The CloudFront origin
# secret was retired from the anchor path by #202 (origin mTLS gates the edge),
# so it is no longer an allowed value anywhere in the workflows.
SHARED = [
    "${{ secrets.MAIN_BOX_IPV4 }}",
]

# Tenant-environment-only name: the lifecycle writes it on the tenant
# environment, and a repo-level copy would become the per-name fallback for a
# typo'd environment, so the repo-scope step refuses one (#204). Read bare,
# and allowed only inside a TENANT_ENV job (node_allowance).
TENANT_ONLY = ["${{ vars.MANAGED_TENANT }}"]

# Workflows no managed run can select and that read operator values bare.
# Explicit list, not a structural guess: a new file is checked in full.
OPERATOR_ONLY = {"ci.yml", "external-watch.yml"}

# Every `uses:` value per workflow file, exactly. A composite action reads the
# calling job's `vars`, and this pin does not scan action files, so any other
# value fails closed. Tenant-reachable files use SHA-pinned actions only; the
# owner's release actions are allowed (pinned to a commit SHA, `# v1`) only in the release workflows
# (which no managed run can select). An unlisted file may use nothing.
CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
UPLOAD = "actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f"
TOFU = "opentofu/setup-opentofu@a1320f892987e89d278cc92dc5adc984fb93aca4"
USES_ALLOWED = {
    "provision.yml": {CHECKOUT, UPLOAD, TOFU},
    "broker-report-selftest.yml": {CHECKOUT},
    "ci.yml": {CHECKOUT, TOFU},
    "external-watch.yml": {CHECKOUT},
    "release.yml": {"cad0p/semver-calver-release/release@b57af46335825afcbf8173a9fa0a32dbee8d1a01"},
    "validate-package-version.yml": {"cad0p/semver-calver-release/validate-package-version@b57af46335825afcbf8173a9fa0a32dbee8d1a01"},
    "validate-release-pr.yml": {"cad0p/semver-calver-release/validate-release-pr@b57af46335825afcbf8173a9fa0a32dbee8d1a01"},
}

CORE_TAGS = {
    "tag:yaml.org,2002:" + t
    for t in ("str", "int", "float", "bool", "null", "map", "seq", "timestamp")
}

# A per-run auto-secret: the runner mints it for every job, so no repository
# value can fall through to a managed run. Read bare anywhere (a legitimately
# spelled `secrets.GITHUB_TOKEN` was a false red while it was not listed).
RUN_SCOPED = ["${{ secrets.GITHUB_TOKEN }}"]

# Operator-plane and per-anchor names: a managed run resolves ''.
GATED_NAMES = {
    "secrets": [
        "ANCHOR_IPV4", "SCP_USER_ID", "ANCHOR_ROOT_PASSWORD", "GATUS_ENDPOINTS",
        "NTFY_TOPIC", "NTFY_TOKEN", "CF_AOP_CA_PEM",
        "RECORDING_WITNESS_ENDPOINT", "RECORDING_WITNESS_BUCKET",
        "RECORDING_WITNESS_AUDIT_PREFIX", "RECORDING_WITNESS_RECORDINGS_PREFIX",
        "RECORDING_WITNESS_KEY_ID", "RECORDING_WITNESS_KEY",
    ],
    "vars": [
        "ANCHOR_ROLE", "STATUS_PULLER", "ORIGIN_CA_CERT_PEM",
        "RECORDING_WITNESS_RENOTIFY_SECONDS", "RECORDING_WITNESS_QUIET_RENOTIFY_SECONDS",
        "RECORDING_WITNESS_QUIET_SIGNATURE", "RECORDING_WITNESS_ACK_IDENTITIES",
        "RECORDING_WITNESS_COLD_START_SECONDS", "RECORDING_WITNESS_SWEEP_SECONDS",
    ],
}
GATED = [
    "${{ inputs.tenant == '' && %s.%s || '' }}" % (ctx, name)
    for ctx, names in GATED_NAMES.items()
    for name in names
]

# Issue #204: the gated names are read bare inside a TENANT_ENV job; the
# banner job probes each one (plus the environment-only names) at repo scope.
TENANT_ENV = "${{ inputs.tenant != '' && inputs.tenant || 'anchor' }}"
DIRECT_NAMES = GATED_NAMES
DIRECT = [
    "${{ %s.%s }}" % (ctx, name)
    for ctx, names in DIRECT_NAMES.items()
    for name in names
]
ENV_ONLY_NAMES = {"secrets": ["TENANT_CUSTOMER_NUMBER"], "vars": ["MANAGED_TENANT"]}
SCOPE_STEP = "Repo-scope check (managed runs read operator-plane values from their environment only)"
PROBES = {
    "REPO_SCOPE_%s" % name: "${{ %s.%s != '' }}" % (ctx, name)
    for table in (DIRECT_NAMES, ENV_ONLY_NAMES)
    for ctx, names in table.items()
    for name in names
}
# Any status function: an explicit `success()` also replaces GitHub's implicit
# one, so `success() || <anything>` runs after the banner refused.
STATUS_IF = re.compile(r"(?i)\b(always|failure|cancelled|success)\s*\(")
PREFLIGHT_STEP = "Managed-input preflight (tenant/anchor_ref — fail closed before any gate)"
# The banner job and its steps: exact key sets. No `defaults:`/`env:` on the
# job (a `shell:` default or BASH_ENV would neuter every step), no `shell:`,
# `if:`, `continue-on-error:` or `working-directory:` on any step.
BANNER_JOB_KEYS = {"name", "runs-on", "outputs", "steps"}
BANNER_STEP_KEYS = {"name", "id", "run", "env", "uses", "with"}
# provision.yml top level: no workflow-wide `defaults:` or `env:`.
WORKFLOW_KEYS = {"name", "run-name", "on", "concurrency", "permissions", "jobs"}
# The first two banner steps (the preflight, then the repo-scope check) are
# pinned whole: sha256 over [name, sorted env pairs, run]. A deliberate edit
# updates the digest here in the same reviewed change (the mismatch message
# prints the new value). Position matters too: no earlier step can write
# GITHUB_ENV / GITHUB_PATH ahead of them.
PINNED_STEPS = [
    (PREFLIGHT_STEP, "a458a87c5a790ee8a3e160dec75d6dc8dda09075d542f6f762fff7de42e7e46a"),
    (SCOPE_STEP, "5e50af2f480c5c7d143cfde241c4a9286a71ed4607afd17353fb4e1503fb962a"),
]
# Managed alias = the validated tenant input: a managed run never reaches the
# TENANT_USER read, so the form is allowed in any job.
TENANT_USER_FORM = "${{ inputs.tenant != '' && inputs.tenant || vars.TENANT_USER }}"
# Managed customer number = the tenant-only TENANT_CUSTOMER_NUMBER, which a
# managed run resolves environment first, then repository level. Allowed only
# inside a TENANT_ENV job (node_allowance): a job outside the banner's needs
# closure would read a repository-level copy before the refusal (round 2).
TENANT_CUSTOMER_FORM = "${{ inputs.tenant != '' && secrets.TENANT_CUSTOMER_NUMBER || inputs.tenant == '' && secrets.CUSTOMER_NUMBER || '' }}"
ALLOWED = SHARED + RUN_SCOPED + GATED + [TENANT_USER_FORM]

# Every job-level and workflow-level `environment:` value per file, exactly. A
# static environment (e.g. `environment: anchor`) is not the tenant
# expression: a managed run would select it while the banner proved only the
# tenant environment's scope (r4 red-team F-1; the broker refuses the write,
# the pin now refuses the class in-repo). A mapping form is not an exact
# literal, so it fails too. An unlisted file may select no environment.
ENVIRONMENT_ALLOWED = {
    "provision.yml": {TENANT_ENV},
    "broker-report-selftest.yml": {"${{ inputs.environment }}"},
}

# Gate order, pinned whole for the job that first selects the tenant
# environment (r4 red-team F-2): it must need the banner job exactly, and it
# must carry no `if:` at all — any replacement condition (a status function or
# not) could let the environment gate run before the banner refused.
PINNED_JOBS = {
    "device-flow": {"needs": ["visibility-banner"], "if": None},
}

# A job (or workflow) that grants the `actions` scope can read repository
# variables and secret values through the API, i.e. around every expression
# gate here (r4 red-team R-1). A scalar form (`read-all` / `write-all`) grants
# it implicitly and fails closed.
FORBIDDEN_PERMISSIONS = {"actions"}

# Any mention of either context as a word, in any case, INSIDE a `${{ ... }}`
# expression or a bare `if:` value (judge() below). Other text is shell/prose:
# a script variable spelled `vars`, a `run: ./script` line and a comment are
# not references.
CONTEXT = re.compile(r"(?i)(?<![A-Za-z0-9_])(secrets|vars)(?![A-Za-z0-9_])")


def expression_end(value, i):
    """Index of the `}}` closing an expression whose body starts at i, or None.

    Mirrors actions/runner's TemplateReader (TemplateReader.cs): a single quote
    toggles in-string, `''` is an escaped quote INSIDE a string, and `}}` closes
    the expression only when not in-string. A string left open, or a second
    `${{` before the closer, means this scan and GitHub's parser disagree about
    where the expression ends: returns None so the caller fails closed.
    """
    in_string = False
    while i < len(value):
        c = value[i]
        if in_string:
            if c == "'":
                if value.startswith("''", i):
                    i += 2
                    continue
                in_string = False
            i += 1
            continue
        if c == "'":
            in_string = True
            i += 1
            continue
        if value.startswith("}}", i):
            return i
        if value.startswith("${{", i):
            return None
        i += 1
    return None


def expressions(value):
    """(list of `${{ ... }}` texts, divergence?) for one scalar value.

    Only expression text is judged. Divergence is True when the slice cannot be
    trusted — no `}}` outside a string, a string left open, or a nested `${{` —
    so the caller fails closed (this scan would not see what GitHub parses).
    """
    out, i = [], 0
    while True:
        start = value.find("${{", i)
        if start < 0:
            return out, False
        end = expression_end(value, start + 3)
        if end is None:
            return out, True
        out.append(value[start : end + 2])
        i = end + 2


def strip_literals(text):
    """`text` with the body of every single-quoted literal removed.

    Mirrors expression_end: a quote opens a string and `''` inside one is an
    escaped quote. The context word in `contains('secrets.foo', x)` sits inside
    a literal, so it is not a read. An unterminated string keeps its remainder
    verbatim, so a word after an open quote is still judged (fail closed).
    """
    out, i, n = [], 0, len(text)
    while i < n:
        if text[i] != "'":
            out.append(text[i])
            i += 1
            continue
        j = i + 1
        while j < n:
            if text[j] == "'":
                if text.startswith("''", j):
                    j += 2
                    continue
                break
            j += 1
        if j >= n:
            out.append(text[i:])
            break
        out.append("''")
        i = j + 1
    return "".join(out)


def wrap_if(value):
    """A bare `if:` value as one `${{ ... }}` expression, or None.

    GitHub evaluates `if:` as an expression, so the whole value is the body.
    A value already wrapped as one expression is unwrapped first. A nested
    opener, or a `}}` closing early outside a string, means this scan and
    GitHub may disagree: None, so the caller fails closed.
    """
    s = value.strip()
    if s.startswith("${{") and expression_end(s, 3) == len(s) - 2:
        s = s[3:-2].strip()
    if "${{" in s:
        return None
    wrapped = "${{ %s }}" % s
    if expression_end(wrapped, 3) != len(wrapped) - 2:
        return None
    return wrapped


def if_values(doc):
    """Value node of every `if:` key (any case) of every mapping in the document."""
    for n in all_nodes(doc, set()):
        if isinstance(n, yaml.MappingNode):
            for k, v in n.value:
                if isinstance(k, yaml.ScalarNode) and k.value.strip().lower() == "if":
                    yield v


def judge(path, node, expr, allowed):
    """Findings for one expression. Allowed forms are removed from the EXACT
    source text first (so `|| 'x'` cannot be stripped into the empty-string
    form), then literal bodies are stripped, then context words are searched.
    """
    rest = expr
    # Longest first: the probe and gated forms embed the bare form.
    for form in sorted(set(ALLOWED + allowed), key=len, reverse=True):
        rest = rest.replace(form, "")
    rest = strip_literals(rest)
    out = []
    for m in CONTEXT.finditer(rest):
        out.append(
            "%s:%d: ungated '%s' reference: %r"
            % (path, node.start_mark.line + 1, m.group(1),
               rest[max(0, m.start() - 30) : m.end() + 30].replace("\n", " "))
        )
    return out


def if_findings(path, ifs, extra):
    """Each `if:` value judged whole as an expression; refusals fail closed."""
    findings = []
    for v in ifs:
        line = v.start_mark.line + 1
        if not isinstance(v, yaml.ScalarNode):
            findings.append("%s:%d: non-scalar `if:` value (refusing: fail closed)" % (path, line))
            continue
        wrapped = wrap_if(v.value)
        if wrapped is None:
            findings.append("%s:%d: `if:` value is not one expression (refusing: fail closed)" % (path, line))
            continue
        findings.extend(judge(path, v, wrapped, extra.get(id(v), [])))
    return findings


def scalars(node, seen):
    """Every scalar node in the graph: mapping keys and values, sequences."""
    if id(node) in seen:
        return
    seen.add(id(node))
    if isinstance(node, yaml.ScalarNode):
        yield node
    elif isinstance(node, yaml.SequenceNode):
        for child in node.value:
            yield from scalars(child, seen)
    elif isinstance(node, yaml.MappingNode):
        for key, value in node.value:
            yield from scalars(key, seen)
            yield from scalars(value, seen)


def banner_jobs(doc):
    """Every value under a `visibility-banner` key of every `jobs` mapping."""
    out = []
    if isinstance(doc, yaml.MappingNode):
        for key, value in doc.value:
            if isinstance(key, yaml.ScalarNode) and key.value == "jobs" and isinstance(value, yaml.MappingNode):
                for jkey, job in value.value:
                    if isinstance(jkey, yaml.ScalarNode) and jkey.value == "visibility-banner":
                        out.append(job)
    return out


def banner_has_environment(job):
    if not isinstance(job, yaml.MappingNode):
        return True  # not a job mapping: fail closed
    return any(isinstance(k, yaml.ScalarNode) and k.value.strip().lower() == "environment" for k, _ in job.value)


def uses_values(node, seen):
    """Value nodes of every mapping key spelled `uses` (any case)."""
    for n in all_nodes(node, seen):
        if isinstance(n, yaml.MappingNode):
            for k, v in n.value:
                if isinstance(k, yaml.ScalarNode) and k.value.strip().lower() == "uses":
                    yield v


def all_nodes(node, seen):
    if id(node) in seen:
        return
    seen.add(id(node))
    yield node
    if isinstance(node, yaml.SequenceNode):
        for child in node.value:
            yield from all_nodes(child, seen)
    elif isinstance(node, yaml.MappingNode):
        for key, value in node.value:
            yield from all_nodes(key, seen)
            yield from all_nodes(value, seen)


def mget(node, key):
    """Every value node under an exact scalar `key` of a mapping node."""
    if not isinstance(node, yaml.MappingNode):
        return []
    return [v for k, v in node.value if isinstance(k, yaml.ScalarNode) and k.value == key]


def mget_ci(node, key):
    """mget with a case-insensitive KEY match (`environment`, `permissions`, `if`).

    GitHub's schema is case-sensitive, so a case variant cannot execute. These
    three locators match it anyway: a case variant must be judged, never
    skipped. It gains no allowance — the tenant-environment read allowance is
    matched exactly — so judging it only ever adds scrutiny (fail closed).
    """
    if not isinstance(node, yaml.MappingNode):
        return []
    return [v for k, v in node.value if isinstance(k, yaml.ScalarNode) and k.value.lower() == key]


def jobs_of(doc):
    """[(name, job node)] for every `jobs` mapping of the document."""
    out = []
    for jobs in mget(doc, "jobs"):
        if isinstance(jobs, yaml.MappingNode):
            out.extend((k.value, v) for k, v in jobs.value if isinstance(k, yaml.ScalarNode))
    return out


def scalar_list(node):
    if isinstance(node, yaml.ScalarNode):
        return [node.value]
    if isinstance(node, yaml.SequenceNode):
        return [c.value for c in node.value if isinstance(c, yaml.ScalarNode)]
    return None


def is_tenant_env_job(job):
    envs = mget(job, "environment")
    return len(envs) == 1 and isinstance(envs[0], yaml.ScalarNode) and envs[0].value == TENANT_ENV


def scope_findings(path, doc):
    """Issue #204 structure: the banner probe step and the needs closure."""
    findings = []
    jobs = jobs_of(doc)
    by_name = {}
    for name, job in jobs:
        by_name.setdefault(name, []).append(job)
    banner = by_name.get("visibility-banner", [])
    if len(banner) != 1:
        return findings  # reported by the banner-count check
    banner = banner[0]
    for key in ("if", "continue-on-error"):
        if mget(banner, key):
            findings.append("%s: visibility-banner must not carry `%s:`" % (path, key))
    wkeys = key_names(doc)
    if wkeys is None or not wkeys <= WORKFLOW_KEYS:
        findings.append("%s: workflow top-level keys must be within %s (got %s)" % (path, sorted(WORKFLOW_KEYS), sorted(wkeys or [])))
    bkeys = key_names(banner)
    if bkeys is None or not bkeys <= BANNER_JOB_KEYS:
        findings.append("%s: visibility-banner keys must be within %s (got %s)" % (path, sorted(BANNER_JOB_KEYS), sorted(bkeys or [])))
    steps = [st for seq in mget(banner, "steps") if isinstance(seq, yaml.SequenceNode) for st in seq.value]
    for i, st in enumerate(steps):
        skeys = key_names(st)
        if skeys is None or not skeys <= BANNER_STEP_KEYS:
            findings.append("%s: visibility-banner step %d keys must be within %s (got %s)" % (path, i + 1, sorted(BANNER_STEP_KEYS), sorted(skeys or [])))
    for i, (want_name, want_digest) in enumerate(PINNED_STEPS):
        got_name = step_name(steps[i]) if i < len(steps) else None
        if got_name != want_name:
            findings.append("%s: visibility-banner step %d must be %r (got %r)" % (path, i + 1, want_name, got_name))
            continue
        got_digest = step_digest(steps[i])
        if got_digest != want_digest:
            findings.append("%s: visibility-banner step %d (%r) changed: digest %s, pinned %s" % (path, i + 1, want_name, got_digest, want_digest))
    scope = [st for st in steps if any(isinstance(n, yaml.ScalarNode) and n.value == SCOPE_STEP for n in mget(st, "name"))]
    if len(scope) != 1:
        findings.append("%s: visibility-banner must carry the repo-scope step exactly once (found %d)" % (path, len(scope)))
    else:
        st = scope[0]
        for key in ("if", "continue-on-error"):
            if mget(st, key):
                findings.append("%s: the repo-scope step must not carry `%s:`" % (path, key))
        envs = mget(st, "env")
        got = {}
        if len(envs) == 1 and isinstance(envs[0], yaml.MappingNode):
            for k, v in envs[0].value:
                if not isinstance(k, yaml.ScalarNode) or not isinstance(v, yaml.ScalarNode) or k.value in got:
                    findings.append("%s: repo-scope env must be unique scalar pairs" % path)
                    continue
                got[k.value] = v.value
        want = dict(PROBES, TENANT_INPUT="${{ inputs.tenant }}")
        if got != want:
            missing = sorted(set(want) - set(got))
            extra = sorted(set(got) - set(want))
            wrong = sorted(k for k in set(got) & set(want) if got[k] != want[k])
            findings.append("%s: repo-scope probes must equal the pinned set (missing %s, extra %s, wrong %s)" % (path, missing, extra, wrong))
        runs = mget(st, "run")
        body = runs[0].value if len(runs) == 1 and isinstance(runs[0], yaml.ScalarNode) else ""
        for needle in ('for v in ${!REPO_SCOPE_@}; do', 'true) found="$found ${v#REPO_SCOPE_}" ;;', 'if [ -n "$found" ]; then'):
            if needle not in body:
                findings.append("%s: repo-scope step body lost %r" % (path, needle))
    # Every TENANT_ENV job reaches the banner through `needs:`, and nothing on
    # that path runs after a failure.
    def needs(job):
        out = []
        for v in mget(job, "needs"):
            lst = scalar_list(v)
            out.extend(lst if lst is not None else ["<non-scalar>"])
        return out
    for name, job in jobs:
        if not is_tenant_env_job(job):
            continue
        seen, todo, reaches = set(), [name], False
        while todo:
            cur = todo.pop()
            if cur in seen:
                continue
            seen.add(cur)
            if cur == "visibility-banner":
                reaches = True
                continue
            cands = by_name.get(cur, [])
            if len(cands) != 1:
                findings.append("%s: job %r in the needs closure of %r is not defined exactly once" % (path, cur, name))
                continue
            for cond in mget(cands[0], "if"):
                if not isinstance(cond, yaml.ScalarNode) or STATUS_IF.search(cond.value):
                    findings.append("%s: job %r (needs closure of %r) carries a status-function `if:`" % (path, cur, name))
            todo.extend(needs(cands[0]))
        if not reaches:
            findings.append("%s: job %r selects the tenant environment but does not need visibility-banner" % (path, name))
    return findings


def key_names(node):
    """Set of scalar mapping keys, or None when not a mapping / a key is not scalar."""
    if not isinstance(node, yaml.MappingNode):
        return None
    keys = set()
    for k, _ in node.value:
        if not isinstance(k, yaml.ScalarNode):
            return None
        keys.add(k.value)
    return keys


def step_name(st):
    names = mget(st, "name")
    return names[0].value if len(names) == 1 and isinstance(names[0], yaml.ScalarNode) else None


def step_digest(st):
    """sha256 over [name, sorted env pairs, run]; None when not plain scalars."""
    if key_names(st) != {"name", "env", "run"}:
        return None
    envs, runs = mget(st, "env"), mget(st, "run")
    if len(envs) != 1 or not isinstance(envs[0], yaml.MappingNode) or len(runs) != 1 or not isinstance(runs[0], yaml.ScalarNode):
        return None
    pairs = []
    for k, v in envs[0].value:
        if not isinstance(k, yaml.ScalarNode) or not isinstance(v, yaml.ScalarNode):
            return None
        pairs.append([k.value, v.value])
    blob = json.dumps([step_name(st), sorted(pairs), runs[0].value], ensure_ascii=True)
    return hashlib.sha256(blob.encode()).hexdigest()


def node_allowance(doc):
    """id(scalar) -> extra allowed forms by region (no aliases: one path)."""
    extra = {}
    for name, job in jobs_of(doc):
        if is_tenant_env_job(job):
            for n in scalars(job, set()):
                extra[id(n)] = DIRECT + TENANT_ONLY + [TENANT_CUSTOMER_FORM]
        if name == "visibility-banner":
            for seq in mget(job, "steps"):
                if not isinstance(seq, yaml.SequenceNode):
                    continue
                for st in seq.value:
                    if any(isinstance(n, yaml.ScalarNode) and n.value == SCOPE_STEP for n in mget(st, "name")):
                        for env in mget(st, "env"):
                            for n in scalars(env, set()):
                                extra[id(n)] = list(PROBES.values())
    return extra


def environment_findings(path, doc):
    """Every `environment:` under a job, and the workflow's own one, is pinned."""
    findings = []
    allowed = ENVIRONMENT_ALLOWED.get(os.path.basename(path), set())
    for name, node in [("<workflow>", doc)] + list(jobs_of(doc)):
        for value in mget_ci(node, "environment"):
            got = value.value if isinstance(value, yaml.ScalarNode) else None
            if got is None or got not in allowed:
                findings.append(
                    "%s: %s environment: %r is not one of the pinned expressions %s"
                    % (path, name, getattr(value, "value", value), sorted(allowed) or "(none for this file)")
                )
    return findings


def job_pin_findings(path, doc):
    """PINNED_JOBS: gate order for the jobs that select the tenant environment."""
    findings = []
    if os.path.basename(path) != "provision.yml":
        return findings
    for name, want in PINNED_JOBS.items():
        jobs = [job for n, job in jobs_of(doc) if n == name]
        if len(jobs) != 1:
            findings.append("%s: pinned job %r must be defined exactly once (found %d)" % (path, name, len(jobs)))
            continue
        needs = []
        for value in mget(jobs[0], "needs"):
            lst = scalar_list(value)
            needs.extend(lst if lst is not None else ["<non-scalar>"])
        if needs != want["needs"]:
            findings.append("%s: job %r needs: must be exactly %r (got %r)" % (path, name, want["needs"], needs))
        conds = [c.value if isinstance(c, yaml.ScalarNode) else None for c in mget_ci(jobs[0], "if")]
        if conds != ([] if want["if"] is None else [want["if"]]):
            findings.append("%s: job %r if: must be exactly %r (got %r)" % (path, name, want["if"], conds))
    return findings


def permission_findings(path, doc):
    """No job, and no workflow, may grant the `actions` scope — and the workflow declares one."""
    findings = []
    declared = mget_ci(doc, "permissions")
    # A block this pin cannot see is a block it cannot refuse: a workflow with
    # no workflow-level `permissions:` inherits the repository/org default token
    # scopes, so `actions: read` could be live while every check here stays
    # green. Every committed workflow declares one; a new file must too.
    if len(declared) != 1 or not isinstance(declared[0], yaml.MappingNode):
        findings.append(
            "%s: <workflow> must declare exactly one workflow-level `permissions:` mapping (no block would inherit the repository default token scopes unscanned)"
            % path
        )
    for name, node in [("<workflow>", doc)] + list(jobs_of(doc)):
        for value in mget_ci(node, "permissions"):
            if not isinstance(value, yaml.MappingNode):
                findings.append(
                    "%s: %s permissions: must be a mapping that does not grant the `actions` scope (got %r)"
                    % (path, name, getattr(value, "value", value))
                )
                continue
            for key, _ in value.value:
                scope = key.value.strip().lower() if isinstance(key, yaml.ScalarNode) else None
                if scope is None or scope in FORBIDDEN_PERMISSIONS:
                    findings.append(
                        "%s: %s permissions: %r is refused — the `actions` scope (and any non-scalar key) can read repository variables through the API"
                        % (path, name, getattr(key, "value", key))
                    )
    return findings


def check_file(path):
    findings = []
    with open(path, "rb") as fh:
        raw = fh.read()
    try:
        docs = list(yaml.compose_all(raw.decode("utf-8"), Loader=yaml.SafeLoader))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        return ["%s: does not parse (%s)" % (path, exc.__class__.__name__)]
    if len(docs) != 1:
        # Fail closed by name: GitHub reads one document and every other
        # parser disagrees about the rest, so a second one is never scanned
        # into a green.
        return ["%s: %d YAML documents — a workflow must be exactly one (refusing)" % (path, len(docs))]
    nodes = []
    extra = {}
    try:
        events = list(yaml.parse(raw.decode("utf-8"), Loader=yaml.SafeLoader))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        return ["%s: does not parse (%s)" % (path, exc.__class__.__name__)]
    for ev in events:
        if isinstance(ev, yaml.AliasEvent) or getattr(ev, "anchor", None) is not None:
            findings.append("%s:%d: YAML anchor/alias (refused: a shared node crosses job allowances)" % (path, ev.start_mark.line + 1))
    for doc in docs:
        if doc is None:
            continue
        nodes.extend(scalars(doc, set()))
        # Only provision.yml carries the banner repo-scope check, so only it
        # may read the direct names bare.
        if os.path.basename(path) == "provision.yml":
            extra.update(node_allowance(doc))
            findings.extend(scope_findings(path, doc))
        findings.extend(environment_findings(path, doc))
        findings.extend(job_pin_findings(path, doc))
        findings.extend(permission_findings(path, doc))
        for n in all_nodes(doc, set()):
            if isinstance(n, yaml.MappingNode):
                keys = [k.value for k, _ in n.value if isinstance(k, yaml.ScalarNode)]
                for dup in sorted({k for k in keys if keys.count(k) > 1}):
                    findings.append("%s:%d: duplicate mapping key %r (parsers disagree on which wins)" % (path, n.start_mark.line + 1, dup))
            if n.tag not in CORE_TAGS:
                findings.append("%s:%d: non-core YAML tag %s" % (path, n.start_mark.line + 1, n.tag))
        banners = banner_jobs(doc)
        if any(banner_has_environment(j) for j in banners):
            findings.append("%s: visibility-banner must not select an environment" % path)
        if os.path.basename(path) == "provision.yml" and len(banners) != 1:
            findings.append("%s: visibility-banner job must be defined exactly once (found %d)" % (path, len(banners)))
        allowed_uses = USES_ALLOWED.get(os.path.basename(path), set())
        for v in uses_values(doc, set()):
            # A `uses:` value is the only place a local reference matters; the
            # same text in a `run:` line (`run: ./script`) is a shell path.
            if isinstance(v, yaml.ScalarNode) and (v.value.startswith("./") or v.value.startswith(".github/")):
                findings.append("%s:%d: local workflow/action reference %r (not scanned by this pin)" % (path, v.start_mark.line + 1, v.value))
            if not isinstance(v, yaml.ScalarNode) or v.value not in allowed_uses:
                findings.append("%s:%d: `uses:` value not in USES_ALLOWED: %r" % (path, v.start_mark.line + 1, getattr(v, "value", v)))
    # A `${{` with no closer is a parse differential whatever the file and
    # whichever branch below judges it: this scan would not see the text
    # GitHub reads as an expression.
    exprs_of = {}
    for n in nodes:
        exprs_of[id(n)] = expressions(n.value)
        if exprs_of[id(n)][1]:
            findings.append(
                "%s:%d: unterminated `${{` expression: this scan cannot see what GitHub parses (fail closed)"
                % (path, n.start_mark.line + 1)
            )
    texts = [n.value.lower() for n in nodes]
    for n in nodes:
        t = n.value.strip().lower()
        if t in ("workflow_call", "workflow_run", "repository_dispatch"):
            findings.append("%s:%d: %s trigger (reusable/chained workflows are not pinned)" % (path, n.start_mark.line + 1, t))
    reachable = any(t in ("environment", "tenant") for t in texts) or any(
        marker in t for t in texts for marker in ("inputs.tenant", "inputs[", "client_payload", "outputs.tenant")
    )
    if os.path.basename(path) in OPERATOR_ONLY:
        if reachable:
            findings.append("%s: listed operator-only but names an environment or a tenant" % path)
        # A managed run can never execute this workflow: its references are
        # the operator's own values by construction.
        return findings
    # A bare `if:` value is judged whole (if_findings); the `${{ }}` scan skips
    # those nodes so no value is judged twice.
    ifs = [v for doc in docs if doc is not None for v in if_values(doc)]
    findings.extend(if_findings(path, ifs, extra))
    if_ids = {id(v) for v in ifs}
    for node in nodes:
        if id(node) in if_ids:
            continue
        for expr in exprs_of[id(node)][0]:
            findings.extend(judge(path, node, expr, extra.get(id(node), [])))
    return findings


def main():
    wdir = sys.argv[1]
    files = sorted(
        os.path.join(wdir, f) for f in os.listdir(wdir) if f.lower().endswith((".yml", ".yaml"))
    )
    if not files:
        print("FAIL no workflow files under %s" % wdir)
        return 2
    findings = []
    for path in files:
        if os.path.islink(path) or not os.path.isfile(path):
            findings.append("%s: not a regular file" % path)
            continue
        findings.extend(check_file(path))
    for f in findings:
        print(f)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
