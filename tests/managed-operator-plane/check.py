"""tests/managed-operator-plane/check.py: issue #198 operator-plane pin.

A managed tenant run selects its own environment, but GitHub falls back to
repository-level values for every name the environment does not define, and
the operator's values live at repository level. So every `secrets` / `vars`
reference in a workflow that a managed run can reach must be one of the exact
gated forms below, which resolve empty (or to a tenant-only name) whenever
`inputs.tenant` is set.

Default-deny, no hand-rolled parsing: PyYAML composes the node graph (every
key and value scalar, duplicate keys and alias targets included), the allowed
expressions are removed as exact literals, and any remaining mention of the
`secrets` or `vars` context (any case, any syntax: dot, index, toJSON) fails.

A workflow may read the operator's values bare only if it is NAMED in
OPERATOR_ONLY and its node graph still has no `environment` key, no `tenant`
key and no `inputs.tenant` reference (any case). Any other file is checked in
full. Every `uses:` value must be one of the exact USES_ALLOWED strings for
its own file (a per-file map, so a mutable-tag action allowed in a release
workflow cannot be added to provision.yml): a
composite action or reusable workflow runs with the calling job's `vars` and
this pin never scans its file, so a new one is a deliberate pin update. Any
local `uses: ./...` also fails, and a `workflow_call` / `workflow_run` /
`repository_dispatch` trigger fail closed anywhere: they let a managed run
execute, or feed, a file the environment checks never see.
Every node must carry a core YAML tag (a `!!binary` or custom tag would hide
expression text from the scan). provision.yml must define the
`visibility-banner` job exactly once, and no `visibility-banner` key in any
workflow may carry an `environment` key (the approval card is reviewed before
the environment gate; a renamed or duplicated banner job fails too).

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
may carry a status-function `if:` (always/failure/cancelled, or a negated
success) that would run it after the banner refused. Probe forms are allowed
only inside that step; bare forms only inside a TENANT_ENV job. YAML anchors
and aliases are refused (a node shared across jobs would carry one job's
allowance into another).

This is a drift guard over the committed workflow text, not a boundary: the
isolation is GitHub's environment / secret scoping plus the workflow text on
the executed ref. A change that edits both the workflow and this pin passes
it, and so does one that drops the ci.yml run step and updates the
broker-provision-dns blob-hash pins in the same PR (a review control).
Residuals: the allowed forms are a set of literals, not bound per name (a
gated name may use another name's gated form; a managed run still resolves
empty); scripts are not scanned (reading repo variables through the API needs
`actions: read`, which no job grants); a new job with a static
`environment:` is judged by the same literal set only. PyYAML (YAML 1.1) is not GitHub's parser; a parse difference that splits
an expression leaves the context word in place and fails closed.

Usage: check.py WORKFLOW_DIR   (exit 0 = pin holds; findings on stdout)
"""

import os
import re
import sys

try:
    import yaml
except ImportError:  # fail closed: the pin must never skip silently
    print("FAIL PyYAML is required (python3-yaml)")
    sys.exit(2)

# Platform-plane values every anchor legitimately shares: the one CloudFront
# distribution's origin secret and the pc-host address (tang firewall source).
# Tenants hold both by design (disclosed: docs/security-posture.md row 3).
SHARED = [
    "${{ secrets.CLOUDFRONT_ORIGIN_SECRET }}",
    "${{ secrets.MAIN_BOX_IPV4 }}",
]

# Tenant-environment-only name: the lifecycle writes it on the tenant
# environment, and it is reserved at repo level (by convention, not enforced) (a repo-level value would
# become the per-name fallback for a typo'd environment; disclosed in
# docs/usage.md section 2). Read bare.
TENANT_ONLY = [
    "${{ vars.MANAGED_TENANT }}",
]

# Workflows no managed run can select and that read operator values bare.
# Explicit list, not a structural guess: a new file is checked in full.
OPERATOR_ONLY = {"ci.yml", "external-watch.yml"}

# Every `uses:` value per workflow file, exactly. A composite action reads the
# calling job's `vars`, and this pin does not scan action files, so any other
# value fails closed. Tenant-reachable files use SHA-pinned actions only; the
# owner's tag-pinned release actions are allowed only in the release workflows
# (which no managed run can select). An unlisted file may use nothing.
CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
UPLOAD = "actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f"
TOFU = "opentofu/setup-opentofu@a1320f892987e89d278cc92dc5adc984fb93aca4"
USES_ALLOWED = {
    "provision.yml": {CHECKOUT, UPLOAD, TOFU},
    "broker-report-selftest.yml": {CHECKOUT},
    "ci.yml": {CHECKOUT, TOFU},
    "external-watch.yml": {CHECKOUT},
    "release.yml": {"cad0p/semver-calver-release/release@v1"},
    "validate-package-version.yml": {"cad0p/semver-calver-release/validate-package-version@v1"},
    "validate-release-pr.yml": {"cad0p/semver-calver-release/validate-release-pr@v1"},
}

CORE_TAGS = {
    "tag:yaml.org,2002:" + t
    for t in ("str", "int", "float", "bool", "null", "map", "seq")
}

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
        "RECORDING_WITNESS_QUIET_SIGNATURE", "RECORDING_WITNESS_COLD_START_SECONDS",
        "RECORDING_WITNESS_SWEEP_SECONDS",
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
STATUS_IF = re.compile(r"(?i)(\b(always|failure|cancelled)\s*\(|!\s*success\s*\()")
# Managed alias = the validated tenant input; managed customer number = the
# tenant-only environment secret (never defined at repo level).
TENANT_FORMS = [
    "${{ inputs.tenant != '' && inputs.tenant || vars.TENANT_USER }}",
    "${{ inputs.tenant != '' && secrets.TENANT_CUSTOMER_NUMBER || inputs.tenant == '' && secrets.CUSTOMER_NUMBER || '' }}",
]
ALLOWED = SHARED + TENANT_ONLY + GATED + TENANT_FORMS

# Any mention of either context as a word, in any case. Over-approximates on
# prose by design: a comment inside a run: block that names the context fails
# and must be reworded (say "secret values", "variables").
CONTEXT = re.compile(r"(?i)(?<![A-Za-z0-9_])(secrets|vars)(?![A-Za-z0-9_])")


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
    steps = [st for seq in mget(banner, "steps") if isinstance(seq, yaml.SequenceNode) for st in seq.value]
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


def node_allowance(doc):
    """id(scalar) -> extra allowed forms by region (no aliases: one path)."""
    extra = {}
    for name, job in jobs_of(doc):
        if is_tenant_env_job(job):
            for n in scalars(job, set()):
                extra[id(n)] = DIRECT
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


def check_file(path):
    findings = []
    with open(path, "rb") as fh:
        raw = fh.read()
    try:
        docs = list(yaml.compose_all(raw.decode("utf-8"), Loader=yaml.SafeLoader))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        return ["%s: does not parse (%s)" % (path, exc.__class__.__name__)]
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
            if not isinstance(v, yaml.ScalarNode) or v.value not in allowed_uses:
                findings.append("%s:%d: `uses:` value not in USES_ALLOWED: %r" % (path, v.start_mark.line + 1, getattr(v, "value", v)))
    texts = [n.value.lower() for n in nodes]
    for n in nodes:
        t = n.value.strip().lower()
        if t in ("workflow_call", "workflow_run", "repository_dispatch"):
            findings.append("%s:%d: %s trigger (reusable/chained workflows are not pinned)" % (path, n.start_mark.line + 1, t))
        if t.startswith("./") or t.startswith(".github/"):
            findings.append("%s:%d: local workflow/action reference %r (not scanned by this pin)" % (path, n.start_mark.line + 1, n.value))
    reachable = any(t in ("environment", "tenant") for t in texts) or any(
        marker in t for t in texts for marker in ("inputs.tenant", "inputs[", "client_payload", "outputs.tenant")
    )
    if os.path.basename(path) in OPERATOR_ONLY:
        if reachable:
            findings.append("%s: listed operator-only but names an environment or a tenant" % path)
        # A managed run can never execute this workflow: its references are
        # the operator's own values by construction.
        return findings
    for node in nodes:
        rest = node.value
        # Longest first: the probe and gated forms embed the bare form.
        for form in sorted(set(ALLOWED + extra.get(id(node), [])), key=len, reverse=True):
            rest = rest.replace(form, "")
        for m in CONTEXT.finditer(rest):
            line = node.start_mark.line + 1
            findings.append(
                "%s:%d: ungated '%s' reference: %r"
                % (path, line, m.group(1), rest[max(0, m.start() - 30) : m.end() + 30].replace("\n", " "))
            )
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
