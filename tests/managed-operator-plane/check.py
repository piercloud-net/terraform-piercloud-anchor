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
full. Any local `uses: ./...` (a reusable workflow or a composite action,
which this pin does not scan) and a `workflow_call` / `workflow_run` /
`repository_dispatch` trigger fail closed anywhere: they let a managed run
execute, or feed, a file the environment checks never see.
Every node must carry a core YAML tag (a `!!binary` or custom tag would hide
expression text from the scan), and `visibility-banner` must have no
`environment` key (the approval card is reviewed before the environment gate).

This is a drift guard over the committed workflow text, not a boundary: the
isolation is GitHub's environment / secret scoping plus the workflow text on
the executed ref, and a change that edits both the workflow and this pin passes
it. PyYAML (YAML 1.1) is not GitHub's parser; a parse difference that splits
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

# Tenant-environment-only names: the lifecycle writes them on the tenant
# environment and they are reserved at repo level (a repo-level value would
# become the per-name fallback for a typo'd environment; disclosed in
# docs/usage.md section 2). Read bare.
TENANT_ONLY = [
    "${{ vars.MANAGED_TENANT }}",
]

# Workflows no managed run can select and that read operator values bare.
# Explicit list, not a structural guess: a new file is checked in full.
OPERATOR_ONLY = {"ci.yml", "external-watch.yml"}

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


def banner_environment(doc):
    """True when jobs.visibility-banner has an `environment` key."""
    if not isinstance(doc, yaml.MappingNode):
        return False
    for key, value in doc.value:
        if key.value == "jobs" and isinstance(value, yaml.MappingNode):
            for jkey, job in value.value:
                if jkey.value == "visibility-banner" and isinstance(job, yaml.MappingNode):
                    if any(k.value.lower() == "environment" for k, _ in job.value):
                        return True
    return False


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


def check_file(path):
    findings = []
    with open(path, "rb") as fh:
        raw = fh.read()
    try:
        docs = list(yaml.compose_all(raw.decode("utf-8"), Loader=yaml.SafeLoader))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        return ["%s: does not parse (%s)" % (path, exc.__class__.__name__)]
    nodes = []
    for doc in docs:
        if doc is None:
            continue
        nodes.extend(scalars(doc, set()))
        for n in all_nodes(doc, set()):
            if n.tag not in CORE_TAGS:
                findings.append("%s:%d: non-core YAML tag %s" % (path, n.start_mark.line + 1, n.tag))
        if banner_environment(doc):
            findings.append("%s: visibility-banner must not select an environment" % path)
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
        for form in ALLOWED:
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
