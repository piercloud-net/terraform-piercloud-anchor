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

A workflow is operator-only, and may read the operator's values bare, only if
its node graph has no `environment` key, no `tenant` key and no `inputs.tenant`
reference: a managed run can never select it.

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
# distribution's origin secret, the pc-host address (tang firewall source),
# and the lifecycle-written environment marker.
SHARED = [
    "${{ secrets.CLOUDFRONT_ORIGIN_SECRET }}",
    "${{ secrets.MAIN_BOX_IPV4 }}",
    "${{ vars.MANAGED_TENANT }}",
]

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
ALLOWED = SHARED + GATED + TENANT_FORMS

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
        if doc is not None:
            nodes.extend(scalars(doc, set()))
    texts = [n.value for n in nodes]
    operator_only = not any(t in ("environment", "tenant") for t in texts) and not any(
        "inputs.tenant" in t for t in texts
    )
    if operator_only:
        # No job can select an environment and nothing names a tenant, so a
        # managed run can never execute this workflow: its references are the
        # operator's own values by construction.
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
        os.path.join(wdir, f) for f in os.listdir(wdir) if f.endswith((".yml", ".yaml"))
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
