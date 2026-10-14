#!/usr/bin/env python3
"""Fixture manifests for tests/gatus-pull (example-style values only).

Usage: fixtures.py tenant <rule> | fixtures.py platform <rule> | fixtures.py rules
The harness pipes the printed JSON into a case's manifest file. Every value is
synthetic; no live tenant, host or token appears here.
"""
import json
import sys

ALIAS = "pier"


def base(**over):
    doc = {
        "version": 1,
        "generated_at": "2026-10-12T07:00:00Z",
        "tenant": ALIAS,
        "note": "example fixture",
        "endpoints": [{"name": "blog", "url": "https://blog-pier.piercloud.site", "alerts": True, "type": "public"}],
    }
    doc.update(over)
    return doc


def entry(**over):
    doc = {"name": "blog", "url": "https://blog-pier.piercloud.site", "alerts": True, "type": "public"}
    doc.update(over)
    return doc


def host_entry(**over):
    doc = {"name": "host-01", "url": "https://host-01.piercloud.net/healthz"}
    doc.update(over)
    return doc


TENANT_RULES = {
    "valid": base(),
    "valid-two": base(endpoints=[
        entry(name="blog"),
        entry(name="jobs", url="https://jobs-pier.piercloud.site/app"),
    ]),
    "http-scheme": base(endpoints=[entry(url="http://blog-pier.piercloud.site")]),
    "port": base(endpoints=[entry(url="https://blog-pier.piercloud.site:8443")]),
    "userinfo": base(endpoints=[entry(url="https://user:pw@blog-pier.piercloud.site")]),
    "foreign-suffix": base(endpoints=[entry(url="https://blog.example.com")]),
    "ip-literal": base(endpoints=[entry(url="https://127.0.0.1/health")]),
    "dollar": base(endpoints=[entry(url="https://blog-pier.piercloud.site/a$b")]),
    "control-char": base(endpoints=[entry(url="https://blog-pier.piercloud.site/a\u0001b")]),
    "space": base(endpoints=[entry(url="https://blog-pier.piercloud.site/a b")]),
    "quote": base(endpoints=[entry(url="https://blog-pier.piercloud.site/a'b")]),
    "backslash": base(endpoints=[entry(url="https://blog-pier.piercloud.site/a\\b")]),
    "query": base(endpoints=[entry(url="https://blog-pier.piercloud.site/a?b=1")]),
    "fragment": base(endpoints=[entry(url="https://blog-pier.piercloud.site/a#b")]),
    "oversize-url": base(endpoints=[entry(url="https://blog-pier.piercloud.site/" + "a" * 220)]),
    "too-many": base(endpoints=[entry(name="s%02d" % i) for i in range(33)]),
    "reserved-platform": base(endpoints=[entry(name="platform")]),
    "reserved-home": base(endpoints=[entry(name="home", type="private", url="https://home-pier.piercloud.net")]),
    "reserved-slice": base(endpoints=[entry(name="slice", url="https://slice-pier.piercloud.site")]),
    "reserved-host": base(endpoints=[entry(name="host-01", type="private", url="https://host-01.piercloud.net/healthz")]),
    "duplicate": base(endpoints=[entry(), entry()]),
    "uppercase-name": base(endpoints=[entry(name="Blog")]),
    "non-bool-alerts": base(endpoints=[entry(alerts="yes")]),
    "bad-version": base(version=2),
    "wrong-tenant": base(tenant="other"),
    "future-generated-at": base(generated_at="2999-01-01T00:00:00Z"),
    "bad-generated-at": base(generated_at="not-a-time"),
    "empty-list": base(endpoints=[]),
    "disabled-with-entries": base(disabled=True),
    "disabled-optout": base(endpoints=[], disabled=True),
    "unknown-top-field": base(class_field="5"),
    "unknown-entry-field": base(endpoints=[entry(class_field="5")]),
    "endpoint-not-object": base(endpoints=["blog"]),
    "endpoints-not-list": base(endpoints={"name": "blog"}),
    "file-scheme": base(endpoints=[entry(url="file:///etc/passwd")]),
    "nested-three-labels": base(endpoints=[entry(type="private", url="https://a.b.c.pier.piercloud.net")]),
    "deep-public": base(endpoints=[entry(url="https://a.b.piercloud.site")]),
    "anchor-name": base(endpoints=[entry(type="private", url="https://anchor-01-pier.piercloud.net/healthz")]),
    "missing-type": base(endpoints=[{key: value for key, value in entry().items() if key != "type"}]),
    "bad-type-value": base(endpoints=[entry(type="internal")]),
    "bad-type-case": base(endpoints=[entry(type="Public")]),
    "bad-type-bool": base(endpoints=[entry(type=True)]),
    "public-nested": base(endpoints=[entry(type="public", url="https://blog.pier.piercloud.net")]),
    "private-flat": base(endpoints=[entry(type="private", url="https://blog-pier.piercloud.site")]),
    "shared-nested": base(endpoints=[entry(name="fantasy", type="shared", url="https://fantasy.pier.piercloud.net")]),
    "disabled-entry": base(endpoints=[entry(name="old-site", type="private",
                                            url="https://old.pier.piercloud.net", disabled=True)]),
}

PLATFORM_RULES = {
    "valid": {
        "version": 1,
        "generated_at": "2026-10-12T07:00:00Z",
        "platform": [{"name": "platform", "url": "https://platform.piercloud.net/healthz"}],
        "hosts": [host_entry()],
    },
    "edge": {
        "version": 1,
        "generated_at": "2026-10-12T07:00:00Z",
        "platform": [{"name": "platform", "url": "https://platform.piercloud.net/healthz"}],
        "hosts": [host_entry()],
        "edge": True,
    },
    "edge-false": {
        "version": 1,
        "generated_at": "2026-10-12T07:00:00Z",
        "hosts": [host_entry()],
        "edge": False,
    },
    "edge-nonbool": {
        "version": 1,
        "generated_at": "2026-10-12T07:00:00Z",
        "hosts": [host_entry()],
        "edge": "yes",
    },
    "edge-disabled-conflict": {
        "version": 1,
        "generated_at": "2026-10-12T07:00:00Z",
        "disabled": True,
        "edge": True,
    },
    "hosts-only": {
        "version": 1,
        "generated_at": "2026-10-12T07:00:00Z",
        "hosts": [host_entry(name="host-02", url="https://host-02.piercloud.net/healthz")],
    },
    "alerts-field": {
        "version": 1,
        "generated_at": "2026-10-12T07:00:00Z",
        "hosts": [host_entry(alerts=True)],
    },
    "foreign-host": {
        "version": 1,
        "generated_at": "2026-10-12T07:00:00Z",
        "hosts": [host_entry(url="https://evil.example.com/healthz")],
    },
    "wrong-path": {
        "version": 1,
        "generated_at": "2026-10-12T07:00:00Z",
        "hosts": [host_entry(url="https://host-01.piercloud.net/health")],
    },
    "name-url-mismatch": {
        "version": 1,
        "generated_at": "2026-10-12T07:00:00Z",
        "hosts": [host_entry(url="https://host-02.piercloud.net/healthz")],
    },
    "bad-name": {
        "version": 1,
        "generated_at": "2026-10-12T07:00:00Z",
        "hosts": [host_entry(name="web-01")],
    },
    "platform-name-mismatch": {
        "version": 1,
        "generated_at": "2026-10-12T07:00:00Z",
        "platform": [{"name": "platform2", "url": "https://platform.piercloud.net/healthz"}],
    },
    "too-many": {
        "version": 1,
        "generated_at": "2026-10-12T07:00:00Z",
        "hosts": [host_entry(name="host-%03d" % i, url="https://host-%03d.piercloud.net/healthz" % i)
                  for i in range(65)],
    },
    "two-platform-rows": {
        "version": 1,
        "generated_at": "2026-10-12T07:00:00Z",
        "platform": [
            {"name": "platform", "url": "https://platform.piercloud.net/healthz"},
            {"name": "platform", "url": "https://platform.piercloud.net/healthz"},
        ],
    },
    "disabled-optout": {
        "version": 1,
        "generated_at": "2026-10-12T07:00:00Z",
        "platform": [],
        "hosts": [],
        "disabled": True,
    },
}


def main():
    if len(sys.argv) == 2 and sys.argv[1] == "rules":
        print(" ".join(sorted(TENANT_RULES)))
        print(" ".join(sorted(PLATFORM_RULES)))
        return 0
    if len(sys.argv) != 3:
        sys.stderr.write(__doc__)
        return 2
    kind, rule = sys.argv[1], sys.argv[2]
    table = TENANT_RULES if kind == "tenant" else PLATFORM_RULES
    if rule not in table:
        sys.stderr.write("unknown rule %s/%s\n" % (kind, rule))
        return 2
    sys.stdout.write(json.dumps(table[rule], sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
