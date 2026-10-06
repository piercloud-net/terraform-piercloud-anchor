#!/usr/bin/env python3
r"""Regenerate shipper_key_vectors.json from the REAL pc-admin key builder.

Dev tool, not run in CI. The harness (`run-test.sh`) loads the checked-in
`shipper_key_vectors.json` and replays every vector against the local replica
(`shipper_keys.py`); this script is how that file is (re)built with real
provenance:

    python3 tests/recording-witness/generate_shipper_vectors.py \
        --pc-admin ../pc-admin          # a checkout whose HEAD is 807bfd4

The script refuses to write unless the pc-admin checkout HEAD is exactly
`shipper_keys.PINNED_PC_ADMIN_SHA` (full 40-hex) **and** the worktree
`scripts/lib/b2_client.py` bytes equal the committed `HEAD:` blob (anchor #155
F1: `git status` is bypassable with `assume-unchanged`/skip-worktree, so the
guard compares content, not status; replacement refs are disabled with
`--no-replace-objects`, since `git replace` can also swap the blob
`cat-file` returns while HEAD is unchanged — the same local-`.git` class; and
the compared bytes are compiled directly (`load_module_from_source`), never
imported through `spec_from_file_location`/`exec_module`, which would execute
a planted `__pycache__` entry whose header matches the source — round-2
red-team). `--allow-sha-mismatch` is a manual debug
run: a non-clean provenance stamps a non-pin `source_sha` (`<head>-debug`), so
a file generated from unpinned bytes can never pass the harness's exact-pin
`source_sha` assertion if it is committed. It imports the real `scripts/lib/b2_client.py`, builds
the golden + boundary matrix through `build_audit_key` and the replay-conflict
variant matrix through `disambiguate_audit_key`, pins the optional
`YYYYMMDD/` split through `split_audit_date_segment` (valid/flat/malformed),
and self-checks that the replica in this directory reproduces every vector
before writing. The matrix carries **dated** vectors (the pinned builder's
current output), **flat legacy** vectors (the same real-builder basenames
under the pre-#30 `audit/<basename>` layout, built with the replica's
`flat=True` opt-in), the **range** vectors (the inclusive `-<seq-end>` batched
shape from `build_audit_range_key`, incl. the degenerate `[seq, seq]` and the
18-digit ceiling), and the date-segment vectors.

The pin is the **seq-range grammar** (pc-admin #29: the optional inclusive
`<seq-start>-<seq-end>` token on batched non-lifecycle keys, preserved through
`disambiguate_audit_key`; a range on a lifecycle type, a mode marker on a
range and a reversed range refuse) on top of the **prefix-aware full-key SHA
with anchored key type/full-key regexes**. The layout point before it was
262e98c (pc-admin #30's date-partition squash: `build_audit_key` emits
`audit/YYYYMMDD/<basename>` and `split_audit_date_segment` refuses an
all-digit segment that is not a real 8-digit calendar date). The point before
that was 44cfa8f
(pc-admin #39 r3: the full-key basename regexes are `\Z`-anchored, so a
trailing newline after `.json` refuses the parse and is returned unchanged by
`disambiguate_audit_key` — pre-fix `$` matched before the newline and the
capture-group variant rebuild dropped it; the prefix-aware helpers themselves
landed at 9a2fe50 (pc-admin #39: `split_audit_date_segment`/
`parse_audit_key_full`/`disambiguate_audit_key` take the shipper's configured
`prefix` and refuse a foreign prefix or a residual path segment after the
prefix/day; exactly one leading valid `YYYYMMDD/` is stripped and the
remainder must be a bare basename). The previous grammar point was c0ce2f1 (pc-admin #30:
`build_audit_key` emits `audit/YYYYMMDD/<basename>`
and `split_audit_date_segment` refuses an all-digit segment that is not a real
8-digit calendar date). The point before that was 25f7922 (pc-admin #20:
the audit-key type regexes are `\Z`-anchored, so a trailing-newline type such
as `user.login\n` is out of grammar and the real builder sanitizes it to the
documented `unknown` non-session shape instead of building a key with an
embedded newline). Earlier points: 3325aeb (pc-admin #19: the exact
single-segment `session.data` with no effective strict-UUID sid is sanctioned
onto the documented `unknown` non-session shape instead of the sid-less
`session.*` drift shape), a7035a9 (the replay-conflict variant —
`disambiguate_audit_key` appends `_<sha256[:16]>` to the event type when a
rebuilt file replays a taken key with different bytes), 66bd304 (the
`session.rejected` sid-less fold), 929d82c (the 128-char
pre-hash event-type truncation cap), 41735ff (the `_<sha256[:8]>`
collision-resistant suffix on the truncated type) and 342a37c (the `10^18-1`
seq-ceiling clamp in `build_audit_key`). Because the pin must name the
grammar point, regeneration deliberately requires a checkout at exactly that
SHA — no head chasing. When pc-admin's grammar changes: bump the pin in
`shipper_keys.py` and regenerate this file against the new SHA (a
contract-neutral change needs no witness-contract edit; `unknown` is already
a documented non-session shape), keeping the goldens in step.
"""

import argparse
import json
import os
import subprocess
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from shipper_keys import (PINNED_PC_ADMIN_SHA, SESSION_KEY_PARSE_RE,
                          OTHER_KEY_PARSE_RE, audit_key, disambiguate_key,
                          split_date_segment)  # noqa: E402

TS = "20260925T100008Z"
EVENT_TIME = "2026-09-25T10:00:08Z"
LSID = "9f8c4b1e-0d2a-4f7e-9c11-2b3d4e5f6a70"
USID = LSID.upper()
SEQ_MAX = 10 ** 18 - 1


def worktree_bytes(repo, relpath):
    """The worktree bytes at ``relpath`` (hard error if unreadable)."""
    relpath = relpath.replace(os.sep, "/")
    try:
        with open(os.path.join(repo, *relpath.split("/")), "rb") as handle:
            return handle.read()
    except OSError as error:
        raise SystemExit("cannot read %s from %s: %s" % (relpath, repo, error))


def committed_blob(repo, relpath):
    """The committed ``HEAD:`` blob bytes for ``relpath`` (replacement refs off)."""
    relpath = relpath.replace(os.sep, "/")
    committed = subprocess.run(
        ["git", "-C", repo, "--no-replace-objects", "cat-file", "blob", "HEAD:%s" % relpath],
        capture_output=True)
    if committed.returncode != 0:
        raise SystemExit(
            "pc-admin checkout %s has no %s at HEAD (%s); the pin must name a commit "
            "that contains it" % (repo, relpath,
                                  committed.stderr.decode("utf-8", "replace").strip()))
    return committed.stdout


def load_module_from_source(source, path, name):
    """Execute ``source`` as the module ``name`` — never a cached ``.pyc``.

    ``spec_from_file_location(...).exec_module`` executes a ``__pycache__``
    entry when its header mtime/size match the source, so a stale or planted
    pyc could run while the guard vouched for the pinned source bytes (anchor
    #155 red-team round 2). Compile the exact bytes the caller compared
    against ``HEAD:`` — the compared provenance is the executed provenance.
    """
    module = types.ModuleType(name)
    module.__file__ = path
    exec(compile(source, path, "exec"), module.__dict__)
    return module


def real_key(b2, event, session_seq=None, global_seq=0, prefix="audit/"):
    key, seq, next_global, sid = b2.build_audit_key(dict(event), dict(session_seq or {}), global_seq, prefix)
    assert not session_seq or next_global == global_seq, "session key must not consume the global counter"
    return key


def build_vectors(b2):
    vectors = []
    date_segments = []

    def replicate(args, flat=False, seq_end=None):
        # CLI-form args (strings); seq is the 4th positional and the CLI parses it as int.
        args = list(args)
        args[3] = int(args[3])
        return audit_key(*args, flat=flat, seq_end=seq_end)

    def layout_expected(dated_key, layout):
        # The flat legacy layout is the same real-builder basename under
        # `audit/` (the only difference #30 introduced is the day segment).
        if layout == "dated":
            return dated_key
        assert dated_key.startswith("audit/%s/" % TS[:8]), dated_key
        return "audit/" + dated_key[len("audit/%s/" % TS[:8]):]

    def vector(name, kind, event, replica_args, session_seq=None, global_seq=0, layout="dated"):
        dated_expected = real_key(b2, event, session_seq, global_seq)
        expected = layout_expected(dated_expected, layout)
        assert replicate(replica_args, flat=(layout == "flat")) == expected, \
            "replica drift at generation time: %s" % name
        vectors.append({
            "name": name,
            "kind": kind,
            "layout": layout,
            "event": event,
            "replica_args": replica_args,
            "expected": expected,
        })

    def variant_vector(name, event, replica_args, body, session_seq=None, global_seq=0, layout="dated"):
        # The real replay-conflict builder hashes the local BYTES; the replica
        # hashes the UTF-8 encoding of the same string, so both must agree.
        dated_base = real_key(b2, event, session_seq, global_seq)
        dated_expected = b2.disambiguate_audit_key(dated_base, body.encode("utf-8"))
        expected = layout_expected(dated_expected, layout)
        base = layout_expected(dated_base, layout)
        assert expected != base, "the real builder did not build a variant for %s" % name
        replica_base = replicate(replica_args, flat=(layout == "flat"))
        assert replica_base == base, "replica drift at generation time: %s" % name
        assert disambiguate_key(replica_base, body) == expected, "replica variant drift: %s" % name
        vectors.append({
            "name": name,
            "kind": "variant",
            "layout": layout,
            "event": event,
            "replica_args": replica_args,
            "body": body,
            "expected": expected,
        })

    def range_vector(name, kind, event, replica_args, seq_end, layout="dated"):
        # Real provenance for the batched shape (pc-admin #29): the scope the
        # shipper's batch path extracts (audit_event_scope sanitizes the type
        # and sid exactly like build_audit_key), then build_audit_range_key.
        # The replica builds the same shape through its seq_end opt-in.
        _, sid, event_type, ts, _mode = b2.audit_event_scope(dict(event))
        start = int(replica_args[3])
        dated_expected = b2.build_audit_range_key(event_type, ts, sid, start, int(seq_end))
        expected = layout_expected(dated_expected, layout)
        assert replicate(replica_args, flat=(layout == "flat"), seq_end=int(seq_end)) == expected, \
            "replica range drift at generation time: %s" % name
        vectors.append({
            "name": name,
            "kind": kind,
            "layout": layout,
            "event": event,
            "replica_args": replica_args,
            "seq_end": str(seq_end),
            "expected": expected,
        })

    def variant_range_vector(name, event, replica_args, seq_end, body, layout="dated"):
        # A batched replay-conflict variant keeps the inclusive range token
        # (pc-admin disambiguate_audit_key); the witness canonicalizes the
        # suffix back to the base type and reads the same interval identity.
        _, sid, event_type, ts, _mode = b2.audit_event_scope(dict(event))
        start = int(replica_args[3])
        dated_base = b2.build_audit_range_key(event_type, ts, sid, start, int(seq_end))
        dated_expected = b2.disambiguate_audit_key(dated_base, body.encode("utf-8"))
        expected = layout_expected(dated_expected, layout)
        base = layout_expected(dated_base, layout)
        assert expected != base, "the real builder did not build a range variant for %s" % name
        replica_base = replicate(replica_args, flat=(layout == "flat"), seq_end=int(seq_end))
        assert replica_base == base, "replica range drift at generation time: %s" % name
        assert disambiguate_key(replica_base, body) == expected, \
            "replica range variant drift: %s" % name
        vectors.append({
            "name": name,
            "kind": "variant",
            "layout": layout,
            "event": event,
            "replica_args": replica_args,
            "seq_end": str(seq_end),
            "body": body,
            "expected": expected,
        })

    def segment_vector(name, key, prefix="audit/"):
        # Pin the real builder's prefix-aware optional `YYYYMMDD/` split
        # against the replica: valid dated, flat, malformed-day refusals, and
        # foreign-prefix/residual-segment refusals (custom-prefix cases build
        # with their own prefix so the prefix argument round-trips).
        real = b2.split_audit_date_segment(key, prefix)
        replica_segment = split_date_segment(key, prefix)
        assert replica_segment == real, \
            "replica date-segment drift at generation time: %s (%r != %r)" % (name, replica_segment, real)
        date_segments.append({
            "name": name,
            "key": key,
            "prefix": prefix,
            "relative": real[0],
            "day": real[1],
        })

    vector(
        "session.start shell (live v18 start omits interactive)",
        "golden",
        {"time": EVENT_TIME, "event": "session.start", "sid": LSID},
        ["session.start", TS, LSID, "1", "shell"],
    )
    vector(
        "session.start exec (interactive false)",
        "golden",
        {"time": EVENT_TIME, "event": "session.start", "sid": LSID, "interactive": False},
        ["session.start", TS, LSID, "1", "exec"],
    )
    vector(
        "session.end shell",
        "golden",
        {"time": EVENT_TIME, "event": "session.end", "sid": LSID},
        ["session.end", TS, LSID, "2", "shell"],
        session_seq={LSID: 1},
    )
    vector(
        "session.data (no mode suffix)",
        "golden",
        {"time": EVENT_TIME, "event": "session.data", "sid": LSID},
        ["session.data", TS, LSID, "7"],
        session_seq={LSID: 6},
    )
    vector(
        "session.rejected sid dropped (forced sid-less, global counter)",
        "golden",
        {"time": EVENT_TIME, "event": "session.rejected", "sid": LSID},
        ["session.rejected", TS, USID, "5"],
        global_seq=4,
    )
    vector(
        "uppercase sid lowercased",
        "golden",
        {"time": EVENT_TIME, "event": "session.start", "sid": USID},
        ["session.start", TS, USID, "1", "shell"],
    )
    vector(
        "multi-segment session.* sanitized to unknown, sid dropped",
        "golden",
        {"time": EVENT_TIME, "event": "session.foo.bar", "sid": LSID},
        ["session.foo.bar", TS, "", "1"],
        global_seq=0,
    )
    # pc-admin #19 (@ 3325aeb): the exact single-segment `session.data` with
    # an effective non-strict-UUID sid is sanctioned onto the documented
    # `unknown` non-session shape on the global counter (v18 port-forward
    # traffic accounting); a strict-UUID `session.data` keeps its session key
    # (the golden above).
    vector(
        "sid-less session.data (missing sid) sanitized to unknown",
        "golden",
        {"time": EVENT_TIME, "event": "session.data"},
        ["session.data", TS, "", "1"],
        global_seq=0,
    )
    vector(
        "sid-less session.data (empty-string sid) sanitized to unknown",
        "golden",
        {"time": EVENT_TIME, "event": "session.data", "sid": ""},
        ["session.data", TS, "", "2"],
        global_seq=1,
    )
    vector(
        "sid-less session.data (non-string sid) sanitized to unknown",
        "golden",
        {"time": EVENT_TIME, "event": "session.data", "sid": 42},
        ["session.data", TS, "", "3"],
        global_seq=2,
    )
    # The non-UUID (string) case is two-sided: the replica args carry the raw
    # sid, so a ``not effective_sid`` -> ``not sid`` mutant refuses instead of
    # sanitizing and the vector replay reddens (red-team round-1 MED on #149).
    vector(
        "sid-less session.data (non-UUID sid) sanitized to unknown",
        "golden",
        {"time": EVENT_TIME, "event": "session.data", "sid": "not-a-uuid"},
        ["session.data", TS, "not-a-uuid", "4"],
        global_seq=3,
    )
    vector(
        "non-session event with a sid drops the sid",
        "golden",
        {"time": EVENT_TIME, "event": "user.login", "sid": LSID},
        ["user.login", TS, "", "6"],
        global_seq=5,
    )

    vector(
        "seq lower boundary 1",
        "boundary",
        {"time": EVENT_TIME, "event": "session.data", "sid": LSID},
        ["session.data", TS, LSID, "1"],
    )
    vector(
        "seq 999999 (six digits)",
        "boundary",
        {"time": EVENT_TIME, "event": "session.data", "sid": LSID},
        ["session.data", TS, LSID, "999999"],
        session_seq={LSID: 999998},
    )
    vector(
        "seq 10^6 (seven digits, past the old replica ceiling)",
        "boundary",
        {"time": EVENT_TIME, "event": "session.data", "sid": LSID},
        ["session.data", TS, LSID, "1000000"],
        session_seq={LSID: 999999},
    )
    vector(
        "seq 10^18-1 (witness 18-digit ceiling)",
        "boundary",
        {"time": EVENT_TIME, "event": "session.data", "sid": LSID},
        ["session.data", TS, LSID, str(SEQ_MAX)],
        session_seq={LSID: SEQ_MAX - 1},
    )

    # Cross-repo seed (pc-admin @ 41735ff): the builder caps an over-long event
    # type at 128 chars, drops a trailing separator and appends
    # `_<sha256[:8]>`. The cap keeps B2 keys bounded; the hash keeps distinct
    # over-long types from aliasing to one key (the R5 finding).
    long_type = "z" * 130
    vector(
        "over-long event type truncated below the cap + `_<sha256[:8]>` suffix",
        "boundary",
        {"time": EVENT_TIME, "event": long_type},
        [long_type, TS, "", "1"],
    )
    separator_type = "a" * 118 + "." + "b" * 30
    vector(
        "over-long type truncation drops a trailing separator before the suffix",
        "boundary",
        {"time": EVENT_TIME, "event": separator_type},
        [separator_type, TS, "", "1"],
    )
    alias_a = "z" * 128 + "alpha"
    alias_b = "z" * 128 + "beta"
    vector(
        "over-long type A (shared 119-char head, distinct hash suffix)",
        "boundary",
        {"time": EVENT_TIME, "event": alias_a},
        [alias_a, TS, "", "1"],
    )
    vector(
        "over-long type B (shared 119-char head, distinct hash suffix)",
        "boundary",
        {"time": EVENT_TIME, "event": alias_b},
        [alias_b, TS, "", "1"],
    )
    assert real_key(b2, {"time": EVENT_TIME, "event": alias_a}, None, 0) != real_key(
        b2, {"time": EVENT_TIME, "event": alias_b}, None, 0), \
        "the real builder aliased two distinct over-long event types"
    # Scope edge (pc-admin #19): the sanction is an exact match on the RAW
    # type before the cap, so an over-long non-exact type with a UUID sid is
    # still a session key (truncated type + `_<sha256[:8]>` suffix), exactly
    # like the real builder.
    overlong_session_data = "session.data" + "q" * 500
    vector(
        "over-long non-exact session.data with a UUID sid keeps a truncated session key",
        "boundary",
        {"time": EVENT_TIME, "event": overlong_session_data, "sid": LSID},
        [overlong_session_data, TS, LSID, "1"],
    )

    # Flat legacy layout: the identical real-builder basenames under
    # `audit/<basename>` (the pre-#30 output the dual window still accepts),
    # built by the replica's explicit `flat=True` opt-in. The expected value
    # is derived from the real builder's dated key by removing only the day
    # segment, so the basename grammar keeps real provenance.
    vector(
        "flat legacy session.start shell",
        "flat-legacy",
        {"time": EVENT_TIME, "event": "session.start", "sid": LSID},
        ["session.start", TS, LSID, "1", "shell"],
        layout="flat",
    )
    vector(
        "flat legacy session.data",
        "flat-legacy",
        {"time": EVENT_TIME, "event": "session.data", "sid": LSID},
        ["session.data", TS, LSID, "7"],
        session_seq={LSID: 6},
        layout="flat",
    )
    vector(
        "flat legacy session.rejected sid-less",
        "flat-legacy",
        {"time": EVENT_TIME, "event": "session.rejected", "sid": LSID},
        ["session.rejected", TS, USID, "5"],
        global_seq=4,
        layout="flat",
    )
    vector(
        "flat legacy user.login",
        "flat-legacy",
        {"time": EVENT_TIME, "event": "user.login", "sid": LSID},
        ["user.login", TS, "", "6"],
        global_seq=5,
        layout="flat",
    )
    vector(
        "flat legacy uppercase sid lowercased",
        "flat-legacy",
        {"time": EVENT_TIME, "event": "session.start", "sid": USID},
        ["session.start", TS, USID, "1", "shell"],
        layout="flat",
    )
    variant_vector(
        "flat legacy session.start exec replay-conflict variant",
        {"time": EVENT_TIME, "event": "session.start", "sid": LSID, "interactive": False},
        ["session.start", TS, LSID, "1", "exec"],
        "{\"event\":\"session.start\",\"seq\":1,\"v\":\"replay-flat-start\"}",
        layout="flat",
    )

    # Optional prefix-aware `YYYYMMDD/` split (pc-admin #30 + #39): a valid
    # dated segment is stripped and a flat key is unchanged, but the key must
    # start with the configured prefix and the remainder after the single
    # leading day must be a bare basename — a prefixless key, a session-named
    # or other directory, a second day or a wrong-length date-like segment is
    # refused (never stripped into a flat parse or laundered into a variant).
    segment_vector(
        "valid dated segment stripped",
        "audit/20260925/20260925T100008Z-user.login.000001.json",
    )
    segment_vector(
        "flat key has no day segment",
        "audit/20260925T100008Z-user.login.000001.json",
    )
    segment_vector(
        "prefixless dated key refused (foreign prefix)",
        "20260925/20260925T100008Z-user.login.000001.json",
    )
    segment_vector(
        "calendar-invalid day segment refused (month 09 day 32)",
        "audit/20260932/20260925T100008Z-user.login.000001.json",
    )
    segment_vector(
        "calendar-invalid day segment refused (month 00)",
        "audit/20260000/20260925T100008Z-user.login.000001.json",
    )
    segment_vector(
        "all-zero day segment refused",
        "audit/00000000/20260925T100008Z-user.login.000001.json",
    )
    segment_vector(
        "short numeric day segment refused (never stripped)",
        "audit/2026092/20260925T100008Z-user.login.000001.json",
    )
    segment_vector(
        "long numeric day segment refused (never stripped)",
        "audit/202609251/20260925T100008Z-user.login.000001.json",
    )
    segment_vector(
        "session-named segment refused (residual path segment, not a day)",
        "audit/session.start/20260925T100008Z-user.login.000001.json",
    )
    segment_vector(
        "non-numeric segment refused (residual path segment, not a day)",
        "audit/user.login/20260925T100008Z-user.login.000001.json",
    )
    segment_vector(
        "second day segment refused (only one leading day is stripped)",
        "audit/20260925/20260926/20260925T100008Z-user.login.000001.json",
    )
    segment_vector(
        "wrong-length date-like segment refused (20260925x)",
        "audit/20260925x/20260925T100008Z-user.login.000001.json",
    )
    segment_vector(
        "directory before the day refused (audit/foo/20260925/)",
        "audit/foo/20260925/20260925T100008Z-user.login.000001.json",
    )
    segment_vector(
        "custom prefix valid dated segment stripped",
        "custom/audit/20260925/20260925T100008Z-user.login.000001.json",
        prefix="custom/audit/",
    )
    segment_vector(
        "custom prefix rejects an audit/-prefixed key (foreign prefix)",
        "audit/20260925/20260925T100008Z-user.login.000001.json",
        prefix="custom/audit/",
    )

    # Full-key trailing-newline refusal (pc-admin #39 r3 @ 44cfa8f): both
    # full-key basename regexes are ``\Z``-anchored, so ``…json\n`` refuses
    # the parse and ``disambiguate_audit_key`` returns the key unchanged.
    # Pre-fix ``$`` matched before the newline, the parse succeeded, and the
    # capture-group variant rebuild dropped the newline — laundering a key
    # the witness reads as contract-mismatch/naming-contract drift. Dated,
    # flat and session basenames are all pinned; the replica is asserted to
    # refuse/return-unchanged at generation time too.
    full_key_refusals = []

    def full_key_refusal_vector(name, base_key):
        full = base_key + "\n"
        assert b2.parse_audit_key_full(full) == (None, None), \
            "the real full-key parser accepted a trailing-newline key: %s" % name
        assert b2.disambiguate_audit_key(full, b"x") == full, \
            "the real variant builder laundered a trailing-newline key: %s" % name
        assert b2.split_audit_date_segment(full, "audit/") == split_date_segment(full), \
            "the real date-segment split diverged from the replica on %s" % name
        relative, _ = split_date_segment(full)
        basename = relative[len("audit/"):]
        assert SESSION_KEY_PARSE_RE.match(basename) is None \
            and OTHER_KEY_PARSE_RE.match(basename) is None, \
            "the replica parsed a trailing-newline basename: %s" % name
        assert disambiguate_key(full, b"x") == full, \
            "the replica laundered a trailing-newline key: %s" % name
        full_key_refusals.append({"name": name, "key": full, "prefix": "audit/"})

    full_key_refusal_vector(
        "dated user.login full key with a trailing newline (\\Z full-key anchors)",
        real_key(b2, {"time": EVENT_TIME, "event": "user.login", "sid": LSID}, None, 5),
    )
    full_key_refusal_vector(
        "flat legacy user.login full key with a trailing newline (\\Z full-key anchors)",
        layout_expected(
            real_key(b2, {"time": EVENT_TIME, "event": "user.login", "sid": LSID}, None, 5),
            "flat"),
    )
    full_key_refusal_vector(
        "dated session.start full key with a trailing newline (\\Z full-key anchors)",
        real_key(b2, {"time": EVENT_TIME, "event": "session.start", "sid": LSID}, None, 0),
    )
    full_key_refusal_vector(
        "dated session.data range full key with a trailing newline (\\Z full-key anchors)",
        b2.build_audit_range_key("session.data", TS, LSID, 2, 7),
    )

    # Cross-repo seed (pc-admin @ a7035a9): a rebuilt audit file that replays a
    # taken key with DIFFERENT bytes ships under `disambiguate_audit_key` — the
    # event type gains `_<sha256[:16]>`; a session lifecycle variant drops its
    # mode marker and the sid-less shape keeps the segment count (the hash
    # joins the last type segment). The witness absorbs a variant as the same
    # event identity as its base key; these vectors pin the real builder's
    # variant shape against the replica.
    variant_vector(
        "session.start exec replay-conflict variant (mode marker dropped)",
        {"time": EVENT_TIME, "event": "session.start", "sid": LSID, "interactive": False},
        ["session.start", TS, LSID, "1", "exec"],
        "{\"event\":\"session.start\",\"seq\":1,\"v\":\"replay-start\"}",
    )
    variant_vector(
        "session.end shell replay-conflict variant (mode marker dropped)",
        {"time": EVENT_TIME, "event": "session.end", "sid": LSID},
        ["session.end", TS, LSID, "2", "shell"],
        "{\"event\":\"session.end\",\"seq\":2,\"v\":\"replay-end\"}",
        session_seq={LSID: 1},
    )
    variant_vector(
        "session.rejected sid-less replay-conflict variant (hash joins last segment)",
        {"time": EVENT_TIME, "event": "session.rejected", "sid": LSID},
        ["session.rejected", TS, USID, "5"],
        "{\"event\":\"session.rejected\",\"seq\":5,\"v\":\"replay-rejected\"}",
        global_seq=4,
    )
    variant_vector(
        "user.login replay-conflict variant (hash joins last segment)",
        {"time": EVENT_TIME, "event": "user.login", "sid": LSID},
        ["user.login", TS, "", "6"],
        "{\"event\":\"user.login\",\"seq\":6,\"v\":\"replay-login\"}",
        global_seq=5,
    )
    variant_vector(
        "over-long type truncation variant (truncation suffix kept, conflict suffix appended)",
        {"time": EVENT_TIME, "event": long_type},
        [long_type, TS, "", "1"],
        "{\"event\":\"over-long\",\"seq\":1,\"v\":\"replay-truncated\"}",
    )

    # pc-admin #29 seq-range grammar: the optional inclusive range token on
    # batched (non-lifecycle) keys. The real builder is
    # `build_audit_range_key` (the shipper's batch path feeds it the
    # `audit_event_scope` output); the replica builds the same shape through
    # its `seq_end` opt-in. A one-line batch keeps the legacy single-seq shape
    # (the dual window) and the degenerate `[seq, seq]` range is legal.
    range_vector(
        "session.data range 2-7 (dated)",
        "golden",
        {"time": EVENT_TIME, "event": "session.data", "sid": LSID},
        ["session.data", TS, LSID, "2"],
        "7",
    )
    range_vector(
        "user.login range 3-9 (dated)",
        "golden",
        {"time": EVENT_TIME, "event": "user.login", "sid": LSID},
        ["user.login", TS, "", "3"],
        "9",
    )
    range_vector(
        "session.data degenerate range 5-5 (dual shape)",
        "boundary",
        {"time": EVENT_TIME, "event": "session.data", "sid": LSID},
        ["session.data", TS, LSID, "5"],
        "5",
    )
    range_vector(
        "session.data 18-digit ceiling range 1-10^18-1",
        "boundary",
        {"time": EVENT_TIME, "event": "session.data", "sid": LSID},
        ["session.data", TS, LSID, "1"],
        str(SEQ_MAX),
    )
    range_vector(
        "flat legacy session.data range 2-7",
        "flat-legacy",
        {"time": EVENT_TIME, "event": "session.data", "sid": LSID},
        ["session.data", TS, LSID, "2"],
        "7",
        layout="flat",
    )
    variant_range_vector(
        "session.data range 2-7 replay-conflict variant (range preserved)",
        {"time": EVENT_TIME, "event": "session.data", "sid": LSID},
        ["session.data", TS, LSID, "2"],
        "7",
        "{\"event\":\"session.data\",\"seq\":2,\"v\":\"replay-range\"}",
    )
    variant_range_vector(
        "user.login range 3-9 replay-conflict variant (range preserved)",
        {"time": EVENT_TIME, "event": "user.login", "sid": LSID},
        ["user.login", TS, "", "3"],
        "9",
        "{\"event\":\"user.login\",\"seq\":3,\"v\":\"replay-range-other\"}",
    )

    refusals = [
        {"name": "seq 0 (real floor is 1; legacy-only fixture)",
         "replica_args": ["session.data", TS, LSID, "0"],
         "why": "build_audit_key emits previous+1, so the shipper cannot produce seq 0"},
        {"name": "seq 10^18 (19 digits, witness naming drift)",
         "replica_args": ["session.data", TS, LSID, str(SEQ_MAX + 1)],
         "why": "the witness accepts [0-9]{1,18}; a 19-digit seq is drift"},
        {"name": "non-UUID sid on session.start (only exact session.data is sanctioned)",
         "replica_args": ["session.start", TS, "not-a-uuid", "1", ""],
         "why": "the scoped #19 sanction is the exact session.data type only; the "
                "real builder keeps shipping this on the sid-less drift shape"},
        {"name": "case-variant session.Data with a non-UUID sid (exact match only)",
         "replica_args": ["session.Data", TS, "not-a-uuid", "1", ""],
         "why": "the #19 sanction is case-sensitive on the exact type; the real "
                "builder ships the sid-less drift shape"},
        {"name": "case-variant session.dAtA with a non-UUID sid (exact match only)",
         "replica_args": ["session.dAtA", TS, "not-a-uuid", "1", ""],
         "why": "the #19 sanction is case-sensitive on the exact type; the real "
                "builder ships the sid-less drift shape"},
        {"name": "over-long non-exact session.data type without a sid",
         "replica_args": ["session.data" + "q" * 500, TS, "", "1"],
         "why": "the #19 sanction is exact and runs before the truncation cap; "
                "the capped near-match stays the sid-less drift shape"},
        {"name": "session.start without a sid",
         "replica_args": ["session.start", TS, "", "1", "shell"],
         "why": "a session key needs a strict-UUID sid"},
        {"name": "lifecycle without the mandatory mode",
         "replica_args": ["session.start", TS, LSID, "1", ""],
         "why": "the real builder always emits .shell or .exec on lifecycle keys"},
        {"name": "mode on a non-lifecycle session event",
         "replica_args": ["session.data", TS, LSID, "1", "shell"],
         "why": "the mode suffix is contract-defined on session.start/session.end only"},
        {"name": "mode on a non-session event",
         "replica_args": ["user.login", TS, "", "1", "shell"],
         "why": "non-session events never carry a mode"},
        {"name": "non-session event with a sid",
         "replica_args": ["user.login", TS, LSID, "1", ""],
         "why": "the real builder drops the sid for non-session shapes"},
        {"name": "over-long type outside the grammar",
         "replica_args": ["a" * 128 + "-bad", TS, "", "1"],
         "why": "the real builder sanitizes an invalid type to `unknown`; the "
                "truncation cap applies only to grammar-valid types, so the "
                "replica must refuse the literal shape"},
        # pc-admin #20 (\Z anchors): a trailing newline is outside the type
        # grammar, so the real builder sanitizes it to the documented `unknown`
        # shape and the replica refuses it. The UUID sid on the session.data/
        # session.start cases keeps the refusal regression-sensitive: under a
        # `$` mutant those args would build an embedded-newline key instead of
        # refusing. The trailing-CR and embedded-newline cases are pins that
        # keep refusing under either anchor (a `$` never ignored a trailing
        # CR; position-0 anchoring rejects an embedded newline).
        {"name": "user.login with a trailing newline (\\Z anchors)",
         "replica_args": ["user.login\n", TS, "", "1"],
         "why": "pc-admin #20 \\Z-anchored the type regexes; a trailing newline "
                "is out of grammar and the real builder sanitizes the type to "
                "`unknown`"},
        {"name": "session.data with a trailing newline and a UUID sid (\\Z anchors)",
         "replica_args": ["session.data\n", TS, LSID, "1"],
         "why": "pc-admin #20 \\Z-anchored the type regexes; the real builder "
                "sanitizes the type to `unknown`, never a session key with an "
                "embedded newline"},
        {"name": "session.start with a trailing newline and a UUID sid (\\Z anchors)",
         "replica_args": ["session.start\n", TS, LSID, "1", ""],
         "why": "pc-admin #20 \\Z-anchored the type regexes; the real builder "
                "sanitizes the type to `unknown`, never a key with an embedded "
                "newline"},
        {"name": "session.data with a trailing CR (\\Z anchors; pre-#20 pin)",
         "replica_args": ["session.data\r", TS, "", "1"],
         "why": "already refused before #20 (`$` ignores only a trailing "
                "newline); the \\Z anchor keeps it out of the grammar"},
        {"name": "user.login with an embedded newline (position-0 anchoring pin)",
         "replica_args": ["evil\nuser.login", TS, "", "1"],
         "why": "an embedded newline is out of grammar under any anchor; the "
                "real builder sanitizes the type to `unknown` and the replica "
                "refuses it"},
        # pc-admin #29 range drifts: the real build_audit_range_key refuses the
        # same shapes (asserted below before the replica check).
        {"name": "reversed session range (7-2)",
         "replica_args": ["session.data", TS, LSID, "7"],
         "seq_end": "2",
         "why": "a range is inclusive with seq_end >= seq_start; a reversed "
                "token is drift"},
        {"name": "reversed non-session range (7-2)",
         "replica_args": ["user.login", TS, "", "7"],
         "seq_end": "2",
         "why": "the reversed-range refusal is shape-wide, not session-only"},
        {"name": "range on a lifecycle type (session.end 1-2)",
         "replica_args": ["session.end", TS, LSID, "1"],
         "seq_end": "2",
         "why": "lifecycle events stay one object per event (D1)"},
        {"name": "mode marker on a range (session.data 1-2 shell)",
         "replica_args": ["session.data", TS, LSID, "1", "shell"],
         "seq_end": "2",
         "why": "the mode marker is contract-defined on the single-object "
                "lifecycle keys only (D5)"},
        {"name": "range end beyond the 18-digit ceiling",
         "replica_args": ["user.login", TS, "", "1"],
         "seq_end": str(SEQ_MAX + 1),
         "why": "the witness accepts [0-9]{1,18}; a 19-digit range end is drift"},
    ]
    # Real-builder provenance for the range refusals: build_audit_range_key
    # refuses the same shapes the replica refuses below.
    for real_args in (
            ("session.data", LSID, 7, 2),
            ("user.login", "", 7, 2),
            ("session.end", LSID, 1, 2),
            ("session.data", LSID, 1, 2, "shell"),
            ("user.login", "", 1, SEQ_MAX + 1)):
        try:
            b2.build_audit_range_key(real_args[0], TS, real_args[1], real_args[2],
                                     real_args[3], *(real_args[4:]))
        except ValueError:
            continue
        raise AssertionError("the real range builder accepted a drift shape: %r" % (real_args,))
    for refusal in refusals:
        try:
            replicate(refusal["replica_args"], seq_end=refusal.get("seq_end"))
        except ValueError:
            continue
        raise AssertionError("replica unexpectedly accepted refusal vector: %s" % refusal["name"])
    return {
        "pinned_pc_admin_sha": PINNED_PC_ADMIN_SHA,
        "grammar_note": "builder layout last changed at 807bfd4 (pc-admin #29: the optional "
                        "inclusive seq-range token on batched non-lifecycle keys - "
                        "build_audit_range_key emits `<seq-start>-<seq-end>`, the parser returns "
                        "seq_end, and disambiguate_audit_key preserves the range through the "
                        "replay-conflict variant; a range on a lifecycle type, a mode marker "
                        "on a range and a reversed range refuse); previous grammar point "
                        "262e98c (pc-admin #30's date-partition squash: "
                        "build_audit_key emits `audit/YYYYMMDD/<basename>` from the "
                        "event's UTC day, and split_audit_date_segment refuses an "
                        "all-digit segment that is not a real 8-digit calendar date); "
                        "44cfa8f (pc-admin #39 r3: "
                        "the full-key basename regexes are \\Z-anchored, so a "
                        "trailing-newline key refuses the parse and is returned "
                        "unchanged by disambiguate_audit_key - never laundered "
                        "through the capture-group rebuild; the prefix-aware "
                        "helpers landed at 9a2fe50 (pc-admin #39: "
                        "split_audit_date_segment/parse_audit_key_full/"
                        "disambiguate_audit_key take the configured `prefix` and refuse "
                        "a foreign prefix or a residual path segment after the "
                        "prefix/day - only one leading valid YYYYMMDD/ is stripped and "
                        "the remainder must be a bare basename; disambiguate_audit_key "
                        "keeps the passed prefix and returns the key unchanged on "
                        "refusal)); "
                        "earlier point 25f7922 (pc-admin #20: the audit-key type "
                        "regexes are \\Z-anchored, so a trailing-newline type is out of "
                        "grammar and is sanitized to the documented `unknown` non-session "
                        "shape); earlier points 3325aeb (pc-admin #19: the exact "
                        "single-segment `session.data` with no effective strict-UUID sid "
                        "is sanctioned onto the documented `unknown` non-session shape), "
                        "a7035a9 (the replay-conflict `_<sha256[:16]>` variant keys from "
                        "disambiguate_audit_key), 66bd304 (session.rejected sid-less), "
                        "929d82c (the 128-char pre-hash event-type truncation cap), "
                        "41735ff (the `_<sha256[:8]>` suffix on the truncated type) and "
                        "342a37c (the 10^18-1 seq-ceiling clamp in build_audit_key)",
        "layout_note": "dated vectors are the pinned builder's `audit/YYYYMMDD/<basename>` "
                       "output; flat-legacy vectors are the same real-builder basenames "
                       "under `audit/<basename>` (the dual-window legacy layout, built "
                       "with the replica's explicit flat=True); range vectors carry the "
                       "optional `seq_end` (the inclusive batched token); date_segments "
                       "pins the optional prefix-aware day-segment split (valid dated, "
                       "flat, malformed-date and foreign-prefix/residual-segment "
                       "refusals, custom-prefix positive/negative)",
        "generated_by": "tests/recording-witness/generate_shipper_vectors.py against pc-admin scripts/lib/b2_client.py",
        "vectors": vectors,
        "date_segments": date_segments,
        "full_key_refusals": full_key_refusals,
        "refusals": refusals,
    }


def blob_matches_head(repo, relpath):
    """True iff the worktree bytes at ``relpath`` equal the committed HEAD blob.

    The old ``git status --porcelain`` check is bypassable with
    ``git update-index --assume-unchanged`` (and skip-worktree): the worktree
    bytes change while status stays clean, so the generator would import
    unpinned builder bytes while stamping the pin (anchor #155 F1). Compare
    content instead. ``--no-replace-objects`` closes the sibling bypass: a
    ``git replace`` ref makes ``cat-file blob HEAD:<path>`` return the
    replacement bytes while HEAD (the pin check) is unchanged (anchor #155
    red-team LOW). A path missing from HEAD is a hard error: the pin names
    a commit that must contain it. The caller compiles the same bytes it
    compares (``load_module_from_source``), so a planted ``__pycache__`` entry
    cannot substitute the executed module (anchor #155 red-team round 2).
    """
    return worktree_bytes(repo, relpath) == committed_blob(repo, relpath)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pc-admin", default=os.path.join(HERE, "..", "..", "..", "pc-admin"),
                        help="pc-admin checkout (default: sibling ../pc-admin)")
    parser.add_argument("--out", default=os.path.join(HERE, "shipper_key_vectors.json"))
    parser.add_argument("--allow-sha-mismatch", action="store_true",
                        help="debug only: generate from an unpinned checkout (never commit the result)")
    args = parser.parse_args()

    repo = os.path.abspath(args.pc_admin)
    head = subprocess.run(["git", "-C", repo, "rev-parse", "HEAD"], check=True,
                          capture_output=True, text=True).stdout.strip()
    provenance_clean = head == PINNED_PC_ADMIN_SHA
    if not provenance_clean and not args.allow_sha_mismatch:
        raise SystemExit(
            "pc-admin checkout %s is at %s, not the pinned %s; bump the pin deliberately first "
            "(or pass --allow-sha-mismatch for a debug run)" % (repo, head[:12], PINNED_PC_ADMIN_SHA[:12])
        )
    # A checkout at the pin with a dirty b2_client.py still imports UNPINNED
    # builder bytes while the file would claim the pin (security round-1 LOW
    # on #149). Refuse unless this is an explicit debug run: the pin is a
    # provenance claim about the committed blob, not just the commit id.
    # anchor #155 F1: compare CONTENT, not `git status` — assume-unchanged /
    # skip-worktree hide a worktree edit from status, and `git replace` can
    # swap the blob `cat-file` returns; the compare disables replacement refs.
    # The SAME bytes are then compiled by `load_module_from_source` (never a
    # cached/planted `__pycache__` entry — anchor #155 red-team round 2), so
    # the compared provenance is the executed provenance.
    relpath = "scripts/lib/b2_client.py"
    builder_source = worktree_bytes(repo, relpath)
    content_clean = builder_source == committed_blob(repo, relpath)
    if not content_clean and not args.allow_sha_mismatch:
        raise SystemExit(
            "pc-admin checkout %s has scripts/lib/b2_client.py differing from the committed "
            "blob at HEAD; the vectors must come from the committed bytes at the pinned SHA "
            "(git status can be bypassed with assume-unchanged/skip-worktree, and "
            "git replace with a swapped blob). "
            "(or pass --allow-sha-mismatch for a debug run)" % repo
        )
    provenance_clean = provenance_clean and content_clean
    b2 = load_module_from_source(builder_source, os.path.join(repo, *relpath.split("/")),
                                 "pcadmin_b2_client")
    payload = build_vectors(b2)
    # A debug run (unpinned HEAD or uncommitted builder bytes) must never be
    # committable: stamp a non-pin source_sha so the harness's exact-pin
    # assertion fails closed if the file is ever committed (anchor #155 F1).
    payload["source_sha"] = head if provenance_clean else head + "-debug"
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=False)
        handle.write("\n")
    print("wrote %s (%d vectors, %d refusals) from %s" % (
        args.out, len(payload["vectors"]), len(payload["refusals"]), head[:12]))


if __name__ == "__main__":
    main()
