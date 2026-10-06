#!/usr/bin/env python3
r"""Regenerate shipper_key_vectors.json from the REAL pc-admin key builder.

Dev tool, not run in CI. The harness (`run-test.sh`) loads the checked-in
`shipper_key_vectors.json` and replays every vector against the local replica
(`shipper_keys.py`); this script is how that file is (re)built with real
provenance:

    python3 tests/recording-witness/generate_shipper_vectors.py \
        --pc-admin ../pc-admin          # a checkout whose HEAD is 25f7922

The script refuses to write unless the pc-admin checkout HEAD is exactly
`shipper_keys.PINNED_PC_ADMIN_SHA` (full 40-hex) **and** the worktree
`scripts/lib/b2_client.py` bytes equal the committed `HEAD:` blob (anchor #155
F1: `git status` is bypassable with `assume-unchanged`/skip-worktree, so the
guard compares content, not status; replacement refs are disabled with
`--no-replace-objects`, since `git replace` can also swap the blob
`cat-file` returns while HEAD is unchanged — the same local-`.git` class). `--allow-sha-mismatch` is a manual debug
run: a non-clean provenance stamps a non-pin `source_sha` (`<head>-debug`), so
a file generated from unpinned bytes can never pass the harness's exact-pin
`source_sha` assertion if it is committed. It imports the real `scripts/lib/b2_client.py`, builds
the golden + boundary matrix through `build_audit_key` and the replay-conflict
variant matrix through `disambiguate_audit_key`, and self-checks that the
replica in this directory reproduces every vector before writing.

The pin is the **grammar-defining SHA**: the builder grammar last changed at
25f7922 (pc-admin #20: the audit-key type regexes are `\Z`-anchored, so a
trailing-newline type such as `user.login\n` is out of grammar and the real
builder sanitizes it to the documented `unknown` non-session shape instead of
building a key with an embedded newline). The previous grammar point was
3325aeb (pc-admin #19: the exact single-segment `session.data` with no
effective strict-UUID sid is sanctioned onto the documented `unknown`
non-session shape instead of the sid-less `session.*` drift shape). Earlier
points: a7035a9 (the replay-conflict variant —
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
import importlib.util
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from shipper_keys import PINNED_PC_ADMIN_SHA, audit_key, disambiguate_key  # noqa: E402

TS = "20260925T100008Z"
EVENT_TIME = "2026-09-25T10:00:08Z"
LSID = "9f8c4b1e-0d2a-4f7e-9c11-2b3d4e5f6a70"
USID = LSID.upper()
SEQ_MAX = 10 ** 18 - 1


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def real_key(b2, event, session_seq=None, global_seq=0, prefix="audit/"):
    key, seq, next_global, sid = b2.build_audit_key(dict(event), dict(session_seq or {}), global_seq, prefix)
    assert not session_seq or next_global == global_seq, "session key must not consume the global counter"
    return key


def build_vectors(b2):
    vectors = []

    def replicate(args):
        # CLI-form args (strings); seq is the 4th positional and the CLI parses it as int.
        args = list(args)
        args[3] = int(args[3])
        return audit_key(*args)

    def vector(name, kind, event, replica_args, session_seq=None, global_seq=0):
        expected = real_key(b2, event, session_seq, global_seq)
        assert replicate(replica_args) == expected, "replica drift at generation time: %s" % name
        vectors.append({
            "name": name,
            "kind": kind,
            "event": event,
            "replica_args": replica_args,
            "expected": expected,
        })

    def variant_vector(name, event, replica_args, body, session_seq=None, global_seq=0):
        # The real replay-conflict builder hashes the local BYTES; the replica
        # hashes the UTF-8 encoding of the same string, so both must agree.
        base = real_key(b2, event, session_seq, global_seq)
        expected = b2.disambiguate_audit_key(base, body.encode("utf-8"))
        assert expected != base, "the real builder did not build a variant for %s" % name
        replica_base = replicate(replica_args)
        assert replica_base == base, "replica drift at generation time: %s" % name
        assert disambiguate_key(replica_base, body) == expected, "replica variant drift: %s" % name
        vectors.append({
            "name": name,
            "kind": "variant",
            "event": event,
            "replica_args": replica_args,
            "body": body,
            "expected": expected,
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
    ]
    for refusal in refusals:
        try:
            replicate(refusal["replica_args"])
        except ValueError:
            continue
        raise AssertionError("replica unexpectedly accepted refusal vector: %s" % refusal["name"])
    return {
        "pinned_pc_admin_sha": PINNED_PC_ADMIN_SHA,
        "grammar_note": "builder grammar last changed at 25f7922 (pc-admin #20: the "
                        "audit-key type regexes are \\Z-anchored, so a trailing-newline "
                        "type is out of grammar and is sanitized to the documented "
                        "`unknown` non-session shape); previous grammar points 3325aeb "
                        "(pc-admin #19: the exact single-segment `session.data` with no "
                        "effective strict-UUID sid is sanctioned onto the documented "
                        "`unknown` non-session shape), a7035a9 (the replay-conflict "
                        "`_<sha256[:16]>` variant keys from disambiguate_audit_key), "
                        "66bd304 (session.rejected sid-less), 929d82c (the 128-char "
                        "pre-hash event-type truncation cap), 41735ff (the `_<sha256[:8]>` "
                        "suffix on the truncated type) and 342a37c (the 10^18-1 seq-ceiling "
                        "clamp in build_audit_key)",
        "generated_by": "tests/recording-witness/generate_shipper_vectors.py against pc-admin scripts/lib/b2_client.py",
        "vectors": vectors,
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
    a commit that must contain it.
    """
    relpath = relpath.replace(os.sep, "/")
    committed = subprocess.run(
        ["git", "-C", repo, "--no-replace-objects", "cat-file", "blob", "HEAD:%s" % relpath],
        capture_output=True)
    if committed.returncode != 0:
        raise SystemExit(
            "pc-admin checkout %s has no %s at HEAD (%s); the pin must name a commit "
            "that contains it" % (repo, relpath,
                                  committed.stderr.decode("utf-8", "replace").strip()))
    try:
        with open(os.path.join(repo, *relpath.split("/")), "rb") as handle:
            worktree = handle.read()
    except OSError as error:
        raise SystemExit("cannot read %s from %s: %s" % (relpath, repo, error))
    return worktree == committed.stdout


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
    # skip-worktree hide a worktree edit from status while the import still
    # reads the mutated bytes.
    content_clean = blob_matches_head(repo, "scripts/lib/b2_client.py")
    if not content_clean and not args.allow_sha_mismatch:
        raise SystemExit(
            "pc-admin checkout %s has scripts/lib/b2_client.py differing from the committed "
            "blob at HEAD; the vectors must come from the committed bytes at the pinned SHA "
            "(git status can be bypassed with assume-unchanged/skip-worktree). "
            "(or pass --allow-sha-mismatch for a debug run)" % repo
        )
    provenance_clean = provenance_clean and content_clean
    b2 = load_module(os.path.join(repo, "scripts", "lib", "b2_client.py"), "pcadmin_b2_client")
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
