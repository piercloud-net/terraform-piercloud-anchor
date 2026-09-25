#!/usr/bin/env python3
"""Regenerate shipper_key_vectors.json from the REAL pc-admin key builder.

Dev tool, not run in CI. The harness (`run-test.sh`) loads the checked-in
`shipper_key_vectors.json` and replays every vector against the local replica
(`shipper_keys.py`); this script is how that file is (re)built with real
provenance:

    python3 tests/recording-witness/generate_shipper_vectors.py \
        --pc-admin ../pc-admin          # a checkout whose HEAD is 66bd304

The script refuses to write unless the pc-admin checkout HEAD matches
`shipper_keys.PINNED_PC_ADMIN_SHA` (`--allow-sha-mismatch` only for a manual
debug run — never commit output from a mismatched checkout; the harness
asserts the committed file's `source_sha` starts with the pin, so such a file
fails CI). It imports the real `scripts/lib/b2_client.py`, builds the golden +
boundary matrix through `build_audit_key`, and self-checks that the replica in
this directory reproduces every vector before writing.

The pin is the **grammar-defining SHA**: the builder grammar last changed at
66bd304 and is unchanged through 5580ac0 (pc-admin PR #7 copy re-verified
byte-identical), so regeneration from either checkout yields the identical
`vectors`/`refusals` payload. When pc-admin's grammar changes: bump the pin in
`shipper_keys.py`, regenerate this file against the new SHA, and update the
witness contract + goldens in the same breath.
"""

import argparse
import importlib.util
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from shipper_keys import PINNED_PC_ADMIN_SHA, audit_key  # noqa: E402

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

    refusals = [
        {"name": "seq 0 (real floor is 1; legacy-only fixture)",
         "replica_args": ["session.data", TS, LSID, "0"],
         "why": "build_audit_key emits previous+1, so the shipper cannot produce seq 0"},
        {"name": "seq 10^18 (19 digits, witness naming drift)",
         "replica_args": ["session.data", TS, LSID, str(SEQ_MAX + 1)],
         "why": "the witness accepts [0-9]{1,18}; a 19-digit seq is drift"},
        {"name": "non-UUID sid on session.*",
         "replica_args": ["session.start", TS, "not-a-uuid", "1", ""],
         "why": "the real builder ships a non-UUID sid on the sid-less drift shape"},
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
    ]
    for refusal in refusals:
        try:
            replicate(refusal["replica_args"])
        except ValueError:
            continue
        raise AssertionError("replica unexpectedly accepted refusal vector: %s" % refusal["name"])
    return {
        "pinned_pc_admin_sha": PINNED_PC_ADMIN_SHA,
        "grammar_note": "builder grammar last changed at 66bd304; unchanged through 5580ac0 "
                        "(pc-admin PR #7 copy re-verified byte-identical)",
        "generated_by": "tests/recording-witness/generate_shipper_vectors.py against pc-admin scripts/lib/b2_client.py",
        "vectors": vectors,
        "refusals": refusals,
    }


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
    if not head.startswith(PINNED_PC_ADMIN_SHA) and not args.allow_sha_mismatch:
        raise SystemExit(
            "pc-admin checkout %s is at %s, not the pinned %s; bump the pin deliberately first "
            "(or pass --allow-sha-mismatch for a debug run)" % (repo, head[:12], PINNED_PC_ADMIN_SHA)
        )
    b2 = load_module(os.path.join(repo, "scripts", "lib", "b2_client.py"), "pcadmin_b2_client")
    payload = build_vectors(b2)
    payload["source_sha"] = head
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=False)
        handle.write("\n")
    print("wrote %s (%d vectors, %d refusals) from %s" % (
        args.out, len(payload["vectors"]), len(payload["refusals"]), head[:12]))


if __name__ == "__main__":
    main()
