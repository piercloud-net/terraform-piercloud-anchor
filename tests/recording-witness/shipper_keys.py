#!/usr/bin/env python3
"""Replica of the pc-admin shipper's audit-key grammar (b2_client.build_audit_key).

PINNED AGAINST: cad0p/pc-admin @ 66bd304 (scripts/lib/b2_client.py,
`session_mode` + `build_audit_key`). The golden strings in
tests/recording-witness/run-test.sh were generated from that SHA; a pc-admin
grammar change must bump this pin, regenerate the golden and update the
witness contract in the same breath.

The witness correlates audit events with recordings through object key names, so
harness fixtures MUST be built with the real shipper grammar (6-digit
zero-padded per-session seq, the compile-time timestamp shape, and the
`shell|exec` mode suffix on session.start/session.end only). Hand-written keys
are what let the live-v18 `session.start`-reads-`shell` contract slip past the
harness.

The canonical implementation lives in pc-admin at `scripts/lib/b2_client.py`
(`session_mode` + `build_audit_key`, pinned by pc-admin's own
`tools/tests/test-audit-ship.sh`). CI checks out this repo alone, so this file
is a deliberate replica; when pc-admin's grammar changes, change this file in
the same breath.

Replica rules (deliberately strict — the harness fails loudly instead of
silently building a shape the real shipper never emits, but every shape the
real builder DOES emit on its documented path is reproduced faithfully):

- Only a `session.*` event with a **strict-UUID** sid becomes a session key; a
  non-UUID sid is refused here. (The real builder at the pinned SHA would ship
  it on the sid-less global shape — refuse so a fixture can never pin a shape
  the shipper cannot produce.)
- The sid is **lowercased** exactly like the real builder (`build_audit_key`
  lowercases a strict-UUID sid); the witness groups sessions
  case-insensitively, so an uppercase fixture pins the lowercased key.
- The `shell|exec` mode suffix is lifecycle-only and **mandatory** on
  `session.start`/`session.end` (the real builder always emits `.shell` or
  `.exec`); legacy pre-marker lifecycle keys are not buildable here by design
  — hand-write those drift fixtures.
- A multi-segment `session.*` type is sanitized to `unknown` on the sid-less
  global shape, exactly like the real builder (the witness's session
  classifier is single-segment, so the raw type would read as drift).
- Non-session events never carry a sid (the real builder drops it).
- `session.rejected` is forced to the sid-less non-session shape: the witness
  allowlists it there and the real builder at the pinned SHA (66bd304) drops
  any sid for this type, shipping it under the global counter. A regression to
  the pre-fold sid-bearing shape would be read by the witness as a session
  with no `session.start` (`session-start-missing`), so the replica never
  builds it and the golden/refusal teeth pin that.
- `seq` mirrors the real grammar: the builder emits `previous + 1` (floor 1 —
  seq 0 is legacy-only and must be hand-written) formatted `%06d`, so 7+
  digits are legal past 999999; the ceiling is the witness's `[0-9]{1,18}`
  grammar pc-admin's `SEQ_PATTERN` mirrors.

Golden + boundary vectors are generated from the pinned real builder and
checked in (`shipper_key_vectors.json`, regenerated with
`generate_shipper_vectors.py` against the pc-admin checkout); the harness
replays every vector against this replica, so silent drift fails there.

CLI:  shipper_keys.py <event-type> <ts> [sid] [seq] [mode]
      prints the full audit key (single line).
"""

import re
import sys

PINNED_PC_ADMIN_SHA = "66bd304"

TS_PATTERN = r"^[0-9]{8}T[0-9]{6}Z$"
UUID_PATTERN = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
TS_RE = re.compile(TS_PATTERN)
UUID_RE = re.compile(UUID_PATTERN)
EVENT_TYPE_RE = re.compile(r"^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*$")
SESSION_TYPE_RE = re.compile(r"^session\.[A-Za-z0-9_]+$")
# The real builder emits `%06d` (7+ digits past 999999); the ceiling mirrors
# the witness's `[0-9]{1,18}` grammar that pc-admin's SEQ_PATTERN mirrors.
SEQ_MAX = 10 ** 18 - 1

# Session lifecycle events get the `interactive`-derived mode suffix; every
# other event type never carries one (b2_client.SESSION_MODE_EVENTS).
SESSION_MODE_EVENTS = frozenset({"session.start", "session.end"})
# Teleport v18 emits session.rejected without a session id; the witness
# allowlists it on the sid-less shape (documented, not naming drift).
SID_LESS_SESSION_EVENTS = frozenset({"session.rejected"})


def audit_key(event_type, ts, sid="", seq=1, mode=""):
    """Build one audit object key exactly as pc-admin's shipper does."""
    if not TS_RE.match(ts):
        raise ValueError("timestamp must be YYYYmmddTHHMMSSZ, got %r" % ts)
    if not isinstance(seq, int) or isinstance(seq, bool) or not 1 <= seq <= SEQ_MAX:
        raise ValueError(
            "seq must be >= 1 (the real builder emits previous+1; seq 0 is a "
            "hand-written legacy fixture) and fit the witness's 18-digit grammar, got %r" % (seq,)
        )
    if not EVENT_TYPE_RE.match(event_type):
        raise ValueError("event type outside the shipper grammar: %r" % event_type)
    if event_type.startswith("session.") and not SESSION_TYPE_RE.match(event_type):
        # Multi-segment session.*: the witness's session classifier is
        # single-segment, so the real builder sanitizes the whole type to
        # `unknown` and drops the sid (global shape). Mirror it.
        event_type = "unknown"
        sid = ""
    if sid and not UUID_RE.fullmatch(sid):
        raise ValueError(
            "non-UUID sid %r: the real shipper ships this on the sid-less global shape" % sid
        )
    if sid:
        # The real builder lowercases; the witness groups sessions
        # case-insensitively, so an uppercase fixture pins the lowercased key.
        sid = sid.lower()
    if mode and (mode not in ("shell", "exec") or event_type not in SESSION_MODE_EVENTS):
        raise ValueError("mode %r is only valid on session.start/session.end" % mode)
    if event_type in SESSION_MODE_EVENTS and mode not in ("shell", "exec"):
        raise ValueError(
            "%r requires the mandatory shell|exec mode suffix the real shipper always emits" % event_type
        )
    if event_type in SID_LESS_SESSION_EVENTS:
        # Forced sid-less (module docstring): the real builder at the pinned
        # SHA drops any sid for session.rejected; a sid-bearing key would alert
        # the witness session-start-missing.
        return "audit/%s-%s.%06d.json" % (ts, event_type, seq)
    if SESSION_TYPE_RE.match(event_type):
        if not sid:
            raise ValueError(
                "session.* %r without a sid: the real shipper keeps a session key only for a UUID sid"
                % event_type
            )
        suffix = ".%s" % mode if mode else ""
        return "audit/%s-%s.%s.%06d%s.json" % (ts, event_type, sid, seq, suffix)
    if sid:
        raise ValueError("non-session %r with a sid: the real shipper drops the sid for this shape" % event_type)
    return "audit/%s-%s.%06d.json" % (ts, event_type, seq)


if __name__ == "__main__":
    event_type = sys.argv[1]
    ts = sys.argv[2]
    sid = sys.argv[3] if len(sys.argv) > 3 else ""
    seq = int(sys.argv[4]) if len(sys.argv) > 4 else 1
    mode = sys.argv[5] if len(sys.argv) > 5 else ""
    try:
        print(audit_key(event_type, ts, sid, seq, mode))
    except ValueError as exc:
        print("shipper_keys: %s" % exc, file=sys.stderr)
        sys.exit(2)
