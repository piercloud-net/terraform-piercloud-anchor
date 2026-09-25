#!/usr/bin/env python3
"""Replica of the pc-admin shipper's audit-key grammar (b2_client.build_audit_key).

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

CLI:  shipper_keys.py <event-type> <ts> [sid] [seq] [mode]
      prints the full audit key (single line).
"""

import sys

# Session lifecycle events get the `interactive`-derived mode suffix; every
# other event type never carries one (b2_client.SESSION_MODE_EVENTS).
SESSION_MODE_EVENTS = frozenset({"session.start", "session.end"})


def audit_key(event_type, ts, sid="", seq=1, mode=""):
    """Build one audit object key exactly as pc-admin's shipper does."""
    suffix = f".{mode}" if (mode and event_type in SESSION_MODE_EVENTS) else ""
    if sid:
        return f"audit/{ts}-{event_type}.{sid}.{seq:06d}{suffix}.json"
    return f"audit/{ts}-{event_type}.{seq:06d}.json"


if __name__ == "__main__":
    event_type = sys.argv[1]
    ts = sys.argv[2]
    sid = sys.argv[3] if len(sys.argv) > 3 else ""
    seq = int(sys.argv[4]) if len(sys.argv) > 4 else 1
    mode = sys.argv[5] if len(sys.argv) > 5 else ""
    print(audit_key(event_type, ts, sid, seq, mode))
