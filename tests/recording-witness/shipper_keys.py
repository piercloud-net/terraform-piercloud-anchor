#!/usr/bin/env python3
"""Replica of the pc-admin shipper's audit-key grammar (b2_client.build_audit_key).

PINNED AGAINST: cad0p/pc-admin @ a7035a9701517c7d9edfc5baa7cc04cc0ca72189 — the
**grammar-defining SHA**: the builder grammar last changed there (the
replay-conflict variant: `disambiguate_audit_key` appends `_<sha256[:16]>` to
the event type when a rebuilt file replays a taken key with different bytes)
and is unchanged since (pc-admin round-9 @ `e41fac8` added ETag normalization
and persisted-float validation only — no key-grammar change).
The previous grammar points were 41735ff (the over-long event-type cap:
truncate to 128 chars, drop a trailing separator and append an
`_<sha256[:8]>` suffix) and 66bd304 (the session.rejected sid-less fold).
The golden strings in tests/recording-witness/run-test.sh and the checked-in
vector matrix were generated from the pinned SHA; a pc-admin grammar change
must bump this pin, regenerate both and update the witness contract in the
same breath.

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
  allowlists it there and the real builder at the pinned SHA (`a7035a9`;
  unchanged since `66bd304`) drops any sid for this type, shipping it under
  the global counter. A regression to
  the pre-fold sid-bearing shape would be read by the witness as a session
  with no `session.start` (`session-start-missing`), so the replica never
  builds it and the golden/refusal teeth pin that.
- An event type longer than 128 chars is truncated to the cap with a trailing
  separator dropped and `_<sha256[:8]>` appended (an underscore segment inside
  the witness's `[A-Za-z0-9_]+` type grammar): the cap keeps B2 keys bounded
  (1024-byte ceiling) and the hash keeps two distinct over-long types from
  aliasing to one key (a plain truncation could make the shipper's
  HEAD-before-PUT replay absorb a different event). The truncation applies
  only to grammar-valid types — an invalid over-long type is sanitized to
  `unknown` by the real builder and is refused here.
- `seq` mirrors the real grammar: the builder emits `previous + 1` (floor 1 —
  seq 0 is legacy-only and must be hand-written) formatted `%06d`, so 7+
  digits are legal past 999999; the ceiling is the witness's `[0-9]{1,18}`
  grammar pc-admin's `SEQ_PATTERN` mirrors.

Golden + boundary vectors are generated from the pinned real builder and
checked in (`shipper_key_vectors.json`, regenerated with
`generate_shipper_vectors.py` against the pc-admin checkout); the harness
replays every vector against this replica, so silent drift fails there.

CLI:  shipper_keys.py <event-type> <ts> [sid] [seq] [mode]
      shipper_keys.py --variant <body> <event-type> <ts> [sid] [seq] [mode]
      prints the audit key (single line); the `--variant` form prints the
      replay-conflict variant key for <body>.
"""

import hashlib
import re
import sys

PINNED_PC_ADMIN_SHA = "a7035a9701517c7d9edfc5baa7cc04cc0ca72189"

TS_PATTERN = r"^[0-9]{8}T[0-9]{6}Z$"
UUID_PATTERN = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
TS_RE = re.compile(TS_PATTERN)
UUID_RE = re.compile(UUID_PATTERN)
EVENT_TYPE_RE = re.compile(r"^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*$")
SESSION_TYPE_RE = re.compile(r"^session\.[A-Za-z0-9_]+$")
# The real builder emits `%06d` (7+ digits past 999999); the ceiling mirrors
# the witness's `[0-9]{1,18}` grammar that pc-admin's SEQ_PATTERN mirrors.
SEQ_MAX = 10 ** 18 - 1

# Over-long event-type cap (b2_client.MAX_EVENT_TYPE_LENGTH +
# EVENT_TYPE_HASH_LENGTH): truncate below the cap, drop a trailing separator
# and append `_<sha256[:8]>` of the full type. The suffix is an underscore
# segment inside the witness's `[A-Za-z0-9_]+` type grammar, and the hash keeps
# distinct over-long types from aliasing to one key.
MAX_EVENT_TYPE_LENGTH = 128
EVENT_TYPE_HASH_LENGTH = 8

# Replay-conflict variant (b2_client.CONFLICT_HASH_LENGTH +
# disambiguate_audit_key): a rebuilt file that replays a taken key with
# different bytes ships a variant whose event type carries `_<sha256[:16]>` of
# the local content. A session lifecycle variant drops its mode marker; on the
# sid-less shape the hash joins the last type segment (segment count
# unchanged). The witness canonicalizes the suffix back to the base type and
# treats the variant as the same event identity.
CONFLICT_HASH_LENGTH = 16
SESSION_KEY_PARSE_RE = re.compile(
    r"^(?P<ts>[0-9]{8}T[0-9]{6}Z)-(?P<type>session\.[A-Za-z0-9_]+)\.(?P<sid>"
    + UUID_PATTERN
    + r")\.(?P<seq>[0-9]{1,18})(?:\.(?P<mode>shell|exec))?\.json$"
)
OTHER_KEY_PARSE_RE = re.compile(
    r"^(?P<ts>[0-9]{8}T[0-9]{6}Z)-(?P<type>[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*)\.(?P<seq>[0-9]{1,18})\.json$"
)

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
    if len(event_type) > MAX_EVENT_TYPE_LENGTH:
        # The real builder caps an over-long type below B2's 1024-byte key
        # limit: truncate, drop a trailing separator, and append a short hash
        # of the FULL type so distinct over-long types cannot alias to one key
        # (pc-admin R5 @ 41735ff). Only grammar-valid types reach this point;
        # an invalid type was sanitized to `unknown` above. Mirror exactly.
        digest = hashlib.sha256(event_type.encode("utf-8")).hexdigest()
        head = event_type[: MAX_EVENT_TYPE_LENGTH - EVENT_TYPE_HASH_LENGTH - 1].rstrip(".")
        event_type = "%s_%s" % (head, digest[:EVENT_TYPE_HASH_LENGTH])
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


def disambiguate_key(key, body):
    """Mirror pc-admin's `disambiguate_audit_key` (replay-conflict variant).

    Appends `_<sha256[:16]>` of the local content to the event type: a session
    variant drops its mode marker; on the sid-less shape the hash joins the
    last type segment. Returns the key unchanged outside the shipper grammar,
    exactly like the producer (the caller never invents a shape the witness
    cannot classify).
    """
    payload = body if isinstance(body, bytes) else str(body).encode("utf-8")
    digest = hashlib.sha256(payload).hexdigest()[:CONFLICT_HASH_LENGTH]
    prefix, _, basename = key.rpartition("/")
    match = SESSION_KEY_PARSE_RE.match(basename)
    if match:
        parts = match.groupdict()
        variant = "%s-%s_%s.%s.%s.json" % (
            parts["ts"], parts["type"], digest, parts["sid"], parts["seq"])
    else:
        match = OTHER_KEY_PARSE_RE.match(basename)
        if not match:
            return key
        parts = match.groupdict()
        head, _, last = parts["type"].rpartition(".")
        hashed = "%s.%s_%s" % (head, last, digest) if head else "%s_%s" % (last, digest)
        variant = "%s-%s.%s.json" % (parts["ts"], hashed, parts["seq"])
    return "%s/%s" % (prefix, variant) if prefix else variant


if __name__ == "__main__":
    argv = sys.argv[1:]
    variant_body = None
    if argv and argv[0] == "--variant":
        if len(argv) < 2:
            print("shipper_keys: --variant needs a body string", file=sys.stderr)
            sys.exit(2)
        variant_body = argv[1]
        argv = argv[2:]
    if len(argv) < 2:
        print(
            "usage: shipper_keys.py <event-type> <ts> [sid] [seq] [mode] "
            "| shipper_keys.py --variant <body> <event-type> <ts> [sid] [seq] [mode]",
            file=sys.stderr,
        )
        sys.exit(2)
    event_type = argv[0]
    ts = argv[1]
    sid = argv[2] if len(argv) > 2 else ""
    try:
        seq = int(argv[3]) if len(argv) > 3 else 1
    except ValueError:
        print("shipper_keys: seq must be an integer, got %r" % (argv[3],), file=sys.stderr)
        sys.exit(2)
    mode = argv[4] if len(argv) > 4 else ""
    try:
        key = audit_key(event_type, ts, sid, seq, mode)
        if variant_body is not None:
            key = disambiguate_key(key, variant_body)
        print(key)
    except ValueError as exc:
        print("shipper_keys: %s" % exc, file=sys.stderr)
        sys.exit(2)
