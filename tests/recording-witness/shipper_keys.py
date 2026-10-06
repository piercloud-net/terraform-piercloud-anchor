#!/usr/bin/env python3
r"""Replica of the pc-admin shipper's audit-key grammar (b2_client.build_audit_key).

PINNED AGAINST: cad0p/pc-admin @ c0ce2f1567af64dbc2de09eb45e9e36c4b2c48fd — the
**date-partition SHA**: pc-admin #30 made `build_audit_key` emit
``audit/YYYYMMDD/<basename>`` (the day derived from the same UTC instant as
``<ts>``) and added ``split_audit_date_segment``/``parse_audit_key_full``, which
refuse an all-digit segment that is not a real 8-digit calendar date instead of
laundering it into a flat parse. Flat legacy keys (``audit/<basename>``) remain
accepted through the dual window and are built by the replica's ``flat=True``
opt-in; the builder default is dated. The previous grammar point was
25f79223cadd2a0ca6781d575215ebd2a7c0ddc8 (pc-admin #20 anchored the audit-key type
regexes at `\Z`; Python's `$` also matches before a trailing newline, so a type
like `user.login\n` would pass and build a key with an embedded newline the
witness reads as `contract-mismatch` drift; the real builder now sanitizes such
a type to the documented `unknown` non-session shape and the replica refuses
it).
The point before that was 3325aeb (pc-admin #19: the exact single-segment
`session.data` with no effective strict-UUID sid ships on the documented
`unknown` non-session shape instead of the sid-less `session.*` drift shape).
Earlier points: a7035a9 (the replay-conflict variant:
`disambiguate_audit_key` appends `_<sha256[:16]>` to the event type when a
rebuilt file replays a taken key with different bytes; pc-admin round-9 @
`e41fac8` added ETag normalization and persisted-float validation only — no
key-grammar change), 66bd304 (the session.rejected sid-less
fold), 929d82c (the 128-char pre-hash event-type truncation cap), 41735ff (the
`_<sha256[:8]>` collision-resistant suffix on the truncated type) and 342a37c
(the `10^18-1` seq-ceiling clamp in `build_audit_key`).
The golden strings in tests/recording-witness/run-test.sh and the checked-in
vector matrix were generated from the pinned SHA; a pc-admin grammar change
must bump this pin and regenerate both (a contract-neutral change like #19
needs no witness-contract edit — `audit/<ts>-unknown.<seq>.json` is already a
documented non-session shape the collector absorbs).

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

- Only a `session.*` event with a **strict-UUID** sid becomes a session key.
  The exact single-segment `session.data` with no effective strict-UUID sid
  (missing, `""`, non-UUID) is sanctioned to the documented `unknown`
  non-session shape exactly like the real builder (pc-admin #19); every other
  `session.*` with a non-UUID sid is refused here (the real builder keeps
  shipping it on the sid-less drift shape — refuse so a fixture can never pin
  a shape the shipper cannot produce), except `session.rejected`, which drops
  any sid under the forced-sid-less rule below.
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
  allowlists it there and the real builder at the pinned SHA (behavior here
  unchanged since `66bd304`) drops any sid for this type, shipping it under
  the global counter. A regression to
  the pre-fold sid-bearing shape would be read by the witness as a session
  with no `session.start` (`session-start-missing`), so the replica never
  builds it and the golden/refusal teeth pin that.
- A type with a trailing newline is out of grammar (`\Z`-anchored type
  regexes, pc-admin #20): the real builder sanitizes it to `unknown`; the
  replica refuses it so a fixture can never pin a key with an embedded
  newline the witness reads as `contract-mismatch` drift.
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
replays every vector against this replica, so silent drift fails there. The
matrix carries dated vectors (the pinned builder's current output), flat
legacy vectors (the same basenames under the pre-#30 layout, built with
`flat=True`), and date-segment vectors pinning the optional `YYYYMMDD/`
split (valid dated, flat, and malformed-date refusals).

CLI:  shipper_keys.py [--flat|--dated] <event-type> <ts> [sid] [seq] [mode]
      shipper_keys.py --variant <body> <event-type> <ts> [sid] [seq] [mode]
      prints the audit key (single line); the `--variant` form prints the
      replay-conflict variant key for <body>. The default layout is the pinned
      builder's dated `audit/YYYYMMDD/<basename>`; `--flat` builds the legacy
      flat key (the harness's pre-#30 fixtures opt in explicitly).
"""

import hashlib
import re
import sys
from datetime import datetime

PINNED_PC_ADMIN_SHA = "c0ce2f1567af64dbc2de09eb45e9e36c4b2c48fd"
# Date-partition grammar (pc-admin #30): ``audit/YYYYMMDD/<basename>``. The
# segment must be a real calendar date; a non-calendar all-digit segment is
# malformed and refused, never stripped (mirrors
# ``split_audit_date_segment``).
AUDIT_DAY_LENGTH = 8
AUDIT_DAY_DIGITS_RE = re.compile(r"^[0-9]+$")

# ``\Z``, not ``$``: Python's ``$`` also matches before a trailing newline,
# so a timestamp like ``20260925T100008Z\n`` would pass and build a key with
# an embedded newline (anchor #155 F2, the same trailing-newline class as the
# type regexes / anchors #151/#152).
TS_PATTERN = r"^[0-9]{8}T[0-9]{6}Z\Z"
UUID_PATTERN = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
TS_RE = re.compile(TS_PATTERN)
UUID_RE = re.compile(UUID_PATTERN)
# ``\Z``, not ``$``: Python's ``$`` also matches before a trailing newline,
# so a type like ``user.login\n`` would pass and build a key with an embedded
# newline the witness reads as contract-mismatch drift (pc-admin #20).
EVENT_TYPE_RE = re.compile(r"^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*\Z")
SESSION_TYPE_RE = re.compile(r"^session\.[A-Za-z0-9_]+\Z")
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
# pc-admin #19 (pinned @ 3325aeb): the exact single-segment `session.data`
# with no effective strict-UUID sid ships on the documented `unknown`
# non-session shape (Teleport v18 port-forward traffic accounting carries no
# sid). Same constant name as pc-admin's for cross-repo grepping.
SID_LESS_UNKNOWN_SESSION_EVENTS = frozenset({"session.data"})


# Date-partition split (pc-admin #30 ``split_audit_date_segment``). Mirrored
# here so the generator can pin the real builder's segment semantics against
# this replica: a valid ``YYYYMMDD/`` segment is stripped, a flat key is
# returned unchanged, and an all-digit segment that is not a real calendar
# date returns ``(None, segment)`` — malformed, never stripped.
def _valid_audit_day(segment):
    if len(segment) != AUDIT_DAY_LENGTH or not AUDIT_DAY_DIGITS_RE.fullmatch(segment):
        return None
    try:
        datetime.strptime(segment, "%Y%m%d")
    except ValueError:
        return None
    return segment


def split_date_segment(key):
    """Split an optional valid ``YYYYMMDD/`` day segment off a full audit key.

    Returns ``(relative_key, day)`` — the key without the day segment and the
    validated day string — or ``(None, segment)`` for an all-digit segment
    that is not a real calendar date. A key without a date segment returns
    ``(key, None)`` unchanged (flat legacy keys take this path). Pure; mirrors
    pc-admin's ``split_audit_date_segment`` exactly.
    """
    prefix, sep, basename = key.rpartition("/")
    if not sep:
        return key, None
    head, sep2, segment = prefix.rpartition("/")
    if not sep2:
        # ``<segment>/<basename>`` with no directory prefix
        head, segment = "", prefix
    if not AUDIT_DAY_DIGITS_RE.fullmatch(segment):
        return key, None
    if _valid_audit_day(segment) is None:
        return None, segment
    return ("%s/%s" % (head, basename) if head else basename), segment


def _layout_prefix(ts, flat):
    """``audit/`` for a flat legacy key, ``audit/YYYYMMDD/`` for dated."""
    return "audit/" if flat else "audit/%s/" % ts[:8]


def audit_key(event_type, ts, sid="", seq=1, mode="", flat=False):
    """Build one audit object key exactly as pc-admin's shipper does.

    The pinned builder is **date-partitioned**: ``audit/YYYYMMDD/<basename>``,
    the day derived from the same UTC instant as ``<ts>``. ``flat=True``
    builds the legacy ``audit/<basename>`` layout (accepted through the dual
    window; the harness's historical fixtures opt in explicitly).
    """
    if not isinstance(ts, str) or not TS_RE.match(ts):
        raise ValueError("timestamp must be YYYYmmddTHHMMSSZ, got %r" % ts)
    if not isinstance(seq, int) or isinstance(seq, bool) or not 1 <= seq <= SEQ_MAX:
        raise ValueError(
            "seq must be >= 1 (the real builder emits previous+1; seq 0 is a "
            "hand-written legacy fixture) and fit the witness's 18-digit grammar, got %r" % (seq,)
        )
    if not isinstance(event_type, str) or not EVENT_TYPE_RE.match(event_type):
        raise ValueError("event type outside the shipper grammar: %r" % event_type)
    effective_sid = sid if isinstance(sid, str) and UUID_RE.fullmatch(sid) else ""
    if event_type.startswith("session.") and (
        not SESSION_TYPE_RE.match(event_type)
        or (not effective_sid and event_type in SID_LESS_UNKNOWN_SESSION_EVENTS)
    ):
        # Multi-segment session.*: the witness's session classifier is
        # single-segment, so the real builder sanitizes the whole type to
        # `unknown` and drops the sid (global shape). Scoped sanction
        # (pc-admin #19 @ 3325aeb): the exact single-segment `session.data`
        # with no effective strict-UUID sid (missing, "", non-UUID) is
        # likewise sanctioned to the documented `unknown` non-session shape;
        # every other `session.*` keeps the sid-less drift shape the replica
        # refuses below. Exact match on the raw type, before the truncation
        # cap.
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
    if sid and (not isinstance(sid, str) or not UUID_RE.fullmatch(sid)):
        if event_type not in SID_LESS_SESSION_EVENTS:
            raise ValueError(
                "non-UUID sid %r: the real shipper ships this on the sid-less global shape" % sid
            )
        # session.rejected drops any sid — non-string/non-UUID included: the
        # real builder normalizes the sid to "" before the forced-sid-less
        # shape, so the documented key stays buildable from the live input
        # (functional round-10 LOWs) instead of refusing or crashing on a
        # non-string that would raise TypeError from the regex.
        sid = ""
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
        return "%s%s-%s.%06d.json" % (_layout_prefix(ts, flat), ts, event_type, seq)
    if SESSION_TYPE_RE.match(event_type):
        if not sid:
            raise ValueError(
                "session.* %r without a sid: the real shipper keeps a session key only for a UUID sid"
                % event_type
            )
        suffix = ".%s" % mode if mode else ""
        return "%s%s-%s.%s.%06d%s.json" % (_layout_prefix(ts, flat), ts, event_type, sid, seq, suffix)
    if sid:
        raise ValueError("non-session %r with a sid: the real shipper drops the sid for this shape" % event_type)
    return "%s%s-%s.%06d.json" % (_layout_prefix(ts, flat), ts, event_type, seq)


def disambiguate_key(key, body):
    """Mirror pc-admin's `disambiguate_audit_key` (replay-conflict variant).

    Appends `_<sha256[:16]>` of the local content to the event type: a session
    variant drops its mode marker; on the sid-less shape the hash joins the
    last type segment. A date-partitioned key keeps its ``YYYYMMDD/`` day
    segment (the variant stays on the same day/layout), and a key whose
    day segment is malformed is returned unchanged (refused, never laundered
    into a flat variant), exactly like the pinned builder. Returns the key
    unchanged outside the shipper grammar, exactly like the producer (the
    caller never invents a shape the witness cannot classify).
    """
    relative, day = split_date_segment(key)
    if relative is None:
        return key
    payload = body if isinstance(body, bytes) else str(body).encode("utf-8")
    digest = hashlib.sha256(payload).hexdigest()[:CONFLICT_HASH_LENGTH]
    prefix, _, basename = relative.rpartition("/")
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
    if day:
        prefix = "%s/%s" % (prefix, day) if prefix else day
    return "%s/%s" % (prefix, variant) if prefix else variant


if __name__ == "__main__":
    argv = sys.argv[1:]
    variant_body = None
    flat = False
    rest = []
    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg == "--variant":
            if index + 1 >= len(argv):
                print("shipper_keys: --variant needs a body string", file=sys.stderr)
                sys.exit(2)
            variant_body = argv[index + 1]
            index += 2
            continue
        if arg == "--flat":
            flat = True
            index += 1
            continue
        if arg == "--dated":
            flat = False
            index += 1
            continue
        rest.append(arg)
        index += 1
    argv = rest
    if len(argv) < 2:
        print(
            "usage: shipper_keys.py [--flat|--dated] <event-type> <ts> [sid] [seq] [mode] "
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
        key = audit_key(event_type, ts, sid, seq, mode, flat=flat)
        if variant_body is not None:
            key = disambiguate_key(key, variant_body)
        print(key)
    except ValueError as exc:
        print("shipper_keys: %s" % exc, file=sys.stderr)
        sys.exit(2)
