#!/usr/bin/env bash
# tests/recording-witness/run-test.sh — recording-completeness witness.
#
# Offline, cred-free, no cloud: extracts the REAL witness render span from
# scripts/010-provision.sh (never a copy; same pattern as tests/origin-ca),
# renders the witness, and drives it against a local mock S3 listing endpoint
# (mock_s3.py). What it proves:
#   (a) the rendered witness is valid bash and passes shellcheck -S warning;
#   (b) the rendered systemd units carry the canonical paths and the decided
#       5-minute cadence (OnUnitInactiveSec=5min);
#   (c) env parsing: none = off, all-valid = on, partial/invalid = partial;
#   (d) verdicts on mocked S3 metadata: healthy -> ok (and free of any
#       hidden-object finding; a noncurrent version from a legitimate re-PUT
#       is not one); a delete marker under audit/ or recordings/ -> alert
#       hidden-object (hiding detected; counts per prefix + sampled keys);
#       missing/stale heartbeat ->
#       alert heartbeat-missing / heartbeat-stale; session.start older than the
#       grace with no recording object/upload -> alert recording-gap; a
#       completed tar with no session.end past the grace -> alert
#       session-end-missing (the tar alone must not keep it green forever); an
#       in-progress upload with an old session.end -> alert completer-lag; the
#       long-live-session negative (old upload, NO session.end, within the
#       open-upload bound) stays ok (review finding 2); a missing <seq> ->
#       alert sequence-gap; a repeated (sid, seq) -> alert sequence-duplicate;
#       unrecognized session keys -> alert naming-contract; event keys with no
#       session.start -> alert session-start-missing; a session whose first
#       seq is neither 0 nor 1 -> alert sequence-origin; a wedged open upload
#       (no session.end) past the open-upload bound -> alert
#       open-upload-stale; exec-mode sessions ship no tar and stay ok (the
#       session.end marker is authoritative - live v18 reads `.shell` on
#       session.start for exec sessions too); an in-flight live-v18 exec
#       session (shell start, no end yet, past grace) alerts recording-gap
#       conservatively with ambiguity wording and clears once the exec end
#       lands; shell/legacy sessions with an end and no tar -> alert
#       recording-gap; duplicate session.end objects resolve by the newest
#       LastModified (both mode directions pinned); a malformed mode marker ->
#       naming-contract; sid-less session.rejected keys are not drift (nor is
#       the pc-admin #19-sanctioned `unknown` shape for a sid-less
#       session.data), while a sid-bearing rejected key (the pre-fold pc-admin
#       shape) is read as a session with no session.start ->
#       session-start-missing; a
#       replay-conflict variant key (base + `_<sha256[:16]>`) is absorbed as
#       the SAME event identity as its base (no sequence-duplicate, no naming
#       drift) with the base key authoritative for the lifecycle mode, while a
#       genuine same-seq duplicate at a different ts still alerts
#       sequence-duplicate and a variant-only session start stays
#       conservatively session-start-missing; the identity tuple excludes the
#       mode marker and drives sequence counting only, so a same-(ts, type,
#       seq) `.exec`/`.shell` marker pair still resolves by the newest
#       LastModified (conflicting equal-LM tie -> conservative shell) and a
#       variant-first listing order cannot force-skip the canonical base;
#       a
#       renamed session prefix (sess.start) is still drift; an audit key that
#       matches no documented shape -> alert contract-mismatch; future
#       LastModified *and* future Initiated timestamps -> error (clock skew,
#       enforced at collection time for every listed object, incl. exec
#       sessions and completed tars that never reach a per-session age check);
#       equal-LastModified contradictory duplicate starts/ends fail closed to
#       the conservative shell in both listing orders; an uppercase-sid tar or
#       in-progress upload still satisfies the lowercased session's gap check
#       (sid case is normalized consistently for the recordings lookup); an
#       orphan completed tar
#       whose sid has no audit events at all alerts session-start-missing past
#       the grace (and stays quiet inside it);
#       mode-marker fixtures are built with the pc-admin shipper key grammar
#       (shipper_keys.py, pinned to cad0p/pc-admin @ 25f7922; the generator's
#       provenance guard compares content, not `git status` — an
#       assume-unchanged/skip-worktree worktree edit cannot smuggle unpinned
#       builder bytes, replacement refs are disabled (`git replace` cannot
#       swap the compared blob), and the compared bytes are compiled directly
#       (a planted `__pycache__` entry cannot run) — and the replica `TS_RE`
#       is `\Z`-anchored, anchor #155;
#       golden strings,
#       refusal teeth, and the checked-in golden+boundary+variant vector
#       matrix generated from the real builder — never hand-written — incl.
#       the over-long event-type truncation cap with its `_<sha256[:8]>`
#       suffix and the replay-conflict `_<sha256[:16]>` variant keys; a
#       fixture can pin non-conformant listing orders;
#   (e) fail-closed: a failing listing run reports error (exit 2) while the
#       last baseline in state.json is held; a corrupt state.json (bad numeric
#       field) reports error and repairs instead of crashing, holding the
#       readable baseline, and an unreadable, oversized (a bounded BYTE read:
#       a multi-byte state over 1 MiB bytes is invalid input) or
#       pathologically nested document is preserved as state.json.corrupt (or
#       a timestamped .corrupt.<stamp> sibling, never overwriting an existing
#       one) and repaired instead of an uncaught RecursionError/MemoryError;
#       an invalid-UTF-8 state takes the same preserve-and-repair path with
#       the encoding failure named;
#       a preservation failure (unwritable state dir) warns with the actual
#       destination it tried;
#       planted symlinks
#       at state.json.tmp/verdict.log are never followed or reused into a
#       victim; malformed XML, an S3 error document and a truncated list
#       without a continuation token all error; a denied (403, missing
#       listFiles), malformed or truncated version listing errors too;
#   (f) strictly list-only: every request the witness makes is a signed GET
#       list call (ListObjectsV2 / ListObjectVersions / ListMultipartUploads)
#       — no HEAD, no object GET, no ListParts, no write; pagination is
#       followed for all three list families, and every scenario
#       SigV4-signature-verifies server-side;
#   (g) the 0600 env file holds the key and the witness never prints it;
#   (h) install renders all four artifacts (mode 0600 env) and a later
#       provision without the env removes them (no stale timer);
#   (i) run-once acceptance: a Type=oneshot start rc is non-zero for an
#       alerting witness too, so the run maps the paired rc/ExecMainStatus
#       (0:0 / 1:1 / 1:2) -> ok/alert/error and dies when the unit demonstrably
#       did not run (status unset/203, unpaired rc, or a wedged start whose
#       InvocationID did not advance); the timer's immediate first fire on a
#       long-up box (issue #143) is drained (bounded, 3600 polls) before the
#       capture and retried exactly once if a start still merged with it, so a
#       merged timer-triggered invocation is never mis-filed as a stale start
#       (a merged write followed by a failed retry write dies on the
#       re-anchored run_seq baseline, and a unit that never drains dies at the
#       bound with zero starts on the pre-start drain — the retry-path drain
#       can fire after the merged start, fail-closed either way); the
#       run also dies when state.json's per-run identity
#       (run_seq) did not advance this invocation (a failed state write, or a
#       start that left the previous verdict) — run identity, not the
#       second-resolution updated_at, so a genuine same-second run counts; an
#       explicit `repaired` record OF THIS invocation is accepted even though
#       an unreadable `run_seq` restarts the counter at 1 (a repaired record
#       must carry the error verdict — the gate enforces that after
#       advancement on every path, not only when the prior run_seq collides,
#       so a repaired ok/alert record is refused however the prior run_seq
#       rendered and the run still fails closed), while a stale repair marker
#       from a previous invocation still dies; a
#       run longer than any recency window is accepted because the anchor is
#       advancement, not recency; state and ExecMainStatus mismatches die; the
#       printed detail has session ids redacted (public run-log safety);
#       verdict.log rotates once it crosses its size bound;
#   (j) ntfy bookkeeping: state transitions push, a first-ever green never
#       pushes (and does not arm the recovery retry), a repeated non-green
#       state is suppressed inside the renotify window, renotifies outside it,
#       a changed finding signature pushes immediately and an unchanged one
#       stays quiet (signatures hash stable identities only - the separate
#       finding-signature teeth below prove age-only drift never changes one
#       and that every identity component moves it: all sequence-gap ranges,
#       the hidden version_id, the drift key, the session-start condition),
#       the operator's quiet pin quiets exactly its own `alert` signature to
#       the quiet window while any other signature keeps the default window
#       (a malformed pin - including a trailing newline - disables quieting
#       with a bounded warning, never aborting or echoing; an out-of-range
#       window falls back to the default; the fixed error signature is never
#       quieted), a failed push never advances `last_notify_signature` while a
#       landed push does, a
#       failed recovery push is retried on the next green run until it lands
#       (the retry boundary is the per-run identity, so a same-second
#       transition still retries), a stored last-notify epoch in the future
#       still renotifies (clock-corrected state cannot silence forever),
#       BadStatusLine/IncompleteRead push failures are caught and logged (not
#       fatal), a token that cannot be an HTTP header value (control chars /
#       CR/LF / non-ASCII / oversized) skips the push with a bounded warning
#       instead of aborting the run or echoing the token, ntfy redirects are
#       refused and the signed S3 list GETs refuse redirects too (a 3xx never
#       re-sends an Authorization header to another host/scheme),
#       and steady ok stays silent afterwards (fake notifier, no network);
#   (k) delta cursors + merged sweeps (issue #153): a warm sweep writes the
#       high-water cursors and the view.json sidecar; a quiet run makes
#       only the cursored tails (flat discovery + selected dated days +
#       heartbeat + recordings) plus the full multipart family (no
#       versions, no unfiltered object pages) and returns the byte-identical
#       verdict/signature; a replayed below-cursor key is caught at the forced
#       sweep; a delete marker on an old key lands at the sweep bound; cursor
#       loss, a foreign/out-of-prefix cursor and a mismatched view all take
#       the preserve+repair+unfiltered-sweep path with an error verdict (never
#       green); a failed sweep latches until one succeeds; a quiet delta never
#       re-seeds and advances run_seq; the seed defers the first sweep and
#       still reports the cold-start alert; range-split sweeps equal a serial
#       sweep and use the persisted boundaries; delta tails follow pagination;
#       a delta listing that returns a key at/below its cursor errors closed;
#   (l) dual-layout audit keys (issue #159, phase 1): dated session and
#       non-session keys classify; malformed/calendar-invalid day segments
#       and date-impersonating segments are drift that never moves a cursor;
#       a dated re-ship folds onto the same (ts, type, seq) identity as its
#       flat key; the unseeded transition probe sees same-day dated keys that
#       sort below the flat cursor (no repair/sweep); a future day is never
#       listed and a persisted future dated cursor fails closed; the first
#       dated day above/below the flat cursor is listed/not-listed
#       deterministically under both mock `start_after`-on-CommonPrefixes
#       behaviours and the sweep closes the below-flat day; a day below the
#       dated cursor is not re-listed (request-count pin); the below-cursor
#       residual and the writer-revert disclosure are sweep-bounded;
#       non-day/malformed prefixes are never listed in delta; the seed
#       starts at the window-start day prefix and seeds the dated cursor;
#       the replica builds the dated layout by default (`--flat` legacy) and
#       the checked-in vectors replay dated goldens, flat legacy vectors and
#       the day-segment split (valid/flat/malformed refusals).
set -euo pipefail

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HARNESS_DIR}/../.." && pwd)"
PROVISION="${ROOT}/scripts/010-provision.sh"
MOCK_S3="${HARNESS_DIR}/mock_s3.py"

WORK="$(mktemp -d /tmp/recording-witness.XXXXXX)"
MOCK_PID=""
cleanup() {
  if [ -n "${MOCK_PID}" ]; then
    kill "${MOCK_PID}" 2>/dev/null || true
    wait "${MOCK_PID}" 2>/dev/null || true
  fi
  rm -rf "${WORK}"
}
trap cleanup EXIT

command -v python3 >/dev/null 2>&1 || { printf 'FAIL python3 is required\n'; exit 1; }

pass=0
fail=0
# Check-count floor: pinned to the real count so a removed tooth (or a suite
# that stops running scenarios) fails loudly instead of shrinking silently.
# Bump it with every intended check. The shellcheck lint tooth is skipped when
# it is absent (a local run without it must not fail the full floor;
# CI ships shellcheck and runs the tooth), so the effective floor subtracts
# the recorded skip (functional round-2 LOW: a 473-pass no-shellcheck run
# hard-failed the 474 floor).
MIN_CHECKS=942
SHELLCHECK_SKIPPED=0
ok()  { pass=$((pass + 1)); printf 'ok   %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL %s\n' "$1"; }
is()  { # $1 label, $2 expected, $3 actual
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi
}
mode_of() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1" 2>/dev/null || echo "?"; }
key() { # audit key built by the pc-admin shipper grammar (never hand-written);
        # the legacy flat layout (the dated layout is `dated_key`)
  python3 "${HARNESS_DIR}/shipper_keys.py" --flat "$@"
}
variant_key() { # replay-conflict variant: --variant <body> <event-type> <ts> [sid] [seq] [mode]
  python3 "${HARNESS_DIR}/shipper_keys.py" --flat --variant "$@"
}
dated_key() { # dated `audit/YYYYMMDD/<basename>` (the pinned builder's layout)
  python3 "${HARNESS_DIR}/shipper_keys.py" "$@"
}
dated_variant_key() { # dated replay-conflict variant
  python3 "${HARNESS_DIR}/shipper_keys.py" --variant "$@"
}
fresh_stamp() { # current UTC in the witness's state.json format
  python3 -c 'import datetime; print(datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))'
}
audit_stamp() { # current UTC in the shipper key format, offset by $1 seconds
  python3 -c 'import datetime,sys; print((datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(seconds=int(sys.argv[1]))).strftime("%Y%m%dT%H%M%SZ"))' "$1"
}
# Pin the replica to the pc-admin shipper grammar. The golden strings below
# were generated from the real builder at cad0p/pc-admin @ 9a2fe50
# (scripts/lib/b2_client.py build_audit_key/session_mode/disambiguate_audit_key/
# split_audit_date_segment, the full-SHA pin in shipper_keys.py; the pinned
# point (pc-admin #39) made the full-key helpers prefix-aware (`audit/`
# default): only one leading valid day segment is stripped after the prefix,
# the remainder must be a bare basename, and a foreign prefix or residual path
# segment refuses instead of being laundered into a flat parse or variant; the
# preceding layout point (pc-admin #30) made build_audit_key emit `audit/YYYYMMDD/<basename>`
# (the dated default) and added the optional-segment split that refuses a
# non-calendar all-digit day; the previous grammar-defining point (pc-admin
# #20) `\Z`-anchored the audit-key type regexes (a trailing-newline type is
# out of grammar and sanitized to the documented `unknown` non-session shape),
# the point before that 3325aeb (pc-admin #19) scoped the sid-less
# `session.data` sanction onto the documented `unknown` non-session shape,
# then a7035a9 added the replay-conflict `_<sha256[:16]>` variant keys, and
# the earlier point 41735ff added the over-long event-type truncation cap
# with the `_<sha256[:8]>` suffix — all pinned by the vector matrix below); a
# pc-admin grammar change must bump the pin and regenerate these (a
# contract-neutral change needs no witness-contract edit). The flat goldens
# use the `key`/`variant_key` helpers (explicit `--flat`: the pre-#30 legacy
# layout the dual window still accepts) and the dated goldens use
# `dated_key`/`dated_variant_key` (the pinned builder's current default).
# Drift fixtures (non-UUID or sid-less session keys, malformed modes) stay
# hand-written literals on purpose: the replica refuses shapes the real
# shipper never emits, so a fixture request for one is itself a failure (the
# teeth after the golden).
REPLICA_SID="9f8c4b1e-0d2a-4f7e-9c11-2b3d4e5f6a70"
is "replica golden session.start shell" \
  "audit/20260925T100008Z-session.start.${REPLICA_SID}.000001.shell.json" \
  "$(key session.start 20260925T100008Z "${REPLICA_SID}" 1 shell)"
is "replica golden session.end exec" \
  "audit/20260925T100008Z-session.end.${REPLICA_SID}.000002.exec.json" \
  "$(key session.end 20260925T100008Z "${REPLICA_SID}" 2 exec)"
is "replica golden session.data (no mode suffix)" \
  "audit/20260925T100008Z-session.data.${REPLICA_SID}.000007.json" \
  "$(key session.data 20260925T100008Z "${REPLICA_SID}" 7)"
is "replica golden session.rejected forced sid-less" \
  "audit/20260925T100008Z-session.rejected.000005.json" \
  "$(key session.rejected 20260925T100008Z "${REPLICA_SID}" 5)"
# Regression tooth: the sid-less input must produce the identical key, so a
# replica change back to the pre-fold sid-bearing shape fails here.
is "replica golden session.rejected sid-less (sid dropped, not consumed)" \
  "audit/20260925T100008Z-session.rejected.000005.json" \
  "$(key session.rejected 20260925T100008Z "" 5)"
# The forced-sid-less rule drops ANY sid, non-UUID included, exactly like the
# real builder (functional round-10 LOW: the non-UUID check used to precede
# the forced-sid-less branch and refused the documented key).
is "replica golden session.rejected with a non-UUID sid (any sid dropped)" \
  "audit/20260925T100008Z-session.rejected.000005.json" \
  "$(key session.rejected 20260925T100008Z not-a-uuid 5)"
is "replica golden non-session key sid-less" \
  "audit/20260925T100008Z-user.login.000006.json" \
  "$(key user.login 20260925T100008Z "" 6)"
# Round-4 LOW 3 fixed divergences, pinned as literal goldens as well as in
# the checked-in real-builder vector matrix below: uppercase sid lowercased,
# multi-segment session.* sanitized to `unknown`, 7-digit seq past 999999.
is "replica golden uppercase sid lowercased" \
  "audit/20260925T100008Z-session.start.${REPLICA_SID}.000001.shell.json" \
  "$(key session.start 20260925T100008Z "9F8C4B1E-0D2A-4F7E-9C11-2B3D4E5F6A70" 1 shell)"
is "replica golden multi-segment session.* sanitized to unknown" \
  "audit/20260925T100008Z-unknown.000001.json" \
  "$(key session.foo.bar 20260925T100008Z "" 1)"
# pc-admin #19 (@ 3325aeb): the exact single-segment `session.data` with no
# effective strict-UUID sid is sanctioned onto the documented `unknown`
# non-session shape (v18 port-forward traffic accounting); the expected
# literal is re-derived from the rule, so a replica that stops mirroring the
# scoped sanction fails here too (the vector matrix pins the real-builder
# output).
is "replica golden sid-less session.data sanitized to unknown" \
  "audit/20260925T100008Z-unknown.000002.json" \
  "$(key session.data 20260925T100008Z "" 2)"
# A non-UUID (but string) sid must take the same sanctioned path: the sanction
# predicate is the *effective* sid, not the raw truthiness — the red-team
# round-1 ``not effective_sid`` -> ``not sid`` mutant must fail here.
is "replica golden session.data with a non-UUID sid sanitized to unknown" \
  "audit/20260925T100008Z-unknown.000003.json" \
  "$(key session.data 20260925T100008Z not-a-uuid 3)"
is "replica golden seq 10^6 (seven digits, past the old ceiling)" \
  "audit/20260925T100008Z-session.data.${REPLICA_SID}.1000000.json" \
  "$(key session.data 20260925T100008Z "${REPLICA_SID}" 1000000)"
# Round-6 cross-repo sync: the builder caps an over-long event type at 128
# chars, drops a trailing separator and appends `_<sha256[:8]>` (pc-admin @
# 41735ff). The expected key here is re-derived independently from the rule so
# a replica that stops mirroring the cap fails on these literals too (the
# vector matrix below pins the real-builder output).
LONG_TYPE="$(python3 -c 'print("z" * 130)')"
LONG_KEY="$(python3 - "${LONG_TYPE}" <<'PY'
import hashlib
import sys

event_type = sys.argv[1]
head = event_type[:128 - 8 - 1].rstrip(".")
print("audit/20260925T100008Z-%s_%s.000001.json" % (head, hashlib.sha256(event_type.encode()).hexdigest()[:8]))
PY
)"
is "replica golden over-long type truncated + hash suffix" \
  "${LONG_KEY}" \
  "$(key "${LONG_TYPE}" 20260925T100008Z "" 1)"
ALIAS_A="$(python3 -c 'print("z" * 128 + "alpha")')"
ALIAS_B="$(python3 -c 'print("z" * 128 + "beta")')"
if [ "$(key "${ALIAS_A}" 20260925T100008Z "" 1)" != "$(key "${ALIAS_B}" 20260925T100008Z "" 1)" ]; then
  ok "distinct over-long types with a shared 119-char head keep distinct keys"
else
  bad "over-long type truncation aliased two distinct types to one key"
fi
# Round-8 cross-repo sync: a replay-conflict variant key (pc-admin @ a7035a9)
# appends `_<sha256[:16]>` of the body bytes to the event type; a session
# lifecycle variant drops its mode marker and the sid-less shape joins the
# hash to the last type segment. The expected suffix is re-derived here from
# the body, so a replica that stops mirroring the variant shape fails these
# literals too (the vector matrix below pins the real-builder output).
VARIANT_BODY='{"event":"session.start","v":"harness-golden"}'
VARIANT_HASH="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest()[:16])' "${VARIANT_BODY}")"
is "replica golden session.start variant (mode dropped)" \
  "audit/20260925T100008Z-session.start_${VARIANT_HASH}.${REPLICA_SID}.000001.json" \
  "$(variant_key "${VARIANT_BODY}" session.start 20260925T100008Z "${REPLICA_SID}" 1 exec)"
is "replica golden session.rejected variant (hash joins last segment)" \
  "audit/20260925T100008Z-session.rejected_${VARIANT_HASH}.000005.json" \
  "$(variant_key "${VARIANT_BODY}" session.rejected 20260925T100008Z "${REPLICA_SID}" 5)"
is "replica golden user.login variant (hash joins last segment)" \
  "audit/20260925T100008Z-user.login_${VARIANT_HASH}.000006.json" \
  "$(variant_key "${VARIANT_BODY}" user.login 20260925T100008Z "" 6)"
VARIANT_BODY_OTHER='{"event":"session.start","v":"harness-other"}'
if [ "$(variant_key "${VARIANT_BODY}" session.start 20260925T100008Z "${REPLICA_SID}" 1 exec)" \
     != "$(variant_key "${VARIANT_BODY_OTHER}" session.start 20260925T100008Z "${REPLICA_SID}" 1 exec)" ]; then
  ok "distinct replay-variant body bytes build distinct variant keys"
else
  bad "replay-conflict variant key ignored the body bytes"
fi
# Dated layout (pc-admin #30, the pinned builder's default): the same
# basenames under `audit/YYYYMMDD/`, and the variant keeps its day segment.
# These literals pin the dated golden independently of the vector matrix.
DATE="20260925"
is "replica dated golden session.start shell" \
  "audit/${DATE}/20260925T100008Z-session.start.${REPLICA_SID}.000001.shell.json" \
  "$(dated_key session.start 20260925T100008Z "${REPLICA_SID}" 1 shell)"
is "replica dated golden session.end exec" \
  "audit/${DATE}/20260925T100008Z-session.end.${REPLICA_SID}.000002.exec.json" \
  "$(dated_key session.end 20260925T100008Z "${REPLICA_SID}" 2 exec)"
is "replica dated golden session.data (no mode suffix)" \
  "audit/${DATE}/20260925T100008Z-session.data.${REPLICA_SID}.000007.json" \
  "$(dated_key session.data 20260925T100008Z "${REPLICA_SID}" 7)"
is "replica dated golden session.rejected forced sid-less" \
  "audit/${DATE}/20260925T100008Z-session.rejected.000005.json" \
  "$(dated_key session.rejected 20260925T100008Z "${REPLICA_SID}" 5)"
is "replica dated golden non-session key sid-less" \
  "audit/${DATE}/20260925T100008Z-user.login.000006.json" \
  "$(dated_key user.login 20260925T100008Z "" 6)"
is "replica dated golden session.start variant keeps the day segment" \
  "audit/${DATE}/20260925T100008Z-session.start_${VARIANT_HASH}.${REPLICA_SID}.000001.json" \
  "$(dated_variant_key "${VARIANT_BODY}" session.start 20260925T100008Z "${REPLICA_SID}" 1 exec)"
is "replica dated golden user.login variant keeps the day segment" \
  "audit/${DATE}/20260925T100008Z-user.login_${VARIANT_HASH}.000006.json" \
  "$(dated_variant_key "${VARIANT_BODY}" user.login 20260925T100008Z "" 6)"
# The replica must refuse any unexpected shape instead of silently building a
# key the real shipper cannot emit.
replica_refuses() { # <label> <expected-refusal-reason> + shipper_keys.py args; non-zero = refused
  # Drop the label AND the expected reason: the CLI signature is
  # <event-type> <ts> [sid] [seq] [mode]. Passing the label as the event type
  # made every tooth a no-op (red-team round-1 HIGH on #149) — the CLI died
  # on the shifted ``ts`` argument. Asserting the refusal *reason* keeps that
  # fix regression-sensitive: a no-op refusal (wrong argv, CLI dying on an
  # unrelated argument) fails the tooth instead of counting as this shape
  # being refused (red-team round-2 LOW).
  local label="$1" expected="$2" err=""
  shift 2
  if err="$(python3 "${HARNESS_DIR}/shipper_keys.py" "$@" 2>&1 >/dev/null)"; then
    bad "replica accepted an unexpected shape: $label"
  elif [[ "$err" != *"$expected"* ]]; then
    bad "replica refused '$label' for the wrong reason (want '$expected'): $err"
  else
    ok "replica refuses unexpected shape: $label"
  fi
}
replica_refuses "session.start non-UUID sid" "non-UUID sid" session.start 20260925T100008Z not-a-uuid 1
# Non-canonical sid shapes: the replica must NOT normalize (no strip/lstrip/
# rstrip/partition, no dash/brace/quote/URN unwrapping, no space or
# separator deletion, no width folding) — the real builder ``fullmatch``es
# the canonical strict-UUID pattern only. Every shape here takes the
# sanctioned `unknown` path on the exact single-segment `session.data` and
# the refusal path on any other session type. The grid pins the per-shape
# mutants found across lens rounds 2–6 (search/match, strip family and
# side-specific trims, delimiter/quote/URN wrappers, interior separators,
# fullwidth/zero-width folding); pattern-arity relaxations are killed
# outright by the pattern-constant pin below. Uppercase is canonical (the
# builder lowercases) and is pinned by the vector matrix separately.
ZWSP="$(printf '\xe2\x80\x8b')"
SID_SHAPE_SEQ=6
for sid_shape in \
  "leading-junk|x${REPLICA_SID}y" \
  "trailing-junk|${REPLICA_SID}y" \
  "leading-space| ${REPLICA_SID}" \
  "trailing-space|${REPLICA_SID} " \
  "overlong-tail|${REPLICA_SID}f" \
  "short-tail|${REPLICA_SID%?}" \
  "no-dash|${REPLICA_SID//-/}" \
  "braces|{${REPLICA_SID}}" \
  "urn|urn:uuid:${REPLICA_SID}" \
  "leading-dash|-${REPLICA_SID}" \
  "trailing-dash|${REPLICA_SID}-" \
  "brace-open|{${REPLICA_SID}" \
  "brace-close|${REPLICA_SID}}" \
  "double-quoted|\"${REPLICA_SID}\"" \
  "single-quoted|'${REPLICA_SID}'" \
  "interior-space|9f8c4b1e -0d2a-4f7e-9c11-2b3d4e5f6a70" \
  "underscore-separators|9f8c4b1e_0d2a_4f7e_9c11_2b3d4e5f6a70" \
  "fullwidth-hex|9ｆ8ｃ4ｂ1ｅ-0d2a-4f7e-9c11-2b3d4e5f6a70" \
  "zero-width-suffix|${REPLICA_SID}${ZWSP}" \
; do
  shape_name="${sid_shape%%|*}"; shaped_sid="${sid_shape#*|}"
  SID_SHAPE_SEQ=$((SID_SHAPE_SEQ + 1))
  is "replica golden session.data with a ${shape_name} sid sanitized to unknown" \
    "audit/20260925T100008Z-unknown.$(printf '%06d' "${SID_SHAPE_SEQ}").json" \
    "$(key session.data 20260925T100008Z "${shaped_sid}" "${SID_SHAPE_SEQ}")"
  replica_refuses "session.start ${shape_name} sid" "non-UUID sid" session.start 20260925T100008Z "${shaped_sid}" 1 shell
done
replica_refuses "session.start missing sid and mode" "mandatory" session.start 20260925T100008Z "" 1
replica_refuses "non-session with sid" "non-session" user.login 20260925T100008Z "${REPLICA_SID}" 1
replica_refuses "mode on non-lifecycle event" "only valid" session.data 20260925T100008Z "${REPLICA_SID}" 1 shell
replica_refuses "mode on non-session event" "only valid" user.login 20260925T100008Z "" 1 shell
replica_refuses "lifecycle without the mandatory mode" "mandatory" session.start 20260925T100008Z "${REPLICA_SID}" 1
replica_refuses "seq zero (legacy hand-written fixture only)" "seq must be" session.data 20260925T100008Z "${REPLICA_SID}" 0
replica_refuses "seq beyond the witness 18-digit grammar" "seq must be" session.data 20260925T100008Z "${REPLICA_SID}" 1000000000000000000
replica_refuses "session.start missing sid with mode" "without a sid" session.start 20260925T100008Z "" 1 shell
replica_refuses "over-long type outside the grammar (real builder sanitizes to unknown)" "outside the shipper grammar" \
  "$(python3 -c 'print("a" * 128 + "-bad")')" 20260925T100008Z "" 1
replica_refuses "session.Data case-variant non-UUID sid (the #19 sanction is exact)" "non-UUID sid" \
  session.Data 20260925T100008Z not-a-uuid 1
replica_refuses "session.dAtA case-variant non-UUID sid (the #19 sanction is exact)" "non-UUID sid" \
  session.dAtA 20260925T100008Z not-a-uuid 1
replica_refuses "over-long non-exact session.data type without a sid (capped near-match stays refused)" "without a sid" \
  "$(python3 -c 'print("session.data" + "q" * 500)')" 20260925T100008Z "" 1
# pc-admin #20: the type regexes are `\Z`-anchored, so a trailing newline is
# outside the grammar. The bash `$'…'` form carries a REAL newline (a plain
# "session.data\n" would be a literal backslash-n and pass vacuously), and
# the reason assert makes the tooth anchor-sensitive: under a `$` mutant the
# same argv would reach the sid-less-session refusal instead.
replica_refuses "trailing-newline type (real newline, \Z grammar)" "outside the shipper grammar" \
  $'session.data\n' 20260925T100008Z "" 1

# Direct-API teeth for the sid type (functional round-10 LOWs): the CLI is
# string-only, so only a direct call can pass a non-string sid. The real
# builder normalizes a non-string/non-UUID sid to ""; the replica must drop
# it on session.rejected, sanitize it on the exact session.data, and refuse
# with ValueError everywhere else — never crash with a TypeError from the
# regex. Non-string ts/event_type take the same clean ValueError path
# (functional round-11 INFO). Every replica-importing heredoc runs under
# `python3 -I` (cwd off sys.path), including this one. The checker prints a
# sentinel the bash layer asserts, so an import-time exit/panic that skips the
# whole checker cannot accidentally count as a pass; a replica that deliberately
# forges the marker is the documented in-process residual (red-team round-11
# LOW; trust round-12 INFO). Keep the wrapped heredoc bodies backtick-free:
# bash 3.2's `$()` scanner miscounts them and fails to parse (functional
# round-12 LOW).
if teeth_out="$(python3 -I - "${HARNESS_DIR}" <<'PY'
import importlib.util
import os
import sys

here = sys.argv[1]
spec = importlib.util.spec_from_file_location("shipper_keys", os.path.join(here, "shipper_keys.py"))
replica = importlib.util.module_from_spec(spec)
spec.loader.exec_module(replica)
ts = "20260925T100008Z"
if replica.audit_key("session.rejected", ts, 123, 5, flat=True) != "audit/%s-session.rejected.000005.json" % ts:
    raise SystemExit("session.rejected with a non-string sid must drop the sid")
if replica.audit_key("session.data", ts, 123, 1, flat=True) != "audit/%s-unknown.000001.json" % ts:
    raise SystemExit("session.data with a non-string sid must sanitize to unknown")
if replica.audit_key("session.rejected", ts, 123, 5) != "audit/20260925/%s-session.rejected.000005.json" % ts:
    raise SystemExit("the replica default layout must be the pinned dated layout")
try:
    replica.audit_key("session.start", ts, 123, 1, "shell", flat=True)
except ValueError:
    pass
else:
    raise SystemExit("session.start with a non-string sid must be refused with ValueError")
try:
    replica.audit_key("user.login", 1, "", 1)
except ValueError:
    pass
else:
    raise SystemExit("a non-string ts must be refused with ValueError")
try:
    replica.audit_key(1, ts, "", 1)
except ValueError:
    pass
else:
    raise SystemExit("a non-string event type must be refused with ValueError")
print("teeth=ok")
PY
)" && [[ "$teeth_out" == "teeth=ok" ]]; then
  ok "replica: non-string sid handling (drop on rejected/data, clean ValueError elsewhere)"
else
  bad "replica non-string sid handling diverged or the checker did not run (out: ${teeth_out:-<empty>})"
fi

# Provenance-checked golden + boundary matrix: shipper_key_vectors.json was
# generated from the REAL pc-admin builder at the pinned SHA
# (generate_shipper_vectors.py); every vector must replay exactly and every
# refusal must stay refused, or silent replica drift passes the harness.
# The bash layer asserts the exact printed sentinel line (counts + pinned
# source), so neither a skipped checker nor an appended extra line can read as
# a pass.
if matrix_out="$(python3 -I - "${HARNESS_DIR}" <<'PY'
import hashlib
import importlib.util
import json
import os
import re
import sys

here = sys.argv[1]
spec = importlib.util.spec_from_file_location("shipper_keys", os.path.join(here, "shipper_keys.py"))
replica = importlib.util.module_from_spec(spec)
spec.loader.exec_module(replica)
# Read the matrix bytes ONCE: the content pin and the replay must see the same
# bytes (a second open lets a FIFO swap feed the digest one file and the
# replay another — red-team round-3 LOW).
matrix_path = os.path.join(here, "shipper_key_vectors.json")
with open(matrix_path, "rb") as matrix_file:
    matrix_bytes = matrix_file.read()
vectors = json.loads(matrix_bytes.decode("utf-8"))


def replay(args, body=None, flat=False):
    args = list(args)
    args[3] = int(args[3])
    key = replica.audit_key(*args, flat=flat)
    if body is not None:
        # 'kind: "variant"' vectors carry the real builder's
        # 'disambiguate_audit_key' output for this body.
        key = replica.disambiguate_key(key, body)
    return key


if vectors.get("pinned_pc_admin_sha") != replica.PINNED_PC_ADMIN_SHA:
    raise SystemExit("vector pin %r != shipper_keys pin %r" % (
        vectors.get("pinned_pc_admin_sha"), replica.PINNED_PC_ADMIN_SHA))

# Matrix size pin: a deleted vector/segment/refusal entry must fail loudly
# instead of shrinking the matrix silently (red-team round-2 LOW M10). Update
# this pin together with the matrix.
if (len(vectors["vectors"]) != 32 or len(vectors["date_segments"]) != 15
        or len(vectors["refusals"]) != 17):
    raise SystemExit(
        "vector matrix size changed: %d vectors / %d segments / %d refusals "
        "(pinned 32/15/17) - update this pin together with the matrix"
        % (len(vectors["vectors"]), len(vectors["date_segments"]), len(vectors["refusals"])))

# Matrix content pin (red-team round-3 LOW): a coherent same-size rewrite
# (both event.sid and replica_args[2], or an entry swap) must fail loudly.
# Regenerate the matrix with generate_shipper_vectors.py and bump this sha256
# together with the file. The digest covers the SAME bytes that are replayed
# (single read above).
matrix_sha = hashlib.sha256(matrix_bytes).hexdigest()
MATRIX_SHA256 = "3fe6d705b75ab0ca2e8a4f42738b3680c6bd98cf06cf3a3da604fd81e60b03da"
if matrix_sha != MATRIX_SHA256:
    raise SystemExit(
        "vector matrix content changed (sha256 %s != pinned %s) - regenerate via "
        "generate_shipper_vectors.py and bump this pin" % (matrix_sha, MATRIX_SHA256))

# Pattern-constant pin (red-team round-6 LOW): a finite sid corpus cannot
# enumerate every possible pattern relaxation (group arity, extra dash
# classes); pin the literal strict-UUID pattern the replica must use (the
# same string the pinned pc-admin builder uses).
CANONICAL_UUID_PATTERN = (r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                          r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
if replica.UUID_PATTERN != CANONICAL_UUID_PATTERN:
    raise SystemExit(
        "replica UUID_PATTERN %r != pinned canonical pattern %r"
        % (replica.UUID_PATTERN, CANONICAL_UUID_PATTERN))
# The compiled matcher is what both call sites actually use: pin its pattern
# too, or a 're.compile(<other pattern>)' rebind bypasses the constant pin
# (round-7 MEDIUM — the semantics the constant pin rejects when written on
# the pattern line stay reachable on the compile line).
if replica.UUID_RE.pattern != CANONICAL_UUID_PATTERN:
    raise SystemExit(
        "replica UUID_RE.pattern %r != pinned canonical pattern %r"
        % (replica.UUID_RE.pattern, CANONICAL_UUID_PATTERN))
# Trailing-newline class (anchor #155 F2): pin the timestamp regex too.
# Python's `$` also matches before a trailing newline, so a `$`-anchored
# TS_RE accepts `20260925T100008Z\n` and builds a key with an embedded
# newline. The real builder's `audit_ts` emits `strftime` output (always
# newline-free), so this is defense-in-depth symmetry with the `\Z` type
# anchors (pc-admin #20).
CANONICAL_TS_PATTERN = r"^[0-9]{8}T[0-9]{6}Z\Z"
if replica.TS_RE.pattern != CANONICAL_TS_PATTERN:
    raise SystemExit(
        "replica TS_RE.pattern %r != pinned canonical pattern %r"
        % (replica.TS_RE.pattern, CANONICAL_TS_PATTERN))


def source_sha_ok(value):
    # Round-6 F6: exact 40-hex equality. 'startswith(pin)' accepted the short
    # prefix, a prefix plus junk, and any longer prefix-sharing hex string.
    return (isinstance(value, str)
            and re.fullmatch(r"[0-9a-f]{40}", value) is not None
            and value == replica.PINNED_PC_ADMIN_SHA)


source_sha = vectors.get("source_sha")
if not source_sha_ok(source_sha):
    raise SystemExit(
        "vector source_sha %r is not exactly the 40-hex grammar pin %r - a file generated with "
        "--allow-sha-mismatch must never be committed" % (source_sha, replica.PINNED_PC_ADMIN_SHA))
for hostile in (replica.PINNED_PC_ADMIN_SHA[:7], replica.PINNED_PC_ADMIN_SHA[:7] + "!!!",
                replica.PINNED_PC_ADMIN_SHA + "0", replica.PINNED_PC_ADMIN_SHA + "!!!",
                replica.PINNED_PC_ADMIN_SHA.upper(),
                # anchor #155 F1: a debug run stamps `<pin>-debug`; the
                # predicate must refuse it, never accept a pin-prefixed stamp.
                replica.PINNED_PC_ADMIN_SHA + "-debug"):
    if source_sha_ok(hostile):
        raise SystemExit("source_sha predicate accepted a hostile value: %r" % hostile)
for vector in vectors["vectors"]:
    sid_arg = vector["replica_args"][2]
    if not isinstance(sid_arg, str):
        raise SystemExit("%s: replica_args sid is not a string: %r" % (vector["name"], sid_arg))
    event_sid = vector.get("event", {}).get("sid")
    if isinstance(event_sid, str) and event_sid and replica.UUID_RE.fullmatch(event_sid) is None:
        # #19 two-sidedness (red-team round-2 LOW M6): a non-UUID sid vector
        # must pass the RAW sid through — the builder's sanction keys on the
        # *effective* sid, so rewriting this arg to "" makes the vector
        # floor-proof against the effective/raw mutant.
        if sid_arg != event_sid:
            raise SystemExit(
                "%s: non-UUID sid %r was rewritten to %r in replica_args"
                % (vector["name"], event_sid, sid_arg))
    got = replay(vector["replica_args"], vector.get("body"), flat=(vector.get("layout") == "flat"))
    if got != vector["expected"]:
        raise SystemExit("%s: expected %s got %s" % (vector["name"], vector["expected"], got))
for segment in vectors["date_segments"]:
    # Date-segment split (pc-admin #30 + #39): valid dated segments strip,
    # flat keys are unchanged, and malformed all-digit segments, a foreign
    # prefix and residual path segments are refused (never laundered). Each
    # entry carries its own prefix so the prefix argument round-trips.
    got = replica.split_date_segment(segment["key"], segment.get("prefix", "audit/"))
    if list(got) != [segment["relative"], segment["day"]]:
        raise SystemExit("%s: expected %r got %r" % (
            segment["name"], [segment["relative"], segment["day"]], list(got)))
for refusal in vectors["refusals"]:
    try:
        replay(refusal["replica_args"])
    except ValueError:
        continue
    raise SystemExit("refusal accepted: %s" % refusal["name"])
print("vectors=%d segments=%d refusals=%d pin=%s source=%s" % (
    len(vectors["vectors"]), len(vectors["date_segments"]), len(vectors["refusals"]),
    vectors["pinned_pc_admin_sha"], source_sha[:12]))
PY
)" && [[ "$matrix_out" == "vectors=32 segments=15 refusals=17 pin=9a2fe505b892411d25f731c2cf4e6361967fb911 source=9a2fe505b892" ]]; then
  ok "replica replays the real-builder golden+boundary vectors (pin-matched, refusals held)"
else
  bad "shipper replica diverged from the checked-in real-builder vectors or the checker did not run (out: ${matrix_out:-<empty>})"
fi

# F2 tooth (anchor #155): the replica TS_RE must be \Z-anchored. Python's `$`
# also matches before a trailing newline, so a `$`-anchored revert accepts
# this timestamp (rc 0) and builds a key with an embedded newline; the tooth
# then fails.
if python3 "${HARNESS_DIR}/shipper_keys.py" user.login $'20260925T100008Z\n' "" 1 >/dev/null 2>&1; then
  bad "replica TS_RE accepted a trailing-newline timestamp (must be \\Z-anchored)"
else
  ok "replica TS_RE refuses a trailing-newline timestamp (\\Z-anchored)"
fi

# F1 tooth (anchor #155): the generator's provenance guard must compare the
# worktree bytes against the committed HEAD blob, not `git status` —
# `update-index --assume-unchanged` hides a worktree edit from status while an
# import still reads the mutated bytes. Prove the helper True on pristine
# bytes, then mutate + assume-unchanged and prove status is clean AND the
# helper is False.
f1_repo="${WORK}/f1-repo"
mkdir -p "${f1_repo}/scripts/lib"
git -C "${f1_repo}" init -q
git -C "${f1_repo}" config user.email "harness@example.invalid"
git -C "${f1_repo}" config user.name "recording-witness harness"
# Commit on a scratch branch, never the init default (a protected-branch
# guard would refuse a fixture commit on `main`).
git -C "${f1_repo}" checkout -q -b harness-fixture
printf 'PINNED = 1\n' > "${f1_repo}/scripts/lib/b2_client.py"
git -C "${f1_repo}" add scripts/lib/b2_client.py
git -C "${f1_repo}" -c commit.gpgsign=false commit -q -m "pinned bytes"
f1_helper() {
  python3 -I -c 'import sys; sys.path.insert(0, sys.argv[1]); import generate_shipper_vectors as g; print(g.blob_matches_head(sys.argv[2], "scripts/lib/b2_client.py"))' "${HARNESS_DIR}" "$1"
}
f1_pristine="$(f1_helper "${f1_repo}")"
printf 'MUTATED = 1\n' > "${f1_repo}/scripts/lib/b2_client.py"
git -C "${f1_repo}" update-index --assume-unchanged scripts/lib/b2_client.py
f1_status="$(git -C "${f1_repo}" status --porcelain)"
f1_mutated="$(f1_helper "${f1_repo}")"
if [ "$f1_pristine" = "True" ] && [ "$f1_mutated" = "False" ] && [ -z "$f1_status" ]; then
  ok "generator provenance guard compares content (assume-unchanged edit refused, status clean)"
else
  bad "generator provenance guard: pristine=${f1_pristine:-<empty>} mutated=${f1_mutated:-<empty>} status='${f1_status}' (a content compare must catch an assume-unchanged edit)"
fi
# Sibling bypass (anchor #155 red-team LOW): a `git replace` ref makes
# `cat-file blob HEAD:<path>` return the replacement bytes while HEAD (the pin
# check) is unchanged; `--no-replace-objects` in the helper must keep the
# compare honest. Replace the committed blob with the mutated worktree blob
# and require the helper to still report False (a `--no-replace-objects`
# revert returns True here and fails this tooth).
git -C "${f1_repo}" replace -f "$(git -C "${f1_repo}" rev-parse HEAD:scripts/lib/b2_client.py)" "$(git -C "${f1_repo}" hash-object -w "${f1_repo}/scripts/lib/b2_client.py")"
f1_replaced="$(f1_helper "${f1_repo}")"
if [ "$f1_replaced" = "False" ]; then
  ok "generator provenance guard refuses a git-replace'd blob (--no-replace-objects)"
else
  bad "generator provenance guard: a git replace ref defeated the content compare (helper=${f1_replaced:-<empty>})"
fi
# Sibling bypass (anchor #155 red-team round 2): `spec_from_file_location(...)
# .exec_module` executes a `__pycache__` entry whose header mtime/size match
# the source, so a planted pyc could run while the guard vouched for the
# pinned bytes. `load_module_from_source` compiles the given bytes; plant a
# matching poisoned pyc and require the loader to ignore it.
f1_pyc_dir="${WORK}/f1-pyc"
mkdir -p "${f1_pyc_dir}"
printf 'PINNED = 1\n' > "${f1_pyc_dir}/b2_client.py"
if python3 -I - "${HARNESS_DIR}" "${f1_pyc_dir}" "${WORK}/f1-pyc-marker" <<'PY'
import importlib.util
import marshal
import os
import struct
import sys

harness, root, marker = sys.argv[1], sys.argv[2], sys.argv[3]
sys.path.insert(0, harness)
import generate_shipper_vectors as g

src = os.path.join(root, "b2_client.py")
stat = os.stat(src)
cache = importlib.util.cache_from_source(src)
os.makedirs(os.path.dirname(cache), exist_ok=True)
poison = "open(%r, 'w').write('tampered')\nPINNED = 999\n" % marker
code = compile(poison, src, "exec")
with open(cache, "wb") as handle:
    handle.write(importlib.util.MAGIC_NUMBER)
    handle.write(struct.pack("<III", 0, int(stat.st_mtime) & 0xFFFFFFFF, stat.st_size & 0xFFFFFFFF))
    handle.write(marshal.dumps(code))
with open(src, "rb") as handle:
    source = handle.read()
module = g.load_module_from_source(source, src, "probe")
if os.path.exists(marker):
    raise SystemExit("planted pyc executed")
if module.PINNED != 1:
    raise SystemExit("module did not come from the source bytes (PINNED=%r)" % (module.PINNED,))
print("pyc-ignored")
PY
then
  ok "generator loader compiles the compared bytes, never a planted __pycache__ entry"
else
  bad "generator loader executed a planted __pycache__ entry (source bytes not compiled)"
fi

# Canonical-sid oracle: a literal grid cannot enumerate every normalization
# mutant of the sid predicate. Assert the replica's acceptance equals an
# INDEPENDENT canonical oracle over a GENERATED corpus: every Unicode
# control (Cc), format (Cf), separator (Zs/Zl/Zp) and combining-mark
# (Mn/Me) codepoint inserted at prefix/suffix/interior, ASCII punctuation
# insertions and wrapper pairs, separator translations, a
# confusable/compatibility substitution set (incl. NFKC-foldable forms), and
# single-char deletions. A mutant that normalizes the sid before matching
# (strip/trim/replace/translate/normalize) diverges somewhere below; a
# mutant that rebinds the compiled matcher is killed by the UUID_RE.pattern
# pin in the vector block. The internal size AND distinctness floors run
# before the replica import and are re-checked immediately after it; the bash
# layer asserts the completion marker plus both printed numbers (size and
# distinct) against the 6500 floor — a post-import replacement of
# __main__.oracle_sids (truncated, or a same-size repeated literal) would
# otherwise ship the marker and pass (red-team round-13/round-14 MEDIUMs).
# The corpus size tracks the interpreter's Unicode DB (7137 on 3.9, 7476 on
# 3.11, 7602 on 3.12/3.13, 7707 on 3.14), so bash checks the numbers only
# against the floors, never an exact value: a skipped checker or a corpus
# below either floor cannot read as a pass (a replacement that clears both
# floors with substituted content is the documented deliberate-tamper
# residue).
oracle_rc=0
oracle_out="$(python3 -I - "${HARNESS_DIR}" <<'PY'
import importlib.util
import os
import re
import sys
import unicodedata

here = sys.argv[1]
ORACLE_TS = "20260925T100008Z"
ORACLE_BASE = "9f8c4b1e-0d2a-4f7e-9c11-2b3d4e5f6a70"
# Independent canonical predicate: same literal as the vector-block pin.
CANONICAL_UUID_PATTERN = (r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                          r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
# Build the independent predicate and the generated corpus BEFORE importing
# the replica, from the pristine primitives: an import-time rebind of
# 're.compile' / 'unicodedata.category' / '.normalize' — or a mutation of the
# shared function objects themselves ('re.compile.__code__ = ...', which a
# by-reference "freeze" cannot stop) — cannot change what the oracle already
# captured, and the corpus plus both floors are final before any replica code
# runs (red-team round-10 LOWs). The invocation is 'python3 -I' so the cwd is
# off sys.path and a shadow 're.py'/'unicodedata.py' cannot load either
# (red-team round-10 INFO).
ORACLE_RE = re.compile(CANONICAL_UUID_PATTERN)
# Capture the floor primitives BEFORE the import: the post-import floor
# re-check and the printed counts must not see a replica-builtins rebind
# (red-team round-14 LOW), and a count-preserving corpus replacement must
# still fail the distinctness floor (round-14 MEDIUM).
_canonical_len = len
_canonical_set = set

oracle_sids = [ORACLE_BASE, ORACLE_BASE.upper()]
pad_chars = []
for codepoint in range(0x110000):
    char = chr(codepoint)
    if unicodedata.category(char) in ("Cc", "Cf", "Zs", "Zl", "Zp", "Mn", "Me"):
        pad_chars.append(char)
pad_chars.extend("_-.:;,'\"\x60()[]{}<>|/\\!?@#$%^&*+=~ ")
for char in pad_chars:
    oracle_sids.append(char + ORACLE_BASE)
    oracle_sids.append(ORACLE_BASE + char)
    oracle_sids.append(ORACLE_BASE[:4] + char + ORACLE_BASE[4:])
for open_char, close_char in (("(", ")"), ("<", ">"), ("[", "]"), ("{", "}"),
                              ("\x60", "\x60"), ("'", "'"), ('"', '"')):
    oracle_sids.append(open_char + ORACLE_BASE + close_char)
oracle_sids.append("urn:uuid:" + ORACLE_BASE)
for separator in (".", "_", ":", " ", "|", "/", "\\", ",", ";", ""):
    oracle_sids.append(ORACLE_BASE.replace("-", separator))
confusables = {
    "0": "oOо٠", "1": "lIі١", "2": "zZ٢", "3": "з٣", "4": "٤д", "5": "sS$٥",
    "6": "gGб٦", "7": "tT۷", "8": "Ȣ٨", "9": "gq٩",
    "a": "аáα@", "b": "Ьß", "c": "сϲ¢", "d": "ԁդ", "e": "еé€", "f": "ғƒ",
}
for index, char in enumerate(ORACLE_BASE):
    for replacement in confusables.get(char.lower(), ""):
        oracle_sids.append(ORACLE_BASE[:index] + replacement + ORACLE_BASE[index + 1:])
for low, high in ((0x2070, 0x209F), (0x2100, 0x214F), (0x2150, 0x218F),
                  (0x2460, 0x24FF), (0x1D400, 0x1D7FF), (0xFF01, 0xFF5E)):
    for codepoint in range(low, high + 1):
        folded = unicodedata.normalize("NFKC", chr(codepoint))
        if len(folded) == 1 and folded in "0123456789abcdefABCDEF":
            for index, char in enumerate(ORACLE_BASE):
                if char == folded.lower():
                    oracle_sids.append(ORACLE_BASE[:index] + chr(codepoint) + ORACLE_BASE[index + 1:])
for index in range(len(ORACLE_BASE)):
    oracle_sids.append(ORACLE_BASE[:index] + ORACLE_BASE[index + 1:])
# Synthetic canonical-pattern near-misses: a 36-char dashless hex string and
# an all-dash string are non-canonical; they pin hostile same-'.pattern'
# matchers that accept a broad hex/dash class behaviorally.
oracle_sids.append("a" * 36)
oracle_sids.append("-" * 36)
if len(oracle_sids) < 6500:
    raise SystemExit("canonical-sid oracle corpus shrank: %d cases" % len(oracle_sids))
# A size floor alone passes a degenerate corpus (one literal repeated); require
# distinct sids too so the corpus cannot be replaced by a repeated literal.
if len(set(oracle_sids)) < 6500:
    raise SystemExit("canonical-sid oracle corpus lost distinctness: %d unique sids" % len(set(oracle_sids)))

# Now import the replica and run its checks against the already-frozen corpus
# and predicate. Re-assert the pattern pins in THIS process too: the
# vector-block pins run in a separate interpreter, so a per-process rebind
# would escape them.
spec = importlib.util.spec_from_file_location("shipper_keys", os.path.join(here, "shipper_keys.py"))
replica = importlib.util.module_from_spec(spec)
spec.loader.exec_module(replica)
if replica.UUID_PATTERN != CANONICAL_UUID_PATTERN or replica.UUID_RE.pattern != CANONICAL_UUID_PATTERN:
    raise SystemExit("replica UUID pattern pins diverged in the oracle process")
# Re-enforce both floors on the corpus as it stands AFTER the replica import:
# a replica can reassign __main__.oracle_sids at import time, and a
# count-preserving replacement would otherwise mask a divergence while the
# pre-import floors still vouch for the original corpus (red-team round-14
# MEDIUM). _canonical_len/_canonical_set are the pre-import captures, so a
# builtins rebind cannot fabricate these numbers either (round-14 LOW).
if _canonical_len(oracle_sids) < 6500:
    raise SystemExit("canonical-sid oracle corpus shrank after import: %d cases" % _canonical_len(oracle_sids))
if _canonical_len(_canonical_set(oracle_sids)) < 6500:
    raise SystemExit("canonical-sid oracle corpus lost distinctness after import: %d unique sids" % _canonical_len(_canonical_set(oracle_sids)))

failures = []
for sid in oracle_sids:
    canonical = ORACLE_RE.fullmatch(sid) is not None
    try:
        data_key = replica.audit_key("session.data", ORACLE_TS, sid, 1, flat=True)
    except ValueError:
        data_key = None
    try:
        replica.audit_key("session.start", ORACLE_TS, sid, 1, "shell", flat=True)
        start_scoped = True
    except ValueError:
        start_scoped = False
    if canonical:
        good = start_scoped and data_key == "audit/%s-session.data.%s.000001.json" % (ORACLE_TS, sid.lower())
    else:
        good = (not start_scoped) and data_key == "audit/%s-unknown.000001.json" % ORACLE_TS
    if not good:
        failures.append((sid, canonical, start_scoped, data_key))
if failures:
    sid, canonical, start_scoped, data_key = failures[0]
    raise SystemExit(
        "canonical-sid oracle divergence on %d/%d cases "
        "(first %r canonical=%s start_scoped=%s data_key=%s)"
        % (len(failures), len(oracle_sids), sid, canonical, start_scoped, data_key))
print("oracle=%d cases, %d distinct" % (_canonical_len(oracle_sids), _canonical_len(_canonical_set(oracle_sids))))
print("oracle=ok")
PY
)" || oracle_rc=$?
# Enforce both corpus floors on the printed counts (second-to-last line): the
# checker's internal floors run before the replica import, so a post-import
# replacement of __main__.oracle_sids — truncated, or the same-size repeated
# literal — would otherwise ship the marker and pass (red-team round-13/14
# MEDIUMs; the checker re-checks the floors too). The count is
# interpreter-dependent, so only the floors are compared, never an exact
# value.
oracle_last="${oracle_out##*$'\n'}"
oracle_prev="${oracle_out%$'\n'*}"
oracle_prev="${oracle_prev##*$'\n'}"
oracle_counts="${oracle_prev#oracle=}"
oracle_count="${oracle_counts%% cases*}"
oracle_distinct="${oracle_counts##* cases, }"
oracle_distinct="${oracle_distinct%% *}"
if [[ "$oracle_rc" == 0 && "$oracle_last" == "oracle=ok" \
      && "$oracle_prev" == oracle=*" cases, "*" distinct" \
      && "$oracle_count" =~ ^[0-9]+$ && "$oracle_distinct" =~ ^[0-9]+$ \
      && "$oracle_count" -ge 6500 && "$oracle_distinct" -ge 6500 ]]; then
  ok "canonical-sid oracle corpus (generated; no normalization divergence)"
else
  bad "shipper replica diverged from the canonical-sid oracle corpus or the checker did not run (out: ${oracle_out:-<empty>})"
fi

# The extracted span calls these on-box helpers; stub them in the harness.
log()  { printf 'harness: %s\n' "$*" >&2; }
warn() { printf 'harness WARNING: %s\n' "$*" >&2; }
die()  { printf 'FAIL(die): %s\n' "$*" >&2; exit 1; }

# ---- extract the real span (markers must be unique) ----------------------
BEGIN='# --- BEGIN RECORDING WITNESS (tests/recording-witness extracts this span; keep markers) ---'
END='# --- END RECORDING WITNESS ---'
for marker in "$BEGIN" "$END"; do
  count="$(grep -cF -- "$marker" "$PROVISION" || true)"
  [ "$count" = "1" ] || { printf 'FAIL marker %s found %s times\n' "$marker" "${count:-0}"; exit 1; }
done
begin_line="$(grep -nF -- "$BEGIN" "$PROVISION" | cut -d: -f1)"
end_line="$(grep -nF -- "$END" "$PROVISION" | cut -d: -f1)"
sed -n "$((begin_line + 1)),$((end_line - 1))p" "$PROVISION" >"${WORK}/span.src"
[ -s "${WORK}/span.src" ] || { printf 'FAIL extracted witness span is empty\n'; exit 1; }
# shellcheck disable=SC1090  # extracted span, path is fixed above
source "${WORK}/span.src"
for fn in render_recording_witness render_recording_witness_service render_recording_witness_timer \
          recording_witness_state recording_witness_config_problem recording_witness_install recording_witness_disable; do
  declare -f "$fn" >/dev/null || { printf 'FAIL extraction did not yield %s\n' "$fn"; exit 1; }
done

# ---- (a) rendered witness: bash -n + shellcheck --------------------------
WITNESS="${WORK}/pc-recording-witness.sh"
render_recording_witness >"${WITNESS}"
chmod +x "${WITNESS}"
if bash -n "${WITNESS}"; then ok "rendered witness parses (bash -n)"; else bad "rendered witness fails bash -n"; fi
if command -v shellcheck >/dev/null 2>&1; then
  if shellcheck -S warning "${WITNESS}"; then ok "rendered witness passes shellcheck -S warning"; else bad "rendered witness fails shellcheck -S warning"; fi
else
  printf 'note: shellcheck not installed — lint tooth skipped here (CI runs it)\n'
  SHELLCHECK_SKIPPED=1
fi

# ---- (b) rendered units --------------------------------------------------
render_recording_witness_service >"${WORK}/witness.service"
render_recording_witness_timer >"${WORK}/witness.timer"
grep -q '^ExecStart=/usr/local/sbin/pc-recording-witness.sh$' "${WORK}/witness.service" \
  && ok "service ExecStart is the canonical witness path" || bad "service ExecStart wrong"
grep -q '^ReadWritePaths=/var/lib/piercloud/recording-witness$' "${WORK}/witness.service" \
  && ok "service ReadWritePaths is the state dir" || bad "service ReadWritePaths wrong"
grep -q '^OnUnitInactiveSec=5min$' "${WORK}/witness.timer" \
  && ok "timer cadence is 5 min" || bad "timer cadence wrong"
grep -q '^OnBootSec=2min$' "${WORK}/witness.timer" \
  && ok "timer runs once 2 min after boot" || bad "timer OnBootSec wrong"

# ---- (c) env parsing -----------------------------------------------------
unset RECORDING_WITNESS_ENDPOINT RECORDING_WITNESS_BUCKET RECORDING_WITNESS_AUDIT_PREFIX \
      RECORDING_WITNESS_RECORDINGS_PREFIX RECORDING_WITNESS_KEY_ID RECORDING_WITNESS_KEY
is "no env -> off" "off" "$(recording_witness_state)"
export RECORDING_WITNESS_ENDPOINT="https://s3.eu-central-003.backblazeb2.com"
export RECORDING_WITNESS_BUCKET="pc-admin-dr"
export RECORDING_WITNESS_AUDIT_PREFIX="audit/"
export RECORDING_WITNESS_RECORDINGS_PREFIX="recordings/"
export RECORDING_WITNESS_KEY_ID="key-id"
export RECORDING_WITNESS_KEY="key-value"
is "full valid env -> on" "on" "$(recording_witness_state)"
saved_key="${RECORDING_WITNESS_KEY}"
unset RECORDING_WITNESS_KEY
is "missing key -> partial" "partial" "$(recording_witness_state)"
RECORDING_WITNESS_KEY="${saved_key}"
RECORDING_WITNESS_ENDPOINT="ftp://example.invalid"
is "bad endpoint -> partial" "partial" "$(recording_witness_state)"
RECORDING_WITNESS_ENDPOINT="https://s3.eu-central-003.backblazeb2.com"
RECORDING_WITNESS_AUDIT_PREFIX="audit"
is "prefix without slash -> partial" "partial" "$(recording_witness_state)"
RECORDING_WITNESS_AUDIT_PREFIX="audit/"
case "$(recording_witness_config_problem)" in
  '') ok "full valid env has no config problem" ;;
  *) bad "full valid env reports a problem: $(recording_witness_config_problem)" ;;
esac

# ---- mock S3 scenarios ---------------------------------------------------
MOCK_PORT=""
MOCK_PORT_FILE="${WORK}/mock.port"
FIXTURE="${WORK}/fixture.json"
REQUEST_LOG="${WORK}/requests.log"
: >"${REQUEST_LOG}"
SID="9f8c4b1e-0d2a-4f7e-9c11-2b3d4e5f6a70"
SID2="1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"

start_mock() {
  if [ -n "${MOCK_PID}" ]; then
    kill "${MOCK_PID}" 2>/dev/null || true
    wait "${MOCK_PID}" 2>/dev/null || true
    MOCK_PID=""
  fi
  rm -f "${MOCK_PORT_FILE}"
  python3 "${MOCK_S3}" "${FIXTURE}" "${MOCK_PORT_FILE}" "${REQUEST_LOG}" &
  MOCK_PID=$!
  attempt=0
  while [ ! -s "${MOCK_PORT_FILE}" ]; do
    attempt=$((attempt + 1))
    if [ "$attempt" -gt 50 ]; then bad "mock server did not start"; return 1; fi
    sleep 0.1
  done
  MOCK_PORT="$(cat "${MOCK_PORT_FILE}")"
}

fixture() { # read a fixture JSON on stdin, inject the SigV4 signature, save
  python3 -c '
import json
import sys

data = json.load(sys.stdin)
data.setdefault(
    "signature",
    {"key_id": "test-key-id-0001", "key": "test-secret-SENTINEL-0009", "region": "test-region"},
)
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(data, handle)
' "${FIXTURE}"
}

state_field() { # $1 = dotted path into the CASE_STATE_DIR state.json
  python3 -c '
import json, sys
try:
    node = json.load(open(sys.argv[1]))
except (OSError, ValueError, RecursionError):
    node = {}
for part in sys.argv[2].split("."):
    node = node.get(part, "") if isinstance(node, dict) else ""
print(node)
' "${CASE_STATE_DIR:-${WORK}/state}/state.json" "$1" 2>/dev/null || true
}

force_sweep_state() { # rewrite a readable state.json into a valid, sweep-due observed block
  # Optional second argument `keep-cursors` preserves the persisted cursors
  # (the below-cursor replay tooth: the forced sweep must be able to catch a
  # key below its own cursor, so it cannot be handed blank cursors).
  local state_path="$1/state.json"
  [ -f "${state_path}" ] || return 0
  python3 - "${state_path}" "${2:-}" <<'PY'
import json
import sys

path = sys.argv[1]
keep_cursors = len(sys.argv) > 2 and sys.argv[2] == "keep-cursors"
try:
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
except (OSError, ValueError, RecursionError):
    raise SystemExit(0)
if not isinstance(data, dict):
    raise SystemExit(0)
run_seq = data.get("run_seq")
if isinstance(run_seq, bool) or not isinstance(run_seq, int) or run_seq < 0:
    run_seq = 0
existing = data.get("observed") if isinstance(data.get("observed"), dict) else {}
boundaries = existing.get("sweep_boundaries") if isinstance(existing.get("sweep_boundaries"), list) else []
cursors = existing.get("cursors") if isinstance(existing.get("cursors"), dict) else {}
if not keep_cursors:
    cursors = {"audit_heartbeat": "", "audit_session": "", "recordings": ""}
data["observed"] = {
    "cursor_version": 1,
    "generation": 1,
    "written_run_seq": run_seq,
    "last_sweep_ok_epoch": 0,
    "last_sweep_ok_run_seq": 0,
    "sweep_due_epoch": 0,
    "sweep_failed": False,
    "coverage": {"mode": "sweep", "window_start": None, "compact_blind": False},
    "cursors": cursors,
    # Keep prior boundaries: a forced sweep may still range-split, and the
    # union of the branches is the same key set whichever boundaries were
    # sampled from an earlier fixture.
    "sweep_boundaries": boundaries,
}
with open(path, "w", encoding="utf-8") as handle:
    json.dump(data, handle)
PY
}

run_case_raw() { # like run_case but never rewrites the persisted observed block
  CASE_STATE_DIR="${1:-${WORK}/state}"
  cat >"${WORK}/witness.env" <<EOF
RECORDING_WITNESS_ENDPOINT=http://127.0.0.1:${MOCK_PORT}
RECORDING_WITNESS_REGION=test-region
RECORDING_WITNESS_BUCKET=pc-admin-dr
RECORDING_WITNESS_AUDIT_PREFIX=audit/
RECORDING_WITNESS_RECORDINGS_PREFIX=recordings/
RECORDING_WITNESS_KEY_ID=test-key-id-0001
RECORDING_WITNESS_KEY=test-secret-SENTINEL-0009
RECORDING_WITNESS_STATE_DIR=${CASE_STATE_DIR}
# The cold-start window is disabled unless a tooth asks for a seed (a fresh
# state dir is then an exact full sweep, keeping historical verdicts).
RECORDING_WITNESS_COLD_START_SECONDS=${RECORDING_WITNESS_COLD_START_SECONDS:-0}
EOF
  if [ -n "${RECORDING_WITNESS_LIST_WORKERS:-}" ]; then
    printf 'RECORDING_WITNESS_LIST_WORKERS=%s\n' "${RECORDING_WITNESS_LIST_WORKERS}" >>"${WORK}/witness.env"
  fi
  if [ -n "${RECORDING_WITNESS_EXTRA_ENV:-}" ]; then
    printf '%s\n' "${RECORDING_WITNESS_EXTRA_ENV}" >>"${WORK}/witness.env"
  fi
  export RECORDING_WITNESS_ENV_FILE="${WORK}/witness.env"
  CASE_RC=0
  "${WITNESS}" >"${WORK}/witness.out" 2>"${WORK}/witness.err" || CASE_RC=$?
  CASE_STATE="$(state_field state)"
  CASE_DETAIL="$(state_field detail)"
}

run_delta() { # delta/seed teeth: keep the persisted cursors + view sidecar
  run_case_raw "$@"
}

run_case() { # fixture at ${FIXTURE} ($1 = optional state dir); sets CASE_RC / CASE_STATE / CASE_DETAIL
  CASE_STATE_DIR="${1:-${WORK}/state}"
  # Stage-3 seam: every historical scenario stays a byte-identical exact
  # sweep by forcing the observed block sweep-due (0), even after a previous
  # run advanced its cursors. Delta teeth use run_delta, which skips this.
  force_sweep_state "${CASE_STATE_DIR}"
  run_case_raw "${CASE_STATE_DIR}"
}

fixture <<JSON
{"bucket":"pc-admin-dr","page_size":2,
 "signature":{"key_id":"test-key-id-0001","key":"test-secret-SENTINEL-0009","region":"test-region"},
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"audit/20260925T135000Z-session.start.${SID}.0.json","ago":300},
  {"key":"audit/20260925T135100Z-session.data.${SID}.1.json","ago":299},
  {"key":"audit/20260925T135200Z-session.end.${SID}.2.json","ago":298},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_case
is "healthy fixture (paginated) -> exit 0" "0" "${CASE_RC}"
is "healthy fixture -> ok verdict" "ok" "${CASE_STATE}"
case "${CASE_DETAIL}" in
  *hidden-object*) bad "healthy fixture (no delete markers) reported hidden-object: ${CASE_DETAIL}" ;;
  *) ok "healthy fixture with no delete markers stays free of hidden-object" ;;
esac

fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":1200},
  {"key":"audit/20260925T135000Z-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_case
is "stale heartbeat -> exit 1" "1" "${CASE_RC}"
is "stale heartbeat -> alert verdict" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in *heartbeat-stale*) ok "stale heartbeat detail names heartbeat-stale" ;; *) bad "stale heartbeat detail: ${CASE_DETAIL}" ;; esac

fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[],
 "uploads":[]}
JSON
start_mock
run_case
is "no heartbeat object -> exit 1" "1" "${CASE_RC}"
is "no heartbeat object -> alert verdict" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in *heartbeat-missing*) ok "heartbeat-missing detail names heartbeat-missing" ;; *) bad "heartbeat-missing detail: ${CASE_DETAIL}" ;; esac

fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"audit/20260925T130000Z-session.start.${SID}.0.json","ago":1200},
  {"key":"audit/20260925T130100Z-session.end.${SID}.1.json","ago":1199}],
 "uploads":[]}
JSON
start_mock
run_case
is "session.start without recording -> exit 1" "1" "${CASE_RC}"
is "session.start without recording -> alert" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in *recording-gap*) ok "recording gap detail names recording-gap" ;; *) bad "recording gap detail: ${CASE_DETAIL}" ;; esac

fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"audit/20260925T120000Z-session.start.${SID}.0.json","ago":3600},
  {"key":"audit/20260925T125000Z-session.end.${SID}.1.json","ago":1000}],
 "uploads":[{"key":"recordings/${SID}.tar","upload_id":"u-1","ago":3600}]}
JSON
start_mock
run_case
is "upload with old session.end -> exit 1" "1" "${CASE_RC}"
is "upload with old session.end -> alert" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in *completer-lag*) ok "completer lag detail names completer-lag" ;; *) bad "completer lag detail: ${CASE_DETAIL}" ;; esac

fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"audit/20260925T120000Z-session.start.${SID}.0.json","ago":3600}],
 "uploads":[{"key":"recordings/${SID}.tar","upload_id":"u-1","ago":3600}]}
JSON
start_mock
run_case
is "long live session (old upload, no session.end) -> exit 0" "0" "${CASE_RC}"
is "long live session -> ok verdict (review finding 2 tooth)" "ok" "${CASE_STATE}"

fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"audit/20260925T135000Z-session.start.${SID}.0.json","ago":300},
  {"key":"audit/20260925T135100Z-session.data.${SID}.1.json","ago":299},
  {"key":"audit/20260925T135200Z-session.end.${SID}.3.json","ago":298},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_case
is "missing <seq> -> exit 1" "1" "${CASE_RC}"
is "missing <seq> -> alert" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in *sequence-gap*) ok "sequence gap detail names sequence-gap" ;; *) bad "sequence gap detail: ${CASE_DETAIL}" ;; esac

fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"audit/20260925T135000Z-session.start.${SID}.0.json","ago":300},
  {"key":"audit/20260925T135100Z-session.data.${SID}.1.json","ago":299},
  {"key":"audit/20260925T135200Z-session.leave.${SID}.1.json","ago":298},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_case
is "repeated (sid, seq) -> exit 1" "1" "${CASE_RC}"
is "repeated (sid, seq) -> alert" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in *sequence-duplicate*) ok "duplicate seq detail names sequence-duplicate" ;; *) bad "duplicate seq detail: ${CASE_DETAIL}" ;; esac

fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"audit/20260925T135000Z-session.start.not-a-uuid.0.json","ago":300}],
 "uploads":[]}
JSON
start_mock
run_case
is "unrecognized session key -> exit 1" "1" "${CASE_RC}"
is "unrecognized session key -> alert" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in *naming-contract*) ok "naming drift detail names naming-contract" ;; *) bad "naming drift detail: ${CASE_DETAIL}" ;; esac

# ---- red-team finding 1: stream closure, seq origin, open-upload bound ----

fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"audit/20260925T135100Z-session.data.${SID}.1.json","ago":299},
  {"key":"audit/20260925T135200Z-session.end.${SID}.2.json","ago":298},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_case
is "session events without session.start -> exit 1" "1" "${CASE_RC}"
is "session events without session.start -> alert" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in *session-start-missing*) ok "stream-closure detail names session-start-missing" ;; *) bad "stream-closure detail: ${CASE_DETAIL}" ;; esac

fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"audit/20260925T135000Z-session.start.${SID}.5.shell.json","ago":300},
  {"key":"audit/20260925T135100Z-session.data.${SID}.6.json","ago":299},
  {"key":"audit/20260925T135200Z-session.end.${SID}.7.shell.json","ago":298},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_case
is "session starting at seq 5 -> exit 1" "1" "${CASE_RC}"
is "session starting at seq 5 -> alert" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in *sequence-origin*) ok "seq-origin detail names sequence-origin" ;; *) bad "seq-origin detail: ${CASE_DETAIL}" ;; esac

fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"audit/20260925T060000Z-session.start.${SID}.0.json","ago":90000},
  {"key":"audit/20260925T060100Z-session.data.${SID}.1.json","ago":89900}],
 "uploads":[{"key":"recordings/${SID}.tar","upload_id":"u-1","ago":86400}]}
JSON
start_mock
run_case
is "wedged open upload 24h, no session.end -> exit 1" "1" "${CASE_RC}"
is "wedged open upload 24h, no session.end -> alert" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in *open-upload-stale*) ok "open-upload detail names open-upload-stale" ;; *) bad "open-upload detail: ${CASE_DETAIL}" ;; esac

# 30 single-value gaps (seqs 0,2,4,...,60 + end 61): the renderer must cap at
# 20 ranges + ellipsis and complete fast. The round-1 length assertion was
# tautological because state.json is clipped server-side; this checks the
# bounded renderer itself. Keys come from the shipper grammar (the
# replica-importing heredocs run `python3 -I`: cwd off sys.path).
python3 -I - "${HARNESS_DIR}" "$SID" <<'PY' | fixture
import json
import sys

sys.path.insert(0, sys.argv[1])
from shipper_keys import audit_key

sid = sys.argv[2]
objects = [
    {"key": "audit/heartbeat/20260925T140000Z.json", "ago": 45},
    # Legacy seq-0 origin, hand-written on purpose: the real builder floors at
    # 1 (previous+1) and the replica refuses to build seq 0.
    {"key": "audit/20260925T135000Z-session.start.%s.0.shell.json" % sid, "ago": 300},
]
for seq in range(2, 61, 2):
    objects.append({"key": audit_key("session.data", "20260925T135100Z", sid, seq, flat=True), "ago": 299})
objects.append({"key": audit_key("session.end", "20260925T135200Z", sid, 61, "shell", flat=True), "ago": 298})
objects.append({"key": "recordings/%s.tar" % sid, "ago": 297})
print(json.dumps({"bucket": "pc-admin-dr", "objects": objects, "uploads": []}))
PY
start_mock
gap_start="$(date +%s)"
run_case
gap_elapsed=$(( $(date +%s) - gap_start ))
is "30 seq gaps -> exit 1 (bounded, no hang)" "1" "${CASE_RC}"
is "30 seq gaps -> alert" "alert" "${CASE_STATE}"
if python3 - "${CASE_DETAIL}" <<'PY'
import sys

text = sys.argv[1]
marker = "missing <seq> "
if marker not in text:
    raise SystemExit("no sequence-gap missing list in: %s" % text[:200])
rendered = text.split(marker, 1)[1].strip().split(",")
if len(rendered) > 21:
    raise SystemExit("renderer materialised %d ranges" % len(rendered))
if rendered[-1] != "...":
    raise SystemExit("bounded renderer must end with ... (got %r)" % rendered[-1])
PY
then ok "30 seq gaps render as at most 20 ranges + ellipsis (real renderer bound)"; else bad "30 seq gaps: renderer bound assertion failed"; fi
if [ "${gap_elapsed}" -le 15 ]; then
  ok "30 seq gaps complete without materialising the range (${gap_elapsed}s)"
else
  bad "30 seq gaps took ${gap_elapsed}s (renderer may be materialising)"
fi
sig_capped_a="$(state_field signature)"
# Red-team finding (PR #148): the identity must cover ALL missing ranges, not
# only the 20 the detail renderer caps at. Fixture B keeps the same first 20
# missing ranges (an identical detail render) and a different 21st+ remainder
# -> the signature must move. Pre-fix both hashed the capped render, so the
# tooth fails on the old code.
python3 -I - "${HARNESS_DIR}" "$SID" <<'PY' | fixture
import json
import sys

sys.path.insert(0, sys.argv[1])
from shipper_keys import audit_key

sid = sys.argv[2]
objects = [
    {"key": "audit/heartbeat/20260925T140000Z.json", "ago": 45},
    {"key": "audit/20260925T135000Z-session.start.%s.0.shell.json" % sid, "ago": 300},
]
# Missing odds 1..39 (the same first 20 single-value ranges as fixture A),
# then odds 41..59 present: the remainder is now evens 42..60 instead of
# 41,43,...,59.
for seq in range(2, 41, 2):
    objects.append({"key": audit_key("session.data", "20260925T135100Z", sid, seq, flat=True), "ago": 299})
for seq in range(41, 60, 2):
    objects.append({"key": audit_key("session.data", "20260925T135200Z", sid, seq, flat=True), "ago": 298})
objects.append({"key": audit_key("session.end", "20260925T135300Z", sid, 61, "shell", flat=True), "ago": 297})
objects.append({"key": "recordings/%s.tar" % sid, "ago": 296})
print(json.dumps({"bucket": "pc-admin-dr", "objects": objects, "uploads": []}))
PY
start_mock
run_case
is "capped-remainder gap fixture -> alert" "alert" "${CASE_STATE}"
if [ -n "${sig_capped_a}" ] && [ "${sig_capped_a}" != "$(state_field signature)" ]; then
  ok "sequence-gap identity covers ranges beyond the capped detail render"
else
  bad "sequence-gap identity ignored the capped remainder (signatures equal)"
fi

# ---- cross-repo: session mode markers (exec sessions ship no tar) --------
# These fixtures are built with the pc-admin shipper key grammar
# (shipper_keys.py replicates scripts/lib/b2_client.py build_audit_key): the
# round-1 hand-written keys are what let the live-v18 contract slip
# (session.start omits `interactive` and reads `.shell` even for exec). The
# `key` helper builds the flat legacy layout explicitly; the dated layout is
# exercised by the #159 scenarios below.
K_START_SHELL="$(key session.start 20260925T135000Z "$SID" 1 shell)"
K_DATA_2="$(key session.data 20260925T135100Z "$SID" 2)"
K_END_SHELL="$(key session.end 20260925T135200Z "$SID" 3 shell)"
K_START_EXEC="$(key session.start 20260925T135000Z "$SID" 1 exec)"
K_END_EXEC="$(key session.end 20260925T135200Z "$SID" 3 exec)"

fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"${K_START_EXEC}","ago":1200},
  {"key":"${K_DATA_2}","ago":1199},
  {"key":"${K_END_EXEC}","ago":1198}],
 "uploads":[]}
JSON
start_mock
run_case
is "exec session (exec markers, no tar) -> exit 0" "0" "${CASE_RC}"
is "exec session (exec markers, no tar) -> ok verdict" "ok" "${CASE_STATE}"

# Live Teleport v18 exec: session.start reads `.shell` (no `interactive` on the
# start event); only session.end can say exec. The end marker is authoritative.
fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"${K_START_SHELL}","ago":1200},
  {"key":"${K_DATA_2}","ago":1199},
  {"key":"${K_END_EXEC}","ago":1198}],
 "uploads":[]}
JSON
start_mock
run_case
is "live v18 exec (shell start + exec end, no tar) -> exit 0" "0" "${CASE_RC}"
is "live v18 exec (shell start + exec end, no tar) -> ok verdict" "ok" "${CASE_STATE}"

# In-flight live v18 exec session: the start reads `.shell` and the `.exec`
# end only ships when the command finishes, so past the 10-min grace the
# witness alerts `recording-gap` — it cannot read the event body to know the
# session is exec. This is the documented residual, pinned here: the alert is
# conservative (the safe direction) and the wording names the ambiguity. The
# fixture directly above is the same session once the `.exec` end lands: ok.
fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"${K_START_SHELL}","ago":1200},
  {"key":"${K_DATA_2}","ago":1199}],
 "uploads":[]}
JSON
start_mock
run_case
is "in-flight live v18 exec (shell start, no end, past grace) -> exit 1 (conservative)" "1" "${CASE_RC}"
is "in-flight live v18 exec -> alert verdict" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in *recording-gap*) ok "in-flight exec detail names recording-gap" ;; *) bad "in-flight exec detail: ${CASE_DETAIL}" ;; esac
case "${CASE_DETAIL}" in *"no session.end yet"*) ok "in-flight exec detail names the end-less ambiguity" ;; *) bad "in-flight exec detail lacks the ambiguity wording: ${CASE_DETAIL}" ;; esac

# Duplicate session.end objects: resolution must use the newest LastModified
# (and that key's mode), not the first key the list returns. The mock lists
# objects by key sort, so seq 3 is seen before seq 4 — the mode of seq 4 has
# to win in both directions.
K_END_3_SHELL="$(key session.end 20260925T135200Z "$SID" 3 shell)"
K_END_3_EXEC="$(key session.end 20260925T135200Z "$SID" 3 exec)"
K_END_4_SHELL="$(key session.end 20260925T135200Z "$SID" 4 shell)"
K_END_4_EXEC="$(key session.end 20260925T135200Z "$SID" 4 exec)"

fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"${K_START_SHELL}","ago":1200},
  {"key":"${K_DATA_2}","ago":1199},
  {"key":"${K_END_3_SHELL}","ago":600},
  {"key":"${K_END_4_EXEC}","ago":500}],
 "uploads":[]}
JSON
start_mock
run_case
is "duplicate ends, newest is exec -> exit 0 (newest LastModified wins)" "0" "${CASE_RC}"
is "duplicate ends, newest is exec -> ok verdict" "ok" "${CASE_STATE}"

fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"${K_START_EXEC}","ago":1200},
  {"key":"${K_DATA_2}","ago":1199},
  {"key":"${K_END_3_EXEC}","ago":600},
  {"key":"${K_END_4_SHELL}","ago":500}],
 "uploads":[]}
JSON
start_mock
run_case
is "duplicate ends, newest is shell -> exit 1 (newest LastModified wins)" "1" "${CASE_RC}"
is "duplicate ends, newest is shell -> alert verdict" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in *recording-gap*) ok "duplicate-end shell detail names recording-gap" ;; *) bad "duplicate-end shell detail: ${CASE_DETAIL}" ;; esac

# Duplicate session.start objects (round-4 LOW 4): resolution must use the
# newest LastModified + its mode, exactly like ends. The mock lists objects by
# key sort, so swapping the key timestamps swaps the listing order while the
# LastModified assignment stays: the newest marker (shell, past the grace)
# must win in both orders — a first-key-wins reader would silently exempt the
# session when the stale `.exec` start sorts first.
K_START_1_EXEC="$(key session.start 20260925T134000Z "$SID" 1 exec)"
K_START_1_SHELL="$(key session.start 20260925T134000Z "$SID" 1 shell)"
K_START_2_EXEC="$(key session.start 20260925T135000Z "$SID" 2 exec)"
K_START_2_SHELL="$(key session.start 20260925T135000Z "$SID" 2 shell)"

fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"${K_START_1_EXEC}","ago":1200},
  {"key":"${K_START_2_SHELL}","ago":700}],
 "uploads":[]}
JSON
start_mock
run_case
is "contradictory starts, stale exec key lists first -> exit 1 (newest shell wins)" "1" "${CASE_RC}"
is "contradictory starts, stale exec key lists first -> alert" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in *recording-gap*) ok "duplicate-start exec-first detail names recording-gap" ;; *) bad "duplicate-start exec-first detail: ${CASE_DETAIL}" ;; esac

fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"${K_START_1_SHELL}","ago":700},
  {"key":"${K_START_2_EXEC}","ago":1200}],
 "uploads":[]}
JSON
start_mock
run_case
is "contradictory starts, newest shell key lists first -> exit 1 (order-independent)" "1" "${CASE_RC}"
is "contradictory starts, newest shell key lists first -> alert" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in *recording-gap*) ok "duplicate-start shell-first detail names recording-gap" ;; *) bad "duplicate-start shell-first detail: ${CASE_DETAIL}" ;; esac

fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"${K_START_1_SHELL}","ago":1200},
  {"key":"${K_START_2_EXEC}","ago":700}],
 "uploads":[]}
JSON
start_mock
run_case
is "contradictory starts, newest exec key lists second -> exit 0 (newest exempts)" "0" "${CASE_RC}"
is "contradictory starts, newest exec key lists second -> ok verdict" "ok" "${CASE_STATE}"

fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"${K_START_1_EXEC}","ago":700},
  {"key":"${K_START_2_SHELL}","ago":1200}],
 "uploads":[]}
JSON
start_mock
run_case
is "contradictory starts, newest exec key lists first -> exit 0 (order-independent)" "0" "${CASE_RC}"
is "contradictory starts, newest exec key lists first -> ok verdict" "ok" "${CASE_STATE}"

# Round-5: a genuine equal-LastModified tie with conflicting declared modes
# has no "newest" marker to pick. First-key-wins was order-dependent (an
# `.exec` tie sorting first silently exempted the session); a conflicting tie
# fails closed to the conservative `.shell` in BOTH listing orders.
fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"${K_START_1_EXEC}","ago":1200},
  {"key":"${K_START_2_SHELL}","ago":1200}],
 "uploads":[]}
JSON
start_mock
run_case
is "equal-LM contradictory starts, exec key first -> exit 1 (tie fails closed)" "1" "${CASE_RC}"
is "equal-LM contradictory starts, exec key first -> alert verdict" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in *recording-gap*) ok "equal-LM start tie detail names recording-gap (conservative shell)" ;; *) bad "equal-LM start tie detail: ${CASE_DETAIL}" ;; esac

fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"${K_START_1_SHELL}","ago":1200},
  {"key":"${K_START_2_EXEC}","ago":1200}],
 "uploads":[]}
JSON
start_mock
run_case
is "equal-LM contradictory starts, shell key first -> exit 1 (both orders)" "1" "${CASE_RC}"
is "equal-LM contradictory starts, shell key first -> alert verdict" "alert" "${CASE_STATE}"

# The same tie on the authoritative end marker: an `.exec` end sorting first
# used to win and silently exempt; the conflicting tie is conservative shell
# (seq-clean via the data seq 2, so only the tie drives the verdict).
fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"${K_START_1_SHELL}","ago":1200},
  {"key":"${K_DATA_2}","ago":1199},
  {"key":"${K_END_3_EXEC}","ago":600},
  {"key":"${K_END_4_SHELL}","ago":600}],
 "uploads":[]}
JSON
start_mock
run_case
is "equal-LM contradictory ends, exec key first -> exit 1 (tie fails closed)" "1" "${CASE_RC}"
is "equal-LM contradictory ends, exec key first -> alert verdict" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in *recording-gap*) ok "equal-LM end tie detail names recording-gap (conservative shell)" ;; *) bad "equal-LM end tie detail: ${CASE_DETAIL}" ;; esac

fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"${K_START_1_SHELL}","ago":1200},
  {"key":"${K_DATA_2}","ago":1199},
  {"key":"${K_END_3_SHELL}","ago":600},
  {"key":"${K_END_4_EXEC}","ago":600}],
 "uploads":[]}
JSON
start_mock
run_case
is "equal-LM contradictory ends, shell key first -> exit 1 (both orders)" "1" "${CASE_RC}"
is "equal-LM contradictory ends, shell key first -> alert verdict" "alert" "${CASE_STATE}"

# The mirror case: an end that says shell wins over an exec start
# (conservative - a tar is expected).
fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"${K_START_EXEC}","ago":1200},
  {"key":"${K_DATA_2}","ago":1199},
  {"key":"${K_END_SHELL}","ago":1198}],
 "uploads":[]}
JSON
start_mock
run_case
is "exec start + shell end -> exit 1 (end is authoritative)" "1" "${CASE_RC}"
is "exec start + shell end -> alert (conservative shell)" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in *recording-gap*) ok "exec-start/shell-end detail names recording-gap" ;; *) bad "exec-start/shell-end detail: ${CASE_DETAIL}" ;; esac

fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"${K_START_SHELL}","ago":1200},
  {"key":"${K_DATA_2}","ago":1199},
  {"key":"${K_END_SHELL}","ago":1198}],
 "uploads":[]}
JSON
start_mock
run_case
is "shell session with end, no tar -> exit 1" "1" "${CASE_RC}"
is "shell session with end, no tar -> alert" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in *recording-gap*) ok "shell gap detail names recording-gap" ;; *) bad "shell gap detail: ${CASE_DETAIL}" ;; esac

fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"audit/20260925T135000Z-session.start.${SID}.1.json","ago":1200},
  {"key":"audit/20260925T135100Z-session.data.${SID}.2.json","ago":1199},
  {"key":"audit/20260925T135200Z-session.end.${SID}.3.json","ago":1198}],
 "uploads":[]}
JSON
start_mock
run_case
is "legacy shape (no mode marker), no tar -> exit 1" "1" "${CASE_RC}"
is "legacy shape (no mode marker), no tar -> alert (conservative shell)" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in *recording-gap*) ok "legacy gap detail names recording-gap" ;; *) bad "legacy gap detail: ${CASE_DETAIL}" ;; esac

fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"${K_START_EXEC}","ago":1200},
  {"key":"audit/20260925T135200Z-session.end.${SID}.3.json","ago":1198}],
 "uploads":[]}
JSON
start_mock
run_case
is "exec start + legacy end -> exit 1" "1" "${CASE_RC}"
is "exec start + legacy end -> alert (legacy end is conservative shell)" "alert" "${CASE_STATE}"

fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"audit/20260925T135000Z-session.start.${SID}.1.pty.json","ago":300}],
 "uploads":[]}
JSON
start_mock
run_case
is "malformed mode marker -> exit 1" "1" "${CASE_RC}"
is "malformed mode marker -> alert" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in *naming-contract*) ok "malformed-mode detail names naming-contract" ;; *) bad "malformed-mode detail: ${CASE_DETAIL}" ;; esac

fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"${K_START_SHELL}","ago":300},
  {"key":"audit/20260925T135100Z-session.data.${SID}.2.shell.json","ago":299},
  {"key":"${K_END_SHELL}","ago":298},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_case
is "mode marker on a non start/end event -> exit 1" "1" "${CASE_RC}"
case "${CASE_DETAIL}" in *naming-contract*) ok "misplaced-mode detail names naming-contract" ;; *) bad "misplaced-mode detail: ${CASE_DETAIL}" ;; esac

# Round-9 NIT: the same mode-drift rule must hold for a replay-conflict
# variant shape. The identity-based `continue` ran before the naming check,
# so this key stayed silent while the plain shape above alerts. A variant
# drops its mode marker by contract, and the mode is lifecycle-only on every
# shape, so a mode here is drift. Hand-written on purpose: the shipper replica
# refuses to build a shape the real builder never emits.
fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"${K_START_SHELL}","ago":300},
  {"key":"audit/20260925T135100Z-session.data_0123456789abcdef.${SID}.2.exec.json","ago":299},
  {"key":"${K_END_SHELL}","ago":298},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_case
is "mode marker on a variant-shaped non start/end event -> exit 1" "1" "${CASE_RC}"
case "${CASE_DETAIL}" in *naming-contract*) ok "variant-shaped misplaced-mode detail names naming-contract" ;; *) bad "variant-shaped misplaced-mode detail: ${CASE_DETAIL}" ;; esac

# ---- completed tar + lost session.end (the tar must not stay green alone) --
K_TAR_START="$(key session.start 20260925T120000Z "$SID" 1 shell)"
K_TAR_DATA="$(key session.data 20260925T120100Z "$SID" 2)"
K_FRESH_START="$(key session.start 20260925T135000Z "$SID" 1 shell)"
K_FRESH_DATA="$(key session.data 20260925T135100Z "$SID" 2)"

fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"${K_TAR_START}","ago":3600},
  {"key":"${K_TAR_DATA}","ago":3599},
  {"key":"recordings/${SID}.tar","ago":3600}],
 "uploads":[]}
JSON
start_mock
run_case
is "completed tar + no session.end (past grace) -> exit 1" "1" "${CASE_RC}"
is "completed tar + no session.end (past grace) -> alert" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in *session-end-missing*) ok "lost-end detail names session-end-missing" ;; *) bad "lost-end detail: ${CASE_DETAIL}" ;; esac

fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"${K_FRESH_START}","ago":1200},
  {"key":"${K_FRESH_DATA}","ago":1199},
  {"key":"recordings/${SID}.tar","ago":60}],
 "uploads":[]}
JSON
start_mock
run_case
is "completed tar + no session.end (within grace) -> exit 0" "0" "${CASE_RC}"
is "completed tar + no session.end (within grace) -> ok verdict" "ok" "${CASE_STATE}"

# tar + session.end (the healthy fixture above) stays ok: no end false positive.

# Round-5: an orphan completed tar whose sid has no audit events at all is the
# extreme tail of stream closure. The session loop only visits observed
# sessions, so the recordings listing itself must be checked past the grace.
fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"recordings/${SID}.tar","ago":3600}],
 "uploads":[]}
JSON
start_mock
run_case
is "orphan completed tar, no audit events (past grace) -> exit 1" "1" "${CASE_RC}"
is "orphan completed tar, no audit events -> alert verdict" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in *session-start-missing*) ok "orphan-tar detail names session-start-missing (stream closure)" ;; *) bad "orphan-tar detail: ${CASE_DETAIL}" ;; esac

# Within the completer-lag grace the tar may just have landed before its audit
# tail: stay quiet (no over-eager alert).
fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"recordings/${SID}.tar","ago":60}],
 "uploads":[]}
JSON
start_mock
run_case
is "orphan completed tar within grace -> exit 0 (no premature alert)" "0" "${CASE_RC}"
is "orphan completed tar within grace -> ok verdict" "ok" "${CASE_STATE}"

# ---- shipper contract: sid-less session events + shape-based drift -------

fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"audit/20260925T135000Z-session.start.${SID}.1.shell.json","ago":300},
  {"key":"audit/20260925T135100Z-session.data.${SID}.2.json","ago":299},
  {"key":"audit/20260925T135200Z-session.end.${SID}.3.shell.json","ago":298},
  {"key":"audit/20260925T135300Z-session.rejected.000001.json","ago":297},
  {"key":"$(key session.data 20260925T135300Z "" 2)","ago":296},
  {"key":"recordings/${SID}.tar","ago":296}],
 "uploads":[]}
JSON
start_mock
run_case
is "sid-less session.rejected + sanctioned session.data keys -> exit 0" "0" "${CASE_RC}"
is "sid-less session.rejected + sanctioned unknown keys -> ok verdict (no naming-contract false positive)" "ok" "${CASE_STATE}"

# Regression punch-through tooth: the pre-fold pc-admin shape (a sid-bearing
# session.rejected key) must be caught by the witness as a session with no
# session.start — this is exactly the alert the forced-sid-less shipper rule
# prevents.
fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"audit/20260925T135300Z-session.rejected.${SID}.1.json","ago":297}],
 "uploads":[]}
JSON
start_mock
run_case
is "sid-bearing session.rejected key (pre-fold shape) -> exit 1" "1" "${CASE_RC}"
is "sid-bearing session.rejected key -> alert" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in *session-start-missing*) ok "sid-bearing rejected detail names session-start-missing (the regression the sid-less rule prevents)" ;; *) bad "sid-bearing rejected detail: ${CASE_DETAIL}" ;; esac

# ---- round-8: replay-conflict variants (`_<sha256[:16]>`) --------------
# A rebuilt audit file that replays a taken key with different bytes ships
# under a deterministic variant key (pc-admin `disambiguate_audit_key` @
# a7035a9): the event type gains `_<sha256[:16]>`, a session lifecycle variant
# drops its mode marker, and the sid-less shape joins the hash to the last
# type segment. List-only, the witness sees only the NAME: base and variant
# share the (ts, canonical type, seq) identity, so the variant must be
# absorbed (no sequence-duplicate) and must not read as naming drift, while
# the base key stays authoritative for the lifecycle mode. B2 lists ascending
# keys and `.` < `_`, so a base always precedes its variant.
START_BODY='{"event":"session.start","v":"harness-variant"}'
DATA_BODY='{"event":"session.data","v":"harness-variant"}'
END_BODY='{"event":"session.end","v":"harness-variant"}'
START_BASE="$(key session.start 20260925T135000Z "${SID}" 1 shell)"
START_VARIANT="$(variant_key "${START_BODY}" session.start 20260925T135000Z "${SID}" 1 shell)"
if [ "$(printf '%s\n' "${START_BASE}" "${START_VARIANT}" | LC_ALL=C sort | head -n 1)" = "${START_BASE}" ]; then
  ok "base key sorts before its replay variant (ascending listing: base wins)"
else
  bad "variant key sorts before its base (${START_VARIANT} < ${START_BASE})"
fi

# (a) a completed session with a base + variant on start/data/end: every
# variant is the same identity, the lifecycle resolves from the base keys and
# the tar closes the gap -> ok.
fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"${START_BASE}","ago":300},
  {"key":"$(variant_key "${START_BODY}" session.start 20260925T135000Z "${SID}" 1 shell)","ago":299},
  {"key":"$(key session.data 20260925T135100Z "${SID}" 2)","ago":299},
  {"key":"$(variant_key "${DATA_BODY}" session.data 20260925T135100Z "${SID}" 2)","ago":298},
  {"key":"$(key session.end 20260925T135200Z "${SID}" 3 shell)","ago":298},
  {"key":"$(variant_key "${END_BODY}" session.end 20260925T135200Z "${SID}" 3 shell)","ago":297},
  {"key":"recordings/${SID}.tar","ago":296}],
 "uploads":[]}
JSON
start_mock
run_case
is "base + replay-conflict variant (start/data/end) -> exit 0" "0" "${CASE_RC}"
is "base + replay-conflict variant absorbed -> ok (no sequence-duplicate, no naming drift)" "ok" "${CASE_STATE}"

# (a2) the base lifecycle marker stays authoritative: an exec start plus a
# NEWER variant (mode dropped) must not clobber the exec exemption; a live
# exec session (no tar, no end, past the grace) stays ok. Re-aged (round 9):
# base 1200 s / variant 700 s. Both markers are past the 600 s grace, so a
# clobbering variant would resolve `shell` at its own (newer) 700 s clock and
# alert `recording-gap` - the earlier 900/300 ages kept the clobber inside
# the grace and the tooth passed even with the variant guard deleted.
fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"$(key session.start 20260925T134000Z "${SID}" 1 exec)","ago":1200},
  {"key":"$(variant_key "${START_BODY}" session.start 20260925T134000Z "${SID}" 1 exec)","ago":700},
  {"key":"$(key session.data 20260925T134100Z "${SID}" 2)","ago":699}],
 "uploads":[]}
JSON
start_mock
run_case
is "exec start + newer replay variant (mode dropped) -> exit 0" "0" "${CASE_RC}"
is "base key authoritative for the lifecycle mode -> ok (variant does not clobber exec)" "ok" "${CASE_STATE}"

# (a3) same (ts, canonical type, seq) contradictory-mode starts (round-9 root
# cause): the mode marker is NOT part of the identity tuple, so both keys must
# reach the lifecycle resolver. The identity-clobber let the first-listed
# key force-skip the second, so a stale `.exec` (B2 lists `.exec` < `.shell`)
# silently exempted a session whose newer marker says shell -> false green.
fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"$(key session.start 20260925T134000Z "${SID}" 1 exec)","ago":1200},
  {"key":"$(key session.start 20260925T134000Z "${SID}" 1 shell)","ago":700}],
 "uploads":[]}
JSON
start_mock
run_case
is "same-ts exec+shell starts, newer shell -> exit 1 (stale exec must not exempt)" "1" "${CASE_RC}"
is "same-ts exec+shell starts, newer shell -> alert verdict" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in *recording-gap*) ok "same-ts start pair detail names recording-gap" ;; *) bad "same-ts start pair detail: ${CASE_DETAIL}" ;; esac

# The equal-LastModified tie of the same pair has no newest marker, so it must
# fail closed to the conservative `.shell` in both listing orders. Real B2
# order lists `.exec` first; a fixture-ordered listing pins the `.shell`-first
# order the identity-clobber also silently mis-resolved (it happened to alert,
# but only via the clobber path - the resolver must see both keys).
fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"$(key session.start 20260925T134000Z "${SID}" 1 exec)","ago":1200},
  {"key":"$(key session.start 20260925T134000Z "${SID}" 1 shell)","ago":1200}],
 "uploads":[]}
JSON
start_mock
run_case
is "same-ts exec+shell start tie (exec first) -> exit 1 (fails closed)" "1" "${CASE_RC}"
is "same-ts exec+shell start tie (exec first) -> alert verdict" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in *recording-gap*) ok "same-ts start tie (exec first) detail names recording-gap" ;; *) bad "same-ts start tie (exec first) detail: ${CASE_DETAIL}" ;; esac

fixture <<JSON
{"bucket":"pc-admin-dr","list_order":"fixture",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"$(key session.start 20260925T134000Z "${SID}" 1 shell)","ago":1200},
  {"key":"$(key session.start 20260925T134000Z "${SID}" 1 exec)","ago":1200}],
 "uploads":[]}
JSON
start_mock
run_case
is "same-ts exec+shell start tie (shell first, fixture order) -> exit 1 (both orders)" "1" "${CASE_RC}"
is "same-ts exec+shell start tie (shell first) -> alert verdict" "alert" "${CASE_STATE}"

# The same pair with a NEWER `.exec`, shell listed first: the strictly-newest
# marker wins with its mode in either listing order, so the newer exec key
# exempts the session (the identity-clobber kept the first-listed shell).
fixture <<JSON
{"bucket":"pc-admin-dr","list_order":"fixture",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"$(key session.start 20260925T134000Z "${SID}" 1 shell)","ago":1200},
  {"key":"$(key session.start 20260925T134000Z "${SID}" 1 exec)","ago":700}],
 "uploads":[]}
JSON
start_mock
run_case
is "same-ts shell-first, newer exec start -> exit 0 (newest wins in both orders)" "0" "${CASE_RC}"
is "same-ts shell-first, newer exec start -> ok verdict" "ok" "${CASE_STATE}"

# The same identity-clobber on the authoritative end marker: a same-(ts, seq)
# `.exec` end listed first (B2 order) silently exempted a session whose newer
# end says shell (round-9 repro); both ends must reach the resolver.
fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"$(key session.start 20260925T134000Z "${SID}" 1 shell)","ago":1200},
  {"key":"$(key session.data 20260925T134100Z "${SID}" 2)","ago":1199},
  {"key":"$(key session.end 20260925T134200Z "${SID}" 3 exec)","ago":600},
  {"key":"$(key session.end 20260925T134200Z "${SID}" 3 shell)","ago":500}],
 "uploads":[]}
JSON
start_mock
run_case
is "same-ts exec+shell ends, newer shell -> exit 1 (stale exec end must not exempt)" "1" "${CASE_RC}"
is "same-ts exec+shell ends, newer shell -> alert verdict" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in *recording-gap*) ok "same-ts end pair detail names recording-gap" ;; *) bad "same-ts end pair detail: ${CASE_DETAIL}" ;; esac

# (a4) variant-first listing order (non-conformant; real B2 lists ascending
# keys, so a base precedes its variant): the canonical base must still
# resolve the lifecycle marker. The identity-clobber let the variant claim
# the identity slot and force-skip the base -> a spurious
# `session-start-missing` on a live exec session (round-9 repro).
fixture <<JSON
{"bucket":"pc-admin-dr","list_order":"fixture",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"$(variant_key "${START_BODY}" session.start 20260925T134000Z "${SID}" 1 exec)","ago":700},
  {"key":"$(key session.start 20260925T134000Z "${SID}" 1 exec)","ago":1200}],
 "uploads":[]}
JSON
start_mock
run_case
is "variant listed before its base -> exit 0 (base still resolves)" "0" "${CASE_RC}"
is "variant listed before its base -> ok (no spurious session-start-missing)" "ok" "${CASE_STATE}"

# (b) a session.rejected replay variant is the same documented sid-less event
# after canonicalization - never naming drift.
fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"$(key session.rejected 20260925T135300Z "" 5)","ago":297},
  {"key":"$(variant_key "${START_BODY}" session.rejected 20260925T135300Z "" 5)","ago":296}],
 "uploads":[]}
JSON
start_mock
run_case
is "session.rejected replay-conflict variant -> exit 0" "0" "${CASE_RC}"
is "session.rejected variant is not naming drift -> ok" "ok" "${CASE_STATE}"

# (c) regression tooth: the identity dedupe keys on (ts, canonical type, seq),
# so a GENUINE same-seq duplicate under a different ts still alerts
# sequence-duplicate (a (sid, seq)-only dedupe would silently absorb it).
fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"$(key session.start 20260925T135000Z "${SID}" 1 shell)","ago":300},
  {"key":"$(key session.data 20260925T135100Z "${SID}" 2)","ago":299},
  {"key":"$(key session.data 20260925T135200Z "${SID}" 2)","ago":298},
  {"key":"$(key session.end 20260925T135300Z "${SID}" 3 shell)","ago":297},
  {"key":"recordings/${SID}.tar","ago":296}],
 "uploads":[]}
JSON
start_mock
run_case
is "genuine same-seq duplicate at a different ts -> exit 1" "1" "${CASE_RC}"
is "genuine same-seq duplicate at a different ts -> alert" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in *sequence-duplicate*) ok "genuine duplicate still names sequence-duplicate" ;; *) bad "genuine duplicate detail: ${CASE_DETAIL}" ;; esac

# (d) a variant with no base key never fabricates a lifecycle marker: it stays
# a conservative session-start-missing (the shipper only variants a key that
# already exists; this pins the defense-in-depth rule).
fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"$(variant_key "${START_BODY}" session.start 20260925T135000Z "${SID}" 1 exec)","ago":300}],
 "uploads":[]}
JSON
start_mock
run_case
is "variant-only session start -> exit 1" "1" "${CASE_RC}"
is "variant-only session start -> alert" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in *session-start-missing*) ok "variant-only start stays conservative: session-start-missing" ;; *) bad "variant-only start detail: ${CASE_DETAIL}" ;; esac

fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"audit/20260925T135000Z-sess.start.${SID}.1.json","ago":300}],
 "uploads":[]}
JSON
start_mock
run_case
is "renamed session prefix (sess.start) -> exit 1" "1" "${CASE_RC}"
is "renamed session prefix (sess.start) -> alert" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in *naming-contract*) ok "renamed-prefix drift detail names naming-contract" ;; *) bad "renamed-prefix drift detail: ${CASE_DETAIL}" ;; esac

fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"audit/20260925T135000Z-user.login.json","ago":300}],
 "uploads":[]}
JSON
start_mock
run_case
is "unknown audit key shape -> exit 1" "1" "${CASE_RC}"
is "unknown audit key shape -> alert" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in *contract-mismatch*) ok "contract-mismatch is reachable with a heartbeat present" ;; *) bad "contract-mismatch detail: ${CASE_DETAIL}" ;; esac

# ---- trailing-newline key names: \Z-anchored key classifiers (#152) -------
# The provisioned span's key classifiers are \Z-anchored (full string), so a
# newline-suffixed key name is judged as drift instead of being absorbed as
# its non-newline shape. pc-admin #20 \Z-anchors the builder, so the real
# producer cannot emit these names - the teeth are the anti-regression proof
# for the anchored span (a `$` reversion turns them green/misclassified).
NEWLINE_USER_KEY="$(key user.login 20260925T135000Z "" 6)"$'\n'
python3 - "${NEWLINE_USER_KEY}" <<'PY' | fixture
import json
import sys

print(json.dumps({
    "bucket": "pc-admin-dr",
    "objects": [
        {"key": "audit/heartbeat/20260925T140000Z.json", "ago": 45},
        {"key": sys.argv[1], "ago": 300},
    ],
    "uploads": [],
}))
PY
start_mock
run_case
is "newline-suffixed user.login key -> exit 1" "1" "${CASE_RC}"
is "newline-suffixed user.login key -> alert" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in *contract-mismatch*) ok "newline-suffixed user.login key alerts contract-mismatch" ;; *) bad "newline-suffixed user.login detail: ${CASE_DETAIL}" ;; esac

NEWLINE_SESSION_KEY="$(key session.start 20260925T135000Z "${SID}" 1 shell)"$'\n'
python3 - "${NEWLINE_SESSION_KEY}" <<'PY' | fixture
import json
import sys

print(json.dumps({
    "bucket": "pc-admin-dr",
    "objects": [
        {"key": "audit/heartbeat/20260925T140000Z.json", "ago": 45},
        {"key": sys.argv[1], "ago": 300},
    ],
    "uploads": [],
}))
PY
start_mock
run_case
is "newline-suffixed session.start key -> exit 1" "1" "${CASE_RC}"
is "newline-suffixed session.start key -> alert" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in *naming-contract*) ok "newline-suffixed session.start key alerts naming-contract" ;; *) bad "newline-suffixed session.start detail: ${CASE_DETAIL}" ;; esac

# A newline-suffixed recording key never matches the recording check, so it
# cannot satisfy the shell session's gap: the session still alerts
# recording-gap (with `$` the tar is absorbed and this fixture stays green).
NEWLINE_GAP_START="$(key session.start 20260925T130000Z "${SID}" 1 shell)"
NEWLINE_TAR_KEY="recordings/${SID}.tar"$'\n'
python3 - "${NEWLINE_GAP_START}" "${NEWLINE_TAR_KEY}" <<'PY' | fixture
import json
import sys

print(json.dumps({
    "bucket": "pc-admin-dr",
    "objects": [
        {"key": "audit/heartbeat/20260925T140000Z.json", "ago": 45},
        {"key": sys.argv[1], "ago": 1200},
        {"key": sys.argv[2], "ago": 300},
    ],
    "uploads": [],
}))
PY
start_mock
run_case
is "newline-suffixed recording key -> exit 1" "1" "${CASE_RC}"
is "newline-suffixed recording key -> alert" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in *recording-gap*) ok "newline-suffixed tar never satisfies the recording check (recording-gap)" ;; *) bad "newline-suffixed tar detail: ${CASE_DETAIL}" ;; esac

# A newline-suffixed heartbeat key is not a heartbeat: it must not match
# HEARTBEAT_KEY_RE, so the only heartbeat-shaped object can neither satisfy
# the freshness check (head detail carries `heartbeat-missing: ...` first)
# nor dodge drift classification (`contract-mismatch: ...` second). With `$`
# the key is absorbed as a healthy heartbeat (age 300s) and this fixture stays
# green: this tooth is what pins HEARTBEAT_KEY_RE's \Z.
NEWLINE_HEARTBEAT_KEY="audit/heartbeat/20260925T140000Z.json"$'\n'
python3 - "${NEWLINE_HEARTBEAT_KEY}" <<'PY' | fixture
import json
import sys

print(json.dumps({
    "bucket": "pc-admin-dr",
    "objects": [
        {"key": sys.argv[1], "ago": 300},
    ],
    "uploads": [],
}))
PY
start_mock
run_case
is "newline-suffixed heartbeat key -> exit 1" "1" "${CASE_RC}"
is "newline-suffixed heartbeat key -> alert" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in *contract-mismatch*) ok "newline-suffixed heartbeat key alerts contract-mismatch" ;; *) bad "newline-suffixed heartbeat key detail: ${CASE_DETAIL}" ;; esac

# The fifth anchored classifier, CONFLICT_SUFFIX_RE, is provably inert and
# needs no tooth: its only input is the newline-free `etype` capture from the
# already-\Z-anchored key classifiers, never a raw key name.

# ---- clock skew: future timestamps must error, never look healthy --------

fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":-3600}],
 "uploads":[]}
JSON
start_mock
run_case
is "future heartbeat timestamp -> exit 2 (fail-closed)" "2" "${CASE_RC}"
is "future heartbeat timestamp -> error verdict" "error" "${CASE_STATE}"
case "${CASE_DETAIL}" in *"clock skew"*) ok "heartbeat skew detail names clock skew" ;; *) bad "heartbeat skew detail: ${CASE_DETAIL}" ;; esac

fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"audit/20260925T135000Z-session.start.${SID}.1.json","ago":-3600}],
 "uploads":[]}
JSON
start_mock
run_case
is "future session.start timestamp -> exit 2" "2" "${CASE_RC}"
is "future session.start timestamp -> error verdict" "error" "${CASE_STATE}"
case "${CASE_DETAIL}" in *"clock skew"*) ok "session-start skew detail names clock skew" ;; *) bad "session-start skew detail: ${CASE_DETAIL}" ;; esac

fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"${K_START_SHELL}","ago":300}],
 "uploads":[{"key":"recordings/${SID}.tar","upload_id":"u-1","ago":-3600}]}
JSON
start_mock
run_case
is "future upload Initiated timestamp -> exit 2" "2" "${CASE_RC}"
is "future upload Initiated timestamp -> error verdict" "error" "${CASE_STATE}"
case "${CASE_DETAIL}" in *"clock skew"*) ok "upload-skew detail names clock skew" ;; *) bad "upload-skew detail: ${CASE_DETAIL}" ;; esac

# Round-5: the skew contract is enforced at collection time for EVERY listed
# timestamp, including paths that never reach a per-session age check: an
# exec session (the exec branch continues before any age check) and a
# completed tar whose session.end is present (the tar branch skips its own
# age check).
fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"${K_START_EXEC}","ago":-600},
  {"key":"${K_DATA_2}","ago":-600},
  {"key":"${K_END_EXEC}","ago":-600}],
 "uploads":[]}
JSON
start_mock
run_case
is "future exec start/data/end -> exit 2 (collection-time skew)" "2" "${CASE_RC}"
is "future exec start/data/end -> error verdict" "error" "${CASE_STATE}"
case "${CASE_DETAIL}" in *"clock skew"*) ok "future-exec skew detail names clock skew" ;; *) bad "future-exec skew detail: ${CASE_DETAIL}" ;; esac

fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"${K_START_1_SHELL}","ago":1200},
  {"key":"${K_DATA_2}","ago":1199},
  {"key":"${K_END_SHELL}","ago":1198},
  {"key":"recordings/${SID}.tar","ago":-600}],
 "uploads":[]}
JSON
start_mock
run_case
is "future completed-tar LastModified (end present) -> exit 2" "2" "${CASE_RC}"
is "future completed-tar LastModified (end present) -> error verdict" "error" "${CASE_STATE}"
case "${CASE_DETAIL}" in *"clock skew"*) ok "future-tar skew detail names clock skew" ;; *) bad "future-tar skew detail: ${CASE_DETAIL}" ;; esac

# ---- ListMultipartUploads pagination + malformed/error-document paths ----

fixture <<JSON
{"bucket":"pc-admin-dr","page_size":1,
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"audit/20260925T135000Z-session.start.${SID}.1.shell.json","ago":300},
  {"key":"audit/20260925T135100Z-session.end.${SID}.2.shell.json","ago":60},
  {"key":"audit/20260925T135000Z-session.start.${SID2}.1.shell.json","ago":300},
  {"key":"audit/20260925T135100Z-session.end.${SID2}.2.shell.json","ago":60}],
 "uploads":[
  {"key":"recordings/${SID}.tar","upload_id":"u-1","ago":300},
  {"key":"recordings/${SID2}.tar","upload_id":"u-1","ago":300}]}
JSON
start_mock
run_case
is "paginated ListMultipartUploads -> exit 0" "0" "${CASE_RC}"
is "paginated ListMultipartUploads -> ok verdict" "ok" "${CASE_STATE}"

fixture <<JSON
{"bucket":"pc-admin-dr","fail_objects":"malformed","objects":[],"uploads":[]}
JSON
start_mock
run_case
is "malformed object-list XML -> exit 2" "2" "${CASE_RC}"
is "malformed object-list XML -> error verdict" "error" "${CASE_STATE}"
case "${CASE_DETAIL}" in *unparseable*) ok "malformed XML detail is explicit" ;; *) bad "malformed XML detail: ${CASE_DETAIL}" ;; esac

fixture <<JSON
{"bucket":"pc-admin-dr","fail_objects":"error-doc-200",
 "objects":[{"key":"audit/heartbeat/20260925T140000Z.json","ago":45}],"uploads":[]}
JSON
start_mock
run_case
is "200 error document on objects -> exit 2 (fail-closed)" "2" "${CASE_RC}"
case "${CASE_DETAIL}" in
  *ListObjectsV2*expected\ ListBucketResult*) ok "200 error-document objects detail names the non-list body" ;;
  *) bad "200 error-document objects detail: ${CASE_DETAIL}" ;;
esac
fixture <<JSON
{"bucket":"pc-admin-dr","fail_objects":"error-doc-in-list-root",
 "objects":[{"key":"audit/heartbeat/20260925T140000Z.json","ago":45}],"uploads":[]}
JSON
start_mock
run_case
is "wrapped error document on objects -> exit 2 (fail-closed)" "2" "${CASE_RC}"
case "${CASE_DETAIL}" in
  *ListObjectsV2*"<Error> child"*) ok "wrapped error-document objects detail names the Error child" ;;
  *) bad "wrapped error-document objects detail: ${CASE_DETAIL}" ;;
esac

fixture <<JSON
{"bucket":"pc-admin-dr","fail_uploads":"error-doc",
 "objects":[{"key":"audit/heartbeat/20260925T140000Z.json","ago":45}],"uploads":[]}
JSON
start_mock
run_case
is "error-document uploads list -> exit 2" "2" "${CASE_RC}"
is "error-document uploads list -> error verdict" "error" "${CASE_STATE}"
case "${CASE_DETAIL}" in *ListMultipartUploads*HTTP*403*) ok "error-document detail names the failing call + status" ;; *) bad "error-document detail: ${CASE_DETAIL}" ;; esac

fixture <<JSON
{"bucket":"pc-admin-dr","fail_objects":"truncated-no-token",
 "objects":[{"key":"audit/heartbeat/20260925T140000Z.json","ago":45}],"uploads":[]}
JSON
start_mock
run_case
is "truncated object list without continuation token -> exit 2" "2" "${CASE_RC}"
case "${CASE_DETAIL}" in *"truncated without a continuation token"*) ok "object truncation detail is explicit" ;; *) bad "object truncation detail: ${CASE_DETAIL}" ;; esac

fixture <<JSON
{"bucket":"pc-admin-dr","fail_uploads":"truncated-no-token",
 "objects":[{"key":"audit/heartbeat/20260925T140000Z.json","ago":45}],
 "uploads":[{"key":"recordings/${SID}.tar","upload_id":"u-1","ago":300}]}
JSON
start_mock
run_case
is "truncated upload list without key marker -> exit 2" "2" "${CASE_RC}"
case "${CASE_DETAIL}" in *"truncated without a key/upload marker"*) ok "upload truncation detail is explicit" ;; *) bad "upload truncation detail: ${CASE_DETAIL}" ;; esac

fixture <<JSON
{"bucket":"pc-admin-dr","fail_uploads":"error-doc-200",
 "objects":[{"key":"audit/heartbeat/20260925T140000Z.json","ago":45}],
 "uploads":[{"key":"recordings/${SID}.tar","upload_id":"u-1","ago":300}]}
JSON
start_mock
run_case
is "200 error document on uploads -> exit 2 (fail-closed)" "2" "${CASE_RC}"
case "${CASE_DETAIL}" in
  *ListMultipartUploads*expected\ ListMultipartUploadsResult*) ok "200 error-document uploads detail names the non-list body" ;;
  *) bad "200 error-document uploads detail: ${CASE_DETAIL}" ;;
esac
fixture <<JSON
{"bucket":"pc-admin-dr","fail_uploads":"error-doc-in-list-root",
 "objects":[{"key":"audit/heartbeat/20260925T140000Z.json","ago":45}],
 "uploads":[{"key":"recordings/${SID}.tar","upload_id":"u-1","ago":300}]}
JSON
start_mock
run_case
is "wrapped error document on uploads -> exit 2 (fail-closed)" "2" "${CASE_RC}"
case "${CASE_DETAIL}" in
  *ListMultipartUploads*"<Error> child"*) ok "wrapped error-document uploads detail names the Error child" ;;
  *) bad "wrapped error-document uploads detail: ${CASE_DETAIL}" ;;
esac

fixture <<JSON
{"bucket":"pc-admin-dr","fail_uploads":"truncated-no-upload-marker",
 "objects":[{"key":"audit/heartbeat/20260925T140000Z.json","ago":45}],
 "uploads":[{"key":"recordings/${SID}.tar","upload_id":"u-1","ago":300}]}
JSON
start_mock
run_case
is "truncated upload list without upload marker -> exit 2" "2" "${CASE_RC}"
case "${CASE_DETAIL}" in *"truncated without a key/upload marker"*) ok "upload-marker truncation detail is explicit" ;; *) bad "upload-marker truncation detail: ${CASE_DETAIL}" ;; esac

# ---- verdict.log rotation bound ------------------------------------------

fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"audit/20260925T135000Z-session.start.${SID}.1.shell.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
python3 - <<PY
with open("${WORK}/state/verdict.log", "w", encoding="utf-8") as handle:
    handle.write("x" * 1200000)
PY
run_case
if [ -f "${WORK}/state/verdict.log.1" ]; then ok "verdict.log rotates at the size bound" ; else bad "verdict.log did not rotate" ; fi
rotated_bytes="$(wc -c <"${WORK}/state/verdict.log.1" 2>/dev/null | tr -d ' ')"
fresh_bytes="$(wc -c <"${WORK}/state/verdict.log" 2>/dev/null | tr -d ' ')"
if [ "${rotated_bytes:-0}" -ge 1048576 ] && [ "${fresh_bytes:-0}" -lt 1048576 ]; then
  ok "rotation keeps the old generation and starts a fresh bounded log (${rotated_bytes}/${fresh_bytes} bytes)"
else
  bad "rotation bounds wrong (${rotated_bytes:-missing}/${fresh_bytes:-missing} bytes)"
fi

# baseline held across an un-runnable run
mkdir -p "${WORK}/state"
printf '%s\n' '{"version":1,"state":"ok","detail":"seeded baseline","updated_at":"2026-09-25T00:00:00Z","last_notify_epoch":0,"baseline":{"state":"ok","detail":"seeded baseline","updated_at":"2026-09-25T00:00:00Z"}}' >"${WORK}/state/state.json"
fixture <<JSON
{"bucket":"pc-admin-dr","fail":"list","objects":[],"uploads":[]}
JSON
start_mock
run_case
is "failing listing -> exit 2 (fail-closed)" "2" "${CASE_RC}"
is "failing listing -> error verdict" "error" "${CASE_STATE}"
is "failing listing -> baseline held" "ok" "$(state_field baseline.state)"
is "failing listing -> baseline detail held" "seeded baseline" "$(state_field baseline.detail)"
case "${CASE_DETAIL}" in *"error:"*) ok "error detail is explicit" ;; *) bad "error detail: ${CASE_DETAIL}" ;; esac

# un-runnable: missing env file
missing_rc=0
RECORDING_WITNESS_ENV_FILE="${WORK}/does-not-exist.env" "${WITNESS}" >"${WORK}/missing.out" 2>"${WORK}/missing.err" || missing_rc=$?
is "missing env file -> exit 2" "2" "${missing_rc}"

# ---- round-5: corrupt state.json repairs, never a silent crash -----------
# R1: a type-valid state.json with a non-numeric counter used to raise an
# uncaught ValueError before notify/write_state (no verdict line, no push,
# forever). It must report an error verdict, write state + verdict log, and
# hold the readable baseline.
CORRUPT_DIR="${WORK}/state-corrupt-numeric"
mkdir -p "${CORRUPT_DIR}"
printf '%s\n' '{"version":1,"state":"ok","detail":"seeded","updated_at":"2026-09-25T00:00:00Z","run_seq":"not-a-number","last_notify_epoch":0,"baseline":{"state":"ok","detail":"seeded baseline","updated_at":"2026-09-25T00:00:00Z"}}' >"${CORRUPT_DIR}/state.json"
fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"${K_START_1_SHELL}","ago":300},
  {"key":"${K_DATA_2}","ago":299},
  {"key":"${K_END_SHELL}","ago":298},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_case "${CORRUPT_DIR}"
is "garbled run_seq -> exit 2 (error verdict, not a crash)" "2" "${CASE_RC}"
is "garbled run_seq -> error verdict" "error" "${CASE_STATE}"
case "${CASE_DETAIL}" in *"state field run_seq is invalid"*) ok "garbled run_seq detail names the invalid field" ;; *) bad "garbled run_seq detail: ${CASE_DETAIL}" ;; esac
is "garbled run_seq -> readable baseline held" "seeded baseline" "$(python3 -c 'import json,sys; print((json.load(open(sys.argv[1])).get("baseline") or {}).get("detail",""))' "${CORRUPT_DIR}/state.json")"
if [ -f "${CORRUPT_DIR}/verdict.log" ] && grep -q ' error ' "${CORRUPT_DIR}/verdict.log"; then
  ok "garbled run_seq -> verdict line written (no silent crash)"
else
  bad "garbled run_seq -> verdict log missing the error line"
fi
if grep -q 'Traceback' "${WORK}/witness.err"; then bad "garbled run_seq -> uncaught traceback"; else ok "garbled run_seq -> no uncaught traceback"; fi

# R6: an unreadable state.json used to overwrite the stored baseline with
# null silently. It is now preserved as state.json.corrupt (forensics +
# recoverable baseline) and the repaired record reports baseline: null
# (never fabricated).
BROKEN_DIR="${WORK}/state-unreadable"
mkdir -p "${BROKEN_DIR}"
printf 'not json at all\n' >"${BROKEN_DIR}/state.json"
run_case "${BROKEN_DIR}"
is "unreadable state.json -> exit 2 (fail closed)" "2" "${CASE_RC}"
is "unreadable state.json -> error verdict" "error" "${CASE_STATE}"
is "unreadable state.json -> repaired baseline is null (never fabricated)" "null" "$(python3 -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1])).get("baseline")))' "${BROKEN_DIR}/state.json")"
if [ -f "${BROKEN_DIR}/state.json.corrupt" ] && grep -q 'seeded baseline' "${BROKEN_DIR}/state.json.corrupt" 2>/dev/null; then
  ok "unreadable state.json preserved as state.json.corrupt"
elif [ -f "${BROKEN_DIR}/state.json.corrupt" ]; then
  ok "unreadable state.json preserved as state.json.corrupt (raw content kept)"
else
  bad "unreadable state.json was overwritten without a .corrupt copy"
fi
if [ -f "${BROKEN_DIR}/verdict.log" ] && grep -q ' error ' "${BROKEN_DIR}/verdict.log"; then
  ok "unreadable state.json -> verdict line written"
else
  bad "unreadable state.json -> verdict log missing the error line"
fi

# ---- round-6 F1: a token that cannot be an HTTP header value fails the push,
# never the run. The emoji token used to raise UnicodeEncodeError and the
# newline token ValueError OUTSIDE notify's transport handler, aborting before
# state.json/verdict.log (and the ValueError text echoed the token bytes).
run_bad_token_case() { # $1 = state dir, $2 = token literal
  CASE_STATE_DIR="$1"
  mkdir -p "${CASE_STATE_DIR}"
  cat >"${WORK}/witness.env" <<EOF
RECORDING_WITNESS_ENDPOINT=http://127.0.0.1:${MOCK_PORT}
RECORDING_WITNESS_REGION=test-region
RECORDING_WITNESS_BUCKET=pc-admin-dr
RECORDING_WITNESS_AUDIT_PREFIX=audit/
RECORDING_WITNESS_RECORDINGS_PREFIX=recordings/
RECORDING_WITNESS_KEY_ID=test-key-id-0001
RECORDING_WITNESS_KEY=test-secret-SENTINEL-0009
RECORDING_WITNESS_STATE_DIR=${CASE_STATE_DIR}
NTFY_TOPIC='pc-admin test'
EOF
  python3 - "$2" "${WORK}/witness.env" <<'PY'
import sys

token, path = sys.argv[1], sys.argv[2]
quoted = "'" + token.replace("'", "'\\''") + "'"
with open(path, "a", encoding="utf-8") as handle:
    handle.write("NTFY_TOKEN=%s\n" % quoted)
PY
  export RECORDING_WITNESS_ENV_FILE="${WORK}/witness.env"
  CASE_RC=0
  "${WITNESS}" >"${WORK}/witness.out" 2>"${WORK}/witness.err" || CASE_RC=$?
  CASE_STATE="$(state_field state)"
}
fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[{"key":"audit/heartbeat/20260925T140000Z.json","ago":1200}],
 "uploads":[]}
JSON
start_mock
emoji_token="$(python3 -c 'print("abc\U0001f600def", end="")')"
newline_token="$(python3 -c 'print("abc\ndef", end="")')"
huge_token="$(python3 -c 'print("A" * 100000, end="")')"
for token_case in emoji newline huge; do
  case "${token_case}" in
    emoji) token="${emoji_token}" ;;
    newline) token="${newline_token}" ;;
    huge) token="${huge_token}" ;;
  esac
  bad_token_dir="${WORK}/state-bad-token-${token_case}"
  run_bad_token_case "${bad_token_dir}" "${token}"
  is "bad token (${token_case}) -> alert verdict, files written" "alert" "${CASE_STATE}"
  is "bad token (${token_case}) exits 1 (alert, not a crash)" "1" "${CASE_RC}"
  if [ -f "${bad_token_dir}/state.json" ] && [ -f "${bad_token_dir}/verdict.log" ]; then
    ok "bad token (${token_case}) writes state.json + verdict.log"
  else
    bad "bad token (${token_case}) left no files"
  fi
  if grep -q 'Traceback' "${WORK}/witness.err"; then
    bad "bad token (${token_case}) crashed with a traceback"
  else
    ok "bad token (${token_case}) never crashes"
  fi
  if grep -q 'ntfy push skipped' "${WORK}/witness.out"; then
    ok "bad token (${token_case}) logs the skipped push"
  else
    bad "bad token (${token_case}) skip not logged"
  fi
  if python3 - "${token}" "${WORK}/witness.out" "${WORK}/witness.err" \
      "${bad_token_dir}/state.json" "${bad_token_dir}/verdict.log" <<'PY'
import os
import sys

token = sys.argv[1].encode("utf-8")
for path in sys.argv[2:]:
    if os.path.exists(path) and token and token in open(path, "rb").read():
        raise SystemExit("token bytes found in %s" % path)
PY
  then
    ok "bad token (${token_case}) never echoes into logs/state"
  else
    bad "bad token (${token_case}) echoed token bytes somewhere"
  fi
done
unset emoji_token newline_token huge_token

# ---- round-6 F3: planted symlinks never redirect state/verdict writes ----
SYMLINK_DIR="${WORK}/state-symlink"
mkdir -p "${SYMLINK_DIR}"
victim_tmp="${WORK}/victim-tmp.txt"
victim_log="${WORK}/victim-log.txt"
printf 'victim-tmp' >"${victim_tmp}"
printf 'victim-log' >"${victim_log}"
chmod 644 "${victim_tmp}" "${victim_log}"
ln -s "${victim_tmp}" "${SYMLINK_DIR}/state.json.tmp"
ln -s "${victim_log}" "${SYMLINK_DIR}/verdict.log"
fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"audit/20260925T135000Z-session.start.${SID}.000001.shell.json","ago":300},
  {"key":"audit/20260925T135100Z-session.data.${SID}.000002.json","ago":299},
  {"key":"audit/20260925T135200Z-session.end.${SID}.000003.shell.json","ago":298},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_case "${SYMLINK_DIR}"
is "symlinked tmp/log target -> exit 0" "0" "${CASE_RC}"
is "symlinked tmp/log target -> ok verdict" "ok" "${CASE_STATE}"
is "state.json.tmp symlink victim content untouched" "victim-tmp" "$(cat "${victim_tmp}")"
is "state.json.tmp symlink victim mode untouched" "644" "$(mode_of "${victim_tmp}")"
is "verdict.log symlink victim content untouched" "victim-log" "$(cat "${victim_log}")"
if [ -f "${SYMLINK_DIR}/state.json" ] && [ ! -L "${SYMLINK_DIR}/state.json" ]; then
  ok "state.json written as a regular file (tmp symlink not followed)"
else
  bad "state.json missing or still a symlink"
fi
if grep -q 'cannot append verdict log' "${WORK}/witness.out"; then
  ok "symlinked verdict.log refused with a warning (victim untouched)"
else
  bad "symlinked verdict.log was not refused"
fi
TMP_DIR_BLOCK="${WORK}/state-tmp-directory"
mkdir -p "${TMP_DIR_BLOCK}/state.json.tmp"
run_case "${TMP_DIR_BLOCK}"
is "directory at state.json.tmp -> exit 0 (write refused, run continues)" "0" "${CASE_RC}"
if [ -d "${TMP_DIR_BLOCK}/state.json.tmp" ] && grep -q 'cannot write state file' "${WORK}/witness.out"; then
  ok "directory at state.json.tmp refused loudly"
else
  bad "directory at state.json.tmp not refused loudly"
fi

# ---- round-6 F4: deeply nested state.json -> error + repair, never a crash
DEEP_DIR="${WORK}/state-deep"
mkdir -p "${DEEP_DIR}"
python3 -c 'import sys; open(sys.argv[1], "w").write("[" * 200000)' "${DEEP_DIR}/state.json"
run_case "${DEEP_DIR}"
is "deeply nested state.json -> exit 2 (error verdict)" "2" "${CASE_RC}"
is "deeply nested state.json -> error state" "error" "${CASE_STATE}"
if [ -f "${DEEP_DIR}/state.json.corrupt" ] && [ -f "${DEEP_DIR}/verdict.log" ]; then
  ok "deeply nested state preserved as .corrupt + verdict written"
else
  bad "deeply nested state was not preserved/repaired"
fi
if grep -q 'Traceback' "${WORK}/witness.err"; then
  bad "deeply nested state crashed with a traceback"
else
  ok "deeply nested state never crashes (RecursionError bounded)"
fi

# ---- round-7 R2: an oversized state.json is invalid input, never an OOM ---
# The read is bounded (1 MiB): a planted 2 MiB state used to be read whole
# before parsing (a 200 MB file under a memory cap raised an uncaught
# MemoryError before any verdict). It must take the preserve+repair path.
OVERSIZE_DIR="${WORK}/state-oversize"
mkdir -p "${OVERSIZE_DIR}"
python3 - "${OVERSIZE_DIR}/state.json" <<'PY'
import sys

with open(sys.argv[1], "w", encoding="utf-8") as handle:
    handle.write('{"version":2,"state":"ok","detail":"' + "A" * (2 * 1024 * 1024)
                 + '","run_seq":41,"baseline":{"state":"ok","detail":"oversized baseline","updated_at":"2026-09-25T00:00:00Z"}}')
PY
run_case "${OVERSIZE_DIR}"
is "oversized state.json -> exit 2 (error verdict, not a crash)" "2" "${CASE_RC}"
is "oversized state.json -> error state" "error" "${CASE_STATE}"
is "oversized state repair marks the record repaired" "True" "$(state_field repaired)"
case "${CASE_DETAIL}" in
  *"state file exceeds"*) ok "oversized state detail names the size bound" ;;
  *) bad "oversized state detail: ${CASE_DETAIL}" ;;
esac
if [ -f "${OVERSIZE_DIR}/state.json.corrupt" ] && [ -f "${OVERSIZE_DIR}/verdict.log" ]; then
  ok "oversized state preserved as .corrupt + verdict written"
else
  bad "oversized state was not preserved/repaired"
fi
if grep -q 'Traceback' "${WORK}/witness.err"; then bad "oversized state crashed with a traceback"; else ok "oversized state never crashes (read bounded)"; fi

# ---- round-8: the state bound is BYTES, not characters -------------------
# The old text-mode read counted characters, so a valid JSON state under the
# 1 MiB character cap but over 1 MiB UTF-8 bytes slipped past the bound. The
# binary read must treat it as oversized (preserve + repaired error verdict).
OVERSIZE_UTF8_DIR="${WORK}/state-oversize-utf8"
mkdir -p "${OVERSIZE_UTF8_DIR}"
python3 - "${OVERSIZE_UTF8_DIR}/state.json" <<'PY'
import sys

with open(sys.argv[1], "w", encoding="utf-8") as handle:
    # ~717k chars (< 1 MiB) but ~1.4 MB as UTF-8 (over the byte bound).
    handle.write('{"version":2,"state":"ok","detail":"' + "\u00e9" * (700 * 1024)
                 + '","run_seq":41,"baseline":{"state":"ok","detail":"utf8 baseline","updated_at":"2026-09-25T00:00:00Z"}}')
PY
run_case "${OVERSIZE_UTF8_DIR}"
is "multi-byte state.json under the char cap but over the byte bound -> exit 2" "2" "${CASE_RC}"
is "multi-byte oversized state.json -> error state" "error" "${CASE_STATE}"
case "${CASE_DETAIL}" in
  *"state file exceeds"*) ok "byte-bound oversized detail names the size bound" ;;
  *) bad "byte-bound oversized detail: ${CASE_DETAIL}" ;;
esac
if [ -f "${OVERSIZE_UTF8_DIR}/state.json.corrupt" ] && [ -f "${OVERSIZE_UTF8_DIR}/verdict.log" ]; then
  ok "byte-oversized state preserved as .corrupt + verdict written"
else
  bad "byte-oversized state was not preserved/repaired"
fi

# ---- round-9: an invalid-UTF-8 state file is invalid input, never a crash ---
# The binary read decodes UTF-8 after the byte cap; a file with invalid byte
# sequences must take the same preserve-and-repair path (error verdict +
# `.corrupt` + verdict line) and name the encoding failure, instead of an
# uncaught UnicodeDecodeError before any verdict.
INVALID_UTF8_DIR="${WORK}/state-invalid-utf8"
mkdir -p "${INVALID_UTF8_DIR}"
printf '\377\376\375\374 invalid utf8 \303(\n' >"${INVALID_UTF8_DIR}/state.json"
run_case "${INVALID_UTF8_DIR}"
is "invalid-UTF-8 state.json -> exit 2 (fail-closed)" "2" "${CASE_RC}"
is "invalid-UTF-8 state.json -> error verdict" "error" "${CASE_STATE}"
case "${CASE_DETAIL}" in
  *"not valid UTF-8"*) ok "invalid-UTF-8 detail names the encoding failure" ;;
  *) bad "invalid-UTF-8 detail: ${CASE_DETAIL}" ;;
esac
if [ -f "${INVALID_UTF8_DIR}/state.json.corrupt" ] && [ -f "${INVALID_UTF8_DIR}/verdict.log" ]; then
  ok "invalid-UTF-8 state preserved as .corrupt + verdict written"
else
  bad "invalid-UTF-8 state was not preserved/repaired"
fi
if grep -q 'Traceback' "${WORK}/witness.err"; then bad "invalid-UTF-8 state crashed with a traceback"; else ok "invalid-UTF-8 state never crashes"; fi

# ---- round-10 NIT writer side: the record names the systemd invocation that
# wrote it (the identity the run-once gate binds a run_seq-resetting repair
# to), and a normal run is not marked repaired.
INVOCATION_DIR="${WORK}/state-invocation"
mkdir -p "${INVOCATION_DIR}"
HARNESS_INVOCATION="$(python3 -c 'import uuid; print(uuid.uuid4().hex)')"
export INVOCATION_ID="${HARNESS_INVOCATION}"
run_case "${INVOCATION_DIR}"
unset INVOCATION_ID
is "state.json names the systemd INVOCATION_ID that wrote it" \
  "${HARNESS_INVOCATION}" "$(state_field invocation)"
is "a normal run is not marked repaired" "" "$(state_field repaired)"

# ---- round-8: a failed preservation warning names the ACTUAL destination ---
# With an unwritable state dir the preserve/rename cannot land; the warning
# must name the destination the run tried (here a timestamped sibling, because
# state.json.corrupt is taken), not a hardcoded plain `.corrupt` name that
# would send triage to the wrong file.
UNWRITABLE_DIR="${WORK}/state-unwritable"
mkdir -p "${UNWRITABLE_DIR}"
printf 'not json at all\n' >"${UNWRITABLE_DIR}/state.json"
printf 'earlier forensics\n' >"${UNWRITABLE_DIR}/state.json.corrupt"
chmod 0500 "${UNWRITABLE_DIR}"
run_case "${UNWRITABLE_DIR}"
is "unwritable state dir -> exit 2 (fail-closed)" "2" "${CASE_RC}"
if grep -E 'cannot preserve unreadable state as .*/state\.json\.corrupt\.[0-9]{8}T[0-9]{6}Z:' "${WORK}/witness.out" >/dev/null; then
  ok "preservation-failure warning names the timestamped destination it tried"
else
  bad "preservation-failure warning named the wrong destination: $(grep 'cannot preserve' "${WORK}/witness.out" || echo none)"
fi
chmod 0700 "${UNWRITABLE_DIR}" || true

# ---- round-7 R3: an existing .corrupt is never overwritten ---------------
# Earlier forensics live at state.json.corrupt; the new corruption must land
# under a unique timestamped sibling.
KEEP_DIR="${WORK}/state-corrupt-keep"
mkdir -p "${KEEP_DIR}"
printf 'earlier forensics SENTINEL-R7-R3\n' >"${KEEP_DIR}/state.json.corrupt"
printf 'not json at all\n' >"${KEEP_DIR}/state.json"
run_case "${KEEP_DIR}"
is "existing .corrupt + unreadable state -> exit 2" "2" "${CASE_RC}"
is "existing .corrupt + unreadable state -> repaired error state" "error" "${CASE_STATE}"
if grep -q 'SENTINEL-R7-R3' "${KEEP_DIR}/state.json.corrupt"; then
  ok "existing .corrupt keeps the earlier forensics"
else
  bad "existing .corrupt was overwritten"
fi
replacement=""
for candidate in "${KEEP_DIR}"/state.json.corrupt.*; do
  [ -e "${candidate}" ] || continue
  replacement="${candidate}"
  break
done
if [ -n "${replacement}" ] && grep -q 'not json at all' "${replacement}"; then
  ok "new corruption preserved under a unique .corrupt.<stamp> name"
else
  bad "new corruption not preserved under a unique name"
fi

# ---- round-6 F8 + round-7 R3: a directory at .corrupt no longer disables ---
# preservation - the unique-name fallback lands the record anyway. -----------
CORRUPT_DIR_BLOCK="${WORK}/state-corrupt-blocked"
mkdir -p "${CORRUPT_DIR_BLOCK}/state.json.corrupt"
printf 'not json at all\n' >"${CORRUPT_DIR_BLOCK}/state.json"
run_case "${CORRUPT_DIR_BLOCK}"
is "unreadable state + .corrupt directory -> exit 2" "2" "${CASE_RC}"
is "unreadable state + .corrupt directory -> repaired error state" "error" "${CASE_STATE}"
replacement_dir=""
for candidate in "${CORRUPT_DIR_BLOCK}"/state.json.corrupt.*; do
  [ -e "${candidate}" ] || continue
  replacement_dir="${candidate}"
  break
done
if [ -d "${CORRUPT_DIR_BLOCK}/state.json.corrupt" ] && [ -n "${replacement_dir}" ]; then
  ok ".corrupt directory kept + new corruption preserved under a unique name"
else
  bad ".corrupt directory disabled preservation"
fi

# ---- round-6 F5: sid case is normalized for tar/upload lookups ------------
SID_UPPER="$(printf '%s' "${SID}" | tr '[:lower:]' '[:upper:]')"
SID2_UPPER="$(printf '%s' "${SID2}" | tr '[:lower:]' '[:upper:]')"
K_R6_START="$(key session.start 20260925T130000Z "${SID}" 1 shell)"
K_R6_DATA="$(key session.data 20260925T130100Z "${SID}" 2)"
K_R6_END="$(key session.end 20260925T130200Z "${SID}" 3 shell)"
fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"${K_R6_START}","ago":1300},
  {"key":"${K_R6_DATA}","ago":1299},
  {"key":"${K_R6_END}","ago":1298},
  {"key":"recordings/${SID_UPPER}.tar","ago":1297}],
 "uploads":[]}
JSON
start_mock
run_case
is "uppercase-sid tar no longer false-alerts recording-gap" "ok" "${CASE_STATE}"
fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"${K_R6_START}","ago":1300}],
 "uploads":[{"key":"recordings/${SID_UPPER}.tar","upload_id":"u-1","ago":1300}]}
JSON
start_mock
run_case
is "uppercase-sid in-progress upload satisfies the gap check" "ok" "${CASE_STATE}"
fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"${K_R6_START}","ago":1300},
  {"key":"recordings/${SID2_UPPER}.tar","ago":1297}],
 "uploads":[]}
JSON
start_mock
run_case
case "${CASE_DETAIL}" in
  *recording-gap*) ok "uppercase-sid normalization is per-session (an orphan uppercase tar does not cover SID's gap)" ;;
  *) bad "per-session sid normalization wrong: ${CASE_DETAIL}" ;;
esac

# ---- hidden objects: delete markers are tamper evidence -------------------
# Under B2 Object Lock compliance a delete is a HIDE MARKER: the current
# object disappears from ListObjectsV2 while the locked version survives. The
# pipeline never deletes, so ANY delete marker under a watched prefix alerts;
# a noncurrent version from a legitimate re-PUT is not a finding.
K_HIDDEN_A="$(key session.data 20260925T135300Z "${SID}" 3)"
K_HIDDEN_B="$(key session.data 20260925T135400Z "${SID2}" 3)"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":1,
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"audit/20260925T135000Z-session.start.${SID}.1.shell.json","ago":300},
  {"key":"audit/20260925T135100Z-session.data.${SID}.2.json","ago":299},
  {"key":"audit/20260925T135200Z-session.end.${SID}.3.shell.json","ago":298},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[],
 "versions":[
  {"key":"${K_HIDDEN_A}","version_id":"dm-1","is_latest":true,"delete_marker":true,"ago":120},
  {"key":"${K_HIDDEN_B}","version_id":"dm-2","is_latest":true,"delete_marker":true,"ago":119}]}
JSON
start_mock
run_case
is "delete markers under audit/ -> exit 1" "1" "${CASE_RC}"
is "delete markers under audit/ -> alert verdict" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in
  *hidden-object*audit=2*) ok "delete markers under audit/ alert hidden-object with the audit count" ;;
  *) bad "delete marker detail wrong: ${CASE_DETAIL}" ;;
esac
case "${CASE_DETAIL}" in
  *"keys: ${K_HIDDEN_B}"*) ok "hidden-object samples the newest marker first (not listing order)" ;;
  *) bad "newest-marker sampling wrong: ${CASE_DETAIL}" ;;
esac
case "${CASE_DETAIL}" in *"hiding detected"*) ok "hidden-object detail names hiding" ;; *) bad "hidden-object wording: ${CASE_DETAIL}" ;; esac
fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"audit/20260925T135000Z-session.start.${SID}.1.shell.json","ago":300},
  {"key":"audit/20260925T135100Z-session.data.${SID}.2.json","ago":299},
  {"key":"audit/20260925T135200Z-session.end.${SID}.3.shell.json","ago":298},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[],
 "versions":[
  {"key":"recordings/${SID2}.tar","version_id":"dm-rec-1","is_latest":true,"delete_marker":true,"ago":100}]}
JSON
start_mock
run_case
is "delete marker under recordings/ -> exit 1" "1" "${CASE_RC}"
is "delete marker under recordings/ -> alert verdict" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in
  *hidden-object*recordings=1*) ok "delete marker under recordings/ alerts hidden-object with the recordings count" ;;
  *) bad "recordings delete marker detail wrong: ${CASE_DETAIL}" ;;
esac
fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"audit/20260925T135000Z-session.start.${SID}.1.shell.json","ago":300},
  {"key":"audit/20260925T135100Z-session.data.${SID}.2.json","ago":299},
  {"key":"audit/20260925T135200Z-session.end.${SID}.3.shell.json","ago":298},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[],
 "versions":[
  {"key":"audit/20260925T135100Z-session.data.${SID}.2.json","version_id":"v-old","is_latest":false,"delete_marker":false,"ago":5000}]}
JSON
start_mock
run_case
is "noncurrent version (legitimate re-PUT) does not alert" "ok" "${CASE_STATE}"
case "${CASE_DETAIL}" in
  *hidden-object*) bad "noncurrent version reported hidden-object: ${CASE_DETAIL}" ;;
  *) ok "noncurrent version stays free of hidden-object" ;;
esac
fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"audit/20260925T135000Z-session.start.${SID}.1.shell.json","ago":300},
  {"key":"audit/20260925T135100Z-session.data.${SID}.2.json","ago":299},
  {"key":"audit/20260925T135200Z-session.end.${SID}.3.shell.json","ago":298},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[],
 "versions":[
  {"key":"audit/20260925T135100Z-session.data.${SID}.2.json","version_id":"dm-old","is_latest":false,"delete_marker":true,"ago":4000}]}
JSON
start_mock
run_case
is "noncurrent delete marker (a delete happened) -> exit 1" "1" "${CASE_RC}"
is "noncurrent delete marker -> alert verdict" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in
  *hidden-object*audit=1*) ok "noncurrent delete marker still alerts hidden-object" ;;
  *) bad "noncurrent delete marker detail wrong: ${CASE_DETAIL}" ;;
esac
fixture <<JSON
{"bucket":"pc-admin-dr","fail_versions":"error-doc-200",
 "objects":[{"key":"audit/heartbeat/20260925T140000Z.json","ago":45}],
 "uploads":[]}
JSON
start_mock
run_case
is "200 error document on versions -> exit 2 (fail-closed)" "2" "${CASE_RC}"
case "${CASE_DETAIL}" in
  *ListObjectVersions*expected\ ListVersionsResult*) ok "200 error-document detail names the non-list body" ;;
  *) bad "200 error-document detail: ${CASE_DETAIL}" ;;
esac
# Nonconformant server: a genuine error document wrapped inside a valid list
# root at HTTP 200. The root-name guard passes, so the child <Error> guard
# must fail closed instead of reading the body as an empty version listing.
fixture <<JSON
{"bucket":"pc-admin-dr","fail_versions":"error-doc-in-list-root",
 "objects":[{"key":"audit/heartbeat/20260925T140000Z.json","ago":45}],
 "uploads":[]}
JSON
start_mock
run_case
is "error document wrapped in a list root -> exit 2 (fail-closed)" "2" "${CASE_RC}"
case "${CASE_DETAIL}" in
  *ListObjectVersions*"<Error> child"*) ok "wrapped error-document detail names the Error child" ;;
  *) bad "wrapped error-document detail: ${CASE_DETAIL}" ;;
esac
fixture <<JSON
{"bucket":"pc-admin-dr","fail_versions":"truncated-no-version-marker",
 "objects":[{"key":"audit/heartbeat/20260925T140000Z.json","ago":45}],
 "uploads":[],
 "versions":[{"key":"audit/20260925T135100Z-session.data.${SID}.2.json","version_id":"v-1","is_latest":true,"delete_marker":false,"ago":300}]}
JSON
start_mock
run_case
is "truncated version list without version marker -> exit 2" "2" "${CASE_RC}"
case "${CASE_DETAIL}" in
  *ListObjectVersions*"truncated without a key/version marker"*) ok "version-marker truncation detail is explicit" ;;
  *) bad "version-marker truncation detail: ${CASE_DETAIL}" ;;
esac
# Contradictory server: no <IsTruncated> element at all while explicit Next*
# markers are present. The witness must follow the markers (the marker on
# page 2 is the only evidence of the hide), not read page 1 as complete.
K_PAGE1="$(key session.data 20260925T135150Z "${SID}" 9)"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":1,"versions_no_istruncated":true,
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"audit/20260925T135000Z-session.start.${SID}.1.shell.json","ago":300},
  {"key":"audit/20260925T135100Z-session.data.${SID}.2.json","ago":299},
  {"key":"audit/20260925T135200Z-session.end.${SID}.3.shell.json","ago":298},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[],
 "versions":[
  {"key":"${K_PAGE1}","version_id":"v-page1","is_latest":false,"delete_marker":false,"ago":300},
  {"key":"${K_HIDDEN_A}","version_id":"dm-page2","is_latest":true,"delete_marker":true,"ago":120}]}
JSON
start_mock
run_case
is "IsTruncated absent with Next markers present -> exit 1 (marker on page 2)" "1" "${CASE_RC}"
case "${CASE_DETAIL}" in
  *hidden-object*audit=1*) ok "contradictory IsTruncated still follows the Next markers to the hidden object" ;;
  *) bad "contradictory IsTruncated detail: ${CASE_DETAIL}" ;;
esac
# Nonconformant server: a truncated version page with no <IsTruncated> and
# only the version marker. The guard must treat the version marker as
# truncation (paired-marker guard → error), so a future regression to a
# key-marker-only guard is caught.
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":1,"versions_no_istruncated":true,"versions_partial_marker":"version-only",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"audit/20260925T135000Z-session.start.${SID}.1.shell.json","ago":300},
  {"key":"audit/20260925T135100Z-session.data.${SID}.2.json","ago":299},
  {"key":"audit/20260925T135200Z-session.end.${SID}.3.shell.json","ago":298},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[],
 "versions":[
  {"key":"${K_PAGE1}","version_id":"v-page1","is_latest":false,"delete_marker":false,"ago":300},
  {"key":"${K_HIDDEN_A}","version_id":"v-page2","is_latest":false,"delete_marker":false,"ago":120}]}
JSON
start_mock
run_case
is "truncated version page with only a version marker -> exit 2" "2" "${CASE_RC}"
case "${CASE_DETAIL}" in
  *ListObjectVersions*"truncated without a key/version marker"*) ok "version-only marker still fails closed via the paired-marker guard" ;;
  *) bad "version-only marker detail: ${CASE_DETAIL}" ;;
esac
fixture <<JSON
{"bucket":"pc-admin-dr","versions_ignore_prefix":true,
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"audit/20260925T135000Z-session.start.${SID}.1.shell.json","ago":300},
  {"key":"audit/20260925T135100Z-session.data.${SID}.2.json","ago":299},
  {"key":"audit/20260925T135200Z-session.end.${SID}.3.shell.json","ago":298},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[],
 "versions":[
  {"key":"${K_HIDDEN_A}","version_id":"dm-1","is_latest":true,"delete_marker":true,"ago":120}]}
JSON
start_mock
run_case
is "prefix-ignoring server double-listing one marker -> exit 1" "1" "${CASE_RC}"
case "${CASE_DETAIL}" in
  *hidden-object*audit=1*) ok "one hidden version is counted once across both listings" ;;
  *) bad "dedupe count wrong: ${CASE_DETAIL}" ;;
esac
fixture <<JSON
{"bucket":"pc-admin-dr","fail_versions":"denied",
 "objects":[{"key":"audit/heartbeat/20260925T140000Z.json","ago":45}],
 "uploads":[]}
JSON
start_mock
run_case
is "denied version listing (403) -> exit 2 (fail-closed)" "2" "${CASE_RC}"
is "denied version listing -> error verdict" "error" "${CASE_STATE}"
case "${CASE_DETAIL}" in
  *ListObjectVersions*403*) ok "denied version listing detail names the call + status" ;;
  *) bad "denied version listing detail: ${CASE_DETAIL}" ;;
esac
fixture <<JSON
{"bucket":"pc-admin-dr","fail_versions":"malformed",
 "objects":[{"key":"audit/heartbeat/20260925T140000Z.json","ago":45}],
 "uploads":[]}
JSON
start_mock
run_case
is "malformed version-list XML -> exit 2" "2" "${CASE_RC}"
case "${CASE_DETAIL}" in
  *ListObjectVersions*unparseable*) ok "malformed version-list detail is explicit" ;;
  *) bad "malformed version-list detail: ${CASE_DETAIL}" ;;
esac
fixture <<JSON
{"bucket":"pc-admin-dr","fail_versions":"truncated-no-token",
 "objects":[{"key":"audit/heartbeat/20260925T140000Z.json","ago":45}],
 "uploads":[]}
JSON
start_mock
run_case
is "truncated version list without key marker -> exit 2" "2" "${CASE_RC}"
case "${CASE_DETAIL}" in
  *ListObjectVersions*"truncated without a key/version marker"*) ok "version-list truncation detail is explicit" ;;
  *) bad "version-list truncation detail: ${CASE_DETAIL}" ;;
esac

# ---- finding signatures: stable identities, ages never enter -------------
# The notification signature is built from stable identities only. These
# teeth drive the REAL witness against the mock: the same finding set must
# yield the same signature across runs (and a different one when the set
# changes), while an age-only drift must change the displayed detail but keep
# the signature identical - the property that lets the change-trigger push on
# real changes without pushing on every 5-minute run.
SIG_DIR="${WORK}/signature-state"
# One hidden marker -> alert; its key+version set is the signature.
fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"audit/20260925T135000Z-session.start.${SID}.1.shell.json","ago":300},
  {"key":"audit/20260925T135100Z-session.data.${SID}.2.json","ago":299},
  {"key":"audit/20260925T135200Z-session.end.${SID}.3.shell.json","ago":298},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[],
 "versions":[{"key":"${K_HIDDEN_A}","version_id":"dm-1","is_latest":true,"delete_marker":true,"ago":120}]}
JSON
start_mock
run_case "${SIG_DIR}"
is "signature: one hidden marker -> alert" "alert" "${CASE_STATE}"
sig_one="$(state_field signature)"
if printf '%s' "${sig_one}" | grep -Eq '^sha256:[0-9a-f]{64}$'; then
  ok "signature is a sha256:<64 lowercase hex> digest"
else
  bad "signature malformed: ${sig_one}"
fi
# A second marker changes the set -> a different signature.
fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"audit/20260925T135000Z-session.start.${SID}.1.shell.json","ago":300},
  {"key":"audit/20260925T135100Z-session.data.${SID}.2.json","ago":299},
  {"key":"audit/20260925T135200Z-session.end.${SID}.3.shell.json","ago":298},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[],
 "versions":[
  {"key":"${K_HIDDEN_A}","version_id":"dm-1","is_latest":true,"delete_marker":true,"ago":120},
  {"key":"${K_HIDDEN_B}","version_id":"dm-2","is_latest":true,"delete_marker":true,"ago":119}]}
JSON
start_mock
run_case "${SIG_DIR}"
sig_two="$(state_field signature)"
if [ -n "${sig_one}" ] && [ "${sig_one}" != "${sig_two}" ]; then
  ok "signature changes when the hidden-marker set changes"
else
  bad "signature did not change on a marker-set change (${sig_one} vs ${sig_two})"
fi
# The same set on a fresh server -> the same signature (listing order and
# server identity never enter).
fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"audit/20260925T135000Z-session.start.${SID}.1.shell.json","ago":300},
  {"key":"audit/20260925T135100Z-session.data.${SID}.2.json","ago":299},
  {"key":"audit/20260925T135200Z-session.end.${SID}.3.shell.json","ago":298},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[],
 "versions":[{"key":"${K_HIDDEN_A}","version_id":"dm-1","is_latest":true,"delete_marker":true,"ago":120}]}
JSON
start_mock
run_case "${SIG_DIR}"
is "signature is stable across runs for the same finding set" "${sig_one}" "$(state_field signature)"
# Healthy bucket -> its own constant signature, distinct from every alert.
fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"audit/20260925T135000Z-session.start.${SID}.1.shell.json","ago":300},
  {"key":"audit/20260925T135100Z-session.data.${SID}.2.json","ago":299},
  {"key":"audit/20260925T135200Z-session.end.${SID}.3.shell.json","ago":298},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_case "${SIG_DIR}"
is "signature: healthy fixture -> ok" "ok" "${CASE_STATE}"
sig_ok="$(state_field signature)"
if [ -n "${sig_ok}" ] && [ "${sig_ok}" != "${sig_one}" ]; then
  ok "ok signature differs from the alert signature"
else
  bad "ok signature collided with the alert signature (${sig_ok})"
fi
# Age-only drift: heartbeat-stale at 1200s and at 3600s is the same finding
# (same class, same identity). The detail shows the age, the signature must not.
fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[{"key":"audit/heartbeat/20260925T140000Z.json","ago":1200}],
 "uploads":[]}
JSON
start_mock
run_case "${SIG_DIR}"
sig_age_a="$(state_field signature)"
detail_age_a="${CASE_DETAIL}"
fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[{"key":"audit/heartbeat/20260925T140000Z.json","ago":3600}],
 "uploads":[]}
JSON
start_mock
run_case "${SIG_DIR}"
sig_age_b="$(state_field signature)"
detail_age_b="${CASE_DETAIL}"
if [ -n "${sig_age_a}" ] && [ "${sig_age_a}" = "${sig_age_b}" ]; then
  ok "age-only heartbeat drift keeps the signature identical"
else
  bad "heartbeat age drift changed the signature (${sig_age_a} vs ${sig_age_b})"
fi
if [ "${detail_age_a}" != "${detail_age_b}" ]; then
  ok "heartbeat age drift still shows in the displayed detail (the tooth discriminates)"
else
  bad "heartbeat detail did not carry the age: ${detail_age_a}"
fi
# Same property for a session alert: an unresolved shell session past the
# grace (recording-gap, no end) at two different ages.
fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"audit/20260925T135000Z-session.start.${SID2}.1.shell.json","ago":800}],
 "uploads":[]}
JSON
start_mock
run_case "${SIG_DIR}"
sig_gap_a="$(state_field signature)"
is "recording-gap fixture -> alert" "alert" "${CASE_STATE}"
fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"audit/20260925T135000Z-session.start.${SID2}.1.shell.json","ago":1600}],
 "uploads":[]}
JSON
start_mock
run_case "${SIG_DIR}"
sig_gap_b="$(state_field signature)"
if [ -n "${sig_gap_a}" ] && [ "${sig_gap_a}" = "${sig_gap_b}" ]; then
  ok "age-only recording-gap drift keeps the signature identical"
else
  bad "recording-gap age drift changed the signature (${sig_gap_a} vs ${sig_gap_b})"
fi
# Class changes DO move it: heartbeat-missing vs heartbeat-stale.
fixture <<JSON
{"bucket":"pc-admin-dr","objects":[],"uploads":[]}
JSON
start_mock
run_case "${SIG_DIR}"
sig_missing="$(state_field signature)"
if [ -n "${sig_missing}" ] && [ "${sig_missing}" != "${sig_age_a}" ]; then
  ok "heartbeat-missing and heartbeat-stale carry different signatures"
else
  bad "heartbeat classes collided (${sig_missing} vs ${sig_age_a})"
fi
# Drift key IDENTITY enters (not just the count): the same naming-drift class
# under a different key must move the signature. Hand-written on purpose: the
# shipper replica refuses a mode on a non-lifecycle event, so only a broken
# producer can emit this shape. Only the key's timestamp differs between the
# two fixtures (same seq), so the sequence-origin / session-start-missing
# identities stay identical and the drift identity is the only mover.
K_DRIFT_A="audit/20260925T140000Z-session.data.${SID}.7.shell.json"
K_DRIFT_B="audit/20260925T140001Z-session.data.${SID}.7.shell.json"
fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"${K_DRIFT_A}","ago":300}],
 "uploads":[]}
JSON
start_mock
run_case "${SIG_DIR}"
sig_drift_a="$(state_field signature)"
is "naming-drift fixture -> alert" "alert" "${CASE_STATE}"
fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"${K_DRIFT_B}","ago":300}],
 "uploads":[]}
JSON
start_mock
run_case "${SIG_DIR}"
sig_drift_b="$(state_field signature)"
if [ -n "${sig_drift_a}" ] && [ "${sig_drift_a}" != "${sig_drift_b}" ]; then
  ok "a different drift key moves the signature (identity, not just count)"
else
  bad "drift key identity did not enter the signature (${sig_drift_a} vs ${sig_drift_b})"
fi
# The hidden identity covers key AND version_id: the same key under a
# different version id is a different marker set and must move it.
fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"audit/20260925T135000Z-session.start.${SID}.1.shell.json","ago":300},
  {"key":"audit/20260925T135100Z-session.data.${SID}.2.json","ago":299},
  {"key":"audit/20260925T135200Z-session.end.${SID}.3.shell.json","ago":298},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[],
 "versions":[{"key":"${K_HIDDEN_A}","version_id":"dm-ver-A","is_latest":true,"delete_marker":true,"ago":120}]}
JSON
start_mock
run_case "${SIG_DIR}"
sig_ver_a="$(state_field signature)"
fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"audit/20260925T135000Z-session.start.${SID}.1.shell.json","ago":300},
  {"key":"audit/20260925T135100Z-session.data.${SID}.2.json","ago":299},
  {"key":"audit/20260925T135200Z-session.end.${SID}.3.shell.json","ago":298},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[],
 "versions":[{"key":"${K_HIDDEN_A}","version_id":"dm-ver-B","is_latest":true,"delete_marker":true,"ago":120}]}
JSON
start_mock
run_case "${SIG_DIR}"
if [ -n "${sig_ver_a}" ] && [ "${sig_ver_a}" != "$(state_field signature)" ]; then
  ok "hidden identity covers version_id (same key, different version)"
else
  bad "hidden identity ignored version_id (${sig_ver_a})"
fi
# Age-only drift for the remaining age-bearing classes: the displayed detail
# (which carries the age) changes, the signature must not.
fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"audit/20260925T135000Z-session.start.${SID}.1.shell.json","ago":2000},
  {"key":"audit/20260925T135100Z-session.data.${SID}.2.json","ago":1900},
  {"key":"recordings/${SID}.tar","ago":1000}],
 "uploads":[]}
JSON
start_mock
run_case "${SIG_DIR}"
sig_end_a="$(state_field signature)"
detail_end_a="${CASE_DETAIL}"
is "completed tar without session.end -> alert" "alert" "${CASE_STATE}"
fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"audit/20260925T135000Z-session.start.${SID}.1.shell.json","ago":2000},
  {"key":"audit/20260925T135100Z-session.data.${SID}.2.json","ago":1900},
  {"key":"recordings/${SID}.tar","ago":2000}],
 "uploads":[]}
JSON
start_mock
run_case "${SIG_DIR}"
if [ -n "${sig_end_a}" ] && [ "${sig_end_a}" = "$(state_field signature)" ]; then
  ok "age-only session-end-missing drift keeps the signature identical"
else
  bad "session-end-missing age drift changed the signature (${sig_end_a})"
fi
if [ "${detail_end_a}" != "${CASE_DETAIL}" ]; then
  ok "session-end-missing age drift still shows in the detail (the tooth discriminates)"
else
  bad "session-end-missing detail did not carry the age: ${detail_end_a}"
fi
fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"audit/20260925T135000Z-session.start.${SID}.1.shell.json","ago":4000},
  {"key":"audit/20260925T135100Z-session.end.${SID}.2.shell.json","ago":1000}],
 "uploads":[{"key":"recordings/${SID}.tar","upload_id":"u-cl-1","ago":3000}]}
JSON
start_mock
run_case "${SIG_DIR}"
sig_cl_a="$(state_field signature)"
detail_cl_a="${CASE_DETAIL}"
is "old session.end upload -> alert" "alert" "${CASE_STATE}"
fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"audit/20260925T135000Z-session.start.${SID}.1.shell.json","ago":4000},
  {"key":"audit/20260925T135100Z-session.end.${SID}.2.shell.json","ago":2000}],
 "uploads":[{"key":"recordings/${SID}.tar","upload_id":"u-cl-2","ago":3000}]}
JSON
start_mock
run_case "${SIG_DIR}"
if [ -n "${sig_cl_a}" ] && [ "${sig_cl_a}" = "$(state_field signature)" ]; then
  ok "age-only completer-lag drift keeps the signature identical"
else
  bad "completer-lag age drift changed the signature (${sig_cl_a})"
fi
if [ "${detail_cl_a}" != "${CASE_DETAIL}" ]; then
  ok "completer-lag age drift still shows in the detail (the tooth discriminates)"
else
  bad "completer-lag detail did not carry the age: ${detail_cl_a}"
fi
fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[{"key":"audit/heartbeat/20260925T140000Z.json","ago":45}],
 "uploads":[{"key":"recordings/${SID2}.tar","upload_id":"u-ou-1","ago":46800}]}
JSON
start_mock
run_case "${SIG_DIR}"
sig_ou_a="$(state_field signature)"
detail_ou_a="${CASE_DETAIL}"
is "upload open 13h without session.end -> alert" "alert" "${CASE_STATE}"
fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[{"key":"audit/heartbeat/20260925T140000Z.json","ago":45}],
 "uploads":[{"key":"recordings/${SID2}.tar","upload_id":"u-ou-2","ago":50400}]}
JSON
start_mock
run_case "${SIG_DIR}"
if [ -n "${sig_ou_a}" ] && [ "${sig_ou_a}" = "$(state_field signature)" ]; then
  ok "age-only open-upload-stale drift keeps the signature identical"
else
  bad "open-upload-stale age drift changed the signature (${sig_ou_a})"
fi
if [ "${detail_ou_a}" != "${CASE_DETAIL}" ]; then
  ok "open-upload-stale age drift still shows in the detail (the tooth discriminates)"
else
  bad "open-upload-stale detail did not carry the age: ${detail_ou_a}"
fi
# The session-start-missing identity is tagged by condition: an events-without-
# start set and an orphan-tar set for the same sid are different findings.
fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"audit/20260925T135100Z-session.data.${SID}.1.json","ago":299},
  {"key":"audit/20260925T135200Z-session.end.${SID}.2.json","ago":298}],
 "uploads":[]}
JSON
start_mock
run_case "${SIG_DIR}"
sig_ss_a="$(state_field signature)"
is "events without session.start -> alert" "alert" "${CASE_STATE}"
fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"recordings/${SID}.tar","ago":1000}],
 "uploads":[]}
JSON
start_mock
run_case "${SIG_DIR}"
if [ -n "${sig_ss_a}" ] && [ "${sig_ss_a}" != "$(state_field signature)" ]; then
  ok "session-start-missing identity is tagged by condition (events vs orphan tar)"
else
  bad "session-start-missing conditions collapsed to one identity (${sig_ss_a})"
fi

# ---- (f) strictly list-only + SigV4 proof over every request -------------
if python3 - "${REQUEST_LOG}" <<'PY'
import json
import sys

violations = []
entries = 0
pagination = 0
versions_pagination = 0
uploads_pagination = 0
sig_ok = 0
signed_shape = False
for raw in open(sys.argv[1], encoding="utf-8"):
    raw = raw.strip()
    if not raw:
        continue
    entry = json.loads(raw)
    entries += 1
    if entry["method"] != "GET":
        violations.append("non-GET method: %s %s" % (entry["method"], entry["path"]))
    if not entry["auth"]:
        violations.append("unsigned request: %s" % entry["path"])
    if not entry["x_amz_date"] or not entry["x_amz_content_sha256"]:
        violations.append("missing signed headers: %s" % entry["path"])
    if "SignedHeaders=host;x-amz-content-sha256;x-amz-date" in entry["signed_headers"]:
        signed_shape = True
    if entry.get("sig_check") == "ok":
        sig_ok += 1
    if entry.get("sig_check", "").startswith("failed"):
        violations.append("SigV4 verification: %s" % entry["sig_check"])
    if not entry["ok"] and "fixture" not in entry["note"]:
        violations.append("rejected request: %s" % entry["note"])
    if ("list-type=2" not in entry["note"] and "uploads" not in entry["note"]
            and "versions" not in entry["note"] and entry["ok"]):
        violations.append("non-list OK request: %s" % entry["note"])
    for forbidden in ("partNumber=", "uploadId=", "?acl", "?versioning"):
        if forbidden in entry["path"]:
            violations.append("forbidden query %s in %s" % (forbidden, entry["path"]))
    if "continuation-token=" in entry["path"]:
        pagination += 1
    if "versions" in entry["note"] and "version-id-marker=" in entry["path"]:
        versions_pagination += 1
    if "uploads" in entry["note"] and "key-marker=" in entry["path"]:
        uploads_pagination += 1

if entries < 20:
    violations.append("too few requests observed (%d) - scenarios did not run" % entries)
if pagination < 1:
    violations.append("no continuation-token request - object pagination not followed")
if uploads_pagination < 1:
    violations.append("no key-marker request - upload pagination not followed")
if versions_pagination < 1:
    violations.append("no version-id-marker request - version pagination not followed")
if sig_ok != entries:
    violations.append("SigV4 verified on only %d/%d requests (all must verify)" % (sig_ok, entries))
if not signed_shape:
    violations.append("no request carried the expected SigV4 SignedHeaders shape")

if violations:
    for violation in violations:
        print("VIOLATION " + violation)
    sys.exit(1)
print("requests=%d pagination=%d versions_pagination=%d uploads_pagination=%d sig_ok=%d" % (
    entries, pagination, versions_pagination, uploads_pagination, sig_ok))
PY
then ok "every witness request was a signed list call (no HEAD/GET-object/ListParts/write)"; else bad "list-only/SigV4 proof failed"; fi

# ---- (f2) transport: bounded bodies, stale-pool reconnect, worker parity ----
# Bounded response bodies: a 2xx body over the cap must fail the run closed
# (WitnessError), while an oversized non-2xx body is truncated for the
# clipped message instead of allocating it whole.
py_begin="$(grep -n "exec python3 - <<'RECORDING_WITNESS_PY_EOF'" "${PROVISION}" | cut -d: -f1)"
py_end="$(grep -n '^RECORDING_WITNESS_PY_EOF$' "${PROVISION}" | cut -d: -f1)"
sed -n "$((py_begin + 1)),$((py_end - 1))p" "${PROVISION}" >"${WORK}/witness_module.py"
if python3 - "${WORK}" <<'PY'
import importlib.util
import os
import sys
import threading
import types
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

work = sys.argv[1]
spec = importlib.util.spec_from_file_location("witness_transport", os.path.join(work, "witness_module.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class BigHandler(BaseHTTPRequestHandler):
    status = 200
    size = 4096

    def log_message(self, *args):
        pass

    def do_GET(self):
        body = b"x" * BigHandler.size
        self.send_response(BigHandler.status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


server = ThreadingHTTPServer(("127.0.0.1", 0), BigHandler)
threading.Thread(target=server.serve_forever, daemon=True).start()
config = types.SimpleNamespace(
    endpoint="http://127.0.0.1:%d" % server.server_address[1],
    bucket="pc-admin-dr",
    key_id="k",
    key="s",
    signing_region=lambda: "test-region",
)
module.MAX_SUCCESS_BODY = 1024
module.MAX_ERROR_BODY = 1024
module.close_connections()
try:
    module.signed_get(config, {"list-type": "2", "prefix": "audit/"})
except module.WitnessError:
    pass
else:
    raise SystemExit("a 2xx body over MAX_SUCCESS_BODY must raise WitnessError")
module.close_connections()
BigHandler.status = 500
status, body = module.signed_get(config, {"list-type": "2", "prefix": "audit/"})
if status != 500 or len(body) != 1024:
    raise SystemExit("an oversized non-2xx body must be truncated to MAX_ERROR_BODY (got %d bytes)" % len(body))
# F4 tooth: the truncation leaves the rest of the body unread, so the pooled
# keep-alive connection can no longer be reused; it must be dropped now, or
# the next request burns the one bounded reconnect on a dead socket (an
# extra Class C call).
if getattr(module._TRANSPORT, "connection", None) is not None:
    raise SystemExit("a truncated error body must drop the pooled connection")
module.close_connections()
server.shutdown()
print("body caps: 2xx over cap raised; non-2xx truncated at cap; truncated pool dropped")
PY
then ok "transport bounds 2xx bodies (fail-closed) and truncates error bodies"; else bad "transport body-bound test failed"; fi

# A pooled connection the server dropped between calls: the witness must
# reconnect once and re-send the same idempotent list GET, never surface a
# spurious error. The mock drops the first list connection without a
# response; the run must stay green and the log must show the dropped attempt
# followed by a served one.
LIST_WORKERS_OVERRIDE="${RECORDING_WITNESS_LIST_WORKERS:-}"
unset RECORDING_WITNESS_LIST_WORKERS
start_mock
stale_dir="${WORK}/state-stale"
fixture <<JSON
{"bucket":"pc-admin-dr","close_first_list_requests":1,
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"audit/20260925T135000Z-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
SAVED_REQUEST_LOG="${REQUEST_LOG}"
REQUEST_LOG="${WORK}/requests-stale.log"
: >"${REQUEST_LOG}"
start_mock
run_case "${stale_dir}"
REQUEST_LOG="${SAVED_REQUEST_LOG}"
is "stale pooled connection: reconnect + re-send stays green" "0" "${CASE_RC}"
is "stale pooled connection: verdict is ok" "ok" "${CASE_STATE}"
if python3 - "${WORK}/requests-stale.log" <<'PY'
import json
import sys

entries = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8") if line.strip()]
dropped = [index for index, entry in enumerate(entries) if "stale-pool retry" in entry.get("note", "")]
served = [index for index, entry in enumerate(entries) if entry.get("ok")]
# The five families race on the pool, so the dropped attempt is not
# necessarily the first logged line; the load-bearing shape is exactly one
# dropped attempt whose same idempotent re-send is served afterwards.
if len(dropped) != 1 or len(served) < 5:
    raise SystemExit("stale-pool retry not observable: dropped=%d served=%d" % (len(dropped), len(served)))
if not any(index > dropped[0] for index in served):
    raise SystemExit("no served request followed the dropped one")
if len(entries) != 6:
    raise SystemExit("expected 5 family requests + 1 re-send, got %d requests" % len(entries))
print("stale-pool: 1 dropped, %d served, %d requests" % (len(served), len(entries)))
PY
then ok "stale pooled connection: one dropped attempt is followed by a served re-send"; else bad "stale-pool retry evidence missing"; fi

# The displayed heartbeat age can tick across a whole second between two
# runs (the bucket timestamps are second-resolution); the finding set is the
# stable identity, so normalize only the age fragment before comparing.
norm_detail() { printf '%s' "$1" | sed 's/heartbeat_age=[0-9]*s/heartbeat_age=X/'; }

# Worker parity: the parallel family fan-out must not change the verdict,
# detail or finding signature. Same fixture, fresh state dirs, workers 1 vs 4.
parity_dir_serial="${WORK}/state-parity-serial"
parity_dir_parallel="${WORK}/state-parity-parallel"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":2,
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"audit/20260925T135000Z-session.start.${SID}.0.json","ago":300},
  {"key":"audit/20260925T135100Z-session.data.${SID}.1.json","ago":299},
  {"key":"audit/20260925T135200Z-session.end.${SID}.2.json","ago":298},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
RECORDING_WITNESS_LIST_WORKERS=1
run_case "${parity_dir_serial}"
serial_rc="${CASE_RC}"; serial_state="${CASE_STATE}"; serial_detail="${CASE_DETAIL}"
RECORDING_WITNESS_LIST_WORKERS=4
run_case "${parity_dir_parallel}"
unset RECORDING_WITNESS_LIST_WORKERS
is "worker parity: rc identical (serial vs 4 workers)" "${serial_rc}" "${CASE_RC}"
is "worker parity: verdict identical" "${serial_state}" "${CASE_STATE}"
is "worker parity: detail identical" "$(norm_detail "${serial_detail}")" "$(norm_detail "${CASE_DETAIL}")"
if [ -n "${LIST_WORKERS_OVERRIDE}" ]; then export RECORDING_WITNESS_LIST_WORKERS="${LIST_WORKERS_OVERRIDE}"; fi

# M1: the parity teeth compare verdicts, which stay identical even if the
# pool is forced to one thread. Spy on ThreadPoolExecutor so the configured
# fan-out itself is pinned (workers=4 builds a 4-worker pool; workers=1 stays
# the serial seam).
if python3 - "${WORK}" <<'PY'
import importlib.util
import os
import sys
import types

work = sys.argv[1]
spec = importlib.util.spec_from_file_location("witness_workers", os.path.join(work, "witness_module.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

seen = {}
real_executor = module.ThreadPoolExecutor


class SpyExecutor(object):
    def __init__(self, max_workers=None, *args, **kwargs):
        seen["max_workers"] = max_workers
        self._impl = real_executor(max_workers=max_workers, *args, **kwargs)

    def submit(self, *args, **kwargs):
        return self._impl.submit(*args, **kwargs)

    def __enter__(self):
        self._impl.__enter__()
        return self

    def __exit__(self, *args):
        return self._impl.__exit__(*args)


module.ThreadPoolExecutor = SpyExecutor


def fake_signed_get(config, params):
    if params.get("versions") is not None:
        return 200, b"<ListVersionsResult/>"
    if params.get("uploads") is not None:
        return 200, b"<ListMultipartUploadsResult/>"
    return 200, b"<ListBucketResult/>"


module.signed_get = fake_signed_get
config = types.SimpleNamespace(
    endpoint="http://127.0.0.1:1",
    bucket="b",
    key_id="k",
    key="s",
    signing_region=lambda: "test-region",
    audit_prefix="audit/",
    recordings_prefix="recordings/",
    heartbeat_prefix="audit/heartbeat/",
    list_workers=4,
)
module._collect_families(config, ["audit/mid"])
if seen.get("max_workers") != 4:
    raise SystemExit("configured workers=4 did not reach the executor (got %r)" % (seen.get("max_workers"),))
seen.clear()
config.list_workers = 1
module._collect_families(config, ["audit/mid"])
if seen:
    raise SystemExit("workers=1 must stay serial (built a pool with max_workers=%r)" % seen.get("max_workers"))
print("worker count: max_workers honored (4 -> pool, 1 -> serial)")
PY
then ok "worker count: the configured fan-out reaches the executor (workers=1 stays serial)"; else bad "worker-count tooth failed"; fi

# ---- (f3) cold start: windowed seed + coverage disclosure -----------------
# A first run with no observed block lists a window of both audit streams
# (recordings copies are full - a <sid>.tar key carries no timestamp) and
# cannot return ok: the verdict carries the cold-start disclosure and the
# state marks compact_blind until the first sweep. The windowed requests must
# carry start-after markers that exclude the below-window key; a window with
# no heartbeat at all falls back to the exact full sweep.
SEED_OLD_TS="$(audit_stamp -100000)"
SEED_HEARTBEAT_TS="$(audit_stamp -60)"
SEED_START_TS="$(audit_stamp -300)"
SEED_DATA_TS="$(audit_stamp -299)"
SEED_DATED_TS="$(audit_stamp -250)"
seed_state_dir="${WORK}/state-seed-cold"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":2,
 "objects":[
  {"key":"audit/heartbeat/${SEED_OLD_TS}.json","ago":100000},
  {"key":"audit/heartbeat/${SEED_HEARTBEAT_TS}.json","ago":45},
  {"key":"audit/${SEED_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"audit/${SEED_DATA_TS}-session.data.${SID}.1.json","ago":299},
  {"key":"$(dated_key user.login "${SEED_DATED_TS}" "" 9)","ago":250},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
SAVED_REQUEST_LOG="${REQUEST_LOG}"
REQUEST_LOG="${WORK}/requests-seed.log"
: >"${REQUEST_LOG}"
start_mock
RECORDING_WITNESS_COLD_START_SECONDS=3600
run_case "${seed_state_dir}"
unset RECORDING_WITNESS_COLD_START_SECONDS
REQUEST_LOG="${SAVED_REQUEST_LOG}"
is "cold-start seed: exit 1 (a windowed seed can never be green)" "1" "${CASE_RC}"
is "cold-start seed: alert verdict" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in
  *cold-start*) ok "cold-start seed: detail carries the disclosure" ;;
  *) bad "cold-start seed: detail lacks the disclosure: ${CASE_DETAIL}" ;;
esac
is "cold-start seed: coverage mode is seed" "seed" "$(state_field observed.coverage.mode)"
is "cold-start seed: compact_blind is set" "True" "$(state_field observed.coverage.compact_blind)"
if python3 - "${WORK}/requests-seed.log" "${SEED_OLD_TS}" "${SEED_HEARTBEAT_TS}" <<'PY'
import json
import re
import sys
import urllib.parse

log_path, old_ts, recent_ts = sys.argv[1], sys.argv[2], sys.argv[3]
entries = [json.loads(line) for line in open(log_path, encoding="utf-8") if line.strip()]
violations = []
heartbeat_starts = []
session_starts = []
recordings = 0
for entry in entries:
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(entry["path"]).query)
    note = entry.get("note", "")
    if "versions" in note:
        violations.append("seed requested a versions listing: %s" % note)
    if note.startswith("list-type=2"):
        prefix = query.get("prefix", [""])[0]
        start_after = query.get("start-after", [""])[0]
        continuation = query.get("continuation-token", [""])[0]
        if prefix == "recordings/":
            recordings += 1
            if start_after:
                violations.append("recordings seed must be a full listing, got start-after=%r" % start_after)
            continue
        if not start_after and not continuation:
            violations.append("audit seed listing without start-after: %s" % entry["path"])
            continue
        if prefix == "audit/heartbeat/":
            if start_after:
                heartbeat_starts.append(start_after)
        elif prefix == "audit/":
            if start_after:
                session_starts.append(start_after)
if len(heartbeat_starts) != 1 or len(session_starts) != 1 or recordings != 1:
    violations.append("seed request shape: heartbeat=%d session=%d recordings=%d"
                      % (len(heartbeat_starts), len(session_starts), recordings))
else:
    heartbeat_marker = heartbeat_starts[0]
    session_marker = session_starts[0]
    if not ("audit/heartbeat/%s.json" % old_ts < heartbeat_marker
            < "audit/heartbeat/%s.json" % recent_ts):
        violations.append("heartbeat window marker %r does not exclude the old key / include the recent key" % heartbeat_marker)
    # #159: the session seed starts at the window-start DAY prefix (not the
    # `audit/<marker>` timestamp, which sorts above the dated keys of its own
    # day) so both layouts seed.
    if not re.fullmatch(r"audit/[0-9]{8}/", session_marker):
        violations.append("session seed start-after is not a day prefix: %r" % session_marker)
    elif session_marker > "audit/%s" % recent_ts:
        violations.append("session window marker %r sorts after the recent key" % session_marker)
if not any("uploads" in entry.get("note", "") for entry in entries):
    violations.append("seed never listed multipart uploads")
if violations:
    for violation in violations:
        print("VIOLATION " + violation)
    sys.exit(1)
print("seed shape: heartbeat + session windowed, recordings full, uploads full, no versions")
PY
then ok "cold-start seed: windowed audit streams + full recordings/uploads, no versions"; else bad "cold-start seed request shape failed"; fi
is "cold-start seed: the seed seeded the dated cursor from the dated key" \
  "$(dated_key user.login "${SEED_DATED_TS}" "" 9)" "$(state_field observed.cursors.audit_session_dated)"

# The seed wrote the observed block; the next run is an exact full sweep: an
# unfiltered audit listing, versions listed, compact_blind cleared, mode back
# to sweep. (After the delta path lands, an observed sweep-due also forces
# this shape.)
SAVED_REQUEST_LOG="${REQUEST_LOG}"
REQUEST_LOG="${WORK}/requests-postseed.log"
: >"${REQUEST_LOG}"
start_mock
run_case "${seed_state_dir}"
REQUEST_LOG="${SAVED_REQUEST_LOG}"
is "post-seed run: exit 0" "0" "${CASE_RC}"
is "post-seed run: ok verdict" "ok" "${CASE_STATE}"
is "post-seed run: coverage mode is sweep" "sweep" "$(state_field observed.coverage.mode)"
is "post-seed run: compact_blind cleared" "False" "$(state_field observed.coverage.compact_blind)"
if grep -q 'versions prefix=audit/' "${WORK}/requests-postseed.log" \
   && ! grep -q 'list-type=2' "${WORK}/requests-postseed.log"; then
  bad "post-seed sweep shape unexpected"
else
  if python3 - "${WORK}/requests-postseed.log" <<'PY'
import json
import sys
import urllib.parse

entries = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8") if line.strip()]
violations = []
unfiltered = 0
versions = 0
for entry in entries:
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(entry["path"]).query)
    note = entry.get("note", "")
    if "versions" in note:
        versions += 1
    if note.startswith("list-type=2") and not query.get("start-after"):
        unfiltered += 1
if unfiltered < 1:
    violations.append("post-seed sweep has no unfiltered audit listing")
if versions < 2:
    violations.append("post-seed sweep did not list versions for both prefixes (%d)" % versions)
if violations:
    for violation in violations:
        print("VIOLATION " + violation)
    sys.exit(1)
print("post-seed sweep shape: unfiltered objects + versions")
PY
  then ok "post-seed run: exact full sweep (unfiltered listings + versions)"; else bad "post-seed sweep request shape failed"; fi
fi

# A cold-start window with no heartbeat at all must fall back to the exact
# full sweep instead of certifying (or alarming) from an empty window.
empty_seed_dir="${WORK}/state-seed-empty"
fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/${SEED_OLD_TS}.json","ago":100000}],
 "uploads":[]}
JSON
SAVED_REQUEST_LOG="${REQUEST_LOG}"
REQUEST_LOG="${WORK}/requests-seed-empty.log"
: >"${REQUEST_LOG}"
start_mock
RECORDING_WITNESS_COLD_START_SECONDS=3600
run_case "${empty_seed_dir}"
unset RECORDING_WITNESS_COLD_START_SECONDS
REQUEST_LOG="${SAVED_REQUEST_LOG}"
is "empty seed window: falls back to a sweep (mode=sweep)" "sweep" "$(state_field observed.coverage.mode)"
case "${CASE_DETAIL}" in
  *cold-start*) bad "empty seed window still reported a seed disclosure: ${CASE_DETAIL}" ;;
  *heartbeat-stale*) ok "empty seed window fallback swept the old heartbeat into a stale alert" ;;
  *) bad "empty seed window fallback detail unexpected: ${CASE_DETAIL}" ;;
esac

# A failed cold start leaves a version-3 error record with no observed block
# (the failing run could not list, so none was ever built). The next run must
# treat that as a cold start again - never dereference the missing block - or
# one transient failure wedges the witness forever (AttributeError before
# state/verdict). This is the exact two-run repro: fresh state dir + failing
# first run, then a healthy second run that must re-seed (a windowed seed can
# never report ok, so a green second run would be the blind-recovery bug).
failed_seed_dir="${WORK}/state-seed-failed"
fixture <<JSON
{"bucket":"pc-admin-dr",
 "signature":{"key_id":"test-key-id-0001","key":"a-different-secret","region":"test-region"},
 "objects":[
  {"key":"audit/heartbeat/${SEED_HEARTBEAT_TS}.json","ago":45}],
 "uploads":[]}
JSON
start_mock
RECORDING_WITNESS_COLD_START_SECONDS=3600 run_delta "${failed_seed_dir}"
unset RECORDING_WITNESS_COLD_START_SECONDS
is "failed cold start: exit 2 (error, no observed)" "2" "${CASE_RC}"
is "failed cold start: error verdict" "error" "${CASE_STATE}"
if python3 - "${failed_seed_dir}/state.json" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
raise SystemExit(0 if data.get("version") == 3 and "observed" not in data else 1)
PY
then ok "failed cold start: the record is version 3 with no observed block"; else bad "failed cold start record shape unexpected"; fi
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":2,
 "objects":[
  {"key":"audit/heartbeat/${SEED_OLD_TS}.json","ago":100000},
  {"key":"audit/heartbeat/${SEED_HEARTBEAT_TS}.json","ago":45},
  {"key":"audit/${SEED_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
RECORDING_WITNESS_COLD_START_SECONDS=3600 run_delta "${failed_seed_dir}"
unset RECORDING_WITNESS_COLD_START_SECONDS
if [ "${CASE_RC}" = "1" ] && ! grep -q "Traceback" "${WORK}/witness.err"; then
  ok "failed cold start: the retry does not crash (exit 1, no Traceback)"
else
  bad "failed cold start: the retry does not crash (exit 1, no Traceback) (rc='${CASE_RC}')"
fi
is "failed cold start: the retry re-seeds (alert, never green)" "alert" "${CASE_STATE}"
is "failed cold start: the retry wrote a seed block" "seed" "$(state_field observed.coverage.mode)"
case "${CASE_DETAIL}" in
  *cold-start*) ok "failed cold start: the retry carries the cold-start disclosure" ;;
  *) bad "failed cold start retry detail: ${CASE_DETAIL}" ;;
esac

# A bad config value must write the old error record, not crash before the
# verdict with an UnboundLocalError (payload was only bound inside the
# run_checks branch).
bad_cfg_dir="${WORK}/state-bad-config"
RECORDING_WITNESS_EXTRA_ENV='RECORDING_WITNESS_HEARTBEAT_MAX_AGE_SECONDS=abc' run_case "${bad_cfg_dir}"
is "bad config env: exit 2 (error record, no crash)" "2" "${CASE_RC}"
is "bad config env: error verdict" "error" "${CASE_STATE}"
case "${CASE_DETAIL}" in
  *HEARTBEAT_MAX_AGE_SECONDS*|*"must be an integer"*) ok "bad config env: detail names the config error" ;;
  *) bad "bad config env detail: ${CASE_DETAIL}" ;;
esac
if [ -f "${bad_cfg_dir}/state.json" ] && [ -f "${bad_cfg_dir}/verdict.log" ]; then
  ok "bad config env: state and verdict written (old behaviour)"
else
  bad "bad config env: state/verdict missing"
fi

# A stale/foreign observed block (written by a different run identity) is not
# a trustworthy view: the run repairs it with an exact sweep, reports error
# (never green), and rebuilds the block under this run's identity.
stale_observed_dir="${WORK}/state-observed-stale"
fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"audit/20260925T135000Z-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_case "${stale_observed_dir}"
is "stale observed: the warm-up run is green" "ok" "${CASE_STATE}"
python3 - "${stale_observed_dir}/state.json" <<'PY'
import json
import sys

with open(sys.argv[1]) as handle:
    data = json.load(handle)
data["observed"]["written_run_seq"] = 99999
with open(sys.argv[1], "w") as handle:
    json.dump(data, handle)
PY
SAVED_REQUEST_LOG="${REQUEST_LOG}"
REQUEST_LOG="${WORK}/requests-stale-observed.log"
: >"${REQUEST_LOG}"
start_mock
run_delta "${stale_observed_dir}"
REQUEST_LOG="${SAVED_REQUEST_LOG}"
is "stale observed: exit 2 (repair, never green)" "2" "${CASE_RC}"
is "stale observed: error verdict" "error" "${CASE_STATE}"
case "${CASE_DETAIL}" in
  *"observed.written_run_seq"*) ok "stale observed: detail names the foreign run identity" ;;
  *) bad "stale observed: detail unexpected: ${CASE_DETAIL}" ;;
esac
is "stale observed: the record is marked repaired" "True" "$(state_field repaired)"
record_run_seq="$(state_field run_seq)"
observed_run_seq="$(state_field observed.written_run_seq)"
is "stale observed: the rebuilt block carries this run's identity" "${record_run_seq}" "${observed_run_seq}"
if python3 - "${WORK}/requests-stale-observed.log" <<'PY'
import json
import sys
import urllib.parse

entries = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8") if line.strip()]
unfiltered = 0
for entry in entries:
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(entry["path"]).query)
    if entry.get("note", "").startswith("list-type=2") and not query.get("start-after"):
        unfiltered += 1
if unfiltered < 1:
    raise SystemExit("repair run did not perform an unfiltered audit listing")
print("repair run swept unfiltered")
PY
then ok "stale observed: the repair run performed a full unfiltered sweep"; else bad "stale observed repair sweep shape failed"; fi

# ---- (f4) delta cursors + merged sweeps (issue #153) ---------------------
# A warm sweep writes the three high-water cursors plus the view sidecar; a
# quiet delta then lists only the cursors' tails plus the full multipart
# family, never versions (sweep-only) and never an unfiltered object page.
# The verdict/detail/signature must be identical to the sweep: the merge is
# exact, only the listing surface shrinks.
DELTA_HEARTBEAT_TS="$(audit_stamp -60)"
DELTA_START_TS="$(audit_stamp -300)"
DELTA_DATA_TS="$(audit_stamp -299)"
DELTA_END_TS="$(audit_stamp -298)"
delta_dir="${WORK}/state-delta"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"audit/${DELTA_DATA_TS}-session.data.${SID}.1.json","ago":299},
  {"key":"audit/${DELTA_END_TS}-session.end.${SID}.2.json","ago":298},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_delta "${delta_dir}"
is "delta: the warm sweep is green" "ok" "${CASE_STATE}"
warm_detail="${CASE_DETAIL}"
warm_signature="$(state_field signature)"
is "delta: the warm sweep wrote the heartbeat cursor" \
  "audit/heartbeat/${DELTA_HEARTBEAT_TS}.json" "$(state_field observed.cursors.audit_heartbeat)"
is "delta: the warm sweep wrote the session cursor" \
  "audit/${DELTA_END_TS}-session.end.${SID}.2.json" "$(state_field observed.cursors.audit_session)"
is "delta: the warm sweep wrote the recordings cursor" \
  "recordings/${SID}.tar" "$(state_field observed.cursors.recordings)"
SAVED_REQUEST_LOG="${REQUEST_LOG}"
REQUEST_LOG="${WORK}/requests-delta-quiet.log"
: >"${REQUEST_LOG}"
start_mock
run_delta "${delta_dir}"
is "quiet delta: exit 0" "0" "${CASE_RC}"
is "quiet delta: ok verdict" "ok" "${CASE_STATE}"
is "quiet delta: coverage mode is delta" "delta" "$(state_field observed.coverage.mode)"
is "quiet delta: compact_blind stays clear" "False" "$(state_field observed.coverage.compact_blind)"
# The displayed heartbeat age can tick across a whole second between two
# runs (the bucket timestamps are second-resolution); the finding set is the
# stable identity, so normalize only the age fragment before comparing.
warm_detail_norm="$(norm_detail "${warm_detail}")"
is "quiet delta: detail identical to the sweep (age normalized)" "${warm_detail_norm}" "$(norm_detail "${CASE_DETAIL}")"
is "quiet delta: finding signature identical to the sweep" "${warm_signature}" "$(state_field signature)"
if python3 - "${WORK}/requests-delta-quiet.log" <<'PY'
import json
import re
import sys
import urllib.parse

entries = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8") if line.strip()]
violations = []
objects = 0
uploads = 0
versions = 0
day_probes = 0
for entry in entries:
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(entry["path"]).query)
    note = entry.get("note", "")
    if "versions" in note:
        versions += 1
        violations.append("quiet delta listed versions")
    elif note.startswith("list-type=2"):
        objects += 1
        if not query.get("start-after"):
            violations.append("quiet delta object listing without start-after: %s" % entry["path"])
        prefix = query.get("prefix", [""])[0]
        if re.fullmatch(r"audit/[0-9]{8}/", prefix):
            day_probes += 1
    elif "uploads" in note:
        uploads += 1
    else:
        violations.append("quiet delta made an unexpected request: %s" % note)
# The unseeded transition probe adds exactly one dated-day listing while the
# dated cursor is empty (the flat-only fixture here); the heartbeat, flat
# discovery and recordings tails stay.
if len(entries) != 5 or objects != 4 or uploads != 1 or versions != 0 or day_probes != 1:
    violations.append("quiet delta call shape: entries=%d objects=%d uploads=%d versions=%d day_probes=%d"
                      % (len(entries), objects, uploads, versions, day_probes))
if violations:
    for violation in violations:
        print("VIOLATION " + violation)
    sys.exit(1)
print("quiet delta shape: 3 cursored object tails + the transition probe + 1 full uploads, no versions")
PY
then ok "quiet delta: three cursored tails + transition probe + full uploads, no versions, no unfiltered pages"; else bad "quiet delta request shape failed"; fi
cat "${WORK}/requests-delta-quiet.log" >>"${SAVED_REQUEST_LOG}"
REQUEST_LOG="${SAVED_REQUEST_LOG}"

# A replayed old-<ts> key sorts below the session cursor: the delta never
# lists it (the request carries a start-after above it), so the fast verdict
# is unchanged; the forced sweep sees both identities and alerts.
REPLAY_TS="$(audit_stamp -100000)"
REPLAY_KEY="audit/${REPLAY_TS}-session.start.${SID}.0.json"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"${REPLAY_KEY}","ago":400},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"audit/${DELTA_DATA_TS}-session.data.${SID}.1.json","ago":299},
  {"key":"audit/${DELTA_END_TS}-session.end.${SID}.2.json","ago":298},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
SAVED_REQUEST_LOG="${REQUEST_LOG}"
REQUEST_LOG="${WORK}/requests-delta-replay.log"
: >"${REQUEST_LOG}"
start_mock
run_delta "${delta_dir}"
is "below-cursor replay: the fast delta is unchanged and green" "ok" "${CASE_STATE}"
is "below-cursor replay: detail identical to the delta (age normalized)" "${warm_detail_norm}" "$(norm_detail "${CASE_DETAIL}")"
if python3 - "${WORK}/requests-delta-replay.log" "${REPLAY_KEY}" <<'PY'
import json
import sys
import urllib.parse

entries = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8") if line.strip()]
replay_key = sys.argv[2]
bad = False
for entry in entries:
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(entry["path"]).query)
    if entry.get("note", "").startswith("list-type=2") and query.get("prefix", [""])[0] == "audit/":
        marker = query.get("start-after", [""])[0]
        if marker and replay_key > marker:
            print("VIOLATION the audit delta marker %r is below the replay key" % marker)
            bad = True
if bad:
    sys.exit(1)
print("audit delta marker excludes the below-cursor replay key")
PY
then ok "below-cursor replay: the fast delta's session marker excludes it"; else bad "below-cursor replay request shape failed"; fi
cat "${WORK}/requests-delta-replay.log" >>"${SAVED_REQUEST_LOG}"
REQUEST_LOG="${SAVED_REQUEST_LOG}"
replay_cursor="$(state_field observed.cursors.audit_session)"
force_sweep_state "${delta_dir}" keep-cursors
is "below-cursor replay: the forced sweep keeps the persisted cursors" \
  "${replay_cursor}" "$(state_field observed.cursors.audit_session)"
start_mock
run_delta "${delta_dir}"
is "below-cursor replay: the forced sweep catches the duplicate" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in
  *sequence-duplicate*) ok "below-cursor replay: sweep detail names sequence-duplicate" ;;
  *) bad "below-cursor replay sweep detail: ${CASE_DETAIL}" ;;
esac

# A delete marker for an already-listed key is invisible to deltas by design:
# the retained hidden set is carried unchanged until the sweep-only versions
# listing reconciles it. The sweep interval is the hiding-detection bound.
BOUND_TS="${DELTA_START_TS}"
bound_dir="${WORK}/state-bound"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${BOUND_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297}],
 "versions":[{"key":"audit/${BOUND_TS}-session.start.${SID}.0.json","version_id":"v1","delete_marker":false,"ago":300}],
 "uploads":[]}
JSON
start_mock
run_delta "${bound_dir}"
is "delete-marker bound: the warm sweep is green" "ok" "${CASE_STATE}"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${BOUND_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297}],
 "versions":[{"key":"audit/${BOUND_TS}-session.start.${SID}.0.json","version_id":"v1","delete_marker":true,"ago":120}],
 "uploads":[]}
JSON
SAVED_REQUEST_LOG="${REQUEST_LOG}"
REQUEST_LOG="${WORK}/requests-delta-bound.log"
: >"${REQUEST_LOG}"
start_mock
run_delta "${bound_dir}"
is "delete-marker bound: the delta does not see the old-key marker" "ok" "${CASE_STATE}"
if grep -q 'versions' "${WORK}/requests-delta-bound.log"; then
  bad "delete-marker bound: the delta listed versions"
else
  ok "delete-marker bound: the delta made no versions call"
fi
cat "${WORK}/requests-delta-bound.log" >>"${SAVED_REQUEST_LOG}"
REQUEST_LOG="${SAVED_REQUEST_LOG}"
force_sweep_state "${bound_dir}"
start_mock
run_delta "${bound_dir}"
is "delete-marker bound: the forced sweep alerts hidden-object" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in
  *hidden-object*) ok "delete-marker bound: sweep detail names hidden-object" ;;
  *) bad "delete-marker bound sweep detail: ${CASE_DETAIL}" ;;
esac

# Cursor loss and a foreign view are not trustworthy: both take the
# preserve+repair+full-sweep path and report error (never green).
loss_dir="${WORK}/state-loss"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_delta "${loss_dir}"
is "cursor loss: the warm sweep is green" "ok" "${CASE_STATE}"
python3 - "${loss_dir}/state.json" <<'PY'
import json
import sys

with open(sys.argv[1]) as handle:
    data = json.load(handle)
del data["observed"]
with open(sys.argv[1], "w") as handle:
    json.dump(data, handle)
PY
start_mock
run_delta "${loss_dir}"
is "cursor loss: exit 2 (repair, never green)" "2" "${CASE_RC}"
is "cursor loss: error verdict" "error" "${CASE_STATE}"
case "${CASE_DETAIL}" in
  *"observed block is missing"*) ok "cursor loss: detail names the missing observed block" ;;
  *) bad "cursor loss detail: ${CASE_DETAIL}" ;;
esac
is "cursor loss: the record is marked repaired" "True" "$(state_field repaired)"
run_delta "${loss_dir}"
is "cursor loss: the rebuilt block serves the next delta green" "ok" "${CASE_STATE}"
is "cursor loss: the rebuilt block is a delta" "delta" "$(state_field observed.coverage.mode)"

view_dir="${WORK}/state-badview"
start_mock
run_delta "${view_dir}"
is "bad view: the warm sweep is green" "ok" "${CASE_STATE}"
python3 - "${view_dir}/view.json" <<'PY'
import json
import sys

with open(sys.argv[1]) as handle:
    data = json.load(handle)
data["generation"] = int(data.get("generation", 0)) + 1000
with open(sys.argv[1], "w") as handle:
    json.dump(data, handle)
PY
start_mock
run_delta "${view_dir}"
is "bad view: exit 2 (repair, never green)" "2" "${CASE_RC}"
is "bad view: error verdict" "error" "${CASE_STATE}"
case "${CASE_DETAIL}" in
  *"view.generation"*) ok "bad view: detail names the sidecar generation mismatch" ;;
  *) bad "bad view detail: ${CASE_DETAIL}" ;;
esac
is "bad view: the record is marked repaired" "True" "$(state_field repaired)"
python3 - "${view_dir}/state.json" <<'PY'
import json
import sys

with open(sys.argv[1]) as handle:
    data = json.load(handle)
data["observed"]["cursors"]["audit_session"] = "recordings/not-a-session"
with open(sys.argv[1], "w") as handle:
    json.dump(data, handle)
PY
start_mock
run_delta "${view_dir}"
is "foreign cursor: exit 2 (repair, never green)" "2" "${CASE_RC}"
case "${CASE_DETAIL}" in
  *"cursors.audit_session"*) ok "foreign cursor: detail names the out-of-prefix cursor" ;;
  *) bad "foreign cursor detail: ${CASE_DETAIL}" ;;
esac

# A pre-v3 record carries no observed block by construction (the schema
# predates cursors). It is a live-box migration, not a cold start: the first
# run must take the fail-closed repair + full sweep (error, repaired), rebuild
# the block, and the next run serves a fast delta. A failing repair sweep must
# then fall back to the cold-start path, never wedge (finding 1).
v2_dir="${WORK}/state-v2-migration"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_delta "${v2_dir}"
is "v2 migration: the warm sweep is green" "ok" "${CASE_STATE}"
python3 - "${v2_dir}/state.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    data = json.load(handle)
data["version"] = 2
data.pop("observed", None)
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(data, handle)
PY
SAVED_REQUEST_LOG="${REQUEST_LOG}"
REQUEST_LOG="${WORK}/requests-v2-migration.log"
: >"${REQUEST_LOG}"
start_mock
run_delta "${v2_dir}"
REQUEST_LOG="${SAVED_REQUEST_LOG}"
is "v2 migration: exit 2 (repair, never a silent seed)" "2" "${CASE_RC}"
is "v2 migration: error verdict" "error" "${CASE_STATE}"
case "${CASE_DETAIL}" in
  *"version 2"*) ok "v2 migration: detail names the legacy record" ;;
  *) bad "v2 migration detail: ${CASE_DETAIL}" ;;
esac
is "v2 migration: the record is marked repaired" "True" "$(state_field repaired)"
is "v2 migration: the rebuilt record is version 3" "3" "$(state_field version)"
is "v2 migration: the rebuilt block is a sweep" "sweep" "$(state_field observed.coverage.mode)"
if grep -q 'versions' "${WORK}/requests-v2-migration.log"; then
  ok "v2 migration: the repair really swept (versions listed)"
else
  bad "v2 migration: the repair did not list versions"
fi
run_delta "${v2_dir}"
is "v2 migration: the rebuilt block serves the next delta green" "ok" "${CASE_STATE}"
is "v2 migration: the next run is a delta" "delta" "$(state_field observed.coverage.mode)"

# The same migration with a failing repair sweep must not wedge: the error
# record has no observed block, so the next healthy run cold-starts (seed) and
# recovers instead of dereferencing the missing block.
python3 - "${v2_dir}/state.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    data = json.load(handle)
data["version"] = 2
data.pop("observed", None)
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(data, handle)
PY
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,"fail_versions":"denied",
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_delta "${v2_dir}"
is "v2 migration: the failing repair sweep exits 2" "2" "${CASE_RC}"
is "v2 migration: the failing repair sweep is error" "error" "${CASE_STATE}"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
RECORDING_WITNESS_COLD_START_SECONDS=3600 run_delta "${v2_dir}"
unset RECORDING_WITNESS_COLD_START_SECONDS
is "v2 migration: the recovery run cold-starts (alert seed)" "alert" "${CASE_STATE}"
is "v2 migration: the recovery seed wrote a block" "seed" "$(state_field observed.coverage.mode)"

# R2: the session cursor must not sit under the heartbeat prefix. A forged
# (generation-matched) state with audit_session = a heartbeat key passes the
# generic prefix check, but then the session delta lists an empty tail and a
# new session.start with no tar stays invisible (false green). It must be
# rejected as corrupt observed state -> repair + sweep, never green.
forged_dir="${WORK}/state-forged-session-cursor"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_delta "${forged_dir}"
is "forged session cursor: the warm sweep is green" "ok" "${CASE_STATE}"
forged_heartbeat="$(state_field observed.cursors.audit_heartbeat)"
python3 - "${forged_dir}/state.json" "${forged_heartbeat}" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    data = json.load(handle)
data["observed"]["cursors"]["audit_session"] = sys.argv[2]
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(data, handle)
PY
R2_START_TS="$(audit_stamp -5)"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"audit/${R2_START_TS}-session.start.1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5e.0.json","ago":1200},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_delta "${forged_dir}"
is "forged session cursor: exit 2 (repair, never a green empty tail)" "2" "${CASE_RC}"
is "forged session cursor: error verdict" "error" "${CASE_STATE}"
case "${CASE_DETAIL}" in
  *"heartbeat prefix"*) ok "forged session cursor: detail names the heartbeat-prefix violation" ;;
  *) bad "forged session cursor detail: ${CASE_DETAIL}" ;;
esac
is "forged session cursor: the record is marked repaired" "True" "$(state_field repaired)"

# RF1: the heartbeat boundary is the stem, not the trailing-slash prefix. The
# old guard rejected only `audit/heartbeat/...`, so `audit_session` equal to
# the exact stem or to any key after it (`audit/i`, `audit/zzz`) - all sort
# above every real session key (which start with a digit) - passed as a
# trustworthy cursor: the session delta listed an empty tail and a fresh
# session.start with no tar was never gap-checked while the run stayed green.
# Every forged value must take the repair + sweep + error path.
stem_cursor_dir="${WORK}/state-stem-cursor"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_delta "${stem_cursor_dir}"
is "stem session cursor: the warm sweep is green" "ok" "${CASE_STATE}"
for forged_cursor in "audit/heartbeat" "audit/i" "audit/zzz"; do
  python3 - "${stem_cursor_dir}/state.json" "${forged_cursor}" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    data = json.load(handle)
data["observed"]["cursors"]["audit_session"] = sys.argv[2]
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(data, handle)
PY
  run_delta "${stem_cursor_dir}"
  is "stem session cursor (${forged_cursor}): exit 2 (repair, never a green tail)" "2" "${CASE_RC}"
  is "stem session cursor (${forged_cursor}): error verdict" "error" "${CASE_STATE}"
  is "stem session cursor (${forged_cursor}): the record is marked repaired" "True" "$(state_field repaired)"
done

# An exact `audit/heartbeat` object is malformed drift, not a session key: it
# sorts above every real session key, so a listing that let it become the
# session cursor would blind the next delta (and the run after that would
# repair). The sweep must still see it (contract drift), while neither the
# sweep cursor computation nor the delta's max() may let it advance the
# session cursor.
stem_object_dir="${WORK}/state-heartbeat-stem-object"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat","ago":60},
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_delta "${stem_object_dir}"
is "heartbeat stem object: the sweep keeps the session cursor below the stem" \
  "audit/${DELTA_START_TS}-session.start.${SID}.0.json" "$(state_field observed.cursors.audit_session)"
is "heartbeat stem object: the sweep keeps the heartbeat cursor a real heartbeat key" \
  "audit/heartbeat/${DELTA_HEARTBEAT_TS}.json" "$(state_field observed.cursors.audit_heartbeat)"
case "${CASE_DETAIL}" in
  *contract*) ok "heartbeat stem object: the malformed key is still flagged as drift" ;;
  *) bad "heartbeat stem object detail: ${CASE_DETAIL}" ;;
esac
run_delta "${stem_object_dir}"
is "heartbeat stem object: the delta does not advance the session cursor to the stem" \
  "audit/${DELTA_START_TS}-session.start.${SID}.0.json" "$(state_field observed.cursors.audit_session)"
is "heartbeat stem object: the next run stays a delta" "delta" "$(state_field observed.coverage.mode)"

# F3.1: the stem bound alone is still boundary-anchored: a forged session
# cursor below the stem but above the whole real session key space (`audit/9`,
# `audit/g`, `audit/heartbea`, `audit/2027`, an acceptance probe) passed the
# generic `audit/` prefix check, and the session delta then listed an empty
# tail while a fresh `session.start` sat below it - green while a real
# recording gap was hidden. The cursor must match the witness's own key
# grammar; every forged value takes the repair + sweep + error path.
shape_cursor_dir="${WORK}/state-shape-cursor"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_delta "${shape_cursor_dir}"
is "shape session cursor: the warm sweep is green" "ok" "${CASE_STATE}"
SHAPE_TS="$(audit_stamp -5)"
for forged_cursor in "audit/9" "audit/9999" "audit/g" "audit/heartbea" "audit/2027" \
                     "audit/a2-check-probe-heartbeat.json"; do
  python3 - "${shape_cursor_dir}/state.json" "${forged_cursor}" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    data = json.load(handle)
data["observed"]["cursors"]["audit_session"] = sys.argv[2]
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(data, handle)
PY
  fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"audit/${SHAPE_TS}-session.start.1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5e.0.json","ago":1200},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
  start_mock
  run_delta "${shape_cursor_dir}"
  is "shape session cursor (${forged_cursor}): exit 2 (repair, never a green tail)" "2" "${CASE_RC}"
  is "shape session cursor (${forged_cursor}): error verdict" "error" "${CASE_STATE}"
  is "shape session cursor (${forged_cursor}): the record is marked repaired" "True" "$(state_field repaired)"
done

# The same shape guard covers the heartbeat and recordings families: a cursor
# that is under its prefix but matches no family shape (`audit/heartbeat/9`,
# `recordings/a2-check-...`) would blind that delta's tail exactly the same
# way - and a heartbeat cursor above every heartbeat key misses the freshness
# signal for up to a sweep. Fail closed.
for forged_pair in "audit_heartbeat|audit/heartbeat/9" \
                   "recordings|recordings/a2-check-probe-heartbeat.json"; do
  forged_family="${forged_pair%%|*}"
  forged_value="${forged_pair#*|}"
  python3 - "${shape_cursor_dir}/state.json" "${forged_family}" "${forged_value}" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    data = json.load(handle)
data["observed"]["cursors"][sys.argv[2]] = sys.argv[3]
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(data, handle)
PY
  start_mock
  run_delta "${shape_cursor_dir}"
  is "shape ${forged_family} cursor: exit 2 (repair, never a green tail)" "2" "${CASE_RC}"
  is "shape ${forged_family} cursor: error verdict" "error" "${CASE_STATE}"
  is "shape ${forged_family} cursor: the record is marked repaired" "True" "$(state_field repaired)"
  case "${CASE_DETAIL}" in
    *"key grammar"*) ok "shape ${forged_family} cursor: detail names the key-grammar violation" ;;
    *) bad "shape ${forged_family} cursor detail: ${CASE_DETAIL}" ;;
  esac
done

# Live-shape regression (orchestrator, list-only on the real bucket): the live
# `audit/` bucket carries unshaped acceptance probes between the real session
# keys and the heartbeat stem (16 x `audit/a2-check-<date>-<hex>.positive` plus
# `audit/a2-check-probe-heartbeat.json`). `max()` over the listing used to put
# the session cursor on the highest probe, so the 5-minute delta listed an
# empty tail (blind) until the next 6 h sweep - green while real sessions
# shipped. The cursor must stay on the last SHAPED key; the probe stays a
# finding and never moves it, and the following deltas still see new sessions.
live_probe_dir="${WORK}/state-live-probe"
LIVE_SID3="5c5c5c5c-5c5c-4c5c-8c5c-5c5c5c5c5c5c"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297},
  {"key":"audit/a2-check-probe-heartbeat.json","ago":60}],
 "uploads":[]}
JSON
start_mock
run_delta "${live_probe_dir}"
is "live probe: the sweep keeps the session cursor on the last shaped key" \
  "audit/${DELTA_START_TS}-session.start.${SID}.0.json" "$(state_field observed.cursors.audit_session)"
case "${CASE_DETAIL}" in
  *contract-mismatch*) ok "live probe: the unshaped object is still flagged as drift" ;;
  *) bad "live probe detail: ${CASE_DETAIL}" ;;
esac
LIVE_SID2_TS="$(audit_stamp -10)"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297},
  {"key":"audit/a2-check-probe-heartbeat.json","ago":60},
  {"key":"audit/${LIVE_SID2_TS}-session.start.${SID2}.0.json","ago":1200}],
 "uploads":[]}
JSON
start_mock
run_delta "${live_probe_dir}"
is "live probe: the next delta sees the new shaped session (no blind tail)" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in
  *"${SID2}"*) ok "live probe: the new session is gap-checked (recording-gap names it)" ;;
  *) bad "live probe detail: ${CASE_DETAIL}" ;;
esac
is "live probe: the delta keeps the cursor on the new shaped key" \
  "audit/${LIVE_SID2_TS}-session.start.${SID2}.0.json" "$(state_field observed.cursors.audit_session)"
is "live probe: the delta does not repair" "" "$(state_field repaired)"
is "live probe: the run stays a delta (the probe is not a repair loop)" "delta" "$(state_field observed.coverage.mode)"
LIVE_SID3_TS="$(audit_stamp -2)"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297},
  {"key":"audit/a2-check-probe-heartbeat.json","ago":60},
  {"key":"audit/${LIVE_SID2_TS}-session.start.${SID2}.0.json","ago":1200},
  {"key":"audit/${LIVE_SID3_TS}-session.start.${LIVE_SID3}.0.json","ago":1200}],
 "uploads":[]}
JSON
start_mock
run_delta "${live_probe_dir}"
case "${CASE_DETAIL}" in
  *"${LIVE_SID3}"*) ok "live probe: the following delta still sees a new session (the cursor never sat on the probe)" ;;
  *) bad "live probe second-delta detail: ${CASE_DETAIL}" ;;
esac

# The same live-shape guard for the recordings family: an unshaped probe above
# the shaped tar id space must not become the recordings cursor, or the next
# delta's tar tail is blind (a new completed tar - orphan or not - invisible
# until the sweep). The cursor stays on the highest SHAPED tar.
live_rec_dir="${WORK}/state-live-rec-probe"
LIVE_TAR_LOW="00000000-0000-4000-8000-000000000000.tar"
LIVE_TAR_NEW="11111111-1111-4111-8111-111111111111.tar"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"recordings/${LIVE_TAR_LOW}","ago":297},
  {"key":"recordings/a2-check-probe-heartbeat.json","ago":60}],
 "uploads":[]}
JSON
start_mock
run_delta "${live_rec_dir}"
is "live recordings probe: the sweep keeps the recordings cursor on the last shaped tar" \
  "recordings/${LIVE_TAR_LOW}" "$(state_field observed.cursors.recordings)"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"recordings/${LIVE_TAR_LOW}","ago":297},
  {"key":"recordings/a2-check-probe-heartbeat.json","ago":60},
  {"key":"recordings/${LIVE_TAR_NEW}","ago":1200}],
 "uploads":[]}
JSON
start_mock
run_delta "${live_rec_dir}"
is "live recordings probe: the delta sees the new shaped tar (no blind tail)" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in
  *session-start-missing*) ok "live recordings probe: the new orphan tar is checked (session-start-missing)" ;;
  *) bad "live recordings probe detail: ${CASE_DETAIL}" ;;
esac
is "live recordings probe: the delta keeps the cursor on the new shaped tar" \
  "recordings/${LIVE_TAR_NEW}" "$(state_field observed.cursors.recordings)"

# RF3.1: the family regexes are `\Z`-anchored (Python's `$` also matches
# before a trailing newline). A bucket key ending `json\n`/`tar\n` used to
# pass both the shape predicates and the classifier's own regexes: the sweep
# cursor moved onto it (it sorts above every real key), the classifier read
# it as a shipped session/heartbeat/recording key, and the next delta listed
# an empty tail while a real recording gap sat below the cursor - green.
# Such a key must be drift that never moves a cursor; the shaped keys beside
# it keep the cursors and the delta still sees a hidden session's gap.
newline_dir="${WORK}/state-trailing-newline"
NL_TS="$(audit_stamp -20)"
NL_HIDDEN_TS="$(audit_stamp -60)"
NL_SID="7b7b7b7b-7b7b-4b7b-8b7b-7b7b7b7b7b7b"
NL_HIDDEN_SID="1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5e"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json\n","ago":59},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"audit/${NL_TS}-session.start.${NL_SID}.0.json\n","ago":20},
  {"key":"audit/${NL_TS}-user.login.1.json\n","ago":19},
  {"key":"recordings/${SID}.tar","ago":297},
  {"key":"recordings/${NL_SID}.tar\n","ago":18}],
 "uploads":[]}
JSON
start_mock
run_delta "${newline_dir}"
is "trailing-newline keys: the sweep keeps the session cursor on the shaped key" \
  "audit/${DELTA_START_TS}-session.start.${SID}.0.json" "$(state_field observed.cursors.audit_session)"
is "trailing-newline keys: the sweep keeps the heartbeat cursor on the shaped key" \
  "audit/heartbeat/${DELTA_HEARTBEAT_TS}.json" "$(state_field observed.cursors.audit_heartbeat)"
is "trailing-newline keys: the sweep keeps the recordings cursor on the shaped tar" \
  "recordings/${SID}.tar" "$(state_field observed.cursors.recordings)"
case "${CASE_DETAIL}" in
  *naming-contract*) ok "trailing-newline session key: the drift is flagged (naming-contract)" ;;
  *) bad "trailing-newline session key detail: ${CASE_DETAIL}" ;;
esac
case "${CASE_DETAIL}" in
  *contract-mismatch*) ok "trailing-newline non-session/heartbeat keys: the drift is flagged (contract-mismatch)" ;;
  *) bad "trailing-newline non-session detail: ${CASE_DETAIL}" ;;
esac
# The delta must still see a new shaped session: with the cursor poisoned onto
# `...json\n` (the pre-\Z bug) the tail is empty and the hidden gap stays ok.
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json\n","ago":59},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"audit/${NL_TS}-session.start.${NL_SID}.0.json\n","ago":20},
  {"key":"audit/${NL_TS}-user.login.1.json\n","ago":19},
  {"key":"audit/${NL_HIDDEN_TS}-session.start.${NL_HIDDEN_SID}.0.json","ago":1200},
  {"key":"recordings/${SID}.tar","ago":297},
  {"key":"recordings/${NL_SID}.tar\n","ago":18}],
 "uploads":[]}
JSON
start_mock
run_delta "${newline_dir}"
is "trailing-newline keys: the next delta sees the new shaped session (no blind tail)" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in
  *"${NL_HIDDEN_SID}"*) ok "trailing-newline keys: the hidden session is gap-checked (recording-gap names it)" ;;
  *) bad "trailing-newline keys second-delta detail: ${CASE_DETAIL}" ;;
esac

# Forged state with a trailing-newline cursor: the load guard must reject it
# (repair + sweep + error), never trust it as a shaped cursor; the shaped
# control is green.
newline_forge_dir="${WORK}/state-newline-forge"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_delta "${newline_forge_dir}"
is "newline cursor guard: the shaped warm sweep is green (control)" "ok" "${CASE_STATE}"
NL_FORGE_SESSION="audit/${DELTA_START_TS}-session.start.${SID}.0.json"$'\n'
NL_FORGE_NONSESSION="audit/${DELTA_START_TS}-user.login.1.json"$'\n'
NL_FORGE_HEARTBEAT="audit/heartbeat/${DELTA_HEARTBEAT_TS}.json"$'\n'
NL_FORGE_RECORDING="recordings/${SID}.tar"$'\n'
NL_FORGE_HIDDEN="audit/20200101T000000Z-session.start.${NL_HIDDEN_SID}.0.json"
for forged_pair in "session|audit_session|${NL_FORGE_SESSION}" \
                   "non-session|audit_session|${NL_FORGE_NONSESSION}" \
                   "heartbeat|audit_heartbeat|${NL_FORGE_HEARTBEAT}" \
                   "recordings|recordings|${NL_FORGE_RECORDING}"; do
  forged_kind="${forged_pair%%|*}"
  forged_rest="${forged_pair#*|}"
  forged_family="${forged_rest%%|*}"
  forged_value="${forged_rest#*|}"
  python3 - "${newline_forge_dir}/state.json" "${forged_family}" "${forged_value}" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    data = json.load(handle)
data["observed"]["cursors"][sys.argv[2]] = sys.argv[3]
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(data, handle)
PY
  fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"${NL_FORGE_HIDDEN}","ago":1200},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
  start_mock
  run_delta "${newline_forge_dir}"
  is "newline cursor (${forged_kind}, ${forged_family}): exit 2 (repair, never a green tail)" "2" "${CASE_RC}"
  is "newline cursor (${forged_kind}, ${forged_family}): error verdict" "error" "${CASE_STATE}"
  is "newline cursor (${forged_kind}, ${forged_family}): the record is marked repaired" "True" "$(state_field repaired)"
  case "${CASE_DETAIL}" in
    *"key grammar"*) ok "newline cursor (${forged_kind}, ${forged_family}): detail names the key-grammar violation" ;;
    *) bad "newline cursor (${forged_kind}, ${forged_family}) detail: ${CASE_DETAIL}" ;;
  esac
done

# TF3.1: `is_audit_session_key` must also mirror the classifier's drift rule.
# A NON_SESSION-shaped `session.*` key with no sid is naming-contract drift,
# not a documented non-session event; the predicate used to accept ANY
# NON_SESSION match, so a drift key (sorting above the real key space) could
# move the cursor and, forged into state, blind the delta green.
# Past-dated on purpose: a future-dated drift key would be rejected by the
# round-5 future-<ts> filter before the classifier mirror runs, masking the
# drift tooth (round-5 RT5.2). Keep it non-future so the mirror is the only
# defense.
drift_key="audit/$(audit_stamp -10)-session.start.0.json"
drift_dir="${WORK}/state-drift-cursor"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297},
  {"key":"${drift_key}","ago":60}],
 "uploads":[]}
JSON
start_mock
run_delta "${drift_dir}"
is "drift session key: the sweep keeps the session cursor on the shaped key" \
  "audit/${DELTA_START_TS}-session.start.${SID}.0.json" "$(state_field observed.cursors.audit_session)"
case "${CASE_DETAIL}" in
  *naming-contract*) ok "drift session key: the classifier still flags it (naming-contract)" ;;
  *) bad "drift session key detail: ${CASE_DETAIL}" ;;
esac
python3 - "${drift_dir}/state.json" "${drift_key}" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    data = json.load(handle)
data["observed"]["cursors"]["audit_session"] = sys.argv[2]
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(data, handle)
PY
DRIFT_HIDDEN_TS="$(audit_stamp -100)" # below the drift key: the forged-cursor blind-tail premise
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"${drift_key}","ago":60},
  {"key":"audit/${DRIFT_HIDDEN_TS}-session.start.${NL_HIDDEN_SID}.0.json","ago":1200},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_delta "${drift_dir}"
is "drift session cursor (forged): exit 2 (repair, never a green tail)" "2" "${CASE_RC}"
is "drift session cursor (forged): error verdict" "error" "${CASE_STATE}"
is "drift session cursor (forged): the record is marked repaired" "True" "$(state_field repaired)"
case "${CASE_DETAIL}" in
  *"key grammar"*) ok "drift session cursor (forged): detail names the key-grammar violation" ;;
  *) bad "drift session cursor (forged) detail: ${CASE_DETAIL}" ;;
esac

# The drift mirror must not over-reject the documented sid-less session event:
# `session.rejected` and its replay-conflict variant keep the non-session
# shape and must stay valid cursor movers (sweep and delta).
rejected_dir="${WORK}/state-rejected-cursor"
REJ_TS="$(audit_stamp -100)"
REJ_VAR_TS="$(audit_stamp -90)"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297},
  {"key":"audit/${REJ_TS}-session.rejected.000001.json","ago":100},
  {"key":"audit/${REJ_VAR_TS}-session.rejected_0123456789abcdef.000002.json","ago":90}],
 "uploads":[]}
JSON
start_mock
run_delta "${rejected_dir}"
is "sid-less session.rejected: the sweep advances the cursor over the documented key" \
  "audit/${REJ_VAR_TS}-session.rejected_0123456789abcdef.000002.json" \
  "$(state_field observed.cursors.audit_session)"
REJ2_TS="$(audit_stamp -2)"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297},
  {"key":"audit/${REJ_TS}-session.rejected.000001.json","ago":100},
  {"key":"audit/${REJ_VAR_TS}-session.rejected_0123456789abcdef.000002.json","ago":90},
  {"key":"audit/${REJ2_TS}-session.rejected.000003.json","ago":2}],
 "uploads":[]}
JSON
start_mock
run_delta "${rejected_dir}"
is "sid-less session.rejected: the delta also advances over it" \
  "audit/${REJ2_TS}-session.rejected.000003.json" "$(state_field observed.cursors.audit_session)"

# FF3.1: the delta merge's heartbeat filter needs its own tooth. An unshaped
# key in the heartbeat tail (`audit/heartbeat/9`) must not advance the
# heartbeat cursor: it sorts above every real `<ts>.json` key, so the next
# tail would list nothing and freshness would read the stale retained
# heartbeat. The unshaped key stays a finding.
hb_merge_dir="${WORK}/state-hb-merge"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_delta "${hb_merge_dir}"
is "heartbeat merge filter: the warm sweep is green" "ok" "${CASE_STATE}"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/heartbeat/9","ago":30},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_delta "${hb_merge_dir}"
is "heartbeat merge filter: the delta keeps the cursor on the shaped heartbeat" \
  "audit/heartbeat/${DELTA_HEARTBEAT_TS}.json" "$(state_field observed.cursors.audit_heartbeat)"
case "${CASE_DETAIL}" in
  *contract-mismatch*) ok "heartbeat merge filter: the unshaped heartbeat key is still flagged" ;;
  *) bad "heartbeat merge filter detail: ${CASE_DETAIL}" ;;
esac
# A new shaped heartbeat above the poisoned cursor (the mutant keeps `9`) must
# still be seen: with the cursor at `9` the next run can only repair.
HB_NEW_TS="$(audit_stamp -2)"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/heartbeat/9","ago":30},
  {"key":"audit/heartbeat/${HB_NEW_TS}.json","ago":2},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_delta "${hb_merge_dir}"
is "heartbeat merge filter: the next run still sees the new shaped heartbeat (cursor moves)" \
  "audit/heartbeat/${HB_NEW_TS}.json" "$(state_field observed.cursors.audit_heartbeat)"
is "heartbeat merge filter: the unshaped key never forces a repair" "delta" "$(state_field observed.coverage.mode)"

# RT4.1: a shaped key dated in the FUTURE sorts above the whole real key
# space. Letting it move a cursor (sweep or delta merge) pins the cursor above
# every real key: the next delta lists an empty tail while a real session gap
# sits below it - green until the sweep. A future-<ts> key must never move a
# cursor, and a persisted future cursor must fail closed into repair + sweep.
# The calendar-invalid shape (`99999999T999999Z`) parses to nothing and is
# rejected too. The fixtures are year-9999 on purpose: a hardcoded 2027 stamp
# would stop being future-dated on 2027-01-01 and fail these checks with no
# code change (round-5 RT5.1 time bomb).
future_dir="${WORK}/state-future-cursor"
FUT_KEY="audit/99991231T235959Z-user.login.1.json"
FUT_HB_KEY="audit/heartbeat/99991231T235959Z.json"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"${FUT_HB_KEY}","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"${FUT_KEY}","ago":60},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_delta "${future_dir}"
is "future-ts keys: the sweep keeps the session cursor on the real shaped key" \
  "audit/${DELTA_START_TS}-session.start.${SID}.0.json" "$(state_field observed.cursors.audit_session)"
is "future-ts keys: the sweep keeps the heartbeat cursor on the real heartbeat" \
  "audit/heartbeat/${DELTA_HEARTBEAT_TS}.json" "$(state_field observed.cursors.audit_heartbeat)"
FUT_HIDDEN_TS="$(audit_stamp -5)"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"${FUT_HB_KEY}","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"${FUT_KEY}","ago":60},
  {"key":"audit/${FUT_HIDDEN_TS}-session.start.${NL_HIDDEN_SID}.0.json","ago":1200},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_delta "${future_dir}"
is "future-ts keys: the next delta sees the new shaped session (no blind tail)" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in
  *"${NL_HIDDEN_SID}"*) ok "future-ts keys: the hidden session is gap-checked (recording-gap names it)" ;;
  *) bad "future-ts keys second-delta detail: ${CASE_DETAIL}" ;;
esac
is "future-ts keys: the delta merge keeps the session cursor on the newest real key (never the future key)" \
  "audit/${FUT_HIDDEN_TS}-session.start.${NL_HIDDEN_SID}.0.json" "$(state_field observed.cursors.audit_session)"
is "future-ts keys: the delta merge keeps the heartbeat cursor on the real heartbeat" \
  "audit/heartbeat/${DELTA_HEARTBEAT_TS}.json" "$(state_field observed.cursors.audit_heartbeat)"

# RT5.3: the tolerance scale must be pinned. A key dated within the
# clock-skew tolerance may move a cursor; one beyond must not - an inflated
# tolerance would pick the further-future key, an over-strict all-future
# rejection would keep the real key. Non-session keys on purpose: a future
# `session.start` beyond the tolerance also trips the collection-time
# clock-skew error.
bound_dir="${WORK}/state-bound-cursor"
BOUND_IN_KEY="audit/$(audit_stamp 60)-user.login.1.json"
BOUND_OUT_KEY="audit/$(audit_stamp 1000)-user.login.2.json"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"${BOUND_IN_KEY}","ago":60},
  {"key":"${BOUND_OUT_KEY}","ago":60},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_delta "${bound_dir}"
is "clock-skew bound: a within-tolerance future key may move the session cursor" \
  "${BOUND_IN_KEY}" "$(state_field observed.cursors.audit_session)"

# RT5.4: an absurd operator tolerance (timedelta overflow, >= ~8.64e13 s)
# must not brick the run: every key is simply rejected (never moves a
# cursor) and the run still lands a verdict.
overflow_dir="${WORK}/state-overflow-tolerance"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
RECORDING_WITNESS_EXTRA_ENV='RECORDING_WITNESS_CLOCK_SKEW_TOLERANCE_SECONDS=999999999999999' run_delta "${overflow_dir}"
is "absurd clock-skew tolerance: exit 0 (no crash)" "0" "${CASE_RC}"
is "absurd clock-skew tolerance: ok verdict" "ok" "${CASE_STATE}"
# The chosen semantics are rejection, not clamp-to-default: no shaped audit
# key may move a cursor under the absurd tolerance (a clamp fix would move
# them). Recordings keys carry no `<ts>` and stay cursor movers. The
# assertion is composite with the run state so it cannot pass vacuously when
# the run error-lands (guard removal) with no cursors written; the recordings
# cursor pins that processing happened at all (a global-reset regression).
is "absurd clock-skew tolerance: shaped keys never move a cursor on an ok run" \
  "ok:" "${CASE_STATE}:$(state_field observed.cursors.audit_session)"
is "absurd clock-skew tolerance: the recordings cursor still advances (no ts)" \
  "recordings/${SID}.tar" "$(state_field observed.cursors.recordings)"

# Forged state with a future-dated cursor (calendar-valid session-family,
# calendar-invalid sid-less, future heartbeat): the load guard must reject it
# (repair + sweep + error), never trust it as a shaped cursor.
future_forge_dir="${WORK}/state-future-forge"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_delta "${future_forge_dir}"
is "future cursor guard: the shaped warm sweep is green (control)" "ok" "${CASE_STATE}"
for forged_future in "future session|audit_session|${FUT_KEY}" \
                     "invalid-calendar session|audit_session|audit/99999999T999999Z-session.rejected.0.json" \
                     "future heartbeat|audit_heartbeat|${FUT_HB_KEY}"; do
  forged_kind="${forged_future%%|*}"
  forged_rest="${forged_future#*|}"
  forged_family="${forged_rest%%|*}"
  forged_value="${forged_rest#*|}"
  python3 - "${future_forge_dir}/state.json" "${forged_family}" "${forged_value}" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    data = json.load(handle)
data["observed"]["cursors"][sys.argv[2]] = sys.argv[3]
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(data, handle)
PY
  fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
  start_mock
  run_delta "${future_forge_dir}"
  is "future cursor (${forged_kind}): exit 2 (repair, never a green tail)" "2" "${CASE_RC}"
  is "future cursor (${forged_kind}): error verdict" "error" "${CASE_STATE}"
  is "future cursor (${forged_kind}): the record is marked repaired" "True" "$(state_field repaired)"
  case "${CASE_DETAIL}" in
    *"future-dated"*) ok "future cursor (${forged_kind}): detail names the future-dated violation" ;;
    *) bad "future cursor (${forged_kind}) detail: ${CASE_DETAIL}" ;;
  esac
done

# An unknown cursor version is not trusted: the observed block must take the
# repair + sweep path, never a delta (deleting the version guard would let a
# future/corrupt schema ride the old cursor semantics).
cursor_version_dir="${WORK}/state-cursor-version"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_delta "${cursor_version_dir}"
is "cursor version: the warm sweep is green" "ok" "${CASE_STATE}"
python3 - "${cursor_version_dir}/state.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    data = json.load(handle)
data["observed"]["cursor_version"] = 2
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(data, handle)
PY
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_delta "${cursor_version_dir}"
is "cursor version: exit 2 (repair, never trusted)" "2" "${CASE_RC}"
is "cursor version: error verdict" "error" "${CASE_STATE}"
case "${CASE_DETAIL}" in
  *"cursor version"*) ok "cursor version: detail names the unknown cursor version" ;;
  *) bad "cursor version detail: ${CASE_DETAIL}" ;;
esac
is "cursor version: the record is marked repaired" "True" "$(state_field repaired)"

# A failed sweep latches: every later run forces a sweep until one succeeds,
# so a delta can never paper over an unreconciled history.
latch_dir="${WORK}/state-latch"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_delta "${latch_dir}"
is "sweep latch: the warm sweep is green" "ok" "${CASE_STATE}"
python3 - "${latch_dir}/state.json" <<'PY'
import json
import sys

with open(sys.argv[1]) as handle:
    data = json.load(handle)
data["observed"]["sweep_failed"] = True
with open(sys.argv[1], "w") as handle:
    json.dump(data, handle)
PY
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,"fail_versions":"denied",
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_delta "${latch_dir}"
is "sweep latch: the failing sweep exits 2" "2" "${CASE_RC}"
is "sweep latch: the failing sweep is error" "error" "${CASE_STATE}"
is "sweep latch: the latch is carried through the failure" "True" "$(state_field observed.sweep_failed)"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
SAVED_REQUEST_LOG="${REQUEST_LOG}"
REQUEST_LOG="${WORK}/requests-delta-latch.log"
: >"${REQUEST_LOG}"
start_mock
run_delta "${latch_dir}"
is "sweep latch: the next healthy run sweeps and clears the latch" "ok" "${CASE_STATE}"
is "sweep latch: coverage mode is sweep" "sweep" "$(state_field observed.coverage.mode)"
is "sweep latch: the latch cleared" "False" "$(state_field observed.sweep_failed)"
if grep -q 'versions' "${WORK}/requests-delta-latch.log"; then
  ok "sweep latch: the recovery run really swept (versions listed)"
else
  bad "sweep latch: the recovery run did not list versions"
fi
cat "${WORK}/requests-delta-latch.log" >>"${SAVED_REQUEST_LOG}"
REQUEST_LOG="${SAVED_REQUEST_LOG}"

# M2: a naturally failed sweep (no pre-seeded latch) must set sweep_failed,
# and the latch alone must force the next sweep even with a far-future due.
latch_natural_dir="${WORK}/state-latch-natural"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_delta "${latch_natural_dir}"
is "natural latch: the warm sweep is green" "ok" "${CASE_STATE}"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,"fail_versions":"denied",
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_case "${latch_natural_dir}"
is "natural latch: a failed planned sweep sets the latch (no pre-seed)" "True" "$(state_field observed.sweep_failed)"
python3 - "${latch_natural_dir}/state.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    data = json.load(handle)
# Push the schedule far out: only the latch can force the next sweep.
data["observed"]["sweep_due_epoch"] = 4102444800
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(data, handle)
PY
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_delta "${latch_natural_dir}"
is "natural latch: the next run sweeps on the latch alone" "sweep" "$(state_field observed.coverage.mode)"
is "natural latch: the clean sweep clears the latch" "False" "$(state_field observed.sweep_failed)"

# Finding 6: the internal delta-overflow fallback is a real sweep too. A
# failed fallback sweep must latch even though the plan still said "delta".
fallback_dir="${WORK}/state-fallback-latch"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":1,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_delta "${fallback_dir}"
is "fallback latch: the warm sweep is green" "ok" "${CASE_STATE}"
python3 - "${FIXTURE}" <<'PY'
import json
import sys

# > DELTA_MAX_PAGES (50) new heartbeat keys above the cursor with page_size=1:
# the delta tail overflows, falls back to a sweep, and versions are denied.
objects = [
    # Date-inert on purpose (round-6 lenses): these 60 keys only need to sit
    # above the session cursor - the `audit/heartbeat/` prefix sorts above
    # every digit-leading `<ts>` key, so their dates never matter (verified:
    # a 2020-dated copy still passes the full suite); year-9999 keeps the
    # hygiene rule (no expiring fixture stamps) without changing the scenario.
    {"key": "audit/heartbeat/99991231T%02d0000Z.json" % index, "ago": 60}
    for index in range(60)
]
objects.append({"key": "audit/20260925T135000Z-session.start.9f8c4b1e-0d2a-4f7e-9c11-2b3d4e5f6a70.0.json", "ago": 300})
objects.append({"key": "recordings/9f8c4b1e-0d2a-4f7e-9c11-2b3d4e5f6a70.tar", "ago": 297})
json.dump({"bucket": "pc-admin-dr", "page_size": 1, "fail_versions": "denied",
           "objects": objects, "uploads": []}, open(sys.argv[1], "w", encoding="utf-8"))
PY
start_mock
run_delta "${fallback_dir}"
is "fallback latch: the failing fallback sweep exits 2" "2" "${CASE_RC}"
is "fallback latch: the failing fallback sweep latched" "True" "$(state_field observed.sweep_failed)"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_delta "${fallback_dir}"
is "fallback latch: the next healthy run sweeps and clears the latch" "ok" "${CASE_STATE}"
is "fallback latch: the recovery run is a sweep" "sweep" "$(state_field observed.coverage.mode)"
is "fallback latch: the latch cleared" "False" "$(state_field observed.sweep_failed)"

# Double-run idempotency: a second apply/quiet run takes the delta path, does
# not re-seed, keeps the generation, advances run_seq and leaves the verdict
# and finding signature byte-identical.
idem_dir="${WORK}/state-idem"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_delta "${idem_dir}"
is "double run: the warm sweep is green" "ok" "${CASE_STATE}"
warm_run_seq="$(state_field run_seq)"
warm_generation="$(state_field observed.generation)"
run_delta "${idem_dir}"
is "double run: the first quiet run is a green delta" "ok" "${CASE_STATE}"
is "double run: the first quiet run is a delta" "delta" "$(state_field observed.coverage.mode)"
first_run_seq="$(state_field run_seq)"
is "double run: run_seq advanced" "$((warm_run_seq + 1))" "${first_run_seq}"
is "double run: a quiet delta keeps the view generation" "${warm_generation}" "$(state_field observed.generation)"
first_detail="${CASE_DETAIL}"
first_signature="$(state_field signature)"
run_delta "${idem_dir}"
is "double run: the second quiet run is a green delta" "ok" "${CASE_STATE}"
is "double run: the second quiet run is a delta" "delta" "$(state_field observed.coverage.mode)"
is "double run: run_seq advanced again" "$((first_run_seq + 1))" "$(state_field run_seq)"
is "double run: verdict detail is byte-identical (age normalized)" "$(norm_detail "${first_detail}")" "$(norm_detail "${CASE_DETAIL}")"
is "double run: finding signature is byte-identical" "${first_signature}" "$(state_field signature)"
is "double run: no re-seed and no repair" "" "$(state_field repaired)"

# Sweep deferral: a cold-start seed cannot chain straight into a sweep on the
# acceptance / post-start timer fire. The next run is a delta (still ALERT
# with the cold-start disclosure); only the due sweep clears it.
defer_dir="${WORK}/state-defer"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
RECORDING_WITNESS_COLD_START_SECONDS=3600 run_delta "${defer_dir}"
is "sweep deferral: the seed cannot be green" "alert" "${CASE_STATE}"
is "sweep deferral: the seed wrote the seed mode" "seed" "$(state_field observed.coverage.mode)"
is "sweep deferral: compact_blind is set" "True" "$(state_field observed.coverage.compact_blind)"
defer_due="$(state_field observed.sweep_due_epoch)"
if [ "${defer_due}" -gt 0 ] 2>/dev/null; then
  ok "sweep deferral: the first sweep is deferred into the future"
else
  bad "sweep deferral: sweep_due_epoch is not a future epoch: ${defer_due}"
fi
defer_delta=$((defer_due - $(date +%s)))
if [ "${defer_delta}" -gt 300 ] && [ "${defer_delta}" -le 900 ]; then
  ok "sweep deferral: the deferral is the min(sweep, 900)s cap (${defer_delta}s)"
else
  bad "sweep deferral: deferral is not the 900s cap: ${defer_delta}s"
fi
SAVED_REQUEST_LOG="${REQUEST_LOG}"
REQUEST_LOG="${WORK}/requests-defer-delta.log"
: >"${REQUEST_LOG}"
start_mock
run_delta "${defer_dir}"
is "sweep deferral: the next run is a delta, not a sweep" "delta" "$(state_field observed.coverage.mode)"
is "sweep deferral: the delta still carries the cold-start alert" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in
  *cold-start*) ok "sweep deferral: detail keeps the cold-start disclosure" ;;
  *) bad "sweep deferral delta detail: ${CASE_DETAIL}" ;;
esac
if grep -q 'versions' "${WORK}/requests-defer-delta.log"; then
  bad "sweep deferral: the deferred run listed versions"
else
  ok "sweep deferral: the deferred run made no versions call"
fi
cat "${WORK}/requests-defer-delta.log" >>"${SAVED_REQUEST_LOG}"
REQUEST_LOG="${SAVED_REQUEST_LOG}"
force_sweep_state "${defer_dir}"
start_mock
run_delta "${defer_dir}"
is "sweep deferral: the forced sweep clears the disclosure" "ok" "${CASE_STATE}"
is "sweep deferral: the sweep mode is recorded" "sweep" "$(state_field observed.coverage.mode)"
is "sweep deferral: compact_blind cleared" "False" "$(state_field observed.coverage.compact_blind)"

# F3: a delta evaluates ages against the retained merged view, not only the
# new tail. Backdate the retained heartbeat in the view sidecar and run a
# delta that lists no new heartbeat: the age alarm must fire on the delta
# path (a fixture-only age scenario cannot cover retained state).
delta_age_dir="${WORK}/state-delta-age"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_delta "${delta_age_dir}"
is "delta age: the warm sweep is green" "ok" "${CASE_STATE}"
python3 - "${delta_age_dir}/view.json" <<'PY'
import json
import sys
from datetime import datetime, timedelta, timezone

with open(sys.argv[1], encoding="utf-8") as handle:
    data = json.load(handle)
old = (datetime.now(timezone.utc) - timedelta(seconds=1200)).isoformat()  # ci-allowlist: datetime.isoformat() is a stdlib call, not an SCP image reference.
for key in list(data.get("audit_objects", {})):
    if key.startswith("audit/heartbeat/"):
        data["audit_objects"][key] = old
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(data, handle)
PY
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_delta "${delta_age_dir}"
is "delta age: a retained stale heartbeat alerts on the delta path" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in
  *heartbeat-stale*) ok "delta age: detail names heartbeat-stale from the retained view" ;;
  *) bad "delta age detail: ${CASE_DETAIL}" ;;
esac
is "delta age: the run really took the delta path" "delta" "$(state_field observed.coverage.mode)"

# Range-split sweeps: the second sweep uses the boundaries the first sweep
# persisted; the union of range branches must be byte-identical to a serial
# sweep of the same bucket.
range_dir="${WORK}/state-range"
serial_dir="${WORK}/state-range-serial"
python3 -I - "${HARNESS_DIR}" "${SID}" <<'PY' | fixture
import json
import sys

sys.path.insert(0, sys.argv[1])
from shipper_keys import audit_key

sid = sys.argv[2]
objects = [
    {"key": "audit/heartbeat/20260925T140000Z.json", "ago": 45},
    {"key": "audit/20260925T130000Z-session.start.%s.0.shell.json" % sid, "ago": 300},
]
for seq in range(1, 7):
    objects.append({"key": audit_key("session.data", "20260925T1300%02dZ" % seq, sid, seq, flat=True), "ago": 299})
objects.append({"key": audit_key("session.end", "20260925T130100Z", sid, 7, "shell", flat=True), "ago": 298})
objects.append({"key": "recordings/%s.tar" % sid, "ago": 297})
print(json.dumps({"bucket": "pc-admin-dr", "page_size": 50, "objects": objects, "uploads": []}))
PY
start_mock
RECORDING_WITNESS_LIST_WORKERS=4 run_delta "${range_dir}"
is "range split: the first serial-branch sweep is green" "ok" "${CASE_STATE}"
range_first_detail="${CASE_DETAIL}"
range_boundaries="$(state_field observed.sweep_boundaries)"
if [ "${range_boundaries}" != "[]" ] && [ -n "${range_boundaries}" ]; then
  ok "range split: the first sweep persisted audit boundaries"
else
  bad "range split: no boundaries persisted: ${range_boundaries}"
fi
range_boundary="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["observed"]["sweep_boundaries"][0])' "${range_dir}/state.json" 2>/dev/null || true)"
force_sweep_state "${range_dir}"
SAVED_REQUEST_LOG="${REQUEST_LOG}"
REQUEST_LOG="${WORK}/requests-range-split.log"
: >"${REQUEST_LOG}"
start_mock
RECORDING_WITNESS_LIST_WORKERS=4 run_delta "${range_dir}"
is "range split: the boundary-split sweep is green" "ok" "${CASE_STATE}"
is "range split: split verdict detail equals the unsplit sweep (age normalized)" "$(norm_detail "${range_first_detail}")" "$(norm_detail "${CASE_DETAIL}")"
if python3 - "${WORK}/requests-range-split.log" "${range_boundary}" <<'PY'
import json
import sys
import urllib.parse

entries = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8") if line.strip()]
boundary = sys.argv[2]
object_ranges = []
version_ranges = []
for entry in entries:
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(entry["path"]).query)
    note = entry.get("note", "")
    if note.startswith("list-type=2") and query.get("prefix", [""])[0] == "audit/":
        object_ranges.append(query.get("start-after", [""])[0])
    if "versions" in note and query.get("prefix", [""])[0] == "audit/":
        version_ranges.append(query.get("key-marker", [""])[0])
if "" not in object_ranges:
    print("VIOLATION no unfiltered first audit object branch")
    sys.exit(1)
if boundary not in object_ranges:
    print("VIOLATION no audit object branch starts after the persisted boundary %r" % boundary)
    sys.exit(1)
if "" not in version_ranges or boundary not in version_ranges:
    print("VIOLATION version branches do not use the persisted boundary: %r" % version_ranges)
    sys.exit(1)
print("range split shape: %d object branches + %d version branches" % (len(object_ranges), len(version_ranges)))
PY
then ok "range split: object + version branches start after the persisted boundary"; else bad "range split request shape failed"; fi
cat "${WORK}/requests-range-split.log" >>"${SAVED_REQUEST_LOG}"
REQUEST_LOG="${SAVED_REQUEST_LOG}"
RECORDING_WITNESS_LIST_WORKERS=1 run_delta "${serial_dir}"
is "range split: a serial sweep of the same fixture is green" "ok" "${CASE_STATE}"
is "range split: split and serial verdicts are identical (age normalized)" "$(norm_detail "${CASE_DETAIL}")" "$(norm_detail "${range_first_detail}")"
unset RECORDING_WITNESS_LIST_WORKERS

# Delta pagination: new keys above the cursor must be followed through
# continuation tokens in every delta stream.
pag_dir="${WORK}/state-paginate"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":2,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_delta "${pag_dir}"
is "delta pagination: the warm sweep is green" "ok" "${CASE_STATE}"
PAG_HEARTBEAT_TS="$(audit_stamp -120)"
PAG_START_TS="$(audit_stamp -290)"
python3 -I - "${HARNESS_DIR}" "${SID2}" "${PAG_HEARTBEAT_TS}" "${PAG_START_TS}" <<'PY' | fixture
import json
import sys

sys.path.insert(0, sys.argv[1])
from shipper_keys import audit_key

sid, heartbeat_ts, start_ts = sys.argv[2], sys.argv[3], sys.argv[4]
objects = [{"key": "audit/heartbeat/%s.json" % heartbeat_ts, "ago": 120}]
objects.append({"key": "audit/%s-session.start.%s.0.shell.json" % (start_ts, sid), "ago": 290})
for seq in range(1, 6):
    objects.append({"key": audit_key("session.data", start_ts, sid, seq, flat=True), "ago": 289})
objects.append({"key": audit_key("session.end", start_ts, sid, 6, "shell", flat=True), "ago": 288})
for index in range(3):
    objects.append({"key": "recordings/1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5%d.tar" % index, "ago": 287 - index})
print(json.dumps({"bucket": "pc-admin-dr", "page_size": 2, "objects": objects, "uploads": []}))
PY
SAVED_REQUEST_LOG="${REQUEST_LOG}"
REQUEST_LOG="${WORK}/requests-delta-pagination.log"
: >"${REQUEST_LOG}"
start_mock
run_delta "${pag_dir}"
is "delta pagination: the fast run is green" "ok" "${CASE_STATE}"
if python3 - "${WORK}/requests-delta-pagination.log" <<'PY'
import json
import sys
import urllib.parse

entries = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8") if line.strip()]
continuations = 0
for entry in entries:
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(entry["path"]).query)
    note = entry.get("note", "")
    if note.startswith("list-type=2") and query.get("continuation-token"):
        continuations += 1
if continuations < 1:
    raise SystemExit("no delta continuation-token request - delta pagination not followed")
print("delta pagination: %d continuation-token requests" % continuations)
PY
then ok "delta pagination: continuation tokens are followed for the delta tails"; else bad "delta pagination failed"; fi
cat "${WORK}/requests-delta-pagination.log" >>"${SAVED_REQUEST_LOG}"
REQUEST_LOG="${SAVED_REQUEST_LOG}"

# A delta listing that returns a key at/below its cursor is server
# nonconformance (start-after is exclusive): the run must fail closed.
nonconf_dir="${WORK}/state-nonconformant"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_delta "${nonconf_dir}"
is "nonconformant delta: the warm sweep is green" "ok" "${CASE_STATE}"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,"objects_ignore_start_after":true,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
SAVED_REQUEST_LOG="${REQUEST_LOG}"
REQUEST_LOG="${WORK}/requests-nonconformant.log"
: >"${REQUEST_LOG}"
start_mock
run_delta "${nonconf_dir}"
REQUEST_LOG="${SAVED_REQUEST_LOG}"
is "nonconformant delta: exit 2 (fail-closed)" "2" "${CASE_RC}"
is "nonconformant delta: error verdict" "error" "${CASE_STATE}"
case "${CASE_DETAIL}" in
  *"at or below its cursor"*) ok "nonconformant delta: detail names the cursor violation" ;;
  *) bad "nonconformant delta detail: ${CASE_DETAIL}" ;;
esac
is "nonconformant delta: the record is marked repaired" "True" "$(state_field repaired)"
is "nonconformant delta: the repair ran a full sweep" "sweep" "$(state_field observed.coverage.mode)"
if grep -q 'versions' "${WORK}/requests-nonconformant.log"; then
  ok "nonconformant delta: the repair really swept (versions listed)"
else
  bad "nonconformant delta: the repair did not list versions"
fi
cat "${WORK}/requests-nonconformant.log" >>"${SAVED_REQUEST_LOG}"
# The rebuilt block serves the next fast run (the documented recovery trace).
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_delta "${nonconf_dir}"
is "nonconformant delta: the rebuilt block serves the next run green" "ok" "${CASE_STATE}"
is "nonconformant delta: the next run is a delta" "delta" "$(state_field observed.coverage.mode)"

# Finding 7: a nonconformant page order must not end the session stream
# early. A heartbeat key listed before a session key that sorts below it
# (fixture order) must not drop the session key: without the ordered guard
# the delta returns at the heartbeat and stays green on a real recording-gap.
unordered_dir="${WORK}/state-unordered-page"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_delta "${unordered_dir}"
is "unordered page: the warm sweep is green" "ok" "${CASE_STATE}"
UNORDERED_TS="$(audit_stamp -5)"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,"list_order":"fixture",
 "objects":[
  {"key":"audit/heartbeat/$(audit_stamp -30).json","ago":30},
  {"key":"audit/${UNORDERED_TS}-session.start.1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5e.0.json","ago":1200},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_delta "${unordered_dir}"
is "unordered page: the session key after the heartbeat is still seen" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in
  *recording-gap*) ok "unordered page: detail names the recording-gap the early stop would hide" ;;
  *) bad "unordered page detail: ${CASE_DETAIL}" ;;
esac

# FF2: the early stop must not fire on a truncated page. With page_size=1 the
# first page ([heartbeat]) is trivially "ordered", so the old guard returned
# at the heartbeat and never fetched page 2 - where the nonconformant server
# put the fresh session key - leaving the run green. Only a complete
# (IsTruncated=false) ordered page may end the session stream.
cross_page_dir="${WORK}/state-unordered-cross-page"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_delta "${cross_page_dir}"
is "cross-page heartbeat: the warm sweep is green" "ok" "${CASE_STATE}"
CROSS_TS="$(audit_stamp -5)"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":1,"list_order":"fixture",
 "objects":[
  {"key":"audit/heartbeat/$(audit_stamp -30).json","ago":30},
  {"key":"audit/${CROSS_TS}-session.start.1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5e.0.json","ago":1200},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_delta "${cross_page_dir}"
is "cross-page heartbeat: the session key on page 2 is still seen" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in
  *recording-gap*) ok "cross-page heartbeat: detail names the recording-gap the early stop would hide" ;;
  *) bad "cross-page heartbeat detail: ${CASE_DETAIL}" ;;
esac

# #161: the delta session listing must not page through the heartbeat subtree.
# With page_size=50 and a heartbeat tail that spills past the session keys'
# page, the round-2 complete-page rule alone pages through the whole subtree
# (62 session keys + 2500 heartbeats = 52 pages > DELTA_MAX_PAGES -> sweep
# fallback). The explicit `until` bound stops at the crossing page (page 2:
# 12 session keys then heartbeats) - the priced conformant-ordering trade -
# while a truncated page entirely at/above the bound (FF2 above, the >50k
# tooth below) keeps paginating.
bound_dir="${WORK}/state-session-bound"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_delta "${bound_dir}"
is "#161 bound: the warm sweep is green" "ok" "${CASE_STATE}"
BOUND_TS="$(audit_stamp -240)"
BOUND_SID="c1a2b3c4-d5e6-4f70-8a9b-0c1d2e3f4a5b"
python3 - "${FIXTURE}" "${DELTA_HEARTBEAT_TS}" "${DELTA_START_TS}" "${SID}" "${BOUND_TS}" "${BOUND_SID}" <<'PY'
import json
import sys

fixture, warm_hb, warm_start, warm_sid, bound_ts, bound_sid = sys.argv[1:7]
objects = [
    {"key": "audit/heartbeat/%s.json" % warm_hb, "ago": 60},
    {"key": "audit/%s-session.start.%s.0.json" % (warm_start, warm_sid), "ago": 300},
    {"key": "recordings/%s.tar" % warm_sid, "ago": 297},
]
# A complete new session after the warm cursor: start + 60 data + end, so the
# session keys alone span more than one page_size=50 page.
objects.append({"key": "audit/%s-session.start.%s.0.json" % (bound_ts, bound_sid), "ago": 240})
for seq in range(1, 61):
    objects.append({"key": "audit/%s-session.data.%s.%d.json" % (bound_ts, bound_sid, seq), "ago": 239})
objects.append({"key": "audit/%s-session.end.%s.61.shell.json" % (bound_ts, bound_sid), "ago": 238})
objects.append({"key": "recordings/%s.tar" % bound_sid, "ago": 237})
# 2499 heartbeat keys (year-9999, date-inert) sit above every session key:
# with the warm key the heartbeat family is exactly 2500 keys = 50 pages (the
# DELTA_MAX_PAGES bound, so the heartbeat listing itself does not overflow),
# while the old session listing (62 + 2499 = 52 pages) overflowed to a sweep.
# (2499, not 2500: the mock resumes a continuation token as an offset into the
# unfiltered list, so a 2501-key family would take 51 token pages.)
for index in range(2499):
    objects.append({"key": "audit/heartbeat/99991231T%02d%02d00Z.json" % (index // 60, index % 60), "ago": 60})
json.dump({"bucket": "pc-admin-dr", "page_size": 50, "objects": objects, "uploads": []},
          open(fixture, "w", encoding="utf-8"))
PY
SAVED_REQUEST_LOG="${REQUEST_LOG}"
REQUEST_LOG="${WORK}/requests-session-bound.log"
: >"${REQUEST_LOG}"
start_mock
run_delta "${bound_dir}"
REQUEST_LOG="${SAVED_REQUEST_LOG}"
is "#161 bound: the session tail stays a delta (no sweep fallback)" "delta" "$(state_field observed.coverage.mode)"
is "#161 bound: the new session is seen (green)" "ok" "${CASE_STATE}"
if python3 - "${WORK}/requests-session-bound.log" <<'PY'
import json
import sys
import urllib.parse

session_requests = 0
heartbeat_requests = 0
for raw in open(sys.argv[1], encoding="utf-8"):
    raw = raw.strip()
    if not raw:
        continue
    entry = json.loads(raw)
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(entry["path"]).query)
    if query.get("list-type") != ["2"]:
        continue
    prefix = query.get("prefix", [""])[0]
    if prefix == "audit/":
        session_requests += 1
    elif prefix == "audit/heartbeat/":
        heartbeat_requests += 1
if session_requests != 2:
    raise SystemExit("session listing made %d requests (expected 2: the crossing page stops the tail)" % session_requests)
if heartbeat_requests != 50:
    raise SystemExit("heartbeat listing made %d requests (expected 50)" % heartbeat_requests)
print("bounded")
PY
then
  ok "#161 bound: the session listing stops at the crossing page (2 requests, never the heartbeat subtree)"
else
  bad "#161 bound: the session listing paged through the heartbeat subtree (expected 2 session requests)"
fi

# R3: the recordings tail is key-ordered (<sid>.tar carries no timestamp), so
# a NEW tar whose id sorts below the recordings cursor is invisible to the
# fast run. This is the disclosed recordings-tail bound: a new orphan tar (no
# audit events at all) is caught at the next sweep, not by the delta.
r3_dir="${WORK}/state-recordings-tail"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297}],
 "uploads":[]}
JSON
start_mock
run_delta "${r3_dir}"
is "recordings tail: the warm sweep is green" "ok" "${CASE_STATE}"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"audit/heartbeat/${DELTA_HEARTBEAT_TS}.json","ago":60},
  {"key":"audit/${DELTA_START_TS}-session.start.${SID}.0.json","ago":300},
  {"key":"recordings/${SID}.tar","ago":297},
  {"key":"recordings/00000000-0000-4000-8000-000000000000.tar","ago":1200}],
 "uploads":[]}
JSON
start_mock
run_delta "${r3_dir}"
is "recordings tail: the below-cursor tar is invisible to the delta (disclosed bound)" "ok" "${CASE_STATE}"
force_sweep_state "${r3_dir}"
start_mock
run_delta "${r3_dir}"
is "recordings tail: the sweep catches the orphan tar" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in
  *session-start-missing*) ok "recordings tail: sweep detail names session-start-missing" ;;
  *) bad "recordings tail sweep detail: ${CASE_DETAIL}" ;;
esac

# ---- #159 dual-layout audit keys: date strip + bounded dated streams -----
# The witness accepts the legacy flat `audit/<basename>` layout and the
# date-partitioned `audit/YYYYMMDD/<basename>` layout during the transition:
# one strip helper (calendar-validated, malformed segments never stripped),
# layout-specific predicates/cursors, bounded day selection for the delta
# (cursor day + newer discovered days + the unseeded transition probe), and
# the future-day exclusion. Existing verdicts above stay unchanged.
DL_SID="3d3d3d3d-3d3d-4d3d-8d3d-3d3d3d3d3d3d"
DL_SID2="4e4e4e4e-4e4e-4e4e-8e4e-4e4e4e4e4e4e"
DL_HB_TS="$(audit_stamp -60)"
DL_HEARTBEAT="audit/heartbeat/${DL_HB_TS}.json"

# (1) Dated session/non-session classification + dated stream advance.
DL_DATED_START="$(dated_key session.start 20260925T130000Z "${DL_SID}" 1 shell)"
DL_DATED_DATA="$(dated_key session.data 20260925T130100Z "${DL_SID}" 2)"
DL_DATED_END="$(dated_key session.end 20260925T130200Z "${DL_SID}" 3 shell)"
DL_DATED_LOGIN="$(dated_key user.login 20260925T130300Z "" 4)"
dl_dated_dir="${WORK}/state-159-dated"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"${DL_HEARTBEAT}","ago":60},
  {"key":"${DL_DATED_START}","ago":300},
  {"key":"${DL_DATED_DATA}","ago":299},
  {"key":"${DL_DATED_END}","ago":298},
  {"key":"${DL_DATED_LOGIN}","ago":297},
  {"key":"recordings/${DL_SID}.tar","ago":296}],
 "uploads":[]}
JSON
start_mock
run_case "${dl_dated_dir}"
is "dated layout: the sweep is green" "ok" "${CASE_STATE}"
case "${CASE_DETAIL}" in
  *sessions=1*) ok "dated layout: the dated session is classified (sessions=1)" ;;
  *) bad "dated layout: sessions count unexpected: ${CASE_DETAIL}" ;;
esac
is "dated layout: the flat session cursor stays empty (dated keys never move it)" \
  "" "$(state_field observed.cursors.audit_session)"
is "dated layout: the sweep seeds the dated session cursor" \
  "${DL_DATED_LOGIN}" "$(state_field observed.cursors.audit_session_dated)"
DL_DATED_CURSOR="$(state_field observed.cursors.audit_session_dated)"
DL_NEW_START="$(dated_key session.start 20260925T130500Z "${DL_SID2}" 1 shell)"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"${DL_HEARTBEAT}","ago":60},
  {"key":"${DL_DATED_START}","ago":300},
  {"key":"${DL_DATED_DATA}","ago":299},
  {"key":"${DL_DATED_END}","ago":298},
  {"key":"${DL_DATED_LOGIN}","ago":297},
  {"key":"${DL_NEW_START}","ago":1200},
  {"key":"recordings/${DL_SID}.tar","ago":296}],
 "uploads":[]}
JSON
SAVED_REQUEST_LOG="${REQUEST_LOG}"
REQUEST_LOG="${WORK}/requests-159-dated-delta.log"
: >"${REQUEST_LOG}"
start_mock
run_delta "${dl_dated_dir}"
REQUEST_LOG="${SAVED_REQUEST_LOG}"
is "dated delta: exit 1 (the new session has no tar)" "1" "${CASE_RC}"
case "${CASE_DETAIL}" in
  *"${DL_SID2}"*) ok "dated delta: the new dated session is gap-checked (names the sid)" ;;
  *) bad "dated delta detail: ${CASE_DETAIL}" ;;
esac
is "dated delta: the dated cursor advances over the new dated key" \
  "${DL_NEW_START}" "$(state_field observed.cursors.audit_session_dated)"
is "dated delta: the flat cursor stays empty" "" "$(state_field observed.cursors.audit_session)"
is "dated delta: the run stays a delta (no repair)" "delta" "$(state_field observed.coverage.mode)"
is "dated delta: no repair record" "" "$(state_field repaired)"
if python3 - "${WORK}/requests-159-dated-delta.log" "${DL_DATED_CURSOR}" <<'PY'
import json
import sys
import urllib.parse

entries = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8") if line.strip()]
resumed = 0
for entry in entries:
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(entry["path"]).query)
    if entry.get("note", "").startswith("list-type=2") and query.get("prefix", [""])[0] == "audit/20260925/":
        if query.get("start-after", [""])[0] == sys.argv[2]:
            resumed += 1
if resumed != 1:
    raise SystemExit("the dated cursor's own day was not resumed from the cursor (%d requests)" % resumed)
print("dated cursor day resumed")
PY
then
  ok "dated delta: the dated cursor's own day is resumed with start-after=the cursor"
else
  bad "dated delta: the cursor-day listing did not resume from the dated cursor"
fi

# (2) Malformed/calendar-invalid/date-impersonation drift: never stripped,
# never silently classified, never allowed to move either cursor.
DL_FLAT_OK="$(key session.start 20260925T130000Z "${DL_SID}" 1 shell)"
DL_CAL_BAD="audit/20260932/20260925T130000Z-session.start.${DL_SID}.7.shell.json"
DL_SHORT_DAY="audit/2026092/20260925T130000Z-user.login.8.json"
DL_IMPERSONATE="audit/session.start/20260925T130000Z-session.start.${DL_SID2}.9.shell.json"
dl_drift_dir="${WORK}/state-159-drift"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"${DL_HEARTBEAT}","ago":60},
  {"key":"${DL_FLAT_OK}","ago":300},
  {"key":"${DL_CAL_BAD}","ago":299},
  {"key":"${DL_SHORT_DAY}","ago":298},
  {"key":"${DL_IMPERSONATE}","ago":297},
  {"key":"recordings/${DL_SID}.tar","ago":296}],
 "uploads":[]}
JSON
start_mock
run_case "${dl_drift_dir}"
is "dated drift: exit 1 (drift alerts)" "1" "${CASE_RC}"
case "${CASE_DETAIL}" in
  *naming-contract*) ok "dated drift: the malformed/impersonating session-shaped keys are naming-contract" ;;
  *) bad "dated drift naming-contract detail: ${CASE_DETAIL}" ;;
esac
case "${CASE_DETAIL}" in
  *contract-mismatch*) ok "dated drift: the wrong-length numeric segment is contract-mismatch" ;;
  *) bad "dated drift contract-mismatch detail: ${CASE_DETAIL}" ;;
esac
is "dated drift: the flat cursor stays on the valid flat key" \
  "${DL_FLAT_OK}" "$(state_field observed.cursors.audit_session)"
is "dated drift: no malformed day moves the dated cursor" "" "$(state_field observed.cursors.audit_session_dated)"

# (3) Mixed-layout identity: a dated re-ship of the same (ts, type, seq)
# canonicalizes onto the flat key's identity (no false sequence-duplicate).
DL_MIX_TS="$(audit_stamp -200)"
DL_MIX_DATA_TS="$(audit_stamp -199)"
DL_MIX_END_TS="$(audit_stamp -198)"
DL_MIX_FLAT_START="$(key session.start "${DL_MIX_TS}" "${DL_SID}" 1 shell)"
DL_MIX_FLAT_DATA="$(key session.data "${DL_MIX_DATA_TS}" "${DL_SID}" 2)"
DL_MIX_DATED_DATA="$(dated_key session.data "${DL_MIX_DATA_TS}" "${DL_SID}" 2)"
DL_MIX_FLAT_END="$(key session.end "${DL_MIX_END_TS}" "${DL_SID}" 3 shell)"
dl_mix_dir="${WORK}/state-159-mixed"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"${DL_HEARTBEAT}","ago":60},
  {"key":"${DL_MIX_FLAT_START}","ago":300},
  {"key":"${DL_MIX_FLAT_DATA}","ago":299},
  {"key":"${DL_MIX_DATED_DATA}","ago":298},
  {"key":"${DL_MIX_FLAT_END}","ago":297},
  {"key":"recordings/${DL_SID}.tar","ago":296}],
 "uploads":[]}
JSON
start_mock
run_case "${dl_mix_dir}"
is "mixed layout: the sweep is green (no false sequence-duplicate)" "ok" "${CASE_STATE}"
is "mixed layout: the flat cursor is the flat end key" \
  "${DL_MIX_FLAT_END}" "$(state_field observed.cursors.audit_session)"
is "mixed layout: the dated cursor is the dated data key" \
  "${DL_MIX_DATED_DATA}" "$(state_field observed.cursors.audit_session_dated)"

# (4) Transition scenario: the first dated keys land on the switch day and
# sort BELOW the flat cursor, so only the unseeded transition probe sees
# them. All seen, no missed session, no repair/sweep.
DL_TR_FLAT_START="$(key session.start 20260925T130000Z "${DL_SID}" 1 shell)"
DL_TR_DATED_START="$(dated_key session.start 20260925T130500Z "${DL_SID2}" 1 shell)"
dl_trans_dir="${WORK}/state-159-transition"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"${DL_HEARTBEAT}","ago":60},
  {"key":"${DL_TR_FLAT_START}","ago":300},
  {"key":"recordings/${DL_SID}.tar","ago":296}],
 "uploads":[]}
JSON
start_mock
run_case "${dl_trans_dir}"
is "transition: the flat-only warm sweep is green" "ok" "${CASE_STATE}"
is "transition: the warm sweep wrote the flat cursor" \
  "${DL_TR_FLAT_START}" "$(state_field observed.cursors.audit_session)"
is "transition: the warm sweep left the dated cursor legacy-empty" "" \
  "$(state_field observed.cursors.audit_session_dated)"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"${DL_HEARTBEAT}","ago":60},
  {"key":"${DL_TR_FLAT_START}","ago":300},
  {"key":"${DL_TR_DATED_START}","ago":1200},
  {"key":"recordings/${DL_SID}.tar","ago":296}],
 "uploads":[]}
JSON
SAVED_REQUEST_LOG="${REQUEST_LOG}"
REQUEST_LOG="${WORK}/requests-159-transition.log"
: >"${REQUEST_LOG}"
start_mock
run_delta "${dl_trans_dir}"
REQUEST_LOG="${SAVED_REQUEST_LOG}"
is "transition: the same-day dated key is seen (recording-gap, exit 1)" "1" "${CASE_RC}"
case "${CASE_DETAIL}" in
  *"${DL_SID2}"*) ok "transition: the dated session is gap-checked (names the sid)" ;;
  *) bad "transition detail: ${CASE_DETAIL}" ;;
esac
is "transition: the dated cursor seeds from the transition day" \
  "${DL_TR_DATED_START}" "$(state_field observed.cursors.audit_session_dated)"
is "transition: the flat cursor is not moved by the dated key" \
  "${DL_TR_FLAT_START}" "$(state_field observed.cursors.audit_session)"
is "transition: the run stays a delta (no repair/sweep)" "delta" "$(state_field observed.coverage.mode)"
is "transition: no repair record" "" "$(state_field repaired)"
if python3 - "${WORK}/requests-159-transition.log" "audit/20260925/" <<'PY'
import json
import sys
import urllib.parse

entries = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8") if line.strip()]
probe = 0
for entry in entries:
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(entry["path"]).query)
    if entry.get("note", "").startswith("list-type=2") and query.get("prefix", [""])[0] == sys.argv[2]:
        probe += 1
if probe != 1:
    raise SystemExit("the transition probe did not run exactly once (%d)" % probe)
print("transition probe ran")
PY
then ok "transition: the unseeded transition probe listed the flat cursor's own day"; else bad "transition probe request shape failed"; fi

# (5) Future-day vector: a valid later-than-(now+skew) day never moves a
# cursor, the validator fails closed on a persisted future-day cursor, and a
# heavy future day with an empty dated cursor is never listed (no enumeration,
# no forced sweep, the date stays unseeded).
DL_FUTURE_KEY="audit/20991231/20260925T130000Z-session.start.${DL_SID2}.1.shell.json"
dl_future_dir="${WORK}/state-159-future"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"${DL_HEARTBEAT}","ago":60},
  {"key":"${DL_DATED_LOGIN}","ago":30},
  {"key":"${DL_FUTURE_KEY}","ago":30}],
 "uploads":[]}
JSON
start_mock
run_case "${dl_future_dir}"
is "future day: the sweep is green (no start-without-tar alert inside the grace)" "ok" "${CASE_STATE}"
is "future day: the sweep keeps the dated cursor on the real dated key" \
  "${DL_DATED_LOGIN}" "$(state_field observed.cursors.audit_session_dated)"
DL_FUTURE_CURSOR="$(state_field observed.cursors.audit_session_dated)"
python3 - "${dl_future_dir}/state.json" "${DL_FUTURE_KEY}" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    data = json.load(handle)
data["observed"]["cursors"]["audit_session_dated"] = sys.argv[2]
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(data, handle)
PY
start_mock
run_delta "${dl_future_dir}"
is "future day cursor: exit 2 (repair, never a pinned empty dated tail)" "2" "${CASE_RC}"
is "future day cursor: error verdict" "error" "${CASE_STATE}"
case "${CASE_DETAIL}" in
  *audit_session_dated*future-dated*|*future-dated*audit_session_dated*) ok "future day cursor: detail names the future-dated dated cursor" ;;
  *) bad "future day cursor detail: ${CASE_DETAIL}" ;;
esac
is "future day cursor: the record is marked repaired" "True" "$(state_field repaired)"
# A poisoned dated cursor does not match the dated grammar (a flat key or a
# heartbeat key in the dated slot fails closed into the repair + sweep path,
# never a delta).
dl_poison_dir="${WORK}/state-159-poisoned-dated"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"${DL_HEARTBEAT}","ago":60},
  {"key":"${DL_DATED_LOGIN}","ago":30}],
 "uploads":[]}
JSON
start_mock
run_case "${dl_poison_dir}"
is "poisoned dated cursor: the shaped warm sweep is green (control)" "ok" "${CASE_STATE}"
DL_POISON_FLAT="$(key user.login 20260925T130300Z "" 4)"
for poisoned_dated in "flat|${DL_POISON_FLAT}" "heartbeat|${DL_HEARTBEAT}"; do
  poisoned_kind="${poisoned_dated%%|*}"
  poisoned_value="${poisoned_dated#*|}"
  python3 - "${dl_poison_dir}/state.json" "${poisoned_value}" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    data = json.load(handle)
data["observed"]["cursors"]["audit_session_dated"] = sys.argv[2]
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(data, handle)
PY
  start_mock
  run_delta "${dl_poison_dir}"
  is "poisoned dated cursor (${poisoned_kind}): exit 2 (repair, never trusted)" "2" "${CASE_RC}"
  is "poisoned dated cursor (${poisoned_kind}): error verdict" "error" "${CASE_STATE}"
  is "poisoned dated cursor (${poisoned_kind}): the record is marked repaired" "True" "$(state_field repaired)"
  case "${CASE_DETAIL}" in
    *"audit_session_dated"*grammar*) ok "poisoned dated cursor (${poisoned_kind}): detail names the dated cursor grammar" ;;
    *) bad "poisoned dated cursor (${poisoned_kind}) detail: ${CASE_DETAIL}" ;;
  esac
done
# Heavy future day with an empty dated cursor above the flat cursor: the
# discovery returns its prefix, the client-side future filter must drop it, so
# there is no per-run enumeration (which would overflow the page budget) and
# no forced sweep, and the date stays unseeded.
dl_future_heavy_dir="${WORK}/state-159-future-heavy"
DL_FH_FLAT="$(key session.start 20260925T130000Z "${DL_SID}" 1 shell)"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"${DL_HEARTBEAT}","ago":60},
  {"key":"${DL_FH_FLAT}","ago":300},
  {"key":"recordings/${DL_SID}.tar","ago":296}],
 "uploads":[]}
JSON
start_mock
run_case "${dl_future_heavy_dir}"
is "heavy future day: the flat warm sweep is green" "ok" "${CASE_STATE}"
python3 - "${FIXTURE}" "${DL_HEARTBEAT}" "${DL_FH_FLAT}" "${DL_SID}" <<'PY'
import json
import sys

fixture, heartbeat, flat_start, sid = sys.argv[1:5]
objects = [
    {"key": heartbeat, "ago": 60},
    {"key": flat_start, "ago": 300},
    {"key": "recordings/%s.tar" % sid, "ago": 296},
]
for index in range(200):
    objects.append({
        "key": "audit/20991231/20260925T13%02d%02dZ-user.login.%d.json" % (index // 60, index % 60, index + 1),
        "ago": 30,
    })
json.dump({"bucket": "pc-admin-dr", "page_size": 2, "objects": objects, "uploads": []},
          open(fixture, "w", encoding="utf-8"))
PY
SAVED_REQUEST_LOG="${REQUEST_LOG}"
REQUEST_LOG="${WORK}/requests-159-future-heavy.log"
: >"${REQUEST_LOG}"
start_mock
run_delta "${dl_future_heavy_dir}"
REQUEST_LOG="${SAVED_REQUEST_LOG}"
is "heavy future day: the run stays a delta (no forced sweep)" "delta" "$(state_field observed.coverage.mode)"
is "heavy future day: the future date stays unseeded" "" "$(state_field observed.cursors.audit_session_dated)"
if grep -q 'prefix=audit/20991231/' "${WORK}/requests-159-future-heavy.log" \
   || grep -q 'prefix=audit%2F20991231%2F' "${WORK}/requests-159-future-heavy.log"; then
  bad "heavy future day: the delta enumerated the future day"
else
  ok "heavy future day: the future day is never listed in delta"
fi

# (6) Empty dated cursor: a first dated day ABOVE the flat cursor is listed
# and seeds the cursor; a first dated day BELOW it is not delta-listed (the
# client filter is deterministic under both server behaviours) and the sweep
# finds it.
DL_ABOVE_DATED="$(dated_key user.login 20260926T130000Z "" 1)"
dl_above_dir="${WORK}/state-159-above"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"${DL_HEARTBEAT}","ago":60},
  {"key":"${DL_TR_FLAT_START}","ago":300},
  {"key":"recordings/${DL_SID}.tar","ago":296}],
 "uploads":[]}
JSON
start_mock
run_case "${dl_above_dir}"
is "empty cursor above: the flat warm sweep is green" "ok" "${CASE_STATE}"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"${DL_HEARTBEAT}","ago":60},
  {"key":"${DL_TR_FLAT_START}","ago":300},
  {"key":"${DL_ABOVE_DATED}","ago":30},
  {"key":"recordings/${DL_SID}.tar","ago":296}],
 "uploads":[]}
JSON
start_mock
run_delta "${dl_above_dir}"
is "empty cursor above: the delta is green" "ok" "${CASE_STATE}"
is "empty cursor above: the first dated day above the flat cursor seeds the dated cursor" \
  "${DL_ABOVE_DATED}" "$(state_field observed.cursors.audit_session_dated)"
is "empty cursor above: the run stays a delta" "delta" "$(state_field observed.coverage.mode)"
DL_BELOW_DATED="$(dated_key session.start 20260925T130000Z "${DL_SID2}" 1 shell)"
DL_BELOW_FLAT_LATE="$(key session.start 20260926T130000Z "${DL_SID}" 1 shell)"
dl_below_dir="${WORK}/state-159-below"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"${DL_HEARTBEAT}","ago":60},
  {"key":"${DL_BELOW_FLAT_LATE}","ago":300},
  {"key":"recordings/${DL_SID}.tar","ago":296}],
 "uploads":[]}
JSON
start_mock
run_case "${dl_below_dir}"
is "empty cursor below: the flat warm sweep is green" "ok" "${CASE_STATE}"
is "empty cursor below: the flat cursor is on the later day" \
  "${DL_BELOW_FLAT_LATE}" "$(state_field observed.cursors.audit_session)"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"${DL_HEARTBEAT}","ago":60},
  {"key":"${DL_BELOW_FLAT_LATE}","ago":300},
  {"key":"${DL_BELOW_DATED}","ago":1200},
  {"key":"recordings/${DL_SID}.tar","ago":296}],
 "uploads":[]}
JSON
SAVED_REQUEST_LOG="${REQUEST_LOG}"
REQUEST_LOG="${WORK}/requests-159-below.log"
: >"${REQUEST_LOG}"
start_mock
run_delta "${dl_below_dir}"
REQUEST_LOG="${SAVED_REQUEST_LOG}"
is "empty cursor below: the delta stays green (the below-flat day is not listed)" "ok" "${CASE_STATE}"
is "empty cursor below: the dated cursor stays empty" "" "$(state_field observed.cursors.audit_session_dated)"
if python3 - "${WORK}/requests-159-below.log" <<'PY'
import json
import sys
import urllib.parse

entries = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8") if line.strip()]
violations = []
for entry in entries:
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(entry["path"]).query)
    if entry.get("note", "").startswith("list-type=2") and query.get("prefix", [""])[0] == "audit/20260925/":
        violations.append("delta listed the below-flat day: %s" % entry["path"])
if violations:
    for violation in violations:
        print("VIOLATION " + violation)
    sys.exit(1)
print("below-flat day not listed (conformant server)")
PY
then ok "empty cursor below: the conformant server never lists the below-flat day"; else bad "empty cursor below request shape failed"; fi
# The non-filtering branch (a server that ignores start_after for prefixes)
# must reach the same decision through the client-side filter.
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,"prefixes_ignore_start_after":true,
 "objects":[
  {"key":"${DL_HEARTBEAT}","ago":60},
  {"key":"${DL_BELOW_FLAT_LATE}","ago":300},
  {"key":"${DL_BELOW_DATED}","ago":1200},
  {"key":"recordings/${DL_SID}.tar","ago":296}],
 "uploads":[]}
JSON
SAVED_REQUEST_LOG="${REQUEST_LOG}"
REQUEST_LOG="${WORK}/requests-159-below-nonfilter.log"
: >"${REQUEST_LOG}"
start_mock
run_delta "${dl_below_dir}"
REQUEST_LOG="${SAVED_REQUEST_LOG}"
is "empty cursor below (non-filtering server): the delta stays green" "ok" "${CASE_STATE}"
is "empty cursor below (non-filtering server): the dated cursor stays empty" "" \
  "$(state_field observed.cursors.audit_session_dated)"
if python3 - "${WORK}/requests-159-below-nonfilter.log" <<'PY'
import json
import sys
import urllib.parse

entries = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8") if line.strip()]
violations = []
for entry in entries:
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(entry["path"]).query)
    if entry.get("note", "").startswith("list-type=2") and query.get("prefix", [""])[0] == "audit/20260925/":
        violations.append("delta listed the below-flat day: %s" % entry["path"])
if violations:
    for violation in violations:
        print("VIOLATION " + violation)
    sys.exit(1)
print("below-flat day not listed (non-filtering server, client filter)")
PY
then ok "empty cursor below: the non-filtering server is filtered client-side (same decision)"; else bad "empty cursor below non-filtering request shape failed"; fi
force_sweep_state "${dl_below_dir}"
start_mock
run_delta "${dl_below_dir}"
is "empty cursor below: the sweep finds the below-flat dated session" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in
  *"${DL_SID2}"*) ok "empty cursor below: the sweep gap-checks it (names the sid)" ;;
  *) bad "empty cursor below sweep detail: ${CASE_DETAIL}" ;;
esac
is "empty cursor below: the sweep seeds the dated cursor" \
  "${DL_BELOW_DATED}" "$(state_field observed.cursors.audit_session_dated)"

# (7) Bounded day selection: a discovered day BELOW the dated cursor is not
# re-listed (request-count pin); a late dated key on a below-cursor day is
# the disclosed sweep-bounded residual; a writer revert advances the flat
# cursor past an unlisted dated day (also sweep-bounded).
DL_SEL_FLAT="$(key session.start 20260925T130000Z "${DL_SID}" 1 shell)"
DL_SEL_D2="$(dated_key user.login 20260927T130000Z "" 1)"
DL_SEL_D2_NEW="$(dated_key user.login 20260927T130500Z "" 3)"
DL_SEL_D1_RESIDUAL="$(dated_key session.start 20260926T130000Z "${DL_SID2}" 1 shell)"
dl_sel_dir="${WORK}/state-159-selection"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"${DL_HEARTBEAT}","ago":60},
  {"key":"${DL_SEL_FLAT}","ago":300},
  {"key":"${DL_SEL_D2}","ago":30},
  {"key":"recordings/${DL_SID}.tar","ago":296}],
 "uploads":[]}
JSON
start_mock
run_case "${dl_sel_dir}"
is "day selection: the warm sweep is green" "ok" "${CASE_STATE}"
is "day selection: the dated cursor is on the later day" \
  "${DL_SEL_D2}" "$(state_field observed.cursors.audit_session_dated)"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":1,
 "objects":[
  {"key":"${DL_HEARTBEAT}","ago":60},
  {"key":"${DL_SEL_FLAT}","ago":300},
  {"key":"${DL_SEL_D1_RESIDUAL}","ago":1200},
  {"key":"${DL_SEL_D2}","ago":30},
  {"key":"${DL_SEL_D2_NEW}","ago":20},
  {"key":"recordings/${DL_SID}.tar","ago":296}],
 "uploads":[]}
JSON
SAVED_REQUEST_LOG="${REQUEST_LOG}"
REQUEST_LOG="${WORK}/requests-159-selection.log"
: >"${REQUEST_LOG}"
start_mock
run_delta "${dl_sel_dir}"
REQUEST_LOG="${SAVED_REQUEST_LOG}"
is "day selection: the delta stays green (the below-cursor day is not listed)" "ok" "${CASE_STATE}"
is "day selection: the dated cursor advances only on its own day" \
  "${DL_SEL_D2_NEW}" "$(state_field observed.cursors.audit_session_dated)"
if python3 - "${WORK}/requests-159-selection.log" <<'PY'
import json
import sys
import urllib.parse

entries = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8") if line.strip()]
day_listings = []
for entry in entries:
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(entry["path"]).query)
    if not entry.get("note", "").startswith("list-type=2"):
        continue
    prefix = query.get("prefix", [""])[0]
    if prefix.startswith("audit/2026092"):
        day_listings.append(prefix)
violations = []
if day_listings.count("audit/20260927/") != 1:
    violations.append("expected exactly one listing for the cursor day, got %r" % day_listings)
if "audit/20260926/" in day_listings:
    violations.append("the below-cursor day was re-listed: %r" % day_listings)
if "audit/20260925/" in day_listings:
    violations.append("the flat cursor day was re-listed: %r" % day_listings)
if violations:
    for violation in violations:
        print("VIOLATION " + violation)
    sys.exit(1)
print("day selection request pin: %r" % day_listings)
PY
then ok "day selection: only the dated cursor's own day is listed (request-count pin)"; else bad "day selection request-count pin failed"; fi
force_sweep_state "${dl_sel_dir}"
start_mock
run_delta "${dl_sel_dir}"
is "below-cursor residual: the sweep catches the late below-cursor session" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in
  *"${DL_SID2}"*) ok "below-cursor residual: the sweep gap-checks it (names the sid)" ;;
  *) bad "below-cursor residual sweep detail: ${CASE_DETAIL}" ;;
esac
# Writer revert: flat keys resume and advance the flat cursor past a dated
# day the delta has not listed; that day is not re-listed in delta (the
# disclosure) and the sweep closes it.
DL_REV_FLAT="$(key session.start 20260925T130000Z "${DL_SID}" 1 shell)"
DL_REV_DATED_CURSOR="$(dated_key user.login 20260927T130000Z "" 1)"
DL_REV_RESUMED_FLAT="$(key user.login 20260929T130000Z "" 4)"
DL_REV_MISSED_DATED="$(dated_key session.start 20260928T130000Z "${DL_SID2}" 1 shell)"
dl_revert_dir="${WORK}/state-159-revert"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"${DL_HEARTBEAT}","ago":60},
  {"key":"${DL_REV_FLAT}","ago":300},
  {"key":"${DL_REV_DATED_CURSOR}","ago":30},
  {"key":"recordings/${DL_SID}.tar","ago":296}],
 "uploads":[]}
JSON
start_mock
run_case "${dl_revert_dir}"
is "writer revert: the warm sweep is green" "ok" "${CASE_STATE}"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"${DL_HEARTBEAT}","ago":60},
  {"key":"${DL_REV_FLAT}","ago":300},
  {"key":"${DL_REV_RESUMED_FLAT}","ago":30},
  {"key":"${DL_REV_DATED_CURSOR}","ago":30},
  {"key":"recordings/${DL_SID}.tar","ago":296}],
 "uploads":[]}
JSON
start_mock
run_delta "${dl_revert_dir}"
is "writer revert: the resumed flat key advances the flat cursor" \
  "${DL_REV_RESUMED_FLAT}" "$(state_field observed.cursors.audit_session)"
is "writer revert: the dated cursor is unchanged" \
  "${DL_REV_DATED_CURSOR}" "$(state_field observed.cursors.audit_session_dated)"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"${DL_HEARTBEAT}","ago":60},
  {"key":"${DL_REV_FLAT}","ago":300},
  {"key":"${DL_REV_RESUMED_FLAT}","ago":30},
  {"key":"${DL_REV_DATED_CURSOR}","ago":30},
  {"key":"${DL_REV_MISSED_DATED}","ago":1200},
  {"key":"recordings/${DL_SID}.tar","ago":296}],
 "uploads":[]}
JSON
SAVED_REQUEST_LOG="${REQUEST_LOG}"
REQUEST_LOG="${WORK}/requests-159-revert.log"
: >"${REQUEST_LOG}"
start_mock
run_delta "${dl_revert_dir}"
REQUEST_LOG="${SAVED_REQUEST_LOG}"
is "writer revert: the missed dated day is not re-listed in delta (disclosed)" "ok" "${CASE_STATE}"
is "writer revert: the dated cursor stays put" \
  "${DL_REV_DATED_CURSOR}" "$(state_field observed.cursors.audit_session_dated)"
if grep -q 'prefix=audit/20260928/' "${WORK}/requests-159-revert.log" \
   || grep -q 'prefix=audit%2F20260928%2F' "${WORK}/requests-159-revert.log"; then
  bad "writer revert: the delta listed the missed dated day"
else
  ok "writer revert: the missed dated day is below the resumed flat cursor (sweep-bounded)"
fi
force_sweep_state "${dl_revert_dir}"
start_mock
run_delta "${dl_revert_dir}"
is "writer revert: the sweep closes the missed dated day" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in
  *"${DL_SID2}"*) ok "writer revert: the sweep gap-checks the missed session (names the sid)" ;;
  *) bad "writer revert sweep detail: ${CASE_DETAIL}" ;;
esac

# (8) Prefix drift: a non-day prefix above the flat cursor is never listed in
# delta (its keys classify at the sweep), and a date-impersonating prefix is
# not stripped into a flat parse.
DL_PREFIX_DRIFT="audit/notaday/20260925T130000Z-session.start.${DL_SID2}.1.shell.json"
DL_PREFIX_IMPERSONATE="audit/session.data/20260925T130000Z-session.start.${DL_SID2}.2.shell.json"
dl_prefix_dir="${WORK}/state-159-prefix-drift"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"${DL_HEARTBEAT}","ago":60},
  {"key":"${DL_TR_FLAT_START}","ago":300},
  {"key":"recordings/${DL_SID}.tar","ago":296}],
 "uploads":[]}
JSON
start_mock
run_case "${dl_prefix_dir}"
is "prefix drift: the warm sweep is green" "ok" "${CASE_STATE}"
fixture <<JSON
{"bucket":"pc-admin-dr","page_size":50,
 "objects":[
  {"key":"${DL_HEARTBEAT}","ago":60},
  {"key":"${DL_TR_FLAT_START}","ago":300},
  {"key":"${DL_PREFIX_DRIFT}","ago":1200},
  {"key":"${DL_PREFIX_IMPERSONATE}","ago":1200},
  {"key":"recordings/${DL_SID}.tar","ago":296}],
 "uploads":[]}
JSON
SAVED_REQUEST_LOG="${REQUEST_LOG}"
REQUEST_LOG="${WORK}/requests-159-prefix-drift.log"
: >"${REQUEST_LOG}"
start_mock
run_delta "${dl_prefix_dir}"
REQUEST_LOG="${SAVED_REQUEST_LOG}"
is "prefix drift: the delta stays a green no-op (drift does not repair)" "ok" "${CASE_STATE}"
is "prefix drift: the run stays a delta" "delta" "$(state_field observed.coverage.mode)"
if grep -qE 'prefix=audit(%2F|/)notaday(%2F|/)' "${WORK}/requests-159-prefix-drift.log" \
   || grep -qE 'prefix=audit(%2F|/)session\.data(%2F|/)' "${WORK}/requests-159-prefix-drift.log"; then
  bad "prefix drift: the delta listed a malformed/impersonating prefix"
else
  ok "prefix drift: malformed/impersonating prefixes are never listed in delta"
fi
force_sweep_state "${dl_prefix_dir}"
start_mock
run_delta "${dl_prefix_dir}"
is "prefix drift: the sweep classifies the drifted keys (naming-contract)" "alert" "${CASE_STATE}"
case "${CASE_DETAIL}" in
  *naming-contract*) ok "prefix drift: the sweep names naming-contract" ;;
  *) bad "prefix drift sweep detail: ${CASE_DETAIL}" ;;
esac

# ---- (g) the key is never printed ----------------------------------------
if grep -q 'SENTINEL' "${WORK}/witness.out" "${WORK}/witness.err" "${WORK}/state/verdict.log" "${WORK}/state/state.json" 2>/dev/null; then
  bad "the witness printed key material somewhere"
else
  ok "the witness never prints the key (stdout/stderr/verdict/state clean)"
fi
grep -q 'SENTINEL' "${WORK}/witness.env" && ok "the env fixture carries the sentinel key" || bad "env fixture missing the key"

# The run-case env file's key is the one the witness signs with: a fixture
# that verifies a different secret makes the mock reject every request, so the
# witness must fail closed. (This replaces a fixture self-grep that proved
# nothing.)
SAVED_REQUEST_LOG="${REQUEST_LOG}"
REQUEST_LOG="${WORK}/requests-wrong-key.log"
: >"${REQUEST_LOG}"
fixture <<JSON
{"bucket":"pc-admin-dr",
 "signature":{"key_id":"test-key-id-0001","key":"a-different-secret","region":"test-region"},
 "objects":[{"key":"audit/heartbeat/20260925T140000Z.json","ago":45}],
 "uploads":[]}
JSON
start_mock
run_case
REQUEST_LOG="${SAVED_REQUEST_LOG}"
is "wrong env-file key -> exit 2 (the env key is really used)" "2" "${CASE_RC}"
is "wrong env-file key -> error verdict (fail-closed)" "error" "${CASE_STATE}"

# ---- (h) install + disable path (fake systemctl, throwaway paths) --------
FAKEBIN="${WORK}/bin"
mkdir -p "${FAKEBIN}"
cat >"${FAKEBIN}/systemctl" <<'FAKE'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${FAKE_SYSTEMCTL_LOG}"
prop=""
prev=""
for arg in "$@"; do
  if [ "${prev}" = "-p" ]; then prop="${arg}"; fi
  prev="${arg}"
done
case "$1" in
  start)
    # Type=oneshot realism: start fails whenever the main process exits
    # non-zero. FAKE_START_RC models a start that wedges before ExecStart:
    # no new invocation and no state write. FAKE_MERGE_FIRST_START models the
    # issue #143 race: the first start merges with a timer-triggered
    # invocation that was already running — that in-flight (real) run writes
    # state.json, but InvocationID does not advance; the retry start does.
    # Otherwise the invocation counter advances and (unless
    # FAKE_NO_STATE_WRITE=1) state.json gets a new per-run identity (run_seq)
    # plus a fresh updated_at, exactly like a real witness run.
    start_count=0
    if [ -n "${FAKE_START_COUNT_FILE:-}" ]; then
      start_count="$(cat "${FAKE_START_COUNT_FILE}" 2>/dev/null || echo 0)"
      start_count=$((start_count + 1))
      printf '%s\n' "${start_count}" >"${FAKE_START_COUNT_FILE}"
    fi
    if [ -n "${FAKE_START_RC:-}" ]; then exit "${FAKE_START_RC}"; fi
    merged=0
    if [ "${FAKE_MERGE_FIRST_START:-0}" = "1" ] && [ "${start_count}" = "1" ]; then merged=1; fi
    if [ "${FAKE_NO_INVOCATION_BUMP:-0}" != "1" ] && [ "${merged}" != "1" ]; then
      printf 'inv-%s-%s\n' "$$" "${RANDOM}" >"${FAKE_INVOCATION_FILE}"
    fi
    # FAKE_RETRY_NO_STATE_WRITE=1 models a retry whose own state write fails:
    # the merged first start writes its record, the second (retry) start does not.
    write_state=1
    if [ "${FAKE_NO_STATE_WRITE:-0}" = "1" ]; then write_state=0; fi
    if [ "${FAKE_RETRY_NO_STATE_WRITE:-0}" = "1" ] && [ "${start_count}" -ge 2 ]; then write_state=0; fi
    if [ "${write_state}" = "1" ] && [ -f "${FAKE_STATE_FILE:-/dev/null}" ]; then
      python3 - "${FAKE_STATE_FILE}" "${FAKE_NEW_UPDATED_AT:-}" "${FAKE_INVOCATION_FILE:-}" "${FAKE_REPAIR_STATE:-0}" "${FAKE_REPAIR_VERDICT:-error}" "${FAKE_REPAIR_RUN_SEQ:-}" <<'PYSTATE'
import datetime
import json
import sys

try:
    data = json.load(open(sys.argv[1]))
except (OSError, ValueError):
    data = {}
if sys.argv[4] == "1":
    # Round-10 NIT: model the witness preserve+repair write. The old record
    # was unreadable/invalid, so the run identity resets to 1 (which can equal
    # the value jq read before the run), the verdict is forced to error (the
    # shipped writer's repair verdict; FAKE_REPAIR_VERDICT models a faulty or
    # hostile writer that claims a non-error repair instead), and the record
    # carries `repaired` plus the INVOCATION_ID of the run that wrote it.
    data["repaired"] = True
    # FAKE_REPAIR_RUN_SEQ models a hostile writer that advances the counter
    # instead of resetting it to 1 (round-13 D6); empty keeps the real
    # unreadable-run_seq repair shape (reset to 1).
    data["run_seq"] = int(sys.argv[6] or 1)
    data["state"] = sys.argv[5]
else:
    data.pop("repaired", None)
    data["run_seq"] = int(data.get("run_seq") or 0) + 1
data["updated_at"] = sys.argv[2] or (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
if sys.argv[3]:
    data["invocation"] = open(sys.argv[3]).read().strip()
json.dump(data, open(sys.argv[1], "w"))
PYSTATE
    fi
    case "${FAKE_EXEC_STATUS:-0}" in
      0) exit 0 ;;
      *) exit 1 ;;
    esac ;;
  show)
    case "${prop}" in
      InvocationID) cat "${FAKE_INVOCATION_FILE}" 2>/dev/null || true ;;
      ActiveState)
        # FAKE_ACTIVE_POLL_FILE, when set, counts every ActiveState poll
        # (the bounded-drain teeth assert the poll count). With
        # FAKE_SERVICE_ACTIVE_POLLS=N the unit is still running for the first
        # N-1 polls and drained from poll N on (the issue #143 in-flight
        # timer invocation); the default is drained.
        seen=0
        if [ -n "${FAKE_ACTIVE_POLL_FILE:-}" ]; then
          seen="$(cat "${FAKE_ACTIVE_POLL_FILE}" 2>/dev/null || echo 0)"
          seen=$((seen + 1))
          printf '%s\n' "${seen}" >"${FAKE_ACTIVE_POLL_FILE}"
        fi
        if [ -n "${FAKE_ACTIVE_POLL_SLEEP_FILE:-}" ]; then
          # Issue #143 red-team F1: record the sleep count observed at this
          # poll, so the bounded-drain tooth can pin the poll->sleep
          # interleaving (the volume counters alone stay green when the
          # sleeps are moved out of the poll body).
          sleep_seen=0
          if [ -n "${FAKE_SLEEP_COUNT_FILE:-}" ] && [ -f "${FAKE_SLEEP_COUNT_FILE}" ]; then
            sleep_seen="$(cat "${FAKE_SLEEP_COUNT_FILE}" 2>/dev/null || echo 0)"
          fi
          printf '%s\n' "${sleep_seen}" >>"${FAKE_ACTIVE_POLL_SLEEP_FILE}"
        fi
        polls="${FAKE_SERVICE_ACTIVE_POLLS:-0}"
        if [ "${polls}" -gt 0 ] 2>/dev/null && [ "${seen}" -lt "${polls}" ]; then
          printf 'active\n'
          exit 0
        fi
        printf '%s\n' "${FAKE_ACTIVE_STATE:-inactive}"
        ;;
      *) printf '%s\n' "${FAKE_EXEC_STATUS:-0}" ;;
    esac
    exit 0 ;;
esac
exit 0
FAKE
chmod +x "${FAKEBIN}/systemctl"
# The drain-bound tooth drives all 3600 wait-idle polls; FAKE_SLEEP_NOWAIT
# removes the wall-clock cost while keeping the iteration count (and with it
# the bound) exercised, and FAKE_SLEEP_COUNT_FILE + FAKE_SLEEP_ARGS_FILE pin
# the sleep count and its argument (`1`; the `/usr/bin/env` shape is pinned
# statically by the drain-loop tooth) so a bound regression that keeps the
# poll count (a deleted `/usr/bin/env sleep 1`, a shortened sleep, fewer
# iterations with an early break) still fails. Every other test sleeps for real.
cat >"${FAKEBIN}/sleep" <<'FAKESLEEP'
#!/usr/bin/env bash
if [ -n "${FAKE_SLEEP_COUNT_FILE:-}" ]; then
  seen="$(cat "${FAKE_SLEEP_COUNT_FILE}" 2>/dev/null || echo 0)"
  printf '%s\n' "$((seen + 1))" >"${FAKE_SLEEP_COUNT_FILE}"
fi
if [ -n "${FAKE_SLEEP_ARGS_FILE:-}" ]; then
  printf '%s\n' "${1:-}" >>"${FAKE_SLEEP_ARGS_FILE}"
fi
if [ "${FAKE_SLEEP_NOWAIT:-0}" = "1" ]; then exit 0; fi
exec /bin/sleep "$@"
FAKESLEEP
chmod +x "${FAKEBIN}/sleep"
export FAKE_SYSTEMCTL_LOG="${WORK}/systemctl.log"
export PATH="${FAKEBIN}:${PATH}"

export RECORDING_WITNESS_SBIN="${WORK}/opt/pc-recording-witness.sh"
export RECORDING_WITNESS_ENV_FILE="${WORK}/etc/recording-witness.env"
export RECORDING_WITNESS_STATE_DIR="${WORK}/var/lib/recording-witness"
export RECORDING_WITNESS_SERVICE="${WORK}/units/pc-recording-witness.service"
export RECORDING_WITNESS_TIMER="${WORK}/units/pc-recording-witness.timer"
export RECORDING_WITNESS_ENDPOINT="https://s3.eu-central-003.backblazeb2.com"
export RECORDING_WITNESS_BUCKET="pc-admin-dr"
export RECORDING_WITNESS_AUDIT_PREFIX="audit/"
export RECORDING_WITNESS_RECORDINGS_PREFIX="recordings/"
export RECORDING_WITNESS_KEY_ID="install-key-id"
export RECORDING_WITNESS_KEY="install-key-value-SENTINEL-0010"
export RECORDING_WITNESS_RENOTIFY_SECONDS="2400"
export RECORDING_WITNESS_QUIET_RENOTIFY_SECONDS="172800"
export RECORDING_WITNESS_QUIET_SIGNATURE="sha256:0000000000000000000000000000000000000000000000000000000000000000"
export RECORDING_WITNESS_COLD_START_SECONDS="7200"
export RECORDING_WITNESS_SWEEP_SECONDS="3600"

recording_witness_install
[ -x "${RECORDING_WITNESS_SBIN}" ] && ok "install renders the witness script (executable)" || bad "install left no executable witness"
[ -s "${RECORDING_WITNESS_SERVICE}" ] && ok "install renders the service unit" || bad "install left no service unit"
[ -s "${RECORDING_WITNESS_TIMER}" ] && ok "install renders the timer unit" || bad "install left no timer unit"
is "installed env file mode is 0600" "600" "$(mode_of "${RECORDING_WITNESS_ENV_FILE}")"
if grep -q 'install-key-value-SENTINEL-0010' "${RECORDING_WITNESS_ENV_FILE}"; then
  ok "installed env file holds the rendered witness key"
else
  bad "installed env file lost the rendered witness key"
fi
if grep -q '^RECORDING_WITNESS_RENOTIFY_SECONDS=2400$' "${RECORDING_WITNESS_ENV_FILE}"; then
  ok "installed env file carries the optional renotify window"
else
  bad "installed env file lost the optional renotify window"
fi
if grep -q '^RECORDING_WITNESS_QUIET_RENOTIFY_SECONDS=172800$' "${RECORDING_WITNESS_ENV_FILE}"; then
  ok "installed env file carries the optional quiet window"
else
  bad "installed env file lost the optional quiet window"
fi
if grep -q '^RECORDING_WITNESS_QUIET_SIGNATURE=sha256:0' "${RECORDING_WITNESS_ENV_FILE}"; then
  ok "installed env file carries the optional quiet signature"
else
  bad "installed env file lost the optional quiet signature"
fi
if grep -q '^RECORDING_WITNESS_COLD_START_SECONDS=7200$' "${RECORDING_WITNESS_ENV_FILE}"; then
  ok "installed env file carries the optional cold-start window"
else
  bad "installed env file lost the optional cold-start window"
fi
if grep -q '^RECORDING_WITNESS_SWEEP_SECONDS=3600$' "${RECORDING_WITNESS_ENV_FILE}"; then
  ok "installed env file carries the optional sweep interval"
else
  bad "installed env file lost the optional sweep interval"
fi
unset RECORDING_WITNESS_RENOTIFY_SECONDS RECORDING_WITNESS_QUIET_RENOTIFY_SECONDS RECORDING_WITNESS_QUIET_SIGNATURE RECORDING_WITNESS_COLD_START_SECONDS RECORDING_WITNESS_SWEEP_SECONDS
# Install enables the timer WITHOUT --now: the timer-stop acceptance below
# owns the first start, so no timer fire can merge with the seed run.
if grep -q '^enable pc-recording-witness.timer$' "${FAKE_SYSTEMCTL_LOG}" 2>/dev/null; then
  ok "install enables the timer"
else
  bad "install did not enable the timer: $(cat "${FAKE_SYSTEMCTL_LOG}" 2>/dev/null)"
fi
if grep -q 'enable --now pc-recording-witness.timer' "${FAKE_SYSTEMCTL_LOG}" 2>/dev/null; then
  bad "install still enables the timer with --now (the acceptance must own the first start)"
else
  ok "install does not start the timer with --now"
fi

# Seed a verdict log: the disable path must keep it as evidence (docs claim).
mkdir -p "${RECORDING_WITNESS_STATE_DIR}"
printf '%s\n' 'kept-evidence-line' >"${RECORDING_WITNESS_STATE_DIR}/verdict.log"
recording_witness_disable
if [ ! -e "${RECORDING_WITNESS_SBIN}" ] && [ ! -e "${RECORDING_WITNESS_ENV_FILE}" ] && [ ! -e "${RECORDING_WITNESS_SERVICE}" ] && [ ! -e "${RECORDING_WITNESS_TIMER}" ]; then
  ok "disable removes script + env + units (no stale timer)"
else
  bad "disable left artifacts behind"
fi
if [ -f "${RECORDING_WITNESS_STATE_DIR}/verdict.log" ] && grep -q 'kept-evidence-line' "${RECORDING_WITNESS_STATE_DIR}/verdict.log"; then
  ok "disable keeps the verdict log as evidence"
else
  bad "disable removed the verdict log"
fi
if grep -q 'disable --now pc-recording-witness.timer' "${FAKE_SYSTEMCTL_LOG}" 2>/dev/null; then
  ok "disable stops and disables the timer"
else
  bad "disable did not disable the timer"
fi
if recording_witness_disable; then ok "disable is idempotent"; else bad "second disable failed"; fi

# ---- (i) run-once: ExecMainStatus mapping + invocation freshness + redaction ----
mkdir -p "${WORK}/state"
export RECORDING_WITNESS_STATE_DIR="${WORK}/state"
# The run-once freshness anchor is "THIS invocation advanced state": the fake
# systemctl models a real run by bumping InvocationID and writing a new
# per-run identity (run_seq; updated_at is second-resolution and may repeat)
# plus the INVOCATION_ID that wrote the record; a read-failure repair is
# modelled by keeping run_seq at 1 and writing `repaired`; the
# wedged/rollback paths switch that off.
export FAKE_STATE_FILE="${WORK}/state/state.json"
export FAKE_INVOCATION_FILE="${WORK}/fake-invocation"
printf 'inv-seed\n' >"${FAKE_INVOCATION_FILE}"
SIGNATURE_SEED="$(printf 'sha256:%064d' 0)"
unset FAKE_START_RC FAKE_NO_INVOCATION_BUMP FAKE_NO_STATE_WRITE FAKE_NEW_UPDATED_AT \
      FAKE_MERGE_FIRST_START FAKE_RETRY_NO_STATE_WRITE FAKE_START_COUNT_FILE FAKE_SERVICE_ACTIVE_POLLS \
      FAKE_ACTIVE_POLL_FILE FAKE_ACTIVE_STATE FAKE_SLEEP_NOWAIT FAKE_SLEEP_COUNT_FILE FAKE_SLEEP_ARGS_FILE
seed_state() { # $1 = state, $2 = updated_at (wall clock), $3 = run_seq (default 41)
  printf '{"version":2,"state":"%s","detail":"sessions=1 uploads=0 audit_objects=3 recordings_objects=1 heartbeat_age=45s recording recordings/%s.tar session %s","updated_at":"%s","run_seq":%s,"last_notify_epoch":0,"signature":"%s"}\n' \
    "$1" "${SID}" "${SID}" "$2" "${3:-41}" "${SIGNATURE_SEED}" >"${WORK}/state/state.json"
}
seed_repair_state() { # $1 = invocation id recorded by an EARLIER repair run
  seed_state error "$(fresh_stamp)" 1
  python3 - "${WORK}/state/state.json" "$1" <<'PYSTATE'
import json
import sys

with open(sys.argv[1]) as handle:
    data = json.load(handle)
data["repaired"] = True
data["invocation"] = sys.argv[2]
with open(sys.argv[1], "w") as handle:
    json.dump(data, handle)
PYSTATE
}
run_once_call() { # sets runonce_rc / runonce_out
  runonce_rc=0
  runonce_out="$( (recording_witness_run_once) 2>&1 )" || runonce_rc=$?
}

seed_state ok "$(fresh_stamp)"
unset FAKE_START_RC
export FAKE_EXEC_STATUS=0
run_once_call
is "run-once: ok + ExecMainStatus=0 exits 0" "0" "${runonce_rc}"
case "${runonce_out}" in
  *"witness verdict: OK"*) ok "run-once surfaces the OK verdict" ;;
  *) bad "run-once OK output: ${runonce_out}" ;;
esac
case "${runonce_out}" in
  *"${SID}"*) bad "run-once leaked the raw session id into the run log" ;;
  *) ok "run-once redacts session ids from the run log" ;;
esac
case "${runonce_out}" in
  *"<redacted:"*) ok "run-once detail carries redaction markers" ;;
  *) bad "run-once detail lacks redaction markers: ${runonce_out}" ;;
esac
case "${runonce_out}" in
  *"witness finding signature: ${SIGNATURE_SEED}"*) ok "run-once surfaces the finding signature for pinning" ;;
  *) bad "run-once signature line missing: ${runonce_out}" ;;
esac

# alert (exit 1) makes systemctl start return non-zero; that must warn, not die
seed_state alert "$(fresh_stamp)"
export FAKE_EXEC_STATUS=1
run_once_call
is "run-once: rc=1 + ExecMainStatus=1 + alert warns (exit 0)" "0" "${runonce_rc}"
case "${runonce_out}" in
  *"witness verdict: ALERT"*) ok "run-once maps ExecMainStatus=1 to the ALERT warn path" ;;
  *) bad "run-once alert output: ${runonce_out}" ;;
esac

# error (exit 2) fails the run closed with the ERROR verdict
seed_state error "$(fresh_stamp)"
export FAKE_EXEC_STATUS=2
run_once_call
is "run-once: rc=1 + ExecMainStatus=2 + error fails closed" "1" "${runonce_rc}"
case "${runonce_out}" in
  *"witness verdict: ERROR"*) ok "run-once maps ExecMainStatus=2 to the ERROR die path" ;;
  *) bad "run-once error output: ${runonce_out}" ;;
esac

# unit demonstrably did not run: ExecMainStatus 203 (exec error) -> die
seed_state ok "$(fresh_stamp)"
export FAKE_EXEC_STATUS=203
run_once_call
is "run-once: exec error 203 dies" "1" "${runonce_rc}"
case "${runonce_out}" in
  *"demonstrably did not run"*) ok "run-once names the exec-error path" ;;
  *) bad "run-once exec-error output: ${runonce_out}" ;;
esac

# failed start + ExecMainStatus=0 is not a witness verdict -> die, no stale OK
seed_state ok "$(fresh_stamp)"
export FAKE_START_RC=1
export FAKE_EXEC_STATUS=0
run_once_call
is "run-once: failed start + ExecMainStatus=0 dies" "1" "${runonce_rc}"
case "${runonce_out}" in
  *"demonstrably did not run"*) ok "run-once refuses a start that did not run the witness" ;;
  *) bad "run-once failed-start output: ${runonce_out}" ;;
esac
case "${runonce_out}" in
  *"witness verdict: OK"*) bad "run-once reported a stale OK after a failed start" ;;
  *) ok "run-once never reports a stale OK after a failed start" ;;
esac

# Wedged start that never executed ExecStart while the stale ExecMainStatus
# still carries the previous alert's 1: the paired rc/EMS gate passes, but
# InvocationID did not advance — the previous verdict must never read as
# current (the exact round-3 repro).
seed_state alert "$(fresh_stamp)"
export FAKE_START_RC=1
export FAKE_EXEC_STATUS=1
run_once_call
is "run-once: wedged start + fresh-looking prior alert dies" "1" "${runonce_rc}"
case "${runonce_out}" in
  *"new invocation"*) ok "run-once names the unchanged InvocationID" ;;
  *) bad "run-once wedged-start output: ${runonce_out}" ;;
esac
case "${runonce_out}" in
  *"witness verdict: ALERT"*) bad "run-once reported the previous ALERT as current after a wedged start" ;;
  *) ok "run-once never reports the previous verdict after a wedged start" ;;
esac

# Issue #143: on a long-up box the witness timer fires its service as soon as
# the timer is enabled, so a fresh install (or a reinstall whose timer is
# already running) can find that timer-triggered invocation in flight when
# run-once reads the unit. Its own `systemctl start` then merges with the
# in-flight job: the merged start returns the in-flight run's result and
# InvocationID does NOT advance, even though that run wrote a perfectly valid
# state.json. The acceptance must drain the unit, retry exactly once (the
# merged run's write becoming the new run_seq baseline), and read the retry
# invocation's verdict — not refuse the valid record and not read the merged
# run's record as this run's.
seed_state ok "$(fresh_stamp)" 41
printf 'inv-inflight-143\n' >"${FAKE_INVOCATION_FILE}"
printf '0\n' >"${WORK}/start-count"
export FAKE_MERGE_FIRST_START=1 FAKE_START_COUNT_FILE="${WORK}/start-count"
unset FAKE_START_RC FAKE_NO_INVOCATION_BUMP FAKE_NO_STATE_WRITE FAKE_NEW_UPDATED_AT
export FAKE_EXEC_STATUS=0
unset FAKE_SERVICE_ACTIVE_POLLS FAKE_ACTIVE_POLL_FILE
run_once_call
is "run-once: merged timer invocation + bounded retry reaches a verdict (issue #143)" "0" "${runonce_rc}"
case "${runonce_out}" in
  *"witness verdict: OK"*) ok "run-once retries the merged start and reads a trustworthy verdict" ;;
  *) bad "run-once merged-start output: ${runonce_out}" ;;
esac
case "${runonce_out}" in
  *"new invocation"*) bad "run-once refused the merged timer invocation as a wedged start" ;;
  *) ok "run-once does not mis-file the merged timer invocation as a wedged start" ;;
esac
is "run-once: merged start was followed by exactly one retry" "2" "$(cat "${WORK}/start-count")"
merged_invocation="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1])).get("invocation", ""))' "${WORK}/state/state.json")"
if [ -n "${merged_invocation}" ] && [ "${merged_invocation}" != "inv-inflight-143" ]; then
  ok "run-once verdict belongs to the retry invocation, not the merged in-flight run"
else
  bad "run-once read the merged in-flight run's record (invocation=${merged_invocation:-none})"
fi
unset FAKE_MERGE_FIRST_START FAKE_START_COUNT_FILE

# Harness tooth for the retry re-anchor (red-team LOW / functional NIT-1):
# the merged first start writes a valid record (run_seq 41 -> 42) but the
# retry's OWN write fails. With the re-anchor, the merged record is the new
# baseline and the missing retry write must die on it (42 == 42). Without the
# re-anchor the stale baseline (41) makes the merged record look advanced, so
# the acceptance reads the merged invocation's verdict as this run's (rc=0,
# invocation=inv-inflight-143). Deleting the re-anchor line must fail this.
seed_state ok "$(fresh_stamp)" 41
printf 'inv-inflight-143\n' >"${FAKE_INVOCATION_FILE}"
printf '0\n' >"${WORK}/retry-fail-count"
export FAKE_MERGE_FIRST_START=1 FAKE_START_COUNT_FILE="${WORK}/retry-fail-count" FAKE_RETRY_NO_STATE_WRITE=1
unset FAKE_START_RC FAKE_NO_INVOCATION_BUMP FAKE_NO_STATE_WRITE FAKE_NEW_UPDATED_AT FAKE_SERVICE_ACTIVE_POLLS FAKE_ACTIVE_POLL_FILE
export FAKE_EXEC_STATUS=0
run_once_call
is "run-once: merged write + failed retry write dies on the re-anchored baseline" "1" "${runonce_rc}"
case "${runonce_out}" in
  *"did not advance (run_seq=42, before=42"*) ok "run-once re-anchored the retry baseline to the merged run's write" ;;
  *) bad "run-once did not re-anchor the retry baseline: ${runonce_out}" ;;
esac
case "${runonce_out}" in
  *"witness verdict: OK"*) bad "run-once accepted the merged record after the retry's write failed" ;;
  *) ok "run-once never reports the merged record as the retry's verdict" ;;
esac
unset FAKE_MERGE_FIRST_START FAKE_RETRY_NO_STATE_WRITE FAKE_START_COUNT_FILE

# Issue #143 (drain leg): a reinstall can catch a timer-triggered invocation
# already running. run-once must wait (bounded) for the unit to go inactive
# BEFORE it reads InvocationID, so its own start cannot merge with the
# in-flight job at all. The fake reports the unit active for one poll and
# drained from the second poll on; the fix must poll it out before starting.
seed_state ok "$(fresh_stamp)" 51
printf '0\n' >"${WORK}/active-polls"
export FAKE_ACTIVE_POLL_FILE="${WORK}/active-polls" FAKE_SERVICE_ACTIVE_POLLS=2
unset FAKE_START_RC FAKE_NO_INVOCATION_BUMP FAKE_NO_STATE_WRITE FAKE_NEW_UPDATED_AT
export FAKE_EXEC_STATUS=0
unset FAKE_MERGE_FIRST_START FAKE_START_COUNT_FILE
run_once_call
is "run-once: in-flight invocation is drained before the start (issue #143)" "0" "${runonce_rc}"
case "${runonce_out}" in
  *"witness verdict: OK"*) ok "run-once waits out the in-flight timer invocation, then reads the verdict" ;;
  *) bad "run-once drain output: ${runonce_out}" ;;
esac
is "run-once: drained the unit (active poll then inactive) before starting" "2" "$(cat "${WORK}/active-polls")"
unset FAKE_ACTIVE_POLL_FILE FAKE_SERVICE_ACTIVE_POLLS

# Red-team LOW: the drain matcher's state set was unpinned — adding
# `activating` (the in-flight oneshot state) or dropping `failed` (the
# post-alert/error oneshot state) kept every check green. Pin both ends
# directly against the sourced span function and the fake systemctl.
# Red-team LOW (round 2): the set was still open — adding `deactivating` (a
# stop still winding down) or `reloading` (a reload in progress) also kept
# the suite green, so those two must-not-drain states are pinned the same way.
export FAKE_ACTIVE_STATE=activating
if recording_witness_service_drained; then
  bad "run-once: \`activating\` must not count as drained (issue #143)"
else
  ok "run-once: \`activating\` (in-flight oneshot) does not count as drained (issue #143)"
fi
export FAKE_ACTIVE_STATE=failed
if recording_witness_service_drained; then
  ok "run-once: \`failed\` (post-alert/error oneshot) counts as drained (issue #143)"
else
  bad "run-once: \`failed\` must count as drained or every post-alert dispatch burns the bound (issue #143)"
fi
export FAKE_ACTIVE_STATE=deactivating
if recording_witness_service_drained; then
  bad "run-once: \`deactivating\` must not count as drained (issue #143)"
else
  ok "run-once: \`deactivating\` (a stop still winding down) does not count as drained (issue #143)"
fi
export FAKE_ACTIVE_STATE=reloading
if recording_witness_service_drained; then
  bad "run-once: \`reloading\` must not count as drained (issue #143)"
else
  ok "run-once: \`reloading\` (a reload in progress) does not count as drained (issue #143)"
fi
unset FAKE_ACTIVE_STATE

# Retry/drain bound (red-team INFO-2): a unit that never reports drained must
# die fail-closed at the bounded 3600-poll wait BEFORE any `systemctl start` —
# zero starts for this pre-start drain, never a start-then-retry loop (the
# retry-path drain can fire after a merged start already ran — fail-closed
# either way). FAKE_SLEEP_NOWAIT keeps the 3600 iterations but removes their
# wall-clock cost; FAKE_ACTIVE_STATE=active reports active on every poll,
# FAKE_ACTIVE_POLL_FILE pins the iteration count (3600 loop polls + the final
# ActiveState read for the die message = 3601), FAKE_SLEEP_COUNT_FILE pins
# the sleeps (3600) and FAKE_SLEEP_ARGS_FILE pins their argument (`1`), so a
# bound regression fails whether it changes the poll count, the sleep count
# or only the wall-clock wait (a deleted `sleep 1`, `sleep 0.1`, an early
# break) instead of shipping with a stale "3600s" message. The count/arg
# teeth pin volume, not the shape: FAKE_ACTIVE_POLL_SLEEP_FILE records the
# sleep count observed at every poll so the interleaving tooth (poll N must
# see N-1 sleeps) fails a loop whose sleeps are moved out of the poll body
# (a busy poll with identical counters), and two static teeth pin the
# executed drain sleep (the last statement before the loop's `done` must be
# a foreground `/usr/bin/env sleep 1` — catches a backgrounded or shortened
# sleep or a reverted absolute path — and no sleep/command/builtin/env
# definition may exist: the absolute `/usr/bin/env` cannot itself be
# shadowed and execs the real sleep, so the bound survives any shadow
# spelling).
# A regression that
# starts before the drain, or retries beyond the bound, moves the start
# counter off 0; one that loops without the bound hangs this check instead of
# failing it.
# The 3600-iteration drain wait forks the fake scripts 7200 times, which
# dominates the suite runtime. The drain sleep is `/usr/bin/env sleep 1`
# (the #143 hardening), and `/usr/bin/env` resolves `sleep` through PATH, so
# the `sleep()` function below is BYPASSED for the drain path — the
# `${FAKEBIN}/sleep` script carries the iteration/count/argument/interleaving
# teeth (and the 7200 forks remain; the absolute-path call is a shadowing
# defence, not a spawn optimisation). The function stays for any direct
# `sleep` call in sourced code. The `systemctl()` function serves only
# ActiveState (the only call the wait makes); every other subcommand
# delegates to the fake script on PATH. Unset after the tooth so the other
# tests use the script.
sleep() {
  if [ -n "${FAKE_SLEEP_COUNT_FILE:-}" ]; then
    seen="$(cat "${FAKE_SLEEP_COUNT_FILE}" 2>/dev/null || echo 0)"
    printf '%s\n' "$((seen + 1))" >"${FAKE_SLEEP_COUNT_FILE}"
  fi
  if [ -n "${FAKE_SLEEP_ARGS_FILE:-}" ]; then
    printf '%s\n' "${1:-}" >>"${FAKE_SLEEP_ARGS_FILE}"
  fi
  if [ "${FAKE_SLEEP_NOWAIT:-0}" = "1" ]; then return 0; fi
  command sleep "$@"
}
systemctl() {
  if [ "${1:-}" = "show" ]; then
    prop=""
    prev=""
    for arg in "$@"; do
      if [ "${prev}" = "-p" ]; then prop="${arg}"; fi
      prev="${arg}"
    done
    if [ "${prop}" = "ActiveState" ]; then
      seen=0
      if [ -n "${FAKE_ACTIVE_POLL_FILE:-}" ]; then
        seen="$(cat "${FAKE_ACTIVE_POLL_FILE}" 2>/dev/null || echo 0)"
        seen=$((seen + 1))
        printf '%s\n' "${seen}" >"${FAKE_ACTIVE_POLL_FILE}"
      fi
      if [ -n "${FAKE_ACTIVE_POLL_SLEEP_FILE:-}" ]; then
        sleep_seen=0
        if [ -n "${FAKE_SLEEP_COUNT_FILE:-}" ] && [ -f "${FAKE_SLEEP_COUNT_FILE}" ]; then
          sleep_seen="$(cat "${FAKE_SLEEP_COUNT_FILE}" 2>/dev/null || echo 0)"
        fi
        printf '%s\n' "${sleep_seen}" >>"${FAKE_ACTIVE_POLL_SLEEP_FILE}"
      fi
      polls="${FAKE_SERVICE_ACTIVE_POLLS:-0}"
      if [ "${polls}" -gt 0 ] 2>/dev/null && [ "${seen}" -lt "${polls}" ]; then
        printf 'active\n'
        return 0
      fi
      printf '%s\n' "${FAKE_ACTIVE_STATE:-inactive}"
      return 0
    fi
  fi
  command systemctl "$@"
}
seed_state ok "$(fresh_stamp)" 61
printf '0\n' >"${WORK}/no-drain-start-count"
printf '0\n' >"${WORK}/no-drain-polls"
printf '0\n' >"${WORK}/no-drain-sleeps"
: >"${WORK}/no-drain-sleep-args"
: >"${WORK}/no-drain-poll-sleeps"
export FAKE_ACTIVE_STATE=active FAKE_START_COUNT_FILE="${WORK}/no-drain-start-count" FAKE_ACTIVE_POLL_FILE="${WORK}/no-drain-polls" FAKE_SLEEP_COUNT_FILE="${WORK}/no-drain-sleeps" FAKE_SLEEP_ARGS_FILE="${WORK}/no-drain-sleep-args" FAKE_ACTIVE_POLL_SLEEP_FILE="${WORK}/no-drain-poll-sleeps" FAKE_SLEEP_NOWAIT=1
unset FAKE_START_RC FAKE_NO_INVOCATION_BUMP FAKE_NO_STATE_WRITE FAKE_MERGE_FIRST_START FAKE_RETRY_NO_STATE_WRITE
export FAKE_EXEC_STATUS=0
run_once_call
is "run-once: a unit that never drains dies fail-closed (issue #143)" "1" "${runonce_rc}"
case "${runonce_out}" in
  *"did not drain within 3600s"*) ok "run-once names the bounded drain failure" ;;
  *) bad "run-once non-drain output: ${runonce_out}" ;;
esac
is "run-once: a non-draining unit performed 0 starts" "0" "$(cat "${WORK}/no-drain-start-count")"
is "run-once: a non-draining unit polls the bounded 3600-iteration wait (3600 + the final read)" "3601" "$(cat "${WORK}/no-drain-polls")"
is "run-once: a non-draining unit sleeps the bounded 3600 iterations" "3600" "$(cat "${WORK}/no-drain-sleeps")"
is "run-once: every drain sleep waits the pinned 1 s" "1" "$(sort -u "${WORK}/no-drain-sleep-args")"
# Issue #143 red-team F1: poll N must observe N-1 sleeps (0..3600 for the
# shipped loop; the die path's final ActiveState read is poll 3601). Moving
# the sleeps out of the poll body keeps every volume counter green but
# collapses the bounded wait to a busy poll — this fails it.
if awk 'NR - 1 != $1 { exit 1 }' "${WORK}/no-drain-poll-sleeps"; then
  ok "run-once: every drain poll is separated by the preceding sleep (issue #143)"
else
  bad "run-once: drain polls and sleeps are not interleaved (issue #143): $(tr '\n' ' ' <"${WORK}/no-drain-poll-sleeps")"
fi
# Issue #143 red-team F2 (+ rounds 4-6 F1, r6 F1/F2): counters cannot prove
# the sleep blocks — a backgrounded `sleep 1 &` keeps them all green while
# the bounded wait stops waiting, and a bare `sleep 1` elsewhere keeps a
# presence-only tooth green while the executed loop sleep is shortened
# (`timeout 0.5 sleep 1`) or shadowed by a `sleep` function. Pin the executed
# line: the drain loop (the `for ((attempt...))` header) must end — at depth
# 0, so nested decoy loops cannot latch — in a foreground `/usr/bin/env sleep 1`
# (a trailing comment is fine); exactly one such header may match — a second
# exact header (a decoy loop after the real one) fails instead of overwriting
# the remembered body — and the executed drain loop must be the only C-style
# `for ((` loop in the script (r4 red-team mutF: a respelled executed header
# plus a sacrificial exact-header decoy otherwise nullifies the exactly-one
# rule while the unscanned respelled loop carries the clock early-exit; r5
# red-team candB: a same-line prefix — `:; for (( …` — is matched by the
# non-anchored alternation; r5 candA/candC: `for \` + newline + `(( …`, or
# the mid-token `fo\` + newline + `r (( …`, lets bash form the loop while the
# line-based scan sees neither half) — and no `sleep` definition may exist in
# any body form (r9 red-team HIGH: a compound-bodied `sleep () ( : )` before
# the witness span ran the whole suite 535/0 while every drain call no-opped
# and the 3600s bound collapsed to ~2s; the old tooth only matched `{`-body
# forms; r10 broadened the same any-body refusal to `systemctl` and made a
# non-identifier `function`-keyword name fail — see below), on both the raw
# and the continuation-joined view.
#
# r6 red-team F1/F2 + r7 trust HIGH: the old continuation tooth scanned a
# wait-idle span extracted by the first column-0 `}`; a multi-line quoted
# string could close that span early (a quoted `}` line) and the opener regex
# missed valid bash spellings (`name () {`, `function name {`, indented), so
# a split `for \` + `(( …` header could hide between lines while both count
# teeth stayed green (533/0 with the bound collapsed to 300s). Both teeth
# (and the sleep-shadow tooth) now run against a continuation-joined copy:
# the join is quote/comment-state aware (single/double quotes persist across
# lines; `#` starts a comment only at a word boundary), so a real
# continuation joins into the counted forms, while a backslash that is NOT a
# bash continuation (comment, single-quoted, escaped) does not merge — a
# naive text join merged `# comment \` with the next (executed) line into
# one comment line every scanner skips (the r7 trust HIGH), so any such
# trailing backslash fails the check fail-closed instead. No wait-idle span
# extraction remains (the marker-span extraction for the install span is
# unrelated). r9 red-team HIGH: a compound-bodied command definition named
# after the sleep utility evaded the old brace-body tooth (535/0 while the
# drain bound collapsed to ~2s). The drain loop calls `/usr/bin/env sleep 1`:
# `/usr/bin/env` at an absolute path cannot itself be function/alias-shadowed
# and execs the real sleep binary, so the bound's wall clock is immune to ANY
# shadow spelling of sleep, command, builtin or env — the first r9 fold's
# `command sleep 1` was bypassable (`command` is not a special builtin; a
# `command () { :; }` definition made `command sleep 0.2` return in 0.000s) —
# while the broadened static tooth refuses definition-shaped text for those
# names outright (any body form, both the raw and joined views).
#
# r10 red-team: the crafted-definition class is a regression detector for the
# drain path's FINITE NAME SURFACE, not a sandbox. The surface: the helpers
# `recording_witness_service_drained` and `recording_witness_wait_idle`, the
# fail-closed `die`, the `systemctl` query inside the check (and its at-bound
# repeat), the `/usr/bin/env sleep` loop sleep, and the loop/builtins.
# Reproduced misses, each suite-green before this fold: a `function
# /usr/bin/env { :; }` (or `function /bin/sleep { :; }`) path-name keyword
# definition shadowed the absolute-path invocation — the POSIX `/usr/bin/env
# ()` form was already caught by the basename pattern, the keyword form was
# not; a second `recording_witness_service_drained`, a `systemctl` function
# lying about ActiveState, a second `recording_witness_wait_idle`, and a
# `die () { :; }` override each neutralized one link of the drain path
# (fail-open at poll 0, or a silenced at-bound abort) while every static
# tooth stayed green. The closure: (1) a `function <name>` definition must
# carry a plain identifier name (`[A-Za-z_][A-Za-z0-9_]*`) — a decorated path
# name fails; (2) `systemctl` definitions are refused outright (the script
# only ever invokes it), like the existing sleep/command/builtin/env names;
# (3) each of the three drain-path functions — `die` included — is pinned to
# EXACTLY ONE definition on both views: a second definition anywhere in the
# script fails. The real script's single definitions and every invocation
# stay green.
#
# r13 red-team: three HIGHs plus a MED stayed suite-green (538/0) while the
# on-box arm failed open. (1) `x=; h${x}ash -p /usr/bin/true systemctl`
# rebuilt the `hash` token with a parameter expansion; the joined view kept
# `h{x}ash` (it stripped only `$`), so the command-position match missed.
# (2) `enable -n exit` (with a `command_not_found_handle` definition)
# disabled the `exit` builtin, so the at-bound `die`'s `exit 1` hit the
# handler and returned 0; `builtin enable -n exit` is the same. (3)
# `trap 'exit 0' EXIT` rewrote the process rc. (4) a PATH-prepended shadow
# `systemctl` misreported state; the r12 wording claimed that needs a
# root-level PATH write — false, the script edits itself as root. The
# closure: strip parameter expansions (`${...}` and `$name`) from the joined
# view before the command-position match (`h${x}ash` -> `hash`), add `!` to
# the command-position class, refuse ANSI-C `$'` quoting in code (0
# occurrences in the script), refuse command-position `builtin`/`enable`/
# `trap` invocations (the script's only `enable` occurrences are `systemctl
# enable --now …` subcommands), add `command_not_found_handle` to the
# refused-definition name set, and refuse `PATH=`/`PATH+=`/`export PATH`/
# `unset PATH` in code (0 occurrences). Each refusal is a deliberate
# over-refusal: the shipped script never uses these forms.
#
# r14 red-team/functional: every closure above (and the r7/r8 definition
# scan) stripped comments with a per-line `sub(/[[:space:]]#.*$/, …)` BEFORE
# its quote handling, so a `#` inside a quoted span (`echo " # " ; <payload>`)
# truncated the scanned view and the payload became invisible — six repros,
# each suite-green with the payload executing on-box: a parameter-rebuilt
# `h${x}ash`, an ANSI-C `$'\x68…'`, a command-position `builtin … hash`,
# `trap 'exit 0' EXIT`, `enable -n exit`, `PATH="/tmp/shad:${PATH}"`; the
# command-position class also missed the reserved-word separators (`if true;
# then trap …; fi`, `{ trap …; }`, `time trap …`, `if true; then h${x}ash …;
# fi`), a brace-sequence spelling (`{h..h}ash -p …`) slipped past the
# literal-token match, the quote-blind `line` view falsely refused the shipped
# prose (`log "PATH=${PATH}"`, `log "export PATH and unset PATH here"`), and
# the PATH tooth missed the builtin assignment forms (`printf -v PATH …`,
# `read -r PATH …`). The closure: the join scanner now also emits a
# quote-aware-comment-stripped continuation-joined copy (`PROVISION_CODE`)
# and the closure teeth read it instead of re-stripping comments; the
# command-position match is preceded by a reserved-word normalizer
# (`then`/`do`/`else`/`elif`/`time`/`{`/`}` rewritten to `;`, iterated); any
# brace sequence (`{…..…}`) in code is refused (the script has zero); the
# PATH tooth strips quoted spans (so quoted prose stays green) and also
# refuses `printf -v PATH` / `read … PATH`; the ANSI-C refusal now sees a
# `$'` even behind a quoted `#` decoy. Deliberate over-refusals: the
# reserved-word normalizer and the brace-sequence refusal (fail-closed; the
# shipped script uses neither form).
#
# Boundary (disclosed): the teeth are a regression detector for the drain
# path's pinned source (any definition of the utilities/builtins
# sleep/command/builtin/env/systemctl and of the rc-path exit/return plus
# printf/local/true plus the `command_not_found_handle` hook; `die` plus the
# two drain-path helpers pinned to a single definition occurrence each, with
# the `die` definition pinned to the EXACT shipped line — a dead, quoted,
# subshell or multiline rewrite fails closed; the
# `recording_witness_service_drained` body and the at-bound `die`
# invocation pinned to the shipped source lines; `hash` refused as a word and
# in the quote-joined/expansion-stripped view at a command position,
# including `builtin`/`command hash`, and any brace sequence
# (`{…..…}`) refused; command-position `builtin`/`enable`/`trap` invocations
# refused after the reserved-word normalizer
# (`then`/`do`/`else`/`elif`/`time`/`{`/`}`); `PATH` assignment/export/unset
# plus the builtin assignment forms `printf -v PATH` / `read … PATH` refused;
# any ANSI-C `$'` quoting in code refused; non-identifier `function` names) —
# the comment-stripping teeth read a quote-aware-comment-stripped
# continuation-joined view, so a `#` inside a quoted span cannot truncate the
# scan; not a sandbox: an adversary who can edit the provision script can
# also edit
# this harness, so crafted edits outside that pinned source (and harness
# self-edits) are out of scope by construction. Deliberate over-refusals
# (fail-closed): a `die` spelling that deviates from the exact shipped line
# (`exit "1"`, multiline, tab-indented), any `hash` spelling at a command
# position, any `$'` quoting in code, any brace sequence in code, and any
# `PATH` assignment/export/unset (incl. `printf -v PATH`/`read … PATH`).
# Residual (intentional-crafting class, disclosed): a dynamically constructed
# `eval`/`alias`+`expand_aliases`/sourced shadow is not statically detectable
# — behaviorally neutralized by the absolute `/usr/bin/env` for the drain
# sleep — a command-substitution-rebuilt word (`ha$(printf s)h -p …`) and a
# refused word rebuilt from a non-empty parameter expansion (`${x:-a}`) are
# not statically resolvable and stay in the crafted-edit class,
# blocking-equivalent loop forms stay heuristic (state pins + on-box
# wall-clock backstop), and any other such crafted edit outside the pinned
# source is out of scope by construction.
PROVISION_JOINED="${WORK}/provision-joined.sh"
PROVISION_CODE="${WORK}/provision-code.sh"
# The same scanner also emits a comment-stripped copy (`PROVISION_CODE`):
# r14 red-team/functional HIGH — a `#` inside a quoted span (`echo " # " ;
# <payload>`) made the per-tooth `sub(/[[:space:]]#.*$/, …)` truncate the
# scanned view before the closure transforms, so a parameter-expansion-
# rebuilt `hash`, an ANSI-C `$'…'`, a command-position `builtin`/`enable`/
# `trap` or a `PATH=` assignment after the decoy was invisible while the
# payload executed on-box. The scanner already tracks quote state (single/
# double/ANSI-C) for the continuation decision, so it also records where a
# true comment starts and emits the quote-aware-comment-stripped, still
# continuation-joined copy; the closure teeth below read it instead of
# re-stripping comments naively.
if awk -v q="'" -v code_out="${PROVISION_CODE}" '
  {
    line = $0
    n = length(line)
    esc = 0
    com_at = 0
    for (i = 1; i <= n; i++) {
      c = substr(line, i, 1)
      if (com) break
      if (sq) { if (c == q) sq = 0; continue }
      if (dq) {
        if (esc) { esc = 0; continue }
        if (c == "\\") { esc = 1; continue }
        if (c == "\"") { dq = 0; continue }
        continue
      }
      if (ansic) {
        if (esc) { esc = 0; continue }
        if (c == "\\") { esc = 1; continue }
        if (c == q) { ansic = 0; continue }
        continue
      }
      if (esc) { esc = 0; continue }
      if (c == "\\") { esc = 1; continue }
      if (c == "$" && substr(line, i+1, 1) == q) { ansic = 1; i++; continue }
      if (c == q) { sq = 1; continue }
      if (c == "\"") { dq = 1; continue }
      if (c == "#" && (i == 1 || substr(line, i-1, 1) ~ /[[:space:];&|()]/)) { com = 1; com_at = i; break }
    }
    code_line = (com_at > 0) ? substr(line, 1, com_at-1) : line
    cont = (esc == 1 && !com && !sq)
    if (cont) {
      printf "%s", substr(line, 1, n-1)
      printf "%s", substr(code_line, 1, n-1) > code_out
    } else {
      print
      print code_line > code_out
      if (n > 0 && substr(line, n, 1) == "\\") {
        print "trailing backslash at line " NR " is not a bash continuation (comment, single-quoted, or escaped) — refused fail-closed" > "/dev/stderr"
        bad = 1
      }
    }
    com = 0
  }
  END { exit bad ? 1 : 0 }
' "${PROVISION}" >"${PROVISION_JOINED}"; then
  ok "run-once: the joined view consumes every real continuation (no comment/quoted trailing backslash; the quote-aware-comment-stripped code view is emitted)"
else
  bad "run-once: a trailing backslash is not a bash continuation (comment/single-quoted/escaped) — refused fail-closed (issue #143)"
fi
# r8 red-team HIGH: a comment ends at the physical newline, so `# … \` does
# not continue — the next line executes. Any line with a `#` before a
# trailing backslash is refused fail-closed REGARDLESS of quote state: this
# is the lexer-independent guard against a crafted quote-state desync (the
# r8 `$'a\'"'` line flipped the join into a permanent double-quote state and
# merged an executed line into a comment). The one legitimate occurrence (a
# `#` inside the multi-line die string) was reworded away; the over-refusal
# (a `#` inside any string/heredoc before a trailing backslash) is deliberate.
if awk '/#.*\\[[:space:]]*$/ { print "line " NR " has a # before a trailing backslash — refused fail-closed" > "/dev/stderr"; bad = 1 } END { exit bad ? 1 : 0 }' "${PROVISION}"; then
  ok "run-once: no # before a trailing backslash (a comment never continues)"
else
  bad "run-once: a line carries a # before a trailing backslash — the next line would execute while a joined scan hides it (issue #143)"
fi
if awk '
  /(^|[^[:alnum:]_])for[[:space:]]*\(\(/ {
    c_headers++; c_header_lines = c_header_lines (c_header_lines == "" ? "" : ", ") NR
  }
  /^[[:space:]]*for[[:space:]]*\(\(attempt[[:space:]]*=[[:space:]]*0;[[:space:]]*attempt[[:space:]]*<[[:space:]]*3600;[[:space:]]*attempt\+\+\)\);[[:space:]]*do[[:space:]]*(#.*)?$/ {
    headers++; header_lines = header_lines (header_lines == "" ? "" : ", ") NR
    in_loop = 1; depth = 0; prev = ""; next
  }
  in_loop {
    if ($0 ~ /^[[:space:]]*#/ || $0 ~ /^[[:space:]]*$/) next
    if ($0 ~ /^[[:space:]]*done[[:space:]]*(#.*)?$/) {
      if (depth == 0) { loop_prev = prev; in_loop = 0; next }
      depth--
      prev = $0
      next
    }
    if ($0 ~ /(^|[[:space:]])do[[:space:]]*(#.*)?$/) depth++
    prev = $0
  }
  END {
    if (headers != 1 || c_headers != 1) {
      print "drain-loop C-style headers: " headers " exact, " c_headers " total (expected 1 and 1): exact line(s) " header_lines "; all line(s) " c_header_lines > "/dev/stderr"
      exit 1
    }
    exit (loop_prev ~ /^[[:space:]]*\/usr\/bin\/env[[:space:]]+sleep 1[[:space:]]*(#.*)?$/) ? 0 : 1
  }
' "${PROVISION_JOINED}"; then
  ok "run-once: the drain loop ends in a foreground \`/usr/bin/env sleep 1\` (issue #143)"
else
  bad "run-once: the drain loop sleep is missing, backgrounded, shortened, not last or not `/usr/bin/env sleep 1`, a second C-style loop header matched, or a continuation-split header joined into an extra counted loop (issue #143)"
fi
# Red-team MED: the count/shape teeth above run under FAKE_SLEEP_NOWAIT, so a
# wall-clock early exit keeps every count green while the effective bound
# collapses. The first cut was a denylist over the extracted body
# (`break`/`continue`/`SECONDS`/`date`/...); two mutants evaded it with the
# suite at 531/0 (round 2): (1) a `printf -v now '%(%s)T' -1` clock read in
# the body plus a `return 0` once `now >= entry+300` (fail-open: `wait_idle`
# declares "drained" with a live invocation while the die message still
# claims 3600s), and (2) a `: <<'MARKER'` heredoc whose body contains `sleep
# 1` then a bare `done`, which terminates both body scanners early — the real
# `if (( SECONDS >= deadline )); then break; fi` (300) after it was never
# scanned. Replace the denylist with an exact ALLOWLIST of the four intended
# body forms (the drain check, its `return 0`, its `fi` and the
# `/usr/bin/env sleep 1`),
# tolerant of leading whitespace and a trailing `#` comment: any other line —
# the printf clock, the heredoc opener — fails the tooth, and the accumulator
# is latched across every matched body instead of being reset per header. A
# second exact header match (a decoy loop carrying the four pinned forms,
# appended after the real one) also fails the tooth, so the last matching body
# can no longer become authoritative (r3 MED), and the general C-style
# `for ((` count is pinned to 1 (r4 red-team mutF: the executed header
# respelled — `for (( attempt …` — so the anchored regex misses it, plus a
# never-called exact-header decoy satisfying the exactly-one rule, kept the
# suite at 533/0 while the unscanned respelled loop carried the clock
# early-exit). r5 red-team: the general match is non-anchored (`:; for (( …`
# counts too), any `for ((` occurrence anywhere in the script — including
# inert text/heredocs — fails closed (deliberate over-refusal: the script
# ships exactly one C-style loop), and the r6 joined view (both teeth run on
# `PROVISION_JOINED`) turns a `for \` + newline + `(( …` (or the mid-token
# split) into the counted forms instead of letting bash join it past a
# line-based scan. Residual (intentional-crafting class, disclosed): an early
# exit moved outside the rendered loop body (e.g. into a helper) and a
# non-C-style loop construct (`while`/`until`) replacing the drain loop
# together with a sacrificial exact-header decoy stay heuristic; the state
# pins above and the on-box wall-clock behavior remain the backstop.
if awk '
  function pinned(line) {
    sub(/[[:space:]]+#.*$/, "", line)
    sub(/[[:space:]]+$/, "", line)
    sub(/^[[:space:]]+/, "", line)
    return (line == "if recording_witness_service_drained; then" ||
            line == "return 0" ||
            line == "fi" ||
            line == "/usr/bin/env sleep 1")
  }
  /(^|[^[:alnum:]_])for[[:space:]]*\(\(/ {
    c_headers++; c_header_lines = c_header_lines (c_header_lines == "" ? "" : ", ") NR
  }
  /^[[:space:]]*for[[:space:]]*\(\(attempt[[:space:]]*=[[:space:]]*0;[[:space:]]*attempt[[:space:]]*<[[:space:]]*3600;[[:space:]]*attempt\+\+\)\);[[:space:]]*do[[:space:]]*(#.*)?$/ {
    headers++; header_lines = header_lines (header_lines == "" ? "" : ", ") NR
    in_loop = 1; depth = 0; next
  }
  in_loop {
    if ($0 ~ /^[[:space:]]*#/ || $0 ~ /^[[:space:]]*$/) next
    if ($0 ~ /^[[:space:]]*done[[:space:]]*(#.*)?$/) {
      if (depth == 0) { in_loop = 0; next }
      depth--
    }
    if ($0 ~ /(^|[[:space:]])do[[:space:]]*(#.*)?$/) depth++
    if (!pinned($0)) unpinned = unpinned (unpinned == "" ? "" : " | ") "line " NR ": " $0
  }
  END {
    if (headers != 1 || c_headers != 1) print "drain-loop C-style headers: " headers " exact, " c_headers " total (expected 1 and 1): exact line(s) " header_lines "; all line(s) " c_header_lines > "/dev/stderr"
    if (unpinned != "") print "unpinned drain-loop line(s): " unpinned > "/dev/stderr"
    exit (headers == 1 && c_headers == 1 && unpinned == "") ? 0 : 1
  }
' "${PROVISION_JOINED}"; then
  ok "run-once: every drain loop body line is one of the four pinned forms (issue #143)"
else
  bad "run-once: the drain loop body carries a line outside the pinned allowlist or a second C-style loop header (a clock read, a break, a heredoc desync or any other unplanned statement) — the bound would not be wall-clock-pinned (issue #143)"
fi
if awk -v q="'" '
  # r9 red-team HIGH + the command-shadow strengthening + r10 red-team:
  # refuse ANY definition spelling of the sleep utility — and of `command`,
  # `builtin`, `env` and `systemctl`, which an earlier `command sleep 1` fix
  # left shadowable (`command` is not a special builtin; `builtin` shadows the
  # same way; `env` is a plain external; a `systemctl` function lying
  # `inactive` fail-opens the drain check at poll 0) — whatever the body form,
  # on the quote-aware-comment-stripped continuation-joined copy
  # (PROVISION_CODE; r14: a quoted `#` decoy must not truncate the scan).
  # Every valid bash
  # definition has `name ()`/`name()` or `function name` on one (post-join)
  # line (a backslash-split `name \` + `()` is rejoined by the join scanner;
  # the bare-newline split is a syntax error), so a definition-shaped match
  # anywhere in code is refused. Comments are already stripped; quoted spans
  # are stripped for `sleep`/`systemctl` (so literal prose/strings stay green
  # by design), while `command`/`builtin`/`env` are matched on the
  # quote-preserved line: a
  # quoted or escaped spelling of those identifiers is not a valid bash
  # function name (`e"nv" () { :; }` is `not a valid identifier`), but real
  # code passes strings to `env` (`env("RECORDING_WITNESS_ENDPOINT")`), and
  # stripping the quotes would turn those calls into `env()` and refuse the
  # shipped script. Invocations (`command -v …`, `env NAME=… …`) and the
  # `#!/usr/bin/env bash` shebang (a comment) stay green; the
  # brace-body/pending logic is gone.
  #
  # r10 trust: the `function` KEYWORD form accepts a non-identifier name
  # (`function /usr/bin/env { :; }` defines a function that shadows the
  # absolute-path invocation `time /usr/bin/env sleep 0.2` → 0.002s), which
  # the basename patterns cannot see; refuse any `function <name>` whose name
  # token is not a plain identifier ([A-Za-z_][A-Za-z0-9_]*). The POSIX
  # `/usr/bin/env ()` form is matched by the `env` basename clause above.
  #
  # r12 red-team HIGH: the drain path and `die` also depend on the `exit`
  # (the fail-closed rc) and `return` (the helper state decision) BUILTINS,
  # which bash lets a function shadow with a plain definition — `exit() { :; }`
  # after the `die` definition made the at-bound abort return 0 (the unit had
  # not drained, yet run_once proceeded), and `return() { :; }` made the drain
  # check report "drained" at poll 0. `printf` (the die message), `local` (the
  # helper scratch) and `true` (`|| true` on the systemctl query) are
  # refused for the same class closure; `command_not_found_handle` (the
  # command-not-found hook — with `enable -n exit` it swallowed the at-bound
  # `die` call, whose `exit 1` returned 0) joins the set by the same rule.
  # Tested: bash accepts ONLY the plain
  # `name()`/`name ()` and `function name` spellings for these names — every
  # quoted or escaped spelling (`ex"it"()`, `ex\it()`, `$'exit'()`,
  # `function "exit"`) is a `not a valid identifier` syntax error — so these
  # plain patterns on both views are the complete accepted set (the joined
  # view also catches a backslash-newline split rejoined to a plain name).
  # Invocations (`exit 1`, `return 0`, `printf …`, `local active`, `true`)
  # stay green.
  #
  # main-sync fold (2026-10-06, PR #156): the merged script embeds Python
  # (`_TRANSPORT = threading.local()`), so the leading boundary excludes `.`
  # — a `.`-preceded `name()` defines the dotted word, never the bare name
  # (`x.local(){ …; }` defines `x.local`; `local` stays the builtin,
  # verified live), so no shadowing path is lost.
  {
    line = $0
    raw = line
    gsub(/"[^"]*"/, "", line)
    gsub(q "[^" q "]*" q, "", line)
    if (line ~ /^[[:space:]]*$/) next
    if (line ~ /(^|[^[:alnum:]_.])sleep[[:space:]]*\([[:space:]]*\)/ ||
        line ~ /(^|[^[:alnum:]_.])function[[:space:]]+sleep([^[:alnum:]_]|$)/ ||
        raw ~ /(^|[^[:alnum:]_.])command[[:space:]]*\([[:space:]]*\)/ ||
        raw ~ /(^|[^[:alnum:]_.])builtin[[:space:]]*\([[:space:]]*\)/ ||
        raw ~ /(^|[^[:alnum:]_.])env[[:space:]]*\([[:space:]]*\)/ ||
        raw ~ /(^|[^[:alnum:]_.])function[[:space:]]+(command|builtin|env)([^[:alnum:]_]|$)/ ||
        line ~ /(^|[^[:alnum:]_.])systemctl[[:space:]]*\([[:space:]]*\)/ ||
        raw ~ /(^|[^[:alnum:]_.])function[[:space:]]+systemctl([^[:alnum:]_]|$)/ ||
        line ~ /(^|[^[:alnum:]_.])(exit|return|printf|local|true|command_not_found_handle)[[:space:]]*\([[:space:]]*\)/ ||
        line ~ /(^|[^[:alnum:]_.])function[[:space:]]+(exit|return|printf|local|true|command_not_found_handle)([^[:alnum:]_]|$)/) {
      shadow = 1
      print FILENAME ":" FNR ": " $0 > "/dev/stderr"
    }
    if (line ~ /(^|[^[:alnum:]_])function[[:space:]]/) {
      rest = line
      sub(/^.*function[[:space:]]+/, "", rest)
      sub(/[[:space:]].*$/, "", rest)
      # r11 functional LOW: strip an extracted token of its trailing
      # `(){`/`{` suffix before the identifier test — `function zzz(){ :; }`
      # left `zzz{` and false-positived; a decorated path name keeps its
      # slash (`function /usr/bin/env{ :; }`) and still fails.
      sub(/[({].*$/, "", rest)
      if (rest !~ /^[A-Za-z_][A-Za-z0-9_]*$/) {
        shadow = 1
        print FILENAME ":" FNR ": non-identifier function name: " $0 > "/dev/stderr"
      }
    }
  }
  END { exit shadow ? 1 : 0 }
' "${PROVISION_CODE}"; then
  ok "run-once: no drain-path utility/builtin definition (\`sleep\`/\`command\`/\`builtin\`/\`env\`/\`systemctl\`/\`exit\`/\`return\`/\`printf\`/\`local\`/\`true\`/\`command_not_found_handle\`) and no non-identifier \`function\` name shadows the drain path (any body form, issue #143)"
else
  bad "run-once: a drain-path utility/builtin definition (\`sleep\`/\`command\`/\`builtin\`/\`env\`/\`systemctl\`/\`exit\`/\`return\`/\`printf\`/\`local\`/\`true\`/\`command_not_found_handle\`) or a non-identifier \`function\` name shadows the drain path (any body form, issue #143)"
fi
# r10 red-team: the drain path resolves its two helpers and the fail-closed
# `die` by name at call time, so any definition AFTER the real one overrides
# it: a second `recording_witness_service_drained` returning 0 declared
# "drained" at poll 0 with the unit active (suite 535/0), a second `die`
# silenced the at-bound abort, and a second `recording_witness_wait_idle`
# replaced the bounded loop (all reproduced; the residual bullet disclosed
# the second-wait_idle spelling but nothing enforced it). Pin each of the
# three to EXACTLY ONE definition, per view (raw and continuation-joined),
# with comments and quoted spans stripped and invocations (no definition
# parens) naturally excluded. The real script defines each once.
#
# r11 red-team MED: the r10 pin counted definition LINES, not definitions —
# `die() { ...; exit 1; }; die() { :; }` on one line passed (count 1) and an
# in-place no-op `die` body passed with the count untouched, both
# suite-green (the override silences every later `die` gate). The count now
# accumulates definition OCCURRENCES per line, and the single `die`
# definition must carry `exit 1` inside its brace body — an `exit 1`
# elsewhere on the line, or a `die` spelled with the `function` keyword form
# (no paren form to pin), fails closed.
#
# r12 red-team HIGH: that textual `exit 1` check accepted an UNREACHABLE
# `exit 1` — `die()  { …; if false; then exit 1; fi; }`, `(exit 1)` and
# `true || exit 1` all kept the suite green while the on-box refusal returned
# 0 and run_once proceeded into the #143 merged-run path. Replace the textual
# check with an exact-line pin of the shipped definition
# (scripts/010-provision.sh:48) on both views: any other line — a dead,
# quoted, subshell or multiline `exit 1`, a tab-indented or trailing-comment
# rewrite — fails closed. The `exit "1"` rewrite is a DELIBERATE
# over-refusal (a valid fail-closed body that no longer matches the pin).
#
# r18 red-team HIGH: the #153 acceptance functions
# (`recording_witness_run_once`/`_accept`/`_timer_start`/`_timer_stop`) are
# extracted-and-sourced from the marker span only, so a post-END redefinition
# (`recording_witness_run_once() { return 0; }` inserted after
# `# --- END RECORDING WITNESS ---`) is invisible to every behavior tooth
# while it overrides the real function on-box (a no-op `run_once` bypasses
# the acceptance's witness run; a no-op `timer_start` leaves the timer
# stopped after a failed acceptance). They join the exactly-once count.
if awk -v q="'" '
  function keyword_defs(line, name) {
    return gsub("(^|[^[:alnum:]_])function[[:space:]]+" name "([^[:alnum:]_]|$)", "F", line)
  }
  function paren_defs(line, name) {
    return gsub("(^|[^[:alnum:]_])" name "[[:space:]]*[(][[:space:]]*[)]", "F", line)
  }
  function defs(line, name,   s) {
    s = line
    # Remove one `function NAME` occurrence before counting the POSIX forms,
    # so `function NAME()` is not counted twice (keyword_defs counts every
    # keyword occurrence, and a leftover second one still gets counted).
    sub("(^|[^[:alnum:]_])function[[:space:]]+" name "([^[:alnum:]_]|$)", "F", s)
    return keyword_defs(line, name) + paren_defs(s, name)
  }
  BEGIN {
    n = split("recording_witness_service_drained recording_witness_wait_idle die recording_witness_run_once recording_witness_accept recording_witness_timer_start recording_witness_timer_stop", names, " ")
    die_line = "die()  { printf " q "\\n\\033[1;31mFAIL:\\033[0m %s\\n" q " \"$*\" >&2; exit 1; }"
  }
  FNR == 1 { file = FILENAME; seen[file] = 1 }
  {
    line = $0
    sub(/^[[:space:]]*#.*/, "", line)
    gsub(/"[^"]*"/, "", line)
    gsub(q "[^" q "]*" q, "", line)
    sub(/[[:space:]]#.*$/, "", line)
    if (line ~ /^[[:space:]]*$/) next
    for (i = 1; i <= n; i++) {
      k = defs(line, names[i])
      if (k == 0) continue
      c[file, names[i]] += k
      if (c[file, names[i]] - k < 2 && c[file, names[i]] > 1)
        print file ":" FNR ": multiple definition occurrences of " names[i] ": " $0 > "/dev/stderr"
      if (names[i] == "die" && $0 != die_line) {
        print file ":" FNR ": die definition diverges from the pinned shipped line: " $0 > "/dev/stderr"
        die_body_bad = 1
      }
    }
  }
  END {
    bad = die_body_bad ? 1 : 0
    for (f in seen) {
      for (i = 1; i <= n; i++) {
        if (c[f, names[i]] != 1) {
          printf "%s: expected exactly 1 definition occurrence of %s, found %d\n", f, names[i], c[f, names[i]] + 0 > "/dev/stderr"
          bad = 1
        }
      }
    }
    exit bad ? 1 : 0
  }
' "${PROVISION}" "${PROVISION_JOINED}"; then
  ok "run-once: \`recording_witness_service_drained\`, \`recording_witness_wait_idle\`, \`die\` and the four #153 acceptance functions (\`recording_witness_run_once\`/\`recording_witness_accept\`/\`recording_witness_timer_start\`/\`recording_witness_timer_stop\`) are each defined exactly once (occurrence-counted) and the \`die\` definition is the exact shipped fail-closed line (issue #143)"
else
  bad "run-once: a drain-path or acceptance function (\`recording_witness_service_drained\`/\`recording_witness_wait_idle\`/\`die\`/\`recording_witness_run_once\`/\`recording_witness_accept\`/\`recording_witness_timer_start\`/\`recording_witness_timer_stop\`) is defined zero or multiple times (per occurrence) or the \`die\` definition is not the exact shipped line (a dead, quoted, subshell or multiline rewrite fails closed; issue #143)"
fi
# r15 red-team HIGH: the multi-line single-quote desync. `s='` on one line,
# then `' ; die() { :; } ; : '`, then `'` — bash pairs the quotes ACROSS the
# lines, so the `die()`/`systemctl()` definition between them EXECUTES, while
# every per-line quote-stripping view hides it (each view strips the `' … '`
# span on its own line) and the suite stayed 540/0. The closure is a
# definition scan on the comment-stripped code view WITHOUT quote stripping:
# the provision script has no legitimate definition-like string (comments are
# already stripped), so any `name()`/`function name` spelling of the
# load-bearing names — quoted or not — is refused; the one legitimate `die`
# definition must still be exactly the pinned shipped line, so a
# desync-hidden rewrite of it also fails closed.
if awk -v q="'" '
  BEGIN {
    die_line = "die()  { printf " q "\\n\\033[1;31mFAIL:\\033[0m %s\\n" q " \"$*\" >&2; exit 1; }"
  }
  {
    line = $0
    # F1 (r16): ANY `function NAME` keyword form on the no-quote-strip view is
    # refused — the script has zero keyword-form definitions (paren form only),
    # so a desync-hidden keyword override of the drain helpers cannot slip.
    if (line ~ /(^|[^[:alnum:]_])function[[:space:]]/) {
      print FILENAME ":" FNR ": a keyword-form definition on the no-quote-strip view: " $0 > "/dev/stderr"
      bad = 1
    }
    n = gsub(/(^|[^[:alnum:]_])die[[:space:]]*\([[:space:]]*\)/, "F", line)
    if (n > 0) {
      c += n
      if ($0 != die_line) {
        print FILENAME ":" FNR ": a die definition outside the pinned shipped line (a multi-line quote desync hides it from the stripped views): " $0 > "/dev/stderr"
        bad = 1
      }
    }
    # F1 (r16): the two drain helpers are each defined exactly once in the
    # script (the span paren-form definitions); a desync-hidden second
    # definition would override them (the r10 pin runs on quote-stripped views).
    h = gsub(/(^|[^[:alnum:]_])recording_witness_service_drained[[:space:]]*\([[:space:]]*\)/, "F", line)
    hd += h
    h = gsub(/(^|[^[:alnum:]_])recording_witness_wait_idle[[:space:]]*\([[:space:]]*\)/, "F", line)
    hi += h
    # r18 red-team HIGH: the four #153 acceptance functions join the
    # no-quote-strip count (a desync-hidden post-END redefinition would
    # otherwise override the span-sourced one on-box).
    h = gsub(/(^|[^[:alnum:]_])recording_witness_run_once[[:space:]]*\([[:space:]]*\)/, "F", line)
    hr += h
    h = gsub(/(^|[^[:alnum:]_])recording_witness_accept[[:space:]]*\([[:space:]]*\)/, "F", line)
    ha += h
    h = gsub(/(^|[^[:alnum:]_])recording_witness_timer_start[[:space:]]*\([[:space:]]*\)/, "F", line)
    hts += h
    h = gsub(/(^|[^[:alnum:]_])recording_witness_timer_stop[[:space:]]*\([[:space:]]*\)/, "F", line)
    htp += h
    # main-sync fold (2026-10-06, PR #156): a `.`-preceded `name()` cannot
    # shadow the bare name (it defines the dotted word; embedded Python
    # `threading.local()` is the false positive this excludes).
    if (line ~ /(^|[^[:alnum:]_.])(sleep|command|builtin|env|systemctl|exit|return|printf|local|true|command_not_found_handle)[[:space:]]*\([[:space:]]*\)/) {
      print FILENAME ":" FNR ": a load-bearing definition visible only without quote stripping: " $0 > "/dev/stderr"
      bad = 1
    }
  }
  END {
    if (c != 1) {
      print "die definitions in the no-quote-strip view: " c " (expected exactly 1, the pinned shipped line)" > "/dev/stderr"
      bad = 1
    }
    if (hd != 1 || hi != 1 || hr != 1 || ha != 1 || hts != 1 || htp != 1) {
      print "drain-path definitions in the no-quote-strip view: service_drained=" hd " wait_idle=" hi " run_once=" hr " accept=" ha " timer_start=" hts " timer_stop=" htp " (expected exactly 1 each)" > "/dev/stderr"
      bad = 1
    }
    exit bad ? 1 : 0
  }
' "${PROVISION_CODE}"; then
  ok "run-once: no load-bearing definition spelling is hidden behind a multi-line quote desync (a definition scan without quote stripping finds only the pinned \`die\` + the two drain helpers + the four #153 acceptance functions, and no keyword-form definition, issue #143)"
else
  bad "run-once: a load-bearing definition spelling (incl. the drain helpers, the #153 acceptance functions, or any \`function NAME\` keyword form) appears in code only when quote stripping is skipped — a multi-line quote desync can execute a definition the per-line scanners hide (issue #143)"
fi
# r16 red-team HIGH: the PATH tooth strips quoted spans, so a quoted token
# (`printf -v 'PATH'`, `declare -x "PATH=…"`, `unset -v 'PATH'`,
# `read -r "PATH"`) or a desync-hidden assignment (`s='` / `' ; PATH=… ; : '`)
# evaded it. This second view strips only quote CHARACTERS/backslashes (no
# span stripping) and requires every PATH write to sit at a command position
# (`^`/`;`/`&`/`|`/`(`/`)`/`{`/`}`), so quoted prose (`log "PATH=${PATH}"`,
# `log "export PATH and unset PATH here"`) stays green while the quoted-token
# and desync spellings are refused. `unset -- PATH` is covered by the option
# class; associative-array declarations (`declare -A` — the rebuilt
# `BASH_CMDS` vector) are refused in the hash tooth (the script has zero).
#
# r17 functional HIGH: a `command`/`builtin` prefix (plain or
# parameter-expansion-rebuilt) composed with a quoted-token PATH write
# (`command export "PATH=…"`, `command printf -v PATH …`,
# `command declare -x "PATH=…"`, `command unset -- PATH`,
# `builtin export "PATH=…"`, `comm${x}and export …`) evaded every branch:
# the prefix pushed the verb off the position class. Strip parameter
# expansions so a rebuilt prefix word joins, then drop `builtin`/`command`
# prefixes (with their options) at a command position so the verb lands
# where the branches match. (A prefix whose separator is itself a parameter
# expansion — `command${IFS}export` — stays in the crafted-edit class like
# the other non-statically-resolvable spellings.)
#
# r17 red-team HIGHs: three composition gaps closed in the same view.
# (a) The command-position class lacked the reserved-word separators and
# `!` (`if true; then PATH=…`, `! PATH=…`, `do PATH=…`) that the r14
# normalizer already handles for the hash/builtin teeth — the view now runs
# the same reserved-word normalizer and the class carries `!`.
# (b) Array-writing builtins that rewrite `PATH` (`mapfile -t PATH`,
# `readarray -t PATH`) were outside every branch (the script has zero).
# (c) The `declare -A` clause lives in the hash tooth on the quote-span-
# stripped view, so a quoted option/name (`declare "-A" "${b}SH_CMDS[…]"`
# rebuilding `BASH_CMDS`) hid from it — the hash tooth now also reads its
# quote/expansion-stripped joined view for that clause.
#
# r19 red-team HIGH: an assignment word before the prefix chain
# (`FOO=bar export "PATH=…"`, `FOO=bar command export …`, `! FOO=bar export`,
# `time FOO=bar export`, `FOO=bar command printf -v "PATH"`,
# `FOO=bar declare -x "PATH=…"`, `FOO=bar mapfile -t "PATH"`) shifted the
# verb past the position class with every static tooth green while the
# assignment poisoned PATH on-box. The loop now also strips assignment words
# at a command position, so the verb lands where the branches match. (An
# assignment whose quoted value contains whitespace — `FOO="a b" export …` —
# is not statically resolvable after the char-level quote strip and stays in
# the disclosed crafted-edit class, like the `${IFS}` separators.)
#
# r20 red-team HIGH + MED (delta re-check): the r19 strip matched only
# `NAME=`, so append/subscript prefixes (`A+=b declare -x "PATH=…"`,
# `FOO[0]=bar export "PATH=…"`, `A[0]=1 …`) still shifted the verb past the
# position class, and a loop-variable binding (`for PATH in /tmp/shad; do …`,
# also `select PATH`) poisoned PATH outside every branch (both pre-existing;
# runtime shadow probes confirmed). The strip now matches
# `NAME(\[sub\])?+=`; the branches also run on each intermediate line — a
# stripped `PATH=…`/`FOO=bar PATH=…` prefix must not hide its own write,
# which the final view alone would (the raw-PATH tooth backstops direct
# `PATH=`/`PATH+=` writes) — and `for`/`select PATH` joins the refusal set.
# A parameter-rebuilt name (`p=PATH; export "$p"=…`) stays in the disclosed
# crafted-edit class.
#
# r21 red-team HIGH (delta re-check): the documented PATH-write classes had
# single-line gaps — an array-element assignment (`PATH[0]=/tmp/shad`,
# `PATH[$i]=`, `PATH[0]+=`), a `declare -- PATH` (the option class required a
# letter after `-`), and a separated mapfile/readarray option argument
# (`mapfile -O 0 PATH`, `mapfile -n 1 PATH`) all evaded both PATH teeth
# (pre-existing; runtime array-PATH probe confirmed). Closed: the assignment
# branch accepts `PATH[sub]+=`, the declare/nameref option class accepts
# `--`, and the mapfile/readarray branch accepts arbitrary separated tokens.
# Disclosed residuals (pre-existing): a physical newline inside a subscript
# (`A[x` ⏎ `]=v trap …`, `PATH[0` ⏎ `]=…`) defeats every per-line tooth — the
# scanner joins backslash continuations but not bracket state, and a per-line
# bracket-balance guard would over-refuse the 31 legitimate unbalanced-bracket
# lines in the shipped span (ANSI escapes, Python list literals); and an
# absurd assignment-prefix chain (5k+ `A=1 ` prefixes) makes the strip loop
# quadratic (DoS-only; rewrites are monotone, so it terminates).
#
# r22 red-team HIGH (r21 delta re-check; the lens ended without a report, its
# driver results recovered and re-verified by the orchestrator): two more
# single-line PATH-write spellings evaded both teeth — `readonly 'PATH'=…` /
# `readonly 'PATH'+=…` (the declaration branch listed declare/typeset/local/
# export only, and the raw backstop's quoted-span strip hid the quoted token)
# and `let 'PATH=5'` (arithmetic assignment; `let` was in no branch). Both
# runtime-proven: PATH becomes `/tmp/shad` / `5`, command lookup fails, and
# `systemctl` resolves into the crafted dir (or not at all) — the drain gate
# can report not-drained while the service is up (the r20/r21 HIGH class).
# Closed: `readonly` joins the declaration branch and a `let` branch matches
# an assignment-shaped `PATH[sub]+=` token (the existing quote/`$`-expansion
# strips run first, so quoted and `command`-prefixed forms are caught).
# Deliberate fail-closed over-refusal: a `let` arithmetic comparison
# (`let PATH == 5`) also matches.
#
# r23 red-team HIGH + MED (r22 delta re-check): two more run-time token
# rebuilders evaded the PATH tooth — locale quoting (`export $"PATH"=…`,
# `readonly $"PATH"=…`, `declare -g $"PATH"=…`, `let $"PATH"=5`,
# `printf -v $"PATH"`, `read $"PATH"`, `mapfile -t $"PATH"`, `unset $"PATH"`)
# and brace-comma expansion in an argument position (`export {PATH,x}=…`,
# `readonly {P,}ATH=…`, `let {PATH,x}=5`, `let PATH{,}=5`,
# `printf -v {P,}ATH`, `read {P,}ATH`, `mapfile -t {P,}ATH`), plus a nameref
# alias target (`declare -n p=PATH` then `p=…`); all suite-green and
# runtime-effective (PATH shadow → the drain gate subverts). Closed: the
# `$"` introducer is stripped before the token scan (`$$"` masked first so a
# PID variable survives), argument-position brace-comma groups are expanded
# textually (bounded: depth 6 / 64 variants per line; overflow refuses
# fail-closed) and each variant matched, and a nameref declaration whose
# target is PATH is refused. A command-word brace-comma (`{h,}ash`,
# `{t,}rap`, `{s,}leep()`) is NOT a gap: bash expands the alternatives as
# separate arguments of the first word — `{t,}rap …` installs `trap -- 'rap'
# …` (no handler subversion) and `{h,}ash -p …` invokes the hash builtin with
# a shifted name argument (no lookup poisoning) — so command lookup is
# unaffected (runtime-probed). Deliberate fail-closed over-refusals: a
# `declare x=PATH` (literal string assignment) and a brace-expansion
# overflow.
#
# r24 red-team + trust HIGH (r23 delta re-check): the r23 brace-comma closure
# was unsound — `expand_braces` omitted `post` from its local-parameter list,
# so recursion clobbered the global and every sibling alternative after the
# first got a truncated suffix (variants silently dropped; the 64-variant cap
# never fired: `export {x,}{PATH,x}=/tmp/shad`, the 7-group and nested
# payloads were suite-green and PATH-effective, and a 125-variant line was a
# suite-green cap-bypass carrier — no expansion of it is exactly `PATH`), and
# the depth
# guard returned "" without setting `expand_over`, so a deeply nested payload
# was dropped fail-open. The r23 nameref closure was also incomplete: a
# two-step target (`declare -n p` then `p=PATH` then `p=…`) evaded the
# same-line `[name]=PATH` regex. Closed: `post` is a function local, a
# depth-cap hit sets `expand_over` (the caller's `hit = expand_over` refuses
# fail-closed), and ANY nameref declaration is refused
# (`declare`/`typeset`/`local` with an option token containing `n`) — the
# shipped span has zero namerefs, so this is a deliberate fail-closed
# over-refusal (`declare -n foo=BAR` included); the one-line
# `declare -n p=PATH` target rule stays as a belt.
if awk -v q="'" '
  function normalize_cmdpos(s,   prev) {
    do {
      prev = s
      gsub(/(^|[;&|()!{}])[[:space:]]*(if|then|do|else|elif|while|until)([[:space:]]+)/, "; ", s)
      gsub(/(^|[;&|()!{}])[[:space:]]*time[[:space:]]+/, "; ", s)
      gsub(/(^|[;&|()!])[[:space:]]*\{[[:space:]]+/, "; ", s)
      gsub(/(^|[;&|()!{}])[[:space:]]*\}[[:space:]]*/, "; ", s)
    } while (s != prev)
    return s
  }
  function expand_braces(s, depth,   m, pre, grp, inner, alts, n, i, out, post) {
    if (depth > 6) { expand_over = 1; return "" }
    if (expand_over) return ""
    m = match(s, /\{[^{}]*,[^{}]*\}/)
    if (m == 0) return s "\n"
    pre = substr(s, 1, m - 1)
    grp = substr(s, m, RLENGTH)
    post = substr(s, m + RLENGTH)
    inner = substr(grp, 2, length(grp) - 2)
    n = split(inner, alts, ",")
    out = ""
    for (i = 1; i <= n; i++) {
      expand_count++
      if (expand_count > 64) { expand_over = 1; return "" }
      out = out expand_braces(pre alts[i] post, depth + 1)
    }
    return out
  }
  function path_write(s) {
    return (s ~ /(^|[;&|()!{}])[[:space:]]*PATH(\[[^]]*\])?\+?=/ ||
            s ~ /(^|[;&|()!{}])[[:space:]]*(export|unset)([[:space:]]+(-[A-Za-z]+|--))*[[:space:]]*PATH([^[:alnum:]_]|$)/ ||
            s ~ /(^|[;&|()!{}])[[:space:]]*printf[[:space:]]+-v[[:space:]]*PATH([^[:alnum:]_]|$)/ ||
            s ~ /(^|[;&|()!{}])[[:space:]]*read([[:space:]]+[^[:space:];&|]+)*[[:space:]]+PATH([^[:alnum:]_]|$)/ ||
            s ~ /(^|[;&|()!{}])[[:space:]]*(declare|typeset|local|export|readonly)([[:space:]]+(-[A-Za-z]+|--))*[[:space:]]+PATH([^[:alnum:]_]|$)/ ||
            s ~ /(^|[;&|()!{}])[[:space:]]*(mapfile|readarray)([[:space:]]+[^[:space:];&|]+)*[[:space:]]+PATH([^[:alnum:]_]|$)/ ||
            s ~ /(^|[;&|()!{}])[[:space:]]*let([[:space:]]+[^[:space:];&|]+)*[[:space:]]+PATH(\[[^]]*\])?[[:space:]]*\+?=/ ||
            s ~ /(^|[;&|()!{}])[[:space:]]*(declare|typeset|local)([[:space:]]+(-[A-Za-z]+|--))*[[:space:]]+[A-Za-z_][A-Za-z0-9_]*=PATH([^[:alnum:]_]|$)/ ||
            s ~ /(^|[;&|()!{}])[[:space:]]*(declare|typeset|local)([[:space:]]+(-[A-Za-z]+|--))*[[:space:]]+-[A-Za-z]*n[A-Za-z]*([[:space:]]+(-[A-Za-z]+|--))*[[:space:]]+[A-Za-z_][A-Za-z0-9_]*/ ||
            s ~ /(^|[;&|()!{}])[[:space:]]*(for|select)[[:space:]]+PATH([^[:alnum:]_]|$)/)
  }
  {
    line = $0
    # r23 red-team HIGH (r22 delta re-check): locale quoting `$"NAME"` expands
    # to NAME (bash translation); strip the introducer so the token is visible
    # (`$$"` is a PID variable plus a closing quote and must survive: mask `$$`
    # first). The shipped script has no real `$"` (one `...com$"` regex false
    # positive, harmless after the strip).
    gsub(/\$\$/, "\001", line)
    gsub(/\$"/, "", line)
    gsub("\001", "$$", line)
    gsub(/"/, "", line)
    gsub(q, "", line)
    gsub(/\\/, "", line)
    gsub(/\$\{[^}]*\}/, "", line)
    gsub(/\$[A-Za-z_][A-Za-z0-9_]*/, "", line)
    # r23 red-team HIGH (r22 delta re-check): brace-comma expansion in an
    # argument position (`export {PATH,x}=…`, `readonly {P,}ATH=…`,
    # `let {PATH,x}=5`, `printf -v {P,}ATH`, `read {P,}ATH`, `mapfile -t
    # {P,}ATH`) rebuilds the PATH token at run time; expand textually
    # (bounded, depth 6 / 64 variants) and match each variant. A command-word
    # brace-comma (`{h,}ash`) is NOT expanded this way by bash (the
    # alternatives become separate arguments of the first word — runtime-probed
    # ineffective), so this tooth only needs the argument-position class.
    # Overflow refuses fail-closed.
    expand_count = 0
    expand_over = 0
    nvar = split(expand_braces(line, 0), variants, "\n")
    hit = expand_over
    for (vi = 1; vi <= nvar; vi++) {
      v = variants[vi]
      do {
        if (path_write(v)) hit = 1
        prev = v
        gsub(/(^|[;&|()!{}])[[:space:]]*(builtin|command)([[:space:]]+-[^[:space:];&|]+)*[[:space:]]+/, "; ", v)
        gsub(/(^|[;&|()!{}])[[:space:]]*[A-Za-z_][A-Za-z0-9_]*(\[[^]]*\])?\+?=[^[:space:];&|]*[[:space:]]+/, "; ", v)
        v = normalize_cmdpos(v)
      } while (v != prev)
      if (path_write(v)) hit = 1
    }
    if (hit) {
      print FILENAME ":" FNR ": command-position PATH write on the no-quote-strip view: " $0 > "/dev/stderr"
      bad = 1
    }
  }
  END { exit bad ? 1 : 0 }
' "${PROVISION_CODE}"; then
  ok "run-once: no command-position PATH write is hidden behind quoted tokens, a \`builtin\`/\`command\` prefix, an array-writing builtin (\`mapfile\`/\`readarray\`), a \`readonly\` declaration, a \`let\` arithmetic assignment, a locale-quoted (\`$"PATH"\`) or brace-comma-expanded token, a nameref declaration, a reserved-word/\`!\` position, an append/subscript assignment prefix, a \`for\`/\`select\` loop-variable binding, or a multi-line quote desync (incl. \`unset -- PATH\` and quoted/\`declare\` forms, issue #143)"
else
  bad "run-once: a command-position PATH write (quoted token, \`builtin\`/\`command\` prefix, \`mapfile\`/\`readarray\`, \`unset -- PATH\`, \`declare -x PATH=…\`, a \`readonly\` declaration, a \`let\` arithmetic assignment, a locale-quoted (\`$"PATH"\`) or brace-comma-expanded token, a nameref declaration, a reserved-word/\`!\` position, an append/subscript assignment prefix, a \`for\`/\`select\` loop-variable binding, or a desync-hidden assignment) appeared in the provision script — a prepended shadow binary could misreport the drain state (issue #143)"
fi
# r11 red-team HIGH (V1) + r12 red-team HIGH: `hash -p /bin/true systemctl`
# (one line before the witness span) poisoned command lookup for every later
# `systemctl` call with no definition and no edit inside the rendered span:
# the suite stayed 536/0 while a fake systemctl reported the unit active and
# the drain returned "drained" at poll 0 (issue #143 fail-open). The first
# tooth matched the word `hash` only on the quote-stripped view, so the
# quote-concatenated / ANSI-C / escaped spellings bash joins before command
# lookup (`"ha""sh" -p …`, `$'hash' -p …`, `h\ash -p …`,
# `builtin h$'ash' …`) stayed suite-green (538/0). The closure: keep the
# stripped-view word match (plain `hash`, `hash ()`), and ADD a quote-joined
# view — remove the quote characters (`$'`/`$"` prefixes included) and
# backslashes — refusing `hash` at a command position
# (`(^|[;&|()])[[:space:]]*hash([^[:alnum:]_]|$)`) plus `builtin hash` /
# `command hash` (no such invocation exists in the script). Prose stays
# green: `die "cannot hash …"` (515/551/573), `log "… cert hash recorded …"`
# (1108), `origin_ca_write_hash`/`origin_ca_cert_hash` identifiers,
# `hashlib`/`hashed`/`_<hash16>` (none is at a command position). The script
# has no legitimate `hash` call. r13 red-team HIGH: the token was rebuilt
# with a parameter expansion (`x=` + `h${x}ash -p …`; the joined view had
# stripped only `$` and kept `h{x}ash`), which also left `en${x}able`-style
# spellings open. The closure also strips parameter expansions (`${…}` and
# `$name`) from the joined view before the command-position match, adds `!`
# to the command-position class, and refuses any ANSI-C `$'` quoting in code
# (the script has 0) so `$'\x68…'`/`$'hash'` cannot smuggle a command word;
# the next tooth refuses command-position `builtin`/`enable`/`trap`.
#
# r14 red-team/functional: the `joined` view stripped comments naively on
# the raw line, so `echo " # " ; $'\x68\x61\x73\x68' …` (and every other
# quoted-# decoy) truncated the `ansic` detection and left the joined match
# seeing `echo "`. The tooth now reads PROVISION_CODE (quote-aware comment
# stripping) and also refuses a `{…..…}` brace sequence in code
# (`{h..h}ash -p …` built the token with bash brace expansion) and
# normalizes the reserved-word separators before the command-position match
# (`if true; then h${x}ash …`; `time h\ash …` — the backslash-joined
# spelling rides the same class).
if awk -v q="'" '
  function normalize_cmdpos(s,   prev) {
    do {
      prev = s
      gsub(/(^|[;&|()!{}])[[:space:]]*(if|then|do|else|elif|while|until)([[:space:]]+)/, "; ", s)
      gsub(/(^|[;&|()!{}])[[:space:]]*time[[:space:]]+/, "; ", s)
      gsub(/(^|[;&|()!])[[:space:]]*\{[[:space:]]+/, "; ", s)
      gsub(/(^|[;&|()!{}])[[:space:]]*\}[[:space:]]*/, "; ", s)
    } while (s != prev)
    return s
  }
  {
    line = $0
    gsub(/"[^"]*"/, "", line)
    gsub(q "[^" q "]*" q, "", line)
    joined = $0
    ansic = (index(joined, "$" q) > 0)
    gsub(/\$\{[^}]*\}/, "", joined)
    gsub(/\$[A-Za-z_][A-Za-z0-9_]*/, "", joined)
    gsub(/[$"]/, "", joined)
    gsub(q, "", joined)
    gsub(/\\/, "", joined)
    joined = normalize_cmdpos(joined)
    if (ansic ||
        line ~ /(^|[^[:alnum:]_])hash([^[:alnum:]_]|$)/ ||
        line ~ /BASH_CMDS/ ||
        joined ~ /BASH_CMDS/ ||
        line ~ /(^|[^[:alnum:]_])(declare|typeset|local)[[:space:]]+-[A-Za-z]*A[A-Za-z]*([^[:alnum:]_]|$)/ ||
        joined ~ /(^|[^[:alnum:]_])(declare|typeset|local)[[:space:]]+-[A-Za-z]*A[A-Za-z]*([^[:alnum:]_]|$)/ ||
        line ~ /\{[^{}]*\.\.[^{}]*\}/ ||
        joined ~ /(^|[;&|()!])[[:space:]]*hash([^[:alnum:]_]|$)/ ||
        joined ~ /(^|[^[:alnum:]_])(builtin|command)[[:space:]]+hash([^[:alnum:]_]|$)/) {
      print FILENAME ":" FNR ": hash invocation: " $0 > "/dev/stderr"
      bad = 1
    }
  }
  END { exit bad ? 1 : 0 }
' "${PROVISION_CODE}"; then
  ok "run-once: no \`hash\` command-lookup poisoning (plain, parameter-expansion-rebuilt, brace-sequence, reserved-word-separated or quote-joined/ANSI-C/escaped spelling at a command position, incl. \`builtin\`/\`command hash\`) in the provision script (issue #143)"
else
  bad "run-once: a \`hash\` command-lookup poisoning spelling appeared in the provision script — plain, parameter-expansion-rebuilt, brace-sequence, reserved-word-separated, quote-concatenated/ANSI-C/escaped at a command position, or \`builtin\`/\`command hash\`; the script has no legitimate \`hash\` call (issue #143)"
fi
# r13 red-team HIGH 2/3: `enable -n exit` disables the `exit` builtin — with
# a `command_not_found_handle` definition the at-bound `die`'s `exit 1` hit
# the handler and returned 0, so `wait_idle` declared a live unit drained;
# `builtin enable -n exit` and `command enable -n exit` reach the same builtin
# and `trap 'exit 0' EXIT` rewrites the process rc. The shipped script never
# invokes `enable` at a command position (its `enable` occurrences are
# `systemctl enable --now …` subcommands — `enable` sits after `systemctl`),
# never invokes `builtin`, and its only `trap` invocations are the two pinned
# acceptance forms (`trap 'recording_witness_timer_start' EXIT`,
# `trap - EXIT`; main-sync fold 2026-10-06 — #153's timer stop/start); refuse
# everything else (plus `command`-prefixed spellings) at a command position
# on the expansion-stripped joined view, so `en${x}able`/`builtin h${x}ash`
# are caught too. Deliberate over-refusal (fail-closed).
#
# r14 red-team: the same quoted-# decoy (`echo " # " ; trap …`) truncated
# this view before the match, and the position class missed a command after
# a reserved-word separator (`if true; then trap …`, `{ trap …; }`,
# `time trap …`). The tooth now reads PROVISION_CODE (quote-aware comment
# stripping) and runs the reserved-word normalizer before the match, so
# `then`/`do`/`else`/`elif`/`time`/`{`/`}` all count as command positions.
#
# r19 red-team HIGH + functional MED (delta re-check): the main-sync allowlist
# collapsed a brace-less `$name` to its name — `trap "$…timer_start" EXIT`
# (value `…; :`) read as the pinned literal and ran an arbitrary EXIT action —
# and the deny branch missed repeated `command` prefixes
# (`command command trap …`, `command -p command trap …`); an assignment word
# (`FOO=bar trap …`) was the same position-class gap. Closed in place: the
# allowlist view no longer strips `$`, and the deny view strips
# `command`/assignment prefixes iteratively before the match.
#
# r20 red-team HIGH (delta re-check): the r19 assignment strip matched only
# `NAME=`, so append/subscript prefixes (`FOO+=bar trap 'exit 0' EXIT`,
# `FOO[0]=bar trap …`, `A[0]=1 trap …`) still shifted the verb past the
# position class (pre-existing; runtime rc-rewrite probe confirmed). The strip
# now matches `NAME(\[sub\])?+=`. (An assignment whose quoted value contains
# whitespace — `FOO="a b" trap …` — stays in the disclosed crafted-edit
# class, like the PATH tooth's and the `${IFS}` separators.)
if awk -v q="'" '
  function normalize_cmdpos(s,   prev) {
    do {
      prev = s
      gsub(/(^|[;&|()!{}])[[:space:]]*(if|then|do|else|elif|while|until)([[:space:]]+)/, "; ", s)
      gsub(/(^|[;&|()!{}])[[:space:]]*time[[:space:]]+/, "; ", s)
      gsub(/(^|[;&|()!])[[:space:]]*\{[[:space:]]+/, "; ", s)
      gsub(/(^|[;&|()!{}])[[:space:]]*\}[[:space:]]*/, "; ", s)
    } while (s != prev)
    return s
  }
  {
    line = $0
    gsub(/\$\{[^}]*\}/, "", line)
    gsub(/\$[A-Za-z_][A-Za-z0-9_]*/, "", line)
    gsub(/[$"]/, "", line)
    gsub(q, "", line)
    gsub(/\\/, "", line)
    line = normalize_cmdpos(line)
    # r19 red-team HIGH: a repeated `command` prefix (`command command trap
    # …`, `command -p command trap …`) shifted the verb past the single
    # `command` branch, and an assignment word (`FOO=bar trap …`) shifted it
    # past the position class; both ran an arbitrary EXIT trap with every
    # static tooth green (the crafted line is in-span — it can replace the
    # shipped trap). Strip `command` prefixes (with their options) and
    # assignment words at a command position, iterating with the
    # reserved-word normalizer like the PATH tooth (r18), so the verb lands
    # where the deny branch matches.
    do {
      prev = line
      gsub(/(^|[;&|()!{}])[[:space:]]*command([[:space:]]+-[^[:space:];&|]+)*[[:space:]]+/, "; ", line)
      gsub(/(^|[;&|()!{}])[[:space:]]*[A-Za-z_][A-Za-z0-9_]*(\[[^]]*\])?\+?=[^[:space:];&|]*[[:space:]]+/, "; ", line)
      line = normalize_cmdpos(line)
    } while (line != prev)
    # main-sync fold (2026-10-06, PR #156): the merged #153 acceptance
    # installs and clears its EXIT trap, so pin exactly those two shipped
    # forms (anchored: a combined or rewritten line stays refused). The
    # allowlist reads a quote/backslash-stripped, expansion-PRESERVED view
    # (r18 red-team HIGH + functional LOW): the main view drops `${x}`/`$x`,
    # so an expansion-rebuilt action or sigspec would read as the pinned
    # form while its runtime effect is attacker-controlled (`x="; exit 0; :"`
    # rewrites the process rc; a substitution runs arbitrary root commands).
    # `$` is never stripped from this view (r19 functional MED + red-team
    # HIGH): stripping it glued a brace-less `$name` onto the pinned word
    # (`trap "recording_witness_timer_$start" EXIT` read as the literal
    # action), so a braced (`${x}`), brace-less (`$start`, incl. a rebuilt
    # sigspec `EX$IT`) or command-substitution spelling stays visible and
    # fails the anchored match. The shipped lines carry no expansion.
    pinned_view = $0
    gsub(/"/, "", pinned_view)
    gsub(q, "", pinned_view)
    gsub(/\\/, "", pinned_view)
    pinned_trap = (pinned_view ~ /^[[:space:]]*trap[[:space:]]+recording_witness_timer_start[[:space:]]+EXIT[[:space:]]*$/ ||
                   pinned_view ~ /^[[:space:]]*trap[[:space:]]+-[[:space:]]+EXIT[[:space:]]*$/)
    if (!pinned_trap &&
        (line ~ /(^|[;&|()!])[[:space:]]*(builtin|enable|trap|eval)([^[:alnum:]_]|$)/ ||
         line ~ /(^|[;&|()!])[[:space:]]*command[[:space:]]+(builtin|enable|trap|eval)([^[:alnum:]_]|$)/)) {
      print FILENAME ":" FNR ": command-position builtin/enable/trap/eval invocation: " $0 > "/dev/stderr"
      bad = 1
    }
  }
  END { exit bad ? 1 : 0 }
' "${PROVISION_CODE}"; then
  ok "run-once: no command-position \`builtin\`/\`enable\`/\`trap\`/\`eval\` invocation (incl. after reserved-word separators; the two pinned acceptance trap forms are allowed) in the provision script (the rc-path builtins stay reachable, issue #143)"
else
  bad "run-once: a command-position \`builtin\`/\`enable\`/\`trap\`/\`eval\` invocation (incl. after a reserved-word separator; outside the two pinned acceptance trap forms) appeared in the provision script — it could disable the \`exit\` builtin, rewrite the process rc, or eval a shadow definition (issue #143)"
fi
# r13 red-team MED: the script runs as root and can prepend a shadow dir to
# `PATH`, planting a `systemctl` (or `sleep`) binary that misreports state —
# the r12 wording claimed that needs "a root-level PATH write (out of scope)",
# false for a self-editing root script. The shipped script never assigns,
# exports or unsets `PATH` (the word appears in comments only); refuse
# `PATH=`, `PATH+=`, `export PATH` and `unset PATH` in code.
#
# r14 red-team/functional: the same quoted-# decoy hid a `PATH=` assignment,
# the quote-blind view falsely refused the shipped prose (`log
# "PATH=${PATH}"`, `log "export PATH and unset PATH here"`), and the builtin
# assignment forms (`printf -v PATH …`, `read -r PATH …`) slipped through.
# The tooth now reads PROVISION_CODE (quote-aware comment stripping), drops
# quoted spans (so quoted prose is not code), and adds the `printf -v PATH`
# and `read … PATH` forms.
# r21 red-team HIGH (delta re-check): the raw backstop's `PATH=` branch also
# missed the array-element form (`PATH[0]=`/`PATH[0]+=`); it now matches
# `PATH(\[sub\])?+=` and accepts `--` in the declare/nameref option class.
# (The cmdpos tooth carries the full r21 closure; this view stays a subset.)

if awk -v q="'" '
  {
    line = $0
    # r23: same locale normalization as the cmdpos tooth (see there).
    gsub(/\$\$/, "\001", line)
    gsub(/\$"/, "", line)
    gsub("\001", "$$", line)
    gsub(/"[^"]*"/, "", line)
    gsub(q "[^" q "]*" q, "", line)
    if (line ~ /(^|[^[:alnum:]_])PATH(\[[^]]*\])?\+?=/ ||
        line ~ /(^|[^[:alnum:]_])export[[:space:]]+PATH([^[:alnum:]_]|$)/ ||
        line ~ /(^|[^[:alnum:]_])unset([[:space:]]+-[A-Za-z]+)*[[:space:]]+PATH([^[:alnum:]_]|$)/ ||
        line ~ /(^|[^[:alnum:]_])printf[[:space:]]+-v[[:space:]]*PATH([^[:alnum:]_]|$)/ ||
        line ~ /(^|[^[:alnum:]_])(declare|typeset|local|export)([[:space:]]+(-[A-Za-z]+|--))*[[:space:]]+-[A-Za-z]*n[A-Za-z]*[[:space:]]+PATH([^[:alnum:]_]|$)/ ||
        line ~ /(^|[^[:alnum:]_])read([[:space:]]+[^[:space:];&|]+)*[[:space:]]+PATH([^[:alnum:]_]|$)/) {
      print FILENAME ":" FNR ": PATH assignment/export/unset: " $0 > "/dev/stderr"
      bad = 1
    }
  }
  END { exit bad ? 1 : 0 }
' "${PROVISION_CODE}"; then
  ok "run-once: no \`PATH\` assignment/export/unset (incl. \`printf -v PATH\`/\`printf -vPATH\`/\`read … PATH\`/nameref/\`unset -v PATH\` forms) in the provision script (issue #143)"
else
  bad "run-once: a \`PATH\` assignment/export/unset or builtin/nameref assignment (\`printf -v PATH\`/\`printf -vPATH\`/\`read … PATH\`/\`declare -n PATH\`/\`unset -v PATH\`) appeared in the provision script — a prepended shadow binary could misreport the drain state (issue #143)"
fi
# r11 red-team HIGH (V4/V5): a command-word substitution redirected a drain
# path invocation with no definition to count: `WITNESS_SYSTEMCTL=/bin/true`
# plus `"${WITNESS_SYSTEMCTL:-systemctl}"` in
# recording_witness_service_drained, and `WITNESS_DIE=:` plus
# `"${WITNESS_DIE:-die}"` at the at-bound call — both suite-green (536/0)
# with the unit active (issue #143 fail-open). Pin the shipped source of both
# invocations exactly: the six body lines of recording_witness_service_drained
# (the local, the systemctl query, the case decision and its arms) and the
# at-bound die line; the paren-form header must appear exactly once, so a
# header respelling (e.g. the `function NAME` keyword form) is refused too.
# Any intended edit to these lines must update this pin (the shipped source
# is the spec); fail-closed over-refusal is deliberate.
if awk '
  BEGIN {
    want[1] = "  local active"
    want[2] = "  active=\"$(systemctl show pc-recording-witness.service -p ActiveState --value 2>/dev/null || true)\""
    want[3] = "  case \"${active}\" in"
    want[4] = "    \"\"|inactive|failed) return 0 ;;"
    want[5] = "    *) return 1 ;;"
    want[6] = "  esac"
    want[7] = "}"
    nwant = 7
    die_line = "  die \"witness unit did not drain within 3600s (ActiveState=${active:-unknown}) — an invocation is in flight and cannot be attributed to this run-once (issue #143); refusing to continue with a possibly merged run\""
  }
  FNR == 1 {
    if (in_body) {
      print file ": recording_witness_service_drained body not terminated by the pinned `}`" > "/dev/stderr"
      badfile[file] = 1
    }
    file = FILENAME; seen[file] = 1; in_body = 0; i = 0
  }
  {
    if (in_body) {
      i++
      if (i > nwant || $0 != want[i]) {
        print file ":" FNR ": drain-path body diverges from the pinned source at line " i ": " $0 > "/dev/stderr"
        badfile[file] = 1
      }
      if (i >= nwant) in_body = 0
      next
    }
    line = $0
    sub(/^[[:space:]]*#.*/, "", line)
    if (line ~ /(^|[^[:alnum:]_])recording_witness_service_drained[[:space:]]*[(][[:space:]]*[)][[:space:]]*[{]/) {
      h[file]++; in_body = 1; i = 0; next
    }
    if ($0 == die_line) d[file]++
  }
  END {
    bad = 0
    for (f in seen) {
      if (h[f] != 1) { print f ": recording_witness_service_drained paren-form headers: " h[f] + 0 " (expected 1)" > "/dev/stderr"; bad = 1 }
      if (badfile[f]) bad = 1
      if (d[f] != 1) { print f ": at-bound die invocation lines: " d[f] + 0 " (expected 1)" > "/dev/stderr"; bad = 1 }
    }
    exit bad ? 1 : 0
  }
' "${PROVISION}" "${PROVISION_JOINED}"; then
  ok "run-once: the \`recording_witness_service_drained\` body and the at-bound \`die\` invocation match the pinned drain-path source (issue #143)"
else
  bad "run-once: a drain-path invocation was redirected (systemctl query, state decision, or the at-bound die call) or the pinned source diverged — an intended edit must update the pin (issue #143)"
fi
case "${runonce_out}" in
  *"refusing to continue with a possibly merged run"*) ok "run-once names the continue-refusal wording" ;;
  *) bad "run-once non-drain wording: ${runonce_out}" ;;
esac
unset FAKE_ACTIVE_STATE FAKE_ACTIVE_POLL_FILE FAKE_ACTIVE_POLL_SLEEP_FILE FAKE_SLEEP_COUNT_FILE FAKE_SLEEP_ARGS_FILE FAKE_SLEEP_NOWAIT
unset -f sleep systemctl

# The unit ran (InvocationID advanced) but could not persist state.json:
# reading the old state would still be stale, so the updated_at check dies.
seed_state ok "$(fresh_stamp)"
unset FAKE_START_RC
export FAKE_EXEC_STATUS=0
export FAKE_NO_STATE_WRITE=1
run_once_call
is "run-once: rc=0 + state not advanced dies" "1" "${runonce_rc}"
case "${runonce_out}" in
  *"did not advance"*) ok "run-once freshness gate names the unadvanced state" ;;
  *) bad "run-once unadvanced-state output: ${runonce_out}" ;;
esac
unset FAKE_NO_STATE_WRITE

# Round-10 NIT: an explicit repair written by THIS invocation resets run_seq
# to 1, which can equal the value jq still read off the unreadable record.
# The repair must count as progress evidence so the acceptance reads the real
# ERROR verdict instead of mis-filing it as a stale state (and the error
# verdict still fails the run closed).
seed_state error "$(fresh_stamp)" 1
unset FAKE_START_RC
unset FAKE_NO_STATE_WRITE
export FAKE_EXEC_STATUS=2
export FAKE_REPAIR_STATE=1
run_once_call
is "run-once: in-invocation repair (run_seq reset) reaches the ERROR verdict" "1" "${runonce_rc}"
case "${runonce_out}" in
  *"witness verdict: ERROR"*) ok "run-once counts this invocation's explicit repair as progress" ;;
  *) bad "run-once did not surface the repair ERROR verdict: ${runonce_out}" ;;
esac
case "${runonce_out}" in
  *"did not advance"*) bad "run-once mis-filed a genuine repair as a stale state" ;;
  *) ok "run-once does not mis-file a genuine repair as a stale state" ;;
esac
unset FAKE_REPAIR_STATE

# Round-12 F1: a repair verdict is always `error`; the gate enforces that
# instead of trusting the writer, so a fault-injected record that combines
# `repaired` + this run's invocation + a non-error verdict (run_seq held at 1,
# exactly like a repair) must die at the freshness gate — never print OK.
seed_state error "$(fresh_stamp)" 1
unset FAKE_START_RC
unset FAKE_NO_STATE_WRITE
export FAKE_EXEC_STATUS=0
export FAKE_REPAIR_STATE=1
export FAKE_REPAIR_VERDICT=ok
run_once_call
is "run-once: repaired non-error record dies (repair must surface an error verdict)" "1" "${runonce_rc}"
case "${runonce_out}" in
  *"witness verdict: OK"*) bad "run-once accepted a repaired non-error record as OK" ;;
  *) ok "run-once refuses a repaired non-error record (no OK)" ;;
esac
case "${runonce_out}" in
  *"did not advance"*) ok "run-once names the unadvanced non-error repair" ;;
  *) bad "run-once non-error repair output: ${runonce_out}" ;;
esac
unset FAKE_REPAIR_STATE FAKE_REPAIR_VERDICT

# Round-13 F1: the round-12 gate sat only inside the run_seq-equality branch,
# so when the PRIOR run_seq did not render as the same non-empty string — an
# unreadable state.json (""), a missing run_seq, "01", 1.0, -1, true — the
# outer advancement check passed and a fault-injected `repaired` + ok/alert
# record bound to THIS invocation was accepted; a hostile writer can also
# simply advance the counter (5 -> 6). The repair-error invariant is enforced
# after advancement now, so every shape must die with no OK/ALERT verdict.
repaired_bypass_case() { # $1 label, $2 before state.json body, $3 repair verdict, $4 repair run_seq, $5 EMS
  printf '%s\n' "$2" >"${WORK}/state/state.json"
  before_render="$(jq -r '.run_seq // ""' "${WORK}/state/state.json" 2>/dev/null || true)"
  unset FAKE_START_RC FAKE_NO_STATE_WRITE FAKE_NEW_UPDATED_AT
  export FAKE_EXEC_STATUS="$5" FAKE_REPAIR_STATE=1 FAKE_REPAIR_VERDICT="$3" FAKE_REPAIR_RUN_SEQ="$4"
  run_once_call
  is "run-once: ${1} dies (a repair can only carry error)" "1" "${runonce_rc}"
  case "${runonce_out}" in
    *"witness verdict: OK"*|*"witness verdict: ALERT"*) bad "run-once accepted ${1}" ;;
    *) ok "run-once refuses ${1} (no OK/ALERT verdict)" ;;
  esac
  # On the non-collision path (the bypass class) the dedicated enforcement
  # message must fire; a jq that renders the prior value equal to the repair
  # counter instead dies at the older freshness gate, which the rc/no-verdict
  # teeth above still cover.
  if [ "$4" != "${before_render}" ]; then
    case "${runonce_out}" in
      *"no trustworthy verdict"*) ok "run-once names the forged repair (${1})" ;;
      *) bad "run-once forged-repair output (${1}): ${runonce_out}" ;;
    esac
  fi
}
repaired_bypass_case "prior state unreadable (empty run_seq) + repaired ok" 'not json at all' ok 1 0
repaired_bypass_case "prior run_seq missing + repaired alert" '{"state":"ok","detail":"x","updated_at":"t"}' alert 1 1
repaired_bypass_case 'prior run_seq "01" + repaired ok' '{"state":"error","detail":"x","updated_at":"t","run_seq":"01"}' ok 1 0
repaired_bypass_case "prior run_seq 1.0 + repaired ok" '{"state":"error","detail":"x","updated_at":"t","run_seq":1.0}' ok 1 0
repaired_bypass_case "prior run_seq -1 + repaired ok" '{"state":"error","detail":"x","updated_at":"t","run_seq":-1}' ok 1 0
repaired_bypass_case "prior run_seq true + repaired ok" '{"state":"error","detail":"x","updated_at":"t","run_seq":true}' ok 1 0
repaired_bypass_case "hostile advance 5 -> 6 + repaired ok" '{"state":"error","detail":"x","updated_at":"t","run_seq":5}' ok 6 0
unset FAKE_REPAIR_STATE FAKE_REPAIR_VERDICT FAKE_REPAIR_RUN_SEQ

# ...but the stale-gate protection stays intact: a repair marker left by a
# PREVIOUS invocation must not cover a run that never persisted state.json.
seed_repair_state "inv-previous"
export FAKE_EXEC_STATUS=0
export FAKE_NO_STATE_WRITE=1
run_once_call
is "run-once: stale repair + failed state write still dies" "1" "${runonce_rc}"
case "${runonce_out}" in
  *"did not advance"*) ok "run-once refuses a stale repair marker from a previous invocation" ;;
  *) bad "run-once accepted a stale repair marker: ${runonce_out}" ;;
esac
unset FAKE_NO_STATE_WRITE

# A genuine run longer than the old +/-300 s recency window: the state it
# wrote is older than 300 s, but its per-run identity moved — accepted.
# Advancement, not recency, is the rule (round-3 F1).
seed_state ok "2026-09-25T00:00:00Z"
export FAKE_NEW_UPDATED_AT="2026-09-25T00:00:01Z"
run_once_call
is "run-once: >300s run accepted (advancement, not recency)" "0" "${runonce_rc}"
case "${runonce_out}" in
  *"witness verdict: OK"*) ok "run-once accepts a slow run's advanced state" ;;
  *) bad "run-once slow-run output: ${runonce_out}" ;;
esac
unset FAKE_NEW_UPDATED_AT

# Same-second double run (round-4 LOW 2): updated_at is second-resolution, so
# the second run can stamp the identical value; the freshness gate must key on
# run_seq, not the timestamp, or a genuine run dies as "state did not advance".
seed_state ok "2026-09-25T00:00:00Z" 41
export FAKE_NEW_UPDATED_AT="2026-09-25T00:00:00Z"
run_once_call
is "run-once: same-second run accepted (run_seq advanced, updated_at identical)" "0" "${runonce_rc}"
case "${runonce_out}" in
  *"witness verdict: OK"*) ok "run-once accepts the same-second run whose only advancement is run_seq" ;;
  *) bad "run-once same-second output: ${runonce_out}" ;;
esac
unset FAKE_NEW_UPDATED_AT

# state and ExecMainStatus must agree: the paired gate can pass while the
# recorded state contradicts the status (seeded tests used state==EMS, so a
# mutation that ignored `state` stayed green — round-3 F3b).
seed_state ok "$(fresh_stamp)"
export FAKE_EXEC_STATUS=1
run_once_call
is "run-once: state ok + ExecMainStatus=1 dies" "1" "${runonce_rc}"
case "${runonce_out}" in
  *"witness verdict: ALERT"*) bad "run-once mapped EMS=1 to ALERT despite state=ok" ;;
  *) ok "run-once refuses a state/ExecMainStatus mismatch (ok:1)" ;;
esac

seed_state alert "$(fresh_stamp)"
export FAKE_EXEC_STATUS=0
run_once_call
is "run-once: state alert + ExecMainStatus=0 dies" "1" "${runonce_rc}"
case "${runonce_out}" in
  *"witness verdict: OK"*) bad "run-once mapped EMS=0 to OK despite state=alert" ;;
  *) ok "run-once refuses a state/ExecMainStatus mismatch (alert:0)" ;;
esac

# Timer-stop acceptance: stop the timer, run one synchronous check, start the
# timer again; the EXIT trap must restart the timer on BOTH exit paths so a
# failed acceptance never leaves monitoring silently stopped. The mocked
# systemctl records stop/start calls; the sequence of timer calls is the
# load-bearing evidence (a stop without a restart fails both teeth).
: >"${FAKE_SYSTEMCTL_LOG}"
seed_state ok "$(fresh_stamp)"
unset FAKE_START_RC FAKE_NO_STATE_WRITE FAKE_NO_INVOCATION_BUMP FAKE_REPAIR_STATE FAKE_REPAIR_VERDICT FAKE_REPAIR_RUN_SEQ FAKE_MERGE_FIRST_START FAKE_RETRY_NO_STATE_WRITE
export FAKE_EXEC_STATUS=0
accept_rc=0
(recording_witness_accept) >"${WORK}/accept-ok.out" 2>&1 || accept_rc=$?
is "timer-stop acceptance: an ok run exits 0" "0" "${accept_rc}"
timer_cmds="$(grep -E '^(stop|start) pc-recording-witness.timer$' "${FAKE_SYSTEMCTL_LOG}" | tr '\n' ',')"
is "timer-stop acceptance: stop then start the timer in order" \
  "stop pc-recording-witness.timer,start pc-recording-witness.timer," "${timer_cmds}"

# Both-path restart: an error verdict makes run-once die; the trap must still
# start the timer before the process exits.
: >"${FAKE_SYSTEMCTL_LOG}"
seed_state error "$(fresh_stamp)"
export FAKE_EXEC_STATUS=2
accept_rc=0
(recording_witness_accept) >"${WORK}/accept-error.out" 2>&1 || accept_rc=$?
is "timer-stop acceptance: an error verdict fails closed" "1" "${accept_rc}"
timer_cmds="$(grep -E '^(stop|start) pc-recording-witness.timer$' "${FAKE_SYSTEMCTL_LOG}" | tr '\n' ',')"
is "timer-stop acceptance: the failing path still restarts the timer" \
  "stop pc-recording-witness.timer,start pc-recording-witness.timer," "${timer_cmds}"
case "$(cat "${WORK}/accept-error.out")" in
  *"witness verdict: ERROR"*) ok "timer-stop acceptance surfaces the ERROR verdict" ;;
  *) bad "timer-stop acceptance error output: $(cat "${WORK}/accept-error.out")" ;;
esac
unset FAKE_EXEC_STATUS

# ---- (j) ntfy transitions / recovery / renotify (fake notifier) ----------
py_begin="$(grep -n "exec python3 - <<'RECORDING_WITNESS_PY_EOF'" "${PROVISION}" | cut -d: -f1)"
py_end="$(grep -n '^RECORDING_WITNESS_PY_EOF$' "${PROVISION}" | cut -d: -f1)"
if [ -n "${py_begin}" ] && [ -n "${py_end}" ] && [ "${py_begin}" -lt "${py_end}" ]; then
  sed -n "$((py_begin + 1)),$((py_end - 1))p" "${PROVISION}" >"${WORK}/witness_module.py"
fi
if [ -s "${WORK}/witness_module.py" ] && python3 - "${WORK}" <<'PY'
import datetime
import importlib.util
import json
import os
import sys
import types

work = sys.argv[1]
spec = importlib.util.spec_from_file_location("witness_module", os.path.join(work, "witness_module.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

now = 1_800_000_000
SIG_A = "sha256:" + "a" * 64
SIG_B = "sha256:" + "b" * 64
# Raw helper invariants: fixtures happen to feed sorted inputs, so pin order
# independence directly, and pin the state entering the digest.
if module.identity_digest(["b", "a"]) != module.identity_digest(["a", "b"]):
    raise SystemExit("identity_digest must be order-independent")
if module.finding_signature("alert", ["z", "a"]) != module.finding_signature("alert", ["a", "z"]):
    raise SystemExit("finding_signature must be order-independent")
if module.finding_signature("alert", []) == module.finding_signature("ok", []):
    raise SystemExit("the state must enter the finding signature")
if module.finding_signature("error", []) == module.finding_signature("ok", []):
    raise SystemExit("the state must enter the finding signature")
for label, actual, expected in [
    ("first non-green pushes", module.should_notify(None, 0, "alert", now, 1800), True),
    ("repeat inside window suppresses", module.should_notify("alert", now - 100, "alert", now, 1800), False),
    ("1799s suppressed", module.should_notify("alert", now - 1799, "alert", now, 1800), False),
    ("1800s renotifies", module.should_notify("alert", now - 1800, "alert", now, 1800), True),
    ("recovery pushes", module.should_notify("alert", now - 1, "ok", now, 1800), True),
    ("steady ok never pushes", module.should_notify("ok", now - 1, "ok", now, 1800), False),
    ("first ok never pushes", module.should_notify(None, 0, "ok", now, 1800), False),
    ("failed recovery retries while the recovery run is newer than the last notified run",
     module.should_notify("ok", now - 100, "ok", now, 1800, 41, 40), True),
    ("landed recovery does not re-push",
     module.should_notify("ok", now - 50, "ok", now, 1800, 41, 41), False),
    ("same-second recovery transition (notify + transition in one second) still retries",
     module.should_notify("ok", now, "ok", now, 1800, 41, 40), True),
    ("same-second landed recovery does not re-push",
     module.should_notify("ok", now, "ok", now, 1800, 41, 41), False),
    ("legacy state without run identity does not re-push",
     module.should_notify("ok", now - 1, "ok", now, 1800, 0, 0), False),
    ("first ok never pushes even with a fresh transition run",
     module.should_notify(None, 0, "ok", now, 1800, 99, 0), False),
    ("future last_notify_epoch (clock stepped ahead) still renotifies",
     module.should_notify("alert", now + 86400, "alert", now, 1800), True),
    ("a changed finding signature pushes inside the window",
     module.should_notify("alert", now - 100, "alert", now, 1800, 0, 0, SIG_B, SIG_A), True),
    ("an unchanged signature stays inside the window",
     module.should_notify("alert", now - 100, "alert", now, 1800, 0, 0, SIG_A, SIG_A), False),
    ("a pinned signature quiets to the quiet window",
     module.should_notify("alert", now - 1799, "alert", now, 1800, 0, 0, SIG_A, SIG_A, SIG_A, 86400), False),
    ("a pinned signature renotifies after the quiet window",
     module.should_notify("alert", now - 86400, "alert", now, 1800, 0, 0, SIG_A, SIG_A, SIG_A, 86400), True),
    ("an unpinned signature keeps the default window",
     module.should_notify("alert", now - 1800, "alert", now, 1800, 0, 0, SIG_B, SIG_B, SIG_A, 86400), True),
    ("an unpinned signature stays inside the default window",
     module.should_notify("alert", now - 1799, "alert", now, 1800, 0, 0, SIG_B, SIG_B, SIG_A, 86400), False),
    ("a pinned signature that changed still pushes immediately",
     module.should_notify("alert", now - 100, "alert", now, 1800, 0, 0, SIG_B, SIG_A, SIG_A, 86400), True),
    ("a pinned non-green transition still pushes",
     module.should_notify("ok", now - 100, "alert", now, 1800, 0, 0, SIG_A, SIG_A, SIG_A, 86400), True),
    ("an empty signature skips the change-trigger",
     module.should_notify("alert", now - 100, "alert", now, 1800, 0, 0, "", "", "", 86400), False),
    ("the fixed error digest is never quieted",
     module.should_notify("error", now - 1800, "error", now, 1800, 0, 0,
                          module.finding_signature("error", []),
                          module.finding_signature("error", []),
                          module.finding_signature("error", []), 86400), True),
]:
    if actual is not expected:
        raise SystemExit("should_notify %s: expected %r got %r" % (label, expected, actual))

# Config defaults, bounds and pin validation are behavior, not decoration.
# The six required values are set for these checks only, then restored.
config_env = {
    "RECORDING_WITNESS_ENDPOINT": "http://127.0.0.1:9",
    "RECORDING_WITNESS_BUCKET": "pc-admin-dr",
    "RECORDING_WITNESS_AUDIT_PREFIX": "audit/",
    "RECORDING_WITNESS_RECORDINGS_PREFIX": "recordings/",
    "RECORDING_WITNESS_KEY_ID": "k",
    "RECORDING_WITNESS_KEY": "s",
}
config_knobs = ["RECORDING_WITNESS_RENOTIFY_SECONDS", "RECORDING_WITNESS_QUIET_RENOTIFY_SECONDS",
                "RECORDING_WITNESS_QUIET_SIGNATURE"]
saved_env = {name: os.environ.get(name) for name in list(config_env) + config_knobs}
os.environ.update(config_env)
for name in config_knobs:
    os.environ.pop(name, None)
config = module.Config()
if config.renotify != 1800 or config.quiet_renotify != 86400:
    raise SystemExit("window defaults wrong: %r %r" % (config.renotify, config.quiet_renotify))
config_logs = []
real_log = module.log
module.log = config_logs.append
os.environ["RECORDING_WITNESS_RENOTIFY_SECONDS"] = "0"
if module.Config().renotify != 1800:
    raise SystemExit("an out-of-range renotify window must fall back to the default")
os.environ["RECORDING_WITNESS_QUIET_RENOTIFY_SECONDS"] = "999999999"
if module.Config().quiet_renotify != 86400:
    raise SystemExit("an out-of-range quiet window must fall back to the default")
os.environ.pop("RECORDING_WITNESS_RENOTIFY_SECONDS")
os.environ.pop("RECORDING_WITNESS_QUIET_RENOTIFY_SECONDS")
if not any("outside [60, 7776000]" in entry for entry in config_logs):
    raise SystemExit("an out-of-range window must warn")
# Python's `$` also matches before a trailing newline: a full-string match is
# what keeps a newline-suffixed pin from being accepted-but-never-matching.
os.environ["RECORDING_WITNESS_QUIET_SIGNATURE"] = SIG_A + "\n"
config = module.Config()
if config.quiet_signature:
    raise SystemExit("a trailing-newline pin must not validate")
if not any("quiet signature is malformed" in entry for entry in config_logs):
    raise SystemExit("a malformed pin must warn")
if any(SIG_A in entry for entry in config_logs):
    raise SystemExit("the malformed-pin warning must not echo the value")
os.environ.pop("RECORDING_WITNESS_QUIET_SIGNATURE")
module.log = real_log
for name, value in saved_env.items():
    if value is None:
        os.environ.pop(name, None)
    else:
        os.environ[name] = value

captured = []


class Response:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class FakeOpener:
    """Stands in for module._NTFY_OPENER; every notify POST goes through it."""

    def __init__(self, hook):
        self.hook = hook

    def open(self, request, timeout=None):
        return self.hook(request, timeout)


def fake_urlopen(request, timeout=None):
    captured.append(request)
    return Response()


REAL_NTFY_OPENER = module._NTFY_OPENER
module._NTFY_OPENER = FakeOpener(fake_urlopen)
config = types.SimpleNamespace(ntfy_topic="pc-admin test", ntfy_token="tok-SENTINEL")
if module.notify(config, "alert", "detail-body") is not True:
    raise SystemExit("notify did not report success against the fake notifier")
request = captured[-1]
if request.full_url != "https://ntfy.sh/pc-admin%20test":
    raise SystemExit("notify URL wrong: %s" % request.full_url)
if request.headers.get("Authorization") != "Bearer tok-SENTINEL":
    raise SystemExit("notify auth header wrong: %r" % request.headers)
if request.data != b"detail-body":
    raise SystemExit("notify body wrong: %r" % request.data)


def failing_urlopen(request, timeout=None):
    raise module.urllib.error.URLError("no route")


module._NTFY_OPENER = FakeOpener(failing_urlopen)
if module.notify(config, "alert", "detail-body") is not False:
    raise SystemExit("notify must return False when the push fails")

# Round-5 R4: http.client.HTTPException subclasses (BadStatusLine,
# IncompleteRead) are transport failures too - they must be logged and
# returned as a failed push, not abort the run before state/verdict.
import http.client


def bad_status_urlopen(request, timeout=None):
    raise http.client.BadStatusLine("garbage")


module._NTFY_OPENER = FakeOpener(bad_status_urlopen)
if module.notify(config, "alert", "detail-body") is not False:
    raise SystemExit("notify must return False on BadStatusLine, not abort")


def incomplete_read_urlopen(request, timeout=None):
    raise http.client.IncompleteRead(b"abc", 10)


module._NTFY_OPENER = FakeOpener(incomplete_read_urlopen)
if module.notify(config, "alert", "detail-body") is not False:
    raise SystemExit("notify must return False on IncompleteRead, not abort")

# Round-6 F1: a token that cannot be an HTTP header value is refused before
# the request opens (the emoji/newline variants used to raise out of notify and
# abort with no state/verdict; the ValueError text echoed the token bytes).
module._NTFY_OPENER = FakeOpener(fake_urlopen)
token_logs = []
real_log = module.log
module.log = token_logs.append
for token_label, bad_token in [
    ("emoji", "abc\U0001f600def"),
    ("newline", "abc\ndef"),
    ("oversized", "A" * 100000),
]:
    bad_config = types.SimpleNamespace(ntfy_topic="pc-admin test", ntfy_token=bad_token)
    before = len(captured)
    if module.notify(bad_config, "alert", "detail-body") is not False:
        raise SystemExit("%s token must fail the push" % token_label)
    if len(captured) != before:
        raise SystemExit("%s token must be refused before the request opens" % token_label)
    joined = "\n".join(str(entry) for entry in token_logs)
    if bad_token in joined:
        raise SystemExit("%s token echoed into the log" % token_label)
if not any("ntfy push skipped" in str(entry) for entry in token_logs):
    raise SystemExit("a refused token must be logged as a skipped push")

# A late header-validation failure (putheader) must stay caught too, and the
# catch must log only the exception class (the message can embed the header).
for exc_label, late_exc in [
    ("ValueError", ValueError("Invalid header value b'Bearer late-SENTINEL'")),
    ("UnicodeEncodeError", UnicodeEncodeError("latin-1", u"Bearer late-SENTINEL", 0, 1, "boom")),
]:
    def raising(request, timeout=None, _exc=late_exc):
        raise _exc

    module._NTFY_OPENER = FakeOpener(raising)
    token_logs[:] = []
    if module.notify(config, "alert", "detail-body") is not False:
        raise SystemExit("a %s on the request path must fail the push" % exc_label)
    joined = "\n".join(str(entry) for entry in token_logs)
    if "late-SENTINEL" in joined or "Invalid header value" in joined:
        raise SystemExit("a %s message echoed the header value into the log" % exc_label)
module.log = real_log

# Round-6 F2: every redirect is refused, so a 302 to another host/scheme can
# never re-send Authorization (the leak pc-admin fixed as R3). The real opener
# is exercised against a local redirector + hijack listener.
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

hijack_auth = []


class HijackHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        hijack_auth.append(self.headers.get("Authorization"))
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")


class RedirectHandler(BaseHTTPRequestHandler):
    code = 302
    target = ""

    def log_message(self, *args):
        pass

    def do_POST(self):
        self.send_response(RedirectHandler.code)
        self.send_header("Location", RedirectHandler.target)
        self.send_header("Content-Length", "0")
        self.end_headers()


hijack_server = ThreadingHTTPServer(("127.0.0.1", 0), HijackHandler)
threading.Thread(target=hijack_server.serve_forever, daemon=True).start()
redirect_server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
threading.Thread(target=redirect_server.serve_forever, daemon=True).start()
RedirectHandler.target = "http://127.0.0.1:%d/hijacked" % hijack_server.server_address[1]
module._NTFY_OPENER = REAL_NTFY_OPENER
for redirect_code in (301, 302, 303, 307, 308):
    RedirectHandler.code = redirect_code
    redirect_request = module.urllib.request.Request(
        "http://127.0.0.1:%d/start" % redirect_server.server_address[1],
        data=b"detail-body",
        method="POST",
    )
    redirect_request.add_header("Authorization", "Bearer tok-REDIRECT-SENTINEL")
    try:
        module.open_ntfy(redirect_request, timeout=5)
    except module.urllib.error.HTTPError:
        pass
    else:
        raise SystemExit("the ntfy opener followed a %d redirect" % redirect_code)
if hijack_auth:
    raise SystemExit("redirect target received Authorization %r" % hijack_auth)
hijack_server.shutdown()
redirect_server.shutdown()
module._NTFY_OPENER = FakeOpener(fake_urlopen)

# Stateful transition/recovery through main()'s bookkeeping.
state_dir = os.path.join(work, "ntfy-state")
os.environ.update({
    "RECORDING_WITNESS_STATE_DIR": state_dir,
    "RECORDING_WITNESS_ENDPOINT": "http://127.0.0.1:9",
    "RECORDING_WITNESS_BUCKET": "pc-admin-dr",
    "RECORDING_WITNESS_AUDIT_PREFIX": "audit/",
    "RECORDING_WITNESS_RECORDINGS_PREFIX": "recordings/",
    "RECORDING_WITNESS_KEY_ID": "k",
    "RECORDING_WITNESS_KEY": "s",
    "RECORDING_WITNESS_RENOTIFY_SECONDS": "1800",
    "NTFY_TOPIC": "pc-admin test",
})
# Stateful transition/recovery through main()'s bookkeeping, with a notifier
# that fails the first recovery attempt (round-3 F4: a failed recovery push
# must be retried while the recovery run identity is newer than the last
# success).
flaky = {"fail": False}


def flaky_urlopen(request, timeout=None):
    captured.append(request)
    if flaky["fail"]:
        raise module.urllib.error.URLError("flaky")
    return Response()


module._NTFY_OPENER = FakeOpener(flaky_urlopen)
captured[:] = []
verdict = ["alert"]
sig = ["sha256:" + "1" * 64]
module.run_checks = lambda config, now, plan: (
    verdict[0], "detail", sig[0],
    {
        # A synthetic exact sweep payload: main()'s state/view bookkeeping
        # stays valid across the repeated main() calls this block drives.
        "mode": "sweep",
        "window_start": None,
        "dirty": True,
        "cursors": {"audit_heartbeat": "", "audit_session": "", "recordings": ""},
        "boundaries": [],
        "audit_objects": {},
        "recording_objects": {},
        "hidden": [],
    },
)

# First-ever green baseline (round-4 LOW 1): two consecutive green runs must
# not push, and the first-ever run must not arm the recovery retry. Then a
# real non-green -> ok recovery still pushes exactly once.
fresh_state_dir = os.path.join(work, "ntfy-fresh-state")
os.environ["RECORDING_WITNESS_STATE_DIR"] = fresh_state_dir
captured[:] = []
verdict[0] = "ok"
fresh_codes = [module.main(), module.main()]
if len(captured) != 0:
    raise SystemExit("first-ever green (and the next green) must not push, got %d" % len(captured))
fresh_record = json.load(open(os.path.join(fresh_state_dir, "state.json")))
if int(fresh_record.get("state_since_run") or 0) != 0 or int(fresh_record.get("last_notify_run") or 0) != 0:
    raise SystemExit("first-ever green armed the recovery retry: %r" % fresh_record)
verdict[0] = "alert"
fresh_codes.append(module.main())
if len(captured) != 1:
    raise SystemExit("post-baseline alert must push once, got %d" % len(captured))
verdict[0] = "ok"
fresh_codes.append(module.main())
if len(captured) != 2:
    raise SystemExit("post-baseline recovery must push once, got %d" % len(captured))
fresh_codes.append(module.main())
if len(captured) != 2:
    raise SystemExit("landed recovery must not re-push, got %d" % len(captured))
if fresh_codes != [0, 0, 1, 0, 0]:
    raise SystemExit("fresh first-green sequence exit codes wrong: %r" % fresh_codes)

os.environ["RECORDING_WITNESS_STATE_DIR"] = state_dir
captured[:] = []
verdict[0] = "alert"
codes = [module.main()]
if len(captured) != 1:
    raise SystemExit("first alert must push once, got %d" % len(captured))
codes.append(module.main())
if len(captured) != 1:
    raise SystemExit("repeat alert inside the window must not push, got %d" % len(captured))
state_path = os.path.join(state_dir, "state.json")
record = json.load(open(state_path))
record["last_notify_epoch"] = int(datetime.datetime.now(datetime.timezone.utc).timestamp()) - 1801
json.dump(record, open(state_path, "w"))
codes.append(module.main())
if len(captured) != 2:
    raise SystemExit("renotify outside the window must push, got %d" % len(captured))
# Simulate the last successful push landing before the recovery transition
# (a same-second transition epoch would make the retry condition ambiguous;
# real runs are minutes apart).
record = json.load(open(state_path))
record["last_notify_epoch"] = 1
json.dump(record, open(state_path, "w"))
verdict[0] = "ok"
# A failed push must not advance last_notify_signature either: move the
# signature first, so a mutation that advances it unconditionally is caught.
sig[:] = ["sha256:" + "9" * 64]
flaky["fail"] = True
codes.append(module.main())  # recovery transition: push attempted, fails
if len(captured) != 3:
    raise SystemExit("failed recovery must attempt exactly one push, got %d" % len(captured))
record = json.load(open(state_path))
if (record["state"] != "ok"
        or int(record.get("state_since_run") or 0) <= int(record.get("last_notify_run") or 0)
        or record.get("last_notify_epoch") != 1
        or record.get("last_notify_signature") == sig[0]):
    raise SystemExit("failed recovery must record the ok transition (state_since_run > last_notify_run) without advancing last_notify_epoch/last_notify_signature: %r" % record)
flaky["fail"] = False
codes.append(module.main())  # next green run retries the recovery push
if len(captured) != 4:
    raise SystemExit("failed recovery must retry on the next green run, got %d" % len(captured))
if json.load(open(state_path)).get("last_notify_signature") != sig[0]:
    raise SystemExit("the landed recovery retry must advance last_notify_signature")
if captured[-1].headers.get("Tags") != "white_check_mark":
    raise SystemExit("recovery retry must carry the ok tag: %r" % captured[-1].headers)
record = json.load(open(state_path))
if int(record["last_notify_epoch"]) <= 1:
    raise SystemExit("recovery retry must advance last_notify_epoch")
codes.append(module.main())  # one success covers the transition: steady ok silent
if len(captured) != 4:
    raise SystemExit("steady ok after a landed recovery must not push, got %d" % len(captured))
if codes != [1, 1, 1, 0, 0, 0]:
    raise SystemExit("main exit codes wrong: %r" % codes)

# Finding-signature change-trigger + the operator's quiet pin through main().
# A changed finding set pushes immediately (inside the renotify window); an
# unchanged set stays quiet; the pin quiets exactly its own signature to the
# quiet window while an unpinned/other signature keeps the default window; a
# malformed pin disables quieting with a bounded warning instead of aborting.
def _set_last_epoch(delta):
    data = json.load(open(state_path))
    data["last_notify_epoch"] = int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + delta
    json.dump(data, open(state_path, "w"))


captured[:] = []
verdict[0] = "alert"
sig[:] = [SIG_B]
codes = [module.main()]  # ok -> alert transition: pushes
if len(captured) != 1:
    raise SystemExit("the alert transition must push once, got %d" % len(captured))
codes.append(module.main())
if len(captured) != 1:
    raise SystemExit("an unchanged signature inside the window must stay quiet, got %d" % len(captured))
record = json.load(open(state_path))
if record.get("last_notify_signature") != SIG_B:
    raise SystemExit("a landed push must persist last_notify_signature: %r" % record.get("last_notify_signature"))
sig[:] = [SIG_A]
codes.append(module.main())  # signature changed while the window is fresh: pushes
if len(captured) != 2:
    raise SystemExit("a changed signature must push immediately, got %d" % len(captured))
codes.append(module.main())
if len(captured) != 2:
    raise SystemExit("the new signature inside the window must stay quiet, got %d" % len(captured))
# An upgraded-in-place record (no last_notify_signature yet) must push once on
# the first run whose signature is known, then settle: the field is
# bookkeeping, and its absence errs toward notifying.
record = json.load(open(state_path))
record.pop("last_notify_signature", None)
record["last_notify_epoch"] = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
json.dump(record, open(state_path, "w"))
codes.append(module.main())
if len(captured) != 3:
    raise SystemExit("a legacy record without last_notify_signature must push once, got %d" % len(captured))
codes.append(module.main())
if len(captured) != 3:
    raise SystemExit("the legacy record must settle after the first push, got %d" % len(captured))
# Pin the current signature: inside the quiet window no push, even though the
# default 30-minute window has expired.
os.environ["RECORDING_WITNESS_QUIET_SIGNATURE"] = SIG_A
os.environ["RECORDING_WITNESS_QUIET_RENOTIFY_SECONDS"] = "86400"
_set_last_epoch(-1801)
codes.append(module.main())
if len(captured) != 3:
    raise SystemExit("a pinned signature must stay quiet inside the quiet window, got %d" % len(captured))
# ... and it renotifies once the quiet window has passed.
_set_last_epoch(-86401)
codes.append(module.main())
if len(captured) != 4:
    raise SystemExit("a pinned signature must renotify after the quiet window, got %d" % len(captured))
# A finding-set change leaves the pin behind: push immediately, default cadence.
sig[:] = [SIG_B]
_set_last_epoch(0)
codes.append(module.main())
if len(captured) != 5:
    raise SystemExit("a changed signature must leave the pin and push immediately, got %d" % len(captured))
codes.append(module.main())
if len(captured) != 5:
    raise SystemExit("the unpinned unchanged signature must keep the default window, got %d" % len(captured))
# A malformed pin disables quieting (bounded warning, never abort/echo): the
# verdict still lands and the default window applies.
os.environ["RECORDING_WITNESS_QUIET_SIGNATURE"] = "sha256:XYZ"
_set_last_epoch(-1801)
codes.append(module.main())
if len(captured) != 6:
    raise SystemExit("a malformed pin must fall back to the default window, got %d" % len(captured))
if json.load(open(state_path)).get("state") != "alert":
    raise SystemExit("a malformed pin must not take the witness down")
os.environ.pop("RECORDING_WITNESS_QUIET_SIGNATURE", None)
os.environ.pop("RECORDING_WITNESS_QUIET_RENOTIFY_SECONDS", None)
if codes != [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]:
    raise SystemExit("signature/pin exit codes wrong: %r" % codes)

# Round-5 R1: a corrupted numeric field in a type-valid state.json used to
# crash main() before notify/write_state (no push, no verdict, forever). It
# must repair, report error, and push the error verdict (fake notifier).
corrupt_dir = os.path.join(work, "ntfy-corrupt-state")
os.makedirs(corrupt_dir, exist_ok=True)
os.environ["RECORDING_WITNESS_STATE_DIR"] = corrupt_dir
with open(os.path.join(corrupt_dir, "state.json"), "w", encoding="utf-8") as handle:
    json.dump({"version": 2, "state": "ok", "detail": "seeded", "updated_at": "2026-09-25T00:00:00Z",
               "run_seq": "not-a-number", "last_notify_epoch": 0,
               "baseline": {"state": "ok", "detail": "seeded baseline", "updated_at": "2026-09-25T00:00:00Z"}},
              handle)
module._NTFY_OPENER = FakeOpener(flaky_urlopen)
flaky["fail"] = False
captured[:] = []
verdict[0] = "alert"
corrupt_code = module.main()
if corrupt_code != 2:
    raise SystemExit("corrupt run_seq must exit 2 (error), got %r" % corrupt_code)
if len(captured) != 1:
    raise SystemExit("corrupt run_seq must push the error verdict, got %d pushes" % len(captured))
if captured[-1].headers.get("Title") != "recording witness: error":
    raise SystemExit("corrupt run_seq push must carry the error title: %r" % captured[-1].headers)
repaired = json.load(open(os.path.join(corrupt_dir, "state.json")))
if repaired.get("state") != "error" or not isinstance(repaired.get("run_seq"), int):
    raise SystemExit("corrupt state must be repaired with an error verdict: %r" % repaired)
if (repaired.get("baseline") or {}).get("detail") != "seeded baseline":
    raise SystemExit("corrupt-numeric repair must hold the readable baseline: %r" % repaired.get("baseline"))
PY
then ok "ntfy: transitions push, repeats suppress, 30-min renotify + failed-recovery retry (fake notifier)"; else bad "ntfy bookkeeping test failed"; fi

# ---- round-7 R1: signed S3 list GETs refuse redirects too -----------------
# The witness S3 client used stock urlopen, so a 3xx from the endpoint
# forwarded the SigV4 Authorization header cross-origin. signed_get() must
# surface the redirect as a failed call and send nothing to the target; the
# redirect origin itself must still have received the signed request.
if python3 - "${WORK}" <<'PY'
import importlib.util
import os
import sys
import threading
import types
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

work = sys.argv[1]
spec = importlib.util.spec_from_file_location("witness_module", os.path.join(work, "witness_module.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

hijack_auth = []
redirect_auth = []


class HijackHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        hijack_auth.append(self.headers.get("Authorization"))
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class RedirectHandler(BaseHTTPRequestHandler):
    code = 302
    target = ""

    def log_message(self, *args):
        pass

    def do_GET(self):
        redirect_auth.append(self.headers.get("Authorization"))
        self.send_response(RedirectHandler.code)
        self.send_header("Location", RedirectHandler.target)
        self.send_header("Content-Length", "0")
        self.end_headers()


hijack_server = ThreadingHTTPServer(("127.0.0.1", 0), HijackHandler)
threading.Thread(target=hijack_server.serve_forever, daemon=True).start()
redirect_server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
threading.Thread(target=redirect_server.serve_forever, daemon=True).start()
RedirectHandler.target = "http://127.0.0.1:%d/hijacked" % hijack_server.server_address[1]

s3_config = types.SimpleNamespace(
    endpoint="http://127.0.0.1:%d" % redirect_server.server_address[1],
    bucket="pc-admin-dr",
    key_id="test-key-id-0001",
    key="test-secret-SENTINEL-0009",
    signing_region=lambda: "test-region",
)
for redirect_code in (301, 302, 303, 307, 308):
    RedirectHandler.code = redirect_code
    status, _body = module.signed_get(s3_config, {"list-type": "2", "prefix": "audit/"})
    if status != redirect_code:
        raise SystemExit("signed_get followed/ignored a %d redirect (status %r)" % (redirect_code, status))
if not any(auth and auth.startswith("AWS4-HMAC-SHA256 Credential=") for auth in redirect_auth):
    raise SystemExit("the redirect origin never saw a signed request - the test did not exercise SigV4")
if hijack_auth:
    raise SystemExit("signed S3 redirect target received Authorization %r" % hijack_auth)
hijack_server.shutdown()
redirect_server.shutdown()
print("signed_get refused 5 redirect codes; signed requests at the redirect origin=%d; hijack headers=%d"
      % (len(redirect_auth), len(hijack_auth)))
PY
then ok "signed S3 list GETs refuse redirects (no SigV4 Authorization forwarding)"; else bad "signed S3 redirect refusal failed"; fi

# ---- wiring: the dispatch paths must carry the witness env -------------
for witness_var in RECORDING_WITNESS_ENDPOINT RECORDING_WITNESS_BUCKET RECORDING_WITNESS_AUDIT_PREFIX \
                   RECORDING_WITNESS_RECORDINGS_PREFIX RECORDING_WITNESS_KEY_ID RECORDING_WITNESS_KEY; do
  if grep -q "$witness_var" "${ROOT}/.github/workflows/provision.yml"; then
    ok "provision.yml carries $witness_var"
  else
    bad "provision.yml lost $witness_var (witness would silently go dormant)"
  fi
  if grep -q "$witness_var" "${ROOT}/.github/scripts/020-provision-anchor.sh"; then
    ok "020 env prefix carries $witness_var"
  else
    bad "020 env prefix lost $witness_var (witness would silently go dormant)"
  fi
done
# The optional cadence knobs are public variables, not secrets, but a
# dispatch that drops them would silently pin/quiet nothing. The provision.yml
# names are grepped; 020's pass-through is EXECUTED (the real ENV_PREFIX line,
# evaluated with sentinels) so a regression to an empty assignment cannot stay
# green behind a name grep.
for witness_var in RECORDING_WITNESS_RENOTIFY_SECONDS RECORDING_WITNESS_QUIET_RENOTIFY_SECONDS \
                   RECORDING_WITNESS_QUIET_SIGNATURE RECORDING_WITNESS_COLD_START_SECONDS \
                   RECORDING_WITNESS_SWEEP_SECONDS; do
  if grep -q "$witness_var" "${ROOT}/.github/workflows/provision.yml"; then
    ok "provision.yml carries $witness_var"
  else
    bad "provision.yml lost $witness_var (quiet cadence would never reach the box)"
  fi
done
q() { printf %s "$1" | sed "s/'/'\\\\''/g"; }
export TENANT_USER="tenant-sentinel" ANCHOR_HOSTNAME="anchor-sentinel" STATUS_HOST="status-sentinel" \
  GATUS_ENDPOINTS="" NTFY_TOPIC="" NTFY_TOKEN="" ORIGIN_CA_CERT_PEM="" CF_AOP_CA_PEM="" \
  RECORDING_WITNESS_ENDPOINT="endpoint-sentinel" RECORDING_WITNESS_BUCKET="bucket-sentinel" \
  RECORDING_WITNESS_AUDIT_PREFIX="audit/" RECORDING_WITNESS_RECORDINGS_PREFIX="recordings/" \
  RECORDING_WITNESS_KEY_ID="keyid-sentinel" RECORDING_WITNESS_KEY="key-sentinel" \
  RECORDING_WITNESS_RENOTIFY_SECONDS="2400" RECORDING_WITNESS_QUIET_RENOTIFY_SECONDS="172800" \
  RECORDING_WITNESS_QUIET_SIGNATURE="${SIGNATURE_SEED}" \
  RECORDING_WITNESS_COLD_START_SECONDS="7200" RECORDING_WITNESS_SWEEP_SECONDS="3600"
eval "$(sed -n 's/^  \(ENV_PREFIX=.*\)$/\1/p' "${ROOT}/.github/scripts/020-provision-anchor.sh")"
eval "$ENV_PREFIX"
is "020 ENV_PREFIX passes the renotify window through" "2400" "${RECORDING_WITNESS_RENOTIFY_SECONDS:-}"
is "020 ENV_PREFIX passes the quiet window through" "172800" "${RECORDING_WITNESS_QUIET_RENOTIFY_SECONDS:-}"
is "020 ENV_PREFIX passes the quiet signature through" "${SIGNATURE_SEED}" "${RECORDING_WITNESS_QUIET_SIGNATURE:-}"
is "020 ENV_PREFIX passes the cold-start window through" "7200" "${RECORDING_WITNESS_COLD_START_SECONDS:-}"
is "020 ENV_PREFIX passes the sweep interval through" "3600" "${RECORDING_WITNESS_SWEEP_SECONDS:-}"
if grep -q 'tests/recording-witness/run-test.sh' "${ROOT}/.github/workflows/ci.yml"; then
  ok "ci.yml runs the recording-witness harness"
else
  bad "ci.yml does not run the recording-witness harness"
fi
if grep -q 'origin-ca|recording-witness)/' "${ROOT}/.github/workflows/ci.yml"; then
  ok "ci.yml path gate includes tests/recording-witness/"
else
  bad "ci.yml path gate missing tests/recording-witness/"
fi

if [ "$pass" -lt "$((MIN_CHECKS - SHELLCHECK_SKIPPED))" ]; then
  bad "check-count floor: ${pass} passed < $((MIN_CHECKS - SHELLCHECK_SKIPPED)) pinned ($((MIN_CHECKS)) minus the shellcheck skip)"
fi
printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
