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
#       (shipper_keys.py, pinned to cad0p/pc-admin @ 3325aeb; golden strings,
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
#       long-up box (issue #143) is drained (bounded, 100 polls) before the
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
#       and steady ok stays silent afterwards (fake notifier, no network).
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
# shellcheck is absent (a local run without it must not fail the full floor;
# CI ships shellcheck and runs the tooth), so the effective floor subtracts
# the recorded skip (functional round-2 LOW: a 473-pass no-shellcheck run
# hard-failed the 474 floor).
MIN_CHECKS=513
SHELLCHECK_SKIPPED=0
ok()  { pass=$((pass + 1)); printf 'ok   %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL %s\n' "$1"; }
is()  { # $1 label, $2 expected, $3 actual
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi
}
mode_of() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1" 2>/dev/null || echo "?"; }
key() { # audit key built by the pc-admin shipper grammar (never hand-written)
  python3 "${HARNESS_DIR}/shipper_keys.py" "$@"
}
variant_key() { # replay-conflict variant: --variant <body> <event-type> <ts> [sid] [seq] [mode]
  python3 "${HARNESS_DIR}/shipper_keys.py" --variant "$@"
}
fresh_stamp() { # current UTC in the witness's state.json format
  python3 -c 'import datetime; print(datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))'
}
# Pin the replica to the pc-admin shipper grammar. The golden strings below
# were generated from the real builder at cad0p/pc-admin @ 3325aeb
# (scripts/lib/b2_client.py build_audit_key/session_mode/disambiguate_audit_key,
# the full-SHA pin in shipper_keys.py; the grammar-defining point (pc-admin
# #19) scoped the sid-less `session.data` sanction onto the documented
# `unknown` non-session shape, the previous point a7035a9 added the
# replay-conflict `_<sha256[:16]>` variant keys, and the earlier point 41735ff
# added the over-long event-type truncation cap with the `_<sha256[:8]>`
# suffix — all pinned by the vector matrix below); a pc-admin grammar change
# must bump the pin and regenerate these (a contract-neutral change needs no
# witness-contract edit). Drift fixtures (non-UUID or
# sid-less session keys, malformed modes) stay hand-written literals on
# purpose: the replica now refuses shapes the real shipper never emits, so a
# fixture request for one is itself a failure (the teeth after the golden).
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

# Provenance-checked golden + boundary matrix: shipper_key_vectors.json was
# generated from the REAL pc-admin builder at the pinned SHA
# (generate_shipper_vectors.py); every vector must replay exactly and every
# refusal must stay refused, or silent replica drift passes the harness.
if python3 - "${HARNESS_DIR}" <<'PY'
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


def replay(args, body=None):
    args = list(args)
    args[3] = int(args[3])
    key = replica.audit_key(*args)
    if body is not None:
        # `kind: "variant"` vectors carry the real builder's
        # `disambiguate_audit_key` output for this body.
        key = replica.disambiguate_key(key, body)
    return key


if vectors.get("pinned_pc_admin_sha") != replica.PINNED_PC_ADMIN_SHA:
    raise SystemExit("vector pin %r != shipper_keys pin %r" % (
        vectors.get("pinned_pc_admin_sha"), replica.PINNED_PC_ADMIN_SHA))

# Matrix size pin: a deleted vector/refusal entry must fail loudly instead of
# shrinking the matrix silently (red-team round-2 LOW M10). Update this pin
# together with the matrix.
if len(vectors["vectors"]) != 26 or len(vectors["refusals"]) != 12:
    raise SystemExit(
        "vector matrix size changed: %d vectors / %d refusals (pinned 26/12) - "
        "update this pin together with the matrix"
        % (len(vectors["vectors"]), len(vectors["refusals"])))

# Matrix content pin (red-team round-3 LOW): a coherent same-size rewrite
# (both event.sid and replica_args[2], or an entry swap) must fail loudly.
# Regenerate the matrix with generate_shipper_vectors.py and bump this sha256
# together with the file. The digest covers the SAME bytes that are replayed
# (single read above).
matrix_sha = hashlib.sha256(matrix_bytes).hexdigest()
MATRIX_SHA256 = "4c7116af9cfa5e02c73924d59bf676cf7281af6f3e176fafc69396746adba7a8"
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
# too, or a `re.compile(<other pattern>)` rebind bypasses the constant pin
# (round-7 MEDIUM — the semantics the constant pin rejects when written on
# the pattern line stay reachable on the compile line).
if replica.UUID_RE.pattern != CANONICAL_UUID_PATTERN:
    raise SystemExit(
        "replica UUID_RE.pattern %r != pinned canonical pattern %r"
        % (replica.UUID_RE.pattern, CANONICAL_UUID_PATTERN))


def source_sha_ok(value):
    # Round-6 F6: exact 40-hex equality. `startswith(pin)` accepted the short
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
                replica.PINNED_PC_ADMIN_SHA.upper()):
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
    got = replay(vector["replica_args"], vector.get("body"))
    if got != vector["expected"]:
        raise SystemExit("%s: expected %s got %s" % (vector["name"], vector["expected"], got))
for refusal in vectors["refusals"]:
    try:
        replay(refusal["replica_args"])
    except ValueError:
        continue
    raise SystemExit("refusal accepted: %s" % refusal["name"])
print("vectors=%d refusals=%d pin=%s source=%s" % (
    len(vectors["vectors"]), len(vectors["refusals"]), vectors["pinned_pc_admin_sha"], source_sha[:12]))
PY
then ok "replica replays the real-builder golden+boundary vectors (pin-matched, refusals held)"; else bad "shipper replica diverged from the checked-in real-builder vectors"; fi

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
# pin in the vector block. The corpus-size floor makes a gutted corpus fail
# loudly, and this block emits its own counted check.
if python3 - "${HARNESS_DIR}" <<'PY'
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
# Freeze the predicate primitives BEFORE importing the replica: an import
# could otherwise rebind re.compile / unicodedata.category / .normalize and
# make this oracle agree with a relaxed matcher while the CLI and vector
# processes stay strict (red-team round-9 LOW).
_oracle_compile = re.compile
_oracle_category = unicodedata.category
_oracle_normalize = unicodedata.normalize
spec = importlib.util.spec_from_file_location("shipper_keys", os.path.join(here, "shipper_keys.py"))
replica = importlib.util.module_from_spec(spec)
spec.loader.exec_module(replica)
# Re-assert the pattern pins in THIS process too: the vector-block pins run
# in a separate interpreter, so a per-process rebind would escape them.
if replica.UUID_PATTERN != CANONICAL_UUID_PATTERN or replica.UUID_RE.pattern != CANONICAL_UUID_PATTERN:
    raise SystemExit("replica UUID pattern pins diverged in the oracle process")
ORACLE_RE = _oracle_compile(CANONICAL_UUID_PATTERN)

oracle_sids = [ORACLE_BASE, ORACLE_BASE.upper()]
pad_chars = []
for codepoint in range(0x110000):
    char = chr(codepoint)
    if _oracle_category(char) in ("Cc", "Cf", "Zs", "Zl", "Zp", "Mn", "Me"):
        pad_chars.append(char)
pad_chars.extend("_-.:;,'\"`()[]{}<>|/\\!?@#$%^&*+=~ ")
for char in pad_chars:
    oracle_sids.append(char + ORACLE_BASE)
    oracle_sids.append(ORACLE_BASE + char)
    oracle_sids.append(ORACLE_BASE[:4] + char + ORACLE_BASE[4:])
for open_char, close_char in (("(", ")"), ("<", ">"), ("[", "]"), ("{", "}"),
                              ("`", "`"), ("'", "'"), ('"', '"')):
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
        folded = _oracle_normalize("NFKC", chr(codepoint))
        if len(folded) == 1 and folded in "0123456789abcdefABCDEF":
            for index, char in enumerate(ORACLE_BASE):
                if char == folded.lower():
                    oracle_sids.append(ORACLE_BASE[:index] + chr(codepoint) + ORACLE_BASE[index + 1:])
for index in range(len(ORACLE_BASE)):
    oracle_sids.append(ORACLE_BASE[:index] + ORACLE_BASE[index + 1:])
# Synthetic canonical-pattern near-misses: a 36-char dashless hex string and
# an all-dash string are non-canonical; they pin hostile same-`.pattern`
# matchers that accept a broad hex/dash class behaviorally.
oracle_sids.append("a" * 36)
oracle_sids.append("-" * 36)
if len(oracle_sids) < 6500:
    raise SystemExit("canonical-sid oracle corpus shrank: %d cases" % len(oracle_sids))
# A size floor alone passes a degenerate corpus ([BASE] * 901); require
# distinct sids too so the corpus cannot be replaced by a repeated literal.
if len(set(oracle_sids)) < 6500:
    raise SystemExit("canonical-sid oracle corpus lost distinctness: %d unique sids" % len(set(oracle_sids)))

failures = []
for sid in oracle_sids:
    canonical = ORACLE_RE.fullmatch(sid) is not None
    try:
        data_key = replica.audit_key("session.data", ORACLE_TS, sid, 1)
    except ValueError:
        data_key = None
    try:
        replica.audit_key("session.start", ORACLE_TS, sid, 1, "shell")
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
print("oracle=%d cases" % len(oracle_sids))
PY
then ok "canonical-sid oracle corpus (generated; no normalization divergence)"; else bad "shipper replica diverged from the canonical-sid oracle corpus"; fi

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
except (OSError, ValueError):
    node = {}
for part in sys.argv[2].split("."):
    node = node.get(part, "") if isinstance(node, dict) else ""
print(node)
' "${CASE_STATE_DIR:-${WORK}/state}/state.json" "$1" 2>/dev/null || true
}

run_case() { # fixture at ${FIXTURE} ($1 = optional state dir); sets CASE_RC / CASE_STATE / CASE_DETAIL
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
EOF
  export RECORDING_WITNESS_ENV_FILE="${WORK}/witness.env"
  CASE_RC=0
  "${WITNESS}" >"${WORK}/witness.out" 2>"${WORK}/witness.err" || CASE_RC=$?
  CASE_STATE="$(state_field state)"
  CASE_DETAIL="$(state_field detail)"
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
# bounded renderer itself. Keys come from the shipper grammar.
python3 - "${HARNESS_DIR}" "$SID" <<'PY' | fixture
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
    objects.append({"key": audit_key("session.data", "20260925T135100Z", sid, seq), "ago": 299})
objects.append({"key": audit_key("session.end", "20260925T135200Z", sid, 61, "shell"), "ago": 298})
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
python3 - "${HARNESS_DIR}" "$SID" <<'PY' | fixture
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
    objects.append({"key": audit_key("session.data", "20260925T135100Z", sid, seq), "ago": 299})
for seq in range(41, 60, 2):
    objects.append({"key": audit_key("session.data", "20260925T135200Z", sid, seq), "ago": 298})
objects.append({"key": audit_key("session.end", "20260925T135300Z", sid, 61, "shell"), "ago": 297})
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
# (session.start omits `interactive` and reads `.shell` even for exec).
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
# The drain-bound tooth drives all 100 wait-idle polls; FAKE_SLEEP_NOWAIT
# removes the wall-clock cost while keeping the iteration count (and with it
# the bound) exercised, and FAKE_SLEEP_COUNT_FILE + FAKE_SLEEP_ARGS_FILE pin
# the sleep count and its argument (`sleep 1`) so a bound regression that
# keeps the poll count (a deleted `sleep 1`, a shorter sleep, fewer iterations
# with an early break) still fails. Every other test sleeps for real.
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
unset RECORDING_WITNESS_RENOTIFY_SECONDS RECORDING_WITNESS_QUIET_RENOTIFY_SECONDS RECORDING_WITNESS_QUIET_SIGNATURE
if grep -q 'enable --now pc-recording-witness.timer' "${FAKE_SYSTEMCTL_LOG}" 2>/dev/null; then
  ok "install enables the timer"
else
  bad "install did not enable the timer: $(cat "${FAKE_SYSTEMCTL_LOG}" 2>/dev/null)"
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

# Retry/drain bound (red-team INFO-2): a unit that never reports drained must
# die fail-closed at the bounded 100-poll wait BEFORE any `systemctl start` —
# zero starts for this pre-start drain, never a start-then-retry loop (the
# retry-path drain can fire after a merged start already ran — fail-closed
# either way). FAKE_SLEEP_NOWAIT keeps the 100 iterations but removes their
# wall-clock cost; FAKE_ACTIVE_STATE=active reports active on every poll,
# FAKE_ACTIVE_POLL_FILE pins the iteration count (100 loop polls + the final
# ActiveState read for the die message = 101), FAKE_SLEEP_COUNT_FILE pins
# the sleeps (100) and FAKE_SLEEP_ARGS_FILE pins their argument (`1`), so a
# bound regression fails whether it changes the poll count, the sleep count
# or only the wall-clock wait (a deleted `sleep 1`, `sleep 0.1`, an early
# break) instead of shipping with a stale "100s" message. The count/arg
# teeth pin volume, not the shape: FAKE_ACTIVE_POLL_SLEEP_FILE records the
# sleep count observed at every poll so the interleaving tooth (poll N must
# see N-1 sleeps) fails a loop whose sleeps are moved out of the poll body
# (a busy poll with identical counters), and two static teeth pin the
# executed drain sleep (the last statement before the loop's `done` must be
# a foreground `sleep 1` — catches a backgrounded or shortened sleep — and
# no `sleep` function may shadow it). A regression that
# starts before the drain, or retries beyond the bound, moves the start
# counter off 0; one that loops without the bound hangs this check instead of
# failing it.
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
  *"did not drain within 100s"*) ok "run-once names the bounded drain failure" ;;
  *) bad "run-once non-drain output: ${runonce_out}" ;;
esac
is "run-once: a non-draining unit performed 0 starts" "0" "$(cat "${WORK}/no-drain-start-count")"
is "run-once: a non-draining unit polls the bounded 100-iteration wait (100 + the final read)" "101" "$(cat "${WORK}/no-drain-polls")"
is "run-once: a non-draining unit sleeps the bounded 100 iterations" "100" "$(cat "${WORK}/no-drain-sleeps")"
is "run-once: every drain sleep waits the pinned 1 s" "1" "$(sort -u "${WORK}/no-drain-sleep-args")"
# Issue #143 red-team F1: poll N must observe N-1 sleeps (0..100 for the
# shipped loop; the die path's final ActiveState read is poll 101). Moving
# the sleeps out of the poll body keeps every volume counter green but
# collapses the bounded wait to a busy poll — this fails it.
if awk 'NR - 1 != $1 { exit 1 }' "${WORK}/no-drain-poll-sleeps"; then
  ok "run-once: every drain poll is separated by the preceding sleep (issue #143)"
else
  bad "run-once: drain polls and sleeps are not interleaved (issue #143): $(tr '\n' ' ' <"${WORK}/no-drain-poll-sleeps")"
fi
# Issue #143 red-team F2 (+ rounds 4-6 F1): counters cannot prove the sleep
# blocks — a backgrounded `sleep 1 &` keeps them all green while the bounded
# wait stops waiting, and a bare `sleep 1` elsewhere keeps a presence-only
# tooth green while the executed loop sleep is shortened (`timeout 0.5 sleep
# 1`) or shadowed by a `sleep` function. Pin the executed line: the drain
# loop (the `for ((attempt...))` header) must end — at depth 0, so nested
# decoy loops cannot latch — in a foreground `sleep 1` (a trailing comment is
# fine); and no `sleep` function may exist in plain code (`sleep()` or
# `function sleep`, same-line or brace-on-next-line; comments and quoted
# spans ignored). Residual (intentional-crafting class, disclosed): `eval`/
# `alias`+`expand_aliases`/sourced-file shadows and blocking-equivalent loop
# forms are not detected (fail-closed by design).
if awk '
  /^[[:space:]]*for[[:space:]]*\(\(attempt[[:space:]]*=[[:space:]]*0;[[:space:]]*attempt[[:space:]]*<[[:space:]]*100;[[:space:]]*attempt\+\+\)\);[[:space:]]*do[[:space:]]*(#.*)?$/ {
    seen_loop = 1; in_loop = 1; depth = 0; prev = ""; next
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
  END { exit (seen_loop && loop_prev ~ /^[[:space:]]*sleep 1[[:space:]]*(#.*)?$/) ? 0 : 1 }
' "${PROVISION}"; then
  ok "run-once: the drain loop ends in a foreground \`sleep 1\` (issue #143)"
else
  bad "run-once: the drain loop sleep is missing, backgrounded, shortened or not last (issue #143)"
fi
if awk -v q="'" '
  {
    line = $0
    sub(/^[[:space:]]*#.*/, "", line)
    gsub(/"[^"]*"/, "", line)
    gsub(q "[^" q "]*" q, "", line)
    sub(/[[:space:]]#.*$/, "", line)
    if (line ~ /^[[:space:]]*$/) next
    if (line ~ /(^|[^[:alnum:]_])function[[:space:]]+sleep([[:space:]]*\(\))?[[:space:]]*\{/) shadow = 1
    if (line ~ /(^|[^[:alnum:]_])sleep[[:space:]]*\(\)[[:space:]]*\{/) shadow = 1
    if (!pending && line ~ /(^|[^[:alnum:]_])(function[[:space:]]+sleep([[:space:]]*\(\))?|sleep[[:space:]]*\(\))[[:space:]]*$/) { pending = 1; next }
    if (pending) { if (line ~ /^[[:space:]]*\{/) shadow = 1; pending = 0 }
  }
  END { exit shadow ? 1 : 0 }
' "${PROVISION}"; then
  ok "run-once: no \`sleep\` function shadows the drain sleep (issue #143)"
else
  bad "run-once: a \`sleep\` function shadows the drain sleep (issue #143)"
fi
case "${runonce_out}" in
  *"refusing to continue with a possibly merged run"*) ok "run-once names the continue-refusal wording" ;;
  *) bad "run-once non-drain wording: ${runonce_out}" ;;
esac
unset FAKE_ACTIVE_STATE FAKE_ACTIVE_POLL_FILE FAKE_ACTIVE_POLL_SLEEP_FILE FAKE_SLEEP_COUNT_FILE FAKE_SLEEP_ARGS_FILE FAKE_SLEEP_NOWAIT

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
module.run_checks = lambda config, now: (verdict[0], "detail", sig[0])

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
                   RECORDING_WITNESS_QUIET_SIGNATURE; do
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
  RECORDING_WITNESS_QUIET_SIGNATURE="${SIGNATURE_SEED}"
eval "$(sed -n 's/^  \(ENV_PREFIX=.*\)$/\1/p' "${ROOT}/.github/scripts/020-provision-anchor.sh")"
eval "$ENV_PREFIX"
is "020 ENV_PREFIX passes the renotify window through" "2400" "${RECORDING_WITNESS_RENOTIFY_SECONDS:-}"
is "020 ENV_PREFIX passes the quiet window through" "172800" "${RECORDING_WITNESS_QUIET_RENOTIFY_SECONDS:-}"
is "020 ENV_PREFIX passes the quiet signature through" "${SIGNATURE_SEED}" "${RECORDING_WITNESS_QUIET_SIGNATURE:-}"
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
