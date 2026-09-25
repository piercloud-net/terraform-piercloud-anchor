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
#   (d) verdicts on mocked S3 metadata: healthy -> ok; missing/stale heartbeat ->
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
#       naming-contract; sid-less session.rejected keys are not drift, while a
#       sid-bearing rejected key (the pre-fold pc-admin shape) is read as a
#       session with no session.start -> session-start-missing; a
#       renamed session prefix (sess.start) is still drift; an audit key that
#       matches no documented shape -> alert contract-mismatch; future
#       LastModified *and* future Initiated timestamps -> error (clock skew);
#       mode-marker fixtures are built with the pc-admin shipper key grammar
#       (shipper_keys.py, pinned to cad0p/pc-admin @ 66bd304; golden strings,
#       refusal teeth, and the checked-in golden+boundary vector matrix
#       generated from the real builder — never hand-written);
#   (e) fail-closed: a failing listing run reports error (exit 2) while the
#       last baseline in state.json is held; malformed XML, an S3 error
#       document and a truncated list without a continuation token all error;
#   (f) strictly list-only: every request the witness makes is a signed GET
#       list call (ListObjectsV2 / ListMultipartUploads) — no HEAD, no
#       object GET, no ListParts, no write; pagination is followed for both
#       list families, and every scenario SigV4-signature-verifies server-side;
#   (g) the 0600 env file holds the key and the witness never prints it;
#   (h) install renders all four artifacts (mode 0600 env) and a later
#       provision without the env removes them (no stale timer);
#   (i) run-once acceptance: a Type=oneshot start rc is non-zero for an
#       alerting witness too, so the run maps the paired rc/ExecMainStatus
#       (0:0 / 1:1 / 1:2) -> ok/alert/error and dies when the unit demonstrably
#       did not run (status unset/203, unpaired rc, or a wedged start whose
#       InvocationID did not advance) or when state.json's per-run identity
#       (run_seq) did not advance this invocation (a failed state write, or a
#       start that left the previous verdict) — run identity, not the
#       second-resolution updated_at, so a genuine same-second run counts; a
#       run longer than any recency window is accepted because the anchor is
#       advancement, not recency; state and ExecMainStatus mismatches die; the
#       printed detail has session ids redacted (public run-log safety);
#       verdict.log rotates once it crosses its size bound;
#   (j) ntfy bookkeeping: state transitions push, a first-ever green never
#       pushes (and does not arm the recovery retry), a repeated non-green
#       state is suppressed inside the renotify window, renotifies outside it,
#       a failed recovery push is retried on the next green run until it lands
#       (the retry boundary is the per-run identity, so a same-second
#       transition still retries), and steady ok stays silent afterwards
#       (fake notifier, no network).
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
ok()  { pass=$((pass + 1)); printf 'ok   %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL %s\n' "$1"; }
is()  { # $1 label, $2 expected, $3 actual
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi
}
mode_of() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1" 2>/dev/null || echo "?"; }
key() { # audit key built by the pc-admin shipper grammar (never hand-written)
  python3 "${HARNESS_DIR}/shipper_keys.py" "$@"
}
fresh_stamp() { # current UTC in the witness's state.json format
  python3 -c 'import datetime; print(datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))'
}
# Pin the replica to the pc-admin shipper grammar. The golden strings below
# were generated from the real builder at cad0p/pc-admin @ 66bd304
# (scripts/lib/b2_client.py build_audit_key/session_mode, the SHA pinned in
# shipper_keys.py); a pc-admin grammar change must bump the pin, regenerate
# these and update the witness contract together. Drift fixtures (non-UUID or
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
is "replica golden seq 10^6 (seven digits, past the old ceiling)" \
  "audit/20260925T100008Z-session.data.${REPLICA_SID}.1000000.json" \
  "$(key session.data 20260925T100008Z "${REPLICA_SID}" 1000000)"
# The replica must refuse any unexpected shape instead of silently building a
# key the real shipper cannot emit.
replica_refuses() { # label + shipper_keys.py args; non-zero = refused
  if python3 "${HARNESS_DIR}/shipper_keys.py" "$@" >/dev/null 2>&1; then
    bad "replica accepted an unexpected shape: $*"
  else
    ok "replica refuses unexpected shape: $*"
  fi
}
replica_refuses "session.start non-UUID sid" session.start 20260925T100008Z not-a-uuid 1
replica_refuses "session.start missing sid and mode" session.start 20260925T100008Z "" 1
replica_refuses "non-session with sid" user.login 20260925T100008Z "${REPLICA_SID}" 1
replica_refuses "mode on non-lifecycle event" session.data 20260925T100008Z "${REPLICA_SID}" 1 shell
replica_refuses "mode on non-session event" user.login 20260925T100008Z "" 1 shell
replica_refuses "lifecycle without the mandatory mode" session.start 20260925T100008Z "${REPLICA_SID}" 1
replica_refuses "seq zero (legacy hand-written fixture only)" session.data 20260925T100008Z "${REPLICA_SID}" 0
replica_refuses "seq beyond the witness 18-digit grammar" session.data 20260925T100008Z "${REPLICA_SID}" 1000000000000000000
replica_refuses "session.start missing sid with mode" session.start 20260925T100008Z "" 1 shell

# Provenance-checked golden + boundary matrix: shipper_key_vectors.json was
# generated from the REAL pc-admin builder at the pinned SHA
# (generate_shipper_vectors.py); every vector must replay exactly and every
# refusal must stay refused, or silent replica drift passes the harness.
if python3 - "${HARNESS_DIR}" <<'PY'
import importlib.util
import json
import os
import sys

here = sys.argv[1]
spec = importlib.util.spec_from_file_location("shipper_keys", os.path.join(here, "shipper_keys.py"))
replica = importlib.util.module_from_spec(spec)
spec.loader.exec_module(replica)
vectors = json.load(open(os.path.join(here, "shipper_key_vectors.json"), encoding="utf-8"))


def replay(args):
    args = list(args)
    args[3] = int(args[3])
    return replica.audit_key(*args)


if vectors.get("pinned_pc_admin_sha") != replica.PINNED_PC_ADMIN_SHA:
    raise SystemExit("vector pin %r != shipper_keys pin %r" % (
        vectors.get("pinned_pc_admin_sha"), replica.PINNED_PC_ADMIN_SHA))
for vector in vectors["vectors"]:
    got = replay(vector["replica_args"])
    if got != vector["expected"]:
        raise SystemExit("%s: expected %s got %s" % (vector["name"], vector["expected"], got))
for refusal in vectors["refusals"]:
    try:
        replay(refusal["replica_args"])
    except ValueError:
        continue
    raise SystemExit("refusal accepted: %s" % refusal["name"])
print("vectors=%d refusals=%d pin=%s" % (
    len(vectors["vectors"]), len(vectors["refusals"]), vectors["pinned_pc_admin_sha"]))
PY
then ok "replica replays the real-builder golden+boundary vectors (pin-matched, refusals held)"; else bad "shipper replica diverged from the checked-in real-builder vectors"; fi

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

state_field() { # $1 = dotted path into state.json
  python3 -c '
import json, sys
try:
    node = json.load(open(sys.argv[1]))
except (OSError, ValueError):
    node = {}
for part in sys.argv[2].split("."):
    node = node.get(part, "") if isinstance(node, dict) else ""
print(node)
' "${WORK}/state/state.json" "$1" 2>/dev/null || true
}

run_case() { # fixture must be at ${FIXTURE}; sets CASE_RC / CASE_STATE / CASE_DETAIL
  cat >"${WORK}/witness.env" <<EOF
RECORDING_WITNESS_ENDPOINT=http://127.0.0.1:${MOCK_PORT}
RECORDING_WITNESS_REGION=test-region
RECORDING_WITNESS_BUCKET=pc-admin-dr
RECORDING_WITNESS_AUDIT_PREFIX=audit/
RECORDING_WITNESS_RECORDINGS_PREFIX=recordings/
RECORDING_WITNESS_KEY_ID=test-key-id-0001
RECORDING_WITNESS_KEY=test-secret-SENTINEL-0009
RECORDING_WITNESS_STATE_DIR=${WORK}/state
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

# ---- shipper contract: sid-less session events + shape-based drift -------

fixture <<JSON
{"bucket":"pc-admin-dr",
 "objects":[
  {"key":"audit/heartbeat/20260925T140000Z.json","ago":45},
  {"key":"audit/20260925T135000Z-session.start.${SID}.1.shell.json","ago":300},
  {"key":"audit/20260925T135100Z-session.data.${SID}.2.json","ago":299},
  {"key":"audit/20260925T135200Z-session.end.${SID}.3.shell.json","ago":298},
  {"key":"audit/20260925T135300Z-session.rejected.000001.json","ago":297},
  {"key":"recordings/${SID}.tar","ago":296}],
 "uploads":[]}
JSON
start_mock
run_case
is "sid-less session.rejected key -> exit 0" "0" "${CASE_RC}"
is "sid-less session.rejected key -> ok verdict (no naming-contract false positive)" "ok" "${CASE_STATE}"

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
case "${CASE_DETAIL}" in *"truncated without a key marker"*) ok "upload truncation detail is explicit" ;; *) bad "upload truncation detail: ${CASE_DETAIL}" ;; esac

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

# ---- (f) strictly list-only + SigV4 proof over every request -------------
if python3 - "${REQUEST_LOG}" <<'PY'
import json
import sys

violations = []
entries = 0
pagination = 0
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
    if "list-type=2" not in entry["note"] and "uploads" not in entry["note"] and entry["ok"]:
        violations.append("non-list OK request: %s" % entry["note"])
    for forbidden in ("partNumber=", "uploadId=", "?acl", "?versioning"):
        if forbidden in entry["path"]:
            violations.append("forbidden query %s in %s" % (forbidden, entry["path"]))
    if "continuation-token=" in entry["path"]:
        pagination += 1
    if "key-marker=" in entry["path"]:
        uploads_pagination += 1

if entries < 20:
    violations.append("too few requests observed (%d) - scenarios did not run" % entries)
if pagination < 1:
    violations.append("no continuation-token request - object pagination not followed")
if uploads_pagination < 1:
    violations.append("no key-marker request - upload pagination not followed")
if sig_ok != entries:
    violations.append("SigV4 verified on only %d/%d requests (all must verify)" % (sig_ok, entries))
if not signed_shape:
    violations.append("no request carried the expected SigV4 SignedHeaders shape")

if violations:
    for violation in violations:
        print("VIOLATION " + violation)
    sys.exit(1)
print("requests=%d pagination=%d uploads_pagination=%d sig_ok=%d" % (
    entries, pagination, uploads_pagination, sig_ok))
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
    # no new invocation and no state write. Otherwise the invocation counter
    # advances and (unless FAKE_NO_STATE_WRITE=1) state.json gets a new
    # per-run identity (run_seq) plus a fresh updated_at, exactly like a real
    # witness run.
    if [ -n "${FAKE_START_RC:-}" ]; then exit "${FAKE_START_RC}"; fi
    if [ "${FAKE_NO_INVOCATION_BUMP:-0}" != "1" ]; then
      printf 'inv-%s-%s\n' "$$" "${RANDOM}" >"${FAKE_INVOCATION_FILE}"
    fi
    if [ "${FAKE_NO_STATE_WRITE:-0}" != "1" ] && [ -f "${FAKE_STATE_FILE:-/dev/null}" ]; then
      python3 - "${FAKE_STATE_FILE}" "${FAKE_NEW_UPDATED_AT:-}" <<'PYSTATE'
import datetime
import json
import sys

try:
    data = json.load(open(sys.argv[1]))
except (OSError, ValueError):
    data = {}
data["run_seq"] = int(data.get("run_seq") or 0) + 1
data["updated_at"] = sys.argv[2] or (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
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
      *) printf '%s\n' "${FAKE_EXEC_STATUS:-0}" ;;
    esac
    exit 0 ;;
esac
exit 0
FAKE
chmod +x "${FAKEBIN}/systemctl"
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
# per-run identity (run_seq; updated_at is second-resolution and may repeat);
# the wedged/rollback paths switch that off.
export FAKE_STATE_FILE="${WORK}/state/state.json"
export FAKE_INVOCATION_FILE="${WORK}/fake-invocation"
printf 'inv-seed\n' >"${FAKE_INVOCATION_FILE}"
unset FAKE_START_RC FAKE_NO_INVOCATION_BUMP FAKE_NO_STATE_WRITE FAKE_NEW_UPDATED_AT
seed_state() { # $1 = state, $2 = updated_at (wall clock), $3 = run_seq (default 41)
  printf '{"version":2,"state":"%s","detail":"sessions=1 uploads=0 audit_objects=3 recordings_objects=1 heartbeat_age=45s recording recordings/%s.tar session %s","updated_at":"%s","run_seq":%s,"last_notify_epoch":0}\n' \
    "$1" "${SID}" "${SID}" "$2" "${3:-41}" >"${WORK}/state/state.json"
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
]:
    if actual is not expected:
        raise SystemExit("should_notify %s: expected %r got %r" % (label, expected, actual))

captured = []


class Response:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def fake_urlopen(request, timeout=None):
    captured.append(request)
    return Response()


module.urllib.request.urlopen = fake_urlopen
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


module.urllib.request.urlopen = failing_urlopen
if module.notify(config, "alert", "detail-body") is not False:
    raise SystemExit("notify must return False when the push fails")

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


module.urllib.request.urlopen = flaky_urlopen
captured[:] = []
verdict = ["alert"]
module.run_checks = lambda config, now: (verdict[0], "detail")

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
flaky["fail"] = True
codes.append(module.main())  # recovery transition: push attempted, fails
if len(captured) != 3:
    raise SystemExit("failed recovery must attempt exactly one push, got %d" % len(captured))
record = json.load(open(state_path))
if (record["state"] != "ok"
        or int(record.get("state_since_run") or 0) <= int(record.get("last_notify_run") or 0)
        or record.get("last_notify_epoch") != 1):
    raise SystemExit("failed recovery must record the ok transition (state_since_run > last_notify_run) without advancing last_notify_epoch: %r" % record)
flaky["fail"] = False
codes.append(module.main())  # next green run retries the recovery push
if len(captured) != 4:
    raise SystemExit("failed recovery must retry on the next green run, got %d" % len(captured))
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
PY
then ok "ntfy: transitions push, repeats suppress, 30-min renotify + failed-recovery retry (fake notifier)"; else bad "ntfy bookkeeping test failed"; fi

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

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
