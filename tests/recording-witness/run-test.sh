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
#   (d) verdicts on mocked S3 metadata: healthy -> ok; stale heartbeat ->
#       alert heartbeat-stale; session.start older than the grace with no
#       recording object/upload -> alert recording-gap; an in-progress upload
#       with an old session.end -> alert completer-lag; the long-live-session
#       negative (old upload, NO session.end) stays ok (review finding 2);
#       a missing <seq> -> alert sequence-gap; a repeated (sid, seq) ->
#       alert sequence-duplicate; unrecognized session keys ->
#       alert naming-contract;
#   (e) fail-closed: a failing listing run reports error (exit 2) while the
#       last baseline in state.json is held;
#   (f) strictly list-only: every request the witness makes is a signed GET
#       list call (ListObjectsV2 / ListMultipartUploads) — no HEAD, no
#       object GET, no ListParts, no write; pagination is followed;
#   (g) the 0600 env file holds the key and the witness never prints it;
#   (h) install renders all four artifacts (mode 0600 env) and a later
#       provision without the env removes them (no stale timer).
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

fixture() { cat >"${FIXTURE}"; }

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
    if not entry["ok"] and "fixture failure mode" not in entry["note"]:
        violations.append("rejected request: %s" % entry["note"])
    if "list-type=2" not in entry["note"] and "uploads" not in entry["note"] and entry["ok"]:
        violations.append("non-list OK request: %s" % entry["note"])
    for forbidden in ("partNumber=", "uploadId=", "?acl", "?versioning"):
        if forbidden in entry["path"]:
            violations.append("forbidden query %s in %s" % (forbidden, entry["path"]))
    if "continuation-token=" in entry["path"]:
        pagination += 1

if entries < 20:
    violations.append("too few requests observed (%d) - scenarios did not run" % entries)
if pagination < 1:
    violations.append("no continuation-token request - pagination not followed")
if sig_ok < 1:
    violations.append("no request passed full SigV4 signature verification")
if not signed_shape:
    violations.append("no request carried the expected SigV4 SignedHeaders shape")

if violations:
    for violation in violations:
        print("VIOLATION " + violation)
    sys.exit(1)
print("requests=%d pagination=%d sig_ok=%d" % (entries, pagination, sig_ok))
PY
then ok "every witness request was a signed list call (no HEAD/GET-object/ListParts/write)"; else bad "list-only/SigV4 proof failed"; fi

# ---- (g) the key is never printed ----------------------------------------
if grep -q 'SENTINEL' "${WORK}/witness.out" "${WORK}/witness.err" "${WORK}/state/verdict.log" "${WORK}/state/state.json" 2>/dev/null; then
  bad "the witness printed key material somewhere"
else
  ok "the witness never prints the key (stdout/stderr/verdict/state clean)"
fi
grep -q 'SENTINEL' "${WORK}/witness.env" && ok "the env file holds the key (0600)" || bad "env fixture missing the key"

# ---- (h) install + disable path (fake systemctl, throwaway paths) --------
FAKEBIN="${WORK}/bin"
mkdir -p "${FAKEBIN}"
cat >"${FAKEBIN}/systemctl" <<'FAKE'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${FAKE_SYSTEMCTL_LOG}"
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
if grep -q 'enable --now pc-recording-witness.timer' "${FAKE_SYSTEMCTL_LOG}" 2>/dev/null; then
  ok "install enables the timer"
else
  bad "install did not enable the timer: $(cat "${FAKE_SYSTEMCTL_LOG}" 2>/dev/null)"
fi

recording_witness_disable
if [ ! -e "${RECORDING_WITNESS_SBIN}" ] && [ ! -e "${RECORDING_WITNESS_ENV_FILE}" ] && [ ! -e "${RECORDING_WITNESS_SERVICE}" ] && [ ! -e "${RECORDING_WITNESS_TIMER}" ]; then
  ok "disable removes script + env + units (no stale timer)"
else
  bad "disable left artifacts behind"
fi
if grep -q 'disable --now pc-recording-witness.timer' "${FAKE_SYSTEMCTL_LOG}" 2>/dev/null; then
  ok "disable stops and disables the timer"
else
  bad "disable did not disable the timer"
fi
if recording_witness_disable; then ok "disable is idempotent"; else bad "second disable failed"; fi

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
