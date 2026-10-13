#!/usr/bin/env bash
# tests/gatus-pull/run-test.sh — dynamic status-page puller (issue #186).
#
# Offline, cred-free: extracts the REAL puller span from
# scripts/010-provision.sh (`# --- BEGIN GATUS PULLER ...`; never a copy),
# renders the on-box wrapper (bash + embedded stdlib-only Python), and drives
# the real Python against:
#   - a PATH-stubbed `curl` (manifest transport, recorded argv + per-URL
#     fixtures: .code/.body/.headers/.exit), so the pinned curl flags and the
#     If-None-Match behavior are proven on the real call path;
#   - a local HTTP stub that serves the statuses API from the fragment file
#     (the same shape the puller computes) and records ntfy POSTs;
#   - a sitecustomize resolver stub (the OS DNS resolver is the only stubbed
#     piece; the puller's own resolution logic runs).
# What it proves:
#   (a) the rendered wrapper is valid bash, the embedded module compiles, and
#       the module is stdlib-only (no PyYAML) with a strict fragment grammar;
#   (b) a valid tenant + platform manifest renders the EXACT golden fragment
#       (tests/gatus-pull/expected-fragment.yaml), every row carries
#       client.ignore-redirect, and the write is atomic (no temp leftovers);
#   (c) every tenant/platform validation rule is red, fail-closed (rc 0, no
#       write, last-known-good held), incl. the empty-list rejection, the
#       disabled:true opt-out, reserved names, case-folded duplicates, URL
#       allowlist/charset/port/userinfo/query/`$`/control chars, caps,
#       version/tenant/generated_at, and the SSRF resolution guard;
#   (d) platform schema: valid + allowlist rejects + alerts-field absent +
#       own name set/caps;
#   (e) 404/410 is not-published (no failure counter); 5xx counts per channel
#       and the 3-failure ladder pushes one notice + a recovery message;
#   (f) identical rendered bytes are a no-op; a known ETag is sent as
#       If-None-Match and a 304 keeps the last-known-good;
#   (g) a candidate rejected by the local statuses-API key set restores
#       .last-good, pushes a notice and exits 1 (nothing is committed);
#   (h) removals are notified by name from a successful valid fetch only;
#   (i) merged-key uniqueness against config.yaml's static rows fails closed;
#   (j) the two-writer boundary (config.yaml is never written; the fragment
#       never carries a .yaml temp name) and the file:// seam (local only;
#       a remote manifest declaring file:// is red);
#   (k) install/disable: 0755 script, 0600 env, seeded fragment, hardened
#       units with flock + jitter, and disable removes the artifacts;
#   (l) no secret (NTFY_TOKEN) is ever logged.
set -euo pipefail

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HARNESS_DIR}/../.." && pwd)"
PROVISION="${ROOT}/scripts/010-provision.sh"
CI="${ROOT}/.github/workflows/ci.yml"
GOLDEN="${HARNESS_DIR}/expected-fragment.yaml"

WORK="$(mktemp -d /tmp/gatus-pull.XXXXXX)"
SERVER_PID=""
cleanup() {
  if [ -n "${SERVER_PID}" ]; then
    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
  rm -rf "${WORK}"
}
trap cleanup EXIT

command -v python3 >/dev/null 2>&1 || { printf 'FAIL python3 is required\n'; exit 1; }

pass=0
fail=0
MIN_CHECKS=178
ok()  { pass=$((pass + 1)); printf 'ok   %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL %s\n' "$1"; }
is()  { # $1 label, $2 expected, $3 actual
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi
}
has() { # $1 label, $2 haystack, $3 needle
  case "$2" in *"$3"*) ok "$1" ;; *) bad "$1 (missing: $3)" ;; esac
}
lacks() { # $1 label, $2 haystack, $3 needle
  case "$2" in *"$3"*) bad "$1 (unexpected: $3)" ;; *) ok "$1" ;; esac
}

# ---- extract the real span (markers must be unique) -----------------------
BEGIN='# --- BEGIN GATUS PULLER (tests/gatus-pull extracts this span; keep markers) ---'
END='# --- END GATUS PULLER ---'
for marker in "$BEGIN" "$END"; do
  count="$(grep -cF -- "$marker" "$PROVISION" || true)"
  [ "$count" = "1" ] || { printf 'FAIL marker %s found %s times\n' "$marker" "${count:-0}"; exit 1; }
done
begin_line="$(grep -nF -- "$BEGIN" "$PROVISION" | cut -d: -f1)"
end_line="$(grep -nF -- "$END" "$PROVISION" | cut -d: -f1)"
sed -n "$((begin_line + 1)),$((end_line - 1))p" "$PROVISION" >"${WORK}/span.src"
[ -s "${WORK}/span.src" ] || { printf 'FAIL extracted puller span is empty\n'; exit 1; }

cat >"${WORK}/stubs.src" <<'EOF'
log()  { printf 'harness: %s\n' "$*" >&2; }
warn() { printf 'harness WARNING: %s\n' "$*" >&2; }
die()  { printf 'FAIL(die): %s\n' "$*" >&2; exit 1; }
EOF
# shellcheck disable=SC1090  # extracted span, path is fixed above
source "${WORK}/span.src"
for fn in gatus_puller_mode render_gatus_puller render_gatus_puller_service \
          render_gatus_puller_timer gatus_puller_install gatus_puller_disable \
          gatus_puller_print_state gatus_puller_run_once; do
  declare -f "$fn" >/dev/null || { printf 'FAIL extraction did not yield %s\n' "$fn"; exit 1; }
done

# ---- (a) rendered wrapper + embedded module -------------------------------
render_gatus_puller >"${WORK}/pull.sh"
if bash -n "${WORK}/pull.sh"; then ok "rendered puller parses (bash -n)"; else bad "rendered puller fails bash -n"; fi
has "wrapper sources the env file" "$(cat "${WORK}/pull.sh")" '. "$ENV_FILE"'
has "wrapper execs python3 with args" "$(cat "${WORK}/pull.sh")" 'exec python3 - "$@" <<'"'"'GATUS_PULLER_PY_EOF'"'"''
if command -v shellcheck >/dev/null 2>&1; then
  if shellcheck -S warning "${WORK}/pull.sh"; then ok "rendered puller passes shellcheck -S warning"; else bad "rendered puller fails shellcheck -S warning"; fi
else
  printf 'note: shellcheck not installed - lint tooth skipped here (CI runs it)\n'
fi
py_begin="$(grep -nF "exec python3 - \"\$@\" <<'GATUS_PULLER_PY_EOF'" "$PROVISION" | cut -d: -f1)"
py_end="$(grep -n '^GATUS_PULLER_PY_EOF$' "$PROVISION" | cut -d: -f1)"
[ -n "$py_begin" ] && [ -n "$py_end" ] || { printf 'FAIL could not locate the embedded Python span\n'; exit 1; }
sed -n "$((py_begin + 1)),$((py_end - 1))p" "$PROVISION" >"${WORK}/module.py"
if python3 -m py_compile "${WORK}/module.py"; then ok "embedded puller module compiles"; else bad "embedded puller module does not compile"; fi
lacks "module is stdlib-only (no PyYAML import)" "$(cat "${WORK}/module.py")" "import yaml"
has "module documents the strict grammar" "$(cat "${WORK}/module.py")" "strict line grammar"
has "module has the strict grammar parser" "$(cat "${WORK}/module.py")" "def verify_fragment_text"
has "module resolves accepted hosts once" "$(cat "${WORK}/module.py")" "class Resolver"
has "module rejects non-global addresses" "$(cat "${WORK}/module.py")" "not ip.is_global"
has "module carries the file:// seam" "$(cat "${WORK}/module.py")" 'url.startswith("file://")'
has "module keeps a .last-good sibling" "$(cat "${WORK}/module.py")" '.last-good'
has "module writes temp files that are not .yaml" "$(cat "${WORK}/module.py")" 'suffix=".tmp"'
for flag in '"--proto", "=https"' '"--max-redirs", "0"' '"--max-time", "20"' '"--max-filesize", str(MAX_BODY)' '"--speed-limit", "1000"' '"--speed-time", "10"' '"If-None-Match: " + etag'; do
  has "curl flag pinned: ${flag}" "$(cat "${WORK}/module.py")" "$flag"
done
lacks "no --max-redirs value other than 0" "$(cat "${WORK}/module.py")" '"--max-redirs", "10"'
# systemd hardening (rendered from the real functions)
render_gatus_puller_service >"${WORK}/puller.service"
render_gatus_puller_timer >"${WORK}/puller.timer"
for tooth in "NoNewPrivileges=yes" "ProtectSystem=strict" "ProtectHome=yes" "PrivateTmp=yes" \
             "CapabilityBoundingSet=" "ReadWritePaths=/etc/gatus /var/lib/piercloud" \
             "ExecStart=/usr/bin/flock -n -E 0 /var/lib/piercloud/gatus-pull.lock /usr/local/sbin/piercloud-gatus-pull.sh"; do
  has "service hardening: ${tooth}" "$(cat "${WORK}/puller.service")" "$tooth"
done
# ProtectSystem=strict makes /run read-only, so the lock must sit inside a
# ReadWritePaths entry or the first `systemctl start` fails on flock.
lock_path="$(sed -n 's|^ExecStart=/usr/bin/flock -n -E 0 \([^ ]*\) .*|\1|p' "${WORK}/puller.service")"
lock_dir="$(dirname "$lock_path")"
rw_paths="$(sed -n 's/^ReadWritePaths=//p' "${WORK}/puller.service")"
case " $rw_paths " in
  *" $lock_dir "*) ok "lock dir is writable under ProtectSystem=strict" ;;
  *) bad "lock dir ${lock_dir} is not in ReadWritePaths (${rw_paths})" ;;
esac
has "timer cadence 10 min" "$(cat "${WORK}/puller.timer")" "OnUnitInactiveSec=10min"
has "timer jitter" "$(cat "${WORK}/puller.timer")" "RandomizedDelaySec=2min"

# ---- stub curl + resolver + status/ntfy server ----------------------------
mkdir -p "${WORK}/bin" "${WORK}/stub"
cat >"${WORK}/bin/curl" <<'STUB_CURL'
#!/usr/bin/env bash
# PATH-stubbed curl for the puller harness: records argv, serves per-URL
# fixtures (.code/.body/.headers/.exit), prints the -w code.
set -u
dir="${STUB_CURL_DIR:?STUB_CURL_DIR unset}"
original=("$@")
body=""; headers=""; writefmt=""; url=""; hdr=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) body="$2"; shift 2 ;;
    -D) headers="$2"; shift 2 ;;
    -w) writefmt="$2"; shift 2 ;;
    -H) hdr="${hdr}${2}"$'\n'; shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
key="$(printf '%s' "$url" | tr -c 'A-Za-z0-9' '_')"
printf '%s\n' "${original[@]}" >"${dir}/last-args.txt"
printf '%s\n' "${original[@]}" >"${dir}/args.${key}.txt"
if [ -n "$headers" ]; then
  if [ -f "${dir}/${key}.headers" ]; then cp "${dir}/${key}.headers" "$headers"; else : >"$headers"; fi
fi
if [ -f "${dir}/${key}.exit" ]; then exit "$(cat "${dir}/${key}.exit")"; fi
code="$(cat "${dir}/${key}.code" 2>/dev/null || printf 200)"
if [ -n "$body" ]; then
  if [ -f "${dir}/${key}.body" ]; then cp "${dir}/${key}.body" "$body"; else : >"$body"; fi
fi
[ -n "$writefmt" ] && printf '%s' "$code"
exit 0
STUB_CURL
chmod +x "${WORK}/bin/curl"

cat >"${WORK}/stub/sitecustomize.py" <<'STUB_DNS'
import os
import socket

_real = socket.getaddrinfo


def _fake(host, port, *args, **kwargs):
    if host in ("127.0.0.1", "localhost", "::1") or ":" in host or host.replace(".", "").isdigit():
        return _real(host, port, *args, **kwargs)
    ips = os.environ.get("STUB_RESOLVE_IPS", "93.184.216.34").split(",")
    if ips == ["FAIL"]:
        raise socket.gaierror(-2, "Name or service not known")
    out = []
    for ip in ips:
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        out.append((family, socket.SOCK_STREAM, 6, "", (ip, port or 443)))
    return out


socket.getaddrinfo = _fake
STUB_DNS

cat >"${WORK}/status-server.py" <<'STUB_SERVER'
import http.server
import json
import os
import re
import sys

port_file, work = sys.argv[1], sys.argv[2]
fragment_file = os.path.join(work, "status.fragment")
mode_file = os.path.join(work, "status.mode")
notices = os.path.join(work, "notices.log")


def rows_from_fragment():
    path = ""
    try:
        with open(fragment_file, "r", encoding="utf-8") as handle:
            path = handle.read().strip()
        text = open(path, "r", encoding="utf-8", errors="replace").read()
    except OSError:
        return []
    rows = []
    current = None
    for line in text.splitlines():
        match = re.match(r"^  - name: (.+)$", line)
        if match:
            current = {"name": match.group(1), "group": ""}
            rows.append(current)
            continue
        match = re.match(r"^    group: (.+)$", line)
        if match and current is not None:
            current["group"] = match.group(1)
    return rows


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self.path.startswith("/api/"):
            self._send(404, b"")
            return
        try:
            mode = open(mode_file, "r", encoding="utf-8").read().strip()
        except OSError:
            mode = "ok"
        if mode == "garbage":
            self._send(200, b"not json")
            return
        if mode == "empty":
            self._send(200, b"[]")
            return
        rows = rows_from_fragment()
        if mode.startswith("drop:"):
            drop = mode.split(":", 1)[1]
            rows = [row for row in rows if row["name"] != drop]
        self._send(200, json.dumps(rows).encode("utf-8"))

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        with open(notices, "ab") as handle:
            handle.write(("Title: %s\nAuth: %s\n\n" % (
                self.headers.get("Title", ""),
                "yes" if self.headers.get("Authorization") else "no",
            )).encode("utf-8"))
            handle.write(body + b"\n---\n")
        self._send(200, b"")


server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
with open(port_file, "w") as handle:
    handle.write(str(server.server_address[1]))
server.serve_forever()
STUB_SERVER
python3 "${WORK}/status-server.py" "${WORK}/port.txt" "${WORK}" &
SERVER_PID=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do [ -s "${WORK}/port.txt" ] && break; sleep 0.2; done
PORT="$(cat "${WORK}/port.txt")"
[ -n "$PORT" ] || { printf 'FAIL status stub did not start\n'; exit 1; }

export STUB_RESOLVE_IPS=93.184.216.34
export PATH="${WORK}/bin:${PATH}"

# ---- case helpers ----------------------------------------------------------
CASE=""
new_case() {
  CASE="${WORK}/case-$1"
  rm -rf "$CASE"
  mkdir -p "$CASE/curl"
  FRAGMENT="$CASE/tenant-endpoints.yaml"
  STATE="$CASE/gatus-pull.state"
  CONFIG="$CASE/config.yaml"
  printf 'endpoints:\n' >"$CONFIG"
  {
    printf 'GATUS_PULL_ALIAS=pier\n'
    printf 'GATUS_PULL_ROLE=operator\n'
    printf 'GATUS_PULL_TENANT_URL=file://%s/tenant.json\n' "$CASE"
    printf 'GATUS_PULL_PLATFORM_URL=file://%s/platform.json\n' "$CASE"
    printf 'GATUS_PULL_FRAGMENT=%s\n' "$FRAGMENT"
    printf 'GATUS_PULL_CONFIG=%s\n' "$CONFIG"
    printf 'GATUS_PULL_STATE=%s\n' "$STATE"
    printf 'GATUS_PULL_STATUS_URL=http://127.0.0.1:%s/api/v1/endpoints/statuses\n' "$PORT"
    printf 'GATUS_PULL_NTFY_URL=http://127.0.0.1:%s\n' "$PORT"
    printf 'GATUS_PULL_ACCEPT_TIMEOUT=2\n'
    printf 'GATUS_PULL_ACCEPT_INTERVAL=1\n'
  } >"$CASE/env"
  python3 "${HARNESS_DIR}/fixtures.py" platform disabled-optout >"$CASE/platform.json"
  printf '%s\n' "$FRAGMENT" >"${WORK}/status.fragment"
  printf 'ok\n' >"${WORK}/status.mode"
  rm -f "${WORK}/notices.log"
}
set_https_urls() {
  {
    printf 'GATUS_PULL_TENANT_URL=https://meta-pier.piercloud.site/.well-known/pc-status.json\n'
    printf 'GATUS_PULL_PLATFORM_URL=https://platform.piercloud.net/.well-known/pc-status.json\n'
  } >>"$CASE/env"
}
set_topic() {
  printf 'NTFY_TOPIC=pc-test\n' >>"$CASE/env"
  [ -n "${1:-}" ] && printf 'NTFY_TOKEN=%s\n' "$1" >>"$CASE/env"
  return 0
}
stub_key() { printf '%s' "$1" | tr -c 'A-Za-z0-9' '_'; }
stub_fixture() { # $1 url, $2 kind (code|body|headers|exit), stdin = value
  local key; key="$(stub_key "$1")"
  cat >"$CASE/curl/${key}.$2"
}
seed() { ( cd "$CASE" && GATUS_PULLER_ENV_FILE="$CASE/env" PYTHONPATH="${WORK}/stub" bash "${WORK}/pull.sh" --seed >"$CASE/seed.out" 2>"$CASE/seed.err" ); }
pull() { ( cd "$CASE" && GATUS_PULLER_ENV_FILE="$CASE/env" PYTHONPATH="${WORK}/stub" STUB_CURL_DIR="$CASE/curl" bash "${WORK}/pull.sh" "$@" >"$CASE/stdout.log" 2>"$CASE/stderr.log" ); }
pull_rc() { local rc=0; pull "$@" || rc=$?; printf '%s' "$rc"; }
seed_once() { seed || true; }
notices() { cat "${WORK}/notices.log" 2>/dev/null || true; }
state_field() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get(sys.argv[2],{}).get(sys.argv[3],""))' "$STATE" "$1" "$2"; }

# ---- (b) exact golden fragment + redirect policy + atomicity ---------------
new_case golden
python3 "${HARNESS_DIR}/fixtures.py" tenant valid >"$CASE/tenant.json"
python3 "${HARNESS_DIR}/fixtures.py" platform valid >"$CASE/platform.json"
set_topic
seed_once
rc="$(pull_rc)"
is "valid manifests: pull exits 0" "0" "$rc"
if cmp -s "$FRAGMENT" "$GOLDEN"; then ok "valid manifests: exact golden fragment bytes"; else bad "valid manifests: fragment differs from the golden"; diff -u "$GOLDEN" "$FRAGMENT" | head -20 || true; fi
is "valid manifests: row count" "5" "$(grep -c '^  - name:' "$FRAGMENT")"
is "every rendered row carries ignore-redirect" \
  "$(grep -c '^  - name:' "$FRAGMENT")" "$(grep -c '^      ignore-redirect: true$' "$FRAGMENT")"
has "golden carries the seeded platform row" "$(cat "$FRAGMENT")" "  - name: platform"
has "golden carries the slice row" "$(cat "$FRAGMENT")" "  - name: your piercloud"
has "golden carries the private gate row" "$(cat "$FRAGMENT")" "  - name: private (gate)"
has "golden carries the platform host row" "$(cat "$FRAGMENT")" "  - name: host-01"
has "golden carries the tenant row" "$(cat "$FRAGMENT")" "  - name: blog"
has "golden carries the alias group" "$(cat "$FRAGMENT")" "    group: pier"
has "golden carries the platform group" "$(cat "$FRAGMENT")" "    group: platform"
case "$(cat "$FRAGMENT")" in
  *"shared (gate)"*) bad "no shared-gate row is seeded (no install-time signal)" ;;
  *) ok "no shared-gate row is seeded (no install-time signal)" ;;
esac
# Alert classes (D5): class 5 (night-emergency bridge) on platform/slice/gate
# rows, class 4 (native ntfy, priority 4, no resolve) on public tenant rows.
row_block() { awk -v n="$1" '$0 == "  - name: " n { f=1 } f && /^  - name: / && $0 != "  - name: " n { exit } f { print }' "$FRAGMENT"; }
has "class 4: tenant row uses native ntfy" "$(row_block blog)" "- type: ntfy"
lacks "class 4: tenant row carries no resolve bridge" "$(row_block blog)" "send-on-resolved"
has "class 4: tenant row pins priority 4" "$(row_block blog)" "priority: 4"
has "class 5: gate row uses the ntfy-JSON bridge" "$(row_block 'private (gate)')" "- type: custom"
has "class 5: gate row resolves at priority 3" "$(row_block 'private (gate)')" 'RESOLVED: "3"'
has "class 5: slice row uses the ntfy-JSON bridge" "$(row_block 'your piercloud')" "- type: custom"
is "valid manifests: no notices" "" "$(notices)"
[ -f "${FRAGMENT}.last-good" ] && ok "last-good sibling exists" || bad "last-good sibling missing"
if cmp -s "${FRAGMENT}.last-good" "$GOLDEN"; then bad "last-good is not the accepted candidate"; else ok "last-good is not the accepted candidate"; fi
if ls "$CASE"/.gatus-fragment-* >/dev/null 2>&1; then bad "atomic write left a temp file"; else ok "atomic write left no temp file"; fi
mtime_before="$(stat -c %Y "$FRAGMENT")"
sleep 1
rc="$(pull_rc)"
is "identical bytes: second pull exits 0" "0" "$rc"
has "identical bytes: no-op logged" "$(cat "$CASE/stderr.log")" "fragment unchanged (identical bytes)"
is "identical bytes: fragment mtime unchanged" "$mtime_before" "$(stat -c %Y "$FRAGMENT")"
rc="$(pull_rc --state)"
is "--state exits 0" "0" "$rc"
has "--state prints the rendered hash" "$(cat "$CASE/stdout.log")$(cat "$CASE/stderr.log")" "rendered_hash=sha256:"
has "--state prints last_success" "$(cat "$CASE/stdout.log")$(cat "$CASE/stderr.log")" "last_success"

# ---- (c) tenant validation red rules --------------------------------------
TENANT_RED="http-scheme port userinfo foreign-suffix ip-literal dollar control-char space quote backslash query fragment oversize-url too-many reserved-platform reserved-home reserved-slice reserved-host duplicate uppercase-name non-bool-alerts bad-version wrong-tenant future-generated-at bad-generated-at empty-list disabled-with-entries unknown-top-field unknown-entry-field endpoint-not-object endpoints-not-list file-scheme nested-three-labels deep-public"
for rule in $TENANT_RED; do
  new_case "red-${rule}"
  python3 "${HARNESS_DIR}/fixtures.py" tenant "$rule" >"$CASE/tenant.json"
  seed_once
  cp "$FRAGMENT" "$CASE/before.yaml"
  rc="$(pull_rc)"
  label="tenant red rule: ${rule}"
  if [ "$rc" = "0" ] && cmp -s "$FRAGMENT" "$CASE/before.yaml" \
     && grep -q "tenant manifest failure" "$CASE/stderr.log"; then
    ok "$label"
  else
    bad "$label (rc=$rc; fail-closed proof missing)"
  fi
done

# oversize raw body (over 64 KiB) is a fetch failure, not a parse
new_case red-oversize-body
python3 - "$CASE/tenant.json" <<'PY'
import json
import sys
doc = {"version": 1, "generated_at": "2026-10-12T07:00:00Z", "tenant": "pier",
       "note": "x" * 70000,
       "endpoints": [{"name": "blog", "url": "https://blog-pier.piercloud.site"}]}
open(sys.argv[1], "w").write(json.dumps(doc))
PY
seed_once
cp "$FRAGMENT" "$CASE/before.yaml"
rc="$(pull_rc)"
[ "$rc" = "0" ] && cmp -s "$FRAGMENT" "$CASE/before.yaml" && grep -q "over 65536 bytes" "$CASE/stderr.log" \
  && ok "tenant red rule: oversize-body" || bad "tenant red rule: oversize-body"

# SSRF resolution guard: an allowlisted host resolving to a private address
new_case red-private-resolution
python3 "${HARNESS_DIR}/fixtures.py" tenant valid >"$CASE/tenant.json"
seed_once
cp "$FRAGMENT" "$CASE/before.yaml"
rc=0; STUB_RESOLVE_IPS=10.0.0.5 pull || rc=$?
[ "$rc" = "0" ] && cmp -s "$FRAGMENT" "$CASE/before.yaml" && grep -q "non-public address" "$CASE/stderr.log" \
  && ok "tenant red rule: private resolution" || bad "tenant red rule: private resolution"
new_case red-loopback-resolution
python3 "${HARNESS_DIR}/fixtures.py" tenant valid >"$CASE/tenant.json"
seed_once
cp "$FRAGMENT" "$CASE/before.yaml"
rc=0; STUB_RESOLVE_IPS=127.0.0.1 pull || rc=$?
[ "$rc" = "0" ] && cmp -s "$FRAGMENT" "$CASE/before.yaml" && grep -q "non-public address" "$CASE/stderr.log" \
  && ok "tenant red rule: loopback resolution" || bad "tenant red rule: loopback resolution"
new_case red-unresolvable
python3 "${HARNESS_DIR}/fixtures.py" tenant valid >"$CASE/tenant.json"
seed_once
cp "$FRAGMENT" "$CASE/before.yaml"
rc=0; STUB_RESOLVE_IPS=FAIL pull || rc=$?
[ "$rc" = "0" ] && cmp -s "$FRAGMENT" "$CASE/before.yaml" && grep -q "does not resolve" "$CASE/stderr.log" \
  && ok "tenant red rule: unresolvable host" || bad "tenant red rule: unresolvable host"

# valid opt-out: disabled: true with an empty list writes no tenant rows
new_case optout
python3 "${HARNESS_DIR}/fixtures.py" tenant disabled-optout >"$CASE/tenant.json"
seed_once
cp "$FRAGMENT" "$CASE/before.yaml"
rc="$(pull_rc)"
[ "$rc" = "0" ] && cmp -s "$FRAGMENT" "$CASE/before.yaml" && ok "disabled: true opt-out is accepted (no rows)" \
  || bad "disabled: true opt-out is accepted (no rows)"
lacks "opt-out did not emit a tenant failure" "$(cat "$CASE/stderr.log")" "tenant manifest failure"

# valid allowlist shapes: the anchor name is inside the tenant allowlist
new_case allow-anchor
python3 "${HARNESS_DIR}/fixtures.py" tenant anchor-name >"$CASE/tenant.json"
seed_once
rc="$(pull_rc)"
[ "$rc" = "0" ] && grep -q 'name: blog' "$FRAGMENT" && grep -q 'url: https://anchor-01-pier.piercloud.net/healthz' "$FRAGMENT" \
  && ok "tenant allowlist accepts the anchor-01 host" || bad "tenant allowlist accepts the anchor-01 host"

# ---- (d) platform schema ---------------------------------------------------
PLATFORM_RED="alerts-field foreign-host wrong-path name-url-mismatch bad-name platform-name-mismatch too-many two-platform-rows"
for rule in $PLATFORM_RED; do
  new_case "pred-${rule}"
  python3 "${HARNESS_DIR}/fixtures.py" tenant disabled-optout >"$CASE/tenant.json"
  python3 "${HARNESS_DIR}/fixtures.py" platform "$rule" >"$CASE/platform.json"
  seed_once
  cp "$FRAGMENT" "$CASE/before.yaml"
  rc="$(pull_rc)"
  if [ "$rc" = "0" ] && cmp -s "$FRAGMENT" "$CASE/before.yaml" \
     && grep -q "platform manifest failure" "$CASE/stderr.log"; then
    ok "platform red rule: ${rule}"
  else
    bad "platform red rule: ${rule} (rc=$rc; fail-closed proof missing)"
  fi
done
new_case platform-hosts-only
python3 "${HARNESS_DIR}/fixtures.py" tenant disabled-optout >"$CASE/tenant.json"
python3 "${HARNESS_DIR}/fixtures.py" platform hosts-only >"$CASE/platform.json"
seed_once
rc="$(pull_rc)"
[ "$rc" = "0" ] && grep -q 'name: host-02' "$FRAGMENT" \
  && grep -q 'url: https://platform.piercloud.net/healthz' "$FRAGMENT" \
  && ok "platform hosts-only keeps the seeded platform row + adds the host" \
  || bad "platform hosts-only keeps the seeded platform row + adds the host"
new_case platform-optout
python3 "${HARNESS_DIR}/fixtures.py" tenant disabled-optout >"$CASE/tenant.json"
python3 "${HARNESS_DIR}/fixtures.py" platform disabled-optout >"$CASE/platform.json"
seed_once
cp "$FRAGMENT" "$CASE/before.yaml"
rc="$(pull_rc)"
[ "$rc" = "0" ] && cmp -s "$FRAGMENT" "$CASE/before.yaml" && ok "platform disabled opt-out is accepted" \
  || bad "platform disabled opt-out is accepted"

# ---- (e) 404 not-published vs the 5xx ladder -------------------------------
new_case not-published
set_https_urls
set_topic
stub_fixture "https://meta-pier.piercloud.site/.well-known/pc-status.json" code <<<"404"
stub_fixture "https://platform.piercloud.net/.well-known/pc-status.json" code <<<"404"
seed_once
rc="$(pull_rc)"; rc2="$(pull_rc)"
is "404: pull exits 0" "0" "$rc"
is "404: second pull exits 0" "0" "$rc2"
is "404: tenant failure counter stays 0" "0" "$(state_field tenant failures)"
is "404: platform failure counter stays 0" "0" "$(state_field platform failures)"
is "404: no notice pushed" "" "$(notices)"
has "404: logged as not-published" "$(cat "$CASE/stderr.log")" "not published"

new_case ladder
set_https_urls
set_topic "tk_supersecret"
stub_fixture "https://meta-pier.piercloud.site/.well-known/pc-status.json" code <<<"500"
stub_fixture "https://platform.piercloud.net/.well-known/pc-status.json" code <<<"404"
seed_once
cp "$FRAGMENT" "$CASE/before.yaml"
pull_rc >/dev/null
is "ladder: failure 1 counted" "1" "$(state_field tenant failures)"
is "ladder: no notice after 1 failure" "" "$(notices)"
pull_rc >/dev/null
is "ladder: failure 2 counted" "2" "$(state_field tenant failures)"
is "ladder: no notice after 2 failures" "" "$(notices)"
pull_rc >/dev/null
is "ladder: failure 3 counted" "3" "$(state_field tenant failures)"
has "ladder: one notice at the third failure" "$(notices)" "failing"
has "ladder: notice names the channel" "$(notices)" "tenant manifest"
has "ladder: token was sent to the ntfy endpoint" "$(notices)" "Auth: yes"
lacks "ladder: token never logged (stdout)" "$(cat "$CASE/stdout.log")" "tk_supersecret"
lacks "ladder: token never logged (stderr)" "$(cat "$CASE/stderr.log")" "tk_supersecret"
cmp -s "$FRAGMENT" "$CASE/before.yaml" && ok "ladder: rows stay last-known-good" || bad "ladder: rows stay last-known-good"
stub_fixture "https://meta-pier.piercloud.site/.well-known/pc-status.json" code <<<"200"
python3 "${HARNESS_DIR}/fixtures.py" tenant valid | stub_fixture "https://meta-pier.piercloud.site/.well-known/pc-status.json" body
pull_rc >/dev/null
is "ladder: recovery resets the counter" "0" "$(state_field tenant failures)"
has "ladder: recovery notice pushed" "$(notices)" "recovered"

# ---- (f) ETag / If-None-Match / 304 ---------------------------------------
new_case etag
set_https_urls
stub_fixture "https://meta-pier.piercloud.site/.well-known/pc-status.json" code <<<"200"
python3 "${HARNESS_DIR}/fixtures.py" tenant valid | stub_fixture "https://meta-pier.piercloud.site/.well-known/pc-status.json" body
printf 'ETag: "abc"\n' | stub_fixture "https://meta-pier.piercloud.site/.well-known/pc-status.json" headers
stub_fixture "https://platform.piercloud.net/.well-known/pc-status.json" code <<<"404"
seed_once
rc="$(pull_rc)"
is "etag: first pull exits 0" "0" "$rc"
has "etag: state stores the ETag" "$(cat "$STATE")" 'abc'
tenant_key="$(stub_key "https://meta-pier.piercloud.site/.well-known/pc-status.json")"
has "etag: first request carries the pinned curl flags" "$(cat "$CASE/curl/args.${tenant_key}.txt")" "--proto"
has "etag: first request uses =https proto" "$(cat "$CASE/curl/args.${tenant_key}.txt")" "=https"
has "etag: first request forbids redirects" "$(cat "$CASE/curl/args.${tenant_key}.txt")" "--max-redirs"
has "etag: first request caps time" "$(cat "$CASE/curl/args.${tenant_key}.txt")" "--max-time"
has "etag: first request caps size" "$(cat "$CASE/curl/args.${tenant_key}.txt")" "--max-filesize"
has "etag: first request pins speed-limit" "$(cat "$CASE/curl/args.${tenant_key}.txt")" "--speed-limit"
stub_fixture "https://meta-pier.piercloud.site/.well-known/pc-status.json" code <<<"304"
mtime_before="$(stat -c %Y "$FRAGMENT")"
sleep 1
rc="$(pull_rc)"
is "etag: 304 pull exits 0" "0" "$rc"
has "etag: 304 sends If-None-Match" "$(cat "$CASE/curl/args.${tenant_key}.txt")" 'If-None-Match: "abc"'
has "etag: 304 is a no-op" "$(cat "$CASE/stderr.log")" "fragment unchanged (identical bytes)"
is "etag: 304 keeps the fragment bytes" "$mtime_before" "$(stat -c %Y "$FRAGMENT")"

# ---- (g) acceptance mismatch -> .last-good restore -------------------------
new_case accept
python3 "${HARNESS_DIR}/fixtures.py" tenant valid-two >"$CASE/tenant.json"
set_topic
seed_once
rc="$(pull_rc)"
is "accept: initial pull exits 0" "0" "$rc"
cp "$FRAGMENT" "$CASE/accepted.yaml"
python3 "${HARNESS_DIR}/fixtures.py" tenant valid >"$CASE/tenant.json"
printf 'drop:blog\n' >"${WORK}/status.mode"
rc="$(pull_rc)"
is "accept: rejected candidate exits 1" "1" "$rc"
cmp -s "$FRAGMENT" "$CASE/accepted.yaml" && ok "accept: fragment restored to last-good" || bad "accept: fragment restored to last-good"
cmp -s "${FRAGMENT}.last-good" "$CASE/accepted.yaml" && ok "accept: .last-good holds the accepted fragment" || bad "accept: .last-good holds the accepted fragment"
has "accept: rejection notice pushed" "$(notices)" "candidate rejected"
is "accept: rejected entries are not committed" "2" "$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["tenant"]["entries"]))' "$STATE")"
printf 'ok\n' >"${WORK}/status.mode"

# ---- (g2) crash window: an unaccepted in-place candidate is re-gated -------
new_case crash
python3 "${HARNESS_DIR}/fixtures.py" tenant valid >"$CASE/tenant.json"
set_topic
seed_once
pull_rc >/dev/null
cp "$FRAGMENT" "$CASE/accepted.yaml"
# Simulate a kill between the write and the acceptance commit: the fragment
# bytes are the fresh candidate, the state never recorded them as accepted.
python3 - "$STATE" <<'PY'
import json
import sys
state = json.load(open(sys.argv[1]))
state.pop("rendered_hash", None)
open(sys.argv[1], "w").write(json.dumps(state))
PY
printf 'drop:blog\n' >"${WORK}/status.mode"
rc="$(pull_rc)"
is "crash window: unaccepted no-op candidate exits 1" "1" "$rc"
has "crash window: re-acceptance rejects and notices" "$(notices)" "candidate rejected"
has "crash window: no-op was re-gated, not adopted" "$(cat "$CASE/stderr.log")" "fragment unchanged but not yet accepted"
printf 'ok\n' >"${WORK}/status.mode"

# ---- (h) removal notice ----------------------------------------------------
new_case removal
python3 "${HARNESS_DIR}/fixtures.py" tenant valid-two >"$CASE/tenant.json"
set_topic
seed_once
pull_rc >/dev/null
python3 "${HARNESS_DIR}/fixtures.py" tenant valid >"$CASE/tenant.json"
rm -f "${WORK}/notices.log"
rc="$(pull_rc)"
is "removal: pull exits 0" "0" "$rc"
has "removal: notice lists the removed name" "$(notices)" "jobs"
has "removal: notice title names removals" "$(notices)" "rows removed"
lacks "removal: fragment no longer carries the removed row" "$(cat "$FRAGMENT")" "name: jobs"
is "removal: last_tenant_names updated" '["blog"]' "$(python3 -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1])).get("last_tenant_names")))' "$STATE")"
rm -f "${WORK}/notices.log"
pull_rc >/dev/null
is "removal: no repeat notice on the next identical pull" "" "$(notices)"

# ---- (i) merged uniqueness vs config.yaml ----------------------------------
new_case collision
python3 "${HARNESS_DIR}/fixtures.py" tenant valid >"$CASE/tenant.json"
printf 'endpoints:\n  - name: blog\n    group: pier\n    url: https://static.example.com/\n' >"$CONFIG"
cp "$CONFIG" "$CASE/config.before"
seed_once
cp "$FRAGMENT" "$CASE/before.yaml"
rc="$(pull_rc)"
is "merged uniqueness: collision exits 1 (counted, not fatal)" "1" "$rc"
has "merged uniqueness: names the collision" "$(cat "$CASE/stderr.log")" "collide"
is "merged uniqueness: tenant failure counted" "1" "$(state_field tenant failures)"
is "merged uniqueness: platform failure counted" "1" "$(state_field platform failures)"
cmp -s "$FRAGMENT" "$CASE/before.yaml" && ok "merged uniqueness: fragment not written" || bad "merged uniqueness: fragment not written"
cmp -s "$CONFIG" "$CASE/config.before" && ok "two-writer boundary: config.yaml untouched" || bad "two-writer boundary: config.yaml untouched"

# ---- (j) two-writer boundary + install/disable -----------------------------
render_span="$(sed -n "/gatus-render:start/,/gatus-render:end/p" "$PROVISION")"
case "$render_span" in
  *"tenant-endpoints"*) bad "010 render span never names the fragment" ;;
  *) ok "010 render span never names the fragment" ;;
esac
gatus_run="$(grep -A8 'docker run -d --name gatus' "$PROVISION" | sed -n '1,/GATUS_IMAGE/p')"
has "gatus container runs in directory mode" "$gatus_run" "-e GATUS_CONFIG_PATH=/config"
lacks "gatus container carries no NTFY env" "$gatus_run" "-e NTFY"
lacks "gatus container carries no GATUS_ENDPOINTS env" "$gatus_run" "-e GATUS_ENDPOINTS"
lacks "gatus container carries no token env" "$gatus_run" "TOKEN"
has "gatus container mounts the config dir" "$gatus_run" ":/config:ro"
lacks "puller span never writes GATUS_CONFIG" "$(cat "${WORK}/span.src")" '>"$GATUS_CONFIG"'
new_case boundary
python3 "${HARNESS_DIR}/fixtures.py" tenant disabled-optout >"$CASE/tenant.json"
python3 "${HARNESS_DIR}/fixtures.py" platform disabled-optout >"$CASE/platform.json"
printf 'endpoints:\n  - name: tang (via Caddy)\n' >"$CONFIG"
cp "$CONFIG" "$CASE/config.before"
seed_once
rc="$(pull_rc)"
is "boundary: seed-only pull exits 0" "0" "$rc"
cmp -s "$CONFIG" "$CASE/config.before" && ok "two-writer boundary: config.yaml byte-identical after a pull" || bad "two-writer boundary: config.yaml byte-identical after a pull"
if ls "$CASE"/*.yaml.tmp >/dev/null 2>&1; then bad "boundary: .yaml temp file appeared"; else ok "boundary: no .yaml temp file appeared"; fi

# install / disable (throwaway paths + systemctl stub)
mkdir -p "${WORK}/install" "${WORK}/sysbin"
cat >"${WORK}/sysbin/systemctl" <<'STUB_SYSTEMCTL'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${STUB_SYSTEMCTL_LOG:?}"
exit 0
STUB_SYSTEMCTL
chmod +x "${WORK}/sysbin/systemctl"
install_env() {
  export STATUS_PULLER=on TENANT_USER=pier ANCHOR_ROLE=operator NTFY_TOPIC=pc-test NTFY_TOKEN=tk_supersecret
  export GATUS_PULLER_SBIN="${WORK}/install/sbin/pull.sh"
  export GATUS_PULLER_ENV_FILE="${WORK}/install/etc/gatus-pull.env"
  export GATUS_PULLER_STATE_DIR="${WORK}/install/var"
  export GATUS_PULLER_STATE_FILE="${WORK}/install/var/gatus-pull.state"
  export GATUS_PULLER_FRAGMENT="${WORK}/install/etc/gatus/tenant-endpoints.yaml"
  export GATUS_PULLER_CONFIG_DIR="${WORK}/install/etc/gatus"
  export GATUS_PULLER_SERVICE="${WORK}/install/systemd/piercloud-gatus-pull.service"
  export GATUS_PULLER_TIMER="${WORK}/install/systemd/piercloud-gatus-pull.timer"
  export GATUS_CONFIG="${WORK}/install/etc/gatus/config.yaml"
  mkdir -p "$(dirname "$GATUS_CONFIG")"
  printf 'endpoints:\n' >"$GATUS_CONFIG"
  export STUB_SYSTEMCTL_LOG="${WORK}/install/systemctl.log"
  export PATH="${WORK}/sysbin:${PATH}"
}
install_env
( source "${WORK}/stubs.src"; source "${WORK}/span.src"; gatus_puller_install ) \
  >"${WORK}/install/out.log" 2>"${WORK}/install/err.log" || true
[ -x "${WORK}/install/sbin/pull.sh" ] && ok "install: script installed 0755" || bad "install: script installed 0755"
is "install: env file mode 0600" "600" "$(stat -c %a "${WORK}/install/etc/gatus-pull.env" 2>/dev/null || echo missing)"
is "install: seeded fragment mode 0644" "644" "$(stat -c %a "${WORK}/install/etc/gatus/tenant-endpoints.yaml" 2>/dev/null || echo missing)"
is "install: service unit mode 0644" "644" "$(stat -c %a "${WORK}/install/systemd/piercloud-gatus-pull.service" 2>/dev/null || echo missing)"
has "install: env carries the tenant manifest URL" "$(cat "${WORK}/install/etc/gatus-pull.env")" "meta-pier.piercloud.site/.well-known/pc-status.json"
has "install: env carries the platform manifest URL" "$(cat "${WORK}/install/etc/gatus-pull.env")" "platform.piercloud.net/.well-known/pc-status.json"
has "install: env carries the ntfy topic" "$(cat "${WORK}/install/etc/gatus-pull.env")" "NTFY_TOPIC=pc-test"
has "install: seeded fragment carries the shared rows" "$(cat "${WORK}/install/etc/gatus/tenant-endpoints.yaml")" "name: your piercloud"
has "install: systemctl daemon-reload called" "$(cat "${WORK}/install/systemctl.log")" "daemon-reload"
has "install: timer enabled" "$(cat "${WORK}/install/systemctl.log")" "enable piercloud-gatus-pull.timer"
( source "${WORK}/stubs.src"; source "${WORK}/span.src"; gatus_puller_disable ) \
  >>"${WORK}/install/out.log" 2>>"${WORK}/install/err.log" || true
[ ! -e "${WORK}/install/etc/gatus/tenant-endpoints.yaml" ] && ok "disable: fragment removed with the puller" || bad "disable: fragment removed with the puller"
[ ! -e "${WORK}/install/systemd/piercloud-gatus-pull.timer" ] && ok "disable: timer removed" || bad "disable: timer removed"
[ ! -e "${WORK}/install/sbin/pull.sh" ] && ok "disable: script removed" || bad "disable: script removed"

# seed-only-when-absent
new_case seed-absent
seed_once
cp "$FRAGMENT" "$CASE/seed.yaml"
rc=0; seed || rc=$?
is "seed: second seed exits 0" "0" "$rc"
has "seed: second seed leaves the file untouched" "$(cat "$CASE/seed.err")" "already present"
cmp -s "$FRAGMENT" "$CASE/seed.yaml" && ok "seed: bytes unchanged" || bad "seed: bytes unchanged"

# ---- CI wiring -------------------------------------------------------------
has "CI runs this harness" "$(cat "$CI")" "tests/gatus-pull/run-test.sh"
has "CI path gate covers this harness" "$(cat "$CI")" "gatus-pull"

printf '\n%s passed, %s failed\n' "$pass" "$fail"
if [ "$pass" -lt "$MIN_CHECKS" ]; then
  printf 'FAIL check-count floor: %s < %s\n' "$pass" "$MIN_CHECKS"
  fail=$((fail + 1))
fi
[ "$fail" -eq 0 ]
