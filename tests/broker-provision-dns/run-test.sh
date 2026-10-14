#!/usr/bin/env bash
# tests/broker-provision-dns/run-test.sh — b3b (#189): the provision DNS
# stage writes through the pc-control broker, and the direct provider-token
# writer is retired.
#
# Static, offline harness (no network, no credentials): pins the shape of the
# provision.yml `anchor-dns` job (broker lib call over OIDC, managed-lane
# guard, tenant environment, resolved IPv4, fail-before-thumbprint ordering),
# proves the retired provider surface (script, harness, variable and secret
# names) is gone from every production surface (test-tree scripts included;
# the `run-test.sh` pin records and the two by-design retirement records
# docs/security-posture.md / docs/verification.md excepted), and cross-checks that the
# committed CI wiring still names every harness (a dropped run-list line
# cannot silently skip one). All extractions are block-scalar-aware: a decoy
# `|`/`>` scalar (anchors/tags/quoted keys included) that quotes the job or
# the CI run step cannot stand in for the real one, and the raw
# exactly-one-job-key counts catch a form the stripper does not recognise.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
PROV=".github/workflows/provision.yml"
CI=".github/workflows/ci.yml"
LIB=".github/scripts/lib/broker-dns.sh"
REPORT_LIB=".github/scripts/lib/broker-report.sh"
BIND_E2E="tests/bind-e2e/run-bind-e2e.sh"

pass=0
fail=0
ok()  { pass=$((pass + 1)); printf 'ok   %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL %s\n' "$1"; }
is()  { # $1 label, $2 expected, $3 actual
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi
}
contains() { # $1 label, $2 needle, $3 haystack
  case "$3" in *"$2"*) ok "$1" ;; *) bad "$1 (missing '$2')" ;; esac
}
lacks() { # $1 label, $2 needle, $3 haystack -- ok when the needle is ABSENT
  case "$3" in *"$2"*) bad "$1 (found '$2')" ;; *) ok "$1" ;; esac
}
lacks_word() { # $1 label, $2 word, $3 haystack -- word-boundary absence
  if grep -qwE -- "$2" <<<"$3"; then bad "$1 (found '$2')"; else ok "$1"; fi
}
# End line of a key's span, flow-aware: the span runs from the key's line
# ($2) to the first column-0 non-comment line seen while the flow depth is
# zero, no quoted scalar is open, and the line is neither a block-sequence
# entry (`- ...`) nor a block-scalar header (`|`/`>...`), both of which
# continue the key's value instead of starting a new top-level key
# (r26/r27 HIGH). A mixed-indent flow collection (`on: [`
# + column-0 entries + a later indent-2 entry) is one collection to YAML, so
# a plain "next column-0 line" terminator let an added trigger hide between
# them (r22 functional LOW).
#
# Comment and quote indicators are recognised at a YAML TOKEN BOUNDARY only,
# tracked as `tokend` (line start, whitespace, a flow indicator, or a REAL
# quote/collection close; `:` and `?` preserve the boundary state they are
# in). A mid-token `'`/`"`/`#`/`:`/`?` is plain-scalar content (`it's`,
# `a#b`, `a:#`, `a?#b`, `dogs'#`): treating one as an opener/comment dropped
# the rest of the line and closed a live flow early, hiding a trigger from
# every pin — the r23/r24 HIGH class across a `]`/`}` inside quotes, a
# mid-token `#`, the explicit-key `?`, a post-close `#`, a `:` before a flow
# value, and mid-plain quote chars (r23 red-team/functional, r24
# trust/functional). A double-quoted scalar's escape state is LINE-LOCAL:
# a `\` at EOL escapes the break itself, so it must not consume the next
# line's first character (r25 HIGH). Quoted contents are not counted at
# all, so a mis-read can only extend the span. Empty when no terminator is
# found (EOF).
flow_end() { # $1 file, $2 start line
  awk -v s="$2" '
    function sq() { return sprintf("%c", 39) }
    function depth(line,   i, c, d, tokend) {
      d = 0; tokend = 1
      for (i = 1; i <= length(line); i++) {
        c = substr(line, i, 1)
        if (q == "") {
          if (c == "#") { if (tokend) break; tokend = 0 }
          else if (c == "\"" || c == sq()) { if (tokend) { q = c }; tokend = 0 }
          else if (c == "[" || c == "{") { d++; tokend = 1 }
          else if (c == "]" || c == "}") { d--; tokend = 1 }
          else if (c == ",") { tokend = 1 }
          else if (c == " " || c == "\t") { tokend = 1 }
          else if (c != ":" && c != "?") { tokend = 0 }
        } else if (q == "\"") {
          if (esc) { esc = 0 }
          else if (c == "\\") { esc = 1 }
          else if (c == "\"") { q = ""; tokend = 1 }
          else { tokend = 0 }
        } else {
          if (c == sq()) {
            if (substr(line, i + 1, 1) == sq()) { i++ }
            else { q = ""; tokend = 1 }
          } else { tokend = 0 }
        }
      }
      # A trailing backslash inside a double-quoted scalar escapes the
      # LINE BREAK itself (YAML), so the escape is consumed by the newline
      # and must not leak into the next line: the continuation line has a
      # fresh first character. Carrying `esc` across lines let a `\`-at-EOL
      # + `\"` continuation close the scalar early, ending the `on:` span
      # at a column-0 line YAML still parses inside the open flow (r25 HIGH).
      if (q == "\"" && esc) esc = 0
      return d
    }
    NR == s { d = depth($0); next }
    NR > s {
      if ($0 ~ /^[[:space:]]*$/) { next }
      # A column-0 BLOCK SEQUENCE entry (`- x`, `-`, `- |`) continues the
      # current key value: YAML lets a block sequence sit at the same
      # indent as its parent key (`on:` then `- push`), and a block-scalar
      # entry hides indented content that no other pin sees (r26 HIGH).
      # A column-0 BLOCK SCALAR HEADER (`|`, `|-`, `>2-`, ...) is the
      # value NODE itself when it follows `on:` directly, and its content
      # is indented (r27 HIGH). Neither form is ever a top-level key, so
      # neither terminates the span.
      if (q == "" && d <= 0 && $0 ~ /^[^[:space:]#]/ && $0 !~ /^-([[:space:]]|$)/ && $0 !~ /^[|>]/) { print NR; exit }
      d += depth($0)
    }
  ' "$1"
}
# flow_end unit fixtures: the span end must never move EARLIER than the real
# YAML block (r23 HIGH regression). Each case pins the exact end line; a
# fixture with no terminator prints nothing (EOF extension).
fe_case() { # $1 expected end ("EOF" = no terminator), $2 label, $3 content
  local f got
  f="$(mktemp)"
  printf '%s' "$3" > "$f"
  got="$(flow_end "$f" 1)"
  rm -f "$f"
  if [ "$1" = "EOF" ]; then is "$2" "" "$got"; else is "$2" "$1" "$got"; fi
}
fe_case 5 "flow_end: quoted ] inside a flow does not end the span early" $'on: ["a]b",\npush,\n  pull_request_target,\n]\npermissions:\n'
fe_case 4 "flow_end: quoted } inside a flow mapping does not end the span early" $'on: {"a}b": x,\n  pull_request_target,\n}\npermissions:\n'
fe_case 7 "flow_end: mid-token # is plain content, not a comment" $'on: [a#b, [c,\npush,\n],\npush2,\n  pull_request_target,\n]\npermissions:\n'
fe_case 3 "flow_end: # after a flow comma is a comment" $'on: [a,# ]\npush]\npermissions:\n'
fe_case 5 "flow_end: ? explicit-key quoted scalar does not end the span early" $'on: [?\'a]b\',\npush,\n  pull_request_target,\n]\npermissions:\n'
fe_case 3 "flow_end: # after an explicit-key ? is a comment" $'on: [?# ]\npush]\npermissions:\n'
fe_case 5 "flow_end: # after a closing quote is a comment" $'on: [a, "b"# ] decoy\n, d,\n  pull_request_target,\n]\npermissions:\n'
fe_case 5 "flow_end: # after a closing collection is a comment" $'on: {"pull_request": {branches: [main]}# ] decoy\n, workflow_dispatch,\n  pull_request_target,\n}\npermissions:\n'
fe_case 5 "flow_end: quoted value after : in a flow mapping is not counted" $'on: {"pull_request": {"branches":"x]y"}\n, workflow_dispatch: null,\n  pull_request_target: null,\n}\npermissions:\n'
fe_case 3 "flow_end: multi-line quoted scalar continuation is not a terminator" $'on: "a\nb"\npermissions:\n'
fe_case 5 "flow_end: mid-token apostrophe does not open a quote" $'on: [it\'s, [a, b\'s,\n], push,\npull_request_target,\n]\npermissions:\n'
fe_case 5 "flow_end: mid-token double quote does not open a quote" $'on: [it"s, [a, b"s,\n], push,\npull_request_target,\n]\npermissions:\n'
fe_case 6 "flow_end: mid-plain apostrophe + # is content, not a comment" $'on: {"a": dogs\'# , "b": [c,\n]\n, workflow_dispatch,\n    pull_request_target,\n}\npermissions:\n'
fe_case 7 "flow_end: mid-plain : + # is content, not a comment" $'on: {push: {branches: [main, a:#], schedule: [{cron: \'0 0 * * *\',\n}],\n}\n,\n  pull_request_target: null,\n}\npermissions:\n'
fe_case "EOF" "flow_end: unterminated flow extends to EOF (no early end)" $'on: [it\'s,\n  push,\n'
fe_case 5 "flow_end: escaped line break keeps the quoted scalar open (r25 F1)" $'on: {push: {branches: ["x\\\n\\"]y", main, \'release/*\']},\nworkflow_dispatch: null,\n}\npermissions:\n'
fe_case 3 "flow_end: escaped line break then a real close ends at the terminator (r25 F1)" $'on: ["a\\\n" , b]\npermissions:\n'
fe_case 5 "flow_end: single-quoted close then # is a comment" $'on: [a, \'b\'# ] decoy\n, d,\n  pull_request_target,\n]\npermissions:\n'
fe_case 4 "flow_end: block-scalar entry under a column-0 sequence is pinned (r26 HIGH)" $'on:\n- >-\n  push\npermissions:\n'
fe_case 4 "flow_end: mapping entry under a column-0 sequence is pinned (r26 HIGH)" $'on:\n- push: null\n  pull_request_target: null\npermissions:\n'
fe_case 4 "flow_end: plain column-0 sequence entries are pinned (r26 HIGH)" $'on:\n- push\n- pull_request_target\npermissions:\n'
fe_case 4 "flow_end: bare column-0 block-scalar header is pinned (r27 HIGH)" $'on:\n|-\n  push\npermissions:\n'
fe_case 4 "flow_end: folded block-scalar header with indicators is pinned (r27 HIGH)" $'on:\n>2-\n  push\npermissions:\n'
fe_case 4 "flow_end: literal block-scalar entry under a column-0 sequence is pinned (r27 LOW)" $'on:\n- |\n  push\npermissions:\n'
fe_case 4 "flow_end: bare column-0 sequence entry is pinned (r27 LOW)" $'on:\n-\n  push\npermissions:\n'
fe_case 4 "flow_end: bare literal header with no indicators is pinned (r28 LOW)" $'on:\n|\n  push\npermissions:\n'
fe_case 4 "flow_end: bare folded header with no indicators is pinned (r28 LOW)" $'on:\n>\n  push\npermissions:\n'
fe_case 4 "flow_end: header with indicator and comment is pinned (r28 LOW)" $'on:\n|- # c\n  push\npermissions:\n'
fe_case 4 "flow_end: header with a trailing space is pinned (r28 LOW)" $'on:\n|- \n  push\npermissions:\n'

# Root-shape fail-closed (r24 red-team HIGH, r25 F2): every locator below
# matches COLUMN-0 lines, but YAML allows the root mapping itself to be
# indented while a column-0 multi-line quoted scalar carries decoy `on:`/
# `permissions:`/`jobs:` lines -- the pins would then hash decoy bytes and
# a real trigger/job added under the indented root changes nothing.
# Require no BOM, no column-0 `---`/`...`-prefixed line (ANY suffix:
# `--- &a` anchors an indented root, r25 F2), and a first content line
# that is a plain column-0 `key:` (an anchor/property-only first line
# leaves the root mapping indented under it). In-tree all seven start at
# column 0 with `name:`. Prints the reason, empty when the shape is OK.
root_shape_bad() { # $1 file
  local bom first bad=""
  bom="$(head -c3 "$1" | od -An -tx1 | tr -d ' \n' || true)"
  first="$(grep -m1 -E '^[[:space:]]*[^#[:space:]]' "$1" || true)"
  [ "$bom" = "efbbbf" ] && bad="BOM"
  if grep -qE '^(---|\.\.\.)' "$1"; then bad="${bad:+$bad, }document marker"; fi
  if [ -z "$first" ]; then
    bad="${bad:+$bad, }first content line indented or missing"
  elif ! grep -qE '^[A-Za-z_][A-Za-z0-9_-]*:' <<<"$first"; then
    bad="${bad:+$bad, }first content line is not a plain column-0 key"
  fi
  printf '%s' "$bad"
}
rs_case() { # $1 expected (OK/BAD), $2 label, $3 content
  local f got
  f="$(mktemp)"
  printf '%s' "$3" > "$f"
  got="$(root_shape_bad "$f")"
  rm -f "$f"
  if [ "$1" = "OK" ]; then is "$2" "" "$got"; else
    if [ -n "$got" ]; then ok "$2"; else bad "$2 (expected fail-closed)"; fi
  fi
}
rs_case OK  "root shape: plain name: first line" $'name: x\non: [push]\njobs: {}\n'
bomf="$(mktemp)"; printf '\xef\xbb\xbfname: x\n' > "$bomf"
contains "root shape: BOM fails closed" "BOM" "$(root_shape_bad "$bomf")"
rm -f "$bomf"
rs_case BAD "root shape: bare --- marker" $'---\nname: x\n'
rs_case BAD "root shape: --- with an anchor (r25 F2)" $'name: x\n--- &a\non: [push]\njobs: {}\n'
rs_case BAD "root shape: ... marker" $'...\n'
rs_case BAD "root shape: first content line indented" $'  name: x\n'
rs_case BAD "root shape: anchor-only first line" $'&a\n  name: x\n'

# YAML anchors relocate bytes: `env:\n  A: &a push` + `on: *a` puts the
# real trigger value in an unpinned child while the `on:` span pins only
# `on: *a`; an alias KEY (`run-name: &k "on"` + `*k: |-`) makes the locator
# pin decoy bytes (r28 red-team HIGH/MEDIUM — actionlint-clean, all four
# digests byte-identical). An alias cannot resolve without an anchor, so
# `&name` definitions are banned blanket in every workflow (node-start
# anchored; a mid-scalar `&&`, `2>&1` and glob stars stay legal). No in-tree use.
anchor_count() { # $1 file -- anchor-definition tokens at a NODE START
  # The name tail admits `&`, so any ampersand run (`&a`, `&&b`, `&&&b`, and
  # a bare `&&` = anchor `&`) is caught: go-yaml v4 (actionlint's parser,
  # the r29/r30 oracle) scans every `&` run as the name, while PyYAML/Psych
  # reject them -- the ban is fail-closed. The prefix is a NODE-START
  # context (`: `/`- ` value starts, flow `[`/`{`/`,`, line start, `?` (no
  # space required in flow), a tag), so a mid-scalar shell `&&`
  # (`make && make`, `2>&1 &&`, `[ -s x ] &&`) stays legal while the
  # r29-r32 lens anchor spellings are caught.
  grep -cE '(^[[:space:]]*|:[[:space:]]*|-[[:space:]]+|[[:space:]]*[\[{,][[:space:]]*|[?][[:space:]]*|[!][^[:space:]]*[[:space:]]+)&[^][:space:],{}]' "$1" || true
}
aa_case() { # $1 expected, $2 label, $3 content
  local f got
  f="$(mktemp)"
  printf '%s' "$3" > "$f"
  got="$(anchor_count "$f")"
  rm -f "$f"
  is "$2" "$1" "$got"
}
aa_case 1 "anchor ban: block anchor" $'env:\n  A: &a push\n'
aa_case 1 "anchor ban: flow anchor" $'x: [&a push]\n'
aa_case 1 "anchor ban: punctuation-start name (permissive-parser form)" $'x: &.a 1\n'
aa_case 0 "anchor ban: && is not an anchor" $'run: make && make test\n'
aa_case 0 "anchor ban: 2>&1 is not an anchor" $'run: cmd 2>&1\n'
aa_case 0 "anchor ban: branch glob is not an anchor" $'branches: [main, release/*]\n'
aa_case 1 "anchor ban: double-ampersand name (spec-permissive form)" $'x: &&b 1\n'
aa_case 0 "anchor ban: mid-scalar && is plain content" $'run: make &&test\n'
aa_case 1 "anchor ban: triple-ampersand name (go-yaml run)" $'env:\n  A: &&&b push\n'
aa_case 1 "anchor ban: bare double-ampersand name (go-yaml anchor &)" $'env:\n  A: && push\n'
aa_case 1 "anchor ban: tag-prefixed run name" $'x: !!str &&b 1\n'
aa_case 1 "anchor ban: flow colon with no space (r30 red-team F1)" $'env: {"k":&a push}\n'
aa_case 1 "anchor ban: flow explicit key with no space (r31 red-team)" $'x: {?&a y: z}\n'
aa_case 1 "anchor ban: explicit key with space (r32 red-team F2)" $'? &a x: y\n'
aa_case 1 "anchor ban: line-start block anchor (r31 functional F2)" $'key:\n  &a value\n'
aa_case 1 "anchor ban: block sequence anchor (r31 functional F2)" $'- &a value\n'
aa_case 0 "anchor ban: in-tree shell && continuation is content" $'run: cmd >/dev/null 2>&1 && cmd2\n'

[ -f "$PROV" ] || { printf 'FAIL provision.yml not found: %s\n' "$PROV"; exit 1; }
[ -f "$CI" ] || { printf 'FAIL ci.yml not found: %s\n' "$CI"; exit 1; }
[ -f "$LIB" ] || { printf 'FAIL broker-dns lib not found: %s\n' "$LIB"; exit 1; }
[ -f "$REPORT_LIB" ] || { printf 'FAIL broker-report lib not found: %s\n' "$REPORT_LIB"; exit 1; }

# A line-based extraction cannot tell a real job from a block scalar that
# quotes one (`run-name: |2` + a byte-copy of the job satisfies every text
# pin while the real job is gutted). Build a block-scalar-stripped structural
# view (NR + text) and locate the job THERE, then extract its lines from the
# original file: content lines of `key: |`/`>` scalars (any indicator form)
# are dropped, the header line stays. Anchors/tags (`&a |`, `!tag |`) and
# quoted keys are recognised; an explicit indentation indicator is header
# indent + N; a scalar whose first content line is not deeper than the header
# is empty and does not swallow the next line. A form the stripper does not
# recognise leaves its content in the structural view, where the raw
# exactly-one job-key count catches the duplicate.
PROV_STRUCT="$(awk '
function indent(s,   m) { match(s, /^ */); return RLENGTH }
function qprefix(s,   i, c, q) {
  q = 0
  for (i = 1; i <= length(s); i++) {
    c = substr(s, i, 1)
    if (c == "\"") { q = 1 - q }
    else if (c == "#" && q == 0) { return substr(s, 1, i - 1) }
  }
  return s
}
{
  if (skip) {
    if ($0 ~ /^[[:space:]]*$/) next
    i = indent($0)
    if (sind < 0) {
      if (i <= ihdr) { skip = 0 } else { sind = i; next }
    } else if (i >= sind) { next } else { skip = 0 }
  }
  printf "%d\t%s\n", NR, $0
  if (($0 ~ /^[[:space:]]*[^#[:space:]].*:[[:space:]]*((&[^[:space:]#]+|![^[:space:]#]+)[[:space:]]+)*[|>]([0-9][-+]?|[-+][0-9]?)?[[:space:]]*(#.*)?$/ || $0 ~ /^[[:space:]]*\?[[:space:]]*((&[^[:space:]#]+|![^[:space:]#]+)[[:space:]]+)*[|>]([0-9][-+]?|[-+][0-9]?)?[[:space:]]*(#.*)?$/) && qprefix($0) ~ /[|>]([0-9][-+]?|[-+][0-9]?)?[[:space:]]*$/) {
    ihdr = indent($0)
    if (match($0, /[|>][-+]?[0-9]/)) { sind = ihdr + substr($0, RSTART + RLENGTH - 1, 1) + 0 }
    else { sind = -1 }
    skip = 1
  }
}'  "$PROV")"
[ -n "$PROV_STRUCT" ] || { printf 'FAIL structural view of %s is empty\n' "$PROV"; exit 1; }
prov_raw_live="$(grep -v '^[[:space:]]*#' "$PROV")"
JOB_START="$(awk -F'\t' '$2 ~ /^  ((&[^[:space:]]+|![^[:space:]]+)[[:space:]]+)*anchor-dns:[[:space:]]*((&[^[:space:]]+|![^[:space:]]+)[[:space:]]*)?(#.*)?$/ {print $1; exit}' <<<"$PROV_STRUCT")"
[ -n "$JOB_START" ] || { printf 'FAIL anchor-dns job key not found in %s\n' "$PROV"; exit 1; }
JOB_END="$(awk -F'\t' -v s="$JOB_START" '$1 > s && $2 ~ /^  [^ #].*:[[:space:]]*((&[^[:space:]]+|![^[:space:]]+)[[:space:]]*)?(#.*)?$/ {print $1; exit}' <<<"$PROV_STRUCT")"
[ -n "$JOB_END" ] || { printf 'FAIL anchor-dns job end not found in %s\n' "$PROV"; exit 1; }
JOB_RAW="$(sed -n "$((JOB_START + 1)),$((JOB_END - 1))p" "$PROV")"
JOB="$(printf '%s\n' "$JOB_RAW" | grep -v '^[[:space:]]*#' || true)"
[ -n "$JOB" ] || { printf 'FAIL anchor-dns job body not found in %s\n' "$PROV"; exit 1; }
# Exactly one job key at top level: a decoy scalar the stripper does not
# recognise would add a second (and the structural view would pick it first).
is "exactly one anchor-dns job key line in provision.yml" "1" "$(grep -cE "^  (\\?[[:space:]]*)?((&[^[:space:]]+|![^[:space:]]+)[[:space:]]+)*(\"anchor-dns\"|'anchor-dns'|anchor-dns)[[:space:]]*:?[[:space:]]*((&[^[:space:]]+|![^[:space:]]+)[[:space:]]*)?(#.*)?$" "$PROV")"
# Spelling-agnostic structural census: every raw line that starts at indent 2
# with a non-space, non-comment character is a structural line of the
# workflow top level (on/concurrency/permissions children plus the eight job
# keys). A duplicate or decoy job key in ANY spelling (tags, quotes, hex
# escapes, explicit keys) adds one, so it fails until the pin is deliberately
# updated.
# The job SET is pinned by name: the indent-2 census is a count, so a new
# job added while a default-equivalent indent-2 line is removed (e.g.
# concurrency `cancel-in-progress: false`) keeps the count green. Any
# deliberate job addition/rename updates this pin.
JOBS_START="$(awk -F'\t' '$2 ~ /^jobs:[[:space:]]*(#.*)?$/ {print $1; exit}' <<<"$PROV_STRUCT")"
# Parsed to end-of-file: ending the span at the first column-0 line let a
# flow-collection continuation at column 0 truncate it and hide every job
# key after it (r17 F1). A top-level key after jobs (none in-tree, and not
# specially handled here) contributes its indent-2 lines to the set check, so
# the set changes and the pin must be deliberately updated.
JOBS_END=$(( $(awk 'END{print NR}' "$PROV") + 1 ))
if [ -n "$JOBS_START" ] && [ -n "$JOBS_END" ]; then
  # Every indent-2 non-comment line of the jobs block is a job key: normalise
  # the spelling (leading node properties, trailing comment, `: <value>`,
  # surrounding quotes) and compare the whole set, so a hostile key in ANY
  # spelling is either normalised into the set check (and reds as an unknown
  # name) or reds by not normalising to a known name.
  actual_jobs="$(sed -n "$((JOBS_START + 1)),$((JOBS_END - 1))p" "$PROV" \
    | grep -E '^  [^[:space:]]' | grep -vE '^  #' \
    | sed -e 's/[[:space:]]+#.*$//' -e 's/^  //' \
    | sed -E -e 's/^((&|!)[^[:space:]]+[[:space:]]+)+//' \
    | sed -e 's/[[:space:]]*:.*$//' \
    | sed -E -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//")" || true
  expected_jobs='visibility-banner
device-flow
anchor-dns
apply-placeholder
check-hygiene
update-ip-placeholder
destroy-gate
thumbprint'
  is "provision.yml job set is pinned (pin: update for a deliberate job change)" "$expected_jobs" "$actual_jobs"
else
  bad "provision.yml jobs span not found"
fi
is "provision.yml structural indent-2 line count (pin: update for a new top-level line)" "12" "$(printf '%s\n' "$PROV_STRUCT" | cut -f2- | grep -cE '^  [^[:space:]#]')"

# ---- the broker-dns lib is the one writer --------------------------------
contains "broker-dns lib defines write_anchor_dns" 'write_anchor_dns()' "$(cat "$LIB")"
contains "dns lib reuses the shared broker helpers" 'broker-report.sh' "$(cat "$LIB")"
contains "broker mint pins the broker audience" '"piercloud-broker"' "$(cat "$REPORT_LIB")"
# The sourced libs are the effective writer: pin their bytes, so an
# env-gated direct provider call added inside one cannot hide behind the
# write step's green pin. The job authenticates per-run via OIDC and must
# never carry a standing secret.
is "broker-dns lib blob hash (pin: update after a deliberate edit)" "c668738f19c28344ac0f591d4cc283e36d761a1292afc789ea897399f53f8862" "$(sha256sum "$LIB" | cut -d' ' -f1)"
is "broker-report lib blob hash (pin: update after a deliberate edit)" "0cd7b5bb73ecd115bb1478776365a2ee6b0d3c739f45f466f5513acda1718533" "$(sha256sum "$REPORT_LIB" | cut -d' ' -f1)"
is "bind-e2e script blob hash (pin: update after a deliberate edit)" "a817fef8dcb94a15d992c32af97c2d7d9462ce1c0245824c9506de06811be366" "$(sha256sum "$BIND_E2E" | cut -d' ' -f1)"

# bind-e2e harness-dir teeth (r25 F3): a symlinked package directory is
# not listed by `find -type d` but shadows the in-tree p521 module exactly
# like a real subdirectory. The check is extracted from the script (its
# call site is pinned by the blob hash above) and exercised on synthetic
# trees: clean passes; a real subdirectory AND a lone symlink each fail
# closed.
harness_dir_src="$(sed -n '/^harness_dir_untidy()/,/^}/p' "$BIND_E2E" || true)"
if [ -z "$harness_dir_src" ]; then
  bad "bind-e2e harness_dir_untidy() not found"
else
  eval "$harness_dir_src"
  bdir="$(mktemp -d)"
  mkdir -p "$bdir/clean" "$bdir/dironly/pkg" "$bdir/symonly"
  ln -s "$bdir/dironly/pkg" "$bdir/symonly/link"
  is "bind-e2e dir check: clean harness dir passes" "" "$(harness_dir_untidy "$bdir/clean")"
  if [ -n "$(harness_dir_untidy "$bdir/dironly")" ]; then ok "bind-e2e dir check: subdirectory fails closed"; else bad "bind-e2e dir check: subdirectory fails closed"; fi
  if [ -n "$(harness_dir_untidy "$bdir/symonly")" ]; then ok "bind-e2e dir check: symlink fails closed"; else bad "bind-e2e dir check: symlink fails closed"; fi
  rm -rf "$bdir"
fi
lacks "anchor-dns job uses no standing secret" 'secrets.' "$JOB"

# ---- job shape: broker call, managed lane, OIDC ---------------------------
contains "job routes through the broker" 'Anchor DNS upsert + verify through the pc-control broker (fail-closed)' "$JOB"
contains "job needs device-flow (same-run report)" 'needs: [device-flow]' "$JOB"
contains "job is apply-gated" "if: inputs.mode == 'apply'" "$JOB"
contains "job selects the tenant environment" "environment: \${{ inputs.tenant != '' && inputs.tenant || 'anchor' }}" "$JOB"
contains "job requests the OIDC token" 'id-token: write' "$JOB"
contains "job keeps contents read" 'contents: read' "$JOB"
contains "job sets the broker base" 'BROKER_URL: https://broker.piercloud.net' "$JOB"
contains "job passes the anchor_ref input" 'ANCHOR_REF: ${{ inputs.anchor_ref }}' "$JOB"
contains "job passes the device-flow resolved IPv4" 'ANCHOR_IPV4: ${{ needs.device-flow.outputs.anchor_ipv4 }}' "$JOB"
contains "job checks out without persisted credentials" 'persist-credentials: false' "$JOB"

# The security-relevant lines are pinned as WHOLE lines at the exact YAML
# body indentation (10 spaces), and ordered: a substring pin survives
# comment decoys, `: '...'` no-ops, deeper indentation (wrapping in a dead
# `if`) and step reorder.
JOB_LINES="$(printf '%s\n' "$JOB")"
# `|| true` keeps the diagnostics: under `set -e` + pipefail a missing line
# would abort the harness before the intended `bad` message prints.
src_line="$(printf '%s\n' "$JOB_LINES" | grep -nE '^          \. \.github/scripts/lib/broker-dns\.sh$' | cut -d: -f1 || true)"
call_line="$(printf '%s\n' "$JOB_LINES" | grep -nE '^          write_anchor_dns "\$ANCHOR_REF" "\$ANCHOR_IPV4"$' | cut -d: -f1 || true)"
guard_line="$(printf '%s\n' "$JOB_LINES" | grep -nE '^          if \[ -z "\$ANCHOR_REF" \]; then$' | cut -d: -f1 || true)"
guard_exit="$(printf '%s\n' "$JOB_LINES" | grep -cE '^            exit 1$' || true)"
[ -n "$src_line" ] && ok "job sources the broker-dns lib (exact line)" || bad "broker-dns source line not found at the expected indentation"
[ -n "$call_line" ] && ok "job calls write_anchor_dns with ref + ipv4 (exact line)" || bad "write_anchor_dns call line not found at the expected indentation"
[ -n "$guard_line" ] && ok "guard is a live if (exact line)" || bad "guard if line not found at the expected indentation"
is "guard exits non-zero" "1" "$guard_exit"
if [ -n "$guard_line" ] && [ -n "$call_line" ] && [ "$guard_line" -lt "$call_line" ]; then ok "guard runs before the write"; else bad "guard line ($guard_line) must precede the write line ($call_line)"; fi
if [ -n "$src_line" ] && [ -n "$call_line" ] && [ "$src_line" -lt "$call_line" ]; then ok "lib sourced before the write"; else bad "source line ($src_line) must precede the write line ($call_line)"; fi
# A dead step or a shadowed function defeats the line pins above: no
# step-level `if:`/`continue-on-error` may appear (the job's own apply gate
# is the only `if:` at 4-space indent), and the call/source may appear once.
is "no step-level if in the job" "0" "$(printf '%s\n' "$JOB_LINES" | grep -cE "^(      - |        )(&[^[:space:]]+[[:space:]]+|![^[:space:]]+[[:space:]]+)*[\"']?if[\"']?[[:space:]]*:")"
is "no continue-on-error in the job" "0" "$(printf '%s\n' "$JOB_LINES" | grep -cE "^(      - |        )(&[^[:space:]]+[[:space:]]+|![^[:space:]]+[[:space:]]+)*[\"']?continue-on-error[\"']?[[:space:]]*:")"
is "job-level if is exactly the apply gate" "1" "$(printf '%s\n' "$JOB_LINES" | grep -cE '^    if: inputs\.mode == .apply.$')"
is "exactly one write_anchor_dns source line" "1" "$(printf '%s\n' "$JOB_LINES" | grep -cE '^          \. \.github/scripts/lib/broker-dns\.sh$')"
# The step set is pinned: an extra unpinned step (e.g. a direct provider
# fallback with a split URL) changes the count/order and must update the pin.
is "exactly three steps in the anchor-dns job" "3" "$(printf '%s\n' "$JOB_LINES" | grep -cE '^      - name: ')"
# A step item need not carry a name (`- uses:` / `- run:`): count the
# sequence items too, so a nameless extra step is caught.
is "exactly three step items in the anchor-dns job" "3" "$(printf '%s\n' "$JOB_LINES" | grep -cE '^      -($|[[:space:]])')"
expected_step_names='Checkout (no credentials persisted)
Managed-lane guard (b3b #189 retired the direct-token writer)
Upsert anchor A + dashboard CNAME through the broker'
actual_step_names="$(printf '%s\n' "$JOB_LINES" | grep -E '^      - name: ' | sed -e 's/^      - name: //')"
is "anchor-dns step names in order" "$expected_step_names" "$actual_step_names"
is "exactly one write_anchor_dns call line" "1" "$(printf '%s\n' "$JOB_LINES" | grep -cE '^          write_anchor_dns "\$ANCHOR_REF" "\$ANCHOR_IPV4"$')"
is "no shadowing write_anchor_dns definition in the job" "0" "$(printf '%s\n' "$JOB_LINES" | grep -cE '^[[:space:]]*(function[[:space:]]+)?write_anchor_dns[[:space:]]*(\(\))?[[:space:]]*(\{|$)')"
# Job-level switches change how every step runs without touching the pinned
# step text: `continue-on-error` swallows a guard/write failure, `defaults`
# can replace the shell with a no-op. Both are banned, as are the bash
# startup-file variables that can neuter the job's `set -euo pipefail`.
is "no job-level continue-on-error" "0" "$(printf '%s\n' "$JOB_LINES" | grep -cE "^    (&[^[:space:]]+[[:space:]]+|![^[:space:]]+[[:space:]]+)*[\"']?continue-on-error[\"']?[[:space:]]*:")"
is "no job-level defaults" "0" "$(printf '%s\n' "$JOB_LINES" | grep -cE "^    (&[^[:space:]]+[[:space:]]+|![^[:space:]]+[[:space:]]+)*[\"']?defaults[\"']?[[:space:]]*:")"
is "exactly one job-level if in the anchor-dns job" "1" "$(printf '%s\n' "$JOB_LINES" | grep -cE "^    (&[^[:space:]]+[[:space:]]+|![^[:space:]]+[[:space:]]+)*[\"']?if[\"']?[[:space:]]*:")"
is "exactly one strict apply-gate if" "1" "$(printf '%s\n' "$JOB_LINES" | grep -cE '^    if: inputs\.mode == .apply.$')" 
for k in if strategy defaults continue-on-error; do
  is "no job-level explicit-key $k in the anchor-dns job" "0" "$(printf '%s\n' "$JOB_LINES" | grep -cE "^    \\?[[:space:]]*((&[^[:space:]]+|![^[:space:]]+)[[:space:]]+)*[\"']?${k}[\"']?[[:space:]]*(#.*)?$")"
  is "no step-level explicit-key $k in the anchor-dns job" "0" "$(printf '%s\n' "$JOB_LINES" | grep -cE "^        \\?[[:space:]]*((&[^[:space:]]+|![^[:space:]]+)[[:space:]]+)*[\"']?${k}[\"']?[[:space:]]*(#.*)?$")"
done
is "no workflow-level defaults" "0" "$(grep -cE "^(&[^[:space:]]+[[:space:]]+|![^[:space:]]+[[:space:]]+)*[\"']?defaults[\"']?[[:space:]]*:" "$PROV")"
for v in BASH_ENV ENV SHELLOPTS BASHOPTS; do
  lacks_word "job does not set $v" "$v" "$JOB"
done

# Byte-exact pin of the write step: the line pins above cannot see a
# same-indent `exit 0`/`if false` wrap, a `function` keyword shadow or an
# injected step-level `env:`, because YAML strips the body indent and bash
# does not care about the residual indentation. The whole step (comments
# included) is hashed, so any content edit must update the pin (a trailing
# blank line is stripped by $( ) and cannot change the executed script).
# Extraction is job-scoped: the step must live inside the anchor-dns job,
# so a decoy step in a workflow-level block scalar / another job cannot
# satisfy the pin, and the same `_`/uppercase job boundary applies.
STEP_BLOB="$(awk '
  /^      - name: Upsert anchor A \+ dashboard CNAME through the broker$/ {f=1}
  f && /^      - name: / && $0 !~ /Upsert anchor A \+ dashboard CNAME through the broker$/ {exit}
  f && /^  [A-Za-z_][A-Za-z0-9_-]*:$/ {exit}
  f {print}
' <<<"$JOB_RAW")"
is "write step blob hash (pin: update after a deliberate edit)" "5293b16c734b119a757a0653e8824f44b224910d9909bc5f18f4b8bef9c5f806" "$(printf '%s\n' "$STEP_BLOB" | sha256sum | cut -d' ' -f1)"
# The guard step is byte-pinned too: its body decides whether a ref-less
# apply can reach the write (a prefix such as
# `ANCHOR_REF="${ANCHOR_REF:-anchor-01}"` inside the run block would neuter
# it without touching any pinned line).
GUARD_BLOB="$(awk '
  /^      - name: Managed-lane guard \(b3b #189 retired the direct-token writer\)$/ {f=1}
  f && /^      - name: / && $0 !~ /Managed-lane guard/ {exit}
  f && /^  [A-Za-z_][A-Za-z0-9_-]*:$/ {exit}
  f {print}
' <<<"$JOB_RAW")"
is "guard step blob hash (pin: update after a deliberate edit)" "ef59e00c3696d06e3b3c2ed4fe2e9d20ab317fa110a619613fd13b1c86a46fe7" "$(printf '%s\n' "$GUARD_BLOB" | sha256sum | cut -d' ' -f1)"
# Exactly one guard step and one write step anywhere in the workflow, and
# exactly one write_anchor_dns token in the job: a second (unpinned) writer
# step that runs `... || true`, or a relocated copy, is caught here.
is "exactly one guard-step header in the workflow" "1" "$(grep -cE '^      - name: Managed-lane guard \(b3b #189 retired the direct-token writer\)$' "$PROV")"
is "exactly one write-step header in the workflow" "1" "$(grep -cE '^      - name: Upsert anchor A \+ dashboard CNAME through the broker$' "$PROV")"
is "exactly one write_anchor_dns token in the job" "1" "$(printf '%s\n' "$JOB_LINES" | grep -c 'write_anchor_dns')"
# The whole job body is byte-pinned: the step pins above cannot see the
# checkout identity (`repository:`/`ref:` under `with:` would source an
# attacker's broker-dns.sh), a job-env injection (LD_PRELOAD), or any other
# added/edited line in the job. Any deliberate job edit updates this pin.
is "anchor-dns job blob hash (pin: update after a deliberate edit)" "a6334e45c3a174abd93ff125f34b71a39d6e353263a7d330d450ae2f6834e45d" "$(printf '%s\n' "$JOB_RAW" | sha256sum | cut -d' ' -f1)"
for v in LD_PRELOAD LD_LIBRARY_PATH; do
  lacks_word "job does not set $v" "$v" "$JOB"
done
# The writer may live only here: a second call in another job, or an
# obfuscated same-job call (`write_anchor_""dns`), adds a token.
is "exactly one write_anchor mention in the job" "1" "$(printf '%s\n' "$JOB_LINES" | grep -c 'write_anchor')"
is "exactly one write_anchor_dns token in provision.yml" "1" "$(grep -c 'write_anchor_dns' "$PROV")"

# ---- the managed-lane guard fails closed ----------------------------------
contains "guard names the b3b broker path" 'anchor DNS now goes through the pc-control broker (b3b, #189)' "$JOB"

# ---- the retired provider surface is absent from the job ------------------
for v in NET_DNS_PROVIDER STATUS_EDGE_DOMAIN CLOUDFLARE_DNS_TOKEN GCORE_DNS_TOKEN; do
  lacks_word "job does not consume $v" "$v" "$JOB"
done
lacks "job does not call the retired writer" '030-anchor-dns.sh' "$JOB"
lacks "job does not name a provider zone override" 'NET_DNS_ZONE' "$JOB"

# ---- workflow wiring: fail before any thumbprint --------------------------
prov_live="$(printf '%s\n' "$PROV_STRUCT" | cut -f2- | grep -v '^[[:space:]]*#')"
# Workflow-level env can set the startup variables too: ban them provision-wide.
for v in BASH_ENV ENV SHELLOPTS BASHOPTS; do
  lacks_word "provision does not set $v" "$v" "$prov_raw_live"
done
contains "thumbprint waits for the DNS job" 'needs: [device-flow, anchor-dns]' "$prov_live"
lacks "provision no longer references the retired writer" '030-anchor-dns.sh' "$prov_raw_live"
for v in NET_DNS_PROVIDER STATUS_EDGE_DOMAIN CLOUDFLARE_DNS_TOKEN GCORE_DNS_TOKEN; do
  lacks_word "provision does not use $v anywhere" "$v" "$prov_raw_live"
done

# ---- the retired surface is gone from the tree ----------------------------
if [ -e .github/scripts/030-anchor-dns.sh ]; then bad "retired writer still present"; else ok "retired writer deleted"; fi
if [ -e tests/anchor-dns ]; then bad "retired harness still present"; else ok "retired harness deleted"; fi

# ---- CI: the new harness is wired, the old one is not ---------------------
ci_live="$(grep -v '^[[:space:]]*#' "$CI")"
# ci.yml gets the same block-scalar-aware structural view: the unit-tests
# job and its run step are located structurally, so a decoy scalar cannot
# spoof either.
CI_STRUCT="$(awk '
function indent(s,   m) { match(s, /^ */); return RLENGTH }
function qprefix(s,   i, c, q) {
  q = 0
  for (i = 1; i <= length(s); i++) {
    c = substr(s, i, 1)
    if (c == "\"") { q = 1 - q }
    else if (c == "#" && q == 0) { return substr(s, 1, i - 1) }
  }
  return s
}
{
  if (skip) {
    if ($0 ~ /^[[:space:]]*$/) next
    i = indent($0)
    if (sind < 0) {
      if (i <= ihdr) { skip = 0 } else { sind = i; next }
    } else if (i >= sind) { next } else { skip = 0 }
  }
  printf "%d\t%s\n", NR, $0
  if (($0 ~ /^[[:space:]]*[^#[:space:]].*:[[:space:]]*((&[^[:space:]#]+|![^[:space:]#]+)[[:space:]]+)*[|>]([0-9][-+]?|[-+][0-9]?)?[[:space:]]*(#.*)?$/ || $0 ~ /^[[:space:]]*\?[[:space:]]*((&[^[:space:]#]+|![^[:space:]#]+)[[:space:]]+)*[|>]([0-9][-+]?|[-+][0-9]?)?[[:space:]]*(#.*)?$/) && qprefix($0) ~ /[|>]([0-9][-+]?|[-+][0-9]?)?[[:space:]]*$/) {
    ihdr = indent($0)
    if (match($0, /[|>][-+]?[0-9]/)) { sind = ihdr + substr($0, RSTART + RLENGTH - 1, 1) + 0 }
    else { sind = -1 }
    skip = 1
  }
}'  "$CI")"
ci_unit_START="$(awk -F'\t' '$2 ~ /^  unit-tests-scripts:[[:space:]]*(#.*)?$/ {print $1; exit}' <<<"$CI_STRUCT")"
ci_unit_END="$(awk -F'\t' -v s="$ci_unit_START" '$1 > s && $2 ~ /^  [^ #].*:[[:space:]]*((&[^[:space:]]+|![^[:space:]]+)[[:space:]]*)?(#.*)?$/ {print $1; exit}' <<<"$CI_STRUCT")"
ci_unit=""
ci_unit_raw=""
[ -n "$ci_unit_START" ] && [ -n "$ci_unit_END" ] && ci_unit="$(sed -n "$((ci_unit_START + 1)),$((ci_unit_END - 1))p" "$CI" | grep -v '^[[:space:]]*#' || true)"
[ -n "$ci_unit_START" ] && [ -n "$ci_unit_END" ] && ci_unit_raw="$(sed -n "$((ci_unit_START + 1)),$((ci_unit_END - 1))p" "$CI")"
[ -n "$ci_unit" ] || bad "ci.yml unit-tests-scripts job not found"
# The gate and run-list assertions are scoped to the unit-tests-scripts job
# block: a mention in another job's run line or a commented-out line cannot
# satisfy them.
ci_gate="$(grep -m1 -F "elif grep -qE '^(\.github/scripts/" <<<"$ci_unit" || true)"
[ -n "$ci_gate" ] || bad "ci.yml unit-tests gate line not found"
contains "ci runs this harness" 'bash tests/broker-provision-dns/run-test.sh' "$ci_unit"
lacks "ci no longer runs the retired harness" 'tests/anchor-dns/run-test.sh' "$ci_live"
lacks "ci path gate no longer names the retired harness" 'anchor-dns' "$ci_live"
# The gate is checked FUNCTIONALLY: extract the regex literal from the gate
# LINE itself (not from anywhere in the job) and prove it matches this
# harness's path. A decoy `grep -qE` elsewhere, or a token parked in an
# inline comment, cannot satisfy it.
gate_raw="$(printf '%s\n' "$ci_gate" | grep -oE "grep -qE '[^']*'" || true)"
is "exactly one gate regex on the gate line" "1" "$(printf '%s\n' "$gate_raw" | grep -c . || true)"
gate_pattern="$(head -n1 <<<"$gate_raw" | sed -e "s/^grep -qE '//" -e "s/'$//")"
[ -n "$gate_pattern" ] || bad "could not extract the unit-tests gate regex"
if [ -n "$gate_pattern" ]; then
  if grep -qE "$gate_pattern" <<<"tests/broker-provision-dns/run-test.sh"; then
    ok "unit-tests gate regex matches this harness path"
  else
    bad "unit-tests gate regex does not match this harness path"
  fi
fi
# The harness-run step is byte-pinned and located structurally: an
# `if: false` rewrite, an early `exit 0`, or a `set +e` inside it must
# update the pin.
RUN_START="$(awk -F'\t' '$2 == "      - name: Run the committed script harnesses (cheap first)" {print $1; exit}' <<<"$CI_STRUCT")"
RUN_END="$(awk -F'\t' -v s="$RUN_START" '$1 > s && $2 ~ /^      - name: / {print $1; exit}' <<<"$CI_STRUCT")"
if [ -n "$RUN_START" ] && [ -n "$RUN_END" ]; then
  RUN_STEP_BLOB="$(sed -n "${RUN_START},$((RUN_END - 1))p" "$CI")"
  is "harness-run step blob hash (pin: update after a deliberate edit)" "286baff6b596031b9d0faaa716dac758b1515251ee3fafa2454d639184991182" "$(printf '%s\n' "$RUN_STEP_BLOB" | sha256sum | cut -d' ' -f1)"
  is "harness-run step keeps the gate expression" "1" "$(printf '%s\n' "$RUN_STEP_BLOB" | grep -cE '^        if: steps\.gate\.outputs\.run == .yes.$')"
else
  bad "harness-run step span not found in ci.yml"
fi
is "exactly one harness-run step header" "1" "$(grep -cE '^      - name: Run the committed script harnesses \(cheap first\)$' "$CI")"
# The whole unit-tests-scripts job body is byte-pinned: the step pins cannot
# see an inserted step in the same job that rewrites a harness on the runner
# before the pinned run step executes it (the static harnesses read the PR
# tree, not the runner workspace). Any deliberate job edit updates this pin.
is "unit-tests-scripts job blob hash (pin: update after a deliberate edit)" "d28a8019bf4a441e04e5409c93ab5ec0b4591520ebf0e9adc57ceca9e57076b3" "$(printf '%s\n' "$ci_unit_raw" | sha256sum | cut -d' ' -f1)"
# The whole scp-endpoint-allowlist job body is byte-pinned: the allowlist
# step pin hashes the consumer, not the producer of its contract source
# (`/tmp/contract-ci.yml` is written by an earlier step in the same job), so
# a rewrite inserted into another step would re-admit a retired provider
# while the pinned step stays green. Exactly one job key line (any spelling)
# may exist; the span is located structurally and fails closed when the end
# is missing.
SCP_START="$(awk -F'\t' '$2 ~ /^  ((&[^[:space:]]+|![^[:space:]]+)[[:space:]]+)*scp-endpoint-allowlist:[[:space:]]*((&[^[:space:]]+|![^[:space:]]+)[[:space:]]*)?(#.*)?$/ {print $1; exit}' <<<"$CI_STRUCT")"
SCP_END="$(awk -F'\t' -v s="$SCP_START" '$1 > s && $2 ~ /^  [^ #].*:[[:space:]]*((&[^[:space:]]+|![^[:space:]]+)[[:space:]]*)?(#.*)?$/ {print $1; exit}' <<<"$CI_STRUCT")"
is "exactly one scp-endpoint-allowlist job key line in ci.yml" "1" "$(grep -cE "^  (\\?[[:space:]]*)?((&[^[:space:]]+|![^[:space:]]+)[[:space:]]+)*(\"scp-endpoint-allowlist\"|'scp-endpoint-allowlist'|scp-endpoint-allowlist)[[:space:]]*:?[[:space:]]*((&[^[:space:]]+|![^[:space:]]+)[[:space:]]*)?(#.*)?$" "$CI")"
if [ -n "$SCP_START" ] && [ -n "$SCP_END" ]; then
  SCP_JOB_BLOB="$(sed -n "$((SCP_START + 1)),$((SCP_END - 1))p" "$CI")"
  is "scp-endpoint-allowlist job blob hash (pin: update after a deliberate edit)" "f7d98c0ac8deb7e8ddfc407ee0129492c2858e9d286c7942a41779fce5727827" "$(printf '%s\n' "$SCP_JOB_BLOB" | sha256sum | cut -d' ' -f1)"
else
  bad "scp-endpoint-allowlist job span not found in ci.yml"
fi
is "exactly one unit-tests-scripts job key line in ci.yml" "1" "$(grep -cE "^  (\\?[[:space:]]*)?((&[^[:space:]]+|![^[:space:]]+)[[:space:]]+)*(\"unit-tests-scripts\"|'unit-tests-scripts'|unit-tests-scripts)[[:space:]]*:?[[:space:]]*(#.*)?$" "$CI")"
# Spelling-agnostic census for ci.yml (same doctrine as provision.yml):
# every indent-2 non-space/non-comment line of the stripped view is a
# structural line of the top level (on/env/permissions children plus the job
# keys). A
# duplicate or decoy job key in ANY spelling adds one.
is "ci.yml structural indent-2 line count (pin: update for a new top-level line)" "15" "$(printf '%s\n' "$CI_STRUCT" | cut -f2- | grep -cE '^  [^[:space:]#]')"
# The job SET is pinned by name too: the census is a count, so a new job
# added while a semantic-neutral indent-2 line is removed (`permissions:
# { contents: read }` replacing the block form) keeps the count green — and
# a new job runs with repo secrets and can shadow a required check by name.
# Every indent-2 non-comment line of the jobs block is normalised and
# compared; any deliberate job addition/rename updates this pin.
CI_JOBS_START="$(awk -F'\t' '$2 ~ /^jobs:[[:space:]]*(#.*)?$/ {print $1; exit}' <<<"$CI_STRUCT")"
# Parsed to end-of-file (a column-0 flow continuation must not truncate the
# span; see the provision job-set comment).
CI_JOBS_END=$(( $(awk 'END{print NR}' "$CI") + 1 ))
if [ -n "$CI_JOBS_START" ] && [ -n "$CI_JOBS_END" ]; then
  actual_ci_jobs="$(sed -n "$((CI_JOBS_START + 1)),$((CI_JOBS_END - 1))p" "$CI" \
    | grep -E '^  [^[:space:]]' | grep -vE '^  #' \
    | sed -e 's/[[:space:]]+#.*$//' -e 's/^  //' \
    | sed -E -e 's/^((&|!)[^[:space:]]+[[:space:]]+)+//' \
    | sed -e 's/[[:space:]]*:.*$//' \
    | sed -E -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//")" || true
  expected_ci_jobs='fmt
validate
key-material-grep
scp-endpoint-allowlist
pat-print-grep
shared-origin-grep
unit-tests-scripts
bind-e2e
jq-boolean-guard
scrub-canary'
  is "ci.yml job set is pinned (pin: update for a deliberate job change)" "$expected_ci_jobs" "$actual_ci_jobs"
else
  bad "ci.yml jobs span not found"
fi
# Every workflow's job set is pinned as ONE digest: a job added to any
# workflow (release.yml carries write permissions) or a new workflow file
# (`.yml` or `.yaml`) changes it. The digest pins job NAMES only: three job
# bodies are whole-job byte-pinned (`anchor-dns`, `unit-tests-scripts`,
# `scp-endpoint-allowlist`), external-watch.yml and broker-report-selftest.yml
# wiring is pinned by their own harnesses, and the remaining job bodies
# (incl. release.yml, validate-package-version.yml, validate-release-pr.yml)
# get only name pins here (other harnesses pin parts of some bodies, e.g.
# the banner and device-flow jobs). A duplicate top-level `jobs:` key in any spelling
# the count recognises fails here; the escaped spelling
# (`"j\u006fbs":`) is caught by the all-workflow hex/octal-escape ban
# below. Pin update is deliberate (same PR as the workflow change).
wf_job_digest=""
wf_top_digest=""
wf_on_digest=""
wf_perm_digest=""
for wf in .github/workflows/*.yml .github/workflows/*.yaml; do
  [ -f "$wf" ] || continue
  # Root-shape fail-closed (r24 red-team HIGH): every locator below matches
  # COLUMN-0 lines, but YAML allows the root mapping itself to be indented
  # while a column-0 multi-line quoted scalar carries decoy `on:`/
  # `permissions:`/`jobs:` lines — the pins would then hash decoy bytes and
  # a real trigger/job added under the indented root changes nothing. Require
  # no BOM, no column-0 `---`/`...`-prefixed line, and a plain column-0
  # `key:` as the first content line, so the root mapping is exactly the
  # column-0 line set the
  # locators read. `--- &a` (any `---`/`...` suffix) and an anchor-only
  # first line are rejected too (r25 F2). (In-tree all seven start at
  # column 0 with `name:`.)
  wf_root_bad="$(root_shape_bad "$wf")"
  if [ -n "$wf_root_bad" ]; then
    bad "$wf root shape: $wf_root_bad (fail closed)"
    wf_top_digest="$wf_top_digest|$wf:BADROOT"
    wf_on_digest="$wf_on_digest|$wf:BADROOT"
    wf_perm_digest="$wf_perm_digest|$wf:BADROOT"
    wf_job_digest="$wf_job_digest|$wf:BADROOT"
    continue
  fi
  ok "$wf root shape (no BOM/document marker, first content line at column 0)"
  # The TOP-LEVEL line sequence is pinned on its own: the jobs-last invariant
  # and every job-set span read content from `jobs:` down, so a decoy key
  # placed BEFORE `jobs:` (with indent-2 children, compensated in the census)
  # would be invisible to every job pin. Every column-0 non-comment line is
  # hashed RAW: the old token extraction was lossy (a quoted key with an
  # internal colon truncated to the pre-colon word, and a comma-bearing key
  # collided with the comma-joined token string — r21 F1/F2), so a
  # replacement could keep the digest green. Raw hashing is collision-resistant
  # over the hashed line set: a change to ANY column-0 non-comment line — a
  # decoy key in any spelling, a quoted/renamed/removed key, a same-line value
  # rewrite, a `---` separator, a flow continuation — changes the pin. The
  # pin is a hash of the lines, so it is collision-resistant, not injective in
  # the mathematical sense; column-0 comment lines and whitespace-indented
  # lines are not part of the pin (comments are non-executable, indented lines
  # are not top-level). Spelling stability is traded for that coverage: a
  # cosmetic respelling or reorder also reds (deliberate pin update).
  wf_top_digest="$wf_top_digest|$wf:$(grep -E '^[^[:space:]#]' "$wf" | sha256sum | cut -d' ' -f1 || true)"
  # The `on:` trigger block is pinned per workflow: the top-level line digest
  # sees only column-0 lines, so an indent-2 trigger added under `on:`
  # (e.g. `pull_request_target:`) was invisible to every other pin (r21 F4).
  # The span is hashed raw from the `on:` key line to the next column-0
  # non-comment line; flow continuations at column 0 are already in the
  # top-level digest, and a missing or ambiguous `on:` key fails closed.
  on_lines="$(grep -nE '^((&|!)[^[:space:]]+[[:space:]]+)*(["'"'"']?on["'"'"']?)[[:space:]]*:' "$wf" | cut -d: -f1 || true)"
  on_count="$(printf '%s\n' "$on_lines" | grep -c . || true)"
  if [ "$on_count" != "1" ]; then
    bad "$wf top-level on: key count (expected 1, got $on_count)"
    wf_on_digest="$wf_on_digest|$wf:AMBIGUOUS"
  else
    on_end="$(flow_end "$wf" "$on_lines")"
    [ -n "$on_end" ] || on_end=$(( $(awk 'END{print NR}' "$wf") + 1 ))
    wf_on_digest="$wf_on_digest|$wf:$(sed -n "${on_lines},$((on_end - 1))p" "$wf" | sha256sum | cut -d' ' -f1)"
  fi
  # The top-level `permissions:` block is pinned per workflow too: token
  # scopes are security-relevant and an indented child value rewrite
  # (`contents: read` -> `write`) is invisible to the raw top-level line
  # digest and to the count-only censuses (r22 trust MEDIUM / r21 F7). Same
  # span/locator doctrine as `on:`; every in-tree workflow has exactly one.
  perm_lines="$(grep -nE '^((&|!)[^[:space:]]+[[:space:]]+)*(["'"'"']?permissions["'"'"']?)[[:space:]]*:' "$wf" | cut -d: -f1 || true)"
  perm_count="$(printf '%s\n' "$perm_lines" | grep -c . || true)"
  if [ "$perm_count" != "1" ]; then
    bad "$wf top-level permissions: key count (expected 1, got $perm_count)"
    wf_perm_digest="$wf_perm_digest|$wf:AMBIGUOUS"
  else
    perm_end="$(flow_end "$wf" "$perm_lines")"
    [ -n "$perm_end" ] || perm_end=$(( $(awk 'END{print NR}' "$wf") + 1 ))
    wf_perm_digest="$wf_perm_digest|$wf:$(sed -n "${perm_lines},$((perm_end - 1))p" "$wf" | sha256sum | cut -d' ' -f1)"
  fi
  jobs_keys="$(grep -cE "^((&|!)[^[:space:]]+[[:space:]]+)*([\"']?jobs[\"']?)[[:space:]]*:[[:space:]]*(#.*)?\$" "$wf" || true)"
  if [ "$jobs_keys" != "1" ]; then
    bad "$wf top-level jobs key count (expected 1, got $jobs_keys)"
    wf_job_digest="$wf_job_digest|$wf:AMBIGUOUS"
    continue
  fi
  jstart="$(grep -nE '^jobs:[[:space:]]*(#.*)?$' "$wf" | head -n1 | cut -d: -f1 || true)"
  if [ -z "$jstart" ]; then
    bad "$wf has no top-level jobs: key"
    wf_job_digest="$wf_job_digest|$wf:NOJOBS"
    continue
  fi
  # The jobs block is parsed to end-of-file: ending the span at the first
  # column-0 line let a flow-collection continuation at column 0 truncate it
  # and hide every job key after it (r17 F1). But an end-of-file span also
  # sweeps in the indent-2 children of any top-level key placed AFTER jobs,
  # so jobs is required to be the LAST top-level key: no column-0
  # non-comment, non-blank line may follow it. In all seven workflows jobs is
  # last; a genuine top-level key after jobs, a `---` document separator, or
  # a column-0 flow-collection continuation (r17 F1) each land here and fail
  # closed, instead of letting a re-indented jobs block + a decoy key
  # spelling out the pinned names keep the digest green (r18 F1/F2).
  if sed -n "$((jstart + 1)),\$p" "$wf" | grep -qE '^[^[:space:]#]'; then
    bad "$wf has a column-0 non-comment line after jobs: (jobs must be the last top-level key)"
    wf_job_digest="$wf_job_digest|$wf:AMBIGUOUS"
    continue
  fi
  jend=$(( $(awk 'END{print NR}' "$wf") + 1 ))
  # A quoted job key can hide a colon (`"release: evil":`), which the
  # first-colon strip would truncate to the plain name and hide the rename.
  # Quoted keys are not needed in-tree; fail closed on any. The quote may
  # be preceded by YAML node properties (`&x "release: evil":`,
  # `!!str "release: evil":`), so strip the same property prefix the
  # name extraction strips before looking for the quote.
  if sed -n "$((jstart + 1)),$((jend - 1))p" "$wf" | grep -qE '^  ((&|!)[^[:space:]]+[[:space:]]+)*["'"'"']'; then
    bad "$wf job key is quoted (unexpected spelling)"
    wf_job_digest="$wf_job_digest|$wf:BADNAME"
    continue
  fi
  raw_keys="$(sed -n "$((jstart + 1)),$((jend - 1))p" "$wf" \
    | grep -E '^  [^[:space:]]' | grep -vE '^  #' \
    | sed -E -e 's/[[:space:]]+#.*$//' -e 's/^  //' \
    | sed -E -e 's/^((&|!)[^[:space:]]+[[:space:]]+)+//')" || true
  # The digest truncates each key at its first colon, so a rename to
  # `<known>:evil:` (plain YAML) or `&a "release:evil":` would yield the
  # known name. Every raw key must start with a valid GitHub job id
  # (alphanumerics, `-`, `_`, starting with a letter or `_`) whose colon is a
  # real mapping separator (followed by whitespace or end of line — in YAML a
  # colon inside a plain key is not followed by whitespace). Anything after
  # the separator is the job's value and is left to that job's own pins where
  # they exist — this digest pins names only (three bodies are whole-job
  # byte-pinned elsewhere in this harness); a value-side anchor/tag, e.g.
  # `release: &a`, is legal YAML.
  if grep -qvE '^[A-Za-z_][A-Za-z0-9_-]*[[:space:]]*:([[:space:]].*)?$' <<<"$raw_keys"; then
    bad "$wf job key fails the GitHub job-id grammar (rename/truncation guard)"
    wf_job_digest="$wf_job_digest|$wf:BADNAME"
    continue
  fi
  names="$(sed -n "$((jstart + 1)),$((jend - 1))p" "$wf" \
    | grep -E '^  [^[:space:]]' | grep -vE '^  #' \
    | sed -E -e 's/[[:space:]]+#.*$//' -e 's/^  //' \
    | sed -E -e 's/^((&|!)[^[:space:]]+[[:space:]]+)+//' \
    | sed -e 's/[[:space:]]*:.*$//' \
    | sed -E -e 's/^"//' -e 's/"$//')" || true
  if [ -z "$names" ]; then
    bad "$wf jobs block yielded no job names (flow-form or non-standard indent)"
    wf_job_digest="$wf_job_digest|$wf:NONAMES"
    continue
  fi
  names="$(tr '\n' ',' <<<"$names")"
  wf_job_digest="$wf_job_digest|$wf:$names"
done
job_digest_got="$(printf '%s' "$wf_job_digest" | sha256sum | cut -d' ' -f1)"
is "workflow job-set digest is pinned (pin: update for a deliberate job change)" "fecbf8ee8084834e45f604442f29b0639bfd9260cc12c08b8000c8e206347fb2" "$job_digest_got"
if [ "$job_digest_got" != "fecbf8ee8084834e45f604442f29b0639bfd9260cc12c08b8000c8e206347fb2" ]; then
  printf '   job-set parts (to update the pin):\n'; printf '%s' "$wf_job_digest" | tr '|' '\n' | sed 's/^/     /'; printf '\n'
fi
top_digest_got="$(printf '%s' "$wf_top_digest" | sha256sum | cut -d' ' -f1)"
is "workflow top-level key sequence is pinned (pin: update for a deliberate top-level key change)" "79697d40de1560fdff6c3c014c5f023e93fde0425295d70438f98baa985b4618" "$top_digest_got"
if [ "$top_digest_got" != "79697d40de1560fdff6c3c014c5f023e93fde0425295d70438f98baa985b4618" ]; then
  printf '   top-level key parts (to update the pin):\n'; printf '%s' "$wf_top_digest" | tr '|' '\n' | sed 's/^/     /'; printf '\n'
  printf '   top-level line content (each workflow, hashed as-is; strip the "     | " prefix):\n'
  for wf in .github/workflows/*.yml .github/workflows/*.yaml; do
    [ -f "$wf" ] || continue
    printf '     %s:\n' "$wf"
    grep -E '^[^[:space:]#]' "$wf" | sed 's/^/     | /' || true
  done
fi
on_digest_got="$(printf '%s' "$wf_on_digest" | sha256sum | cut -d' ' -f1)"
is "workflow on: trigger blocks are pinned (pin: update for a deliberate trigger change)" "4e7f26bf4c989cd1329dad27ea393924f24d3ed9842371b61ab5121d8142591f" "$on_digest_got"
if [ "$on_digest_got" != "4e7f26bf4c989cd1329dad27ea393924f24d3ed9842371b61ab5121d8142591f" ]; then
  printf '   on: parts (to update the pin):\n'; printf '%s' "$wf_on_digest" | tr '|' '\n' | sed 's/^/     /'; printf '\n'
fi
perm_digest_got="$(printf '%s' "$wf_perm_digest" | sha256sum | cut -d' ' -f1)"
is "workflow top-level permissions blocks are pinned (pin: update for a deliberate scope change)" "1988700a260b3e6e87ebfab47f56009ed7a389b831fcea86f172b7a66a11f6eb" "$perm_digest_got"
if [ "$perm_digest_got" != "1988700a260b3e6e87ebfab47f56009ed7a389b831fcea86f172b7a66a11f6eb" ]; then
  printf '   permissions: parts (to update the pin):\n'; printf '%s' "$wf_perm_digest" | tr '|' '\n' | sed 's/^/     /'; printf '\n'
fi
# A workflow must not gain (or repoint) an execution of test-tree content:
# the `tests/*/run-test.sh` pin records are exempt from the retired-name scan,
# so an unpinned job could otherwise `run: bash tests/broker-provision-dns/run-test.sh`
# and a harness record would run in a production job. The exact set of
# workflow lines mentioning the `tests` path token OR `run-test.sh` is pinned
# as one digest (comments included); a new, edited or removed reference fails
# closed until the pin is deliberately updated. The pin is literal-token-only:
# a shell-assembled `tests` token still fires the pin while `run-test.sh` is
# literal; a fully-assembled path (both tokens) fires no pin (disclosed
# residual).
TESTS_REF_RE='(^|[^[:alnum:]_-])tests([^[:alnum:]_-]|$)|run-test\.sh'
wf_tests_digest=""
for wf in .github/workflows/*.yml .github/workflows/*.yaml; do
  [ -f "$wf" ] || continue
  wf_tests_digest="$wf_tests_digest|$wf:$(grep -E "$TESTS_REF_RE" "$wf" | sha256sum | cut -d' ' -f1 || true)"
done
tests_digest_got="$(printf '%s' "$wf_tests_digest" | sha256sum | cut -d' ' -f1)"
is "workflow tests-reference set is pinned (pin: update for a deliberate change)" "dae05af53c379e28936506e5a7aa0448b94aa4036bad5f78a48654969aca1b2a" "$tests_digest_got"
if [ "$tests_digest_got" != "dae05af53c379e28936506e5a7aa0448b94aa4036bad5f78a48654969aca1b2a" ]; then
  printf '   tests-reference parts (to update the pin):\n'; printf '%s' "$wf_tests_digest" | tr '|' '\n' | sed 's/^/     /'; printf '\n'
  printf '   tests-reference content (each workflow, hashed as-is; strip the "     | " prefix):\n'
  for wf in .github/workflows/*.yml .github/workflows/*.yaml; do
    [ -f "$wf" ] || continue
    printf '     %s:\n' "$wf"
    grep -E "$TESTS_REF_RE" "$wf" | sed 's/^/     | /' || true
  done
fi
# The unit-tests job itself must stay live and shell-predictable: no
# job-level if/defaults/strategy, no workflow defaults, no bash startup-file
# variables anywhere in ci.yml, and the allowlist must no longer name the
# retired direct provider APIs.
is "no job-level if on the unit-tests job" "0" "$(printf '%s\n' "$ci_unit" | grep -cE "^    (&[^[:space:]]+[[:space:]]+|![^[:space:]]+[[:space:]]+)*[\"']?if[\"']?[[:space:]]*:")"
is "no job-level defaults on the unit-tests job" "0" "$(printf '%s\n' "$ci_unit" | grep -cE "^    (&[^[:space:]]+[[:space:]]+|![^[:space:]]+[[:space:]]+)*[\"']?defaults[\"']?[[:space:]]*:")"
is "no job-level strategy on the unit-tests job" "0" "$(printf '%s\n' "$ci_unit" | grep -cE "^    (&[^[:space:]]+[[:space:]]+|![^[:space:]]+[[:space:]]+)*[\"']?strategy[\"']?[[:space:]]*:")"
is "no workflow-level defaults in ci.yml" "0" "$(grep -cE "^(&[^[:space:]]+[[:space:]]+|![^[:space:]]+[[:space:]]+)*[\"']?defaults[\"']?[[:space:]]*:" "$CI")"
for v in BASH_ENV ENV SHELLOPTS BASHOPTS; do
  lacks_word "ci.yml does not set $v" "$v" "$ci_live"
done
for v in LD_PRELOAD LD_LIBRARY_PATH; do
  lacks_word "ci.yml does not set $v" "$v" "$ci_live"
  lacks_word "provision.yml does not set $v" "$v" "$prov_raw_live"
done
lacks "ci allowlist no longer names the Cloudflare DNS API" 'api.cloudflare.com' "$(cat "$CI")"
lacks "ci allowlist no longer names the Gcore DNS API" 'api.gcore.com' "$(cat "$CI")"
# ci.yml liveness: a disabled or empty unit-tests job, a job-level shell
# override, or a workflow-level shell default would make every harness
# assertion moot.
is "exactly one gate elif in the unit-tests job" "1" "$(printf '%s\n' "$ci_unit" | grep -cE 'elif grep -qE')"
gate_ln="$(printf '%s\n' "$ci_unit" | grep -nE 'elif grep -qE' | head -n1 | cut -d: -f1 || true)"
if [ -n "$gate_ln" ]; then
  gate_next="$(printf '%s\n' "$ci_unit" | sed -n "$((gate_ln + 1)),\$p" | awk '/^[[:space:]]*(elif|else|fi)([[:space:]]|$)/ {exit} {print}' | grep -vE '^[[:space:]]*(#|$)' | head -n1 || true)"
  is "gate branch sets run=yes" '              echo "run=yes" >> "$GITHUB_OUTPUT"' "$gate_next"
else
  bad "gate elif line not found in the unit-tests job"
fi
# The whole gate step is byte-pinned: a later run=no write, a redefined
# GITHUB_OUTPUT, a shadowed grep, or any other subversion inside it must
# update the pin.
GATE_START="$(awk -F'\t' '$2 == "      - name: Gate on changed paths (CI scripts or harnesses)" {print $1; exit}' <<<"$CI_STRUCT")"
GATE_END="$(awk -F'\t' -v s="$GATE_START" '$1 > s && $2 ~ /^      - name: / {print $1; exit}' <<<"$CI_STRUCT")"
if [ -n "$GATE_START" ] && [ -n "$GATE_END" ]; then
  GATE_STEP_BLOB="$(sed -n "${GATE_START},$((GATE_END - 1))p" "$CI")"
  is "gate step blob hash (pin: update after a deliberate edit)" "0f85dbbe46c2abad81a846cc32397163ec1a3cb9a50afe5c674849b1ebcd18e9" "$(printf '%s\n' "$GATE_STEP_BLOB" | sha256sum | cut -d' ' -f1)"
else
  bad "gate step span not found in ci.yml"
fi
is "exactly one gate-step header" "1" "$(grep -cE '^      - name: Gate on changed paths \(CI scripts or harnesses\)$' "$CI")"
is "unit-tests job has no if" "0" "$(printf '%s\n' "$ci_unit" | grep -cE "^    (&[^[:space:]]+[[:space:]]+|![^[:space:]]+[[:space:]]+)*[\"']?if[\"']?[[:space:]]*:")"
is "unit-tests job has no strategy" "0" "$(printf '%s\n' "$ci_unit" | grep -cE "^    (&[^[:space:]]+[[:space:]]+|![^[:space:]]+[[:space:]]+)*[\"']?strategy[\"']?[[:space:]]*:")"
is "unit-tests job has no continue-on-error" "0" "$(printf '%s\n' "$ci_unit" | grep -cE "^    (&[^[:space:]]+[[:space:]]+|![^[:space:]]+[[:space:]]+)*[\"']?continue-on-error[\"']?[[:space:]]*:")"
is "unit-tests job has no defaults" "0" "$(printf '%s\n' "$ci_unit" | grep -cE "^    (&[^[:space:]]+[[:space:]]+|![^[:space:]]+[[:space:]]+)*[\"']?defaults[\"']?[[:space:]]*:")"
for k in if strategy defaults continue-on-error; do
  is "unit-tests job has no explicit-key $k" "0" "$(printf '%s\n' "$ci_unit" | grep -cE "^    \\?[[:space:]]*((&[^[:space:]]+|![^[:space:]]+)[[:space:]]+)*[\"']?${k}[\"']?[[:space:]]*(#.*)?$")"
done
# An explicit mapping key can carry its name across lines (`? "i\` + `f"`),
# which no single-line regex sees. Neither workflow has a legitimate explicit
# key at any mapping level (indent 0-8), so the form is banned blanket; the
# per-key checks above stay as diagnostics.
is "ci.yml has no explicit mapping keys" "0" "$(grep -cE '^ {0,8}\?([[:space:]]|$)' "$CI")"
is "provision.yml has no explicit mapping keys" "0" "$(grep -cE '^ {0,8}\?([[:space:]]|$)' "$PROV")"
# Explicit mapping keys are banned in EVERY workflow: `? jobs` + a following
# `: {...}` is an alternate spelling for a duplicate top-level key that the
# raw count cannot see (the Actions parser may reject it, but the ban is the
# fail-closed backstop). Zero legitimate uses in-tree.
for wf in .github/workflows/*.yml .github/workflows/*.yaml; do
  [ -f "$wf" ] || continue
  is "$wf has no explicit mapping keys" "0" "$(grep -cE '^ {0,8}\?([[:space:]]|$)' "$wf")"
done
# A dotfile workflow (`.github/workflows/.evil.yml`) is invisible to every
# glob in this harness and to GitHub's own path filters; there is none
# in-tree and the digests would not see one, so fail closed.
if compgen -G '.github/workflows/.*.yml' >/dev/null || compgen -G '.github/workflows/.*.yaml' >/dev/null; then
  bad "dotfile workflow present under .github/workflows/ (invisible to every glob and digest)"
else
  ok "no dotfile workflows under .github/workflows/"
fi
# No workflow may reference `.local` (gitignored local configuration): a
# force-added `.local` payload executed by a committed step would sit
# outside the scan surface (r21 F5). Zero legitimate uses in-tree.
local_refs="$(grep -lE '(^|[^[:alnum:]_-])\.local([^[:alnum:]_-]|$)' .github/workflows/*.yml .github/workflows/*.yaml 2>/dev/null || true)"
if [ -z "$local_refs" ]; then ok "no workflow references .local (outside the scan surface)"; else bad "workflow references .local (outside the scan surface): $local_refs"; fi
# YAML treats bare CR (and NEL/LS/PS, which libyaml/Psych — the CI's parser
# proxy — accept as line breaks) as a new line, but grep splits on LF only:
# a "\r"-prefixed line is a real YAML line at column 0 that every grep-based
# pin and census skips (r22 red-team HIGH: a hidden job and duplicate
# top-level keys passed all 21 harnesses). Psych also treats a U+FEFF BOM
# as ignorable anywhere, so `env: [\n\uFEFF&a push\n]` + `on: *a` resolves
# while every byte-oriented prefix misses the anchor (r32 red-team F1).
# The in-tree workflows are LF-only and BOM-free, so fail closed on any
# non-LF line break OR a BOM byte sequence and keep the line models aligned.
line_break_scan() { # $1.. files -- prints files with a non-LF break or a BOM byte
  LC_ALL=C grep -lE $'(\r|\xc2\x85|\xe2\x80\xa8|\xe2\x80\xa9|\xef\xbb\xbf)' "$@" 2>/dev/null || true
}
# The scan's teeth (r32 red-team F1 mutation gap): a clean LF file passes;
# every hostile byte sequence fails closed. Extracted so a drop of any
# alternative is caught here, not only on a hostile in-tree tree.
lbf="$(mktemp)"
is "line-break scan: clean file passes" "" "$(line_break_scan "$lbf")"
for lbcase in CR NEL LS PS BOM; do
  case "$lbcase" in
    CR)  printf 'name: x\r\n' > "$lbf" ;;
    NEL) printf 'name: x\xc2\x85\n' > "$lbf" ;;
    LS)  printf 'name: x\xe2\x80\xa8\n' > "$lbf" ;;
    PS)  printf 'name: x\xe2\x80\xa9\n' > "$lbf" ;;
    BOM) printf 'env: [\n\xef\xbb\xbf&a push\n]\n' > "$lbf" ;;
  esac
  is "line-break scan: $lbcase fails closed" "$lbf" "$(line_break_scan "$lbf")"
done
# Multi-file arity (r33 red-team LOW): a "$@"->"$1" mutant must not survive.
lbf2="$(mktemp)"; printf 'name: y\n' > "$lbf2"
printf 'name: x\r\n' > "$lbf"
is "line-break scan: every listed file is scanned" "$lbf" "$(line_break_scan "$lbf2" "$lbf")"
is "line-break scan: dirty first file is scanned" "$lbf" "$(line_break_scan "$lbf" "$lbf2")"
rm -f "$lbf" "$lbf2"
# The in-tree call site must be exactly ONE assignment keeping both GLOBS
# (a dropped .yaml glob is invisible while no .yaml workflow exists — r33
# red-team LOW; a glob replaced by a plain filename carrying the
# extension, and a later broken overwrite of the variable, are caught too
# — r34 functional/red-team LOWs). The pattern is applied to the
# extracted assignment line, so the check's own text cannot self-match.
lb_assign="$(grep -E '^lb_files=' "$0" || true)"
is "line-break scan call site: exactly one assignment" "1" "$(printf '%s\n' "$lb_assign" | grep -c . || true)"
is "line-break scan call site covers .yml and .yaml globs" "1" "$(printf '%s\n' "$lb_assign" | grep -cE '^lb_files="\$\(line_break_scan .*\*\.yml .*\*\.yaml\)"$' || true)"
lb_files="$(line_break_scan .github/workflows/*.yml .github/workflows/*.yaml)"
if [ -z "$lb_files" ]; then ok "workflows are LF-only and BOM-free (no CR/NEL/LS/PS/U+FEFF — YAML vs grep parity)"; else bad "workflow contains a non-LF line break or a BOM (YAML vs grep differential): $lb_files"; fi
# A YAML merge key (`<<: *anchor`) can inject a mapping — including
# `if: false` / `continue-on-error: true` — from an anchor defined elsewhere,
# invisible to every key regex. Block, flow and tagged spellings (`<< :`,
# `&m <<:`, `- <<: *evil`, `{ <<: *evil }`, `!!merge '<<': *evil`) all
# resolve as merges under YAML, so the `<<:` token is banned in EVERY workflow
# file (heredocs/herestrings use `<<NAME`/`<<<`, never a colon), and the
# `!!merge` / verbose `2002:merge` tags are banned outright. Zero legitimate
# uses in-tree.
for wf in .github/workflows/*.yml .github/workflows/*.yaml; do
  [ -f "$wf" ] || continue
  is "$wf has no YAML merge keys" "0" "$(grep -cE '<<[[:space:]]*:' "$wf")"
  is "$wf has no YAML merge tags" "0" "$(grep -cE '!!merge|2002:merge' "$wf")"
  is "$wf has no YAML anchors" "0" "$(anchor_count "$wf")"
done
is "ci.yml has no workflow defaults" "0" "$(grep -cE "^(&[^[:space:]]+[[:space:]]+|![^[:space:]]+[[:space:]]+)*[\"']?defaults[\"']?[[:space:]]*:" "$CI")"
lacks_word "unit-tests job does not set BASH_ENV" BASH_ENV "$ci_unit"
lacks_word "ci.yml does not set BASH_ENV" BASH_ENV "$ci_live"
for f in "$CI" "$PROV"; do
  if grep -qE '\\[uUxX][0-9a-fA-F]|\\[0-7]' <<<"$(grep -v '^[[:space:]]*#' "$f")"; then
    bad "$(basename "$f") contains a hex/octal escape (name-assembly route, banned blanket)"
  else
    ok "$(basename "$f") has no hex/octal escape"
  fi
done
# Escapes are banned in EVERY workflow: `"j\u006fbs":` decodes to a
# duplicate top-level key that defeats the raw count, the span terminator
# and the explicit-key ban (PyYAML resolves it).
for wf in .github/workflows/*.yml .github/workflows/*.yaml; do
  [ -f "$wf" ] || continue
  if grep -qE '\\[uUxX][0-9a-fA-F]|\\[0-7]' <<<"$(grep -v '^[[:space:]]*#' "$wf")"; then
    bad "$wf contains a hex/octal escape (name-assembly route, banned blanket)"
  else
    ok "$wf has no hex/octal escape"
  fi
done
# The in-tree allowlist default must not admit the retired provider APIs
# (PR runs use origin/main's fetched pattern; this pins the post-merge state).
allowed_default="$(grep -E '^[[:space:]]*allowed_url=' "$CI" || true)"
[ -n "$allowed_default" ] || bad "ci.yml allowed_url default not found"
is "exactly one line-leading allowed_url assignment" "1" "$(grep -cE '^[[:space:]]*allowed_url=' "$CI")"
is "ci.yml allowed_url default blob hash (pin: update after a deliberate edit)" "2995ad1ff3581328f07a567d6ffa840d3dad8cc14627869d8dc2288ff7b57617" "$(printf '%s' "$allowed_default" | sha256sum | cut -d' ' -f1)"
lacks "ci.yml does not append to allowed_url" 'allowed_url+=' "$(cat "$CI")"
lacks "ci.yml allowlist default does not name cloudflare" 'cloudflare' "$allowed_default"
lacks "ci.yml allowlist default does not name gcore" 'gcore' "$allowed_default"
# The whole allowlist step is byte-pinned: the default-line pin above cannot
# see a later re-assignment (`declare allowed_url=...`) that re-admits the
# retired provider APIs without touching the pinned line. Exactly one raw
# step header may exist, or a byte-identical copy earlier in the file (even
# inside a scalar the structural stripper does not honour) would satisfy the
# hash while the real step is weakened. A step at end-of-file has no
# following sibling/job line and fails closed as "span not found": a move to
# EOF changes the step's job membership, so it must update this guard
# deliberately (over-approximation accepted; trailing comments after the step
# also join the pin).
is "exactly one allowlist-step header in ci.yml" "1" "$(grep -cE '^      - name: Fail on anything netcup-shaped outside the allowlist$' "$CI")"
ALLOW_START="$(printf '%s\n' "$CI_STRUCT" | awk -F'\t' '$2 == "      - name: Fail on anything netcup-shaped outside the allowlist" {print $1; exit}')"
ALLOW_END="$(printf '%s\n' "$CI_STRUCT" | awk -F'\t' -v s="$ALLOW_START" '$1 > s && ($2 ~ /^      - / || $2 ~ /^  [^ #]/) {print $1; exit}')"
if [ -n "$ALLOW_START" ] && [ -n "$ALLOW_END" ]; then
  ALLOW_STEP_BLOB="$(sed -n "${ALLOW_START},$((ALLOW_END - 1))p" "$CI")"
  is "allowlist step blob hash (pin: update after a deliberate edit)" "9af2491dbc47cd000e75bfb7b682891c25d710ec6f0552837c5e426c60bcdc57" "$(printf '%s\n' "$ALLOW_STEP_BLOB" | sha256sum | cut -d' ' -f1)"
else
  bad "allowlist step span not found in ci.yml"
fi

# ---- production surfaces carry no retired name ----------------------------
# Every file in the repo outside .git/ and the gitignored .local/ proof
# config is a production surface (extensionless and Markdown included),
# except two record classes that name the retired identifiers by design:
# the `tests/*/run-test.sh` harness records (exactly one level — the pins
# themselves; a nested `run-test.sh` is scanned like any other file) and
# docs/security-posture.md + docs/verification.md. Recording the whole tree
# closes the execute-a-test-script route: an unpinned job could
# otherwise `run: bash tests/evil.sh` — however the path is spelled, shell
# assembly included — and a direct provider write inside the script would
# never be scanned. A new `tools/evil.sh`, `tools/dns-fallback.env`,
# `evil.bash`, `.github/workflows/evil.yaml`, `scripts/lib/helper`,
# `.terraform/payload.sh` or sourced
# `docs/evil.md` must not sit outside the scan. There is no bytecode-cache
# exemption: a planted `.pyc` is an execution route (the recording-witness
# harness deletes its cache before its first python call and writes none
# back, so any in-tree `__pycache__`/`.pyc` is scanned — a binary pyc fails
# the NUL check below) — r21 F3. A
# `terraform-provider-*`/`tofu-provider-*`
# provider binary is only exempt from the NUL check below (exact path shape;
# a descendant of a provider-shaped directory is scanned) — r21 F6. Word
# boundaries keep the live broker config name (`PC_BROKER_STATUS_EDGE_DOMAIN`)
# legal while the retired repo variable is caught. Comments are INCLUDED: a
# stale comment is drift too. The named groups are still checked explicitly
# so a renamed/moved directory cannot silently empty the scan; a grep error
# (rc>1) is a failure, not a pass.
shopt -s nullglob
for d in .github/workflows .github/scripts scripts; do
  [ -d "$d" ] || bad "surface directory missing: $d"
done
for pat in '.github/workflows/*.yml' '.github/scripts/*.sh' 'scripts/*.sh'; do
  compgen -G "$pat" >/dev/null || bad "surface group matched nothing: $pat"
done
surface_files=()
while IFS= read -r f; do
  # bash regex, not `find -path`: `*` in a find path pattern crosses `/`,
  # which would over-exclude a nested `tests/a/b/run-test.sh` from the scan.
  if [[ "$f" =~ ^\./tests/[^/]+/run-test\.sh$ ]]; then continue; fi
  if [[ "$f" == "./docs/security-posture.md" || "$f" == "./docs/verification.md" ]]; then continue; fi
  # No bytecode-cache exemption: a planted `.pyc` is an execution route
  # (Python loads a PEP 552 hash-based pyc instead of the source) and the
  # recording-witness harness deletes its cache before the first python call
  # and writes none back, so any in-tree `__pycache__`/`.pyc` is scanned like
  # any other file (a binary pyc fails the NUL check) — r21 F3.
  surface_files+=("$f")
done < <(find . \( -path ./.git -o -path ./.local \) -prune -o -type f -print | sort)
[ "${#surface_files[@]}" -gt 0 ] || bad "no production surfaces matched"
# A symlink in the production surface would dodge the scan entirely: fail
# closed instead (the tree has none). This check is unconditional — a
# `tests/*/run-test.sh` record replaced by a symlink would otherwise run the
# wrong file in CI with every other pin green.
symlinks="$(find . \( -path ./.git -o -path ./.local \) -prune -o -type l -print | sort)"
if [ -z "$symlinks" ]; then ok "no symlinks in the production surface"; else bad "symlink in the production surface: $symlinks"; fi
# A binary or encoded payload (e.g. UTF-16LE) in the production surface can
# carry a retired identifier that no text grep sees; fail closed on any NUL
# byte. The tree has none.
nul_files=""
for f in "${surface_files[@]}"; do
  # A tofu provider binary under `.terraform/providers/` carries NUL bytes by
  # design: only the NUL check tolerates it, and the name/host scan still
  # covers it. Everywhere else a provider-shaped name is scanned like any
  # other file, and everything else must be text (a UTF-16/other encoding
  # payload fails closed).
  # Exact shape, not a `case` glob: a `case` pattern's `*` crosses `/`, so
  # `.../terraform-provider-aws/inner.sh` was exempt too (r21 F6). The regex
  # requires exactly one non-slash directory component and a non-slash
  # basename.
  if [[ "$f" =~ ^\./\.terraform/providers/[^/]+/(terraform|tofu)-provider-[^/]+$ ]]; then continue; fi
  if ! cmp -s <(LC_ALL=C tr -d '\0' < "$f") "$f"; then nul_files="$nul_files $f"; fi
done
if [ -z "$nul_files" ]; then ok "no production surface file contains a NUL byte"; else bad "production surface files contain NUL bytes (binary/encoded):$nul_files"; fi
for f in "${surface_files[@]}"; do
  [ -f "$f" ] || bad "scanned surface missing: $f"
done
for v in NET_DNS_PROVIDER STATUS_EDGE_DOMAIN CLOUDFLARE_DNS_TOKEN GCORE_DNS_TOKEN; do
  rc=0
  hits="$(grep -linwE -- "$v" "${surface_files[@]}")" || rc=$?
  case "$rc" in
    0) bad "production surface uses $v: $hits" ;;
    1) ok "no production surface uses $v" ;;
    *) bad "grep failed scanning for $v (rc=$rc)" ;;
  esac
done
writer_rc=0
writer_hits="$(grep -lnE '030-anchor-dns|tests/anchor-dns' "${surface_files[@]}")" || writer_rc=$?
case "$writer_rc" in
  0) bad "production surface references the retired writer/harness: $writer_hits" ;;
  1) ok "no production surface references the retired writer/harness" ;;
  *) bad "grep failed scanning for the retired writer/harness (rc=$writer_rc)" ;;
esac
# The retired provider APIs must not reappear even when URL_EXTRACT cannot
# see the URL (`${SCHEME}://api.gcore.com`, `HTTPS://...`): the API
# hostnames are banned case-insensitively across the whole production
# surface: any subdomain of the retired providers (`api.gcore.com`, the
# legacy `api.gcorelabs.com`, `api.cloudflare.com`, `dns.gcore.com`),
# escaped-dot spellings included. A bare provider domain in prose (the
# Cloudflare edge-ranges comment in main.tf) is not an API host and stays
# legal; a variable-assembled hostname remains a disclosed residual.
for pat in '[[:alnum:]_-]+\\*\.gcore\\*\.com' '[[:alnum:]_-]+\\*\.gcorelabs\\*\.com' '[[:alnum:]_-]+\\*\.cloudflare\\*\.com'; do
  host_rc=0
  host_hits="$(grep -liE -- "$pat" "${surface_files[@]}")" || host_rc=$?
  case "$host_rc" in
    0) bad "production surface names a retired provider host ($pat): $host_hits" ;;
    1) ok "no production surface names a retired provider host ($pat)" ;;
    *) bad "grep failed scanning for '$pat' (rc=$host_rc)" ;;
  esac
done

# Composite and local actions execute in the same context: every action
# manifest anywhere outside tests/ (a `uses: ./actions/foo` local action
# included) and every file under an actions/ or .github/actions/ directory
# joins the scan. Retired names must not appear in any of them.
action_files=()
while IFS= read -r f; do action_files+=("$f"); done < <(find . \( -path ./.git -o -path ./tests \) -prune -o -type f \( -name 'action.yml' -o -name 'action.yaml' \) -print | sort)
for d in .github/actions actions; do
  if [ -d "$d" ]; then
    while IFS= read -r f; do action_files+=("$f"); done < <(find "$d" -type f | sort)
  fi
done
if [ "${#action_files[@]}" -gt 0 ]; then
  for v in NET_DNS_PROVIDER STATUS_EDGE_DOMAIN CLOUDFLARE_DNS_TOKEN GCORE_DNS_TOKEN; do
    rc=0
    hits="$(grep -lnwE -- "$v" "${action_files[@]}")" || rc=$?
    case "$rc" in
      0) bad "action manifest/script uses $v: $hits" ;;
      1) ok "no action manifest/script uses $v" ;;
      *) bad "grep failed scanning action files for $v (rc=$rc)" ;;
    esac
  done
  rc=0
  hits="$(grep -lnE '030-anchor-dns|tests/anchor-dns' "${action_files[@]}")" || rc=$?
  case "$rc" in
    0) bad "action manifest/script references the retired writer/harness: $hits" ;;
    1) ok "no action manifest/script references the retired writer/harness" ;;
    *) bad "grep failed scanning action files for the retired writer/harness (rc=$rc)" ;;
  esac
fi

# Dynamic secret/variable indexing can reconstruct any banned name from split
# literals (`secrets[format('{0}{1}', 'CLOUDFLARE', '_DNS_TOKEN')]`), which no
# word-boundary grep can see — ban the bracket form across the whole
# executable .github surface. Literal `secrets.NAME` / `vars.NAME` stays the
# only admitted spelling.
gh_files="$(find .github -type f \( -name '*.yml' -o -name '*.yaml' -o -name '*.sh' \) | sort)"
[ -n "$gh_files" ] || bad "no .github files found for the dynamic-index scan"
for pat in 'secrets[[:space:]]*\[' 'vars[[:space:]]*\['; do
  rc=0
  hits="$(grep -lnE -- "$pat" $gh_files)" || rc=$?
  case "$rc" in
    0) bad "dynamic indexing matching '$pat' in .github: $hits" ;;
    1) ok "no dynamic indexing matching '$pat' in .github" ;;
    *) bad "grep failed scanning for '$pat' (rc=$rc)" ;;
  esac
done

# A dropped run-list line silently skips a harness and no harness can catch
# its own absence — the cross-check lives here, in managed-inputs and in
# edge-origin-auth, so removing one checker's line still leaves two failing.
# Deleting the harness FILE is caught at CI runtime (the run step's `bash`
# exits 127) unless its run-list line is removed in the same PR; that joint
# removal is a disclosed review-only residual (the unit-tests-scripts
# whole-job pin catches a runner-side overwrite, not an absent file).
shopt -s nullglob
harnesses=(tests/*/run-test.sh)
[ ${#harnesses[@]} -gt 0 ] || bad "no tests/*/run-test.sh harnesses found"
for t in "${harnesses[@]}"; do
  # Whole-line, indentation-tolerant match inside the unit-tests-scripts job:
  # an `echo skipped # bash ...` decoy, a commented-out line, or a run line
  # in any other job does not satisfy it.
  if grep -qE "^[[:space:]]+bash ${t//./\\.}[[:space:]]*$" <<<"$ci_unit"; then
    ok "ci.yml run list includes $t"
  else
    bad "ci.yml run list includes $t"
  fi
done

# Exact passing-check floor (count-only, same class as banner-workflow-diff):
# deleting or emptying a counted check (the byte-pin block included) fails
# the suite instead of silently reducing coverage; a same-count gutting —
# deleting an ok-less guard, or this block itself — is invisible here and
# relies on review plus the CI run list. Update deliberately when adding or
# removing checks.
CHECK_FLOOR=284
if [ "$pass" -eq "$CHECK_FLOOR" ]; then :; else bad "check floor: expected exactly $CHECK_FLOOR passing checks, got $pass"; fi

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
