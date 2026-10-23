#!/usr/bin/env bash
# tests/edge-origin-auth/run-test.sh — CloudFront origin-auth proofs (call D).
#
# The :443 origin leg has three controls: the firewall admits only the
# CloudFront origin-facing ranges + the main box (main.tf); Caddy admits by the
# RAW TCP peer (remote_ip; never header-derived) (scripts/010-provision.sh);
# and the origin client certificate is verified at the TLS layer
# (client_auth require_and_verify, #202). The retired shared X-Piercloud-Origin
# header gate is gone, and this harness pins its ABSENCE. It drives the REAL
# render span (extracted, never a copy) and asserts:
#   - fail-closed: ill-formed MAIN_BOX_IPV4 refuses to render the :443 block;
#     an unset or malformed retired CLOUDFRONT_ORIGIN_SECRET no longer refuses
#     (#202 tooth b) and is never rendered (tooth a);
#   - gate content: the raw-peer @not_edge_peer matcher + abort, the main-box
#     bypass, remote_ip, NO header matcher, and NO trusted_proxies/client_ip_headers;
#   - mutation (d): re-inserting the retired @unauthorized matcher into the real
#     render is refused by the extracted self-check;
#   - :80 serves tang + ACME only (no @status dashboard handler);
#   - HSTS on the :443 site (max-age=15552000, no includeSubDomains);
#   - sync tooth: the 010 constant == cloudfront_ranges.tf (same set, 81);
#   - firewall wiring: :443 loops the CloudFront ranges + the main-box rule,
#     :80 still loops cf_edge_cidrs;
#   - pipeline wiring: provision.yml no longer references the retired secret
#     (tooth c), 020 never exports it, MAIN_BOX_IPV4 stays wired, ci.yml runs
#     this harness with its path gate intact.
# Cred-free, offline (no caddy, no network).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
PROVISION_SH="scripts/010-provision.sh"
RANGES_TF="cloudfront_ranges.tf"
MAIN_TF="main.tf"
PROV=".github/workflows/provision.yml"
ANCHOR_020=".github/scripts/020-provision-anchor.sh"
CI=".github/workflows/ci.yml"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0
ok()  { pass=$((pass + 1)); printf 'ok   %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL %s\n' "$1"; }
is()  { # $1 label, $2 expected, $3 actual
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi
}
has() { # $1 file, $2 literal, $3 label
  if grep -Fq -- "$2" "$1"; then ok "$3"; else bad "$3 (missing '$2' in $1)"; fi
}
hasnt() { # $1 file, $2 literal, $3 label
  if grep -Fq -- "$2" "$1"; then bad "$3 (unexpected '$2' in $1)"; else ok "$3"; fi
}

# ---- real render span (extracted, never a copy) ---------------------------
die()  { printf '\nFAIL: %s\n' "$*" >&2; exit 1; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
b="$(grep -n -m1 'BEGIN CADDY RENDER' "${PROVISION_SH}" | cut -d: -f1)"
e="$(grep -n -m1 'END CADDY RENDER' "${PROVISION_SH}" | cut -d: -f1)"
[ -n "$b" ] && [ -n "$e" ] && [ "$b" -lt "$e" ] || die "Caddy render markers missing/ambiguous in ${PROVISION_SH}"
sed -n "$((b + 1)),$((e - 1))p" "${PROVISION_SH}" > "${WORK}/render.src"
# shellcheck disable=SC1090
source "${WORK}/render.src"
command -v render_caddyfile >/dev/null || die "extraction did not yield render_caddyfile"
command -v caddy_status_names >/dev/null || die "extraction did not yield caddy_status_names"
# Production origin-range constant, extracted — never retyped, cannot drift.
eval "$(grep '^CLOUDFRONT_ORIGIN_CIDRS=' "${PROVISION_SH}")"
[ -n "${CLOUDFRONT_ORIGIN_CIDRS:-}" ] || die "CLOUDFRONT_ORIGIN_CIDRS extraction failed"

MAIN_BOX="192.0.2.99"
DASH_HOST="prodprobe.status.piercloud.net"
# The self-check reads both ports at call time (render_443 exports them in a
# subshell, so they must exist at top level too).
TANG_PORT="8081"
GATUS_PORT="8080"
SECRET="harness-origin-secret"
cf_cel="$(printf "'%s'," ${CLOUDFRONT_ORIGIN_CIDRS})"
cf_cel="${cf_cel%,}"

render_443() { # print the :443 dashboard shape (fail-closed on bad env)
  export CADDY_HTTP_ADDR=":80" CADDY_SKIP_HTTPS="" TANG_PORT="8081" GATUS_PORT="8080"
  export CADDY_CHALLENGE_DIR="${WORK}/acme-challenge"
  export TENANT_USER=prodprobe STATUS_HOST=""
  export DASH_TLS_STANZA="	# harness: no origin pair; auto-HTTPS stub."
  caddy_status_names
  render_caddyfile
}
expect_fail() { # $1 label, $2 expected message substring; caller sets the env
  local out rc
  set +e
  out="$(render_443 2>&1)"
  rc=$?
  set -e
  if [ "$rc" -eq 0 ]; then bad "$1 (render succeeded; expected refusal)"; return 0; fi
  ok "$1 (refused, rc=$rc)"
  case "$out" in
    *"$2"*) ok "$1 message" ;;
    *) bad "$1 message (missing '$2' in: $(printf '%s' "$out" | tail -c 300))" ;;
  esac
}

# ---- fail-closed ----------------------------------------------------------
export MAIN_BOX_IPV4="${MAIN_BOX}"
unset CLOUDFRONT_ORIGIN_SECRET
( render_443 ) >"${WORK}/Caddyfile.nosecret" || die "render with CLOUDFRONT_ORIGIN_SECRET unset refused (#202: the retired secret must not be required)"
ok "render succeeds with CLOUDFRONT_ORIGIN_SECRET unset (#202 tooth b)"

export CLOUDFRONT_ORIGIN_SECRET="${SECRET}"
unset MAIN_BOX_IPV4
expect_fail "missing MAIN_BOX_IPV4 refuses" "MAIN_BOX_IPV4 is not set"

export CLOUDFRONT_ORIGIN_SECRET='sec ret' MAIN_BOX_IPV4="${MAIN_BOX}"
( render_443 ) >"${WORK}/Caddyfile.badsecret" || die "render with a malformed retired secret refused (#202)"
hasnt "${WORK}/Caddyfile.badsecret" 'sec ret' "a malformed retired secret is never rendered (#202)"

export CLOUDFRONT_ORIGIN_SECRET="${SECRET}" MAIN_BOX_IPV4="1.2.3"
expect_fail "short MAIN_BOX_IPV4 refuses" "not a bare IPv4"

export MAIN_BOX_IPV4="999.999.999.999"
expect_fail "out-of-range MAIN_BOX_IPV4 refuses" "not a bare IPv4"

export MAIN_BOX_IPV4="1.2.3.4.5"
expect_fail "five-octet MAIN_BOX_IPV4 refuses" "not a bare IPv4"

export MAIN_BOX_IPV4=$'1.2.3.4\n5.6.7.8'
expect_fail "multiline MAIN_BOX_IPV4 refuses" "digits and dots only"

export MAIN_BOX_IPV4="1.2.3.04"
expect_fail "leading-zero octet MAIN_BOX_IPV4 refuses" "not a bare IPv4"

export MAIN_BOX_IPV4=$'192.0.2.99\n'
expect_fail "trailing-newline MAIN_BOX_IPV4 refuses" "digits and dots only"

export CLOUDFRONT_ORIGIN_SECRET="${SECRET}" MAIN_BOX_IPV4="${MAIN_BOX}"
saved_cidrs="${CLOUDFRONT_ORIGIN_CIDRS}"
CLOUDFRONT_ORIGIN_CIDRS=""
expect_fail "empty CLOUDFRONT_ORIGIN_CIDRS refuses" "CLOUDFRONT_ORIGIN_CIDRS is empty"
CLOUDFRONT_ORIGIN_CIDRS="${saved_cidrs}"

# ---- happy-path render + gate content -------------------------------------
export CLOUDFRONT_ORIGIN_SECRET="${SECRET}" MAIN_BOX_IPV4="${MAIN_BOX}"
( render_443 ) > "${WORK}/Caddyfile.443" || die "happy-path render failed"
has "${WORK}/Caddyfile.443" 'abort @not_edge_peer' "gate aborts non-CloudFront peers"
hasnt "${WORK}/Caddyfile.443" '@unauthorized' "gate has no header-only matcher (the retired @unauthorized is gone)"
hasnt "${WORK}/Caddyfile.443" "${SECRET}" "render never carries the retired origin secret, even when set (#202 tooth a)"
hasnt "${WORK}/Caddyfile.443" 'X-Piercloud-Origin' "render never names the retired origin header (#202 tooth a)"
hasnt "${WORK}/Caddyfile.443" 'CLOUDFRONT_ORIGIN_SECRET' "render never names the retired secret variable (#202 tooth a)"
hasnt "${WORK}/Caddyfile.443" 'header({' "render has no header({ matcher (#202 tooth a)"
has "${WORK}/Caddyfile.443" 'remote_ip(' "gate matches the raw TCP peer (remote_ip)"
hasnt "${WORK}/Caddyfile.443" 'trusted_proxies' "no trusted_proxies (header cannot move the peer gate)"
hasnt "${WORK}/Caddyfile.443" 'client_ip_headers' "no client_ip_headers (header is never admission)"
has "${WORK}/Caddyfile.443" 'header Strict-Transport-Security "max-age=15552000"' "HSTS max-age=15552000 on the :443 site"
hasnt "${WORK}/Caddyfile.443" 'includeSubDomains' "HSTS does not includeSubDomains"
# Red-team F3: strict SNI/Host is pinned explicitly, never left to the Caddy
# default, and never disabled (insecure_off would let an empty SNI select the
# match-less TLS policy, which has no client_auth).
has "${WORK}/Caddyfile.443" 'strict_sni_host on' "render pins strict SNI/Host matching explicitly (F3)"
hasnt "${WORK}/Caddyfile.443" 'insecure_off' "render never disables strict SNI/Host (F3)"

# :80 carries tang + ACME only — no dashboard handler (origin hardening).
awk '/^:80 \{/{f=1} f{print} f&&/^}$/{exit}' "${WORK}/Caddyfile.443" > "${WORK}/http.block"
has "${WORK}/http.block" 'handle /.well-known/acme-challenge/*' ":80 keeps the ACME challenge handler"
has "${WORK}/http.block" 'handle /adv*' ":80 keeps tang /adv*"
has "${WORK}/http.block" 'handle /rec*' ":80 keeps tang /rec*"
has "${WORK}/http.block" 'abort' ":80 keeps the catch-all abort"
has "${WORK}/Caddyfile.443" "https://${DASH_HOST} {" ":443 site covers the derived dashboard host"
hasnt "${WORK}/http.block" "${DASH_HOST}" ":80 has no dashboard Host matcher"
hasnt "${WORK}/http.block" "127.0.0.1:${GATUS_PORT}" ":80 has no dashboard proxy"
hasnt "${WORK}/Caddyfile.443" '@status' "render has no @status matcher"

# ---- hardening self-check (extracted, never a copy) -----------------------
# The converge self-check that runs on the box is the thing standing between a
# regressed render and a green apply. Execute it here against the hardened
# render and a regressed fixture for every leg that could silently regress, so
# a render/matcher drift reddens CI instead of every live run. The check is a
# text tripwire, not a boundary (tests/bind-e2e is the behavioural tooth);
# these fixtures keep every leg load-bearing, and each asserts the die MESSAGE
# so a fixture cannot be refused by the wrong leg. (The readable-file guard is
# asserted directly; the wiring pins are asserted textually below.)
is "exactly one BEGIN HARDENING CHECK marker" "1" "$(grep -c 'BEGIN HARDENING CHECK' "${PROVISION_SH}")"
is "exactly one END HARDENING CHECK marker" "1" "$(grep -c 'END HARDENING CHECK' "${PROVISION_SH}")"
hc_b="$(grep -n -m1 'BEGIN HARDENING CHECK' "${PROVISION_SH}" | cut -d: -f1)"
hc_e="$(grep -n -m1 'END HARDENING CHECK' "${PROVISION_SH}" | cut -d: -f1)"
[ -n "$hc_b" ] && [ -n "$hc_e" ] && [ "$hc_b" -lt "$hc_e" ] || die "hardening-check markers missing/ambiguous in ${PROVISION_SH}"
sed -n "$((hc_b + 1)),$((hc_e - 1))p" "${PROVISION_SH}" > "${WORK}/hardening.src"
# shellcheck disable=SC1090
source "${WORK}/hardening.src"
command -v assert_caddyfile_hardened >/dev/null || die "extraction did not yield assert_caddyfile_hardened"
docker() { return 1; } # the failure path's log dump is not part of the assertion
hard_run() { # $1 file -> rc, output in ${WORK}/hardening.out
  ( assert_caddyfile_hardened "$1" ) >"${WORK}/hardening.out" 2>&1
}
hard_ok() { # $1 file, $2 label -> the self-check must ACCEPT it
  if hard_run "$1"; then ok "$2"; else bad "$2 (self-check refused a hardened render: $(tail -1 "${WORK}/hardening.out"))"; fi
}
hard_die() { # $1 file, $2 message substring, $3 label -> must REFUSE, for that reason
  if hard_run "$1"; then bad "$3 (self-check accepted a regressed render)"; return 0; fi
  if grep -Fq -- "$2" "${WORK}/hardening.out"; then ok "$3"; else bad "$3 (refused for the wrong leg: $(tail -1 "${WORK}/hardening.out"))"; fi
}
# Wiring: the definition is executed by a real no-argument call asserting the
# serving file, so deleting the call, passing an argument, or retargeting the
# default cannot stay green.
is "assert_caddyfile_hardened: one definition + one call" "2" "$(grep -c 'assert_caddyfile_hardened' "${PROVISION_SH}")"
is "the converge self-check call site is the bare call" "1" "$(grep -cE '^    assert_caddyfile_hardened$' "${PROVISION_SH}")"
is "the self-check default is the serving Caddyfile" "1" "$(grep -cF 'local cfg="${1:-${CADDY_CONFIG}}" live http_block https_block bad_up gatus_hits' "${PROVISION_SH}")"
has "${PROVISION_SH}" 'if [ -z "${CADDY_SKIP_HTTPS:-}" ]; then' "the self-check stays behind the CADDY_SKIP_HTTPS harness guard"

hard_ok "${WORK}/Caddyfile.443" "self-check accepts the hardened render"
# Fixture 0: an empty file (a truncated install) — the readability guard, which
# every other leg would otherwise read as "nothing to complain about".
: > "${WORK}/Caddyfile.empty"
hard_die "${WORK}/Caddyfile.empty" "cannot read the rendered Caddyfile" "self-check refuses an empty/truncated Caddyfile"
# Fixture 1: a :80 dashboard handler under a DIFFERENT matcher name.
sed 's#^\tlog_skip$#\tlog_skip\n\t@dash {\n\t\thost citest.status.piercloud.net\n\t}\n\thandle @dash {\n\t\treverse_proxy 127.0.0.1:'"${GATUS_PORT}"'\n\t}#' \
  "${WORK}/Caddyfile.443" > "${WORK}/Caddyfile.dash-regressed"
has "${WORK}/Caddyfile.dash-regressed" "reverse_proxy 127.0.0.1:${GATUS_PORT}" "regressed fixture 1 carries a :80 dashboard handler"
hasnt "${WORK}/Caddyfile.dash-regressed" '@status' "regressed fixture 1 avoids the @status spelling"
hard_die "${WORK}/Caddyfile.dash-regressed" "proxies something other than tang" "self-check refuses a :80 dashboard handler under another matcher"
# Fixture 2: the same handler with a QUOTED upstream — the tang-only leg must
# catch it regardless of quoting (an exact-literal match would not).
sed 's#^\tlog_skip$#\tlog_skip\n\t@dash {\n\t\thost citest.status.piercloud.net\n\t}\n\thandle @dash {\n\t\treverse_proxy "127.0.0.1:'"${GATUS_PORT}"'"\n\t}#' \
  "${WORK}/Caddyfile.443" > "${WORK}/Caddyfile.quoted-regressed"
hard_die "${WORK}/Caddyfile.quoted-regressed" "proxies something other than tang" "self-check refuses a quoted :80 dashboard upstream"
# Fixture 3: a SECOND site block binding :80 (a host-specific http:// block is
# legal next to the bare :80 one), proxying the dashboard.
{ cat "${WORK}/Caddyfile.443"; printf '\nhttp://citest.status.piercloud.net {\n\treverse_proxy 127.0.0.1:%s\n}\n' "${GATUS_PORT}"; } > "${WORK}/Caddyfile.second-site"
hard_die "${WORK}/Caddyfile.second-site" "references the Gatus port" "self-check refuses a second :80 site proxying the dashboard"
# Fixture 4: the removed @status spelling back.
sed 's#^\tlog_skip$#\tlog_skip\n\t@status {\n\t\thost citest.status.piercloud.net\n\t}#' \
  "${WORK}/Caddyfile.443" > "${WORK}/Caddyfile.status-regressed"
has "${WORK}/Caddyfile.status-regressed" '@status {' "regressed fixture 4 carries @status"
hard_die "${WORK}/Caddyfile.status-regressed" "still carries the removed :80 dashboard handler" "self-check refuses the @status spelling"
# Fixture 5: the header-derived proxy trust back, in its real position (the
# global servers option block).
sed 's#^\tadmin 127.0.0.1:2019$#\tadmin 127.0.0.1:2019\n\tservers {\n\t\ttrusted_proxies static 192.0.2.0/24\n\t}#' \
  "${WORK}/Caddyfile.443" > "${WORK}/Caddyfile.trust-regressed"
has "${WORK}/Caddyfile.trust-regressed" 'trusted_proxies static 192.0.2.0/24' "regressed fixture 5 carries trusted_proxies"
hard_die "${WORK}/Caddyfile.trust-regressed" "still carries the removed :80 dashboard handler and/or header-derived proxy trust" "self-check refuses re-introduced proxy trust"
# Fixture 6: client_ip_headers alone (the other half of the removed pair).
sed 's#^\tadmin 127.0.0.1:2019$#\tadmin 127.0.0.1:2019\n\tservers {\n\t\tclient_ip_headers CloudFront-Viewer-Address\n\t}#' \
  "${WORK}/Caddyfile.443" > "${WORK}/Caddyfile.clientip-regressed"
has "${WORK}/Caddyfile.clientip-regressed" 'client_ip_headers CloudFront-Viewer-Address' "regressed fixture 6 carries client_ip_headers"
hasnt "${WORK}/Caddyfile.clientip-regressed" 'trusted_proxies' "regressed fixture 6 carries no trusted_proxies (the legs are independent)"
hard_die "${WORK}/Caddyfile.clientip-regressed" "still carries the removed :80 dashboard handler and/or header-derived proxy trust" "self-check refuses client_ip_headers alone"
# Fixture 7: the :80 site block gone but HSTS intact — a discriminator for the
# presence leg (fixture 9's no-HSTS file would otherwise be refused by HSTS).
awk '/^:80 \{/ { on = 1; n = gsub(/{/, "{"); m = gsub(/}/, "}"); depth += n - m; next } on { n = gsub(/{/, "{"); m = gsub(/}/, "}"); depth += n - m; if (depth <= 0) { on = 0 } ; next } { print }' \
  "${WORK}/Caddyfile.443" > "${WORK}/Caddyfile.no-http-block"
hasnt "${WORK}/Caddyfile.no-http-block" '^:80 {' ":80 block removed from the presence fixture"
has "${WORK}/Caddyfile.no-http-block" 'Strict-Transport-Security' "the presence fixture keeps HSTS (so the :80 leg is what must fire)"
hard_die "${WORK}/Caddyfile.no-http-block" "has no :80 site block" "self-check refuses a render with no :80 block (that leg, not HSTS)"
# Fixture 8: HSTS present but commented out.
sed 's|^\theader Strict-Transport-Security|\t# header Strict-Transport-Security|' \
  "${WORK}/Caddyfile.443" > "${WORK}/Caddyfile.hsts-commented"
hard_die "${WORK}/Caddyfile.hsts-commented" "lacks the :443 site-level HSTS header" "self-check refuses a commented-out HSTS line"
# Fixture 9: HSTS max-age drifted.
sed 's|max-age=15552000|max-age=1|' "${WORK}/Caddyfile.443" > "${WORK}/Caddyfile.hsts-drift"
hard_die "${WORK}/Caddyfile.hsts-drift" "lacks the :443 site-level HSTS header" "self-check refuses a drifted HSTS max-age"
# Fixture 10: HSTS moved inside a handle (one extra indent) — an abort path
# never sends it, so the site-level literal is pinned.
sed 's|^\theader Strict-Transport-Security|\t\theader Strict-Transport-Security|' \
  "${WORK}/Caddyfile.443" > "${WORK}/Caddyfile.hsts-indented"
hard_die "${WORK}/Caddyfile.hsts-indented" "lacks the :443 site-level HSTS header" "self-check refuses an indented (handle-scoped) HSTS line"
# Fixture 11: HSTS set and then deleted again.
awk '{ print } $0 ~ /^\theader Strict-Transport-Security "max-age=15552000"$/ { print "\theader -Strict-Transport-Security" }' \
  "${WORK}/Caddyfile.443" > "${WORK}/Caddyfile.hsts-deleted"
hard_die "${WORK}/Caddyfile.hsts-deleted" "deletes Strict-Transport-Security again" "self-check refuses an HSTS line deleted right after it is set"
# Fixture 12: a hardened render whose COMMENTS mention the retired directives
# must still pass (the check reads configuration lines, not prose).
sed 's|^\tlog_skip$|\tlog_skip\n\t# retired: @status + trusted_proxies client_ip_headers (issue 225)|' \
  "${WORK}/Caddyfile.443" > "${WORK}/Caddyfile.prose-mention"
has "${WORK}/Caddyfile.prose-mention" '# retired: @status + trusted_proxies client_ip_headers' "fixture 12 mentions the directives in a comment"
hard_ok "${WORK}/Caddyfile.prose-mention" "self-check ignores a prose mention of the retired directives"
# Fixture 13: the render REFORMATTED so the ACME handler's closing brace sits
# at column 0 and the dashboard handler follows it — pins the brace-depth scan
# (a prefix scan stops at that brace and never sees the handler).
awk -v gatus="${GATUS_PORT}" '
  BEGIN { depth0 = 0 }
  /^:80 \{/ { in80 = 1 }
  in80 && $0 == "\t}" && !done { print "}"; print "@dash {"; print "\thost citest.status.piercloud.net"; print "}"; print "handle @dash {"; print "\treverse_proxy 127.0.0.1:" gatus; print "}"; done = 1; next }
  { print }
' "${WORK}/Caddyfile.443" > "${WORK}/Caddyfile.reformatted"
is "regressed fixture 13 has a nested brace at column 0" "yes" "$(grep -qE '^}$' "${WORK}/Caddyfile.reformatted" && echo yes || echo no)"
is "regressed fixture 13 carries two Gatus upstreams" "2" "$(grep -c -F ":${GATUS_PORT}" "${WORK}/Caddyfile.reformatted")"
hard_die "${WORK}/Caddyfile.reformatted" "proxies something other than tang" "self-check scans past a column-0 nested brace"
# Fixture 14: the dashboard upstream moved OUT of the https site into a second
# host-specific http:// site (the Gatus port still occurs exactly once, so only
# the "inside the https site" leg can catch it).
sed 's|^\t\treverse_proxy 127.0.0.1:'"${GATUS_PORT}"'$|\t\t# backend moved|' \
  "${WORK}/Caddyfile.443" > "${WORK}/Caddyfile.upstream-outside"
{ cat "${WORK}/Caddyfile.upstream-outside"; printf '\nhttp://citest.status.piercloud.net {\n\treverse_proxy 127.0.0.1:%s\n}\n' "${GATUS_PORT}"; } > "${WORK}/Caddyfile.upstream-outside.tmp"
mv "${WORK}/Caddyfile.upstream-outside.tmp" "${WORK}/Caddyfile.upstream-outside"
is "fixture 14 keeps exactly one Gatus upstream" "1" "$(grep -c -F ":${GATUS_PORT}" "${WORK}/Caddyfile.upstream-outside")"
hard_die "${WORK}/Caddyfile.upstream-outside" "outside the https:// dashboard site" "self-check requires the dashboard upstream inside the https site"
# Fixture 15: no https:// dashboard site at all — the placement legs cannot run,
# so the check must refuse rather than pass vacuously.
awk '/^https:\/\// { on = 1; n = gsub(/{/, "{"); m = gsub(/}/, "}"); depth += n - m; next } on { n = gsub(/{/, "{"); m = gsub(/}/, "}"); depth += n - m; if (depth <= 0) { on = 0 }; next } { print }' \
  "${WORK}/Caddyfile.443" > "${WORK}/Caddyfile.no-https-block"
hasnt "${WORK}/Caddyfile.no-https-block" '^https://' "regressed fixture 15 has no https site block"
hard_die "${WORK}/Caddyfile.no-https-block" "has no https:// dashboard site block" "self-check refuses a render with no https dashboard site"
# Fixture 16: a NEW :80 handler serving files (no reverse_proxy at all) — the
# handler allowlist is the leg that must catch it.
sed 's#^\tlog_skip$#\tlog_skip\n\thandle /dash* {\n\t\troot * /srv/dashboard\n\t\tfile_server\n\t}#' \
  "${WORK}/Caddyfile.443" > "${WORK}/Caddyfile.static-dash"
has "${WORK}/Caddyfile.static-dash" 'file_server' "regressed fixture 16 serves files on :80"
is "regressed fixture 16 keeps exactly one Gatus upstream" "1" "$(grep -c -F ":${GATUS_PORT}" "${WORK}/Caddyfile.static-dash")"
hard_die "${WORK}/Caddyfile.static-dash" "unexpected" "self-check refuses an extra :80 handler (static dashboard)"
# Fixture 17: the HSTS delete spelled in lower case (header names are
# case-insensitive in Caddy).
awk '{ print } $0 ~ /^\theader Strict-Transport-Security "max-age=15552000"$/ { print "\theader -strict-transport-security" }' \
  "${WORK}/Caddyfile.443" > "${WORK}/Caddyfile.hsts-deleted-lc"
has "${WORK}/Caddyfile.hsts-deleted-lc" 'header -strict-transport-security' "regressed fixture 17 deletes HSTS in lower case"
hard_die "${WORK}/Caddyfile.hsts-deleted-lc" "deletes Strict-Transport-Security again" "self-check refuses a lower-case HSTS delete"

not_edge_line="$(grep -m1 '@not_edge_peer' "${WORK}/Caddyfile.443" || true)"
case "${not_edge_line}" in
  *"!(remote_ip(${cf_cel}, '127.0.0.1/32', '::1/128', '${MAIN_BOX}/32'))"*) ok "not_edge_peer matcher lists all 81 ranges + loopback (v4+v6) + the main box" ;;
  *) bad "not_edge_peer matcher shape (got: $(printf '%s' "${not_edge_line}" | tail -c 200))" ;;
esac
# (d) mutation: re-insert the retired @unauthorized header matcher into the REAL
# render, right after the raw-peer abort where it used to sit. The render is
# text, so the mutant is spliced from the real output, never retyped. The mutant
# must carry the retired gate (so the refusal cannot be vacuous), and the
# extracted self-check, which runs before every converge, must refuse it for
# that reason.
T=$'\t'
unauth_gate="${T}${T}@unauthorized \`!(remote_ip('127.0.0.1/32', '::1/128', '${MAIN_BOX}/32') || header({'X-Piercloud-Origin':'${SECRET}'}))\`"
awk -v gate="${unauth_gate}" -v gate2="${T}${T}abort @unauthorized" -v anchor="${T}${T}abort @not_edge_peer" \
  '{ print } $0 == anchor { print gate; print gate2 }' "${WORK}/Caddyfile.443" > "${WORK}/Caddyfile.unauth-mutant"
has "${WORK}/Caddyfile.unauth-mutant" 'abort @unauthorized' "mutation (d): the re-inserted header gate is present in the mutant"
hard_die "${WORK}/Caddyfile.unauth-mutant" "retired shared origin header (#202)" "mutation (d): the self-check refuses a render that re-inserts @unauthorized"

# Fixture 18 (red-team F1): a LOWER-case retired header matcher. Caddy
# canonicalizes header names, so `header x-piercloud-origin` is the same header
# as X-Piercloud-Origin; a case-sensitive tooth passes it and the regression ships.
lc_gate="${T}${T}@lc header x-piercloud-origin probe-value"
awk -v gate="${lc_gate}" -v anchor="${T}${T}abort @not_edge_peer" \
  '{ print } $0 == anchor { print gate }' "${WORK}/Caddyfile.443" > "${WORK}/Caddyfile.lc-header"
has "${WORK}/Caddyfile.lc-header" 'header x-piercloud-origin' "fixture 18: the lower-case retired header matcher is in the fixture"
hard_die "${WORK}/Caddyfile.lc-header" "retired shared origin header (#202)" "self-check refuses a lower-case header x-piercloud-origin matcher (F1)"
# Fixture 19 (red-team F5): a LEGITIMATE CEL header matcher is not the retired
# header and must never false-red the gate.
acc_gate="${T}${T}@accept header({'Accept':'application/json'})"
awk -v gate="${acc_gate}" -v anchor="${T}${T}abort @not_edge_peer" \
  '{ print } $0 == anchor { print gate }' "${WORK}/Caddyfile.443" > "${WORK}/Caddyfile.legit-header"
has "${WORK}/Caddyfile.legit-header" "header({'Accept'" "fixture 19: a legitimate header({...}) matcher is in the fixture"
hard_ok "${WORK}/Caddyfile.legit-header" "self-check accepts a legitimate header({'Accept':...}) matcher (F5: no false red)"
# The teeth are the two retired names, case-insensitively, at both sites (the
# in-function self-check and the post-render write gate), and no longer the
# case-sensitive header({ alternative.
is "010 teeth: two case-insensitive grep sites over the retired names" "2" "$(grep -cF "grep -Eqi 'x-piercloud-origin|cloudfront_origin_secret'" "${PROVISION_SH}")"
hasnt "${PROVISION_SH}" 'X-Piercloud-Origin|CLOUDFRONT_ORIGIN_SECRET|header\(\{' "the old case-sensitive teeth pattern (with header({) is gone (F1/F5)"

# The gate must sit INSIDE the catch-all handle: Caddy adapts `abort` after
# `handle`, so a site-level gate is dead code (tests/bind-e2e pins the
# adapted route order; this pins the text-level placement everywhere else).
awk '/^https:\/\//{f=1} f{print}' "${WORK}/Caddyfile.443" > "${WORK}/dash.block"
catchall_line="$(grep -n -m1 '^	handle {$' "${WORK}/dash.block" | cut -d: -f1 || true)"
gate_line="$(grep -n -m1 '@not_edge_peer' "${WORK}/dash.block" | cut -d: -f1 || true)"
proxy_line="$(grep -n -m1 'reverse_proxy 127.0.0.1:' "${WORK}/dash.block" | cut -d: -f1 || true)"
if [ -n "${catchall_line}" ] && [ -n "${gate_line}" ] && [ -n "${proxy_line}" ] && [ "${catchall_line}" -lt "${gate_line}" ] && [ "${gate_line}" -lt "${proxy_line}" ]; then
  ok "gate sits inside the catch-all handle, before the proxy"
else
  bad "gate placement (catch-all=${catchall_line} gate=${gate_line} proxy=${proxy_line})"
fi

# ---- sync tooth: 010 constant == cloudfront_ranges.tf ---------------------
tf_list="$(awk '/cloudfront_origin_facing_cidrs = \[/{f=1;next} f&&/^ *\]/{f=0} f' "${RANGES_TF}" \
  | grep -oE '"[^"]+"' | tr -d '"' | LC_ALL=C sort)"
sh_list="$(printf '%s\n' ${CLOUDFRONT_ORIGIN_CIDRS} | LC_ALL=C sort)"
is "cloudfront_ranges.tf entry count" "81" "$(printf '%s\n' "${tf_list}" | wc -l | tr -d ' ')"
is "010 range count" "81" "$(printf '%s\n' ${CLOUDFRONT_ORIGIN_CIDRS} | wc -w | tr -d ' ')"
is "010 == cloudfront_ranges.tf (sorted set)" "${sh_list}" "${tf_list}"

# ---- firewall wiring ------------------------------------------------------
has "${MAIN_TF}" 'for cidr in local.cloudfront_origin_facing_cidrs' "main.tf :443 loop = CloudFront origin ranges"
has "${MAIN_TF}" 'for cidr in local.cf_edge_cidrs' "main.tf :80 loop still = Cloudflare edge ranges"
if grep -A8 'for cidr in local.cloudfront_origin_facing_cidrs' "${MAIN_TF}" | grep -Fq 'destination_ports = "443"'; then
  ok "CloudFront loop is the :443 rule"
else
  bad "CloudFront loop is not a :443 rule"
fi
if grep -A8 'for cidr in local.cf_edge_cidrs' "${MAIN_TF}" | grep -Fq 'destination_ports = "80"'; then
  ok "Cloudflare loop is the :80 rule"
else
  bad "Cloudflare loop is not a :80 rule"
fi
if grep -A2 'destination_ports = "443"' "${MAIN_TF}" | grep -Fq 'allow_main_box_ipv4}/32"]'; then
  ok "main-box :443 bypass rule present"
else
  bad "main-box :443 bypass rule missing"
fi
if grep -A2 'destination_ports = "443"' "${MAIN_TF}" | grep -Fq 'allow_main_box_ipv6'; then
  bad "main.tf admits a main-box IPv6 peer on :443 with no Caddy counterpart"
else
  ok "no main-box IPv6 :443 rule (the Caddy bypass is v4-only)"
fi

# ---- render custody -------------------------------------------------------
has "${PROVISION_SH}" 'install -m 0600 /dev/null "$TMP_CADDY"' "rendered Caddyfile pre-created root-only"
has "${PROVISION_SH}" 'chmod 600 "${CADDY_CONFIG}"' "unchanged render re-asserts 0600 on the live Caddyfile"
has "${PROVISION_SH}" '"PRIVATE KEY"*)' "AOP bundle rejects key-bearing PEMs (it is written world-readable)"
has "${PROVISION_SH}" 'rm -f "$TMP_CADDY"; die "rendered Caddyfile failed validate' "validate failure removes the rendered file"
has "${PROVISION_SH}" 'rendered Caddyfile carries the retired shared origin header (#202)' "render-time tooth refuses a retired-header render before it is written"

# ---- pipeline wiring ------------------------------------------------------
hasnt "${PROV}" 'secrets.CLOUDFRONT_ORIGIN_SECRET' "provision.yml never references secrets.CLOUDFRONT_ORIGIN_SECRET (#202 tooth c)"
hasnt "${PROV}" 'CLOUDFRONT_ORIGIN_SECRET' "provision.yml names no retired origin-secret variable"
has "${PROV}" 'MAIN_BOX_IPV4: ${{ secrets.MAIN_BOX_IPV4 }}' "provision.yml passes MAIN_BOX_IPV4"
has "${PROV}" '::add-mask::${{ secrets.MAIN_BOX_IPV4 }}' "provision.yml masks the main-box address"
hasnt "${ANCHOR_020}" 'CLOUDFRONT_ORIGIN_SECRET' "020 never exports the retired secret (the box env carries none)"
has "${ANCHOR_020}" "MAIN_BOX_IPV4='\$(q \"\${MAIN_BOX_IPV4:-}\")'" "020 exports MAIN_BOX_IPV4"
has "${CI}" 'tests/edge-origin-auth/run-test.sh' "ci.yml runs this harness"
has "${CI}" 'edge-origin-auth|origin-mtls|origin-ca|recording-witness|broker-report)/' "ci.yml path gate includes edge-origin-auth (witness pin intact)"
# The extraction is anchored on the unit-tests gate's own prefix (not the
# first `elif grep -qE` in the file) so reordering jobs cannot silently move
# the case onto another gate (functional/red-team #170 LOW), and it runs on
# a block-scalar-stripped structural view so a decoy scalar cannot spoof it.
EDGE_CI_STRUCT="$(awk '
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
EDGE_CI_UNIT_START="$(awk -F'\t' '$2 ~ /^  unit-tests-scripts:[[:space:]]*(#.*)?$/ {print $1; exit}' <<<"$EDGE_CI_STRUCT")"
EDGE_CI_UNIT_END="$(awk -F'\t' -v s="$EDGE_CI_UNIT_START" '$1 > s && $2 ~ /^  [^ #].*:[[:space:]]*(#.*)?$/ {print $1; exit}' <<<"$EDGE_CI_STRUCT")"
EDGE_CI_UNIT=""
[ -n "$EDGE_CI_UNIT_START" ] && [ -n "$EDGE_CI_UNIT_END" ] && EDGE_CI_UNIT="$(sed -n "$((EDGE_CI_UNIT_START + 1)),$((EDGE_CI_UNIT_END - 1))p" "$CI" | grep -v '^[[:space:]]*#' || true)"
is "exactly one unit-tests-scripts job key line in ci.yml" "1" "$(grep -cE '^  unit-tests-scripts:' "$CI")"
gate_line_ci="$(grep -m1 -F "elif grep -qE '^(\\.github/scripts/" <<<"$EDGE_CI_UNIT" || true)"
case "${gate_line_ci}" in
  *'.*\.tf$'*) ok "ci.yml unit-tests gate runs on .tf-only changes" ;;
  *) bad "ci.yml unit-tests gate skips .tf-only changes (the sync tooth would not run)" ;;
esac

# Third independent wiring-completeness checker (b3b #189): every committed
# harness must be named in the ci.yml run list; no harness can catch its own
# removal. Three checkers in three harnesses mean dropping one still leaves
# two failing. The match is scoped to the unit-tests-scripts job block of
# the block-scalar-stripped structural view and is whole-line/
# indentation-tolerant, so a decoy `echo skipped # bash ...`, a
# commented-out line, a decoy scalar or a run line in another job fails
# here.
[ -n "${EDGE_CI_UNIT:-}" ] || bad "ci.yml unit-tests-scripts job not found"
shopt -s nullglob
edge_harnesses=(tests/*/run-test.sh)
[ ${#edge_harnesses[@]} -gt 0 ] || bad "no tests/*/run-test.sh harnesses found"
for t in "${edge_harnesses[@]}"; do
  if grep -qE "^[[:space:]]+bash ${t//./\\.}[[:space:]]*$" <<<"$EDGE_CI_UNIT"; then
    ok "ci.yml run list includes $t"
  else
    bad "ci.yml run list includes $t"
  fi
done

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
