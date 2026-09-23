#!/usr/bin/env bash
# tests/gatus-render/run-test.sh — offline, cred-free harness for the
# dispatch-managed Gatus render (issue #134).
#
# Extracts the REAL render span from scripts/010-provision.sh
# (`# --- gatus-render:start/end ---`; never a copy) and drives it with
# fixture env. Proves:
#   (a) the platform row renders on every anchor, monitor-only on tenant
#       shapes and alerting on the operator shape (call C1/C2);
#   (b) the alert shapes (call C9): class-5 rows (main/platform) publish
#       through the ntfy-JSON custom bridge with TRIGGERED 5 / RESOLVED 3 and
#       send-on-resolved; class-4 rows (GATUS_ENDPOINTS pairs, dashboard TLS)
#       use the native ntfy provider with provider-override priority 4;
#   (c) the built-in-name collision guard (call C6): a `platform=` pair always
#       fails, a `main=` pair fails only when the `main` built-in rendered;
#   (d) the role gate fails closed on an unknown ANCHOR_ROLE;
#   (e) with no NTFY_TOPIC the config is alert-free (checks only);
#   (f) regression: tang + dashboard TLS rows and their conditions survive.
#
# The span needs helpers defined earlier in 010 (log/warn/die/caddy_status_names)
# and GATUS_CONFIG; it is executed in a subshell per case so `die` only ends
# that case. No network, no cloud, no root.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROVISION="$ROOT/scripts/010-provision.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0
ok()  { pass=$((pass + 1)); printf 'ok   %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL %s\n' "$1"; }
has()    { # $1 label, $2 haystack, $3 needle
  case "$2" in *"$3"*) ok "$1" ;; *) bad "$1 (missing: $3)" ;; esac
}
lacks() { # $1 label, $2 haystack, $3 needle
  case "$2" in *"$3"*) bad "$1 (unexpected: $3)" ;; *) ok "$1" ;; esac
}

[ -f "$PROVISION" ] || { printf 'FAIL provision script not found: %s\n' "$PROVISION"; exit 1; }

# ---- extract the real span (markers must be unique) ----------------------
BEGIN='# --- gatus-render:start ---'
END='# --- gatus-render:end ---'
for m in "$BEGIN" "$END"; do
  n="$(grep -cF -- "$m" "$PROVISION" || true)"
  [ "$n" = "1" ] || { printf 'FAIL marker %s found %s times in %s\n' "$m" "${n:-0}" "$PROVISION"; exit 1; }
done
b="$(grep -nF -- "$BEGIN" "$PROVISION" | cut -d: -f1)"
e="$(grep -nF -- "$END" "$PROVISION" | cut -d: -f1)"
sed -n "$((b + 1)),$((e - 1))p" "$PROVISION" >"${WORK}/span.src"
[ -s "${WORK}/span.src" ] || { printf 'FAIL extracted gatus span is empty\n'; exit 1; }
has "span carries the role gate" "$(cat "${WORK}/span.src")" "ANCHOR_ROLE"
has "span carries the platform row" "$(cat "${WORK}/span.src")" "name: platform"

# Harness overrides: the same helpers 010 defines earlier, plus the config
# path the span writes to (never the real /etc/gatus/config.yaml).
cat >"${WORK}/stubs.src" <<'EOF'
set -euo pipefail
log()  { printf 'harness: %s\n' "$*" >&2; }
warn() { printf 'harness WARNING: %s\n' "$*" >&2; }
die()  { printf 'FAIL(die): %s\n' "$*" >&2; exit 1; }
caddy_status_names() { :; }   # STATUS_HOST/ANCHOR_HOSTNAME come from the fixture env
EOF

render() { # $1 = case label; the caller exports the env for the case
  local dir="$WORK/$1"
  mkdir -p "$dir"
  { cat "${WORK}/stubs.src"; printf 'GATUS_CONFIG=%q\n' "$dir/config.yaml"; cat "${WORK}/span.src"; } >"$dir/run.sh"
  ( cd "$dir"; bash run.sh >"$dir/stdout.log" 2>"$dir/stderr.log" )
}

fixture_env() { # common fixture env; per-case vars are set by the case itself
  export TENANT_USER=pier \
         ANCHOR_HOSTNAME=anchor-01-pier.piercloud.net \
         STATUS_HOST=status-pier.piercloud.net \
         NTFY_TOKEN=""
  unset ANCHOR_ROLE NTFY_TOPIC GATUS_ENDPOINTS
}

block() { # $1 = endpoint name, $2 = config file -> that endpoint's YAML block
  awk -v want="  - name: $1" '
    $0 == want { inb = 1; print; next }
    inb && /^  - name: / { inb = 0; next }
    inb { print }
  ' "$2"
}

yaml_ok() { # $1 label, $2 config file (ruby/psych when available)
  if command -v ruby >/dev/null 2>&1; then
    if ruby -ryaml -e 'YAML.load_file(ARGV[0], aliases: true)' "$2" >/dev/null 2>&1; then
      ok "$1"
    else
      bad "$1 (YAML does not parse)"
    fi
  fi
}

# ---- (a) tenant shape + push topic ---------------------------------------
fixture_env
export NTFY_TOPIC=pc-test-topic GATUS_ENDPOINTS="host=https://host.piercloud.net/healthz"
if render tenant_topic; then ok "tenant shape renders" ; else bad "tenant shape renders"; sed -n '1,3p' "$WORK/tenant_topic/stderr.log"; fi
CFG="$WORK/tenant_topic/config.yaml"
yaml_ok "tenant shape YAML parses" "$CFG"
platform_block="$(block platform "$CFG")"
has "tenant: platform row present" "$platform_block" "url: https://platform.piercloud.net/healthz"
has "tenant: platform interval 60s" "$platform_block" "interval: 60s"
has "tenant: platform status condition" "$platform_block" '[STATUS] == 200'
lacks "tenant: platform row is monitor-only (no alerts)" "$platform_block" "alerts:"
main_block="$(block main "$CFG")"
has "main uses the ntfy-JSON bridge" "$main_block" "type: custom"
has "main resolves at priority 3" "$main_block" 'RESOLVED: "3"'
has "main triggers at priority 5" "$main_block" 'TRIGGERED: "5"'
has "main sends on resolve" "$main_block" "send-on-resolved: true"
pairs_block="$(block host "$CFG")"
has "pairs use the native provider" "$pairs_block" "type: ntfy"
has "pairs carry priority 4" "$pairs_block" "priority: 4"
dashboard_block="$(block "dashboard TLS (via edge)" "$CFG")"
has "dashboard TLS carries priority 4" "$dashboard_block" "priority: 4"
has "dashboard TLS keeps the cert condition" "$dashboard_block" "[CERTIFICATE_EXPIRATION] > 720h"
has "tang row survives" "$(block "tang (via Caddy)" "$CFG")" "url: http://hostanchor/adv"
alerting="$(sed -n '/^alerting:/,/^endpoints:/p' "$CFG")"
has "alerting carries the native ntfy provider" "$alerting" "url: https://ntfy.sh"
has "alerting carries the JSON bridge" "$alerting" "https://ntfy.sh/"
has "bridge body carries the topic" "$alerting" '"topic":"pc-test-topic"'
has "bridge body uses the state placeholder" "$alerting" "[ALERT_TRIGGERED_OR_RESOLVED]"
has "bridge default placeholders 5/3" "$alerting" "TRIGGERED: \"5\""
lacks "no Authorization header without a token" "$alerting" "Authorization"

# ---- (b) operator shape ---------------------------------------------------
fixture_env
export NTFY_TOPIC=pc-test-topic ANCHOR_ROLE=operator
if render operator_topic; then ok "operator shape renders"; else bad "operator shape renders"; fi
CFG="$WORK/operator_topic/config.yaml"
yaml_ok "operator shape YAML parses" "$CFG"
platform_block="$(block platform "$CFG")"
has "operator: platform row alerts" "$platform_block" "alerts:"
has "operator: platform uses the bridge" "$platform_block" "type: custom"
has "operator: platform threshold 3" "$platform_block" "failure-threshold: 3"
has "operator: platform sends on resolve" "$platform_block" "send-on-resolved: true"
has "operator: platform placeholders 5/3" "$platform_block" "RESOLVED: \"3\""

# ---- (b2) explicit tenant role + token header -----------------------------
fixture_env
export NTFY_TOPIC=pc-test-topic ANCHOR_ROLE=tenant NTFY_TOKEN="tk_testtoken"
if render tenant_token; then ok "tenant role (explicit) + token renders"; else bad "tenant role (explicit) + token renders"; fi
CFG="$WORK/tenant_token/config.yaml"
platform_block="$(block platform "$CFG")"
lacks "explicit tenant: platform row is monitor-only" "$platform_block" "alerts:"
alerting="$(sed -n '/^alerting:/,/^endpoints:/p' "$CFG")"
has "token adds the bridge Authorization header" "$alerting" 'Authorization: "Bearer tk_testtoken"'
has "token adds the native provider token" "$alerting" "token: tk_testtoken"

# ---- (c) no push topic ----------------------------------------------------
fixture_env
if render no_topic; then ok "no-topic shape renders"; else bad "no-topic shape renders"; fi
CFG="$WORK/no_topic/config.yaml"
yaml_ok "no-topic YAML parses" "$CFG"
lacks "no-topic: no alerts anywhere" "$(cat "$CFG")" "alerts:"
lacks "no-topic: no custom provider" "$(cat "$CFG")" "custom:"
has "no-topic: warns instead of pushing" "$(cat "$CFG")" "No push channel"
has "no-topic: platform row still rendered" "$(block platform "$CFG")" "name: platform"

# ---- (d) fail-closed role gate -------------------------------------------
fixture_env
export ANCHOR_ROLE=bogus
if render bad_role; then bad "bad ANCHOR_ROLE fails closed" ; else ok "bad ANCHOR_ROLE fails closed"; fi
has "bad role names the accepted values" "$(cat "$WORK/bad_role/stderr.log")" "bad ANCHOR_ROLE"

# ---- (e) built-in-name collision guard (C6) -------------------------------
fixture_env
export GATUS_ENDPOINTS="platform=https://example.org/health"
if render collide_platform; then bad "platform= pair fails closed"; else ok "platform= pair fails closed"; fi
has "platform collision names the built-in" "$(cat "$WORK/collide_platform/stderr.log")" "collides with a built-in endpoint"

fixture_env
export GATUS_ENDPOINTS="main=https://example.org/health"
if render collide_main; then bad "main= pair fails closed with a tenant"; else ok "main= pair fails closed with a tenant"; fi
has "main collision names the built-in" "$(cat "$WORK/collide_main/stderr.log")" "collides with a built-in endpoint"

fixture_env
unset TENANT_USER
export GATUS_ENDPOINTS="main=https://example.org/health"
if render main_pair_no_tenant; then ok "main= pair accepted when the built-in did not render"; else bad "main= pair accepted when the built-in did not render"; fi
has "hand-run pair renders as a normal row" "$(block main "$WORK/main_pair_no_tenant/config.yaml")" "url: https://example.org/health"

# ---- (f) bad GATUS_ENDPOINTS pairs still fail closed (regression) ---------
fixture_env
export GATUS_ENDPOINTS="bad.name=https://example.org"
if render bad_pair; then bad "malformed pair fails closed"; else ok "malformed pair fails closed"; fi

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
