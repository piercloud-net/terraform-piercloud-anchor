#!/usr/bin/env bash
# scripts/lib/naming.sh — canonical tenant naming (issue #105, D8).
#
# ONE source for the derived names: the workflow resolve step sources this
# file, .github/scripts/030-anchor-dns.sh sources it, and scripts/010-provision.sh
# carries a byte-identical embedded copy of the block below (console-hand-run
# fallback; nested `# --- BEGIN NAMING ---` / `# --- END NAMING ---` markers
# INSIDE its CADDY RENDER span). tests/naming-scheme/run-test.sh diffs the
# embedded block against this file. Edit HERE and copy the block; never fork it.
#
# Scheme (2026-09-11 naming ADR): every platform name is `<site>-<tenant>`,
# one label deep — anchor: anchor-01-<tenant>.piercloud.net (NN=01; -02+ is a
# future multi-anchor case), dashboard: status-<tenant>.piercloud.net.
#
# validate_tenant_username is deliberately strict and fails closed on the
# LOWERCASED RAW value: the sanitizer maps `.pier`, `pier-`, `pier--carlo`
# all to `pier`, so validating the sanitized value would be fail-open.
# The reserved prefixes keep tenant names from masquerading as platform
# labels and from colliding with the `pcu<random>` alias scheme.

# --- BEGIN NAMING ---
validate_tenant_username() { # $1 = lowercased RAW tenant username; 0 ok, 1 fail (message names the value)
  case "$1" in
    *[!a-z0-9]* | '')
      printf 'invalid TENANT_USER "%s": must match ^[a-z0-9]{1,20}$ before normalization (letters/digits only, 1-20 chars).\n' "$1" >&2
      return 1 ;;
  esac
  if [ "${#1}" -gt 20 ]; then
    printf 'invalid TENANT_USER "%s": must match ^[a-z0-9]{1,20}$ before normalization (letters/digits only, 1-20 chars).\n' "$1" >&2
    return 1
  fi
  case "$1" in
    anchor* | status* | pcu*)
      printf 'invalid TENANT_USER "%s": reserved prefix — names starting with anchor/status/pcu are platform labels, not tenants.\n' "$1" >&2
      return 1 ;;
  esac
  return 0
}

sanitize_tenant() { # $1 = raw tenant username -> lowercase [a-z0-9-], hyphen runs collapsed, edges trimmed
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | sed -e 's/[^a-z0-9-]/-/g' -e 's/-\{2,\}/-/g' -e 's/^-//' -e 's/-$//'
}

derive_anchor_hostname() { # $1 = sanitized tenant -> anchor-<NN>-<tenant> (NN=01; -02+ is future)
  printf 'anchor-01-%s\n' "$1"
}

derive_status_host() { # $1 = sanitized tenant -> status-<tenant> (dashboard singleton, one label)
  printf 'status-%s\n' "$1"
}
# --- END NAMING ---
