#!/usr/bin/env bash
# (Re)build the branded test-browser app bundle: "$APP_NAME" (default: CfT PierCloud).
#
# Source: Chrome for Testing (Google's automation build) — NOT stock Chrome.
# Why: CfT uses its own keychain item ("Chromium Safe Storage"), so this app is
# cryptographically separate from the personal Chrome profiles ("Chrome Safe
# Storage"). Branding stock Chrome instead would need the Chrome key (prompt)
# and share a key domain with personal browsing.
#
# CfT ships ad-hoc/linker-signed (no team, no entitlements), so branding is
# simple: clone, rename Info.plist, re-sign ad-hoc.
#
# Storage: `cp -Rc` is an APFS copy-on-write clone — blocks are shared with the
# source, so the clone costs almost no space. Re-run after CfT updates (or to
# refresh the brand).
#
# macOS only. On Linux/headless, use the plain-Chromium equivalent documented
# in tools/verification-browser/README.md.
#
# Env knobs: BROWSER_HOME, CFT_DIR, APP_DIR, APP_NAME, BUNDLE_ID. See
# tools/verification-browser/README.md for the full table.
set -euo pipefail

if [ "$(uname -s)" != "Darwin" ]; then
  echo "build-app.sh is macOS-only (app bundle + codesign)." >&2
  echo "On Linux/headless, launch plain Chromium with the equivalent flags — see the 'Linux / headless' section of tools/verification-browser/README.md." >&2
  exit 1
fi

BROWSER_HOME="${BROWSER_HOME:-$HOME/.piercloud/test-browser}"
CFT_DIR="${CFT_DIR:-$BROWSER_HOME/cft}"
APP_DIR="${APP_DIR:-$HOME/Applications}"
APP_NAME="${APP_NAME:-CfT PierCloud}"
BUNDLE_ID="${BUNDLE_ID:-com.google.chrome.for.testing.piercloud}"
DEST="$APP_DIR/$APP_NAME.app"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

case "$(uname -m)" in
  arm64) CFT_PLATFORM="mac-arm64" ;;
  x86_64) CFT_PLATFORM="mac-x64" ;;
  *) echo "unsupported architecture: $(uname -m) — macOS arm64/x86_64 only" >&2; exit 1 ;;
esac
CFT_APP="$CFT_DIR/chrome-$CFT_PLATFORM/Google Chrome for Testing.app"
CFT_BIN="$CFT_APP/Contents/MacOS/Google Chrome for Testing"
API="https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json"

echo "BROWSER_HOME=$BROWSER_HOME"
echo "CFT_DIR=$CFT_DIR"
echo "APP_DIR=$APP_DIR"
echo "APP_NAME=$APP_NAME"
echo "BUNDLE_ID=$BUNDLE_ID"
echo "CFT_PLATFORM=$CFT_PLATFORM"

latest="$(curl -fsSL --max-time 30 "$API" | python3 -c "import json,sys; d=json.load(sys.stdin)['channels']['Stable']; print(d['version'])")"
url="$(curl -fsSL --max-time 30 "$API" | python3 -c "
import json,sys
d=json.load(sys.stdin)['channels']['Stable']
print([x['url'] for x in d['downloads']['chrome'] if x['platform']=='$CFT_PLATFORM'][0])")"

have=""
[ -x "$CFT_BIN" ] && have="$("$CFT_BIN" --version 2>/dev/null | awk '{print $NF}')"

if [ "$have" != "$latest" ]; then
  echo "fetching CfT $latest (have: ${have:-none})"
  mkdir -p "$CFT_DIR"; cd "$CFT_DIR"
  curl -fsSL --max-time 900 -o cft.zip "$url"
  unzip -q -o cft.zip
  rm -f cft.zip
fi

[ -x "$CFT_BIN" ] || { echo "CfT binary missing after fetch: $CFT_BIN" >&2; exit 1; }

rm -rf "$DEST"; mkdir -p "$(dirname "$DEST")"
cp -Rc "$CFT_APP" "$DEST"
plutil -replace CFBundleDisplayName -string "$APP_NAME" "$DEST/Contents/Info.plist"
plutil -replace CFBundleName        -string "$APP_NAME" "$DEST/Contents/Info.plist"
plutil -replace CFBundleIdentifier  -string "$BUNDLE_ID" "$DEST/Contents/Info.plist"
xattr -cr "$DEST"
codesign --force --sign - "$DEST"

echo "built: $DEST  (CfT $latest)"
echo "launch with: $SCRIPT_DIR/launch.sh"
