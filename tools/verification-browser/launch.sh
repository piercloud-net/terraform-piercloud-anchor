#!/usr/bin/env bash
# Launch the branded test browser, idempotent (no-op when CDP already answers).
# Companion: build-app.sh (downloads/updates CfT + rebuilds the branded app).
#
# Env knobs: BROWSER_HOME, APP_DIR, APP_NAME, CDP_PORT, PROFILE. See
# tools/verification-browser/README.md for the full table.
#
# On Linux/headless, launch your own Chromium with the same flags — see the
# README's 'Linux / headless' section; cdp.py and approve-device.sh work the
# same once CDP answers.
set -euo pipefail

BROWSER_HOME="${BROWSER_HOME:-$HOME/.piercloud/test-browser}"
APP_DIR="${APP_DIR:-$HOME/Applications}"
APP_NAME="${APP_NAME:-CfT PierCloud}"
CDP_PORT="${CDP_PORT:-9333}"
PROFILE="${PROFILE:-$BROWSER_HOME/cft-profile}"
LOG="$BROWSER_HOME/chrome.log"
APP="$APP_DIR/$APP_NAME.app"
BIN="$APP/Contents/MacOS/Google Chrome for Testing"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "BROWSER_HOME=$BROWSER_HOME"
echo "APP_DIR=$APP_DIR"
echo "APP_NAME=$APP_NAME"
echo "CDP_PORT=$CDP_PORT"
echo "PROFILE=$PROFILE"
echo "LOG=$LOG"

[ -x "$BIN" ] || { echo "test browser app missing at $APP — run $SCRIPT_DIR/build-app.sh" >&2; exit 1; }

if curl -fsS --max-time 2 "http://127.0.0.1:$CDP_PORT/json/version" >/dev/null 2>&1; then
  echo "test browser already running (CDP :$CDP_PORT)"
  if command -v osascript >/dev/null 2>&1; then
    osascript -e "tell application \"$APP_NAME\" to activate" 2>/dev/null || true
  fi
  exit 0
fi

mkdir -p "$PROFILE"
nohup "$BIN" \
  --user-data-dir="$PROFILE" \
  --remote-debugging-port="$CDP_PORT" --remote-allow-origins='*' \
  --no-first-run --about:blank > "$LOG" 2>&1 &
echo "launched $APP_NAME (CDP :$CDP_PORT, profile $PROFILE)"
echo "driver: python3 $SCRIPT_DIR/cdp.py {targets|url|nav URL|eval JS|shot FILE}"
