#!/usr/bin/env python3
"""Minimal CDP driver for the verification browser (targets / url / nav / eval / shot).

Reads CDP_PORT (default 9333) so several browsers can run side by side.
Requires the `websocket-client` package:
    python3 -m pip install --user websocket-client
(PEP 668 externally-managed Python: use --user or a virtualenv — see
tools/verification-browser/README.md.)

Never prints profile data: commands return page URLs / evaluated values only.
"""
import json
import os
import sys
import urllib.error
import urllib.request

try:
    import websocket
except ImportError:
    print(
        "cdp.py needs the 'websocket-client' package: "
        "python3 -m pip install --user websocket-client "
        "(externally-managed Python: use --user or a venv — see "
        "tools/verification-browser/README.md)",
        file=sys.stderr,
    )
    sys.exit(2)

PORT = os.environ.get("CDP_PORT", "9333")


def targets():
    with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/json/list") as r:
        return json.load(r)


def page_targets():
    pages = [t for t in targets() if t.get("type") == "page"]
    if not pages:
        print("no page targets — open a tab in the verification browser", file=sys.stderr)
        sys.exit(1)
    return pages


def send(ws_url, method, params=None, mid=1):
    ws = websocket.create_connection(ws_url)
    try:
        ws.send(json.dumps({"id": mid, "method": method, "params": params or {}}))
        while True:
            msg = json.loads(ws.recv())
            if msg.get("id") == mid:
                if "error" in msg:
                    raise RuntimeError(msg["error"])
                return msg.get("result", {})
    finally:
        ws.close()


def evaluate(ws_url, expression):
    result = send(ws_url, "Runtime.evaluate", {"expression": expression, "returnByValue": True})
    return result.get("result", {})


def shot(ws_url, path):
    import base64
    result = send(ws_url, "Page.captureScreenshot", {"format": "png"})
    with open(path, "wb") as fh:
        fh.write(base64.b64decode(result["data"]))
    return path


def usage():
    print("usage: cdp.py {targets|url|nav URL|eval JS|shot FILE}", file=sys.stderr)
    sys.exit(2)


def main():
    if len(sys.argv) < 2:
        usage()
    cmd = sys.argv[1]
    if cmd == "targets":
        print(json.dumps([{"url": t["url"][:80]} for t in targets() if t.get("type") == "page"], indent=1))
        return
    if cmd == "nav" and len(sys.argv) < 3:
        usage()
    if cmd == "eval" and len(sys.argv) < 3:
        usage()
    if cmd == "shot" and len(sys.argv) < 3:
        usage()
    if cmd not in ("url", "nav", "eval", "shot"):
        usage()
    ws = page_targets()[0]["webSocketDebuggerUrl"]
    if cmd == "url":
        print(evaluate(ws, "location.href").get("value", ""))
    elif cmd == "nav":
        send(ws, "Page.navigate", {"url": sys.argv[2]})
        print("navigated")
    elif cmd == "shot":
        import time
        time.sleep(2)
        print(shot(ws, sys.argv[2]))
    elif cmd == "eval":
        print(json.dumps(evaluate(ws, sys.argv[2]))[:2000])


if __name__ == "__main__":
    try:
        main()
    except urllib.error.URLError as exc:
        print(f"cannot reach the verification browser on CDP :{PORT} ({exc}) — start it with launch.sh", file=sys.stderr)
        sys.exit(1)
