# Verification browser (CDP-driven Chrome for Testing)

Operator tooling for the live-verification steps in [docs/verification.md](../../docs/verification.md): a branded Chrome for Testing (CfT) instance with its own persistent profile, driven over the Chrome DevTools Protocol (CDP).

**These tools are operator-run, not CI-called.** CI never launches a browser, never stores a session, and never automates the netcup approval (S1 / C-A in [docs/invariants.md](../../docs/invariants.md)); every approval is a per-run human action in a visible window.

## Why a branded Chrome for Testing

CfT uses its own macOS keychain item (`Chromium Safe Storage`), separate from personal Chrome's (`Chrome Safe Storage`), so this profile is cryptographically separate from your personal browsing — neither browser can read the other's profile. Branding stock Chrome instead would share the personal key domain. `build-app.sh` makes the bundle: clone CfT, rename Info.plist, ad-hoc sign.

## Requirements

- macOS for the branded bundle (`build-app.sh`); Linux/headless uses a documented plain-Chromium equivalent (below).
- `python3` with the `websocket-client` package: `python3 -m pip install --user websocket-client`. On PEP 668 externally-managed Pythons (Homebrew/System) a bare `pip install` fails — use `--user` or a virtualenv; `cdp.py` prints this hint when the import fails.
- `gh` CLI, logged in, for the `approve-device.sh` run/annotation lookups (not needed when passing `--device-url`).
- `curl` (CDP health check + CfT download).

## Environment knobs

| Variable | Default | Used by | Meaning |
|---|---|---|---|
| `BROWSER_HOME` | `$HOME/.piercloud/test-browser` | all | Base directory for the profile and log |
| `CFT_DIR` | `$HOME/.cft` | `build-app.sh` | Shared CfT base — one install for all projects; the app bundle is an APFS COW clone of it |
| `CFT_SKIP_FETCH` | `0` | `build-app.sh` | `1` = rebuild from the existing `CFT_DIR` without downloading (requires the binary there) |
| `APP_DIR` | `$HOME/Applications` | `build-app.sh`, `launch.sh` | Where the branded app bundle lives |
| `APP_NAME` | `CfT PierCloud` | `build-app.sh`, `launch.sh` | Bundle/display name |
| `BUNDLE_ID` | `com.google.chrome.for.testing.piercloud` | `build-app.sh` | Bundle identifier |
| `CDP_PORT` | `9333` | `launch.sh`, `cdp.py`, `approve-device.sh` | CDP endpoint port |
| `PROFILE` | `$BROWSER_HOME/cft-profile` | `launch.sh` (reported by `approve-device.sh`) | Persistent browser profile — the session store |
| `PYTHON` | `python3` | `approve-device.sh` | Interpreter used to run `cdp.py` |

Every script echoes the values it resolved. Moving `PROFILE` (with the browser stopped) preserves the sign-ins.

### Shared base CfT

One base install lives at `~/.cft/` (the default `CFT_DIR`); each project's app bundle is an APFS copy-on-write clone of it (≈0 extra disk) and each project keeps its own profile — only the browser data is independent:

- `build-app.sh` fetches the latest stable CfT into the base when the version changed, then rebuilds this project's branded app from it.
- `CFT_SKIP_FETCH=1 ./build-app.sh` rebuilds from the existing base without downloading (used when another project already updated it).

## One-time setup (macOS)

1. `./build-app.sh` — resolves the latest stable CfT for your architecture, downloads/unzips it into the shared base (`CFT_DIR`, default `~/.cft`) when the version changed, clones it (`cp -Rc`, copy-on-write) to `$APP_DIR/$APP_NAME.app`, brands the Info.plist with `APP_NAME`/`BUNDLE_ID`, and re-signs ad-hoc. Re-run after CfT updates or to refresh the brand; `CFT_SKIP_FETCH=1 ./build-app.sh` rebuilds from the existing base without downloading.
2. `./launch.sh` — starts the browser on CDP `:$CDP_PORT` (idempotent: a no-op when CDP already answers) and activates the window.
3. In that window, sign in to netcup SCP. macOS prompts once for `Chromium Safe Storage` — choose **Always Allow** (login keychain password required). Deny → logins do not persist; re-running `build-app.sh` changes the signature and the prompt returns.

The profile is a **credential store** — treat it like a password vault, never commit or share it. The repo ignores any `*-profile/` directory; by default the profile lives outside the clone.

## Day-to-day

```bash
./launch.sh                  # idempotent: no-op when CDP already answers
python3 ./cdp.py targets     # list page targets (URL only)
python3 ./cdp.py url         # print the active page URL
python3 ./cdp.py nav URL     # navigate the first page target
python3 ./cdp.py eval JS     # evaluate JS, return JSON (truncated)
python3 ./cdp.py shot FILE   # screenshot to FILE
```

The browser is a normal visible window: sign-ins, keychain prompts, and 2FA happen there, not in the script. `cdp.py` never reads profile files — it only speaks CDP.

## Approving a device-flow run

`./approve-device.sh <run-id> [owner/repo]` (repo defaults to the clone's `origin`) encapsulates the proven sequence:

1. resolves the device URL from the first available source — `--device-url <url>` / `DEVICE_URL`, then the ntfy topic (`--ntfy-topic` / `NTFY_TOPIC` **with** `--ntfy-token` / `NTFY_TOKEN`, required — a public topic is spoofable and would phish the warm session; the token needs read access; bounded JSON-API polling), then the **live run-page log read through this same verification browser** (the CfT window is navigated to the run's device-flow job page and the streaming log is scraped for the approval link; bounded), then the check-run notice annotation titled `PierCloud device approval` (bounded — it only becomes readable after the step ends, so it is a last resort), else it stops with instructions;
2. pre-flights the automation profile's netcup SCP session on `/scp-ui/` (URL-only detection);
3. navigates to the device URL and confirms the Keycloak Grant Access page;
4. clicks Grant Access once with a bare `.click()`, allows one retry, then polls for `/realms/scp/device/status` + `Device Login Successful` within the ~570 s approval window;
5. prints `DEVICE_LOGIN_SUCCESSFUL`, or fails closed with `NOT_CONFIRMED` and recovery steps.

The `provision.yml` device flow is one long step: its log is not readable through the REST API until the job completes (i.e. after approval). The live channels are the run page's streaming log — which this script reads through the verification browser when ntfy is not configured — and the ntfy push; the check-run notice annotation only appears after the step ends. With `--device-url` the run id is optional — copy the URL from the live run page and pass it directly. Run `./approve-device.sh --preflight` any time (no run id) to check the profile's SCP session before dispatching.

**Redaction rule:** the device `user_code` is never printed or pasted — every URL `approve-device.sh` prints passes through a `user_code=<redacted>` filter, and job logs are never dumped. The `device_code` itself never leaves the single runner step (masked at birth), so it cannot appear in a log; the `user_code` is public by design (it is the approval surface) but short-lived (~10 min) and useless without the profile's own netcup session — still keep it out of logs and chats.

### Session loss and NOT_CONFIRMED

`NOT_CONFIRMED` means the automation profile was not signed in at netcup SCP (or the click did not land). A login in your personal browser does not help — the approval happens as the account signed in **inside this browser**.

1. Open the verification browser window and sign in to netcup SCP there.
2. Re-run `./approve-device.sh <run-id>`.
3. If the run already failed its poll, re-dispatch `provision.yml` and approve the new code the same way.

A warm SCP UI session does **not** guarantee the Grant Access page: the device-flow client runs a separate SSO, and every device grant may ask for a fresh sign-in — complete it in that window when prompted. If the device grant itself is disabled, STOP and escalate: there is no fallback (C-A).

## Linux / headless

No branded bundle is needed; launch plain Chromium with the same flag shape:

```bash
chromium \
  --user-data-dir="$BROWSER_HOME/chromium-profile" \
  --remote-debugging-port="$CDP_PORT" --remote-allow-origins='*' \
  --no-first-run --about:blank
```

The profile gets its own keyring item; keep it under the same `BROWSER_HOME` outside the clone. `cdp.py` and `approve-device.sh` work unchanged once CDP answers; `build-app.sh` and `launch.sh` are macOS-specific (app bundle + window activation).
