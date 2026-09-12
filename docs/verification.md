# Verification — CI gates, review, live proof

This is the verification checklist `/impl` looks for: what CI proves on every PR, how independent review works in this repo, and what must be proven live (with which authoritative signal) before a change counts as done.

Read it together with [conventions.md](conventions.md) (review + public-safety rules) and [invariants.md](invariants.md) (S1 / C-A review blockers). The device-flow approval mechanics live in [tools/verification-browser/README.md](../tools/verification-browser/README.md).

## 1. How to use this file

1. Identify your change type in §4 and note its live-proof checklist.
2. Run the CI gates (§2): `gh pr checks <pr>` must be green (pass, or a legitimate path-gated skip) on the exact PR head SHA.
3. Get an independent review (§3): security first, verdict recorded on that SHA.
4. Prove live (§4) against a real anchor on the reviewed SHA; record the run URL and the observed signals in the PR.
5. Close out (§6): merge, PR note, vault note, kanban.

If a needed signal is missing from this file, that is a docs gap — add it in the same PR that needed it.

## 2. CI gates

Eleven checks run per PR: nine in [`ci.yml`](../.github/workflows/ci.yml) plus `validate-package-version` and `validate-release-pr` in their own workflows. Most run on every PR; two are path-gated — when their trigger paths are untouched they still report `pass`, with the payload steps skipped.

| Check (job name) | Trigger | What it proves |
|---|---|---|
| `tofu fmt` | always | HCL is canonically formatted (`tofu fmt -check -recursive`). |
| `tofu validate (cred-free)` | always | `tofu init -backend=false` + `validate` pass for the root module AND `examples/quickstart`, with no provider credentials. |
| `key-material grep (from main)` | always | No JWK private `d` scalar and no PEM private-key block in tracked code; the patterns are enforced from `main`, so a PR cannot weaken its own check. |
| `SCP endpoint allowlist grep (from main)` | always | No forbidden provisioning-adjacent surfaces (the `rescue`/… stem list) in tracked `.tf`/`.sh`/`.yml`, and no netcup/API endpoint outside the allowlist; also enforced from `main`. |
| `secret-print grep (C-A, from main)` | always | No bounded acronym-print, personal-token phrase, CLI auth-subcommand, or bearer-print shapes in `.yml`/`.sh`; from `main`. |
| `unit-tests (scripts)` | path-gated | The committed script harnesses (token refresh, sweep pre/post, naming scheme) pass, and `bash -n` + `shellcheck -S warning` pass over `.github/scripts/**`. |
| `bind-proof e2e (Caddy fronting mock tang)` | path-gated | A real `clevis luks bind` + unlock runs through the repo's rendered Caddyfile against a mock tang — the Caddy-in-front path stays bind-proven. |
| `jq boolean-read guard (false != empty)` | always | No boolean field is read with jq's `// empty` (jq treats `false` as empty; live-found 2026-09-10). |
| `scrub-canary (redactor proof)` | always | The poll-failure redactor still strips passwords, JWK `d`, and PEM bodies from log dumps and respects its byte bound. |
| `validate-package-version` | always (PRs to `main`) | `package.json` version discipline holds (release pipeline `cad0p/semver-calver-release`). |
| `validate-release-pr` | always (PRs to `main`) | Release-PR rules hold (e.g. `CHANGELOG.md` edits only on release branches). |

Path-gated triggers (from the gates in `ci.yml`):

- `unit-tests (scripts)` runs when a changed path matches `^(\.github/scripts/|\.github/workflows/|scripts/(lib/|010-provision\.sh)|tests/(scp-token-refresh|sweep-pre-classify|sweep-post-shapes|naming-scheme)/)`.
- `bind-proof e2e` runs when a changed path matches `^(scripts/|\.github/workflows/|tests/bind-e2e/)|\.tf$`.

On push to `main` both path-gated jobs run unconditionally. If the changed-file list cannot be determined, both run (fail-open to extra proof).

How to read checks:

```bash
gh pr checks <pr>            # one line per check: pass / fail / pending / skipping
gh pr checks <pr> --watch    # wait until all checks settle
gh run view <run-id> --log   # full log when something is red
```

A path-gated job that reports `pass` with its payload steps skipped is green for merge purposes: it means the changed paths cannot affect what that job proves. Anything else red is a blocker — fix on the branch and re-verify, because a verdict applies to the commit it reviewed (§3).

## 3. Independent review + verify

Condensed from [conventions.md](conventions.md#review-protocol-independent-review-security-first):

- An independent reviewer is a separate instance (human or agent) that did not author the change and reviews the artifact, not the author's account of it.
- Security is the first lens: S1 / C-A credential custody, exposure windows, injection into shell / HCL / `$GITHUB_ENV` / `$GITHUB_OUTPUT`, and fail-open behaviour.
- Findings must be reproduced before reporting: a failing command, a payload, or a reverted-fix test.
- The verdict is recorded in the PR and names the exact commit SHA it reviewed.
- Any commit pushed after a verdict needs a verify pass by a reviewer seeded with the finding (a fresh instance for agent reviewers); a verdict applies only to the commit it reviewed.

## 4. Live proof per change type

Live proof means running the real flow against a real anchor and capturing the authoritative signal — not re-reading a green CI check. Record the run URL, the commit SHA, and the observed values in the PR.

### Provisioning run (`scripts/`, `.tf`, workflows)

- [ ] Dispatch `provision.yml` `mode=apply` from the reviewed branch and approve the device flow (§5).
- [ ] Run log assertions all pass: firewall policy created/attached; A1 window opened then closed (swept pre + post); tang thumbprint printed; Caddy + Gatus deployed; DNS upsert + verify-after-write; device-grant teardown revoked.
- [ ] `dig +short anchor-01-<tenant>.piercloud.net` returns the anchor IPv4 (DNS-only record — clevis must reach tang directly, no edge in front).
- [ ] `curl -s -o /dev/null -w '%{http_code}' http://anchor-01-<tenant>.piercloud.net/adv` prints `200` from the main box, and times out from an unlisted address (the firewall actually gates tang).
- [ ] `curl -s -o /dev/null -w '%{http_code}' https://status-<tenant>.piercloud.net/` prints `200`, and the statuses API returns data.
- [ ] No key material in state/plan (CI key-material grep + the provisioning script's own assertion); the thumbprint is saved in the password manager.
- [ ] Firewall shape: main box + Cloudflare edge only, `:80` tang + ACME, `:443` edge only, egress ACCEPT-all, no SSH left open.

### Retention cap / `mode=check` assert (workflow + docs)

- [ ] CI green; a `mode=check` dispatch from the reviewed SHA exits 0 and the run log shows the assert output (`retention-days literals checked: N`, N ≥ 1).
- [ ] The head-sha artifact upload log shows **no** `Retention days cannot be greater than the maximum allowed retention set` clamp warning (presence of that warning on an older run is the defect, not a pass).
- [ ] `gh api repos/<owner>/<repo>/actions/artifacts` shows the fresh artifact's `expires_at` ≈ `created_at` + 90d — corroboration only (the platform clamps silently, so this alone proves nothing).
- [ ] The fail path is reproduced locally against fixtures (`tests/retention-cap/run-test.sh`) — red with `file:line` on a >90 fixture.
- [ ] No live `mode=apply` unless provisioning behaviour changed; say that explicitly in the PR (the thumbprint upload is apply-gated and shares the same action + value).

### Dashboard / edge

- [ ] `https://status-<tenant>.piercloud.net/` is `200` over TLS; the certificate chain is valid well beyond the window (`external-watch.yml` asserts HTTP 200, live statuses data, and ≥14 days of cert validity).
- [ ] Visitor→edge leg: Cloudflare Universal SSL covers the ONE flat label — no Advanced Certificate Manager / Total TLS needed (if a two-label hostname is ever needed, ACM returns; issue #107).
- [ ] Edge→origin leg: Full (Strict) holds and the origin cert (`CF_ORIGIN_CERT_PEM`/`CF_ORIGIN_KEY_PEM`) verifies; Caddy auto-TLS is never relied on for proxied hosts (HTTP-01 catch-22, issue #88).
- [ ] Edge ceremony: Cache Rule bypass on `/.well-known/acme-challenge/*`; no WAF / Bot-Fight block on it.
- [ ] AOP, when `CF_AOP_CA_PEM` is set: cert-less origin pull is rejected at the handshake and the edge pull serves `200` — the run asserts both halves.
- [ ] Tang unaffected throughout: `http://anchor-01-<tenant>.piercloud.net/adv` still answers `200`.

### DNS / migration

- [ ] Anchor record: `dig +short anchor-01-<tenant>.piercloud.net` returns the anchor IPv4 (proxied `false`, TTL 300).
- [ ] Dashboard record: `dig +short status-<tenant>.piercloud.net` returns Cloudflare anycast addresses (more than one A record) — the origin IP must not leak.
- [ ] The run log's verify-after-write step matches name + address + proxied flag; a verify miss fails the run fail-closed.
- [ ] Main-box move: `mode=update-ip` ADD-before-move — the new IP is added and the old kept until the main box boots through the new one, then removed; re-check with `dig` and a clevis boot.
- [ ] Record cutover: after the flip, the DNS-name-based Gatus monitors keep their history and the dashboard still resolves through the edge.

### Authenticated Origin Pulls (AOP)

- [ ] CF side first: zone-level AOP enabled with our own leaf cert uploaded; THEN `CF_AOP_CA_PEM` set and the anchor re-dispatched.
- [ ] Run assertions: cert-less origin pull rejected; edge pull serves `200`.
- [ ] Rollback order (only when rolling back): unset `CF_AOP_CA_PEM` + re-dispatch FIRST, disable the CF setting second (the reverse order black-holes every edge pull).
- [ ] Rebuild caveat: a rebuild dispatched while `CF_AOP_CA_PEM` is still planted fails before DNS converges — recover by deleting the secret, converging DNS, then re-enabling AOP.

### Naming (`anchor-01-<tenant>`, `status-<tenant>`)

- [ ] `tofu plan`/outputs show `anchor_hostname = anchor-01-<tenant>.piercloud.net`; `tests/naming-scheme/` is green.
- [ ] Live: SCP server name, firewall policy name, and the DNS record all carry the canonical `anchor-01-<tenant>` form.
- [ ] Dashboard host is the ONE flat label `status-<tenant>.piercloud.net` (Universal SSL coverage; two labels would require ACM — issue #107).

### Docs-only

- [ ] CI green (the greps and release validators still run on every PR).
- [ ] Independent review of the rendered docs: links resolve, commands are copy-pasteable, no real hostnames/IPs/credentials.
- [ ] No live run needed — say so explicitly in the PR's verification section instead of leaving it blank. Operator tooling under `tools/` additionally gets a local smoke test of the changed scripts (the tools are not CI-called).

## 5. Device-flow approval (CfT PierCloud)

Every netcup use is human-approved per run (S1) through Keycloak's device grant. Approval happens in the branded **CfT PierCloud** browser — a Chrome for Testing instance with its own keychain item, cryptographically separate from personal Chrome — never in the personal browser (wrong profile = wrong session) and never in CI (a stored session would be a standing credential).

**Setup when absent (macOS):** `tools/verification-browser/build-app.sh` (fetch CfT, brand, ad-hoc sign) → `launch.sh` (idempotent, CDP `:$CDP_PORT`) → sign in to netcup SCP **in that window** (one-time `Chromium Safe Storage` keychain prompt → Always Allow). Mechanics and env knobs: [tools/verification-browser/README.md](../tools/verification-browser/README.md).

**Pre-flight:** `tools/verification-browser/approve-device.sh --preflight` (or open `https://www.servercontrolpanel.de/scp-ui/` in the automation profile). Authenticated shows the SCP UI; unauthenticated redirects to the Keycloak sign-in form. If the form appears, the session is gone — sign in inside the CfT window; a login in the personal browser does not help. This is the `NOT_CONFIRMED` failure mode.

**Approval sequence:**

1. Dispatch `provision.yml` `mode=apply`; the run mints a device code and its `Device code request` job renders the card (code lifetime ~10 min, poll window ~570 s).
2. Run `tools/verification-browser/approve-device.sh <run-id>`: it reads the device URL from the job log, pre-flights the profile, navigates, confirms the Keycloak Grant Access page, clicks `#kc-login`, and polls for `/realms/scp/device/status` + `Device Login Successful` → prints `DEVICE_LOGIN_SUCCESSFUL`.
3. Manual fallback: read the device URL from the `Device code request` job log, navigate the CfT window there, click Grant Access, confirm the success page.

**Redaction:** never print or paste the `user_code`; `approve-device.sh` redacts `user_code=…` in every URL it prints. The code is not masked in the run card by design (masking breaks the job handoff) — it lives ~600 s and is useless without the profile's own session.

**Failure modes:**

- `NOT_CONFIRMED` — the profile lost its SCP session or the click did not land. Sign in inside the CfT window, re-run the approval script; if the run already failed its poll, re-dispatch.
- Fresh sign-in on the grant page — expected intermittently: the device-flow client runs its own SSO and does not inherit a warm `scp-ui` session; complete the sign-in in that window when asked.
- Device grant disabled — STOP + escalate; no fallback exists (C-A), see [dr.md](dr.md).
- Runner killed before teardown — the refresh token can stay live up to ~30 days; revoke the offline session in netcup's Keycloak, then re-dispatch (see [dr.md](dr.md)).

## 6. Definition of done

- [ ] CI green on the PR head SHA (pass, or legitimate path-gated skip).
- [ ] Independent review verdict recorded in the PR on the exact SHA; post-verdict commits have a verify pass.
- [ ] Live proof recorded in the PR: run URL for the reviewed SHA + the §4 signals (or an explicit "docs-only, no live run").
- [ ] Vault note updated (changelog / feature / debugging, as appropriate).
- [ ] Kanban card updated.
- [ ] Merged via squash (the only allowed merge method; `main` stays linear), with a `## Release notes` section in the PR body.
