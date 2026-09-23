# DR runbook + boot-failure decision tree

Steady-state operations for your tang anchor: what breaks, how you notice, and what to do — all runnable from any browser, phone included. No plans or roadmaps here; this page covers the anchor you already run.

Related: [usage.md](usage.md) (end-to-end flow) · [invariants.md](invariants.md) (S1 / C-A review blockers).

## T0 / T1 / T2 — emergency-unlock ladder (advise, never mandate)

- **T0 baseline (shipped with this template):** LUKS passphrase keyslot in your password manager (PM) + dropbear-initramfs paste on the main box + public-repo break-glass card (provider → console-URL map). The passphrase stays in the PM — never on any service. The runbook "website" stores NOTHING.
- **T1 advised:** WireGuard peer in the main box initramfs (dropbear behind WG, no public initramfs port); Gatus must ALERT, not just monitor; PM emergency kit + recovery codes completed day-1, printed off-device (see the day-1 checklist below).
- **T2 opt-in:** BYO twin anchor — a second small box at a DIFFERENT provider, both user-owned, SSS t-of-2 via `extra_tang_urls`. The only availability upgrade that adds zero trust parties. Product default stays single anchor t:1 (see [usage.md](usage.md)).

## DR table

| Situation | Detection | Do | Do NOT |
|---|---|---|---|
| Anchor death (box down, tangd wedged) | Gatus ALERTs (T1); main box falls back to passphrase prompt at boot | Unlock with the passphrase keyslot; rebuild the anchor, re-bind or `regen` (same-URL fast path below) at your desk | Panic-migrate the main box anywhere |
| Shared platform unhealthy (`platform` row red) | Gatus `platform` row — monitor-only on tenant pages (no push; the operator anchor alerts on the same row) | Nothing on your side: the operator is already alerted. Red `main` + red `platform` = a platform problem; green `main` = your slice is fine | Rebuild or rebind your main box for a platform-side failure |
| Firewall policy deleted | Main-box canary (drift report planned — compare policies in the SCP until then) | Re-run [`provision.yml`](../.github/workflows/provision.yml) `mode=apply`; it re-converges the policy | Hand-edit policies in the SCP and forget them (drift returns) |
| Firewall drift (rule changed out-of-band) | Canary failure (+ `mode=check` drift report when live) | Same as above: dispatched re-apply | Assume the anchor is "just slow" — check the drift report first |
| Stale binding (main box moved, source IP changed) | Clevis fails after a move; canary carries the new IP | `mode=update-ip`: ADD the new IP first, confirm boot, then remove the old (ADD-before-move; operator requests, OWNER executes) | Remove the old IP before the new one boots (cutover lockout) |
| SCP outage (netcup control plane down) | SCP/API unreachable; anchor itself still answers clevis | **SCP outage: do NOT migrate hosts.** Wait it out — running anchors keep unlocking; nothing needs the API until you change something | Migrate hosts mid-outage (strands the moved box behind a stale rule with zero remediation) |
| Lost phone | You, noticing | Day-1 kit: recovery codes + root password in the PM emergency kit, printed off-device — recover GitHub/netcup access from any browser, then re-enroll | Keep all second factors on the one device (month-6 lesson — see checklist) |
| Device grant disabled (netcup turns off the OAuth device flow) | `mode=apply` fails at the approval step | STOP + open an issue in your tenant repo. Do not proceed. (C-A — no fallback of any kind is designed or permitted) | Invent a fallback: no one-run tokens, no pasted long-lived secrets, no "temporary" standing credential |
| Runner killed or run cancelled before teardown | The run stops mid-flight, so the `always()` teardown never runs — the device-grant refresh token can stay live up to ~30 days | Revoke your offline session for the tenant in netcup's Keycloak (SCP) admin/account UI, then re-dispatch `mode=apply` | Assume the token died with the runner — only a teardown that actually ran revokes it |
| Dashboard cert stale (per-anchor cert nearing expiry, or an install that never served) | Gatus `dashboard TLS` endpoint fails its `[CERTIFICATE_EXPIRATION]` condition → ntfy ALERT when a push topic is set; ~30d warning window | Re-run the signing flow: fetch the on-box CSR, sign it in the Cloudflare dashboard, set the cert-only `ORIGIN_CA_CERT_PEM` variable, re-dispatch `mode=apply` (the run validates + installs in place + reloads Caddy). Rotation drill below. Tang is unaffected throughout (plain HTTP, separate port, zero TLS dependency) | Touch tang or the firewall to "fix" the dashboard; bind anything new while the dashboard is red |

`platform` is the shared infrastructure your server runs on — monitor-only on tenant pages (diagnosis, not a page). The operator's first check when it is red is the host watchdog state behind the endpoint (`/healthz` 503 = stale checks). While the fleet has one host, the row is that host; the aggregate meaning widens as hosts are added.

**Operator anchors:** the `platform` row alerts (tenant pages stay monitor-only). The role is the `ANCHOR_ROLE` repo variable — `operator` alerts, unset/`tenant` is monitor-only, anything else fails the run closed. After setting it (with a real `NTFY_TOPIC`), re-dispatch `mode=apply` and check the run log's `Gatus alert stanzas:` line names `platform`: an unset role silently downgrades the row to monitor-only. A run that clears the variable for a tenant-shape proof must restore it and re-dispatch to confirm the operator shape.

## Boot-failure decision tree (main box asks for a passphrase)

Your main box dropped to a passphrase prompt instead of unlocking via the anchor. Four causes, in order:

1. **Is the anchor up?** Check Gatus from the anchor's SCP console (`curl -s localhost:8080 | head -5` — HTTP 200 = alive). No → anchor death: type the passphrase (T0), then rebuild at your desk (same-URL `regen` below). Yes → step 2.
2. **Did anything firewall-shaped change?** Diff the firewall policies in the SCP (`mode=check` drift report planned). Drift or a deleted policy → `mode=apply` re-converges it, reboot, done. Clean → step 3.
3. **Did the main box move (new IP)?** Stale binding: the anchor only answers the IPs in the policy. `mode=update-ip` with ADD-before-move, confirm boot, then remove the old IP. No move → step 4.
4. **Was the anchor rebuilt or its tang keys rotated?** The binding points at keys that no longer exist: unlock with the passphrase, then unbind + re-bind (or `regen` on the same URL), verifying the new thumbprint out-of-band — never `-y` blind.

## Discovery fallback (multi-server accounts only)

Single-server accounts never need this. If a run aborts with `expected 1 server, found N`, set `ANCHOR_IPV4` (repo secret) to the server-ready email's "IP address" verbatim (`203.0.113.10/22`-style suffix included; the run strips it) and re-dispatch. The value only selects among the addresses the resolved server itself reports (`GET /servers/{id}`): a value that matches none of them fails the run closed at the resolve step — SSH and the A record always carry an address the resolved server itself reports. (A value that selects *another* server in the same netcup account is closed only by the platform-side registry-IP cross-check, #132.) When the resolved server reports several IPv4s, a run with no explicit value fails loud with the address count — the addresses themselves are never printed to the public run log; read them in the netcup SCP and re-dispatch with one as `ANCHOR_IPV4`. Prefer renaming one box to `anchor-01-<you>` so discovery stays automatic.

## Same-URL rebuild = `regen` (2-minute DR)

Bind clevis to a DNS name (`anchor-01-<alias>.piercloud.net`, see `anchor_hostname`), never the raw IP. A rebuilt anchor at the same URL needs only `clevis luks regen -d <device> tang` — same URL, fresh keys, no unbind+bind ceremony.

## Caddy dashboard: edge checklist + cutover reversibility

Caddy (`caddy:2.11.4-alpine`, pinned + Renovate-watched) owns `:80`; `tangd.socket` listens on `127.0.0.1:8081`; Gatus stays loopback-only (`127.0.0.1:8080`, Caddy proxies the status host to it). The Caddyfile is dispatch-managed (same render pattern as the Gatus config): `handle /adv* + /rec*` → `127.0.0.1:8081` plain, NO redirect; `/.well-known/acme-challenge/*` → HTTP-01; the exact status hostname (`host status-<tenant>.piercloud.net`, rendered from TENANT_USER — `status-invalid.invalid` sentinel on hand runs) → `127.0.0.1:8080`; explicit per-tenant site blocks, NEVER `on_demand` TLS; catch-all aborts. Tang paths are never served on the `:443` dashboard vhost (they abort there). Caddy runs with host networking (its `127.0.0.1` dials reach tangd/Gatus on the host loopback; the netcup firewall stays the ingress gate). Monitoring note: Gatus probes tang only through Caddy's `:80` (a bridge-network container cannot dial tangd's `127.0.0.1`); tang-direct is proven every run by a host-level curl to `:8081/adv` before any proxy proof runs.

Operator edge ceremony (operator-plane, verified by eye after each change; the DNS-edit token the anchor run holds cannot set these, so it stays outside the public repo — codification target: the private operator control plane). **Two TLS legs must both be up — they fail independently:**

- **Leg 1 — visitor → edge.** The dashboard host `status-<tenant>.piercloud.net` is ONE flat label, so Cloudflare's free Universal SSL (apex + one label) covers it — the dashboard needs no **Advanced Certificate Manager** / **Total TLS**. If a two-label hostname is ever needed on this zone, ACM returns; gate/timing is tracked in issue #107.
- **Leg 2 — edge → origin.** Full (Strict) needs a valid origin cert on the box. Do NOT rely on Caddy auto-TLS (HTTP-01) for any proxied host (the flat dashboard included): Always-Use-HTTPS redirects the challenge to https, and the https follow-up needs the origin cert ACME is still trying to obtain — a catch-22 (live 2026-09-10, issue #88). Deploy a per-anchor pair (below); a run that cannot handshake `:443` logs the WARNING variant of the dashboard check, not a failure.

- SSL/TLS mode **Full (Strict)** (edge → origin encrypted, origin cert verified).
- Cache Rule **Bypass** for `/.well-known/acme-challenge/*` (HTTP-01 must reach the box, never a cached edge hit).
- No WAF custom rule / Bot Fight Mode block on that path (challenge fetches look like bots).
- Zone-level **Authenticated Origin Pulls** with our own cert: mint a CA + leaf offline, upload the **leaf cert + key** to Cloudflare (zone-level AOP; global AOP's shared cert is publicly downloadable and adds ~no security), enable the setting, THEN set the `CF_AOP_CA_PEM` repo secret (**the CA bundle**) + re-dispatch — Caddy verifies the edge client cert at the handshake (`require_and_verify` + trust pool, 2.11.4), and the run itself asserts both halves (cert-less origin pull rejected; edge pull serves 200). Order matters: CF side first, origin second — the reverse black-holes every edge pull. Rollback, in this order: unset `CF_AOP_CA_PEM` + re-dispatch FIRST (the origin stops requiring the cert; edge pulls keep working while Cloudflare still presents it), then disable the CF setting (`102 --aop-disable`). The reverse order black-holes every edge pull until the redeploy. **DR rebuild note:** the provision job's AOP half asserts the *edge* pull, which needs the proxied record the DNS stage upserts **after** close — a rebuild dispatched while `CF_AOP_CA_PEM` is still planted fails the provision job before DNS can converge (host does not resolve ⇒ curl exit 6; record still pointing at the dead old box ⇒ edge 521/522 / curl 22, reported with the trust-mismatch hint + this DNS caveat). Recover by temporarily `gh secret delete CF_AOP_CA_PEM` + re-dispatch, let the DNS stage converge, then re-enable AOP (`102 --aop`). Until then, edge auth is firewall-allowlist + Host binding (documented degradation, dashboard-only).
- Origin CA pair (issue #123, M2): one per-anchor cert per box. The anchor generates its OWN key on the box (`/etc/caddy/origin-ca.key`, ECDSA P-256, **never leaves** — no key material ever travels through repo secrets or variables) and a CSR for the single SAN `status-<tenant>.piercloud.net`; the run publishes it as the `origin-ca-csr-<tenant>` artifact. Sign it in the Cloudflare dashboard (Origin CA, "use my CSR"; a 15-year validity is fine — Cloudflare sends no expiry notifications, calendar it anyway), then paste the **signed cert only** into the tenant's `ORIGIN_CA_CERT_PEM` repo **variable** (cert-only public material) and re-dispatch: the run validates it fail-closed against the on-box key (public-key match, exactly one SAN equal to the status host, currently valid), writes it in place (the container bind-mounts the file, so the inode must survive), reloads Caddy and only then records the new cert hash as served. This is the interim operator path — in-band broker signing replaces the variable in the M1 follow-up (operator tracking).
- Transition + one-way marker: a box that still carries the legacy shared wildcard pair (`/etc/caddy/origin.{crt,key}`) keeps serving it until the per-anchor pair has actually served on `:443`; that run drops the one-way `/etc/caddy/.origin-ca-active` marker, after which the legacy pair is **never selected again** — even if the per-anchor pair disappears, no silent resurrection (dashboard TLS stays pending until a per-anchor cert returns). After every dashboard is on its per-anchor cert (marker present, edge 200 under Full Strict), revoke the shared wildcard cert in the Cloudflare dashboard — LAST — and delete the retired pair secrets; the on-box legacy files are inert and can go with the usual disk cleanup.
- Rotation drill (manual, until `102 --rotate-origin`/`--revoke-origin` land): delete `/etc/caddy/origin-ca.key`, `.csr`, `.crt` and `.origin-ca.crt.sha256` on the box, re-dispatch `mode=apply` (a fresh key + CSR are minted; the one-way marker keeps the legacy pair suppressed, so the dashboard is briefly pending), sign the new CSR, set `ORIGIN_CA_CERT_PEM`, re-dispatch to install and serve, verify the edge 200, then revoke the previous cert in the Cloudflare dashboard. Never regenerate the key in place while a cert exists — the state machine refuses it by design.
- Deployed cert material, NOT a standing API token: the box presents its origin cert but cannot rewrite the zone.

Cutover reversibility (if Caddy ever wedges and the `:80` proxy with it — tang itself stays up on loopback throughout): on the box, `docker stop caddy`, remove `/etc/systemd/system/tangd.socket.d/listen.conf`, `systemctl daemon-reload`, `systemctl restart tangd.socket`, confirm `systemctl show tangd.socket -p Listen` answers `:80` again; then re-dispatch `mode=apply` to re-pin the firewall to the pre-Caddy shape. Dashboard stays down until Caddy returns — tang does not wait for it.

Bind-proof in CI (the keyboard problem): `tests/bind-e2e/` fronts a mock tang with the repo's real rendered Caddyfile and runs `clevis luks bind` + `unlock` through it on every PR touching `scripts/`, `main.tf`, workflows, or the harness — the Caddy-in-front path stays bind-proven without the tenant's keyboard.

## Rescue-chroot runbook (DR only)

Rescue boot is the last resort, not a workflow: the netcup rescue system disables the firewall entirely while it runs. After ANY rescue boot, rotate the tang keys afterwards (`--rotate` path, then re-bind / `regen`), because the disk was attached to a second system.

## Quarterly drill (at your desk, 15 minutes)

1. Stop the anchor (or its tang service).
2. Reboot the main box; confirm it falls back to the passphrase prompt.
3. Unlock with the passphrase from your PM (proves T0 still works).
4. Restart the anchor; reboot the main box again; confirm unattended unlock returns.
5. If anything surprised you, fix the docs first (this file), then the setup.

## Day-1 off-device checklist

Do this the day you provision, on paper, off the phone (lost-phone month-6 lesson: GitHub 2FA + netcup TOTP + ntfy + the root-password email can all live on one device — don't let them be ONLY there):

- [ ] Recovery codes (GitHub + netcup) in the PM emergency kit, printed off-device.
- [ ] Anchor root password in the PM emergency kit (it is locked via `passwd -l root` after provisioning — the printed copy is break-glass).
- [ ] Tang thumbprint in the PM + committed break-glass file reviewed (H1 chain: run artifact with `retention-days: 90` = the public-repo cap, a 90-day convenience copy only — never rely on logs or artifacts alone — plus the committed file via reviewable App PR and the platform registry, both pending; `mode=check` asserts the cap).
- [ ] LUKS passphrase keyslot confirmed as true root (you can unlock the main box with it, keyboard-only, right now).
- [ ] ntfy topic test-delivered to a second device.
