# DR runbook + boot-failure decision tree

Steady-state operations for your tang anchor: what breaks, how you notice,
and what to do — all runnable from any browser, phone included. No plans or roadmaps here;
this page covers the anchor you already run.

Related: [usage.md](usage.md) (end-to-end flow) ·
[invariants.md](invariants.md) (S1 / C-A review blockers).

## T0 / T1 / T2 — emergency-unlock ladder (advise, never mandate)

- **T0 baseline (shipped with this template):** LUKS passphrase keyslot in
  your password manager (PM) + dropbear-initramfs paste on the main box +
  public-repo break-glass card (provider → console-URL map). The passphrase
  stays in the PM — never on any service. The runbook "website" stores
  NOTHING.
- **T1 advised:** WireGuard peer in the main box initramfs (dropbear behind
  WG, no public initramfs port); Gatus must ALERT, not just monitor; PM
  emergency kit + recovery codes completed day-1, printed off-device (see
  the day-1 checklist below).
- **T2 opt-in:** BYO twin anchor — a second small box at a DIFFERENT
  provider, both user-owned, SSS t-of-2 via `extra_tang_urls`. The only
  availability upgrade that adds zero trust parties. Product default stays
  single anchor t:1 (see [usage.md](usage.md)).

## DR table

| Situation | Detection | Do | Do NOT |
|---|---|---|---|
| Anchor death (box down, tangd wedged) | Gatus ALERTs (T1); main box falls back to passphrase prompt at boot | Unlock with the passphrase keyslot; rebuild the anchor, re-bind or `regen` (same-URL fast path below) at your desk | Panic-migrate the main box anywhere |
| Firewall policy deleted | Main-box canary (drift report planned — compare policies in the SCP until then) | Re-run [`provision.yml`](../.github/workflows/provision.yml) `mode=apply`; it re-converges the policy | Hand-edit policies in the SCP and forget them (drift returns) |
| Firewall drift (rule changed out-of-band) | Canary failure (+ `mode=check` drift report when live) | Same as above: dispatched re-apply | Assume the anchor is "just slow" — check the drift report first |
| Stale binding (main box moved, source IP changed) | Clevis fails after a move; canary carries the new IP | `mode=update-ip`: ADD the new IP first, confirm boot, then remove the old (ADD-before-move; operator requests, OWNER executes) | Remove the old IP before the new one boots (cutover lockout) |
| SCP outage (netcup control plane down) | SCP/API unreachable; anchor itself still answers clevis | **SCP outage: do NOT migrate hosts.** Wait it out — running anchors keep unlocking; nothing needs the API until you change something | Migrate hosts mid-outage (strands the moved box behind a stale rule with zero remediation) |
| Lost phone | You, noticing | Day-1 kit: recovery codes + root password in the PM emergency kit, printed off-device — recover GitHub/netcup access from any browser, then re-enroll | Keep all second factors on the one device (month-6 lesson — see checklist) |
| Device grant disabled (netcup turns off the OAuth device flow) | `mode=apply` fails at the approval step | STOP + open an issue in your tenant repo. Do not proceed. (C-A — no fallback of any kind is designed or permitted) | Invent a fallback: no one-run tokens, no pasted long-lived secrets, no "temporary" standing credential |
| Dashboard cert stale (Caddy did not renew) | Gatus `dashboard TLS` endpoint fails its `[CERTIFICATE_EXPIRATION]` condition → ntfy ALERT; ~30d warning window | Re-dispatch `mode=apply` (Caddy retries HTTP-01); if still failing, check the edge checklist below (cache bypass on the challenge path, no WAF/Bot-Fight block). Tang is unaffected throughout (plain HTTP, separate port, zero TLS dependency) | Touch tang or the firewall to "fix" the dashboard; bind anything new while the dashboard is red |

## Boot-failure decision tree (main box asks for a passphrase)

Your main box dropped to a passphrase prompt instead of unlocking via the
anchor. Four causes, in order:

1. **Is the anchor up?** Check Gatus from the anchor's SCP console (`curl -s localhost:8080 | head -5` — HTTP 200 = alive).
   No → anchor death: type the passphrase (T0), then rebuild at your desk
   (same-URL `regen` below). Yes → step 2.
2. **Did anything firewall-shaped change?** Diff the firewall policies in the SCP (`mode=check` drift report planned).
   Drift or a deleted
   policy → `mode=apply` re-converges it, reboot, done. Clean → step 3.
3. **Did the main box move (new IP)?** Stale binding: the anchor only
   answers the IPs in the policy. `mode=update-ip` with ADD-before-move,
   confirm boot, then remove the old IP. No move → step 4.
4. **Was the anchor rebuilt or its tang keys rotated?** The binding points
   at keys that no longer exist: unlock with the passphrase, then unbind +
   re-bind (or `regen` on the same URL), verifying the new thumbprint
   out-of-band — never `-y` blind.

## Discovery fallback (multi-server accounts only)

Single-server accounts never need this. If a run aborts with
`expected 1 server, found N`, set `ANCHOR_IPV4` (repo secret) to the
server-ready email's "IP address" verbatim (`203.0.113.10/22`-style
suffix included; the run strips it) and re-dispatch. Prefer renaming
one box to `anchor-<you>-01` so discovery stays automatic.

## Same-URL rebuild = `regen` (2-minute DR)

Bind clevis to a DNS name (`anchor-<alias>-01.piercloud.net`, see
`anchor_hostname`), never the raw IP. A rebuilt anchor at the same URL
needs only `clevis luks regen -d <device> tang` — same URL, fresh keys,
no unbind+bind ceremony.

## Caddy dashboard: edge checklist + cutover reversibility

Caddy (`caddy:2.11.2-alpine`, pinned + Renovate-watched) owns `:80`;
`tangd.socket` listens on `127.0.0.1:8081`; Gatus stays loopback-only
(`127.0.0.1:8080`, Caddy proxies the status host to it). The Caddyfile is
dispatch-managed (same render pattern as the Gatus config): `handle /adv* +
/rec*` → `127.0.0.1:8081` plain, NO redirect; `/.well-known/acme-challenge/*`
→ HTTP-01; `Host status.*` → `127.0.0.1:8080`; explicit per-tenant site
blocks, NEVER `on_demand` TLS; catch-all aborts. Tang paths are never served
on the `:443` dashboard vhost (they abort there).

Operator edge ceremony (one-time per zone, Cloudflare dashboard — the
DNS-edit token the run holds cannot set these, so they are deliberately
manual, verified by eye after each change):

- SSL/TLS mode **Full (Strict)** (edge → origin encrypted, origin cert verified).
- Cache Rule **Bypass** for `/.well-known/acme-challenge/*` (HTTP-01 must reach the box, never a cached edge hit).
- No WAF custom rule / Bot Fight Mode block on that path (challenge fetches look like bots).
- Zone-level **Authenticated Origin Pulls** with our own cert: upload the CA in the zone dashboard, then set the `CF_AOP_CA_PEM` repo secret (public bundle) + re-dispatch — Caddy enforces the edge client cert at the handshake. Until then, edge auth is firewall-allowlist + Host binding (documented degradation, dashboard-only).
- Origin CA pair: issued in the Cloudflare dashboard per tenant hostname, planted as the `CF_ORIGIN_CERT_PEM` / `CF_ORIGIN_KEY_PEM` repo secrets (operator-plane, set at template time — the tenant pastes nothing), re-dispatch to deploy. Deployed key material, NOT a standing API token: the box presents its origin cert but cannot rewrite the zone.

Cutover reversibility (if Caddy ever wedges and the `:80` proxy with it —
tang itself stays up on loopback throughout): on the box, `docker stop caddy`,
remove `/etc/systemd/system/tangd.socket.d/listen.conf`, `systemctl daemon-reload`,
`systemctl restart tangd.socket`, confirm `systemctl show tangd.socket -p Listen`
answers `:80` again; then re-dispatch `mode=apply` to re-pin the firewall to
the pre-Caddy shape. Dashboard stays down until Caddy returns — tang does not wait for it.

## Rescue-chroot runbook (DR only)

Rescue boot is the last resort, not a workflow: the netcup rescue system
disables the firewall entirely while it runs. After ANY rescue boot,
rotate the tang keys afterwards (`--rotate` path, then re-bind /
`regen`), because the disk was attached to a second system.

## Quarterly drill (at your desk, 15 minutes)

1. Stop the anchor (or its tang service).
2. Reboot the main box; confirm it falls back to the passphrase prompt.
3. Unlock with the passphrase from your PM (proves T0 still works).
4. Restart the anchor; reboot the main box again; confirm unattended
   unlock returns.
5. If anything surprised you, fix the docs first (this file), then the setup.

## Day-1 off-device checklist

Do this the day you provision, on paper, off the phone (lost-phone
month-6 lesson: GitHub 2FA + netcup TOTP + ntfy + the root-password email
can all live on one device — don't let them be ONLY there):

- [ ] Recovery codes (GitHub + netcup) in the PM emergency kit, printed
  off-device.
- [ ] Anchor root password in the PM emergency kit (it is locked via
  `passwd -l root` after provisioning — the printed copy is break-glass).
- [ ] Tang thumbprint in the PM + committed break-glass file reviewed
  (H1 chain: run artifact with `retention-days: 400` = artifacts only —
  never rely on logs alone — plus the committed file via reviewable App
  PR; `mode=check` warns on the repo retention setting).
- [ ] LUKS passphrase keyslot confirmed as true root (you can unlock the
  main box with it, keyboard-only, right now).
- [ ] ntfy topic test-delivered to a second device.
