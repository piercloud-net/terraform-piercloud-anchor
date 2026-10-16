# Usage — end-to-end walkthrough

From zero to an unattended-booting encrypted main box, runnable END-TO-END from any browser — laptop or phone. Time: ~30 minutes, mostly netcup web UI + taps.

Flow: order piko → repo from template → workflow dispatch → device-flow approval → A1 provisions → thumbprint via run artifact (Actions → run → Artifacts; ntfy push + committed break-glass file pending) → clevis bind → monthly one-tap check.

Related: [dr.md](dr.md) (DR table, decision tree, day-1 checklist) · [invariants.md](invariants.md) (S1 / C-A review blockers).

## 0. What you need

- A netcup account (identity verification happens at order time).
- A browser (laptop or phone) + a password manager (PM).
- Your main box: any Debian-family machine with a LUKS-encrypted root.
- Your main box's public IPv4 — the run allows ONLY this address to reach tang. It comes pre-configured (pinned from your signup) — nothing to enter. Wrong/CGNAT-shared IP = locked out at first reboot: if your main box sits behind CGNAT, open a repo issue BEFORE dispatching. Anchor IPv4 is REQUIRED (runners have no IPv6); v6-only is unsupported.

## 1. Order the anchor ("piko"-class VPS)

In the netcup SCP (web UI, TOTP 2FA), order a small VPS — the [VPS pico G11s](https://www.netcup.com/en/server/vps/vps-pico-g11s-iv-12m-nue) (~€1.90/mo VAT-incl, 12-mo term, Nürnberg) is plenty for tang + Gatus. Official Debian-family image, root password by email. Do NOT apply a welcome voucher: pico products can't be combined with vouchers (the voucher exceeds the cart minimum), so the order won't submit. Ordering isn't instant: netcup staff manually review new orders — you'll get an email ("Your order will be checked by one of our employees shortly") and a follow-up once it's through. Wait for that before provisioning.

**First login (CCP):** the "Your login credentials for the netcup CCP" email holds your customer number + password. Log in at <https://www.customercontrolpanel.de/> (paste both, select "I don't process personal data"), open the personal page (person icon), change the password, then scroll to two-factor authentication and enable it: tap (or right-click) the QR code to save it to your password manager, then copy the temporary code from the PM back to confirm. Finally check the 💵 tab that the invoice is paid — if not, pay it via the 💳 next to "unpaid".

**SCP login (separate credentials):** the server control panel at <https://www.servercontrolpanel.de/SCP/> uses its own password, sent in the "Access data for SCP" email — change it on first login and enable 2FA there too.

**Server-ready email:** "Ihr vServer bei netcup ist bereitgestellt" (from donotreply@netcup.de) carries the hostname, IP, username, and root password — ignore the password entirely. Keep the email for the printed SSH fingerprints to verify the host key on first contact. Note the preconfigured firewall: the "netcup Mail Block" policy blocks SMTP both ways — remove it in SCP → Firewall only if you want SMTP alerts from the anchor.

Collect these as you go — each feeds one repo secret in §2. Where they go (phone path, primary): open the repo → `…` (top right) → Settings → Secrets and variables → Actions → **Secrets** tab → Repository secrets. Everything you paste goes there (the Variables tab holds operator pre-sets — `TENANT_USER` — nothing to touch; the DNS provider variables are no longer consumed (b3b broker cutover; deletion read back with that slice)). Always repository level — never Environment secrets/variables (the workflow's one Environment, `anchor`, is only a deployment-approval gate and holds no values).

- **customer number** (same value on both account emails) → `CUSTOMER_NUMBER` — the ONE required secret (provider credential only; the SCP user id resolves itself from your approval token — override via `SCP_USER_ID` repo secret only if yours differs)
- nothing else to enter: your username, hostname, anchor IP, DNS, and default monitor (your homepage) are pre-set or derived — dispatch takes no identifiers apart from the managed `tenant` + `anchor_ref` inputs (§3)

Create them here: [👉 Repo → Settings → Secrets → New repository secret](../../../settings/secrets/actions/new) (one per value above).

Secrets set? Dispatch now: [👉 Actions → provision.yml → Run workflow](../../../actions/workflows/provision.yml) (`mode` preselects `apply`).

Single anchor t:1 is the product (a twin anchor at a different provider is a T2 opt-in via `extra_tang_urls` — see [dr.md](dr.md)).

## 2. Repo from template + repo secrets (C-E visibility rule)

"Use this template" → your repo. **No stored netcup API tokens of any kind (S1)** — every run authenticates via your per-run approval below (the one-run A1 root password is the single exception: write-only, locked out + deleted after use). What lives in the repo are identifiers only (anchor IP, customer number) plus your monitor targets: values are write-only and log-masked. Your username lives in the pre-set `TENANT_USER` variable — nothing to enter. Set once via the taps above, or CLI (secrets prompt so nothing touches shell history). Laptop/CLI path (power users) — phone users can skip this block, it sets the same values as the taps above:

<details>
<summary>CLI equivalents</summary>

```bash
# secrets (write-only) — just the first line:
gh secret set CUSTOMER_NUMBER  # username on both account emails (the ONE required secret)
# later, when exploring: extra monitor targets + push (see §8)
gh secret set GATUS_ENDPOINTS         # e.g. blog=https://blog.example.com
```

</details>

No discovery-URL setup: the Keycloak doc address is baked into the workflow (public constant, same realm for everyone).

Visibility rule (C-E): identifiers in secrets always; public default once secrets land (values stay invisible to forks). Anyone with a (free) GitHub account can read every run log, summary and artifact; anonymous visitors see run and artifact metadata — keep identities out of the alias plane. Reviewer gate: no required reviewer by default; the LOUD banner + approval card are the mechanism. Opting into a reviewer (repo settings, the `anchor` environment) pauses the run for the deployment tap and makes your GitHub login anonymous-readable through the environments API — the reason it is never the default and never names an operator. The approval card shows the exact commit (short+full head SHA + compare-diff link + workflow file count with an UNCHANGED/CHANGED banner). The repo is authoritative for execution; any UI is advisory display only.

**Managed anchors (dispatched by the platform with a `tenant`).** A managed run selects the tenant's own environment and reads none of the operator's repo-level values except the platform-plane `CLOUDFRONT_ORIGIN_SECRET` and `MAIN_BOX_IPV4` (issue #198). `ANCHOR_ROLE`, `NTFY_*`, `RECORDING_WITNESS_*`, `ORIGIN_CA_CERT_PEM`, `STATUS_PULLER`, `GATUS_ENDPOINTS`, `CF_AOP_CA_PEM`, `ANCHOR_IPV4`, `SCP_USER_ID` and `ANCHOR_ROOT_PASSWORD` resolve empty, even when the tenant environment defines them. The alias is the `tenant` input (`TENANT_USER` is not read); it must match the pc-control environment grammar `^[a-z0-9]{3,15}$` and must not start with `anchor`/`status`/`pcu`/`platform`, and the preflight refuses anything else before any gate. The netcup customer number is the environment-scoped `TENANT_CUSTOMER_NUMBER` secret: a managed run without it stops before the device card.

Managed-run residuals (disclosed):
- No recording witness and no ntfy alerts: a managed run sends no push and installs no witness (witness alerts move to the slice track, pc-control #20).
- No per-anchor TLS chain and no status puller: the dashboard certificate and the dynamic status page are operator-only until the broker DNS-01 path ships for tenants.
- The device code appears only in the public run log: managed tenants have no private device-code channel yet (pc-control #145).
- `TENANT_CUSTOMER_NUMBER` must be created on the tenant environment by hand: nothing writes it yet.
- Tenant boxes hold the shared `CLOUDFRONT_ORIGIN_SECRET` (rendered into the root-only Caddyfile, and a tenant has root on its box). With its own CloudFront distribution, a tenant can reach any anchor's dashboard origin directly. That reach is status-page content only; tang and API paths abort. This is reasoned from the Caddy gate and the CloudFront ranges, not live-tested (security-posture row 3; per-anchor origin secret: #202).
- `MAIN_BOX_IPV4` tells each tenant the pc-host address (its firewall admits it). It is informational only: spoofing a TCP source from a tenant box is not practical.
- `MANAGED_TENANT` and `TENANT_CUSTOMER_NUMBER` are reserved: never define them at repo level. GitHub falls back to repo-level values per name, so a repo-level value would satisfy the marker or the customer-number check for a typo'd environment. This is a convention; neither the pin nor the workflow enforces it.
- The pin (`tests/managed-operator-plane`) scans workflow text only: scripts are not scanned (reading repo variables through the API needs `actions: read`, which no job grants), and the allowed forms are literals not bound per name.

## 3. Dispatch and approve (S1)

Actions → [`provision.yml`](../.github/workflows/provision.yml) → `mode=apply`, from any browser. Managed tenants dispatch with `tenant` + `anchor_ref`: since b3b (#189) anchor DNS writes through the pc-control broker, so a ref-less or tenant-less `apply` is refused at the preflight before anything is provisioned — the template/static-lane apply is retired until a broker binding for it ships. Apart from those two managed inputs the dispatch takes only the mode (plus action flags) — no identifiers: your username already lives in the repo's `TENANT_USER` variable, and everything sensitive resolves from repo secrets inside the run.

Only the URL + code (+ alias, action, pinned commit and review link) are ever printed — `curl -sS`, no `-v`, no `TF_LOG`. The short-lived netcup `device_code` is masked at birth inside the single job/step that mints and polls it, so it never crosses a job boundary; the runner redacts it from every later log line ("masked at birth" means redaction, not absence). The card carries the action, the pinned commit and the review link. The `user_code` stays public by design: it is the approval surface (never printed beyond the card, never stored, dead in 600s, and useless without your own netcup session). The access and refresh tokens stay masked and never cross jobs.

By default there is NO required reviewer: the run proceeds straight to the code, and the LOUD banner is your check. If your repo opts into a reviewer (the `anchor` environment), GitHub pauses the run first: approve the pending deployment (check the commit matches the banner card), THEN approve the netcup code below — two taps, in that order; the first approves WHAT runs, the second lets it touch your account, and your GitHub login becomes anonymous-readable through the environments API once configured.

The run prints a netcup device-flow URL + `XXXX-XXXX` user code (plus a push via ntfy, once you set that up later — see §8). You approve at netcup's own Keycloak (your session, your 2FA, ~600s window) — the approval is one tap, phone browsers included. The runner polls, receives an ephemeral token, provisions, and the token dies with the runner — the run revokes the device-grant refresh token at teardown; a teardown that cannot prove the credential dead fails the run RED (no silent green). Only the URL + code (+ alias, action, pinned commit and review link) are ever printed — `curl -sS`, no `-v`, no `TF_LOG` (masking note: the access token, the refresh token and the netcup `device_code` stay masked; the `user_code` on the card is public by design, see above). The card carries, verbatim: "we will never email or message you a code to re-confirm." If the device grant is ever disabled: STOP + open an issue in your repo so the operator sees it (C-A — no fallback exists, none is permitted).

If the runner is killed or the run is cancelled before teardown, the run's refresh token can stay live for up to ~30 days — recovery: [dr.md, "Runner killed or run cancelled before teardown" row](dr.md#dr-table).

## 4. A1 provisions, thumbprint lands via run artifact (H1 chain)

The run opens the hardened A1 self-open /32 SSH window, sets its own one-time root password when none was pasted (applied on the running box via the guest agent — no reboot, no tap needed; concurrent runs serialize on a lock-wait), and provisions the anchor (no standing SSH keys by design: the script ends with `passwd -l root`; console-recovery note: rescue disables the netcup firewall — any rescue boot → rotate tang keys afterwards), then closes the window (detach-then-delete; the pre and `always()` post sweep steps run in every mode but delete only in `mode=apply`, other modes report). Key rotation: dispatch `mode=apply` with `rotate_keys=true` (forwards `--rotate` to the provisioning script: dots out old tang keys per netcup procedure).

The tang thumbprint reaches you via the H1 chain — run artifact (`retention-days: 90` = the public-repo cap, a 90-day convenience copy only; the durable legs — committed break-glass file via reviewable App PR and the platform registry — are pending). Never rely on logs or artifacts alone (repo logs are a separate setting, also capped at 90 days on public repos). `mode=check` asserts every workflow's retention stays within the cap. **Save the thumbprint in your PM NOW** (and finish the [day-1 checklist](dr.md#day-1-off-device-checklist)).

The run also creates/verifies the anchor DNS record (`anchor-01-<alias>.piercloud.net` → anchor IPv4) and the dashboard CNAME (`<you>.status.piercloud.net` → the platform status edge) automatically, after A1 close and before any thumbprint goes out. The same run fronts the uptime dashboard at `https://<you>.status.piercloud.net` (served through the platform status edge; visitor TLS ends at the edge, and the edge→origin leg's TLS is terminated on the box by Caddy; nothing to enter). *(Edge live 2026-10-07; the anchor-side cutover (nested-SAN cert + origin auth) is the remaining step — until it lands the flat `status-<you>.piercloud.net` name serves through the orange cloud.)*

## 5. Bind your main box (clevis) — at its keyboard, not your phone

On your **main box** (this step needs a real keyboard — the SCP console or direct access; it cannot be done from your phone):

```bash
apt-get install clevis clevis-luks clevis-initramfs
# find your LUKS device (yours may differ — pick the crypto_LUKS line):
# lsblk -f
# NAME   FSTYPE      LABEL  MOUNTPOINT
# sda
# ├─sda1 vfat
# └─sda3 crypto_LUKS        ← this one
clevis luks bind -d /dev/sda3 tang '{"url":"http://anchor-01-pier.piercloud.net"}'
```

**Verify the thumbprint** shown at bind time against the value you saved in step 4 — out-of-band, never `-y` blind. If it doesn't match, answer NO and investigate. Binding the DNS name (`anchor_hostname`) means a future same-URL rebuild is just `regen` (see [dr.md](dr.md)). Then:

```bash
update-initramfs -u
```

(Debian note: for some remote-unlock setups the initramfs needs an `IP=` line in `/etc/initramfs-tools/initramfs.conf` to bring the network up — if the boot prompt never clears, check that first.)

Keep the passphrase keyslot forever — it is the true root. Disk unlock uses NBDE (clevis→tang) with a passphrase recovery keyslot; tang is availability, never the security anchor.

## 6. Monthly one-tap `mode=check` (hygiene, not load-bearing)

Planned — check mode currently answers a skeleton; the full drift/orphan/retention/versions report lands with live M0. Design: one dispatch: retention-cap assertion + versions-behind notice. Under S1 there is nothing to keep alive (no stored tokens) — missed months degrade visibility, never availability. Until it lands, compare the anchor's policy in SCP → Firewall against the last run summary by eye.

## 7. Tenant move: `mode=update-ip` (ADD-before-move)

Planned — the mode currently answers a skeleton; ADD-before-move enforcement lands with live M0. Design: main box moved and its IP changed? Dispatch `mode=update-ip` with `add_ipv4`/`add_ipv6` (optional `remove_ipv4`): the new IP is ADDED first, the old kept during transition, removed only after confirmed boot. Move requests arrive with the new IP; you dispatch the update-ip yourself — a batch move = N per-run approvals, never one shared token. Until it lands, open a repo issue with the new IP and the operator updates the policy.

## 8. Destroy: `mode=destroy` (policy + attachment ONLY)

Planned — enforcement (including the canary-fail proof gate) lands with live M0. Design: requires `ack_main_unbound` (confirm the main box is unbound first) + canary-fail proof. Tears down the firewall policy + attachment only — the server and the tang keys are untouched. Until it lands, delete nothing yourself — open a repo issue.

## 9. Explore later: push alerts + extra monitors (optional, after the bind)

The anchor already watches tang itself, the shared platform, your piercloud slice (`your piercloud`), and the private gate — plus the shared gate when a shared site is in use. On a puller anchor the dashboard groups rows by owner: `anchor` (the anchor's own tang/dashboard rows), `platform`, and your alias. The platform row is monitor-only on your page — it exists so you can tell "platform problem" from "my problem". The operator anchor watches the same platform and alerts on it. When you want taps on the shoulder instead:

- install the [ntfy app](https://ntfy.sh), subscribe to any random topic name (yours), then set repo secrets `NTFY_TOPIC` (that name) + `NTFY_TOKEN` only if your ntfy server needs auth (empty for ntfy.sh hosted) — re-dispatch `mode=apply` to take effect. This is the template-repo path: a managed anchor run sends no ntfy and reads no `NTFY_*` value (issue #198); its tenant-controlled alert channel is pc-control issue #20.
- **slice-managed anchors (`STATUS_PULLER` set):** your site rows come from the slice's `pc-status.json` manifest (rendered from `pc.yaml` by the deploy skill) and the anchor re-renders them on a ~10-minute timer — no re-dispatch per endpoint. Each entry carries its site class in a required `type` field — `public` (a `<site>-<alias>.piercloud.site` URL) gets its own monitor row; `shared`/`private` (a site under `<alias>.piercloud.net`) get **no** app-health row (an anonymous probe cannot see inside a gate) but keep that class's gate row alive. The first puller dispatch drops the legacy `GATUS_ENDPOINTS` pairs with a loud dispatch-time log (publish them in the manifest, then delete the secret). Reserved manifest names: `platform`, `slice`, `home`, `host-*`.
- **standalone anchors (switch unset):** extra targets are the `GATUS_ENDPOINTS` repo secret, comma-separated `name=url` (`blog=https://blog.example.com`, HTTP(S) only) + re-dispatch. `main` and `platform` are reserved monitor names — a `GATUS_ENDPOINTS` pair using either fails the run.
- **seeded rows, honestly:** on a puller anchor the seeded rows exist regardless of your manifest — `platform`, `your piercloud` (your slice's health endpoint) and `private (gate)` (the Teleport login route); a `shared (gate)` row joins automatically while a `type: shared` site exists (Pocket ID's login route), and the `public edge` row (platform channel; the Cloudflare edge in front of your public sites) appears when the platform enables it. `your piercloud`, the gate rows and `public edge` stay **red** until the slice ships its health endpoint and the gates/edge are built; `your piercloud` replaces the retired `main` homepage row. The slice, gate, platform and edge rows page as night-emergency (class 5); your own site rows page time-sensitive (class 4, no recovery message).

Dynamic monitor changes (the puller) never touch tang, Caddy or the firewall, and the only credential involved is the same ntfy publish token your alerts already use: the puller writes only the Gatus fragment, its `.last-good` sibling, and its own state file, and every other anchor change stays dispatch-only ([docs/invariants.md](invariants.md)). If a manifest fetch fails, the last-known-good rows stay up and a push notice fires only after 3 consecutive failures; removals — including the derived `shared (gate)` row leaving with the last shared site — are notified by name.

## 10. External watch: always-on, GitHub-side (automatic)

`external-watch.yml` runs every 15 minutes on GitHub's network and probes the public dashboard: `HTTP 200`, the statuses API actually returning data, and an edge certificate valid for at least 14 more days. It is the third vantage point — Gatus runs *on* the anchor and the main-box canary on your main box, so if both go quiet, GitHub is the only watcher left standing (and the only one whose alert path does not die with either box). When the puller is enabled (`STATUS_PULLER` set), it also checks **who watches the puller**: each manifest must be HTTP 200 (404/410 = not published, skipped) with a `generated_at` no older than 24 h, and every monitored row (public manifest entries plus the seeded `platform` / gate / `your piercloud` rows and the derived `shared (gate)` / `public edge` rows; `shared`/`private` entries are not monitored, so not expected) must appear in the dashboard's public endpoint keys — a changed manifest that never reached Gatus means a dead puller timer or a frozen fragment. It also fails on the reverse: a dashboard row in a parsed channel's own group that the manifest does not justify (a stale derived gate/edge row or a removed site row) means the puller never applied the change. A change caught in the propagation window (up to the puller's ~10-minute cycle) reports once and clears on the next run.

- A failure files an issue labelled **`external-watch`** (open = failing, with the probe detail and a run link) and fails the run, so GitHub also notifies repo watchers. Recovery auto-comments and closes the issue.
- Push alerts need no extra setup: once `NTFY_TOPIC`/`NTFY_TOKEN` exist (§9), the watch pushes there too.
- Manual run / test: Actions → `external-watch` → Run workflow (`probe_url` overrides the target, which is how the failure/recovery path is proven).
- Free on public repos; cadence is the workflow `cron`, cert window is `MIN_CERT_DAYS` in the probe step.

## What this repo never does

- No stored netcup tokens, no crons (S1) — every netcup use is human-approved per run via the device flow.
- No credentials in code, state, or CI. Tang keys are generated on the anchor and never enter terraform state; CI greps tracked files for key material (patterns enforced from `main`).
- No netcup identifiers in public run output: server id, SCP user id, order name, MAC and the account's server list are masked at first receipt or never printed; policy names carry the public hostname / run id only. This repo is public — anyone with a (free) GitHub account can read every run log, summary and artifact; anonymous visitors see run and artifact metadata.
- The explicit deny-list (logs/summaries/artifacts/committed files): customer number, SCP user id, server id, order name, MAC, device/access/refresh tokens, root-password paths/values, private keys, account server lists, a resolved server's address inventory beyond its public A-record address, tenant GitHub identities, SSH host keys, tang fingerprints (published only via H1).
- No sovereignty-downgrade fallback, ever (C-A) — failed check = no apply.
- The anchor holds no credential that reaches your main box (its cross-box interactions are answering clevis challenges on TCP/80, serving ACME challenges to the Cloudflare edge on TCP/80 and the dashboard to the CloudFront edge on TCP/443 (edge live 2026-10-07; the anchor-side cutover is the remaining step), and probing your public endpoints for availability — no credential reaches the main box either way).
- Workflows never touch rescue/image/snapshot/iso/disk surfaces (CI allowlist grep from `main`); tang-key management is never offered through automation.
