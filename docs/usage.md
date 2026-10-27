# Usage — end-to-end walkthrough

From zero to an unattended-booting encrypted main box, runnable END-TO-END from any browser — laptop or phone. Time: ~30 minutes, mostly netcup web UI + taps.

Flow: order piko → repo from template → workflow dispatch → device-flow approval → A1 provisions → thumbprint via run artifact (Actions → run → Artifacts; ntfy push + committed break-glass file pending) → clevis bind → monthly one-tap check.

Related: [dr.md](dr.md) (DR table, decision tree, day-1 checklist) · [invariants.md](invariants.md) (S1 / C-A review blockers).

## 0. What you need

- A netcup account (identity verification happens at order time).
- A browser (laptop or phone) + a password manager (PM).
- Your main box: any Debian-family machine with a LUKS-encrypted root.
- Your main box's public IPv4 — the run allows ONLY this address to reach tang (its direct `:443` access, if ever used, also needs a client certificate since 4d157dd). It comes pre-configured (pinned from your signup) — nothing to enter. Wrong/CGNAT-shared IP = locked out at first reboot: if your main box sits behind CGNAT, open a repo issue BEFORE dispatching. Anchor IPv4 is REQUIRED (runners have no IPv6); v6-only is unsupported.

## 1. Order the anchor ("piko"-class VPS)

In the netcup SCP (web UI, TOTP 2FA), order a small VPS — the [VPS pico G11s](https://www.netcup.com/en/server/vps/vps-pico-g11s-iv-12m-nue) (~€1.90/mo VAT-incl, 12-mo term, Nürnberg) is plenty for tang + Gatus. Official Debian-family image, root password by email. Do NOT apply a welcome voucher: pico products can't be combined with vouchers (the voucher exceeds the cart minimum), so the order won't submit. Ordering isn't instant: netcup staff manually review new orders — you'll get an email ("Your order will be checked by one of our employees shortly") and a follow-up once it's through. Wait for that before provisioning.

**First login (CCP):** the "Your login credentials for the netcup CCP" email holds your customer number + password. Log in at <https://www.customercontrolpanel.de/> (paste both, select "I don't process personal data"), open the personal page (person icon), change the password, then scroll to two-factor authentication and enable it: tap (or right-click) the QR code to save it to your password manager, then copy the temporary code from the PM back to confirm. Finally check the 💵 tab that the invoice is paid — if not, pay it via the 💳 next to "unpaid".

**SCP login (separate credentials):** the server control panel at <https://www.servercontrolpanel.de/SCP/> uses its own password, sent in the "Access data for SCP" email — change it on first login and enable 2FA there too.

**Server-ready email:** "Ihr vServer bei netcup ist bereitgestellt" (from donotreply@netcup.de) carries the hostname, IP, username, and root password — ignore the password entirely. Keep the email for the printed SSH fingerprints to verify the host key on first contact. Note the preconfigured firewall: the "netcup Mail Block" policy blocks SMTP both ways — remove it in SCP → Firewall only if you want SMTP alerts from the anchor.

One value, one owner. Where it goes: the anchor's own GitHub environment (repo → `…` top right → Settings → Environments → your anchor's environment). Who writes it: **the operator**, once, by hand, from the dispatch repository — nothing in this repo writes environment secrets yet, and tenants have no access to the dispatch repository.

- **customer number** (same value on both account emails) → `TENANT_CUSTOMER_NUMBER` on the anchor's environment — the ONE required secret and the operator's one action: `gh secret set --env <tenant> TENANT_CUSTOMER_NUMBER` from the dispatch repository (prompted, so it never lands in shell history). Not a provider input: it gates the tenant refusal and the approver guard (`API_USER == CUSTOMER_NUMBER` in provision.yml). The SCP user id resolves itself from your approval token — override via the `SCP_USER_ID` secret only if yours differs
- nothing else to enter: your hostname, anchor IP, DNS, and default monitor (your homepage) are pre-set or derived — dispatch takes no identifiers apart from the managed `tenant` + `anchor_ref` inputs (§3)

Never a repository-level copy of an environment-scoped managed name: the ungated banner job refuses a managed dispatch while any of `ANCHOR_ROLE`, `NTFY_*`, `RECORDING_WITNESS_*`, `ORIGIN_CA_CERT_PEM`, `STATUS_PULLER`, `GATUS_ENDPOINTS`, `CF_AOP_CA_PEM`, `ANCHOR_IPV4`, `SCP_USER_ID`, `ANCHOR_ROOT_PASSWORD`, `TENANT_CUSTOMER_NUMBER` or `MANAGED_TENANT` is defined at repository or organization level (§2). The one genuinely shared platform value, `MAIN_BOX_IPV4`, stays at repository level by design and is not refused. The DNS provider variables are no longer consumed (b3b broker cutover; deletion read back with that slice).

Environment settings, where the operator sets it once: [👉 Repo → Settings → Environments](../../../settings/environments). Your own steps stay yours: approve the netcup device flow (§3) and keep the thumbprint you receive (§4) in your password manager.

Secrets set? Dispatch now: [👉 Actions → provision.yml → Run workflow](../../../actions/workflows/provision.yml) (`mode` preselects `apply`).

Single anchor t:1 is the product (a twin anchor at a different provider is a T2 opt-in via `extra_tang_urls` — see [dr.md](dr.md)).

## 2. Repo from template + anchor values (C-E visibility rule)

"Use this template" → your repo. **No stored netcup API tokens of any kind (S1)** — every run authenticates via your per-run approval below (the one-run A1 root password is the single exception: write-only, locked out + deleted after use). What lives there are identifiers only (anchor IP, customer number) plus your monitor targets: values are write-only and log-masked. Your username is the managed `tenant` input — nothing to enter. Set once by the operator via the taps above, or CLI from a machine with admin on the dispatch repository (secrets prompt so nothing touches shell history) — phone users can skip this block, it sets the same values as the taps above:

<details>
<summary>CLI equivalents</summary>

```bash
# secrets (write-only) — operator action, from the dispatch repo; just the first
# line (<tenant> = the anchor's environment):
gh secret set --env <tenant> TENANT_CUSTOMER_NUMBER  # username on both account emails (the ONE required secret)
# later, when exploring: extra monitor targets + push (see §8)
gh secret set --env <tenant> GATUS_ENDPOINTS         # e.g. blog=https://blog.example.com
```

</details>

No discovery-URL setup: the Keycloak doc address is baked into the workflow (public constant, same realm for everyone).

Visibility rule (C-E): identifiers in secrets always; public default once secrets land (values stay invisible to forks). Anyone with a (free) GitHub account can read every run log, summary and artifact; anonymous visitors see run and artifact metadata — keep identities out of the alias plane. Reviewer gate: no required reviewer by default; the LOUD banner + approval card are the mechanism. Opting into a reviewer (repo settings, the `anchor` environment) pauses the run for the deployment tap and makes your GitHub login anonymous-readable through the environments API — the reason it is never the default and never names an operator. The approval card shows the exact commit (short+full head SHA + compare-diff link + workflow file count with an UNCHANGED/CHANGED banner). The repo is authoritative for execution; any UI is advisory display only.

**Managed anchors (dispatched by the platform with a `tenant`).** A managed run selects the tenant's own environment and reads its operator-plane values from that environment only (issue #204): `ANCHOR_ROLE`, `NTFY_*`, `RECORDING_WITNESS_*`, `ORIGIN_CA_CERT_PEM`, `STATUS_PULLER`, `GATUS_ENDPOINTS`, `CF_AOP_CA_PEM`, `ANCHOR_IPV4`, `SCP_USER_ID` and `ANCHOR_ROOT_PASSWORD`. GitHub falls back from an environment to the repository (and organization) per name, so the ungated banner job refuses a managed dispatch while any of these names, or `MANAGED_TENANT`/`TENANT_CUSTOMER_NUMBER`, is defined at repository or organization level: it names the names (never the values) and stops before any gate or device card. Move each value into the anchor's environment and delete the repository-level copy. Operator runs (no `tenant`) select the `anchor` environment and read its value first, then the repository level, so deleting a repository-level copy also removes it from operator runs that the `anchor` environment does not cover (for example the banner approval-card ntfy push, which reads the repository-level `NTFY_TOPIC`); and `TENANT_USER` and `CUSTOMER_NUMBER` stay operator-only (a managed run never reads them). The platform-plane `MAIN_BOX_IPV4` stays shared at repository level. The alias is the `tenant` input (the `TENANT_USER` value is not used: the expression short-circuits; GitHub's runtime population of the `vars` context is not verified). It must match the pc-control environment grammar `^[a-z0-9]{3,15}$`, must not start with `anchor`/`status`/`pcu`/`platform`, and must not be one of pc-control's reserved names `edge`, `console`, `ops`, `keys`, `unlock`, `bounce`, `mail`, `broker`, `www`; the preflight refuses anything else before any gate, and the binding step re-runs the canonical validator (`scripts/lib/naming.sh`), which carries the same shape (3-15), prefix and reserved-name rules — so a console hand-run path refuses them too. The netcup customer number is the environment-scoped `TENANT_CUSTOMER_NUMBER` secret: a managed run without it stops before the device card.

Managed-run residuals (disclosed):
- Environment values are written by the operator, by hand, from the dispatch repository (tenants have no access to it) — nothing in this repo writes environment secrets yet. Nothing writes the witness, ntfy, TLS-chain or status-puller values either: an environment without them gets no witness, no ntfy pushes, no per-anchor TLS chain and the static monitor rows.
- The approval push from the banner job stays operator-only: that job selects no environment, so it cannot read an environment's `NTFY_TOPIC`. The device-flow job's own push uses the environment's topic.
- The device code appears in the public run log: managed tenants have no private device-code channel yet (pc-control #145).
- Until the platform lifecycle writes environment secrets, `TENANT_CUSTOMER_NUMBER` is the operator's one manual step, run on the tenant's environment (§1): nothing in this repo writes it yet.
- A box holds no origin secret once a run on this release re-renders its Caddyfile. The shared `CLOUDFRONT_ORIGIN_SECRET` (rendered into the root-only Caddyfile by earlier releases; a tenant has root on its box) is retired at #202: this release neither renders nor checks it; until a re-render, the older value stays in the root-only file, and a hand-configured box also keeps its one-time `.pre-managed.bak` copy until someone removes it. Before this release, a tenant with its own CloudFront distribution and that value could reach the dashboard origin of any anchor not yet on origin mTLS. That reach is status-page content only; tang and API paths abort on the dashboard vhost. On this release the origin admits a request only with a client certificate signed by the committed origin-mTLS CA (`scripts/origin-mtls-ca.pem`, public material; the trust pool is that CA only, since `CF_AOP_CA_PEM` is refused beside it) at the TLS handshake, plus an admitted TCP peer. The platform's ACM client key is not exportable, and a tenant's own distribution cannot present it (reasoned from the trust pool, not live-tested). CloudFront keeps sending `X-Piercloud-Origin` until the platform repo drops it in a follow-up apply; after that apply, operators may delete the `CLOUDFRONT_ORIGIN_SECRET` repository secret. The rollback floor is in `docs/dr.md`. The former ungated `:80` dashboard proxy is gone (#225): `:80` serves tang + ACME only, and a spoofed `CloudFront-Viewer-Address` does not move the gate (live-tested 2026-10-22).
- The `:443` dashboard echoes `Pc-Edge-Client-Sha256`: the SHA-256 (lowercase hex, of the DER) of the verified edge client certificate. It is platform-owned, not secret, the same value on every anchor, and used only for the platform's leaf-rotation check. A tenant may remove the line from their own box; that only drops their own echo.
- `MAIN_BOX_IPV4` tells each tenant the pc-host address (its firewall admits it). It is informational only: spoofing a TCP source from a tenant box is not practical.
- The repo-scope check sees repository and organization scope through presence probes in a job with no environment; it is a refusal, not a sandbox. A value added at repository level after the banner job ran is read by that run (a race the operator controls; the next dispatch refuses).
- Deployment-branch policy: the proof environments carry a `v*` tag policy and `anchor` has none (not verified here — neither the workflow nor the pin checks it); `pc-control admin env harden` is expected to set tenant policies.
- The pin (`tests/managed-operator-plane`) scans workflow text only: scripts are not scanned. Reading repository variables through the API needs `actions: read`; the pin refuses that scope in any **declared** `permissions:` block (job or workflow level) and requires every workflow file to declare exactly one workflow-level `permissions:` mapping — all seven do, so a new file with no block reds the pin instead of escaping the refusal — hence the route needs a reviewed pin edit, and the allowed forms are literals not bound per name (a gated name may use another name's gated form; the repo-scope probes still name every declared value one by one). Every `environment:` (job level, and the workflow's own) is a per-file exact allowlist, so a later job that names a static environment other than the tenant expression (the `anchor-dns`-with-`environment: anchor` class) is refused by the pin itself, not only by the broker's registry check; the gate order is pinned too (`device-flow` must need `visibility-banner` exactly and carry no `if:` at all), and a workflow file must compose to exactly one YAML document. Repository-level `MANAGED_TENANT`/`TENANT_CUSTOMER_NUMBER` are refused by the banner's repo-scope probes, not by a repo-level name check: that check lives in the pc-lifecycle verify run (API credentials), so it is disclosed rather than duplicated here.

## 3. Dispatch and approve (S1)

Actions → [`provision.yml`](../.github/workflows/provision.yml) → `mode=apply`, from any browser. Managed tenants dispatch with `tenant` + `anchor_ref`: since b3b (#189) anchor DNS writes through the pc-control broker, so a ref-less or tenant-less `apply` is refused at the preflight before anything is provisioned — the template/static-lane apply is retired until a broker binding for it ships. Apart from those two managed inputs the dispatch takes only the mode (plus action flags) — no identifiers: on a managed `mode=apply` run the alias is the `tenant` input and the operator-plane values resolve from that tenant's environment inside the run. The tenant-less `update-ip`/`destroy` lane (no anchor-DNS write, so no broker binding needed) selects the `anchor` environment and falls back to repository-level values for anything it does not define; a ref-less run on that lane warns loudly in the preflight ([dr.md](dr.md)), while a tenant-less run that does pass `anchor_ref` is legal and silent.

Only the URL + code (+ alias, action, pinned commit and review link) are ever printed — `curl -sS`, no `-v`, no `TF_LOG`. The short-lived netcup `device_code` is masked at birth inside the single job/step that mints and polls it, so it never crosses a job boundary; the runner redacts it from every later log line ("masked at birth" means redaction, not absence). The card carries the action, the pinned commit and the review link. The `user_code` stays public by design: it is the approval surface (never printed beyond the card, never stored, dead in 600s, and useless without your own netcup session). The access and refresh tokens stay masked and never cross jobs.

By default there is NO required reviewer: the run proceeds straight to the code, and the LOUD banner is your check. If your repo opts into a reviewer (the `anchor` environment), GitHub pauses the run first: approve the pending deployment (check the commit matches the banner card), THEN approve the netcup code below — two taps, in that order; the first approves WHAT runs, the second lets it touch your account, and your GitHub login becomes anonymous-readable through the environments API once configured.

The run prints a netcup device-flow URL + `XXXX-XXXX` user code (plus a push via ntfy, once you set that up later — see §8). You approve at netcup's own Keycloak (your session, your 2FA, ~600s window) — the approval is one tap, phone browsers included. The runner polls, receives an ephemeral token, provisions, and the token dies with the runner — the run revokes the device-grant refresh token at teardown; a teardown that cannot prove the credential dead fails the run RED (no silent green). Only the URL + code (+ alias, action, pinned commit and review link) are ever printed — `curl -sS`, no `-v`, no `TF_LOG` (masking note: the access token, the refresh token and the netcup `device_code` stay masked; the `user_code` on the card is public by design, see above). The card carries, verbatim: "we will never email or message you a code to re-confirm." If the device grant is ever disabled: STOP + open an issue in your repo so the operator sees it (C-A — no fallback exists, none is permitted).

If the runner is killed or the run is cancelled before teardown, the run's refresh token can stay live for up to ~30 days — recovery: [dr.md, "Runner killed or run cancelled before teardown" row](dr.md#dr-table).

## 4. A1 provisions, thumbprint lands via run artifact (H1 chain)

The run opens the hardened A1 self-open /32 SSH window, sets its own one-time root password when none was pasted (applied on the running box via the guest agent — no reboot, no tap needed; concurrent runs serialize on a lock-wait), and provisions the anchor (no standing SSH keys by design: the script ends with `passwd -l root`; console-recovery note: rescue disables the netcup firewall — any rescue boot → rotate tang keys afterwards), then closes the window (detach-then-delete; the pre and `always()` post sweep steps run in every mode but delete only in `mode=apply`, other modes report). Key rotation: dispatch `mode=apply` (a managed dispatch: `tenant` + `anchor_ref`) with `rotate_keys=true` (forwards `--rotate` to the provisioning script: dots out old tang keys per netcup procedure).

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

- install the [ntfy app](https://ntfy.sh), subscribe to any random topic name (yours), then set `NTFY_TOPIC` (that name) + `NTFY_TOKEN` (only if your ntfy server needs auth; empty for ntfy.sh hosted) on the anchor's GitHub environment, then re-dispatch `mode=apply` (a managed dispatch: `tenant` + `anchor_ref`) to take effect. A managed anchor reads `NTFY_*` from its tenant environment only (issue #204): a repository-level `NTFY_TOPIC` or `NTFY_TOKEN` makes the banner refuse the dispatch. The operator writes them, on your anchor's environment (nothing in this repo writes environment secrets yet); your tenant-controlled alert channel is pc-control issue #20.
- **slice-managed anchors (`STATUS_PULLER` set):** your site rows come from the slice's `pc-status.json` manifest (rendered from `pc.yaml` by the deploy skill) and the anchor re-renders them on a ~10-minute timer — no re-dispatch per endpoint. Each entry carries its site class in a required `type` field — `public` (a `<site>-<alias>.piercloud.site` URL) gets its own monitor row; `shared`/`private` (a site under `<alias>.piercloud.net`) get **no** app-health row (an anonymous probe cannot see inside a gate) but keep that class's gate row alive. The first puller dispatch drops the legacy `GATUS_ENDPOINTS` pairs with a loud dispatch-time log (publish them in the manifest, then delete the secret). Reserved manifest names: `platform`, `slice`, `home`, `host-*`.
- **anchors without the switch:** extra targets are the `GATUS_ENDPOINTS` secret on the anchor's GitHub environment (a repository-level copy makes the banner refuse the managed dispatch), comma-separated `name=url` (`blog=https://blog.example.com`, HTTP(S) only) + re-dispatch. `main` and `platform` are reserved monitor names — a `GATUS_ENDPOINTS` pair using either fails the run.
- **seeded rows, honestly:** on a puller anchor the seeded rows exist regardless of your manifest — `platform`, `your piercloud` (your slice's health endpoint) and `private (gate)` (the Teleport login route); a `shared (gate)` row joins automatically while a `type: shared` site exists (Pocket ID's login route), and the `public edge` row (platform channel; the Cloudflare edge in front of your public sites) appears when the platform enables it. `your piercloud`, the gate rows and `public edge` stay **red** until the slice ships its health endpoint and the gates/edge are built; `your piercloud` replaces the retired `main` homepage row. The slice, gate, platform and edge rows page as night-emergency (class 5); your own site rows page time-sensitive (class 4, no recovery message).

Dynamic monitor changes (the puller) never touch tang, Caddy or the firewall, and the only credential involved is the same ntfy publish token your alerts already use: the puller writes only the Gatus fragment, its `.last-good` sibling, and its own state file, and every other anchor change stays dispatch-only ([docs/invariants.md](invariants.md)). If a manifest fetch fails, the last-known-good rows stay up and a push notice fires only after 3 consecutive failures; removals — including the derived `shared (gate)` row leaving with the last shared site — are notified by name.

## 10. External watch: always-on, GitHub-side (automatic)

`external-watch.yml` runs every 15 minutes on GitHub's network and probes the public dashboard: `HTTP 200`, the statuses API actually returning data, and an edge certificate valid for at least 14 more days. It is the third vantage point — Gatus runs *on* the anchor and the main-box canary on your main box, so if both go quiet, GitHub is the only watcher left standing (and the only one whose alert path does not die with either box). When the puller is enabled (`STATUS_PULLER` set), it also checks **who watches the puller**: each manifest must be HTTP 200 (404/410 = not published, skipped) with a `generated_at` no older than 24 h, and every monitored row (public manifest entries plus the seeded `platform` / gate / `your piercloud` rows and the derived `shared (gate)` / `public edge` rows; `shared`/`private` entries are not monitored, so not expected) must appear in the dashboard's public endpoint keys — a changed manifest that never reached Gatus means a dead puller timer or a frozen fragment. It also fails on the reverse: a dashboard row in a parsed channel's own group that the manifest does not justify (a stale derived gate/edge row or a removed site row) means the puller never applied the change. A change caught in the propagation window (up to the puller's ~10-minute cycle) reports once and clears on the next run.

- A failure files an issue labelled **`external-watch`** (open = failing, with the probe detail and a run link) and fails the run, so GitHub also notifies repo watchers. Recovery auto-comments and closes the issue.
- Push alerts need no extra setup: once `NTFY_TOPIC`/`NTFY_TOKEN` exist (§9), the watch pushes there too.
- A dispatch repo serving several managed anchors lists them in the repository variable `EXTERNAL_WATCH_TENANTS` (`alias` or `alias:puller`, comma- or space-separated; aliases follow the managed tenant grammar): one watch leg and one incident issue per tenant, probing `https://<alias>.status.piercloud.net/` (with the D6 checks when `:puller`). Managed values live in each anchor's environment, which a scheduled run cannot read, so the watch's own push channel is `EXTERNAL_WATCH_NTFY_TOPIC`/`EXTERNAL_WATCH_NTFY_TOKEN` (falling back to `NTFY_TOPIC`/`NTFY_TOKEN`). Unset = the single target above. A list the watch refuses (one bad entry refuses the whole list; the reason names the entry position and rule, never its text) falls back to that single target and opens a `watch config refused` incident. Tenants on the `pcu…` alias scheme cannot be listed (the managed grammar reserves that prefix). When you switch the list on or off, or remove or rename an alias, close the incidents that no longer match a leg by hand (see [docs/dr.md](dr.md)).
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
