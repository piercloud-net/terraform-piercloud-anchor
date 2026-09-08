# Usage — end-to-end walkthrough

From zero to an unattended-booting encrypted main box, runnable END-TO-END
from any browser — laptop or phone. Time: ~30 minutes, mostly
netcup web UI + taps.

Flow: order piko → repo from template → workflow dispatch →
device-flow approval → A1 provisions → thumbprint via run artifact (Actions →
run → Artifacts; ntfy push + committed break-glass file pending) → clevis
bind → monthly one-tap check.

Related: [dr.md](dr.md) (DR table, decision tree, day-1 checklist) ·
[invariants.md](invariants.md) (S1 / C-A review blockers).

## 0. What you need

- A netcup account (identity verification happens at order time).
- A browser (laptop or phone) + a password manager (PM).
- Your main box: any Debian-family machine with a LUKS-encrypted root.
- Your main box's public IPv4 — the run allows ONLY this address to reach
  tang. It comes pre-configured (pinned from your signup) — nothing to
  enter. Wrong/CGNAT-shared IP = locked out at first reboot: if your main
  box sits behind CGNAT, open a repo issue BEFORE dispatching.
  Anchor IPv4 is REQUIRED (runners have no IPv6); v6-only is unsupported.

## 1. Order the anchor ("piko"-class VPS)

In the netcup SCP (web UI, TOTP 2FA), order a small VPS — the [VPS pico G11s](https://www.netcup.com/en/server/vps/vps-pico-g11s-iv-12m-nue) (~€1.90/mo VAT-incl, 12-mo term, Nürnberg) is plenty for tang +
Gatus. Official Debian-family image, root password by email. Do NOT apply a welcome voucher: pico products can't be combined with vouchers (the voucher exceeds the cart minimum), so the order won't submit. Ordering isn't instant: netcup staff manually review new orders — you'll get an email ("Your order will be checked by one of our employees shortly") and a follow-up once it's through. Wait for that before provisioning.

**First login (CCP):** the "Your login credentials for the netcup CCP" email holds your customer number + password. Log in at <https://www.customercontrolpanel.de/> (paste both, select "I don't process personal data"), open the personal page (person icon), change the password, then scroll to two-factor authentication and enable it: tap (or right-click) the QR code to save it to your password manager, then copy the temporary code from the PM back to confirm. Finally check the 💵 tab that the invoice is paid — if not, pay it via the 💳 next to "unpaid".

**SCP login (separate credentials):** the server control panel at <https://www.servercontrolpanel.de/SCP/> uses its own password, sent in the "Access data for SCP" email — change it on first login and enable 2FA there too.

**Server-ready email:** "Ihr vServer bei netcup ist bereitgestellt" (from donotreply@netcup.de) carries the hostname, IP, username, and root password — you can ignore the password entirely (leave `ANCHOR_ROOT_PASSWORD` unset: the run mints its own one-time password via the API and locks root when done). Keep the email for the printed SSH fingerprints to verify the host key on first contact. Note the preconfigured firewall: the "netcup Mail Block" policy blocks SMTP both ways — remove it in SCP → Firewall only if you want SMTP alerts from the anchor.

Collect these as you go — each feeds one repo secret in §2. Where they go (phone path, primary): open the repo → `…` (top right) → Settings → Secrets and variables → Actions → **Secrets** tab → Repository secrets. Everything you paste goes there (the Variables tab holds operator pre-sets — nothing to touch). Always repository level — never Environment secrets/variables (the workflow's one Environment, `anchor`, is only a deployment-approval gate and holds no values).

- **customer number** (same value on both account emails) → `CUSTOMER_NUMBER` — the ONE required secret (provider credential only; the SCP user id resolves itself from your approval token — override via `SCP_USER_ID` repo secret only if yours differs)
- nothing else to enter: your username, hostname, anchor IP, DNS, and default monitor (your homepage) are pre-set or derived — dispatch takes no identifiers

Create them here: [👉 Repo → Settings → Secrets → New repository secret](../../../settings/secrets/actions/new) (one per value above).

Secrets set? Dispatch now: [👉 Actions → provision.yml → Run workflow](../../../actions/workflows/provision.yml) (`mode` preselects `apply`).

Single anchor t:1 is the product (a twin anchor at a different provider is
a T2 opt-in via `extra_tang_urls` — see [dr.md](dr.md)).

## 2. Repo from template + repo secrets (C-E visibility rule)

"Use this template" → your repo. **No stored netcup API tokens of any kind
(S1)** — every run authenticates via your per-run approval below (the one-run A1 root password is the single exception: write-only, locked out + deleted after use). What
lives in the repo are identifiers only (anchor IP, customer
number) plus your monitor targets: values are write-only and log-masked.
Your username lives in the pre-set `TENANT_USER` variable — nothing to enter.
Set once via the taps above, or CLI (secrets prompt so nothing touches shell
history). Laptop/CLI path (power users) — phone users can skip this block, it sets the same values as the taps above:

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

Visibility rule (C-E): identifiers in secrets always; public default once
secrets land (values stay invisible to forks); env gate wherever a tenant
reviewer identity exists. The approval card shows the exact commit
(short+full head SHA + compare-diff link + workflow file count with an
UNCHANGED/CHANGED banner). The repo is authoritative for execution; any UI
is advisory display only.

## 3. Dispatch and approve (S1)

Actions → [`provision.yml`](../.github/workflows/provision.yml) → `mode=apply`, from any browser. Dispatch takes the mode (plus action flags) — no identifiers: your username already lives in the repo's `TENANT_USER` variable, and everything sensitive
resolves from repo secrets inside the run.

Only the URL + code (+ alias) are ever printed — `curl -sS`, no `-v`, no `TF_LOG`. The short-lived code is deliberately NOT `::add-mask::`-masked (masks silently break the job-handoff outputs); instead it is never printed beyond the card, never stored, dead in 600s, and useless without your own netcup session. The access token stays masked and never crosses jobs.

If your repo has you as a reviewer (power path), GitHub pauses the run first: approve the pending deployment (check the commit matches the banner card), THEN approve the netcup code below. Two taps, in that order — the first approves WHAT runs, the second lets it touch your account. Without a reviewer identity the run proceeds straight to the code, and the LOUD banner is your check.

The run prints a netcup device-flow URL + `XXXX-XXXX` user code (plus a push via ntfy, once you set that up later — see §8). You approve at netcup's own Keycloak (your
session, your 2FA, ~600s window) — the approval is one tap, phone browsers included. The runner polls, receives an ephemeral
token, provisions, and the token dies with the runner. Only the URL + code
(+ alias) are ever printed — `curl -sS`, no `-v`, no `TF_LOG` (masking note: the access token stays masked; the short-lived code is unmasked-by-design, see above). The card carries, verbatim: "we will never email or message you a code to re-confirm." If the device grant is ever disabled:
STOP + open an issue in your repo so the operator sees it (C-A — no fallback exists, none is permitted).

## 4. A1 provisions, thumbprint lands via run artifact (H1 chain)

The run first sets its own one-time root password when none was pasted (one power-cycle — machine-wait, no tap needed; concurrent runs serialize on a lock-wait), then opens the hardened A1 self-open /32 SSH window and provisions the
anchor (no standing SSH keys by design: the script ends with `passwd -l root`;
console-recovery note: rescue disables the netcup firewall — any rescue
boot → rotate tang keys afterwards), then closes the window
(detach-then-delete, swept pre + `always()` post, all modes). Key rotation:
dispatch `mode=apply` with `rotate_keys=true` (forwards `--rotate` to the
provisioning script: dots out old tang keys per netcup procedure).

The tang thumbprint reaches you via the H1 chain — run artifact
(`retention-days: 400` = artifacts ONLY; committed break-glass file via
reviewable App PR pending). Never rely on logs alone (repo
logs live 90d/400max, runs/checks get deleted). `mode=check` warns on the
repo retention setting. **Save the thumbprint in your PM NOW** (and finish
the [day-1 checklist](dr.md#day-1-off-device-checklist)).

The run also creates/verifies the anchor DNS record (`anchor-<alias>-01.piercloud.net` → anchor IPv4) automatically, after A1 close and before any thumbprint goes out.

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
clevis luks bind -d /dev/sda3 tang '{"url":"http://anchor-pier-01.piercloud.net"}'
```

**Verify the thumbprint** shown at bind time against the value you saved
in step 4 — out-of-band, never `-y` blind. If it doesn't match, answer NO
and investigate. Binding the DNS name (`anchor_hostname`) means a future
same-URL rebuild is just `regen` (see [dr.md](dr.md)). Then:

```bash
update-initramfs -u
```

(Debian note: for some remote-unlock setups the initramfs needs an `IP=`
line in `/etc/initramfs-tools/initramfs.conf` to bring the network up —
if the boot prompt never clears, check that first.)

Keep the passphrase keyslot forever — it is the true root. Disk unlock
uses NBDE (clevis→tang) with a passphrase recovery keyslot; tang is
availability, never the security anchor.

## 6. Monthly one-tap `mode=check` (hygiene, not load-bearing)

Planned — check mode currently answers a skeleton; the full drift/orphan/retention/versions report lands with live M0. Design: one dispatch:
retention-setting warning + versions-behind notice. Under S1 there is
nothing to keep alive (no stored tokens) — missed months degrade
visibility, never availability. Until it lands, compare the anchor's policy
in SCP → Firewall against the last run summary by eye.

## 7. Tenant move: `mode=update-ip` (ADD-before-move)

Planned — the mode currently answers a skeleton; ADD-before-move enforcement lands with live M0. Design: main box moved and its IP changed? Dispatch `mode=update-ip` with
`add_ipv4`/`add_ipv6` (optional `remove_ipv4`): the new IP is ADDED first,
the old kept during transition, removed only after confirmed boot.
Move requests arrive with the new IP; you dispatch the update-ip yourself — a batch move = N per-run approvals, never one shared token. Until it lands, open a repo issue with the new IP and the operator updates the policy.

## 8. Destroy: `mode=destroy` (policy + attachment ONLY)

Planned — enforcement (including the canary-fail proof gate) lands with live M0. Design: requires `ack_main_unbound` (confirm the main box is unbound first) +
canary-fail proof. Tears down the firewall policy + attachment only — the
server and the tang keys are untouched. Until it lands, delete nothing yourself — open a repo issue.

## 8. Explore later: push alerts + extra monitors (optional, after the bind)

The anchor already watches your homepage and tang itself, and prints statuses into the run log. When you want taps on the shoulder instead:

- install the [ntfy app](https://ntfy.sh), subscribe to any random topic name (yours), then set repo secrets `NTFY_TOPIC` (that name) + `NTFY_TOKEN` only if your ntfy server needs auth (empty for ntfy.sh hosted) — re-dispatch `mode=apply` to take effect.
- extra targets: `GATUS_ENDPOINTS` repo secret, comma-separated `name=url` (`blog=https://blog.example.com`, HTTP(S) only) + re-dispatch.

## What this repo never does

- No stored netcup tokens, no crons (S1) — every netcup use is
  human-approved per run via the device flow.
- No credentials in code, state, or CI. Tang keys are generated on the
  anchor and never enter terraform state; CI greps tracked files for key
  material (patterns enforced from `main`).
- No sovereignty-downgrade fallback, ever (C-A) — failed check = no apply.
- The anchor holds no credential that reaches your main box (its only
  cross-box interaction is answering clevis challenges on TCP/80).
- Workflows never touch rescue/image/snapshot/iso/disk surfaces (CI
  allowlist grep from `main`); tang-key management is never offered
  through automation.
