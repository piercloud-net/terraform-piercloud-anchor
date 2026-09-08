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

**Server-ready email:** "Ihr vServer bei netcup ist bereitgestellt" (from donotreply@netcup.de) carries the hostname, IP, username, and root password — the password becomes the one-run `A1_ROOT_PASSWORD` repo secret (or the console login), and the printed SSH fingerprints let you verify the host key on first contact. The run locks root (`passwd -l root`) when done, so the emailed password dies after provisioning — delete it. Note the preconfigured firewall: the "netcup Mail Block" policy blocks SMTP both ways — remove it in SCP → Firewall only if you want SMTP alerts from the anchor.

Collect these as you go — each feeds one repo secret in §2. Where they go (phone path, primary): open the repo → `…` (top right) → Settings → Secrets and variables → Actions → **Secrets** tab → Repository secrets. Everything you paste goes there (the Variables tab holds operator pre-sets — nothing to touch). Always repository level — never Environment secrets/variables (the workflow's one Environment, `anchor`, is only a deployment-approval gate and holds no values).

- **customer number** (same value on both account emails) → `NETCUP_CUSTOMER_NUMBER` — also used as the SCP user id, unless `NETCUP_SCP_USER_ID` is set (a repo secret, only if yours differs)
- **anchor IPv4** (server-ready email, under "IP address" — paste verbatim, `203.0.113.10/22`-style suffix included; the run strips it) → `NETCUP_ANCHOR_IPV4` — the run also resolves `server_id` from it, so no numeric id to copy anywhere
- **root password** (server-ready email) → `A1_ROOT_PASSWORD`
- **monitor targets** (your main server's services, by DNS name — comma-separated `name=url`, e.g. `main=https://example.com,blog=https://blog.example.com`; HTTP(S) only) → `GATUS_ENDPOINTS` repo *secret* (your service map stays write-only)
- nothing else to enter: your username, hostname, and DNS are pre-set in the repo — dispatch takes no identifiers

Why is the one-run password a *stored* secret instead of a dispatch input? Dispatch inputs persist on the run record, visible to anyone who can view the repo — and this template defaults public — so an input would publish the password. A repo secret is write-only and log-masked; combined with `passwd -l root` at the end of the run plus deleting the secret afterwards, the password's validity dies with the provisioning.

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
# secrets (write-only)
gh secret set NETCUP_CUSTOMER_NUMBER  # username on both account emails
gh secret set NETCUP_ANCHOR_IPV4      # piko IP ("IP address" in server email)
gh secret set A1_ROOT_PASSWORD        # one-run — delete after use
# optional push channel (empty = verdict stays in the run summary)
gh secret set NTFY_TOPIC
gh secret set NTFY_TOKEN              # publish-scoped
# monitor targets, comma-separated name=url (HTTP(S) only)
gh secret set GATUS_ENDPOINTS         # e.g. main=https://example.com
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

If your repo has you as a reviewer (power path), GitHub pauses the run first: approve the pending deployment (check the commit matches the banner card), THEN approve the netcup code below. Two taps, in that order — the first approves WHAT runs, the second lets it touch your account. Without a reviewer identity the run proceeds straight to the code, and the LOUD banner is your check.

The run prints a netcup device-flow URL + `XXXX-XXXX` user code (and sends
them via ntfy). You approve at netcup's own Keycloak (your
session, your 2FA, ~600s window) — the approval is one tap, phone browsers included. The runner polls, receives an ephemeral
token, provisions, and the token dies with the runner. Only the URL + code
(+ alias) are ever printed — `curl -sS`, no `-v`, no `TF_LOG`, device
secret masked first. The card carries, verbatim: "we will never email or message you a code to re-confirm." If the device grant is ever disabled:
STOP + open an issue in your repo so the operator sees it (C-A — no fallback exists, none is permitted).

## 4. A1 provisions, thumbprint lands via run artifact (H1 chain)

The run opens the hardened A1 self-open /32 SSH window, provisions the
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
