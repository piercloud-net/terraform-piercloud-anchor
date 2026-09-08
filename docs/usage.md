# Usage — end-to-end walkthrough

From zero to an unattended-booting encrypted main box, runnable END-TO-END
from any browser — laptop or phone. Time: ~30 minutes, mostly
netcup web UI + taps.

Flow: order piko → repo from template → workflow dispatch →
device-flow approval → A1 provisions → thumbprint via ntfy + artifact +
committed file → clevis bind → monthly one-tap check.

Related: [dr.md](dr.md) (DR table, decision tree, day-1 checklist) ·
[invariants.md](invariants.md) (S1 / C-A review blockers).

## 0. What you need

- A netcup account (identity verification happens at order time).
- A browser (laptop or phone) + a password manager (PM).
- Your main box: any Debian-family machine with a LUKS-encrypted root.
- Your main box's public IPv4 — the only address allowed to reach tang.
  Anchor IPv4 is REQUIRED (runners have no IPv6); v6-only is unsupported.

## 1. Order the anchor ("piko"-class VPS)

In the netcup SCP (web UI, TOTP 2FA), order a small VPS — the [VPS pico G11s](https://www.netcup.com/en/server/vps/vps-pico-g11s-iv-12m-nue) (~€1.90/mo VAT-incl, 12-mo term, Nürnberg) is plenty for tang +
Gatus. Official Debian-family image, root password by email. Do NOT apply a welcome voucher: pico products can't be combined with vouchers (the voucher exceeds the cart minimum), so the order won't submit. Ordering isn't instant: netcup staff manually review new orders — you'll get an email ("Your order will be checked by one of our employees shortly") and a follow-up once it's through. Wait for that before provisioning.

**First login (CCP):** the "Your login credentials for the netcup CCP" email holds your customer number + password. Log in at <https://www.customercontrolpanel.de/> (paste both, select "I don't process personal data"), open the personal page (person icon), change the password, then scroll to two-factor authentication and enable it: tap (or right-click) the QR code to save it to your password manager, then copy the temporary code from the PM back to confirm. Finally check the 💵 tab that the invoice is paid — if not, pay it via the 💳 next to "unpaid".

**SCP login (separate credentials):** the server control panel at <https://www.servercontrolpanel.de/SCP/> uses its own password, sent in the "Access data for SCP" email — change it on first login and enable 2FA there too.

**Server-ready email:** "Ihr vServer bei netcup ist bereitgestellt" (from donotreply@netcup.de) carries the hostname, IP, username, and root password — the password becomes the one-run `A1_ROOT_PASSWORD` input (or the console login), and the printed SSH fingerprints let you verify the host key on first contact. The run locks root (`passwd -l root`) when done, so the emailed password dies after provisioning — delete it. Note the preconfigured firewall: the "netcup Mail Block" policy blocks SMTP both ways — remove it in SCP → Firewall only if you want SMTP alerts from the anchor.

Collect these as you go — each feeds one repo secret in §2:

- **username** you sign up with (e.g. `pier`) → entered as `server_alias` at dispatch; hostname (`anchor-pier-01`) and DNS derive from it, nothing to copy
- **customer number** (same value on both account emails) → `NETCUP_CUSTOMER_NUMBER` — also used as the SCP user id, unless `NETCUP_SCP_USER_ID` is set (only if yours differs)
- **anchor IPv4** (server-ready email, under "IP address") → `NETCUP_ANCHOR_IPV4` — the run also resolves `server_id` from it, so no numeric id to copy anywhere
- **root password** (server-ready email) → `A1_ROOT_PASSWORD`

Why is the one-run password a *stored* secret instead of a dispatch input? Dispatch inputs persist on the run record, visible to anyone who can view the repo — and this template defaults public — so an input would publish the password. A repo secret is write-only and log-masked; combined with `passwd -l root` at the end of the run plus deleting the secret afterwards, the password's validity dies with the provisioning. (The SSH keys are public material and could travel either way; they live in secrets for uniformity.)

Single anchor t:1 is the product (a twin anchor at a different provider is
a T2 opt-in via `extra_tang_urls` — see [dr.md](dr.md)).

## 2. Repo from template + repo secrets (C-E visibility rule)

"Use this template" → your repo. **No stored netcup secrets of any kind
(S1)** — every run authenticates via your per-run approval below. What
lives in REPO-level secrets are identifiers only (anchor IP, customer
number, OIDC URL): values are write-only and log-masked.
Paste them in your repo — `gh` prompts for each value so nothing touches
shell history:

```bash
# identifiers (order + server-ready emails)
gh secret set NETCUP_CUSTOMER_NUMBER  # username on both account emails
gh secret set NETCUP_ANCHOR_IPV4      # piko IP ("IP address" in server email)
# one-run provisioning inputs (emailed root password dies after use — delete it)
gh secret set A1_ROOT_PASSWORD
gh secret set A1_SSH_PUBKEY_1         # your admin keys (mandate: 2)
gh secret set A1_SSH_PUBKEY_2
gh secret set NETCUP_OIDC_DISCOVERY_URL  # https://www.servercontrolpanel.de/realms/scp/.well-known/openid-configuration
# optional push channel (empty = verdict stays in the run summary)
gh secret set NTFY_TOPIC
gh secret set NTFY_TOKEN              # publish-scoped
```

### Operator values (not for tenants)

Two tiers, both operator-held — tenants never touch either. The slice IP is assigned by the operator, so the tenant never sets it:

- **Org secret** (once): `CLOUDFLARE_DNS_TOKEN` — zone-scoped DNS:Edit on `piercloud.net`, visibility all repos. The run upserts each tenant's anchor record with it.
- **Per tenant repo** (at creation; inventory lives in pcad.it-infra):

```bash
gh secret set NETCUP_MAIN_BOX_IPV4    # tenant slice IP
gh variable set TENANT_USER --body "pier"  # pins which alias this repo may dispatch (fail-closed)
# only if it differs from the customer number:
# gh secret set NETCUP_SCP_USER_ID
```

Self-serve template users set `TENANT_USER` themselves (typo guard); operator-provisioned tenants get it pinned at handover. Slice moves use `mode=update-ip` (ADD-before-move, §7) — the operator requests, the OWNER executes.

Visibility rule (C-E): identifiers in secrets always; public default once
secrets land (values stay invisible to forks); env gate wherever a tenant
reviewer identity exists. The approval card shows the exact commit
(short+full head SHA + compare-diff link + workflow file count with an
UNCHANGED/CHANGED banner). The repo is authoritative for execution; any UI
is advisory display only.

## 3. Dispatch and approve (S1)

Actions → [`provision.yml`](../.github/workflows/provision.yml) → `mode=apply`, from any browser. The ONLY
identifier in the dispatch inputs is `server_alias` — enter your username
(e.g. `pier`); hostname and DNS derive from it. Everything sensitive
resolves from repo secrets inside the run.

The run prints a netcup device-flow URL + `XXXX-XXXX` user code (and sends
them via ntfy). You approve at netcup's own Keycloak (your
session, your 2FA, ~600s window) — the approval is one tap, phone browsers included. The runner polls, receives an ephemeral
token, provisions, and the token dies with the runner. Only the URL + code
(+ alias) are ever printed — `curl -sS`, no `-v`, no `TF_LOG`, device
secret masked first. The card carries, verbatim: "we will never email or message you a code to re-confirm." If the device grant is ever disabled:
STOP + escalate (C-A — no fallback exists, none is permitted).

## 4. A1 provisions, thumbprint lands three ways (H1 chain)

The run opens the hardened A1 self-open /32 SSH window, provisions the
anchor (mandate: 2 SSH keys at A1; the script ends with `passwd -l root`;
console-recovery note: rescue disables the netcup firewall — any rescue
boot → rotate tang keys afterwards), then closes the window
(detach-then-delete, swept pre + `always()` post, all modes).

The tang thumbprint reaches you via the H1 chain — run artifact
(`retention-days: 400` = artifacts ONLY) + committed break-glass file via
reviewable PR from a separate App identity. Never rely on logs alone (repo
logs live 90d/400max, runs/checks get deleted). `mode=check` warns on the
repo retention setting. **Save the thumbprint in your PM NOW** (and finish
the [day-1 checklist](dr.md#day-1-off-device-checklist)).

The run also creates/verifies the anchor DNS record (`anchor-<alias>-01.piercloud.net` → anchor IPv4) automatically, after A1 close and before any thumbprint goes out.

## 5. Bind your main box (clevis)

On your **main box**:

```bash
apt-get install clevis clevis-luks clevis-initramfs
# find your LUKS device: lsblk -f
clevis luks bind -d <device> tang '{"url":"http://anchor-pier-01.piercloud.net"}'
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

One dispatch: drift report + orphan list +
retention-setting warning + versions-behind notice. Under S1 there is
nothing to keep alive (no stored tokens) — missed months degrade
visibility, never availability.

## 7. Tenant move: `mode=update-ip` (ADD-before-move)

Main box moved and its IP changed? Dispatch `mode=update-ip` with
`add_ipv4`/`add_ipv6` (optional `remove_ipv4`): the new IP is ADDED first,
the old kept during transition, removed only after confirmed boot.
Operator requests, OWNER executes; a batch move = N per-tenant approvals,
never one operator token.

## 8. Destroy: `mode=destroy` (policy + attachment ONLY)

Requires `ack_main_unbound` (confirm the main box is unbound first) +
canary-fail proof. Tears down the firewall policy + attachment only — the
server and the tang keys are untouched.

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
  allowlist grep from `main`); operator tooling never offers tang-key
  management.
