# terraform-piercloud-anchor

One-click **tang/clevis NBDE anchor** for your server: an OpenTofu module that
turns a small always-on VPS (netcup) into a network-bound disk-unlock server,
plus an uptime monitor — so your encrypted main box can boot unattended, and
you find out if the anchor ever goes down.

**Your disk is ciphertext. You hold the keys. Your host cannot read your data,
even with root.**

Words you'll meet: **thumbprint** = the anchor's key fingerprint (a short
string you compare by eye); **bind** = telling your main box to trust that
thumbprint at boot; **keyslot** = one of the LUKS unlock methods on your disk
(your passphrase lives in one — it is the true root); **initramfs** = the tiny
early-boot system that asks the anchor for the key; **A1** = the one-run
admin session used to install the anchor.

## Why this exists (NBDE in one paragraph)

Full-disk LUKS encryption has an old problem: an encrypted server cannot boot
unattended — something must supply the unlock key at boot. **NBDE (Network-Bound
Disk Encryption)** solves this with two small pieces: at boot, `clevis` in the
initramfs of your main box asks a tiny always-on **tang** server for a key,
combines it with a key the disk already holds, and unlocks — a
challenge-response exchange where no secret ever travels on the wire. You keep
the **LUKS passphrase keyslot (in your password manager) as the true root**;
tang is *availability*, never the security anchor. The classic primer:
[An easier way to manage disk decryption at boot (Red Hat)](https://www.redhat.com/en/blog/easier-way-manage-disk-decryption-boot-red-hat-enterprise-linux-75-using-nbde)

## What this module does — and what you do yourself

**You order the server manually** (netcup requires manual identity
verification anyway). The module then *adopts* it by `server_id` or exact
server name — it does not create or destroy servers (the netcup SCP API cannot)
— and configures:

- the server's SCP attributes (hostname, OS optimization, autostart),
- a firewall policy scoped to your main box plus the Cloudflare edge: **TCP/80 ingress from your main
  box IP and the Cloudflare edge ranges only, TCP/443 from the edge only** (tang speaks plain HTTP by design — ECDH + thumbprint
  pinning provide the cryptography; the narrow firewall provides the control; the dashboard lives behind the orange cloud, so the edge must reach the origin),
  with an explicit egress ACCEPT-all so the anchor can always answer,
- the firewall attachment on the anchor's network interface.

Then **the dispatched run** ([`provision.yml`](.github/workflows/provision.yml)
`mode=apply` → device-flow approval) opens its own /32
window and provisions the anchor: installs `tang`, prints its
**thumbprint**, and installs Docker + the **Gatus** availability
monitor — dispatch-managed config, no admin account, no UI bootstrap. The script
generates the tang keypair **on the box**; nothing it prints is secret
except the thumbprint you choose to save.

The module provisions **no SSH access and no standing credentials** — inbound
or outbound. Nobody logs into the anchor: every change arrives through a
per-run approved dispatch (the runner is the admin path). Re-entry after the
root lock is per-event (reset the root password in SCP → set the one-run
secret → re-dispatch); rescue mode stays the last resort (it disables the
netcup firewall — any rescue boot → rotate tang keys afterwards).

## The flow, for a first-time user

Every step below runs from any browser — laptop or phone; phone browsers work for the whole flow, including the approval tap.

1. **Order the anchor** — in the netcup shop (buying happens there; the SCP manages servers you already own): the [VPS pico G11s](https://www.netcup.com/en/server/vps/vps-pico-g11s-iv-12m-nue)
   (~€1.90/mo VAT-incl, 12-mo term) is plenty; any Debian-family image,
   root password by email. Skip the welcome voucher (pico can't be combined
   with vouchers — the order won't submit). Ordering isn't instant (staff review;
   wait for netcup's email, then first logins (CCP + SCP): new passwords +
   2FA + invoice check). Anchor IPv4
   is REQUIRED (runners have no IPv6; v6-only unsupported). Note the
   anchor's IP ("IP address" in netcup's server-ready email). Hostname,
   DNS, and the slice IP come pre-configured — nothing to pick.
   *(details: [walkthrough §1](docs/usage.md#1-order-the-anchor-piko-class-vps))*
2. **Repo from template + repo values** — "Use this template", then set
   repo secrets (customer number — the one required secret —
   monitor targets, optional ntfy). No stored netcup API
   tokens of any kind (S1): every run authenticates via your per-run
   approval. The main-box IP,
   DNS, and your username come pre-configured in your repo — nothing to
   enter. Public default once
   values land (write-only, log-masked, invisible to forks).
   *(details: [walkthrough §2](docs/usage.md#2-repo-from-template--repo-secrets-c-e-visibility-rule))*
3. **Dispatch + approve** — Actions → [`provision.yml`](.github/workflows/provision.yml)
   `mode=apply` (no identifiers in the inputs — your username already lives
   in the repo) →
   approve the device-flow URL + code at netcup's own Keycloak, from any browser. The
   ephemeral token dies with the runner. *(details: [walkthrough §3](docs/usage.md#3-dispatch-and-approve-s1))*
4. **A1 provisions** — the run opens its own /32 window, installs `tang`,
   creates/verifies the anchor DNS record (`anchor-<alias>-01.piercloud.net`),
   prints its **thumbprint** (to run artifact today — ntfy push + committed
   break-glass file pending; never logs alone), installs the Gatus monitor, and
   ends with `passwd -l root`. **Save the thumbprint in your password
   manager NOW**, then finish the
   [day-1 checklist](docs/dr.md#day-1-off-device-checklist).
   *(details: [walkthrough §4](docs/usage.md#4-a1-provisions-thumbprint-lands-three-ways-h1-chain))*
5. **Monitor (automatic, extend later)** — the run already watches your
   homepage (`https://<you>.piercloud.net`, derived from your username) plus
   tang itself, and prints the statuses into the run log. More targets later:
   set the `GATUS_ENDPOINTS` repo secret to comma-separated `name=url` pairs
   (`blog=https://blog.example.com`, HTTP(S) only) and re-dispatch
   `mode=apply`. Probe **by DNS name** so the monitor follows migrations
   automatically.
6. **Bind your main box** — install `clevis clevis-luks clevis-initramfs`,
   run the printed `clevis luks bind` command against the DNS name
   (`anchor-<alias>-01.piercloud.net`, e.g. `anchor-pier-01.piercloud.net`), confirming the thumbprint matches
   out-of-band — never `-y` blind — then rebuild the initramfs.
   *(details: [walkthrough §5](docs/usage.md#5-bind-your-main-box-clevis))*
7. **Reboot-test twice + monthly one-tap check.** The unlock prompt may
   flash, then continue on its own when clevis reaches the anchor. That is
   success. Keep the passphrase keyslot forever — it is the true root.
   `mode=check` monthly is hygiene, not load-bearing. *([walkthrough §6](docs/usage.md#6-monthly-one-tap-modecheck-hygiene-not-load-bearing),
   docs/dr.md)*

## Quickstart

```bash
# 0. Order a small netcup VPS ("piko" class is plenty) in the netcup shop, install any
#    Debian-family OS. The run discovers the server itself — no IP to copy.
# 1. "Use this template" on GitHub, set the repo values
#    (customer number — the one required secret — plus monitor targets) — no netcup tokens stored.
# 2. Dispatch the provision.yml workflow (Actions tab, mode=apply)
#    from any browser (no identifiers to enter), and approve the device-flow
#    code at netcup's Keycloak.
# 3. Save the tang thumbprint (run artifact under the Actions run —
#    ntfy push + committed break-glass file pending) in your password manager NOW.
```

Module consumers (registry/GitHub source, `examples/quickstart` as the root
module) pass the same variables the workflow resolves from repo secrets —
`server_id` (stable key; policy name
`piercloud-anchor-${hostname}-${server_id}`), `allow_main_box_ipv4`
(`203.0.113.10`-style), `hostname`, `scp_user_id` — with the provider token
arriving ephemerally per run (never stored). Full walkthrough (including
the `clevis luks bind` on your main box and the reboot test):
[docs/usage.md](docs/usage.md).

## What YOU must do

1. **Save the thumbprint** from the run's artifact (Actions → the run →
   Artifacts) in your password manager the moment provisioning finishes.
   You will compare it by eye when binding your main box.
2. **Wire your main box — at its keyboard, not your phone**: install
   `clevis clevis-luks clevis-initramfs`, run
   the printed `clevis luks bind -d /dev/sda3 tang '{"url":"http://anchor-pier-01.piercloud.net"}'`
   (your LUKS device — find it with `lsblk -f`, see walkthrough §5)
   — confirming the thumbprint matches what you saved — then
   `update-initramfs -u` and reboot-test twice.
3. **Keep the passphrase keyslot.** The tang anchor is convenience and
   availability; the passphrase is the true root. If the anchor dies, you
   unlock with the passphrase.
4. **Watch your server from the anchor.** The run installs Gatus on the
   anchor — an independent, always-on vantage point *outside* your main box.
   Monitors are dispatch-managed: your homepage is watched automatically;
   extra targets go in the `GATUS_ENDPOINTS` repo secret +
   re-dispatch `mode=apply`, read the statuses in the run log. Probe your
   main server's services **by DNS name** (Gatus never caches DNS,
   so when you migrate and flip the record, the monitor follows automatically
   and the availability history stays continuous across the cutover), and
   set the `NTFY_TOPIC` secret so failures are
   **pushed** to you, not waiting on a dashboard.
5. **Understand the anchor**: it is an unencrypted, always-on box whose only
   job is holding an unlock key and answering clevis challenges. It holds
   *no* credential that reaches your main box. **You administer the anchor;
   the anchor administers nothing.**

## The two hard invariants

- **Tang keys never touch Terraform state.** The keypair is generated on the
  anchor by the script — never by the module — so no unlock key can leak into
  state, plan output, or CI. CI asserts key material stays out of tracked
  files; the script fails loudly if state files appear near the key material.
- **The anchor is a key-holder, never an access-path.** It holds no SSH keys,
  tokens, or sockets that reach your main box; the only cross-box interaction
  is answering clevis challenges on TCP/80 from your main box IP. If the
  anchor is compromised, the worst outcome is that an attacker could have
  answered a boot-time challenge — not a path into your main box.

## Trust: what we can and cannot do

Single anchor t:1 is the product (a twin anchor at a different provider
is a T2 opt-in, never the default). Emergency-unlock ladder: T0 baseline
(passphrase in PM + dropbear paste + break-glass card) · T1 advised
(WireGuard peer in initramfs, Gatus ALERTs, PM emergency kit + recovery
codes day-1, printed off-device) · T2 opt-in (BYO twin anchor,
`extra_tang_urls`, SSS t-of-2 at a DIFFERENT provider). Details:
[docs/dr.md](docs/dr.md).

The paragraphs below are the standing disclosure — quoted verbatim in
the UI as well:

> GitHub plane: "fresh VMs in Microsoft Azure, created for your job and destroyed after it, operated by GitHub — not by piercloud… every approval card shows the exact commit your provisioning will run, and it will refuse to proceed if that commit changed since you last approved."
>
> Operator plane: netcup token exists only in runner memory, "we cannot decrypt, and the logs we can read prove we never held the key."
>
> Hypervisor-RAM floor: "In the normal path the operator backend never receives, stores, or logs your recovery key… We cannot prove this to you cryptographically today — the installer and first-boot scripts are our code on our hardware… (disclosed; cryptographically closable only with SEV-SNP attestation, on our roadmap)."
>
> "piercloud never holds your keys. Your netcup account, your LUKS passphrase, your tang thumbprint. We run the plumbing and can see when your server last called home — nothing more. Fire us any day."
>
> "Disk unlock uses NBDE (clevis→tang) with a passphrase recovery keyslot; synced passkeys cannot reach Linux initramfs, so LUKS is not bound to passkeys."

Jurisdiction, honestly: FR box / DE anchor / IT operator — EIO or direct
e-Evidence orders are delay plus two-compulsion cost, NOT prevention;
rotation is forward security only.

### Data: at rest, in transit, at runtime

**Encrypted to your instance, unreadable at rest by the host, runtime confidentiality arriving via attested confidential computing — and an application-level encryption layer available on top for apps that want it.**

- **At rest — ciphertext.** Your disks are LUKS-encrypted with keys the host never holds: seizure, a disk copy, or root on the host yields ciphertext only.
- **In transit — disclosed edge.** A service can be served directly (TLS terminates in your own instance — no third party in the data path) or behind the piercloud edge on Cloudflare when you want its DDoS protection. When proxied, Cloudflare terminates visitor TLS and can see request content in memory — no default log retention, but US legal process applies under Cloudflare's DPA. An application-level encryption layer between client and origin — the origin can decrypt it, unless the app is fully end-to-end encrypted — is the only way a proxied site's content stays unreadable to the edge (transport TLS is terminated by Cloudflare, not by your VM).
- **At runtime — the disclosed floor.** Today the host can read running instance memory (accepted and disclosed). Phase 2 closes it with confidential computing (AMD SEV-SNP): per-VM memory encryption plus remote attestation that your own verifier checks before keys are released (side-channel limits are documented, not hidden).

Visibility (C-E): identifiers in repo secrets always; public default once
secrets land; the approval card is LOUD about what commit you approve
(and shows SHA + diff vs default branch today; refuse-on-change pin pending the backend recorder); the repo is authoritative, any UI advisory.
Thumbprint chain (H1): run artifact today (Actions → run → Artifacts,
`retention-days: 400` = artifacts only — never rely on logs alone); ntfy +
committed break-glass file via reviewable App PR are PENDING; `mode=check`
warns on the repo retention setting.

## Versioning & pinning

Releases are tagged `vX.Y.Z` (with curated GitHub releases; automatic
prereleases on `main`). Pin the module in your root module like:

```hcl
source = "piercloud-net/anchor/piercloud"
# or from GitHub directly:
source = "github.com/piercloud-net/terraform-piercloud-anchor?ref=v0.1.0"
```

During the 0.x series, floating references `?ref=v0` and `?ref=v0.0` exist and
track the latest 0.x release; after the 1.0.0 release, `?ref=v1` follows it.

## Provider

This module uses the community provider [`rixlhq/netcup`](https://registry.terraform.io/providers/rixlhq/netcup/latest/docs)
(netcup has no official Terraform/OpenTofu provider). The netcup token exists
only in per-run runner memory via your device-flow approval (S1) — never
in code, never committed, never stored.

## Public-reader note

This repository is a small, self-contained, open-source tool. It documents
exactly what you see here — nothing about who runs it, at what scale, or why
beyond what the README states. Please don't infer more.

## License

Apache-2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

The piercloud name and logo are not licensed: no endorsement by, or affiliation
with, the piercloud project is implied by use of this module.
