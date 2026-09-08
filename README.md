# terraform-piercloud-anchor

One-click **tang/clevis NBDE anchor** for your server: an OpenTofu module that
turns a small always-on VPS (netcup) into a network-bound disk-unlock server,
plus an uptime monitor — so your encrypted main box can boot unattended, and
you find out if the anchor ever goes down.

**Your disk is ciphertext. You hold the keys. Your host cannot read your data,
even with root.**

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
- a firewall policy scoped to your main box: **TCP/80 ingress from your main
  box IP only** (tang speaks plain HTTP by design — ECDH + thumbprint
  pinning provide the cryptography; the narrow firewall provides the control),
  with an explicit egress ACCEPT-all so the anchor can always answer,
- the firewall attachment on the anchor's network interface.

Then **one script** (run by you on the anchor's console) installs `tang`,
prints its **thumbprint**, and installs Docker + the **Gatus** availability
monitor — config-as-file, no admin account, no UI bootstrap. The script
generates the tang keypair **on the box**; nothing it prints is secret
except the thumbprint you choose to save.

The module provisions **no SSH access** — inbound or outbound. You administer
the anchor from the netcup SCP remote console, or by adding your own SSH key
via netcup SCP at order time.

## The flow, for a first-time user

1. **Order the anchor** — in the netcup SCP: a small VPS ("piko" class is
   plenty), any Debian-family image, root password set at order time. Note
   the server name (or id), your SCP user id, and the anchor's IP.
   *(docs/usage.md §1)*
2. **Create SCP API credentials** (access + refresh token) in the SCP and
   export them as `NETCUP_*` environment variables. *(docs/usage.md §2)*
3. **`tofu apply`** the module — it adopts your server and configures the
   firewall. Takes the variables shown in the Quickstart below.
   *(docs/usage.md §3)*
4. **Run ONE script on the anchor** — netcup SCP → your server → remote
   console → log in as root → paste the `curl … | bash` line from the
   Quickstart. It installs tang, prints the **thumbprint** (save it in your
   password manager immediately), and installs the Gatus monitor.
   *(docs/usage.md §4)*
5. **Configure the monitor** — one file on the anchor:
   `/etc/gatus/config.yaml`. Pick an alerting channel (ntfy / Telegram /
   SMTP) and add endpoints for **your main server's services by DNS name**.
   *(docs/usage.md §5)*
6. **Bind your main box** — install `clevis clevis-luks clevis-initramfs`,
   run the printed `clevis luks bind` command, confirm the thumbprint
   matches, rebuild the initramfs. *(docs/usage.md §6)*
7. **Reboot-test twice.** The unlock prompt may flash, then continue on its
   own when clevis reaches the anchor. That is success. Keep the passphrase
   keyslot forever — it is the true root. *(docs/usage.md §7)*

## Quickstart

```bash
# 0. Order a small netcup VPS ("piko" class is plenty) in the SCP, install any
#    Debian-family OS, note the server name and its id.
# 1. Create SCP API credentials (access + refresh token) and export them:
export NETCUP_SCP_ACCESS_TOKEN="..."   # never commit these
export NETCUP_SCP_REFRESH_TOKEN="..."
export NETCUP_CUSTOMER_NUMBER="..."    # or pass var.customer_number

# 2. Apply the module (see examples/quickstart for a full root module):
tofu init
tofu apply -var server_name="SCPI-123456" \
           -var allow_main_box_ipv4="203.0.113.10" \
           -var hostname="anchor-pier-01" \
           -var scp_user_id=1234

# 3. Open the netcup SCP -> your server -> remote console (browser VNC),
#    log in as root, then run the provisioning script:
curl -fsSL https://raw.githubusercontent.com/piercloud-net/terraform-piercloud-anchor/main/scripts/010-provision.sh | bash

# 4. Save the printed tang thumbprint in your password manager NOW.
```

Full walkthrough (including the `clevis luks bind` on your main box and the
reboot test): [docs/usage.md](docs/usage.md).

## What YOU must do

1. **Save the thumbprint** in your password manager when the script prints it.
   You will verify it when binding your main box.
2. **Wire your main box**: install `clevis clevis-luks clevis-initramfs`, run
   the printed `clevis luks bind -d <device> tang '{"url":"http://anchor-pier-01.piercloud.net"}'`
   — confirming the thumbprint matches what you saved — then
   `update-initramfs -u` and test a reboot.
3. **Keep the passphrase keyslot.** The tang anchor is convenience and
   availability; the passphrase is the true root. If the anchor dies, you
   unlock with the passphrase.
4. **Watch your server from the anchor.** The script installs Gatus on the
   anchor — an independent, always-on vantage point *outside* your main box.
   Probe your main server's services **by DNS name** (Gatus never caches DNS,
   so when you migrate and flip the record, the monitor follows automatically
   and the availability history stays continuous across the cutover), and
   configure an alerting channel (ntfy / Telegram / SMTP) so failures are
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
(netcup has no official Terraform/OpenTofu provider). API credentials come
from the environment (`NETCUP_*`) — never from code, never committed.

## Public-reader note

This repository is a small, self-contained, open-source tool. It documents
exactly what you see here — nothing about who runs it, at what scale, or why
beyond what the README states. Please don't infer more.

## License

Apache-2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

The piercloud name and logo are not licensed: no endorsement by, or affiliation
with, the piercloud project is implied by use of this module.
