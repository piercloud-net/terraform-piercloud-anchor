# Usage — end-to-end walkthrough

From zero to an unattended-booting encrypted main box. Time: ~30 minutes,
mostly netcup web UI.

## 0. What you need

- A netcup account (identity verification happens at order time).
- Your main box: any Debian-family machine with a LUKS-encrypted root.
- Your main box's public IP (IPv4, optionally IPv6) — the only address that
  will be allowed to reach tang.

## 1. Order the anchor ("piko"-class VPS)

In the netcup SCP, order a small VPS (a 1 vCore / 1 GB / 30 GB "piko" is
plenty for tang + Gatus), any Debian-family image, set the root
password at order time, and note:

- the **server name** (e.g. `SCPI-1234567`) or the numeric **server id**,
- the **user id** of your SCP account (Account → Users) — needed for firewall
  management,
- the **IPv4** (and IPv6, if you want it) of the anchor.

## 2. Create SCP API credentials

In the netcup SCP, create API credentials for the SCP REST API (an access
token, plus an optional refresh token for automatic renewal). Export them —
never write them to disk or code:

```bash
export NETCUP_SCP_ACCESS_TOKEN="..."
export NETCUP_SCP_REFRESH_TOKEN="..."
export NETCUP_CUSTOMER_NUMBER="..."   # optional if you pass var.customer_number
```

## 3. Apply the module

Use `examples/quickstart` as the root module (copy it, or point `source` at
the registry/GitHub address):

```bash
tofu init
tofu apply \
  -var server_name="SCPI-1234567" \
  -var allow_main_box_ipv4="203.0.113.10" \
  -var allow_main_box_ipv6="2001:db8::10" \
  -var hostname="anchor-pier-01" \
  -var scp_user_id=1234
```

The module adopts the server (it cannot create or delete servers — the netcup
SCP API doesn't allow it), sets its hostname/autostart, creates the firewall
policy (TCP/80 from your main box only + explicit egress ACCEPT) and attaches
it to the anchor's interface. The `next_step` output tells you what's next.

## 4. Run the provisioning script on the anchor

**Execution channel: the netcup SCP remote console** (server → remote console
/ browser VNC). Log in as root with the password from step 1. No SSH inbound
is provisioned anywhere — administration of the anchor is user-direct: the
SCP console, or your own SSH key added via netcup SCP at order time.

```bash
curl -fsSL https://raw.githubusercontent.com/piercloud-net/terraform-piercloud-anchor/main/scripts/010-provision.sh | bash
```

(Or paste the script into the console. It is idempotent — safe to re-run.)

The script: installs `tang`, enables `tangd.socket` (port 80), generates the
tang keypair **on the box**, prints the **thumbprint**, asserts that no tang
key material appears in any terraform state in the working directory, and
installs Docker + **Gatus** (bound to `127.0.0.1:8080`, config at
`/etc/gatus/config.yaml`, sqlite history in the `gatus-data` volume).

**Save the thumbprint in your password manager NOW.**

## 5. Configure the monitor

The one file to edit on the anchor is `/etc/gatus/config.yaml` (written on
first run; re-running the script never overwrites your edits):

1. Configure an alerting channel (ntfy / Telegram / SMTP) in `alerting`.
2. Uncomment the "YOUR MAIN SERVER" endpoints, pointing them at your
   server's real DNS names — they follow DNS flips automatically, and the
   availability history stays continuous across cutovers.
3. Apply with `docker restart gatus`; check `docker logs gatus` for
   config errors.

Optional UI: Gatus serves a dashboard on `127.0.0.1:8080`. Reach it via your
own SSH tunnel (needs an SSH key YOU added in the netcup SCP):

```bash
ssh -L 8080:127.0.0.1:8080 root@<anchor-ip>
# open http://localhost:8080
```

## 6. Bind your main box (clevis)

On your **main box**:

```bash
apt-get install clevis clevis-luks clevis-initramfs
# find your LUKS device: lsblk -f
clevis luks bind -d <device> tang '{"url":"http://anchor-pier-01.piercloud.net"}'
```

**Verify the thumbprint** shown at bind time against the value you saved in
step 4. If it doesn't match, answer NO and investigate. Then:

```bash
update-initramfs -u
```

(Debian note: for some remote-unlock setups the initramfs needs an `IP=`
line in `/etc/initramfs-tools/initramfs.conf` to bring the network up —
if the boot prompt never clears, check that first.)

## 7. Reboot test — twice

Reboot the main box. A brief passphrase prompt that continues on its own is
the *success* behavior: clevis reached the anchor, got the key, and unlocked.
Verify twice (and re-run `010-provision.sh` once from the top and confirm the
anchor still converges — scripts/README.md invariants).

Disaster-recovery sanity check: stop tang on the anchor (or shut the anchor
down) and confirm the main box falls back to the passphrase prompt.

## What this repo never does

- No SSH inbound anywhere — the module provisions no SSH keys; admin the
  anchor from the SCP console or your own key added via netcup SCP.
- No credentials in code, state, or CI. tang keys are generated on the anchor
  and never enter terraform state; the script's key-leak assertion guards
  this. CI greps tracked files for key material.
- The anchor holds no credential that reaches your main box.
