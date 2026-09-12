# Quickstart example

A complete, runnable root module that adopts an existing netcup server and
turns it into a tang/clevis NBDE anchor. Copy this directory (or use it as
your root module via `source`), fill in the placeholders, and `tofu apply`.

```bash
export NETCUP_SCP_ACCESS_TOKEN="..."
export NETCUP_SCP_REFRESH_TOKEN="..."

tofu init
tofu apply \
  -var server_id=1234567 \
  -var allow_main_box_ipv4="203.0.113.10" \
  -var allow_main_box_ipv6="2001:db8::10" \
  -var hostname="anchor-01-pier" \
  -var scp_user_id=1234
```

Then follow the printed `next_step` output (run the provisioning script on
the anchor's console, save the thumbprint, bind your main box). Full
walkthrough: [../../docs/usage.md](../../docs/usage.md).

T2 twin-anchor / bind-name opt-ins (all default to single anchor t:1):
`extra_tang_urls`, `extra_allowed_source_ips`, `anchor_hostname`
(same-URL rebuild = regen), plus `stateless_readopt` for stateless
import-apply-discard runs — see `main.tf`.
