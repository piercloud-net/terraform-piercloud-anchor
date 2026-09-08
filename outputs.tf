output "server_id" {
  description = "Id of the adopted server."
  value       = local.resolved_server_id
}

output "ipv4" {
  description = "Primary IPv4 address of the anchor (null until the server is adopted with firewall management enabled)."
  value       = try([for ip in data.netcup_scp_server_interfaces.anchor[0].scp_server_interfaces[*].ipv4addresses : ip[0].ip][0], null)
}

output "ipv6" {
  description = "Primary IPv6 address of the anchor (null if none is routed to the server)."
  value = try(
    [for ip in data.netcup_scp_server_interfaces.anchor[0].scp_server_interfaces[*].ipv6addresses : ip[0].ip][0],
    null
  )
}

output "firewall_policy_id" {
  description = "Id of the managed firewall policy (null when var.scp_user_id is unset and the firewall is not managed)."
  value       = var.scp_user_id != null ? netcup_scp_user_firewall_policy.tang[0].id : null
}

output "bind_name" {
  description = "DNS name your main box binds (same-URL rebuild = regen with no main-box change). Null when var.anchor_hostname is unset — bind output.ipv4 instead."
  value       = local.anchor_bind_name
}

output "regen_hint" {
  description = "How a rebuild reuses the bind name (null when var.anchor_hostname is unset; no secrets)."
  value = local.anchor_bind_name != null ? (
    length(local.twin_tang_urls) > 0
    ? "Point ${local.anchor_bind_name} at the new anchor IPv4, reinstall, re-bind SSS t-of-2 with the twin URLs, verify the thumbprint out-of-band. Same URL = regen, no main-box unbind."
    : "Point ${local.anchor_bind_name} at the new anchor IPv4, reinstall, re-bind, verify the thumbprint out-of-band. Same URL = regen, no main-box unbind."
  ) : null
}

output "next_step" {
  description = "What to do next: run the provisioning script on the anchor and save the tang thumbprint."
  value       = <<-EOT
    1. Open the netcup SCP, open your server, then the remote console (browser VNC).
    2. Log in as root (the password you set when ordering the server).
    3. Run:
       curl -fsSL https://raw.githubusercontent.com/piercloud-net/terraform-piercloud-anchor/main/scripts/010-provision.sh | bash
    4. Save the printed tang thumbprint in your password manager NOW.
    5. On your main box, run the printed `clevis luks bind` command.
    Full walkthrough: docs/usage.md
  EOT
}
