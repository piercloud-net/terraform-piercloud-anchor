# Adopt an existing netcup server and turn it into a tang/clevis NBDE anchor.
#
# Prerequisites:
#   - a netcup server ordered in the SCP (any Debian-family image installed) # ci-allowlist: prose — install-time OS wording, not a live image-install reference.
#   - SCP API credentials in the environment (NETCUP_* — see ../../docs/usage.md)
#   - your main box's public IP(s)
#
# Replace the placeholder values below, or pass them with -var / a tfvars file.

terraform {
  required_version = ">= 1.11"

  required_providers {
    netcup = {
      source  = "rixlhq/netcup"
      version = "~> 1.2"
    }
  }
}

provider "netcup" {}

variable "server_id" {
  description = "Numeric id of the netcup server to adopt (placeholder default — replace or pass with -var / a tfvars file)."
  type        = number
  default     = 1234567
}

variable "stateless_readopt" {
  description = "Set true for stateless runs with no persisted state (import-apply-discard): re-adopts the existing server into the empty state instead of erroring. Default false = zero import blocks. Leave false for normal stateful use — an import block targeting an already-tracked resource fails the run."
  type        = bool
  default     = false
}

# Stateless re-adopt (canonical conditional-import pattern: for_each, empty
# = zero). Import blocks are root-only, so this lives here in the caller
# root — never inside the child module — targeting the adopted server.
import {
  for_each = var.stateless_readopt ? toset([tostring(var.server_id)]) : toset([])
  to       = module.tang_anchor.netcup_scp_server.anchor[0]
  id       = each.value
}

module "tang_anchor" {
  source = "../../"

  server_id           = var.server_id  # or server_name = "SCPI-1234567"
  allow_main_box_ipv4 = "203.0.113.10" # your main box's IPv4
  allow_main_box_ipv6 = null           # optional: your main box's IPv6
  hostname            = "anchor-01-pier"
  scp_user_id         = 1234 # SCP user id owning the firewall policy

  # M3 twin-anchor / bind-name opt-ins (T2 only — defaults = single anchor t:1).
  extra_tang_urls          = []   # e.g. ["http://198.51.100.7"]
  extra_allowed_source_ips = []   # e.g. ["198.51.100.20"]
  anchor_hostname          = null # e.g. "anchor-01-pier.piercloud.net" (same-URL rebuild = regen)
}

output "anchor_ipv4" {
  value = module.tang_anchor.ipv4
}

output "bind_name" {
  value = module.tang_anchor.bind_name
}

output "next_step" {
  value = module.tang_anchor.next_step
}
