variable "customer_number" {
  description = "netcup customer number (SCP). Can also be supplied via the NETCUP_CUSTOMER_NUMBER environment variable instead."
  type        = string
  default     = null
}

variable "scp_user_id" {
  description = "Numeric id of the SCP user that will own the firewall policy. Find it in the netcup SCP under Account > Users, or via `data.netcup_scp_user`. Required for the module to manage the firewall policy; leave null to skip firewall provisioning (guided by the `next_step` output)."
  type        = number
  default     = null
}

variable "server_id" {
  description = "Numeric id of the netcup server to adopt. Exactly one of server_id / server_name must be set."
  type        = number
  default     = null

  validation {
    condition     = (var.server_id != null || var.server_name != null) && (var.server_id == null || var.server_name == null)
    error_message = "Set exactly one of server_id or server_name (neither or both is invalid)."
  }
}

variable "server_name" {
  description = "Exact SCP name of the netcup server to adopt (resolved to an id via data source lookup). Exactly one of server_id / server_name must be set."
  type        = string
  default     = null
}

variable "allow_main_box_ipv4" {
  description = "IPv4 address of your main box; tang (TCP/80) accepts challenges from this address only."
  type        = string

  validation {
    condition     = can(cidrhost("${var.allow_main_box_ipv4}/32", 0))
    error_message = "Must be a single IPv4 address (a /32 is appended automatically when building the firewall source)."
  }
}

variable "allow_main_box_ipv6" {
  description = "Optional IPv6 address of your main box; also allowed to reach tang (TCP/80)."
  type        = string
  default     = null

  validation {
    condition     = var.allow_main_box_ipv6 == null || can(cidrhost("${var.allow_main_box_ipv6}/128", 0))
    error_message = "Must be a single IPv6 address (a /128 is appended automatically when building the firewall source)."
  }
}

variable "hostname" {
  description = "Hostname to set on the adopted server (SCP hostname attribute)."
  type        = string
}

variable "extra_tang_urls" {
  description = "T2 twin-anchor opt-in ONLY: advertise URLs of additional tang servers (e.g. a second box at a different provider) for the SSS bind on the main box. Default empty = single anchor t:1 (the product default). Surfaced via outputs for the bind command; the firewall needs nothing on the twin's behalf."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for u in var.extra_tang_urls : can(regex("^https?://[^/:]+(:[0-9]+)?(/.*)?$", u))])
    error_message = "Each entry must be a plain http(s) tang advertise URL (host, optional port, optional path — no query, no fragment)."
  }
}

variable "extra_allowed_source_ips" {
  description = "T2 twin-anchor / BYO opt-in ONLY: additional single IPs admitted to tang (TCP/80) besides var.allow_main_box_ipv4/_ipv6. Default empty = single-anchor t:1 rule set unchanged."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for ip in var.extra_allowed_source_ips : can(cidrhost("${ip}/32", 0)) || can(cidrhost("${ip}/128", 0))])
    error_message = "Each entry must be a single IPv4 or IPv6 address (a /32 or /128 suffix is appended automatically when building the firewall source)."
  }
}

variable "anchor_hostname" {
  description = "Optional DNS name clients bind instead of the anchor IP (e.g. anchor-pier-01.piercloud.net): same-URL rebuild = regen with no main-box change. Null (default) = bind output.ipv4. No DNS records are managed — point the name at the anchor IP yourself."
  type        = string
  default     = null

  validation {
    condition     = var.anchor_hostname == null || can(regex("^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$", var.anchor_hostname))
    error_message = "Must be a plain DNS hostname (e.g. anchor-pier-01.piercloud.net): no scheme, no port, no path, no trailing dot."
  }
}

variable "stateless_readopt" {
  description = "Wiring point for stateless runs with no persisted state (CI device-flow apply: import-apply-discard). The conditional `import` block itself lives in the CALLER's root (import blocks are root-only; see examples/quickstart/main.tf) — never in this module. Has no effect on its own; the caller keys its import for_each on its own flag."
  type        = bool
  default     = false
}

locals {
  server_id_by_name = var.server_name != null ? [
    for s in data.netcup_scp_servers.all[0].scp_servers : s.id if s.name == var.server_name
  ] : []

  resolved_server_id = var.server_id != null ? var.server_id : (
    length(local.server_id_by_name) == 1 ? local.server_id_by_name[0] : null
  )
}
