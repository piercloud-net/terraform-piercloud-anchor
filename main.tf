provider "netcup" {
  customer_number = var.customer_number
}

# Server id comes either directly from var.server_id, or from an exact-name
# lookup in the account server list. The exactly-one-of rule is enforced by
# a variable validation (see variables.tf); the account-level ambiguity
# (zero or several servers with the same name) is caught by the check block.
data "netcup_scp_servers" "all" {
  count = var.server_name != null ? 1 : 0
}

data "netcup_scp_server_interfaces" "anchor" {
  count     = local.resolved_server_id != null ? 1 : 0
  server_id = local.resolved_server_id
}

# Stateless re-adopt note (no `import` block lives here on purpose): import
# blocks are root-only, and this module is consumed as a CHILD module
# (registry use, examples/quickstart) — an embedded block fails every
# consumer's validate, even with an empty for_each (verified). The
# canonical conditional-import pattern (for_each, empty = zero) lives in
# examples/quickstart/main.tf targeting
# module.tang_anchor.netcup_scp_server.anchor[0]. The device-flow workflow
# runs this tree AS its root; its mode=apply generates the equivalent
# one-shot import file at runtime (import-apply-discard) when live testing
# lands — never a committed block here. Firewall-policy re-adopt is
# intentionally never imported (its account-side id is not known
# pre-apply); the first live stateless apply confirms the provider's
# create-path behavior for the steady-state policy.

# Adopt (do not create) the existing server and patch its mutable attributes.
# Servers cannot be created or deleted through the SCP API — the user orders
# the box manually; this resource adopts it and keeps its config in sync.
resource "netcup_scp_server" "anchor" {
  count = local.resolved_server_id != null ? 1 : 0

  server_id       = local.resolved_server_id
  hostname        = var.hostname
  os_optimization = "LINUX"
  # No autostart here by design (live 2026-09-08): the provider PUTs all
  # fields on any update and the API 400s `server.autostart.alreadyactive`
  # when it is already on — which is the netcup default for new servers.
  # Keep it as-ordered; confirm once in SCP → server → autostart.
}

# Account-level firewall policy: tang (TCP/80) is reachable only from the
# main box. Egress is explicitly ACCEPT-all: some SCP firewall implementations
# have a DROP_ALL egress implicit rule; we never want the anchor to be
# cut off from answering clevis challenges.
resource "netcup_scp_user_firewall_policy" "tang" {
  count = var.scp_user_id != null ? 1 : 0

  user_id     = var.scp_user_id
  name        = local.policy_name
  description = "tang (TCP/80) from the main box only; egress open. Managed by terraform-piercloud-anchor."

  rules = concat(
    [
      {
        action            = "ACCEPT"
        direction         = "INGRESS"
        protocol          = "TCP"
        destination_ports = "80"
        sources           = ["${var.allow_main_box_ipv4}/32"]
      },
    ],
    var.allow_main_box_ipv6 != null ? [
      {
        action            = "ACCEPT"
        direction         = "INGRESS"
        protocol          = "TCP"
        destination_ports = "80"
        sources           = ["${var.allow_main_box_ipv6}/128"]
      },
    ] : [],
    local.extra_ingress_rules,
    [
      {
        action    = "ACCEPT"
        direction = "EGRESS"
        protocol  = "TCP"
      },
    ],
  )
}

# Attach the policy to the anchor's first network interface.
resource "netcup_scp_server_interface_firewall" "anchor" {
  count = var.scp_user_id != null && local.resolved_server_id != null && local.interface_mac != null ? 1 : 0

  # attach (enabled firewall management only)

  server_id = local.resolved_server_id
  mac       = local.interface_mac
  active    = true

  user_policy_ids = [netcup_scp_user_firewall_policy.tang[0].id]

  # Live 2026-09-08: the server resource's hostname PUT is async (server
  # lock ~minutes); the parallel interface PUT 409'd with
  # `server.lock.error`. Serialize: wait for the server update to settle
  # before touching its interface.
  depends_on = [netcup_scp_server.anchor]
}

locals {
  # Stable policy key: server_id survives hostname renames (renamed from
  # piercloud-tang-${hostname} during the repo rename; no deployments exist).
  policy_name = "piercloud-anchor-${var.hostname}-${local.resolved_server_id}"

  # T2 twin-anchor opt-in (both empty by default = single anchor t:1, and
  # the firewall above collapses to exactly the pre-M3 rule set).
  # extra_allowed_source_ips feeds additional INGRESS TCP/80 rules above
  # (one per entry; /32 for IPv4, /128 for IPv6).
  # extra_tang_urls feeds the SSS bind snippet via outputs (bind_name /
  # regen_hint): nothing needs to reach this anchor on the twin's behalf,
  # so twin URLs carry no firewall meaning here.
  twin_tang_urls   = var.extra_tang_urls
  anchor_bind_name = var.anchor_hostname

  extra_ingress_rules = [
    for ip in var.extra_allowed_source_ips : {
      action            = "ACCEPT"
      direction         = "INGRESS"
      protocol          = "TCP"
      destination_ports = "80"
      sources           = ["${ip}${strcontains(ip, ":") ? "/128" : "/32"}"]
    }
  ]

  # First interface of the adopted server; sorted for determinism.
  # try() guards the empty-interface-list case (an unguarded [0] crashes
  # plan with "Invalid index ... empty set"); the firewall resource's count
  # re-checks for a non-null MAC before consuming it.
  interface_mac = var.scp_user_id != null && local.resolved_server_id != null ? (
    try(sort([for i in data.netcup_scp_server_interfaces.anchor[0].scp_server_interfaces : i.mac])[0], null)
  ) : null
}

check "server_id_resolution" {
  assert {
    condition     = local.resolved_server_id != null
    error_message = "server_id could not be resolved: set var.server_id directly, or set var.server_name to the exact SCP name of the server to adopt (exactly one of the two)."
  }
}

check "server_name_unique" {
  assert {
    condition = var.server_name == null || length(local.server_id_by_name) == 1
    error_message = format(
      "Server name %q matched %d servers in your netcup account; it must match exactly one. Rename the server in the SCP or use var.server_id instead.",
      var.server_name != null ? var.server_name : "", length(local.server_id_by_name),
    )
  }
}
