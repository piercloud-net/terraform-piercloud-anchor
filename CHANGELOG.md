# Changelog

All notable changes to this project will be documented in this file.

## [calver-released]

<!-- USER-EDITABLE SECTION START -->
<!-- Add your curated release notes here. -->
<!-- USER-EDITABLE SECTION END -->

### 🚀 Features

- Phone-first provision with DNS automation (closes #14, closes #8)
- TAP-TO-APPROVE card on the run summary (closes #18)
- Approval card in its own job so it renders live (closes #24)
- Passwordless bootstrap + zero-IP discovery (closes #50)
- Caddy dashboard TLS + custom-domain pattern (closes #49)

### 🐛 Bug Fixes

- Default dispatch mode to apply (closes #16)
- Split device request from poll so the card renders (closes #22)
- Unmask device_code for the job handoff (closes #26)
- Conditional ntfy auth + fail loudly (closes #28)
- Api_call handoff without subshell (closes #33)
- Resolve SCP user id from token userinfo (closes #35)
- Drop non-idempotent autostart (closes #37)
- Serialize interface firewall after async server update (closes #39)
- Open the A1 window after steady-state apply (closes #41)
- Create tang key dir before keygen (closes #43)
- Install Docker before running Gatus (closes #45)
- Explicit sqlite storage type for Gatus (closes #47)
- Bootstrap probes SSH only after A1 window opens, bounded attempts (closes #59)
- One firewall rule per edge CIDR, provider-order-proof (closes #61)
- Poll SCP 202 tasks, uuid shadowed by local (closes #63)
- Dump task uuid + scrubbed body on async failure (closes #66)
- Set root password while RUNNING (agent-based reset, no power cycle) (closes #68)
- Tolerate the systemd socket-type suffix on tangd Listen (closes #71)
- Cycle tangd.service after the socket move (closes #73)
- Serve tang keys from the unit keydir + assert the JWS advertisement (closes #75, closes #77, closes #78)
- Make the /adv probe self-diagnosing and tool-gap tolerant (closes #79)
- Accept the JWS general serialization in the /adv probe (closes #81)
- Dashboard vhost checks in the pre-DNS / auto-TLS state (closes #83)
- Read the DNS proxied flag without jq's false-as-empty trap (closes #85)
- Converge tang key material to one bindable set (closes #87)
- Probe the Caddy :443 origin with SNI (closes #92)
- *(aop)* Verify the client cert + Caddy 2.11.4 + AOP-aware :443 proof (closes #97)
- *(aop)* Probe hardening + CI compiles the client_auth stanza (closes #99)

### 📚 Documentation

- Post-transfer registry/source addresses (closes #12)
- Tap target from secrets to dispatch (closes #20)
- Working tap targets + ntfy out of bootstrap (closes #30, closes #31)
- Passwordless-first framing in usage.md (closes #50)
- Two-leg edge/origin TLS ceremony + wildcard Origin CA pair (closes #90)

### ⚙️ Miscellaneous Tasks

- Relicense MIT -> Apache-2.0 ([#6](https://github.com/piercloud-net/terraform-piercloud-anchor/pull/6))
- Allowlist tasks/users SCP endpoints (closes #50)
- Mock-tang bind-proof e2e through real Caddy render (closes #57)
- External-watch — GitHub-side cron probes the public dashboard (closes #94)


## [Unreleased]
