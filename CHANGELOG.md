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

### 🐛 Bug Fixes

- Default dispatch mode to apply (closes #16)
- Split device request from poll so the card renders (closes #22)
- Unmask device_code for the job handoff (closes #26)
- Conditional ntfy auth + fail loudly (closes #28)
- Api_call handoff without subshell (closes #33)
- Resolve SCP user id from token userinfo (closes #35)
- Drop non-idempotent autostart (closes #37)
- Serialize interface firewall after async server update (closes #39)

### 📚 Documentation

- Post-transfer registry/source addresses (closes #12)
- Tap target from secrets to dispatch (closes #20)
- Working tap targets + ntfy out of bootstrap (closes #30, closes #31)

### ⚙️ Miscellaneous Tasks

- Relicense MIT -> Apache-2.0 ([#6](https://github.com/piercloud-net/terraform-piercloud-anchor/pull/6))


## [Unreleased]
