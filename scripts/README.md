# scripts/ — numbered, on-box

Every script in this directory follows the same invariants:

1. **Numbered.** `NNN-name.sh` (three-digit, zero-padded — matches the
   pcad.it-infra house convention), ordered by execution phase. Numbers are
   never reused; new scripts take the next free number.
2. **On-box, dispatch-run.** Scripts run ON the target box, started by the
   A1 dispatch (the runner pipes them over per-run-approved SSH) — or by a
   human pasting them into the netcup SCP remote console as fallback.
   API-touching CI workflows (`.github/workflows/` +
   CI-called `.github/scripts/`, below) hold user-box credentials only inside
   the per-run device-flow (the token dies with the runner).
3. **Idempotent.** Safe to re-run at any time, on any state — re-running must
   converge, never break.
4. **Verify live twice.** After first provision, re-run the script from the
   top and confirm the box still converges cleanly (drift check), and verify
   the service does its job twice (for the anchor: a successful clevis boot
   after a reboot, twice).
5. **No secrets.** No credential is ever embedded, fetched, or echoed by a
   script. Values that must be saved (thumbprint, generated passwords) are
   printed once, to the console, for the human to store in their password
   manager.

| Script | Runs on | Purpose |
|---|---|---|
| `010-provision.sh` | the anchor box | install tang (loopback socket) + Caddy edge proxy (dispatch-managed Caddyfile: tang proxy, ACME HTTP-01, dashboard TLS) + dispatch-managed Gatus monitor (rendered from env, statuses printed), print thumbprint, key-leak assertion, print clevis bind next steps |

## CI-called scripts (`.github/scripts/`) — not human-run

The domain split: `scripts/` = on-box payloads (run via dispatch SSH or pasted
by hand); `.github/scripts/` = CI-called, runs on the
ephemeral Actions runner holding the per-run device-flow token, and IS the
thing that opens the A1 SSH window and connects. Numbering (`NNN-`) is
unique across BOTH directories — new scripts take the next free number in
either place (020 is taken by the A1 entrypoint below).

| Script | Runs on | Purpose |
|---|---|---|
| `.github/scripts/020-provision-anchor.sh` | the Actions runner | A1 hardened /32 window lifecycle (`sweep-pre`/`open`/`provision`/`close`/`sweep-post`) + plain-ssh provisioning handoff; `--rotate` passthrough, `passwd -l root` last |
| `.github/scripts/030-anchor-dns.sh` | the Actions runner | Cloudflare A-record upsert + verify-after-write for `anchor-01-<tenant>.piercloud.net`; fail-closed without the org token |
| `.github/scripts/040-retention-cap.sh` | the Actions runner | `mode=check` retention-cap assertion: fails loudly when any workflow's `retention-days` leaves the public-repo 1–90 band (H1: artifacts are a convenience copy, never the durable record) |
