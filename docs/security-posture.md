# Security posture — standing credentials on the anchor

This is the anchor repo's RT-1 standing-credential inventory: what long-lived credentials the module can place on a box, where they live, and what blast radius a compromised anchor gives. The trustee framing that this inventory feeds is the RT-1 security-trust-model note (pcad.it-infra `research/2026-09-13-r6-security-trustmodel`).

## Default posture

The module provisions **no SSH access and no write-capable standing credentials for the anchor's infrastructure** — inbound or outbound. The one credential with a write surface is the ntfy publish token used by the alerting plane (row 2): it can publish to the tenant's notification topic, and nothing else. Nobody logs into the anchor: every change arrives through a per-run approved dispatch (the runner is the admin path), and the netcup device-flow token dies with the runner. Re-entry after the root lock is per-event; rescue mode stays the last resort and disables the netcup firewall (any rescue boot → rotate tang keys).

## Standing-credential inventory

| # | Credential | Where it lives | Capability | Blast radius if the anchor is compromised | Rotate / retire |
|---|---|---|---|---|---|
| 1 | `pc-admin-witness` B2 application key | `/etc/piercloud/recording-witness.env` (mode 0600, root-only) **and** the anchor repo's `RECORDING_WITNESS_KEY` / `RECORDING_WITNESS_KEY_ID` GitHub secrets | **`listFiles` (metadata-only; object, version and multipart listings)** on the operator's `pc-admin-dr` bucket — **whole-bucket, no `namePrefix`** (a scoped key returns 200 filtered and can silently miss markers): `ListObjectsV2` + `ListObjectVersions` + `ListMultipartUploads`. **No `readFiles`, no `writeFiles`, no `deleteFiles`** — object content, thumbnails and recordings are unreachable, and nothing can be modified or deleted | Metadata disclosure: object names (session IDs, timestamps, event types), version ids / `IsLatest` / delete-marker flags and object timestamps. No recording content, no audit-event content, no write/delete/retention-bypass path | B2 console key rotation → update the repo secrets → re-dispatch `mode=apply`; retire by deleting the six `RECORDING_WITNESS_*` secrets and re-dispatching (the run removes the env file and the timer) |
| 2 | `NTFY_TOKEN` ntfy access token (pre-existing Gatus alerting; reused by the witness when enabled) | `/etc/gatus/config.yaml` (Gatus alerting) and, when the witness is enabled, `/etc/piercloud/recording-witness.env` (mode 0600, root-only), **and** the anchor repo's `NTFY_TOKEN` GitHub secret | **Publish to the tenant's ntfy topic** (the module only needs publish; a read-scoped token can also read the topic) | An attacker on the anchor can push spoofed alerts onto the tenant topic and, with a read-scoped token, read its message backlog — alert fatigue / social engineering / topic-content disclosure. No host, tang, Teleport or B2 access; the token reaches nothing outside ntfy | ntfy console → update the `NTFY_TOKEN` repo secret → re-dispatch `mode=apply` (Gatus and, if enabled, the witness env re-render) |

There are **no other standing credentials** in the module surface: no SSH keys, no Teleport tokens, no sockets. The only standing API credentials are the list-only witness key (row 1, optional, present only when all six `RECORDING_WITNESS_*` secrets are set) and the ntfy publish token (row 2, pre-existing Gatus alerting, reused by the witness when enabled). The default template carries neither.

## CI-side (runner) credentials

The `anchor-dns` job (`.github/workflows/provision.yml` → `.github/scripts/030-anchor-dns.sh`) is the one workflow that consumes a DNS-write credential. Both DNS secrets below are **org secrets, visibility all** (GitHub has no finer visibility here), so they are readable by any workflow in the repo — the controls are scope, custody and retirement, not visibility:

| Secret | Scope | Custody / rotation | Retirement |
|---|---|---|---|
| `CLOUDFLARE_DNS_TOKEN` | `DNS:Edit` + `Zone:Read` on the `piercloud.net` zone only (Cloudflare tokens cannot be scoped below a zone) | Rotate in the Cloudflare dashboard; Vault-brokered short-lived creds are the platform-side path, not this CI secret | Retires at/after the B `.net` zone move (the zone leaves Cloudflare) and at the stage-2 broker cutover |
| `GCORE_DNS_TOKEN` | **No zone scoping** — Gcore tokens are account-wide, so this is near-account-wide DNS write authority over the **dedicated platform account** (pc-canary.com now; `piercloud.net` post-B) | A2 interim, owner-approved 2026-10-06 (call C): dedicated token with explicit expiry + calendar rotation; risk-register entry for the H3→M1 window | Deleted at the stage-2 broker cutover (entry criteria: broker anchor path live + registry value validation #8/#124) |

Both secrets are injected into the job env by GitHub; only the active provider's path (selected by the `NET_DNS_PROVIDER` repo variable) reads and masks its token — the script never reads the other. The script enforces the standing invariants: mask-first, token passed via a mode-0600 header file (`-H @file`, never argv or logs), `curl` + `jq` only, fail-closed when the active provider's token is absent, and verify-after-write before any thumbprint is issued. The end state is the M1 broker API with a short-lived OpenBao-minted role — both org secrets deleted, org-secret count back to 0.

## Why the witness key is acceptable

- The anchor is deliberately the weakest box: unencrypted, always-on, cheapest class, different jurisdiction. Its existing job already requires it to be reachable and to hold an unlock key (tang). The witness adds metadata visibility, not access: the anchor still holds **no credential that reaches the main box**, and the witness key reaches nothing outside the operator's own DR bucket.
- The witness must never be able to read content — that is the security property, not a convenience: completeness is verifiable from listing alone, and the negative checks are part of the live acceptance (`scripts/030-recording-pipeline.sh` in `pc-admin` proves the key can list but cannot `GET`/`HEAD`).
- Honest residual: the witness runs on an operator-owned box, so the completeness claim is self-accountability until the CC-phase external manifest leg; a pre-SNP host-root attacker can also forge completion records. The arm's-length property being bought here is *detection* of pipeline suppression, not prevention.

## Related

- [recording-witness.md](recording-witness.md) — component design, checks, enablement, honest claim.
- [invariants.md](invariants.md) — Invariant 2 (the anchor is a key-holder, never an access-path) — unchanged by the witness: the witness key is list-only and reaches no user box.
- [verification.md](verification.md) — the staged live proof for the witness.
