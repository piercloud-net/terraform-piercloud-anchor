# Security posture — standing credentials on the anchor

This is the anchor repo's RT-1 standing-credential inventory: what long-lived credentials the module can place on a box, where they live, and what blast radius a compromised anchor gives. The trustee framing that this inventory feeds is the RT-1 security-trust-model note (pcad.it-infra `research/2026-09-13-r6-security-trustmodel`).

## Default posture

The module provisions **no SSH access and no write-capable standing credentials** — inbound or outbound. Nobody logs into the anchor: every change arrives through a per-run approved dispatch (the runner is the admin path), and the netcup device-flow token dies with the runner. Re-entry after the root lock is per-event; rescue mode stays the last resort and disables the netcup firewall (any rescue boot → rotate tang keys).

## Standing-credential inventory

| # | Credential | Where it lives | Capability | Blast radius if the anchor is compromised | Rotate / retire |
|---|---|---|---|---|---|
| 1 | `pc-admin-witness` B2 application key | `/etc/piercloud/recording-witness.env` (mode 0600, root-only) **and** the anchor repo's `RECORDING_WITNESS_KEY` / `RECORDING_WITNESS_KEY_ID` GitHub secrets | **`listFiles` only** on the operator's `pc-admin-dr` bucket: `ListObjectsV2` + `ListMultipartUploads`. **No `readFiles`, no `writeFiles`, no `deleteFiles`** — object content, thumbnails and recordings are unreachable, and nothing can be modified or deleted | Metadata disclosure: object names (session IDs, timestamps, event types) and object timestamps. No recording content, no audit-event content, no write/delete/retention-bypass path | B2 console key rotation → update the repo secrets → re-dispatch `mode=apply`; retire by deleting the six `RECORDING_WITNESS_*` secrets and re-dispatching (the run removes the env file and the timer) |

There are **no other standing credentials** in the module surface: no SSH keys, no Teleport tokens, no API tokens, no sockets. The witness above exists only when the operator enables it (all six `RECORDING_WITNESS_*` secrets set); the default template carries none.

## Why the witness key is acceptable

- The anchor is deliberately the weakest box: unencrypted, always-on, cheapest class, different jurisdiction. Its existing job already requires it to be reachable and to hold an unlock key (tang). The witness adds metadata visibility, not access: the anchor still holds **no credential that reaches the main box**, and the witness key reaches nothing outside the operator's own DR bucket.
- The witness must never be able to read content — that is the security property, not a convenience: completeness is verifiable from listing alone, and the negative checks are part of the live acceptance (`scripts/030-recording-pipeline.sh` in `pc-admin` proves the key can list but cannot `GET`/`HEAD`).
- Honest residual: the witness runs on an operator-owned box, so the completeness claim is self-accountability until the CC-phase external manifest leg; a pre-SNP host-root attacker can also forge completion records. The arm's-length property being bought here is *detection* of pipeline suppression, not prevention.

## Related

- [recording-witness.md](recording-witness.md) — component design, checks, enablement, honest claim.
- [invariants.md](invariants.md) — Invariant 2 (the anchor is a key-holder, never an access-path) — unchanged by the witness: the witness key is list-only and reaches no user box.
- [verification.md](verification.md) — the staged live proof for the witness.
