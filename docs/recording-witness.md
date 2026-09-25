# Recording-completeness witness (list-only)

The **recording-completeness witness** is an optional component of this module. When enabled, it renders a small systemd timer on the anchor that checks the *metadata* of the operator's B2 recording bucket and raises ntfy alerts when the recording pipeline stops looking complete. It is the anchor-side detection half of the A2 recording pipeline (`pc-admin` ships recorded sessions and audit events to B2 with Object Lock); it exists because Object Lock fixes the *content* of what was shipped, not the *completeness* of what should have been shipped.

**Rail amendment (2026-09-21):** the anchor's job expands from *tang + uptime monitor* to *tang + uptime monitor + list-only witness*. The rail stays "no sensitive data, ever": the witness sees metadata only — never content. See [security-posture.md](security-posture.md) and the anchor ADR amendment (pcad.it-infra `decisions/2026-08-29-vps-to-bare-metal-luks-migration`, amendment 2026-09-21).

## Strictly list-only

The witness holds a B2 application key with the **`listFiles` capability only** — no `readFiles`, no `writeFiles`, no `deleteFiles`. It therefore cannot fetch a recording, an audit event or a thumbnail, and it cannot change anything in the bucket. The three calls it ever makes are:

- `ListObjectsV2` (audit prefix) — audit event keys + the shipper heartbeat objects;
- `ListObjectsV2` (recordings prefix) — completed `<session-id>.tar` objects;
- `ListMultipartUploads` (recordings prefix) — in-progress uploads (the completer-lag signal).

It never calls `GET`/`HEAD` on an object (HEAD requires `readFiles`) and **never calls `ListParts`** (that requires `writeFiles`). `ListObjectVersions` is deliberately *not* used either: it needs the separate `listFileVersions` capability, which the witness key does not carry. The committed harness (`tests/recording-witness/`) proves the list-only property against a mock endpoint that records and rejects every non-list request.

## The shipper key contract it checks

The witness is parameterized by prefixes, but it *correlates* audit events with recordings through the key names the `pc-admin` shipper must produce (plan §2). If the names change, the witness raises `naming-contract`/`contract-mismatch` alerts instead of silently passing:

| Object | Key shape |
|---|---|
| Audit event (session-scoped) | `<ts>-<event-type>.<session-id>.<seq>.json` (e.g. `20260925T140321Z-session.start.9f8c…a70.0.json`) |
| Audit event (non-session) | `<ts>-<event-type>.<seq>.json` (not part of the per-session sequence check) |
| Shipper heartbeat | `audit/heartbeat/<ts>.json` every 5 min |
| Session recording | `recordings/<session-id>.tar` (multipart in progress → completed object) |

`<ts>` is a list-parseable UTC timestamp; `<seq>` is a per-session gap-free, duplicate-free counter (the witness reads the clocks from S3 `LastModified`/`Initiated`, not from the key text).

## Checks (owner-decided 2026-09-25)

- **Cadence:** the timer runs every 5 minutes (`OnBootSec=2min`, `OnUnitInactiveSec=5min`).
- **Heartbeat freshness:** newest `audit/heartbeat/*` object older than **15 min** (or missing) → `heartbeat-stale` / `heartbeat-missing` (shipper or egress suppression).
- **Recording gap:** a `session.start` older than the **10 min** grace with neither a `recordings/<session-id>.tar` object nor an in-progress upload → `recording-gap`.
- **Completer lag:** an in-progress upload under `recordings/` whose session has a `session.end` event older than **15 min** → `completer-lag`. A bare "multipart older than 15 min" is **never** an alert: Teleport opens one multipart upload per session at start and keeps it open for the whole session, so long live sessions are normal.
- **Sequence continuity:** per session, the `<seq>` values must be gap- and duplicate-free → `sequence-gap` / `sequence-duplicate`.

## Verdicts, state and fail-closed behaviour

Verdict states and exit codes: `ok` (0) / `alert` (1) / `error` (2). The systemd service is `Type=oneshot`, so a non-green run leaves the unit failed and visible in the run/provision log.

- `/var/lib/piercloud/recording-witness/state.json` (0600) — the latest verdict (`state`, `detail`, `updated_at`), the last **baseline** (the last runnable verdict), and notification bookkeeping.
- `/var/lib/piercloud/recording-witness/verdict.log` — append-only, one line per run: `<ts> <state> <detail>`.

**Fail-closed:** a witness that cannot run (bad key, B2 error, unreadable config) reports `error` — it never looks green — and **holds the baseline** (a failed run does not advance the last good baseline). Alerts push through ntfy on state transitions, with a recovery push and a 30-minute re-notify while non-green; a failed push is logged and retried on the next run.

## Enablement (operator; repo secrets)

The component is **dormant by default** — no `RECORDING_WITNESS_*` env means no timer, and tenants are unaffected. A later provision without the env removes a previously installed witness (script, env file, units) so a retire never leaves a stale timer behind; the verdict log is kept as evidence.

The operator anchor sets six repo secrets (in `piercloud-net/terraform-piercloud-anchor`), all secretly, **never via argv or logs**. From a checkout where `pc-admin/.local/b2.env` (mode 600) holds `B2_ENDPOINT`, `B2_BUCKET`, `B2_WITNESS_KEY_ID`, `B2_WITNESS_KEY`:

```bash
set -a; . .local/b2.env; set +a   # values stay in the shell, never argv
printf '%s' "$B2_ENDPOINT"       | gh secret set RECORDING_WITNESS_ENDPOINT          --repo piercloud-net/terraform-piercloud-anchor
printf '%s' "$B2_BUCKET"         | gh secret set RECORDING_WITNESS_BUCKET            --repo piercloud-net/terraform-piercloud-anchor
printf '%s' 'audit/'             | gh secret set RECORDING_WITNESS_AUDIT_PREFIX      --repo piercloud-net/terraform-piercloud-anchor
printf '%s' 'recordings/'        | gh secret set RECORDING_WITNESS_RECORDINGS_PREFIX --repo piercloud-net/terraform-piercloud-anchor
printf '%s' "$B2_WITNESS_KEY_ID" | gh secret set RECORDING_WITNESS_KEY_ID            --repo piercloud-net/terraform-piercloud-anchor
printf '%s' "$B2_WITNESS_KEY"    | gh secret set RECORDING_WITNESS_KEY               --repo piercloud-net/terraform-piercloud-anchor
```

Then dispatch `provision.yml` `mode=apply` (owner device-flow approval). The run installs the timer, runs one check synchronously and prints the verdict; `error` fails the run closed, `alert` warns (the pipeline may genuinely be down). The staged pipeline order is: the `pc-admin` `scripts/030-recording-pipeline.sh` live checks first (including the witness-key negative: list allowed, `GET`/`HEAD` denied), then the anchor provision.

Rotate the key in the B2 console, update the repo secrets, re-dispatch. Retire by deleting the six secrets and re-dispatching.

## What this witness is and is not (honest claim)

- **Detection, not prevention.** It detects gaps, stale heartbeats and completer lag from metadata. It cannot stop a suppression.
- **Pre-SNP residual:** a host-root attacker can also forge completion records; the witness raises the cost of undetected suppression, it does not make completeness unconditional. The CC phase moves the recording termination point into the confidential guest.
- **Operator-owned self-accountability:** pre-CC there is no third-party-completeness claim; the witness runs on the operator's own anchor. The Rekor-style external manifest leg is deferred to the CC phase.
- **Tenant reuse is parameterized, not free.** The check code is prefix/bucket-parameterized, but a tenant anchor must adopt the same shipper naming and provision the witness (repo secrets + key) itself; nothing transfers automatically.

Operational checks for maintainers live in [verification.md](verification.md) ("Recording witness"). The standing-credential inventory entry is in [security-posture.md](security-posture.md).
