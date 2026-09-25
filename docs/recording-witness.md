# Recording-completeness witness (list-only)

The **recording-completeness witness** is an optional component of this module. When enabled, it renders a small systemd timer on the anchor that checks the *metadata* of the operator's B2 recording bucket and raises ntfy alerts when the recording pipeline stops looking complete. It is the anchor-side detection half of the A2 recording pipeline (`pc-admin` ships recorded sessions and audit events to B2 with Object Lock); it exists because Object Lock fixes the *content* of what was shipped, not the *completeness* of what should have been shipped.

**Rail amendment (2026-09-21):** the anchor's job expands from *tang + uptime monitor* to *tang + uptime monitor + list-only witness*. The rail stays "no sensitive data, ever": the witness sees metadata only — never content. See [security-posture.md](security-posture.md) and the anchor ADR amendment (pcad.it-infra `decisions/2026-08-29-vps-to-bare-metal-luks-migration`, amendment 2026-09-21).

## Strictly list-only

The witness holds a B2 application key with the **`listFiles` capability only** — no `readFiles`, no `writeFiles`, no `deleteFiles`. It therefore cannot fetch a recording, an audit event or a thumbnail, and it cannot change anything in the bucket. The three calls it ever makes are:

- `ListObjectsV2` (audit prefix) — audit event keys + the shipper heartbeat objects;
- `ListObjectsV2` (recordings prefix) — completed `<session-id>.tar` objects;
- `ListMultipartUploads` (recordings prefix) — in-progress uploads (the completer-lag signal).

It never calls `GET`/`HEAD` on an object (HEAD requires `readFiles`) and **never calls `ListParts`** (that requires `writeFiles`). `ListObjectVersions` is deliberately *not* used either: it needs the separate `listFileVersions` capability, which the witness key does not carry. The committed harness (`tests/recording-witness/`) proves the list-only property against a mock endpoint that records and rejects every non-list request, and SigV4-verifies every request it sees.

## The shipper key contract it checks

The witness is parameterized by prefixes, but it *correlates* audit events with recordings through the key names the `pc-admin` shipper must produce (plan §2). If the names change, the witness raises `naming-contract`/`contract-mismatch` alerts instead of silently passing:

| Object | Key shape |
|---|---|
| Audit event (session-scoped) | `<ts>-<event-type>.<session-id>.<seq>.json` (e.g. `20260925T140321Z-session.data.9f8c…a70.2.json`) |
| Audit event (session start/end, D1) | `<ts>-session.start.<session-id>.<seq>.<mode>.json` (same for `session.end`), `mode` ∈ {`shell`,`exec`} — the mode marker is shipped by the `pc-admin` D1 shipper. Live Teleport v18 emits `interactive` on the **end** event only, so `session.end` is authoritative when present; a start/end **without** the marker is the legacy shape and is treated as `shell` (conservative — a tar is expected) |
| Audit event (non-session) | `<ts>-<event-type>.<seq>.json` (not part of the per-session sequence check). Sid-less session events documented by the shipper (currently Teleport v18's `session.rejected`) ship this shape and are **not** drift. The shipper always emits `session.rejected` sid-less (any sid is dropped, pc-admin @ `66bd304`); a sid-bearing `session.rejected` key is classified as a session event instead (no `naming-contract`) and alerts `session-start-missing` — the regression the sid-less rule prevents |
| Shipper heartbeat | `audit/heartbeat/<ts>.json` every 5 min |
| Session recording | `recordings/<session-id>.tar` (multipart in progress → completed object) |

`<ts>` is the shipper's list-parseable UTC timestamp (`YYYYmmddTHHMMSSZ`); `<seq>` is a per-session gap-free, duplicate-free counter whose first value is **0 or 1** (the shipped pipeline starts at 1; the witness reads the clocks from S3 `LastModified`/`Initiated`, not from the key text).

Drift is judged by *shape* (a `session.*` event type, or a UUID-shaped session id anywhere in the key), not by one literal substring, so a rename that drops `session.` but keeps the sid still fails closed. Audit keys that match no documented shape at all raise `contract-mismatch` (it no longer requires the heartbeat tree to be empty — `heartbeat-missing` covers that separately).

## Checks (owner-decided 2026-09-25; review folds 2026-09-25)

- **Cadence:** the timer runs every 5 minutes (`OnBootSec=2min`, `OnUnitInactiveSec=5min`).
- **Heartbeat freshness:** newest `audit/heartbeat/*` object older than **15 min** (or missing) → `heartbeat-stale` / `heartbeat-missing` (shipper or egress suppression).
- **Recording gap:** a `session.start` older than the **10 min** grace with neither a `recordings/<session-id>.tar` object nor an in-progress upload → `recording-gap`. **`exec`-mode sessions are exempt once their end ships**: Teleport does not record non-interactive exec sessions (`tsh ssh <host> <cmd>` emits `session.start`/`session.end` but no tar), and the D1 mode marker in the key is how the list-only witness tells them apart. `session.end` is authoritative when present (live v18 marks only the end); with no end yet the `session.start` marker governs. A session with no mode marker, or a legacy end without one, is treated as `shell` and still gap-checked. **In-flight caveat:** because live v18 marks only the end, a no-end `.shell` start past the grace may be an in-flight *exec* session (it reads `.shell` until its `.exec` end lands) — so it alerts conservatively, with wording that names the ambiguity, until the end or tar arrives. The same shape is also exactly what an interactive session whose recording never started looks like, so no longer bound or suppression is used: a longer bound would only delay both the false positive and the real gap.
- **Lost session end:** a completed `recordings/<session-id>.tar` older than the **15 min** completer-lag window whose session has no `session.end` → `session-end-missing`. The tar alone satisfies the gap check, so without this check a lost audit tail after a completed recording would stay green forever (bounded only by B2 event retention). Exec sessions never produce a tar, so they cannot trip it; a tar that just landed stays quiet inside the grace.
- **Stream closure:** session events that exist for a session id with **no `session.start`** → `session-start-missing` (without a start there is no gap clock at all, so the absence itself must alert); a session whose first `<seq>` is neither 0 nor 1 → `sequence-origin`.
- **Completer lag:** an in-progress upload under `recordings/` whose session has a `session.end` event older than **15 min** → `completer-lag`.
- **Open-upload bound:** an in-progress upload under `recordings/` with **no `session.end`** older than the open-upload bound (default **12 h**) → `open-upload-stale`. This is deliberately distinct from `completer-lag` (which needs the end event) and from the old "a bare multipart older than 15 min is never an alert" rule: a live session *within the bound* is normal because Teleport opens one multipart upload per session at start and keeps it open for the session's whole life, but past the bound a wedged upload can no longer stay green indefinitely.
- **Sequence continuity:** per session, the `<seq>` values must be gap- and duplicate-free with an origin of 0/1 → `sequence-gap` / `sequence-duplicate` / `sequence-origin`. The missing set is rendered boundedly from the observed values (never materializing `range(low, high+1)`), so crafted seq text cannot hang the check.
- **Clock skew:** any S3 timestamp more than **5 min** in the future (`LastModified`/`Initiated` comes from B2, so a negative age means the anchor clock is behind) → `error`, never a healthy verdict.

## Verdicts, state and fail-closed behaviour

Verdict states and exit codes: `ok` (0) / `alert` (1) / `error` (2). The systemd service is `Type=oneshot`, so a non-green run leaves the unit failed and visible in the run/provision log.

- `/var/lib/piercloud/recording-witness/state.json` (0600) — the latest verdict (`state`, `detail`, `updated_at`), the last **baseline** (the last runnable verdict), and notification bookkeeping.
- `/var/lib/piercloud/recording-witness/verdict.log` — append-only, one line per run: `<ts> <state> <detail>`; it rotates once at 1 MiB to `verdict.log.1` (bounded evidence at ~2 MiB).

**Fail-closed:** a witness that cannot run (bad key, B2 error, unreadable config, future-dated metadata) reports `error` — it never looks green — and **holds the baseline** (a failed run does not advance the last good baseline). Alerts push through ntfy on state transitions, with a recovery push and a 30-minute re-notify while non-green; a failed push is logged and retried on the next run (a failed **recovery** push is retried on the next green run until it lands, and a landed recovery is never re-pushed).

**Run-once acceptance:** the provision run runs one check synchronously and prints the verdict. Because the unit is `Type=oneshot`, a witness `alert` (exit 1) also makes `systemctl start` return non-zero: the acceptance maps `0`/`1`/`2` → ok/alert/error (only the paired `systemctl rc` + `ExecMainStatus` combinations count; `ExecMainStatus` unset/203 means the unit did not run) and never reports a stale verdict. Freshness is anchored to **this invocation**, not wall-clock recency: the acceptance snapshots `InvocationID` and `state.json`'s `updated_at` before `systemctl start` and requires both to advance, so a wedged start (no new invocation) or a failed state write can never surface the previous verdict as current, while a genuine run longer than any recency window is still accepted. The printed detail redacts session ids/recording keys (hash + length) so the public run log stays non-identifying.

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

Then dispatch `provision.yml` `mode=apply` (owner device-flow approval). The run installs the timer, runs one check synchronously and prints the verdict; `error` fails the run closed, `alert` warns (the pipeline may genuinely be down). **The first live dispatch, before D1 heartbeats exist, is expected to print `witness verdict: ALERT - heartbeat-missing: no objects under audit/heartbeat/` — that is correct first-run output (it warns, exit 0, the provision continues) and it clears once heartbeats land; it is not a defect.** The staged pipeline order is: the `pc-admin` `scripts/030-recording-pipeline.sh` live checks first (including the witness-key negative: list allowed, `GET`/`HEAD` denied), then the anchor provision.

Rotate the key in the B2 console, update the repo secrets, re-dispatch. Retire by deleting the six secrets and re-dispatching.

## What this witness is and is not (honest claim)

- **Detection, not prevention.** It detects gaps, stale heartbeats and completer lag from metadata. It cannot stop a suppression.
- **Pre-SNP residual:** a host-root attacker can also forge completion records; the witness raises the cost of undetected suppression, it does not make completeness unconditional. The CC phase moves the recording termination point into the confidential guest.
- **The mode marker is self-declared by the shipper.** A suppresser who can ship a `session.end` marked `exec` can dodge the tar check for that session. This is a disclosed non-detection, bounded by the same pre-SNP floor (host root can forge anyway) and by the paired-event checks that still apply (start/end presence, sequence continuity, heartbeats). The mode marker is **not** a content claim — the witness never reads the event body.
- **In-flight exec sessions alert conservatively.** Live v18 `session.start` omits `interactive`, so a `.shell` start with no end cannot be told apart from an in-flight exec session; past the 10-min grace it raises `recording-gap` (the wording names the ambiguity) until the `.exec` end or the tar lands. Suppressing it would also silence a genuinely missing interactive recording — the check deliberately accepts that bounded false-positive window instead (see the recording-gap bullet above).
- **Clock source is `LastModified`, not the key text.** The grace clocks read S3 `LastModified`/`Initiated`; a re-PUT of a `session.start` key resets its gap grace, while a backlog replay after an outage re-ships old `<ts>` keys with fresh timestamps. A `<ts>`↔`LastModified` divergence check was considered and rejected as the higher-risk option: it would false-alarm exactly during legitimate backlog recovery, and an actor with audit-write access can forge the marker shapes anyway (pre-SNP floor). The shipper's HEAD-before-PUT blocks benign key replay; the residual is a reset of a grace clock, not a hidden gap.
- **Relabeled session events can be absorbed as non-session keys.** Drift is judged by shape; an event rewritten to the documented non-session shape (e.g. `<ts>-login.<seq>.json`) is indistinguishable from a legitimate non-session event and does not alert. Witness-side global sequence continuity was considered and rejected (interleaved streams make it noisy without a global anchor); the residual is disclosed rather than over-claimed.
- **SSH / Tier-0 sessions only.** The A2 checks correlate `session.*` lifecycle events and `recordings/<sid>.tar`, i.e. the SSH/Tier-0 recording pipeline. Non-SSH protocol recordings (`app.session.*`, `db.*`, `windows.*`) are not matched today; a missing DB/app/Windows recording is a **known non-detection**, re-derived when those pipelines land.
- **Operator-owned self-accountability:** pre-CC there is no third-party-completeness claim; the witness runs on the operator's own anchor. The Rekor-style external manifest leg is deferred to the CC phase.
- **Tenant reuse is parameterized, not free.** The check code is prefix/bucket-parameterized, but a tenant anchor must adopt the same shipper naming and provision the witness (repo secrets + key) itself; nothing transfers automatically.

Operational checks for maintainers live in [verification.md](verification.md) ("Recording witness"). The standing-credential inventory entry is in [security-posture.md](security-posture.md).
