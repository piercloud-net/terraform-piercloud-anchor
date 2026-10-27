# On-box updaters (Lane A, issue #51)

The anchor applies a narrow class of updates by itself between dispatches: the bits neither the operator nor the tenant chooses. Everything that decides **what** may install (allowed origins, reboot window, container track, soak, schedule, the updater code itself) is rendered by `scripts/010-provision.sh` in a per-run approved dispatch; only the payload floats. The scoped invariant-2 amendment is in [invariants.md](invariants.md); credentials are inventoried in [security-posture.md](security-posture.md); the off switches are in [dr.md](dr.md).

## OS security updates + kernel reboot window (slice A-OS)

**Policy (rendered on every `mode=apply`).** `010` installs `unattended-upgrades` and writes `/etc/apt/apt.conf.d/52piercloud-unattended-upgrades`:

- The allowed origin is the running release's **security pocket only**, chosen from `/etc/os-release` `ID` at render time: Debian -> `origin=Debian,codename=${distro_codename}-security,label=Debian-Security`; Ubuntu -> `origin=Ubuntu,archive=${distro_codename}-security`. Any other `ID` (including derivatives such as Raspbian) refuses the run (fail closed). No `-updates`, `-proposed`, backports, ESM or third-party origins.
- `#clear` lines drop the distro defaults (`Origins-Pattern` and `Allowed-Origins` lists from `50unattended-upgrades`), so the rendered pattern is the whole policy.
- `APT::Periodic::Update-Package-Lists "1"`, `APT::Periodic::Unattended-Upgrade "1"`, `Remove-Unused-Kernel-Packages "true"`, `Automatic-Reboot "true"` at the reboot window (`Automatic-Reboot-WithUsers "true"`: nobody logs in to the anchor).
- Timer drop-ins (`piercloud-os-updates.conf`): `apt-daily.timer` at 01:30 UTC and `apt-daily-upgrade.timer` at 02:30 UTC, each with `RandomizedDelaySec=15m`, so a kernel lands before the default 03:30 window and boots the same night.

**Variables (approval-gated; the anchor's GitHub environment on a managed run).**

| Variable | Default | Values |
|---|---|---|
| `OS_AUTO_UPDATES` | unset = **on** | `on`; `off` = actively disabled (`APT::Periodic::Unattended-Upgrade "0"`, empty origin list, no status row, report script and token removed). Anything else refuses the run |
| `OS_AUTO_REBOOT_TIME` | `03:30` | `HH:MM` UTC between `00:00` and `04:59`. A time before the upgrade run (e.g. `00:30`) reboots the following night |

Both flow like the other operator-plane variables: `provision.yml` A1 env -> `020` `ENV_PREFIX` -> `010`; the repo-scope step refuses a managed dispatch while either is defined at repository or organization level (`tests/managed-operator-plane`).

**Reboot and tang.** A reboot takes tang down for about a minute; tang matters only when the main box boots in that same minute. `tangd.socket` is socket-activated and enabled, so tang comes back by itself; the converge checks below refuse a run where it is not enabled. `Automatic-Reboot-Time` is handed to `shutdown(8)`, which reads local time: on a non-UTC box the run renders the converted local time and warns (re-dispatch after a DST change).

**Status row.** One Gatus external endpoint, `os-security-updates` in group `anchor` (key `anchor_os-security-updates`), with `heartbeat.interval: 26h`. A drop-in adds `ExecStartPost=-/usr/local/sbin/piercloud-os-updates-report.sh` to `apt-daily-upgrade.service`; the script pushes `POST /api/v1/endpoints/anchor_os-security-updates/external?success=&error=&duration=` to the loopback Gatus:

- `success=true` when the newest of `/var/lib/apt/periodic/unattended-upgrades-stamp` (written by `unattended-upgrade` only after a successful run) and the install marker `/var/lib/piercloud/os-updates.installed` is younger than 48 h. The marker is touched on a fresh or re-enabled install, so a new box gets 48 h of grace.
- The `error` field carries counts only: `[stale-over-48h,]pending-security:<n>,reboot-required:<yes|no>,last-ok-age-h:<h|never>`. Gatus v5.36.0 records it only on a failed result, so a green row shows no counts.
- A missed heartbeat (no push for 26 h: the timer, the service or the script is dead) records a failure. With a push channel (`NTFY_TOPIC`) the row alerts once at class 4 (native ntfy, priority 4, recovery message); routine success never pushes.
- The provision run pushes once after Gatus is up (retrying across the config reload) so the row is green straight after a dispatch.

**Token.** The external endpoint needs a bearer token. `010` generates a fresh random token on every run (`openssl rand -hex 32`), stores it at `/etc/piercloud/os-updates.token` (0600, root-only) and renders it into `/etc/gatus/config.yaml`. The report script hands it to `curl -K -` on stdin, never on argv, and never prints it. It can only push results for this one row on the loopback-bound Gatus. Because the token changes per run, every dispatch re-renders `config.yaml` (Gatus reloads it).

**Converge self-checks (each fails the run closed).**

- `apt-config dump` shows exactly the rendered origin and no `Allowed-Origins` entry (another `apt.conf.d` file cannot widen the policy unseen).
- `unattended-upgrade --dry-run` exits 0 on the rendered config.
- `systemctl is-enabled tangd.socket` is `enabled`.
- `apt-daily.timer` and `apt-daily-upgrade.timer` are enabled and load their drop-ins; with updates on, `apt-daily-upgrade.service` loads the report drop-in.

**Harness.** `tests/os-updates/run-test.sh` (in `ci.yml`) extracts the real span and proves the per-distro pattern and refusal, the off switch, the window validation, token handling, the staleness logic, the converge checks and the shared `GATUS EXTERNAL` render, with a mutant per rule.

**Honest residuals.** Payload trust is the distribution's signed archive (apt's own signature check); the anchor adds no extra verification. A broken security update can take the box down until a rollback dispatch (see [dr.md](dr.md)). The window is at most one security update per night plus one reboot; live services (Caddy, Gatus) run in containers and are untouched by apt, except that a `docker.io` security update restarts the Docker daemon.


## Caddy + Gatus containers within the approved major line (slice A-IMG)

**Policy (rendered on every `mode=apply`).** The track is derived from the repo pin in `010`: Caddy `caddy:2.11.4-alpine` -> `2.x.y-alpine`, Gatus `twinproduction/gatus:v5.36.0` -> `v5.x.y`. Minor and patch releases and same-tag rebuilds (a new digest under the same tag) flow; a new major, another repository name or another registry only arrives through a repo pin change and a dispatch (Lane B). Tags outside the exact track shape are ignored: `3.x`, `2.11.7` (no `-alpine`), `2.11.7-builder-alpine`, Windows tags and two-part tags such as `2.11-alpine`.

**Variables (approval-gated; the anchor's GitHub environment on a managed run).**

| Variable | Default | Values |
|---|---|---|
| `IMG_AUTO_UPDATES` | unset = **on** | `on`; `off` = updater removed, the box runs the repo pins again (recorded state deleted, bad-digest holds kept), status rows and token removed. Anything else refuses the run |
| `IMG_UPDATE_SOAK_HOURS` | `6` | whole hours `0`-`720`: a build is only taken once its registry push time (`tag_last_pushed`) is at least this old |

Both flow like the other operator-plane variables: `provision.yml` A1 env -> `020` `ENV_PREFIX` -> `010`; the repo-scope step refuses a managed dispatch while either is defined at repository or organization level.

**Updater.** `/usr/local/sbin/piercloud-img-update` (rendered by `010`; it embeds the very `010` helpers via `declare -f`, never a copy) runs from `piercloud-img-update.timer` (`OnActiveSec=30min`, `OnUnitInactiveSec=6h`, `RandomizedDelaySec=30min`) under `flock -n` on `/run/piercloud-img-update.lock`; a provision run holds the same lock from the Gatus section on, so the two never race. Per container (Gatus first, then Caddy):

1. Read the Docker Hub tags API (up to 3 pages, HTTPS only) and pick the newest tag in the track that is above the current version (or the same version with a different digest), soaked, and not held as bad.
2. Pull it **by digest** (`repo@sha256:...`). A pull or registry failure is logged and retried next round (no alert; the 26 h heartbeat catches a persistent outage).
3. Caddy only: `caddy validate` the **live** Caddyfile with the candidate, with exactly the mounts the provision validate uses (`img_caddy_validate`). A rejection marks the digest bad.
4. Recreate the container with exactly the `docker run` arguments provision uses (`img_run_gatus` / `img_run_caddy`, shared by both).
5. Run the converge self-checks: Gatus serves `/api/v1/endpoints/statuses`, tang answers direct on loopback, Caddy `:80` proxies tang, the serving Caddyfile carries the origin hardening (`assert_caddyfile_hardened`), and with a status host the cert-less `:443` probe is rejected at TLS with a client-auth alert and the public edge returns 200 (`certless_probe` / `edge_pull_200`, shared with the provision run).
6. Pass: record `ref=repo:tag@sha256:...` in `/var/lib/piercloud-img/<name>.state` (directory 0700, root-only) and push `success=true`. Fail: hold the digest as bad (`<name>.bad`, never retried), restore the previous reference, re-run the checks, and push `success=false` with `rolled-back ver=<tag> dig=<12 hex> reason=<class>` (or `restore-failed ...`).

**Precedence with the repo pin.** A provision run uses max(repo pin, recorded current) within the same track: it never downgrades below what the updater moved to; a pin above the recorded version wins; a pin in a different major (or repository) resets the track and deletes the recorded state; a recorded digest that is held as bad is never selected. `IMG_AUTO_UPDATES=off` returns to the pin.

**Status rows.** Two Gatus external endpoints in group `anchor`: `caddy updates` (key `anchor_caddy-updates`) and `gatus updates` (key `anchor_gatus-updates`), rendered through the shared external-endpoint span, each with `heartbeat.interval: 26h`. Every run pushes `POST /api/v1/endpoints/{key}/external?success=&error=&duration=` to the loopback Gatus. The error string carries only the version, a 12-hex digest prefix and a reason class. With a push channel (`NTFY_TOPIC`) a red result alerts once (native ntfy, priority 4, failure threshold 1, no resolve message); since a bad digest is never retried, one bad candidate is one alert, and routine success never pushes. The updater sends a direct ntfy only when it cannot reach Gatus to report a failure.

**Token.** `010` generates a fresh random token on every run (`openssl rand -hex 32`) at `/etc/piercloud-img/status-token` (0600, root-only, directory 0700) and renders it into `/etc/gatus/config.yaml` (0600). The updater only reads both files (it never rewrites or re-modes them), hands the token to `curl -K -` on stdin, never on argv, and never prints it.

**Provenance.** Neither container publishes a verifiable signature (no cosign/notation signatures, empty referrers); both indexes carry only unsigned BuildKit attestations (SPDX/SLSA in-toto statements). There is no pinned identity to verify, so the updater does not pretend to: payload trust is Docker Hub + the exact digest + the soak + the self-checks + the automatic rollback ([security-posture.md](security-posture.md)).

**Harness.** `tests/img-updater/run-test.sh` (in `ci.yml`) extracts the real spans, stubs docker/curl/systemctl and replays recorded Docker Hub tag listings (no network): track filter, soak, precedence, bad-digest hold, validate rejection, rollback and restore failure, the off switch, install modes, token handling and the dispatch plumbing, with a mutant per rule.

**Honest residuals.** A compromised upstream publisher account can ship a malicious build within the track; the soak and self-checks narrow but do not close that window. The self-checks prove serving, not behaviour under every request. A rollback is to the previous digest only; anything older is a dispatch with `IMG_AUTO_UPDATES=off` (back to the pins) or a pin change.
