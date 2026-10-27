# On-box updaters (Lane A, issue #51)

The anchor applies a narrow class of updates by itself between dispatches: the bits neither the operator nor the tenant chooses. Everything that decides **what** may install (allowed origins, reboot window, schedule, the updater code itself) is rendered by `scripts/010-provision.sh` in a per-run approved dispatch; only the payload floats. The scoped invariant-2 amendment is in [invariants.md](invariants.md); credentials are inventoried in [security-posture.md](security-posture.md); the off switches are in [dr.md](dr.md).

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
