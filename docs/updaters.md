# On-box updaters (Lane A, issue #51)

The anchor applies a narrow class of updates by itself between dispatches: the bits neither the operator nor the tenant chooses. Everything that decides **what** may install (allowed origins, reboot window, schedule, the updater code itself) is rendered by `scripts/010-provision.sh` in a per-run approved dispatch; only the payload floats. The scoped invariant-2 amendment is in [invariants.md](invariants.md); credentials are inventoried in [security-posture.md](security-posture.md); the off switches are in [dr.md](dr.md).

## OS security updates + kernel reboot window (slice A-OS)

**Policy (rendered on every `mode=apply`).** `010` installs `unattended-upgrades` and writes `/etc/apt/apt.conf.d/52piercloud-unattended-upgrades`:

- The allowed origin is the running release's **security pocket only**, chosen from `/etc/os-release` `ID` at render time: Debian -> `origin=Debian,codename=${distro_codename}-security,label=Debian-Security`; Ubuntu -> `origin=Ubuntu,archive=${distro_codename}-security`. Any other `ID` (including derivatives such as Raspbian) refuses the run (fail closed). No `-updates`, `-proposed`, backports, ESM or third-party origins.
- `#clear` lines drop the distro defaults (`Origins-Pattern` and `Allowed-Origins` lists from `50unattended-upgrades`), so the rendered pattern is the whole policy.
- `APT::Periodic::Update-Package-Lists "1"`, `APT::Periodic::Unattended-Upgrade "1"`, `Remove-Unused-Kernel-Packages "true"`. `Unattended-Upgrade::Automatic-Reboot` is always `"false"`: the reboot is the gated timer below, not unattended-upgrade's.
- Timer drop-ins (`piercloud-os-updates.conf`): `apt-daily.timer` at 01:30 UTC and `apt-daily-upgrade.timer` at 02:30 UTC, each with `RandomizedDelaySec=15m`, so a kernel lands before the default 03:30 window and boots the same night.
- **UTC.** The run sets the box timezone to UTC (`timedatectl set-timezone UTC` when it is not) and refuses a box that stays non-UTC; the converge line reads `box timezone is UTC (OK)`. Every timer also states `UTC` in its `OnCalendar=`, so there is no render-time local-time conversion.

**Refusal discipline.** Input validation, `tangd.socket` enabled and UTC are checked before anything is written. Any refusal, before or after arming (bad variable, unsupported distro, an origin apt sees beyond the rendered one, a failing `--dry-run`, a timer without its drop-in, a disabled reboot timer), first **disarms** the box: the policy file is rewritten with `APT::Periodic::Unattended-Upgrade "0"` and `Automatic-Reboot "false"`, the three timer/service drop-ins, the reboot timer + service, the report script, the gate script and the token are removed, then the run fails. A refused run never leaves a widened or half-armed box.

**Variables (approval-gated; the anchor's GitHub environment on a managed run).**

| Variable | Default | Values |
|---|---|---|
| `OS_AUTO_UPDATES` | unset = **on** | `on`; `off` = disarmed (as above; the run logs `OS updates: DISABLED by the approval-gated variable OS_AUTO_UPDATES=off ...` and the `os-security-updates` row is removed from the status page). Anything else refuses the run (and disarms) |
| `OS_AUTO_REBOOT_TIME` | `03:30` | `HH:MM` UTC between `00:00` and `04:59`. A time before the upgrade run (e.g. `00:30`) reboots the following night |

Both flow like the other operator-plane variables: `provision.yml` A1 env -> `020` `ENV_PREFIX` -> `010`; the repo-scope step refuses a managed dispatch while either is defined at repository or organization level (`tests/managed-operator-plane`). Trust model of `off`: it is an approval-gated environment variable like every other operator-plane input, so turning updates off takes the same approved dispatch as turning them on; the removed row plus the `DISABLED` converge line are the visible trace.

**Reboot gate.** `piercloud-os-reboot.timer` (`OnCalendar=*-*-* <window>:00 UTC`, `Persistent=false`, no jitter) starts `piercloud-os-reboot.service`, a oneshot whose `ExecCondition=/usr/local/sbin/piercloud-os-reboot-gate.sh` reboots (`systemctl reboot`) only when all hold:

- `/run/reboot-required` exists (written by the kernel/libc postinst);
- no provision run is alive: every `010` run writes `/run/piercloud-provision.pid` (pid + process start time) at its top, before any tang key work; the gate holds while that exact process lives, and ignores a stale file from a dead run or a reused pid;
- no tang key rotation is pending (`<tang keys dir>/.rotation-pending`): the reboot is held until the operator clears the marker after the rebind (docs/dr.md); the report shows `reboot-required:held-rotation`;
- `apt-daily-upgrade.service` is not running.

A held reboot retries at the next night's window. Chosen over a systemd inhibitor because root's scheduled shutdown bypasses block inhibitors, and over unattended-upgrade's own `Automatic-Reboot` because that schedules `shutdown -r` in logind with no hook to veto it later.

**Reboot and tang.** A reboot takes tang down for about a minute; tang matters only when the main box boots in that same minute. `tangd.socket` is socket-activated and enabled, so tang comes back by itself; the converge checks refuse a run where it is not enabled.

**Status row.** One Gatus external endpoint, `os-security-updates` in group `anchor` (key `anchor_os-security-updates`), with `heartbeat.interval: 26h`. A drop-in adds `ExecStopPost=-/usr/local/sbin/piercloud-os-updates-report.sh --after-run` to `apt-daily-upgrade.service` (runs after success and failure). Green means **actually current**:

- pending security updates are known (`apt-get -s dist-upgrade` and `apt list --upgradable` both succeeded; unknown is always red), and
- **0** security updates are pending, counting both the installable ones and the **kept-back / held** ones (below), and
- the newest `/var/lib/apt/lists/*security*InRelease` is younger than 48 h (absent lists are red), and
- either the last **real run** is younger than 48 h, or the **fresh-install grace** holds (no real run since the install marker `/var/lib/piercloud/os-updates.installed`, and the marker is younger than 26 h: the grace ends at the first real run or after 26 h, whichever comes first).

The grace excuses **only the absence of a completed run**. Pending security updates and stale or absent security lists are red inside the grace too, so a fresh install with pending security updates, or a failed first run on week-old lists, is red at once instead of green for up to 26 h.

**Kept-back security updates.** A security upgrade that apt keeps back (it needs a new dependency or a removal) or that is held (`apt-mark hold`) has no `Inst` line in the `apt-get -s dist-upgrade` simulation, and unattended-upgrades will not install it: it needs a human. The report therefore also reads `apt list --upgradable` and takes every candidate whose suite list (the field after `/`, comma-separated) has an entry ending in `-security`: `stable-security` on Debian trixie (apt 3.0), `noble-updates,noble-security` on Ubuntu 24.04 (apt 2.8). `apt list` shows the candidate whatever the resolver decided, so a kept-back or held package is listed there but not in the simulation. The pending count is the union of both (deduplicated by package name); the ones listed but not simulated are `kept-back-security` and add the reason `security-kept-back`. Checked against the real apt in `debian:trixie-slim` and `ubuntu:24.04`: holding one pending security package moved the simulation `Inst` count down by one while the list kept it, and the report counted it as kept back. A kept-back non-security package does not count. Fix it from the console (`apt-get install <pkg>` or `apt-get dist-upgrade` after reading what it removes, or `apt-mark unhold`).

The real-run marker `/var/lib/piercloud/os-updates.last-run` is written only by `--after-run`, i.e. by the ExecStopPost of a `SERVICE_RESULT=success` apt-daily-upgrade whose `/var/lib/apt/periodic/upgrade-stamp` (written by `apt.systemd.daily` only after unattended-upgrade returned 0) is younger than 26 h. The converge `unattended-upgrade --dry-run` touches unattended-upgrade's own stamp, never this marker, so a re-dispatch cannot reset the staleness alarm. The InRelease mtime is the archive's publish time (apt sets it from the server); the Debian and Ubuntu security archives re-sign far more often than every 48 h (trixie-security observed 6.7 h old at fetch).

- The `error` field carries reasons and counts only: `[pending-unknown|run-stale-over-48h,lists-stale-over-48h,security-pending,security-kept-back,]pending-security:<n>,kept-back-security:<n>,reboot-required:<yes|no|held-rotation>,last-run-age-h:<h|never>,lists-age-h:<h|never>,grace:<yes|no>`. Gatus v5.36.0 records it only on a failed result.
- A missed heartbeat (no push for 26 h) records a failure. With a push channel (`NTFY_TOPIC`) the row alerts once at class 4 (native ntfy, `provider-override: priority: 4`, confirmed against Gatus v5.36.0 `alerting/alert/alert.go` and the ntfy provider's `GetConfig` merge; recovery message); routine success never pushes.
- The report script bakes every path, threshold and command (`/usr/bin/apt-get`, `/usr/bin/apt`, `/usr/bin/curl`, ...) at render time, sets a fixed `PATH`, and reads no `OS_UPD_*` override from its environment.

**Run-once in the dispatch.** After Gatus restarted, the run clears `upgrade-stamp` (otherwise `apt.systemd.daily` skips a second run the same day), runs `timeout 900 systemctl start apt-daily-upgrade.service` synchronously (the ExecStopPost pushes the real-run result), then runs the report once more and logs the row state with counts only. A failed or timed-out run-once, a red row, or a push that does not land is a `WARNING:` line naming the cause class (`service-failed`, `timeout`, `token-missing`, `token-rejected-401`, `gatus-unreachable`, `gatus-http-<code>`), never a hard fail. `OS_AUTO_UPDATES=off` skips it.

**Token.** The external endpoint needs a bearer token. `010` generates a fresh random token on every run (`openssl rand -hex 32`) and renders it into `/etc/gatus/config.yaml`. The swap is ordered so no push 401s: before the in-place config write the run drops `/run/piercloud-os-updates.swap` (pid + start time; reports wait up to 5 min while it is live), the token file `/etc/piercloud/os-updates.token` (0600, root-only) is written only after the config landed byte-identical, and the swap marker clears only after Gatus restarted on the new config. A run that dies earlier keeps the old token + old config pair. The report hands the token to `curl -K -` on stdin (heredoc), never on argv, and never prints it. The push API is reachable only on Gatus's loopback port: Caddy refuses `/api/v1/endpoints/*/external` and every non-GET/HEAD `/api/v1/endpoints/*` path on the dashboard leg for every peer (converge line `serving Caddyfile refuses the Gatus push API on the dashboard leg`; behaviour checked against `caddy:2.11.4-alpine`: upper case, trailing slash, double slash, `%2F` and `/./` spellings all abort).

**Gatus config mode.** `/etc/gatus/config.yaml` holds bearer tokens (ntfy, this row) and is written 0600 root-only: the staging file is created 0600, an existing file is tightened before the new bytes land, and the converge asserts the mode (`Gatus config is mode 0600 ... (OK)`). The Gatus image is `FROM scratch` with no `USER`, so the container reads the bind-mounted file as root. Before #51 the file was written with the default umask (0644) with the ntfy token inside: a pre-existing leak this change closes.

**Converge self-checks (each fails the run closed and disarms).**

- `apt-config dump` shows exactly the rendered origin and no `Allowed-Origins` entry (another `apt.conf.d` file cannot widen the policy unseen).
- `unattended-upgrade --dry-run` exits 0 on the rendered config.
- `systemctl is-enabled tangd.socket` is `enabled`; the box timezone is UTC.
- `apt-daily.timer`, `apt-daily-upgrade.timer` and `piercloud-os-reboot.timer` are enabled; the two apt timers and `apt-daily-upgrade.service` load their drop-ins.

**Harness.** `tests/os-updates/run-test.sh` (in `ci.yml`) extracts the real span and proves the per-distro pattern and refusal, disarm on every refusal, the off switch, UTC enforcement, the window validation and its 1:1 mapping onto the UTC timer (run under `TZ=Europe/Rome`), the token commit order, the green matrix, the grace scope (it never masks pending updates or stale lists), kept-back security upgrades on the Debian and Ubuntu `apt list` shapes, the real-run marker, env-override immunity, the swap wait, the reboot gate, the run-once warnings, the Gatus config mode and the shared `GATUS EXTERNAL` render, with a mutant per rule. `tools/vm-timetravel/run.sh` is the manual VM time-travel proof (not in CI; [verification.md](verification.md)).

**Honest residuals.** Payload trust is the distribution's signed archive (apt's own signature check); the anchor adds no extra verification. A broken security update can take the box down until a rollback dispatch (see [dr.md](dr.md)). The window is at most one security update per night plus one reboot; live services (Caddy, Gatus) run in containers and are untouched by apt, except that a `docker.io` security update restarts the Docker daemon. Root on the box can fake the row (it holds the token); that is inside the trust boundary.
