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

**Policy (rendered on every `mode=apply`).** The track is derived from the repo pin in `010`: Caddy `caddy:2.11.4-alpine` -> `2.x.y-alpine`, Gatus `twinproduction/gatus:v5.36.0` -> `v5.x.y`. Minor and patch releases and same-tag rebuilds (a new digest under the same tag) flow; a new major, another repository name or another registry only arrives through a repo pin change and a dispatch (Lane B). Tags outside the exact track shape are ignored: `3.x`, `2.11.7` (no `-alpine`), `2.11.7-builder-alpine`, Windows tags, two-part tags such as `2.11-alpine`, and any numeral with a leading zero (`2.11.05` never aliases `2.11.5`).

**The repo pin runs by digest.** A provision run resolves each repo pin tag to its registry digest once (`docker pull` + the recorded `RepoDigests`), records it in `/var/lib/piercloud-img/<name>.pin` and runs that digest on every path: a fresh box, no updater record, `IMG_AUTO_UPDATES=off`, a reconcile drop. A pin that cannot be resolved refuses the run; nothing ever runs a bare tag. The record is re-resolved only when the pin tag changes.

**Caddy availability outranks updating.** tang's only listener for the main box is Caddy `:80`; Caddy down at the main box's boot means no unlock. Every rule below follows from that.

**Variables (approval-gated; the anchor's GitHub environment on a managed run).**

| Variable | Default | Values |
|---|---|---|
| `IMG_AUTO_UPDATES` | unset = **on** | `on`; `off` = updater removed, the box runs the repo pins (by their recorded digest) again (recorded state and a disarm deleted; bad-digest holds and pin records kept), status rows and token removed. Anything else refuses the run |
| `IMG_UPDATE_SOAK_HOURS` | `6` | whole hours `0`-`720`: a build is only taken once its registry push time (`tag_last_pushed`) is at least this old |

Both flow like the other operator-plane variables: `provision.yml` A1 env -> `020` `ENV_PREFIX` -> `010`; the repo-scope step refuses a managed dispatch while either is defined at repository or organization level.

**Updater.** `/usr/local/sbin/piercloud-img-update` (rendered by `010`; it embeds the very `010` helpers via `declare -f`, never a copy) runs from `piercloud-img-update.timer` (`OnActiveSec=30min`, `OnUnitInactiveSec=6h`, `RandomizedDelaySec=30min`) under `flock -n` on `/run/piercloud-img-update.lock`; a provision run holds the same lock from the Gatus section on, so the two never race. Per container (Gatus first, then Caddy):

1. **Live health first.** The running container must be up, be the recorded digest (`docker inspect` of its object id lists `repo@sha256:...`), and pass every self-check below. An unhealthy box never swaps (a candidate would be blamed for the box) and reports red `unhealthy:<class>`.
2. **Complete tag list.** Read the Docker Hub tags API (HTTPS only, `name=<major>.` filtered server-side, 100 per page) following `next` until it is null. Any page error, an off-host `next`, or reaching the 20-page cap fails the whole check closed: no update, row red `registry-listing-incomplete`. Never a partial list.
3. **Pick.** The newest tag in the track above the current version (or the same version with a different digest), soaked, not held as bad. A version that already had a held digest soaks again counted from the hold, so a same-version re-push is treated with suspicion.
4. **Pull by digest** (`repo@sha256:...`). A failed pull is retried next round (see the behind rule).
5. **Caddy only: validate the candidate by digest** (`docker run --rm --network none --cap-drop ALL --read-only --tmpfs /config --tmpfs /data <mounts> caddy@sha256:... caddy validate`, the same mounts as the provision validate, `img_caddy_validate`). If the candidate rejects the live Caddyfile, the running digest validates it too: when that also fails it is a Caddyfile problem (red `validate-config`, nothing held); otherwise the candidate is held (reason `validate`).
6. **Recreate** with exactly the provision `docker run` arguments (`img_run_gatus` / `img_run_caddy`), then **assert the running digest == the candidate** before any self-check.
7. **Self-checks, tang path first:** tang direct on loopback, tang **through Caddy `:80`**, Gatus statuses, then the TLS half: without a status host the check fails (`no-status-host`, never a silent pass); the serving Caddyfile carries the origin hardening (`assert_caddyfile_hardened`); with AOP the cert-less `:443` probe is rejected with a client-auth alert and the public edge returns 200; with an origin pair the local `:443` handshakes.
8. **Pass:** record `ref=repo:tag@sha256:...` in `<name>.state` (directory 0700, root-only).

**Failure ladder (any failed candidate).** The candidate digest is held (`<name>.bad`: digest, version, reason class, time). Then:

1. restore the **previous exact digest** with the same arguments and verify it (digest assert + self-checks, tang first): red `rolled-back ver=<tag> dig=<12 hex> reason=<class>`;
2. else fall back to the **provisioned pin digest** (`<name>.pin`) with the same arguments and verify it: red `fell-back-to-pin ... restore=<class>`, the record is dropped (the box is on the pin);
3. else leave the best-effort container running, send a **direct ntfy at once** (not only via Gatus: Gatus may be what broke), push red `all-rungs-failed ... disarmed`, and **disarm** the updater (`/var/lib/piercloud-img/disarmed`): no container is touched again, both rows report red `disarmed:<class>` every round, until the next `mode=apply` dispatch re-arms it.

**Status rows.** Two Gatus external endpoints in group `anchor`: `caddy updates` (key `anchor_caddy-updates`) and `gatus updates` (key `anchor_gatus-updates`), rendered through the shared external-endpoint span, each with `heartbeat.interval: 24h` (the updater pushes every ~6 h; four missed rounds = stale). Every push is **derived from checks run at push time**, never from a cached result, so a later round cannot report green while Caddy is down. Green means all of: live health passes, and the box runs the newest in-track build, or trails it by less than the soak + one cycle (7 h: the 6 h timer, its jitter and slack). A box held behind longer (a held digest, failing pulls, a rejected validate) is red `behind:<tag> reason:<class>` (`bad-<hold reason>`, `pull`, ...), so a frozen updater is never silently green. The error string carries only classes, a version and a 12-hex digest prefix; Gatus v5.36.0 stores it only on a failed result, so a green row shows no version (the current one is in the updater journal and on every red message). With a push channel (`NTFY_TOPIC`) a red row alerts once (native ntfy, priority 4, failure threshold 1, no resolve message) and stays red without re-alerting; the updater also pushes direct when Gatus does not take a red result, and always on `all-rungs-failed`. The direct push hands both the topic URL and the token to `curl -K -` on stdin (never argv).

**Clearing a hold.** Holds are not retried. A newer build in the track moves past them by itself; to take a held version anyway, raise the repo pin to that version and dispatch: a pin change clears every hold at or below the new pin (and the pin itself runs that version by its resolved digest).

**Token.** `010` generates a fresh random token on every run (`openssl rand -hex 32`) at `/etc/piercloud-img/status-token` (0600, root-only, directory 0700) and renders it into `/etc/gatus/config.yaml` (0600). The updater only reads both files (it never rewrites or re-modes them), hands the token to `curl -K -` on stdin, never on argv, and never prints it.

**Provenance.** Neither container publishes a verifiable signature (no cosign/notation signatures, empty referrers). The indexes carry only unsigned BuildKit attestations, and not uniformly: `caddy:2.11.4-alpine` has SLSA provenance on 7/7 platforms and an SPDX SBOM on 6/7 (none for arm/v6); `twinproduction/gatus:v5.36.0` has SLSA provenance on 3/3 and no SBOM. Unsigned statements prove nothing about who built a layer, so the updater does not pretend to verify them: payload trust is Docker Hub + the exact digest + the soak + the confined validate + the self-checks + the failure ladder ([security-posture.md](security-posture.md)).

**Drill (clean rollback, live proof).** As root on the box, with no dispatch and no remote trigger: `IMG_DRILL=caddy flock -n /run/piercloud-img-update.lock /usr/local/sbin/piercloud-img-update` (or `IMG_DRILL=gatus`). After the live-health check passes, the round recreates the **current** digest as the candidate, fails it on purpose (a candidate-scoped fault), and walks the ladder. Expected per step: the container is recreated twice on the same digest; the row turns red with `rolled-back drill ver=<current> dig=<12 hex> reason=drill` (one ntfy when a topic is set); no hold, no disarm; the next round is green. A drill ending in `fell-back-to-pin` or `all-rungs-failed` is a real restore failure (the ladder acts on it as such).

**Harness.** `tests/img-updater/run-test.sh` (in `ci.yml`) extracts the real spans, stubs docker/curl/systemctl and replays recorded Docker Hub tag listings (no network): track filter (incl. leading zeros), soak, precedence on the pin digest, pin resolution and hold expiry, the paged listing (a 4-page stub, a page error, the 20-page cap), candidate binding (validate by digest, confined; a running-digest mismatch), every ladder rung (rolled back, pin fallback, all rungs failed + direct ntfy + disarm, Gatus down), live-derived status (Caddy down, `:80` broken, tang first, no status host, hardening, digest drift), the behind rule, the drill, the off switch, install modes, token handling and the dispatch plumbing, with a mutant per rule.

**Honest residuals.** A compromised upstream publisher account can ship a malicious build within the track; the soak, the confined validate and the self-checks narrow but do not close that window (a hostile build that serves correctly passes them). The self-checks prove serving, not behaviour under every request. A failed swap costs Caddy seconds of downtime per rung. The updater cannot repair a box that was already unhealthy before a round: it reports red and leaves the fix to a dispatch.
