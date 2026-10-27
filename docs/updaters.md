# Updaters

Two kinds of update keep the anchor current: Renovate bumps the pins in this repo (a pin change reaches a box through an approved dispatch; for the Gatus and Caddy images, a newer build in the pin's major track also reaches a box between dispatches through the on-box image lane once soaked), and the on-box updaters (Lane A, issue #51) apply the narrow class of updates neither the operator nor the tenant chooses.

## Dependency updates (Renovate)

Renovate (`renovate.json`) keeps the pins in this repo current. This page is the policy; `renovate.json` is the mechanism. Package rules apply in file order and a later rule overrides an earlier one, except forced rules (see below), so the operator-owned rule R10 sits last.

### Policy

- Advisory fixes (a vulnerable version in use, from Dependabot alerts or OSV): minor and patch bumps automerge with no soak once CI is green (R3). Advisory majors wait for a human.
- Routine minor and patch bumps automerge after a 7-day soak (`minimumReleaseAge`, R1). The status check stays pending until the age passes (`internalChecksFilter: strict`).
- Digest moves (the same tag re-pointed to a new digest) and initial pins (`pin`, `pinDigest`) never automerge, routine or advisory (R2b). A moved tag is the hijack signature, so a human reviews it.
- Majors, routine and advisory, are a PR for human review (R2).
- Netcup-touching paths (`scripts/**`, `.github/scripts/**`, `**/*.tf`, `examples/**`) never automerge, advisory or not (R4, R6). Routine and advisory bumps there group into one `netcup-touching batch` PR labelled `netcup-touching`. `.github/workflows/provision.yml` follows the same batch for every update type, advisory included (R6c): the legacy `anchor` environment is unprotected (see Residual below), so those bumps are human.
- The Gatus and Caddy images pinned in `scripts/010-provision.sh` sit outside that batch (R5). Minor and patch bumps follow the routine soak, advisory fixes automerge with no soak (R3), and majors wait. Gatus and Caddy on any other netcup-touching path never automerge (R6b). On a box, newer builds in the pinned major track (same-tag rebuilds included) also arrive without a pin bump through the on-box image lane: [Gatus and Caddy images (slice A-IMG)](#gatus-and-caddy-images-slice-a-img).
- `cad0p/semver-calver-release` is operator-owned: it runs with `contents: write` in the release workflows. It never automerges, any update type, advisory included, and is labelled `operator-owned` (R10, last).
- OpenTofu: `.opentofu-version` and the `tofu_version` input of `opentofu/setup-opentofu` in `provision.yml` are one group `opentofu` (R7). The group never automerges (R7, `automerge: false`), so `.opentofu-version` bumps are human too: the group contains the `provision.yml` input, which is human (R6c), and Renovate automerges a group only when every member does (`workers/repository/updates/generate.js:251` in the 44.184.1 dist). An update rewrites all three locations: two in `provision.yml`, one in `.opentofu-version`. Each pin is extracted once: the github-actions manager reads the `provision.yml` inputs and one regex reads `.opentofu-version`. `tests/opentofu-pin` fails if the files disagree.
- GitHub Actions pins are commit SHAs with an exact-version comment (`# v7.0.1`), which Renovate tracks (R8). A pin whose comment Renovate cannot parse (for example `# tag: v7`) is skipped as `unversioned-reference`, so every pin uses the exact-version form.
- The `tofu_version` input is a version string, not a digest (R9, `pinDigests: false`).
- `lockFileMaintenance` is off, and no rule targets `.terraform.lock.hcl`: no tracked file matches it, so there is no lock-file update path.
- Notifications use Renovate defaults.

### Why the advisory fast lane is a packageRule

Renovate applies the `vulnerabilityAlerts` block as a forced rule. It sets `minimumReleaseAge: null` (no soak), and its keys win over later rules, so an `automerge: true` there would override the netcup denies (R4, R6). The fast lane is therefore R3, a `matchJsonata` rule (`isVulnerabilityAlert = true`) placed before the denies. R6 denies advisory updates on netcup paths after it.

### Release timestamps: what the soak measures

The soak compares `minimumReleaseAge` with a timestamp that depends on the datasource (Renovate 44.184.1 source):

| Datasource | Pins | Timestamp used | Backdatable by the publisher? |
|---|---|---|---|
| `github-tags` | GitHub Actions `uses:` with `# vX.Y.Z` | The later of the tag date and the GitHub Release timestamp, when a release exists (`github-tags/index.js:60-61`). The release timestamp is the GraphQL `publishedAt`, which Renovate stores as `releaseTimestamp` (`releases-query-adapter.js:18`). Tag date: a lightweight tag uses the target commit's `committedDate`; an annotated tag uses the tagger date (`tags-query-adapter.js:41`, `:56`) | Yes, while no GitHub Release exists. Commit and tagger dates are author-set |
| `github-releases` | `opentofu/opentofu` (`.opentofu-version`, `provision.yml`) | The release's `releaseTimestamp`, from the GraphQL `publishedAt` (`github-releases/index.js:58-62`, `releases-query-adapter.js:18`) | No, when set: server time |
| `github-digest` | not used (every action pin is versioned) | commit date (`index.js:15`) | Yes |
| `docker` | Gatus, Caddy (Docker Hub only) | `tag_last_pushed` (`docker/index.js:627-628`) | Registry push time, not the upstream release time |

Residual: the soak measures the age of that timestamp, not the age of the release. A backdated commit behind a new version tag, with no GitHub Release, carries an old timestamp and passes the soak at once. The soak is therefore not a defence against a hijacked tag. The remaining defences are:

- required checks: `unit-tests (scripts)` and `bind-proof e2e (Caddy fronting mock tang)` must pass before automerge (required on `main` by the ruleset since 2026-10-27);
- SHA pinning: a moved tag shows as a visible SHA diff in the PR;
- least-permission workflow tokens.

`provision.yml` is not a defence. Its `workflow_dispatch` is not an approval gate: the legacy default `anchor` environment (`environment:` at `provision.yml:404`) has no protection rules, and the device-flow job runs with `NTFY_TOKEN` and `SCP_USER_ID` in scope. Its bumps are therefore human (R6c), routine and advisory alike.

### Advisory data

- Advisory data covers GitHub Actions only: Dependabot alerts (a repository setting; alerts only, Dependabot security-update PRs stay off, so Renovate is the only PR author) and OSV (`osvVulnerabilityAlerts: true`, queried by Renovate).
- Dependabot alerts are enabled on the repository (since 2026-10-27); OSV runs alongside as a cross-check.
- Docker images (Gatus, Caddy), the terraform provider (`rixlhq/netcup`) and OpenTofu have no advisory feed here. The R3 lane applies to them only if a feed flags them. Trivy (#249) covers image contents and the provider binary.

### Required check names

- `unit-tests (scripts)` and `bind-proof e2e (Caddy fronting mock tang)` (job names in ci.yml). The short form `bind-proof e2e` matches no job.

## On-box updaters (Lane A, issue #51)

The anchor applies a narrow class of updates by itself between dispatches: the bits neither the operator nor the tenant chooses. Everything that decides **what** may install (allowed origins, reboot window, container track, soak, schedule, the updater code itself) is rendered by `scripts/010-provision.sh` in a per-run approved dispatch; only the payload floats. The scoped invariant-2 amendment is in [invariants.md](invariants.md); credentials are inventoried in [security-posture.md](security-posture.md); the off switches are in [dr.md](dr.md).

### OS security updates + kernel reboot window (slice A-OS)

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

### Gatus and Caddy images (slice A-IMG)

**Policy (rendered on every `mode=apply`).** The track is derived from the repo pin in `010`: Caddy `caddy:2.11.6-alpine` -> `2.x.y-alpine`, Gatus `twinproduction/gatus:v5.37.0` -> `v5.x.y`. Minor and patch releases and same-tag rebuilds (a new digest under the same tag) flow; a new major, another repository name or another registry only arrives through a repo pin change and a dispatch (Lane B). Tags outside the exact track shape are ignored: `3.x`, `2.11.7` (no `-alpine`), `2.11.7-builder-alpine`, Windows tags, two-part tags such as `2.11-alpine`, and any numeral with a leading zero (`2.11.05` never aliases `2.11.5`).

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
