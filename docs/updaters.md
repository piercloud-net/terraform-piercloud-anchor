# Dependency updaters

Renovate (`renovate.json`) keeps the pins in this repo current. This page is the policy; `renovate.json` is the mechanism. Package rules apply in file order and a later rule overrides an earlier one, except forced rules (see below), so the operator-owned rule R10 sits last.

## Policy

- Advisory fixes (a vulnerable version in use, from Dependabot alerts or OSV): minor and patch bumps automerge with no soak once CI is green (R3). Advisory majors wait for a human.
- Routine minor and patch bumps automerge after a 7-day soak (`minimumReleaseAge`, R1). The status check stays pending until the age passes (`internalChecksFilter: strict`).
- Digest moves (the same tag re-pointed to a new digest) and initial pins (`pin`, `pinDigest`) never automerge, routine or advisory (R2b). A moved tag is the hijack signature, so a human reviews it.
- Majors, routine and advisory, are a PR for human review (R2).
- Netcup-touching paths (`scripts/**`, `.github/scripts/**`, `**/*.tf`, `examples/**`) never automerge, advisory or not (R4, R6). Routine bumps group into one `netcup-touching batch` PR labelled `netcup-touching`. Advisory fixes there open individual PRs, each needing review.
- The Gatus and Caddy images pinned in `scripts/010-provision.sh` sit outside that batch (R5). Minor and patch bumps follow the routine soak, advisory fixes automerge with no soak (R3), and majors wait. Gatus and Caddy on any other netcup-touching path never automerge (R6b).
- `cad0p/semver-calver-release` is operator-owned: it runs with `contents: write` in the release workflows. It never automerges, any update type, advisory included, and is labelled `operator-owned` (R10, last).
- OpenTofu: `.opentofu-version` and the `tofu_version` input of `opentofu/setup-opentofu` in `provision.yml` are one group `opentofu` (R7). An update rewrites all three locations: two in `provision.yml`, one in `.opentofu-version`. Each pin is extracted once: the github-actions manager reads the `provision.yml` inputs and one regex reads `.opentofu-version`. `tests/opentofu-pin` fails if the files disagree.
- GitHub Actions pins are commit SHAs with an exact-version comment (`# v7.0.1`), which Renovate tracks (R8). A pin whose comment Renovate cannot parse (for example `# tag: v7`) is skipped as `unversioned-reference`, so every pin uses the exact-version form.
- The `tofu_version` input is a version string, not a digest (R9, `pinDigests: false`).
- `lockFileMaintenance` is off, and no rule targets `.terraform.lock.hcl`: no tracked file matches it, so there is no lock-file update path.
- Notifications use Renovate defaults.

## Why the advisory fast lane is a packageRule

Renovate applies the `vulnerabilityAlerts` block as a forced rule. It sets `minimumReleaseAge: null` (no soak), and its keys win over later rules, so an `automerge: true` there would override the netcup denies (R4, R6). The fast lane is therefore R3, a `matchJsonata` rule (`isVulnerabilityAlert = true`) placed before the denies. R6 denies advisory updates on netcup paths after it.

## Release timestamps: what the soak measures

The soak compares `minimumReleaseAge` with a timestamp that depends on the datasource (Renovate 44.184.1 source):

| Datasource | Pins | Timestamp used | Backdatable by the publisher? |
|---|---|---|---|
| `github-tags` | GitHub Actions `uses:` with `# vX.Y.Z` | The later of the tag date and the GitHub Release `publishedAt`, when a release exists (`github-tags/index.js:60-61`). Tag date: a lightweight tag uses the target commit's `committedDate`; an annotated tag uses the tagger date | Yes, while no GitHub Release exists. Commit and tagger dates are author-set |
| `github-releases` | `opentofu/opentofu` (`.opentofu-version`, `provision.yml`) | `publishedAt` from the GitHub API | No, when set: server time |
| `github-digest` | not used (every action pin is versioned) | commit date (`index.js:15`) | Yes |
| `docker` | Gatus, Caddy (Docker Hub only) | `tag_last_pushed` (`docker/index.js:627-628`) | Registry push time, not the upstream release time |

Residual: the soak measures the age of that timestamp, not the age of the release. A backdated commit behind a new version tag, with no GitHub Release, carries an old timestamp and passes the soak at once. The soak is therefore not a defence against a hijacked tag. The remaining defences are:

- required checks: `unit-tests (scripts)` and `bind-proof e2e (Caddy fronting mock tang)` must pass before automerge (not enforced on `main` until the ruleset is applied after merge);
- SHA pinning: a moved tag shows as a visible SHA diff in the PR;
- least-permission workflow tokens;
- `provision.yml` only runs on a tenant-approved dispatch.

## Advisory data

- Advisory data covers GitHub Actions only: Dependabot alerts (a repository setting; alerts only, Dependabot security-update PRs stay off, so Renovate is the only PR author) and OSV (`osvVulnerabilityAlerts: true`, queried by Renovate).
- Dependabot alerts were not enabled when this was written (the vulnerability-alerts API returned 404), so OSV is the only live feed until the setting is turned on after merge.
- Docker images (Gatus, Caddy), the terraform provider (`rixlhq/netcup`) and OpenTofu have no advisory feed here. The R3 lane applies to them only if a feed flags them. Trivy (#249) covers image contents and the provider binary.

## Required check names

- `unit-tests (scripts)` (ci.yml:614) and `bind-proof e2e (Caddy fronting mock tang)` (ci.yml:733). The short form `bind-proof e2e` matches no job.
