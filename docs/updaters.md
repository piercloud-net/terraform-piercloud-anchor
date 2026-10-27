# Dependency updaters

Renovate (`renovate.json`) keeps the pins in this repo current. This page is the policy; `renovate.json` is the mechanism.

## Policy

- Advisory fixes (a vulnerable version in use, from Dependabot alerts or OSV): minor and patch bumps automerge with no soak once CI is green, except on netcup-touching paths (never automerge there, see below). Advisory majors wait for a human.
- Routine minor and patch bumps, and GitHub Actions digest/pin moves (including the `# v1` pin of `cad0p/semver-calver-release`): automerge after a 7-day soak (`minimumReleaseAge`). The PR's status check stays pending until the age passes (`internalChecksFilter: strict`).
- Majors (routine): always a PR for human review, never automerged.
- Netcup-touching paths (`scripts/**`, `.github/scripts/**`, `**/*.tf`, `**/.terraform.lock.hcl`, `examples/**`) never automerge, advisory or not. Routine bumps queue as one `netcup-touching batch` PR labelled `netcup-touching`; one approval covers the batch. Advisory fixes on these paths open as individual PRs (the vulnerability rule clears the group), each still needing review. A PR does not page anyone.
- Exception: the Gatus and Caddy images pinned in `scripts/010-provision.sh` are carved out of that batch. Minor and patch bumps automerge after the 7-day soak; majors are human. Advisory updates for these images never automerge, because the paths are netcup-touching.
- OpenTofu: `.opentofu-version` and the `tofu_version` pins in `.github/workflows/provision.yml` are one group (`opentofu/opentofu`), so they move together. `tests/opentofu-pin` fails if they disagree.
- GitHub Actions pins are commit SHAs with a trailing `# v1` comment (`pinDigests: true`); digest updates keep the comment current.
- The `tofu_version` input of `opentofu/setup-opentofu` in provision.yml is a version string, not a digest (`pinDigests: false`).
- `lockFileMaintenance` is off: a lock refresh would re-resolve every provider hash outside the batch review.
- No notification config beyond Renovate defaults.

## Why the advisory fast lane is a packageRule

Renovate applies the `vulnerabilityAlerts` block as a forced rule at the end of `packageRules`, so an `automerge` set there would override the netcup exception. The advisory fast lane is instead a `matchJsonata` rule (`isVulnerabilityAlert = true`) placed before the netcup rule.

## Where vulnerability data comes from

- Main source: GitHub Dependabot alerts, a repository setting. Alerts only: Dependabot security-update PRs stay off, so Renovate is the only PR author.
- Cross-check: OSV (`osvVulnerabilityAlerts: true`), queried by Renovate directly.
- Neither covers container image contents or the provider binary. Separate issues will add a Trivy scan and zizmor for workflows.
