# Repo conventions (for contributors and coding agents)

This file holds the engineering conventions of this repo. The two hard invariants live in [invariants.md](invariants.md); the scripts rules live in [scripts/README.md](../scripts/README.md). The user-facing entry point is the [README](../README.md).

## Shape

- Standard OpenTofu module layout: the root IS the module (`versions.tf`, `variables.tf`, `main.tf`, `outputs.tf`); `examples/` holds a runnable quickstart; `scripts/` numbered human-run scripts; `docs/` this folder. No `modules/` wrapper (registry doc generation requirement).
- Provider: community `rixlhq/netcup` (`~> 1.2`); OpenTofu `>= 1.11` (ephemeral values), pinned via `.opentofu-version`.
- The module **adopts** an existing netcup server (the SCP API cannot create or delete servers); the user orders the box manually.

## Release discipline

- All changes land via **pull request**, squash-merged (the only allowed merge method); main stays linear.
- `CHANGELOG.md` follows Keep a Changelog; edits land **only** on `release/from-v*` branches or the release PR — a PR that touches `CHANGELOG.md` off a release branch fails `validate-package-version`.
- Every PR body ends with a `## Release notes` section (one line per user-facing change; "Initial module skeleton — no Breaking" is fine).
- `package.json` is the version manifest read by the release pipeline (`cad0p/semver-calver-release`, actions pinned `@v1`): automatic calver prereleases on push to main, curated stable releases via `release/from-v*` draft PRs. Releases are tagged `vX.Y.Z` (+ floating `v0`/`v0.0` during 0.x; `v1` after 1.0.0).
- Dependency pins are kept fresh by Renovate (see `renovate.json`): the `@v1` action pins, the Gatus + Caddy image pins inside `010-provision.sh` (marked with `# renovate:` directives), and `.opentofu-version`. Minor/patch bumps automerge once CI is green; **major bumps always land as PRs for human review**. A Renovate bump of either image reaches deployed anchors when the user re-runs `scripts/010-provision.sh` (the script recreates the container when the pinned image changed).

## OpenTofu conventions

- `tofu fmt -check -recursive` must pass; run `tofu fmt` before committing.
- CI is cred-free: `tofu init -backend=false && tofu validate` must pass without any provider credentials — keep data sources behind `count` guards so validate stays credential-free. **Never add `tofu plan` to CI** (it would need live credentials).
- Prefer `check` blocks for module-level assertions the user can see at plan time.

## Automation vs human-run (read precisely)

- `scripts/` files never connect anywhere: they run ON the box, started by a human. API-touching CI workflows (`.github/workflows/provision.yml` + CI-called `.github/scripts/`) coexist with those human-run on-box scripts as the deliberate exception: they open the A1 window and call the netcup API, but hold no credentials to user boxes outside the per-run device-flow (S1 — the token dies with the runner). `external-watch.yml` is the second credential-free CI workflow: public GETs of the dashboard only (no token, no user-box access).
- CI greps (endpoint-allowlist, key-material, secret-print) run from `main`, so a PR cannot weaken its own checks; a line carrying `ci-allowlist: <reason>` (10+ chars) is the only escape hatch.
- Retention semantics: `retention-days` covers run ARTIFACTS only (the thumbprint chain relies on `retention-days: 400`); repo log retention is a separate repo setting (90d default) — never rely on logs alone.

## Bootstrap-flow minimalism (reviewers enforce, NEEDS-WORK if violated)

- `docs/usage.md` §1 + `README.md` quickstart carry the happy path ONLY: required secrets, taps, approvals. Zero fallback, legacy, or conditional prose (`only when…`, `legacy`, `leave unset…`) — a tenant reading the bootstrap must never make a decision.
- Fallbacks live in `docs/dr.md` (operator runbook), referenced only by the run's own fail-closed error message — never preemptively in the bootstrap. Legacy is deleted, not documented: no `ANCHOR_*` fallback paragraphs, no commented-out fallback lines in CLI blocks.
- Reviewers: any conditional/fallback/legacy content in the bootstrap flow is a NEEDS-WORK finding, same weight as a code defect.

## Review protocol (independent review, security first)

- Every change gets an independent review before merge (CI-gated Renovate minor/patch automerges excepted — see Release discipline): an independent reviewer is a separate instance (human or agent) that did not author the change and reviews the artifact, not the author's account of it.
- **Security is the first lens**, ahead of correctness and style: credential custody (S1 / C-A — standing secrets, token lifetime, where secrets travel), exposure windows (firewall / temporary access), injection of external data into shell, HCL, `$GITHUB_ENV` / `$GITHUB_OUTPUT`, and fail-open behaviour — a green run that leaves a security property broken is a defect, not a warning.
- Findings must be **reproduced** before reporting: a failing command, a payload, or a reverted-fix test. Evidence, not assertion.
- Fixes to findings — and any commit pushed after a verdict — get a **verify pass by a reviewer instance seeded with the finding** (for agent reviewers, a fresh instance; a commit that answers no finding is checked against the verdict it invalidates) before live proof / merge; a verdict applies only to the commit it reviewed.
- Review verdicts are recorded in the PR so the trail is auditable.
- Precedent: verdicts are recorded as PR comments naming the reviewed commit SHA.

## Public-safety rules for content

- Nothing sensitive in committed files: no credentials, no hostnames/IPs of real deployments, no internal strategy. This is a public repo — write for the public reader.
- Scripts print one-time values (thumbprint, generated passwords) to the console only; never log them to files that could be committed.
