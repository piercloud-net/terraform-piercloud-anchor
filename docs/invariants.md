# Invariants

The hard invariants of this module (review blockers — a PR breaking any of them does not merge). The first two are stated in user terms in the README; this file carries the verbatim statements and the rationale.

## Invariant 1 — tang keys never enter Terraform state

> The tang private key **never** enters tf state or plan output. The keypair
> is generated **on the box** by `scripts/010-provision.sh` — never by the
> module — so state holds server configuration only.

**Rationale.** Terraform/OpenTofu state is a plaintext file that tends to travel: local disks, CI caches, backends. If the tang private key lived in state, every state copy would be a copy of the unlock key. Keeping generation on the box confines the key to the anchor's disk (where it *must* live for tangd to answer) and makes the state safe to store anywhere. Enforced by: key generation existing only in the script (never in `.tf` code), a CI grep for private key material over tracked files, and the script's key-leak assertion (fails loudly if state/plan files in the working directory match the on-box key material).

## Invariant 2 — the anchor is a key-holder, never an access-path

> The anchor holds **no credential that reaches the user's main box** — no
> SSH keys, no Teleport tokens, no API tokens, no agent sockets. Its
> cross-box interactions are answering clevis's TCP/80 challenges from the
> main-box IP, serving ACME challenges on TCP/80 and the dashboard on TCP/443
> (never on `:80`) to the platform edge — the CloudFront origin-facing ranges
> + the main box on TCP/443 are the dashboard leg; Caddy requires a CloudFront
> client certificate signed by the committed origin-mTLS CA at the TLS
> handshake for every `:443` peer, the main box and loopback included
> (`client_auth require_and_verify`, issue #202); the shared `X-Piercloud-Origin`
> header is retired and is not a gate; a pre-mTLS release gated on that header
> alone and is never a valid rollback target — plus probing the tenant's public endpoints
> for availability (narrow firewall rules; no SSH inbound
> from the main box either). Admin
> of the anchor itself is **dispatch-only** (per-run approved runs; re-entry
> per-event via SCP password-reset + re-dispatch; netcup console/rescue as
> last resort). No standing SSH keys exist anywhere. *You administer the anchor;
> the anchor administers nothing.*

**Rationale.** The anchor is the deliberately weakest link: unencrypted, always-on, holds an unlock key, different jurisdiction, cheapest box. If it were an SSH path into the main box, anchor compromise would mean full server access, and the "can unlock a disk image but never obtain one" property would collapse. With the invariant, the worst an attacker gets from the anchor is the ability to answer a boot-time challenge (and tang's ECDH design means they'd need the booting box's cooperation anyway) — not a foothold inside your main box. The dashboard is `:443`-only (`:80` serves tang + ACME; issue #225 removed the plain-HTTP dashboard handler). Enforced by: the module's variable set (no SSH key inputs, no token inputs), the firewall policy (narrow TCP/80+443 ingress rules: main box + Cloudflare edge on :80; CloudFront origin-facing ranges + main box on :443, with the Caddy origin gate admitting only those ranges and the main box and loopback by raw TCP peer, and requiring a client certificate at the TLS handshake from every peer), and inspection of the module surface.

### Scoped amendment — dynamic status-page endpoints (2026-10-12, issue #186)

> Invariant 2's "admin is dispatch-only" is amended for exactly one scoped
> component: the puller may change monitor rows in the Gatus fragment, and
> nothing else; it holds no gate/probe credential, and every other admin
> action stays dispatch-only.

**Rationale.** The dynamic status-page puller fetches public manifests (the
tenant's `pc-status.json`, the platform's) and re-renders
`/etc/gatus/tenant-endpoints.yaml` on a timer. Monitor rows carry no key
capability: the fragment cannot reach tang, Caddy, the firewall, pins or any
credential, so auto-applying it does not widen invariant 2's blast radius.
The puller runs with a hardened systemd unit (`ProtectSystem=strict`,
`ReadWritePaths` limited to the config dir + state dir), holds no gate/probe
credential (gate rows probe the gate's own anonymous login endpoint), reads
`config.yaml` to keep rows collision-free but never writes it, and writes
only the fragment, `.last-good`, and its own state file. Its only secret is
the pre-existing ntfy publish token (a second 0600 root-only copy at
`/etc/piercloud/gatus-pull.env`; inventoried in
[security-posture.md](security-posture.md)). Every other
anchor change — including `config.yaml` — stays dispatch-only (#51 keeps the
staged/approved path). Enforced by: the puller's file ownership (it never
writes `config.yaml`), the systemd unit's `ReadWritePaths`, and
`tests/gatus-pull` (validation + the two-writer boundary).

## Invariant 3 — one netcup account per anchor; one writer per account

> One netcup account holds **exactly one anchor** — never several anchors per
> account. Runs that mutate a managed account serialize on the account's
> **lane**, `anchor-<anchor_ref>` (`anchor_ref` = the opaque registry
> reference for the anchor's account; anchor↔account is 1:1): **one writer
> per account**. A **family / group anchor** (one anchor shared by several
> people) is the supported sharing shape and shares that one lane —
> per-tenant lanes are wrong there, because two members' runs on one anchor
> must not overlap. A **manual** run that omits `anchor_ref` uses the static
> fallback lane `piercloud-netcup-policy`; on a managed account that is a
> *different* lane from `anchor-<ref>`, so it can overlap a live managed run
> — the operator passes the account's ref. Since b3b (#189) `mode=apply` is
> managed-dispatch-only: a ref-less or tenant-less apply fails closed at the
> preflight before any provisioning; a **tenant-less**, ref-less
> `update-ip`/`destroy` (neither touches anchor DNS) emits a loud
> `::warning::`, and a managed `tenant` dispatch without a ref still fails
> closed.

**Rationale.** The pre-sweep (`020-provision-anchor.sh` `cmd_sweep_pre`)
retires every foreign `piercloud-tmp-*` firewall policy on the account, and
that is only safe if no other writer can hold a live window on the same
account. Two writers on one account would let one run retire a live run's
window (killing its SSH mid-provision) — and the account token reaches every
server on the account, not just the anchor (R8 finding F4: one tenant's run
could enumerate the account and reset root on servers that are not theirs).
Making the account the single-writer unit keeps the sweep truthful.

**Enforced by, today:**

- the `anchor-<ref>` lane in `provision.yml` (static `piercloud-netcup-policy`
  fallback; the lane is assigned when the run is created, before input
  validation — a bad dispatch with a valid ref still occupies the lane and
  can cancel its single pending run, which is why the backend ledger, not
  GitHub, is the queue; the ref is matched verbatim, so two spellings of one
  account's ref (e.g. `acct` vs `acct.`) occupy different lanes — the
  registry mints one canonical ref per account);
- the managed-input preflight (ungated `visibility-banner` job): a `tenant`
  dispatch without `anchor_ref`, or with a malformed, uppercase or
  over-long value, fails before the environment gate and the device card;
- the tenant-environment binding check: `MANAGED_TENANT` (set by the
  platform env lifecycle on every provisioned tenant environment) must equal
  the `tenant` input — an auto-created or partially provisioned environment
  fails closed before any netcup use;
- the approver guard (`API_USER == CUSTOMER_NUMBER` — the approval came from
  the account the selected environment expects).

**Not yet in place:** the registry `netcup_account_ref` uniqueness at anchor
create (R6 registry invariant 6 — designed, platform-side, not live) and a
runner-side account↔anchor inventory check (R8 M7 workstream) — until then
the 1:1 relation rests on provisioning discipline, with the lane + preflight
as the repo-side controls.

## Invariant 4 — a managed run reads only its own anchor's values (issue #204)

> A managed dispatch (`tenant` set) reads its operator-plane and per-anchor
> values (role, ntfy, witness key, TLS chain, status puller, extra monitors,
> root password, anchor address, SCP user) from its own GitHub environment.
> No such value may exist at repository or organization level while managed
> dispatches run: GitHub falls back from an environment to the repository per
> name, so a repository-level copy would reach every managed anchor whose
> environment lacks it.

**Rationale.** Issue #198 closed the fall-through by blanking these values on every managed run, which also made a managed operator anchor impossible (no role, no witness, no alerts). Environment-scoped values give each anchor its own set; the refusal keeps the fall-through closed. Enforced by: the ungated banner job's repo-scope step (one presence probe per name, refuses a managed dispatch on any repository- or organization-level copy, before any gate or device card), and the `tests/managed-operator-plane` pin (bare reads only inside tenant-environment jobs; elsewhere only gated literals or the named shared form (`MAIN_BOX_IPV4`), with the tenant-only `MANAGED_TENANT` and `TENANT_CUSTOMER_NUMBER` forms allowed only inside tenant-environment jobs (a job outside the banner closure gets only the global forms); the probe set equal to the pin's declared environment-scoped names plus the two tenant-only names; allowlisted workflow/banner keys; the preflight and repo-scope steps pinned by digest as banner steps 1–2; every tenant-environment job behind the banner with no status function in its `if:`). Unlike #198's unconditional blanking, this is a refusal with a disclosed race. `TENANT_USER` and `CUSTOMER_NUMBER` stay operator-only and are never read by a managed run; the platform-plane `MAIN_BOX_IPV4` is shared by design (the origin secret it once shared with the anchors is retired at #202). **Residual:** a repository-level value created after a run's banner job passed is read by that run's later jobs (an operator-controlled race; the next dispatch refuses).

### Scoped amendment — the external watch's own push channel (2026-10-17, issue #207)

> Invariant 4's "no such value at repository level" is amended for exactly
> two names: the repository secrets `EXTERNAL_WATCH_NTFY_TOPIC` and
> `EXTERNAL_WATCH_NTFY_TOKEN` may exist at repository level. They are read by
> `.github/workflows/external-watch.yml` only, and never by a managed run.
> The same PR also ships the repository **variable** `EXTERNAL_WATCH_TENANTS`
> (`alias`, `alias:puller` pairs: which anchors the watch probes). It carries
> no secret material, so it sits outside invariant 4's secret scope, but it is
> named here because it belongs to the same carve-out: like the two secrets,
> it is read by `.github/workflows/external-watch.yml` only and never by a
> managed run. This names the carve-out surface, not every repository-level
> name the watch reads: the legacy single-target path also reads the
> repository variables `STATUS_PROBE_URL`, `STATUS_PULLER` and `TENANT_USER`,
> and the push path falls back to the repository secrets `NTFY_TOPIC` and
> `NTFY_TOKEN`. Those five stay outside this carve-out — `NTFY_TOPIC` /
> `NTFY_TOKEN` are already invariant 4 names (they sit on the repo-scope
> probe list), and the three variables are the watch's pre-existing legacy
> single-target inputs, unchanged by this amendment.

**Rationale.** The scheduled external watch selects no `environment:`, so it cannot read a tenant environment (tenant environments are also expected to be limited to `v*` tags by the platform, not verified in this repo — see `docs/usage.md`). Its push channel must therefore live at repository level. The names are distinct from every environment-scoped name, so GitHub's per-name fall-through cannot hand them to a managed anchor: no managed job references them (the repo-level tenants variable is not a secret and likewise reaches only the watch). Enforced by: `tests/external-watch` (the two secret names and `EXTERNAL_WATCH_TENANTS` appear in no file under `.github/` or `scripts/` other than `external-watch.yml`, and are absent from the managed repo-scope list, which they need not join because nothing managed reads them). The harness runs from the PR checkout, so a PR can edit this pin; review of the harness diff is the control.

## S1 — every netcup use human-approved per run

> No stored tokens, no crons. Each run authenticates via the tenant's
> per-run device-flow approval from any browser; the ephemeral token dies
> with the runner (TF 1.11 ephemeral values, never state).

**Rationale.** A standing credential in secrets is an account-wide blast radius that outlives attention (token-rotation ambiguity, forgotten taps). Per-run approval dissolves the whole class: stopping taps is a legitimate expiry, not an outage (tangd is autonomous; the passphrase keyslot keeps every boot recoverable). Under S1, `mode=check` is hygiene, not load-bearing — there is nothing to keep alive.

## C-A — no sovereignty-downgrade fallback, ever

> Any check that fails means NO apply. No one-run-token instructions, no
> pasted long-lived secrets, no weakened-flow fallback — including (and
> especially) when the device grant is disabled: STOP + escalate.

**Rationale.** Every fallback that bypasses tenant approval reintroduces the standing-credential blast radius through the back door, plus a verified tang-key-theft path (rescue/snapshot = key exfiltration, not vandalism). CI fails on PAT-print patterns; reviewers treat any fallback as a blocker.

## Tang never wraps recovery material

> Tang binds only ephemeral boot passphrases. Recovery keys are
> possession-gated (passphrase in the tenant's PM), never presence-gated
> behind a network unwrap — a network-reachable tang plus a disk image
> the operator handles at move windows would collapse the separation the
> tenant-owned anchor provides.

**Rationale.** Header key + network reach to the anchor = unwrap, no tenant presence needed. The tenant-owned anchor is the ONLY barrier between operator-held disk images and offline unlock — and it must stay tenant-owned forever.
