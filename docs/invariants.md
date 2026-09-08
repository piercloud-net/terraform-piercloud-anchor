# Invariants

The hard invariants of this module (review blockers — a PR breaking any of
them does not merge). The first two are stated in user terms in the
README; this file carries the verbatim statements and the rationale.

## Invariant 1 — tang keys never enter Terraform state

> The tang private key **never** enters tf state or plan output. The keypair
> is generated **on the box** by `scripts/010-provision.sh` — never by the
> module — so state holds server configuration only.

**Rationale.** Terraform/OpenTofu state is a plaintext file that tends to
travel: local disks, CI caches, backends. If the tang private key lived in
state, every state copy would be a copy of the unlock key. Keeping generation
on the box confines the key to the anchor's disk (where it *must* live for
tangd to answer) and makes the state safe to store anywhere. Enforced by:
key generation existing only in the script (never in `.tf` code), a CI grep
for private key material over tracked files, and the script's key-leak
assertion (fails loudly if state/plan files in the working directory match
the on-box key material).

## Invariant 2 — the anchor is a key-holder, never an access-path

> The anchor holds **no credential that reaches the user's main box** — no
> SSH keys, no Teleport tokens, no API tokens, no agent sockets. Its only
> cross-box interaction is answering clevis's TCP/80 challenges (firewall-
> scoped to the main box IP; no SSH inbound from the main box either). Admin
> of the anchor itself is **user-direct only** (their own SSH key from their
> own device, or netcup console/rescue). *You administer the anchor; the
> anchor administers nothing.*

**Rationale.** The anchor is the deliberately weakest link: unencrypted,
always-on, holds an unlock key, different jurisdiction, cheapest box. If it
were an SSH path into the main box, anchor compromise would mean full server
access, and the "can unlock a disk image but never obtain one" property would
collapse. With the invariant, the worst an attacker gets from the anchor is
the ability to answer a boot-time challenge (and tang's ECDH design means
they'd need the booting box's cooperation anyway) — not a foothold inside
your main box. Enforced by: the module's variable set (no SSH key inputs,
no token inputs), the firewall policy (single TCP/80 ingress rule), and
inspection of the module surface.

## S1 — every netcup use human-approved per run

> No stored tokens, no crons. Each run authenticates via the tenant's
> per-run device-flow approval from any browser; the ephemeral token dies
> with the runner (TF 1.11 ephemeral values, never state).

**Rationale.** A standing credential in repo secrets is an account-wide
blast radius that outlives attention (token-rotation ambiguity, forgotten
taps). Per-run approval dissolves the whole class: stopping taps is a
legitimate expiry, not an outage (tangd is autonomous; the passphrase
keyslot keeps every boot recoverable). Under S1, `mode=check` is hygiene,
not load-bearing — there is nothing to keep alive.

## C-A — no sovereignty-downgrade fallback, ever

> Any check that fails means NO apply. No one-run-token instructions, no
> pasted long-lived secrets, no weakened-flow fallback — including (and
> especially) when the device grant is disabled: STOP + escalate.

**Rationale.** Every fallback that bypasses tenant approval reintroduces
the standing-credential blast radius through the back door, plus a
verified tang-key-theft path (rescue/snapshot = key exfiltration, not
vandalism). CI fails on PAT-print patterns; reviewers treat any fallback
as a blocker.

## Tang never wraps recovery material

> Tang binds only ephemeral boot passphrases. Recovery keys are
> possession-gated (passphrase in the tenant's PM), never presence-gated
> behind a network unwrap — a network-reachable tang plus a disk image
> the operator handles at move windows would collapse the separation the
> tenant-owned anchor provides.

**Rationale.** Header key + network reach to the anchor = unwrap, no
tenant presence needed. The tenant-owned anchor is the ONLY barrier
between operator-held disk images and offline unlock — and it must stay
tenant-owned forever.
