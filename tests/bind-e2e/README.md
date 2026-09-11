# tests/bind-e2e — bind-proof for the Caddy→tang path

The real `clevis luks bind` + reboot test needs the tenant's main-box
keyboard, so the Caddy-in-front-of-tang path was never bind-proven. This
harness proves it in CI on every PR: mock tang on loopback, **real**
`caddy:2.11.4` in front running the repo's **real** rendered Caddyfile
(extracted from `scripts/010-provision.sh` at runtime — never a copy),
then real `clevis luks bind` / `list` / `encrypt`+`decrypt` / `unlock -n`
against loopback LUKS volumes, all through the proxy.

Proves: the shipped render still parses (`caddy validate`, CI shape +
shipped shape + AOP shape — the real `client_auth`/`require_and_verify`/
`trust_pool file` stanza compiled against a generated CA bundle, so a
directive rename fails CI, not the next live dispatch); `/adv` through the
proxy is payload-identical and the
proxied envelope signature verifies (proxy transparent for this
response) — raw compare is impossible, fresh ECDSA nonce per adv,
same as real tangd; exact-Host dashboard
routing; unknown-Host and bare-`/` abort; full bind→unlock through Caddy;
wrong-thumbprint bind refusal with no token left behind.

Assumes, not proves: loop + dm-crypt on the runner (fail-fast if absent);
LUKS2 token path of clevis 20; key custody/rotation (mock keys are
ephemeral); the `:443` dashboard block and its `client_auth` stanza are
validated, never served here (handshake behavior is proven live by the
provision run's AOP probes).

Curve note: the mock exchanges on P-521 — the runner's jose 13 cannot
provision or recover against EC/X25519 at all, and P-521 is what
current-jose `tangd-keygen` emits, so it is the production shape for
current deployments.

Run: `sudo bash tests/bind-e2e/run-bind-e2e.sh` on Linux with apt + root loop/
`dm-crypt` (CI: `ubuntu-latest`, ~3 min, no secrets, no cloud). It is not
runnable on a dev Mac (apt deps, linux/amd64 caddy, loop devices) — for a local
slice, extract the render span and run `caddy validate` as the AOP render case
does; the served client-auth handshake is covered by CI and by the provision
run's live AOP probes.
