# Main-box canary (mutual-silence coverage with anchor-side Gatus)

Install ON the main box (the LUKS machine the anchor unlocks), not the anchor:

```bash
# 1. Edit canary.sh: set ANCHOR_URL (your anchor DNS name), NTFY_BASE/TOPIC/TOKEN.
#    Set LUKS_DEVICE if your root device differs from the default guess.
# 2. Install + enable:
install -m 0755 canary.sh /usr/local/sbin/piercloud-anchor-canary.sh
cp piercloud-anchor-canary.{service,timer} /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now piercloud-anchor-canary.timer
# 3. Prove it: systemctl start piercloud-anchor-canary.service &&
#    journalctl -u piercloud-anchor-canary -n 5   # expect "canary OK"
#    Then break it once on purpose (stop tangd via a firewall test or point
#    ANCHOR_URL at 127.0.0.1:9) and confirm the ntfy push carries the
#    CURRENT public IP + apply snippet.
```

Why this exists: Gatus on the anchor never traverses the anchor's ingress
firewall, so drift, policy deletion, and stale bindings are invisible to it.
The canary checks from the other direction; together neither side can fail
silently. Either side alerting is actionable: the push always carries the
current main-box IP (which the anchor cannot discover itself) so a
`mode=apply` re-converge is one dispatch away.
