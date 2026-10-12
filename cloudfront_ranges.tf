# CloudFront origin-facing ranges — the `:443` origin leg (call D).
#
# CloudFront is NOT Cloudflare AOP: the anchor's :443 admits only these
# ranges (plus the main box), and Caddy enforces the
# `X-Piercloud-Origin` secret header CloudFront injects (it overwrites
# any client-supplied value). Neither control alone is auth; together
# they keep the origin off the open internet.
#
# This list is a MOVING TARGET (AWS publishes changes; no netcup-native
# prefix-list object exists). Refresh with:
#   curl -sS https://ip-ranges.amazonaws.com/ip-ranges.json \
#     | jq -r '[.prefixes[], .ipv6_prefixes[]]
#              | map(select(.service=="CLOUDFRONT_ORIGIN_FACING"))
#              | .[] | (.ip_prefix // .ipv6_prefix)'
# and keep `CLOUDFRONT_ORIGIN_CIDRS` in scripts/010-provision.sh in
# sync — tests/edge-origin-auth asserts the two lists are identical.
# Live-fetched 2026-10-06 (createDate 2026-10-06-13-17-06): 46 IPv4 + 35 IPv6.
locals {
  cloudfront_origin_facing_cidrs = [
    "130.176.88.0/21",
    "54.239.134.0/23",
    "52.82.134.0/23",
    "130.176.86.0/23",
    "130.176.140.0/22",
    "130.176.0.0/18",
    "54.239.204.0/22",
    "130.176.160.0/19",
    "70.132.0.0/18",
    "15.158.0.0/16",
    "130.176.136.0/23",
    "54.239.170.0/23",
    "130.176.96.0/19",
    "54.182.184.0/22",
    "204.246.166.0/24",
    "130.176.64.0/21",
    "54.182.172.0/22",
    "205.251.218.0/24",
    "130.176.144.0/20",
    "54.182.176.0/21",
    "130.176.78.0/23",
    "54.182.248.0/22",
    "64.252.128.0/18",
    "54.182.154.0/23",
    "64.252.64.0/18",
    "54.182.144.0/21",
    "54.182.224.0/21",
    "130.176.128.0/21",
    "52.46.0.0/18",
    "3.172.64.0/18",
    "52.82.128.0/23",
    "18.68.0.0/16",
    "54.182.156.0/22",
    "54.182.160.0/21",
    "54.182.240.0/21",
    "130.176.192.0/19",
    "130.176.76.0/24",
    "54.239.208.0/21",
    "54.182.188.0/23",
    "24.110.128.0/17",
    "3.172.0.0/18",
    "130.176.80.0/22",
    "54.182.128.0/20",
    "130.176.72.0/22",
    "13.124.199.0/24",
    "3.29.57.0/26",
    "2600:9000:1000::/36",
    "2600:9000:5200::/40",
    "2600:9000:6000::/36",
    "2406:da11:438:2300::/56",
    "2406:da1e:705:1600::/56",
    "2406:da1c:8d8c:4600::/56",
    "2406:da14:17bd:2f00::/56",
    "2406:da12:4b:c200::/56",
    "2406:da16:c01:c200::/56",
    "2406:da1a:6df:6c00::/56",
    "2406:da1b:e7c:ad00::/56",
    "2406:da18:9fa:1b00::/56",
    "2406:da1c:787:2b00::/56",
    "2406:da19:e19:4a00::/56",
    "2406:da1f:396:9100::/56",
    "2406:da10:847f:a100::/56",
    "2406:da12:8b2e:9c00::/56",
    "2406:da14:80bb:ea00::/56",
    "2600:1f11:e79:a800::/56",
    "2600:1f1a:4568:b500::/56",
    "2a05:d014:1362:b000::/56",
    "2a05:d019:80b:e300::/56",
    "2a05:d016:9ed:de00::/56",
    "2a05:d01a:8a9:be00::/56",
    "2a05:d011:531:1800::/56",
    "2a05:d018:1a3a:2d00::/56",
    "2a05:d01c:343:c300::/56",
    "2a05:d012:581:b400::/56",
    "2a05:d025:e59:fb00::/56",
    "2600:1f17:4356:f100::/56",
    "2600:1f1e:a7:2300::/56",
    "2600:1f18:7530:7200::/56",
    "2600:1f16:1923:3000::/56",
    "2600:1f1c:da:600::/56",
    "2600:1f13:417:4d00::/56",
  ]
}
