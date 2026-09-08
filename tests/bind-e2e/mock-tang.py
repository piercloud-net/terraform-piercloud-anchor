#!/usr/bin/env python3
"""mock-tang.py — minimal Tang server for the CI bind-proof harness.

Serves the two Tang endpoints clevis actually exercises, with real
McCallum-Relyea recovery math (P-521), so `clevis luks bind` +
`clevis luks unlock` / `clevis decrypt` succeed end-to-end:

  GET  /adv        JWS-signed advertisement (flattened serialization)
  GET  /adv/{kid}  same advertisement when {kid} is the signing-key
                   S256 thumbprint (what clevis requests when `thp`
                   is pinned), else 404 — like tangd
  POST /rec/{kid}  y = s * x over the posted blinding point on
                   secp521r1, returned as a full EC public JWK —
                   like tangd-rec

Exchange curve is P-521, not X25519: the runner's jose (v13) cannot
provision or recover against EC/X25519 keys at all (`jwe enc`
reports "Wrapping failed", `thp` hashes degenerate input), while
P-521 is its native ECMR curve (its own `gen` default) — and is
what current-jose tangd-keygen emits, so it is the production
shape for current deployments.

Crypto: stdlib http.server + `cryptography` (ECDSA P-256 for the
advertisement signature, P-521 keygen) + a small pure-python
secp521r1 module (p521.py) for the recovery scalar-mult —
`cryptography` exposes ECDH shared secrets but no raw
point multiplication, and tangd-rec must return the full POINT.
No KDF runs here by design — Tang's server side is one scalar
multiplication; the Concat KDF lives client-side inside
jose/clevis on both the provision and recovery paths, so it is
consistent by construction.

Deliberate mock simplifications (see tests/bind-e2e/README for the
full proves-vs-assumes list):
  * single signing key (ES256) + single exchange key (P-521/ECMR),
    generated ephemerally at startup — real tangd keeps key files
    on disk and rotates them; key custody is NOT what this proves.
  * /rec/{kid} is not gated on {kid} (one exchange key exists, so
    routing is trivial); unknown paths still 404.
  * plain HTTP on loopback only — the harness fronts it with the
    repo's real rendered Caddyfile, which is the path under test.

Usage:
  mock-tang.py --port 18081 --thp-file thp.txt   # tang mode
  mock-tang.py --stub --port 18082 --stub-body .. # dumb 200 backend
"""
import argparse
import base64
import hashlib
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    from cryptography.exceptions import InvalidSignature  # noqa: F401
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.ec import (
        ECDSA,
        SECP256R1,
        SECP521R1,
    )
    from cryptography.hazmat.primitives.asymmetric.utils import (
        decode_dss_signature,
    )
    import p521
    from p521 import on_curve as _on_curve
    from p521 import scalar_mult as _scalar_mult
except ImportError:
    sys.stderr.write(
        "mock-tang.py: need the `cryptography` package "
        "(apt: python3-cryptography) and p521.py beside it\n"
    )
    sys.exit(2)

COORD_LEN = 66  # P-521 coordinates are 66 bytes


def b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def jwk_thp_s256(members: dict) -> str:
    canonical = json.dumps(members, separators=(",", ":"), sort_keys=True)
    return b64u_encode(hashlib.sha256(canonical.encode("ascii")).digest())


class TangState:
    """Ephemeral server identity: one ES256 signing key, one P-521 key."""

    def __init__(self) -> None:
        sig_priv = ec.generate_private_key(SECP256R1())
        nums = sig_priv.public_key().public_numbers()
        self._sig_priv = sig_priv
        self.sig_x = b64u_encode(nums.x.to_bytes(32, "big"))
        self.sig_y = b64u_encode(nums.y.to_bytes(32, "big"))
        self.sig_thp = jwk_thp_s256(
            {"crv": "P-256", "kty": "EC", "x": self.sig_x, "y": self.sig_y}
        )
        exc_priv = ec.generate_private_key(SECP521R1())
        pnums = exc_priv.private_numbers()
        self._exc_scalar = pnums.private_value
        self.exc_x = b64u_encode(
            pnums.public_numbers.x.to_bytes(COORD_LEN, "big")
        )
        self.exc_y = b64u_encode(
            pnums.public_numbers.y.to_bytes(COORD_LEN, "big")
        )

    @property
    def sig_pub_jwk(self) -> dict:
        return {
            "alg": "ES256",
            "crv": "P-256",
            "key_ops": ["sign", "verify"],
            "kty": "EC",
            "x": self.sig_x,
            "y": self.sig_y,
        }

    @property
    def exc_pub_jwk(self) -> dict:
        # Current-tangd shape: kty EC with a P-521 curve (what
        # jose >= 13 generates for ECMR). clevis checks kty == EC
        # on the /rec reply, so keep it exact.
        return {
            "alg": "ECMR",
            "crv": "P-521",
            "key_ops": ["deriveKey"],
            "kty": "EC",
            "x": self.exc_x,
            "y": self.exc_y,
        }

    def advertisement(self) -> bytes:
        """Flattened-JWS advertisement, the shape clevis verifies."""
        payload = b64u_encode(
            json.dumps(
                {"keys": [self.sig_pub_jwk, self.exc_pub_jwk]},
                separators=(",", ":"),
            ).encode("ascii")
        )
        protected = b64u_encode(
            json.dumps(
                {"alg": "ES256", "cty": "jwk-set+json"},
                separators=(",", ":"),
            ).encode("ascii")
        )
        signing_input = f"{protected}.{payload}".encode("ascii")
        der = self._sig_priv.sign(signing_input, ECDSA(hashes.SHA256()))
        raw = b"".join(
            v.to_bytes(32, "big") for v in decode_dss_signature(der)
        )
        return json.dumps(
            {
                "payload": payload,
                "protected": protected,
                "signature": b64u_encode(raw),
            },
            separators=(",", ":"),
        ).encode("ascii")

    def recover(self, x_b64u: str, y_b64u: str) -> dict:
        """tangd-rec: y = server_scalar * blinding_point (P-521)."""
        peer = (
            int.from_bytes(b64u_decode(x_b64u), "big"),
            int.from_bytes(b64u_decode(y_b64u), "big"),
        )
        if not _on_curve(peer):
            raise ValueError("blinding point not on P-521")
        rx, ry = _scalar_mult(self._exc_scalar, peer)
        return {
            "crv": "P-521",
            "kty": "EC",
            "x": b64u_encode(rx.to_bytes(COORD_LEN, "big")),
            "y": b64u_encode(ry.to_bytes(COORD_LEN, "big")),
        }


def make_handler(state: TangState | None, stub_body: str | None):
    class Handler(BaseHTTPRequestHandler):
        server_version = "mock-tang"

        def log_message(self, fmt, *args):  # noqa: N802
            sys.stderr.write(f"mock-tang: {self.address_string()} {fmt % args}\n")

        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _route(self) -> None:
            path = self.path.split("?", 1)[0]
            if stub_body is not None:
                if self.command != "GET":
                    self._send(405, b"method not allowed", "text/plain")
                    return
                self._send(200, stub_body.encode(), "text/plain")
                return
            assert state is not None
            if self.command == "GET" and path == "/adv":
                self._send(200, state.advertisement(), "application/jose")
            elif self.command == "GET" and path.startswith("/adv/"):
                kid = path[len("/adv/") :]
                if kid == state.sig_thp:
                    self._send(200, state.advertisement(), "application/jose")
                else:
                    self._send(404, b"unknown signing key", "text/plain")
            elif self.command == "POST" and path.startswith("/rec/"):
                length = int(self.headers.get("Content-Length", "0"))
                try:
                    posted = json.loads(self.rfile.read(length) or b"null")
                    reply = state.recover(posted["x"], posted["y"])
                except Exception as exc:  # fail closed, like tangd
                    sys.stderr.write(f"mock-tang: bad /rec body: {exc}\n")
                    self._send(400, b"invalid JWK", "text/plain")
                    return
                body = json.dumps(reply, separators=(",", ":")).encode()
                self._send(200, body, "application/jwk+json")
            else:
                self._send(404, b"not found", "text/plain")

        do_GET = _route
        do_POST = _route
        do_HEAD = _route
        do_PUT = _route
        do_DELETE = _route

    return Handler


def main(argv: list) -> int:
    ap = argparse.ArgumentParser(description="minimal Tang mock for CI")
    ap.add_argument("--port", type=int, default=8081)
    ap.add_argument("--thp-file", default=None)
    ap.add_argument("--stub", action="store_true")
    ap.add_argument("--stub-body", default="stub-ok")
    args = ap.parse_args(argv)
    if args.stub:
        handler = make_handler(None, args.stub_body)
        print(f"stub backend on 127.0.0.1:{args.port}", flush=True)
    else:
        state = TangState()
        handler = make_handler(state, None)
        print(f"THP={state.sig_thp}", flush=True)
        if args.thp_file:
            with open(args.thp_file, "w") as fh:
                fh.write(state.sig_thp + "\n")
    server = ThreadingHTTPServer(("127.0.0.1", args.port), handler)
    print(f"listening on 127.0.0.1:{args.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
