"""p521.py — minimal pure-stdlib secp521r1 arithmetic for the mock tang.

Why pure-python: the `cryptography` package exposes ECDH shared
secrets (x-coordinates) but no raw scalar-multiplication of an
arbitrary peer point, and tangd-rec must return the full response
POINT y = s * x (both coordinates — clevis unblinds with point
subtraction). P-521 field reduction is cheap (p = 2**521 - 1 is a
Mersenne prime), and one multiplication costs tens of ms — fine
for a CI mock that answers a handful of recovery posts per run.

Constants are the SECG secp521r1 domain parameters (single-line
hex — never re-split them; a past edit mangled split literals and
`on_curve(G)` is the canary).
"""

P = 2**521 - 1
A = P - 3
# Generator and b derived from OpenSSL's secp521r1 (authoritative for the
# client, which reaches it via jose); order cross-checked by n*G == INF.
B = 1093849038073734274511112390766805569936207598951683748994586394495953116150735016013708737573759623248592132296706313309438452531591012912142327488478985984
GX = 2661740802050217063228768716723360960729859168756973147706671368418802944996427808491545080627771902352094241225065558662157113545570916814161637315895999846
GY = 3757180025770020463545507224491183603594455134769762486694567779615544477440556316691234405012945539562144444537289428522585666729196580810124344277578376784
N = 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409

_INF = None  # point at infinity


def _inv(x: int) -> int:
    return pow(x % P, P - 2, P)


def point_add(p1, p2):
    if p1 is _INF:
        return p2
    if p2 is _INF:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return _INF
        # doubling
        lam = (3 * x1 * x1 + A) * _inv(2 * y1) % P
    else:
        lam = (y2 - y1) * _inv(x2 - x1) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def scalar_mult(k: int, point=(GX, GY)):
    result = _INF
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def point_neg(point):
    if point is _INF:
        return _INF
    x, y = point
    return (x, (-y) % P)


def point_sub(p1, p2):
    return point_add(p1, point_neg(p2))


def on_curve(point) -> bool:
    if point is _INF:
        return False
    x, y = point
    return (y * y - (x * x * x + A * x + B)) % P == 0
