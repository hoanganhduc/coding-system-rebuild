#!/usr/bin/env python3
"""Minimal Shamir secret sharing over GF(256) - stdlib only.

Used by bin/escrow-passphrase.sh to split the backup passphrase into N shares
with threshold K (default 2-of-4). Any K shares reconstruct the secret; fewer
than K reveal nothing (information-theoretic). Share format:
  shamir-v1:<index>:<hex>
where <index> is the x-coordinate (1..255) and <hex> encodes one GF(256)
polynomial evaluation per secret byte.

Commands:
  split   <k> <n>            secret on stdin -> N share lines on stdout
  combine                    K+ share lines on stdin -> secret on stdout
  selftest                   exhaustive small roundtrip checks (exit 0/1)
"""

from __future__ import annotations

import secrets as _secrets
import sys

_PRIM = 0x11B  # AES field polynomial


def _gf_mul(a: int, b: int) -> int:
    out = 0
    while b:
        if b & 1:
            out ^= a
        a <<= 1
        if a & 0x100:
            a ^= _PRIM
        b >>= 1
    return out


def _gf_pow(a: int, e: int) -> int:
    out = 1
    for _ in range(e):
        out = _gf_mul(out, a)
    return out


def _gf_inv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError("gf inverse of 0")
    return _gf_pow(a, 254)


def split(secret: bytes, k: int, n: int) -> list[str]:
    if not 2 <= k <= n <= 255:
        raise ValueError("need 2 <= k <= n <= 255")
    if not secret:
        raise ValueError("empty secret")
    coeffs = [[_secrets.randbelow(256) for _ in range(k - 1)] for _ in secret]
    shares = []
    for x in range(1, n + 1):
        ys = bytearray()
        for byte, cs in zip(secret, coeffs):
            y = byte
            for j, c in enumerate(cs, start=1):
                y ^= _gf_mul(c, _gf_pow(x, j))
            ys.append(y)
        shares.append(f"shamir-v1:{x}:{ys.hex()}")
    return shares


def combine(share_lines: list[str]) -> bytes:
    pts: dict[int, bytes] = {}
    length = None
    for line in share_lines:
        line = line.strip()
        if not line:
            continue
        tag, xs, hexpart = line.split(":", 2)
        if tag != "shamir-v1":
            raise ValueError(f"unknown share format: {tag}")
        x = int(xs)
        ys = bytes.fromhex(hexpart)
        if length is None:
            length = len(ys)
        elif len(ys) != length:
            raise ValueError("share length mismatch")
        pts[x] = ys
    if length is None or len(pts) < 2:
        raise ValueError("need at least 2 distinct shares")
    xs = sorted(pts)
    out = bytearray()
    for i in range(length):
        acc = 0
        for xj in xs:
            lj = 1
            for xm in xs:
                if xm != xj:
                    lj = _gf_mul(lj, _gf_mul(xm, _gf_inv(xj ^ xm)))
            acc ^= _gf_mul(pts[xj][i], lj)
        out.append(acc)
    return bytes(out)


def selftest() -> int:
    for k, n in [(2, 3), (2, 4), (3, 5)]:
        for trial in range(20):
            secret = _secrets.token_bytes(_secrets.randbelow(40) + 1)
            shares = split(secret, k, n)
            import itertools
            for subset in itertools.combinations(shares, k):
                if combine(list(subset)) != secret:
                    print(f"FAIL roundtrip k={k} n={n}", file=sys.stderr)
                    return 1
            below = shares[: k - 1]
            if len(below) >= 2 and combine(below) == secret:
                print("FAIL: below-threshold recovery", file=sys.stderr)
                return 1
    print("shamir selftest: ok")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) >= 1 and argv[0] == "selftest":
        return selftest()
    if len(argv) == 3 and argv[0] == "split":
        secret = sys.stdin.buffer.read().rstrip(b"\n")
        for line in split(secret, int(argv[1]), int(argv[2])):
            print(line)
        return 0
    if len(argv) == 1 and argv[0] == "combine":
        sys.stdout.buffer.write(combine(sys.stdin.read().splitlines()))
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
