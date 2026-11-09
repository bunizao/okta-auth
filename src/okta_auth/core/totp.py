from __future__ import annotations

import hashlib
import hmac
import re
import struct
import time

_BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def totp(secret: str, now: float | None = None) -> str:
    """RFC 6238 TOTP with the parameters every Okta-compatible authenticator uses:
    HMAC-SHA-1, 30-second steps, 6 digits. `now` is seconds since the epoch."""
    key = base32_decode(secret)
    counter = int((time.time() if now is None else now) // 30)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()

    # RFC 4226 dynamic truncation.
    offset = mac[19] & 0x0F
    binary = int.from_bytes(mac[offset : offset + 4], "big") & 0x7FFFFFFF
    return str(binary % 1_000_000).zfill(6)


def base32_decode(secret: str) -> bytes:
    """Accepts the forms authenticator apps show: any case, spaces, dashes, padding."""
    clean = re.sub(r"[\s=-]", "", secret).upper()
    if not clean or re.search(r"[^A-Z2-7]", clean):
        # Deliberately says nothing about the value itself.
        raise ValueError("TOTP secret is not valid base32")

    out = bytearray()
    bits = 0
    value = 0
    for char in clean:
        value = (value << 5) | _BASE32.index(char)
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((value >> bits) & 0xFF)
            value &= (1 << bits) - 1
    return bytes(out)
