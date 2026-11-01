"""RFC 6238 TOTP (time-based one-time passwords) — pure stdlib.

Verified against the official RFC 6238 Appendix B test vectors (SHA-1,
8-digit) in the API test suite. Product use: 6 digits, 30-second step,
HMAC-SHA-1, symmetric verification window of ±1 step (±30 s clock skew).

No secrets are ever logged; ``otpauth://`` provisioning URIs follow
Google Authenticator's documented format so any TOTP app works.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

DEFAULT_DIGITS = 6
DEFAULT_PERIOD = 30
VERIFY_WINDOW = 1  # ±1 step tolerated on verification

_ALGORITHMS = {
    "SHA1": hashlib.sha1,
    "SHA256": hashlib.sha256,
    "SHA512": hashlib.sha512,
}


def generate_secret(num_bytes: int = 20) -> str:
    """RFC 4648 base32 secret (160 bits by default — the standard size)."""
    return base64.b32encode(secrets.token_bytes(num_bytes)).decode("ascii").rstrip("=")


def decode_secret(secret_b32: str) -> bytes:
    padded = secret_b32 + "=" * (-len(secret_b32) % 4)
    return base64.b32decode(padded.upper().encode("ascii"))


def hotp(secret: bytes, counter: int, digits: int = DEFAULT_DIGITS, algorithm: str = "SHA1") -> str:
    """RFC 4226 HOTP — the counter-based core TOTP builds on."""
    digest = _ALGORITHMS[algorithm]
    mac = hmac.new(secret, struct.pack(">Q", counter), digest)
    offset = mac.digest()[-1] & 0x0F
    trunk = mac.digest()[offset : offset + 4]
    code = (struct.unpack(">I", trunk)[0] & 0x7FFFFFFF) % (10**digits)
    return str(code).zfill(digits)


def totp_at(
    secret_b32: str, timestamp: float, *, digits: int = DEFAULT_DIGITS,
    period: int = DEFAULT_PERIOD, algorithm: str = "SHA1",
) -> str:
    """The code for an arbitrary moment (exactly what the RFC vectors pin)."""
    counter = int(timestamp // period)
    return hotp(decode_secret(secret_b32), counter, digits=digits, algorithm=algorithm)


def current_code(secret_b32: str, *, at: float | None = None, **kw) -> str:
    return totp_at(secret_b32, at if at is not None else time.time(), **kw)


def verify(
    secret_b32: str, code: str, *, at: float | None = None,
    digits: int = DEFAULT_DIGITS, period: int = DEFAULT_PERIOD,
    window: int = VERIFY_WINDOW, algorithm: str = "SHA1",
) -> bool:
    """Constant-time comparison against the current ± window codes."""
    if not code or not code.strip().isdigit() or len(code.strip()) != digits:
        return False
    now = at if at is not None else time.time()
    provided = code.strip().encode("ascii")
    for skew in range(-window, window + 1):
        expected = totp_at(secret_b32, now + skew * period, digits=digits, period=period, algorithm=algorithm)
        if hmac.compare_digest(expected.encode("ascii"), provided):
            return True
    return False


def verify_step(
    secret_b32: str, code: str, *, at: float | None = None,
    digits: int = DEFAULT_DIGITS, period: int = DEFAULT_PERIOD,
    window: int = VERIFY_WINDOW, algorithm: str = "SHA1",
) -> int | None:
    """Which time-step a code belongs to, or ``None``.

    ``verify`` only answers yes/no, which lets the same 6-digit code be
    replayed for the whole ±window — up to 90 seconds of free reuse for an
    attacker who shoulder-surfs or reads a notification. The caller persists
    the returned step and refuses anything at or below it.
    """
    if not code or not code.strip().isdigit() or len(code.strip()) != digits:
        return None
    now = at if at is not None else time.time()
    provided = code.strip().encode("ascii")
    for skew in range(-window, window + 1):
        step = int((now + skew * period) // period)
        expected = totp_at(secret_b32, step * period, digits=digits, period=period, algorithm=algorithm)
        if hmac.compare_digest(expected.encode("ascii"), provided):
            return step
    return None


def provisioning_uri(secret_b32: str, username: str, issuer: str = "CryptoScan", *, digits: int = DEFAULT_DIGITS, period: int = DEFAULT_PERIOD) -> str:
    """otpauth:// URI understood by every TOTP authenticator app."""
    label = quote(f"{issuer}:{username}", safe=":")
    return (
        f"otpauth://totp/{label}?secret={secret_b32}"
        f"&issuer={quote(issuer)}&algorithm=SHA1&digits={digits}&period={period}"
    )


def generate_recovery_codes(count: int = 10) -> list[str]:
    """One-time recovery codes, shown to the user exactly once (hashes stored)."""
    return ["-".join(secrets.token_hex(2) for _ in range(2)).upper() for _ in range(count)]
