"""Password hashing (PBKDF2-SHA256) with a plaintext fallback for local development."""

from __future__ import annotations

import binascii
import hashlib
import hmac
import os

SCHEME = "pbkdf2_sha256"
DEFAULT_ITERATIONS = 210_000


def hash_password(password: str, *, iterations: int = DEFAULT_ITERATIONS) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return (
        f"{SCHEME}${iterations}$"
        f"{binascii.hexlify(salt).decode('ascii')}$"
        f"{binascii.hexlify(digest).decode('ascii')}"
    )


def verify_password(password: str, stored: str) -> bool:
    if not stored:
        return False
    if stored.startswith(f"{SCHEME}$"):
        try:
            _, iter_s, salt_hex, digest_hex = stored.split("$", 3)
            iterations = int(iter_s)
            salt = binascii.unhexlify(salt_hex)
            expected = binascii.unhexlify(digest_hex)
        except (ValueError, binascii.Error):
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(actual, expected)
    left = password.encode("utf-8")
    right = stored.encode("utf-8")
    if len(left) != len(right):
        hmac.compare_digest(left, left)
        return False
    return hmac.compare_digest(left, right)
