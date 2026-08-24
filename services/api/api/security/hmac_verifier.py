"""GitHub webhook HMAC verification."""

from __future__ import annotations

import hashlib
import hmac


class HMACVerifier:
    def __init__(self, secret: str):
        self.secret = secret.encode() if isinstance(secret, str) else secret

    def verify(self, body: bytes, signature_header: str | None) -> bool:
        if not signature_header:
            return False
        received = signature_header.removeprefix("sha256=")
        expected = hmac.new(self.secret, body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(received, expected)
