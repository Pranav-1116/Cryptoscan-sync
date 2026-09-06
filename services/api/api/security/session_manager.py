"""HMAC-signed session tokens."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from base64 import urlsafe_b64decode, urlsafe_b64encode

from api.config.settings import get_settings


class SessionManager:
    def __init__(self, secret: str | None = None, ttl_seconds: int | None = None):
        settings = get_settings()
        self.secret = (secret or settings.SECRET_KEY).encode()
        self.ttl = ttl_seconds or int(settings.SESSION_EXPIRE_HOURS * 3600)

    def create_session(self, username: str, **kwargs) -> str:
        now = time.time()
        # Roles come ONLY from the authenticated identity. Default to the
        # least-privileged read-only role rather than "admin" — a missing role
        # must never silently elevate a session.
        roles = kwargs.get("roles")
        payload = {
            "username": username,
            "roles": roles if roles else ["readonly"],
            "jti": secrets.token_urlsafe(18),  # unique per minted token
            "created_at": now,
            "expires_at": now + self.ttl,
        }
        return self._sign(payload)

    def create_mfa_challenge(self, username: str, ttl_seconds: int = 300) -> str:
        """Short-lived proof that the password step passed for this user.

        Carries purpose="mfa_challenge" — validate_session() rejects it,
        so a challenge token can never be used as a session token.
        """
        now = time.time()
        return self._sign({
            "username": username,
            "purpose": "mfa_challenge",
            "jti": secrets.token_urlsafe(18),
            "created_at": now,
            "expires_at": now + ttl_seconds,
        })

    def validate_mfa_challenge(self, token: str) -> str | None:
        data = self._decode(token)
        if data and data.get("purpose") == "mfa_challenge":
            return data["username"]
        return None

    def _sign(self, payload: dict) -> str:
        raw = urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        sig = hmac.new(self.secret, raw.encode(), hashlib.sha256).hexdigest()
        return f"{raw}.{sig}"

    def validate_session(self, token: str) -> str | None:
        data = self._decode(token)
        # only purpose-less payloads are sessions; mfa challenges are not
        if data and data.get("purpose") is None:
            return data["username"]
        return None

    def get_session(self, token: str):
        data = self._decode(token)
        if data and data.get("purpose") is None:
            return _SessionView(data)
        return None

    def validate_api_token(self, token: str) -> str | None:
        return self.validate_session(token)

    def invalidate_session(self, token: str) -> None:
        return None

    def _decode(self, token: str) -> dict | None:
        try:
            raw, sig = token.split(".", 1)
            expected = hmac.new(self.secret, raw.encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(sig, expected):
                return None
            pad = "=" * (-len(raw) % 4)
            data = json.loads(urlsafe_b64decode(raw + pad).decode())
            if time.time() > data.get("expires_at", 0):
                return None
            return data
        except Exception:
            return None


class _SessionView:
    def __init__(self, data: dict):
        self.username = data["username"]
        self.roles = data.get("roles") or []
        self.expires_at = data.get("expires_at")
