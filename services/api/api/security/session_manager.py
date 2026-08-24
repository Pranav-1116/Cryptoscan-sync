"""HMAC-signed session tokens."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from base64 import urlsafe_b64decode, urlsafe_b64encode
from typing import Optional

from api.config.settings import get_settings


class SessionManager:
    def __init__(self, secret: str | None = None, ttl_seconds: int | None = None):
        settings = get_settings()
        self.secret = (secret or settings.SECRET_KEY).encode()
        self.ttl = ttl_seconds or int(settings.SESSION_EXPIRE_HOURS * 3600)

    def create_session(self, username: str, **kwargs) -> str:
        now = time.time()
        payload = {
            "username": username,
            "roles": kwargs.get("roles") or ["admin"],
            "created_at": now,
            "expires_at": now + self.ttl,
        }
        raw = urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        sig = hmac.new(self.secret, raw.encode(), hashlib.sha256).hexdigest()
        return f"{raw}.{sig}"

    def validate_session(self, token: str) -> Optional[str]:
        data = self._decode(token)
        return data["username"] if data else None

    def get_session(self, token: str):
        return _SessionView(self._decode(token)) if self._decode(token) else None

    def validate_api_token(self, token: str) -> Optional[str]:
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
