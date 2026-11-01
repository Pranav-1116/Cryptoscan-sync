"""HMAC-signed session tokens."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import time
from base64 import urlsafe_b64decode, urlsafe_b64encode

from api.config.settings import get_settings

logger = logging.getLogger(__name__)


class SessionManager:
    """Mint and validate HMAC-signed sessions.

    Verification accepts ``SECRET_KEY`` plus any key still listed in
    ``SECRET_KEY_PREVIOUS``; signing only ever uses the current key. That is what
    makes a rotation a rotation and not a mass logout: for the overlap window a
    token minted before the change keeps validating, and every token minted after
    it carries the new key — so clearing the previous entry ends the overlap
    exactly once, on purpose.
    """

    def __init__(self, secret: str | None = None, ttl_seconds: int | None = None):
        settings = get_settings()
        self.secret = (secret or settings.SECRET_KEY).encode()
        self.ttl = ttl_seconds or int(settings.SESSION_EXPIRE_HOURS * 3600)
        if secret is not None:
            # An explicit key (a test, a migration tool) means exactly one key:
            # silently accepting the deployment's previous keys would make the
            # argument a lie.
            self.previous_secrets: tuple[bytes, ...] = ()
        else:
            self.previous_secrets = tuple(
                part.strip().encode()
                for part in (getattr(settings, "SECRET_KEY_PREVIOUS", "") or "").split(",")
                if part.strip() and part.strip() != (settings.SECRET_KEY or "").strip()
            )

    @property
    def verification_secrets(self) -> tuple[bytes, ...]:
        return (self.secret, *self.previous_secrets)

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

    def invalidate_session(self, token: str) -> bool:
        """Revoke a token in the durable store.

        This used to return ``None`` and do nothing, which reads as success at
        every call site — a logout that only forgets the cookie leaves the
        token valid for its full lifetime, exactly what an attacker who copied
        it is counting on. It now reports whether a session row was revoked;
        callers that must fail closed should check the result.
        """
        try:
            from db.connection.session import SessionLocal
            from db.repositories.user_repository import UserRepository

            session = SessionLocal()
            try:
                revoked = UserRepository(session).revoke_session(token)
                session.commit()
                return bool(revoked)
            finally:
                session.close()
        except Exception:  # noqa: BLE001 — no store configured (dev) or DB down
            logger.warning("session invalidation could not reach the session store")
            return False

    def _decode(self, token: str) -> dict | None:
        try:
            raw, sig = token.split(".", 1)
            matched = None
            for index, key in enumerate(self.verification_secrets):
                expected = hmac.new(key, raw.encode(), hashlib.sha256).hexdigest()
                if hmac.compare_digest(sig, expected):
                    matched = index
                    break
            if matched is None:
                return None
            if matched:
                # Signed by a retired key: valid during the overlap, visible in
                # the log so an operator can see the window actually closing.
                logger.info("session_accepted_with_previous_secret_key", extra={"previous_key_index": matched})
            pad = "=" * (-len(raw) % 4)
            data = json.loads(urlsafe_b64decode(raw + pad).decode())
            if time.time() > data.get("expires_at", 0):
                return None
            return data
        except Exception as _handler_exc:
            logger.warning(
                "exception_suppressed",
                extra={"error_type": type(_handler_exc).__name__},
            )
            return None


class _SessionView:
    def __init__(self, data: dict):
        self.username = data["username"]
        self.roles = data.get("roles") or []
        self.expires_at = data.get("expires_at")
