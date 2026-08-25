"""Username/password authentication against configured admin user."""

from __future__ import annotations

import hmac
import time
from collections import defaultdict
from dataclasses import dataclass

from api.config.settings import get_settings
from api.security.passwords import verify_password


class AuthenticationError(Exception):
    def __init__(self, message: str = "Invalid credentials"):
        self.message = message
        super().__init__(message)


@dataclass
class User:
    user_id: str
    username: str
    roles: list[str]


_FAILURES: dict[str, list[float]] = defaultdict(list)


def reset_lockout_state() -> None:
    _FAILURES.clear()


class AuthService:
    def __init__(self, session=None):
        self.settings = get_settings()

    def authenticate(self, username: str, password: str, *, client_key: str = "") -> User:
        bucket = f"{(username or '').lower()}|{client_key or '-'}"
        self._raise_if_locked(bucket)
        expected_user = self.settings.ADMIN_USERNAME
        stored_secret = self.settings.ADMIN_PASSWORD_HASH or self.settings.ADMIN_PASSWORD
        user_ok = hmac.compare_digest((username or "").encode("utf-8"), expected_user.encode("utf-8"))
        pass_ok = verify_password(password or "", stored_secret)
        if not (user_ok and pass_ok):
            self._record_failure(bucket)
            raise AuthenticationError("Invalid username or password")
        _FAILURES.pop(bucket, None)
        return User(user_id=username, username=username, roles=["admin"])

    def _raise_if_locked(self, bucket: str) -> None:
        if self.settings.is_test:
            return
        window = max(int(self.settings.LOGIN_LOCKOUT_SECONDS), 1)
        cutoff = time.time() - window
        recent = [stamp for stamp in _FAILURES.get(bucket, []) if stamp >= cutoff]
        _FAILURES[bucket] = recent
        if len(recent) >= max(int(self.settings.LOGIN_MAX_FAILURES), 1):
            raise AuthenticationError("Too many failed sign-in attempts. Try again later.")

    def _record_failure(self, bucket: str) -> None:
        if self.settings.is_test:
            return
        _FAILURES[bucket].append(time.time())
