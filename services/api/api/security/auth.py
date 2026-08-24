"""Username/password authentication against configured admin user."""

from __future__ import annotations

import hmac
from dataclasses import dataclass

from api.config.settings import get_settings


class AuthenticationError(Exception):
    def __init__(self, message: str = "Invalid credentials"):
        self.message = message
        super().__init__(message)


@dataclass
class User:
    user_id: str
    username: str
    roles: list[str]


class AuthService:
    def __init__(self, session=None):
        self.settings = get_settings()

    def authenticate(self, username: str, password: str) -> User:
        expected_user = self.settings.ADMIN_USERNAME
        expected_pass = self.settings.ADMIN_PASSWORD
        user_ok = hmac.compare_digest(username.encode(), expected_user.encode())
        pass_ok = hmac.compare_digest(password.encode(), expected_pass.encode())
        if not (user_ok and pass_ok):
            raise AuthenticationError("Invalid username or password")
        return User(user_id=username, username=username, roles=["admin"])
