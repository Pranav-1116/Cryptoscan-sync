"""Username/password authentication against the users table (with env-admin bootstrap)."""

from __future__ import annotations

import hmac
import logging
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone

from api.config.settings import get_settings
from api.security.passwords import verify_password

logger = logging.getLogger(__name__)


class AuthenticationError(Exception):
    def __init__(self, message: str = "Invalid credentials"):
        self.message = message
        super().__init__(message)


def reset_lockout_state() -> None:
    """Reset the in-memory fallback lockout (DB-backed lockout lives in the users table)."""
    _FAILURES.clear()


@dataclass
class User:
    user_id: str
    username: str
    roles: list[str]
    mfa_enabled: bool = False


_FAILURES: dict[str, list[float]] = defaultdict(list)


def _aware(dt: datetime | None) -> datetime | None:
    """SQLite returns naive datetimes — assume UTC (shared_models.chrono)."""
    from shared_models.chrono import aware

    return aware(dt)


class AuthService:
    """Authenticates against the `users` table.

    - With a DB session: full multi-user auth, persistent lockout, audit trail.
    - Without a session (CLI/scripts/dev fallback): the legacy single-admin
      path against settings credentials with in-memory lockout. Production
      always goes through the DB (see routers/auth.py).
    - Bootstrap: if the users table is empty, the first successful login with
      the settings admin credentials persists the admin account (PBKDF2 hash).
    """

    def __init__(self, session=None):
        self.settings = get_settings()
        self.session = session

    def _repo(self):
        if self.session is None:
            return None
        from db.repositories.user_repository import UserRepository

        return UserRepository(self.session)

    # ------------------------------------------------------------- bootstrap

    def bootstrap_admin(self) -> bool:
        """Create the initial admin user from settings if the table is empty."""
        repo = self._repo()
        if repo is None or repo.count_users() > 0:
            return False
        from api.security.passwords import hash_password

        settings = self.settings
        stored = settings.ADMIN_PASSWORD_HASH or ""
        if not stored.startswith("pbkdf2_sha256$") and settings.ADMIN_PASSWORD:
            stored = hash_password(settings.ADMIN_PASSWORD)
        if not stored:
            logger.warning("bootstrap_admin_skipped_no_credentials")
            return False
        repo.create_user(
            settings.ADMIN_USERNAME or "admin",
            stored,
            roles=["admin"],
            display_name="Bootstrap Admin",
        )
        self.session.commit()
        logger.info("bootstrap_admin_created", extra={"username": settings.ADMIN_USERNAME})
        return True

    # ------------------------------------------------------------ authenticate

    def authenticate(self, username: str, password: str, *, client_key: str = "") -> User:
        if self.session is None:
            return self._authenticate_env_fallback(username, password, client_key=client_key)
        return self._authenticate_db(username, password, client_key=client_key)

    # -- DB path -----------------------------------------------------------

    def _authenticate_db(self, username: str, password: str, *, client_key: str = "") -> User:
        repo = self._repo()
        now = datetime.now(timezone.utc)
        candidate = (username or "").strip().lower()

        if repo.count_users() == 0:
            # Bootstrap path: verify against env admin once, then persist.
            settings = self.settings
            expected_user = settings.ADMIN_USERNAME
            stored_secret = settings.ADMIN_PASSWORD_HASH or settings.ADMIN_PASSWORD
            user_ok = hmac.compare_digest(candidate.encode("utf-8"), expected_user.encode("utf-8"))
            if user_ok and verify_password(password or "", stored_secret):
                self.bootstrap_admin()
                repo.audit(candidate, "auth.bootstrap_admin", ip=client_key)
                self.session.commit()
                return User(user_id=candidate, username=candidate, roles=["admin"])
            repo.audit(candidate or "unknown", "auth.login", outcome="FAILURE", ip=client_key,
                       detail="bootstrap credentials rejected")
            self.session.commit()
            raise AuthenticationError("Invalid username or password")

        user = repo.get_by_username(candidate)
        if user is None:
            repo.audit(candidate or "unknown", "auth.login", outcome="FAILURE", ip=client_key,
                       detail="unknown user")
            self.session.commit()
            raise AuthenticationError("Invalid username or password")

        locked_until = _aware(user.locked_until)
        if locked_until is not None and locked_until > now:
            repo.audit(candidate, "auth.login", outcome="LOCKED", ip=client_key)
            self.session.commit()
            raise AuthenticationError("Account temporarily locked. Try again later.")

        if not user.is_active:
            repo.audit(candidate, "auth.login", outcome="DISABLED", ip=client_key)
            self.session.commit()
            raise AuthenticationError("Account is disabled.")

        if not verify_password(password or "", user.password_hash):
            repo.record_failure(
                candidate,
                max_failures=self.settings.LOGIN_MAX_FAILURES,
                lockout_seconds=self.settings.LOGIN_LOCKOUT_SECONDS,
            )
            repo.audit(candidate, "auth.login", outcome="FAILURE", ip=client_key,
                       detail="bad password")
            self.session.commit()
            raise AuthenticationError("Invalid username or password")

        repo.reset_failures(candidate)
        repo.audit(candidate, "auth.login", ip=client_key)
        self.session.commit()
        return User(
            user_id=user.id,
            username=user.username,
            roles=user.role_list,
            mfa_enabled=bool(user.mfa_enabled),
        )

    # -- Legacy env path (no DB) --------------------------------------------

    def _authenticate_env_fallback(self, username: str, password: str, *, client_key: str = "") -> User:
        import time

        settings = self.settings
        bucket = f"{(username or '').lower()}|{client_key or '-'}"
        now = time.time()
        _FAILURES[bucket] = [t for t in _FAILURES.get(bucket, []) if now - t < settings.LOGIN_LOCKOUT_SECONDS]
        if len(_FAILURES[bucket]) >= settings.LOGIN_MAX_FAILURES:
            raise AuthenticationError("Too many failed login attempts. Try again later.")
        expected_user = settings.ADMIN_USERNAME
        stored_secret = settings.ADMIN_PASSWORD_HASH or settings.ADMIN_PASSWORD
        user_ok = hmac.compare_digest((username or "").encode("utf-8"), expected_user.encode("utf-8"))
        pass_ok = verify_password(password or "", stored_secret)
        if not (user_ok and pass_ok):
            _FAILURES[bucket].append(now)
            raise AuthenticationError("Invalid username or password")
        _FAILURES.pop(bucket, None)
        return User(user_id=username, username=username, roles=["admin"])
