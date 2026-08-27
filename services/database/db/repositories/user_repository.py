"""Repository for users, sessions, and the audit trail."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models.user import AuditLog, User, UserSession, VALID_ROLES


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class UserRepository:
    def __init__(self, session: Session):
        self.session = session

    # ------------------------------------------------------------------ users

    def count_users(self) -> int:
        from sqlalchemy import func

        return int(self.session.execute(select(func.count()).select_from(User)).scalar_one())

    def get_by_username(self, username: str) -> User | None:
        return self.session.execute(
            select(User).where(User.username == (username or "").strip().lower())
        ).scalar_one_or_none()

    def create_user(
        self,
        username: str,
        password_hash: str,
        roles: list[str] | None = None,
        *,
        display_name: str | None = None,
        email: str | None = None,
        is_active: bool = True,
    ) -> User:
        clean_roles = sorted({r for r in (roles or ["viewer"]) if r in VALID_ROLES}) or ["viewer"]
        user = User(
            username=(username or "").strip().lower(),
            password_hash=password_hash,
            roles=",".join(clean_roles),
            display_name=display_name,
            email=email,
            is_active=is_active,
        )
        self.session.add(user)
        self.session.flush()
        return user

    def set_roles(self, username: str, roles: list[str]) -> User | None:
        user = self.get_by_username(username)
        if user is None:
            return None
        clean = sorted({r for r in roles if r in VALID_ROLES})
        user.roles = ",".join(clean) if clean else user.roles
        self.session.flush()
        return user

    def set_active(self, username: str, is_active: bool) -> User | None:
        user = self.get_by_username(username)
        if user is None:
            return None
        user.is_active = is_active
        if is_active:
            user.failed_attempts = 0
            user.locked_until = None
        self.session.flush()
        return user

    def set_password(self, username: str, password_hash: str) -> User | None:
        user = self.get_by_username(username)
        if user is None:
            return None
        user.password_hash = password_hash
        user.failed_attempts = 0
        user.locked_until = None
        self.session.flush()
        return user

    def list_users(self) -> list[User]:
        return list(self.session.execute(select(User).order_by(User.username)).scalars().all())

    # ---------------------------------------------------------------- lockout

    def record_failure(self, username: str, *, max_failures: int, lockout_seconds: int) -> User | None:
        user = self.get_by_username(username)
        if user is None:
            return None
        user.failed_attempts = (user.failed_attempts or 0) + 1
        if user.failed_attempts >= max_failures:
            user.locked_until = datetime.now(timezone.utc) + timedelta(seconds=lockout_seconds)
            user.failed_attempts = 0
        self.session.flush()
        return user

    def reset_failures(self, username: str) -> None:
        user = self.get_by_username(username)
        if user is not None:
            user.failed_attempts = 0
            user.locked_until = None
            user.last_login_at = datetime.now(timezone.utc)
            self.session.flush()

    # --------------------------------------------------------------- sessions

    def create_session(self, token: str, username: str, expires_at: datetime, ip: str | None = None) -> UserSession:
        row = UserSession(
            token_hash=token_hash(token),
            username=username,
            created_at_ts=datetime.now(timezone.utc),
            expires_at=expires_at,
            ip_address=ip,
        )
        self.session.add(row)
        self.session.flush()
        return row

    def get_session(self, token: str) -> UserSession | None:
        return self.session.execute(
            select(UserSession).where(UserSession.token_hash == token_hash(token))
        ).scalar_one_or_none()

    def revoke_session(self, token: str) -> bool:
        row = self.get_session(token)
        if row is None:
            return False
        row.revoked_at = datetime.now(timezone.utc)
        self.session.flush()
        return True

    def revoke_all_sessions(self, username: str) -> int:
        rows = list(
            self.session.execute(
                select(UserSession).where(
                    UserSession.username == username,
                    UserSession.revoked_at.is_(None),
                )
            ).scalars().all()
        )
        now = datetime.now(timezone.utc)
        for row in rows:
            row.revoked_at = now
        self.session.flush()
        return len(rows)

    # ------------------------------------------------------------------ audit

    def audit(
        self,
        actor: str,
        action: str,
        *,
        target_type: str | None = None,
        target_id: str | None = None,
        detail: dict | str | None = None,
        ip: str | None = None,
        outcome: str = "SUCCESS",
    ) -> AuditLog:
        if isinstance(detail, (dict, list)):
            detail = json.dumps(detail, default=str)
        row = AuditLog(
            actor=actor or "unknown",
            action=action,
            target_type=target_type,
            target_id=target_id,
            detail=detail,
            ip_address=ip,
            outcome=outcome,
        )
        self.session.add(row)
        self.session.flush()
        return row

    def list_audit(self, *, page: int = 1, page_size: int = 50, actor: str | None = None, action: str | None = None):
        stmt = select(AuditLog).order_by(AuditLog.created_at.desc())
        if actor:
            stmt = stmt.where(AuditLog.actor == actor)
        if action:
            stmt = stmt.where(AuditLog.action == action)
        rows = list(
            self.session.execute(
                stmt.offset((page - 1) * page_size).limit(page_size)
            ).scalars().all()
        )
        return rows
