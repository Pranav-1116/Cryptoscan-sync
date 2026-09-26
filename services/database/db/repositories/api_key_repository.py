"""Repository for machine API keys (hashed lookup, revocation, usage stamping)."""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models.api_key import KEY_PREFIX, ApiKey

_RAW_LEN = 36  # secrets.token_urlsafe(36) -> 48 chars; keep >= 32 entropy bits floor


def hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class ApiKeyRepository:
    def __init__(self, session: Session):
        self.session = session

    # -------------------------------------------------------------- lifecycle

    def create(
        self,
        *,
        name: str,
        created_by: str,
        roles: list[str] | None = None,
        expires_at: datetime | None = None,
        scopes: list[str] | None = None,
        allowed_methods: list[str] | None = None,
        rate_per_minute: int = 0,
        allowed_ips: list[str] | str | None = None,
        rotate_after_days: int | None = None,
        tenant_id: str | None = None,
    ) -> tuple[ApiKey, str]:
        """Create a key; returns (row, raw_key). The raw key is shown once."""
        from identity.api_key_guard import normalize_allowlist

        clean = name.strip()
        if not clean:
            raise ValueError("name is required")
        clean_roles = sorted({r for r in (roles or ["viewer"]) if r in ApiKey.valid_roles()})
        if not clean_roles:
            raise ValueError(f"roles must be a subset of {', '.join(ApiKey.valid_roles())}")
        ip_rules = normalize_allowlist(allowed_ips)  # raises ValueError on junk
        raw = KEY_PREFIX + secrets.token_urlsafe(_RAW_LEN)
        row = ApiKey(
            name=clean[:100],
            key_hash=hash_key(raw),
            key_prefix=raw[:12],
            created_by=created_by[:100],
            roles=",".join(clean_roles),
            expires_at=expires_at,
            scopes=",".join(scopes) if scopes else None,
            allowed_methods=",".join(m.upper() for m in allowed_methods) if allowed_methods else None,
            rate_per_minute=max(0, int(rate_per_minute or 0)),
            allowed_ips=",".join(ip_rules) if ip_rules else None,
            rotate_after_days=(int(rotate_after_days) if rotate_after_days else None),
            tenant_id=tenant_id,
        )
        self.session.add(row)
        self.session.flush()
        return row, raw

    def get_by_raw(self, raw: str) -> Optional[ApiKey]:
        """Look up by raw key material; only active keys are returned."""
        if not raw or not raw.startswith(KEY_PREFIX) or len(raw) <= len(KEY_PREFIX) + 16:
            return None
        row = self.session.execute(
            select(ApiKey).where(ApiKey.key_hash == hash_key(raw))
        ).scalar_one_or_none()
        if row is None or not row.is_active_key:
            return None
        return row

    def get(self, key_id: str) -> Optional[ApiKey]:
        return self.session.get(ApiKey, key_id)

    def list_keys(self, include_revoked: bool = True, *, tenant_id: str | None = None,
                  platform: bool = False) -> list[ApiKey]:
        stmt = select(ApiKey).order_by(ApiKey.created_at.desc())
        if platform:
            stmt = stmt.where(ApiKey.tenant_id.is_(None))
        elif tenant_id is not None:
            stmt = stmt.where(ApiKey.tenant_id == tenant_id)
        rows = list(self.session.execute(stmt).scalars().all())
        if include_revoked:
            return rows
        return [r for r in rows if r.is_active_key]

    def revoke(self, key_id: str) -> Optional[ApiKey]:
        row = self.get(key_id)
        if row is None or row.revoked_at is not None:
            return row
        row.revoked_at = datetime.now(timezone.utc)
        self.session.flush()
        return row

    def mark_used(self, key_id: str) -> None:
        """Best-effort last_used_at stamp; callers swallow failures."""
        row = self.get(key_id)
        if row is None:
            return
        row.last_used_at = datetime.now(timezone.utc)
        self.session.flush()

    def record_request(self, key_id: str, *, denied: bool = False) -> None:
        """Best-effort lifetime usage counter increment (+ last_used stamp)."""
        row = self.get(key_id)
        if row is None:
            return
        row.request_count = int(row.request_count or 0) + (0 if denied else 1)
        row.denied_count = int(row.denied_count or 0) + (1 if denied else 0)
        row.last_used_at = datetime.now(timezone.utc)
        self.session.flush()
