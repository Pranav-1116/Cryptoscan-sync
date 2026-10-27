"""Organization-level settings (key/value, JSON values).

Used to persist the active sector profile and related estate configuration so
the universal engine and reports read a consistent sector context.
"""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models.app_setting import AppSetting


class SettingsRepository:
    def __init__(self, session: Session):
        self.session = session

    def get_raw(self, key: str, *, tenant_id: str | None = None) -> str | None:
        stmt = select(AppSetting).where(AppSetting.key == key)
        if tenant_id is not None:
            stmt = stmt.where(AppSetting.tenant_id == tenant_id)
        row = self.session.execute(stmt).scalar_one_or_none()
        return row.value if row is not None else None

    def get(self, key: str, default: Any = None, *, tenant_id: str | None = None) -> Any:
        raw = self.get_raw(key, tenant_id=tenant_id)
        if raw is None:
            return default
        try:
            return json.loads(raw)
        except (TypeError, ValueError):
            return raw

    def set(
        self,
        key: str,
        value: Any,
        *,
        updated_by: str | None = None,
        tenant_id: str | None = None,
    ) -> AppSetting:
        raw = value if isinstance(value, str) else json.dumps(value, default=str)
        stmt = select(AppSetting).where(AppSetting.key == key)
        if tenant_id is not None:
            stmt = stmt.where(AppSetting.tenant_id == tenant_id)
        row = self.session.execute(stmt).scalars().first()
        if row is None:
            row = AppSetting(
                key=key, value=raw, updated_by=updated_by,
                tenant_id=tenant_id,
            )
            self.session.add(row)
        else:
            row.value = raw
            row.updated_by = updated_by
            if tenant_id is not None and row.tenant_id != tenant_id:
                raise PermissionError("settings tenant does not match requested tenant")
        self.session.flush()
        return row

    def all(self) -> dict[str, Any]:
        rows = self.session.execute(select(AppSetting)).scalars().all()
        out: dict[str, Any] = {}
        for row in rows:
            try:
                out[row.key] = json.loads(row.value) if row.value else None
            except (TypeError, ValueError):
                out[row.key] = row.value
        return out


#: well-known key for the active sector profile id
SECTOR_SETTING_KEY = "sector_profile"
