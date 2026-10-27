"""Machine API-key management (admin): create, list, revoke.

The raw key is returned exactly once, at creation. Everything else (list,
audit trail) sees only the prefix. Keys authenticate any API endpoint via the
`X-API-Key` header — see api.dependencies — which is the integration surface
for CI pipelines, SIEM pulls, and scripts that cannot hold a browser session.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.dependencies import get_db_session, require_roles
from api.events.bus import get_event_bus
from db.repositories.api_key_repository import ApiKeyRepository
from db.repositories.user_repository import UserRepository

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api-keys", tags=["api-keys"])


class ApiKeyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    roles: list[str] = Field(default_factory=lambda: ["viewer"])
    expires_at: Optional[datetime] = None


class ApiKeyOut(BaseModel):
    id: str
    name: str
    key_prefix: str
    roles: list[str]
    created_by: str
    created_at: datetime
    expires_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    active: bool


class ApiKeyCreated(ApiKeyOut):
    raw_key: str  # shown once


def _to_out(row) -> ApiKeyOut:
    return ApiKeyOut(
        id=row.id,
        name=row.name,
        key_prefix=row.key_prefix + "…",
        roles=row.role_list,
        created_by=row.created_by,
        created_at=row.created_at,
        expires_at=row.expires_at,
        last_used_at=row.last_used_at,
        revoked_at=row.revoked_at,
        active=row.is_active_key,
    )


@router.post("", response_model=ApiKeyCreated, status_code=201)
def create_api_key(
    body: ApiKeyCreate,
    user: str = Depends(require_roles("admin")),
    db: Session = Depends(get_db_session),
) -> ApiKeyCreated:
    repo = ApiKeyRepository(db)
    try:
        row, raw = repo.create(
            name=body.name, created_by=user, roles=body.roles, expires_at=body.expires_at
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    db.commit()
    UserRepository(db).audit(
        user,
        "auth.api_key_create",
        target_type="api_key",
        target_id=row.id,
        detail={"name": row.name, "roles": row.role_list},
    )
    db.commit()
    get_event_bus().publish(
        "apikey.create", {"name": row.name, "roles": row.role_list, "created_by": user},
        source="api-keys",
    )
    out = ApiKeyCreated(**_to_out(row).model_dump(), raw_key=raw)
    return out


@router.get("", response_model=list[ApiKeyOut])
def list_api_keys(
    include_revoked: bool = Query(True),
    user: str = Depends(require_roles("admin")),
    db: Session = Depends(get_db_session),
) -> list[ApiKeyOut]:
    rows = ApiKeyRepository(db).list_keys(include_revoked=include_revoked)
    return [_to_out(r) for r in rows]


@router.delete("/{key_id}", response_model=ApiKeyOut)
def revoke_api_key(
    key_id: str,
    user: str = Depends(require_roles("admin")),
    db: Session = Depends(get_db_session),
) -> ApiKeyOut:
    repo = ApiKeyRepository(db)
    row = repo.revoke(key_id)
    if row is None:
        raise HTTPException(status_code=404, detail="API key not found")
    db.commit()
    UserRepository(db).audit(
        user, "auth.api_key_revoke", target_type="api_key", target_id=row.id,
        detail={"name": row.name},
    )
    db.commit()
    get_event_bus().publish(
        "apikey.revoke", {"name": row.name, "revoked_by": user}, source="api-keys"
    )
    return _to_out(row)

