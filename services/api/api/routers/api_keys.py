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

from db.repositories.api_key_repository import ApiKeyRepository
from db.repositories.user_repository import UserRepository
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.dependencies import get_db_session, require_roles
from api.events.bus import get_event_bus

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api-keys", tags=["api-keys"])


class ApiKeyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    roles: list[str] = Field(default_factory=lambda: ["viewer"])
    expires_at: Optional[datetime] = None
    scopes: list[str] = Field(
        default_factory=list,
        description="Allowed API path prefixes, e.g. ['/findings','/scans']. Empty = all.",
    )
    allowed_methods: list[str] = Field(
        default_factory=lambda: ["GET"],
        description="Allowed HTTP methods. Defaults to read-only GET.",
    )
    rate_per_minute: int = Field(0, ge=0, le=1_000_000, description="Requests/min cap; 0 = no key cap.")
    allowed_ips: list[str] = Field(
        default_factory=list,
        description="Optional IP/CIDR allowlist, e.g. ['10.0.0.0/8','203.0.113.4']. Empty = any.",
    )
    rotate_after_days: Optional[int] = Field(
        None, ge=1, le=3650, description="Reminder-only rotation age in days.")


class ApiKeyOut(BaseModel):
    id: str
    name: str
    key_prefix: str
    roles: list[str]
    scopes: list[str]
    allowed_methods: list[str]
    allowed_ips: list[str] = Field(default_factory=list)
    rotate_after_days: Optional[int] = None
    rotation_state: Optional[str] = None
    rate_per_minute: int
    request_count: int = 0
    denied_count: int = 0
    created_by: str
    created_at: datetime
    expires_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    active: bool


class ApiKeyCreated(ApiKeyOut):
    raw_key: str  # shown once


def _to_out(row) -> ApiKeyOut:
    rotation_state = None
    try:
        from identity.api_key_guard import rotation_status

        rotation_state = rotation_status(
            created_at=row.created_at,
            expires_at=row.expires_at,
            rotate_after_days=getattr(row, "rotate_after_days", None),
            revoked_at=row.revoked_at,
        )["state"]
    except Exception:  # pragma: no cover - rotation info is advisory
        rotation_state = None
    return ApiKeyOut(
        id=row.id,
        name=row.name,
        key_prefix=row.key_prefix + "…",
        roles=row.role_list,
        scopes=getattr(row, "scopes_list", []) or [],
        allowed_methods=getattr(row, "method_list", []) or [],
        allowed_ips=getattr(row, "ip_allowlist", []) or [],
        rotate_after_days=getattr(row, "rotate_after_days", None),
        rotation_state=rotation_state,
        rate_per_minute=int(getattr(row, "rate_per_minute", 0) or 0),
        request_count=int(getattr(row, "request_count", 0) or 0),
        denied_count=int(getattr(row, "denied_count", 0) or 0),
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
    # validate/normalize the platform constraints deterministically
    try:
        from apikeys.policy import normalize_methods, normalize_rate, normalize_scopes

        scopes = normalize_scopes(body.scopes)
        methods = normalize_methods(body.allowed_methods)
        rate = normalize_rate(body.rate_per_minute)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    repo = ApiKeyRepository(db)
    try:
        row, raw = repo.create(
            name=body.name,
            created_by=user,
            roles=body.roles,
            expires_at=body.expires_at,
            scopes=scopes,
            allowed_methods=methods,
            rate_per_minute=rate,
            allowed_ips=body.allowed_ips,
            rotate_after_days=body.rotate_after_days,
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


@router.get("/rotation/report")
def rotation_report(
    user: str = Depends(require_roles("admin")),
    db: Session = Depends(get_db_session),
) -> dict:
    """Deterministic key-rotation reminder report.

    Groups active keys by rotation state (EXPIRING_SOON / ROTATION_DUE /
    ROTATION_SOON / OK) so admins see what needs rotating. No ML.
    """
    from identity.api_key_guard import rotation_status

    rows = ApiKeyRepository(db).list_keys(include_revoked=False)
    items = []
    counts: dict[str, int] = {}
    for row in rows:
        st = rotation_status(
            created_at=row.created_at,
            expires_at=row.expires_at,
            rotate_after_days=getattr(row, "rotate_after_days", None),
            revoked_at=row.revoked_at,
        )
        state = st["state"]
        counts[state] = counts.get(state, 0) + 1
        items.append({
            "id": row.id,
            "name": row.name,
            "key_prefix": row.key_prefix + "…",
            "state": state,
            "age_days": st["age_days"],
            "days_until_expiry": st["days_until_expiry"],
            "recommended_action": st["recommended_action"],
            "allowed_ips": list(getattr(row, "ip_allowlist", []) or []),
            "rotate_after_days": getattr(row, "rotate_after_days", None),
        })
    actionable = sum(counts.get(s, 0) for s in
                     ("EXPIRED", "EXPIRING_SOON", "ROTATION_DUE"))
    return {"total_active": len(rows), "counts": counts,
            "actionable": actionable, "keys": items}


class ApiKeyPolicyUpdate(BaseModel):
    allowed_ips: Optional[list[str]] = None
    rotate_after_days: Optional[int] = Field(None, ge=1, le=3650)


@router.patch("/{key_id}", response_model=ApiKeyOut)
def update_api_key_policy(
    key_id: str,
    body: ApiKeyPolicyUpdate,
    user: str = Depends(require_roles("admin")),
    db: Session = Depends(get_db_session),
) -> ApiKeyOut:
    """Update the per-key IP allowlist and/or rotation age."""
    from identity.api_key_guard import normalize_allowlist

    repo = ApiKeyRepository(db)
    row = repo.get(key_id)
    if row is None or row.revoked_at is not None:
        raise HTTPException(status_code=404, detail="API key not found")
    if body.allowed_ips is not None:
        try:
            rules = normalize_allowlist(body.allowed_ips)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        row.allowed_ips = ",".join(rules) if rules else None
    if body.rotate_after_days is not None:
        row.rotate_after_days = body.rotate_after_days
    db.commit()
    UserRepository(db).audit(
        user, "auth.api_key_policy_update", target_type="api_key", target_id=row.id,
        detail={"allowed_ips": row.ip_allowlist, "rotate_after_days": row.rotate_after_days},
    )
    db.commit()
    return _to_out(row)

