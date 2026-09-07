"""Notification routing preferences (spec §37).

Persists the per-tenant event-class -> channel routing (in-app / email /
webhook / SIEM) chosen in the console. Stored as an AppSetting (JSON) so the
routing survives restarts and is read by the delivery layer. No secrets here —
channel destinations are configured separately under /enterprise/integrations.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session
from db.repositories.settings_repository import SettingsRepository

router = APIRouter(prefix="/notifications", tags=["notifications"])

ROUTING_SETTING_KEY = "notification.routing.v1"

#: the event classes the console exposes (ids/names/severity are catalog config;
#: only the per-channel boolean routing map is persisted per tenant).
DEFAULT_ROUTING: list[dict] = []


class RoutingItem(BaseModel):
    id: str
    name: str
    severity: str = "INFO"
    channels: dict[str, bool] = Field(default_factory=dict)


class RoutingPayload(BaseModel):
    routing: list[RoutingItem]


def _repo(db: Session) -> SettingsRepository:
    return SettingsRepository(db)


@router.get("/routing")
def get_routing(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    data = _repo(db).get(ROUTING_SETTING_KEY, default=[])
    return {"routing": data if isinstance(data, list) else [], "persisted": isinstance(data, list) and bool(data)}


@router.put("/routing")
def put_routing(body: RoutingPayload, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    # normalize channels to the four known destinations
    allowed = {"inApp", "email", "webhook", "siem"}
    cleaned = []
    for item in body.routing:
        cleaned.append({
            "id": item.id,
            "name": item.name,
            "severity": item.severity,
            "channels": {k: bool(v) for k, v in item.channels.items() if k in allowed},
        })
    _repo(db).set(ROUTING_SETTING_KEY, cleaned, updated_by=user)
    db.commit()
    return {"ok": True, "routing": cleaned, "count": len(cleaned), "updated_by": user}
