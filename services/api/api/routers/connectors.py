"""Connector Framework / SDK endpoints (blueprint #13).

Surfaces the ZELNX Connector SDK registry: which connector kinds/methods are
available, and lets a caller validate a connector definition + authorize a run
against the tenant scope before anything touches a target. Also reflects the
COnnector catalog the onboarding model already declares, so operators see the
full contract (kinds + methods) even before a connector implementation is
installed.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session
from db.models.onboarding import CONNECTOR_KINDS, CONNECTOR_METHODS

# import built-in connectors so the registry is populated
import connector_sdk.contrib  # noqa: F401
from connector_sdk import available, get_connector

router = APIRouter(prefix="/connectors", tags=["connectors"])


@router.get("/sdk")
def sdk_catalog(
    scope: str | None = None,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Available connectors from the SDK registry + the declared catalog."""
    return {
        "source": "connector_sdk",
        "registered": available(scope),
        "catalog_kinds": list(CONNECTOR_KINDS),
        "catalog_methods": list(CONNECTOR_METHODS),
    }


@router.post("/sdk/validate")
def validate_connector(
    payload: dict,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Validate a connector definition against the SDK contract (read-only).

    Returns whether the kind/method resolve to a registered connector and the
    connector's declared mode (passive/active). Never runs a scan.
    """
    kind = payload.get("kind", "other")
    method = payload.get("method", "api")
    try:
        inst = get_connector(kind, method, name=payload.get("name"))
    except KeyError:
        # registered catalog but not an SDK implementation yet -> honest state
        return {
            "valid": False,
            "kind": kind,
            "method": method,
            "implemented": False,
            "detail": f"connector kind={kind!r} method={method!r} is cataloged but has no SDK implementation",
        }
    return {"valid": True, "implemented": True, "connector": inst.describe()}
