"""Compliance endpoints: evidence pack automation, attestations, WORM policy,
and the read-only auditor surface (scope-limited, separate credential class).
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


import os
import time

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from api.dependencies import get_current_user, get_db_session

router = APIRouter(prefix="/compliance", tags=["compliance"])


def _require_admin(user: str = Depends(get_current_user)) -> str:

    if user != "admin":
        raise HTTPException(status_code=403, detail="Requires role: admin")
    return user


@router.get("/evidence")
def evidence(request: Request, user: str = Depends(_require_admin),
             db=Depends(get_db_session)):
    """Automated SOC-2-style evidence pack from live state (no templates)."""
    from compliance.engine import collect_evidence

    pack = collect_evidence(db, app_settings=request.app.state.settings)
    request.app.state.evidence_pack = pack
    return pack


@router.post("/attestations")
def create_attestation(request: Request, body: "AttestationIn",
                       user: str = Depends(_require_admin),
                       db=Depends(get_db_session)):
    from compliance.engine import create_attestation as _create

    pack = request.app.state.evidence_pack
    if pack is None or pack.get("pack_sha256") != body.pack_sha256:
        pack = None
    if pack is None:
        from compliance.engine import collect_evidence

        pack = collect_evidence(db, app_settings=request.app.state.settings)
        request.app.state.evidence_pack = pack
    secret = os.environ.get("ATTESTATION_SECRET") or os.environ.get("SECRET_KEY")
    att = _create(pack, scope=body.scope, signed_by=body.signed_by, secret=secret)
    att["pack_sha256"] = pack["pack_sha256"]
    return att


class AttestationIn(BaseModel):
    scope: str
    signed_by: str
    pack_sha256: str | None = None


@router.post("/attestations/verify")
def verify_attestation(body: "AttestationVerifyIn",
                       user: str = Depends(_require_admin)):
    from compliance.engine import verify_attestation as _verify

    secret = os.environ.get("ATTESTATION_SECRET") or os.environ.get("SECRET_KEY")
    return _verify(body.model_dump(), secret)


class AttestationVerifyIn(BaseModel):
    jws: str
    snapshot: dict | None = None


@router.get("/retention")
def retention_policy(user: str = Depends(get_current_user),
                     db=Depends(get_db_session)):
    from compliance.engine import DEFAULT_RETENTION, can_delete

    from db.repositories.settings_repository import SettingsRepository

    # authenticated console surface (2026-10 auth audit): the retention
    # clock is derived from the caller's partitioned audit trail, so an
    # anonymous reader learned org-specific facts for free. The
    # auditor-key path for external auditors is /compliance/audit/retention.
    policy = SettingsRepository(db).get("compliance.retention", None) or DEFAULT_RETENTION
    # live example: oldest audit-log record age -> WORM verdict. The audit
    # trail is tenant-partitioned (2026-10): read the caller's partition,
    # never the global store — one tenant's processing history is not
    # another tenant's retention clock.
    oldest = None
    try:
        from db.tenancy import current_tenant
        from eventstream.bus import get_bus_for_tenant

        envs = list(get_bus_for_tenant(current_tenant()).replay("audit-log"))
        if envs:
            oldest = min(float(e.get("ts_epoch", time.time())) for e in envs)
    except Exception as _handler_exc:
        logger.warning(
            "exception_suppressed",
            extra={"error_type": type(_handler_exc).__name__},
        )
        pass
    allowed, reason = can_delete("audit_log", oldest, policy)
    return {"policy": policy, "oldest_audit_record_epoch": oldest,
            "delete_allowed_now": allowed, "reason": reason}


# ---------------------------------------------------------------------------
# auditor API — read-only, explicitly scoped, fail-closed
# ---------------------------------------------------------------------------
AUDITOR_SCOPES = {"evidence": "/compliance/audit/evidence",
                  "retention": "/compliance/retention"}


def require_auditor(request: Request) -> str:
    """Auditor access: dedicated ``X-Auditor-Key`` matching AUDITOR_API_KEY,
    or an admin session. Fail-closed in production without the key."""
    key = request.headers.get("x-auditor-key")
    expected = os.environ.get("AUDITOR_API_KEY")
    if expected and key and key == expected:
        return "auditor"
    if os.environ.get("ENVIRONMENT", "").lower() in {"production"}:
        raise HTTPException(status_code=401, detail="auditor key required")
    from api.dependencies import get_optional_user

    user = get_optional_user(request)
    if user != "admin":
        raise HTTPException(status_code=401, detail="auditor access requires "
                                                    "X-Auditor-Key or admin session")
    return "admin"


@router.get("/audit/evidence")
def audit_evidence(request: Request, db=Depends(get_db_session)):
    require_auditor(request)
    return evidence(request, user="admin", db=db)


@router.get("/audit/retention")
def audit_retention(request: Request, db=Depends(get_db_session)):
    require_auditor(request)
    return retention_policy(db=db)
