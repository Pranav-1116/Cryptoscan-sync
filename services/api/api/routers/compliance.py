"""Compliance endpoints: evidence pack automation, attestations, WORM policy,
the requirements register (requirement → evidence / gaps / expiry / sign-off),
and the read-only auditor surface (scope-limited, separate credential class).
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


import hashlib
import json
import os
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import desc

from api.dependencies import get_current_user, get_db_session
from db.models.compliance_record import ComplianceAttestation, ComplianceEvidencePack

router = APIRouter(prefix="/compliance", tags=["compliance"])


def _require_admin(user: str = Depends(get_current_user)) -> str:

    if user != "admin":
        raise HTTPException(status_code=403, detail="Requires role: admin")
    return user


@router.get("/evidence")
def evidence(request: Request, user: str = Depends(_require_admin), db=Depends(get_db_session)):
    """Automated SOC-2-style evidence pack from live state (no templates).

    Live collection only — pass ``POST /evidence/packs`` to pin a durable,
    content-addressed pack that requirements evaluation and attestations
    reference.
    """
    from compliance.engine import collect_evidence

    return collect_evidence(db, app_settings=request.app.state.settings)


@router.post("/attestations")
def create_attestation(
    request: Request, body: "AttestationIn", user: str = Depends(_require_admin), db=Depends(get_db_session)
):
    """Sign a PERSISTED evidence pack — reviewer sign-off must be durable.

    The signature covers the exact pinned pack (pack_sha256), so a later
    reader can re-verify what the reviewer actually saw. A hash that does
    not reference a pinned pack is refused: sign-offs over ephemeral live
    state were indistinguishable from sign-offs over nothing.
    """
    from compliance.engine import create_attestation as _create

    row = db.query(ComplianceEvidencePack).filter(ComplianceEvidencePack.pack_sha256 == body.pack_sha256).one_or_none()
    if row is None:
        raise HTTPException(
            status_code=404,
            detail=(
                "no persisted evidence pack with this hash — pin the "
                "current evidence first: POST /api/v1/compliance/evidence/packs"
            ),
        )
    pack = {**row.payload, "pack_sha256": row.pack_sha256}
    secret = os.environ.get("ATTESTATION_SECRET") or os.environ.get("SECRET_KEY")
    att = _create(pack, scope=body.scope, signed_by=body.signed_by, secret=secret)
    record = ComplianceAttestation(
        pack_id=row.id,
        pack_sha256=row.pack_sha256,
        scope=body.scope,
        signed_by=body.signed_by,
        jws=att["jws"],
        snapshot=att["snapshot"],
        signed_at=datetime.now(timezone.utc),
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return {**att, "attestation_id": record.id, "persisted": True}


class AttestationIn(BaseModel):
    scope: str
    signed_by: str
    pack_sha256: str


@router.get("/attestations")
def list_attestations(user: str = Depends(_require_admin), db=Depends(get_db_session)):
    """Durable sign-offs, re-verified on read.

    ``jws_valid`` is recomputed against the current signing secret for every
    row — a rotated key or a tampered signature surfaces as invalid instead
    of silently counting as sign-off.
    """
    from compliance.engine import verify_attestation as _verify

    secret = os.environ.get("ATTESTATION_SECRET") or os.environ.get("SECRET_KEY")
    out = []
    for row in db.query(ComplianceAttestation).order_by(desc(ComplianceAttestation.signed_at)).all():
        verdict = _verify({"jws": row.jws}, secret)
        out.append(
            {
                "attestation_id": row.id,
                "pack_sha256": row.pack_sha256,
                "scope": row.scope,
                "signed_by": row.signed_by,
                "signed_at": row.signed_at.isoformat() if row.signed_at else None,
                "jws_valid": bool(verdict.get("valid")),
                "note": None
                if verdict.get("valid")
                else "signature does not verify under the current key — rotated or tampered",
            }
        )
    return {"attestations": out, "count": len(out)}


# ---------------------------------------------------------------------------
# requirements register — requirement → evidence / gaps / expiry / sign-off
# ---------------------------------------------------------------------------
def _pack_integrity(row: ComplianceEvidencePack) -> str:
    """Recompute the content address over the stored payload."""
    body = json.dumps(row.payload, sort_keys=True, default=str).encode()
    recomputed = hashlib.sha256(body).hexdigest()
    return "OK" if recomputed == row.pack_sha256 else "MISMATCH"


@router.post("/evidence/packs")
def snapshot_evidence(request: Request, user: str = Depends(_require_admin), db=Depends(get_db_session)):
    """Pin the CURRENT live evidence as a durable, content-addressed pack.

    Requirement evaluation, expiry and reviewer sign-off all reference the
    pinned pack — a moving live state can be checked, but not signed or
    aged. Idempotent: an identical pack is returned, not duplicated.
    """
    from compliance.engine import collect_evidence

    pack = collect_evidence(db, app_settings=request.app.state.settings)
    sha = pack["pack_sha256"]
    existing = db.query(ComplianceEvidencePack).filter(ComplianceEvidencePack.pack_sha256 == sha).one_or_none()
    if existing is not None:
        return {
            "pack_id": existing.id,
            "pack_sha256": sha,
            "created": False,
            "controls": len(pack.get("controls") or []),
            "summary": pack.get("summary"),
            "verify_path": f"/api/v1/compliance/evidence/packs/{existing.id}",
            "note": "an identical pack is already pinned (content-addressed)",
        }
    generated_at = _parse_utc(pack.get("generated_at")) or datetime.now(timezone.utc)
    row = ComplianceEvidencePack(
        pack_sha256=sha,
        payload={k: v for k, v in pack.items() if k != "pack_sha256"},
        summary=pack.get("summary") or {},
        generated_at=generated_at,
        collected_by=user,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return {
        "pack_id": row.id,
        "pack_sha256": sha,
        "created": True,
        "controls": len(pack.get("controls") or []),
        "summary": pack.get("summary"),
        "verify_path": f"/api/v1/compliance/evidence/packs/{row.id}",
        "note": "pack pinned — requirements evaluation and sign-off reference it",
    }


def _parse_utc(value) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None


@router.get("/evidence/packs")
def list_packs(user: str = Depends(_require_admin), db=Depends(get_db_session)):
    rows = (
        db.query(ComplianceEvidencePack)
        .order_by(desc(ComplianceEvidencePack.generated_at), desc(ComplianceEvidencePack.created_at))
        .all()
    )
    return {
        "packs": [
            {
                "pack_id": r.id,
                "pack_sha256": r.pack_sha256,
                "generated_at": r.generated_at.isoformat() if r.generated_at else None,
                "collected_by": r.collected_by,
                "controls": len((r.payload or {}).get("controls") or []),
                "integrity": _pack_integrity(r),
                "verify_path": f"/api/v1/compliance/evidence/packs/{r.id}",
            }
            for r in rows
        ],
        "count": len(rows),
    }


@router.get("/evidence/packs/{pack_id}")
def get_pack(pack_id: str, user: str = Depends(_require_admin), db=Depends(get_db_session)):
    """Serve the pinned pack VERBATIM — never regenerated — with an
    integrity self-check (recomputed content address vs the pinned hash)."""
    row = db.get(ComplianceEvidencePack, pack_id)
    if row is None:
        raise HTTPException(status_code=404, detail="no evidence pack with this id")
    integrity = _pack_integrity(row)
    return {
        "pack_id": row.id,
        "pack_sha256": row.pack_sha256,
        "generated_at": row.generated_at.isoformat() if row.generated_at else None,
        "collected_by": row.collected_by,
        "integrity": integrity,
        "controls": len((row.payload or {}).get("controls") or []),
        "summary": (row.payload or {}).get("summary"),
        "payload": row.payload,
        "note": (
            None
            if integrity == "OK"
            else "MISMATCH: stored payload does not hash to the pinned "
            "content address — tampered or corrupted; not trusted"
        ),
    }


@router.get("/requirements")
def requirements(user: str = Depends(_require_admin), db=Depends(get_db_session)):
    """Evaluate the requirements register against the LATEST pinned pack.

    Each requirement reports its exact evidence (mapped control checks),
    its gap, its expiry against its own freshness window, and reviewer
    sign-off from durable attestations over THIS pack. No pinned pack (or
    an integrity MISMATCH) means every requirement honestly reports
    ``no_evidence`` — never a quiet green score.
    """
    from compliance.engine import verify_attestation as _verify
    from compliance.requirements import evaluate_requirements

    latest = (
        db.query(ComplianceEvidencePack)
        .order_by(desc(ComplianceEvidencePack.generated_at), desc(ComplianceEvidencePack.created_at))
        .first()
    )
    if latest is None:
        report = evaluate_requirements(None, [])
        return {
            **report,
            "pack": None,
            "note": (
                "no evidence pack has been pinned — requirements are "
                "not evaluated. Pin one: POST /api/v1/compliance/evidence/packs"
            ),
        }

    integrity = _pack_integrity(latest)
    if integrity == "MISMATCH":
        report = evaluate_requirements(None, [])
        return {
            **report,
            "pack": {"pack_id": latest.id, "pack_sha256": latest.pack_sha256, "integrity": integrity},
            "note": (
                "the latest pinned pack fails its integrity self-check "
                "(payload no longer hashes to the pinned content "
                "address) — treated as untrusted; requirements are "
                "not evaluated against it"
            ),
        }

    secret = os.environ.get("ATTESTATION_SECRET") or os.environ.get("SECRET_KEY")
    rows = db.query(ComplianceAttestation).filter(ComplianceAttestation.pack_sha256 == latest.pack_sha256).all()
    attestations = [
        {
            "scope": a.scope,
            "signed_by": a.signed_by,
            "signed_at": a.signed_at.isoformat() if a.signed_at else None,
            "pack_sha256": a.pack_sha256,
            "jws_valid": bool(_verify({"jws": a.jws}, secret).get("valid")),
        }
        for a in rows
    ]

    pack = {**latest.payload, "pack_sha256": latest.pack_sha256}
    report = evaluate_requirements(pack, attestations)
    return {
        **report,
        "pack": {
            "pack_id": latest.id,
            "pack_sha256": latest.pack_sha256,
            "generated_at": (latest.generated_at.isoformat() if latest.generated_at else None),
            "collected_by": latest.collected_by,
            "integrity": integrity,
            "verify_path": f"/api/v1/compliance/evidence/packs/{latest.id}",
        },
        "attestations": attestations,
        "note": (
            "evidence ages: each requirement expires against its own "
            "freshness window measured from the pack's collection "
            "time — re-pin to refresh"
        ),
    }


@router.post("/attestations/verify")
def verify_attestation(body: "AttestationVerifyIn", user: str = Depends(_require_admin)):
    from compliance.engine import verify_attestation as _verify

    secret = os.environ.get("ATTESTATION_SECRET") or os.environ.get("SECRET_KEY")
    return _verify(body.model_dump(), secret)


class AttestationVerifyIn(BaseModel):
    jws: str
    snapshot: dict | None = None


@router.get("/retention")
def retention_policy(user: str = Depends(get_current_user), db=Depends(get_db_session)):
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
    return {"policy": policy, "oldest_audit_record_epoch": oldest, "delete_allowed_now": allowed, "reason": reason}


# ---------------------------------------------------------------------------
# auditor API — read-only, explicitly scoped, fail-closed
# ---------------------------------------------------------------------------
AUDITOR_SCOPES = {"evidence": "/compliance/audit/evidence", "retention": "/compliance/retention"}


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
        raise HTTPException(status_code=401, detail="auditor access requires X-Auditor-Key or admin session")
    return "admin"


@router.get("/audit/evidence")
def audit_evidence(request: Request, db=Depends(get_db_session)):
    require_auditor(request)
    return evidence(request, user="admin", db=db)


@router.get("/audit/retention")
def audit_retention(request: Request, db=Depends(get_db_session)):
    require_auditor(request)
    return retention_policy(db=db)
