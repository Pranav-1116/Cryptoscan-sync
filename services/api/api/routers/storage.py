"""Storage optimization API: usage truth, policies, sweeps, restore tests.

Spec §2.1/§7 surfaces. Every mutating endpoint follows the house contract:
dry-run by default, performing something requires saying so (``dry_run:
false``), and every performed deletion is audited server-side
(db.privileged_ops). Read surfaces report the truth the monitoring
control needs: stored vs plaintext bytes, compression savings, tier
distribution, unreferenced backlog and near-full alerts.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.dependencies import (
    TenantContext, get_db_session, get_current_user, get_tenant_context,
    require_query_tenant_scope,
)
from api.security.rbac import require_permission
from db.storage import (
    ContentAddressedStore, ContentGoneError, QuotaExceeded,
    ensure_default_policies, gc_unreferenced, policy_for, record_evidence_content,
    retention_sweep, run_restore_test, space_alerts, transition_tiers, usage,
    usage_report, verify_restorable,
)
from db.models.content_object import ContentObject
from db.models.storage_policy import RestoreTestRecord, StoragePolicy
from db.tenancy import tenant_scope

router = APIRouter(prefix="/storage", tags=["storage"],
                   dependencies=[Depends(require_query_tenant_scope)])

# Declared once at module level so the boundary drill can read
# ``.permissions`` off the exact objects the route table enforces, and tests
# can override the exact dependency instances.
require_storage_read = require_permission("storage.read")
require_storage_ingest = require_permission("storage.ingest")
require_storage_operate = require_permission("storage.operate")
require_storage_policy = require_permission("storage.policy")


class SweepIn(BaseModel):
    dry_run: bool = True
    archive_dir: Optional[str] = Field(
        default=None,
        description="Where archive-verified copies land before a drop.")


class EvidenceIn(BaseModel):
    content_b64: str
    collector: str
    source_location: str
    owner: str
    authorization_context: Optional[Dict[str, Any]] = None
    evidence_record_id: Optional[str] = None
    observation_ref: Optional[str] = None
    category: str = "asset_observation"
    collected_at: Optional[datetime] = None


class PolicyIn(BaseModel):
    category: str
    retention_days: int = Field(ge=0)
    hot_days: int = Field(ge=0)
    warm_days: int = Field(ge=0)
    compress: bool = True
    expired_action: str = Field(pattern="^(archive|delete)$")


@router.get("/usage", dependencies=[Depends(require_storage_read)])
def storage_usage(
    db: Session = Depends(get_db_session),
    user: str = Depends(get_current_user),
    ctx: TenantContext = Depends(get_tenant_context),
    tenant_id: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    """Storage truth: counts, plaintext vs stored bytes, savings, tiers,
    unreferenced backlog — plus the near-full alerts that must fire before
    the disk fills (control 9)."""
    tid = tenant_id or ctx.tenant_id
    report = usage_report(db, tid)
    quota = usage(db, tid or "")
    return {
        "usage": report.to_dict(),
        "quota": {
            "bytes_used": quota.bytes_used,
            "object_count": quota.object_count,
            "limit_bytes": quota.limit_bytes,
            "limit_objects": quota.limit_objects,
        },
        "alerts": [
            {"level": a.level, "kind": a.kind, "subject": a.subject, "detail": a.detail}
            for a in space_alerts(db, tenant_id=tid)
        ],
    }


@router.get("/policies", dependencies=[Depends(require_storage_read)])
def list_policies(
    db: Session = Depends(get_db_session),
    user: str = Depends(get_current_user),
    ctx: TenantContext = Depends(get_tenant_context),
    tenant_id: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    """Effective retention/lifecycle policy per evidence category."""
    ensure_default_policies(db)
    tid = tenant_id or ctx.tenant_id
    from db.models.content_object import EVIDENCE_CATEGORIES
    policies = []
    for category in EVIDENCE_CATEGORIES:
        p = policy_for(db, tid, category)
        policies.append({
            "category": category,
            "retention_days": p.retention_days if not isinstance(p, dict) else p["retention_days"],
            "hot_days": p.hot_days if not isinstance(p, dict) else p["hot_days"],
            "warm_days": p.warm_days if not isinstance(p, dict) else p["warm_days"],
            "compress": p.compress if not isinstance(p, dict) else p["compress"],
            "expired_action": p.expired_action if not isinstance(p, dict) else p["expired_action"],
            "source": "tenant" if (tid and getattr(p, "tenant_id", None) == tid) else "platform",
        })
    return {"policies": policies}


@router.put("/policies", dependencies=[Depends(require_storage_policy)])
def set_policy(
    body: PolicyIn,
    db: Session = Depends(get_db_session),
    user: str = Depends(get_current_user),
    ctx: TenantContext = Depends(get_tenant_context),
    tenant_id: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    """Override a category policy for one tenant (gated: storage.policy)."""
    tid = tenant_id or ctx.tenant_id
    if not tid:
        raise HTTPException(status_code=400, detail="tenant scope required")
    row = db.query(StoragePolicy).filter(
        StoragePolicy.tenant_id == tid, StoragePolicy.category == body.category
    ).one_or_none()
    if row is None:
        row = StoragePolicy(tenant_id=tid, **body.model_dump())
        db.add(row)
    else:
        for name, value in body.model_dump().items():
            setattr(row, name, value)
    db.flush()
    return {"policy": body.model_dump(), "tenant_id": tid}


@router.post("/evidence", dependencies=[Depends(require_storage_ingest)])
def store_evidence(
    body: EvidenceIn,
    db: Session = Depends(get_db_session),
    user: str = Depends(get_current_user),
    ctx: TenantContext = Depends(get_tenant_context),
    tenant_id: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    """Record one collection event: bytes deduplicate, provenance never does.

    Identical bytes collected tomorrow return the same content address and
    a NEW provenance link — owners, times, source locations and
    authorization contexts are preserved separately (spec 2.1, the
    critical distinction)."""
    import base64
    try:
        data = base64.b64decode(body.content_b64, validate=True)
    except Exception:
        raise HTTPException(status_code=422, detail="content_b64 is not valid base64")
    tid = tenant_id or ctx.tenant_id
    if not tid:
        raise HTTPException(status_code=400, detail="tenant scope required")
    cas = ContentAddressedStore(db)
    try:
        ref = record_evidence_content(
            db, tenant_id=tid, data=data, collected_at=body.collected_at,
            collector=body.collector, source_location=body.source_location,
            owner=body.owner, authorization_context=body.authorization_context,
            evidence_record_id=body.evidence_record_id,
            observation_ref=body.observation_ref, category=body.category,
            store=cas,
        )
    except QuotaExceeded as exc:
        raise HTTPException(status_code=413, detail=str(exc))
    db.flush()
    return {
        "content_sha256": ref.sha256, "stored": not ref.deduped,
        "plain_size": ref.plain_size, "stored_size": ref.stored_size,
        "codec": ref.codec,
    }


@router.get("/objects/{sha256}", dependencies=[Depends(require_storage_read)])
def object_metadata(
    sha256: str,
    db: Session = Depends(get_db_session),
    user: str = Depends(get_current_user),
    ctx: TenantContext = Depends(get_tenant_context),
    tenant_id: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    """Metadata only — the searchable row without the large bytes
    (metadata separation)."""
    tid = tenant_id or ctx.tenant_id
    row = db.query(ContentObject).filter(
        ContentObject.tenant_id == (tid or ""), ContentObject.sha256 == sha256
    ).one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="unknown content object")
    return {
        "sha256": row.sha256, "kind": row.kind, "category": row.category,
        "codec": row.codec, "plain_size": row.plain_size,
        "stored_size": row.stored_size, "chunk_count": row.chunk_count,
        "storage_tier": row.storage_tier, "ref_count": row.ref_count,
        "body_dropped_at": row.body_dropped_at,
    }


@router.post("/retention/sweep", dependencies=[Depends(require_storage_operate)])
def sweep_retention(
    body: SweepIn,
    db: Session = Depends(get_db_session),
    user: str = Depends(get_current_user),
    ctx: TenantContext = Depends(get_tenant_context),
    tenant_id: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    """Retention + tier lifecycle sweep. Dry-run by default."""
    ensure_default_policies(db)
    tiers = transition_tiers(db, dry_run=body.dry_run)
    sweeps = retention_sweep(db, dry_run=body.dry_run, archive_dir=body.archive_dir)
    db.flush()
    return _report(tiers, sweeps)


@router.post("/gc", dependencies=[Depends(require_storage_operate)])
def sweep_gc(
    body: SweepIn,
    db: Session = Depends(get_db_session),
    user: str = Depends(get_current_user),
) -> Dict[str, Any]:
    """Garbage-collect unreferenced content objects (ref_count == 0, past
    the grace period). Dry-run by default."""
    report = gc_unreferenced(db, dry_run=body.dry_run)
    db.flush()
    return {
        "dry_run": report.dry_run,
        "actions": [
            {"action": a.action, "sha256": a.sha256, "category": a.category,
             "detail": a.detail, "performed": a.performed}
            for a in report.actions
        ],
    }


@router.post("/restore-test", dependencies=[Depends(require_storage_operate)])
def restore_test(
    db: Session = Depends(get_db_session),
    user: str = Depends(get_current_user),
    ctx: TenantContext = Depends(get_tenant_context),
    tenant_id: Optional[str] = Query(default=None),
    object_sha256: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    """Verify that stored evidence can actually be recovered (control 10),
    recording every result as evidence of the control itself."""
    tid = tenant_id or ctx.tenant_id
    if not tid:
        raise HTTPException(status_code=400, detail="tenant scope required")
    if object_sha256:
        results = [verify_restorable(db, tenant_id=tid, object_sha256=object_sha256)]
    else:
        results = run_restore_test(db, tenant_id=tid)
    db.flush()
    return {
        "results": [
            {"object_sha256": r.object_sha256, "restored_from_tier": r.restored_from_tier,
             "ok": r.ok, "bytes_verified": r.bytes_verified, "detail": r.detail}
            for r in results
        ],
    }


def _report(*reports) -> Dict[str, Any]:
    actions = []
    dry_run = True
    for report in reports:
        dry_run = dry_run and report.dry_run
        for a in report.actions:
            actions.append({"action": a.action, "sha256": a.sha256,
                            "category": a.category, "detail": a.detail,
                            "performed": a.performed})
    return {"dry_run": dry_run, "actions": actions}


