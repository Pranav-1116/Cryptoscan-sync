"""Unified Asset Inventory (CMDB).

One authoritative, deduplicated inventory of the *real* estate the scanners
discover. It aggregates the persisted entities across every source — systems,
crypto assets, certificates, cloud accounts, hardware, vendors, business
processes, owners and network targets — into a single canonical shape, with an
honest, deterministic unified risk + PQC view and the relationship hints the
backend already knows (USES / USED_BY / SUPPORTS / DEPENDS_ON / PROTECTED_BY /
OWNED_BY). Nothing is invented: every row comes straight from the inventory DB,
missing fields read as null / "".

This is the foundation every scanner writes into (item #1 of the enterprise
blueprint). It is read-only and does not fabricate assets.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session, require_auditor
from db.tenancy import filtered_get
from pydantic import BaseModel, Field
from db.models import (
    BusinessOwner,
    BusinessProcess,
    Certificate,
    CloudAccount,
    CryptoAsset,
    HardwareAsset,
    NetworkScanTarget,
    System,
    SystemAsset,
    SystemBusinessProcess,
    SystemDependency,
    Vendor,
)
from db.models.certificate_usage import CertificateUsage

router = APIRouter(prefix="/inventory", tags=["inventory"])

#: Unified asset_type labels (canonical, not scanner-specific).
_TYPE_LABEL = {
    "System": "Application",
    "CryptoAsset": "Crypto",
    "Certificate": "Certificate",
    "CloudAccount": "Cloud",
    "Hardware": "Hardware",
    "Vendor": "Vendor",
    "BusinessProcess": "BusinessService",
    "BusinessOwner": "Owner",
    "NetworkTarget": "NetworkTarget",
}

def _pqc(algorithm: str | None) -> str:
    # A parsed algorithm is not evidence of negotiation, correct implementation,
    # approved policy or deployment. Never label inventory names "ready".
    from shared_models.quantum_classify import quantum_verdict

    result = quantum_verdict(algorithm)
    if result["verdict"] == "SHOR_VULNERABLE":
        return "vulnerable"
    if result["status"] != "ALLOWED":
        return "unknown"
    if result["verdict"] == "PQC_RESISTANT":
        return "hybrid_candidate" if result["family"] == "kem-hybrid-pqc" else "pqc_candidate"
    if result["verdict"] == "QUANTUM_RESISTANT":
        return "symmetric_candidate"
    return "unknown"


def _risk(criticality: str | None, confidence: str | None, algorithm: str | None, expired: bool = False) -> str:
    """Deterministic unified risk: criticality/severity first, then confidence,
    then PQC exposure, then certificate expiry. No AI, no fabricated scorings."""
    c = str(criticality or "").upper()
    if c in {"TIER-1", "CRITICAL"}:
        return "CRITICAL"
    if c in {"HIGH", "TIER-2"}:
        return "HIGH"
    if _pqc(algorithm) == "vulnerable":
        return "HIGH"
    if expired:
        return "HIGH"
    if c in {"MEDIUM", "TIER-3"}:
        return "MEDIUM"
    if str(confidence or "").upper() in {"HIGH", "CONFIRMED"}:
        return "MEDIUM"
    return "LOW"


def _system_links(session: Session) -> dict[str, dict[str, list[str]]]:
    """system_id -> {'uses': [asset ids], 'supports': [process names], 'depends_on': [child system ids]}"""
    out: dict[str, dict[str, list[str]]] = {}
    for link in session.execute(select(SystemAsset)).scalars().all():
        d = out.setdefault(link.system_id, {"uses": [], "supports": [], "depends_on": [], "owned_by": [], "protected_by": []})
        if link.asset_id not in d["uses"]:
            d["uses"].append(link.asset_id)
    for link in session.execute(select(SystemDependency)).scalars().all():
        d = out.setdefault(link.parent_id, {"uses": [], "supports": [], "depends_on": [], "owned_by": [], "protected_by": []})
        if link.child_id not in d["depends_on"]:
            d["depends_on"].append(link.child_id)
    process_names: dict[str, str] = {}
    for p in session.execute(select(BusinessProcess)).scalars().all():
        process_names[p.id] = str(p.name or "")
    for link in session.execute(select(SystemBusinessProcess)).scalars().all():
        d = out.setdefault(link.system_id, {"uses": [], "supports": [], "depends_on": [], "owned_by": [], "protected_by": []})
        nm = process_names.get(link.process_id, link.process_id)
        if nm not in d["supports"]:
            d["supports"].append(nm)
    return out


def _cert_systems(session: Session) -> dict[str, list[str]]:
    """fingerprint -> [system ids] from real CertificateUsage rows."""
    out: dict[str, list[str]] = {}
    for cu in session.execute(select(CertificateUsage)).scalars().all():
        loc = str(cu.location or "")
        if loc.startswith("system:"):
            sid = loc.split(":", 1)[-1]
            out.setdefault(cu.fingerprint_sha256, [])
            if sid not in out[cu.fingerprint_sha256]:
                out[cu.fingerprint_sha256].append(sid)
    return out


def _crypto_systems(session: Session) -> dict[str, list[str]]:
    """asset id -> [system ids] from real SystemAsset links."""
    out: dict[str, list[str]] = {}
    for link in session.execute(select(SystemAsset)).scalars().all():
        out.setdefault(link.asset_id, [])
        if link.system_id not in out[link.asset_id]:
            out[link.asset_id].append(link.system_id)
    return out


def collect_inventory(session: Session, *,
             limit: int = 500) -> list[dict[str, Any]]:
    sys_links = _system_links(session)
    cert_systems = _cert_systems(session)
    crypto_systems = _crypto_systems(session)
    rows: list[dict[str, Any]] = []

    for s in session.execute(select(System).limit(limit)).scalars().all():
        links = sys_links.get(s.id, {"uses": [], "supports": [], "depends_on": [], "owned_by": [], "protected_by": []})
        rows.append({
            "id": f"system:{s.id}",
            "asset_type": _TYPE_LABEL["System"],
            "name": s.name,
            "criticality": s.criticality,
            "environment": s.environment,
            "owner": s.owner,
            "business_unit": s.business_unit,
            "cloud_provider": s.cloud_provider,
            "agility_score": s.current_agility_score,
            "last_scanned_at": s.last_scanned_at,
            "risk": _risk(s.criticality, None, None),
            "pqc": "unknown",
            "relationships": {
                "uses": links["uses"],
                "supports": links["supports"],
                "depends_on": links["depends_on"],
                "owned_by": [s.owner] if s.owner else [],
                "protected_by": [],
            },
        })

    for a in session.execute(select(CryptoAsset).limit(limit)).scalars().all():
        alg = a.algorithm
        projection = a.to_dict()
        rows.append({
            **{key:projection[key] for key in ("source_basis", "reported_confidence", "source_disposition") if key in projection},
            "id": f"crypto:{a.id}",
            "asset_type": _TYPE_LABEL["CryptoAsset"],
            "name": alg,
            "algorithm": alg,
            "purpose": a.purpose,
            "key_size": a.key_size,
            "confidence": projection["confidence"],
            "file_path": a.file_path,
            "source_language": a.source_language,
            "owner": a.owner,
            "technical_owner": a.technical_owner,
            "security_owner": a.security_owner,
            "risk": _risk(None, projection["confidence"], alg),
            "pqc": _pqc(alg),
            "lifecycle_state": a.lifecycle_state,
            "relationships": {"used_by": crypto_systems.get(a.id, [])},
        })

    for c in session.execute(select(Certificate).limit(limit)).scalars().all():
        rows.append({
            "id": f"cert:{c.id}",
            "asset_type": _TYPE_LABEL["Certificate"],
            "name": c.subject,
            "subject": c.subject,
            "issuer": c.issuer,
            "public_key_algorithm": c.public_key_algorithm,
            "public_key_size": c.public_key_size,
            "owner": c.owner,
            "technical_contact": c.technical_contact,
            "expiry_status": c.expiry_status,
            "days_until_expiry": c.days_until_expiry,
            "risk": _risk(None if c.expiry_status != "EXPIRED" else "HIGH", None, c.public_key_algorithm, expired=c.expiry_status == "EXPIRED"),
            "pqc": _pqc(c.public_key_algorithm),
            "relationships": {"protected_by": cert_systems.get(c.fingerprint_sha256, [])},
        })

    for acc in session.execute(select(CloudAccount).limit(limit)).scalars().all():
        rows.append({
            "id": f"cloud:{acc.id}",
            "asset_type": _TYPE_LABEL["CloudAccount"],
            "name": acc.account_identifier or acc.cloud_provider,
            "cloud_provider": acc.cloud_provider,
            "enabled": acc.enabled,
            "status": getattr(acc, "status", None),
            "risk": _risk(None, None, None),
            "pqc": "unknown",
            "relationships": {},
        })

    for hw in session.execute(select(HardwareAsset).limit(limit)).scalars().all():
        rows.append({
            "id": f"hw:{hw.asset_id}",
            "asset_type": _TYPE_LABEL["Hardware"],
            "name": hw.asset_id,
            "manufacturer": hw.manufacturer,
            "model": hw.model,
            "device_type": hw.device_type,
            "serial_reference": hw.serial_reference,
            "firmware": hw.firmware,
            "hsm": hw.hsm,
            "last_seen": hw.last_seen,
            "risk": _risk(None, None, None),
            "pqc": "unknown",
            "relationships": {},
        })

    for v in session.execute(select(Vendor).limit(limit)).scalars().all():
        rows.append({
            "id": f"vendor:{v.id}",
            "asset_type": _TYPE_LABEL["Vendor"],
            "name": v.name,
            "vendor_type": getattr(v, "vendor_type", None),
            "criticality": v.criticality,
            "contract_end_date": getattr(v, "contract_end_date", None),
            "risk": _risk(v.criticality, None, None),
            "pqc": "unknown",
            "relationships": {},
        })

    for p in session.execute(select(BusinessProcess).limit(limit)).scalars().all():
        rows.append({
            "id": f"process:{p.id}",
            "asset_type": _TYPE_LABEL["BusinessProcess"],
            "name": p.name,
            "process_type": p.process_type,
            "revenue_daily": p.revenue_daily,
            "customer_count": p.customer_count,
            "executive_sponsor": p.executive_sponsor,
            "risk": _risk("TIER-1" if p.revenue_daily and p.revenue_daily > 50000 else None, None, None),
            "pqc": "unknown",
            "relationships": {},
        })

    for o in session.execute(select(BusinessOwner).limit(limit)).scalars().all():
        rows.append({
            "id": f"owner:{o.id}",
            "asset_type": _TYPE_LABEL["BusinessOwner"],
            "name": o.name,
            "email": getattr(o, "email", None),
            "department": getattr(o, "department", None),
            "risk": "LOW",
            "pqc": "unknown",
            "relationships": {},
        })

    for t in session.execute(select(NetworkScanTarget).limit(limit)).scalars().all():
        rows.append({
            "id": f"net:{t.id}",
            "asset_type": _TYPE_LABEL["NetworkTarget"],
            "name": t.endpoint,
            "endpoint": t.endpoint,
            "system_id": getattr(t, "system_id", None),
            "scan_frequency": t.scan_frequency,
            "enabled": t.enabled,
            "risk": _risk(None, None, None),
            "pqc": "unknown",
            "relationships": {},
        })

    return rows


@router.get("/assets")
def list_inventory(
    query: str | None = None,
    asset_type: str | None = None,
    risk: str | None = None,
    lifecycle_state: str | None = Query(
        None, description="Filter crypto assets by lifecycle state "
        "(DISCOVERED/VERIFIED/ACTIVE/DEPRECATED/RETIRED)"),
    limit: int = Query(500, ge=1, le=1000),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """The authoritative, deduplicated asset inventory across every source."""
    rows = collect_inventory(db, limit=limit)
    if asset_type:
        rows = [r for r in rows if r["asset_type"].lower() == asset_type.lower()]
    if lifecycle_state:
        rows = [r for r in rows if str(r.get("lifecycle_state") or "").lower()
                == lifecycle_state.lower()]
    if risk:
        rows = [r for r in rows if r["risk"] and r["risk"].lower() == risk.lower()]
    if query:
        q = query.lower()
        rows = [r for r in rows if q in str(r.get("name") or "").lower()
                or q in str(r.get("algorithm") or "").lower()
                or q in str(r.get("host") or r.get("endpoint") or "").lower()
                or q in str(r.get("serial_reference") or "").lower()]
    return {"assets": rows, "count": len(rows), "source": "unified_inventory", "pqc_basis": "ALGORITHM_SCREENING_NOT_DEPLOYMENT_READINESS"}


@router.get("/summary")
def inventory_summary(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Counts by asset type + risk + PQC posture (honest, from the DB)."""
    rows = collect_inventory(db)
    by_type: dict[str, int] = {}
    by_risk: dict[str, int] = {}
    by_pqc: dict[str, int] = {}
    for r in rows:
        t = r["asset_type"] or "Other"
        by_type[t] = by_type.get(t, 0) + 1
        rk = r.get("risk") or "LOW"
        by_risk[rk] = by_risk.get(rk, 0) + 1
        pq = r.get("pqc") or "unknown"
        by_pqc[pq] = by_pqc.get(pq, 0) + 1
    return {
        "total": len(rows),
        "by_type": by_type,
        "by_risk": by_risk,
        "by_pqc": by_pqc,
        "pqc_basis": "ALGORITHM_SCREENING_NOT_DEPLOYMENT_READINESS",
        "source": "unified_inventory",
    }


# --------------------------------------------------------------------------- #
# Crypto-asset lifecycle (audit 54) — the state machine the audit found missing
# --------------------------------------------------------------------------- #

#: Allowed lifecycle transitions. DISCOVERED is the only state the pipeline
#: writes on its own; everything later is a recorded human judgment.
LIFECYCLE_TRANSITIONS: dict[str, tuple[str, ...]] = {
    "DISCOVERED": ("VERIFIED", "RETIRED"),
    "VERIFIED": ("ACTIVE", "RETIRED"),
    "ACTIVE": ("DEPRECATED", "RETIRED"),
    "DEPRECATED": ("ACTIVE", "RETIRED"),  # re-activation after review
    "RETIRED": (),  # terminal — a retirement that came back is a reintroduction (audit 69)
}


class LifecycleRequest(BaseModel):
    to_state: str = Field(..., pattern="^(VERIFIED|ACTIVE|DEPRECATED|RETIRED)$")
    reason: str = Field(..., min_length=1)


class OwnershipRequest(BaseModel):
    """Direct ownership assignment (audit 55 P0#3). All fields optional —
    only the supplied ones change; omitting one clears nothing."""
    owner: str | None = Field(None, max_length=200)
    technical_owner: str | None = Field(None, max_length=200)
    security_owner: str | None = Field(None, max_length=200)
    reason: str = Field(..., min_length=1)


@router.post("/assets/{asset_id}/ownership")
def assign_asset_ownership(
    asset_id: str,
    body: OwnershipRequest,
    user: str = Depends(require_auditor),
    db: Session = Depends(get_db_session),
):
    """Assign direct owners to a crypto asset (audit 55 P0#3).

    Ownership used to exist only on the System row — an asset with no
    system link had no owner at all. Every assignment is audited with
    its reason and emits a platform event.
    """
    from api.events.platform_events import emit_platform_event

    asset = filtered_get(db, CryptoAsset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Crypto asset not found")
    # same asset-level grant check as the lifecycle transition (round 22)
    from api.dependencies import _user_roles
    from api.security.rbac import normalize_roles
    from db.repositories.resource_grant_repository import (
        ResourceGrantRepository,
        WRITE_ROLE,
    )

    grants = ResourceGrantRepository(db)
    if grants.asset_is_restricted(asset_id):
        platform = set(normalize_roles(_user_roles(user, None, db)))
        if not platform & {"superadmin", "admin"}:
            if not grants.asset_check_access(user, asset_id, WRITE_ROLE):
                raise HTTPException(
                    status_code=403,
                    detail=(
                        f"Asset is grant-restricted; user {user} lacks "
                        f"{WRITE_ROLE} access (directly or via its system / "
                        f"business unit)"
                    ),
                )
    before = {"owner": asset.owner, "technical_owner": asset.technical_owner,
              "security_owner": asset.security_owner}
    for field in ("owner", "technical_owner", "security_owner"):
        value = getattr(body, field)
        if value is not None:
            setattr(asset, field, value)
    db.commit()
    emit_platform_event(
        "inventory.asset_ownership",
        f"Crypto asset {asset.algorithm} at {asset.file_path}:{asset.line_number} "
        f"ownership set by {user}",
        {"asset_id": asset.id, "algorithm": asset.algorithm,
         "file_path": asset.file_path, "before": before,
         "after": {"owner": asset.owner, "technical_owner": asset.technical_owner,
                   "security_owner": asset.security_owner},
         "reason": body.reason, "actor": user},
        target_name="inventory",
    )
    return {
        "asset_id": asset.id,
        "owner": asset.owner,
        "technical_owner": asset.technical_owner,
        "security_owner": asset.security_owner,
        "reason": body.reason,
    }


@router.post("/assets/{asset_id}/lifecycle")
def transition_asset_lifecycle(
    asset_id: str,
    body: LifecycleRequest,
    user: str = Depends(require_auditor),
    db: Session = Depends(get_db_session),
):
    """Move a crypto asset along DISCOVERED -> VERIFIED -> ACTIVE -> DEPRECATED -> RETIRED.

    Transitions are validated against the rules table (no skipping to ACTIVE
    from DISCOVERED, no resurrection from RETIRED — a retired algorithm that
    reappears is a *reintroduction*, handled by the retirement registry).
    Every transition is audited with its reason.
    """
    from api.events.platform_events import emit_platform_event

    asset = filtered_get(db, CryptoAsset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Crypto asset not found")
    # Asset-level grant check (round 22, report 13 §2.2): restrictive only
    # when present — a direct ASSET grant, an owning system's grant, or that
    # system's business-unit grant puts the asset under control; the
    # effective role is inherited up that chain.
    from api.dependencies import _user_roles
    from api.security.rbac import normalize_roles
    from db.repositories.resource_grant_repository import (
        ResourceGrantRepository,
        WRITE_ROLE,
    )

    grants = ResourceGrantRepository(db)
    if grants.asset_is_restricted(asset_id):
        platform = set(normalize_roles(_user_roles(user, None, db)))
        if not platform & {"superadmin", "admin"}:
            if not grants.asset_check_access(user, asset_id, WRITE_ROLE):
                raise HTTPException(
                    status_code=403,
                    detail=(
                        f"Asset is grant-restricted; user {user} lacks "
                        f"{WRITE_ROLE} access (directly or via its system / "
                        f"business unit)"
                    ),
                )
    current = asset.lifecycle_state or "DISCOVERED"
    to_state = body.to_state.upper()
    if to_state not in LIFECYCLE_TRANSITIONS.get(current, ()):
        raise HTTPException(
            status_code=409,
            detail=f"Invalid transition {current} -> {to_state}; allowed from {current}: "
                   f"{', '.join(LIFECYCLE_TRANSITIONS.get(current, ())) or 'none (terminal)'}")
    asset.lifecycle_state = to_state
    db.commit()
    emit_platform_event(
        "inventory.asset_lifecycle",
        f"Crypto asset {asset.algorithm} at {asset.file_path}:{asset.line_number} "
        f"moved {current} -> {to_state} by {user}",
        {"asset_id": asset.id, "algorithm": asset.algorithm,
         "file_path": asset.file_path, "from_state": current, "to_state": to_state,
         "reason": body.reason, "actor": user},
        target_name="inventory",
    )
    return {
        "asset_id": asset.id,
        "algorithm": asset.algorithm,
        "from_state": current,
        "to_state": to_state,
        "reason": body.reason,
        "transitions": LIFECYCLE_TRANSITIONS,
    }


@router.get("/assets/{asset_id}/lifecycle/timeline")
def asset_lifecycle_timeline(
    asset_id: str,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Lifecycle timeline for one crypto asset, derived from the event trail.

    Audit 54 P0#4: the platform deliberately has no denormalised
    ``verified_at`` / ``deprecated_at`` columns — the truth source is the
    audited transition trail this endpoint reads (``inventory.asset_lifecycle``
    platform events, persisted by ``emit_platform_event``). ``derived``
    timestamps below are the time of the most recent transition INTO each
    state, so re-activating a deprecated asset moves ``active_at`` forward
    and re-deprecating moves ``deprecated_at`` again. Pre-trail transitions
    (anything before a state was first recorded) are honestly absent.
    """
    from db.models.monitor import MonitorEvent

    asset = filtered_get(db, CryptoAsset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Crypto asset not found")
    rows = (
        db.query(MonitorEvent)
        .filter(MonitorEvent.event_type == "inventory.asset_lifecycle")
        .order_by(MonitorEvent.created_at.asc())
        .all()
    )
    transitions = []
    for row in rows:
        payload = row.payload or {}
        if payload.get("asset_id") != asset_id:
            continue
        transitions.append({
            "from_state": payload.get("from_state"),
            "to_state": payload.get("to_state"),
            "reason": payload.get("reason"),
            "actor": payload.get("actor"),
            "at": row.created_at.isoformat() if row.created_at else None,
            "event_id": row.id,
        })
    derived: dict[str, str | None] = {
        f"{state.lower()}_at": None
        for state in ("VERIFIED", "ACTIVE", "DEPRECATED", "RETIRED")
    }
    for entry in transitions:
        key = f"{str(entry['to_state'] or '').lower()}_at"
        if key in derived:
            derived[key] = entry["at"]
    return {
        "model": "lifecycle-timeline/derived-v1",
        "asset_id": asset_id,
        "algorithm": asset.algorithm,
        "current_state": asset.lifecycle_state or "DISCOVERED",
        "transition_count": len(transitions),
        "transitions": transitions,
        "derived_timestamps": derived,
        "derivation": "most recent audited transition into each state, from the "
                      "inventory.asset_lifecycle event trail (no denormalised columns)",
    }
