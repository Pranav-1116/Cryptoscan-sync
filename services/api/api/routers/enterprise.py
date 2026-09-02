"""P1 enterprise API — policy-as-code, compliance, ITSM, CMDB/SIEM integrations,
multi-region/DR, crypto knowledge base, and air-gapped signed transfer.

Deterministic and fail-closed; integrates with the P0 control plane
(tenants, safe-scan, queue events for SIEM).
"""

from __future__ import annotations

import logging

from db.repositories.enterprise_repository import EnterpriseRepository
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session, require_roles

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/enterprise", tags=["enterprise"])


def _repo(db: Session) -> EnterpriseRepository:
    return EnterpriseRepository(db)


def _audit(db: Session, actor: str, action: str, **kw) -> None:
    try:
        from db.repositories.user_repository import UserRepository

        UserRepository(db).audit(actor, action, target_type="enterprise", **kw)
    except Exception:
        logger.debug("enterprise audit skipped", exc_info=True)


def _publish(event_type: str, payload: dict) -> None:
    try:
        from api.events.bus import get_event_bus

        get_event_bus().publish(event_type, payload, source="enterprise")
    except Exception:
        logger.debug("enterprise event skipped", exc_info=True)


# ------------------------------------------------------------------ policy
class PolicyRequest(BaseModel):
    model_config = {"extra": "forbid"}
    name: str
    layer: str = "organization"
    sector: str | None = None
    region: str | None = None
    tenant_id: str | None = None
    rules: list[dict] = Field(default_factory=list)
    is_active: bool = True


@router.put("/policies", status_code=status.HTTP_201_CREATED)
def put_policy(body: PolicyRequest,
               user: str = Depends(require_roles("superadmin", "admin", "ciso")),
               db: Session = Depends(get_db_session)):
    from control_plane.policy_as_code import policy_version

    if body.layer not in ("sector", "region", "organization", "control", "risk"):
        raise HTTPException(status_code=422, detail="bad layer")
    version = policy_version({"rules": body.rules})
    doc = _repo(db).upsert_policy(name=body.name, layer=body.layer, sector=body.sector,
                                  region=body.region, tenant_id=body.tenant_id,
                                  version=version, rules=body.rules, is_active=body.is_active,
                                  created_by=user)
    _audit(db, user, "enterprise.policy_set", target_id=doc.id,
           detail={"name": body.name, "version": version, "rules": len(body.rules)})
    db.commit()
    return {"policy_id": doc.id, "name": doc.name, "version": doc.version}


@router.get("/policies")
def list_policies(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    return {"policies": [p.to_dict() for p in _repo(db).list_policies()]}


class PolicyEvalRequest(BaseModel):
    target: dict
    sector: str | None = None
    region: str | None = None
    layers: list[str] | None = None  # optional explicit layer filter


@router.post("/policies/evaluate")
def evaluate(body: PolicyEvalRequest,
             user: str = Depends(require_roles("superadmin", "admin", "ciso", "security_analyst")),
             db: Session = Depends(get_db_session)):
    from control_plane.policy_as_code import evaluate_policy, merge_policy_layers

    repo = _repo(db)
    docs = repo.list_policies()
    selected = [d for d in docs
                if (body.layers is None or d.layer in body.layers)
                and (d.sector is None or body.sector is None or d.sector == body.sector)
                and (d.region is None or body.region is None or d.region == body.region)]
    layers = [{"id": d.name, "rules": d.rules} for d in selected]
    merged = merge_policy_layers(*layers)
    result = evaluate_policy(merged, body.target)
    repo.record_evaluation(policy_version=merged["version"], target_type="target",
                           verdict=result.verdict, results=result.to_dict())
    db.commit()
    return result.to_dict()


# --------------------------------------------------------------- compliance
class ControlRequest(BaseModel):
    framework: str
    control_id: str
    title: str | None = None
    sector: str | None = None
    assets: list[str] = Field(default_factory=list)


@router.post("/compliance/controls", status_code=status.HTTP_201_CREATED)
def add_control(body: ControlRequest,
                user: str = Depends(require_roles("superadmin", "admin", "ciso", "security_analyst")),
                db: Session = Depends(get_db_session)):
    c = _repo(db).upsert_control(framework=body.framework, control_id=body.control_id,
                                 title=body.title, sector=body.sector, assets=body.assets)
    db.commit()
    return {"control_id": c.id, "framework": c.framework, "control": c.control_id}


class ComplianceEvalRequest(BaseModel):
    findings: list[dict] = Field(default_factory=list)
    evidence: list[dict] = Field(default_factory=list)
    framework: str | None = None


@router.post("/compliance/evaluate")
def compliance_evaluate(body: ComplianceEvalRequest,
                        user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    from control_plane.compliance import framework_posture

    repo = _repo(db)
    controls = repo.list_controls(body.framework)
    control_dicts = [{"id": c.control_id, "framework": c.framework, "assets": c.assets}
                     for c in controls]
    posture = framework_posture(control_dicts, body.findings, body.evidence)
    # snapshot for history
    for r in posture["controls"]:
        repo.record_compliance_status(framework=r["framework"], control_id=r["control_id"],
                                      status=r["status"], open_findings=r["open_findings"],
                                      evidence_count=r["evidence"],
                                      compliance_pct=posture["compliance_pct"],
                                      coverage_pct=posture["coverage_pct"])
    db.commit()
    return posture


# --------------------------------------------------------------------- ITSM
class TicketRequest(BaseModel):
    model_config = {"extra": "forbid"}
    title: str
    finding_id: str | None = None
    asset_id: str | None = None
    severity: str = "medium"
    provider: str = "manual"
    assignee: str | None = None


@router.post("/itsm/tickets", status_code=status.HTTP_201_CREATED)
def create_ticket(body: TicketRequest,
                  user: str = Depends(require_roles("superadmin", "admin", "ciso", "security_analyst")),
                  db: Session = Depends(get_db_session)):
    t = _repo(db).create_ticket(provider=body.provider, title=body.title,
                                finding_id=body.finding_id, asset_id=body.asset_id,
                                severity=body.severity, assignee=body.assignee,
                                created_by=user)
    _audit(db, user, "enterprise.ticket_created", target_id=t.id,
           detail={"finding_id": body.finding_id, "state": t.state})
    _publish("itsm.ticket_created", {"ticket_id": t.id, "finding_id": body.finding_id})
    db.commit()
    return {"ticket_id": t.id, "state": t.state, "external_ref": t.external_ref}


class TicketTransition(BaseModel):
    action: str  # triage/assign/start/migrate/validate/pass/fail/close/reopen


@router.post("/itsm/tickets/{ticket_id}/transition")
def transition_ticket(ticket_id: str, body: TicketTransition,
                      user: str = Depends(require_roles("superadmin", "admin", "ciso", "security_analyst")),
                      db: Session = Depends(get_db_session)):
    from control_plane.integrations import ticket_state_machine

    repo = _repo(db)
    ticket = repo.get_ticket(ticket_id)
    if ticket is None:
        raise HTTPException(status_code=404, detail="Ticket not found")
    new_state = ticket_state_machine(ticket.state, body.action)
    if new_state == ticket.state:
        raise HTTPException(status_code=409, detail=f"invalid transition '{body.action}' from {ticket.state}")
    repo.transition_ticket(ticket_id, new_state, actor=user)
    _audit(db, user, "enterprise.ticket_transition", target_id=ticket_id,
           detail={"action": body.action, "state": new_state})
    _publish("itsm.ticket_transition", {"ticket_id": ticket_id, "state": new_state})
    db.commit()
    return {"ticket_id": ticket_id, "state": new_state}


@router.get("/itsm/tickets")
def list_tickets(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    return {"tickets": [t.to_dict() for t in _repo(db).list_tickets()]}


# ----------------------------------------------------------------- CMDB/SIEM
class IntegrationRequest(BaseModel):
    model_config = {"extra": "forbid"}
    kind: str  # cmdb/itsm/siem/soar
    provider: str
    name: str
    endpoint: str | None = None
    config: dict = Field(default_factory=dict)
    credential_id: str | None = None


@router.post("/integrations", status_code=status.HTTP_201_CREATED)
def register_integration(body: IntegrationRequest,
                         user: str = Depends(require_roles("superadmin", "admin", "ciso")),
                         db: Session = Depends(get_db_session)):
    if body.kind not in ("cmdb", "itsm", "siem", "soar"):
        raise HTTPException(status_code=422, detail="kind must be cmdb/itsm/siem/soar")
    i = _repo(db).upsert_integration(kind=body.kind, provider=body.provider, name=body.name,
                                     endpoint=body.endpoint, config=body.config,
                                     credential_id=body.credential_id)
    _audit(db, user, "enterprise.integration_registered", target_id=i.id,
           detail={"kind": body.kind, "provider": body.provider})
    db.commit()
    return {"integration_id": i.id, "kind": i.kind, "provider": i.provider}


@router.get("/integrations")
def list_integrations(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    return {"integrations": [i.to_dict(exclude={"config"}) for i in _repo(db).list_integrations()]}


class CmdbImport(BaseModel):
    records: list[dict]
    discovered: list[dict]


@router.post("/integrations/cmdb/resolve")
def cmdb_resolve(body: CmdbImport,
                 user: str = Depends(require_roles("superadmin", "admin", "ciso", "security_analyst")),
                 db: Session = Depends(get_db_session)):
    from control_plane.integrations import resolve_cmdb_assets

    result = resolve_cmdb_assets(body.records, body.discovered)
    repo = _repo(db)
    integ = repo.list_integrations()
    for i in integ:
        if i.kind == "cmdb":
            repo.mark_integration_synced(i.id, "resolved")
    db.commit()
    return {"matched": result["matched"], "new_unmatched": result["new_unmatched"],
            "cmdb_stale": result["cmdb_stale"], "enriched": result["enriched"]}


class SiemExport(BaseModel):
    events: list[dict]
    provider: str = "splunk"


@router.post("/integrations/siem/export")
def siem_export(body: SiemExport,
                user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    from control_plane.integrations import normalize_siem_events

    normalized = normalize_siem_events(body.events, body.provider)
    # publish each onto the durable queue/outbox for downstream SOC processing
    repo = _repo(db)
    for n in normalized:
        repo.enqueue_siem_event(n)
    _publish("siem.export", {"provider": body.provider, "count": len(normalized)})
    db.commit()
    return {"exported": len(normalized), "provider": body.provider,
            "cef": [n["cef"] for n in normalized]}


# --------------------------------------------------------------- regions/DR
class RegionRequest(BaseModel):
    code: str
    name: str
    is_primary: bool = False
    healthy: bool = True
    rpo_minutes: int = 60
    rto_minutes: int = 60
    last_backup_at: str | None = None


@router.put("/regions", status_code=status.HTTP_201_CREATED)
def put_region(body: RegionRequest,
               user: str = Depends(require_roles("superadmin", "admin", "ciso")),
               db: Session = Depends(get_db_session)):
    r = _repo(db).upsert_region(**body.model_dump())
    db.commit()
    return {"code": r.code, "is_primary": r.is_primary}


@router.get("/regions/health")
def regions_health(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    from control_plane.regions import assess_dr

    repo = _repo(db)
    regions = repo.list_regions()
    reports = []
    for r in regions:
        rep = assess_dr({"rpo_minutes": r.rpo_minutes, "rto_minutes": r.rto_minutes},
                        last_backup_at=r.last_backup_at,
                        primary_healthy=r.healthy if r.is_primary else True,
                        secondary_healthy=any(x.healthy for x in regions if not x.is_primary))
        reports.append({"code": r.code, "is_primary": r.is_primary, "healthy": r.healthy, **rep})
    return {"regions": reports}


# ------------------------------------------------------------- crypto KB
class KbEntry(BaseModel):
    algorithm: str
    status: str
    category: str | None = None
    pqc: bool = False
    migration_candidate: str | None = None
    notes: str | None = None


@router.put("/crypto-kb", status_code=status.HTTP_201_CREATED)
def put_kb_entry(body: KbEntry,
                 user: str = Depends(require_roles("superadmin", "admin", "ciso")),
                 db: Session = Depends(get_db_session)):
    e = _repo(db).upsert_kb_entry(**body.model_dump())
    db.commit()
    return {"algorithm": e.algorithm, "status": e.status}


@router.get("/crypto-kb")
def crypto_kb(algorithm: str | None = None, user: str = Depends(get_current_user),
              db: Session = Depends(get_db_session)):
    from control_plane.knowledge import lookup

    if algorithm:
        builtin = lookup(algorithm)
        override = _repo(db).get_kb_entry(algorithm)
        return {"algorithm": algorithm, "builtin": builtin,
                "override": override.to_dict() if override else None}
    return {"entries": [e.to_dict() for e in _repo(db).list_kb_entries()]}


# --------------------------------------------------- air-gapped signed transfer
class SignedExportRequest(BaseModel):
    document: dict
    secret: str = Field(..., min_length=8)


@router.post("/airgap/export")
def airgap_export(body: SignedExportRequest,
                  user: str = Depends(require_roles("superadmin", "admin", "ciso", "auditor")),
                  db: Session = Depends(get_db_session)):
    from control_plane.integrations import build_signed_export

    pkg = build_signed_export(body.document, body.secret)
    _audit(db, user, "enterprise.airgap_exported",
           detail={"content_hash": pkg["content_hash"]})
    db.commit()
    return {"package": {k: v for k, v in pkg.items() if k != "signature"} |
            {"signature": pkg["signature"]}}


class SignedImport(BaseModel):
    package: dict
    secret: str = Field(..., min_length=8)


@router.post("/airgap/import")
def airgap_import(body: SignedImport,
                  user: str = Depends(require_roles("superadmin", "admin", "ciso")),
                  db: Session = Depends(get_db_session)):
    from control_plane.integrations import load_signed_export

    try:
        doc = load_signed_export(body.package, body.secret)
    except ValueError as exc:
        _audit(db, user, "enterprise.airgap_import_rejected", detail={"reason": str(exc)}, outcome="FAILURE")
        db.commit()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    _audit(db, user, "enterprise.airgap_imported",
           detail={"keys": list(doc.keys()) if isinstance(doc, dict) else "n/a"})
    db.commit()
    return {"accepted": True, "document_keys": list(doc.keys()) if isinstance(doc, dict) else []}
