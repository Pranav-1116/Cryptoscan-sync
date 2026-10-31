"""P1 enterprise API — policy-as-code, compliance, ITSM, CMDB/SIEM integrations,
multi-region/DR, crypto knowledge base, and air-gapped signed transfer.

Deterministic and fail-closed; integrates with the P0 control plane
(tenants, safe-scan, queue events for SIEM).
"""

from __future__ import annotations

import logging

from db.repositories.enterprise_repository import EnterpriseRepository
from fastapi import APIRouter, Body, Depends, HTTPException, status
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


def _fan_out(db: Session, event_type: str, payload: dict) -> list[dict]:
    """Best-effort real signed HTTP delivery to registered integrations.

    Never raises: network failure leaves the durable queue/outbox as the
    record of record (and /control/deliveries/flush retries). Returns the
    per-integration delivery result dicts.
    """
    try:
        from control_plane.delivery import deliver_event_for_repo

        results = deliver_event_for_repo(db, {"event_type": event_type, "payload": payload},
                                         sleep=lambda _s: None)
        for r in results:
            _publish("siem.delivered" if r.get("kind") == "siem" else "itsm.delivered",
                     {"integration": r.get("integration_id"), "status": r.get("status"),
                      "http_status": r.get("http_status"), "event": event_type})
        return results
    except Exception:
        logger.warning("enterprise fan-out failed for %s", event_type, exc_info=True)
        return []


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


class PipelineRequest(BaseModel):
    findings: list[dict] | None = Field(default=None, max_length=10000)  # supplied batch; else live DB
    sector: str | None = None
    region: str | None = None
    limit: int = Field(default=500, le=10000)


@router.post("/pipeline/evaluate")
def run_findings_pipeline(body: PipelineRequest,
                          user: str = Depends(require_roles("superadmin", "admin", "ciso", "security_analyst")),
                          db: Session = Depends(get_db_session)):
    """Run the real data flow: (live) findings -> merged policy-as-code
    evaluation -> crypto-KB classification -> compliance control mapping.
    Persists compliance status snapshots and returns per-finding verdicts."""
    from control_plane.pipeline import run_pipeline

    repo = _repo(db)
    findings = body.findings if body.findings is not None else repo.live_findings(body.limit)
    policy_docs = [d for d in repo.list_policies()
                   if (body.sector is None or d.sector is None or d.sector == body.sector)]
    layers = [{"id": d.name, "rules": d.rules} for d in policy_docs]
    controls = repo.list_controls()
    result = run_pipeline(findings, layers, controls=controls)
    posture = result.get("posture")
    if posture:
        for r in posture["controls"]:
            repo.record_compliance_status(framework=r["framework"], control_id=r["control_id"],
                                          status=r["status"], open_findings=r["open_findings"],
                                          evidence_count=r["evidence"],
                                          compliance_pct=posture["compliance_pct"],
                                          coverage_pct=posture["coverage_pct"])
    _audit(db, user, "enterprise.pipeline_evaluated",
           detail={"findings": result["total_findings"], "risks": result["risks"]})
    db.commit()
    return result


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
    # Real outbound fan-out to registered ITSM integrations (signed HTTP POST),
    # each attempt audited; failures never block ticket creation (outbox retains).
    deliveries = _fan_out(db, "itsm.ticket_created",
                          {"ticket": t.to_dict(), "finding_id": body.finding_id,
                           "asset_id": body.asset_id, "severity": t.severity,
                           "detail": t.title})
    db.commit()
    return {"ticket_id": t.id, "state": t.state, "external_ref": t.external_ref,
            "deliveries": [d.get("status") for d in deliveries]}


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
    if body.endpoint:
        from control_plane.delivery import WebhookUrlError, validate_webhook_url

        try:
            validate_webhook_url(body.endpoint)
        except WebhookUrlError as exc:
            raise HTTPException(status_code=422, detail=f"unsafe integration endpoint: {exc}") from exc
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


@router.post("/integrations/{integration_id}/test")
def test_integration(integration_id: str,
                     user: str = Depends(require_roles("superadmin", "admin", "ciso")),
                     db: Session = Depends(get_db_session)):
    """Send a signed ZELNX connectivity-test event to one integration over real
    HTTP and report the deterministic result (used by the Integrations console
    'Test connection' button). Records a cp_delivery_logs audit row."""
    from control_plane.delivery import deliver

    repo = _repo(db)
    integ = next((i for i in repo.list_integrations() if i.id == integration_id), None)
    if integ is None:
        raise HTTPException(status_code=404, detail="Integration not found")
    event = {"event_type": "siem.connectivity_test" if integ.kind in ("siem", "soar")
             else "itsm.connectivity_test",
             "payload": {"severity": "info", "detail": "ZELNX connectivity test",
                         "asset": "zelnx-console", "category": "alert"}}
    result = deliver(integ.to_dict(), event, sleep=lambda _s: None, max_attempts=2)
    from db.repositories.control_plane_repository import ControlPlaneRepository

    ControlPlaneRepository(db).record_delivery(result=result.to_dict(),
                                               event_type=event["event_type"])
    repo.mark_integration_synced(integ.id, result.status)
    _audit(db, user, "enterprise.integration_tested", target_id=integ.id,
           detail={"status": result.status, "http_status": result.http_status})
    _publish("integrations.tested", {"integration_id": integ.id, "status": result.status})
    db.commit()
    return {"integration_id": integ.id, "status": result.status,
            "http_status": result.http_status, "attempts": result.attempts,
            "error": result.error, "signed": result.signature is not None,
            "duration_ms": result.duration_ms}


@router.get("/integrations/deliveries")
def integration_deliveries(user: str = Depends(get_current_user),
                           db: Session = Depends(get_db_session)):
    """Recent outbound delivery results for the Integrations console."""
    from db.repositories.control_plane_repository import ControlPlaneRepository

    cp = ControlPlaneRepository(db)
    return {"deliveries": [l.to_dict() for l in cp.list_delivery_logs(limit=50)],
            "stats": cp.delivery_stats()}


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
    # persist enriched matches into the canonical asset-identity table so the
    # business context (owner/BU/criticality/classification) is retained.
    from control_plane.identity import resolve_identity
    from db.repositories.control_plane_repository import ControlPlaneRepository

    cp = ControlPlaneRepository(db)
    enriched_records = []
    for item in result["enriched"]:
        d = item["discovered"]
        observations = [
            {"source": "discovery", "asset_type": d.get("asset_type"),
             "identifiers": {k: d[k] for k in ("serial", "fqdn", "instance_id", "hardware_uuid") if d.get(k)}},
            {"source": "cmdb", "asset_type": d.get("asset_type"),
             "owner": item.get("owner"), "business_unit": item.get("business_unit"),
             "criticality": item.get("criticality"), "application": item.get("application"),
             "data_classification": item.get("data_classification"),
             "identifiers": {k: d[k] for k in ("serial", "fqdn", "instance_id", "hardware_uuid") if d.get(k)}},
        ]
        fused = resolve_identity(observations)
        attrs = fused.pop("attributes", {})
        identity = cp.upsert_asset_identity(
            fused["canonical_id"], asset_type=attrs.get("asset_type") or d.get("asset_type"),
            name=d.get("fqdn") or d.get("hostname"), owner=item.get("owner"),
            business_unit=item.get("business_unit"), criticality=item.get("criticality"),
            application=item.get("application"),
            data_classification=item.get("data_classification"),
            confidence=fused["confidence"], evidence_sources=fused["evidence_sources"],
            source_refs={"cmdb_ci": item.get("cmdb_ci")})
        enriched_records.append(identity.canonical_id)
    integ = repo.list_integrations()
    for i in integ:
        if i.kind == "cmdb":
            repo.mark_integration_synced(i.id, "resolved")
    _audit(db, user, "enterprise.cmdb_resolved",
           detail={"matched": result["matched"], "persisted": len(enriched_records)})
    db.commit()
    return {"matched": result["matched"], "new_unmatched": result["new_unmatched"],
            "cmdb_stale": result["cmdb_stale"], "enriched": result["enriched"],
            "identities_persisted": len(enriched_records)}


class SiemExport(BaseModel):
    events: list[dict] = Field(max_length=10000)  # bound the export batch (OWASP A04 DoS)
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
    # Immediate best-effort real delivery to enabled SIEM/SOAR webhooks; the
    # queue row remains the durable record for anything not accepted now.
    deliveries = []
    for n in normalized[:10]:  # bound synchronous fan-out; flush handles the rest
        deliveries.extend(_fan_out(db, "siem.finding", n.get("payload", n)))
    db.commit()
    return {"exported": len(normalized), "provider": body.provider,
            "cef": [n["cef"] for n in normalized],
            "deliveries": [{"status": d.get("status"), "http_status": d.get("http_status"),
                            "integration_id": d.get("integration_id"),
                            "attempts": d.get("attempts"), "error": d.get("error")}
                           for d in deliveries]}


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


# ------------------------------------------- withdrawn: live air-gap transfer
#
# This used to be a live transfer path: ``/airgap/bundle`` read findings out of
# the running control plane, ``/airgap/export`` signed a document with a secret
# the *caller* supplied, and ``/airgap/import`` verified a signature and then
# answered ``accepted: true`` without writing anything.
#
# Three things were wrong with it, and only the last one was visible in a test:
#
#   * the signing key crossed the API boundary in the request body, so the server
#     never held a key it could trust and "signed" meant "signed by whoever
#     called";
#   * "import" was a no-op that reported success. An operator cannot tell that
#     from a working ingestion, which is worse than an error;
#   * it carried no evidence, so it could not be the air-gap evidence path no
#     matter how the signature was handled.
#
# The path is withdrawn rather than deleted: a caller that still uses it gets a
# 410 naming what to use instead, not a 404 that reads like a typo in a URL.
WITHDRAWN_TRANSFER = {
    "withdrawn": "the live air-gap transfer path /api/v1/enterprise/airgap/{bundle,export,import}",
    "reason": (
        "it moved live platform documents signed with a caller-supplied secret into an "
        "installation, and its import reported success without storing anything. Neither is "
        "an evidence path: what it transferred could not be audited back to a collector"
    ),
    "evidence_export": (
        "cryptoscan bundle export --out DIR [--sign-key key.pem] — stored evidence, the twin "
        "snapshot and the BOM projections, each with the endpoint that answered it, and a "
        "manifest whose `limits` state what the bundle does not carry"
    ),
    "evidence_verify": "cryptoscan bundle verify DIR [--public-key trusted.pem]",
    "feed_updates": (
        "POST /api/v1/resilience/airgap/build-bundle on a connected host, then "
        "POST /api/v1/resilience/airgap/import-feed inside the gapped site — signed advisory "
        "feeds ingested into the live vulnerability store, server-held signing key"
    ),
    "docs": "docs/airgap-deployment.md",
}


#: The three routes that answer 410. Kept as data so the generated API reference
#: and the build-status audit can mark them withdrawn instead of listing them as
#: ordinary endpoints (docs/api-reference/rest-api.md used to read as if they worked).
WITHDRAWN_ROUTES: tuple[str, ...] = (
    "/api/v1/enterprise/airgap/bundle",
    "/api/v1/enterprise/airgap/export",
    "/api/v1/enterprise/airgap/import",
)


def withdrawn_routes() -> tuple[str, ...]:
    """The withdrawn paths, for generators that render the route surface."""
    return WITHDRAWN_ROUTES


def _withdrawn(endpoint: str) -> None:
    raise HTTPException(status_code=410, detail={**WITHDRAWN_TRANSFER, "endpoint": endpoint})


@router.post("/airgap/bundle", deprecated=True)
def airgap_bundle(_: dict | None = Body(default=None, description="ignored: the endpoint is withdrawn"),
                  user: str = Depends(require_roles("superadmin", "admin", "ciso", "auditor"))):
    """Withdrawn (410). Use `cryptoscan bundle export`; see docs/airgap-deployment.md."""
    _withdrawn(WITHDRAWN_ROUTES[0])


@router.post("/airgap/export", deprecated=True)
def airgap_export(_: dict | None = Body(default=None, description="ignored: the endpoint is withdrawn"),
                  user: str = Depends(require_roles("superadmin", "admin", "ciso", "auditor"))):
    """Withdrawn (410). A document signed with a caller-supplied secret is not an export."""
    _withdrawn(WITHDRAWN_ROUTES[1])


@router.post("/airgap/import", deprecated=True)
def airgap_import(_: dict | None = Body(default=None, description="ignored: the endpoint is withdrawn"),
                  user: str = Depends(require_roles("superadmin", "admin", "ciso"))):
    """Withdrawn (410). The old handler answered `accepted` and stored nothing."""
    _withdrawn(WITHDRAWN_ROUTES[2])
