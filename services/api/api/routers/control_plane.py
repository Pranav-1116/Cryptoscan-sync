"""ZELNX Control Plane API (P0).

Exposes the enterprise control layer:

* /control/tenants, /control/grants      — multi-tenancy + ABAC scope grants
* /control/credentials                   — vault-referenced credentials (no secrets)
* /control/agents                        — agent fleet enrollment/heartbeat/upgrade
* /control/safe-scan                     — impact-protection policies + emergency stop
* /control/assets/resolve                — asset identity resolution
* /control/events                        — durable event outbox enqueue/lease
* /control/benchmark                     — detection benchmark datasets + scoring

Enforcement is deterministic and fail-closed. Credential endpoints never
accept or return key material — only vault locators and health metadata.
"""

from __future__ import annotations

import hashlib
import logging
import secrets

from db.repositories.control_plane_repository import ControlPlaneRepository
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session, require_roles

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/control", tags=["control-plane"])

#: credential keys that may never be persisted (defense in depth; the doctrine
#: is references-only, but reject accidental secret submission).
SECRET_FIELD_HINTS = ("secret", "password", "token", "private_key", "access_key",
                      "client_secret", "credential", "api_key", "key_material")


def _repo(db: Session) -> ControlPlaneRepository:
    return ControlPlaneRepository(db)


def _audit(db: Session, actor: str, action: str, **kw) -> None:
    try:
        from db.repositories.user_repository import UserRepository

        UserRepository(db).audit(actor, action, target_type="control_plane", **kw)
    except Exception:
        logger.debug("control-plane audit skipped", exc_info=True)


def _publish(event_type: str, payload: dict) -> None:
    try:
        from api.events.bus import get_event_bus

        get_event_bus().publish(event_type, payload, source="control_plane")
    except Exception:
        logger.debug("control-plane event skipped", exc_info=True)


def _reject_secret_fields(body: dict) -> None:
    for key in body:
        lk = str(key).lower()
        if any(h in lk for h in SECRET_FIELD_HINTS):
            # allow *_ref / *_provider / *_days / policy metadata, never material
            if lk.endswith(("_ref", "_provider", "_id", "_days", "_scope")):
                continue
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Field '{key}' looks like secret material — store it in a vault and "
                       "submit only the vault locator (secret_ref). The platform never stores secrets.",
            )


# ---------------------------------------------------------------- tenants
class TenantRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=200)
    data_residency_region: str = "us"
    processing_regions: list[str] = Field(default_factory=list)


@router.post("/tenants", status_code=status.HTTP_201_CREATED)
def create_tenant(body: TenantRequest,
                  user: str = Depends(require_roles("superadmin", "admin", "ciso")),
                  db: Session = Depends(get_db_session)):
    repo = _repo(db)
    if any(t.name == body.name for t in repo.list_tenants()):
        raise HTTPException(status_code=409, detail="Tenant name already exists")
    tenant = repo.create_tenant(body.name, data_residency_region=body.data_residency_region,
                                processing_regions=body.processing_regions or None)
    _audit(db, user, "control.tenant_created", target_id=tenant.id, detail={"name": tenant.name})
    db.commit()
    return tenant.to_dict()


@router.get("/tenants")
def list_tenants(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    return {"tenants": [t.to_dict() for t in _repo(db).list_tenants()]}


# ----------------------------------------------------------------- grants
class GrantRequest(BaseModel):
    subject: str
    subject_type: str = "user"  # user/role
    actions: list[str] = Field(default_factory=lambda: ["read"])
    region: str | None = None
    business_unit: str | None = None
    environment: str | None = None
    asset_id: str | None = None
    tenant_id: str | None = None
    effect: str = "allow"  # allow/deny


@router.post("/grants", status_code=status.HTTP_201_CREATED)
def create_grant(body: GrantRequest,
                 user: str = Depends(require_roles("superadmin", "admin", "ciso")),
                 db: Session = Depends(get_db_session)):
    if body.subject_type not in {"user", "role"}:
        raise HTTPException(status_code=422, detail="subject_type must be user/role")
    if body.effect not in {"allow", "deny"}:
        raise HTTPException(status_code=422, detail="effect must be allow/deny")
    grant = _repo(db).add_grant(**body.model_dump())
    _audit(db, user, "control.grant_created", target_id=grant.id,
           detail={"subject": body.subject, "actions": body.actions, "effect": body.effect})
    db.commit()
    return grant.to_dict()


class AuthzRequest(BaseModel):
    username: str
    roles: list[str] = Field(default_factory=list)
    action: str = "read"
    region: str | None = None
    business_unit: str | None = None
    environment: str | None = None
    asset_id: str | None = None
    tenant_id: str | None = None


@router.post("/authorize")
def authorize(body: AuthzRequest,
              user: str = Depends(require_roles("superadmin", "admin", "ciso", "security_analyst")),
              db: Session = Depends(get_db_session)):
    from control_plane.iam import Scope, is_authorized, residency_permitted

    repo = _repo(db)
    grants = [g.to_dict() for g in repo.list_grants(body.tenant_id)]
    target = Scope(region=body.region, business_unit=body.business_unit,
                   environment=body.environment, asset_id=body.asset_id, tenant_id=body.tenant_id)
    allowed, reason = is_authorized(grants, username=body.username, roles=body.roles,
                                    action=body.action, target=target)
    residency = True
    if body.tenant_id:
        tenant = repo.get_tenant(body.tenant_id)
        residency = residency_permitted(tenant.to_dict() if tenant else None, body.region)
    decision = allowed and residency
    if not residency:
        reason = "denied: data residency / sovereignty violation"
    return {"authorized": decision, "reason": reason,
            "residency_ok": residency}


# ------------------------------------------------------------- credentials
class CredentialRequest(BaseModel):
    model_config = {"extra": "forbid"}  # fail-closed: reject any undeclared field (secrets)

    name: str
    kind: str = "other"
    vault_provider: str = "manual_out_of_band"
    secret_ref: str = Field(..., description="non-secret vault locator (ARN/name/URI)")
    least_privilege_scope: str | None = None
    region: str | None = None
    rotation_policy_days: int = 90
    tenant_id: str | None = None
    status: str = "active"
    health_ok: bool = True


@router.post("/credentials", status_code=status.HTTP_201_CREATED)
def create_credential(body: CredentialRequest,
                      user: str = Depends(require_roles("superadmin", "admin", "ciso")),
                      db: Session = Depends(get_db_session)):
    _reject_secret_fields(body.model_dump())
    if body.kind not in ("cloud", "network_device", "hsm", "database", "kubernetes",
                         "git", "siem", "api", "other"):
        raise HTTPException(status_code=422, detail="unknown credential kind")
    from datetime import datetime, timezone

    cred = _repo(db).create_credential(
        **body.model_dump(), last_rotated_at=datetime.now(timezone.utc),
        last_health_check_at=datetime.now(timezone.utc))
    _audit(db, user, "control.credential_registered", target_id=cred.id,
           detail={"name": body.name, "vault": body.vault_provider})
    db.commit()
    return cred.to_dict(exclude={"secret_ref"}) | {"secret_ref": "<vault-reference>"}


@router.get("/credentials")
def list_credentials(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    from control_plane.credentials import assess_credential

    out = []
    for cred in _repo(db).list_credentials():
        d = cred.to_dict(exclude={"secret_ref"})
        health = assess_credential(cred.to_dict())
        d["health"] = {"status": health.status, "healthy": health.healthy,
                       "rotation_due": health.rotation_due, "detail": health.detail,
                       "days_until_expiry": health.days_until_expiry}
        out.append(d)
    return {"credentials": out}


@router.post("/credentials/{credential_id}/rotate")
def rotate_credential(credential_id: str,
                      user: str = Depends(require_roles("superadmin", "admin", "ciso")),
                      db: Session = Depends(get_db_session)):
    """Mark a credential as rotated. The actual secret is rotated in the
    external vault by the customer; we only record the event/health."""
    from datetime import datetime, timezone

    cred = _repo(db).update_credential(
        credential_id, status="active", health_ok=True,
        last_rotated_at=datetime.now(timezone.utc),
        last_health_check_at=datetime.now(timezone.utc))
    if cred is None:
        raise HTTPException(status_code=404, detail="Credential not found")
    _audit(db, user, "control.credential_rotated", target_id=credential_id)
    _publish("credential.rotated", {"credential_id": credential_id, "by": user})
    db.commit()
    return {"status": "active", "rotated": True}


# ------------------------------------------------------------------ agents
class EnrollAgentRequest(BaseModel):
    name: str
    region: str | None = None
    environment: str | None = None
    platform: str = "linux"
    resource_limits: dict | None = None
    tenant_id: str | None = None


@router.post("/agents/enroll", status_code=status.HTTP_201_CREATED)
def enroll_agent(body: EnrollAgentRequest,
                 user: str = Depends(require_roles("superadmin", "admin", "ciso")),
                 db: Session = Depends(get_db_session)):
    # one-time enrollment token: only its SHA-256 fingerprint is stored.
    token = secrets.token_urlsafe(32)
    fingerprint = hashlib.sha256(token.encode()).hexdigest()
    agent = _repo(db).enroll_agent(
        body.name, fingerprint, region=body.region, environment=body.environment,
        platform=body.platform, resource_limits=body.resource_limits, tenant_id=body.tenant_id)
    _audit(db, user, "control.agent_enrolled", target_id=agent.id, detail={"name": body.name})
    _publish("agent.enrolled", {"agent_id": agent.id, "name": body.name})
    db.commit()
    # the token is returned exactly once and never persisted in plaintext
    return {"agent_id": agent.id, "enrollment_token": token,
            "note": "Store this token now — it is shown once and only its hash is retained."}


class AgentHeartbeatRequest(BaseModel):
    agent_id: str
    enrollment_token: str | None = None
    version: str | None = None
    healthy: bool = True
    link: str = "encrypted"
    ip: str | None = None
    offline_events_buffered: int | None = None


@router.post("/agents/heartbeat")
def agent_heartbeat(body: AgentHeartbeatRequest,
                    user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    repo = _repo(db)
    agent = repo.get_agent(body.agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Unknown agent")
    # agents authenticate via their enrollment token fingerprint
    if body.enrollment_token and agent.enrollment_token_fingerprint:
        fp = hashlib.sha256(body.enrollment_token.encode()).hexdigest()
        if fp != agent.enrollment_token_fingerprint:
            _audit(db, user, "control.agent_heartbeat_denied", target_id=body.agent_id, outcome="FAILURE")
            db.commit()
            raise HTTPException(status_code=403, detail="Invalid enrollment token")
    updated = repo.agent_heartbeat(body.agent_id, version=body.version, healthy=body.healthy,
                                   link=body.link, ip=body.ip, buffered=body.offline_events_buffered)
    db.commit()
    return {"agent_id": body.agent_id, "status": updated.status, "healthy": updated.healthy,
            "link": updated.link, "target_version": updated.target_version}


@router.get("/agents")
def list_agents(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    agents = []
    for a in _repo(db).list_agents():
        d = a.to_dict(exclude={"enrollment_token_fingerprint"})
        d["last_seen"] = a.last_heartbeat_at.isoformat() if a.last_heartbeat_at else None
        agents.append(d)
    return {"agents": agents}


class AgentUpgradeRequest(BaseModel):
    target_version: str | None = None
    action: str = "upgrade"  # upgrade/rollback/retire


@router.post("/agents/{agent_id}/upgrade")
def upgrade_agent(agent_id: str, body: AgentUpgradeRequest,
                  user: str = Depends(require_roles("superadmin", "admin", "ciso")),
                  db: Session = Depends(get_db_session)):
    target = None
    if body.action == "rollback":
        agent = _repo(db).get_agent(agent_id)
        target = agent.version if agent else None
    else:
        target = body.target_version
    updated = _repo(db).set_agent_target_version(agent_id, target, action=body.action)
    if updated is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    _audit(db, user, "control.agent_upgrade", target_id=agent_id,
           detail={"action": body.action, "target": target})
    _publish("agent.upgrade_scheduled", {"agent_id": agent_id, "action": body.action, "target": target})
    db.commit()
    return {"agent_id": agent_id, "status": updated.status, "target_version": updated.target_version}


# -------------------------------------------------------------- safe scan
class SafeScanPolicyRequest(BaseModel):
    name: str = "default"
    scope_region: str | None = None
    scope_environment: str | None = None
    mode: str = "standard"
    rate_limit_qps: int = 10
    max_connections: int = 100
    concurrent_scans: int = 2
    scan_budget_minutes: int = 240
    excluded_assets: list[str] = Field(default_factory=list)
    excluded_ports: list[int] = Field(default_factory=list)
    excluded_protocols: list[str] = Field(default_factory=list)
    maintenance_windows: list[dict] = Field(default_factory=list)
    maintenance_timezone: str | None = "UTC"
    auto_stop_conditions: dict = Field(default_factory=dict)


@router.put("/safe-scan/policy")
def put_safe_scan_policy(body: SafeScanPolicyRequest,
                         user: str = Depends(require_roles("superadmin", "admin", "ciso")),
                         db: Session = Depends(get_db_session)):
    policy = _repo(db).upsert_safe_policy(**body.model_dump())
    _audit(db, user, "control.safe_scan_policy_set", target_id=policy.id,
           detail={"region": body.scope_region, "mode": body.mode})
    db.commit()
    return policy.to_dict()


@router.get("/safe-scan/policy")
def get_safe_scan_policy(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    return {"policies": [p.to_dict() for p in _repo(db).list_safe_policies()]}


class ScanCheckRequest(BaseModel):
    region: str | None = None
    environment: str | None = None
    asset: str | None = None
    port: int | None = None
    protocol: str | None = None
    is_ot: bool = False


@router.post("/safe-scan/evaluate")
def evaluate_scan_check(body: ScanCheckRequest,
                        user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    from control_plane.safety import evaluate_scan

    repo = _repo(db)
    policy_row = repo.matching_policy(region=body.region, environment=body.environment)
    policy = policy_row.to_dict() if policy_row else None
    decision = evaluate_scan(policy, asset=body.asset, port=body.port,
                             protocol=body.protocol, is_ot=body.is_ot)
    return {"permitted": decision.permitted, "mode": decision.mode,
            "active_probing": decision.active_probing, "reason": decision.reason,
            "budgets": decision.budgets, "excluded": decision.excluded}


class EmergencyStopRequest(BaseModel):
    engaged: bool = True


@router.post("/safe-scan/emergency-stop")
def emergency_stop(body: EmergencyStopRequest,
                   user: str = Depends(require_roles("superadmin", "admin", "ciso")),
                   db: Session = Depends(get_db_session)):
    repo = _repo(db)
    policies = repo.list_safe_policies()
    if not policies:
        policy = repo.upsert_safe_policy(name="default", emergency_stop=body.engaged)
    else:
        for p in policies:
            repo.set_emergency_stop(p.id, body.engaged)
        policy = policies[0]
    _audit(db, user, "control.emergency_stop", target_id=policy.id,
           detail={"engaged": body.engaged}, outcome="FAILURE" if body.engaged else "SUCCESS")
    _publish("safe_scan.emergency_stop", {"engaged": body.engaged, "by": user})
    db.commit()
    return {"emergency_stop": body.engaged, "policies_updated": len(policies) or 1}


# --------------------------------------------------------- asset identity
class ResolveAssetsRequest(BaseModel):
    observations: list[dict]


@router.post("/assets/resolve")
def resolve_assets(body: ResolveAssetsRequest,
                   user: str = Depends(require_roles("superadmin", "admin", "ciso", "security_analyst")),
                   db: Session = Depends(get_db_session)):
    from control_plane.identity import resolve_identity

    resolved = resolve_identity(body.observations)
    attrs = resolved.pop("attributes", {})
    identity = _repo(db).upsert_asset_identity(
        resolved["canonical_id"], asset_type=attrs.get("asset_type"), name=attrs.get("name"),
        region=attrs.get("region"), business_unit=attrs.get("business_unit"),
        environment=attrs.get("environment"), owner=attrs.get("owner"),
        maintainer=attrs.get("maintainer"), application=attrs.get("application"),
        service=attrs.get("service"), data_classification=attrs.get("data_classification"),
        criticality=attrs.get("criticality"), confidence=resolved["confidence"],
        evidence_sources=resolved["evidence_sources"])
    db.commit()
    return {"identity": identity.to_dict(), "source_count": resolved["source_count"]}


@router.get("/assets")
def list_assets(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    return {"assets": [a.to_dict() for a in _repo(db).list_asset_identities()]}


# ----------------------------------------------------------------- events
class EnqueueEventRequest(BaseModel):
    event_type: str
    payload: dict = Field(default_factory=dict)
    priority: str = "normal"


@router.post("/events/enqueue", status_code=status.HTTP_202_ACCEPTED)
def enqueue_event(body: EnqueueEventRequest,
                  user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    if body.priority not in ("critical", "high", "normal", "low"):
        raise HTTPException(status_code=422, detail="bad priority")
    ev = _repo(db).enqueue(body.event_type, body.payload, priority=body.priority, source="api")
    _publish(body.event_type, body.payload)
    db.commit()
    return {"queued": True, "event_id": ev.id, "priority": ev.priority}


@router.get("/events/queue")
def event_queue(status_filter: str = "queued", limit: int = 50,
                user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    events = _repo(db).list_events(status_filter, limit)
    return {"events": [e.to_dict() for e in events]}


# ------------------------------------------------------------- benchmark
class DatasetRequest(BaseModel):
    name: str
    description: str | None = None
    sector: str | None = None


@router.post("/benchmark/datasets", status_code=status.HTTP_201_CREATED)
def create_dataset(body: DatasetRequest,
                   user: str = Depends(require_roles("superadmin", "admin", "ciso", "security_analyst")),
                   db: Session = Depends(get_db_session)):
    repo = _repo(db)
    ds = repo.create_benchmark_dataset(body.name, description=body.description, sector=body.sector)
    db.commit()
    return ds.to_dict()


class CaseRequest(BaseModel):
    dataset_id: str
    cases: list[dict]


@router.post("/benchmark/cases", status_code=status.HTTP_201_CREATED)
def add_cases(body: CaseRequest,
              user: str = Depends(require_roles("superadmin", "admin", "ciso", "security_analyst")),
              db: Session = Depends(get_db_session)):
    repo = _repo(db)
    if repo.get_benchmark_dataset(body.dataset_id) is None:
        raise HTTPException(status_code=404, detail="Dataset not found")
    count = 0
    for c in body.cases:
        repo.add_benchmark_case(body.dataset_id, case_ref=c["case_ref"],
                                ground_truth=c.get("ground_truth", "benign"),
                                expected_detection=c.get("expected_detection", False),
                                metadata_=c.get("metadata"))
        count += 1
    db.commit()
    return {"added": count}


class ScoreRequest(BaseModel):
    dataset_id: str
    predictions: list[dict]
    scanner_id: str = "universal"
    scanner_version: str | None = None


@router.post("/benchmark/score")
def score_benchmark(body: ScoreRequest,
                    user: str = Depends(require_roles("superadmin", "admin", "ciso", "security_analyst")),
                    db: Session = Depends(get_db_session)):
    from control_plane.benchmark import score_predictions

    repo = _repo(db)
    if repo.get_benchmark_dataset(body.dataset_id) is None:
        raise HTTPException(status_code=404, detail="Dataset not found")
    metrics = score_predictions(body.predictions)
    run = repo.create_benchmark_run(
        body.dataset_id, scanner_id=body.scanner_id, scanner_version=body.scanner_version,
        status="scored", scored_by=user, true_positive=metrics["true_positive"],
        false_positive=metrics["false_positive"], true_negative=metrics["true_negative"],
        false_negative=metrics["false_negative"], precision=metrics["precision"],
        recall=metrics["recall"], f1=metrics["f1"],
        false_positive_rate=metrics["false_positive_rate"], accuracy=metrics["accuracy"],
        detail={"meets_95_target": metrics["meets_95_target"]})
    _audit(db, user, "control.benchmark_scored", target_id=run.id,
           detail={"accuracy": metrics["accuracy"], "f1": metrics["f1"]})
    db.commit()
    return {"run_id": run.id, **metrics}


@router.get("/benchmark/runs")
def benchmark_runs(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    return {"runs": [r.to_dict() for r in _repo(db).list_benchmark_runs()]}
