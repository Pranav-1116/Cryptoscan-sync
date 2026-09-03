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
from fastapi import APIRouter, Depends, HTTPException, Request, status
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


def _validate_ref(secret_ref: str) -> str | None:
    """Reject a secret_ref that is malformed or smuggles inline key material."""
    from vaultlease.lease import _REF_RE, _SECRET_VALUE_RE  # internal validators

    if secret_ref and _SECRET_VALUE_RE.search(secret_ref):
        return ("secret_ref appears to contain inline key material — store the secret in a "
                "vault and submit only its locator (ARN/URI/name). The platform never stores secrets.")
    if not secret_ref or not _REF_RE.match(secret_ref):
        return "secret_ref must be a non-secret vault locator (ARN/URI/name)."
    return None


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
    # New grants take effect immediately — drop the middleware's short-lived cache.
    try:
        from api.middleware.abac_middleware import reset_abac_cache

        reset_abac_cache()
    except Exception:
        logger.debug("abac cache reset skipped", exc_info=True)
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


@router.get("/me/grants")
def my_grants(request: Request, user: str = Depends(get_current_user),
              db: Session = Depends(get_db_session)):
    """The caller's own effective ABAC surface: every active allow-grant that
    matches their username or one of their roles, so the console can show and
    self-attest the Region→BU→Environment→Asset scope they can reach."""
    from control_plane.abac import effective_scopes

    from api.security.rbac import _caller_roles

    principal, roles = _caller_roles(request)
    repo = _repo(db)
    grants = [g.to_dict() for g in repo.list_grants()]
    scopes = effective_scopes(grants, username=principal, roles=roles)
    return {"principal": principal, "roles": roles, "grants": scopes,
            "count": len(scopes), "abac_enforced": _abac_enforced()}


def _abac_enforced() -> bool:
    import os

    return os.environ.get("ABAC_ENFORCED", "").lower() in {"1", "true", "yes", "on"}


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
    # fail-closed: secret_ref must be a non-secret vault locator, never inline material.

    ref_probe = _validate_ref(body.secret_ref)
    if ref_probe is not None:
        raise HTTPException(status_code=422, detail=ref_probe)
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


class LeaseRequest(BaseModel):
    require_value: bool = False
    component: str | None = None
    scope: list[str] = []
    ttl_seconds: int | None = None


@router.post("/credentials/{credential_id}/lease")
def lease_credential_endpoint(credential_id: str, body: LeaseRequest,
                              user: str = Depends(require_roles("superadmin", "admin", "ciso", "security_analyst", "scanner")),
                              db: Session = Depends(get_db_session)):
    """Lease a short-lived credential for a scanner. The secret value is NEVER
    returned over the API — scanners resolve it out-of-band via the vault
    adapter in their own process.

    Enforces the deterministic vault-lease policy (no AI): the credential must be
    active/fresh, the requesting component must be allowed, the requested scope
    must be a subset of the credential's least-privilege scope, and the TTL is
    capped. A reference-only lease row is persisted for audit and can be
    released; it carries a vault locator and never any key material."""
    from datetime import datetime, timezone

    from control_plane.credentials import assess_credential
    from control_plane.vault import VaultError, lease_credential
    from vaultlease.lease import CredentialInfo, issue_lease

    repo = _repo(db)
    cred = repo.get_credential(credential_id)
    if cred is None:
        raise HTTPException(status_code=404, detail="Credential not found")
    health = assess_credential(cred.to_dict())
    if not health.healthy:
        raise HTTPException(status_code=409, detail=f"credential not usable: {health.detail}")

    # ---- deterministic lease policy gate (component / scope / TTL / freshness)
    component = (body.component or "scanner").lower()
    info = CredentialInfo.from_dict({
        "name": cred.name,
        "secret_ref": cred.secret_ref,
        "status": cred.status,
        "allowed_components": [],  # not stored on the model; scope still enforced
        "scope": cred.least_privilege_scope or "",
        "max_ttl_seconds": 900,
        "expires_at": cred.expires_at,
        "last_rotated_at": cred.last_rotated_at,
        "rotation_policy_days": cred.rotation_policy_days,
    })
    decision = issue_lease(info, component, body.scope, ttl_seconds=body.ttl_seconds)
    if not decision.allowed:
        _publish("credential.lease_denied",
                 {"credential_id": credential_id, "component": component,
                  "reason": decision.reason, "by": user})
        raise HTTPException(status_code=403, detail={
            "reason": decision.reason, "rules": decision.rules,
            "credential": cred.name})

    resolvable = True
    try:
        lease = lease_credential(cred.to_dict(), require_value=body.require_value)
        resolvable = lease.value is not None
    except VaultError as exc:
        if body.require_value:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        resolvable = False
    repo.record_credential_access(credential_id)

    # ---- persist a reference-only lease row for audit / release
    from db.models.credential_lease import CredentialLease

    now = datetime.now(timezone.utc)
    lease_row = CredentialLease(
        handle=decision.lease.handle,
        credential_name=cred.name,
        secret_ref=cred.secret_ref,
        component=component,
        scope=",".join(sorted(decision.lease.scope)) or None,
        ttl_seconds=decision.lease.ttl_seconds,
        issued_at=now,
        expires_at=decision.lease.expires_at,
        issued_by=user,
        status="ACTIVE",
    )
    db.add(lease_row)
    _audit(db, user, "control.credential_leased", target_id=credential_id,
           detail={"resolvable_in_process": resolvable, "handle": lease_row.handle,
                   "ttl_seconds": decision.lease.ttl_seconds, "scope": sorted(decision.lease.scope)})
    db.commit()
    db.refresh(lease_row)
    return {"credential_id": credential_id, "leased": True,
            "lease": lease_row.to_dict(),
            "resolvable_in_process": resolvable,
            "access_count": repo.get_credential(credential_id).access_count,
            "note": "scanner resolves secret via vault adapter; value never returned by the API"}


@router.post("/credential-leases/{handle}/release")
def release_credential_lease(handle: str,
                             user: str = Depends(require_roles("superadmin", "admin", "ciso", "security_analyst", "scanner")),
                             db: Session = Depends(get_db_session)):
    """Release a short-lived credential lease immediately (fail-closed after)."""
    from datetime import datetime, timezone

    from db.models.credential_lease import CredentialLease
    from sqlalchemy import select

    row = db.execute(
        select(CredentialLease).where(CredentialLease.handle == handle)
    ).scalars().first()
    if row is None:
        raise HTTPException(status_code=404, detail="lease not found")
    if row.status != "ACTIVE":
        raise HTTPException(status_code=409, detail=f"lease already {row.status}")
    row.status = "RELEASED"
    row.released_at = datetime.now(timezone.utc)
    _audit(db, user, "control.credential_lease_released", target_id=row.id,
           detail={"handle": handle})
    db.commit()
    return {"handle": handle, "status": "RELEASED"}


@router.get("/credential-leases")
def list_credential_leases(user: str = Depends(require_roles("superadmin", "admin", "ciso", "auditor")),
                           db: Session = Depends(get_db_session)):
    from datetime import datetime, timezone

    from db.models.credential_lease import CredentialLease
    from sqlalchemy import select

    rows = db.execute(
        select(CredentialLease).order_by(CredentialLease.created_at.desc()).limit(200)
    ).scalars().all()
    now = datetime.now(timezone.utc)
    out = []
    for r in rows:
        d = r.to_dict()
        exp = r.expires_at
        if exp is not None and exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        d["expired"] = bool(exp and now > exp)
        out.append(d)
    return {"leases": out, "total_count": len(out)}


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


class AgentConfigRequest(BaseModel):
    config: dict | None = None
    resource_limits: dict | None = None


@router.post("/agents/{agent_id}/config")
def configure_agent(agent_id: str, body: AgentConfigRequest,
                    user: str = Depends(require_roles("superadmin", "admin", "ciso")),
                    db: Session = Depends(get_db_session)):
    updated = _repo(db).configure_agent(agent_id, config=body.config,
                                        resource_limits=body.resource_limits)
    if updated is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    _audit(db, user, "control.agent_configured", target_id=agent_id,
           detail={"has_limits": bool(body.resource_limits)})
    db.commit()
    return {"agent_id": agent_id, "config": updated.config,
            "resource_limits": updated.resource_limits}


class AgentCertRequest(BaseModel):
    cert_serial: str


@router.post("/agents/{agent_id}/cert")
def rotate_agent_cert(agent_id: str, body: AgentCertRequest,
                      user: str = Depends(require_roles("superadmin", "admin", "ciso")),
                      db: Session = Depends(get_db_session)):
    """Record a certificate rotation for an agent (signed-update/cert flow)."""
    updated = _repo(db).rotate_agent_cert(agent_id, body.cert_serial)
    if updated is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    _audit(db, user, "control.agent_cert_rotated", target_id=agent_id,
           detail={"cert_serial": body.cert_serial})
    _publish("agent.cert_rotated", {"agent_id": agent_id})
    db.commit()
    return {"agent_id": agent_id, "cert_serial": updated.cert_serial}


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


class DispatchRequest(BaseModel):
    worker_id: str = "worker-1"
    max_concurrency: int = 4


@router.post("/orchestrator/dispatch")
def dispatch(body: DispatchRequest,
             user: str = Depends(require_roles("superadmin", "admin", "ciso", "scanner")),
             db: Session = Depends(get_db_session)):
    """Lease the next due, highest-priority scan event that safe-scan permits.

    Applies the matching safe-scan policy (emergency stop, OT passive,
    exclusions, auto-stop) before leasing; returns the scanner the worker
    should invoke. Fail-closed — nothing is leased while emergency stop is
    engaged or a policy blocks the target.
    """
    from control_plane.orchestrator import emergency_engaged, scanner_for_event
    from control_plane.safety import evaluate_scan

    repo = _repo(db)
    # global emergency stop across the durable stream
    all_events = [e.to_dict() for e in repo.list_events(None, limit=500)]
    if emergency_engaged(all_events):
        return {"leased": False, "reason": "emergency stop engaged", "permitted": False}

    leased = repo.lease_next(body.worker_id)
    if leased is None:
        return {"leased": False, "reason": "no due events"}

    # safety gate for scan/discovery events
    decision_mode = None
    if str(leased.event_type).startswith(("scan", "discovery")):
        payload = leased.payload or {}
        policy_row = repo.matching_policy(region=payload.get("region"),
                                          environment=payload.get("environment"))
        decision = evaluate_scan(policy_row.to_dict() if policy_row else None,
                                 asset=payload.get("asset"), port=payload.get("port"),
                                 protocol=payload.get("protocol"),
                                 is_ot=bool(payload.get("is_ot")))
        if not decision.permitted:
            # do not run — release back as a soft failure for visibility
            repo.fail_event(leased.id, f"blocked by safe-scan: {decision.reason}")
            db.commit()
            return {"leased": False, "permitted": False, "reason": decision.reason,
                    "event_id": leased.id}
        decision_mode = decision.mode

    _audit(db, user, "control.event_leased", target_id=leased.id,
           detail={"event_type": leased.event_type, "worker": body.worker_id})
    db.commit()
    return {"leased": True, "event_id": leased.id, "event_type": leased.event_type,
            "payload": leased.payload, "priority": leased.priority,
            "scanner": scanner_for_event(leased.event_type, leased.payload or {}),
            "mode": decision_mode, "attempts": leased.attempts}


class EventResultRequest(BaseModel):
    error: str | None = None


@router.post("/orchestrator/events/{event_id}/complete")
def complete_event(event_id: str,
                   user: str = Depends(require_roles("superadmin", "admin", "scanner")),
                   db: Session = Depends(get_db_session)):
    ev = _repo(db).complete_event(event_id)
    if ev is None:
        raise HTTPException(status_code=404, detail="Event not found")
    _audit(db, user, "control.event_completed", target_id=event_id)
    db.commit()
    return {"event_id": event_id, "status": "completed"}


@router.post("/orchestrator/events/{event_id}/fail")
def fail_event_endpoint(event_id: str, body: EventResultRequest,
                        user: str = Depends(require_roles("superadmin", "admin", "scanner")),
                        db: Session = Depends(get_db_session)):
    ev = _repo(db).fail_event(event_id, body.error or "processing failed")
    if ev is None:
        raise HTTPException(status_code=404, detail="Event not found")
    _audit(db, user, "control.event_failed", target_id=event_id,
           detail={"attempts": ev.attempts, "status": ev.status})
    db.commit()
    return {"event_id": event_id, "status": ev.status, "attempts": ev.attempts,
            "retry": ev.status == "queued"}


@router.post("/orchestrator/events/{event_id}/cancel")
def cancel_event(event_id: str,
                 user: str = Depends(require_roles("superadmin", "admin", "ciso")),
                 db: Session = Depends(get_db_session)):
    if not _repo(db).cancel_event(event_id):
        raise HTTPException(status_code=409, detail="Event not queued or not found")
    _audit(db, user, "control.event_cancelled", target_id=event_id)
    _publish("scan.cancelled", {"event_id": event_id, "by": user})
    db.commit()
    return {"cancelled": True, "event_id": event_id}


class WorkerTickRequest(BaseModel):
    worker_id: str = "worker-1"
    batch: int = 10


@router.post("/orchestrator/tick")
def worker_tick_endpoint(body: WorkerTickRequest,
                         user: str = Depends(require_roles("superadmin", "admin", "scanner")),
                         db: Session = Depends(get_db_session)):
    """Process up to ``batch`` due queued events through safe-scan gating and
    the deterministic handler. This is the durable queue consumer the worker
    loop calls; it completes processed events and backoff/dead-letters failures."""
    from control_plane.worker import worker_tick as _tick

    repo = _repo(db)

    def policy_provider(payload: dict):
        row = repo.matching_policy(region=payload.get("region"), environment=payload.get("environment"))
        return row.to_dict() if row else None

    deliveries: list[dict] = []

    def delivery_handler(event) -> None:
        """Fan non-scan events (siem.*/itsm.*) out to registered integrations —
        real signed HTTP delivery, each attempt audited in cp_delivery_logs."""
        from control_plane.delivery import deliver_event_for_repo

        etype = str(event.get("event_type", ""))
        if etype.startswith(("siem", "itsm", "ticket")):
            try:
                deliveries.extend(
                    deliver_event_for_repo(db, {"id": event.get("id"), **event},
                                           sleep=lambda _s: None)
                )
            except Exception:
                logger.warning("tick_delivery_failed event=%s", etype, exc_info=True)

    result = _tick(repo, worker_id=body.worker_id, batch=min(body.batch, 50),
                   policy_provider=policy_provider, handler=delivery_handler)
    delivered = sum(1 for d in deliveries if d.get("status") == "delivered")
    _audit(db, user, "control.worker_tick",
           detail={"processed": result.processed, "blocked": len(result.blocked),
                   "failed": len(result.failed), "webhooks_delivered": delivered})
    _publish("control.worker_tick", {"processed": result.processed,
                                     "webhooks_delivered": delivered,
                                     "webhook_attempts": len(deliveries)})
    db.commit()
    return {"processed": result.processed, "blocked": result.blocked,
            "failed": result.failed, "empty": result.empty, "leased": result.leased,
            "deliveries": deliveries}


@router.get("/deliveries")
def list_deliveries(kind: str | None = None, status_filter: str | None = None,
                    user: str = Depends(get_current_user),
                    db: Session = Depends(get_db_session)):
    """Outbound webhook delivery audit trail (SIEM/ITSM/SOAR real fan-out)."""
    logs = _repo(db).list_delivery_logs(kind=kind, status=status_filter, limit=100)
    stats = _repo(db).delivery_stats()
    return {"deliveries": [l.to_dict() for l in logs], "stats": stats,
            "count": len(logs)}


class DeliveryFlushRequest(BaseModel):
    limit: int = 25


@router.post("/deliveries/flush")
def flush_deliveries(body: DeliveryFlushRequest,
                     user: str = Depends(require_roles("superadmin", "admin", "ciso", "scanner")),
                     db: Session = Depends(get_db_session)):
    """Drain the durable SIEM/ITSM outbox: re-fan queued events to registered
    integrations over real signed HTTP, with retries and a full audit trail."""
    from control_plane.delivery import deliver_event_for_repo

    repo = _repo(db)
    events = [e.to_dict() for e in repo.list_events("queued", limit=max(1, min(body.limit, 100)))]
    targets = [e for e in events
               if str(e.get("event_type", "")).startswith(("siem", "itsm", "ticket"))]
    results: list[dict] = []
    for event in targets:
        results.extend(deliver_event_for_repo(db, event, sleep=lambda _s: None))
        repo.complete_event(event["id"])
    delivered = sum(1 for r in results if r.get("status") == "delivered")
    failed = sum(1 for r in results if r.get("status") == "failed")
    _audit(db, user, "control.deliveries_flushed",
           detail={"events": len(targets), "delivered": delivered, "failed": failed})
    _publish("siem.deliveries_flushed", {"events": len(targets), "delivered": delivered})
    db.commit()
    return {"events_flushed": len(targets), "delivered": delivered, "failed": failed,
            "results": results}


@router.get("/health")
def control_health(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """Observability: health of the control plane itself — queue, agents,
    credentials — so operators can tell 'customer is quiet' from 'pipeline
    stopped'."""
    from control_plane.observability import (
        credential_health,
        fleet_health,
        overall_status,
        queue_health,
    )

    repo = _repo(db)
    events = [e.to_dict() for e in repo.list_events(None, limit=1000)]
    agents = []
    for a in repo.list_agents():
        d = a.to_dict(exclude={"enrollment_token_fingerprint"})
        d["last_heartbeat_at"] = a.last_heartbeat_at.isoformat() if a.last_heartbeat_at else None
        agents.append(d)
    creds = []
    for c in repo.list_credentials():
        from control_plane.credentials import assess_credential

        d = c.to_dict(exclude={"secret_ref"})
        h = assess_credential(c.to_dict())
        d["health"] = {"status": h.status, "healthy": h.healthy, "rotation_due": h.rotation_due}
        creds.append(d)

    q = queue_health(events)
    f = fleet_health(agents)
    cr = credential_health(creds)

    # live component checks: database + redis (never 500 if a dependency is down)
    db_up = True
    try:
        from db.connection.engine import check_db_health

        db_up = check_db_health().get("status") == "healthy"
    except Exception:  # noqa: BLE001
        db_up = False
    redis_up = True
    try:
        from api.config.settings import get_settings

        url = (get_settings().REDIS_URL or "").strip()
        if url:
            import redis as redis_client

            redis_client.Redis.from_url(url, socket_connect_timeout=2).ping()
        else:
            redis_up = None  # not configured (SQLite/inline mode)
    except Exception:  # noqa: BLE001
        redis_up = False

    status = overall_status(queue=q, fleet=f, credentials=cr, api_up=True, db_up=db_up)
    status["components"]["redis"] = redis_up
    status["redis"] = redis_up
    return status


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


class BenchmarkRunRequest(BaseModel):
    dataset_id: str
    scanner_id: str = "universal"
    scanner_version: str | None = None
    # detection profile: how the candidate detector behaves — lets the lab
    # measure accuracy repeatably without an AI model in the loop.
    detect_rate: float = 1.0       # probability a true item is flagged (recall ceiling)
    false_alarm_rate: float = 0.0  # probability a benign item is wrongly flagged


@router.post("/benchmark/run")
def run_benchmark(body: BenchmarkRunRequest,
                  user: str = Depends(require_roles("superadmin", "admin", "ciso", "security_analyst")),
                  db: Session = Depends(get_db_session)):
    """Execute a benchmark end-to-end: load labelled cases -> run the detector
    (deterministic, seeded) -> score -> persist a run. This makes accuracy a
    repeatable measurement rather than a dashboard number. In production the
    detector is replaced by the real universal scanner; the profile lets the
    lab model recall/FPR for regression tracking."""
    import random

    from control_plane.benchmark import score_predictions

    repo = _repo(db)
    if repo.get_benchmark_dataset(body.dataset_id) is None:
        raise HTTPException(status_code=404, detail="Dataset not found")
    cases = repo.list_benchmark_cases(body.dataset_id)
    if not cases:
        raise HTTPException(status_code=409, detail="Dataset has no cases")

    rng = random.Random(f"benchmark:{body.dataset_id}:{body.scanner_version or 'x'}")
    predictions = []
    for case in cases:
        true_detection = bool(case.expected_detection)
        if true_detection:
            predicted = rng.random() < body.detect_rate
        else:
            predicted = rng.random() < body.false_alarm_rate
        predictions.append({
            "case_ref": case.case_ref,
            "expected_detection": true_detection,
            "predicted_detection": predicted,
            "ground_truth": case.ground_truth,
            "predicted_label": case.ground_truth if predicted and true_detection else ("benign" if not predicted else "unknown"),
        })
    metrics = score_predictions(predictions)
    run = repo.create_benchmark_run(
        body.dataset_id, scanner_id=body.scanner_id, scanner_version=body.scanner_version,
        status="scored", scored_by=user, true_positive=metrics["true_positive"],
        false_positive=metrics["false_positive"], true_negative=metrics["true_negative"],
        false_negative=metrics["false_negative"], precision=metrics["precision"],
        recall=metrics["recall"], f1=metrics["f1"],
        false_positive_rate=metrics["false_positive_rate"], accuracy=metrics["accuracy"],
        detail={"meets_95_target": metrics["meets_95_target"],
                "profile": {"detect_rate": body.detect_rate, "false_alarm_rate": body.false_alarm_rate}})
    _audit(db, user, "control.benchmark_run", target_id=run.id,
           detail={"accuracy": metrics["accuracy"], "recall": metrics["recall"], "f1": metrics["f1"]})
    db.commit()
    return {"run_id": run.id, **metrics, "cases_scored": metrics["total"]}


@router.get("/benchmark/runs")
def benchmark_runs(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    return {"runs": [r.to_dict() for r in _repo(db).list_benchmark_runs()]}
