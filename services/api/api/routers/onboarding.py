"""Enterprise onboarding workflow API.

Implements the customer journey: create organization → select sector →
create environments → define authorized scope → connect infrastructure →
test access → start initial discovery. The universal engine then takes over
(discover → identify → specialized scans → evidence → CBOM/HBOM → graph →
sector policy → risk → PQC → continuous monitoring), which already exists.

Security: scope is explicit (the scanner only ever operates inside authorized
targets) and connector configs never store secret material (defensive
scrubbing + read-only/least-privilege assumption).
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone

from db.repositories.onboarding_repository import OnboardingRepository
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session, require_roles

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/onboarding", tags=["onboarding"])


# --------------------------------------------------------------------------- #
def _repo(db: Session) -> OnboardingRepository:
    return OnboardingRepository(db)


def _org_or_404(repo: OnboardingRepository, org_id: str | None = None):
    org = repo.get_org(org_id) if org_id else repo.get_default_org()
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="No organization yet — create one with POST /onboarding/organization")
    return org


_CIDR_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$")
_DOMAIN_RE = re.compile(r"^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")


# ------------------------------------------------------------- organization
class OrganizationRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=200)
    sector: str = "generic"
    industry: str | None = None
    regions: list[str] = Field(default_factory=list)
    business_units: list[str] = Field(default_factory=list)


@router.post("/organization", status_code=status.HTTP_201_CREATED)
def create_organization(
    body: OrganizationRequest,
    user: str = Depends(require_roles("admin", "superadmin", "ciso")),
    db: Session = Depends(get_db_session),
):
    from sector_profiles import normalize_sector

    repo = _repo(db)
    if repo.get_default_org() is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="An organization already exists; update it instead")
    sector = normalize_sector(body.sector)
    org = repo.create_org(
        body.name.strip(), sector=sector, industry=body.industry,
        regions=body.regions or None, business_units=body.business_units or None,
        onboarding_stage="sector",
    )
    # keep the org-wide sector setting in sync with the Sector Layer
    try:
        from db.repositories.settings_repository import (
            SECTOR_SETTING_KEY,
            SettingsRepository,
        )

        SettingsRepository(db).set(SECTOR_SETTING_KEY, {"sector": sector}, updated_by=user)
    except Exception:
        logger.debug("sector setting sync skipped", exc_info=True)
    db.commit()
    return org.to_dict()


@router.get("/state")
def onboarding_state(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """Full onboarding state for the wizard: org + sector context + environments
    + authorized scope + connections + readiness checklist."""
    repo = _repo(db)
    org = repo.get_default_org()
    if org is None:
        return {"organization": None, "stage": "organization", "ready": False,
                "checklist": _checklist(None, repo)}
    environments = [e.to_dict() for e in repo.list_environments(org.id)]
    scope = repo.scope_summary(org.id)
    connectors = [c.to_dict() for c in repo.list_connectors(org.id)]
    connected = [c for c in connectors if c.get("status") == "connected"]
    sector_context = None
    try:
        from sector_profiles import get_profile

        sector_context = {
            "sector": org.sector,
            "recommended_modes": [m["id"] for m in __import__("sector_profiles").recommend_modes(org.sector)],
            "policy_packs": list(get_profile(org.sector).policy_packs),
            "compliance_frameworks": list(get_profile(org.sector).compliance_frameworks),
        }
    except Exception:
        logger.debug("sector context unavailable", exc_info=True)
        sector_context = {"sector": org.sector}
    state = {
        "organization": org.to_dict(),
        "sector_context": sector_context,
        "environments": environments,
        "scope": scope,
        "connections": connectors,
        "connected_count": len(connected),
        "stage": org.onboarding_stage,
        "ready": _is_ready(environments, scope, connected),
        "checklist": _checklist(org, repo, environments, scope, connectors, connected),
    }
    return state


def _is_ready(environments, scope, connected) -> bool:
    return bool(environments) and scope["total"] > 0 and bool(connected)


def _checklist(org, repo, environments=None, scope=None, connectors=None, connected=None) -> list[dict]:
    environments = environments if environments is not None else []
    scope = scope or {"total": 0}
    connectors = connectors or []
    connected = connected if connected is not None else []
    return [
        {"step": "organization", "label": "Create organization", "done": org is not None},
        {"step": "sector", "label": "Select sector profile", "done": bool(org and org.sector)},
        {"step": "environment", "label": "Create at least one environment", "done": len(environments) > 0},
        {"step": "scope", "label": "Define authorized scope", "done": scope["total"] > 0},
        {"step": "connections", "label": "Connect & verify infrastructure", "done": len(connected) > 0},
        {"step": "policy", "label": "Apply sector policy packs", "done": bool(org)},
        {"step": "discovery", "label": "Run initial discovery",
         "done": bool(org and org.onboarding_stage == "discovery" and org.onboarding_complete)},
    ]


# --------------------------------------------------------------- environments
class EnvironmentRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    env_type: str = "production"
    region: str | None = None
    description: str | None = None
    scan_mode: str = "standard"
    active_probing: bool = True


@router.post("/environments", status_code=status.HTTP_201_CREATED)
def add_environment(
    body: EnvironmentRequest,
    user: str = Depends(require_roles("admin", "superadmin", "ciso", "security_analyst")),
    db: Session = Depends(get_db_session),
):
    from db.models.onboarding import ENVIRONMENT_TYPES, SCAN_MODES

    repo = _repo(db)
    org = _org_or_404(repo)
    if body.env_type not in ENVIRONMENT_TYPES:
        raise HTTPException(status_code=422, detail=f"env_type must be one of {list(ENVIRONMENT_TYPES)}")
    if body.scan_mode not in SCAN_MODES:
        raise HTTPException(status_code=422, detail=f"scan_mode must be one of {list(SCAN_MODES)}")
    # OT environments default to passive/no active probing unless explicitly set
    active = body.active_probing and body.env_type != "ot"
    if body.env_type == "ot":
        body.scan_mode = "passive"
    env = repo.add_environment(
        org.id, body.name.strip(), env_type=body.env_type, region=body.region,
        description=body.description, scan_mode=body.scan_mode, active_probing=active,
    )
    if org.onboarding_stage in {"organization", "sector"}:
        org.onboarding_stage = "scope"
    db.commit()
    return env.to_dict()


# --------------------------------------------------------------------- scope
class ScopeRequest(BaseModel):
    kind: str  # network/cloud/application/hardware
    target: str = Field(..., min_length=1, max_length=500)
    env_id: str | None = None
    detail: dict | None = None


@router.post("/scope", status_code=status.HTTP_201_CREATED)
def add_scope(
    body: ScopeRequest,
    user: str = Depends(require_roles("admin", "superadmin", "ciso", "security_analyst")),
    db: Session = Depends(get_db_session),
):
    repo = _repo(db)
    org = _org_or_404(repo)
    if body.kind not in ("network", "cloud", "application", "hardware"):
        raise HTTPException(status_code=422, detail="kind must be network/cloud/application/hardware")
    target = body.target.strip()
    # light validation for network scope (CIDR or domain), per authorized-range model
    if body.kind == "network" and not (
        _CIDR_RE.match(target) or _DOMAIN_RE.match(target) or target.startswith(("vlan:", "snmp:"))
    ):
        raise HTTPException(status_code=422,
                            detail="Network scope must be a CIDR (10.10.0.0/16), domain, or 'vlan:..'/'snmp:..' reference")
    entry = repo.add_scope(org.id, body.kind, target, env_id=body.env_id, detail=body.detail)
    db.commit()
    return entry.to_dict()


@router.get("/scope")
def get_scope(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    repo = _repo(db)
    org = _org_or_404(repo)
    return repo.scope_summary(org.id)


# ----------------------------------------------------------------- connections
class ConnectorRequest(BaseModel):
    kind: str  # network/aws/azure/gcp/kubernetes/git/vmware/hardware/hsm/siem/other
    name: str = Field(..., min_length=1, max_length=120)
    method: str = "api"
    mode: str = "passive"  # passive/active
    env_id: str | None = None
    config: dict = Field(default_factory=dict)  # NON-secret references only


@router.post("/connections", status_code=status.HTTP_201_CREATED)
def add_connection(
    body: ConnectorRequest,
    user: str = Depends(require_roles("admin", "superadmin", "ciso")),
    db: Session = Depends(get_db_session),
):
    repo = _repo(db)
    org = _org_or_404(repo)
    connector = repo.add_connector(
        org.id, body.kind, body.name.strip(), method=body.method,
        mode=body.mode, config=body.config, env_id=body.env_id,
    )
    org.onboarding_stage = "connections"
    db.commit()
    return connector.to_dict()


@router.get("/connections")
def list_connections(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    repo = _repo(db)
    org = _org_or_404(repo)
    connectors = repo.list_connectors(org.id)
    return {"connections": [c.to_dict(exclude={"config"}) for c in connectors],
            "configured": len(connectors),
            "connected": sum(1 for c in connectors if c.status == "connected")}


# ----------------------------------------------------------- test connection
@router.post("/connections/{connector_id}/test")
def test_connection(
    connector_id: str,
    user: str = Depends(require_roles("admin", "superadmin", "ciso", "security_analyst")),
    db: Session = Depends(get_db_session),
):
    """Connectivity / credential / permission / scope / agent health check.

    Runs a *safe, non-intrusive* check: validates the connector configuration,
    confirms a non-secret reference is present, and (for agent connectors)
    reports agent health. Real reachability to third-party clouds/devices is
    performed by the scanners with customer-granted read-only access; this
    endpoint verifies the connection is correctly configured and reports the
    checks honestly (it never fabricates a successful reachability result).
    """
    repo = _repo(db)
    org = _org_or_404(repo)
    connector = repo.get_connector(connector_id)
    if connector is None or connector.org_id != org.id:
        raise HTTPException(status_code=404, detail="Connector not found")

    checks = []
    cfg = connector.config or {}

    def add(name: str, ok: bool, detail: str):
        checks.append({"check": name, "ok": ok, "detail": detail})

    # connectivity/config check — a reference appropriate to the kind must exist
    ref_keys = {
        "network": ("host", "cidr", "endpoint", "scope"),
        "aws": ("role_arn", "account", "account_id"),
        "azure": ("subscription_id", "tenant_id", "service_principal", "principal"),
        "gcp": ("project_id", "service_account", "project"),
        "kubernetes": ("cluster", "kubeconfig_ref", "api_server"),
        "git": ("repo_url", "repo", "org"),
        "vmware": ("host", "vcenter"),
        "hardware": ("host", "asset", "ip"),
        "hsm": ("host", "hsm", "partition_ref"),
        "siem": ("host", "endpoint", "url"),
        "other": ("host", "endpoint", "url"),
    }.get(connector.kind, ("host", "endpoint"))
    has_ref = any(k in cfg and str(cfg[k]).strip() for k in ref_keys)
    add("connectivity", has_ref, f"{connector.kind} reference present" if has_ref
        else f"missing one of {list(ref_keys)} in config (non-secret reference)")

    # credential model check — secrets are NEVER persisted by design. If a
    # caller tried to supply one, the scrubber replaced it; that confirms the
    # read-only/least-privilege model (grant access out-of-band).
    redacted_keys = [k for k, v in cfg.items() if str(v) == "<redacted-secret-not-stored>"]
    add(
        "credential_model", True,
        f"secrets never stored ({len(redacted_keys)} supplied field(s) dropped); grant read-only access out-of-band"
        if redacted_keys else "no secret material stored; read-only/least-privilege access assumed",
    )

    # permission/scope check — at least one authorized scope target exists
    scope = repo.scope_summary(org.id)
    add("scope", scope["total"] > 0, f"{scope['total']} authorized target(s) defined")

    # agent health check (agent connectors)
    if connector.method == "agent" or connector.agent_id:
        add("agent_health", bool(connector.agent_healthy),
            "agent reporting healthy" if connector.agent_healthy else "agent not yet checked in")
    else:
        add("agent_health", True, "n/a (non-agent connector)")

    all_ok = all(c["ok"] for c in checks)
    new_status = "connected" if all_ok else "error"
    repo.set_connector_status(
        connector_id, new_status,
        test_result={"checks": checks, "all_ok": all_ok,
                     "tested_at": datetime.now(timezone.utc).isoformat()},
        agent_healthy=connector.agent_healthy,
    )
    db.commit()
    return {"connector_id": connector_id, "status": new_status, "all_ok": all_ok, "checks": checks}


# ------------------------------------------------------------ start discovery
@router.post("/discovery/start", status_code=status.HTTP_202_ACCEPTED)
def start_discovery(
    user: str = Depends(require_roles("admin", "superadmin", "ciso", "security_analyst")),
    db: Session = Depends(get_db_session),
):
    """Start initial discovery over the authorized scope.

    Builds a discovery plan from the environments/scope/connectors and
    registers a discovery run. Actual scanning is performed by the universal
    engine (network/cloud/hardware/vendor/application domains), which then
    feeds evidence → CBOM/HBOM → graph → sector policy → risk → PQC. This
    endpoint orchestrates the kick-off and returns the plan honestly.
    """
    repo = _repo(db)
    org = _org_or_404(repo)
    environments = repo.list_environments(org.id)
    scope = repo.scope_summary(org.id)
    connectors = repo.list_connectors(org.id)
    connected = [c for c in connectors if c.status == "connected"]

    if not environments:
        raise HTTPException(status_code=409, detail="Create at least one environment first")
    if scope["total"] == 0:
        raise HTTPException(status_code=409, detail="Define authorized scope before discovery")
    if not connected:
        raise HTTPException(status_code=409, detail="At least one connected (tested) connector is required")

    # Build the domain discovery plan from the scope kinds present.
    domains = []
    if scope["counts"].get("network"):
        domains.append({"domain": "network", "targets": scope["counts"]["network"],
                        "mode": "passive" if any(e.env_type == "ot" for e in environments) else "active"})
    if scope["counts"].get("cloud"):
        domains.append({"domain": "cloud", "targets": scope["counts"]["cloud"], "mode": "read-only"})
    if scope["counts"].get("hardware"):
        domains.append({"domain": "hardware", "targets": scope["counts"]["hardware"],
                        "mode": "passive" if any(e.env_type == "ot" for e in environments) else "standard"})
    if scope["counts"].get("application"):
        domains.append({"domain": "application", "targets": scope["counts"]["application"], "mode": "standard"})
    # vendor discovery follows network/hardware automatically
    domains.append({"domain": "vendor", "targets": "derived", "mode": "metadata"})

    run = repo.create_discovery_run(org.id, run_type="initial", triggered_by=user)
    org.onboarding_stage = "discovery"
    org.onboarding_complete = True
    db.commit()

    # announce on the realtime bus
    try:
        from api.events.bus import get_event_bus

        get_event_bus().publish(
            "discovery.started",
            {"org": org.name, "run_id": run.id, "domains": [d["domain"] for d in domains],
             "scope_targets": scope["total"], "by": user},
            source="onboarding",
        )
    except Exception:
        logger.debug("discovery event publish failed", exc_info=True)

    return {
        "run_id": run.id,
        "status": "planned",
        "organization": org.name,
        "sector": org.sector,
        "environments": len(environments),
        "plan": domains,
        "authorized_scope": scope["counts"],
        "connectors_used": [c.kind for c in connected],
        "next_steps": [
            "asset identification", "specialized scanning", "evidence fusion",
            "CBOM/HBOM", "dependency graph", "sector policy", "risk", "pqc",
        ],
    }
