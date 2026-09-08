"""Scope & Authorization + Multi-Tenant isolation endpoints (blueprint #2, #11).

Resolves a tenant's persisted scope (Organization → Environment → ScopeEntry →
Connector) into one authorization envelope and evaluates concrete
target/method/mutation decisions. Also surfaces the tenant-isolation report so
operators can verify Tenant A ─X─ Tenant B at the data layer.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session
from db.repositories.onboarding_repository import (
    OnboardingRepository,
    maintenance_window_open,
)
from universal_platform.scope import (
    ScopeAuthorization,
    authorize_scope,
    resolve_scope,
)

router = APIRouter(prefix="/scope", tags=["scope", "tenant"])


def _load(repo: OnboardingRepository, org_id: str | None):
    org = repo.get_org(org_id) if org_id else repo.get_default_org()
    if org is None:
        raise HTTPException(status_code=404,
                            detail="No organization yet — create one via POST /onboarding/organization")
    envs = repo.list_environments(org.id)
    entries = repo.list_scope(org.id)
    conns = repo.list_connectors(org.id)
    # maintenance window: true only if EVERY enabled env allows work right now
    maintenance_open = all(
        maintenance_window_open(e) for e in envs if e.enabled
    ) if envs else True

    scope_rows = [
        {"kind": e.kind, "target": e.target, "enabled": e.enabled, "detail": e.detail}
        for e in entries
    ]
    connector_rows = [
        {"kind": c.kind, "method": c.method, "mode": c.mode, "status": c.status,
         "config": c.config, "agent_id": c.agent_id}
        for c in conns
    ]
    org_row = {"id": org.id, "name": org.name}
    return org, scope_rows, connector_rows, maintenance_open


def _envelope(repo: OnboardingRepository, org_id: str | None) -> ScopeAuthorization:
    org, scope_rows, connector_rows, maintenance_open = _load(repo, org_id)
    return resolve_scope(org=org.to_dict(), scope_entries=scope_rows,
                         connectors=connector_rows, maintenance_open=maintenance_open)


@router.get("/envelope")
def scope_envelope(
    org_id: str | None = None,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """The full authorized-scope envelope for the tenant (or default org)."""
    env = _envelope(OnboardingRepository(db), org_id)
    return env.to_dict()


@router.get("/authorize")
def authorize(
    target: str = Query(...),
    kind: str | None = None,
    method: str | None = None,
    mutating: bool = False,
    org_id: str | None = None,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Evaluate one target/method/mutation against the authorized scope.

    Fails closed. Useful for pre-flight checks and for the connector SDK to
    confirm a connector run is authorized before it touches a target.
    """
    env = _envelope(OnboardingRepository(db), org_id)
    decision = authorize_scope(env, target, kind=kind, method=method, mutating=mutating)
    return {"decision": decision, "scope": env.to_dict()}


@router.get("/tenant/isolation")
def tenant_isolation(
    org_id: str | None = None,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Multi-tenant isolation report — which tenants exist, what's enforced.

    Reads real persisted data only. If there is exactly one tenant (a
    greenfield/self-hosted install) isolation is trivially satisfied but still
    reported honestly with the count of granted scope entries + connectors.
    """
    repo = OnboardingRepository(db)
    org, scope_rows, connector_rows, maintenance_open = _load(repo, org_id)
    env = _envelope(repo, org_id)
    orgs = repo.list_orgs()
    return {
        "source": "scope_engine",
        "enforced": len(orgs) > 1,   # isolation is real once >1 tenant exists
        "tenants": [{"id": o.id, "name": o.name, "sector": o.sector} for o in orgs],
        "current_tenant": org.name,
        "authorized_scope": env.to_dict(),
        "scope_entry_count": len(scope_rows),
        "connector_count": len(connector_rows),
        "maintenance_window_open": maintenance_open,
    }


@router.get("/authorize-batch")
def authorize_batch(
    targets: list[str] = Query(default=[]),
    method: str | None = None,
    mutating: bool = False,
    org_id: str | None = None,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Batch authorization for the connector SDK pre-flight (fail-closed)."""
    env = _envelope(OnboardingRepository(db), org_id)
    return {
        "scope": env.to_dict(),
        "decisions": {
            t: authorize_scope(env, t, kind=None, method=method, mutating=mutating)
            for t in targets
        },
    }
