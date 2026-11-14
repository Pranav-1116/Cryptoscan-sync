"""Scope & Authorization + Multi-Tenant isolation endpoints (blueprint #2, #11).

Resolves a tenant's persisted scope (Organization → Environment → ScopeEntry →
Connector) into one authorization envelope and evaluates concrete
target/method/mutation decisions. Also surfaces the tenant-isolation report so
operators can verify Tenant A ─X─ Tenant B at the data layer.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
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
    _org_row = {"id": org.id, "name": org.name}
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


# --- scope revisions and the server-side diff --------------------------------

def _revision_state(db: Session, org_id: str | None, ref: str):
    """Resolve one revision reference ('current' or a snapshot id)."""
    from db.repositories.scope_snapshot_repository import (
        ScopeSnapshotRepository,
        scope_content_hash,
    )

    if ref == "current":
        org, scope_rows, conns, maintenance_open = _load(OnboardingRepository(db), org_id)
        env = resolve_scope(org=org.to_dict(), scope_entries=scope_rows,
                            connectors=conns, maintenance_open=maintenance_open)
        envelope = env.to_dict()
        meta = {"ref": "current", "snapshot_id": None, "label": None,
                "created_at": None,
                "content_hash": scope_content_hash(scope_rows, envelope)}
        return meta, scope_rows, envelope
    row = ScopeSnapshotRepository(db).get(ref)
    if row is None:
        raise HTTPException(status_code=404,
                            detail=f"scope snapshot {ref} does not exist")
    meta = {"ref": ref, "snapshot_id": row.id, "label": row.label,
            "created_at": row.created_at.isoformat() if row.created_at else None,
            "content_hash": row.content_hash}
    return meta, list(row.entries or []), dict(row.envelope or {})


@router.post("/snapshots", status_code=201)
def create_scope_snapshot(
    label: str | None = None,
    org_id: str | None = None,
    request: Request = None,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Capture the current authorized scope as a named revision.

    Snapshots are the unit `GET /scope/diff` compares. The stored state is
    exactly what the resolver produced — the database keeps no scope
    history to re-derive, so a revision that was never captured cannot be
    diffed later.
    """
    from db.repositories.scope_snapshot_repository import ScopeSnapshotRepository

    org, scope_rows, conns, maintenance_open = _load(OnboardingRepository(db), org_id)
    env = resolve_scope(org=org.to_dict(), scope_entries=scope_rows,
                        connectors=conns, maintenance_open=maintenance_open)
    row = ScopeSnapshotRepository(db).create(
        org_id=org.id,
        entries=scope_rows,
        envelope=env.to_dict(),
        label=label,
        tenant_id=getattr(request.state, "tenant_id", None),
        created_by=user if isinstance(user, str) else None,
    )
    return {
        "id": row.id, "label": row.label, "content_hash": row.content_hash,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "entries": len(row.entries or []),
    }


@router.get("/snapshots")
def list_scope_snapshots(
    limit: int = Query(50, ge=1, le=500),
    org_id: str | None = None,
    request: Request = None,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Known scope revisions, newest first. Empty means none were captured —
    not that the scope never changed."""
    from db.repositories.scope_snapshot_repository import ScopeSnapshotRepository

    rows = ScopeSnapshotRepository(db).list(
        org_id=org_id,
        tenant_id=getattr(request.state, "tenant_id", None),
        limit=limit)
    return [
        {"id": r.id, "label": r.label, "content_hash": r.content_hash,
         "created_at": r.created_at.isoformat() if r.created_at else None,
         "entries": len(r.entries or [])}
        for r in rows
    ]


@router.get("/diff")
def scope_diff(
    from_: str = Query(..., alias="from"),
    to: str = Query("current"),
    org_id: str | None = None,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Diff two scope revisions — computed here, never in a terminal.

    `from`/`to` are snapshot ids, or the literal `current` for the live
    envelope. The verdicts: `added` (+, effective), `removed` (−),
    `changed` (~, before/after) and `blocked` (!, declared but disabled or
    excluded — never a widening of authority). Envelope-level differences
    travel in `envelope_changed`. Two identical revisions are not proof the
    scope was enforced — only that it did not change between captures.
    """
    from universal_platform.scope import diff_scope_revisions

    from_meta, from_entries, from_envelope = _revision_state(db, org_id, from_)
    to_meta, to_entries, to_envelope = _revision_state(db, org_id, to)
    result = diff_scope_revisions(from_entries, from_envelope,
                                  to_entries, to_envelope)
    return {"from": from_meta, "to": to_meta, **result}
