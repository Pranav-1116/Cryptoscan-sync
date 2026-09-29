"""Live Scanning flow — the "one product" surface.

    Customer -> Scope & Authorization -> Credential Vault -> SCAN ORCHESTRATOR
        -> network / cloud / hardware / vendor / crypto discovery domains
        -> one global scan ID + phase state machine -> live environment.

``/live/orchestrator/start`` resolves the authorized scope into real per-domain
scanner targets, validates credentials, issues ONE global scan id, and drives
the real scanners via ``LiveScanRunner``. ``/live/environment`` aggregates the
whole estate into ONE view — domain live counts, the correlation graph, the
current scan phase/progress, and the live event stream — so the customer sees a
single product, not four scanners.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session, require_roles
from api.events.bus import get_event_bus
from api.live_scan.orchestrator import collapse_scan_events, get_scan_orchestrator
from api.routers.inventory import collect_inventory
from api.graph_builder import graph_from_db
from db.repositories.onboarding_repository import OnboardingRepository

router = APIRouter(prefix="/live", tags=["live", "scans"])

_OPERATORS = ("admin", "superadmin", "ciso", "security_analyst", "scanner")


def _org_policy(repo: OnboardingRepository, org_id: str) -> dict | None:
    """Load the persisted scan/privacy policy for an org (JSON in app_settings)."""
    try:
        from db.models.app_setting import AppSetting
        from sqlalchemy import select

        row = repo.session.execute(
            select(AppSetting).where(AppSetting.key == f"org:{org_id}:scan_policy")
        ).scalars().first()
        if row is None:
            return None
        import json
        return json.loads(row.value or "{}")
    except Exception as _handler_exc:  # noqa: BLE001 — policy read is best-effort
        logger.warning(
            "exception_suppressed",
            extra={"error_type": type(_handler_exc).__name__},
        )
        return None





def _scope_rows(repo: OnboardingRepository):
    org = repo.get_default_org()
    if org is None:
        return None, [], [], []
    envs = repo.list_environments(org.id)
    entries = [
        {"kind": e.kind, "target": e.target, "enabled": e.enabled, "detail": e.detail}
        for e in repo.list_scope(org.id)
    ]
    conns = [
        {"kind": c.kind, "method": c.method, "mode": c.mode, "status": c.status,
         "config": c.config, "agent_id": c.agent_id}
        for c in repo.list_connectors(org.id)
    ]
    return org, entries, conns, envs


@router.post("/orchestrator/start", status_code=202)
def orchestrator_start(
    scanners: list[str] | None = None,
    user: str = Depends(require_roles(*_OPERATORS)),
    db: Session = Depends(get_db_session),
):
    """Start one integrated scan for the tenant's authorized scope."""
    repo = OnboardingRepository(db)
    org, entries, conns, envs = _scope_rows(repo)
    if org is None:
        raise HTTPException(status_code=404,
                            detail="No organization yet — create one via POST /onboarding/organization")
    orch = get_scan_orchestrator()
    run = orch.start(org.to_dict(), entries, conns, envs, only=scanners, db=db,
                     updated_by=user, actor=user, policy=_org_policy(repo, org.id),
                     sector=getattr(org, "sector", None))
    return {"status": "started", "scan": run.to_dict()}


@router.get("/orchestrator/status")
def orchestrator_status(
    user: str = Depends(get_current_user),
):
    """Current integrated scan run: scan id, phase, per-domain progress."""
    return get_scan_orchestrator().status()


@router.get("/orchestrator/history")
def orchestrator_history(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
    limit: int = 25,
):
    """Recent integrated scan runs, rebuilt from the durable platform event log.

    Unlike ``/orchestrator/status`` (which only holds the current in-memory run),
    this reconstructs *finished* runs from the persisted ``platform`` events, so
    run history survives restarts and is visible from any worker.
    """
    from db.models.monitor import MonitorEvent

    rows = (
        db.query(MonitorEvent)
        .filter(
            MonitorEvent.target_name == "platform",
            MonitorEvent.event_type.in_(("SCAN_STARTED", "SCAN_PHASE", "SCAN_COMPLETED", "SCAN_FAILED")),
        )
        .order_by(MonitorEvent.created_at.desc(), MonitorEvent.id.desc())
        .limit(800)
        .all()
    )
    events = [
        {
            "event_type": r.event_type,
            "payload": r.payload or {},
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in reversed(rows)  # oldest-first so collapse + sort yields newest-first
    ]
    runs = collapse_scan_events(events)
    return {"source": "scan_orchestrator", "runs": runs[: max(0, int(limit))]}


@router.get("/environment")
def live_environment(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """ONE live view of the whole estate.

    All four domains (network / hardware / vendor / crypto) read from the SAME
    authoritative inventory + correlation graph + live event stream, so the
    customer sees one integrated environment. No separate per-scanner datasets.
    """
    try:
        rows = collect_inventory(db, limit=1000)
    except Exception:  # noqa: BLE001
        rows = []
    domain_counts = {
        "network": sum(1 for r in rows if r["asset_type"] in ("NetworkTarget",) or r.get("asset_type") == "NetworkTarget"),
        "hardware": sum(1 for r in rows if r["asset_type"] == "Hardware"),
        "vendor": sum(1 for r in rows if r["asset_type"] == "Vendor"),
        "crypto": sum(1 for r in rows if r["asset_type"] == "Crypto"),
        "certificate": sum(1 for r in rows if r["asset_type"] == "Certificate"),
        "application": sum(1 for r in rows if r["asset_type"] == "Application"),
        "total": len(rows),
    }
    # correlation graph summary (same persisted graph the CMDB / dependency view uses)
    graph_summary: dict[str, Any] = {}
    try:
        vis = graph_from_db(db).to_vis()
        nodes = vis.get("nodes") or []
        edges = vis.get("edges") or []
        kinds: dict[str, int] = {}
        for n in nodes:
            k = str(n.get("kind") or "node")
            kinds[k] = kinds.get(k, 0) + 1
        graph_summary = {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "by_kind": kinds,
            "backend": vis.get("backend"),
        }
    except Exception:  # noqa: BLE001
        graph_summary = {"note": "graph unavailable"}
    # live event stream (recent real events)
    bus = get_event_bus()
    events = bus.recent(since_id=0, limit=30)
    orch = get_scan_orchestrator().status()
    return {
        "source": "live_environment",
        "domains": domain_counts,
        "graph": graph_summary,
        "events": {"events": events, "latest_id": bus.latest_id(), "subscribers": bus.subscriber_count()},
        "scan": orch.get("scan"),
        "runner": orch.get("runner"),
    }
