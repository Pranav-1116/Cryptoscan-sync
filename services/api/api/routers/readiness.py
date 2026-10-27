"""Tenant-scoped readiness projection.

This endpoint reports current mechanical state and open qualification gaps. It
never upgrades local scanner output into customer/provider/regulated evidence.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from api.dependencies import get_current_user
from api.live_scan.runner import get_live_scan_runner
from api.readiness.assurance import build_readiness_summary

router = APIRouter(prefix="/readiness", tags=["readiness"])


@router.get("/summary")
def readiness_summary(user: str = Depends(get_current_user)) -> dict[str, Any]:
    runner = get_live_scan_runner()
    tenant_id = None
    try:
        from db.tenancy import current_tenant

        tenant_id = current_tenant()
    except (ImportError, RuntimeError):
        pass
    snapshot = runner.snapshot_for_tenant(tenant_id)
    dependency: dict[str, Any] = {"status": "SKIP", "reason": "no persisted cascade projection supplied"}
    if isinstance(snapshot, dict):
        live_cbom = snapshot.get("live_cbom") or {}
        if isinstance(live_cbom, dict):
            graph = live_cbom.get("dependency_graph") or live_cbom.get("dependencies")
            if graph is not None:
                dependency = {
                    "status": "PASS",
                    "edges": len(graph) if isinstance(graph, list) else graph.get("edges", 0) if isinstance(graph, dict) else 0,
                    "unresolved_relationships": (graph.get("unresolved_relationships") or []) if isinstance(graph, dict) else [],
                    "evidence_type": "live_cbom_projection",
                }
    return build_readiness_summary(snapshot, dependency=dependency)
