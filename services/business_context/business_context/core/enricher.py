"""Attach revenue / customer impact to assets and rank them."""

from __future__ import annotations

from typing import Any, Iterable

from business_context.aggregators.metrics import (
    min_sla,
    sum_customers,
    sum_revenue,
    sum_transactions,
    union_classifications,
    union_scopes,
)
from business_context.prioritization.scorer import priority_label, priority_score, rank_assets
from graph_engine.core.engine import GraphEngine

__all__ = ["enrich_assets", "priority_score"]


def enrich_assets(
    assets: Iterable[dict[str, Any]],
    *,
    systems: Iterable[dict[str, Any]] = (),
    edges: Iterable[dict[str, Any]] = (),
    processes: Iterable[dict[str, Any]] = (),
    owners: Iterable[dict[str, Any]] = (),
) -> list[dict[str, Any]]:
    systems = list(systems)
    processes = list(processes)
    graph = GraphEngine().build(
        systems=systems, assets=assets, edges=edges, processes=processes, owners=owners
    )
    by_system: dict[str, str] = {}
    for system in systems:
        sid = str(system.get("id") or "")
        for asset_id in system.get("asset_ids") or []:
            by_system[str(asset_id)] = sid
    enriched = []
    for asset in assets:
        payload = dict(asset)
        system_id = payload.get("system_id") or by_system.get(str(payload.get("id") or ""))
        impact = (
            graph.business_impact(system_id or payload.get("id") or "")
            if system_id
            else {
                "total_revenue_at_risk": 0,
                "total_customers_at_risk": 0,
                "affected_processes": [],
                "business_owners": [],
                "compliance_scopes": [],
            }
        )
        related_processes = [
            proc
            for proc in processes
            if proc.get("name") in (impact.get("affected_processes") or [])
            or system_id in (proc.get("system_ids") or [])
        ]
        related_systems = [sys for sys in systems if str(sys.get("id")) == str(system_id)]
        revenue = impact.get("total_revenue_at_risk") or sum_revenue(related_processes)
        customers = impact.get("total_customers_at_risk") or sum_customers(related_processes)
        failing = str(payload.get("compliance_status") or "").upper() == "FAIL"
        score = priority_score(
            revenue_daily=revenue or 0,
            customer_count=customers or 0,
            compliance_fail=failing,
            technical_severity="CRITICAL" if failing else "MEDIUM",
        )
        context = {
            "total_revenue_at_risk": revenue or 0,
            "total_customers_at_risk": customers or 0,
            "total_transaction_volume": sum_transactions(related_processes),
            "min_sla_uptime": min_sla(related_processes),
            "affected_processes": impact.get("affected_processes") or [p.get("name") for p in related_processes],
            "business_owners": impact.get("business_owners") or [],
            "compliance_scopes": impact.get("compliance_scopes") or union_scopes(related_systems),
            "data_classifications": union_classifications(related_processes),
            "priority_score": score,
            "priority": priority_label(score, compliance_fail=failing, revenue_daily=float(revenue or 0)),
        }
        extra = dict(payload.get("extra") or {})
        extra["business_context"] = context
        payload["extra"] = extra
        payload["business_context"] = context
        enriched.append(payload)
    return rank_assets(enriched)
