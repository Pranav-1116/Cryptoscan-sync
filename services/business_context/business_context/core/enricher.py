"""Attach revenue / customer impact to assets and rank them."""

from __future__ import annotations

from typing import Any, Iterable

from graph_engine.core.engine import GraphEngine


def priority_score(
    *,
    revenue_daily: float = 0,
    customer_count: int = 0,
    compliance_fail: bool = False,
    technical_severity: str = "MEDIUM",
) -> float:
    severity = {"CRITICAL": 100, "HIGH": 70, "MEDIUM": 40, "LOW": 15, "INFO": 5}.get(
        str(technical_severity).upper(), 40
    )
    return round(
        float(revenue_daily) * 0.4
        + int(customer_count) * 0.0001
        + (80 if compliance_fail else 0)
        + severity * 0.3,
        2,
    )


def enrich_assets(
    assets: Iterable[dict[str, Any]],
    *,
    systems: Iterable[dict[str, Any]] = (),
    edges: Iterable[dict[str, Any]] = (),
    processes: Iterable[dict[str, Any]] = (),
    owners: Iterable[dict[str, Any]] = (),
) -> list[dict[str, Any]]:
    systems = list(systems)
    graph = GraphEngine().build(systems=systems, assets=assets, edges=edges, processes=processes, owners=owners)
    by_system: dict[str, str] = {}
    for system in systems:
        sid = str(system.get("id") or "")
        for asset_id in system.get("asset_ids") or []:
            by_system[str(asset_id)] = sid
    enriched = []
    for asset in assets:
        payload = dict(asset)
        system_id = payload.get("system_id") or by_system.get(str(payload.get("id") or ""))
        impact = graph.business_impact(system_id or payload.get("id") or "") if system_id else {
            "total_revenue_at_risk": 0,
            "total_customers_at_risk": 0,
            "affected_processes": [],
            "business_owners": [],
            "compliance_scopes": [],
        }
        failing = str(payload.get("compliance_status") or "").upper() == "FAIL"
        score = priority_score(
            revenue_daily=impact.get("total_revenue_at_risk") or 0,
            customer_count=impact.get("total_customers_at_risk") or 0,
            compliance_fail=failing,
            technical_severity="CRITICAL" if failing else "MEDIUM",
        )
        rank = "P0" if score >= 500_000 or failing and (impact.get("total_revenue_at_risk") or 0) > 0 else (
            "P1" if failing else "P2"
        )
        context = {
            "total_revenue_at_risk": impact.get("total_revenue_at_risk") or 0,
            "total_customers_at_risk": impact.get("total_customers_at_risk") or 0,
            "affected_processes": impact.get("affected_processes") or [],
            "business_owners": impact.get("business_owners") or [],
            "compliance_scopes": impact.get("compliance_scopes") or [],
            "priority_score": score,
            "priority": rank,
        }
        extra = dict(payload.get("extra") or {})
        extra["business_context"] = context
        payload["extra"] = extra
        payload["business_context"] = context
        enriched.append(payload)
    enriched.sort(key=lambda row: row["business_context"]["priority_score"], reverse=True)
    return enriched
