"""Remediation prioritization API — the ranked work queue.

`GET /api/v1/priority` folds OPEN drift events and runtime findings through
the deterministic correlation engine (revenue x severity x agility) using:
- business-process revenue bands (revenue_daily / customer_count) when the
  system is mapped to processes,
- the system's 6-factor agility score when calculated,
- the system dependency graph for BFS blast radius,
- the replacement rule table + migration plan templates.

Everything comes from platform tables — empty estate yields an empty ranked
list. No AI, no invented numbers.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from api.dependencies import get_current_user, get_db_session

router = APIRouter(prefix="/priority", tags=["priority"])


class RankedItem(BaseModel):
    rank: int
    ref_id: str | None = None
    source: str
    kind: str
    severity_in: str
    priority: float
    effort: float
    explanation: str
    replacement: dict | None = None
    plan: dict | None = None
    correlated: list[str] = []


class PriorityResponse(BaseModel):
    ranked: list[RankedItem]
    counts_by_severity: dict[str, int]
    coverage: dict


@router.get("", response_model=PriorityResponse)
def remediation_priority(
    limit: int = Query(50, ge=1, le=500),
    profile: str = Query("default", pattern="^[a-z0-9_-]{1,40}$"),
    user: str = Depends(get_current_user),
    db=Depends(get_db_session),
):
    from correlation.priority import (
        agility_fraction,
        build_input,
        counts_by_severity,
        prioritize,
        revenue_tier,
    )

    from db.models.business_process import BusinessProcess
    from db.models.drift_event import DriftEvent
    from db.models.runtime_finding import RuntimeFinding
    from db.models.system import System
    from db.models.system_agility_score import SystemAgilityScore
    from db.models.system_business_process import SystemBusinessProcess
    from db.models.system_dependency import SystemDependency

    # ---- context: graph, agility, revenue bands (all real tables) --------
    system_names: dict[str, str] = {s.id: s.name for s in db.query(System).all()}

    # blast-radius graph keyed by system NAME (findings target names)
    graph: dict[str, list[str]] = {}
    for edge in db.query(SystemDependency).all():
        parent = system_names.get(edge.parent_id, edge.parent_id)
        child = system_names.get(edge.child_id, edge.child_id)
        graph.setdefault(parent, []).append(child)

    agility_by_system: dict[str, float] = {}
    for row in db.query(SystemAgilityScore).all():
        agility_by_system[row.system_id] = agility_fraction(row.agility_score)

    revenue_by_system: dict[str, int] = {}
    owner_process_ids: set[str] = set()
    for mapping in db.query(SystemBusinessProcess).all():
        owner_process_ids.add(mapping.process_id)
    processes = {p.id: p for p in db.query(BusinessProcess).all()}
    for mapping in db.query(SystemBusinessProcess).all():
        proc = processes.get(mapping.process_id)
        if proc is None:
            continue
        tier = revenue_tier(proc.revenue_daily, proc.customer_count)
        current = revenue_by_system.get(mapping.system_id)
        if current is None or tier > current:
            revenue_by_system[mapping.system_id] = tier

    # ---- collect open drift events ---------------------------------------
    events: list[dict[str, Any]] = []
    sources_seen = {"drift": 0, "runtime": 0}
    for de in (
        db.query(DriftEvent)
        .filter(DriftEvent.resolution_status == "OPEN")
        .order_by(DriftEvent.severity.desc(), DriftEvent.detected_at.desc())
        .limit(limit * 2)
        .all()
    ):
        details = de.drift_details or {}
        target = str(details.get("target") or details.get("system_id") or de.id)
        system_id = details.get("system_id") if isinstance(details.get("system_id"), str) else None
        events.append(build_input(
            kind=str(de.drift_type or "drift"),
            severity=str(de.severity or "MEDIUM"),
            target=system_names.get(system_id, target) if system_id else target,
            evidence=str(details.get("summary") or details.get("reason") or de.drift_type),
            algorithm=details.get("algorithm"),
            revenue_impact=revenue_by_system.get(system_id or "", 3),
            agility=agility_by_system.get(system_id or "", 0.5),
        ) | {"ref_id": de.id, "source": "drift"})
        sources_seen["drift"] += 1

    # ---- runtime findings with registry verdicts --------------------------
    weak_statuses = {"RISK", "DISALLOWED", "DEPRECATED"}
    for rf in (
        db.query(RuntimeFinding)
        .filter(RuntimeFinding.weak_tls.is_(True) |
                (RuntimeFinding.status.in_(weak_statuses)))
        .order_by(RuntimeFinding.last_seen_at.desc())
        .limit(limit * 2)
        .all()
    ):
        events.append(build_input(
            kind="runtime_finding",
            severity="HIGH" if rf.weak_tls else "MEDIUM",
            target=rf.hostname or rf.scanner_id,
            evidence=f"{rf.process_name or 'process'}: {rf.algorithm or rf.cipher_suite or 'weak TLS'}"
                     f" (x{rf.observation_count})",
            algorithm=rf.algorithm,
            revenue_impact=3,
            agility=0.5,
        ) | {"ref_id": rf.id, "source": "runtime"})
        sources_seen["runtime"] += 1

    ranked = prioritize(events, graph=graph, profile=profile)[:limit]
    coverage = {
        "open_drift_events": sources_seen["drift"],
        "runtime_findings": sources_seen["runtime"],
        "systems_with_agility": len(agility_by_system),
        "systems_with_revenue_mapping": len(revenue_by_system),
        "graph_edges": sum(len(v) for v in graph.values()),
        "processes_linked": len(owner_process_ids & set(processes)),
        "profile": profile,
    }
    return PriorityResponse(
        ranked=[RankedItem(
            rank=r["rank"], ref_id=r.get("ref_id"), source=r["source"],
            kind=r["kind"], severity_in=r["severity_in"],
            priority=r["priority"], effort=r["effort"],
            explanation=r["explanation"], replacement=r.get("replacement"),
            plan=r.get("plan"), correlated=r.get("correlated") or [],
        ) for r in ranked],
        counts_by_severity=counts_by_severity(ranked),
        coverage=coverage,
    )
