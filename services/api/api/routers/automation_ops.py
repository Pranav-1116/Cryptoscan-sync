"""Deterministic automation operations (no AI/ML): certificate watch sweep,
sector policy activation, and blast-radius analysis.

* POST /automation/cert-watch          assess live certificates, emit alerts
* GET  /automation/sectors             list activatable regulated sectors
* POST /automation/sectors/{sector}/activate   derive policy config + seed rules
* POST /automation/blast-radius        dependency BFS -> impact layers
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session, require_roles

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/automation", tags=["automation"])

_ADMINS = ("admin", "superadmin", "ciso", "security_analyst")


def _publish(event_type: str, payload: dict) -> None:
    try:
        from api.events.bus import get_event_bus

        get_event_bus().publish(event_type, payload, source="automation")
    except Exception:  # noqa: BLE001
        logger.debug("automation publish skipped", exc_info=True)


# ----------------------------------------------------------------- cert watch
@router.post("/cert-watch")
def cert_watch(db: Session = Depends(get_db_session),
               user: str = Depends(require_roles(*_ADMINS))):
    """Sweep live certificates and emit thresholded expiry/strength alerts.

    Each alert is published as ``certificate.expiring`` (consumed by the
    automation bridge -> certificate playbook). Returns the watch report.
    """
    from db.models.certificate import Certificate
    from automation.watchers.cert_expiry import watch_certificates

    rows = db.execute(select(Certificate).limit(100_000)).scalars().all()
    certs = [{
        "id": r.id,
        "fingerprint_sha256": r.fingerprint_sha256,
        "not_after": r.not_after.isoformat() if r.not_after else None,
        "public_key_algorithm": r.public_key_algorithm,
        "public_key_size": r.public_key_size,
        "is_self_signed": r.is_self_signed,
        "subject": r.subject,
    } for r in rows]

    report = watch_certificates(certs)
    for alert in report.alerts:
        _publish("certificate.expiring", {
            "cert_id": alert["cert_id"],
            "days_remaining": alert["days_remaining"],
            "severity": alert["severity"],
            "state": alert["state"],
            "reasons": alert["reasons"],
        })
    out = report.as_dict()
    out["swept_by"] = user
    out["source"] = "live_certificates"
    return out


# ----------------------------------------------------------------- sectors
@router.get("/sectors")
def list_sectors(user: str = Depends(get_current_user)):
    from automation.sector_activation import available_sectors

    return {"sectors": available_sectors(), "total_count": len(available_sectors())}


class ActivateSectorResult(BaseModel):
    seeded_rule_ids: list[str] = Field(default_factory=list)


@router.post("/sectors/{sector}/activate", status_code=201)
def activate_sector_endpoint(
    sector: str,
    db: Session = Depends(get_db_session),
    user: str = Depends(require_roles(*_ADMINS)),
):
    """Derive the deterministic sector policy configuration and seed its
    safe (recommend-tier) automation rules. Change actions remain approval-gated."""
    from automation.sector_activation import activate_sector
    from automation.rules_engine import AutomationRule, RulesError
    from db.models.automation import AutomationRuleRow

    try:
        act = activate_sector(sector)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    seeded: list[str] = []
    for rdict in act.seed_rules:
        try:
            AutomationRule.from_dict({**rdict, "enabled": True})  # validate
        except RulesError as exc:
            logger.warning("sector_rule_invalid %s: %s", rdict.get("rule_id"), exc)
            continue
        row = db.execute(
            select(AutomationRuleRow).where(AutomationRuleRow.rule_id == rdict["rule_id"])
        ).scalars().first()
        if row is None:
            row = AutomationRuleRow(rule_id=rdict["rule_id"], created_by=user)
            db.add(row)
        row.name = rdict.get("name") or rdict["rule_id"]
        row.when = rdict["when"]
        row.conditions = rdict.get("if") or []
        row.actions = rdict.get("then") or []
        row.severity = str(rdict.get("severity") or "MEDIUM").upper()
        row.enabled = True
        seeded.append(rdict["rule_id"])
    db.commit()
    _publish("automation.sector_activated", {"sector": act.sector, "by": user,
                                             "rules": len(seeded)})
    return {**act.as_dict(), "activated_by": user, "seeded_rule_ids": seeded}


# ----------------------------------------------------------------- blast radius
class BlastBody(BaseModel):
    origin: str
    edges: list[list[str]] = Field(default_factory=list,
                                   description="directed [source, target] dependency edges")
    nodes: dict[str, dict] | None = None
    max_hops: int = Field(default=12, ge=1, le=24)
    use_live: bool = Field(default=True,
                           description="merge edges from the live system_dependencies table")


def _live_dependency_edges(db: Session) -> list[tuple[str, str]]:
    """Materialize directed edges from the live dependency inventory."""
    try:
        from db.models.system_dependency import SystemDependency

        rows = db.execute(select(SystemDependency).limit(200_000)).scalars().all()
        return [(str(r.parent_id), str(r.child_id)) for r in rows]
    except Exception:  # noqa: BLE001
        logger.debug("live dependency edge lookup failed", exc_info=True)
        return []


def _live_system_nodes(db: Session) -> dict[str, dict]:
    """Map live systems to node metadata (type/criticality) for layer classification."""
    try:
        from db.models.system import System

        rows = db.execute(select(System).limit(200_000)).scalars().all()
        nodes: dict[str, dict] = {}
        for r in rows:
            meta: dict = {"name": r.name}
            for attr in ("system_type", "type", "criticality"):
                val = getattr(r, attr, None)
                if val is not None:
                    meta[attr] = val
            # name-based layer hint lets deterministic BFS classify services etc.
            lname = str(r.name or "").lower()
            if "service" in lname:
                meta["type"] = "business_service"
            elif "api" in lname or "gateway" in lname:
                meta["type"] = "api"
            extra = getattr(r, "extra", None) or {}
            if isinstance(extra, dict) and extra.get("type"):
                meta["type"] = extra["type"]
            nodes[str(r.id)] = meta
        return nodes
    except Exception:  # noqa: BLE001
        logger.debug("live system node lookup failed", exc_info=True)
        return {}


@router.post("/blast-radius")
def blast_radius(body: BlastBody, db: Session = Depends(get_db_session),
                 user: str = Depends(get_current_user)):
    """Deterministic downstream impact (certificates/apps/APIs/business services).

    By default merges edges from the live ``system_dependencies`` inventory with
    any explicitly supplied edges; the same graph always yields the same radius.
    """
    from automation.blast_radius import analyze_blast_radius

    edge_set: set[tuple[str, str]] = {
        (str(a), str(b)) for a, b in body.edges if a and b
    }
    live_edges: list[tuple[str, str]] = []
    nodes = dict(body.nodes or {})
    if body.use_live:
        live_edges = _live_dependency_edges(db)
        edge_set.update(live_edges)
        for nid, meta in _live_system_nodes(db).items():
            nodes.setdefault(nid, meta)

    edges = sorted(edge_set)
    result = analyze_blast_radius(body.origin, edges, nodes=nodes,
                                  max_hops=body.max_hops)
    out = result.as_dict()
    out["evaluated_by"] = user
    out["edge_count"] = len(edges)
    out["live_edge_count"] = len(live_edges)
    out["edges_source"] = "live_system_dependencies+posted" if body.use_live else "posted"
    # large blast radius on a critical change is worth an alert (deterministic)
    biz = out["impact_layers"].get("business_service", 0)
    if biz >= 1 or result.reachable >= 10:
        _publish("alert.raised", {
            "event_kind": "blast_radius", "asset_id": body.origin,
            "severity": result.highest_criticality,
            "business_services": result.business_services,
            "reachable_nodes": result.reachable})
    return out


# ----------------------------------------------------------------- live CBOM
class CbomUpdateBody(BaseModel):
    observations: list[dict] = Field(default_factory=list, max_length=200_000)
    use_live: bool = False


def _live_crypto_observations(db: Session) -> list[dict]:
    """Materialize CBOM components from live evidence/crypto-assets."""
    out: list[dict] = []
    try:
        from db.models.evidence_record import EvidenceRecord

        rows = db.execute(select(EvidenceRecord).limit(200_000)).scalars().all()
        for r in rows:
            out.append({
                "component_id": str(getattr(r, "id", "")),
                "algorithm": getattr(r, "algorithm", None),
                "key_size": getattr(r, "key_size", None),
                "mode": None,
                "library": None,
                "library_version": None,
                "file_path": getattr(r, "file_path", None),
            })
    except Exception:  # noqa: BLE001
        logger.debug("live CBOM evidence lookup failed", exc_info=True)
    return out


def cbom_version_tick(db: Session, observations: list[dict] | None = None,
                      user: str = "system-sweep") -> dict:
    """Idempotent CBOM versioning: append a new content-addressed version only
    when the canonicalized component set changed. Shared by the HTTP endpoint
    and the periodic bridge sweep (deterministic; same state -> same result)."""
    from automation.cbom_versioning import _canon_component, _component_key, _state_fingerprint
    from db.models.automation import CbomVersionRow

    if observations is None:
        observations = _live_crypto_observations(db)
    components = [_canon_component(c) for c in observations]
    fingerprint = _state_fingerprint(components)

    prev = db.execute(
        select(CbomVersionRow).order_by(CbomVersionRow.version.desc()).limit(1)
    ).scalars().first()

    if prev is not None and prev.fingerprint == fingerprint:
        return {"changed": False, "version": prev.version, "fingerprint": fingerprint,
                "added": [], "removed": [], "source": "unchanged"}

    prev_comps = {_component_key(c): c for c in (prev.components or [])} if prev else {}
    cur_comps = {_component_key(c): c for c in components}
    added = [c for k, c in sorted(cur_comps.items()) if k not in prev_comps]
    removed = [c for k, c in sorted(prev_comps.items()) if k not in cur_comps]

    new_version = (prev.version + 1) if prev else 1
    row = CbomVersionRow(
        version=new_version, fingerprint=fingerprint,
        parent_fingerprint=prev.fingerprint if prev else None,
        component_count=len(components), components=components,
        added=added, removed=removed, created_by=user,
    )
    db.add(row)
    db.commit()
    db.refresh(row)

    if added:
        _publish("crypto.asset_detected", {"version": new_version,
                                           "added_count": len(added),
                                           "algorithms": sorted({c["algorithm"] for c in added})})
    if removed:
        _publish("drift.detected", {"version": new_version,
                                    "removed_count": len(removed)})
    return {"changed": True, **row.to_dict(), "source": "live_evidence"}


@router.post("/cbom/versions", status_code=201)
def cbom_update(body: CbomUpdateBody,
                db: Session = Depends(get_db_session),
                user: str = Depends(require_roles(*_ADMINS))):
    """Record a new live CBOM version from observations (or live evidence).

    Creates an immutable, content-addressed version only when the canonicalized
    component set changed; returns the added/removed diff. Change events are
    published so the bridge can correlate (crypto_asset_detected / drift).
    """
    observations = body.observations
    if body.use_live or not observations:
        result = cbom_version_tick(db, observations=None, user=user)
    else:
        result = cbom_version_tick(db, observations=observations, user=user)
        result["source"] = "posted" if result.get("changed") else result.get("source")
    return result


@router.get("/cbom/versions")
def cbom_history(limit: int = 20, db: Session = Depends(get_db_session),
                 user: str = Depends(get_current_user)):
    from db.models.automation import CbomVersionRow

    rows = db.execute(
        select(CbomVersionRow).order_by(CbomVersionRow.version.desc()).limit(min(limit, 200))
    ).scalars().all()
    return {"versions": [r.to_dict() for r in rows], "total_count": len(rows),
            "latest_version": rows[0].version if rows else 0}


# ----------------------------------------------------------------- risk
class RiskBody(BaseModel):
    assets: dict[str, dict] = Field(default_factory=dict)
    edges: list[list[str]] = Field(default_factory=list,
                                   description="directed caller->callee dependency edges")
    changed_assets: list[str] = Field(default_factory=list)


@router.post("/risk/recalculate")
def risk_recalculate(body: RiskBody, user: str = Depends(get_current_user)):
    """Recalculate asset risk and propagate it up the dependency chain.

    A vulnerable library lifts the application that embeds it, which lifts the
    business service that consumes it (sections 8/12). Pure deterministic
    arithmetic; same inputs -> same scores.
    """
    from automation.risk import recalculate as _recalc

    edges = [(str(a), str(b)) for a, b in body.edges]
    result = _recalc(body.assets, edges, changed_assets=body.changed_assets or None)
    out = result.as_dict()
    out["evaluated_by"] = user
    if result.affected_business_services:
        _publish("alert.raised", {
            "event_kind": "risk_recalculated",
            "business_services": result.affected_business_services,
            "max_band": out["max_band"], "max_score": out["max_score"]})
    return out


# ----------------------------------------------------------------- health
@router.post("/health/sweep")
def health_sweep(db: Session = Depends(get_db_session),
                 user: str = Depends(require_roles(*_ADMINS))):
    """Assess live connectors and agent fleet; raise operational alerts.

    Emits connector_failed / agent_offline events for unhealthy targets
    (consumed by the automation bridge) and returns the full health report.
    """
    from automation.health import watch_agents, watch_connectors

    connectors = []
    try:
        from db.models.onboarding import Connector

        for c in db.execute(select(Connector).limit(10_000)).scalars():
            connectors.append({
                "id": c.id, "name": c.name, "kind": c.kind, "status": c.status,
                "agent_link": c.agent_link, "agent_healthy": c.agent_healthy,
                "last_tested_at": c.last_tested_at,
                "agent_last_seen_at": c.agent_last_seen_at.isoformat()
                if c.agent_last_seen_at else None,
                "test_result": c.test_result,
            })
    except Exception:  # noqa: BLE001
        logger.debug("connector health sweep lookup failed", exc_info=True)

    agents = []
    try:
        from db.models.control_plane import Agent

        for a in db.execute(select(Agent).limit(10_000)).scalars():
            agents.append({
                "id": a.id, "name": a.name, "status": a.status, "link": a.link,
                "version": a.version, "target_version": a.target_version,
                "healthy": a.healthy,
                "last_heartbeat_at": a.last_heartbeat_at.isoformat()
                if a.last_heartbeat_at else None,
            })
    except Exception:  # noqa: BLE001
        logger.debug("agent health sweep lookup failed", exc_info=True)

    conn_report = watch_connectors(connectors)
    agent_report = watch_agents(agents)

    for a in conn_report.alerts:
        _publish("connector_failed" if a.kind == "connector" else "alert.raised", {
            "target_id": a.target_id, "state": a.state.value, "reasons": a.reasons})
        _publish("alert.raised", {"event_kind": "connector_failed",
                                  "asset_id": a.target_id, "severity": a.severity.value,
                                  "reasons": a.reasons})
    for a in agent_report.alerts:
        _publish("agent_offline", {"target_id": a.target_id, "state": a.state.value,
                                    "reasons": a.reasons})

    return {
        "swept_by": user,
        "connectors": conn_report.as_dict(),
        "agents": agent_report.as_dict(),
        "alert_count": conn_report.alert_count + agent_report.alert_count,
    }


# ----------------------------------------------------------------- post-migration
class PostMigrationBody(BaseModel):
    system_id: str | None = None
    migration_project_id: str | None = None
    pre_findings: list[dict] = Field(default_factory=list, max_length=200_000)
    post_findings: list[dict] = Field(default_factory=list, max_length=200_000)
    pre_covered_assets: list[str] = Field(default_factory=list)
    post_covered_assets: list[str] = Field(default_factory=list)


@router.post("/post-migration/validate", status_code=201)
def post_migration_validate(body: PostMigrationBody,
                            db: Session = Depends(get_db_session),
                            user: str = Depends(require_roles(*_ADMINS))):
    """DETECT -> ANALYZE -> VERIFY: after a migration, re-scan and verify the
    crypto state deterministically.

    Uses the governance migration validator (no AI). PASS => zero regressions:
    emits remediation closure events (findings to close). FAIL => regressions
    found: raises a critical alert + ticket (never auto-closes on failure).
    """
    from governance.migration_validate import MigrationSnapshot, validate_migration

    pre = MigrationSnapshot.from_findings(body.pre_findings,
                                          set(body.pre_covered_assets or []))
    post = MigrationSnapshot.from_findings(body.post_findings,
                                           set(body.post_covered_assets or []))
    result = validate_migration(pre, post)
    passed = bool(result.passed)

    if passed:
        # closure: each remediated finding can be auto-recommended for closure
        # (recommend-tier; closing production tickets stays approval-gated).
        _publish("alert.raised", {
            "event_kind": "migration_validated", "asset_id": body.system_id,
            "severity": "INFO",
            "remediated": len(result.remediated),
            "detail": f"migration verified: {len(result.remediated)} weak finding(s) remediated"})
        for rem in result.remediated:
            _publish("remediation.verified", {
                "asset_id": body.system_id, "finding_key": rem.get("key"),
                "algorithm": rem.get("algorithm")})
    else:
        _publish("alert.raised", {
            "event_kind": "migration_regression", "asset_id": body.system_id,
            "severity": "CRITICAL",
            "regressions": result.regressions,
            "detail": f"migration FAILED with {len(result.regressions)} regression(s)"})
        _publish("ticket.requested", {
            "asset_id": body.system_id, "event_kind": "migration_regression",
            "severity": "CRITICAL", "regressions": result.regressions})

    out = result.as_dict()
    out["system_id"] = body.system_id
    out["migration_project_id"] = body.migration_project_id
    out["validated_by"] = user
    out["action"] = "PASS: remediated findings cleared" if passed else \
        "FAIL: regressions reopened; critical alert raised"
    return out


class PlatformHealthBody(BaseModel):
    metrics: dict[str, float] = Field(default_factory=dict)


@router.post("/health/platform")
def platform_health(body: PlatformHealthBody,
                    user: str = Depends(get_current_user)):
    """Classify self-monitoring metrics (API/worker/queue/event/scanner) vs SLOs."""
    from automation.health import watch_platform

    report = watch_platform(body.metrics)
    for a in report.alerts:
        _publish("alert.raised", {"event_kind": "self_monitoring",
                                  "asset_id": a.target_id, "severity": a.severity.value,
                                  "metric": a.target_id, "reasons": a.reasons})
    out = report.as_dict()
    out["evaluated_by"] = user
    return out
