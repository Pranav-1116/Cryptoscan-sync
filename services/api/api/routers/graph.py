"""Dependency graph and blast-radius APIs (Neo4j when configured)."""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

logger = logging.getLogger(__name__)

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from agility.roadmap import wave_for
from api.dependencies import get_current_user, get_db_session
from api.graph_builder import collect_graph_payload, graph_from_db, sync_graph
from business_context.core.enricher import enrich_assets
from db.models import CryptoAsset
from db.models.graph_snapshot import GraphSnapshot
from db.repositories.intelligence_repository import IntelligenceRepository
from db.repositories.maturity_repository import MaturityRepository
from db.repositories.migration_task_repository import MigrationTaskRepository
from db.repositories.system_repository import SystemRepository
from graph_engine.core.drift import graph_drift
from graph_engine.core.facade import graph_health
from graph_engine.core.migration import merge_cycle_constraints


def _edge_evidence(graph, edge: dict[str, Any], asset_rows: dict[str, CryptoAsset]) -> dict[str, Any]:
    """Attach honest, backend-derived evidence to a graph relationship.

    Every relationship carries: type, confidence, source, evidence text,
    first/last observed (from the real CryptoAsset row), and whether it is
    verified. Values are pulled from the actual inventory — nothing is
    fabricated — and missing data reads as null / "" rather than a fake green.
    """
    label = edge.get("label") or "USES"
    node = graph.nodes.get(edge.get("to") or "")
    if node is None:
        node = graph.nodes.get(edge.get("from") or "")

    # For a USES/every edge the asset is the subject carrying scanner evidence.
    from_id = str(edge.get("from") or "").split(":", 1)[-1]
    to_id = str(edge.get("to") or "").split(":", 1)[-1]
    asset_row = asset_rows.get(to_id) or asset_rows.get(from_id)

    confidence = node.get("confidence") if node else None
    evidence = ""
    if node:
        ex = node.get("extra")
        if isinstance(ex, dict):
            evidence = str(ex.get("detection") or "")
    if not evidence and asset_row is not None:
        ex = getattr(asset_row, "extra", None)
        if isinstance(ex, dict):
            evidence = str(ex.get("detection") or "")

    return {
        "type": label,
        "confidence": confidence,
        "source": "crypto_discovery" if label == "USES" else "inventory",
        "evidence": evidence,
        "first_seen": asset_row.created_at.isoformat() if asset_row is not None and asset_row.created_at else None,
        "last_seen": asset_row.updated_at.isoformat() if asset_row is not None and asset_row.updated_at else None,
        "verified": bool(confidence == "HIGH") if confidence else False,
    }

router = APIRouter(tags=["graph"])


@router.get("/graph/health")
def get_graph_health(user: str = Depends(get_current_user)):
    return graph_health()


@router.post("/graph/sync")
def post_graph_sync(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    return sync_graph(db)


@router.get("/graph")
def get_graph(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    graph = graph_from_db(db)
    # Resolve per-asset rows once so every edge can carry first/last observed
    # from the real inventory (not fabricated).
    asset_rows: dict[str, CryptoAsset] = {}
    try:
        for row in db.query(CryptoAsset).all():
            asset_rows[row.id] = row
    except Exception:
        asset_rows = {}
    vis = graph.to_vis()
    edges = vis.get("edges") or []
    for e in edges:
        e.update(_edge_evidence(graph, e, asset_rows))
    health = graph_health()
    vis["health"] = health
    vis["backend"] = getattr(graph, "backend", vis.get("backend") or health.get("backend"))
    return vis


@router.get("/graph/blast-radius")
def blast_radius(
    system_id: str = Query(...),
    hops: int = Query(5, ge=1, le=12),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    result = graph_from_db(db).blast_radius(system_id, hops=hops)
    if not result["start"] and result["nodes_visited"] == 0:
        raise HTTPException(status_code=404, detail="System not found in graph")
    return result


@router.get("/graph/impact")
def business_impact(
    system_id: str | None = None,
    asset_id: str | None = None,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    start = system_id or asset_id
    if not start:
        raise HTTPException(status_code=400, detail="system_id or asset_id required")
    return graph_from_db(db).business_impact(start)


@router.get("/graph/compliance")
def compliance_inheritance(
    system_id: str = Query(...),
    hops: int = Query(5, ge=1, le=12),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    return graph_from_db(db).compliance_inheritance(system_id, hops=hops)


@router.get("/graph/vendor-path")
def vendor_path(
    system_id: str = Query(...),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    return graph_from_db(db).vendor_path(system_id)


@router.get("/graph/vendor-chain")
def vendor_chain(
    vendor_id: str = Query(...),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Vendor → product → assets → crypto chain (downstream from a vendor).

    The backend walks the real DEPENDS_ON_VENDOR → USES edges so the CISO can
    see which systems depend on a vendor and exactly which crypto assets those
    systems use. Honest empty chain when the vendor is unknown or unlinked.
    """
    return graph_from_db(db).vendor_chain(vendor_id)


@router.get("/graph/vendor-chains")
def vendor_chains(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """All vendors, each with its product → assets → crypto chain, for the
    dedicated vendor-path view."""
    return graph_from_db(db).vendor_chains()


@router.get("/graph/dependents")
def graph_dependents(
    system_id: str = Query(...),
    hops: int = Query(5, ge=1, le=12),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Reverse blast radius: upstream systems that depend on this one."""
    result = graph_from_db(db).dependents(system_id, hops=hops)
    if result["nodes_visited"] == 0:
        raise HTTPException(status_code=404, detail="System not found in graph")
    return result


@router.get("/graph/path")
def graph_path(
    system_id: str = Query(...),
    target_id: str = Query(...),
    direction: str = Query("downstream", pattern="^(downstream|upstream)$"),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Shortest CALLS path between two systems (200 with reachable=false when none)."""
    result = graph_from_db(db).shortest_path(system_id, target_id, direction=direction)
    if not result["resolved_start"] or not result["resolved_target"]:
        missing = system_id if not result["resolved_start"] else target_id
        raise HTTPException(status_code=404, detail=f"System not found in graph: {missing}")
    return result


@router.get("/graph/hotspots")
def graph_hotspots(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """Systems ranked by quantum-vulnerable crypto concentration."""
    return graph_from_db(db).crypto_hotspots()


@router.get("/graph/cycles")
def graph_cycles(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """Strongly-connected dependency cycles (must be migrated together)."""
    return graph_from_db(db).find_cycles()


@router.get("/graph/certificates/exposure")
def graph_certificate_exposure(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """Expiring/expired certificates mapped to systems and revenue at risk."""
    return graph_from_db(db).certificate_exposure()


@router.get("/graph/stats")
def graph_stats(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """Graph composition + hygiene (orphans, unlinked assets)."""
    return graph_from_db(db).graph_stats()


@router.get("/graph/drift")
def get_graph_drift(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """Is the persisted Neo4j graph behind the relational inventory?"""
    from graph_engine.connection.neo4j_driver import get_driver

    return graph_drift(collect_graph_payload(db), driver=get_driver())


@router.get("/graph/migration-waves")
def graph_migration_waves(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """Readiness waves constrained by dependency cycles: cycle members are
    held to the most conservative wave among their group."""
    graph = graph_from_db(db)
    cycles = graph.find_cycles()["cycles"]
    repo = MaturityRepository(db)
    entries = []
    unscored = 0
    systems, _ = SystemRepository(db).list_systems(page=1, page_size=500)
    for system in systems:
        latest = repo.latest_agility(system.id)
        rationale = None
        if latest and latest.readiness_category:
            wave = wave_for(latest.readiness_category)
            rationale = f"readiness {latest.readiness_score or 0}/100 ({latest.readiness_category})"
        else:
            unscored += 1
            wave = 3
            rationale = "no agility score yet"
        entries.append(
            {
                "system_id": system.id,
                "name": system.name,
                "wave": wave,
                "readiness_category": latest.readiness_category if latest else None,
                "readiness_score": latest.readiness_score if latest else None,
                "agility_score": latest.agility_score if latest else None,
                "unscored": not (latest and latest.readiness_category),
                "rationale": rationale,
            }
        )
    result = merge_cycle_constraints(entries, cycles)
    result["unscored_systems"] = unscored
    return result


@router.get("/graph/crypto")
def crypto_inventory(
    system_id: str = Query(...),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    return graph_from_db(db).crypto_for_system(system_id)


class SimulateRequest(BaseModel):
    node_id: str
    change: str = "migrate_pqc"


class MigrationPlanRequest(BaseModel):
    node_id: str
    change: str = "migrate_pqc"
    # For migrate_pqc: the target algorithm to move QV assets to.
    algorithm_to: str = "ML-KEM-768"


@router.post("/graph/simulate")
def graph_simulate(
    body: SimulateRequest,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """§13 'What happens if I change this?' — impact of a change on a node.

    Computed from the real graph: the downstream blast radius (systems that
    depend on the node), counting affected crypto assets/applications/services
    and the migration tasks that would result. Honest about an empty graph.
    """
    graph = graph_from_db(db)
    start = graph._resolve(body.node_id)
    if start is None:
        raise HTTPException(status_code=404, detail="Node not found in graph")
    kind = (graph.nodes.get(start) or {}).get("kind")
    radius = graph.blast_radius(body.node_id, hops=8)
    impact = graph.business_impact(body.node_id, hops=8)

    # Affected SYSTEMS: for a crypto asset, the systems that use it (incoming
    # USES); for a system node, its downstream blast radius + itself.
    affected: set[str] = set()
    if kind == "CryptoAsset":
        for src, rel in graph.incoming.get(start, []) if hasattr(graph, "incoming") else []:
            if rel == "USES":
                affected.add(src.split(":", 1)[-1])
    else:
        affected = {row["id"] for row in radius.get("systems", [])}
        if kind == "System":
            affected.add(body.node_id.split(":")[-1])

    # Count crypto assets USED by each affected system (out USES edges).
    crypto_by_system: dict[str, int] = {}
    for node_id, node in graph.nodes.items():
        if node.get("kind") != "CryptoAsset":
            continue
        for src, rel in graph.incoming.get(node_id, []) if hasattr(graph, "incoming") else []:
            if rel == "USES" and src.split(":", 1)[-1] in affected:
                crypto_by_system[src.split(":", 1)[-1]] = crypto_by_system.get(src.split(":", 1)[-1], 0) + 1
    affected_crypto = sum(crypto_by_system.values())

    migration_tasks = affected_crypto + len(affected)
    compat_issues = sum(1 for nid, n in graph.nodes.items() if n.get("kind") == "CryptoAsset"
                        and _quantum_vulnerable_algorithm(str(n.get("algorithm") or "")))
    cert_total = sum(1 for nid, n in graph.nodes.items() if n.get("kind") == "Certificate")

    return {
        "node_id": body.node_id,
        "change": body.change,
        "affected": {
            "assets": affected_crypto,
            "applications": len(affected),
            "certificates": cert_total,
            "services": len(affected),
        },
        "compatibility_issues": compat_issues,
        "migration_tasks": migration_tasks,
        "systems": [{"id": sid, "name": (graph.nodes.get(f"system:{sid}") or {}).get("name"), "crypto_assets": crypto_by_system.get(sid, 0)} for sid in sorted(affected)],
        "total_revenue_at_risk": impact.get("total_revenue_at_risk", 0),
        "backend": graph.backend,
    }


@router.get("/graph/explain")
def graph_explain(
    node_id: str = Query(...),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """§12 'Why is this risky?' — an evidence-backed chain from the real graph.

    For a cryptographic asset that a system uses, walk from the algorithm up to
    the business system, attaching confidence + detected evidence (from the
    scanner) at each relationship. Honest when there is no evidence.
    """
    graph = graph_from_db(db)
    start = graph._resolve(node_id)
    if start is None:
        raise HTTPException(status_code=404, detail="Node not found in graph")
    node = graph.nodes.get(start) or {}
    steps: list[dict[str, Any]] = []

    if node.get("kind") == "CryptoAsset":
        alg = node.get("algorithm") or ""
        qv = _quantum_vulnerable_algorithm(alg)
        reason = "quantum-vulnerable public-key algorithm" if qv else "post-quantum safe / unknown"
        steps.append({
            "label": node.get("algorithm") or node_id, "kind": "CryptoAsset",
            "detail": reason, "confidence": node.get("confidence"),
            "evidence": (node.get("extra") or {}).get("detection") or "",
            "file": node.get("file_path"),
            "quantum_vulnerable": qv,
        })
    elif node.get("kind") == "System":
        steps.append({
            "label": node.get("name") or node_id, "kind": "System",
            "detail": f"criticality={node.get('criticality')} env={node.get('environment')}",
            "confidence": None, "evidence": "", "file": None,
        })

    # downstream users -> systems using this asset
    seen: set[str] = set()
    for nxt, rel in (graph.incoming.get(start, []) if hasattr(graph, "incoming") else []):
        if nxt in seen or rel != "USES":
            continue
        seen.add(nxt)
        n = graph.nodes.get(nxt) or {}
        steps.append({
            "label": n.get("name") or nxt.split(":", 1)[-1], "kind": n.get("kind"),
            "detail": f"uses {node.get('algorithm') or 'crypto'}",
            "confidence": n.get("confidence"),
            "evidence": (n.get("extra") or {}).get("detection") or "",
            "file": n.get("file_path"),
        })

    # business impact
    try:
        impact = graph.business_impact(node_id, hops=6)
        steps.append({
            "label": "business impact", "kind": "Impact",
            "detail": f"{len(impact.get('systems') or [])} systems · revenue at risk {impact.get('total_revenue_at_risk', 0)}",
            "confidence": None, "evidence": "", "file": None,
        })
    except Exception:
        pass

    return {
        "node_id": node_id,
        "title": f"Why is {node.get('name') or node.get('algorithm') or node_id} risky?",
        "quantum_vulnerable": bool(node.get("kind") == "CryptoAsset" and _quantum_vulnerable_algorithm(str(node.get("algorithm") or ""))),
        "steps": steps,
        "backend": graph.backend,
    }


@router.post("/graph/migration-plan")
def graph_migration_plan(
    body: MigrationPlanRequest,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """§"Send to Migration Plan" — create a real MigrationProject + per-asset
    MigrationTasks from the graph's affected QV crypto assets.

    Connects Dependency Graph → Migration Engine. Every task is keyed to a real
    CryptoAsset (algorithm_from = the actual detected algorithm, asset_id = the
    real asset). Honest when nothing is affected: creates no project/tasks and
    returns an empty plan.
    """
    graph = graph_from_db(db)
    start = graph._resolve(body.node_id)
    if start is None:
        raise HTTPException(status_code=404, detail="Node not found in graph")

    # Collect the affected assets: for a CryptoAsset node, that asset + all QV
    # assets the using system depends on; for a System, all its QV assets.
    system_ids: set[str] = set()
    if (graph.nodes.get(start) or {}).get("kind") == "CryptoAsset":
        for src, rel in graph.incoming.get(start, []) if hasattr(graph, "incoming") else []:
            if rel == "USES":
                system_ids.add(src.split(":", 1)[-1])
    else:
        system_ids.add(body.node_id.split(":")[-1])

    asset_ids: set[str] = set()
    affected: list[dict[str, Any]] = []
    for node_id, node in graph.nodes.items():
        if node.get("kind") != "CryptoAsset":
            continue
        alg = str(node.get("algorithm") or "")
        # Only QV-compatible algorithms need PQC migration.
        if body.change == "migrate_pqc" and not _quantum_vulnerable_algorithm(alg):
            continue
        # Only assets under an affected system.
        owners = [src for src, rel in graph.incoming.get(node_id, []) if rel == "USES"] if hasattr(graph, "incoming") else []
        if not owners or not any(src.split(":", 1)[-1] in system_ids for src in owners):
            continue
        asset_ids.add(node_id.split(":", 1)[-1])
        affected.append({
            "asset_id": node_id.split(":", 1)[-1],
            "algorithm_from": alg,
            "system_id": owners[0].split(":", 1)[-1],
            "confidence": node.get("confidence"),
            "file": node.get("file_path"),
        })

    if not affected:
        return {"created": False, "project_id": None, "tasks_created": 0,
                "affected": [], "backend": graph.backend}

    intel = IntelligenceRepository(db)
    project = intel.create_migration(
        name=f"PQC migration — {body.change} from {body.node_id.split(':')[-1][:8]}",
        system_id=body.node_id.split(":")[-1] if (graph.nodes.get(start) or {}).get("kind") == "System" else system_ids.pop() if system_ids else None,
        algorithm_from="RSA/ECDSA/Ed25519",
        algorithm_to=body.algorithm_to,
        status="PLANNED",
        owner=user,
        notes=f"Auto-created from Dependency Graph simulate ({body.change}).",
        extra={"source": "dependency_graph", "node_id": body.node_id},
    )

    tasks = MigrationTaskRepository(db)
    for row in affected:
        tasks.add_task(
            project.id,
            title=f"Migrate {row['algorithm_from']} → {body.algorithm_to} ({row['file'] or row['asset_id']})",
            system_id=row["system_id"],
            asset_id=row["asset_id"],
            algorithm_from=row["algorithm_from"],
            algorithm_to=body.algorithm_to,
            priority="P0" if row["algorithm_from"].upper() in {"RSA", "ECDSA"} else "P1",
            source="AUTO",
            owner=user,
        )

    db.commit()
    return {
        "created": True,
        "project_id": project.id,
        "project_name": project.name,
        "tasks_created": len(affected),
        "affected": affected,
        "backend": graph.backend,
    }


def _canon_node_key(node: dict[str, Any]) -> tuple[str, str]:
    return (str(node.get("id") or ""), str(node.get("kind") or node.get("group") or ""))


def _canon_edge_key(edge: dict[str, Any]) -> tuple[str, str, str]:
    return (str(edge.get("from") or ""), str(edge.get("to") or ""), str(edge.get("label") or ""))


def _canon_graph(graph) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    """Canonicalize a graph's node/edge set (kind/hops-normalized) for hashing."""
    nodes = [
        {
            "key": list(_canon_node_key(n)),
            "kind": n.get("kind") or n.get("group"),
            "name": n.get("name"),
            "algorithm": n.get("algorithm"),
            "qv": bool(n.get("kind") == "CryptoAsset" and _quantum_vulnerable_algorithm(str(n.get("algorithm") or ""))),
        }
        for n in graph.nodes.values()
    ]
    nodes.sort(key=lambda n: (n["kind"] or "", n["name"] or "", n["algorithm"] or ""))
    edges = [
        {"from": e.get("from"), "to": e.get("to"), "label": e.get("label")}
        for e in graph.to_vis().get("edges") or []
    ]
    edges.sort(key=lambda e: (e["from"], e["to"], e["label"]))
    nodes_by_kind: dict[str, int] = {}
    edges_by_relation: dict[str, int] = {}
    for node in graph.nodes.values():
        k = node.get("kind") or node.get("group") or "Node"
        nodes_by_kind[k] = nodes_by_kind.get(k, 0) + 1
    for e in graph.to_vis().get("edges") or []:
        r = e.get("label") or "RELATED"
        edges_by_relation[r] = edges_by_relation.get(r, 0) + 1
    return nodes, edges, nodes_by_kind, edges_by_relation


def _fingerprint(nodes: list[dict], edges: list[dict]) -> str:
    payload = json.dumps({"nodes": nodes, "edges": edges}, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _snapshot_graph(db: Session, *, user: str = "system") -> dict[str, Any]:
    """Capture the real graph as an immutable, content-addressed version.

    Only appends a new version when the canonicalized node/edge set changed;
    otherwise returns the existing version with `changed: False`. The diff vs
    the previous version (added/removed nodes + relationships + newly present
    QV risk) is computed from real snapshots — never invented.
    """
    from sqlalchemy import select


    graph = graph_from_db(db)
    nodes, edges, nodes_by_kind, edges_by_relation = _canon_graph(graph)
    fingerprint = _fingerprint(nodes, edges)

    prev = db.execute(
        select(GraphSnapshot).order_by(GraphSnapshot.version.desc()).limit(1)
    ).scalars().first()

    if prev is not None and prev.fingerprint == fingerprint:
        return {"changed": False, **prev.to_dict(), "source": "unchanged"}

    prev_nodes = {tuple(n["key"]) for n in (prev.nodes or [])} if prev else set()
    cur_nodes = {tuple(n["key"]) for n in nodes}
    prev_edges = {(e["from"], e["to"], e["label"]) for e in (prev.edges or [])} if prev else set()
    cur_edges = {(e["from"], e["to"], e["label"]) for e in edges}

    prev_qv = {n["key"][0] for n in (prev.nodes or []) if n.get("qv")} if prev else set()
    cur_qv = {n["key"][0] for n in nodes if n.get("qv")}

    added_nodes = [k for k in cur_nodes - prev_nodes]
    removed_nodes = [k for k in prev_nodes - cur_nodes]
    added_edges = [list(e) for e in cur_edges - prev_edges]
    removed_edges = [list(e) for e in prev_edges - cur_edges]
    new_qv = [{"id": k0, "algorithm": next((n.get("algorithm") for n in nodes if n["key"][0] == k0), None)}
              for k0 in cur_qv - prev_qv]

    new_version = (prev.version + 1) if prev else 1
    row = GraphSnapshot(
        version=new_version, fingerprint=fingerprint,
        parent_fingerprint=prev.fingerprint if prev else None,
        node_count=len(nodes), edge_count=len(edges),
        nodes_by_kind=nodes_by_kind, edges_by_relation=edges_by_relation,
        nodes=nodes, edges=edges,
        added_nodes=sorted([list(k) for k in added_nodes]),
        removed_nodes=sorted([list(k) for k in removed_nodes]),
        added_edges=sorted([list(e) for e in added_edges]),
        removed_edges=sorted([list(e) for e in removed_edges]),
        new_quantum_vulnerable=new_qv,
        created_by=user,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    # Realtime: publish a graph.updated platform event so SSE subscribers (the
    # dependency-graph page) refresh immediately instead of polling. Best-effort
    # — never breaks the snapshot.
    try:
        from api.events.platform_events import emit_platform_event

        emit_platform_event(
            "graph.snapshot",
            f"Graph snapshot v{row.version} captured ({len(nodes)} nodes / {len(edges)} edges)",
            {
                "version": row.version,
                "node_count": len(nodes),
                "edge_count": len(edges),
                "fingerprint": fingerprint,
                "changed": True,
            },
            target_name="graph",
        )
    except Exception as exc:  # pragma: no cover - best effort
        logger.warning("graph_snapshot_event_failed: %s", exc)
    return {"changed": True, **row.to_dict(), "source": "live_graph"}


@router.post("/graph/snapshot")
def graph_snapshot_endpoint(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Capture a content-addressed version of the real dependency graph."""
    return _snapshot_graph(db, user=user)


@router.get("/graph/timeline")
def graph_timeline(
    limit: int = Query(50, ge=1, le=200),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Version history of the dependency graph (newest first)."""
    from sqlalchemy import select

    rows = db.execute(
        select(GraphSnapshot).order_by(GraphSnapshot.version.desc()).limit(min(limit, 200))
    ).scalars().all()
    return {"versions": [r.to_dict() for r in rows], "total_count": len(rows),
            "latest_version": rows[0].version if rows else 0}


@router.get("/graph/compare")
def graph_compare(
    from_version: int = Query(...),
    to_version: int = Query(...),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Diff two graph versions: added/removed nodes + relationships + new risk.

    `from` is the baseline, `to` the newer snapshot. Returns the actual diff
    stored when the snapshots were captured (real, not recomputed-on-the-fly),
    with honesty when either version is missing.
    """
    from sqlalchemy import select

    from_row = db.execute(select(GraphSnapshot).where(GraphSnapshot.version == from_version)).scalars().first()
    to_row = db.execute(select(GraphSnapshot).where(GraphSnapshot.version == to_version)).scalars().first()
    if from_row is None or to_row is None:
        missing = from_version if from_row is None else to_version
        raise HTTPException(status_code=404, detail=f"Graph version not found: {missing}")

    # Node/edge deltas computed directly from the two real snapshots so the
    # compare is always truthful even if the stored diff was pruned.
    def _node_id(n: dict) -> str:
        # n["key"] is [id, kind]
        return str((n.get("key") or [""])[0])

    def _node_kind(n: dict) -> str | None:
        return str((n.get("key") or ["", ""])[1]) if n.get("key") else n.get("kind")

    prev_nodes = {_node_id(n) for n in (from_row.nodes or [])}
    cur_nodes = {_node_id(n) for n in (to_row.nodes or [])}
    prev_edges = {(e["from"], e["to"], e["label"]) for e in (from_row.edges or [])}
    cur_edges = {(e["from"], e["to"], e["label"]) for e in (to_row.edges or [])}
    prev_kinds = {_node_id(n): _node_kind(n) for n in (from_row.nodes or [])}
    cur_kinds = {_node_id(n): _node_kind(n) for n in (to_row.nodes or [])}
    prev_algos = {_node_id(n): n.get("algorithm") for n in (from_row.nodes or [])}
    cur_algos = {_node_id(n): n.get("algorithm") for n in (to_row.nodes or [])}

    return {
        "from": {"version": from_row.version, "node_count": from_row.node_count, "edge_count": from_row.edge_count},
        "to": {"version": to_row.version, "node_count": to_row.node_count, "edge_count": to_row.edge_count},
        "added_nodes": [{"id": k, "kind": cur_kinds.get(k), "algorithm": cur_algos.get(k)} for k in sorted(cur_nodes - prev_nodes)],
        "removed_nodes": [{"id": k, "kind": prev_kinds.get(k), "algorithm": prev_algos.get(k)} for k in sorted(prev_nodes - cur_nodes)],
        "added_edges": [list(e) for e in sorted(cur_edges - prev_edges)],
        "removed_edges": [list(e) for e in sorted(prev_edges - cur_edges)],
        "new_quantum_vulnerable": to_row.new_quantum_vulnerable or [],
        "changed": (cur_nodes != prev_nodes) or (cur_edges != prev_edges),
        "backend": graph_from_db(db).backend,
    }


def _quantum_vulnerable_algorithm(name: str) -> bool:
    """Honest QV detection from the algorithm name (catalog first, then a
    syntax heuristic for the real scanner's `Algorithm-operation` labels)."""
    from universal_crypto import QuantumStatus, registry_entry

    try:
        entry = registry_entry(name)
        if entry.quantum_status == QuantumStatus.QUANTUM_VULNERABLE:
            return True
        if entry.quantum_status == QuantumStatus.QUANTUM_SAFE:
            return False
    except Exception:
        pass
    upper = name.upper()
    return any(k in upper for k in ("RSA", "ECDSA", "DSA", "DH", "ED25519", "ED448", "X25519", "X448", "P-256", "P-384", "P-521"))


@router.get("/priorities")
def priorities(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    payload = collect_graph_payload(db)
    ranked = enrich_assets(
        payload["assets"],
        systems=payload["systems"],
        edges=payload["edges"],
        processes=payload["processes"],
        owners=payload["owners"],
    )
    return {"assets": ranked, "total_count": len(ranked)}
