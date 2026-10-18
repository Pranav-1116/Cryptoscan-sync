"""Dependency graph and blast-radius APIs (Neo4j when configured)."""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

from shared_models.relationship_lifecycle import lifecycle_payload, clock, effective_state, edge_changes, utc
from shared_models.traversal_evidence import edge_evidence, envelope, MAX_WITNESSES
from shared_models.dependency_semantics import edge_relation, policy_metadata, propagates

logger = logging.getLogger(__name__)

from fastapi import APIRouter, Depends, HTTPException, Query, Response, Request
from pydantic import BaseModel, AwareDatetime, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from agility.roadmap import wave_for
from api.dependencies import get_current_user, get_db_session, require_roles
from api.graph_builder import collect_graph_payload, graph_from_db, sync_graph
from business_context.core.enricher import enrich_assets
from db.models import CryptoAsset, System
from db.models.graph_snapshot import GraphSnapshot
from db.repositories.intelligence_repository import IntelligenceRepository
from db.repositories.maturity_repository import MaturityRepository
from db.repositories.migration_task_repository import MigrationTaskRepository
from db.repositories.system_repository import SystemRepository
from graph_engine.core.drift import graph_drift
from graph_engine.core.facade import graph_health
from graph_engine.core.migration import apply_import_constraints, merge_cycle_constraints


def _evidence_refs(
    db: Session,
    asset_rows: dict[str, CryptoAsset],
    *,
    per_asset: int = 5,
    max_total: int = 2_000,
) -> dict[str, dict[str, Any]]:
    """Evidence-chain references per asset, from the link table.

    deep/25 §3.4: graph edges carried only descriptive text — no
    cryptographic tie to the evidence chain. The link table (populated by
    the pipeline's dedup stage) now lets every edge cite the exact
    evidence records behind it: id + content_hash + chain_hash, so an
    edge is independently verifiable against the chain sweep.

    Bounded: at most ``per_asset`` refs listed per asset (``count`` stays
    honest), at most ``max_total`` links read.
    """
    from db.models.crypto_asset_evidence import CryptoAssetEvidence
    from db.models.evidence_record import EvidenceRecord

    ids = list(asset_rows.keys())
    if not ids:
        return {}
    try:
        rows = db.execute(
            select(
                CryptoAssetEvidence.asset_id,
                EvidenceRecord.id,
                EvidenceRecord.content_hash,
                EvidenceRecord.chain_hash,
            )
            .join(EvidenceRecord, EvidenceRecord.id == CryptoAssetEvidence.evidence_id)
            .where(CryptoAssetEvidence.asset_id.in_(ids))
            .limit(max_total)
        ).all()
    except Exception:
        logger.debug("edge_evidence_refs_unavailable", exc_info=True)
        return {}
    result: dict[str, dict[str, Any]] = {}
    for asset_id, evidence_id, content_hash, chain_hash in rows:
        bucket = result.setdefault(asset_id, {"refs": [], "count": 0})
        bucket["count"] += 1
        if len(bucket["refs"]) < per_asset:
            bucket["refs"].append(
                {
                    "evidence_id": evidence_id,
                    "content_hash": content_hash,
                    "chain_hash": chain_hash,
                }
            )
    return result


def _edge_evidence(
    graph,
    edge: dict[str, Any],
    asset_rows: dict[str, CryptoAsset],
    evidence_by_asset: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Attach honest, backend-derived evidence to a graph relationship.

    Every relationship carries: type, confidence, source, evidence text,
    first/last observed (from the real CryptoAsset row), and whether it is
    verified. Values are pulled from the actual inventory — nothing is
    fabricated — and missing data reads as null / "" rather than a fake green.
    """
    label = edge.get("label") or "USES"
    graph_nodes = getattr(graph, "nodes", {})
    node = graph_nodes.get(edge.get("to") or "")
    if node is None:
        node = graph_nodes.get(edge.get("from") or "")

    # For a USES/every edge the asset is the subject carrying scanner evidence.
    from_id = str(edge.get("from") or "").split(":", 1)[-1]
    to_id = str(edge.get("to") or "").split(":", 1)[-1]
    asset_row = asset_rows.get(to_id) or asset_rows.get(from_id)

    confidence = edge.get("confidence")
    asset_confidence = getattr(asset_row, "confidence", None) or (node.get("confidence") if node else None)
    evidence = ""
    if node:
        ex = node.get("extra")
        if isinstance(ex, dict):
            evidence = str(ex.get("detection") or "")
    if not evidence and asset_row is not None:
        ex = getattr(asset_row, "extra", None)
        if isinstance(ex, dict):
            evidence = str(ex.get("detection") or "")

    out = {
        "type": label,
        "confidence": confidence,
        # r43/§4.5: the engine's provenance class + source win when present
        # (DECLARED system dependency vs SCANNER_DERIVED inventory link); the
        # coarse subsystem heuristic is only a fallback for backends that
        # predate provenance.
        "provenance": edge.get("provenance") or "UNATTRIBUTED",
        "source": edge.get("source") or ("crypto_discovery" if label == "USES" else "inventory"),
        "evidence": evidence,
        "first_seen": edge.get("first_seen"), "last_seen": edge.get("last_seen"),
        "asset_first_seen": asset_row.created_at.isoformat() if asset_row is not None and asset_row.created_at else None,
        "asset_last_updated": asset_row.updated_at.isoformat() if asset_row is not None and asset_row.updated_at else None,
        "verified": False,
        "asset_detection_confidence": asset_confidence,
        "confidence_meaning": edge.get("confidence_meaning") or "unspecified; not relationship verification or failure probability",
        "references_verified_by_traversal": False,
    }
    # deep/25 §3.4: cite the evidence chain, not just describe it
    if label == "USES" and asset_row is not None and evidence_by_asset is not None:
        refs = evidence_by_asset.get(asset_row.id)
        if refs:
            out["evidence_count"] = refs["count"]
            out["evidence_refs"] = edge.get("evidence_refs") or refs["refs"]
            out["asset_evidence_refs"] = refs["refs"]
            out["evidence_role"] = "asset detection support; not proof of a runtime relationship"
    return out

router = APIRouter(tags=["graph"])


@router.get("/graph/health")
def get_graph_health(user: str = Depends(get_current_user)):
    return graph_health()


# --------------------------------------------------------------------------- #
# Graph export (report 09 rec #12) - GraphML / GEXF over the same graph the
# /graph endpoint serves. Pure serialization: no new data, no inference.
# --------------------------------------------------------------------------- #

def _xml_escape(value: Any) -> str:
    return (
        str(value if value is not None else "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _to_graphml(vis: dict[str, Any]) -> str:
    nodes = vis.get("nodes") or []
    edges = vis.get("edges") or []
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
        '  <key id="d0" for="node" attr.name="kind" attr.type="string"/>',
        '  <key id="d1" for="edge" attr.name="relation" attr.type="string"/>',
        '  <key id="d3" for="edge" attr.name="provenance" attr.type="string"/>',
        '  <key id="d2" for="node" attr.name="label" attr.type="string"/>',
        '  <graph id="cryptoscan-graph" edgedefault="directed">',
    ]
    for node in nodes:
        kind = _xml_escape(node.get("group") or "Unknown")
        label = _xml_escape(node.get("label") or node.get("id"))
        lines.append(
            f'    <node id="{_xml_escape(node.get("id"))}">'
            f'<data key="d0">{kind}</data>'
            f'<data key="d2">{label}</data></node>'
        )
    for index, edge in enumerate(edges):
        lines.append(
            f'    <edge id="e{index}" source="{_xml_escape(edge.get("from"))}" '
            f'target="{_xml_escape(edge.get("to"))}">'
            f'<data key="d1">{_xml_escape(edge.get("label") or "CALLS")}</data>'
            f'<data key="d3">{_xml_escape(edge.get("provenance") or "UNATTRIBUTED")}</data></edge>'
        )
    lines += ["  </graph>", "</graphml>", ""]
    return "\n".join(lines)


def _to_gexf(vis: dict[str, Any]) -> str:
    nodes = vis.get("nodes") or []
    edges = vis.get("edges") or []
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<gexf xmlns="http://gexf.net/1.3" version="1.3">',
        '  <graph mode="static" defaultedgetype="directed">',
        '    <attributes class="node">',
        '      <attribute id="kind" title="kind" type="string"/>',
        "    </attributes>",
        '    <attributes class="edge">',
        '      <attribute id="provenance" title="provenance" type="string"/>',
        "    </attributes>",
        "    <nodes>",
    ]
    for node in nodes:
        lines.append(
            f'      <node id="{_xml_escape(node.get("id"))}" '
            f'label="{_xml_escape(node.get("label") or node.get("id"))}">'
            f'<attvalues><attvalue for="kind" value="{_xml_escape(node.get("group") or "Unknown")}"/>'
            f"</attvalues></node>"
        )
    lines.append("    </nodes>")
    lines.append("    <edges>")
    for index, edge in enumerate(edges):
        lines.append(
            f'      <edge id="e{index}" source="{_xml_escape(edge.get("from"))}" '
            f'target="{_xml_escape(edge.get("to"))}" label="{_xml_escape(edge.get("label") or "CALLS")}">'
            f'<attvalues><attvalue for="provenance" value="{_xml_escape(edge.get("provenance") or "UNATTRIBUTED")}"/>'
            f"</attvalues></edge>"
        )
    lines += ["    </edges>", "  </graph>", "</gexf>", ""]
    return "\n".join(lines)


@router.get("/graph/export")
def export_graph(
    format: str = Query("graphml", pattern="^(graphml|gexf)$"),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Graph export for external analysis tools (Gephi, yEd, Cytoscape)."""
    graph = graph_from_db(db)
    vis = graph.to_vis()
    content = _to_gexf(vis) if format == "gexf" else _to_graphml(vis)
    return Response(
        content=content,
        media_type="application/xml",
        headers={"Content-Disposition": f'attachment; filename="cryptoscan-graph.{format}"'},
    )


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
    evidence_by_asset = _evidence_refs(db, asset_rows)
    vis = graph.to_vis()
    edges = vis.get("edges") or []
    for e in edges:
        e.update(_edge_evidence(graph, e, asset_rows, evidence_by_asset))
    health = graph_health()
    vis["health"] = health
    vis["backend"] = getattr(graph, "backend", vis.get("backend") or health.get("backend"))
    return vis


@router.get("/graph/blast-radius")
def blast_radius(
    system_id: str | None = Query(None),
    asset_id: str | None = Query(None),
    hops: int = Query(5, ge=1, le=12),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Downstream blast radius from a system — or from a crypto asset.

    An asset start fans out over EVERY system that uses it (SystemAsset
    links), because a shared key or library breaks all its users at once;
    the per-system walks are unioned, each system keeping its minimum hop.
    """
    if not system_id and not asset_id:
        raise HTTPException(status_code=400,
                            detail="system_id or asset_id is required")
    if asset_id and not system_id:
        from db.models.system_asset import SystemAsset

        ownership_links = db.query(SystemAsset).filter(SystemAsset.asset_id == asset_id).all()
        owning = sorted({link.system_id for link in ownership_links})
        if not owning:
            raise HTTPException(
                status_code=404,
                detail=f"asset not linked to any system: {asset_id}")
        graph = graph_from_db(db)
        union: dict[str, dict[str, Any]] = {}
        evidence_paths = {}
        as_of = clock()
        graph._as_of = as_of
        for sid in owning:
            part = graph.blast_radius(sid, hops=hops)
            for witness in (part.get("traversal_evidence") or {}).get("paths") or []:
                identifier = witness["system_id"]
                previous = evidence_paths.get(identifier)
                if previous is None or (witness["hops"], witness["nodes"]) < (previous["hops"], previous["nodes"]):
                    evidence_paths[identifier] = witness
            for row in part.get("systems") or []:
                if str(row["id"]) in owning:
                    continue
                prev = union.get(str(row["id"]))
                if prev is None or row["hops"] < prev["hops"]:
                    union[str(row["id"])] = row
        systems = sorted(union.values(),
                         key=lambda row: (row["hops"], str(row.get("name") or "")))
        evidence_paths = {sid: p for sid, p in evidence_paths.items() if sid in union and p["hops"] == union[sid]["hops"]}
        start_edges = [edge_evidence({"from": link.system_id, "to": "asset:" + asset_id, "label": "USES", "record_id": link.id,
                         "source": "system_assets", "provenance": "UNATTRIBUTED"}, now=as_of) for link in ownership_links[:MAX_WITNESSES]]
        return {
            "traversal_evidence": envelope(evidence_paths, union, now=as_of),
            "start_links": {"edges": start_edges, "returned_count": len(start_edges), "requested_count": len(ownership_links),
                            "limit": MAX_WITNESSES, "truncated": len(ownership_links) > MAX_WITNESSES},
            "start": asset_id,
            "start_kind": "asset",
            "owning_systems": owning,
            "systems": systems,
            "hops": hops,
            "nodes_visited": len(union) + len(owning),
            "relationship_policy": policy_metadata(),
            "backend": graph.backend,
        }
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
    # Code-level evidence from the scanner's business-system rollup (cryptoscan-systems.yml):
    # systems the CMDB does not know about join the plan; every system with a code cascade gets
    # its code wave in the rationale; IMPORTS edges (A's code calls crypto living in B) order A after B.
    known = {row["system_id"] for row in entries}
    code_only = 0
    for node_id, node in getattr(graph, "nodes", {}).items():
        if node.get("kind") != "System":
            continue
        sid = node_id.split(":", 1)[-1]
        cc = node.get("code_cascade") or {}
        row = None
        if sid in known:
            row = next(r for r in entries if r["system_id"] == sid)
        elif node.get("source") == "cryptoscan-systems.yml":
            code_only += 1
            code_wave = int(cc.get("earliest_wave") or 3)
            row = {"system_id": sid, "name": node.get("name") or sid, "wave": min(max(code_wave, 1), 3), "readiness_category": None,
                   "readiness_score": None, "agility_score": None, "unscored": False, "source": "cryptoscan-systems.yml",
                   "rationale": f"declared in code, not in the CMDB; code cascade wave {code_wave}"}
            entries.append(row)
        if row is not None and cc:
            row["code_cascade"] = {k: cc.get(k) for k in ("providers", "weak_parameters", "earliest_wave", "algorithms", "scan_id")}
            if sid in known and cc.get("earliest_wave") is not None:
                row["rationale"] = (row.get("rationale") or "") + f"; code: {cc.get('providers') or 0} crypto providers, cascade wave {cc.get('earliest_wave')}"
    imports = [(src, dst) for src, items in getattr(graph, "out", {}).items() for dst, rel in items if rel == "IMPORTS"]
    import_info = apply_import_constraints(entries, imports)
    result = merge_cycle_constraints(entries, cycles)
    result["unscored_systems"] = unscored
    result["code_only_systems"] = code_only
    result.update(import_info)
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
    impact = {}

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
            "link_evidence": edge_evidence(
                {"from": nxt, "to": start, "label": rel, **graph.edge_meta.get((nxt, start, rel), {})}, now=clock()),
        })

    # business impact
    try:
        impact = graph.business_impact(node_id, hops=6)
        steps.append({
            "label": "business impact", "kind": "Impact",
            "detail": f"{len(impact.get('systems') or [])} systems · revenue at risk {impact.get('total_revenue_at_risk', 0)}",
            "confidence": None, "evidence": "", "file": None,
        })
    except Exception as impact_exc:
        logger.warning(
            "graph_business_impact_unavailable",
            extra={"error_type": type(impact_exc).__name__, "node_id": node_id},
        )

    return {
        "node_id": node_id,
        "title": f"Why is {node.get('name') or node.get('algorithm') or node_id} risky?",
        "quantum_vulnerable": bool(node.get("kind") == "CryptoAsset" and _quantum_vulnerable_algorithm(str(node.get("algorithm") or ""))),
        "steps": steps,
        "traversal_evidence": impact.get("traversal_evidence"), "domain_links": impact.get("domain_links"),
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
    vis = graph.to_vis()
    graph_nodes = getattr(graph, "nodes", None) or {n["id"]: n for n in vis.get("nodes") or []}
    as_of = getattr(graph, "as_of", None) or clock()
    nodes = [
        {
            "key": list(_canon_node_key(n)),
            "kind": n.get("kind") or n.get("group"),
            "name": n.get("name"),
            "algorithm": n.get("algorithm"),
            "qv": bool(n.get("kind") == "CryptoAsset" and _quantum_vulnerable_algorithm(str(n.get("algorithm") or ""))),
        }
        for n in graph_nodes.values()
    ]
    nodes.sort(key=lambda n: (n["kind"] or "", n["name"] or "", n["algorithm"] or ""))
    edges = [
        {"from": e.get("from"), "to": e.get("to"), "label": e.get("label"),
         **lifecycle_payload(e), "effective_state": effective_state(e, now=as_of)}
        for e in vis.get("edges") or []
    ]
    edges.sort(key=lambda e: (e["from"], e["to"], e["label"], json.dumps(lifecycle_payload(e), sort_keys=True)))
    nodes_by_kind: dict[str, int] = {}
    edges_by_relation: dict[str, int] = {}
    for node in graph_nodes.values():
        k = node.get("kind") or node.get("group") or "Node"
        nodes_by_kind[k] = nodes_by_kind.get(k, 0) + 1
    for e in graph.to_vis().get("edges") or []:
        r = e.get("label") or "RELATED"
        edges_by_relation[r] = edges_by_relation.get(r, 0) + 1
    return nodes, edges, nodes_by_kind, edges_by_relation


def _fingerprint(nodes: list[dict], edges: list[dict]) -> str:
    payload = json.dumps({"nodes": nodes, "edges": edges, "relationship_policy": policy_metadata()}, sort_keys=True, default=str)
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

    # Tenant-local prev (migration 0071): versions number per tenant, so the
    # fingerprint compare and the +1 must read this tenant's history only —
    # explicit, because platform scope bypasses the ORM guard.
    from db.tenancy import current_tenant

    prev = db.execute(
        select(GraphSnapshot).order_by(GraphSnapshot.version.desc())
        .filter(GraphSnapshot.tenant_id == current_tenant()).limit(1)
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
        relationship_policy=policy_metadata(), lifecycle_as_of=getattr(graph, "as_of", None) or clock(),
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

    lifecycle_changes = edge_changes(from_row.edges or [], to_row.edges or [])
    old_policy = (from_row.relationship_policy or {}).get("version")
    new_policy = (to_row.relationship_policy or {}).get("version")
    return {
        "relationship_lifecycle_changes": lifecycle_changes,
        "policy_comparison": {"before": old_policy, "after": new_policy,
            "comparable": old_policy is not None and old_policy == new_policy},
        "eligibility_change_is_not_remediation": True,
        "from": {"version": from_row.version, "node_count": from_row.node_count, "edge_count": from_row.edge_count},
        "to": {"version": to_row.version, "node_count": to_row.node_count, "edge_count": to_row.edge_count},
        "added_nodes": [{"id": k, "kind": cur_kinds.get(k), "algorithm": cur_algos.get(k)} for k in sorted(cur_nodes - prev_nodes)],
        "removed_nodes": [{"id": k, "kind": prev_kinds.get(k), "algorithm": prev_algos.get(k)} for k in sorted(prev_nodes - cur_nodes)],
        "added_edges": [list(e) for e in sorted(cur_edges - prev_edges)],
        "removed_edges": [list(e) for e in sorted(prev_edges - cur_edges)],
        "new_quantum_vulnerable": to_row.new_quantum_vulnerable or [],
        "changed": (cur_nodes != prev_nodes) or (cur_edges != prev_edges) or bool(lifecycle_changes) or old_policy != new_policy,
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
    except (KeyError, TypeError, ValueError) as registry_exc:
        logger.debug(
            "crypto_registry_entry_unavailable",
            extra={"error_type": type(registry_exc).__name__, "algorithm": name},
        )
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


# --------------------------------------------------------------------------
# Dependency-edge management — the graph's input side
# --------------------------------------------------------------------------

class EdgeRequest(BaseModel):
    """Register one system→system dependency edge.

    Parent/child may be given as system id or name; relation defaults to
    CALLS. Everything downstream (twin, unified cascade, blast radius, system
    CBOMs) reads these edges — this is the only write surface for them.
    """

    parent_id: str | None = None
    parent_name: str | None = None
    child_id: str | None = None
    child_name: str | None = None
    relation: str = "CALLS"
    # provenance: manual (default), discovered (adopted from a scanner or
    # graph snapshot) or imported. Confidence 0..1 is optional.
    source: str = "manual"
    confidence: float | None = None
    valid_until: AwareDatetime | None = None
    evidence_ref: str | None = Field(None, min_length=1, max_length=500)
    confidence_meaning: str | None = Field(None, min_length=1, max_length=200)


def _resolve_system(db: Session, system_id: str | None,
                    system_name: str | None) -> System:
    repo = SystemRepository(db)
    if system_id:
        row = db.query(System).filter(System.id == system_id).first()
        if row is not None:
            return row
    if system_name:
        row = repo.get_by_name(system_name)
        if row is not None:
            return row
    raise HTTPException(
        status_code=404,
        detail=f"system not found: {system_id or system_name}")


def _edge_payload(db: Session, edge) -> dict[str, Any]:
    from db.models.system import System

    names = {s.id: s.name for s in db.query(System).all()}
    return {
        "id": edge.id, "evidence_ref": edge.evidence_ref, "confidence_meaning": edge.confidence_meaning, **lifecycle_payload(edge),
        "effective_state": effective_state(lifecycle_payload(edge), now=clock()),
        "parent_id": edge.parent_id, "child_id": edge.child_id,
        "parent_name": names.get(edge.parent_id),
        "child_name": names.get(edge.child_id),
        "relation": edge.relation or "CALLS",
        "dependency_semantics": {
            "normalized_relation": edge_relation({"relation": edge.relation}),
            "propagates": propagates(edge.relation),
            "policy_version": policy_metadata()["version"],
        },
        "source": getattr(edge, "source", None) or "manual",
        "created_by": getattr(edge, "created_by", None),
        "confidence": getattr(edge, "confidence", None),
        "last_verified": (edge.last_verified.isoformat()
                          if getattr(edge, "last_verified", None) else None),
    }


@router.get("/graph/edges")
def list_dependency_edges(
    relation: str | None = Query(None),
    system_id: str | None = Query(None),
    limit: int = Query(500, ge=1, le=5000),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """List registered dependency edges, optionally filtered by relation
    or by either endpoint of the edge."""
    from db.models.system_dependency import SystemDependency

    stmt = db.query(SystemDependency)
    if relation:
        stmt = stmt.filter(SystemDependency.relation == relation)
    rows = stmt.limit(limit).all()
    if system_id:
        rows = [r for r in rows
                if r.parent_id == system_id or r.child_id == system_id]
    return {"edges": [_edge_payload(db, r) for r in rows], "count": len(rows),
            "relationship_policy": policy_metadata()}


@router.post("/graph/edges")
def register_dependency_edge(
    body: EdgeRequest,
    request: Request,
    user: str = Depends(require_roles("admin", "superadmin", "security_analyst")),
    db: Session = Depends(get_db_session),
):
    """Register a system→system dependency edge (the graph's input side)."""
    from db.models.system_dependency import SystemDependency

    from api.routers.software_supply_chain import _tenant
    tenant = _tenant(request, db, user)
    parent = _resolve_system(db, body.parent_id, body.parent_name)
    child = _resolve_system(db, body.child_id, body.child_name)
    if parent.tenant_id != tenant or child.tenant_id != tenant:
        raise HTTPException(404, "system not found in the selected estate")
    if parent.id == child.id:
        raise HTTPException(status_code=400,
                            detail="self-dependency edges are not allowed")
    existing = db.query(SystemDependency).filter(
        SystemDependency.parent_id == parent.id,
        SystemDependency.child_id == child.id).first()
    if existing is not None:
        raise HTTPException(
            status_code=409,
            detail=f"edge already exists: {parent.id} -> {child.id} "
                   f"({existing.relation or 'CALLS'})")

    source = body.source if body.source in {"manual", "discovered", "imported"} else "manual"
    edge = SystemDependency(tenant_id=tenant, parent_id=parent.id, child_id=child.id, relation=body.relation)
    db.add(edge)
    edge.valid_until = utc(body.valid_until) if body.valid_until is not None else None
    edge.evidence_ref = body.evidence_ref
    edge.confidence_meaning = body.confidence_meaning
    edge.source = source
    edge.created_by = user
    if body.confidence is not None:
        edge.confidence = float(body.confidence)
    if source == "manual":
        from datetime import datetime, timezone

        edge.last_verified = datetime.now(timezone.utc)
    db.commit()
    from api.events.platform_events import emit_platform_event

    emit_platform_event(
        "graph.updated",
        f"Dependency edge registered: {parent.name} -> {child.name} "
        f"({body.relation}, {source})",
        {"parent_id": parent.id, "child_id": child.id,
         "relation": body.relation, "source": source},
        target_name="graph",
    )
    return {"registered": True, "edge": _edge_payload(db, edge)}


@router.delete("/graph/edges/{parent_id}/{child_id}")
def delete_dependency_edge(
    parent_id: str,
    child_id: str,
    request: Request,
    expected_revision: int = Query(..., ge=0),
    reason: str = Query(..., min_length=1, max_length=500),
    evidence_ref: str = Query(..., min_length=1, max_length=500),
    user: str = Depends(require_roles("admin", "superadmin", "security_analyst")),
    db: Session = Depends(get_db_session),
):
    """Retain an audited tombstone; clients must supply a revision and evidence."""
    from api.routers.relationship_lifecycle import scoped, mutate, commit
    from api.routers.software_supply_chain import _tenant
    from db.models.system_dependency import SystemDependency
    if not reason.strip() or not evidence_ref.strip():
        raise HTTPException(422, "reason and evidence_ref must not be blank")
    tenant = _tenant(request, db, user)
    edge = scoped(db, SystemDependency, tenant).filter_by(parent_id=parent_id, child_id=child_id).one_or_none()
    if edge is None:
        raise HTTPException(404, "edge not found")
    mutate(db, edge, "system_dependency", tenant, user, {"lifecycle_state": "DELETED"},
           expected_revision=expected_revision, reason=reason, evidence_ref=evidence_ref)
    commit(db)
    return {"deleted": True, "retained": True, "parent_id": parent_id, "child_id": child_id,
            "edge": _edge_payload(db, edge)}


# --------------------------------------------------------------------------
# Declared linkage: crypto↔hardware, vendor-of-vendor
# --------------------------------------------------------------------------

@router.get("/graph/hardware-links")
def list_hardware_links(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Declared crypto-asset ↔ hardware-device links (operator-declared)."""
    from db.models.cascade_extensions import CryptoHardwareLink

    rows = db.query(CryptoHardwareLink).limit(5000).all()
    return {"links": [{
        "asset_id": r.asset_id, "hardware_asset_id": r.hardware_asset_id,
        "declared_by": r.declared_by, "note": r.note,
    } for r in rows], "count": len(rows)}


@router.post("/graph/hardware-links")
def declare_hardware_link(
    body: dict,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Declare which hardware device serves which crypto asset.

    The platform never infers this (a wrong guess here is a security claim);
    once someone who knows declares it, device cascades name dependents.
    """
    from db.models.cascade_extensions import CryptoHardwareLink
    from db.models.crypto_asset import CryptoAsset
    from db.models.hardware_live import HardwareAsset

    asset_id = str(body.get("asset_id") or "").strip()
    hardware_asset_id = str(body.get("hardware_asset_id") or "").strip()
    if not asset_id or not hardware_asset_id:
        raise HTTPException(status_code=400,
                            detail="asset_id and hardware_asset_id are required")
    if db.query(CryptoAsset).filter(CryptoAsset.id == asset_id).first() is None:
        raise HTTPException(status_code=404, detail=f"crypto asset not found: {asset_id}")
    if db.query(HardwareAsset).filter(
            HardwareAsset.asset_id == hardware_asset_id).first() is None:
        raise HTTPException(status_code=404,
                            detail=f"hardware asset not found: {hardware_asset_id}")
    existing = db.query(CryptoHardwareLink).filter(
        CryptoHardwareLink.asset_id == asset_id,
        CryptoHardwareLink.hardware_asset_id == hardware_asset_id).first()
    if existing is not None:
        raise HTTPException(status_code=409, detail="link already declared")

    link = CryptoHardwareLink(asset_id=asset_id,
                              hardware_asset_id=hardware_asset_id,
                              declared_by=user, note=body.get("note"))
    db.add(link)
    db.commit()
    return {"declared": True, "asset_id": asset_id,
            "hardware_asset_id": hardware_asset_id}


@router.delete("/graph/hardware-links/{asset_id}/{hardware_asset_id}")
def delete_hardware_link(
    asset_id: str,
    hardware_asset_id: str,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    from db.models.cascade_extensions import CryptoHardwareLink

    link = db.query(CryptoHardwareLink).filter(
        CryptoHardwareLink.asset_id == asset_id,
        CryptoHardwareLink.hardware_asset_id == hardware_asset_id).first()
    if link is None:
        raise HTTPException(status_code=404, detail="link not found")
    db.delete(link)
    db.commit()
    return {"deleted": True}


@router.get("/graph/vendor-edges")
def list_vendor_edges(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Declared vendor-of-vendor (sub-tier supply chain) edges."""
    from db.models.cascade_extensions import VendorDependency

    rows = db.query(VendorDependency).limit(5000).all()
    from db.models.vendor import Vendor as _V

    vendor_names = {v.id: v.name for v in db.query(_V).all()}
    return {"edges": [{
        "parent_vendor_id": r.parent_vendor_id,
        "child_vendor_id": r.child_vendor_id,
        "parent_vendor": vendor_names.get(r.parent_vendor_id),
        "child_vendor": vendor_names.get(r.child_vendor_id),
        "relation": r.relation, "declared_by": r.declared_by,
    } for r in rows], "count": len(rows)}


@router.post("/graph/vendor-edges")
def declare_vendor_edge(
    body: dict,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Declare a sub-tier vendor relationship (vendor-of-vendor)."""
    from db.models.cascade_extensions import VendorDependency
    from db.models.vendor import Vendor

    parent = body.get("parent_vendor_id") or body.get("parent_vendor_name")
    child = body.get("child_vendor_id") or body.get("child_vendor_name")
    if not parent or not child:
        raise HTTPException(status_code=400,
                            detail="parent and child vendor (id or name) are required")

    def _vendor(ref) -> Vendor:
        row = (db.query(Vendor).filter(Vendor.id == str(ref)).first()
               or db.query(Vendor).filter(Vendor.name == str(ref)).first())
        if row is None:
            raise HTTPException(status_code=404, detail=f"vendor not found: {ref}")
        return row

    parent_row, child_row = _vendor(parent), _vendor(child)
    if parent_row.id == child_row.id:
        raise HTTPException(status_code=400, detail="self-edges are not allowed")
    existing = db.query(VendorDependency).filter(
        VendorDependency.parent_vendor_id == parent_row.id,
        VendorDependency.child_vendor_id == child_row.id).first()
    if existing is not None:
        raise HTTPException(status_code=409, detail="vendor edge already declared")

    db.add(VendorDependency(parent_vendor_id=parent_row.id,
                            child_vendor_id=child_row.id,
                            relation=body.get("relation"),
                            declared_by=user))
    db.commit()
    return {"declared": True, "parent_vendor_id": parent_row.id,
            "child_vendor_id": child_row.id}


@router.delete("/graph/vendor-edges/{parent_vendor_id}/{child_vendor_id}")
def delete_vendor_edge(
    parent_vendor_id: str,
    child_vendor_id: str,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    from db.models.cascade_extensions import VendorDependency

    edge = db.query(VendorDependency).filter(
        VendorDependency.parent_vendor_id == parent_vendor_id,
        VendorDependency.child_vendor_id == child_vendor_id).first()
    if edge is None:
        raise HTTPException(status_code=404, detail="vendor edge not found")
    db.delete(edge)
    db.commit()
    return {"deleted": True}


# --------------------------------------------------------------------------
# Discovered-edge adoption: scanner cascade + graph snapshots → SystemDependency
# --------------------------------------------------------------------------

@router.get("/graph/edges/discovered")
def discovered_edges(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Candidate dependency edges the scanners already observed.

    Two honest sources: the scanner cascade's ``depends_on_systems`` (from
    cryptoscan-systems.yml declarations plus observed code imports) and the
    latest graph snapshot's edges. Proposals only — nothing is registered
    until an operator adopts them (POST /graph/edges/adopt), because a
    dependency edge is a claim about production.
    """
    from db.models.graph_snapshot import GraphSnapshot
    from db.models.scan import Scan
    from db.models.system_dependency import SystemDependency

    repo = SystemRepository(db)

    def _system_id(ref: str):
        row = (db.query(System).filter(System.id == str(ref)).first()
               or repo.get_by_name(str(ref)))
        return row.id if row else None

    existing = {(d.parent_id, d.child_id)
                for d in db.query(SystemDependency).all()}
    proposals: list[dict[str, Any]] = []
    unresolved: list[str] = []
    seen: set[tuple[str, str]] = set()

    def _propose(parent_ref: str, child_ref: str, source: str, note: str,
                 confidence: float):
        parent_id, child_id = _system_id(parent_ref), _system_id(child_ref)
        if parent_id is None:
            unresolved.append(str(parent_ref))
            return
        if child_id is None:
            unresolved.append(str(child_ref))
            return
        key = (parent_id, child_id)
        if key in seen or key in existing or parent_id == child_id:
            return
        seen.add(key)
        proposals.append({
            "parent_id": parent_id, "child_id": child_id,
            "source": source, "note": note, "confidence": confidence,
        })

    # scanner cascade: this system imports crypto providers from those systems
    scans = db.query(Scan).order_by(Scan.created_at.desc()).limit(200).all()
    for scan in scans:
        cascade = (scan.statistics or {}).get("cascade") or {}
        for entry in cascade.get("systems") or []:
            for dep in entry.get("depends_on_systems") or []:
                _propose(entry.get("system"), dep, "discovered",
                         f"scanner cascade (scan {scan.id}, declared system map + imports)",
                         0.8)

    # latest graph snapshot edges (captured graph versions)
    snap = db.query(GraphSnapshot).order_by(
        GraphSnapshot.version.desc()).first()
    if snap and snap.edges:
        for edge in snap.edges:
            _propose(edge.get("from"), edge.get("to"), "discovered",
                     f"graph snapshot v{snap.version}", 0.7)

    return {"proposals": proposals, "count": len(proposals),
            "unresolved_names": sorted(set(unresolved)),
            "note": "proposals only — adopt explicitly; a dependency edge is a claim about production"}


@router.post("/graph/edges/adopt")
def adopt_edges(
    body: dict,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Adopt selected discovered edges into SystemDependency (the approval
    step of the discovery flow). Each adopted edge carries source=discovered
    and the adopting operator's name."""
    from db.models.system_dependency import SystemDependency

    wanted = body.get("edges") or []
    if not isinstance(wanted, list) or not wanted:
        raise HTTPException(status_code=400, detail="edges[] is required")
    adopted, skipped = [], []
    for item in wanted:
        parent_id, child_id = str(item.get("parent_id") or ""), str(item.get("child_id") or "")
        if not parent_id or not child_id:
            skipped.append({"parent_id": parent_id, "child_id": child_id,
                            "reason": "missing ids"})
            continue
        parent = db.query(System).filter(System.id == parent_id).first()
        child = db.query(System).filter(System.id == child_id).first()
        if parent is None or child is None:
            skipped.append({"parent_id": parent_id, "child_id": child_id,
                            "reason": "system not found"})
            continue
        if db.query(SystemDependency).filter(
                SystemDependency.parent_id == parent_id,
                SystemDependency.child_id == child_id).first() is not None:
            skipped.append({"parent_id": parent_id, "child_id": child_id,
                            "reason": "already registered"})
            continue
        edge = SystemRepository(db).add_dependency(
            parent_id, child_id, item.get("relation") or "CALLS")
        edge.source = "discovered"
        edge.created_by = user
        if item.get("confidence") is not None:
            edge.confidence = float(item.get("confidence"))
        adopted.append(_edge_payload(db, edge))
    db.commit()
    if adopted:
        from api.events.platform_events import emit_platform_event

        emit_platform_event(
            "graph.updated",
            f"{len(adopted)} discovered dependency edge(s) adopted",
            {"adopted": len(adopted), "by": user},
            target_name="graph",
        )
    return {"adopted": adopted, "skipped": skipped,
            "adopted_count": len(adopted)}
