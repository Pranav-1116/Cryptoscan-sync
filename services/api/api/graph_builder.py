"""Build a graph view from PostgreSQL / SQLite, then prefer Neo4j."""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session

from db.models.certificate import Certificate
from db.models.crypto_asset import CryptoAsset
from db.models.scan import Scan
from db.models.system_asset import SystemAsset
from db.repositories.intelligence_repository import IntelligenceRepository
from db.repositories.system_repository import SystemRepository
from graph_engine.config.settings import get_graph_settings
from graph_engine.core.facade import graph_health, resolve_graph
from graph_engine.service_mesh.istio_client import fetch_istio_calls

logger = logging.getLogger(__name__)


#: per-kind bound for secondary collections (certificates, assets) — the
#: same anti-silent-truncation contract as ``list_all_bounded``: bounded,
#: and the bound is reported in the payload's ``collection`` meta.
_PER_KIND_MAX_ROWS = 50_000


def _bounded_all(query, *, max_rows: int = _PER_KIND_MAX_ROWS):
    """Yield rows of a query in bounded pages, collecting a truncation flag."""
    rows: list[Any] = []
    offset = 0
    while len(rows) < max_rows:
        page = query.offset(offset).limit(1000).all()
        if not page:
            break
        rows.extend(page)
        offset += len(page)
    truncated = len(rows) > max_rows
    return (rows[:max_rows] if truncated else rows), truncated


def collect_graph_payload(session: Session) -> dict[str, Any]:
    systems_repo = SystemRepository(session)
    intel = IntelligenceRepository(session)
    # Bounded walk over ALL pages — a single 500-row page silently dropped
    # every system beyond it from the graph, blast radius, and snapshots.
    systems, systems_truncated = systems_repo.list_all_bounded()
    collection_meta = {
        "systems_total": len(systems),
        "systems_truncated": systems_truncated,
        "bounds": {"systems_max_rows": 50_000, "per_kind_max_rows": 50_000},
    }
    system_payloads = []
    edges = []
    asset_payloads = []
    owner_index = {((row.email or "").lower(), (row.name or "").lower()): row for row in intel.list_owners()}
    owners_by_id: dict[str, dict[str, Any]] = {}
    for system in systems:
        assets = systems_repo.assets_for(system.id)
        system_payloads.append(
            {
                "id": system.id,
                "name": system.name,
                "owner": system.owner,
                "environment": system.environment,
                "compliance_scopes": system.compliance_scopes or [],
                "asset_ids": [asset.id for asset in assets],
            }
        )
        for edge in systems_repo.dependencies_for(system.id):
            edges.append(
                {"parent_id": edge.parent_id, "child_id": edge.child_id, "relation": edge.relation or "CALLS"}
            )
        for asset in assets:
            payload = asset.to_dict()
            payload["system_id"] = system.id
            asset_payloads.append(payload)
        if system.owner:
            match = None
            for (email, name), row in owner_index.items():
                if system.owner.lower() in {email, name}:
                    match = row
                    break
            if match:
                item = owners_by_id.setdefault(match.id, {**match.to_dict(), "system_ids": []})
                item["system_ids"].append(system.id)
            else:
                owners_by_id.setdefault(
                    f"sys-owner:{system.id}",
                    {"id": f"sys-owner:{system.id}", "name": system.owner, "system_ids": [system.id]},
                )
    if not asset_payloads:
        fallback_assets, _fb_truncated = _bounded_all(session.query(CryptoAsset))
        asset_payloads = [row.to_dict() for row in fallback_assets]
        links = session.query(SystemAsset).all()
        by_asset = {link.asset_id: link.system_id for link in links}
        for asset in asset_payloads:
            asset["system_id"] = by_asset.get(asset.get("id"))

    processes = []
    for process in intel.list_processes():
        item = process.to_dict()
        item["system_ids"] = intel.process_system_ids(process.id)
        processes.append(item)
    vendors = []
    for vendor in intel.list_vendors():
        item = vendor.to_dict()
        item["system_ids"] = intel.vendor_system_ids(vendor.id)
        vendors.append(item)
    if not owners_by_id:
        owners = [row.to_dict() for row in intel.list_owners()]
    else:
        owners = list(owners_by_id.values())

    certificates = []
    try:
        cert_rows, certs_truncated = _bounded_all(session.query(Certificate))
        collection_meta["certificates_truncated"] = certs_truncated
        for cert in cert_rows:
            payload = cert.to_dict()
            # Genuine system binding recorded by the scanner/linker (extra.system_ids).
            payload["system_ids"] = list((cert.extra or {}).get("system_ids") or [])
            certificates.append(payload)
    except Exception:
        certificates = []

    cloud_resources = []
    for account in intel.list_cloud_accounts():
        cloud_resources.append(account.to_dict())

    # Genuine CloudResource nodes: derived from the real IaC-scan crypto assets
    # (each carries cloud_provider + resource + source_type as the scanner wrote
    # them). Linked to the owning system via the asset's SystemAsset link.
    from sqlalchemy import select
    resource_seen: set[str] = set()
    cloud_asset_rows, cloud_assets_truncated = _bounded_all(session.query(CryptoAsset))
    collection_meta["cloud_resource_assets_truncated"] = cloud_assets_truncated
    for asset in cloud_asset_rows:
        extra = asset.extra or {}
        resource = extra.get("resource")
        provider = extra.get("cloud_provider")
        if not resource or not provider:
            continue
        rkey = f"{provider}:{resource}"
        if rkey in resource_seen:
            continue
        resource_seen.add(rkey)
        sid = session.execute(
            select(SystemAsset.system_id).where(SystemAsset.asset_id == asset.id).limit(1)
        ).scalars().first()
        cloud_resources.append({
            "id": f"{provider}-{resource}",
            "resource_id": resource,
            "cloud_provider": provider,
            "resource_type": extra.get("source_type") or "CLOUD_RESOURCE",
            "name": resource,
            "system_ids": [sid] if sid else [],
        })

    # Network scan targets (real config-driven TLS probes) as NetworkResource
    # nodes, linked to their owning system when one is declared.
    network_resources = []
    for target in intel.list_targets():
        item = target.to_dict()
        item["system_ids"] = [target.system_id] if target.system_id else []
        network_resources.append(item)

    # Container scans as ContainerImage nodes (report 03's container->graph
    # gap, round 21). Honest linkage: a container scan ties to a system only
    # when its scan_id resolves to a Scan whose target_location matches a
    # system's scan_target — no link is invented for floating images.
    container_images = []
    try:
        from db.models.container_scan import ContainerScan

        container_rows, containers_truncated = _bounded_all(session.query(ContainerScan))
        collection_meta["container_scans_truncated"] = containers_truncated
        scan_targets = {
            row.id: str(row.target_location or "")
            for row in session.query(Scan).all()
        }
        target_to_system = {}
        for system in systems:
            if system.scan_target:
                target_to_system.setdefault(str(system.scan_target), system.id)
        for row in container_rows:
            system_ids = []
            scan_target = scan_targets.get(row.scan_id) if row.scan_id else None
            if scan_target and scan_target in target_to_system:
                system_ids = [target_to_system[scan_target]]
            container_images.append({
                "id": str(row.id),
                "target": row.target,
                "name": row.target,
                "image": row.target,
                "package_count": row.package_count,
                "library_count": row.library_count,
                "vuln_count": row.vuln_count,
                "system_ids": system_ids,
            })
    except Exception:
        container_images = []

    merge_code_cascade(session, system_payloads, edges)

    settings = get_graph_settings()
    if settings.ISTIO_PROMETHEUS_URL:
        name_to_id = {row["name"]: row["id"] for row in system_payloads if row.get("name")}
        for call in fetch_istio_calls(settings.ISTIO_PROMETHEUS_URL):
            parent = name_to_id.get(call["parent_id"], call["parent_id"])
            child = name_to_id.get(call["child_id"], call["child_id"])
            edges.append({**call, "parent_id": parent, "child_id": child})

    return {
        "systems": system_payloads,
        "assets": asset_payloads,
        "edges": edges,
        "processes": processes,
        "owners": owners,
        "vendors": vendors,
        "certificates": certificates,
        "cloud_resources": cloud_resources,
        "network_resources": network_resources,
        "container_images": container_images,
        "collection": collection_meta,
    }


_CODE_CASCADE_SCANS = 50


def _code_cascade_systems(session: Session) -> list[tuple[str, dict[str, Any]]]:
    """Latest per-target ``statistics.cascade.systems`` rows from completed scans.

    The scanner rolls code-level providers/dependencies up to the business
    systems declared in ``cryptoscan-systems.yml``; the worker persists that in
    ``Scan.statistics.cascade``. Newest scan per target wins.
    """
    try:
        rows = (
            session.query(Scan)
            .filter(Scan.status == "COMPLETED")
            .order_by(Scan.scan_end.desc().nullslast(), Scan.scan_start.desc())
            .limit(_CODE_CASCADE_SCANS)
            .all()
        )
    except Exception:  # pragma: no cover - defensive: graph must never fail on scan table shape
        logger.exception("code-cascade: could not read scans")
        return []
    out: list[tuple[str, dict[str, Any]]] = []
    seen_targets: set[str] = set()
    for scan in rows:
        if scan.target_location in seen_targets:
            continue
        cascade = ((scan.statistics or {}).get("cascade") or {})
        systems = cascade.get("systems") or []
        if not isinstance(systems, list):
            continue
        seen_targets.add(scan.target_location)
        for row in systems:
            if isinstance(row, dict) and row.get("system"):
                out.append((scan.id, row))
    return out


def merge_code_cascade(session: Session, system_payloads: list[dict[str, Any]], edges: list[dict[str, Any]]) -> dict[str, int]:
    """Join the scanner's business-system rollup into the CMDB system graph.

    * A rollup row whose ``system`` matches a CMDB system id or name annotates
      that node (``code_cascade``); otherwise a new ``System`` node is added
      with ``source="cryptoscan-systems.yml"`` so code-declared systems that
      the CMDB does not know about still appear in blast-radius queries.
    * ``depends_on_systems`` become ``IMPORTS`` edges (code-level evidence),
      kept distinct from CMDB ``CALLS`` edges.
    """
    by_key: dict[str, dict[str, Any]] = {}
    for payload in system_payloads:
        for key in (payload.get("id"), payload.get("name")):
            if key:
                by_key.setdefault(str(key).lower(), payload)
    existing_edges = {(e.get("parent_id"), e.get("child_id"), e.get("relation")) for e in edges}
    stats = {"annotated": 0, "added": 0, "edges": 0}
    for scan_id, row in _code_cascade_systems(session):
        sid = str(row["system"])
        summary = {
            "scan_id": scan_id,
            "providers": int(row.get("providers") or 0),
            "files": int(row.get("files") or 0),
            "algorithms": list(row.get("algorithms") or []),
            "weak_parameters": int(row.get("weak_parameters") or 0),
            "earliest_wave": row.get("earliest_wave"),
            "dependent_systems": list(row.get("dependent_systems") or []),
            "depends_on_systems": list(row.get("depends_on_systems") or []),
        }
        target = by_key.get(sid.lower())
        if target is None:
            target = {
                "id": sid,
                "name": sid,
                "owner": row.get("owner"),
                "environment": "code",
                "criticality": row.get("criticality"),
                "compliance_scopes": [],
                "asset_ids": [],
                "source": "cryptoscan-systems.yml",
            }
            system_payloads.append(target)
            by_key[sid.lower()] = target
            stats["added"] += 1
        else:
            if target.get("code_cascade"):
                continue  # an older scan of another target; newest already applied
            if not target.get("criticality") and row.get("criticality"):
                target["criticality"] = row.get("criticality")
            stats["annotated"] += 1
        target["code_cascade"] = summary
        canonical_parent = target.get("id") or sid
        for dep in summary["depends_on_systems"]:
            child = by_key.get(str(dep).lower())
            child_id = (child or {}).get("id") or str(dep)
            key = (canonical_parent, child_id, "IMPORTS")
            if key not in existing_edges:
                existing_edges.add(key)
                edges.append({"parent_id": canonical_parent, "child_id": child_id, "relation": "IMPORTS", "source": "code-cascade"})
                stats["edges"] += 1
    return stats


def graph_from_db(session: Session, *, driver=None, sync_if_empty: bool = True):
    return resolve_graph(collect_graph_payload(session), driver=driver, sync_if_empty=sync_if_empty)


def sync_graph(session: Session, *, driver=None) -> dict[str, Any]:
    from graph_engine.core.sync_coordinator import sync_payload

    payload = collect_graph_payload(session)
    result = sync_payload(payload, driver=driver)
    if not result.get("synced"):
        memory = resolve_graph(payload, driver=None, sync_if_empty=False)
        vis = memory.to_vis()
        result["nodes"] = len(vis.get("nodes") or [])
        result["edges"] = len(vis.get("edges") or [])
    result["health"] = graph_health(driver)
    # Realtime: publish a graph.updated platform event so SSE subscribers (the
    # dependency-graph page) refresh immediately rather than polling.
    try:
        from api.events.platform_events import emit_platform_event

        emit_platform_event(
            "graph.updated",
            f"Dependency graph synced ({result.get('nodes')} nodes / {result.get('edges')} edges)",
            {
                "nodes": result.get("nodes"),
                "edges": result.get("edges"),
                "synced": result.get("synced", True),
            },
            target_name="graph",
        )
    except Exception as exc:  # pragma: no cover - best effort
        logger.warning("graph_sync_event_failed: %s", exc)
    return result
