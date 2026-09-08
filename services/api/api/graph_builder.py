"""Build a graph view from PostgreSQL / SQLite, then prefer Neo4j."""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session

from db.models.certificate import Certificate
from db.models.crypto_asset import CryptoAsset
from db.models.system_asset import SystemAsset
from db.repositories.intelligence_repository import IntelligenceRepository
from db.repositories.system_repository import SystemRepository
from graph_engine.config.settings import get_graph_settings
from graph_engine.core.facade import graph_health, resolve_graph
from graph_engine.service_mesh.istio_client import fetch_istio_calls

logger = logging.getLogger(__name__)


def collect_graph_payload(session: Session) -> dict[str, Any]:
    systems_repo = SystemRepository(session)
    intel = IntelligenceRepository(session)
    systems, _ = systems_repo.list_systems(page=1, page_size=500)
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
        asset_payloads = [row.to_dict() for row in session.query(CryptoAsset).limit(500).all()]
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
        for cert in session.query(Certificate).limit(500).all():
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
    from db.models.system_asset import SystemAsset
    resource_seen: set[str] = set()
    for asset in session.query(CryptoAsset).limit(500).all():
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
    }


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
