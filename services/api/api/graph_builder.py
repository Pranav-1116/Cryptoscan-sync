"""Build a GraphEngine from the current database."""

from __future__ import annotations

from sqlalchemy.orm import Session

from db.models.crypto_asset import CryptoAsset
from db.models.system_asset import SystemAsset
from db.repositories.intelligence_repository import IntelligenceRepository
from db.repositories.system_repository import SystemRepository
from graph_engine.core.engine import GraphEngine


def graph_from_db(session: Session) -> GraphEngine:
    systems_repo = SystemRepository(session)
    intel = IntelligenceRepository(session)
    systems, _ = systems_repo.list_systems(page=1, page_size=500)
    system_payloads = []
    edges = []
    asset_payloads = []
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
            edges.append({"parent_id": edge.parent_id, "child_id": edge.child_id, "relation": edge.relation or "CALLS"})
        for asset in assets:
            payload = asset.to_dict()
            payload["system_id"] = system.id
            asset_payloads.append(payload)
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
    owners = [row.to_dict() for row in intel.list_owners()]
    return GraphEngine().build(
        systems=system_payloads,
        assets=asset_payloads,
        edges=edges,
        processes=processes,
        owners=owners,
        vendors=vendors,
    )
