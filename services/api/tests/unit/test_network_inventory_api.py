"""API contract tests for the structured network inventory lifecycle."""
from __future__ import annotations


import pytest
from httpx import ASGITransport, AsyncClient

from api.dependencies import get_current_user, get_db_session
from api.main import create_app


class _InventoryRow:
    def __init__(self, inventory_id: str, revision: int, **values):
        self.id = f"inventory-revision-{revision}"
        self.inventory_id = inventory_id
        self.revision = revision
        for key, value in values.items():
            setattr(self, key, value)
        self.tenant_id = "tenant-test"

    def to_dict(self, exclude=None):
        data = {
            "id": self.id,
            "inventory_id": self.inventory_id,
            "revision": self.revision,
            "status": self.status,
            "source": self.source,
            "schema_version": self.schema_version,
            "inventory": self.inventory_json,
            "completeness": self.completeness_json,
            "content_sha256": self.content_sha256,
            "captured_at": self.captured_at.isoformat() if self.captured_at else None,
            "created_by": self.created_by,
            "reviewed_by": self.reviewed_by,
            "review_notes": self.review_notes,
            "tenant_id": self.tenant_id,
        }
        for key in exclude or set():
            data.pop(key, None)
        return data


class _InventoryRepo:
    rows: list[_InventoryRow] = []

    def __init__(self, _db):
        pass

    def latest(self, inventory_id="default"):
        rows = [row for row in self.rows if row.inventory_id == inventory_id]
        return max(rows, key=lambda row: row.revision, default=None)

    def history(self, inventory_id="default", limit=50):
        return sorted(
            [row for row in self.rows if row.inventory_id == inventory_id],
            key=lambda row: row.revision,
            reverse=True,
        )[:limit]

    def create_revision(self, inventory_id="default", **values):
        revision = (self.latest(inventory_id).revision + 1) if self.latest(inventory_id) else 1
        row = _InventoryRow(inventory_id, revision, **values)
        self.rows.append(row)
        return row


@pytest.fixture()
def inventory_app(monkeypatch):
    import db.repositories.network_inventory_repository as inventory_repository

    _InventoryRepo.rows = []
    monkeypatch.setattr(inventory_repository, "NetworkInventoryRepository", _InventoryRepo)
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "operator@example.test"

    def _session():
        yield object()

    app.dependency_overrides[get_db_session] = _session
    return app


@pytest.mark.asyncio
async def test_inventory_schema_and_empty_state_are_authenticated(inventory_app):
    transport = ASGITransport(app=inventory_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        schema = await client.get("/api/v1/network/inventory/schema")
        current = await client.get("/api/v1/network/inventory")

    assert schema.status_code == 200
    assert schema.json()["properties"]["schema"]["default"] == "cryptoscan.network-inventory/1"
    assert current.status_code == 200
    assert current.json()["persisted"] is False
    assert current.json()["completeness"]["status"] == "INCOMPLETE"


@pytest.mark.asyncio
async def test_inventory_write_history_risk_topology_and_drift(inventory_app):
    payload = {
        "inventory_id": "core-network",
        "inventory": {
            "inventory_id": "core-network",
            "devices": [{"device_id": "r1", "device_type": "router", "management_ip": "10.0.0.1"}],
            "configuration": {"snapshots": [
                {"snapshot_id": "baseline", "device_id": "r1", "kind": "BASELINE", "content_sha256": "a" * 64},
                {"snapshot_id": "running", "device_id": "r1", "kind": "RUNNING", "content_sha256": "b" * 64},
            ]},
            "topology": {"graph_edges": [{"source": "r1", "target": "missing-r2", "relationship": "CONNECTED_TO"}]},
        },
        "status": "DRAFT",
        "source": "CONFIG_IMPORT",
    }
    transport = ASGITransport(app=inventory_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        saved = await client.put("/api/v1/network/inventory", json=payload)
        history = await client.get("/api/v1/network/inventory/history?inventory_id=core-network")
        risk = await client.get("/api/v1/network/inventory/risk?inventory_id=core-network")
        topology = await client.get("/api/v1/network/inventory/topology?inventory_id=core-network")
        drift = await client.get("/api/v1/network/inventory/configuration/drift?inventory_id=core-network")
        coverage = await client.get("/api/v1/network/inventory/coverage?inventory_id=core-network")

    assert saved.status_code == 200
    assert saved.json()["revision"] == 1
    assert history.status_code == 200
    assert len(history.json()["revisions"]) == 1
    assert risk.json()["posture"] == "RED"
    assert topology.json()["unknown_endpoints"] == ["missing-r2"]
    assert drift.json()["status"] == "DRIFTED"
    assert coverage.json()["configuration_drift"]["drifted_comparisons"] == 1


@pytest.mark.asyncio
async def test_inventory_api_rejects_secret_and_approval_without_evidence(inventory_app):
    transport = ASGITransport(app=inventory_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        secret = await client.post("/api/v1/network/inventory/validate", json={
            "inventory": {"network_services": {"authentication": {"password": "never"}}}
        })
        approval = await client.put("/api/v1/network/inventory", json={
            "inventory": {"devices": [{"device_id": "r1", "device_type": "router", "management_ip": "10.0.0.1"}]},
            "status": "APPROVED",
            "reviewed_by": "operator@example.test",
        })

    assert secret.status_code == 422
    assert approval.status_code == 422
    assert "approval_issues" in approval.json()["detail"]


@pytest.mark.asyncio
async def test_discovery_endpoint_persists_a_draft_without_raw_scan_data(inventory_app, monkeypatch):
    import network_scanner.enterprise.engine as discovery_engine

    monkeypatch.setattr(discovery_engine, "run_network_discovery", lambda *args, **kwargs: {
        "assets": [{"asset_identity": "r1", "ip_addresses": ["10.0.0.1"], "device_type": "router"}],
        "topology": {"nodes": ["r1"], "edges": []},
        "scan_metadata": {"mode": "SAFE"},
        "asset_summary": {"router": 1},
    })
    transport = ASGITransport(app=inventory_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/v1/network/inventory/discover", json={
            "scope_specs": ["10.0.0.0/24"],
            "inventory_id": "discovered-network",
        })

    assert response.status_code == 200
    assert response.json()["status"] == "DRAFT"
    assert response.json()["inventory"]["evidence"][0]["status"] == "UNVERIFIED"
    assert "assets" not in response.json()
