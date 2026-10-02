"""End-to-end tenant_id isolation for vendor and network API surfaces."""
from __future__ import annotations

import os

import pytest
from httpx import ASGITransport, AsyncClient
from starlette.requests import Request
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401
from api.dependencies import TenantResolutionRefused, get_current_user, get_db_session
from api.main import create_app
from db.connection.session import Base
from db.models.network_inventory import NetworkInventoryRevision
from db.models.vendor import Vendor
from db.models.vendor_crypto import VendorCryptoInventory
from db.models.vendor_profile import VendorProfileRevision
from db.tenancy import install_tenant_guard

TENANT_A = "tenant-a-11111111-1111-1111-1111-111111111111"
TENANT_B = "tenant-b-22222222-2222-2222-2222-222222222222"


def _make_app():
    # Keep this focused harness independent of the caller's process settings.
    os.environ["ENVIRONMENT"] = "test"
    os.environ.setdefault("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    from api.config.settings import get_settings

    get_settings.cache_clear()
    install_tenant_guard()
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    app = create_app()
    # Test environment intentionally omits auth/tenant middleware in the
    # broad API harness. Add the real tenant middleware here so these requests
    # exercise the request boundary, ContextVar scope, and ORM guard together.
    from api.middleware.tenant_scope import TenantScopeMiddleware

    app.add_middleware(TenantScopeMiddleware)

    def current_user(request: Request):
        return request.headers.get("X-Test-User", "user-a")

    app.dependency_overrides[get_current_user] = current_user

    def db_session():
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise

    app.dependency_overrides[get_db_session] = db_session
    return app, session, engine


def _tenant_resolution(request):
    """Test the real middleware/ORM scope with an explicit membership map.

    The production resolver performs the membership lookup; this test replaces
    only that lookup so the in-memory API session remains the same session used
    by the routes. The middleware, tenant_scope context, ORM loader criteria,
    and tenant stamping all remain real.
    """
    user = request.headers.get("X-Test-User", "user-a")
    expected = {"user-a": TENANT_A, "user-b": TENANT_B}.get(user)
    requested = request.headers.get("X-Tenant-ID")
    if expected is None:
        raise TenantResolutionRefused(403, "no tenant membership")
    if requested and requested != expected:
        raise TenantResolutionRefused(404, "Unknown tenant")
    return expected


def _headers(user: str, tenant: str | None = None) -> dict[str, str]:
    result = {"X-Test-User": user}
    if tenant:
        result["X-Tenant-ID"] = tenant
    return result


@pytest.mark.asyncio
async def test_vendor_and_network_rows_are_isolated_end_to_end(monkeypatch):
    app, session, engine = _make_app()
    import api.dependencies as dependencies

    monkeypatch.setattr(dependencies, "resolve_tenant_for_request", _tenant_resolution)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        vendor_a = (await client.post(
            "/api/v1/vendors",
            headers=_headers("user-a", TENANT_A),
            json={"name": "Tenant A Vendor"},
        )).json()
        vendor_b = (await client.post(
            "/api/v1/vendors",
            headers=_headers("user-b", TENANT_B),
            json={"name": "Tenant B Vendor"},
        )).json()

        profile_a = (await client.get(
            f"/api/v1/vendors/{vendor_a['id']}/profile",
            headers=_headers("user-a", TENANT_A),
        )).json()["profile"]
        profile_b = (await client.get(
            f"/api/v1/vendors/{vendor_b['id']}/profile",
            headers=_headers("user-b", TENANT_B),
        )).json()["profile"]
        saved_a = await client.put(
            f"/api/v1/vendors/{vendor_a['id']}/profile",
            headers=_headers("user-a", TENANT_A),
            json={"profile": profile_a, "status": "DRAFT"},
        )
        saved_b = await client.put(
            f"/api/v1/vendors/{vendor_b['id']}/profile",
            headers=_headers("user-b", TENANT_B),
            json={"profile": profile_b, "status": "DRAFT"},
        )

        network_a = await client.put(
            "/api/v1/network/inventory",
            headers=_headers("user-a", TENANT_A),
            json={"inventory_id": "default", "inventory": {"devices": [{
                "device_id": "a-router", "device_type": "router", "management_ip": "10.10.0.1",
            }]}},
        )
        network_b = await client.put(
            "/api/v1/network/inventory",
            headers=_headers("user-b", TENANT_B),
            json={"inventory_id": "default", "inventory": {"devices": [{
                "device_id": "b-router", "device_type": "router", "management_ip": "10.20.0.1",
            }]}},
        )
        network_b_private = await client.put(
            "/api/v1/network/inventory",
            headers=_headers("user-b", TENANT_B),
            json={"inventory_id": "tenant-b-only", "inventory": {"devices": [{
                "device_id": "b-private-router", "device_type": "router", "management_ip": "10.20.1.1",
            }]}},
        )

        vendors_a = await client.get("/api/v1/vendors", headers=_headers("user-a", TENANT_A))
        vendors_b = await client.get("/api/v1/vendors", headers=_headers("user-b", TENANT_B))
        inventory_a = await client.get("/api/v1/network/inventory", headers=_headers("user-a", TENANT_A))
        inventory_b = await client.get("/api/v1/network/inventory", headers=_headers("user-b", TENANT_B))
        inventory_b_private_for_a = await client.get(
            "/api/v1/network/inventory",
            params={"inventory_id": "tenant-b-only"},
            headers=_headers("user-a", TENANT_A),
        )
        inventory_b_private_for_b = await client.get(
            "/api/v1/network/inventory",
            params={"inventory_id": "tenant-b-only"},
            headers=_headers("user-b", TENANT_B),
        )
        history_a = await client.get(
            "/api/v1/network/inventory/history", headers=_headers("user-a", TENANT_A)
        )
        history_b = await client.get(
            "/api/v1/network/inventory/history", headers=_headers("user-b", TENANT_B)
        )

        vendor_a_detail = await client.get(
            f"/api/v1/vendors/{vendor_a['id']}", headers=_headers("user-a", TENANT_A)
        )
        vendor_a_schema = await client.get(
            f"/api/v1/vendors/{vendor_a['id']}/profile/schema",
            headers=_headers("user-a", TENANT_A),
        )
        profile_history_a = await client.get(
            f"/api/v1/vendors/{vendor_a['id']}/profile/history",
            headers=_headers("user-a", TENANT_A),
        )
        questionnaire_a = await client.get(
            f"/api/v1/vendors/{vendor_a['id']}/questionnaire",
            headers=_headers("user-a", TENANT_A),
        )
        risk_a = await client.get(
            f"/api/v1/vendors/{vendor_a['id']}/risk", headers=_headers("user-a", TENANT_A)
        )
        risks_a = await client.get("/api/v1/vendor-risks", headers=_headers("user-a", TENANT_A))
        questionnaire_write_a = await client.post(
            f"/api/v1/vendors/{vendor_a['id']}/questionnaire",
            headers=_headers("user-a", TENANT_A),
            json={"transit": "TLS 1.3", "rest": "AES-256", "kms": "HSM", "pqc": "Planned"},
        )

        cross_vendor = await client.get(
            f"/api/v1/vendors/{vendor_b['id']}/profile",
            headers=_headers("user-a", TENANT_A),
        )
        cross_vendor_detail = await client.get(
            f"/api/v1/vendors/{vendor_b['id']}", headers=_headers("user-a", TENANT_A)
        )
        cross_vendor_schema = await client.get(
            f"/api/v1/vendors/{vendor_b['id']}/profile/schema",
            headers=_headers("user-a", TENANT_A),
        )
        cross_profile_history = await client.get(
            f"/api/v1/vendors/{vendor_b['id']}/profile/history",
            headers=_headers("user-a", TENANT_A),
        )
        cross_questionnaire = await client.get(
            f"/api/v1/vendors/{vendor_b['id']}/questionnaire",
            headers=_headers("user-a", TENANT_A),
        )
        cross_risk = await client.get(
            f"/api/v1/vendors/{vendor_b['id']}/risk", headers=_headers("user-a", TENANT_A)
        )
        cross_profile_validate = await client.post(
            f"/api/v1/vendors/{vendor_b['id']}/profile/validate",
            headers=_headers("user-a", TENANT_A),
            json={"profile": profile_b, "status": "DRAFT"},
        )
        cross_profile_write = await client.put(
            f"/api/v1/vendors/{vendor_b['id']}/profile",
            headers=_headers("user-a", TENANT_A),
            json={"profile": profile_b, "status": "DRAFT"},
        )
        cross_profile_evidence = await client.post(
            f"/api/v1/vendors/{vendor_b['id']}/profile/evidence",
            headers=_headers("user-a", TENANT_A),
            json={
                "evidence_id": "tenant-b-evidence",
                "evidence_type": "OTHER",
                "evidence_reference": "evidence://tenant-b",
            },
        )
        cross_questionnaire_write = await client.post(
            f"/api/v1/vendors/{vendor_b['id']}/questionnaire",
            headers=_headers("user-a", TENANT_A),
            json={},
        )
        cross_cbom = await client.post(
            f"/api/v1/vendors/{vendor_b['id']}/cbom",
            headers=_headers("user-a", TENANT_A),
            json={"sbom": {}},
        )
        cross_docs = await client.post(
            f"/api/v1/vendors/{vendor_b['id']}/docs",
            headers=_headers("user-a", TENANT_A),
            json={"text": "no credentials or secrets"},
        )
        cross_patch = await client.patch(
            f"/api/v1/vendors/{vendor_b['id']}",
            headers=_headers("user-a", TENANT_A),
            json={"criticality": "HIGH"},
        )
        cross_expire = await client.delete(
            f"/api/v1/vendors/{vendor_b['id']}/profile",
            headers=_headers("user-a", TENANT_A),
        )
        cross_api_scan = await client.post(
            f"/api/v1/vendors/{vendor_b['id']}/api-scan",
            headers=_headers("user-a", TENANT_A),
            json={"endpoint": "example.invalid"},
        )
        cross_inventory = await client.get(
            "/api/v1/network/inventory",
            headers=_headers("user-a", TENANT_B),
        )
        cross_inventory_history = await client.get(
            "/api/v1/network/inventory/history",
            params={"inventory_id": "tenant-b-only"},
            headers=_headers("user-a", TENANT_A),
        )
        cross_inventory_risk = await client.get(
            "/api/v1/network/inventory/risk",
            params={"inventory_id": "tenant-b-only"},
            headers=_headers("user-a", TENANT_A),
        )
        cross_inventory_topology = await client.get(
            "/api/v1/network/inventory/topology",
            params={"inventory_id": "tenant-b-only"},
            headers=_headers("user-a", TENANT_A),
        )
        cross_inventory_drift = await client.get(
            "/api/v1/network/inventory/configuration/drift",
            params={"inventory_id": "tenant-b-only"},
            headers=_headers("user-a", TENANT_A),
        )
        cross_inventory_coverage = await client.get(
            "/api/v1/network/inventory/coverage",
            params={"inventory_id": "tenant-b-only"},
            headers=_headers("user-a", TENANT_A),
        )
        default_tenant = await client.get(
            "/api/v1/vendors",
            headers=_headers("user-a"),
        )

    assert saved_a.status_code == 200
    assert saved_b.status_code == 200
    assert network_a.status_code == 200
    assert network_b.status_code == 200
    assert network_b_private.status_code == 200
    assert vendor_a_detail.status_code == 200
    assert vendor_a_schema.status_code == 200
    assert profile_history_a.status_code == 200
    assert questionnaire_a.status_code == 200
    assert risk_a.status_code == 200
    assert risks_a.status_code == 200
    assert questionnaire_write_a.status_code == 200, questionnaire_write_a.text
    assert {row["name"] for row in vendors_a.json()["vendors"]} == {"Tenant A Vendor"}
    assert {row["name"] for row in vendors_b.json()["vendors"]} == {"Tenant B Vendor"}
    assert inventory_a.json()["inventory"]["devices"][0]["device_id"] == "a-router"
    assert inventory_b.json()["inventory"]["devices"][0]["device_id"] == "b-router"
    assert inventory_b_private_for_a.status_code == 200
    assert inventory_b_private_for_a.json()["persisted"] is False
    assert inventory_b_private_for_a.json()["revision"] is None
    assert "b-private-router" not in str(inventory_b_private_for_a.json())
    assert inventory_b_private_for_b.status_code == 200
    assert inventory_b_private_for_b.json()["persisted"] is True
    assert inventory_b_private_for_b.json()["inventory"]["devices"][0]["device_id"] == "b-private-router"
    assert history_a.status_code == 200
    assert history_b.status_code == 200
    assert len(history_a.json()["revisions"]) == 1
    assert len(history_b.json()["revisions"]) == 1
    assert cross_vendor.status_code == 404
    assert cross_vendor_detail.status_code == 404
    assert cross_vendor_schema.status_code == 404
    assert cross_profile_history.status_code == 404
    assert cross_questionnaire.status_code == 404
    assert cross_risk.status_code == 404
    assert cross_profile_validate.status_code == 404
    assert cross_profile_write.status_code == 404
    assert cross_profile_evidence.status_code == 404
    assert cross_questionnaire_write.status_code == 404
    assert cross_cbom.status_code == 404
    assert cross_docs.status_code == 404
    assert cross_patch.status_code == 404
    assert cross_expire.status_code == 404
    assert cross_api_scan.status_code == 404
    assert cross_inventory.status_code == 404
    assert cross_inventory_history.status_code == 200
    assert cross_inventory_history.json()["revisions"] == []
    assert cross_inventory_risk.status_code == 200
    assert cross_inventory_risk.json()["revision"] is None
    assert cross_inventory_topology.status_code == 200
    assert cross_inventory_topology.json()["revision"] is None
    assert cross_inventory_drift.status_code == 200
    assert cross_inventory_drift.json()["revision"] is None
    assert cross_inventory_coverage.status_code == 200
    assert cross_inventory_coverage.json()["revision"] is None
    assert default_tenant.status_code == 200
    assert {row["name"] for row in default_tenant.json()["vendors"]} == {"Tenant A Vendor"}

    vendor_rows = session.execute(select(Vendor).order_by(Vendor.name)).scalars().all()
    profile_rows = session.execute(select(VendorProfileRevision)).scalars().all()
    inventory_rows = session.execute(select(NetworkInventoryRevision)).scalars().all()
    crypto_rows = session.execute(select(VendorCryptoInventory)).scalars().all()
    assert {(row.name, row.tenant_id) for row in vendor_rows} == {
        ("Tenant A Vendor", TENANT_A),
        ("Tenant B Vendor", TENANT_B),
    }
    assert {(row.vendor_id, row.tenant_id) for row in profile_rows} == {
        (vendor_a["id"], TENANT_A),
        (vendor_b["id"], TENANT_B),
    }
    assert {(row.inventory_id, row.tenant_id) for row in inventory_rows} == {
        ("default", TENANT_A),
        ("default", TENANT_B),
        ("tenant-b-only", TENANT_B),
    }
    assert crypto_rows
    assert {row.tenant_id for row in crypto_rows} == {TENANT_A}
    assert {row.vendor_id for row in crypto_rows} == {vendor_a["id"]}
    session.close()
    engine.dispose()


@pytest.mark.asyncio
async def test_production_tenant_resolution_is_exercised_over_http(monkeypatch):
    """Use real membership resolution, not the narrow resolver shim above."""
    app, session, engine = _make_app()
    app.dependency_overrides.pop(get_current_user, None)

    from db.connection import session as connection
    from db.repositories.tenant_repository import TenantRepository
    from api.security.session_manager import SessionManager

    # TenantScopeMiddleware's resolver uses SessionLocal, while route
    # handlers use the in-memory dependency override. Point the production
    # resolver at a fresh session bound to this same in-memory engine.
    real_session_factory = sessionmaker(bind=engine, expire_on_commit=False)
    monkeypatch.setattr(connection, "SessionLocal", real_session_factory)

    tenants = TenantRepository(session)
    tenants.ensure_user("member-a")
    tenants.ensure_user("member-b")
    tenants.ensure_user("orphan-user")
    tenants.ensure_user("multi-user")
    tenant_a = tenants.create(name="Real Alpha", slug="real-alpha", created_by="member-a")
    tenant_b = tenants.create(name="Real Beta", slug="real-beta", created_by="member-b")
    tenants.add_member(tenant_a.id, "member-a", "member")
    tenants.add_member(tenant_b.id, "member-b", "member")
    tenants.add_member(tenant_a.id, "multi-user", "member")
    tenants.add_member(tenant_b.id, "multi-user", "member")
    session.commit()

    def auth(username: str) -> dict[str, str]:
        token = SessionManager().create_session(username, roles=["readonly"])
        return {"Authorization": f"Bearer {token}"}

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        created_a = await client.post(
            "/api/v1/vendors",
            headers=auth("member-a"),
            json={"name": "Real Alpha Vendor"},
        )
        created_b = await client.post(
            "/api/v1/vendors",
            headers=auth("member-b"),
            json={"name": "Real Beta Vendor"},
        )
        listed_a = await client.get("/api/v1/vendors", headers=auth("member-a"))
        cross_b = await client.get(
            f"/api/v1/vendors/{created_b.json()['id']}/profile",
            headers=auth("member-a"),
        )
        orphan = await client.get("/api/v1/vendors", headers=auth("orphan-user"))
        forged = await client.get(
            "/api/v1/vendors",
            headers={**auth("member-a"), "X-Tenant-ID": tenant_b.id},
        )
        ambiguous = await client.get("/api/v1/vendors", headers=auth("multi-user"))

    assert created_a.status_code == 200, created_a.text
    assert created_b.status_code == 200, created_b.text
    assert {row["name"] for row in listed_a.json()["vendors"]} == {"Real Alpha Vendor"}
    assert cross_b.status_code == 404
    assert orphan.status_code == 403
    assert forged.status_code == 404
    assert ambiguous.status_code == 400
    session.close()
    engine.dispose()


@pytest.mark.asyncio
async def test_tenant_middleware_fails_closed_for_unknown_and_ambiguous_requests(monkeypatch):
    app, session, engine = _make_app()
    import api.dependencies as dependencies

    monkeypatch.setattr(dependencies, "resolve_tenant_for_request", _tenant_resolution)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        unknown_user = await client.get(
            "/api/v1/vendors", headers=_headers("not-a-member", TENANT_A)
        )
        forged_tenant = await client.get(
            "/api/v1/vendors", headers=_headers("user-a", TENANT_B)
        )

    assert unknown_user.status_code == 403
    assert forged_tenant.status_code == 404
    session.close()
    engine.dispose()
