"""Round 22 (report 13 §2.2): BU → System → Asset grant inheritance.

A grant on a business unit applies to every system whose ``business_unit``
matches and to those systems' assets. Restriction flows down the same path:
once ANY grant exists for a BU, its systems are under grant control.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register tables
from api.config.settings import get_settings
from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.connection.session import Base
from db.models.crypto_asset import CryptoAsset
from db.models.system import System
from db.models.system_asset import SystemAsset

SECRET = "r22-grants-secret-" + "z" * 20


@pytest.fixture()
def session():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    TestSession = sessionmaker(bind=engine, expire_on_commit=False)
    s = TestSession()
    try:
        yield s
    finally:
        s.close()
        engine.dispose()


def _seed(session):
    payments = System(id="sys-pay", name="payments", business_unit="payments-bu")
    shared = System(id="sys-shared", name="shared", business_unit=None)
    asset = CryptoAsset(algorithm="AES", purpose="ENCRYPTION", file_path="a.java", line_number=1)
    session.add_all([payments, shared, asset])
    session.flush()
    session.add(SystemAsset(system_id="sys-pay", asset_id=asset.id))
    session.commit()
    return asset.id


# --------------------------------------------------------------------- #
# Repository: inheritance semantics
# --------------------------------------------------------------------- #

def test_bu_grant_opens_system_and_restriction_flows_down(session):
    from db.repositories.resource_grant_repository import ResourceGrantRepository

    _seed(session)
    repo = ResourceGrantRepository(session)
    # unrestricted before any grant
    assert repo.system_is_restricted("sys-pay") is False
    assert repo.system_check_access("alice", "sys-pay", "operator") is True

    # a grant on the BU restricts the BU's systems (no direct system grant)
    repo.grant("alice", "BUSINESS_UNIT", "payments-bu", "operator")
    session.commit()
    assert repo.system_is_restricted("sys-pay") is True
    assert repo.system_is_restricted("sys-shared") is False  # other BU-less system untouched
    assert repo.system_check_access("alice", "sys-pay", "operator") is True
    assert repo.system_check_access("bob", "sys-pay", "viewer") is False  # no grant at all
    assert repo.system_check_access("alice", "sys-shared", "viewer") is True  # not restricted

    # direct system grant outranks inherited BU grant
    repo.grant("carol", "SYSTEM", "sys-pay", "viewer")
    session.commit()
    assert repo.system_effective_role("alice", "sys-pay") == "operator"
    assert repo.system_effective_role("carol", "sys-pay") == "viewer"


def test_asset_inherits_through_system_and_bu(session):
    from db.repositories.resource_grant_repository import ResourceGrantRepository

    asset_id = _seed(session)
    repo = ResourceGrantRepository(session)

    # no grants anywhere: unrestricted
    assert repo.asset_is_restricted(asset_id) is False
    assert repo.asset_check_access("alice", asset_id, "operator") is True

    # BU grant restricts the asset through its owning system
    repo.grant("alice", "BUSINESS_UNIT", "payments-bu", "owner")
    session.commit()
    assert repo.asset_is_restricted(asset_id) is True
    assert repo.asset_effective_role("alice", asset_id) == "owner"
    assert repo.asset_check_access("alice", asset_id, "operator") is True
    assert repo.asset_check_access("bob", asset_id, "viewer") is False

    # a direct ASSET grant also works standalone (finest grain)
    repo.grant("bob", "ASSET", asset_id, "viewer")
    session.commit()
    assert repo.asset_effective_role("bob", asset_id) == "viewer"
    assert repo.asset_check_access("bob", asset_id, "viewer") is True
    assert repo.asset_check_access("bob", asset_id, "operator") is False


# --------------------------------------------------------------------- #
# API: BU grant management + inherited enforcement
# --------------------------------------------------------------------- #

def _make_app(current_user="alice", admin_override=False):
    import os

    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", SECRET)
    get_settings.cache_clear()
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    from db.models.user import User

    session.add(User(username="alice", roles="developer", password_hash="x"))
    _seed(session)
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: current_user
    if admin_override:
        from api.dependencies import require_admin

        app.dependency_overrides[require_admin] = lambda: current_user
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    return app, session, engine


@pytest.mark.asyncio
async def test_bu_grant_management_endpoints():
    app, session, engine = _make_app(current_user="admin", admin_override=True)
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/api/v1/systems/business-units/payments-bu/grants",
                json={"subject": "alice", "role": "operator"},
            )
            assert resp.status_code == 200, resp.text
            assert resp.json() == {
                "business_unit": "payments-bu",
                "subject": "alice",
                "role": "operator",
                "restricted": True,
            }

            resp = await client.get("/api/v1/systems/business-units/payments-bu/grants")
            assert resp.status_code == 200
            body = resp.json()
            assert body["restricted"] is True
            assert body["systems_inheriting"] == ["sys-pay"]
            assert body["grants"][0]["subject"] == "alice"

            # revoke returns the BU to open
            resp = await client.delete(
                "/api/v1/systems/business-units/payments-bu/grants/alice"
            )
            assert resp.status_code == 200
            assert resp.json()["restricted"] is False
    finally:
        engine.dispose()


@pytest.mark.asyncio
async def test_bu_grant_gates_system_reads_and_writes():
    # admin seeds a BU grant; alice (developer) then accesses the system
    app, session, engine = _make_app(current_user="admin", admin_override=True)
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/api/v1/systems/business-units/payments-bu/grants",
                json={"subject": "alice", "role": "viewer"},
            )
            assert resp.status_code == 200

        app.dependency_overrides[get_current_user] = lambda: "alice"
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # read (viewer) passes through the inherited grant
            resp = await client.get("/api/v1/systems/sys-pay")
            assert resp.status_code == 200, resp.text

            # write (operator) is beyond the inherited viewer role
            resp = await client.patch(
                "/api/v1/systems/sys-pay", json={"description": "nope"}
            )
            assert resp.status_code == 403
            assert "grant-restricted" in resp.json()["detail"]

            # the BU-less system is untouched by the BU grant
            resp = await client.get("/api/v1/systems/sys-shared")
            assert resp.status_code == 200

            # the system grants view reports the inherited restriction
            app.dependency_overrides[get_current_user] = lambda: "admin"
            resp = await client.get("/api/v1/systems/sys-pay/grants")
            assert resp.status_code == 200
            body = resp.json()
            assert body["restricted"] is True
            assert body["restricted_by"] == "BUSINESS_UNIT"
            assert body["business_unit"] == "payments-bu"
            assert body["business_unit_grants"][0]["subject"] == "alice"
    finally:
        engine.dispose()


@pytest.mark.asyncio
async def test_asset_lifecycle_gated_by_inherited_bu_grant():
    app, session, engine = _make_app(current_user="admin", admin_override=True)
    try:
        asset_id = (
            session.query(CryptoAsset).filter(CryptoAsset.algorithm == "AES").first().id
        )
        transport = ASGITransport(app=app)
        # the lifecycle route authenticates through require_auditor
        from api.dependencies import require_auditor

        app.dependency_overrides[require_auditor] = lambda: (
            app.dependency_overrides[get_current_user]()
        )
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # operator on the BU: lifecycle (write) allowed via inheritance
            resp = await client.post(
                "/api/v1/systems/business-units/payments-bu/grants",
                json={"subject": "alice", "role": "operator"},
            )
            assert resp.status_code == 200

            app.dependency_overrides[get_current_user] = lambda: "alice"
            resp = await client.post(
                f"/api/v1/inventory/assets/{asset_id}/lifecycle",
                json={"to_state": "VERIFIED", "reason": "r22 test"},
            )
            assert resp.status_code == 200, resp.text

            # demote alice to viewer: the write is now forbidden
            app.dependency_overrides[get_current_user] = lambda: "admin"
            resp = await client.post(
                "/api/v1/systems/business-units/payments-bu/grants",
                json={"subject": "alice", "role": "viewer"},
            )
            assert resp.status_code == 200

            app.dependency_overrides[get_current_user] = lambda: "alice"
            resp = await client.post(
                f"/api/v1/inventory/assets/{asset_id}/lifecycle",
                json={"to_state": "ACTIVE", "reason": "should fail"},
            )
            assert resp.status_code == 403
            assert "grant-restricted" in resp.json()["detail"]

            # an unrelated user with no grant anywhere is locked out too
            app.dependency_overrides[get_current_user] = lambda: "mallory"
            resp = await client.post(
                f"/api/v1/inventory/assets/{asset_id}/lifecycle",
                json={"to_state": "ACTIVE", "reason": "should fail"},
            )
            assert resp.status_code == 403
    finally:
        engine.dispose()
