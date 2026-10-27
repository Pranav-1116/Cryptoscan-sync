"""The tenant_id chain, end to end, over the real HTTP stack.

Frontend picker → memberships endpoint → X-Tenant-ID header →
TenantScopeMiddleware → ORM scope → tenant-stamped row → scoped list →
tenant_id visible in the payload. Each link has its own tests; this file
pins the CONNECTION: any seam that breaks the chain (a header nobody
reads, a stamp nobody writes, a list that forgets the owner) fails here
by name.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from api.main import create_app
from api.middleware.tenant_scope import TenantScopeMiddleware
from api.security.passwords import hash_password
from api.security.session_manager import SessionManager
from db.connection.session import Base, configure_session, SessionLocal
from db.models.cascade_extensions import CascadeWatch
from db.models.tenant import Tenant, TenantMembership
from db.repositories.user_repository import UserRepository
from db.tenancy import platform_scope


@pytest.fixture()
def e2e():
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False},
        poolclass=StaticPool)
    Base.metadata.create_all(engine)
    configure_session(engine)
    session = SessionLocal()

    # One authorized writer, member of two orgs: membership must still pin
    # each write/read even though the application role permits cascade edits.
    users = UserRepository(session)
    users.create_user("dual_member", hash_password("x"), ["security_analyst"])
    session.add_all([
        Tenant(id="acme", name="Acme Bank", slug="acme"),
        Tenant(id="globex", name="Globex", slug="globex"),
        TenantMembership(tenant_id="acme", username="dual_member",
                         tenant_role="member"),
        TenantMembership(tenant_id="globex", username="dual_member",
                         tenant_role="owner"),
    ])
    session.commit()

    app = create_app()
    app.add_middleware(TenantScopeMiddleware)  # the real production stack

    manager = SessionManager()
    token = manager.create_session("dual_member", roles=[])
    UserRepository(session).create_session(
        token, "dual_member",
        datetime.now(timezone.utc) + timedelta(hours=1), ip="127.0.0.1")
    session.commit()
    client = TestClient(app)
    client.cookies.set("cryptoscan_session", token)

    try:
        yield {"client": client, "session": session}
    finally:
        session.close()
        engine.dispose()
        app.dependency_overrides.clear()


def test_the_whole_tenant_chain(e2e):
    client, session = e2e["client"], e2e["session"]

    # 1) the picker's directory: memberships derive from the membership
    #    table, never from a caller-supplied tenant id
    res = client.get("/api/v1/saas/memberships")
    assert res.status_code == 200
    orgs = {t["id"]: t["tenant_role"] for t in res.json()["tenants"]}
    assert orgs == {"acme": "member", "globex": "owner"}

    # 2) the header the picker sets is what the backend resolves: whoami
    #    reflects the selected org
    as_acme = client.get("/api/v1/saas/whoami",
                         headers={"X-Tenant-ID": "acme"})
    assert as_acme.json()["tenant_id"] == "acme"
    as_globex = client.get("/api/v1/saas/whoami",
                           headers={"X-Tenant-ID": "globex"})
    assert as_globex.json()["tenant_id"] == "globex"

    # 3) a write under the acme header lands as an acme-owned row — the
    #    stamp the ORM writes is the tenant the header selected
    created = client.post("/api/v1/technology-bom/cascade/watch",
                          headers={"X-Tenant-ID": "acme"},
                          json={"target": "acme-core", "kind": "system"})
    assert created.status_code == 200, created.text
    watch_id = created.json()["id"]
    with platform_scope():
        row = session.query(CascadeWatch).filter_by(id=watch_id).one()
    assert row.tenant_id == "acme"

    # 4) the list is scoped AND names its owner: acme sees its row with
    #    tenant_id in the payload (DB column -> API surface -> console)
    acme_list = client.get("/api/v1/technology-bom/cascade/watches",
                           headers={"X-Tenant-ID": "acme"}).json()
    assert acme_list["count"] == 1
    assert acme_list["watches"][0]["target"] == "acme-core"
    assert acme_list["watches"][0]["tenant_id"] == "acme"

    # 5) globex sees none of it — the same endpoint, another partition
    globex_list = client.get("/api/v1/technology-bom/cascade/watches",
                             headers={"X-Tenant-ID": "globex"}).json()
    assert globex_list["count"] == 0

    # 6) switching the header switches the world: globex's own watch is
    #    visible only to globex, acme's list is unchanged
    client.post("/api/v1/technology-bom/cascade/watch",
                headers={"X-Tenant-ID": "globex"},
                json={"target": "globex-core", "kind": "system"})
    globex_list = client.get("/api/v1/technology-bom/cascade/watches",
                             headers={"X-Tenant-ID": "globex"}).json()
    assert [w["target"] for w in globex_list["watches"]] == ["globex-core"]
    assert all(w["tenant_id"] == "globex" for w in globex_list["watches"])
    acme_list = client.get("/api/v1/technology-bom/cascade/watches",
                           headers={"X-Tenant-ID": "acme"}).json()
    assert [w["target"] for w in acme_list["watches"]] == ["acme-core"]

    # 7) both rows exist — two tenants, two owners, one table
    with platform_scope():
        all_rows = session.query(CascadeWatch).all()
    assert {r.tenant_id for r in all_rows} == {"acme", "globex"}

    # 8) a multi-member request without a header is refused — the chain
    #    requires an explicit choice, it never guesses
    no_header = client.get("/api/v1/saas/whoami")
    assert no_header.status_code == 400

    # 9) a header the user does not belong to is refused — the picker's
    #    options and the middleware's acceptance are the same set
    forged = client.get("/api/v1/saas/whoami",
                        headers={"X-Tenant-ID": "acme"})
    assert forged.status_code == 200  # member of acme: fine
    stranger = client.get("/api/v1/saas/whoami",
                          headers={"X-Tenant-ID": "someone-else"})
    assert stranger.status_code in (403, 404)
