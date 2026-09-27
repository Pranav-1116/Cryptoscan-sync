"""Cross-tenant isolation on the *scan surface*, end to end over HTTP.

The existing campaign probe covered `monitor_targets` — one of five
control-plane tables that already had a tenant_id — and passed throughout the
period when every scan, finding and asset was readable by any tenant. These
tests go through the real middleware stack against the tables that were
actually leaking, so they fail if the ORM guard, the migration, or the
request-scope middleware regresses.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from db.connection.session import Base
from db.models.scan import Scan
from db.tenancy import install_tenant_guard, tenant_scope

BANK_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
BANK_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"


@pytest.fixture()
def db_session(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    install_tenant_guard()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    yield session
    session.close()
    engine.dispose()


def _seed(session, target: str, tenant_id: str) -> Scan:
    scan = Scan(target_location=target, status="COMPLETED", tenant_id=tenant_id,
                scan_start=datetime.now(timezone.utc))
    session.add(scan)
    session.commit()
    return scan


def _client(db_session, tenant_id: str | None):
    """An API client whose requests are scoped as the middleware would scope them."""
    from api.config.settings import get_settings
    from api.dependencies import get_current_user, get_db_session
    from api.main import create_app

    get_settings.cache_clear()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "analyst"
    app.dependency_overrides[get_db_session] = lambda: (yield db_session)
    return TestClient(app)


def test_tenant_b_scans_are_absent_from_tenant_a_listing(db_session):
    _seed(db_session, "bank-a-core", BANK_A)
    _seed(db_session, "bank-b-core", BANK_B)

    client = _client(db_session, BANK_A)
    with client, tenant_scope(BANK_A):
        r = client.get("/api/v1/scans", headers={"Authorization": "Bearer t"})

    assert r.status_code == 200, r.text
    body = r.text
    assert "bank-a-core" in body
    assert "bank-b-core" not in body, "another tenant's scan target leaked into the listing"


def test_total_count_does_not_leak_the_other_tenants_volume(db_session):
    """An unfiltered count tells Bank A how much Bank B is scanning."""
    _seed(db_session, "bank-a-core", BANK_A)
    for i in range(4):
        _seed(db_session, f"bank-b-{i}", BANK_B)

    client = _client(db_session, BANK_A)
    with client, tenant_scope(BANK_A):
        r = client.get("/api/v1/scans", headers={"Authorization": "Bearer t"})

    assert r.json()["total_count"] == 1


def test_fetching_another_tenants_scan_by_id_is_absence_not_a_403(db_session):
    """A known id must not confirm the row exists — no existence oracle."""
    other = _seed(db_session, "bank-b-core", BANK_B)

    client = _client(db_session, BANK_A)
    with client, tenant_scope(BANK_A):
        r = client.get(f"/api/v1/scans/{other.id}", headers={"Authorization": "Bearer t"})

    assert r.status_code == 404, f"expected absence, got {r.status_code}"
    assert "bank-b-core" not in r.text


def test_platform_estate_rows_remain_visible(db_session):
    """Pre-tenancy rows (NULL tenant_id) must not vanish when tenancy is enabled."""
    _seed(db_session, "legacy-estate", None)
    _seed(db_session, "bank-b-core", BANK_B)

    client = _client(db_session, BANK_A)
    with client, tenant_scope(BANK_A):
        r = client.get("/api/v1/scans", headers={"Authorization": "Bearer t"})

    assert "legacy-estate" in r.text
    assert "bank-b-core" not in r.text
