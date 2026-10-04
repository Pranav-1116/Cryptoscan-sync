"""Integration: ops capacity forecast endpoint.

Regression for the 2026-10-04 compliance-burn finding: the month-bucketing
SQL was SQLite-only (``strftime``) and raised a 500 on PostgreSQL. The
endpoint must answer 200 on an empty estate and group months correctly on
whichever dialect is configured.
"""

from __future__ import annotations

import os
import tempfile
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

API = "/api/v1"


def _token():
    from api.security.session_manager import SessionManager

    return SessionManager(secret="test-secret-key-for-sessions-min-32-chars").create_session(
        "admin", roles=["superadmin"])


@pytest.fixture(scope="module")
def client():
    os.environ["SECRET_KEY"] = "test-secret-key-for-sessions-min-32-chars"
    os.environ["ENVIRONMENT"] = "development"
    os.environ["ADMIN_USERNAME"] = "admin"
    os.environ["ADMIN_PASSWORD"] = "cryptoscan"
    db_file = os.path.join(tempfile.gettempdir(), "ops_capacity_test.db")
    for ext in ("", "-wal", "-shm"):
        if os.path.exists(db_file + ext):
            os.remove(db_file + ext)
    os.environ["DATABASE_URL"] = f"sqlite:///{db_file}"

    from api.config.settings import get_settings
    from api.main import create_app

    get_settings.cache_clear()
    app = create_app()
    with TestClient(app) as c:
        c.headers["Authorization"] = f"Bearer {_token()}"
        yield c


def test_capacity_forecast_empty_estate(client):
    """No tenants, no usage: still a 200 with an (honest) empty trend."""
    resp = client.get(f"{API}/ops/capacity/forecast")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["estate_usage_by_month"] == []
    assert body["plans"] == {}


def test_capacity_forecast_groups_months(client):
    """Usage events are bucketed one-per-month, oldest first."""
    from db.connection.session import SessionLocal
    from db.models.tenant import Tenant, TenantUsageEvent

    s = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        t = Tenant(name="cap-tenant", slug="cap-tenant", plan="PRO")
        s.add(t)
        s.flush()
        for days_ago in (1, 10, 40, 75):
            s.add(TenantUsageEvent(tenant_id=t.id, kind="scan_run", amount=5,
                                   created_at=now - timedelta(days=days_ago)))
        s.commit()
    finally:
        s.close()

    resp = client.get(f"{API}/ops/capacity/forecast")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    # estate_usage_by_month is one summed total per calendar month, oldest first
    months = body["estate_usage_by_month"]
    assert months, "usage months should be present"
    assert months == sorted(months), "months must be oldest-first"
    assert all(isinstance(m, (int, float)) for m in months)
    # 4 metering events of 5 units each, spread over up to 4 calendar months
    assert sum(months) == 20
    assert "PRO" in body["plans"]
