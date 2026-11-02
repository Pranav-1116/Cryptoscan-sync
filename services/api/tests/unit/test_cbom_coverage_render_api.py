"""Coverage is stated in the API and in the estate document, not only in a module.

Review items 18 and 19: the asset count has to arrive with the coverage that
qualifies it, and an empty document has to say why it is empty.
"""

from __future__ import annotations

import asyncio

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.connection.session import Base


@pytest.fixture()
def app_and_session():
    engine = create_engine("sqlite:///:memory:",
                           connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    application = create_app()
    application.dependency_overrides[get_current_user] = lambda: "auditor"

    def _session():
        yield session

    application.dependency_overrides[get_db_session] = _session
    application.state.db_session = session
    yield application, session
    application.dependency_overrides.clear()


def _get(client, path):
    async def go():
        async with ASGITransport(app=client) as transport:
            async with AsyncClient(transport=transport, base_url="http://test") as http:
                return await http.get(f"/api/v1{path}",
                                      headers={"Authorization": "Bearer test-token"})

    return asyncio.run(go())


def test_an_empty_estate_makes_no_coverage_claim(app_and_session):
    application, _session = app_and_session
    body = _get(application, "/cbom/coverage").json()
    assert body["inventory"]["completeness"] == "UNKNOWN"
    assert body["inventory"]["may_report_total"] is False
    assert body["quotable"]["phrasing"] == "FLOOR"
    assert "not what exists" in body["inventory"]["statement"]
    assert "the size of the estate is unknown" not in body["quotable"]["text"]


def test_a_scanned_system_makes_the_count_quotable(app_and_session):
    from datetime import datetime, timezone

    from db.models.system import System

    application, session = app_and_session
    session.add(System(name="payments-api", scan_target="https://git/payments",
                       coverage_status="CURRENT",
                       last_scanned_at=datetime.now(timezone.utc)))
    session.commit()
    body = _get(application, "/cbom/coverage").json()
    inventory = body["inventory"]
    assert inventory["systems_total"] == 1 and inventory["systems_inspected"] == 1
    assert inventory["completeness"] == "COMPLETE"
    assert inventory["may_report_total"] is True
    assert body["quotable"]["phrasing"] == "TOTAL"
    assert "0 crypto asset(s) discovered" in inventory["statement"]
