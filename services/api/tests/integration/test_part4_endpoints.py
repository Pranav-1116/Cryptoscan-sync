from __future__ import annotations

from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api.dependencies import get_db_session
from db.connection.session import Base
from db.repositories.job_repository import JobRepository
from db.repositories.maturity_repository import MaturityRepository


@pytest.fixture
def durable_db(app):
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    previous = app.dependency_overrides.get(get_db_session)
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        app.dependency_overrides[get_db_session] = lambda: session
        yield session
    if previous is None:
        app.dependency_overrides.pop(get_db_session, None)
    else:
        app.dependency_overrides[get_db_session] = previous
    engine.dispose()


class TestPart4Endpoints:
    @pytest.mark.asyncio
    async def test_ot_scan_passive(self, authenticated_client: AsyncClient,
                                   durable_db, tmp_path: Path, monkeypatch):
        (tmp_path / "modbus.log").write_text(
            "ts=2024-01-15T10:00:00 src=10.0.2.28 dst=10.0.2.1 port=502 proto=modbus tls=false\n"
        )
        # The OT scan path is now source-root bounded (product vision §4.1):
        # declare this test's tmp dir an allowed root and pin the admission
        # seams — this test exercises the passive collector, not admission.
        monkeypatch.setenv("CRYPTOSCAN_SOURCE_ROOTS", str(tmp_path))
        from api.security import scan_admission as admission

        monkeypatch.setattr(admission, "_control_plane_state", lambda: ([], None))
        monkeypatch.setattr(admission, "_ot_declared", lambda: False)
        monkeypatch.setattr(admission, "_active_job_count", lambda: 0)
        response = await authenticated_client.post("/api/v1/ot/scan", json={"path": str(tmp_path)})
        assert response.status_code == 200
        body = response.json()
        assert body["packets_sent"] == 0
        assert body["findings"]
        assert body["findings"][0]["compliance_issue"] == "OT_UNENCRYPTED_MODBUS"
        job = JobRepository(durable_db).get_by_id(body["job_id"])
        assert job.status == "COMPLETED"
        assert job.progress["coverage"]["findings_count"] == len(body["findings"])
        assert MaturityRepository(durable_db).list_ot_findings()

    @pytest.mark.asyncio
    async def test_cloud_scan_arm(self, authenticated_client: AsyncClient, tmp_path: Path):
        (tmp_path / "azuredeploy.json").write_text(
            '{"$schema":"https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",'
            '"resources":[{"type":"Microsoft.Storage/storageAccounts","name":"logs",'
            '"properties":{"supportsHttpsTrafficOnly":false}}]}'
        )
        response = await authenticated_client.post("/api/v1/cloud/scan", json={"path": str(tmp_path), "live": False})
        assert response.status_code == 200
        assert response.json()["issues"] >= 1
