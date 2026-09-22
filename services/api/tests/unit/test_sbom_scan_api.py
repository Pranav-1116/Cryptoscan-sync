"""E2E SBOM scanner API: scan source tree -> persist hash-signed artifact ->
list + download with sha256 provenance, role gating, and target validation."""

from __future__ import annotations

import hashlib
import json

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.connection.session import Base


@pytest.fixture()
def app_db(tmp_path, monkeypatch):
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    session = Session()

    application = create_app()
    application.dependency_overrides[get_current_user] = lambda: "operator"
    # artifacts live in a per-test dir, not the production volume; the tmp tree
    # must also be an allowed scan root (fail-closed source-path policy)
    monkeypatch.setenv("SBOM_STORAGE_DIR", str(tmp_path / "sboms"))
    monkeypatch.setenv("CRYPTOSCAN_SOURCE_ROOTS", str(tmp_path))
    import api.routers.devsecops as ds

    monkeypatch.setattr(ds, "_SBOM_STORE", None)

    def _session():
        yield session

    application.dependency_overrides[get_db_session] = _session
    yield application, session, tmp_path
    application.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_scan_source_persists_and_downloads(app_db):
    application, session, tmp_path = app_db
    src = tmp_path / "app"
    (src / "sub").mkdir(parents=True)
    (src / "requirements.txt").write_text("requests==2.31.0\ncryptography>=3.4\nflask\n")
    (src / "sub" / "package.json").write_text(json.dumps({"dependencies": {"express": "4.18.0"}}))

    async with ASGITransport(app=application) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/api/v1/devsecops/sbom/scan",
                json={"kind": "source", "target": str(src), "format": "cyclonedx"},
                headers={"Authorization": "Bearer test-token"},
            )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    man = body["manifest"]
    assert man["kind"] == "source" and man["format"] == "cyclonedx"
    assert man["component_count"] == 4
    assert man["manifest_count"] == 2
    assert man["crypto_components"] == 1  # cryptography
    assert man["unpinned"] == 2  # cryptography range + flask missing
    assert body["bom"]["bomFormat"] == "CycloneDX" and body["bom"]["specVersion"] == "1.5"
    artifact_id = body["artifact_id"]

    # artifact is listed
    async with ASGITransport(app=application) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/devsecops/sbom/artifacts",
                                    headers={"Authorization": "Bearer test-token"})
    assert resp.status_code == 200
    arts = resp.json()["artifacts"]
    assert any(a["artifact_id"] == artifact_id for a in arts)

    # download returns the exact persisted bytes with sha256 provenance
    async with ASGITransport(app=application) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(f"/api/v1/devsecops/sbom/{artifact_id}/download",
                                    headers={"Authorization": "Bearer test-token"})
    assert resp.status_code == 200
    payload = resp.content
    assert hashlib.sha256(payload).hexdigest() == man["sha256"]
    assert resp.headers.get("x-sbom-sha256") == man["sha256"]
    assert "attachment" in resp.headers.get("content-disposition", "")
    assert json.loads(payload)["bomFormat"] == "CycloneDX"

    # audit trail recorded
    from db.models.user import AuditLog

    rows = session.execute(
        select(AuditLog).where(AuditLog.target_id == artifact_id)
    ).scalars().all()
    assert rows and rows[0].action == "devsecops.sbom_scan"
    assert rows[0].actor == "operator"


@pytest.mark.asyncio
async def test_scan_source_spdx_format(app_db):
    application, session, tmp_path = app_db
    src = tmp_path / "app"
    src.mkdir()
    (src / "requirements.txt").write_text("cryptography==42.0.0\n")

    async with ASGITransport(app=application) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/api/v1/devsecops/sbom/scan",
                json={"kind": "source", "target": str(src), "format": "spdx"},
                headers={"Authorization": "Bearer test-token"},
            )
    assert resp.status_code == 201, resp.text
    bom = resp.json()["bom"]
    assert bom["spdxVersion"] == "SPDX-2.3"
    assert any(p["name"] == "cryptography" for p in bom["packages"])


@pytest.mark.asyncio
async def test_scan_rejects_escaping_target(app_db):
    application, session, tmp_path = app_db
    async with ASGITransport(app=application) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/api/v1/devsecops/sbom/scan",
                json={"kind": "source", "target": "/etc/passwd"},
                headers={"Authorization": "Bearer test-token"},
            )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_scan_rejects_bad_kind_and_format(app_db):
    application, session, tmp_path = app_db
    async with ASGITransport(app=application) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            r1 = await client.post(
                "/api/v1/devsecops/sbom/scan",
                json={"kind": "dockerfile", "target": str(tmp_path)},
                headers={"Authorization": "Bearer test-token"},
            )
            r2 = await client.post(
                "/api/v1/devsecops/sbom/scan",
                json={"kind": "source", "target": str(tmp_path), "format": "swf"},
                headers={"Authorization": "Bearer test-token"},
            )
    assert r1.status_code == 422
    assert r2.status_code == 422


@pytest.mark.asyncio
async def test_download_unknown_artifact_404(app_db):
    application, session, tmp_path = app_db
    fake = "00000000-0000-4000-8000-000000000000"
    async with ASGITransport(app=application) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            h = {"Authorization": "Bearer test-token"}
            r1 = await client.get(f"/api/v1/devsecops/sbom/{fake}/download", headers=h)
            r2 = await client.get("/api/v1/devsecops/sbom/../../etc/passwd/download", headers=h)
    assert r1.status_code == 404
    assert r2.status_code in (404, 405)


def _viewer_app(tmp_path, monkeypatch):
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    session = Session()
    from db.models.user import User

    session.add(User(username="viewer1", password_hash="x", roles="viewer"))
    session.commit()

    application = create_app()
    application.dependency_overrides[get_current_user] = lambda: "viewer1"
    monkeypatch.setenv("SBOM_STORAGE_DIR", str(tmp_path / "sboms"))
    monkeypatch.setenv("CRYPTOSCAN_SOURCE_ROOTS", str(tmp_path))
    import api.routers.devsecops as ds

    monkeypatch.setattr(ds, "_SBOM_STORE", None)

    def _session():
        yield session

    application.dependency_overrides[get_db_session] = _session
    return application


@pytest.mark.asyncio
async def test_scan_forbidden_for_viewer(app_db, tmp_path, monkeypatch):
    application = _viewer_app(tmp_path / "viewer-store", monkeypatch)
    async with ASGITransport(app=application) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            r1 = await client.post(
                "/api/v1/devsecops/sbom/scan",
                json={"kind": "source", "target": str(tmp_path)},
                headers={"Authorization": "Bearer viewer-token"},
            )
            r2 = await client.get("/api/v1/devsecops/sbom/artifacts",
                                  headers={"Authorization": "Bearer viewer-token"})
    assert r1.status_code == 403
    assert r2.status_code == 403
