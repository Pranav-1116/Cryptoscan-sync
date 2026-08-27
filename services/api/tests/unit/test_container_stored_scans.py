"""Stored container scans: fetch, SBOM, metrics, drift vs previous run."""

from __future__ import annotations

import time

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.connection.session import Base
from db.models.container_scan import ContainerScan  # noqa: F401 — register table


def _result(scan_id, packages, vulns=None, secrets=None):
    return {
        "scan_id": scan_id,
        "target": "registry.local/app:1.0",
        "target_kind": "registry",
        "packages": packages,
        "libraries": [],
        "binaries": [],
        "vulnerabilities": vulns or [],
        "secrets": secrets or [],
        "findings": [],
        "risk_report": {
            "posture": "FAIL" if secrets else ("WARN" if vulns else "PASS"),
            "cve_severity_counts": {
                "CRITICAL": 0, "HIGH": len(vulns or []), "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0
            },
        },
        "scan_telemetry": {
            "status": "OK", "packages": len(packages), "libraries_fingerprinted": 0,
            "binaries": 0, "vulnerabilities": len(vulns or []), "secrets": len(secrets or []),
            "files_scanned": 10, "fingerprint_hit_rate": None,
            "packages_by_manager": {"pip": len(packages)},
            "secrets_by_kind": {kind: 1 for kind in {str(sec.get("kind")) for sec in (secrets or [])} if kind != "None"},
        },
    }


@pytest.fixture()
def app_db():
    from sqlalchemy.pool import StaticPool

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    session = Session()

    application = create_app()
    application.dependency_overrides[get_current_user] = lambda: "testuser"
    def _session():
        yield session

    application.dependency_overrides[get_db_session] = _session

    old_row = ContainerScan(
        scan_id="scan-old", target="registry.local/app:1.0",
        package_count=1, library_count=0, vuln_count=0,
        result=_result("scan-old", [{"name": "openssl", "version": "3.0.7", "manager": "pip"}]),
    )
    session.add(old_row)
    session.flush()
    time.sleep(0.01)
    new_row = ContainerScan(
        scan_id="scan-new", target="registry.local/app:1.0",
        package_count=1, library_count=0, vuln_count=1,
        result=_result(
            "scan-new",
            [{"name": "openssl", "version": "3.0.7", "manager": "pip"}],
            vulns=[{"cve": "CVE-2023-0286", "package": "openssl", "severity": "HIGH"}],
            secrets=[{"kind": "pem-private-key", "path": ".env", "line_number": 2, "confidence": "HIGH"}],
        ),
    )
    session.add(new_row)
    session.flush()
    try:
        yield application
    finally:
        session.close()
        engine.dispose()


@pytest.mark.asyncio
async def test_get_stored_scan(app_db):
    transport = ASGITransport(app=app_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        found = await client.get("/api/v1/container/scans/scan-new")
        missing = await client.get("/api/v1/container/scans/nope")
    assert found.status_code == 200
    assert found.json()["packages"][0]["name"] == "openssl"
    assert missing.status_code == 404


@pytest.mark.asyncio
async def test_stored_scan_sbom(app_db):
    transport = ASGITransport(app=app_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/container/scans/scan-old/sbom")
    assert response.status_code == 200
    sbom = response.json()
    assert sbom["bomFormat"] == "CycloneDX" and sbom["specVersion"] == "1.5"
    purls = [component["purl"] for component in sbom["components"]]
    assert "pkg:pypi/openssl@3.0.7" in purls


@pytest.mark.asyncio
async def test_stored_scan_metrics(app_db):
    transport = ASGITransport(app=app_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/container/scans/scan-new/metrics")
    assert response.status_code == 200
    assert "version=0.0.4" in response.headers["content-type"]
    assert "cryptoscan_container_packages 1" in response.text
    assert 'cryptoscan_container_secrets_by_kind{kind="pem-private-key"} 1' in response.text
    assert 'cryptoscan_container_posture{posture="FAIL"} 1' in response.text


@pytest.mark.asyncio
async def test_stored_scan_drift_vs_previous(app_db):
    transport = ASGITransport(app=app_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/container/scans/scan-new/drift")
    assert response.status_code == 200
    report = response.json()
    assert report["verdict"] == "REGRESSED"
    types = [change["type"] for change in report["changes"]]
    assert "NEW_CVE" in types
    assert "NEW_HARDCODED_SECRET" in types
    assert report["previous_scan_id"] == "scan-old"
    assert report["current_scan_id"] == "scan-new"


@pytest.mark.asyncio
async def test_first_scan_drift_is_honest(app_db):
    transport = ASGITransport(app=app_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/container/scans/scan-old/drift")
    assert response.status_code == 200
    payload = response.json()
    assert payload["verdict"] == "UNCHANGED"
    assert "needs two" in payload["detail"]


@pytest.mark.asyncio
async def test_inline_sbom_endpoint(app_db):
    transport = ASGITransport(app=app_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/v1/container/sbom",
            json={"result": _result("inline", [{"name": "cryptography", "version": "41.0.7", "manager": "pip"}])},
        )
    assert response.status_code == 200
    assert "pkg:pypi/cryptography@41.0.7" in [c.get("purl") for c in response.json()["components"]]


@pytest.mark.asyncio
async def test_stored_scan_spdx(app_db):
    transport = ASGITransport(app=app_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        found = await client.get("/api/v1/container/scans/scan-old/spdx")
        missing = await client.get("/api/v1/container/scans/nope/spdx")
    assert found.status_code == 200
    doc = found.json()
    assert doc["spdxVersion"] == "SPDX-2.3" and doc["dataLicense"] == "CC0-1.0"
    purls = [
        ref["referenceLocator"]
        for pkg in doc["packages"]
        for ref in pkg.get("externalRefs", [])
    ]
    assert "pkg:pypi/openssl@3.0.7" in purls
    assert missing.status_code == 404
