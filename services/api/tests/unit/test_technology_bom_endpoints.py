"""Technology BOM API: live materialization, snapshotting, history, compare, export.

Covers the "Live Asset Intelligence" backend — one asset model materialized into
SBOM/CBOM/HBOM/Vendor views, an immutable content-addressed snapshot versioning
scheme, per-layer version compare, and export (JSON/CSV/CycloneDX/SPDX).
"""

from __future__ import annotations

import db.models  # noqa: F401 — register all tables
import pytest
from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.connection.session import Base
from db.models import (
    BusinessProcess,
    Certificate,
    CryptoAsset,
    HardwareAsset,
    RuntimeFinding,
    Scan,
    System,
    SystemAsset,
    SystemBusinessProcess,
    SystemVendor,
    Vendor,
    Vulnerability,
)
from db.models.system_dependency import SystemDependency
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


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

    # expose the in-memory session + sessionmaker so tests can mutate state
    # between requests (StaticPool reuses a single connection for all sessions).
    application.state.test_session = session
    application.state.test_sessionmaker = Session

    session.add_all([
        System(id="sys-web", name="web-frontend", owner="platform", criticality="TIER-1"),
        System(id="sys-pay", name="payment-api", owner="payments", criticality="TIER-1"),
        System(id="sys-db", name="customer-db", owner="data", criticality="TIER-2"),
        CryptoAsset(id="ca-rsa", algorithm="RSA-2048", file_path="src/Pay.java",
                    purpose="signing", key_size=2048, confidence=1.0),
        CryptoAsset(id="ca-ec", algorithm="ECDSA-P256", file_path="src/Sign.java",
                    purpose="keyexchange", key_size=256, confidence=0.9),
        HardwareAsset(id="hw-hsm-1", asset_id="HSM-0001", manufacturer="ZELNX",
                      model="KMS-S3", device_type="hsm", firmware="7.4.1",
                      hsm=True, tpm=False, risk_level="medium"),
        Vendor(id="vendor-zelnx", name="ZELNX", criticality="HIGH", vendor_type="hsm"),
        Certificate(fingerprint_sha256="ab" * 32, subject="CN=web-frontend"),
    ])
    session.flush()
    session.add_all([
        SystemDependency(parent_id="sys-web", child_id="sys-pay"),
        SystemDependency(parent_id="sys-pay", child_id="sys-db"),
        SystemVendor(id="sv-1", system_id="sys-pay", vendor_id="vendor-zelnx",
                     dependency_type="runtime"),
    ])
    session.commit()
    try:
        yield application
    finally:
        session.close()
        engine.dispose()


@pytest.mark.asyncio
async def test_live_materializes_all_layers(app_db):
    transport = ASGITransport(app=app_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/technology-bom")
    assert resp.status_code == 200
    body = resp.json()
    assert body["live"] is True
    assert body["source"] == "technology_bom"
    # 3 systems (SBOM), 2 crypto (CBOM), 1 hardware (HBOM), 1 vendor
    assert body["components_by_layer"]["sbom"] == 3
    assert body["components_by_layer"]["cbom"] == 2
    assert body["components_by_layer"]["hbom"] == 1
    assert body["components_by_layer"]["vendor"] == 1
    assert body["total_components"] == 7
    assert len(body["fingerprint"]) == 64
    assert body["snapshot_id"].startswith("TECHBOM-")
    assert set(body["layers"].keys()) == {"sbom", "cbom", "hbom", "vendor", "certificates"}


@pytest.mark.asyncio
async def test_snapshot_then_dedup(app_db):
    transport = ASGITransport(app=app_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        first = await client.post("/api/v1/technology-bom/snapshot")
        assert first.status_code == 200
        b1 = first.json()
        assert b1["recorded"] is True
        assert b1["snapshot"]["version"] == 1
        assert b1["snapshot"]["snapshot_id"].startswith("TECHBOM-")

        # identical state -> deduplicated (no new version)
        second = await client.post("/api/v1/technology-bom/snapshot")
        b2 = second.json()
        assert b2["recorded"] is False
        assert b2["snapshot"]["version"] == 1


@pytest.mark.asyncio
async def test_compare_detects_added_component(app_db):
    transport = ASGITransport(app=app_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        v1 = await client.post("/api/v1/technology-bom/snapshot")
        assert v1.json()["recorded"] is True

        # add a NEW crypto asset (StaticPool shares one connection w/ the app)
        new_session = app_db.state.test_sessionmaker()
        new_session.add(CryptoAsset(id="ca-aes", algorithm="AES-256-GCM",
                                    file_path="src/Pay.java", purpose="encryption",
                                    key_size=256, confidence=0.8))
        new_session.commit()
        new_session.close()

        v2 = await client.post("/api/v1/technology-bom/snapshot")
        assert v2.json()["recorded"] is True
        assert v2.json()["snapshot"]["version"] == 2

        compare = await client.get(
            "/api/v1/technology-bom/compare",
            params={"from_version": 1, "to_version": 2},
        )
        assert compare.status_code == 200
        body = compare.json()
        assert body["from"]["state_version"] == 1
        assert body["to"]["state_version"] == 2
        assert body["changed"] is True
        cbom = body["layers"]["cbom"]
        assert cbom["added_count"] == 1
        added_refs = {c["bom-ref"] for c in cbom["added"]}
        assert "crypto:ca-aes:" in added_refs
        assert cbom["removed_count"] == 0


@pytest.mark.asyncio
async def test_history_and_versions(app_db):
    transport = ASGITransport(app=app_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post("/api/v1/technology-bom/snapshot")
        hist = await client.get("/api/v1/technology-bom/history")
        assert hist.status_code == 200
        hb = hist.json()
        assert hb["total_count"] == 1
        assert hb["latest_version"] == 1
        assert hb["versions"][0]["snapshot_id"].startswith("TECHBOM-")

        vers = await client.get("/api/v1/technology-bom/history/versions")
        assert vers.status_code == 200
        assert vers.json()["versions"][0]["total_components"] == 7


@pytest.mark.asyncio
async def test_export_all_formats(app_db):
    transport = ASGITransport(app=app_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        for fmt in ["json", "cyclonedx", "spdx"]:
            resp = await client.get("/api/v1/technology-bom/export", params={"fmt": fmt})
            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert body["format"] == fmt
            assert len(body["integrity_sha256"]) == 64
            assert body["snapshot_id"].startswith("TECHBOM-")
            assert body["state_version"] >= 1

        csv_resp = await client.get("/api/v1/technology-bom/export", params={"fmt": "csv"})
        assert csv_resp.status_code == 200
        assert csv_resp.headers["content-type"].startswith("text/csv")
        assert csv_resp.headers["x-zelnx-integrity-sha256"]


@pytest.mark.asyncio
async def test_export_layer_filter(app_db):
    transport = ASGITransport(app=app_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/technology-bom/export",
                                params={"fmt": "json", "layer": "cbom"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["layer"] == "cbom"
        assert body["data"]["layer"] == "cbom"


@pytest.mark.asyncio
async def test_export_historical_version(app_db):
    transport = ASGITransport(app=app_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        snap = await client.post("/api/v1/technology-bom/snapshot")
        version = snap.json()["snapshot"]["version"]
        resp = await client.get("/api/v1/technology-bom/export",
                                params={"fmt": "json", "version": version})
        assert resp.status_code == 200
        body = resp.json()
        assert body["state_version"] == version
        assert body["snapshot_id"] == snap.json()["snapshot"]["snapshot_id"]


@pytest.mark.asyncio
async def test_live_reports_scan_in_progress(app_db):
    transport = ASGITransport(app=app_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # no scan -> not in progress
        calm = await client.get("/api/v1/technology-bom")
        assert calm.status_code == 200
        assert calm.json()["scan_in_progress"] is False

        # a RUNNING scan -> partially updated BOM
        from datetime import datetime, timezone

        new_session = app_db.state.test_sessionmaker()
        new_session.add(Scan(
            id="scan-live-1", status="RUNNING",
            scan_start=datetime.now(timezone.utc),
            scanner_id="zelix", scanner_version="1.0", target_type="GIT_REPOSITORY",
            target_location="github.com/zelix", operator="test",
        ))
        new_session.commit()
        new_session.close()

        live = await client.get("/api/v1/technology-bom")
        assert live.status_code == 200
        assert live.json()["scan_in_progress"] is True
        assert "LIVE SCAN IN PROGRESS" in live.json()["live_scan_note"]

        exp = await client.get("/api/v1/technology-bom/export", params={"fmt": "json"})
        assert exp.status_code == 200
        assert exp.json()["scan_in_progress"] is True
        csvr = await client.get("/api/v1/technology-bom/export", params={"fmt": "csv"})
        assert csvr.headers.get("x-zelnx-scan-in-progress") == "true"


@pytest.mark.asyncio
async def test_export_unknown_version_404(app_db):
    transport = ASGITransport(app=app_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/technology-bom/export",
                                params={"version": 9999})
        assert resp.status_code == 404


@pytest.mark.asyncio
async def test_export_filters_and_xml_pdf(app_db):
    transport = ASGITransport(app=app_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # filtered json export (layer=cbom) via the Export Service
        r = await client.get("/api/v1/technology-bom/export",
                             params={"fmt": "json", "layer": "cbom"})
        assert r.status_code == 200
        body = r.json()
        assert body["layer"] == "cbom"
        assert "signature_hmac" in body
        assert len(body["signature_hmac"]) == 64

        xml = await client.get("/api/v1/technology-bom/export", params={"fmt": "xml"})
        assert xml.status_code == 200
        assert xml.headers["content-type"].startswith("application/xml")
        assert xml.text.startswith("<?xml")

        pdf = await client.get("/api/v1/technology-bom/export", params={"fmt": "pdf"})
        assert pdf.status_code == 200
        assert pdf.content[:5] == b"%PDF-"
        assert pdf.headers["x-zelnx-integrity-sha256"]

        bad = await client.get("/api/v1/technology-bom/export", params={"fmt": "yaml"})
        assert bad.status_code == 400


@pytest.mark.asyncio
async def test_export_schedule_crud_and_run(app_db):
    transport = ASGITransport(app=app_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        create = await client.post("/api/v1/technology-bom/export-schedules", json={
            "name": "daily-audit-export", "frequency": "daily", "fmt": "cyclonedx",
            "layer": "all", "filters": {"risk_level": "HIGH"}, "recipients": ["a@x.io"],
        })
        assert create.status_code == 200, create.text
        sched = create.json()
        assert sched["frequency"] == "daily"
        sid = sched["id"]

        lst = await client.get("/api/v1/technology-bom/export-schedules")
        assert lst.status_code == 200
        assert lst.json()["count"] == 1

        # run the schedule manually -> persists an export run
        run = await client.post(f"/api/v1/technology-bom/export-schedules/{sid}/run")
        assert run.status_code == 200, run.text
        assert run.json()["run"]["snapshot_id"].startswith("TECHBOM-")
        assert run.json()["run"]["schedule_name"] == "daily-audit-export"
        assert run.json()["run"]["content_sha256"]

        runs = await client.get("/api/v1/technology-bom/export-runs")
        assert runs.status_code == 200
        assert runs.json()["count"] >= 1

        # run-due: schedule was just run, so it is not due again (skip)
        due = await client.post("/api/v1/technology-bom/export-schedules/run-due")
        assert due.status_code == 200
        assert due.json()["ran_total"] == 0

        deactivate = await client.put(f"/api/v1/technology-bom/export-schedules/{sid}",
                                      json={"active": False})
        assert deactivate.status_code == 200
        assert deactivate.json()["active"] is False

        delete = await client.delete(f"/api/v1/technology-bom/export-schedules/{sid}")
        assert delete.status_code == 200


@pytest.mark.asyncio
async def test_export_schedule_after_scan_runs_on_new_snapshot(app_db):
    transport = ASGITransport(app=app_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # event-driven schedule -> due once a new BOM snapshot exists
        await client.post("/api/v1/technology-bom/export-schedules", json={
            "name": "after-scan-export", "frequency": "after_scan", "fmt": "json",
            "layer": "all",
        })

        # no snapshot yet -> not due
        due = await client.post("/api/v1/technology-bom/export-schedules/run-due")
        assert due.json()["ran_total"] == 0

        # create a snapshot, now the after-scan schedule is due
        await client.post("/api/v1/technology-bom/snapshot")
        due2 = await client.post("/api/v1/technology-bom/export-schedules/run-due")
        assert due2.json()["ran_total"] == 1


@pytest.mark.asyncio
async def test_evidence_package(app_db):
    transport = ASGITransport(app=app_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/api/v1/technology-bom/evidence-package")
        assert r.status_code == 200
        body = r.json()
        assert body["kind"] == "technology_bom_evidence_package"
        assert body["content_sha256"]
        assert body["signature_hmac"]
        assert body["bom"]["total_components"] == 7
        assert body["certificates"]["total"] == 1

        pdf = await client.get("/api/v1/technology-bom/evidence-package", params={"fmt": "pdf"})
        assert pdf.status_code == 200
        assert pdf.content[:5] == b"%PDF-"


@pytest.mark.asyncio
async def test_vendor_inventory(app_db):
    transport = ASGITransport(app=app_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/api/v1/technology-bom/vendor")
        assert r.status_code == 200
        body = r.json()
        assert body["vendor_count"] == 1
        v = body["vendors"][0]
        assert v["name"] == "ZELNX"
        assert v["system_count"] == 1
        assert v["systems"] == ["payment-api"]
        assert body["linkage"][0]["vendor"] == "ZELNX"
        assert body["linkage"][0]["system"] == "payment-api"


# --------------------------------------------------------------------------- #
# Assurance & Control — VEX, xBOM, admission, runtime verify
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_assurance_vex_prioritizes(app_db):
    transport = ASGITransport(app=app_db)
    session = app_db.state.test_session
    session.add_all([
        Vulnerability(id="vuln-1", cve="CVE-2024-1111", package="openssl",
                      severity="CRITICAL", summary="RSA padding oracle"),
        RuntimeFinding(id="rf-1", scanner_id="runtime", kind="session",
                       hostname="pay-01", process_name="java", algorithm="DES",
                       key_size=56, tls_version="1.0",
                       cipher_suite="TLS_RSA_WITH_DES_CBC_SHA", dedup_key="DES/pay-01"),
        SystemAsset(id="sa-1", system_id="sys-pay", asset_id="ca-rsa"),
        BusinessProcess(id="bp-1", name="Payment Processing", process_type="payments",
                        revenue_daily=100000, sla_uptime=99.99),
        SystemBusinessProcess(id="sbp-1", system_id="sys-pay", process_id="bp-1"),
    ])
    session.commit()

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/api/v1/technology-bom/assurance")
    assert r.status_code == 200
    body = r.json()
    assert body["vex"] is not None
    assert body["vex"]["total"] >= 1
    by_cve = {f["cve"]: f for f in body["vex"]["findings"]}
    assert by_cve["CVE-2024-1111"]["priority"] in ("P0", "P1")
    assert "admission" in body and "xbom" in body
    assert body["xbom"]["layer_set"] == ["sbom", "cbom", "hbom", "vendor"]
    assert body["xbom"]["count"] >= 1
    assert body["runtime_verify"] is not None
    assert body["runtime_verify"]["drifted"] >= 1


@pytest.mark.asyncio
async def test_admission_endpoint_return_shape(app_db):
    transport = ASGITransport(app=app_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/api/v1/technology-bom/admission")
    assert r.status_code == 200
    body = r.json()
    assert body["source"] == "technology_bom"
    assert body["decision"] in ("PASS", "WARN", "FAIL")
    assert "blocking" in body and "warnings" in body
    assert "snapshot_id" in body and "state_version" in body


@pytest.mark.asyncio
async def test_vex_empty_when_no_vulns(app_db):
    transport = ASGITransport(app=app_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/api/v1/technology-bom/vex")
    assert r.status_code == 200
    body = r.json()
    assert body["vex"] is None
    assert "note" in body


@pytest.mark.asyncio
async def test_runtime_verify_endpoint(app_db):
    transport = ASGITransport(app=app_db)
    app_db.state.test_session.add(
        RuntimeFinding(id="rf-2", scanner_id="runtime", kind="session",
                       hostname="db-01", process_name="python", algorithm="RC4",
                       key_size=128, tls_version="", cipher_suite="TLS_RSA_WITH_RC4_128_SHA",
                       dedup_key="RC4/db-01"))
    app_db.state.test_session.commit()
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/api/v1/technology-bom/runtime-verify")
    assert r.status_code == 200
    body = r.json()
    assert body["runtime_verify"] is not None
    assert body["runtime_verify"]["observed"] >= 1
