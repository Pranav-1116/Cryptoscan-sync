"""Intelligence router endpoint tests — evidence pack, agility, work-orders,
gate, materials, quantum, transfer import/export (previously untested)."""

from __future__ import annotations

import hashlib
import io
import zipfile
from datetime import datetime, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register all tables
from api.dependencies import get_current_user, get_db_session, require_auditor
from api.main import create_app
from db.connection.session import Base
from db.models.evidence_record import EvidenceRecord
from db.models.scan import Scan
from evidence.hashing.chain_hasher import ChainHasher
from evidence.hashing.content_hasher import ContentHasher


def _make_app():
    import os

    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    from api.config.settings import get_settings

    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:",
                           connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "intel-tester"
    app.dependency_overrides[require_auditor] = lambda: "intel-auditor"
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    return app, session


def _seed(session, *, scan_id: str = "scan-1", algorithm: str = "DES"):
    evidence_id = "ev-intelligence"
    finding = {"scanner_id": "s", "metadata": {}}
    content_hash = ContentHasher.compute_hash(finding)
    session.add(Scan(
        id=scan_id, scan_start=datetime(2026, 8, 29, tzinfo=timezone.utc),
        target_location="https://github.com/org/legacy.git",
        target_type="GIT_REPOSITORY", status="COMPLETED",
        statistics={"total_findings": 1},
        manifest_hash=hashlib.sha256(evidence_id.encode()).hexdigest(),
    ))
    session.add(EvidenceRecord(
        id=evidence_id, scan_id=scan_id, content_hash=content_hash,
        chain_hash=ChainHasher.compute_chain_hash(content_hash, scan_session_id=scan_id),
        chain_position=0, previous_hash=None, algorithm=algorithm,
        confidence="HIGH", purpose="ENCRYPTION", mode="CBC", key_size=56,
        file_path="src/Pay.java", line_number=7, finding_data=finding,
        compliance_status="FAIL",
    ))
    session.flush()


class _AppClient:
    """AsyncClient wrapper that also exposes the test DB session."""

    def __init__(self, client: AsyncClient, session):
        self.client = client
        self.session = session

    async def get(self, *args, **kwargs):
        return await self.client.get(*args, **kwargs)

    async def post(self, *args, **kwargs):
        return await self.client.post(*args, **kwargs)


@pytest.fixture
def app_client():
    app, session = _make_app()
    _seed(session)
    transport = ASGITransport(app=app)
    yield _AppClient(AsyncClient(transport=transport, base_url="http://test"), session)
    session.close()


@pytest.mark.asyncio
async def test_evidence_pack_download(app_client):
    response = await app_client.get("/api/v1/scans/scan-1/evidence-pack")
    assert response.status_code == 200
    assert response.headers["content-disposition"].startswith("attachment")
    body = response.json()
    assert body["pack_format"] == "cryptoscan-evidence-pack"
    assert "records" in body


@pytest.mark.asyncio
async def test_evidence_pack_missing_scan_404(app_client):
    response = await app_client.get("/api/v1/scans/nope/evidence-pack")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_verify_pack_round_trip(app_client):
    # build a real pack via the endpoint, then verify it via /verify
    pack = (await app_client.get(
        "/api/v1/scans/scan-1/evidence-pack")).json()
    response = await app_client.post(
        "/api/v1/evidence-pack/verify", json={"pack": pack})
    assert response.status_code == 200
    verification = response.json()
    assert verification["result"] == "PASS"
    assert verification["chain_intact"] is True


@pytest.mark.asyncio
async def test_agility_and_work_orders(app_client):
    agility = await app_client.get("/api/v1/scans/scan-1/agility")
    assert agility.status_code == 200
    assert "score" in agility.json() or "factors" in agility.json()

    orders = await app_client.get("/api/v1/scans/scan-1/work-orders")
    assert orders.status_code == 200
    assert isinstance(orders.json(), (dict, list))


@pytest.mark.asyncio
async def test_gate_and_sarif(app_client):
    gate = await app_client.get("/api/v1/scans/scan-1/gate")
    assert gate.status_code == 200
    body = gate.json()
    assert "decision" in body
    assert "sarif" in body

    sarif = await app_client.get("/api/v1/scans/scan-1/gate.sarif")
    assert sarif.status_code == 200
    sarif_body = sarif.json()
    assert sarif_body["version"] == "2.1.0"


@pytest.mark.asyncio
async def test_materials(app_client):
    response = await app_client.get("/api/v1/scans/scan-1/materials")
    assert response.status_code == 200
    assert "count" in response.json()


@pytest.mark.asyncio
async def test_quantum_risk(app_client):
    response = await app_client.get("/api/v1/scans/scan-1/quantum")
    assert response.status_code == 200
    assert isinstance(response.json(), dict)


@pytest.mark.asyncio
async def test_audit_pack_zip(app_client):
    response = await app_client.get("/api/v1/scans/scan-1/audit-pack")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/zip"
    assert response.content[:2] == b"PK"


@pytest.mark.asyncio
async def test_legacy_raw_evidence_is_redacted_without_mutating_the_chain(app_client):
    row = app_client.session.query(EvidenceRecord).first()
    raw = {
        "source": {"file_path": "src/Pay.java", "line_number": 7,
                   "code_snippet": "SECRET_KEY=synthetic-legacy-secret"},
        "crypto": {"algorithm": "DES", "raw_transformation": "synthetic-legacy-secret"},
        "metadata": {"confidence": "HIGH", "is_hardcoded_key": True},
        "inventory": {"key_label": "test-key", "raw_value": "synthetic-legacy-secret"},
    }
    row.finding_data = raw
    row.is_hardcoded_key = True
    app_client.session.commit()
    original_hash = row.content_hash

    detail = await app_client.get(f"/api/v1/findings/{row.id}")
    exported = await app_client.get("/api/v1/scans/scan-1/export")
    materials = await app_client.get("/api/v1/scans/scan-1/materials")
    audit = await app_client.get("/api/v1/scans/scan-1/audit-pack")
    transfer = await app_client.get("/api/v1/scans/scan-1/transfer")
    assert all(r.status_code == 200 for r in (detail, exported, materials, audit))
    assert transfer.status_code == 409
    for response in (detail, exported, materials):
        assert "synthetic-legacy-secret" not in response.text
    with zipfile.ZipFile(io.BytesIO(audit.content)) as archive:
        assert "synthetic-legacy-secret" not in "".join(
            archive.read(name).decode("utf-8", errors="replace") for name in archive.namelist()
        )
    app_client.session.refresh(row)
    assert row.finding_data == raw
    assert row.content_hash == original_hash


@pytest.mark.asyncio
async def test_transfer_export_and_import_round_trip(app_client):
    exported = await app_client.get("/api/v1/scans/scan-1/transfer")
    assert exported.status_code == 200
    payload = exported.json()
    assert payload["transfer_format"] == "cryptoscan-scan-transfer"
    assert payload["digests"]["payload_digest"]
    assert payload["digests"]["records_digest"]

    # simulate a fresh instance: remove the scan, then import the payload
    scan = app_client.session.get(Scan, "scan-1")
    app_client.session.delete(scan)
    app_client.session.commit()

    imported = await app_client.post("/api/v1/scans/import",
                                     json=payload)
    assert imported.status_code == 200
    body = imported.json()
    assert body["imported"] is True
    assert body["records"] >= 1

    # second import is idempotent — never duplicates
    again = await app_client.post("/api/v1/scans/import", json=payload)
    assert again.json()["imported"] is False


@pytest.mark.asyncio
async def test_import_rejects_tampered_payload(app_client):
    payload = (await app_client.get(
        "/api/v1/scans/scan-1/transfer")).json()
    payload["records"][0]["algorithm"] = "TAMPERED"
    response = await app_client.post("/api/v1/scans/import",
                                     json=payload)
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_report_json_html_and_pdf(app_client):
    report = await app_client.get("/api/v1/scans/scan-1/report?template=pci-dss-4.0")
    assert report.status_code == 200
    body = report.json()
    assert body["scan"]["scan_id"] == "scan-1"
    assert "totals" in body
    assert "report_hash" in body  # present when a template evaluation is requested
    assert "template_evaluation" in body

    html = await app_client.get("/api/v1/scans/scan-1/report.html?template=pci-dss-4.0")
    assert html.status_code == 200
    assert html.headers["content-type"].startswith("text/html")
    assert b"CryptoScan" in html.content

    pdf = await app_client.get("/api/v1/scans/scan-1/report.pdf?template=pci-dss-4.0")
    assert pdf.status_code == 200
    assert pdf.headers["content-type"] == "application/pdf"
    assert pdf.content[:5] == b"%PDF-"
    assert pdf.headers["content-disposition"].startswith("attachment")


@pytest.mark.asyncio
async def test_report_pdf_missing_scan_404(app_client):
    response = await app_client.get("/api/v1/scans/nope/report.pdf")
    assert response.status_code == 404


# ---------------------------------------------- malformed transfer payloads ---- #

@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda p: p.update({"scan": ["not", "an", "object"]}),
                     id="scan-is-a-list"),
        pytest.param(lambda p: p.update({"digests": "not-an-object"}),
                     id="digests-is-a-string"),
        pytest.param(lambda p: p.update({"records": "not-a-list"}),
                     id="records-is-a-string"),
        pytest.param(lambda p: p.update({"records": [{"content_hash": "x"},
                                                    "bare-string-row"]}),
                     id="record-row-is-a-string"),
        pytest.param(lambda p: p.update({"transfer_version": "0.9"}),
                     id="unsupported-version"),
        pytest.param(lambda p: p.update({"transfer_format": "evil"}),
                     id="wrong-format"),
        pytest.param(lambda p: p.pop("scan"),
                     id="scan-missing-entirely"),
        pytest.param(lambda p: p.pop("digests"),
                     id="digests-missing-entirely"),
        pytest.param(lambda p: p["digests"].update({"record_count": "many"}),
                     id="record_count-not-a-number"),
    ],
)
async def test_import_malformed_payloads_are_controlled_4xx(app_client, mutate):
    """Adversarial input gets a 400 with the verifier's reasons — never an
    unhandled 500 (the import boundary faces files from another instance)."""
    payload = (await app_client.get("/api/v1/scans/scan-1/transfer")).json()
    mutate(payload)
    response = await app_client.post("/api/v1/scans/import", json=payload)
    assert response.status_code == 400
    body = response.json()
    assert body["detail"]["errors"]
