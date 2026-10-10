"""Round 22 (report 08 P2#6/#7/#8) at the API surface: standard enveloped
signature on the scan route, semantic diff classification on /cbom/diff."""

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
from cbom.generator import CbomGenerator
from db.connection.session import Base
from db.models.evidence_record import EvidenceRecord
from db.models.scan import Scan

SECRET = "r22-cbom-secret-" + "y" * 21


def _record(algorithm="AES", mode="CBC", path="src/a.java", line=1):
    return {
        "algorithm": algorithm,
        "mode": mode,
        "key_size": 128,
        "file_path": path,
        "line_number": line,
        "confidence": "HIGH",
        "normalized_crypto": {"standard_name": algorithm},
        "finding_id": f"f-{algorithm}-{path}-{line}",
    }


def _bom(records):
    return CbomGenerator().from_records(records, name="svc")


@pytest.fixture()
def app_db(monkeypatch):
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "test-webhook-secret-abc123")
    monkeypatch.setenv("SECRET_KEY", SECRET)
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("CRYPTOSCAN_CBOM_SECRET", SECRET)
    monkeypatch.setenv("CRYPTOSCAN_CBOM_KEY_ID", "k-r22")
    get_settings.cache_clear()
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    TestSession = sessionmaker(bind=engine, expire_on_commit=False)
    application = create_app()
    application.dependency_overrides[get_current_user] = lambda: "testuser"

    def _session():
        session = TestSession()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    application.dependency_overrides[get_db_session] = _session
    return application, TestSession


@pytest.mark.asyncio
async def test_scan_cbom_signed_jsf_emits_standard_field(app_db):
    application, TestSession = app_db
    import datetime as dt

    with TestSession() as db:
        db.add(
            Scan(
                id="scan-r22",
                scan_start=dt.datetime(2026, 10, 10, tzinfo=dt.timezone.utc),
                target_location="https://github.com/org/svc.git",
                target_type="GIT_REPOSITORY",
            )
        )
        db.add(
            EvidenceRecord(
                id="ev-1",
                scan_id="scan-r22",
                content_hash="a" * 64,
                chain_hash="b" * 64,
                chain_position=0,
                algorithm="AES",
                mode="CBC",
                key_size=128,
                file_path="src/a.java",
                line_number=1,
                confidence="HIGH",
                finding_data={"algorithm": "AES", "mode": "CBC"},
                normalized_crypto={"standard_name": "AES"},
            )
        )
        db.commit()

    transport = ASGITransport(app=application)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/cbom/scan/scan-r22", params={"signed": "jsf"})
    assert response.status_code == 200
    bom = response.json()

    # spec-standard field, not a metadata property
    sig = bom.get("signature")
    assert isinstance(sig, dict) and sig.get("value")
    assert sig["algorithm"] == "HS256"
    assert sig["keyId"] == "k-r22"
    assert not any(
        item.get("name") == "cryptoscan:jws"
        for item in (bom.get("metadata") or {}).get("properties") or []
    )
    # round-trips through the standard verifier with the shared secret
    ok, error = CbomGenerator().verify_standard(bom, SECRET)
    assert ok, error
    # ... and through verify_report (which prefers the standard field)
    report = CbomGenerator().verify_report(bom, SECRET)
    assert report["ok"] and report["algorithm"] == "HS256"
    # P2#7 fields present on the scan route
    assert bom["externalReferences"] == [
        {"type": "provenance", "url": "urn:cryptoscan:scan:scan-r22"}
    ]
    assert bom["compositions"][0]["aggregate"] == "INCOMPLETE"


@pytest.mark.asyncio
async def test_jsf_with_xml_is_rejected_not_silently_dropped(app_db):
    application, TestSession = app_db
    import datetime as dt

    with TestSession() as db:
        db.add(
            Scan(
                id="scan-r22",
                scan_start=dt.datetime(2026, 10, 10, tzinfo=dt.timezone.utc),
                target_location="https://github.com/org/svc.git",
                target_type="GIT_REPOSITORY",
            )
        )
        db.commit()
    transport = ASGITransport(app=application)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(
            "/api/v1/cbom/scan/scan-r22", params={"signed": "jsf", "fmt": "xml"}
        )
    assert response.status_code == 400
    assert "JSON" in response.json()["detail"]


@pytest.mark.asyncio
async def test_diff_endpoint_returns_semantic_classification(app_db):
    application, _TestSession = app_db
    before = _bom([_record(algorithm="AES", mode="CBC", path="src/a.java")])
    after = _bom([_record(algorithm="AES", mode="GCM", path="src/a.java")])
    transport = ASGITransport(app=application)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/v1/cbom/diff",
            json={"left": {"bom": before}, "right": {"bom": after}},
        )
    assert response.status_code == 200
    body = response.json()
    assert body["counts"]["changed"] == 1
    assert body["counts"]["added"] == 0
    assert body["counts"]["removed"] == 0
    change = body["changed"][0]
    assert change["classifications"] == ["ALGORITHM_CHANGED"]
    assert change["from"]["mode"] == "CBC"
    assert change["to"]["mode"] == "GCM"
