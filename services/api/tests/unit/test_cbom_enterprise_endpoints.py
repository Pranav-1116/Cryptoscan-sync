"""Enterprise CBOM posture assessment + verify/assess endpoints + ingest gate."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from api.config.settings import get_settings
from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from cbom.assessment import PQC_BY_PRIMITIVE, assess_cbom
from cbom.generator import CbomGenerator
from cbom.signing.key_manager import KeyManager

SECRET = "assessment-test-secret-key-" + "x" * 12


def _bom(records: list[dict]) -> dict:
    return CbomGenerator().from_records(records, name="svc")


def _records(*algorithms: str) -> list[dict]:
    return [
        {"algorithm": algo, "file_path": f"x/{algo}.java", "line_number": i + 1, "finding_id": f"f{i}"}
        for i, algo in enumerate(algorithms)
    ]


# --------------------------------------------------------------------------- #
# Assessment engine
# --------------------------------------------------------------------------- #

def test_clean_cbom_scores_A():
    report = assess_cbom(_bom(_records("AES", "SHA-256", "HMAC-SHA256")))
    assert report["score"] >= 90
    assert report["grade"] == "A"
    assert report["findings"] == []
    assert report["summary"]["designations"]["APPROVED"] >= 1


def test_broken_algorithms_score_D_with_findings():
    # 3 DISALLOWED algorithms x -15 = 55 -> D (F is reserved for worse).
    report = assess_cbom(_bom(_records("MD5", "DES", "RC4")))
    assert report["score"] == 55
    assert report["grade"] == "D"
    names = {f["algorithm"] for f in report["findings"]}
    assert {"MD5", "DES", "RC4"} <= names
    severities = {f["algorithm"]: f["severity"] for f in report["findings"]}
    assert severities["MD5"] == "high"
    recs = {f["algorithm"]: f["recommendation"] for f in report["findings"]}
    assert "SHA-256" in recs["MD5"]
    assert any("Retire broken algorithms" in r for r in report["recommendations"])


def test_quantum_exposure_penalizes_and_recommends_pqc():
    report = assess_cbom(_bom(_records("RSA", "ECDSA", "AES")))
    assert report["summary"]["quantum_vulnerable_algorithms"] == ["ECDSA", "RSA"]
    assert "pke" in report["summary"]["quantum_exposed_families"]
    qfind = [f for f in report["findings"] if "quantum" in f["reason"]]
    assert qfind and all(f["recommendation"] for f in qfind)
    assert any("ML-KEM" in r or "ML-DSA" in r for r in report["recommendations"])
    # AES-only CBOM must outscore the quantum-exposed one.
    aes_only = assess_cbom(_bom(_records("AES")))
    assert aes_only["score"] > report["score"]


def test_unknown_algorithms_flagged_not_fatal():
    report = assess_cbom(_bom(_records("TOTALLY-NOVEL")))
    assert report["summary"]["designations"]["UNKNOWN"] == 1
    assert any("Classify unknown" in r for r in report["recommendations"])
    assert 0 < report["score"] < 100  # penalized but not zeroed


def test_occurrences_counted_but_penalty_per_algorithm():
    many_aes = assess_cbom(_bom(_records(*["AES"] * 10)))
    assert many_aes["score"] == 100
    assert many_aes["summary"]["algorithms"]["AES"] == 10


def test_third_party_cbom_without_crypto_properties():
    # A CycloneDX CBOM from another tool: components named, no cryptoProperties.
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:00000000-0000-0000-0000-000000000001",
        "metadata": {"component": {"type": "application", "name": "vendor-app", "version": "2.0"}},
        "components": [
            {"type": "cryptographic-asset", "name": "RC4", "bom-ref": "c1"},
            {"type": "cryptographic-asset", "name": "RSA-2048", "bom-ref": "c2"},
        ],
    }
    report = assess_cbom(bom)
    assert report["subject"]["name"] == "vendor-app"
    assert any(f["algorithm"].startswith("RC4") for f in report["findings"])


def test_pqc_guidance_covers_all_migration_primitives():
    for primitive in ("pke", "signature", "key-agree", "kem"):
        assert primitive in PQC_BY_PRIMITIVE


# --------------------------------------------------------------------------- #
# API endpoints (real in-memory SQLite app)
# --------------------------------------------------------------------------- #


@pytest.fixture()
def app_no_db(monkeypatch):
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "test-webhook-secret-abc123")
    monkeypatch.setenv("SECRET_KEY", SECRET)
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("CRYPTOSCAN_CBOM_SECRET", SECRET)
    monkeypatch.setenv("CRYPTOSCAN_CBOM_KEY_ID", "k-test")
    monkeypatch.delenv("CRYPTOSCAN_CBOM_RETIRED_SECRETS", raising=False)
    get_settings.cache_clear()
    application = create_app()
    application.dependency_overrides[get_current_user] = lambda: "testuser"
    # Inline-BOM endpoints must not touch the DB; a throwing dependency would
    # surface any accidental DB use as a 500.
    def _no_db():
        raise RuntimeError("db not needed for these endpoints")
        yield

    application.dependency_overrides[get_db_session] = _no_db
    return application


@pytest.mark.asyncio
async def test_verify_endpoint_full_report(app_no_db):
    manager = KeyManager(secret=SECRET, key_id="k-test", environment="test")
    signed = manager.sign(_bom(_records("AES")))
    transport = ASGITransport(app=app_no_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/v1/cbom/verify", json={"bom": signed})
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["signature"]["algorithm"] == "JWS-HS256"
    assert body["signature"]["key_id"] == "k-test"
    assert body["document"]["ok"] is True


@pytest.mark.asyncio
async def test_verify_endpoint_reports_tamper(app_no_db):
    signed = CbomGenerator().sign(_bom(_records("AES")), SECRET, key_id="k-test")
    signed["components"].append(dict(signed["components"][0], name="Injected"))
    transport = ASGITransport(app=app_no_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/v1/cbom/verify", json={"bom": signed})
    assert response.status_code == 200  # the report is the answer
    body = response.json()
    assert body["ok"] is False
    assert "tampered" in (body["signature"]["error"] or "")


@pytest.mark.asyncio
async def test_assess_endpoint_inline_bom(app_no_db):
    transport = ASGITransport(app=app_no_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/v1/cbom/assess", json={"bom": _bom(_records("MD5", "AES"))})
    assert response.status_code == 200
    body = response.json()
    assert body["grade"] in {"B", "C", "D"}
    assert any(f["algorithm"] == "MD5" for f in body["findings"])


@pytest.mark.asyncio
async def test_ingest_tamper_gate_sqlite(monkeypatch):
    import sqlalchemy  # noqa: F401 — presence check for the fixture path
    from db.models.base import Base

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "test-webhook-secret-abc123")
    monkeypatch.setenv("SECRET_KEY", SECRET)
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("CRYPTOSCAN_CBOM_SECRET", SECRET)
    get_settings.cache_clear()

    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    TestSession = sessionmaker(bind=engine)

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

    good = CbomGenerator().sign(_bom(_records("AES")), SECRET)
    tampered = CbomGenerator().sign(_bom(_records("AES")), SECRET)
    tampered["components"].append(dict(tampered["components"][0], name="Injected-3DES"))

    transport = ASGITransport(app=application)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        ok = await client.post(
            "/api/v1/cbom/ingest",
            json={"bom": good, "system_name": "signed-import"},
        )
        assert ok.status_code == 200, ok.text
        rejected = await client.post(
            "/api/v1/cbom/ingest",
            json={"bom": tampered, "system_name": "tampered-import"},
        )
        assert rejected.status_code == 422
        assert "signature verification failed" in rejected.json()["detail"]

        # Unsigned third-party CBOMs still import cleanly.
        unsigned = _bom(_records("AES"))
        external = await client.post(
            "/api/v1/cbom/ingest", json={"bom": unsigned, "system_name": "vendor-bom"}
        )
        assert external.status_code == 200


def test_asymmetric_family_guidance_never_missing():
    """Live data: normalization emits algorithm_family 'asymmetric' — guidance
    must exist for it (and for any unmapped primitive)."""
    bom = _bom(_records("RSA"))
    for component in bom["components"]:
        if str(component.get("name")).upper().startswith("RSA"):
            component["cryptoProperties"]["algorithmProperties"]["primitive"] = "asymmetric"
    report = assess_cbom(bom)
    assert report["summary"]["quantum_exposed_families"] == ["asymmetric"]
    assert any("ML-KEM" in r for r in report["recommendations"])
    for finding in report["findings"]:
        assert finding["recommendation"], f"no guidance for {finding['algorithm']}"
