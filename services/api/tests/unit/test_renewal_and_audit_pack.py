"""Certificate renewal workflow (CR-001) and the audit-export pack."""

from __future__ import annotations

import hashlib
import io
import json
import zipfile
from datetime import datetime, timedelta, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401
from api.dependencies import get_current_user, get_db_session, require_auditor
from api.main import create_app
from db.connection.session import Base
from db.models.certificate import Certificate
from payment_crypto.forecast import ExpiryForecaster

NOW = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)


def _cert(subject: str, days: int, renewal: str = "NONE") -> dict:
    return {"subject": subject, "not_after": (NOW + timedelta(days=days)).isoformat(),
            "fingerprint": hashlib.sha256(subject.encode()).hexdigest()[:16],
            "renewal_status": renewal}


def test_cr001_fires_without_renewal_and_clears_with_one():
    forecast = ExpiryForecaster(now=NOW).forecast([], [
        _cert("CN=critical.bank", 3),              # inside 7d -> severity 4
        _cert("CN=warning.bank", 20),              # inside 30d -> severity 3
        _cert("CN=planned.bank", 20, "PLANNED"),   # workflow owns it
        _cert("CN=calm.bank", 200),                # far out
    ])
    cr = {f["key_id"]: f for f in forecast["findings"] if f["rule_id"] == "CR-001"}
    assert set(cr) == {"CN=critical.bank", "CN=warning.bank"}
    assert cr["CN=critical.bank"]["severity"] == 4
    assert cr["CN=warning.bank"]["severity"] == 3
    assert cr["CN=warning.bank"]["evidence"]["fingerprint"]  # actionable reference


def _make_app():
    import os

    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    from api.config.settings import get_settings

    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "soc"
    app.dependency_overrides[require_auditor] = lambda: "soc-auditor"
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    return app, session, engine


def _seed_certificate(session, subject: str, days: int) -> str:
    fingerprint = hashlib.sha256(subject.encode()).hexdigest()
    session.add(Certificate(
        fingerprint_sha256=fingerprint, subject=subject, issuer="CN=test-ca",
        not_after=datetime.now(timezone.utc) + timedelta(days=days),
        public_key_algorithm="EC", public_key_size=256,
    ))
    session.commit()
    return fingerprint


@pytest.mark.asyncio
async def test_renewal_workflow_via_api():
    app, session, engine = _make_app()
    fingerprint = _seed_certificate(session, "CN=api.bank.example", 14)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        planned = await client.patch(f"/api/v1/certificates/{fingerprint}/renewal",
                                     json={"status": "PLANNED", "ticket": "CHG-0042"})
        assert planned.status_code == 200, planned.text
        assert planned.json()["renewal_status"] == "PLANNED"
        assert planned.json()["renewal_ticket"] == "CHG-0042"

        # CR-001 cleared for this certificate
        forecast = await client.get("/api/v1/payment-crypto/forecast")
        flagged = [f for f in forecast.json()["findings"]
                   if f["rule_id"] == "CR-001" and f["key_id"] == "CN=api.bank.example"]
        assert flagged == []

        bad = await client.patch(f"/api/v1/certificates/{fingerprint}/renewal",
                                 json={"status": "MAYBE"})
        assert bad.status_code == 422
        missing = await client.patch("/api/v1/certificates/" + "0" * 64 + "/renewal",
                                     json={"status": "PLANNED"})
        assert missing.status_code == 404

        done = await client.patch(f"/api/v1/certificates/{fingerprint}/renewal",
                                  json={"status": "DONE"})
        assert done.json()["renewed_at"]  # completion timestamped


@pytest.mark.asyncio
async def test_audit_pack_hashes_and_honest_notes():
    from db.repositories.payment_crypto_repository import PaymentCryptoRepository

    app, session, engine = _make_app()
    PaymentCryptoRepository(session).upsert_key(
        {"key_id": "ZMK-PACK", "algorithm": "AES", "state": "ACTIVE"})
    session.commit()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        pack = await client.get("/api/v1/audit-export/pack")
        assert pack.status_code == 200, pack.text
        assert pack.headers["content-type"].startswith("application/zip")
        assert int(pack.headers["x-pack-files"]) >= 8

        archive = zipfile.ZipFile(io.BytesIO(pack.content))
        names = set(archive.namelist())
        assert {"manifest.json", "payment/keys.json", "payment/ceremonies.json",
                "payment/findings.json", "payment/forecast.json",
                "certificates/inventory.json", "monitor/watch-list.json",
                "hsm-events/recent-90d.json", "system.json"} <= names

        # no completed scan in this app -> honest note files, never silence
        assert "compliance/NO_COMPLETED_SCAN.txt" in names
        assert "evidence/NO_COMPLETED_SCAN.txt" in names

        # every file's manifest hash matches its actual bytes
        manifest = json.loads(archive.read("manifest.json"))
        for path, info in manifest["files"].items():
            payload = archive.read(path)
            assert hashlib.sha256(payload).hexdigest() == info["sha256"], path

        keys = json.loads(archive.read("payment/keys.json"))
        assert [row["key_id"] for row in keys] == ["ZMK-PACK"]
        assert manifest["totals"]["payment_keys"] == 1


@pytest.mark.asyncio
async def test_audit_pack_carries_whole_estate(tmp_path, monkeypatch):
    """The examiner pack covers every estate the PoC produces: cloud KMS,
    ACM certificates, code findings, telecom posture — and says NO_* loudly
    where an estate is empty."""
    from db.models.crypto_asset import CryptoAsset

    # telecom snapshot on disk (the pack reads the same mirror the router does)
    monkeypatch.setenv("CRYPTOSCAN_SNAPSHOT_DIR", str(tmp_path))
    (tmp_path / "telecom_snapshot.json").write_text(json.dumps({
        "generated_at": "2026-09-11T00:00:00+00:00",
        "scanner": "telecom-api-scan",
        "targets_registered": 2,
        "rows": [{"nf_id": "amf-lab-01", "status": "TLS_OK", "severity": "info"}],
        "rollup": {"totals": {"targets": 2}},
    }))
    from api.routers import telecom as telecom_router

    telecom_router._SNAPSHOT = None  # force a disk read

    app, session, engine = _make_app()
    session.add(CryptoAsset(
        algorithm="RSA-3072", key_size=3072, purpose="signing",
        file_path="aws-kms://eu-central-1/k1", source_language="aws-kms",
        confidence="HIGH", extra={"collector": "aws-kms", "first_seen_at": "2026-09-11"}))
    session.add(CryptoAsset(
        algorithm="MD5", file_path="/repo/app/util.py", line_number=42,
        source_language="python", confidence="HIGH", is_hardcoded_key=True))
    session.add(Certificate(
        fingerprint_sha256="f" * 64, subject="CN=acm.bank.example",
        public_key_algorithm="ECDSA-P256", public_key_size=256,
        extra={"collector": "aws-acm", "arn": "arn:aws:acm:eu-central-1:1:certificate/x"}))
    session.commit()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        pack = await client.get("/api/v1/audit-export/pack")
        assert pack.status_code == 200, pack.text

        archive = zipfile.ZipFile(io.BytesIO(pack.content))
        names = set(archive.namelist())
        assert {"cloud/kms-inventory.json", "cloud/acm-certificates.json",
                "code/findings-summary.json", "telecom/posture.json"} <= names
        # populated estates carry no NO_ notes
        assert "cloud/NO_CLOUD_INVENTORY.txt" not in names

        kms = json.loads(archive.read("cloud/kms-inventory.json"))
        assert kms["total"] == 1 and kms["by_collector"] == {"aws-kms": 1}
        assert kms["assets"][0]["reference"] == "aws-kms://eu-central-1/k1"

        acm = json.loads(archive.read("cloud/acm-certificates.json"))
        assert acm["total"] == 1 and acm["certificates"][0]["arn"].startswith("arn:aws:acm")

        code = json.loads(archive.read("code/findings-summary.json"))
        assert code["total"] == 1 and code["hardcoded_keys"] == 1
        assert code["by_language"] == {"python": 1} and code["by_algorithm"] == {"MD5": 1}

        posture = json.loads(archive.read("telecom/posture.json"))
        assert posture["targets_registered"] == 2 and posture["rows"][0]["nf_id"] == "amf-lab-01"

        manifest = json.loads(archive.read("manifest.json"))
        assert manifest["totals"]["cloud_kms_assets"] == 1
        assert manifest["totals"]["cloud_acm_certificates"] == 1
        assert manifest["totals"]["code_finding_assets"] == 1
        assert manifest["totals"]["telecom_targets"] == 2


@pytest.mark.asyncio
async def test_audit_pack_estate_sections_are_honest_when_empty(tmp_path, monkeypatch):
    from api.routers import telecom as telecom_router

    monkeypatch.setenv("CRYPTOSCAN_SNAPSHOT_DIR", str(tmp_path))
    telecom_router._SNAPSHOT = None

    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        pack = await client.get("/api/v1/audit-export/pack")
        archive = zipfile.ZipFile(io.BytesIO(pack.content))
        names = set(archive.namelist())
        assert {"cloud/NO_CLOUD_INVENTORY.txt", "cloud/NO_ACM_CERTIFICATES.txt",
                "code/NO_CODE_FINDINGS.txt", "telecom/NO_TELECOM_DATA.txt"} <= names
        assert "cloud/kms-inventory.json" not in names
        assert "telecom/posture.json" not in names
        manifest = json.loads(archive.read("manifest.json"))
        assert manifest["totals"]["cloud_kms_assets"] == 0
        assert manifest["totals"]["telecom_targets"] == 0


@pytest.mark.asyncio
async def test_exit_report_endpoint_json_md_and_hash(tmp_path, monkeypatch):
    """The exit report reads the same inventories as the pack; JSON carries a
    self-verifying hash, markdown renders it, and both are deterministic."""
    from api.routers import telecom as telecom_router

    monkeypatch.setenv("CRYPTOSCAN_SNAPSHOT_DIR", str(tmp_path))
    # a registered-but-not-yet-populated telecom pass → honest zeros in the block
    (tmp_path / "telecom_snapshot.json").write_text(json.dumps({
        "generated_at": "2026-09-11T00:00:00+00:00", "scanner": "telecom-api-scan",
        "targets_registered": 2, "rows": []}))
    telecom_router._SNAPSHOT = None

    app, session, engine = _make_app()
    _seed_certificate(session, "CN=exit.bank.example", 30)
    from db.models.crypto_asset import CryptoAsset

    session.add(CryptoAsset(algorithm="RSA-2048", file_path="/r/a.py",
                            source_language="python", confidence="HIGH"))
    session.add(CryptoAsset(algorithm="AES-256", key_size=256,
                            file_path="aws-kms://eu-central-1/k",
                            source_language="aws-kms", confidence="HIGH",
                            extra={"collector": "aws-kms"}))
    session.commit()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        body = (await client.get("/api/v1/audit-export/exit-report",
                                 params={"client": "FAB", "window": "2026-09-14..25"}))
        assert body.status_code == 200, body.text
        report = body.json()
        assert report["kind"] == "cryptoscan-poc-exit-report"
        assert report["client"] == "FAB"
        estates = report["executive_summary"]["estates"]
        assert estates["certificates"] == 1
        assert estates["cloud_kms"] == 1
        assert estates["code_findings"] == 1
        # Shor-exposed families flow from the inventory (AES excluded)
        assert report["roadmap"]["families_flagged"] == ["RSA-2048"]
        # telecom snapshot present → block included with honest zeros
        assert report["telecom"]["critical_findings"] == 0
        from reporting.exit_report import verify_exit_report

        assert verify_exit_report(report) is True

        again = (await client.get("/api/v1/audit-export/exit-report",
                                  params={"client": "FAB", "window": "2026-09-14..25",
                                          "format": "json"}))
        # generated_at is part of the report → hashes differ per call unless pinned;
        # determinism is proven at engine level — here assert STRUCTURE equality
        assert again.json()["executive_summary"] == report["executive_summary"]

        md = await client.get("/api/v1/audit-export/exit-report",
                              params={"client": "FAB", "format": "md"})
        assert md.status_code == 200
        assert md.headers["content-type"].startswith("text/markdown")
        assert md.headers["x-report-hash"]
        assert "# PoC exit report — FAB" in md.text
        assert md.headers["x-report-hash"] in md.text
