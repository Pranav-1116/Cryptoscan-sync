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
