"""W55-56 item 5 (API): reports carry a real RS256 signature when a key is configured."""

from __future__ import annotations

import subprocess
from datetime import datetime, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register all tables
from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.connection.session import Base
from db.models.evidence_record import EvidenceRecord
from db.models.scan import Scan


def _make_app(signing_key: str = "", key_id: str = ""):
    import os

    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    if signing_key:
        os.environ["REPORT_SIGNING_KEY"] = signing_key
        os.environ["REPORT_SIGNING_KEY_ID"] = key_id
    else:
        os.environ.pop("REPORT_SIGNING_KEY", None)
        os.environ.pop("REPORT_SIGNING_KEY_ID", None)
    from api.config.settings import get_settings

    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "auditor"
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    return app, session, engine


def _seed(session):
    session.add(
        Scan(id="scan-pki", scan_start=datetime(2026, 8, 29, tzinfo=timezone.utc),
             target_location="https://github.com/org/payments.git", target_type="GIT_REPOSITORY",
             status="COMPLETED", statistics={})
    )
    session.add(
        EvidenceRecord(
            scan_id="scan-pki", content_hash="a" * 64, chain_hash="h" + "0" * 63,
            chain_position=0, previous_hash=None, algorithm="DES", confidence="HIGH",
            purpose="ENCRYPTION", mode=None, key_size=None, file_path="src/Pay.java",
            line_number=7, finding_data={"scanner_id": "s"}, compliance_status="FAIL",
        )
    )
    session.flush()


@pytest.fixture(scope="module")
def keypair(tmp_path_factory):
    directory = tmp_path_factory.mktemp("pki-api")
    private, public = directory / "priv.pem", directory / "pub.pem"
    subprocess.run(["openssl", "genrsa", "-out", str(private), "2048"], check=True, capture_output=True, timeout=60)
    subprocess.run(["openssl", "rsa", "-in", str(private), "-pubout", "-out", str(public)],
                   check=True, capture_output=True, timeout=60)
    return {"private": str(private), "public": str(public), "pem": public.read_text()}


@pytest.mark.asyncio
async def test_report_unsigned_when_no_key_configured(keypair):
    app, session, engine = _make_app()
    _seed(session)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        report = (await client.get("/api/v1/scans/scan-pki/report?template=pci-dss-4.0")).json()
    assert "signature" not in report or report.get("signature") is None  # honest absence


@pytest.mark.asyncio
async def test_report_carries_rs256_signature_and_verifies(keypair):
    app, session, engine = _make_app(signing_key=keypair["private"], key_id="ciso-2026")
    _seed(session)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        report = (await client.get("/api/v1/scans/scan-pki/report?template=pci-dss-4.0")).json()
        signature = report["signature"]
        assert signature["alg"] == "RS256"
        assert signature["key_id"] == "ciso-2026"
        assert signature["value"]

        # the verify endpoint proves it against the issuer's public key
        verified = (
            await client.post(
                "/api/v1/report/verify",
                json={"report": report, "public_key": keypair["pem"]},
            )
        ).json()
        assert verified["ok"] is True and verified["key_id"] == "ciso-2026"

        # tampering in transit is caught
        report["totals"]["fail"] = 0
        tampered = (
            await client.post(
                "/api/v1/report/verify",
                json={"report": report, "public_key": keypair["pem"]},
            )
        ).json()
        assert tampered["ok"] is False
