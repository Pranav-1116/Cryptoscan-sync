"""Field accuracy loop: publish a bank's triage on a scan, pool it into GET /accuracy/field.

Until a bank publishes, the field number is explicitly NO_FIELD_DATA — the readiness doc cites this endpoint, so it
must never invent a value. Readonly sessions cannot publish; a security analyst can; auditors read it back.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401
from api.dependencies import get_db_session
from api.main import create_app
from db.connection.session import Base
from db.models.scan import Scan


def _make_app():
    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    from api.config.settings import get_settings

    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    from db.models.tenant import Tenant
    session.add(Tenant(id="review-bank", name="Synthetic review bank", slug="review-bank"))
    session.commit()
    app = create_app()
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    return app, session


def _act_as(client, session, username: str, roles: str):
    from api.security.session_manager import SessionManager
    from db.repositories.user_repository import UserRepository

    if UserRepository(session).get_by_username(username) is None:
        UserRepository(session).create_user(username, "x", roles=[roles])
        session.commit()
    from db.models.tenant import TenantMembership
    if session.query(TenantMembership).filter_by(tenant_id="review-bank", username=username).first() is None:
        session.add(TenantMembership(tenant_id="review-bank", username=username, tenant_role="member"))
        session.commit()
    client.headers["Authorization"] = f"Bearer {SessionManager().create_session(username, roles=[roles])}"


def _scan(session, sid: str, target: str) -> Scan:
    now = datetime.now(timezone.utc)
    s = Scan(id=sid, tenant_id="review-bank", status="COMPLETED", target_location=target, target_type="GIT_REPOSITORY", scanner_id="static", scanner_version="1.4.0",
             operator="pilot", scan_start=now, scan_end=now, statistics={"files_scanned": 10}, manifest_hash="h" * 64)
    session.add(s)
    session.commit()
    return s


WORKBOOK = {
    "repo": "bank-a/payments-switch", "files_scanned": 120,
    "findings": [
        {"file": "src/Pin.java", "algorithm": "3DES", "verdict": "TP"},
        {"file": "src/Pin.java", "algorithm": "MD5", "verdict": "FP", "note": "log checksum"},
        {"file": "src/Mac.java", "algorithm": "HMAC", "verdict": "TP"},
        {"file": "iso/Pack.cbl", "algorithm": "AES", "verdict": "FP"},
    ],
    "candidate_misses": [{"file": "iso/CSNBENC.cbl", "verdict": "FN", "expected": ["DES"]}, {"file": "README.md", "verdict": "OK"}],
}


@pytest.mark.asyncio
async def test_field_accuracy_loop():
    app, session = _make_app()
    _scan(session, "scan-a", "https://git.bank/payments-switch")
    _scan(session, "scan-b", "https://git.bank/core")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. nothing published → explicit NO_FIELD_DATA, corpus number still shown
        _act_as(client, session, "auditor1", "auditor")
        r = await client.get("/api/v1/accuracy/field")
        assert r.status_code == 200 and r.json()["status"] == "NO_FIELD_DATA" and r.json()["f1"] is None
        assert r.json()["corpus_f1"] is None or r.json()["corpus_f1"] > 0.9
        assert (await client.get("/api/v1/scans/scan-a/triage")).status_code == 404

        # 2. a readonly session cannot publish a review
        _act_as(client, session, "viewer", "readonly")
        assert (await client.post("/api/v1/scans/scan-a/triage", json={"workbook": WORKBOOK})).status_code == 403

        # 3. an analyst publishes a raw workbook (scored server-side) …
        _act_as(client, session, "analyst1", "security_analyst")
        r = await client.post("/api/v1/scans/scan-a/triage", json={"workbook": WORKBOOK, "reviewer": "bank-a crypto CoE"})
        assert r.status_code == 201, r.text
        t = r.json()
        assert (t["tp"], t["fp"], t["fn"]) == (2, 2, 1) and t["precision"] == 0.5 and t["scanner_version"] == "1.4.0"
        # … and a pre-scored TriageResult on another scan (what `bank_triage.py publish` sends)
        pre = {"repo": "bank-a/core", "reviewer": "bank-a crypto CoE", "files_scanned": 40, "tp": 30, "fp": 0, "fn": 2,
               "precision": 1.0, "recall": 0.9375, "f1": 0.9677,
               "by_language": [{"language": "cobol", "tp": 30, "fp": 0, "fn": 2, "precision": 1.0, "recall": 0.9375, "f1": 0.9677}]}
        assert (await client.post("/api/v1/scans/scan-b/triage", json=pre)).status_code == 201
        # an empty review is refused, an unknown scan is 404
        assert (await client.post("/api/v1/scans/scan-a/triage", json={"workbook": {"repo": "x", "findings": []}})).status_code == 422
        assert (await client.post("/api/v1/scans/nope/triage", json=pre)).status_code == 404

        # 4. read back + pooled field number
        _act_as(client, session, "auditor1", "auditor")
        got = (await client.get("/api/v1/scans/scan-a/triage")).json()
        assert got["reviewer"] == "bank-a crypto CoE" and got["fp_examples"][0]["note"] == "log checksum"
        agg = (await client.get("/api/v1/accuracy/field")).json()
        assert agg["approved_customer_sample"] is False and agg["global_accuracy_claim"] is False
        assert agg["status"] == "MEASURED" and agg["triages"] == 2 and agg["repos"] == 2 and agg["files_scanned"] == 160
        assert (agg["tp"], agg["fp"], agg["fn"]) == (32, 2, 3)
        assert agg["precision"] == round(32 / 34, 4) and agg["recall"] == round(32 / 35, 4)
        langs = {l["language"]: l for l in agg["by_language"]}
        assert langs["cobol"]["tp"] == 30 and langs["cobol"]["fp"] == 1 and langs["java"]["fp"] == 1
        if agg["corpus_f1"] is not None:
            assert agg["gap"] == round(agg["corpus_f1"] - agg["f1"], 4)
        only = (await client.get("/api/v1/accuracy/field", params={"repo": "bank-a/core"})).json()
        assert only["triages"] == 1 and only["tp"] == 30
    from db.models.assurance import AssuranceRevision
    assert session.query(AssuranceRevision).filter_by(kind="legacy_triage").count() == 2
    session.close()
