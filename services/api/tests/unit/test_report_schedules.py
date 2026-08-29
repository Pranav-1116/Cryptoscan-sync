"""W55-56 items 7-8: scheduled reports, immutable snapshots, honest email distribution."""

from __future__ import annotations

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

TARGET = "https://github.com/org/payments.git"


def _make_app():
    import os

    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    os.environ.pop("SMTP_HOST", None)
    from api.config.settings import get_settings

    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "auditor"
    app.dependency_overrides[require_auditor] = lambda: "auditor"
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    return app, session, engine


def _seed_scan(session, scan_id="scan-sched"):
    session.add(
        Scan(id=scan_id, scan_start=datetime(2026, 8, 29, tzinfo=timezone.utc),
             target_location=TARGET, target_type="GIT_REPOSITORY",
             status="COMPLETED", statistics={})
    )
    session.add(
        EvidenceRecord(
            scan_id=scan_id, content_hash="a" * 64, chain_hash="h" + "0" * 63,
            chain_position=0, previous_hash=None, algorithm="DES", confidence="HIGH",
            purpose="ENCRYPTION", mode=None, key_size=None, file_path="src/Pay.java",
            line_number=7, finding_data={"scanner_id": "s"}, compliance_status="FAIL",
        )
    )
    session.flush()


def _schedule_body(**overrides) -> dict:
    body = {
        "name": "Quarterly PCI report",
        "template_id": "pci-dss-4.0",
        "frequency": "quarterly",
        "scan_target": TARGET,
        "recipients": ["auditor@corp.example.com"],
    }
    body.update(overrides)
    return body


@pytest.mark.asyncio
async def test_schedule_lifecycle_validates_and_runs():
    app, session, engine = _make_app()
    _seed_scan(session)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # validation is honest up front
        assert (await client.post("/api/v1/report-schedules", json=_schedule_body(template_id="chaos"))).status_code == 422
        assert (await client.post("/api/v1/report-schedules", json=_schedule_body(frequency="hourly"))).status_code == 422
        assert (await client.post("/api/v1/report-schedules", json=_schedule_body(template_id="custom"))).status_code == 422
        duplicate_name = (await client.post("/api/v1/report-schedules", json=_schedule_body())).json()
        assert (await client.post("/api/v1/report-schedules", json=_schedule_body())).status_code == 409

        # a new schedule is due immediately
        due = (await client.get("/api/v1/report-schedules/due")).json()["due"]
        assert [row["name"] for row in due] == ["Quarterly PCI report"]

        run = await client.post(f"/api/v1/report-schedules/{duplicate_name['id']}/run")
        assert run.status_code == 200, run.text
        result = run.json()
        assert result["status"] == "GENERATED"
        assert len(result["report_hash"]) == 64
        assert result["email"]["status"] == "SKIPPED_NO_SMTP"  # honest: no SMTP configured

        # running reschedules +91 days and clears the due list
        assert (await client.get("/api/v1/report-schedules/due")).json()["due"] == []
        schedule = (await client.get("/api/v1/report-schedules")).json()["schedules"][0]
        assert schedule["last_run_at"] and schedule["next_run_at"]

        # the snapshot is the immutable artifact — full report retrievable
        snapshots = (await client.get("/api/v1/report-snapshots")).json()["snapshots"]
        assert snapshots[0]["email_status"] == "SKIPPED_NO_SMTP"
        stored = (await client.get(f"/api/v1/report-snapshots/{snapshots[0]['id']}")).json()
        assert stored["report_hash"] == result["report_hash"]
        assert stored["totals"]["fail"] == 1
        assert stored["snapshot"]["schedule_name"] == "Quarterly PCI report"


@pytest.mark.asyncio
async def test_run_due_reports_each_outcome_honestly():
    app, session, engine = _make_app()
    _seed_scan(session)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # one healthy schedule, one whose target has never been scanned
        await client.post("/api/v1/report-schedules", json=_schedule_body())
        await client.post(
            "/api/v1/report-schedules",
            json=_schedule_body(name="Ghost target", scan_target="https://github.com/org/none.git"),
        )
        ran = (await client.post("/api/v1/report-schedules/run-due")).json()
        assert ran["ran"] == 2
        by_name = {row["schedule"]: row for row in ran["results"]}
        assert by_name["Quarterly PCI report"]["status"] == "GENERATED"
        assert by_name["Ghost target"]["status"] == "SKIPPED_NO_SCAN"

        # manual run of the ghost schedule surfaces the honest 409
        ghost_id = next(
            row["id"] for row in (await client.get("/api/v1/report-schedules")).json()["schedules"]
            if row["name"] == "Ghost target"
        )
        manual = await client.post(f"/api/v1/report-schedules/{ghost_id}/run")
        assert manual.status_code == 409


@pytest.mark.asyncio
async def test_email_dispatch_via_configured_smtp(monkeypatch):
    app, session, engine = _make_app()
    _seed_scan(session)
    from api.config.settings import get_settings

    get_settings.cache_clear()
    import os

    os.environ["SMTP_HOST"] = "smtp.corp.example.com"
    get_settings.cache_clear()

    sent: list = []

    class FakeSMTP:
        def __init__(self, host, port, timeout=15):
            sent.append(("connect", host, port))

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def send_message(self, message):
            sent.append(("send", message["Subject"], message["To"]))

    import reporting.distribution as distribution

    monkeypatch.setattr(distribution.smtplib, "SMTP", FakeSMTP)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        created = (await client.post("/api/v1/report-schedules", json=_schedule_body())).json()
        run = (await client.post(f"/api/v1/report-schedules/{created['id']}/run")).json()
    assert run["email"]["status"] == "SENT"
    assert sent[0] == ("connect", "smtp.corp.example.com", 587)
    subject, to = sent[1][1], sent[1][2]
    assert "violations" in subject and run["report_hash"][:12] in subject
    assert to == "auditor@corp.example.com"
    os.environ.pop("SMTP_HOST", None)


def test_render_email_is_deterministic_and_hash_bearing():
    from reporting.distribution import render_email

    report = {
        "report_hash": "ab" * 32,
        "totals": {"findings": 4, "pass": 1, "fail": 3, "warn": 0},
        "template_evaluation": {"summary": {"pass": 1, "fail": 3, "not_evaluated": 0, "compliant_pct": 25.0}},
        "signature": {"alg": "RS256", "key_id": "ciso-2026", "value": "x"},
    }
    subject, body = render_email(report, template_id="pci-dss-4.0", schedule_name="Quarterly PCI report")
    assert ("ab" * 6) in subject  # first 12 chars of the hash
    assert "25.0% compliant" in body and "RS256" in body and ("ab" * 32) in body
    # unsigned reports say so honestly
    _, unsigned_body = render_email({**report, "signature": {}}, template_id="t", schedule_name="s")
    assert "none (no signing key configured)" in unsigned_body
