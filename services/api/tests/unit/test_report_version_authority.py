"""Report version authority (§4.4, round 69) — the report leg of
scan-run → BOM → report.

A pinned report must be the SAME kind of authority a pinned CBOM is:
content-addressed over its exact payload (signed PDF and the scan→BOM
chain citation included), idempotent (identical pins collapse), served
verbatim with an integrity self-check that flags post-pin mutation as
DETECTED-UNTRUSTED, and honest about rows that predate content
addressing. The chain citation names the pinned BOM snapshot the report
was rendered alongside — or says plainly that none exists.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

import pytest
import sqlalchemy as sa
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register all tables
from api.dependencies import get_current_user, get_db_session, require_auditor
from api.main import create_app
from db.connection.session import Base
from db.models.evidence_record import EvidenceRecord
from db.models.report_snapshot import ReportSnapshot
from db.models.scan import Scan

TARGET = "https://github.com/org/payments.git"
HEX64 = re.compile(r"^[0-9a-f]{64}$")


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


def _seed_scan(session, scan_id="scan-rva"):
    session.add(
        Scan(id=scan_id, scan_start=datetime(2026, 10, 15, tzinfo=timezone.utc),
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


def _pin(client, scan_id="scan-rva", template="pci-dss-4.0"):
    return client.post(f"/api/v1/scans/{scan_id}/report-snapshot",
                       json={"template_id": template})


@pytest.mark.asyncio
async def test_on_demand_pin_content_addresses_the_exact_payload():
    app, session, engine = _make_app()
    _seed_scan(session)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r = await _pin(client)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["created"] is True
        assert HEX64.match(body["payload_hash"]), "content address over the exact payload"
        # the chain block cites the scan's verify path
        served = (await client.get(f"/api/v1/report-snapshots/{body['id']}")).json()
        chain = served["chain"]
        assert chain["scan"] == {"id": "scan-rva",
                                 "verify_path": "/api/v1/scans/scan-rva/verify"}
        # no BOM pinned yet — said plainly, never fabricated
        assert chain["cbom_snapshot"] is None
        assert "No pinned CBOM snapshot" in chain["note"]
        # served verbatim with a passing integrity self-check
        assert served["snapshot"]["integrity"] == "OK"
        assert served["snapshot"]["payload_hash"] == body["payload_hash"]


@pytest.mark.asyncio
async def test_the_report_cites_the_pinned_bom_snapshot():
    """The chain: scan → pinned BOM (content-addressed) → pinned report that
    names it. The report leg is only an authority when it points at the BOM
    leg explicitly."""
    app, session, engine = _make_app()
    _seed_scan(session)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        bom = await client.post("/api/v1/cbom/scan/scan-rva/snapshot")
        assert bom.status_code == 200, bom.text
        bom_id = bom.json()["snapshot_id"]
        bom_hash = bom.json()["content_hash"]

        r = await _pin(client)
        assert r.status_code == 200, r.text
        served = (await client.get(f"/api/v1/report-snapshots/{r.json()['id']}")).json()
        cited = served["chain"]["cbom_snapshot"]
        assert cited is not None
        assert cited["snapshot_id"] == bom_id
        assert cited["content_hash"] == bom_hash
        assert cited["path"] == f"/api/v1/cbom/snapshots/{bom_id}"
        assert cited["component_count"] >= 1
        # the citation resolves — the chain is walkable, not decorative
        resolved = await client.get(cited["path"])
        assert resolved.status_code == 200
        assert resolved.json()["integrity"] == "OK"


@pytest.mark.asyncio
async def test_identical_pins_collapse_and_serve_verbatim():
    app, session, engine = _make_app()
    _seed_scan(session)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        first = (await _pin(client)).json()
        second = (await _pin(client)).json()
        assert second["created"] is False
        assert second["id"] == first["id"]
        listed = await client.get("/api/v1/report-snapshots?scan_id=scan-rva")
        assert listed.json()["total"] == 1


@pytest.mark.asyncio
async def test_post_pin_mutation_is_served_as_detected_untrusted():
    app, session, engine = _make_app()
    _seed_scan(session)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        pinned = (await _pin(client)).json()
        # tamper with the stored payload directly
        row = session.execute(
            sa.select(ReportSnapshot).where(ReportSnapshot.id == pinned["id"])
        ).scalars().one()
        row.report = dict(row.report or {}, totals={"pass": 999, "fail": 0})
        session.commit()
        session.expire_all()

        served = (await client.get(f"/api/v1/report-snapshots/{pinned['id']}")).json()
        assert served["snapshot"]["integrity"] == "MISMATCH"
        assert "Do not trust it" in served["snapshot"]["integrity_note"]


@pytest.mark.asyncio
async def test_scheduled_runs_produce_the_same_authority():
    app, session, engine = _make_app()
    _seed_scan(session)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = await client.post("/api/v1/report-schedules", json={
            "name": "Quarterly PCI", "template_id": "pci-dss-4.0",
            "frequency": "quarterly", "scan_target": TARGET,
            "recipients": [],
        })
        assert created.status_code == 201, created.text
        run = await client.post(f"/api/v1/report-schedules/{created.json()['id']}/run")
        assert run.status_code == 200, run.text
        snapshot_id = run.json()["snapshot_id"]
        assert HEX64.match(run.json()["report_hash"])

        served = (await client.get(f"/api/v1/report-snapshots/{snapshot_id}")).json()
        assert served["snapshot"]["integrity"] == "OK"
        assert HEX64.match(served["snapshot"]["payload_hash"])
        assert "chain" in served


@pytest.mark.asyncio
async def test_legacy_rows_are_labelled_not_pretended():
    app, session, engine = _make_app()
    _seed_scan(session)
    session.add(ReportSnapshot(
        scan_id="scan-rva", template_id="pci-dss-4.0", report_hash="c" * 64,
        payload_hash=None, report={"totals": {"pass": 1}},
        generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    ))
    session.commit()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        listed = (await client.get("/api/v1/report-snapshots?scan_id=scan-rva")).json()
        legacy = next(r for r in listed["snapshots"] if r["payload_hash"] is None)
        served = (await client.get(f"/api/v1/report-snapshots/{legacy['id']}")).json()
        assert served["snapshot"]["integrity"] == "UNVERIFIED_LEGACY"
        assert "predates payload content addressing" in served["snapshot"]["integrity_note"]


@pytest.mark.asyncio
async def test_unknown_scan_and_bad_template_are_refused():
    app, session, engine = _make_app()
    _seed_scan(session)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r = await _pin(client, scan_id="nope")
        assert r.status_code == 404
        r = await _pin(client, template="chaos")
        assert r.status_code == 422
