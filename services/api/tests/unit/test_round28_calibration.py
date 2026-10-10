"""Round 28 (audit 49 P0#4): per-detector calibration scorecards.

`GET /findings/detectors/scorecards` calibrates detectors over recent
scans using retractions (soft-deleted evidence) and decisive authority
losses. Tombstones count toward retraction but never feed conflict
detection.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register tables
from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.connection.session import Base
from db.models.evidence_record import EvidenceRecord
from db.models.scan import Scan

NOW = datetime.now(timezone.utc)


def _make_app(current_user: str = "auditor-1"):
    import os

    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    from api.config.settings import get_settings

    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: current_user
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    return app, session


def _client(app):
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


def _scan(session, scan_id: str, hours_ago: float = 1) -> None:
    when = NOW - timedelta(hours=hours_ago)
    session.add(Scan(id=scan_id, scan_start=when, scan_end=when,
                     target_type="GIT_REPOSITORY",
                     target_location=f"git@acme:{scan_id}.git", status="COMPLETED"))


def _evidence(session, eid: str, scan_id: str, *, detector: str,
              algorithm: str = "RSA", key_size: int = 2048,
              file_path: str = "src/K.java", line: int = 1,
              deleted: bool = False) -> None:
    row = EvidenceRecord(
        id=eid, scan_id=scan_id, algorithm=algorithm, key_size=key_size,
        compliance_status="FAIL", file_path=file_path, line_number=line,
        purpose="ENCRYPTION", content_hash=f"hash-{eid}", chain_hash=f"chain-{eid}",
        chain_position=1, confidence="HIGH",
        finding_data={"source": {"file_path": file_path, "line_number": line}},
        provenance={"scanner_ids": [detector]},
    )
    if deleted:
        row.deleted_at = NOW
        row.deleted_by = "auditor-1"
        row.delete_reason = "false positive"
    session.add(row)


def _card(body: dict, detector: str) -> dict:
    return next(c for c in body["detectors"] if c["detector"] == detector)


@pytest.mark.asyncio
async def test_scorecards_retraction_and_conflict_calibration():
    app, session = _make_app()
    _scan(session, "scan-1")

    # detector-good: 24 clean + 1 retracted (4%) -> CALIBRATED
    for i in range(24):
        _evidence(session, f"g{i}", "scan-1", detector="agent-collector",
                  file_path=f"src/g{i}.java")
    _evidence(session, "g-retracted", "scan-1", detector="agent-collector",
              file_path="src/g-retract.java", deleted=True)

    # detector-noisy: 15 kept + 5 retracted (25%) -> DEGRADED
    for i in range(15):
        _evidence(session, f"n{i}", "scan-1", detector="entropy-heuristic",
                  file_path=f"src/n{i}.java")
    for i in range(5):
        _evidence(session, f"nr{i}", "scan-1", detector="entropy-heuristic",
                  file_path=f"src/nr{i}.java", deleted=True)

    # decisive conflicts: runtime observer vs static observer at five
    # sites. runtime outranks static under the 6-tier hierarchy -> the
    # static side loses each; 5 losses over 25 observations (20%) is a
    # WATCH-level disagreement pattern
    for i in range(20):
        _evidence(session, f"r{i}", "scan-1", detector="runtime-probe",
                  file_path=f"src/r{i}.java")
    for i in range(20):
        _evidence(session, f"s{i}", "scan-1", detector="regex-scanner",
                  file_path=f"src/s{i}.java")
    for i in range(5):
        _evidence(session, f"c-run-{i}", "scan-1", detector="runtime-probe",
                  key_size=2048, file_path=f"src/conflict{i}.java", line=7)
        _evidence(session, f"c-reg-{i}", "scan-1", detector="regex-scanner",
                  key_size=1024, file_path=f"src/conflict{i}.java", line=7)
    session.commit()

    async with _client(app) as client:
        r = await client.get("/api/v1/findings/detectors/scorecards")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["scans_considered"] == 1
        assert body["observations"] == 24 + 1 + 15 + 5 + 20 + 20 + 10

        good = _card(body, "agent-collector")
        assert good["retracted"] == 1
        assert good["retraction_rate"] == round(1 / 25, 4)
        assert good["calibration_tier"] == "CALIBRATED"
        assert good["reliability_multiplier"] == 1.0

        noisy = _card(body, "entropy-heuristic")
        assert noisy["retraction_rate"] == 0.25
        assert noisy["calibration_tier"] == "DEGRADED"
        assert noisy["reliability_multiplier"] == 0.7

        # the conflict is decisive: the runtime side wins, the static
        # side is marked as the loser
        winner = _card(body, "runtime-probe")
        loser = _card(body, "regex-scanner")
        assert winner["conflicts_involved"] == 5
        assert winner["authority_losses"] == 0
        assert winner["calibration_tier"] == "CALIBRATED"
        assert loser["authority_losses"] == 5
        assert loser["authority_loss_rate"] == 0.2
        assert loser["calibration_tier"] == "WATCH"  # 5/25 loss share, 0 retractions

        # the method block keeps the proxy honesty in the payload
        assert "operator judgment" in body["method"]["retraction"]
        assert body["tier_counts"]["CALIBRATED"] >= 1

        # the retracted rows did not manufacture conflicts at their
        # (unique) sites: only the five conflict sites disagree
        total_conflicts = sum(c["conflicts_involved"] for c in body["detectors"])
        assert total_conflicts == 10  # five conflicts, two involved observers each


@pytest.mark.asyncio
async def test_scorecards_empty_and_bounded():
    app, session = _make_app()
    async with _client(app) as client:
        r = await client.get("/api/v1/findings/detectors/scorecards")
        assert r.status_code == 200
        body = r.json()
        assert body["detectors"] == []
        assert body["scans_considered"] == 0

    # the scan window is bounded and ordered most-recent-first
    for i in range(3):
        _scan(session, f"scan-{i}", hours_ago=10 - i)
    _evidence(session, "only", "scan-2", detector="x")
    session.commit()
    async with _client(app) as client:
        body = (await client.get("/api/v1/findings/detectors/scorecards?scan_limit=1")).json()
        assert body["scans_considered"] == 1
        assert [c["detector"] for c in body["detectors"]] == ["x"]

        # scan_limit is validated
        r = await client.get("/api/v1/findings/detectors/scorecards?scan_limit=0")
        assert r.status_code == 422


# --------------------------------------------------------------------------- #
# Scan coverage statement (audit 49 P1#6)
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_scan_coverage_records_negative_evidence():
    app, session = _make_app()
    when = NOW - timedelta(hours=1)
    session.add(Scan(id="cov-1", scan_start=when, scan_end=when,
                     target_type="LOCAL_DIRECTORY", target_location="/repo",
                     status="COMPLETED",
                     statistics={"files_scanned": 100, "files_with_crypto": 3,
                                 "files_skipped": 2, "files_with_errors": 0,
                                 "total_findings": 3,
                                 "findings_by_origin": {"source": 2, "vendored": 1}}))
    # three observations: two attributed detectors, one unattributed
    _evidence(session, "cov-a", "cov-1", detector="agent-collector")
    _evidence(session, "cov-b", "cov-1", detector="entropy-heuristic")
    session.add(EvidenceRecord(
        id="cov-u", scan_id="cov-1", algorithm="AES", compliance_status="PASS",
        file_path="src/u.java", line_number=1, purpose="ENCRYPTION",
        content_hash="h-u", chain_hash="c-u", chain_position=1,
        confidence="LOW", finding_data={}, provenance=None))
    session.commit()

    async with _client(app) as client:
        r = await client.get("/api/v1/scans/cov-1/coverage")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["files_scanned"] == 100
        assert body["total_findings"] == 3
        assert body["clean_scan"] is False

        # the origin universe is fully listed, zeros included
        origins = {o["origin"]: o for o in body["origins"]}
        assert set(origins) == {"source", "test", "generated", "vendored", "archive"}
        assert origins["source"]["observations"] == 2
        assert origins["test"]["zero_observation"] is True
        assert origins["archive"]["zero_observation"] is True

        # detectors with counts + the unattributed class surfaced
        detectors = {d["detector"]: d["observations"] for d in body["detectors"]}
        assert detectors["agent-collector"] == 1
        assert detectors["entropy-heuristic"] == 1
        assert detectors["UNATTRIBUTED"] == 1
        assert body["unattributed_observations"] == 1

        assert "never inferred" in body["method"]["negative_evidence"]

        # unknown scan -> 404
        assert (await client.get("/api/v1/scans/nope/coverage")).status_code == 404


@pytest.mark.asyncio
async def test_scan_coverage_clean_scan_flag():
    app, session = _make_app()
    when = NOW - timedelta(hours=1)
    session.add(Scan(id="cov-clean", scan_start=when, scan_end=when,
                     target_type="LOCAL_DIRECTORY", target_location="/repo",
                     status="COMPLETED",
                     statistics={"files_scanned": 10, "total_findings": 0,
                                 "findings_by_origin": {}}))
    session.commit()
    async with _client(app) as client:
        body = (await client.get("/api/v1/scans/cov-clean/coverage")).json()
        assert body["clean_scan"] is True
        assert all(o["zero_observation"] for o in body["origins"])
        assert body["detectors"] == []
        assert "clean-scan" in body["method"]["clean_scan_path"]
