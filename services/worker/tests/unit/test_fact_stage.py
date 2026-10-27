"""Fact-store pipeline stage (advanced/51 write-side, round 35)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

import db.models  # noqa: F401 — register every table
from db.connection.session import Base
from db.models.cryptographic_fact import CryptographicFact
from db.models.evidence_record import EvidenceRecord
from db.models.scan import Scan
from worker.pipeline import stage_facts


class _Ctx:
    def __init__(self, scan_id):
        self.scan_id = scan_id


@pytest.fixture()
def session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()
    engine.dispose()


def _ev(scan, algo, path, line):
    return EvidenceRecord(
        scan_id=scan, content_hash=f"{scan}{algo}{path}{line}",
        chain_hash="0" * 64, chain_position=line,
        algorithm=algo, purpose="ENCRYPTION", key_size=None,
        file_path=path, line_number=line,
        finding_data={"scanner_id": "ast"}, confidence="HIGH",
        compliance_status="FAIL",
        created_at=datetime(2026, 10, 1, tzinfo=timezone.utc),
    )


def test_stage_rebuilds_facts_for_the_scan_files(session):
    session.add_all([
        _ev("scan-1", "RSA-2048", "src/Keys.java", 11),
        _ev("scan-1", "AES-128", "src/Keys.java", 12),
        _ev("scan-2", "SHA-1", "other/File.java", 3),
    ])
    session.flush()
    ctx = stage_facts.execute(_Ctx("scan-1"), session=session)
    facts = {f.algorithm for f in session.execute(select(CryptographicFact)).scalars()}
    assert facts == {"RSA-2048", "AES-128"}  # scan-2's file untouched
    assert ctx.scan_id == "scan-1"


def test_stage_is_fail_soft_without_rolling_back_scan_or_evidence(session, monkeypatch, caplog):
    session.add(Scan(id="scan-1", scan_start=datetime.now(timezone.utc),
                     target_location="local-repo"))
    session.add(_ev("scan-1", "RSA", "a.py", 1))
    # Leave the caller's scan/evidence pending: begin_nested will flush them
    # before opening its savepoint, and its rollback must still preserve them.

    def _boom(self, *, file_paths):
        self.session.add(CryptographicFact(
            algorithm="RSA", purpose="ENCRYPTION", file_path="a.py", mode="",
        ))
        self.session.flush()  # a partially written projection inside the savepoint
        raise RuntimeError("db exploded")

    monkeypatch.setattr(
        "db.repositories.fact_repository.FactRepository.rebuild", _boom)
    ctx = stage_facts.execute(_Ctx("scan-1"), session=session)  # must not raise
    assert ctx.scan_id == "scan-1"
    assert "facts_stage_failed scan_id=scan-1 error_type=RuntimeError" in caplog.text
    assert session.execute(select(CryptographicFact)).scalars().first() is None
    # This caller is still in charge of the transaction; a later stage can
    # update the scan and commit the evidence without an FK violation.
    scan = session.get(Scan, "scan-1")
    scan.status = "COMPLETED"
    session.commit()
    assert session.get(Scan, "scan-1").status == "COMPLETED"
    assert session.get(Scan, "scan-1").statistics["fact_store_status"] == "FAILED"
    assert session.execute(select(EvidenceRecord)).scalar_one().scan_id == "scan-1"


def test_shared_session_stage_does_not_commit(session, monkeypatch):
    session.add(_ev("scan-1", "RSA", "a.py", 1))
    session.flush()
    def _commit_forbidden():
        raise AssertionError("caller session must not be committed by fact stage")
    monkeypatch.setattr(session, "commit", _commit_forbidden)
    stage_facts.execute(_Ctx("scan-1"), session=session)
    assert session.execute(select(CryptographicFact)).scalar_one().algorithm == "RSA"


def test_stage_no_files_is_a_clean_noop(session):
    ctx = stage_facts.execute(_Ctx("scan-none"), session=session)
    assert ctx.scan_id == "scan-none"
    assert session.execute(select(CryptographicFact)).scalars().first() is None


def test_stage_class_wraps_execute():
    ctx = stage_facts.StageFacts().execute(_Ctx("scan-x"))
    assert ctx.scan_id == "scan-x"
