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


def test_stage_is_fail_soft(session, monkeypatch):
    session.add(_ev("scan-1", "RSA", "a.py", 1))
    session.flush()

    def _boom(self):
        raise RuntimeError("db exploded")

    monkeypatch.setattr(
        "db.repositories.fact_repository.FactRepository.rebuild", _boom)
    ctx = stage_facts.execute(_Ctx("scan-1"), session=session)  # must not raise
    assert ctx.scan_id == "scan-1"
    assert session.execute(select(CryptographicFact)).scalars().first() is None


def test_stage_no_files_is_a_clean_noop(session):
    ctx = stage_facts.execute(_Ctx("scan-none"), session=session)
    assert ctx.scan_id == "scan-none"
    assert session.execute(select(CryptographicFact)).scalars().first() is None


def test_stage_class_wraps_execute():
    ctx = stage_facts.StageFacts().execute(_Ctx("scan-x"))
    assert ctx.scan_id == "scan-x"
