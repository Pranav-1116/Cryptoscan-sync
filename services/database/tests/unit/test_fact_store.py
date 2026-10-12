"""Cryptographic fact store (advanced/51 P0#1 write-side step, round 35)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

import db.models  # noqa: F401 — register every table
from db.connection.session import Base
from db.fact_projection import fact_key, identity_values
from db.models.cryptographic_fact import CryptographicFact
from db.models.evidence_record import EvidenceRecord
from db.repositories.fact_repository import FactRepository


@pytest.fixture()
def session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()
    engine.dispose()


def _ev(scan, algo, path, line, purpose="ENCRYPTION", key_size=None,
        scanner="ast", created=None, deleted=None, hardcoded=False):
    return EvidenceRecord(
        scan_id=scan, content_hash=f"{scan}{algo}{path}{line}{scanner}",
        chain_hash="0" * 64, chain_position=line,
        algorithm=algo, purpose=purpose, key_size=key_size,
        file_path=path, line_number=line,
        finding_data={"scanner_id": scanner}, confidence="HIGH",
        compliance_status="FAIL", is_hardcoded_key=hardcoded,
        created_at=created or datetime(2026, 10, 1, tzinfo=timezone.utc),
        deleted_at=deleted,
    )


def test_identity_is_verbatim_and_shared_with_the_api():
    # "" not None: SQL NULLs are distinct under unique constraints in
    # SQLite, so identity must be exact-match everywhere
    values = identity_values(fact_key({"algorithm": "RSA", "file_path": "a.py"}))
    assert values["purpose"] == "" and values["mode"] == ""
    row = {"algorithm": "RSA", "purpose": None, "file_path": "a.py", "mode": None}
    assert fact_key(row) == fact_key({"algorithm": "RSA", "file_path": "a.py"})


def test_rebuild_groups_evidence_into_facts(session):
    session.add_all([
        _ev("s1", "RSA-2048", "src/Keys.java", 11, key_size=2048, scanner="ast"),
        _ev("s1", "RSA-2048", "src/Keys.java", 44, key_size=2048, scanner="regex"),
        _ev("s2", "RSA-2048", "src/Keys.java", 99, key_size=2048, scanner="ast",
            created=datetime(2026, 10, 5, tzinfo=timezone.utc)),
        _ev("s2", "AES-128", "src/Legacy.java", 7, key_size=128, scanner="ast"),
        _ev("s2", "RSA-2048", "src/Keys.java", 12, key_size=2048, scanner="ast",
            hardcoded=True),
    ])
    session.flush()
    result = FactRepository(session).rebuild()
    assert result == {"facts_upserted": 2, "facts_stale": 0, "evidence_rows": 5}

    facts = {f.algorithm: f for f in session.execute(select(CryptographicFact)).scalars()}
    rsa = facts["RSA-2048"]
    assert rsa.observation_count == 4  # 2048-key observations, all lines
    assert rsa.hardcoded_key_observations == 1
    assert rsa.scanners == ["ast", "regex"]
    assert len(rsa.evidence_ids) == 4
    assert rsa.first_seen is not None and rsa.last_seen is not None
    assert rsa.is_current is True and rsa.rebuilt_at is not None
    assert facts["AES-128"].observation_count == 1


def test_rebuild_is_idempotent(session):
    session.add(_ev("s1", "RSA", "a.py", 1))
    session.flush()
    repo = FactRepository(session)
    first = repo.rebuild()
    second = repo.rebuild()
    assert first["facts_upserted"] == second["facts_upserted"] == 1
    assert session.execute(select(CryptographicFact)).scalars().first().observation_count == 1


def test_per_file_rebuild_marks_vanished_facts_stale(session):
    session.add_all([
        _ev("s1", "3DES", "src/old/Enc.java", 3, purpose="ENCRYPTION"),
        _ev("s1", "AES", "src/new/Enc.java", 4, purpose="ENCRYPTION"),
    ])
    session.flush()
    repo = FactRepository(session)
    repo.rebuild()
    # the 3DES evidence is retracted (soft-deleted) — a per-file rebuild
    # of that file must mark its fact stale, not leave it answering
    row = session.execute(select(EvidenceRecord).where(
        EvidenceRecord.algorithm == "3DES")).scalar_one()
    row.deleted_at = datetime(2026, 10, 6, tzinfo=timezone.utc)
    session.flush()
    result = repo.rebuild(file_paths=["src/old/Enc.java"])
    assert result["facts_upserted"] == 0 and result["facts_stale"] == 1
    facts = {f.algorithm: f for f in session.execute(select(CryptographicFact)).scalars()}
    assert facts["3DES"].is_current is False
    assert facts["3DES"].observation_count == 0
    assert facts["AES"].is_current is True  # untouched file untouched


def test_files_for_scan_scopes_the_rebuild(session):
    session.add_all([
        _ev("s1", "RSA", "a.py", 1),
        _ev("s1", "AES", "b.py", 1),
        _ev("s2", "SHA-1", "c.py", 1),
    ])
    session.flush()
    assert FactRepository(session).files_for_scan("s1") == ["a.py", "b.py"]
    assert FactRepository(session).files_for_scan("nope") == []


def test_list_current_filters(session):
    session.add_all([
        _ev("s1", "RSA", "src/pay/a.py", 1),
        _ev("s1", "AES", "src/old/b.py", 1),
    ])
    session.flush()
    repo = FactRepository(session)
    repo.rebuild()
    rows = repo.list_current(file_prefix="src/pay")
    assert [r.algorithm for r in rows] == ["RSA"]
    assert [r.algorithm for r in repo.list_current(algorithm="AES")] == ["AES"]
