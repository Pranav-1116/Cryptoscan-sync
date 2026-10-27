"""Cryptographic fact store (advanced/51 P0#1 write-side step, round 35)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.operations import Operations
from alembic.script import ScriptDirectory
from pathlib import Path
from sqlalchemy import Column, Integer, MetaData, String, Table, UniqueConstraint, create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from db.tenancy import tenant_scope, install_tenant_guard

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
        scanner="ast", created=None, deleted=None, hardcoded=False, tenant=None):
    return EvidenceRecord(
        tenant_id=tenant, scan_id=scan, content_hash=f"{scan}{algo}{path}{line}{scanner}",
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


def test_bounded_fact_read_filters_before_limit_and_counts_visible_tenants(session):
    session.add_all([
        CryptographicFact(tenant_id="one", algorithm="AES", purpose="",
                          file_path=f"src/other/{i:04d}.py", mode="",
                          observation_count=1)
        for i in range(1100)
    ])
    session.add_all([
        CryptographicFact(tenant_id=tenant, algorithm="AES", purpose="",
                          file_path="src/%_literal.py", mode="",
                          observation_count=2)
        for tenant in (None, "one", "two")
    ])
    session.add_all([
        CryptographicFact(tenant_id="one", algorithm="AES", purpose="",
                          file_path="src/XXliteral.py", mode="",
                          observation_count=2),
        CryptographicFact(tenant_id="one", algorithm="AES", purpose="",
                          file_path="src/%_lower.py", mode="",
                          observation_count=1),
        CryptographicFact(tenant_id="one", algorithm="AES", purpose="",
                          file_path="SRC/%_upper.py", mode="",
                          observation_count=2),
    ])
    session.flush()
    repo = FactRepository(session)
    filters = {"file_prefix": "src/%_", "min_observations": 2}
    assert repo.count_current(**filters) == 3
    assert len(repo.list_current(**filters, limit=1)) == 1
    assert repo.list_current(**filters, limit=1)[0].tenant_id is None
    install_tenant_guard()
    with tenant_scope("one"):
        assert repo.count_current(**filters) == 2  # platform + own, not other tenant
        assert [f.tenant_id for f in repo.list_current(**filters)] == [None, "one"]
        assert repo.count_current(file_prefix="src/other/") == 1100


def test_tenant_local_identity_and_platform_row(session):
    session.add_all([
        _ev("s1", "RSA", "same.py", 1, tenant="one"),
        _ev("s2", "RSA", "same.py", 2, tenant="two"),
        _ev("s3", "RSA", "same.py", 3),
    ])
    session.flush()
    repo = FactRepository(session)
    assert repo.rebuild()["facts_upserted"] == 3
    assert repo.rebuild()["facts_upserted"] == 3
    facts = {f.tenant_id: f for f in repo.list_current()}
    assert set(facts) == {"one", "two", None}
    assert all(f.observation_count == 1 for f in facts.values())
    assert len({tuple(f.evidence_ids) for f in facts.values()}) == 3

    install_tenant_guard()
    with tenant_scope("one"):
        assert {f.tenant_id for f in repo.list_current()} == {"one", None}
        # A scoped admin may not rewrite the platform projection.
        assert repo.rebuild()["facts_upserted"] == 1
    assert facts[None].observation_count == 1


def test_unknown_key_size_has_one_identity_even_across_rebuilds(session):
    session.add(_ev("s1", "AES", "same.py", 1, tenant="one"))
    session.flush()
    repo = FactRepository(session)
    repo.rebuild()
    session.add(_ev("s2", "AES", "same.py", 2, tenant="one"))
    session.flush()
    repo.rebuild()
    facts = repo.list_current()
    assert len(facts) == 1
    assert facts[0].key_size is None and facts[0].observation_count == 2
    # The schema must also reject a duplicate inserted outside the repository.
    with pytest.raises(IntegrityError), session.begin_nested():
        session.add(CryptographicFact(
            tenant_id="one", algorithm="AES", purpose="ENCRYPTION",
            file_path="same.py", mode="", key_size=None,
        ))
        session.flush()


def test_full_rebuild_retires_vanished_facts_and_resets_rollups(session):
    session.add(_ev("s1", "3DES", "old.py", 1, hardcoded=True))
    session.flush()
    repo = FactRepository(session)
    repo.rebuild()
    evidence = session.execute(select(EvidenceRecord)).scalar_one()
    evidence.deleted_at = datetime(2026, 10, 6, tzinfo=timezone.utc)
    session.flush()
    assert repo.rebuild() == {"facts_upserted": 0, "facts_stale": 1, "evidence_rows": 0}
    fact = repo.list_current(include_stale=True)[0]
    assert not fact.is_current and fact.observation_count == 0
    assert fact.evidence_ids == [] and fact.hardcoded_key_observations == 0
    assert fact.first_seen is None and fact.last_seen is None
    assert repo.list_current() == []


def test_sqlite_forward_migration_rejects_ambiguous_rows_and_enforces_identity():
    ini = Path(__file__).resolve().parents[2] / "migrations" / "alembic.ini"
    revision = ScriptDirectory.from_config(Config(str(ini))).get_revision("0087").module
    engine = create_engine("sqlite:///:memory:")
    metadata = MetaData()
    old = Table("cryptographic_facts", metadata,
                Column("id", String(36), primary_key=True),
                Column("tenant_id", String(36), nullable=False),
                Column("algorithm", String(80), nullable=False),
                Column("purpose", String(50)), Column("file_path", String()),
                Column("key_size", Integer), Column("mode", String(50)),
                UniqueConstraint("algorithm", "purpose", "file_path", "key_size",
                                 "mode", name="uq_fact_identity"))
    metadata.create_all(engine)
    with engine.begin() as conn:
        conn.execute(old.insert(), [
            {"id": "a", "tenant_id": "one", "algorithm": "RSA", "file_path": "same.py"},
            {"id": "b", "tenant_id": "one", "algorithm": "RSA", "file_path": "same.py"},
        ])
        with Operations.context(MigrationContext.configure(conn)):
            with pytest.raises(RuntimeError, match="duplicate tenant-local identities"):
                revision.upgrade()
        # The failed preflight leaves every derived row and all evidence untouched.
        assert len(conn.execute(select(old)).all()) == 2
        conn.execute(old.delete().where(old.c.id == "b"))
        with Operations.context(MigrationContext.configure(conn)):
            revision.upgrade()
        conn.execute(old.insert(), [
            {"id": "platform", "tenant_id": None, "algorithm": "RSA", "file_path": "same.py"},
            {"id": "two", "tenant_id": "two", "algorithm": "RSA", "file_path": "same.py"},
        ])
        with pytest.raises(IntegrityError), conn.begin_nested():
            conn.execute(old.insert().values(
                id="duplicate", tenant_id=None, algorithm="RSA", file_path="same.py"))
    engine.dispose()


def test_staleness_is_tenant_local_on_shared_path(session):
    session.add_all([
        _ev("s1", "AES", "same.py", 1, tenant="one"),
        _ev("s2", "AES", "same.py", 2, tenant="two"),
    ])
    session.flush()
    repo = FactRepository(session)
    repo.rebuild()
    evidence = session.execute(select(EvidenceRecord).where(
        EvidenceRecord.tenant_id == "one")).scalar_one()
    evidence.deleted_at = datetime(2026, 10, 6, tzinfo=timezone.utc)
    session.flush()
    assert repo.rebuild(file_paths=["same.py"])["facts_stale"] == 1
    facts = {f.tenant_id: f for f in repo.list_current(include_stale=True)}
    assert not facts["one"].is_current and facts["two"].is_current
    assert set(repo.latest_activity_by_file(["same.py"])) == {
        ("one", "same.py"), ("two", "same.py")}
