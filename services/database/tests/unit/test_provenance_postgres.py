"""Opt-in disposable PostgreSQL checks, never an existing deployment.

CRYPTOSCAN_PROVENANCE_TEST_DATABASE_URL must name an owned cryptoscan_e2e_*
database on a local socket/loopback. Audit concurrency fixtures create/drop
ONLY their own randomly named database and minimal audit table. Read parity
uses the migrated app schema, always rolls back. No credentials in artifacts.
"""
import concurrent.futures
import os
import threading
import time
import uuid

import pytest
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm import Session

from db.import_provenance import import_clause, legacy_import_clause
from db.models.crypto_asset import CryptoAsset
from db.models.user import AuditLog
from db.repositories.user_repository import UserRepository, verify_audit_chain
from shared_models.import_provenance import is_import, is_legacy_import
from test_import_provenance import CASES

URL = os.environ.get("CRYPTOSCAN_PROVENANCE_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not URL, reason="explicit owned disposable PostgreSQL URL required")


def _url():
    url = make_url(URL)
    assert url.get_backend_name() == "postgresql"
    assert (url.database or "").startswith("cryptoscan_e2e_")
    assert not url.host or url.host in {"localhost", "127.0.0.1"} or url.host.startswith("/home/user/")
    return url


@pytest.fixture
def audit_engine():
    url = _url()
    name = "cryptoscan_e2e_audit_" + uuid.uuid4().hex[:12]
    admin = create_engine(url.set(database="postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        connection.execute(text('CREATE DATABASE "' + name + '"'))
    engine = create_engine(url.set(database=name), pool_size=10)
    try:
        AuditLog.__table__.create(engine)
        yield engine
    finally:
        engine.dispose()
        with admin.connect() as connection:
            connection.execute(text('DROP DATABASE "' + name + '"'))
        admin.dispose()


@pytest.mark.parametrize("extra,scanners", CASES)
def test_postgres_sql_read_projection_parity(extra, scanners):
    engine = create_engine(_url())
    try:
        with Session(engine) as db:
            row = CryptoAsset(algorithm="AES", file_path="synthetic-parity", line_number=0, confidence="HIGH", extra=extra, scanner_ids=scanners)
            db.add(row); db.flush()
            observed, legacy = db.execute(select(import_clause(), legacy_import_clause()).select_from(CryptoAsset)
                                         .where(CryptoAsset.id == row.id)).one()
            data = {"extra":extra,"scanner_ids":scanners}
            assert bool(observed) == is_import(data)
            assert bool(legacy) == is_legacy_import(data)
            db.rollback()
    finally:
        engine.dispose()


def _concurrent(engine, monkeypatch, *, unsafe_control=False):
    count = 8
    start = threading.Barrier(count)
    after_head = threading.Barrier(count) if unsafe_control else None
    original_head = UserRepository._audit_chain_head
    def head(repo):
        result = original_head(repo)
        if after_head:
            after_head.wait(timeout=10)
        else:
            time.sleep(0.02)  # widen the historical race, under the fixed lock
        return result
    monkeypatch.setattr(UserRepository, "_audit_chain_head", head)
    def append(i):
        with Session(engine) as db:
            if unsafe_control:
                original_execute = db.execute
                def without_lock(statement, *args, **kwargs):
                    if "pg_advisory_xact_lock" in str(statement):
                        return None  # test-only reproduction of the old unlocked append
                    return original_execute(statement, *args, **kwargs)
                db.execute = without_lock
            start.wait(timeout=10)
            row = UserRepository(db).audit("synthetic-"+str(i), "concurrency.synthetic")
            sequence = row.chain_sequence
            db.commit()
            return sequence
    with concurrent.futures.ThreadPoolExecutor(max_workers=count) as executor:
        sequences = list(executor.map(append, range(count)))
    with Session(engine) as db:
        assert db.execute(select(func.count()).select_from(AuditLog)).scalar_one() == count
        result = verify_audit_chain(db)
    return sequences, result


def test_unlocked_control_commits_a_fork_and_verifier_refuses_it(audit_engine, monkeypatch):
    sequences, verification = _concurrent(audit_engine, monkeypatch, unsafe_control=True)
    assert sequences == [1]*8
    assert verification["status"] != "OK"


def test_concurrent_appends_have_one_global_sequence_and_valid_chain(audit_engine, monkeypatch):
    sequences, verification = _concurrent(audit_engine, monkeypatch)
    assert sorted(sequences) == list(range(1, 9))
    assert verification["status"] == "OK", verification


def test_rollback_releases_lock_without_consuming_a_sequence(audit_engine):
    started = threading.Event()
    first = Session(audit_engine)
    UserRepository(first).audit("synthetic-first", "will.rollback")
    def second():
        with Session(audit_engine) as db:
            started.set()
            row = UserRepository(db).audit("synthetic-second", "will.commit")
            sequence = row.chain_sequence
            db.commit()
            return sequence
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(second)
        assert started.wait(timeout=5)
        try:
            assert not future.done()
        finally:
            first.rollback(); first.close()
        assert future.result(timeout=10) == 1
    with Session(audit_engine) as db:
        assert verify_audit_chain(db)["status"] == "OK"


def test_repeatable_read_cannot_append_from_a_stale_snapshot(audit_engine):
    with Session(audit_engine.execution_options(isolation_level="REPEATABLE READ")) as db:
        with pytest.raises(InvalidRequestError, match="READ COMMITTED"):
            UserRepository(db).audit("synthetic", "refused")
        db.rollback()
        assert db.execute(select(func.count()).select_from(AuditLog)).scalar_one() == 0
