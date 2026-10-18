"""Opt-in real PostgreSQL receipt upsert/claim qualification, no HTTP mocks.

Uses ONLY a uniquely named temporary schema; never drops a database. A
configured but unreachable/misconfigured server FAILS, not skipped proof.
"""
from __future__ import annotations

import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from control_plane.notification_dispatch import LEASE_SECONDS, _insert, _values, claim
from db.models.notification_delivery import NotificationDelivery as Receipt
from db.tenancy import install_tenant_guard, tenant_scope

pytestmark = pytest.mark.live
NOW = datetime(2026, 10, 17, tzinfo=timezone.utc)


@pytest.fixture
def factory():
    url = os.environ.get("CRYPTOSCAN_TEST_PG_URL")
    if not url:
        pytest.skip("set CRYPTOSCAN_TEST_PG_URL to an approved disposable PostgreSQL test instance")
    schema = "notification_test_" + uuid.uuid4().hex
    engine = sa.create_engine(url)
    with engine.begin() as connection:
        connection.execute(sa.schema.CreateSchema(schema))
    isolated = engine.execution_options(schema_translate_map={None: schema})
    try:
        Receipt.__table__.create(isolated)
        install_tenant_guard()
        yield sessionmaker(bind=isolated, expire_on_commit=False)
    finally:
        with engine.begin() as connection:
            connection.execute(sa.schema.DropSchema(schema, cascade=True))
        engine.dispose()


def test_postgres_dedup_is_null_safe_and_tenant_local(factory):
    with factory() as session:
        assert _insert(session, **_values(None, "event", "dest", "siem", "crypto_drift", {}, NOW)) == 1
        assert _insert(session, **_values(None, "event", "dest", "siem", "crypto_drift", {}, NOW)) == 0
        session.commit()
        with tenant_scope("tenant-a"):
            assert _insert(session, **_values("tenant-a", "event", "dest", "siem", "crypto_drift", {}, NOW)) == 1
            session.commit()
        assert session.scalar(sa.select(sa.func.count()).select_from(Receipt)) == 2


def test_postgres_concurrent_claim_and_expiry_recovery(factory):
    values = _values(None, "event", "dest", "siem", "crypto_drift", {}, NOW)
    with factory() as session:
        _insert(session, **values)
        session.commit()
    barrier = threading.Barrier(2)

    def contender():
        with factory() as session:
            barrier.wait(timeout=10)
            return claim(session, values["id"], now=NOW)

    with ThreadPoolExecutor(max_workers=2) as pool:
        tokens = [future.result(timeout=20) for future in [pool.submit(contender), pool.submit(contender)]]
    assert sum(token is not None for token in tokens) == 1
    previous = next(token for token in tokens if token)
    with factory() as session:
        replacement = claim(session, values["id"], now=NOW + timedelta(seconds=LEASE_SECONDS + 1))
        assert replacement and replacement != previous
        changed = session.execute(sa.update(Receipt).where(Receipt.id == values["id"], Receipt.lease_token == previous)
                                  .values(status="delivered").returning(Receipt.id)).scalar_one_or_none()
        assert changed is None
        session.commit()
