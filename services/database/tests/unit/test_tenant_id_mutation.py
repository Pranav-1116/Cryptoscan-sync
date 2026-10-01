"""Ownership columns are immutable after a row is attributed."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, update
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from db.connection.session import Base
from db.models.scan import Scan
from db.tenancy import TenantScopeViolation, install_tenant_guard, tenant_scope

A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"


@pytest.fixture()
def session():
    install_tenant_guard()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    current = sessionmaker(bind=engine, expire_on_commit=False)()
    yield current
    current.close()
    engine.dispose()


def _row(session):
    with tenant_scope(A):
        row = Scan(target_location="https://a.example", status="COMPLETED", scan_start=datetime.now(timezone.utc))
        session.add(row)
        session.commit()
        return row


def test_orm_tenant_id_cannot_be_reassigned(session):
    row = _row(session)
    with tenant_scope(A):
        row.tenant_id = B
        with pytest.raises(TenantScopeViolation, match="immutable"):
            session.commit()
        session.rollback()


def test_bulk_tenant_id_cannot_be_reassigned(session):
    row = _row(session)
    with tenant_scope(A):
        with pytest.raises(TenantScopeViolation, match="immutable"):
            session.execute(update(Scan).where(Scan.id == row.id).values(tenant_id=B))
        session.rollback()
