"""Tenant isolation on the scan surface.

Before this existed, ``ScanRepository.list_scans`` took no tenant argument and
every tenant read every tenant's scans. The isolation is now an ORM-level
filter, so these tests go through the ordinary repositories — if the filter
only worked when a repository remembered to ask for it, that is exactly the
bug being prevented and these would pass while the product leaked.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from db.connection.session import Base
from db.models.scan import Scan
from db.repositories.scan_repository import ScanRepository
from db.tenancy import (
    TenantScoped,
    current_tenant,
    install_tenant_guard,
    platform_scope,
    tenant_scope,
)

BANK_A = "11111111-1111-1111-1111-111111111111"
BANK_B = "22222222-2222-2222-2222-222222222222"


@pytest.fixture()
def session():
    install_tenant_guard()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine, expire_on_commit=False)()
    yield s
    s.close()
    engine.dispose()


def _make_scan(session, target: str, tenant_id: str | None) -> Scan:
    scan = Scan(target_location=target, status="COMPLETED", tenant_id=tenant_id,
                scan_start=datetime.now(timezone.utc))
    session.add(scan)
    session.commit()
    return scan


def test_scan_model_is_tenant_scoped():
    assert issubclass(Scan, TenantScoped)
    assert "tenant_id" in Scan.__table__.columns
    assert Scan.__table__.columns["tenant_id"].index is True


def test_a_tenant_cannot_list_another_tenants_scans(session):
    _make_scan(session, "bank-a-core-banking", BANK_A)
    _make_scan(session, "bank-b-core-banking", BANK_B)

    with tenant_scope(BANK_A):
        scans, total = ScanRepository(session).list_scans()
    targets = {s.target_location for s in scans}

    assert targets == {"bank-a-core-banking"}
    assert total == 1, "the count must be filtered too, or it leaks the other tenant's volume"


def test_a_tenant_cannot_fetch_another_tenants_scan_by_id(session):
    other = _make_scan(session, "bank-b-core-banking", BANK_B)

    with tenant_scope(BANK_A):
        found = ScanRepository(session).get_by_id(other.id)

    assert found is None, "fetching a known id across tenants must be absence, not a 403 oracle"


def test_platform_rows_stay_visible_to_a_tenant(session):
    """An on-prem install that later enables tenancy must keep its history."""
    _make_scan(session, "pre-tenancy-estate", None)
    _make_scan(session, "bank-b", BANK_B)

    with tenant_scope(BANK_A):
        scans, _ = ScanRepository(session).list_scans()

    assert {s.target_location for s in scans} == {"pre-tenancy-estate"}


def test_no_scope_sees_everything(session):
    """Single-tenant and worker contexts are unfiltered."""
    _make_scan(session, "a", BANK_A)
    _make_scan(session, "b", BANK_B)

    scans, total = ScanRepository(session).list_scans()
    assert total == 2


def test_platform_scope_is_an_explicit_cross_tenant_read(session):
    _make_scan(session, "a", BANK_A)
    _make_scan(session, "b", BANK_B)

    with tenant_scope(BANK_A), platform_scope():
        scans, total = ScanRepository(session).list_scans()

    assert total == 2, "a supervisor roll-up must be able to opt out deliberately"


def test_new_rows_are_stamped_with_the_active_tenant(session):
    """A row created inside a tenant scope must not land unattributed."""
    with tenant_scope(BANK_A):
        scan = Scan(target_location="new-estate", status="RUNNING",
                    scan_start=datetime.now(timezone.utc))
        session.add(scan)
        session.commit()
        assert scan.tenant_id == BANK_A

    # and it is invisible to the other tenant
    with tenant_scope(BANK_B):
        scans, total = ScanRepository(session).list_scans()
    assert total == 0


def test_scope_is_restored_after_exit(session):
    assert current_tenant() is None
    with tenant_scope(BANK_A):
        assert current_tenant() == BANK_A
    assert current_tenant() is None


def test_recent_scans_helper_is_filtered_too(session):
    """Every read path, not just the one the fix was written against."""
    _make_scan(session, "bank-a", BANK_A)
    _make_scan(session, "bank-b", BANK_B)

    with tenant_scope(BANK_A):
        recent = ScanRepository(session).get_recent_scans(limit=50)

    assert {s.target_location for s in recent} == {"bank-a"}
