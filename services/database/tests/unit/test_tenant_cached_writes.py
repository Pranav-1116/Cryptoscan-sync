"""Flushes bypass Session DML hooks; cached foreign/platform rows must stay read-only."""
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from control_plane.notification_dispatch import _values
from db.models.notification_delivery import NotificationDelivery
from db.tenancy import TenantScopeViolation, install_tenant_guard, tenant_scope


@pytest.fixture
def session():
    engine = create_engine("sqlite:///:memory:")
    NotificationDelivery.__table__.create(engine)
    install_tenant_guard()
    with Session(engine, expire_on_commit=False) as session:
        yield session
    engine.dispose()


def row(session, owner):
    value = NotificationDelivery(**_values(owner, "event", "destination", "siem",
                                          "remediation_verification", {}, datetime.now(timezone.utc)))
    session.add(value)
    session.commit()
    return value


@pytest.mark.parametrize("owner", [None, "tenant-b"], ids=["platform", "foreign"])
@pytest.mark.parametrize("operation", ["update", "delete"])
@pytest.mark.parametrize("expired", [False, True], ids=["cached", "expired"])
def test_foreign_cached_mutations_fail_before_writes(session, owner, operation, expired):
    value = row(session, owner)  # loaded before entering tenant-a
    identity = value.id
    if expired:
        session.expire(value)
    with tenant_scope("tenant-a"):
        if operation == "update":
            value.last_error = "tampered"
        else:
            session.delete(value)
        with pytest.raises(TenantScopeViolation):
            session.flush()
        session.rollback()
    persisted = session.get(NotificationDelivery, identity)
    assert persisted is not None and persisted.tenant_id == owner and persisted.last_error is None


@pytest.mark.parametrize("operation", ["update", "delete"])
def test_same_owner_cached_writes_still_work(session, operation):
    value = row(session, "tenant-a")
    identity = value.id
    with tenant_scope("tenant-a"):
        if operation == "update":
            value.last_error = "own update"
        else:
            session.delete(value)
        session.commit()
    persisted = session.get(NotificationDelivery, identity)
    assert persisted.last_error == "own update" if operation == "update" else persisted is None


@pytest.mark.parametrize("operation", ["update", "delete"])
def test_explicit_unscoped_platform_units_of_work_still_work(session, operation):
    value = row(session, "tenant-b")
    identity = value.id
    if operation == "update":
        value.last_error = "platform update"
    else:
        session.delete(value)
    session.commit()
    persisted = session.get(NotificationDelivery, identity)
    assert persisted.last_error == "platform update" if operation == "update" else persisted is None


def test_foreign_cached_write_prevents_partial_flush_of_own_changes(session):
    own, foreign = row(session, "tenant-a"), row(session, "tenant-b")
    with tenant_scope("tenant-a"):
        own.last_error = "own pending change"
        session.delete(foreign)
        with pytest.raises(TenantScopeViolation):
            session.flush()
        session.rollback()
    assert len(session.scalars(select(NotificationDelivery)).all()) == 2
    assert own.last_error is None
