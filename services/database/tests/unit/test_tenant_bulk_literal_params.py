"""Fixed SQLAlchemy literal binds must work without admitting dynamic owners."""
import pytest
from sqlalchemy import bindparam, create_engine, func, insert, select
from sqlalchemy.orm import Session

from db.models.notification_delivery import NotificationDelivery
from db.tenancy import TenantScopeViolation, install_tenant_guard, tenant_scope
from control_plane.notification_dispatch import _values
from datetime import datetime, timezone


@pytest.fixture
def session():
    engine = create_engine("sqlite:///:memory:")
    NotificationDelivery.__table__.create(engine)
    install_tenant_guard()
    with Session(engine) as session:
        yield session
    engine.dispose()


def values(owner):
    return _values(owner, "event", "destination", "siem", "remediation_verification", {}, datetime.now(timezone.utc))


def test_matching_fixed_owner_literal_is_accepted(session):
    with tenant_scope("tenant-a"):
        session.execute(insert(NotificationDelivery).values(**values("tenant-a")))
        session.commit()
        assert session.scalar(select(NotificationDelivery.tenant_id)) == "tenant-a"


def test_omitted_owner_is_stamped(session):
    row = values("tenant-a")
    row.pop("tenant_id")
    with tenant_scope("tenant-a"):
        session.execute(insert(NotificationDelivery).values(**row))
        session.commit()
        assert session.scalar(select(NotificationDelivery.tenant_id)) == "tenant-a"


@pytest.mark.parametrize("owner", ["tenant-b", bindparam("runtime_owner"),
                                 bindparam("callable_owner", callable_=lambda: "tenant-a"), func.current_user()])
def test_foreign_or_dynamic_owner_cannot_bypass_guard(session, owner):
    row = values("tenant-a")
    row["tenant_id"] = owner
    with tenant_scope("tenant-a"):
        with pytest.raises(TenantScopeViolation):
            session.execute(insert(NotificationDelivery).values(**row))
        session.rollback()
    assert session.scalar(select(NotificationDelivery)) is None


@pytest.mark.parametrize("rows", ["one", "many"])
def test_execute_parameters_are_stamped_not_only_statement_values(session, rows):
    row = values("tenant-a")
    row.pop("tenant_id")
    with tenant_scope("tenant-a"):
        session.execute(insert(NotificationDelivery), row if rows == "one" else [row])
        session.commit()
        assert session.scalar(select(NotificationDelivery.tenant_id)) == "tenant-a"


@pytest.mark.parametrize("rows", ["one", "many"])
def test_foreign_execute_parameters_are_rejected(session, rows):
    row = values("tenant-b")
    with tenant_scope("tenant-a"):
        with pytest.raises(TenantScopeViolation):
            session.execute(insert(NotificationDelivery), row if rows == "one" else [row])
        session.rollback()
    assert session.scalar(select(NotificationDelivery)) is None


def test_execute_parameters_cannot_override_an_accepted_statement_literal(session):
    row = values("tenant-a")
    with tenant_scope("tenant-a"):
        with pytest.raises(TenantScopeViolation):
            session.execute(insert(NotificationDelivery).values(**row), {"tenant_id": "tenant-b"})
        session.rollback()
    assert session.scalar(select(NotificationDelivery)) is None


def test_named_fixed_bind_cannot_be_overridden_at_execute_time(session):
    row = values("tenant-a")
    row["tenant_id"] = bindparam("owner", value="tenant-a")
    with tenant_scope("tenant-a"):
        with pytest.raises(TenantScopeViolation):
            session.execute(insert(NotificationDelivery).values(**row), {"owner": "tenant-b"})
        session.rollback()
    assert session.scalar(select(NotificationDelivery)) is None


def test_insert_from_select_is_not_an_ownership_bypass(session):
    row = values("tenant-b")
    session.execute(insert(NotificationDelivery).values(**row))
    session.commit()
    statement = insert(NotificationDelivery).from_select(["id", "tenant_id"],
                                                         select(NotificationDelivery.id, NotificationDelivery.tenant_id))
    with tenant_scope("tenant-a"):
        with pytest.raises(TenantScopeViolation, match="SELECT"):
            session.execute(statement)
