"""Tenant boundaries for the durable control-plane history repositories."""

from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register every mapped table
from db.connection.session import Base
from db.repositories.control_plane_repository import ControlPlaneRepository
from db.tenancy import install_tenant_guard, tenant_scope

TENANT_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
TENANT_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"


def test_queue_delivery_and_posture_history_are_tenant_filtered():
    install_tenant_guard()
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    repo = ControlPlaneRepository(session)

    try:
        with tenant_scope(TENANT_A):
            event_a = repo.enqueue("scan.completed", {"tenant_id": TENANT_A})
            repo.record_delivery(
                result={"tenant_id": TENANT_A, "status": "delivered"},
                event_type="scan.completed", event_id=event_a.id,
            )
            repo.create_security_posture(score=91)

        with tenant_scope(TENANT_B):
            event_b = repo.enqueue("scan.completed", {"tenant_id": TENANT_B})
            repo.record_delivery(
                result={"tenant_id": TENANT_B, "status": "failed"},
                event_type="scan.completed", event_id=event_b.id,
            )
            repo.create_security_posture(score=42)
        session.commit()
        session.expunge_all()

        with tenant_scope(TENANT_A):
            assert [row.id for row in repo.list_events()] == [event_a.id]
            assert repo.get_event(event_b.id) is None
            delivery_a = repo.list_delivery_logs()
            assert len(delivery_a) == 1 and delivery_a[0].status == "delivered"
            assert repo.delivery_stats() == {"delivered": 1}
            assert [row.score for row in repo.list_security_postures()] == [91]
            assert repo.latest_security_posture().score == 91

        with tenant_scope(TENANT_B):
            assert [row.id for row in repo.list_events()] == [event_b.id]
            assert repo.get_event(event_a.id) is None
            assert repo.delivery_stats() == {"failed": 1}
            assert [row.score for row in repo.list_security_postures()] == [42]

        # An authorized worker can use an explicit tenant marker even when no
        # request scope is active; it cannot accidentally lease the other one.
        with tenant_scope(None):
            assert [row.id for row in repo.list_events(tenant_id=TENANT_A)] == [event_a.id]
            assert repo.get_event(event_b.id, tenant_id=TENANT_A) is None
    finally:
        session.close()
        engine.dispose()
