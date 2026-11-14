"""Privileged database operations are audited — a deletion nobody recorded
is indistinguishable from a deletion nobody authorized."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker


@pytest.fixture()
def db(tmp_path):
    import db.models  # noqa: F401 — register every model on the metadata
    from db.models.base import Base

    engine = create_engine(f"sqlite:///{tmp_path / 'audit.db'}")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


class TestPrivilegedOps:

    def test_a_privileged_operation_joins_the_chain(self, db):
        from db.models.user import AuditLog
        from db.privileged_ops import record_privileged
        from db.repositories.user_repository import verify_audit_chain

        record_privileged(db, actor="retention-sweep",
                          action="RETENTION_DELETE",
                          target_type="cryptolog_events_y2026m08",
                          target_id="partition",
                          detail={"rows": 1200, "window_days": 180})
        record_privileged(db, actor="retention-sweep",
                          action="RETENTION_DELETE",
                          target_type="cryptolog_events_y2026m07",
                          detail={"rows": 900})
        db.commit()

        rows = db.scalars(select(AuditLog).order_by(
            AuditLog.chain_sequence)).all()
        assert [r.action for r in rows] == ["RETENTION_DELETE",
                                            "RETENTION_DELETE"]
        assert rows[1].previous_hash == rows[0].entry_hash, (
            "the chain links: no privileged action stands alone")
        assert verify_audit_chain(db)["status"] == "OK"

    def test_tampering_with_a_recorded_deletion_is_detectable(self, db):
        from db.models.user import AuditLog
        from db.privileged_ops import record_privileged
        from db.repositories.user_repository import verify_audit_chain

        record_privileged(db, actor="retention-sweep", action="RETENTION_DELETE",
                          target_id="partition-a", detail={"rows": 100})
        record_privileged(db, actor="retention-sweep", action="RETENTION_DELETE",
                          target_id="partition-b", detail={"rows": 200})
        db.commit()

        # Somebody edits history to hide the first deletion.
        first = db.scalars(select(AuditLog).where(
            AuditLog.target_id == "partition-a")).one()
        first.detail = '{"rows": 0}'
        db.commit()

        report = verify_audit_chain(db)
        assert report["status"] == "TAMPERED", (
            "the hash chain turns a quiet edit into a visible break")

    def test_the_actor_is_the_operator_never_an_omission(self, db):
        from db.privileged_ops import record_privileged

        row = record_privileged(db, actor="quarterly-drill",
                                action="RESTORE_DRILL",
                                outcome="SUCCESS")
        assert row.actor == "quarterly-drill"
        assert row.outcome == "SUCCESS"
        assert row.chain_sequence == 1
        assert row.entry_hash
