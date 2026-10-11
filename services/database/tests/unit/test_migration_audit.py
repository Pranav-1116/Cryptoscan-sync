"""Alembic schema-migration auditing (advanced/78, round 33)."""

from __future__ import annotations

from sqlalchemy import create_engine, inspect, select
from sqlalchemy.orm import sessionmaker


def _script_dir():
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    from pathlib import Path

    ini = Path(__file__).resolve().parents[2] / "migrations" / "alembic.ini"
    cfg = Config(str(ini))
    cfg.set_main_option("script_location", str(ini.parent))
    return ScriptDirectory.from_config(cfg)


def _audit_session():
    import db.models  # noqa: F401 — register every table

    from db.connection.session import Base
    from db.models.user import AuditLog

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    return Session(), AuditLog


# ── pure revision walk ────────────────────────────────────────────────


def test_applied_revisions_walks_the_chain():
    script = _script_dir()
    head = script.get_current_head()
    head_script = script.get_revision(head)
    previous = head_script.down_revision

    # one step: previous -> head applies exactly [head]
    assert _walk(script, previous, head) == [head]
    # two steps: the revision before `previous` walks to head applying 2
    if previous is not None:
        pre2 = script.get_revision(previous).down_revision
        if pre2 is not None:
            assert _walk(script, pre2, head) == [previous, head]
    # no change
    assert _walk(script, head, head) == []
    # genesis walk: base -> head applies the whole chain (linear history)
    base = head_script
    while base.down_revision is not None:
        base = script.get_revision(base.down_revision)
    assert len(_walk(script, base.down_revision, head)) == len(_walk(script, None, head))


def _walk(script, before, after):
    from db.migration_audit import applied_revisions

    return applied_revisions(script, before, after)


def test_applied_revisions_rejects_nonsense():
    script = _script_dir()
    assert _walk(script, None, None) == []
    # unknown revision id: walk stops cleanly, no exception
    assert _walk(script, None, "not-a-real-revision") == []


# ── audit writes ──────────────────────────────────────────────────────


def test_audit_applied_migrations_writes_chained_rows():
    from db.migration_audit import AUDIT_ACTION, audit_applied_migrations

    script = _script_dir()
    session, AuditLog = _audit_session()
    engine = session.get_bind()
    head = script.get_current_head()
    previous = script.get_revision(head).down_revision

    with engine.connect() as conn:
        written = audit_applied_migrations(
            conn, before=previous, after=head, script_dir=script)
    assert written == 1
    rows = list(session.execute(
        select(AuditLog).where(AuditLog.action == AUDIT_ACTION)).scalars())
    assert len(rows) == 1
    row = rows[0]
    assert row.actor == "migrator"
    assert row.target_type == "alembic_revision"
    assert row.target_id == head
    assert row.entry_hash and row.chain_sequence is not None
    detail = row.detail
    assert '"direction": "up"' in detail
    assert head in detail

    # a second applied revision chains onto the first
    pre2 = script.get_revision(previous).down_revision
    with engine.connect() as conn:
        written = audit_applied_migrations(
            conn, before=pre2, after=previous, script_dir=script)
    assert written == 1
    rows = list(session.execute(
        select(AuditLog).order_by(AuditLog.chain_sequence)).scalars())
    assert len(rows) == 2
    assert rows[1].previous_hash == rows[0].entry_hash


def test_audit_applied_migrations_bootstrap_is_honest():
    from db.migration_audit import audit_applied_migrations

    # no audit_log table: bootstrap revisions are NOT back-filled
    engine = create_engine("sqlite:///:memory:")
    script = _script_dir()
    with engine.connect() as conn:
        assert audit_applied_migrations(
            conn, before=None, after=script.get_current_head(),
            script_dir=script) == 0
        assert not inspect(conn).has_table("audit_log")  # nothing fabricated

    # no version move: nothing to audit
    session, _ = _audit_session()
    with session.get_bind().connect() as conn:
        assert audit_applied_migrations(
            conn, before="x", after="x", script_dir=script) == 0
    session.close()


def test_nonlinear_move_still_recorded():
    """A version move the linear walk cannot resolve is recorded as one row
    with linear_walk=false — never silently dropped."""
    from db.migration_audit import AUDIT_ACTION, audit_applied_migrations

    class _FakeScriptDir:
        def get_revision(self, rev):
            raise KeyError(rev)

    session, AuditLog = _audit_session()
    with session.get_bind().connect() as conn:
        written = audit_applied_migrations(
            conn, before="old", after="new", script_dir=_FakeScriptDir())
    assert written == 1
    row = session.execute(
        select(AuditLog).where(AuditLog.action == AUDIT_ACTION)).scalar_one()
    assert row.target_id == "new"
    assert '"linear_walk": false' in row.detail
    session.close()
