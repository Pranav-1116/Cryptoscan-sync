"""Who can read the monitor journal: the row's owner, then the target behind it.

Round 81 found ``GET /monitor/events`` answering ``{"events": []}`` against a
database holding 64 durable rows. ``list_events`` scoped exclusively through
``target_id IN (SELECT id FROM monitor_targets ...)`` — and a platform journal
row (what :func:`api.events.platform_events.emit_platform_event` writes, via a
target shim whose ``id`` is None) has no ``MonitorTarget`` behind it at all, so
``NULL IN (...)`` never matched. Two consequences, both pinned here:

* the platform estate's own journal — every ``remediation.task_*`` event — was
  unreachable for the platform admin who owns it; and
* with no registered watch-list targets, which is the normal case outside the
  monitor daemon, the feed was empty for *every* caller, tenant included, even
  for rows stamped with that tenant's id.

Ownership is now read from the row first (``MonitorEvent.tenant_id``, where NULL
*is* the platform estate per :class:`db.tenancy.TenantScoped`) and from the
target second, so the watch-list behaviour that existed before is unchanged.
Neither branch is widened past its scope: a tenant never reads another tenant's
rows, and a platform caller never reads tenant-owned rows through this endpoint
(a cross-tenant roll-up is an explicit ``platform_scope()`` call, not a default).
"""

from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register every mapped table
from db.connection.session import Base
from db.models.monitor import MonitorTarget
from db.repositories.monitor_repository import MonitorRepository
from db.tenancy import install_tenant_guard, tenant_scope

TENANT_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
TENANT_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"


class _PlatformShim:
    """The shape ``emit_platform_event._persist`` hands the repository: a
    target-like object with no id, because a platform journal row describes the
    estate rather than a watch-list target."""

    id = None
    name = "remediation"
    tenant_id = None


def _repo():
    install_tenant_guard()
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    return MonitorRepository(session), session


def _types(rows) -> list[str]:
    return [row.event_type for row in rows]


def test_platform_journal_rows_are_readable_by_the_platform_caller():
    """The round-81 defect: durable platform rows, invisible to their owner."""
    repo, session = _repo()
    try:
        repo.add_event(target=_PlatformShim(), event_type="remediation.task_created",
                       detail="task t-1 proposed", payload={"task_id": "t-1"})
        repo.add_event(target=_PlatformShim(), event_type="remediation.task_verified",
                       detail="task t-1 verified", payload={"task_id": "t-1"})
        session.commit()

        # No registered monitor targets exist — the endpoint used to answer
        # empty here even though both rows are on disk.
        assert session.query(MonitorTarget).count() == 0

        rows = repo.list_events(platform=True, limit=50)
        assert _types(rows) == ["remediation.task_verified", "remediation.task_created"]
        assert all(row.target_id is None and row.tenant_id is None for row in rows)
        assert rows[0].payload["task_id"] == "t-1"

        # A tenant caller does not read the platform estate's journal through
        # this endpoint: the row is not attributed to them.
        assert repo.list_events(tenant_id=TENANT_A, limit=50) == []
    finally:
        session.close()


def test_a_tenant_reads_its_own_journal_rows_and_not_another_tenants():
    """Rows stamped with a tenant are that tenant's to read — including rows
    with no target behind them, which the target-join filter used to drop."""
    repo, session = _repo()
    try:
        with tenant_scope(TENANT_A):
            repo.add_event(target=_PlatformShim(), event_type="remediation.task_created",
                           detail="alpha task proposed")
        with tenant_scope(TENANT_B):
            repo.add_event(target=_PlatformShim(), event_type="remediation.task_created",
                           detail="beta task proposed")
        session.commit()
        session.expunge_all()

        # The emit inside a tenant scope is stamped by the guard, so the row is
        # owned even though nothing behind it is.
        with tenant_scope(TENANT_A):
            assert _types(repo.list_events(tenant_id=TENANT_A, limit=50)) == [
                "remediation.task_created"]
            assert repo.list_events(tenant_id=TENANT_A, limit=50)[0].detail == "alpha task proposed"
        with tenant_scope(TENANT_B):
            rows = repo.list_events(tenant_id=TENANT_B, limit=50)
            assert len(rows) == 1 and rows[0].detail == "beta task proposed"

        # The platform estate's view is the complement: these rows belong to
        # tenants, so a platform caller does not read them here.
        assert repo.list_events(platform=True, limit=50) == []
    finally:
        session.close()


def test_watch_list_target_events_keep_their_previous_scope():
    """The behaviour that existed before the fix is unchanged: a target's events
    follow the target's owner, and ``target_id`` still narrows to one target."""
    repo, session = _repo()
    try:
        # Each target is committed inside the scope that owns it: the stamping
        # hook attributes NEW rows at flush time, so a target flushed outside
        # any scope is platform estate and one flushed inside a tenant's scope
        # is that tenant's.
        platform_target = MonitorTarget(name="edge-platform", target_type="NETWORK",
                                        config={"endpoints": ["edge.example:443"]})
        session.add(platform_target)
        session.commit()
        with tenant_scope(TENANT_A):
            tenant_target = MonitorTarget(name="edge-alpha", target_type="NETWORK",
                                          config={"endpoints": ["alpha.example:443"]})
            session.add(tenant_target)
            session.commit()

        repo.add_event(target=platform_target, event_type="SCAN_OK", detail="platform edge ok")
        with tenant_scope(TENANT_A):
            repo.add_event(target=tenant_target, event_type="SCAN_DEGRADED", detail="alpha weak tls")
        session.commit()
        session.expunge_all()

        assert _types(repo.list_events(platform=True, limit=50)) == ["SCAN_OK"]
        with tenant_scope(TENANT_A):
            assert _types(repo.list_events(tenant_id=TENANT_A, limit=50)) == ["SCAN_DEGRADED"]
            # one target at a time, whichever scope asks
            assert _types(repo.list_events(target_id=tenant_target.id, tenant_id=TENANT_A)) == [
                "SCAN_DEGRADED"]
            assert repo.list_events(target_id=platform_target.id, tenant_id=TENANT_A) == []
        assert _types(repo.list_events(target_id=platform_target.id, platform=True)) == ["SCAN_OK"]
    finally:
        session.close()


def test_a_tenants_event_on_a_platform_target_is_in_both_pictures():
    """Row ownership and target ownership can disagree, and neither is dropped.

    A tenant-scoped caller acting on a platform-estate watch-list target writes
    a row attributed to the tenant (the guard stamps it) about a target the
    platform owns. The platform caller reads it because the target is in its
    watch-list picture — that is what the endpoint showed before this fix — and
    the tenant reads it because the row is attributed to it. A cross-tenant
    roll-up would need an explicit ``platform_scope()``; this is not one, since
    the row's target is platform estate rather than another tenant's.
    """
    repo, session = _repo()
    try:
        platform_target = MonitorTarget(name="shared-edge", target_type="NETWORK",
                                        config={"endpoints": ["shared.example:443"]})
        session.add(platform_target)
        session.commit()

        with tenant_scope(TENANT_A):
            repo.add_event(target=platform_target, event_type="SCAN_DEGRADED",
                           detail="alpha probed the shared edge")
            session.commit()
            own = repo.list_events(tenant_id=TENANT_A, limit=50)
            assert _types(own) == ["SCAN_DEGRADED"]
        session.expunge_all()

        rows = repo.list_events(platform=True, limit=50)
        assert _types(rows) == ["SCAN_DEGRADED"]
        assert rows[0].tenant_id == TENANT_A  # attributed, and still platform-visible
        assert rows[0].target_id == platform_target.id

        # The other tenant reads neither: not the row, not the platform target.
        with tenant_scope(TENANT_B):
            assert repo.list_events(tenant_id=TENANT_B, limit=50) == []
    finally:
        session.close()


def test_limit_is_clamped_and_newest_first():
    """The published bounds of the feed did not move with the scope fix."""
    repo, session = _repo()
    try:
        for index in range(5):
            repo.add_event(target=_PlatformShim(), event_type=f"remediation.task_{index}",
                           detail=f"row {index}")
        session.commit()

        assert len(repo.list_events(platform=True, limit=0)) == 1      # clamped up
        assert len(repo.list_events(platform=True, limit=10_000)) == 5  # clamped to 500, 5 exist
        rows = repo.list_events(platform=True, limit=2)
        assert len(rows) == 2
        assert rows[0].created_at >= rows[1].created_at
    finally:
        session.close()
