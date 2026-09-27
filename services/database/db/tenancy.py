"""Automatic tenant isolation for the scan surface.

The problem this solves
-----------------------
Tenant isolation used to be a per-repository responsibility, and the scan
surface simply never implemented it: ``ScanRepository.list_scans`` took no
tenant argument, so any authenticated member of any tenant read every tenant's
scans, evidence and crypto assets. Only five tenancy-plane tables carried a
``tenant_id`` at all.

Fixing that repository-by-repository across ~40 tables and ~90 routers is the
kind of change where one missed query silently re-opens the hole, and the
missed query looks exactly like the fixed ones. So the filter is applied once,
by the ORM, to every statement that touches a tenant-scoped model.

How it works
------------
1. A model opts in by inheriting :class:`TenantScoped`, which gives it a
   nullable, indexed ``tenant_id``.
2. :func:`install_tenant_guard` registers a ``do_orm_execute`` listener that
   adds ``with_loader_criteria`` to every ORM query, so the filter reaches
   lazy loads and relationship loads too — not just the top-level select.
3. Request handling sets the active tenant with :func:`tenant_scope`. Outside
   any scope the guard is inert, which is what single-tenant and on-prem
   deployments want.

NULL ``tenant_id`` means "platform estate": rows created before tenancy, or by
a single-tenant install. A tenant sees its own rows **and** the platform rows,
because an on-prem install that later enables tenancy must not have its history
vanish. A tenant never sees another tenant's rows.

Writes are guarded separately: :func:`stamp_tenant` sets ``tenant_id`` on new
objects from the active scope, so a row cannot be created unattributed while a
tenant is active.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar

from sqlalchemy import String, event, or_
from sqlalchemy.orm import Mapped, Session, mapped_column, with_loader_criteria

#: The tenant whose rows the current unit of work may see. ``None`` means no
#: tenant scope is active (platform operator, worker, single-tenant install).
_active_tenant: ContextVar[str | None] = ContextVar("cryptoscan_active_tenant", default=None)

#: Set while a deliberate cross-tenant read is in progress (platform admin,
#: supervisor roll-up, migrations). Kept separate from "no tenant" so that
#: bypassing isolation is always an explicit, greppable act.
_bypass: ContextVar[bool] = ContextVar("cryptoscan_tenant_bypass", default=False)


class TenantScoped:
    """Mixin: the model's rows belong to a tenant (NULL = platform estate)."""

    tenant_id: Mapped[str | None] = mapped_column(
        String(36), nullable=True, index=True, default=None
    )


def current_tenant() -> str | None:
    """The active tenant id, or None when no scope is in force."""
    return _active_tenant.get()


def isolation_active() -> bool:
    """True when queries are currently being filtered."""
    return _active_tenant.get() is not None and not _bypass.get()


@contextmanager
def tenant_scope(tenant_id: str | None):
    """Filter every tenant-scoped query to ``tenant_id`` for the duration.

    ``None`` is accepted and means "no scoping" so callers can pass a request's
    tenant through unconditionally.
    """
    # Save/restore rather than Token.reset(): a sync generator dependency in
    # FastAPI is driven from a threadpool, so setup and teardown can run in
    # different contexts and reset() then raises "created in a different
    # Context". Restoring the previous value is context-safe and, because each
    # request runs in its own copied context, still leaves nothing behind.
    previous = _active_tenant.get()
    _active_tenant.set(tenant_id)
    try:
        yield
    finally:
        _active_tenant.set(previous)


@contextmanager
def platform_scope():
    """Deliberately read across tenants (platform admin, supervisor roll-up).

    Separate from ``tenant_scope(None)`` so that every cross-tenant read is an
    explicit call that a reviewer can grep for.
    """
    previous = _bypass.get()
    _bypass.set(True)
    try:
        yield
    finally:
        _bypass.set(previous)


def stamp_tenant(obj) -> None:
    """Attribute a new row to the active tenant, if there is one."""
    if isinstance(obj, TenantScoped) and getattr(obj, "tenant_id", None) is None:
        tenant = current_tenant()
        if tenant is not None:
            obj.tenant_id = tenant


_INSTALLED = False


def install_tenant_guard() -> None:
    """Register the ORM-level filter. Idempotent."""
    global _INSTALLED
    if _INSTALLED:
        return

    @event.listens_for(Session, "do_orm_execute")
    def _apply_tenant_filter(orm_execute_state):  # pragma: no cover - exercised via queries
        if not orm_execute_state.is_select:
            return
        # A relationship/lazy load inherits the criteria of its parent query,
        # so re-applying would double-filter; SQLAlchemy handles that when the
        # option is propagated, which is why include_aliases is set.
        if orm_execute_state.is_column_load or orm_execute_state.is_relationship_load:
            return
        if not isolation_active():
            return
        tenant = current_tenant()
        orm_execute_state.statement = orm_execute_state.statement.options(
            with_loader_criteria(
                TenantScoped,
                # The tenant's own rows, plus the un-attributed platform estate
                # (rows that predate tenancy, or a single-tenant install's data).
                lambda cls: or_(cls.tenant_id == tenant, cls.tenant_id.is_(None)),
                include_aliases=True,
            )
        )

    @event.listens_for(Session, "before_flush")
    def _stamp_new_rows(session, flush_context, instances):  # pragma: no cover
        if current_tenant() is None:
            return
        for obj in session.new:
            stamp_tenant(obj)

    _INSTALLED = True
