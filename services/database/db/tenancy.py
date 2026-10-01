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
objects from the active scope, rejects an explicitly foreign owner, and the
Session DML hook adds an exact-tenant predicate to bulk UPDATE/DELETE. A row
cannot be created or mutated across tenants while a tenant is active.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar

from sqlalchemy import String, event, inspect as sa_inspect, or_, select
from sqlalchemy.orm import Mapped, Session, mapped_column, with_loader_criteria

#: The tenant whose rows the current unit of work may see. ``None`` means no
#: tenant scope is active (platform operator, worker, single-tenant install).
_active_tenant: ContextVar[str | None] = ContextVar("cryptoscan_active_tenant", default=None)

#: Set while a deliberate cross-tenant read is in progress (platform admin,
#: supervisor roll-up, migrations). Kept separate from "no tenant" so that
#: bypassing isolation is always an explicit, greppable act.
_bypass: ContextVar[bool] = ContextVar("cryptoscan_tenant_bypass", default=False)


class TenantScopeViolation(ValueError):
    """Raised when scoped code attempts to forge or cross a tenant boundary."""


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
    """Attribute a new row to the active tenant, if there is one.

    A caller may omit ``tenant_id`` and let the scope stamp it, but it may not
    create a row already attributed to a different tenant.  Silently accepting
    that value would let a tenant create data in another tenant's namespace and
    makes queue/request bugs look like successful work.
    """
    if not isinstance(obj, TenantScoped):
        return
    tenant = current_tenant()
    if tenant is None:
        return
    existing = getattr(obj, "tenant_id", None)
    if existing is not None and existing != tenant:
        raise TenantScopeViolation(
            f"row is attributed to tenant {existing!r}, but active scope is {tenant!r}"
        )
    obj.tenant_id = tenant


_INSTALLED = False


def _dml_changes_tenant_id(statement) -> bool:
    """Return whether an ORM/Core UPDATE tries to rewrite ownership."""
    values = getattr(statement, "_values", None) or {}
    for key in values:
        name = getattr(key, "key", None) or getattr(key, "name", None) or key
        if name == "tenant_id":
            return True
    return False


def filtered_get(session: Session, model, row_id):
    """Primary-key lookup that still passes through tenant SELECT criteria.

    Small non-SQLAlchemy fakes used by pipeline unit tests retain their legacy
    ``get`` seam; real sessions always take the filtered SELECT path.
    """
    if not isinstance(session, Session):  # test doubles only
        return session.get(model, row_id)
    return session.execute(select(model).where(model.id == row_id)).scalars().first()


def install_tenant_guard() -> None:
    """Register the ORM-level filter. Idempotent."""
    global _INSTALLED
    if _INSTALLED:
        return

    @event.listens_for(Session, "do_orm_execute")
    def _apply_tenant_filter(orm_execute_state):  # pragma: no cover - exercised via queries
        if not isolation_active():
            return

        tenant = current_tenant()

        if orm_execute_state.is_select:
            # A relationship/lazy load inherits the criteria of its parent
            # query, so re-applying would double-filter; SQLAlchemy handles
            # that when the option is propagated, which is why include_aliases
            # is set.
            if orm_execute_state.is_column_load or orm_execute_state.is_relationship_load:
                return
            orm_execute_state.statement = orm_execute_state.statement.options(
                with_loader_criteria(
                    TenantScoped,
                    # The tenant's own rows, plus the un-attributed platform
                    # estate (legacy/single-tenant data).
                    lambda cls: or_(cls.tenant_id == tenant, cls.tenant_id.is_(None)),
                    include_aliases=True,
                )
            )
            return

        if orm_execute_state.is_update or orm_execute_state.is_delete:
            # ``with_loader_criteria`` is a SELECT loader option. It does not
            # constrain ORM/Core UPDATE or DELETE statements, including
            # ``session.execute(update(Model.__table__))``. Every DML
            # statement executed through a Session still exposes its mapper,
            # so add an exact-tenant predicate here. Platform NULL rows are
            # intentionally readable but are never writable from a tenant
            # scope.
            mappers = list(getattr(orm_execute_state, "all_mappers", ()) or ())
            if len(mappers) != 1:
                return
            mapper = mappers[0]
            model = mapper.class_
            if not issubclass(model, TenantScoped):
                return
            if _dml_changes_tenant_id(orm_execute_state.statement):
                raise TenantScopeViolation("tenant_id is immutable once a row exists")
            column = mapper.local_table.c.get("tenant_id")
            if column is not None:
                orm_execute_state.statement = orm_execute_state.statement.where(column == tenant)

    @event.listens_for(Session, "before_flush")
    def _stamp_new_rows(session, flush_context, instances):  # pragma: no cover
        for obj in session.dirty:
            if not isinstance(obj, TenantScoped):
                continue
            history = sa_inspect(obj).attrs.tenant_id.history
            if history.has_changes():
                raise TenantScopeViolation("tenant_id is immutable once a row exists")
        if current_tenant() is None:
            return
        for obj in session.new:
            stamp_tenant(obj)

    _INSTALLED = True
