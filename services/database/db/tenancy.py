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

Core and textual SQL are fail-closed
------------------------------------
``with_loader_criteria`` only reaches ORM-enabled statements. A raw
``session.execute(text("select * from scans"))``, or a Core statement built
purely from ``Table.c`` columns, would otherwise read — and, for UPDATE/
DELETE/INSERT, write — every tenant's rows while a scope is active. The guard
therefore inspects every non-ORM statement executed through a Session and
raises :class:`TenantScopeViolation` if its compiled SQL touches a table whose
model inherits :class:`TenantScoped`. Rewriting the query through the ORM (or
an explicit :func:`platform_scope` block for platform code) is the supported
path. ORM-enabled bulk INSERTs (``session.execute(insert(Model), rows)``)
bypass ``before_flush``, so the guard stamps — or, on a foreign claim,
rejects — their ``tenant_id`` directly. Finally, an ORM-shaped SELECT that
embeds Core-constructed subqueries (built from ``Table.c``) is rejected too:
``with_loader_criteria`` covers the statement's own entities but never those
embedded fragments.
"""

from __future__ import annotations

import re
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any

from sqlalchemy import String, Table, event, inspect as sa_inspect, or_, select
from sqlalchemy.orm import Mapped, Session, mapped_column, with_loader_criteria
from sqlalchemy.sql import Join, Select
from sqlalchemy.sql.annotation import AnnotatedColumn, AnnotatedTable

#: The tenant whose rows the current unit of work may see. ``None`` means no
#: tenant scope is active (platform operator, worker, single-tenant install).
_active_tenant: ContextVar[str | None] = ContextVar("cryptoscan_active_tenant", default=None)

#: Set while a deliberate cross-tenant read is in progress (platform admin,
#: supervisor roll-up, migrations). Kept separate from "no tenant" so that
#: bypassing isolation is always an explicit, greppable act.
_bypass: ContextVar[bool] = ContextVar("cryptoscan_tenant_bypass", default=False)

#: Tables whose rows belong to a tenant. Populated automatically as each
#: model class is defined (``TenantScoped.__init_subclass__``), so the Core /
#: textual-SQL guard can recognize scoped tables without importing the models
#: package from here (tenancy.py sits below it in the import graph).
_TENANT_TABLES: set[str] = set()


class TenantScopeViolation(ValueError):
    """Raised when scoped code attempts to forge or cross a tenant boundary."""


class TenantScoped:
    """Mixin: the model's rows belong to a tenant (NULL = platform estate)."""

    tenant_id: Mapped[str | None] = mapped_column(
        String(36), nullable=True, index=True, default=None
    )

    def __init_subclass__(cls, **kwargs):
        # Record the table name the moment the model class is defined so the
        # Core/textual-SQL guard can inspect statements without a registry
        # lookup (and without importing the models package from here).
        super().__init_subclass__(**kwargs)
        name = cls.__dict__.get("__tablename__")
        if name and not cls.__dict__.get("__abstract__", False):
            _TENANT_TABLES.add(str(name))


def scoped_tables() -> frozenset[str]:
    """Names of every table whose model inherits :class:`TenantScoped`."""
    return frozenset(_TENANT_TABLES)


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


def _statement_sql(statement) -> str:
    """Best-effort SQL text of a Core/textual statement, for table matching."""
    raw = getattr(statement, "text", None)
    if isinstance(raw, str):
        return raw
    try:
        return str(statement.compile())
    except Exception as exc:  # pragma: no cover - defensive
        raise TenantScopeViolation(
            "non-ORM statement inside a tenant scope could not be inspected; "
            "rewrite it through the ORM or use db.tenancy.platform_scope()"
        ) from exc


def _reject_cross_tenant_core_statement(statement) -> None:
    """Fail closed when Core/textual SQL touches a tenant-scoped table.

    ``with_loader_criteria`` never applies to these statements and the DML
    rewrite below only sees ORM-enabled ones, so without this check
    ``session.execute(text(...))`` — or a statement assembled purely from
    ``Table.c`` columns — reads and writes every tenant's rows while a scope
    is active. Matching runs against the compiled SQL so tables hidden in
    subqueries are caught too. The greppable opt-out is :func:`platform_scope`.
    """
    if not _TENANT_TABLES:  # pragma: no cover - models always loaded in practice
        return
    sql = _statement_sql(statement)
    for name in sorted(_TENANT_TABLES, key=len, reverse=True):
        if re.search(rf"\b{re.escape(name)}\b", sql, re.IGNORECASE):
            raise TenantScopeViolation(
                f"raw or Core SQL touching tenant-scoped table {name!r} inside "
                f"a tenant scope; use the ORM (auto-filtered) or an explicit "
                f"db.tenancy.platform_scope() block"
            )


def _reject_unfiltered_core_references(statement, covered_tables) -> None:
    """Fail closed on ORM-shaped statements that embed Core SQL fragments.

    ``with_loader_criteria`` covers ORM references — which materialize as
    annotated nodes (``AnnotatedColumn`` / ``AnnotatedTable``) — and it
    propagates into embedded ORM subqueries. It never reaches fragments
    built from ``Table.c`` / ``select_from(Table)``: those read every
    tenant's rows even inside an otherwise ORM-shaped statement. Each select
    level (the statement itself plus every embedded select, subquery, alias
    or exists) is analysed on its own, so a Core reference cannot be masked
    by an ORM reference to the same table at an outer level.
    """
    if not _TENANT_TABLES:  # pragma: no cover - models always loaded in practice
        return

    # Each level is analysed with its OWN ORM references only: seeding inner
    # levels with the outer statement's mapper tables would let an ORM
    # reference mask a Core reference to the same table inside a subquery.
    pending: list[tuple[Any, frozenset[str]]] = [(statement, frozenset(covered_tables))]
    queued = {id(statement)}
    while pending:
        current, extra_covered = pending.pop()
        covered = set(extra_covered)
        plain: set[str] = set()

        # ORM references in this level's own clauses (embedded selects are
        # queued and analysed separately, never mixed into this level).
        stack: list[Any] = [current]
        seen = {id(current)}
        while stack:
            node = stack.pop()
            if isinstance(node, Select) and node is not current:
                if id(node) not in queued:
                    queued.add(id(node))
                    pending.append((node, frozenset()))
                continue
            # ScalarSelect / Alias / Exists wrappers hide an embedded select
            # from get_children(); queue it and do not credit its annotated
            # columns to this level (that would mask a Core reference).
            wrapped = False
            for attr in ("element", "select"):
                inner = getattr(node, attr, None)
                if isinstance(inner, Select) and id(inner) not in queued:
                    queued.add(id(inner))
                    pending.append((inner, frozenset()))
                    wrapped = True
            if wrapped:
                continue
            if isinstance(node, AnnotatedColumn):
                table = getattr(node, "table", None)
                name = getattr(table, "name", None)
                if name:
                    covered.add(name)
            elif isinstance(node, AnnotatedTable):
                covered.add(node.name)
            try:
                children = node.get_children(column_collections=True)
            except TypeError:
                children = node.get_children()
            for child in children:
                if id(child) not in seen:
                    seen.add(id(child))
                    stack.append(child)

        # Plain (non-annotated) tables in this level's FROM clauses.
        try:
            froms = list(current.get_final_froms())  # type: ignore[attr-defined]
        except Exception:
            froms = []
        for node in froms:
            _classify_from(node, plain, pending, queued)
        rogue = sorted((plain & _TENANT_TABLES) - covered)
        if rogue:
            raise TenantScopeViolation(
                f"statement embeds non-ORM references to tenant-scoped "
                f"table(s) {', '.join(rogue)} that the tenant filter cannot "
                f"reach; build the subquery from the ORM entity or use "
                f"db.tenancy.platform_scope()"
            )


def _classify_from(node, plain: set[str], pending: list, queued: set) -> None:
    """Sort a FROM-clause entry into ORM-covered, plain Core, or sub-level."""
    if isinstance(node, AnnotatedTable):
        return  # ORM entity reference: covered by loader criteria
    if isinstance(node, Table):
        plain.add(node.name)
        return
    if isinstance(node, Join):
        _classify_from(node.left, plain, pending, queued)
        _classify_from(node.right, plain, pending, queued)
        return
    element = getattr(node, "element", None)  # Alias / Subquery / CTE wrapper
    if isinstance(element, Table):
        plain.add(element.name)
    elif element is not None and id(element) not in queued:
        queued.add(id(element))
        pending.append((element, frozenset()))


def _guard_orm_bulk_insert(orm_execute_state, tenant: str) -> None:
    """Stamp (or reject) tenant ownership on ORM-enabled bulk INSERTs.

    ``session.execute(insert(Model).values(rows))`` never passes through
    ``before_flush``, so the usual stamping hook cannot see it: unstamped rows
    would land as platform estate, i.e. visible to every tenant. The values
    are inspected here instead: an omitted ``tenant_id`` is stamped from the
    active scope (mirroring :func:`stamp_tenant`), an explicitly foreign one
    is rejected.
    """
    statement = orm_execute_state.statement
    mappers = list(getattr(orm_execute_state, "all_mappers", ()) or ())
    if len(mappers) != 1:
        return
    model = mappers[0].class_
    if not issubclass(model, TenantScoped):
        return

    rows: list[dict] = []
    single = getattr(statement, "_values", None)
    is_single_values = isinstance(single, dict)
    if is_single_values:
        rows.append(single)
    for group in getattr(statement, "_multi_values", None) or ():
        if isinstance(group, (list, tuple)):
            rows.extend(d for d in group if isinstance(d, dict))
        elif isinstance(group, dict):
            rows.append(group)

    claimed: list[str | None] = []
    normalized_rows: list[dict] = []
    for row in rows:
        plain = {getattr(key, "name", None) or getattr(key, "key", None) or key: value
                 for key, value in row.items()}
        claimed.append(plain.get("tenant_id"))
        normalized_rows.append((row, plain))

    for row, plain in normalized_rows:
        claim = plain.get("tenant_id")
        if claim is not None and claim != tenant:
            raise TenantScopeViolation(
                f"bulk insert claims tenant {claim!r} while active scope is {tenant!r}"
            )

    if not rows or all(claim is not None for claim in claimed):
        return  # every row already owned by the active tenant

    if is_single_values:
        # The single-value form accepts a merging .values() call; the
        # multi-values form does not ("can't mix formats"), so its parameter
        # dicts are stamped in place instead (they are read at compile time).
        orm_execute_state.statement = statement.values(tenant_id=tenant)
        return
    for row, plain in normalized_rows:
        if plain.get("tenant_id") is None:
            row["tenant_id"] = tenant


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

        if not orm_execute_state.is_orm_statement:
            # Textual SQL and statements built purely from Table.c columns
            # carry no mappers, so neither with_loader_criteria (SELECT) nor
            # the DML predicate below can reach them. Fail closed.
            _reject_cross_tenant_core_statement(orm_execute_state.statement)
            return

        if orm_execute_state.is_select:
            # A relationship/lazy load inherits the criteria of its parent
            # query, so re-applying would double-filter; SQLAlchemy handles
            # that when the option is propagated, which is why include_aliases
            # is set.
            if orm_execute_state.is_column_load or orm_execute_state.is_relationship_load:
                return
            # ORM-shaped statements can still embed Core-constructed
            # fragments (scalar subqueries built from Table.c, select_from
            # (Table), aliases of tables): with_loader_criteria reaches the
            # statement's own entities but never those fragments, so they
            # would read cross-tenant data. Fail closed on them.
            mappers = list(getattr(orm_execute_state, "all_mappers", ()) or ())
            _reject_unfiltered_core_references(
                orm_execute_state.statement,
                {mapper.local_table.name for mapper in mappers},
            )
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

        if orm_execute_state.is_insert:
            # Bulk INSERTs bypass before_flush, so ownership is stamped (or a
            # foreign claim rejected) here, at statement level.
            _guard_orm_bulk_insert(orm_execute_state, tenant)
            return

        if orm_execute_state.is_update or orm_execute_state.is_delete:
            # ``with_loader_criteria`` is a SELECT loader option. It does not
            # constrain ORM UPDATE or DELETE statements — including
            # ``session.execute(update(Model.__table__))`` shaped statements
            # that reference ORM attributes. Pure-Core DML never reaches this
            # branch (rejected above), and every statement that does still
            # exposes its mapper, so add an exact-tenant predicate here.
            # Platform NULL rows are intentionally readable but are never
            # writable from a tenant scope.
            mappers = list(getattr(orm_execute_state, "all_mappers", ()) or ())
            if len(mappers) != 1:
                return
            mapper = mappers[0]
            model = mapper.class_
            if not issubclass(model, TenantScoped):
                return
            # A Core-constructed subquery in the WHERE clause would read
            # cross-tenant data even though the write itself stays in-tenant
            # (a boolean oracle over other tenants' rows). Fail closed too.
            _reject_unfiltered_core_references(
                orm_execute_state.statement, {mapper.local_table.name}
            )
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
