"""Row-level security: bind the session setting the database's policy reads.

Migration 0132 puts a policy on every tenant-scoped table. A policy alone changes
nothing — PostgreSQL evaluates it against ``cryptoscan.tenant_id``, and if nobody
sets that the policy filters *everything* out. This module is the other half:

* :func:`install_rls_binder` registers a Session ``after_begin`` hook. When the
  connection is PostgreSQL and a tenant scope is active, the transaction starts
  with ``set_config('cryptoscan.tenant_id', <tenant>, true)`` — ``true`` is
  *local*, so the setting dies with the transaction and a pooled connection never
  carries one tenant's identity into the next tenant's request.
* Without a scope the binder writes ``'*'``, which is the same explicit,
  greppable platform mode :func:`db.tenancy.platform_scope` already means, and
  what a single-tenant on-prem install runs as.
* On SQLite, and on any engine where the policy does not exist, the hook returns
  immediately: the ORM guard is still the whole story there, and this module
  never pretends otherwise.

:func:`enforcement` answers the question a bank actually asks — *is the policy
binding this connection, or am I looking at a policy that exempts everyone?* It
reports the roles, whether the current role bypasses RLS, how many tenant tables
are enabled and forced, and whether the policies seen match the tables found.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from db.tenancy import current_tenant, isolation_active

#: The setting both the migration's policy and this binder use.
TENANT_SETTING = "cryptoscan.tenant_id"

#: What the policy compares against to mean "no tenant filter" — the same
#: deliberate, greppable platform mode as ``db.tenancy.platform_scope()``.
PLATFORM_WILDCARD = "*"

_installed = False


def _binding_value() -> str:
    """The value this transaction should carry.

    A tenant scope wins; otherwise the platform wildcard. Returning the wildcard
    when *no* scope is active is what keeps single-tenant installs working — the
    policy's fail-closed branch is for connections this process does not own.
    """
    tenant = current_tenant()
    if tenant:
        return str(tenant)
    return PLATFORM_WILDCARD


def install_rls_binder() -> None:
    """Bind the tenant setting at the start of every PostgreSQL transaction."""
    global _installed
    if _installed:  # pragma: no cover - idempotent by design
        return

    @event.listens_for(Session, "after_begin")
    def _bind(session: Session, _transaction: Any, connection: Any) -> None:  # noqa: ANN401
        if connection.dialect.name != "postgresql":
            return
        value = _binding_value()
        # set_config(..., true) is SET LOCAL: it cannot outlive the transaction,
        # so a pooled connection never inherits one tenant's identity.
        connection.exec_driver_sql(
            "SELECT set_config(%(setting)s, %(value)s, true)",
            {"setting": TENANT_SETTING, "value": value},
        )

    _installed = True


def bind_connection(connection: Any, tenant: str | None) -> None:
    """Set the setting on one connection, outside the ORM hook.

    Used by migrations, drills and any code holding a raw connection. ``None``
    binds the platform wildcard, matching :func:`_binding_value`.
    """
    if connection.dialect.name != "postgresql":
        return
    connection.exec_driver_sql(
        "SELECT set_config(%s, %s, true)",
        (TENANT_SETTING, str(tenant) if tenant else PLATFORM_WILDCARD),
    )


def enforcement(connection: Any) -> dict[str, Any]:
    """Is the boundary enforced by the database on this connection, or not?

    Answers with facts, not a verdict: a caller that wants a yes/no has to read
    ``binds_this_role`` and decide, because "RLS is on" and "RLS binds me" are
    different claims and only the second one is worth anything.
    """
    if connection.dialect.name != "postgresql":
        return {"supported": False, "reason": "not PostgreSQL: no row-level security",
                "binds_this_role": False}

    def one(sql: str, *params: Any) -> Any:
        return connection.exec_driver_sql(sql, params).scalar()

    role = one("SELECT current_user")
    superuser = bool(one("SELECT rolsuper FROM pg_roles WHERE rolname = current_user"))
    bypass = bool(one("SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user"))
    tenant_tables = int(one(
        "SELECT count(*) FROM information_schema.columns "
        "WHERE table_schema = current_schema() AND column_name = 'tenant_id'") or 0)
    enabled = int(one(
        "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
        "WHERE n.nspname = current_schema() AND c.relrowsecurity") or 0)
    forced = int(one(
        "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
        "WHERE n.nspname = current_schema() AND c.relforcerowsecurity") or 0)
    policies = int(one(
        "SELECT count(*) FROM pg_policies WHERE schemaname = current_schema()") or 0)
    owner_exempt_before_force = int(one(
        "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
        "WHERE n.nspname = current_schema() AND c.relrowsecurity "
        "AND NOT c.relforcerowsecurity AND c.relowner = (SELECT oid FROM pg_roles "
        "WHERE rolname = current_user)") or 0)

    return {
        "supported": True,
        "role": role,
        "superuser": superuser,
        "bypassrls": bypass,
        "tenant_tables": tenant_tables,
        "tables_with_rls_enabled": enabled,
        "tables_with_rls_forced": forced,
        "policies": policies,
        "owner_would_be_exempt_without_force": owner_exempt_before_force,
        # A superuser or a BYPASSRLS role reads across tenants by definition.
        "binds_this_role": not (superuser or bypass),
        "scope": current_tenant() if isolation_active() else PLATFORM_WILDCARD,
    }


def attach(engine: Engine) -> None:  # pragma: no cover - convenience
    """Install the binder for a configured engine (no-op on SQLite)."""
    install_rls_binder()
