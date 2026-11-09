"""Row-level security: make the database enforce the tenant boundary too.

Revision 0132. Enables and *forces* row-level security on every table that
carries a ``tenant_id``, with one policy keyed on a session setting.

Guide 126 graded multi-tenant isolation **6 pass · 1 partial** and said plainly
why the partial existed: the isolation is logical. One store, one schema, one
scope applied by the ORM, and a reader who gets the file (or a connection) reads
every tenant's rows. The ORM guard refuses a request; it cannot refuse a psql
prompt, a BI tool, or a service that forgot to import the guard.

What this migration adds is the second lock:

* ``cryptoscan.tenant_id`` is the session setting. ``db.rls`` sets it per
  transaction from the same scope the ORM guard uses.
* The policy is ``tenant_id IS NULL OR tenant_id = cryptoscan_current_tenant()``:
  platform rows (``NULL``) stay visible — an on-prem install that later enables
  tenancy must not lose its history — and a tenant sees only its own rows.
* ``cryptoscan_current_tenant()`` is ``'*'`` when the platform scope is explicit,
  which is the same escape hatch ``db.tenancy.platform_scope()`` already is.
* **No setting at all yields no tenant rows.** ``current_setting(..., true)``
  returns NULL when it has never been set, every comparison is NULL, and the row
  is filtered. A connection that does not know which tenant it is serving reads
  nothing rather than everything — the failure is a blank screen, not a breach.
* ``FORCE ROW LEVEL SECURITY`` is the important half. Without it PostgreSQL
  exempts the table's *owner*, and the application connects as the owner, so the
  policy would be decoration that only bound read-only roles.
* A role may not widen its own reach: ``cryptoscan_platform`` is the only role
  with ``BYPASSRLS`` and it is not the role the application uses by default.

What this does **not** do, stated where it can be read rather than in a footnote:

* It does not encrypt anything. A stolen data file still contains every tenant's
  rows in plaintext, and a superuser (or a role granted ``BYPASSRLS``) reads
  across tenants by design. Isolation is enforced for the application role; it is
  not cryptography and must not be sold as such.
* It does not replace the ORM guard. RLS cannot see ``with_loader_criteria``, and
  the guard cannot see a raw connection; each catches what the other misses, and
  the drill (``scripts/tenant_isolation.py``) measures both.
* On SQLite this migration is a no-op — SQLite has no RLS — so a development
  store keeps the logical-only behaviour and the artifact says so.

Revision ID: 0132
Revises: 0131
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0132"
down_revision = "0131"
branch_labels = None
depends_on = None

#: The session setting the policy reads. Also read by ``db.rls``.
SETTING = "cryptoscan.tenant_id"

#: Roles. The application role keeps its own name; these two exist so a
#: deployment can separate "serves one tenant" from "administers all of them".
TENANT_ROLE = "cryptoscan_tenant"
PLATFORM_ROLE = "cryptoscan_platform"

POLICY = "tenant_isolation"


def _tenant_tables(connection) -> list[str]:
    """Every table carrying a ``tenant_id``, read from the catalogue.

    Asking the database rather than carrying a list means a table added by a
    later migration is protected by a later migration deliberately, and a table
    in this one cannot silently fall out of the set.
    """
    rows = connection.execute(sa.text(
        "SELECT table_name FROM information_schema.columns "
        "WHERE table_schema = current_schema() AND column_name = 'tenant_id' "
        "AND table_name NOT LIKE 'pg_%' ORDER BY table_name"
    )).fetchall()
    return [row[0] for row in rows]


def upgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "postgresql":
        # SQLite has no row-level security. The ORM guard is the whole story
        # there, which is exactly what guide 126's `at_rest` row says.
        return

    op.execute(
        f"""
        CREATE OR REPLACE FUNCTION cryptoscan_current_tenant() RETURNS text
        LANGUAGE sql STABLE AS $$
            SELECT nullif(current_setting('{SETTING}', true), '')
        $$
        """
    )

    for role, bypass in ((TENANT_ROLE, False), (PLATFORM_ROLE, True)):
        op.execute(
            f"""
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN
                    CREATE ROLE {role} NOLOGIN {'BYPASSRLS' if bypass else 'NOBYPASSRLS'};
                END IF;
            END
            $$
            """
        )

    tables = _tenant_tables(connection)
    for table in tables:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        # Without FORCE the owner — which is the account the API connects as —
        # is exempt, and the policy would only bind read-only roles.
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(f"DROP POLICY IF EXISTS {POLICY} ON {table}")
        op.execute(
            f"""
            CREATE POLICY {POLICY} ON {table}
            USING (
                tenant_id IS NULL
                OR tenant_id::text = cryptoscan_current_tenant()
                OR cryptoscan_current_tenant() = '*'
            )
            WITH CHECK (
                tenant_id IS NULL
                OR tenant_id::text = cryptoscan_current_tenant()
                OR cryptoscan_current_tenant() = '*'
            )
            """
        )
        # The tenant role may read and write only through the policy.
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO {TENANT_ROLE}")
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO {PLATFORM_ROLE}")


def downgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "postgresql":
        return
    for table in _tenant_tables(connection):
        # Later revisions split read/write policies. A downgrade past 0132
        # must remove all of them before dropping the function they reference;
        # DROP FUNCTION CASCADE would silently remove unrelated dependencies.
        for policy in (POLICY, "tenant_isolation_select",
                       "tenant_isolation_insert", "tenant_isolation_update",
                       "tenant_isolation_delete"):
            op.execute(f"DROP POLICY IF EXISTS {policy} ON {table}")
        op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
        op.execute(f"REVOKE SELECT, INSERT, UPDATE, DELETE ON {table} "
                   f"FROM {TENANT_ROLE}, {PLATFORM_ROLE}")
    op.execute("DROP FUNCTION IF EXISTS cryptoscan_current_tenant()")
    # The roles are dropped last and only if nothing else owns them: a deployment
    # that pointed its application at `cryptoscan_tenant` must move it first.
    for role in (TENANT_ROLE, PLATFORM_ROLE):
        op.execute(f"DROP ROLE IF EXISTS {role}")
