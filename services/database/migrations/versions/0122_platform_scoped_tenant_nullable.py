"""Let the platform estate name itself NULL, as the ORM already says.

Revision 0122. Alters ``algorithm_advisories.tenant_id``, ``hbom_snapshots.tenant_id``
and four more columns the models declare nullable but the migrations created
``NOT NULL``.

``TenantScoped``'s contract is explicit: a NULL ``tenant_id`` means "platform
estate" — rows discovered or generated once for the whole install (a threat
advisory synced from a feed, an estate HBOM rendered for the operator, the network
inventory of a single-tenant bank) rather than for one tenant. The migrations
created those columns ``NOT NULL`` anyway, so on a real PostgreSQL the ORM built
an INSERT the database rejected:

* ``POST /api/v1/hbom/snapshot`` returned 500 for every estate-wide pin,
  because no tenant scope is active outside a tenancy request;
* the advisory feed could not persist an advisory at platform scope;
* the network topology, resource-grant and custom-role writers — the same code
  path for a bank with tenancy and for an on-prem install without it — could not
  write a row at all without a tenant.

``create_all`` deployments were unaffected, which is why every test passed. The
nullability parity check in ``scripts/tests/test_database_contract.py`` now
compares this for every mapped column and every mapped table.

The tenant-plane tables that were also ``NOT NULL`` behind a nullable model
(memberships, invites, metering and lifecycle events) are fixed the other way:
their models now inherit ``TenantOwned``, because a row of those tables cannot
mean anything without an owner. Nothing is loosened for them.

Known limitation, stated rather than hidden: on the platform estate a NULL
``tenant_id`` is not equal to itself in SQL, so the per-tenant unique constraints
on those tables (``uq_resource_grant``, ``uq_custom_role_per_tenant``,
``uq_topology_node_name``) do not deduplicate platform-scoped rows. The writers
upsert explicitly, so duplicates are not produced today; a partial unique index
on the NULL case is the durable fix and is not part of this migration.

Revision ID: 0122
Revises: 0121
"""
from __future__ import annotations

from alembic import op

revision = "0122"
down_revision = "0121"
branch_labels = None
depends_on = None

#: (table, column) pairs. Each model says nullable, the migration said NOT NULL.
_RELAXED = (
    # estate-wide documents and feed rows: no tenant scope is active for them
    ("algorithm_advisories", "tenant_id"),
    ("hbom_snapshots", "tenant_id"),
    # a connector without an agent link, and a drift event recorded outside a
    # baseline (a first observation), are both real rows
    ("connectors", "agent_link"),
    ("drift_events", "baseline_id"),
    ("drift_events", "drift_details"),
    # written by the platform-scope collectors and by single-tenant installs that
    # have no tenant id at all
    ("topology_nodes", "tenant_id"),
    ("topology_edges", "tenant_id"),
    ("resource_grants", "tenant_id"),
    ("custom_roles", "tenant_id"),
)


def upgrade() -> None:
    for table, column in _RELAXED:
        op.alter_column(table, column, existing_type=None, nullable=True)


def downgrade() -> None:
    for table, column in _RELAXED:
        op.execute(f"DELETE FROM {table} WHERE {column} IS NULL")
        op.alter_column(table, column, existing_type=None, nullable=False)
