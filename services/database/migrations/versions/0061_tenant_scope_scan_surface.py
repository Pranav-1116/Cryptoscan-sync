"""Add tenant_id to the scan surface so tenant isolation can be enforced.

Tenancy was introduced with tenant_id on five control-plane tables (tenants,
memberships, api_keys, monitors, control_plane) and the isolation was described
in db/models/tenant.py as "enforced at the data layer". It was not, for the
tables that hold a customer's actual results: scans, evidence_records,
crypto_assets, systems, drift_events, scan_jobs, container_scans, certificates,
network_scan_runs and baselines carried no tenant column, and their
repositories applied no filter — ``ScanRepository.list_scans`` took no tenant
argument at all. Any authenticated member of any tenant could read every
tenant's findings.

This adds the column. The filter itself is applied by the ORM
(``db.tenancy.install_tenant_guard``) rather than per repository, so a query
written later cannot omit it.

NULL is meaningful and is the default: it marks the platform estate — rows that
predate tenancy, and every row in a single-tenant or on-prem install. The guard
lets a tenant see its own rows plus NULL rows, so enabling tenancy on an
existing deployment does not make its history disappear. Backfilling NULL to
some tenant is deliberately *not* done here: which tenant owns pre-existing
data is a deployment question, not a schema one.

The column is nullable and indexed, so this is an online-safe add on
PostgreSQL (no table rewrite, no default backfill).
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


import sqlalchemy as sa
from alembic import op

revision = "0061"
down_revision = "0060"
branch_labels = None
depends_on = None

#: Tables that hold tenant-owned scan results.
TENANT_SCOPED_TABLES: tuple[str, ...] = (
    "scans",
    "evidence_records",
    "crypto_assets",
    "systems",
    "drift_events",
    "scan_jobs",
    "container_scans",
    "certificates",
    "network_scan_runs",
    "baselines",
)


def _existing_tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def _columns(table: str) -> set[str]:
    return {c["name"] for c in sa.inspect(op.get_bind()).get_columns(table)}


def upgrade() -> None:
    present = _existing_tables()
    for table in TENANT_SCOPED_TABLES:
        if table not in present:
            continue  # table belongs to a service not deployed here
        if "tenant_id" in _columns(table):
            continue
        op.add_column(table, sa.Column("tenant_id", sa.String(length=36), nullable=True))
        op.create_index(f"ix_{table}_tenant_id", table, ["tenant_id"])


def downgrade() -> None:
    present = _existing_tables()
    for table in reversed(TENANT_SCOPED_TABLES):
        if table not in present or "tenant_id" not in _columns(table):
            continue
        try:
            op.drop_index(f"ix_{table}_tenant_id", table_name=table)
        except Exception as _handler_exc:  # index name differs on an older install
            logger.warning(
                "exception_suppressed",
                extra={"error_type": type(_handler_exc).__name__},
            )
            pass
        op.drop_column(table, "tenant_id")
