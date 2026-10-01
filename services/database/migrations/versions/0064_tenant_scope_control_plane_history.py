"""Scope durable control-plane history by tenant.

The original control-plane migration created the event outbox, delivery audit
log, and security-posture history before SaaS tenancy was enabled.  Those rows
are customer-owned when produced from a tenant request, so they need the same
nullable ``tenant_id`` convention as the rest of the scan surface.  Existing
rows remain platform-estate rows until an operator performs an explicit,
customer-verified backfill; this migration never guesses ownership.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0064"
down_revision = "0063"
branch_labels = None
depends_on = None

TABLES = ("cp_queued_events", "cp_security_posture", "cp_delivery_logs")


def _existing_tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def _columns(table: str) -> set[str]:
    return {column["name"] for column in sa.inspect(op.get_bind()).get_columns(table)}


def upgrade() -> None:
    present = _existing_tables()
    for table in TABLES:
        if table not in present or "tenant_id" in _columns(table):
            continue
        op.add_column(table, sa.Column("tenant_id", sa.String(length=36), nullable=True))
        op.create_index(f"ix_{table}_tenant_id", table, ["tenant_id"])


def downgrade() -> None:
    present = _existing_tables()
    for table in reversed(TABLES):
        if table not in present or "tenant_id" not in _columns(table):
            continue
        op.drop_index(f"ix_{table}_tenant_id", table_name=table)
        op.drop_column(table, "tenant_id")
