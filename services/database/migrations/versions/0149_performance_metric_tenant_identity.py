"""Make Performance metric identity tenant-local, including platform rows.

Revision ID: 0149
Revises: 0148

Exporter names and timestamps can recur in two banks. The old globally unique
metric_id let one tenant block the other's measurement. NULL platform rows need
their own unique partial index because SQL UNIQUE treats NULL as distinct.
"""

import sqlalchemy as sa
from alembic import op

revision = "0149"
down_revision = "0148"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_index("ix_performance_metrics_metric_id", table_name="performance_metrics")
    op.create_index("ix_performance_metrics_metric_id", "performance_metrics",
                    ["metric_id"])
    op.create_index("uq_performance_metrics_tenant_metric_id", "performance_metrics",
                    ["tenant_id", "metric_id"], unique=True)
    op.create_index("uq_performance_metrics_platform_metric_id", "performance_metrics",
                    ["metric_id"], unique=True,
                    postgresql_where=sa.text("tenant_id IS NULL"),
                    sqlite_where=sa.text("tenant_id IS NULL"))


def downgrade() -> None:
    # A global index cannot be restored while two tenants legitimately have
    # the same metric ID. Refuse the downgrade instead of deleting a bank row.
    duplicate = op.get_bind().execute(sa.text(
        "SELECT metric_id FROM performance_metrics GROUP BY metric_id "
        "HAVING count(*) > 1 LIMIT 1")).first()
    if duplicate:
        raise RuntimeError("downgrade blocked: tenant-local metric IDs would collide globally")
    op.drop_index("uq_performance_metrics_platform_metric_id",
                  table_name="performance_metrics")
    op.drop_index("uq_performance_metrics_tenant_metric_id",
                  table_name="performance_metrics")
    op.drop_index("ix_performance_metrics_metric_id", table_name="performance_metrics")
    op.create_index("ix_performance_metrics_metric_id", "performance_metrics",
                    ["metric_id"], unique=True)
