"""Index the tenant column of the schedule-run table.

Revision 0121. Creates ``ix_estate_schedule_runs_tenant_id``.

``EstateScheduleRun`` mixes in ``TenantScoped``, which declares ``tenant_id``
with ``index=True``. The table was created in 0108 without that index, so a
``create_all`` deployment had it and a migrated one did not — every tenant-scoped
read of run history would scan the table. ``test_model_migration_index_parity``
caught the drift; this closes it.

Revision ID: 0121
Revises: 0120
"""
from __future__ import annotations

from alembic import op

revision = "0121"
down_revision = "0120"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index("ix_estate_schedule_runs_tenant_id", "estate_schedule_runs", ["tenant_id"])


def downgrade() -> None:
    op.drop_index("ix_estate_schedule_runs_tenant_id", table_name="estate_schedule_runs")
