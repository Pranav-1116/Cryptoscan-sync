"""Make platform-estate schedule names unique even when tenant_id is NULL.

The existing unique constraint on (tenant_id, name) permits duplicate NULL
owners in PostgreSQL. Concurrent platform operators could create two active
schedules with the same name and execute both. Existing duplicates are not
silently removed: the migration refuses until an operator reconciles them.
"""
from alembic import op
import sqlalchemy as sa

revision = "0119"
down_revision = "0118"
branch_labels = depends_on = None


def upgrade():
    op.create_index(
        "uq_estate_schedule_platform_name", "estate_schedules", ["name"],
        unique=True, postgresql_where=sa.text("tenant_id IS NULL"),
        sqlite_where=sa.text("tenant_id IS NULL"),
    )


def downgrade():
    op.drop_index("uq_estate_schedule_platform_name", table_name="estate_schedules")
