"""Measured operator pagination indexes; no data/status/approval rewrites."""
from alembic import op

revision = "0104"
down_revision = "0103"
branch_labels = depends_on = None


def upgrade():
    for table in ("scan_jobs", "remediation_tasks"):
        op.create_index(f"ix_{table}_estate_page", table, ["tenant_id", "created_at", "id"])


def downgrade():
    for table in ("remediation_tasks", "scan_jobs"):
        op.drop_index(f"ix_{table}_estate_page", table_name=table)
