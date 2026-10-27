"""Durable API-key quota windows (§4.8, round 59).

Shared, durable 60s quota counters so every API replica enforces the
SAME window (the process-local counter multiplied the limit by the
replica count). One row per (key_id, window_start), unique together —
the atomic upsert's conflict target; incremented from the API layer.
No data to backfill — windows begin at the first counted request.
"""

from alembic import op
import sqlalchemy as sa

revision = "0093"
down_revision = "0092"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "api_key_quota_windows",
        sa.Column("key_id", sa.String(36), nullable=False),
        sa.Column("window_start", sa.Float(), nullable=False),
        sa.Column("hit_count", sa.Integer(), nullable=False),
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("tenant_id", sa.String(36), nullable=True),
        sa.UniqueConstraint("key_id", "window_start", name="uq_api_key_quota_window"),
    )
    op.create_index("ix_api_key_quota_windows_key_id",
                    "api_key_quota_windows", ["key_id"])
    op.create_index("ix_api_key_quota_windows_tenant_id",
                    "api_key_quota_windows", ["tenant_id"])


def downgrade() -> None:
    op.drop_index("ix_api_key_quota_windows_tenant_id",
                  table_name="api_key_quota_windows")
    op.drop_index("ix_api_key_quota_windows_key_id",
                  table_name="api_key_quota_windows")
    op.drop_table("api_key_quota_windows")
