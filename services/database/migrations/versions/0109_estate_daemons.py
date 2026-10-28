"""Estate daemon heartbeat table (spec 93 §18).

Revision 0109. Creates ``estate_daemons``: one row per daemon identity, upserted
every cycle. Indexed on ``last_cycle_at`` because that is the only column the
liveness probe reads, and on ``worker`` because that is the upsert key.
"""
from alembic import op
import sqlalchemy as sa

revision = "0109"
down_revision = "0108"
branch_labels = depends_on = None


def base():
    return [sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("tenant_id", sa.String(36))]


def upgrade():
    op.create_table(
        "estate_daemons", *base(),
        sa.Column("worker", sa.String(120), nullable=False, unique=True),
        sa.Column("state", sa.String(20), nullable=False, server_default="RUNNING"),
        sa.Column("version", sa.String(40)),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("last_cycle_at", sa.DateTime(timezone=True)),
        sa.Column("last_cycle_seconds", sa.Float()),
        sa.Column("cycles", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("runs", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("failures", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_error", sa.Text()),
        sa.Column("next_wake_at", sa.DateTime(timezone=True)),
        sa.Column("idle_reason", sa.Text()),
        sa.Column("pid", sa.Integer()),
    )
    op.create_index("ix_estate_daemons_worker", "estate_daemons", ["worker"])
    op.create_index("ix_estate_daemons_last_cycle_at", "estate_daemons", ["last_cycle_at"])


def downgrade():
    op.drop_index("ix_estate_daemons_last_cycle_at", table_name="estate_daemons")
    op.drop_index("ix_estate_daemons_worker", table_name="estate_daemons")
    op.drop_table("estate_daemons")
