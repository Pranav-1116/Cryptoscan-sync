"""Estate schedules table (spec 93 §18).

Revision 0108. Creates ``estate_schedules`` and ``estate_schedule_runs``. Both
carry the standard ``id/created_at/updated_at/tenant_id`` shape and are indexed on
the two columns the tick queries: ``next_run_at`` and ``schedule_id``.
"""
from alembic import op
import sqlalchemy as sa

revision = "0108"
down_revision = "0107"
branch_labels = depends_on = None


def base():
    return [sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("tenant_id", sa.String(36))]


def upgrade():
    op.create_table(
        "estate_schedules", *base(),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("scope", sa.String(80), nullable=False, server_default="production"),
        sa.Column("estate", sa.String(120), nullable=False, server_default="default"),
        sa.Column("planes", sa.String(600)),
        sa.Column("interval_minutes", sa.Integer),
        sa.Column("cron", sa.String(120)),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True)),
        sa.Column("last_run_id", sa.String(36)),
        sa.Column("last_verdict", sa.String(40)),
        sa.Column("last_coverage_state", sa.String(20)),
        sa.Column("consecutive_failures", sa.Integer, nullable=False, server_default="0"),
        sa.Column("claimed_by", sa.String(120)),
        sa.Column("claimed_until", sa.DateTime(timezone=True)),
        sa.Column("created_by", sa.String(100)),
        sa.UniqueConstraint("tenant_id", "name", name="uq_estate_schedule_tenant_name"),
    )
    op.create_index("ix_estate_schedules_next_run_at", "estate_schedules", ["next_run_at"])
    op.create_index("ix_estate_schedules_name", "estate_schedules", ["name"])

    op.create_table(
        "estate_schedule_runs", *base(),
        sa.Column("schedule_id", sa.String(36),
                  sa.ForeignKey("estate_schedules.id", ondelete="CASCADE"), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("estate_run_id", sa.String(36)),
        sa.Column("verdict", sa.String(40)),
        sa.Column("coverage_state", sa.String(20)),
        sa.Column("detail", sa.String(800)),
        sa.Column("worker", sa.String(120)),
    )
    op.create_index("ix_estate_schedule_runs_schedule_id", "estate_schedule_runs", ["schedule_id"])


def downgrade():
    op.drop_index("ix_estate_schedule_runs_schedule_id", table_name="estate_schedule_runs")
    op.drop_table("estate_schedule_runs")
    op.drop_index("ix_estate_schedules_name", table_name="estate_schedules")
    op.drop_index("ix_estate_schedules_next_run_at", table_name="estate_schedules")
    op.drop_table("estate_schedules")
