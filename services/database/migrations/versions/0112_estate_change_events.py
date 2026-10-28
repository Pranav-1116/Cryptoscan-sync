"""Detected estate changes (spec 94 §17–§18).

Revision 0112. Creates ``estate_change_events``: one immutable record per detected
transition between two observations, with the claims, the severity consequence and
the projection ids the claims were derived from. Identical observations are not
stored — the run itself is the record that someone looked.
"""
from alembic import op
import sqlalchemy as sa

revision = "0112"
down_revision = "0111"
branch_labels = depends_on = None


def upgrade():
    op.create_table(
        "estate_change_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.String(36)),
        sa.Column("event_id", sa.String(80), nullable=False),
        sa.Column("verdict", sa.String(40), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("changed", sa.Boolean()),
        sa.Column("headline", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text()),
        sa.Column("next_action", sa.Text()),
        sa.Column("changes", sa.JSON()),
        sa.Column("counts", sa.JSON()),
        sa.Column("baseline_projection_id", sa.String(64)),
        sa.Column("current_projection_id", sa.String(64)),
        sa.Column("run_id", sa.String(64)),
        sa.Column("trigger", sa.String(40), nullable=False, server_default="manual"),
        sa.Column("detected_by", sa.String(160)),
        sa.Column("observations", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("first_detected_at", sa.DateTime(timezone=True)),
        sa.Column("last_detected_at", sa.DateTime(timezone=True)),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True)),
        sa.Column("acknowledged_by", sa.String(160)),
        sa.Column("acknowledgement_note", sa.Text()),
    )
    op.create_index("ix_estate_change_events_tenant_id", "estate_change_events", ["tenant_id"])
    op.create_index("ix_estate_change_events_event_id", "estate_change_events", ["event_id"])
    op.create_index("ix_estate_change_events_severity", "estate_change_events", ["severity"])
    op.create_index(
        "ix_estate_change_events_current_projection_id",
        "estate_change_events",
        ["current_projection_id"],
    )
    op.create_index(
        "ix_estate_change_events_tenant_event",
        "estate_change_events",
        ["tenant_id", "event_id"],
        unique=True,
    )
    op.create_index(
        "ix_estate_change_events_severity_created",
        "estate_change_events",
        ["severity", "created_at"],
    )


def downgrade():
    for name in (
        "ix_estate_change_events_severity_created",
        "ix_estate_change_events_tenant_event",
        "ix_estate_change_events_current_projection_id",
        "ix_estate_change_events_severity",
        "ix_estate_change_events_event_id",
        "ix_estate_change_events_tenant_id",
    ):
        op.drop_index(name, table_name="estate_change_events")
    op.drop_table("estate_change_events")
