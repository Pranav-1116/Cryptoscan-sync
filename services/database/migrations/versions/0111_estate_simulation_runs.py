"""Quarantined Digital Twin simulation runs (spec 94 §17, §19).

Revision 0111. Creates ``estate_simulation_runs``.

The table stores answers to "what if", never estate facts, and carries
``quarantined``/``is_estate_state`` as columns so a row cannot be promoted to
estate state by a careless join: the flags travel with the data.
"""
from alembic import op
import sqlalchemy as sa

revision = "0111"
down_revision = "0110"
branch_labels = depends_on = None


def upgrade():
    op.create_table(
        "estate_simulation_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.String(36)),
        sa.Column("simulation_id", sa.String(96), nullable=False),
        sa.Column("kind", sa.String(40), nullable=False),
        sa.Column("scenario", sa.JSON()),
        sa.Column("base_snapshot_id", sa.String(96)),
        sa.Column("base_projection_id", sa.String(64)),
        sa.Column("simulated_projection_id", sa.String(64)),
        sa.Column("matched_evidence", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("affected_assets", sa.JSON()),
        sa.Column("impact", sa.JSON()),
        sa.Column("bom_diff", sa.JSON()),
        sa.Column("blockers", sa.JSON()),
        sa.Column("live_state_modified", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("quarantined", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("is_estate_state", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("observations", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("first_run_at", sa.DateTime(timezone=True)),
        sa.Column("last_run_at", sa.DateTime(timezone=True)),
        sa.Column("created_by", sa.String(160)),
        sa.Column("label", sa.Text()),
    )
    op.create_index("ix_estate_simulation_runs_tenant_id", "estate_simulation_runs", ["tenant_id"])
    op.create_index("ix_estate_simulation_runs_simulation_id", "estate_simulation_runs", ["simulation_id"])
    op.create_index(
        "ix_estate_simulation_runs_tenant_sim",
        "estate_simulation_runs",
        ["tenant_id", "simulation_id"],
        unique=True,
    )
    op.create_index(
        "ix_estate_simulation_runs_base_projection",
        "estate_simulation_runs",
        ["base_projection_id"],
    )


def downgrade():
    op.drop_index("ix_estate_simulation_runs_base_projection", table_name="estate_simulation_runs")
    op.drop_index("ix_estate_simulation_runs_tenant_sim", table_name="estate_simulation_runs")
    op.drop_index("ix_estate_simulation_runs_simulation_id", table_name="estate_simulation_runs")
    op.drop_index("ix_estate_simulation_runs_tenant_id", table_name="estate_simulation_runs")
    op.drop_table("estate_simulation_runs")
