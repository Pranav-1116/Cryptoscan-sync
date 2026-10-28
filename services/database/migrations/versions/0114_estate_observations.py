"""Evidence records and per-fact observation history (spec 94 §11, §19, §28).

Revision 0114. Creates ``estate_evidence`` and ``estate_observations``.

The catalogue (0113) remembers *assets*. It cannot answer "what was this asset's
algorithm on Tuesday", because a changed attribute used to be an overwritten column,
and it cannot answer "which record, from which collector, at what confidence" without
re-reading the discovery payload the evidence came in. These two tables are that
memory:

* ``estate_evidence`` — one row per content-addressed evidence record; seen again, the
  row's ``observation_count`` advances rather than a duplicate appearing;
* ``estate_observations`` — one row per ``(asset, fact_type, value)`` with the window in
  which the value was true. A value that changes retires the old row to ``HISTORICAL``
  and adds a new one; a value that returns is revived. Nothing is deleted, and two
  values still asserted are two ``CURRENT`` rows — a reported conflict, not a choice.
"""
from alembic import op
import sqlalchemy as sa

revision = "0114"
down_revision = "0113"
branch_labels = depends_on = None


def _audit_columns():
    return [
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.String(36)),
    ]


def upgrade():
    op.create_table(
        "estate_evidence",
        *_audit_columns(),
        sa.Column("evidence_id", sa.String(80), nullable=False),
        sa.Column("schema_version", sa.String(80)),
        sa.Column("source", sa.String(400)),
        sa.Column("collector", sa.String(400)),
        sa.Column("evidence_type", sa.String(40), nullable=False),
        sa.Column("confidence", sa.String(20)),
        sa.Column("target_id", sa.String(120), nullable=False),
        sa.Column("layer", sa.String(40)),
        sa.Column("facts", sa.JSON()),
        sa.Column("observed_at", sa.String(64)),
        sa.Column("first_seen_at", sa.DateTime(timezone=True)),
        sa.Column("last_seen_at", sa.DateTime(timezone=True)),
        sa.Column("observation_count", sa.Integer(), nullable=False, server_default="1"),
    )
    op.create_index("ix_estate_evidence_tenant_evidence", "estate_evidence", ["tenant_id", "evidence_id"], unique=True)
    op.create_index("ix_estate_evidence_evidence_id", "estate_evidence", ["evidence_id"])
    op.create_index("ix_estate_evidence_target", "estate_evidence", ["target_id"])
    op.create_index("ix_estate_evidence_collector", "estate_evidence", ["collector"])
    op.create_index("ix_estate_evidence_type", "estate_evidence", ["evidence_type"])
    op.create_index("ix_estate_evidence_layer", "estate_evidence", ["layer"])
    op.create_index("ix_estate_evidence_tenant_id", "estate_evidence", ["tenant_id"])

    op.create_table(
        "estate_observations",
        *_audit_columns(),
        sa.Column("observation_id", sa.String(80), nullable=False),
        sa.Column("asset_id", sa.String(120), nullable=False),
        sa.Column("fact_type", sa.String(120), nullable=False),
        sa.Column("value", sa.Text()),
        sa.Column("value_kind", sa.String(40)),
        sa.Column("evidence_id", sa.String(80)),
        sa.Column("evidence_type", sa.String(40)),
        sa.Column("layer", sa.String(40)),
        sa.Column("lifecycle_state", sa.String(20), nullable=False, server_default="CURRENT"),
        sa.Column("first_seen_at", sa.DateTime(timezone=True)),
        sa.Column("last_seen_at", sa.DateTime(timezone=True)),
        sa.Column("observation_count", sa.Integer(), nullable=False, server_default="1"),
    )
    op.create_index("ix_estate_observations_tenant_obs", "estate_observations", ["tenant_id", "observation_id"], unique=True)
    op.create_index("ix_estate_observations_observation_id", "estate_observations", ["observation_id"])
    op.create_index("ix_estate_observations_asset_id", "estate_observations", ["asset_id"])
    op.create_index("ix_estate_observations_fact_type", "estate_observations", ["fact_type"])
    op.create_index("ix_estate_observations_asset_fact", "estate_observations", ["asset_id", "fact_type"])
    op.create_index("ix_estate_observations_lifecycle", "estate_observations", ["lifecycle_state"])
    op.create_index("ix_estate_observations_evidence", "estate_observations", ["evidence_id"])
    op.create_index("ix_estate_observations_tenant_id", "estate_observations", ["tenant_id"])


def downgrade():
    op.drop_table("estate_observations")
    op.drop_table("estate_evidence")
