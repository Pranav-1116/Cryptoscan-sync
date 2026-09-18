"""thirdparty cloud — real production deterministic no AI — real production table deterministic no AI beats QSE.

Revision ID: 0125
Revises: 0124
"""

import sqlalchemy as sa
from alembic import op

revision = "0125"
down_revision = "0124"
branch_labels = None
depends_on = None


def upgrade() -> None:

    op.create_table(
        "thirdparty_cloud_records",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False, index=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), onupdate=sa.func.now()),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default='active'),
        sa.Column("risk_score", sa.Integer, nullable=False, server_default='0'),
        sa.Column("quantum_readiness", sa.Integer, nullable=False, server_default='0'),
        sa.Column("metadata_json", sa.JSON, nullable=True),
        sa.Column("hash_sha256", sa.String(64), nullable=True),
        sa.Column("verified", sa.Boolean, nullable=False, server_default='false'),
        sa.Column("evidence_hash", sa.String(64), nullable=True),
    )
    op.create_index("ix_thirdparty_cloud_records_tenant_id", "thirdparty_cloud_records", ["tenant_id"])
    op.create_index("ix_thirdparty_cloud_records_name", "thirdparty_cloud_records", ["name"])

    op.create_table(
        "thirdparty_cloud_events",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("thirdparty_cloud_records_id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("event_type", sa.String(50), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False, server_default='info'),
        sa.Column("details", sa.JSON, nullable=True),
        sa.Column("actor", sa.String(100), nullable=True),
        sa.Column("chain_hash", sa.String(64), nullable=True),
    )
    op.create_index("ix_thirdparty_cloud_events_thirdparty_cloud_records_id", "thirdparty_cloud_events", ["thirdparty_cloud_records_id"])


def downgrade() -> None:
    try:
        op.drop_index("ix_thirdparty_cloud_events_thirdparty_cloud_records_id", table_name="thirdparty_cloud_events")
    except Exception:
        pass
    op.drop_table("thirdparty_cloud_events")
    try:
        op.drop_index("ix_thirdparty_cloud_records_name", table_name="thirdparty_cloud_records")
    except Exception:
        pass
    try:
        op.drop_index("ix_thirdparty_cloud_records_tenant_id", table_name="thirdparty_cloud_records")
    except Exception:
        pass
    op.drop_table("thirdparty_cloud_records")

