"""Evidence Chain Enhanced — SHA-256 chain hash, HMAC manifest, WORM 7y.

Revision ID: 0063
Revises: 0062
"""

import sqlalchemy as sa
from alembic import op

revision = "0063"
down_revision = "0062"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "evidence_chains_enhanced",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("tenant_id", sa.String(100), nullable=False, server_default="default"),
        sa.Column("genesis", sa.String(64), nullable=False, server_default="0"*64),
        sa.Column("chain_head", sa.String(64), nullable=False),
        sa.Column("record_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("worm_stored", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("worm_path", sa.String(500), nullable=True),
        sa.Column("created_by", sa.String(100), nullable=True),
    )
    op.create_table(
        "evidence_records_enhanced",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("chain_id", sa.String(36), sa.ForeignKey("evidence_chains_enhanced.id", ondelete="CASCADE"), nullable=False),
        sa.Column("event_type", sa.String(100), nullable=False),
        sa.Column("actor", sa.String(100), nullable=True),
        sa.Column("system_id", sa.String(100), nullable=True),
        sa.Column("payload", sa.JSON(), nullable=True),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("chain_hash", sa.String(64), nullable=False),
        sa.Column("prev_chain_hash", sa.String(64), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.String(100), nullable=True),
    )
    op.create_index("ix_evidence_records_chain_id", "evidence_records_enhanced", ["chain_id"])
    op.create_index("ix_evidence_records_position", "evidence_records_enhanced", ["position"])


def downgrade() -> None:
    op.drop_index("ix_evidence_records_position", table_name="evidence_records_enhanced")
    op.drop_index("ix_evidence_records_chain_id", table_name="evidence_records_enhanced")
    op.drop_table("evidence_records_enhanced")
    op.drop_table("evidence_chains_enhanced")
