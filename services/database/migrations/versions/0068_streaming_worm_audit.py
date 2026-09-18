"""Streaming WORM audit — S3 WORM 7y, audit-log topic, chain hash.

Revision ID: 0068
Revises: 0067
"""

import sqlalchemy as sa
from alembic import op

revision = "0068"
down_revision = "0067"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "streaming_worm_audit",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("topic", sa.String(100), nullable=False),
        sa.Column("partition", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("offset", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("event_type", sa.String(100), nullable=False),
        sa.Column("system_id", sa.String(100), nullable=True),
        sa.Column("payload_hash", sa.String(64), nullable=True),
        sa.Column("chain_hash", sa.String(64), nullable=True),
        sa.Column("prev_chain_hash", sa.String(64), nullable=True),
        sa.Column("worm_path", sa.String(500), nullable=True),
        sa.Column("retention_until", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_streaming_worm_topic", "streaming_worm_audit", ["topic"])
    op.create_index("ix_streaming_worm_system_id", "streaming_worm_audit", ["system_id"])


def downgrade() -> None:
    op.drop_index("ix_streaming_worm_system_id", table_name="streaming_worm_audit")
    op.drop_index("ix_streaming_worm_topic", table_name="streaming_worm_audit")
    op.drop_table("streaming_worm_audit")
