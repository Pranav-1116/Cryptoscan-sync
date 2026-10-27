"""Outbound webhook delivery audit (SIEM/ITSM/SOAR real HTTP fan-out).

Revision ID: 0045
Revises: 0044
Create Date: 2026-09-02
"""
import sqlalchemy as sa
from alembic import op

revision = "0045"
down_revision = "0044"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "cp_delivery_logs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("integration_id", sa.String(36), nullable=True, index=True),
        sa.Column("provider", sa.String(40), nullable=False, server_default="webhook"),
        sa.Column("kind", sa.String(20), nullable=False, server_default="siem", index=True),
        sa.Column("event_type", sa.String(120), nullable=False, index=True),
        sa.Column("event_id", sa.String(36), nullable=True, index=True),
        sa.Column("endpoint", sa.Text(), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="skipped", index=True),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("http_status", sa.Integer(), nullable=True),
        sa.Column("response_excerpt", sa.Text(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("signature_prefix", sa.String(24), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("cp_delivery_logs")
