"""Payment cryptography inventory: HSM keys, ceremonies, audit events, findings.

Revision ID: 0030
Revises: 0029
Create Date: 2026-08-30
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers
revision = "0030"
down_revision = "0029"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "payment_keys",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("key_id", sa.String(100), nullable=False, unique=True),
        sa.Column("name", sa.String(200), nullable=True),
        sa.Column("hsm_device", sa.String(100), nullable=True, index=True),
        sa.Column("key_usage", sa.String(50), nullable=True, index=True),
        sa.Column("algorithm", sa.String(50), nullable=True),
        sa.Column("key_size", sa.Integer(), nullable=True),
        sa.Column("state", sa.String(20), nullable=False, server_default="ACTIVE", index=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("key_block_version", sa.String(10), nullable=True),
        sa.Column("key_block_error", sa.Text(), nullable=True),
        sa.Column("activation_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expiry_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("custodian_count", sa.Integer(), nullable=True),
        sa.Column("source", sa.String(30), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=True),
    )
    op.create_table(
        "key_ceremonies",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("ceremony_id", sa.String(100), nullable=False, unique=True),
        sa.Column("key_id", sa.String(100), nullable=True, index=True),
        sa.Column("held_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("custodians", sa.JSON(), nullable=True),
        sa.Column("m_of_n", sa.String(20), nullable=True),
        sa.Column("dual_control", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("location", sa.String(200), nullable=True),
        sa.Column("documented", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=True),
    )
    op.create_table(
        "hsm_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column("device", sa.String(100), nullable=False, index=True),
        sa.Column("event_type", sa.String(40), nullable=False, index=True),
        sa.Column("key_id", sa.String(100), nullable=True, index=True),
        sa.Column("actor", sa.String(100), nullable=True),
        sa.Column("severity", sa.String(20), nullable=False, server_default="INFO"),
        sa.Column("detail", sa.JSON(), nullable=True),
        sa.Column("raw", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=True),
    )
    op.create_table(
        "payment_policy_findings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("rule_id", sa.String(20), nullable=False, index=True),
        sa.Column("key_id", sa.String(100), nullable=True, index=True),
        sa.Column("severity", sa.Integer(), nullable=False),
        sa.Column("blocking", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="OPEN", index=True),
        sa.Column("resolved_by", sa.String(100), nullable=True),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("payment_policy_findings")
    op.drop_table("hsm_events")
    op.drop_table("key_ceremonies")
    op.drop_table("payment_keys")
