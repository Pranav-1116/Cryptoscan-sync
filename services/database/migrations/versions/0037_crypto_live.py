"""Live crypto scanner persistence (§34/§35 of the Universal Crypto Scanner).

crypto_live_states — current truth of the live crypto environment (state +
versioned CycloneDX CBOM + risk);
crypto_live_events — immutable event journal (timeline + point-in-time
reconstruction). No key material is ever stored — metadata and CBOM only.

Revision ID: 0037
Revises: 0036
Create Date: 2026-08-31
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers
revision = "0037"
down_revision = "0036"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "crypto_live_states",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("asset_id", sa.String(200), nullable=False, unique=True, index=True),
        sa.Column("cbom_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("algorithms", sa.JSON(), nullable=True),
        sa.Column("quantum_status", sa.JSON(), nullable=True),
        sa.Column("capabilities", sa.JSON(), nullable=True),
        sa.Column("usage", sa.JSON(), nullable=True),
        sa.Column("protocols", sa.JSON(), nullable=True),
        sa.Column("certificates", sa.JSON(), nullable=True),
        sa.Column("libraries", sa.JSON(), nullable=True),
        sa.Column("readiness", sa.String(40), nullable=True),
        sa.Column("agility", sa.Integer(), nullable=True),
        sa.Column("risk_score", sa.Integer(), nullable=True),
        sa.Column("risk_level", sa.String(20), nullable=True),
        sa.Column("cbom", sa.JSON(), nullable=True),
        sa.Column("last_event", sa.String(50), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        "crypto_live_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("event_type", sa.String(60), nullable=False, index=True),
        sa.Column("asset_id", sa.String(200), nullable=False, index=True),
        sa.Column("source", sa.String(50), nullable=False, server_default="live"),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column("cbom_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("risk_score", sa.Integer(), nullable=True),
        sa.Column("payload", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_crypto_live_events_asset_at", "crypto_live_events",
                    ["asset_id", "observed_at"])


def downgrade() -> None:
    op.drop_table("crypto_live_events")
    op.drop_table("crypto_live_states")
