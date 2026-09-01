"""24/7 Live Hardware Engine persistence (spec §3/§4/§16).

hardware_assets — current truth of the observed hardware environment;
hardware_events — immutable journal (timeline + point-in-time reconstruction);
hardware_agents — edge-agent heartbeat health.

Revision ID: 0036
Revises: 0035
Create Date: 2026-08-31
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers
revision = "0036"
down_revision = "0035"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "hardware_assets",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("asset_id", sa.String(200), nullable=False, unique=True, index=True),
        sa.Column("agent_id", sa.String(100), nullable=True, index=True),
        sa.Column("manufacturer", sa.String(200), nullable=False, server_default=""),
        sa.Column("model", sa.String(200), nullable=False, server_default=""),
        sa.Column("device_type", sa.String(50), nullable=False, server_default="other"),
        sa.Column("serial_reference", sa.String(200), nullable=True),
        sa.Column("hardware_revision", sa.String(100), nullable=True),
        sa.Column("current_fingerprint", sa.String(64), nullable=True),
        sa.Column("previous_fingerprint", sa.String(64), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_verified", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_firmware_check", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_crypto_check", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_change", sa.String(200), nullable=True),
        sa.Column("firmware", sa.JSON(), nullable=True),
        sa.Column("tpm", sa.JSON(), nullable=True),
        sa.Column("hsm", sa.JSON(), nullable=True),
        sa.Column("capabilities", sa.JSON(), nullable=True),
        sa.Column("crypto_capabilities", sa.JSON(), nullable=True),
        sa.Column("previous_state", sa.JSON(), nullable=True),
        sa.Column("evidence_history", sa.JSON(), nullable=True),
        sa.Column("risk_score", sa.Integer(), nullable=True),
        sa.Column("risk_level", sa.String(20), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        "hardware_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("event_type", sa.String(50), nullable=False, index=True),
        sa.Column("asset_id", sa.String(200), nullable=False, index=True),
        sa.Column("agent_id", sa.String(100), nullable=True),
        sa.Column("source", sa.String(50), nullable=False, server_default="unknown"),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column("change_class", sa.String(40), nullable=True),
        sa.Column("state_verdict", sa.String(20), nullable=True),
        sa.Column("payload", sa.JSON(), nullable=True),
        sa.Column("evidence_id", sa.String(64), nullable=True),
        sa.Column("chain_hash", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        "hardware_agents",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("agent_id", sa.String(100), nullable=False, unique=True, index=True),
        sa.Column("last_heartbeat", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_successful_discovery", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_crypto_check", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_firmware_check", sa.DateTime(timezone=True), nullable=True),
        sa.Column("event_queue_depth", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("event_lag_seconds", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("agent_health", sa.String(20), nullable=False, server_default="HEALTHY"),
        sa.Column("agent_status", sa.String(20), nullable=False, server_default="ONLINE"),
        sa.Column("hardware_count", sa.Integer(), nullable=True),
        sa.Column("version", sa.String(40), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("hardware_agents")
    op.drop_table("hardware_events")
    op.drop_table("hardware_assets")
