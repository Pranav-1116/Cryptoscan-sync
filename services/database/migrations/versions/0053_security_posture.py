""":class:`cp_security_posture` — durable ZELNX security-posture snapshots.

Revision ID: 0053
Revises: 0052
Create Date: 2026-09-08

Adds a time-series table for the security center's deterministic 0-100
security posture. The control plane computes the posture from live signals
(agent fleet health, plugin trust, anomaly flags, failed logins, certificate
expiry, audit-chain integrity, credential health) and persists a snapshot so a
24/7 SOC can track posture over time. This is metadata only — no secret
material is ever stored here.

Mirrors the ``SecurityPosture`` ORM model exactly (see the schema-parity test).
"""
import sqlalchemy as sa
from alembic import op

revision = "0053"
down_revision = "0052"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "cp_security_posture",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column("agents_total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("agents_healthy", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("plugins_total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("plugins_verified", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("threats_open", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("threats_critical", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("failed_logins", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("cert_total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("cert_valid_pct", sa.Integer(), nullable=True),
        sa.Column("audit_ok", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("credentials_active", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("credentials_total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("components", sa.JSON(), nullable=True),
        sa.Column("source", sa.String(20), nullable=False, server_default="live"),
    )
    op.create_index("ix_cp_security_posture_created_at", "cp_security_posture", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_cp_security_posture_created_at", table_name="cp_security_posture")
    op.drop_table("cp_security_posture")
