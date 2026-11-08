"""os certificate metadata

Revision ID: 0144
Revises: 0143
Create Date: 2026-10-16
"""

import sqlalchemy as sa
from alembic import op

revision = "0144"
down_revision = "0143"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "os_certificates",
        sa.Column("id", sa.Integer(), autoincrement=True,
                  nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("certificate_id", sa.String(length=80),
                  nullable=False),
        sa.Column("collection_id", sa.String(length=80),
                  nullable=False),
        sa.Column("asset_id", sa.String(length=80), nullable=False),
        sa.Column("subject", sa.String(length=512), nullable=False,
                  server_default="unknown"),
        sa.Column("issuer", sa.String(length=512), nullable=False,
                  server_default="unknown"),
        sa.Column("not_before", sa.String(length=64), nullable=True),
        sa.Column("not_after", sa.String(length=64), nullable=True),
        sa.Column("thumbprint_sha256", sa.String(length=128),
                  nullable=True),
        sa.Column("public_key_algorithm", sa.String(length=64),
                  nullable=True),
        sa.Column("public_key_bits", sa.Integer(), nullable=True),
        sa.Column("evidence_class", sa.String(length=30),
                  nullable=False),
        sa.Column("evidence_source", sa.String(length=200),
                  nullable=True),
        sa.Column("limitations", sa.JSON(), nullable=True),
        sa.Column("collected_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("certificate_id",
                            name="uq_os_certificates_certificate_id"),
    )
    op.create_index("ix_os_certificates_tenant_collected",
                    "os_certificates", ["tenant_id", "collected_at"])


def downgrade() -> None:
    op.drop_index("ix_os_certificates_tenant_collected",
                  "os_certificates")
    op.drop_table("os_certificates")
