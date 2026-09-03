"""Short-lived vault-lease audit records for scanner credential access.

Revision ID: 0049
Revises: 0048
Create Date: 2026-09-03

Adds credential_leases: reference-only audit rows for bounded TTL/scope vault
leases. Stores a vault locator, never key material. No AI/ML.
"""
import sqlalchemy as sa
from alembic import op

revision = "0049"
down_revision = "0048"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "credential_leases",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("handle", sa.String(length=64), nullable=False),
        sa.Column("credential_name", sa.String(length=200), nullable=False),
        sa.Column("secret_ref", sa.Text(), nullable=False),
        sa.Column("component", sa.String(length=120), nullable=False),
        sa.Column("scope", sa.Text(), nullable=True),
        sa.Column("ttl_seconds", sa.Integer(), nullable=False, server_default="300"),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("released_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("issued_by", sa.String(length=100), nullable=False, server_default=""),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="ACTIVE"),
    )
    op.create_index("ix_cl_handle", "credential_leases", ["handle"], unique=True)
    op.create_index("ix_cl_credential_name", "credential_leases", ["credential_name"])
    op.create_index("ix_cl_component", "credential_leases", ["component"])
    op.create_index("ix_cl_expires_at", "credential_leases", ["expires_at"])
    op.create_index("ix_cl_status", "credential_leases", ["status"])


def downgrade() -> None:
    op.drop_index("ix_cl_status", table_name="credential_leases")
    op.drop_index("ix_cl_expires_at", table_name="credential_leases")
    op.drop_index("ix_cl_component", table_name="credential_leases")
    op.drop_index("ix_cl_credential_name", table_name="credential_leases")
    op.drop_index("ix_cl_handle", table_name="credential_leases")
    op.drop_table("credential_leases")
