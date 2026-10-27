"""Live versioned CBOM (immutable, content-addressed snapshots).

Revision ID: 0051
Revises: 0050
Create Date: 2026-09-03

Adds cbom_versions: each row is an immutable cryptographic bill-of-materials
version with a SHA-256 fingerprint over its canonicalized components, a parent
fingerprint for the version chain, and added/removed diffs. Deterministic,
no AI/ML.
"""
import sqlalchemy as sa
from alembic import op

revision = "0051"
down_revision = "0050"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "cbom_versions",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("parent_fingerprint", sa.String(length=64), nullable=True),
        sa.Column("component_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("components", sa.JSON(), nullable=True),
        sa.Column("added", sa.JSON(), nullable=True),
        sa.Column("removed", sa.JSON(), nullable=True),
        sa.Column("created_by", sa.String(length=100), nullable=False, server_default="system"),
    )
    op.create_index("ix_cv_version", "cbom_versions", ["version"], unique=True)
    op.create_index("ix_cv_fingerprint", "cbom_versions", ["fingerprint"])


def downgrade() -> None:
    op.drop_index("ix_cv_fingerprint", table_name="cbom_versions")
    op.drop_index("ix_cv_version", table_name="cbom_versions")
    op.drop_table("cbom_versions")
