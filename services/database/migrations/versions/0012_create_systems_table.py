"""Create systems table.

Revision ID: 0012
Revises: 0011
"""
from alembic import op
import sqlalchemy as sa

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "systems",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("owner", sa.String(200), nullable=True),
        sa.Column("environment", sa.String(50), nullable=True),
        sa.Column("compliance_scopes", sa.JSON, nullable=True),
        sa.UniqueConstraint("name", name="uq_systems_name"),
    )
    op.create_index("ix_systems_name", "systems", ["name"])


def downgrade() -> None:
    op.drop_index("ix_systems_name", table_name="systems")
    op.drop_table("systems")
