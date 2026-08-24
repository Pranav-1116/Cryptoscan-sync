"""Create system_dependencies table.

Revision ID: 0014
Revises: 0013
"""
from alembic import op
import sqlalchemy as sa

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "system_dependencies",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("parent_id", sa.String(36), sa.ForeignKey("systems.id", ondelete="CASCADE"), nullable=False),
        sa.Column("child_id", sa.String(36), sa.ForeignKey("systems.id", ondelete="CASCADE"), nullable=False),
        sa.Column("relation", sa.String(80), nullable=True),
        sa.UniqueConstraint("parent_id", "child_id", name="uq_system_dep"),
    )


def downgrade() -> None:
    op.drop_table("system_dependencies")
