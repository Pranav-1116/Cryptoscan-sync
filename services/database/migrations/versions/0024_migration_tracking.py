"""Migration tracking: tasks + milestones (Week 53-54).

Revision ID: 0024
Revises: 0023
Create Date: 2026-08-29
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers
revision = "0024"
down_revision = "0023"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "migration_tasks",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("project_id", sa.String(36), nullable=False, index=True),
        sa.Column("system_id", sa.String(36), nullable=True, index=True),
        sa.Column("asset_id", sa.String(36), nullable=True, index=True),
        sa.Column("evidence_id", sa.String(64), nullable=True),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("algorithm_from", sa.String(80), nullable=True),
        sa.Column("algorithm_to", sa.String(80), nullable=True),
        sa.Column("priority", sa.String(4), nullable=False, server_default="P2"),
        sa.Column("effort", sa.String(20), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="TODO"),
        sa.Column("blocked_reason", sa.Text(), nullable=True),
        sa.Column("owner", sa.String(200), nullable=True),
        sa.Column("source", sa.String(10), nullable=False, server_default="MANUAL"),
        sa.Column("external_ref", sa.String(300), nullable=True, index=True),
        sa.Column("due_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "migration_milestones",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("project_id", sa.String(36), nullable=False, index=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("target_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="PLANNED"),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )



def downgrade() -> None:
    op.drop_table("migration_milestones")
    op.drop_table("migration_tasks")
