"""Create container_scans table.

Revision ID: 0015
Revises: 0014
"""
from alembic import op
import sqlalchemy as sa

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "container_scans",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("scan_id", sa.String(36), nullable=True),
        sa.Column("target", sa.Text, nullable=False),
        sa.Column("package_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("library_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("vuln_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("result", sa.JSON, nullable=True),
    )
    op.create_index("ix_container_scans_scan_id", "container_scans", ["scan_id"])


def downgrade() -> None:
    op.drop_index("ix_container_scans_scan_id", table_name="container_scans")
    op.drop_table("container_scans")
