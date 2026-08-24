"""Create vulnerabilities table.

Revision ID: 0016
Revises: 0015
"""
from alembic import op
import sqlalchemy as sa

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "vulnerabilities",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("cve", sa.String(40), nullable=False),
        sa.Column("package", sa.String(200), nullable=False),
        sa.Column("affected", sa.String(80), nullable=True),
        sa.Column("severity", sa.String(20), nullable=False, server_default="MEDIUM"),
        sa.Column("summary", sa.Text, nullable=True),
        sa.Column("package_version", sa.String(80), nullable=True),
        sa.Column("scan_id", sa.String(36), nullable=True),
    )
    op.create_index("ix_vulnerabilities_cve", "vulnerabilities", ["cve"])
    op.create_index("ix_vulnerabilities_package", "vulnerabilities", ["package"])


def downgrade() -> None:
    op.drop_index("ix_vulnerabilities_package", table_name="vulnerabilities")
    op.drop_index("ix_vulnerabilities_cve", table_name="vulnerabilities")
    op.drop_table("vulnerabilities")
