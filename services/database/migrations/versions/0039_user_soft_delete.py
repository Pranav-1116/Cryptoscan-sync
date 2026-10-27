"""Soft delete for users (admin account removal, compliance-safe).

Adds ``users.deleted_at``: NULL = active, a timestamp = removed. The row is
retained so the audit hash chain and historical actor references stay
intact; authentication and the user list exclude deleted accounts.

Revision ID: 0039
Revises: 0038
Create Date: 2026-09-02
"""
import sqlalchemy as sa
from alembic import op

# revision identifiers
revision = "0039"
down_revision = "0038"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_users_deleted_at", "users", ["deleted_at"])


def downgrade() -> None:
    op.drop_index("ix_users_deleted_at", table_name="users")
    op.drop_column("users", "deleted_at")
