"""Custom role definitions (report 13 §2.2 open item, round 30).

The RBAC catalog was fixed at 9 roles + legacy aliases; tenants needing
a narrower key than `ciso` had no way to define one. This migration adds
the `custom_roles` table: a tenant-scoped named permission subset of the
existing permission matrix. A custom role can never grant an action the
matrix does not know (validated at write) and can never collide with a
built-in role name.
"""

from alembic import op
import sqlalchemy as sa

revision = "0081"
down_revision = "0080"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "custom_roles",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False, index=True),
        sa.Column("name", sa.String(100), nullable=False, index=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("permissions", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(100), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("tenant_id", "name", name="uq_custom_role_per_tenant"),
    )


def downgrade() -> None:
    op.drop_table("custom_roles")
