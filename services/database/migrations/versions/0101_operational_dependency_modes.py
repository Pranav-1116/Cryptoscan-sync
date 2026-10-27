"""Declared operational dependency modes; legacy rows remain unknown."""

from alembic import op
import sqlalchemy as sa

revision = "0101"
down_revision = "0100"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("system_dependencies", sa.Column("operational_dependency", sa.JSON(), nullable=True))


def downgrade():
    with op.batch_alter_table("system_dependencies") as batch:
        batch.drop_column("operational_dependency")
